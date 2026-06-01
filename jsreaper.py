#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# ╔══════════════════════════════════════════════════════════════════════╗
# ║                         JSReaper v1.1                               ║
# ║         JavaScript Recon & Analysis Tool for Bug Bounty             ║
# ║                                                                      ║
# ║  Written by @dr34lm                                                  ║
# ║  Twitter/X: https://x.com/dr34lm                                    ║
# ║                                                                      ║
# ║  I built this because I got tired of manually digging through        ║
# ║  minified JS files looking for leaked keys and endpoints.            ║
# ║  This automates the boring part so you can focus on the actual bugs. ║
# ║                                                                      ║
# ║  Works on Linux, macOS, Windows — Python 3.7+                       ║
# ║  Use only on targets you are authorized to test.                     ║
# ╚══════════════════════════════════════════════════════════════════════╝
#
# QUICK START:
#   jsreaper -u example.com --analyze
#   jsreaper -u example.com --analyze --subdomains --probe
#   jsreaper -l targets.txt -t 5 --analyze --waf-aware -o results.json
#
# INSTALL:
#   pip3 install requests beautifulsoup4 colorama jsbeautifier tqdm urllib3
#   chmod +x jsreaper.py && sudo cp jsreaper.py /usr/local/bin/jsreaper
#
# CHANGELOG:
#   v1.0 - initial release
#   v1.1 - added HTTP/HTTPS auto-fallback, lemon-green banner,
#           rich per-severity coloring, full cross-platform support

import argparse
import sys
import os
import re
import json
import time
import random
import hashlib
import datetime
import platform
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse
from collections import defaultdict
import threading

# ─── OS detection ────────────────────────────────────────────────────────────
# needed early so colorama initializes correctly on Windows
IS_WINDOWS = platform.system() == "Windows"
IS_MACOS   = platform.system() == "Darwin"
IS_LINUX   = platform.system() == "Linux"

# ─── Core dependencies ───────────────────────────────────────────────────────
# if any of these are missing the script can't run at all, so fail loud and clear
try:
    import requests
    from bs4 import BeautifulSoup
    from colorama import init, Fore, Back, Style
    # on Windows we need convert=True so ANSI codes get translated
    # on Linux/Mac it's fine without it
    init(autoreset=True, convert=IS_WINDOWS, strip=False)
except ImportError as e:
    print(f"[!] Missing dependency: {e}")
    print("[*] Run this to install everything:")
    print("[*]   pip3 install requests beautifulsoup4 colorama jsbeautifier tqdm urllib3")
    sys.exit(1)

# ─── Optional: JS beautifier ─────────────────────────────────────────────────
# not required but makes minified code way more readable before analysis
try:
    import jsbeautifier
    JS_BEAUTIFIER = True
except ImportError:
    JS_BEAUTIFIER = False

# ─── Optional: progress bars ─────────────────────────────────────────────────
# nice to have but the tool works fine without it
try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False


# ═════════════════════════════════════════════════════════════════════════════
#  BANNER
#  Using ANSI 256-color codes for the lemon-green gradient.
#  Tested on: Parrot OS, Kali, Ubuntu, macOS Terminal, Windows Terminal
# ═════════════════════════════════════════════════════════════════════════════

LEMON = "\033[38;5;154m"   # bright lemon green — top of the logo
LIME  = "\033[38;5;118m"   # lime green         — middle
MINT  = "\033[38;5;121m"   # mint/pale green    — bottom
GOLD  = "\033[38;5;220m"   # gold               — subtitle
GRAY  = "\033[38;5;245m"   # muted gray         — small print
RESET = Style.RESET_ALL

BANNER = f"""
{LEMON}     ██╗███████╗██████╗ ███████╗ █████╗ ██████╗ ███████╗██████╗ 
{LEMON}     ██║██╔════╝██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗
{LIME}     ██║███████╗██████╔╝█████╗  ███████║██████╔╝█████╗  ██████╔╝
{LIME} ██  ██║╚════██║██╔══██╗██╔══╝  ██╔══██║██╔═══╝ ██╔══╝  ██╔══██╗
{MINT} ╚█████╔╝███████║██║  ██║███████╗██║  ██║██║     ███████╗██║  ██║
{MINT}  ╚════╝ ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝
{GOLD}
          ⚡  JavaScript Recon & Analysis Tool  v1.1
{GRAY}          🌐  Linux | macOS | Windows  —  Python 3.7+
{GRAY}          ✍   Written by @dr34lm  |  Authorized Use Only
{RESET}"""


# ═════════════════════════════════════════════════════════════════════════════
#  COLOR SYSTEM
#  Each severity level gets its own background+text badge so findings are
#  impossible to miss at a glance. I picked these colors after testing on
#  both dark and light terminals — they work on both.
# ═════════════════════════════════════════════════════════════════════════════

# badge = colored background block used inline next to each finding
C_CRITICAL = "\033[48;5;196m\033[38;5;231m"   # red bg, white text
C_HIGH     = "\033[48;5;202m\033[38;5;231m"   # orange bg, white text
C_MEDIUM   = "\033[48;5;220m\033[38;5;232m"   # gold bg, dark text (gold bg needs dark text to be readable)
C_LOW      = "\033[48;5;33m\033[38;5;231m"    # blue bg, white text
C_INFO     = "\033[48;5;238m\033[38;5;252m"   # dark gray bg, light text

# foreground-only colors for URLs, labels, section headers etc.
FG_CRITICAL = "\033[38;5;196m"
FG_HIGH     = "\033[38;5;208m"
FG_MEDIUM   = "\033[38;5;220m"
FG_LOW      = "\033[38;5;75m"
FG_INFO     = "\033[38;5;252m"
FG_SUCCESS  = "\033[38;5;154m"   # same lemon green as the banner
FG_LABEL    = "\033[38;5;213m"   # pink/purple for category headers
FG_URL      = "\033[38;5;117m"   # pale cyan for file paths and URLs
FG_RELATION = "\033[38;5;147m"   # lavender for JS import relationships
FG_SECTION  = "\033[38;5;226m"   # bright yellow for section dividers
FG_DIM      = "\033[38;5;242m"   # dim gray for context/secondary info
FG_WAF      = "\033[38;5;203m"   # salmon for WAF warnings
FG_PROBE    = "\033[38;5;208m"   # orange for file probe hits
FG_SUB      = "\033[38;5;120m"   # pale green for subdomains

# lookup dicts so I can just do SEVERITY_FG[severity] instead of a big if/else
SEVERITY_FG    = {"critical": FG_CRITICAL, "high": FG_HIGH,
                  "medium":   FG_MEDIUM,   "low":  FG_LOW, "info": FG_INFO}
SEVERITY_BADGE = {"critical": C_CRITICAL,  "high": C_HIGH,
                  "medium":   C_MEDIUM,    "low":  C_LOW,  "info": C_INFO}

# used when sorting findings — critical always floats to the top
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# emoji icons next to each finding line (Windows CMD falls back to text)
SEVERITY_ICONS = {"critical": "💀", "high": "🔴", "medium": "🟡", "low": "🔵", "info": "⚪"}

# old Windows CMD doesn't render emoji properly — swap to plain text
if IS_WINDOWS and "WT_SESSION" not in os.environ:
    SEVERITY_ICONS = {
        "critical": "[!!!]",
        "high":     "[!! ]",
        "medium":   "[!  ]",
        "low":      "[-  ]",
        "info":     "[.  ]",
    }

# each finding category gets its own distinct fg color
# makes it easy to scan output and spot what type of issue you're looking at
CATEGORY_COLORS = {
    "API Keys & Tokens":           "\033[38;5;213m",
    "AWS Credentials":             "\033[38;5;196m",
    "Authentication & Passwords":  "\033[38;5;203m",
    "OAuth & SSO":                 "\033[38;5;219m",
    "Database Credentials":        "\033[38;5;208m",
    "Cloud & Infrastructure":      "\033[38;5;117m",
    "Sensitive Endpoints & Paths": "\033[38;5;226m",
    "OWASP / Security Issues":     "\033[38;5;203m",
    "Internal Infrastructure":     "\033[38;5;147m",
    "Hardcoded Usernames":         "\033[38;5;220m",
    "Crypto & Hashing":            "\033[38;5;75m",
    "URLs & Subdomains":           "\033[38;5;120m",
    "Version Control & Debug":     "\033[38;5;245m",
}


# ═════════════════════════════════════════════════════════════════════════════
#  USER AGENTS
#  Rotating through real browser UA strings helps avoid simple bot detection.
#  These are all real UA strings from current browsers — nothing fake.
# ═════════════════════════════════════════════════════════════════════════════

USER_AGENTS = [
    # Chrome on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    # Chrome on Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    # Firefox on Linux
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    # Firefox on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    # Safari on Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    # Edge on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    # Firefox on Ubuntu
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    # Mobile Safari (iPhone) — some sites serve different JS bundles to mobile
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
]


# ═════════════════════════════════════════════════════════════════════════════
#  SENSITIVE PATTERNS
#
#  This is the heart of the tool. Each entry is (regex_pattern, severity).
#  I organised them by category so it's easy to add new patterns later.
#
#  Severity levels:
#    critical — report immediately, don't wait
#    high     — strong finding, worth a report
#    medium   — interesting, needs manual confirmation
#    low      — minor, good context but rarely standalone
#    info     — just noting it exists
#
#  Most of these patterns came from real findings I've seen in the wild.
#  Feel free to add your own at the bottom of any category.
# ═════════════════════════════════════════════════════════════════════════════

SENSITIVE_PATTERNS = {

    # ── API keys are the most common JS leak I find ──────────────────────────
    "API Keys & Tokens": [
        (r'api[_\-\s]?key[\s]*[=:]\s*["\']?([A-Za-z0-9_\-]{16,})["\']?',     "high"),
        (r'apikey[\s]*[=:]\s*["\']?([A-Za-z0-9_\-]{16,})["\']?',              "high"),
        (r'api[_\-]?token[\s]*[=:]\s*["\']?([A-Za-z0-9_\-]{16,})["\']?',     "high"),
        (r'access[_\-]?token[\s]*[=:]\s*["\']?([A-Za-z0-9_\-\.]{16,})["\']?',"high"),
        (r'auth[_\-]?token[\s]*[=:]\s*["\']?([A-Za-z0-9_\-\.]{16,})["\']?',  "high"),
        (r'bearer\s+([A-Za-z0-9_\-\.]{20,})',                                  "high"),
        (r'x-api-key[\s]*[=:]\s*["\']?([A-Za-z0-9_\-]{16,})["\']?',          "high"),
    ],

    # ── AWS is critical — exposed keys can drain a company account overnight ─
    "AWS Credentials": [
        (r'AKIA[0-9A-Z]{16}',                                                   "critical"),  # access key ID format
        (r'aws[_\-]?access[_\-]?key[_\-]?id[\s]*[=:]\s*["\']?([A-Z0-9]{20})["\']?',     "critical"),
        (r'aws[_\-]?secret[_\-]?access[_\-]?key[\s]*[=:]\s*["\']?([A-Za-z0-9/+=]{40})["\']?', "critical"),
        (r'aws[_\-]?session[_\-]?token[\s]*[=:]\s*["\']?([A-Za-z0-9/+=]{100,})["\']?',  "critical"),
        (r'amazonaws\.com',                                                     "info"),    # just a reference, not a secret
        (r's3\.amazonaws\.com/([A-Za-z0-9_\-\.]+)',                            "medium"),  # S3 bucket name leak
    ],

    # ── Passwords in JS happen more than you'd think ─────────────────────────
    "Authentication & Passwords": [
        (r'password[\s]*[=:]\s*["\']([^"\']{4,})["\']',                       "high"),
        (r'passwd[\s]*[=:]\s*["\']([^"\']{4,})["\']',                         "high"),
        (r'secret[\s]*[=:]\s*["\']([^"\']{8,})["\']',                         "high"),
        (r'client[_\-]?secret[\s]*[=:]\s*["\']?([A-Za-z0-9_\-\.]{16,})["\']?',"critical"),
        (r'private[_\-]?key[\s]*[=:]\s*["\']([^"\']{8,})["\']',              "critical"),
        (r'-----BEGIN (RSA |EC )?PRIVATE KEY-----',                            "critical"),  # PEM block in JS = very bad
        (r'jwt[_\-]?secret[\s]*[=:]\s*["\']([^"\']{8,})["\']',               "critical"),
    ],

    # ── OAuth misconfigs are great for account takeover chains ───────────────
    "OAuth & SSO": [
        (r'client[_\-]?id[\s]*[=:]\s*["\']([A-Za-z0-9_\-\.]{8,})["\']',     "medium"),
        (r'oauth[_\-]?token[\s]*[=:]\s*["\']?([A-Za-z0-9_\-\.]{16,})["\']?', "high"),
        (r'refresh[_\-]?token[\s]*[=:]\s*["\']([^"\']{16,})["\']',           "high"),
        (r'redirect[_\-]?uri[\s]*[=:]\s*["\']([^"\']+)["\']',                "medium"),  # open redirect risk
    ],

    # ── DB connection strings in JS = direct database access ─────────────────
    "Database Credentials": [
        (r'db[_\-]?password[\s]*[=:]\s*["\']([^"\']+)["\']',                 "critical"),
        (r'database[_\-]?url[\s]*[=:]\s*["\']([^"\']+)["\']',                "high"),
        (r'mongodb(\+srv)?://[^\s"\'<]+',                                      "high"),
        (r'mysql://[^\s"\'<]+',                                                "high"),
        (r'postgresql://[^\s"\'<]+',                                           "high"),
        (r'redis://[^\s"\'<]+',                                                "medium"),
        (r'connection[_\-]?string[\s]*[=:]\s*["\']([^"\']+)["\']',           "high"),
    ],

    # ── Cloud provider keys — all worth reporting ─────────────────────────────
    "Cloud & Infrastructure": [
        (r'firebase[A-Za-z]*[\s]*[=:]\s*["\']([^"\']{10,})["\']',            "high"),
        (r'firebaseConfig\s*=\s*\{([^}]+)\}',                                 "high"),   # full firebase config block
        (r'google[_\-]?api[_\-]?key[\s]*[=:]\s*["\']([A-Za-z0-9_\-]{30,})["\']', "high"),
        (r'AIza[0-9A-Za-z\-_]{35}',                                            "high"),  # Google API key pattern
        (r'azure[_\-]?key[\s]*[=:]\s*["\']([^"\']{10,})["\']',               "high"),
        (r'stripe[_\-]?key[\s]*[=:]\s*["\']?(sk_live_[A-Za-z0-9]{24,})["\']?', "critical"),
        (r'sk_live_[A-Za-z0-9]{24,}',                                          "critical"),  # Stripe live secret key
        (r'pk_live_[A-Za-z0-9]{24,}',                                          "high"),      # Stripe live public key
        (r'twilio[_\-]?auth[_\-]?token[\s]*[=:]\s*["\']([A-Za-z0-9]{32})["\']', "high"),
        (r'sendgrid[_\-]?api[_\-]?key[\s]*[=:]\s*["\']?(SG\.[A-Za-z0-9_\-\.]{40,})["\']?', "high"),
        (r'SG\.[A-Za-z0-9_\-\.]{40,}',                                         "high"),   # SendGrid key format
        (r'heroku[_\-]?api[_\-]?key[\s]*[=:]\s*["\']([A-Za-z0-9\-]{36})["\']', "high"),
        (r'digitalocean[_\-]?token[\s]*[=:]\s*["\']([A-Za-z0-9]{64})["\']',  "high"),
    ],

    # ── Hidden endpoints — good for IDOR and access control testing ───────────
    "Sensitive Endpoints & Paths": [
        (r'["\']/?admin["\'/]',                 "medium"),
        (r'["\']/?api/v[0-9]+[/"\'a-zA-Z]',    "info"),
        (r'["\']/?internal[/"\'a-zA-Z]',        "medium"),
        (r'["\']/?debug[/"\'a-zA-Z]',           "medium"),
        (r'["\']/?swagger[/"\'a-zA-Z]',         "medium"),  # API docs often expose all endpoints
        (r'["\']/?graphql[/"\'a-zA-Z]',         "medium"),
        (r'["\']/?\.git[/"\'a-zA-Z]',           "high"),
        (r'["\']/?\.env[/"\'a-zA-Z]',           "high"),
        (r'["\']/?backup[s]?[/"\'a-zA-Z]',      "medium"),
        (r'["\']/?config[/"\'a-zA-Z]',          "medium"),
        (r'["\']/?upload[s]?[/"\'a-zA-Z]',      "medium"),
        (r'["\']/?phpmyadmin[/"\'a-zA-Z]',      "high"),
        (r'/etc/passwd',                         "critical"),
        (r'/etc/shadow',                         "critical"),
    ],

    # ── OWASP Top 10 indicators — look for these when digging deeper ──────────
    "OWASP / Security Issues": [
        (r'eval\s*\(',                                              "high"),    # A03: code injection
        (r'innerHTML\s*=',                                          "medium"),  # A03: XSS sink
        (r'document\.write\s*\(',                                   "medium"),  # A03: XSS sink
        (r'\.dangerouslySetInnerHTML',                              "medium"),  # A03: React XSS
        (r'localStorage\.setItem\s*\(',                             "info"),    # storing sensitive data client-side?
        (r'sessionStorage\.setItem\s*\(',                           "info"),
        (r'console\.(log|error|warn|info)\s*\(.*?(pass|key|secret|token|auth)', "medium"),  # secrets in logs
        (r'debugger;',                                              "info"),    # leftover debug code
        (r'window\.location\s*=\s*[^;]+\+',                        "medium"),  # A01: open redirect
        (r'\.redirect\s*\([^)]*\+',                                "medium"),  # A01: open redirect
        (r'XMLHttpRequest',                                         "info"),
        (r'fetch\s*\(["\']http',                                    "info"),
        (r'cors[\s]*[=:]\s*["\']?\*["\']?',                        "medium"),  # A05: CORS wildcard
        (r'Access-Control-Allow-Origin["\s:]*\*',                   "medium"),  # A05: CORS wildcard
        (r'document\.cookie',                                       "medium"),  # cookie access
        (r'\.src\s*=\s*[^;]*\+',                                   "medium"),  # A03: DOM XSS via dynamic src
    ],

    # ── Internal IPs in JS = network topology leak ────────────────────────────
    "Internal Infrastructure": [
        (r'192\.168\.\d+\.\d+',                         "medium"),
        (r'10\.\d+\.\d+\.\d+',                          "medium"),
        (r'172\.(1[6-9]|2[0-9]|3[01])\.\d+\.\d+',     "medium"),
        (r'localhost:\d+',                               "medium"),
        (r'127\.0\.0\.1',                               "medium"),
        (r'staging\.[a-z0-9\-]+\.[a-z]+',              "info"),   # staging environments often have weaker auth
        (r'dev\.[a-z0-9\-]+\.[a-z]+',                  "info"),
        (r'test\.[a-z0-9\-]+\.[a-z]+',                 "info"),
        (r'internal\.[a-z0-9\-]+\.[a-z]+',             "medium"),
    ],

    # ── Hardcoded credentials — obvious but still happens all the time ────────
    "Hardcoded Usernames": [
        (r'username[\s]*[=:]\s*["\']([^"\']{3,})["\']',           "medium"),
        (r'user[\s]*[=:]\s*["\']([^"\']{3,})["\'](?!\s*[,{])',    "low"),
        (r'admin[\s]*[=:]\s*["\']([^"\']{3,})["\']',              "high"),
        (r'root[\s]*[=:]\s*["\']([^"\']{3,})["\']',               "high"),
        (r'email[\s]*[=:]\s*["\']([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})["\']', "medium"),
    ],

    # ── Weak crypto is a finding in most programs ──────────────────────────────
    "Crypto & Hashing": [
        (r'md5\s*\(',    "medium"),  # MD5 is broken, shouldn't be used for anything security-related
        (r'sha1\s*\(',   "low"),     # SHA1 is deprecated
        (r'btoa\s*\(',   "medium"),  # base64 encoding secrets isn't encryption
        (r'atob\s*\(',   "medium"),  # decoding base64 — what are you hiding?
        (r'encrypt\s*\(', "info"),
        (r'decrypt\s*\(', "info"),
    ],

    # ── URLs and subdomains buried in JS ─────────────────────────────────────
    "URLs & Subdomains": [
        (r'https?://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(?:/[^\s"\'<>]*)?', "info"),
        (r'//[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}/[^\s"\'<>]+',              "info"),
        (r'["\']([a-zA-Z0-9\-]+\.[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,})["\']',"info"),
    ],

    # ── Source maps are a goldmine — they expose the original unminified code ─
    "Version Control & Debug": [
        (r'sourceMappingURL\s*=\s*(.+\.map)', "medium"),  # .map file = full original source
        (r'TODO[:\s]',    "info"),   # devs leave breadcrumbs
        (r'FIXME[:\s]',   "info"),
        (r'HACK[:\s]',    "info"),   # "HACK: bypass auth check" — yes, this happens
        (r'BUG[:\s]',     "info"),
        (r'XXX[:\s]',     "info"),
        (r'NOSONAR',      "info"),   # code smell suppression
        (r'@deprecated',  "info"),
    ],
}


# ═════════════════════════════════════════════════════════════════════════════
#  FILE TYPES TO HUNT FOR
#  Beyond .js files, these are the other types worth collecting from a target.
#  Some of the most valuable bug bounty finds come from exposed config files.
# ═════════════════════════════════════════════════════════════════════════════

INTERESTING_EXTENSIONS = [
    # JavaScript variants
    ".js", ".mjs", ".jsx", ".ts", ".tsx",
    # Config files — these are the jackpot
    ".json", ".config.js", ".env",
    # Data formats
    ".xml", ".yaml", ".yml", ".toml",
    # Server-side code exposed via misconfiguration
    ".php", ".py", ".rb", ".asp", ".aspx",
    # Database files
    ".sql", ".db",
    # Backup files — devs forget these constantly
    ".bak", ".backup", ".old", ".tmp",
    # Logs
    ".log", ".txt",
    # Source maps (see note above)
    ".map",
    # WebAssembly
    ".wasm",
]


# ═════════════════════════════════════════════════════════════════════════════
#  WAF SIGNATURES
#  Fingerprints for common WAFs. I check both response headers and body
#  because some WAFs hide in the body while others announce themselves
#  in headers. If we detect one, we warn and suggest --waf-aware mode.
# ═════════════════════════════════════════════════════════════════════════════

WAF_SIGNATURES = {
    "Cloudflare":  ["cloudflare", "cf-ray", "__cfduid", "cf-request-id"],
    "Akamai":      ["akamai", "akamai-ghost", "x-check-cacheable"],
    "AWS WAF":     ["awswaf", "x-amzn-requestid", "x-amz-cf-id"],
    "Sucuri":      ["sucuri", "x-sucuri-id", "x-sucuri-cache"],
    "Imperva":     ["imperva", "incap_ses", "visid_incap", "x-iinfo"],
    "Barracuda":   ["barra", "barracuda"],
    "F5 BIG-IP":   ["bigip", "f5", "x-cnection"],
    "ModSecurity": ["mod_security", "modsecurity"],
}

# used to color-code HTTP status responses in the probe section
STATUS_COLOR = {
    200: FG_CRITICAL,   # file exists and is readable — report it
    301: FG_MEDIUM,     # redirect — might be interesting
    302: FG_MEDIUM,
    403: FG_LOW,        # blocked but exists — still worth noting
    429: FG_WAF,        # rate limited
    503: FG_WAF,        # service unavailable, often WAF
}

# ═════════════════════════════════════════════════════════════════════════════
#  SENSITIVE PATHS TO PROBE
#  These are the paths I check when --probe is enabled. Based on real
#  bug reports I've seen on HackerOne and Bugcrowd over the years.
#  A single exposed .env can be a critical finding worth $$$$.
# ═════════════════════════════════════════════════════════════════════════════

COMMON_SENSITIVE_PATHS = [
    # .env files — the holy grail
    "/.env", "/.env.local", "/.env.production", "/.env.backup",
    # git repo exposed
    "/.git/config", "/.git/HEAD", "/.git/COMMIT_EDITMSG",
    # JS config files that sometimes have hardcoded secrets
    "/config.js", "/config.json", "/app.config.js",
    "/webpack.config.js", "/package.json", "/package-lock.json",
    "/composer.json", "/Gemfile",
    # standard recon
    "/robots.txt", "/sitemap.xml",
    # backup files
    "/backup.zip", "/backup.tar.gz", "/backup.sql",
    "/db.sql", "/database.sql", "/dump.sql",
    # WordPress installs
    "/wp-config.php", "/wp-config.php.bak",
    # PHP debug pages
    "/phpinfo.php", "/info.php", "/test.php",
    # admin panels
    "/admin/", "/administrator/", "/panel/",
    # API documentation — maps out the whole attack surface
    "/swagger.json", "/swagger.yaml", "/openapi.json", "/api-docs",
    "/graphql", "/graphiql",
    # server config
    "/.htaccess", "/.htpasswd",
    "/web.config", "/server.xml",
    # flash/silverlight crossdomain
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    # API versioning
    "/api/v1/", "/api/v2/", "/api/v3/",
    # Spring Boot actuator endpoints — huge attack surface on Java apps
    "/actuator", "/actuator/health", "/actuator/env",
    # health/debug endpoints
    "/metrics", "/health", "/status",
    "/debug", "/console", "/__debug__",
    "/trace", "/server-status", "/error_log", "/access_log",
]


# ═════════════════════════════════════════════════════════════════════════════
#  PRINT HELPERS
#  Thread-safe printing so concurrent scans don't mangle each other's output.
#  I learned this the hard way after output was getting scrambled on
#  multi-target scans.
# ═════════════════════════════════════════════════════════════════════════════

print_lock = threading.Lock()

def cprint(msg, color="", prefix=""):
    """thread-safe colored print"""
    with print_lock:
        print(f"{color}{prefix}{msg}{RESET}")

# shorthand helpers — used all over the codebase
def info(msg):    cprint(msg, FG_LOW,      "[*] ")
def success(msg): cprint(msg, FG_SUCCESS,  "[+] ")
def warn(msg):    cprint(msg, FG_WAF,      "[!] ")
def error(msg):   cprint(msg, FG_CRITICAL, "[-] ")

def section_header(title, color=FG_SECTION):
    """prints a double-line bordered section header"""
    width = 70
    # center the title with padding
    pad = (width - len(title) - 4) // 2
    with print_lock:
        print(f"\n{color}{'═' * width}")
        print(f"{'═' * pad}  {title}  {'═' * (width - pad - len(title) - 4)}")
        print(f"{'═' * width}{RESET}")


# ═════════════════════════════════════════════════════════════════════════════
#  URL HANDLING
# ═════════════════════════════════════════════════════════════════════════════

def normalize_url(url):
    """
    Clean up whatever the user throws at us.
    People copy URLs from browser bars, from scope lists, from notes —
    they come in all kinds of formats. This handles:
      example.com           → https://example.com
      http://example.com    → kept as-is
      https://example.com   → kept as-is
      //example.com/path    → https://example.com/path
      ftp://example.com     → https://example.com
    """
    url = url.strip()

    # strip markdown link syntax in case someone copy-pastes from a writeup
    url = re.sub(r'^\[.*?\]\(', '', url).rstrip(')')

    if url.startswith("//"):
        url = "https:" + url
    elif url.startswith("ftp://"):
        # ftp is useless here, just swap it
        url = "https://" + url[6:]
    elif not url.startswith(("http://", "https://")):
        # bare domain — assume https, we'll fall back to http if needed
        url = "https://" + url

    return url.rstrip("/")


def try_http_fallback(url, session, timeout=10):
    """
    Try the URL as given. If it fails and it's https://, retry with http://.

    Some targets (especially internal apps and older bug bounty programs)
    don't have valid SSL certs, or redirect HTTP but not HTTPS. This
    handles both cases transparently so the user doesn't have to think about it.

    Returns (working_url, response) — or (original_url, None) if both fail.
    """
    resp = fetch_url(url, session, timeout=timeout)
    if resp is not None:
        return url, resp

    # https failed — try http before giving up
    if url.startswith("https://"):
        http_url = "http://" + url[8:]
        info(f"HTTPS failed, retrying with HTTP: {http_url}")
        resp = fetch_url(http_url, session, timeout=timeout)
        if resp is not None:
            success(f"HTTP fallback succeeded: {http_url}")
            return http_url, resp

    return url, None


def get_domain(url):
    """extract just the hostname from a URL"""
    return urlparse(url).netloc


def get_platform_info():
    """one-liner system info for the scan header"""
    return f"{platform.system()} {platform.release()} / Python {platform.python_version()}"


def random_delay(waf_mode=False):
    """
    Sleep for a random amount of time between requests.
    In WAF mode the delays are longer and more variable — this mimics
    human browsing patterns and avoids triggering rate-limit rules.
    """
    if waf_mode:
        # 1.5–4 seconds feels human, but still keeps the scan moving
        time.sleep(random.uniform(1.5, 4.0))
    else:
        # small delay even in normal mode — just enough to be polite
        time.sleep(random.uniform(0.1, 0.5))


# ═════════════════════════════════════════════════════════════════════════════
#  HTTP SESSION
# ═════════════════════════════════════════════════════════════════════════════

def build_session(waf_aware=False):
    """
    Build a requests session that looks like a real browser.
    All these headers are what Chrome sends on a normal page load.
    Without them some WAFs flag you immediately.
    """
    session = requests.Session()
    ua = random.choice(USER_AGENTS)

    headers = {
        "User-Agent": ua,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Cache-Control": "max-age=0",
    }

    if waf_aware:
        # look like we arrived from Google — some WAFs check the Referer
        headers["Referer"] = "https://www.google.com/"
        headers["DNT"] = "1"

    session.headers.update(headers)
    return session


# ═════════════════════════════════════════════════════════════════════════════
#  WAF DETECTION
# ═════════════════════════════════════════════════════════════════════════════

def detect_waf(response):
    """
    Check response headers and body for known WAF fingerprints.
    Also flag anything that comes back 403/429/503 with no other
    explanation — that's usually a WAF being protective.
    """
    detected = []

    response_text  = response.text.lower() if response.text else ""
    headers_lower  = {k.lower(): v.lower() for k, v in response.headers.items()}
    combined       = response_text + " " + str(headers_lower)

    for waf_name, signatures in WAF_SIGNATURES.items():
        for sig in signatures:
            if sig.lower() in combined:
                detected.append(waf_name)
                break  # one match is enough per WAF

    # generic block detection when no specific fingerprint matched
    if response.status_code in [403, 406, 429, 503] and not detected:
        detected.append("Unknown WAF (blocked)")

    return list(set(detected))


# ═════════════════════════════════════════════════════════════════════════════
#  URL FETCHER
# ═════════════════════════════════════════════════════════════════════════════

def fetch_url(url, session, timeout=15, waf_aware=False, retries=3):
    """
    Fetch a URL with automatic retry and WAF evasion.
    On each retry in WAF mode we rebuild the session with a fresh UA.
    Exponential backoff on connection errors.
    """
    for attempt in range(retries):
        try:
            if waf_aware and attempt > 0:
                # we got blocked — wait and come back with a fresh identity
                random_delay(waf_mode=True)
                session = build_session(waf_aware=True)

            resp = session.get(url, timeout=timeout, allow_redirects=True, verify=False)

            # rotate UA after each successful request too
            session.headers["User-Agent"] = random.choice(USER_AGENTS)
            return resp

        except requests.exceptions.SSLError:
            # SSL error — try once more with verify=False explicitly
            try:
                resp = session.get(url, timeout=timeout, allow_redirects=True, verify=False)
                return resp
            except Exception:
                pass

        except requests.exceptions.ConnectionError:
            if attempt < retries - 1:
                time.sleep(2 ** attempt)  # 1s, 2s, 4s — exponential backoff

        except requests.exceptions.Timeout:
            if attempt < retries - 1:
                time.sleep(1)

        except Exception:
            if attempt == retries - 1:
                return None

    return None


# ═════════════════════════════════════════════════════════════════════════════
#  JS FILE DISCOVERY
#  This is where the crawling happens. We fetch the target page and pull
#  every JS file reference we can find — from script tags, link tags,
#  and also by regex-scanning the raw HTML for any string ending in .js
# ═════════════════════════════════════════════════════════════════════════════

def extract_js_from_page(url, session, waf_aware=False):
    """
    Crawl a page and extract all JS and interesting file references.
    Returns (js_files, other_files, response).
    """
    js_files    = set()
    other_files = set()

    # use HTTP fallback automatically — no need to think about it
    url, resp = try_http_fallback(url, session, timeout=15)
    if not resp:
        error(f"Could not reach target (tried HTTP and HTTPS): {url}")
        return js_files, other_files, None

    # check for WAF before we go any further
    waf = detect_waf(resp)
    if waf:
        warn(f"WAF detected on {url}: {', '.join(waf)}")
        if waf_aware:
            warn("WAF-aware mode active — adding delays...")

    if resp.status_code != 200:
        warn(f"Got HTTP {resp.status_code} for {url}")
        if resp.status_code in [403, 429, 503]:
            warn("Looks like a WAF block. Try adding --waf-aware")

    soup     = BeautifulSoup(resp.text, "html.parser")
    base_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}"

    # method 1: standard <script src="..."> tags
    for tag in soup.find_all("script", src=True):
        src  = tag["src"]
        full = urljoin(url, src)
        if full.endswith(".js") or ".js?" in full:
            js_files.add(full)

    # method 2: other tags for non-JS interesting files
    for tag in soup.find_all(["link", "a", "iframe", "img"]):
        href = tag.get("href", "") or tag.get("src", "")
        if href:
            full = urljoin(url, href)
            for ext in INTERESTING_EXTENSIONS:
                if ext in full.lower() and ext != ".js":
                    other_files.add(full)

    # method 3: regex scan the raw HTML — catches JS loaded by frameworks
    # that don't use standard script tags (React, Vue, etc.)
    raw = resp.text
    js_patterns = [
        r'src\s*[=:]\s*["\']([^"\']+\.js(?:\?[^"\']*)?)["\']',
        r'import\s+[^"\']*["\']([^"\']+\.js)["\']',
        r'require\s*\(\s*["\']([^"\']+\.js)["\']',
        r'loadScript\s*\(\s*["\']([^"\']+\.js)["\']',
        r'["\']([/a-zA-Z0-9_\-\.]+\.js(?:\?[a-zA-Z0-9=&_\-\.]+)?)["\']',
    ]
    for pattern in js_patterns:
        for match in re.finditer(pattern, raw, re.IGNORECASE):
            path = match.group(1)
            # resolve relative, protocol-relative, and absolute paths
            if path.startswith("//"):
                full = "https:" + path
            elif path.startswith("/"):
                full = base_url + path
            elif path.startswith("http"):
                full = path
            else:
                full = urljoin(url, path)
            js_files.add(full)

    return js_files, other_files, resp


# ═════════════════════════════════════════════════════════════════════════════
#  JS CONTENT ANALYSIS
#  Once we have the raw JS content this function runs all the pattern
#  matching, endpoint extraction, and relationship mapping.
# ═════════════════════════════════════════════════════════════════════════════

def analyze_js_content(url, content, beautify=False):
    """
    Analyze the content of a JS file for secrets, vulns, endpoints,
    and relationships with other JS files.
    Returns a dict with findings, endpoints, js_relations, and a risk score.
    """
    results = {
        "url":          url,
        "size":         len(content),
        "findings":     [],
        "endpoints":    [],
        "js_relations": [],
        "score":        0,
    }

    # de-minify first if requested — analysis is much better on readable code
    if beautify and JS_BEAUTIFIER:
        try:
            content = jsbeautifier.beautify(content)
        except Exception:
            pass  # if it fails just run on the minified version

    lines         = content.split("\n")
    seen_findings = set()   # for deduplication

    # ── run all pattern categories ──────────────────────────────────────────
    for category, patterns in SENSITIVE_PATTERNS.items():
        for pattern, severity in patterns:
            try:
                for match in re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE):
                    matched_str = match.group(0)[:120]   # cap length for display

                    # find which line this is on (for the report)
                    line_num = content[:match.start()].count("\n") + 1
                    line_ctx = lines[line_num - 1].strip()[:150] if line_num <= len(lines) else ""

                    # deduplicate by hashing category + match text
                    # avoids the same pattern firing 50 times in a minified file
                    dedup_key = hashlib.md5(f"{category}{matched_str}".encode()).hexdigest()
                    if dedup_key in seen_findings:
                        continue
                    seen_findings.add(dedup_key)

                    results["findings"].append({
                        "category": category,
                        "severity": severity,
                        "match":    matched_str,
                        "line":     line_num,
                        "context":  line_ctx,
                    })

                    # accumulate risk score — weight by severity
                    score_map = {"critical": 100, "high": 50, "medium": 20, "low": 5, "info": 1}
                    results["score"] += score_map.get(severity, 1)

            except re.error:
                continue   # skip malformed patterns, don't crash

    # ── extract API endpoints ──────────────────────────────────────────────
    for pat in [
        # API-style paths
        r'["\'](\/?(?:api|v[0-9]+|rest|graphql|endpoint|service)[\/a-zA-Z0-9_\-\.?=&%#@!]+)["\']',
        # full URLs
        r'https?://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(?:/[^\s"\'<>]*)?',
    ]:
        for match in re.finditer(pat, content, re.IGNORECASE):
            ep = match.group(1) if match.lastindex else match.group(0)
            if ep not in results["endpoints"] and len(ep) > 3:
                results["endpoints"].append(ep)

    # ── map JS relationships (imports/requires) ────────────────────────────
    # understanding how JS files relate to each other is key to finding
    # auth bypasses and IDOR — the logic often spans multiple files
    for pat in [
        r'(?:import|require)\s*[\(\s]*["\']([^"\']+\.js)["\']',
        r'src\s*[:=]\s*["\']([^"\']+\.js)["\']',
        r'loadScript\s*\(\s*["\']([^"\']+)["\']',
    ]:
        for match in re.finditer(pat, content, re.IGNORECASE):
            rel = match.group(1)
            if rel not in results["js_relations"]:
                results["js_relations"].append(rel)

    return results


# ═════════════════════════════════════════════════════════════════════════════
#  PRINT ANALYSIS RESULTS
# ═════════════════════════════════════════════════════════════════════════════

def print_analysis(results, show_endpoints=True):
    """
    Pretty-print the findings for one JS file.
    Sorted by severity so critical issues are always at the top.
    """
    url      = results["url"]
    findings = sorted(results["findings"], key=lambda x: SEVERITY_ORDER.get(x["severity"], 99))
    score    = results["score"]

    # color the score based on how bad it is
    score_color = (FG_CRITICAL if score >= 200 else
                   FG_HIGH     if score >= 80  else
                   FG_MEDIUM   if score >= 20  else FG_LOW)

    count_color = (FG_CRITICAL if len(findings) >= 10 else
                   FG_HIGH     if len(findings) >= 5  else
                   FG_MEDIUM   if len(findings) >= 1  else FG_SUCCESS)

    # file header
    print(f"\n{FG_DIM}{'─'*70}{RESET}")
    print(f"  {FG_URL}⟫ {url}{RESET}")
    print(f"  {FG_DIM}Size:{RESET} {results['size']:,} bytes  "
          f"{FG_DIM}|  Findings:{RESET} {count_color}{len(findings)}{RESET}  "
          f"{FG_DIM}|  Risk Score:{RESET} {score_color}{score}{RESET}")
    print(f"{FG_DIM}{'─'*70}{RESET}")

    if not findings and not results["endpoints"]:
        print(f"  {FG_SUCCESS}✓ Nothing interesting found in this file.{RESET}")
        return

    # group findings by category for cleaner output
    by_cat = defaultdict(list)
    for f in findings:
        by_cat[f["category"]].append(f)

    for cat, cat_findings in by_cat.items():
        cat_color = CATEGORY_COLORS.get(cat, FG_LABEL)
        plural    = "s" if len(cat_findings) > 1 else ""
        print(f"\n  {cat_color}▸ {cat}  ({len(cat_findings)} finding{plural}){RESET}")

        for f in cat_findings:
            sev     = f["severity"]
            badge   = SEVERITY_BADGE.get(sev, "")
            fg      = SEVERITY_FG.get(sev, "")
            icon    = SEVERITY_ICONS.get(sev, "")
            sev_tag = f" {sev.upper():<8} "

            # main finding line: [SEVERITY]  icon  Line 42  matched_text
            print(f"    {badge}{sev_tag}{RESET}  {icon}  "
                  f"{FG_DIM}Line {f['line']:4d}{RESET}  "
                  f"{fg}{f['match'][:80]}{RESET}")

            # show the surrounding line for context (only if it adds info)
            if f["context"] and f["context"].strip() != f["match"].strip():
                print(f"    {FG_DIM}             → {f['context'][:100]}{RESET}")

    # endpoints section
    if show_endpoints and results["endpoints"]:
        print(f"\n  {FG_SECTION}▸ Endpoints / URLs  ({len(results['endpoints'])}){RESET}")
        for ep in results["endpoints"][:40]:
            print(f"    {FG_URL}  ↳ {ep[:120]}{RESET}")
        if len(results["endpoints"]) > 40:
            info(f"  ... and {len(results['endpoints']) - 40} more endpoints saved to output file")

    # JS relationships
    if results["js_relations"]:
        print(f"\n  {FG_RELATION}▸ JS Relationships / Imports  ({len(results['js_relations'])}){RESET}")
        for rel in results["js_relations"]:
            print(f"    {FG_RELATION}  ↳ {rel}{RESET}")


# ═════════════════════════════════════════════════════════════════════════════
#  SUBDOMAIN RECON
#  Passive only — no brute force. Uses three free public APIs:
#    crt.sh       — certificate transparency logs, great coverage
#    HackerTarget — passive DNS, fast
#    AlienVault   — threat intel, catches stuff the others miss
# ═════════════════════════════════════════════════════════════════════════════

def run_subdomain_recon(domain):
    """
    Query passive subdomain sources and return a set of discovered subdomains.
    Passive = no DNS brute force, no noise, safe to run on any target.
    """
    section_header(f"SUBDOMAIN RECON: {domain}", FG_SECTION)
    subdomains = set()
    session    = build_session()

    sources = [
        ("crt.sh",
         f"https://crt.sh/?q=%.{domain}&output=json"),
        ("HackerTarget",
         f"https://api.hackertarget.com/hostsearch/?q={domain}"),
        ("AlienVault OTX",
         f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"),
    ]

    for name, url in sources:
        info(f"Querying {name}...")
        try:
            resp = session.get(url, timeout=20)
            if resp.status_code != 200:
                warn(f"{name} returned HTTP {resp.status_code}, skipping")
                continue

            if name == "crt.sh":
                # crt.sh returns JSON — parse each certificate entry
                for entry in resp.json():
                    for sub in entry.get("name_value", "").split("\n"):
                        sub = sub.strip().lstrip("*.")
                        if sub.endswith(domain) and sub != domain:
                            subdomains.add(sub)

            elif name == "HackerTarget":
                # HackerTarget returns plain text: "subdomain,ip"
                if "error" not in resp.text.lower():
                    for line in resp.text.strip().split("\n"):
                        if "," in line:
                            sub = line.split(",")[0].strip()
                            if sub.endswith(domain):
                                subdomains.add(sub)

            elif name == "AlienVault OTX":
                # OTX returns JSON with a passive_dns array
                for entry in resp.json().get("passive_dns", []):
                    hn = entry.get("hostname", "")
                    if hn.endswith(domain):
                        subdomains.add(hn)

            success(f"{name}: running total = {len(subdomains)} subdomains")

        except Exception as e:
            warn(f"{name} failed: {e}")

    if subdomains:
        print(f"\n{FG_SUCCESS}  Found {len(subdomains)} unique subdomains:{RESET}")
        for sub in sorted(subdomains):
            print(f"    {FG_SUB}  ⟫ https://{sub}{RESET}")
    else:
        warn("No subdomains found via passive recon.")

    return subdomains


# ═════════════════════════════════════════════════════════════════════════════
#  SENSITIVE FILE PROBE
# ═════════════════════════════════════════════════════════════════════════════

def probe_sensitive_files(base_url, session, threads=5, waf_aware=False):
    """
    Check a list of common sensitive paths against the target.
    Runs in parallel with a thread pool for speed.
    Only reports 200/301/302/403 — 404s are filtered out.
    """
    section_header(f"SENSITIVE FILE PROBE: {base_url}", FG_PROBE)
    found = []

    def check_path(path):
        """check a single path — designed to run in a thread"""
        url = base_url.rstrip("/") + path
        if waf_aware:
            random_delay(waf_mode=True)
        resp = fetch_url(url, session, timeout=8, waf_aware=waf_aware)
        if resp and resp.status_code in [200, 301, 302, 403]:
            return (url, resp.status_code, len(resp.content))
        return None

    # run all checks in parallel
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check_path, path): path for path in COMMON_SENSITIVE_PATHS}
        for future in as_completed(futures):
            result = future.result()
            if result:
                url, status, size = result
                color = STATUS_COLOR.get(status, FG_DIM)
                # 200 = fire emoji because that's a real find
                icon  = "🔥" if status == 200 else "↩" if status in [301, 302] else "🔒"
                sev   = "high" if status == 200 else "medium"
                badge = SEVERITY_BADGE.get(sev, "")
                print(f"  {badge} {status} {RESET}  {icon}  {color}{url}{RESET}  {FG_DIM}({size} bytes){RESET}")
                found.append({"url": url, "status": status, "size": size, "severity": sev})

    if not found:
        success("No sensitive files found (all paths returned 404 or were filtered).")

    return found


# ═════════════════════════════════════════════════════════════════════════════
#  MAIN SCAN ENGINE
#  Orchestrates the full scan pipeline for a single target.
#  Everything hangs off this function.
# ═════════════════════════════════════════════════════════════════════════════

def scan_target(url, args, session):
    """
    Full scan pipeline for one target URL.
    Steps: normalize → discover JS → (deep crawl) → (analyze) → (probe) → (subdomains)
    Returns a dict with all results for this target.
    """
    url    = normalize_url(url)
    domain = get_domain(url)

    section_header(f"TARGET: {url}", LEMON)
    print(f"  {FG_DIM}Domain  :{RESET} {FG_URL}{domain}{RESET}")
    print(f"  {FG_DIM}Time    :{RESET} {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  {FG_DIM}Platform:{RESET} {get_platform_info()}")
    print(f"  {FG_DIM}Protocol:{RESET} {FG_SUCCESS}HTTP + HTTPS auto-detect{RESET}\n")

    # container for everything we find
    all_results = {
        "target":         url,
        "domain":         domain,
        "js_files":       [],
        "other_files":    [],
        "analysis":       [],
        "subdomains":     [],
        "sensitive_files":[],
        "summary":        {},
    }

    # ── STEP 1: discover all JS files on the target ────────────────────────
    info(f"Crawling {url} for JavaScript and interesting files...")
    js_files, other_files, base_resp = extract_js_from_page(
        url, session, waf_aware=args.waf_aware
    )

    all_results["js_files"]    = list(js_files)
    all_results["other_files"] = list(other_files)

    success(f"Found {len(js_files)} JS file(s)  |  {len(other_files)} other interesting file(s)")

    if js_files:
        print(f"\n  {FG_SECTION}JavaScript Files:{RESET}")
        for jf in sorted(js_files):
            print(f"    {FG_URL}  ↳ {jf}{RESET}")

    if other_files and not args.js_only:
        print(f"\n  {FG_MEDIUM}Other Interesting Files:{RESET}")
        for f in sorted(other_files):
            print(f"    {FG_MEDIUM}  ↳ {f}{RESET}")

    # ── STEP 2: deep crawl — follow import chains inside discovered JS ─────
    if args.deep:
        info("Deep mode: following JS import chains recursively...")
        extra_js = set()
        # limit to first 10 files to avoid runaway crawls
        for jf in list(js_files)[:10]:
            sub_js, _, _ = extract_js_from_page(jf, session, waf_aware=args.waf_aware)
            extra_js |= sub_js
        new_js = extra_js - js_files
        if new_js:
            success(f"Deep crawl found {len(new_js)} additional JS file(s)")
            js_files |= new_js
            all_results["js_files"] = list(js_files)

    # ── STEP 3: analyze JS file contents ──────────────────────────────────
    if args.analyze and js_files:
        section_header(f"ANALYZING {len(js_files)} JAVASCRIPT FILE(S)", FG_SECTION)

        def analyze_one(js_url):
            """fetch + analyze a single JS file — runs in thread pool"""
            if args.waf_aware:
                random_delay(waf_mode=True)

            # HTTP/HTTPS fallback on individual JS files too
            js_url, resp = try_http_fallback(js_url, session)
            if not resp or not resp.text:
                return None

            content = resp.text

            # optionally dump raw JS to disk
            if args.dump:
                safe_name = re.sub(r'[^\w\-_.]', '_', js_url)[:80]
                dump_dir  = args.dump_dir or "jsreaper_dumps"
                dump_path = os.path.join(dump_dir, safe_name + ".js")
                os.makedirs(dump_dir, exist_ok=True)
                with open(dump_path, "w", encoding="utf-8", errors="ignore") as df:
                    df.write(f"// Source: {js_url}\n")
                    df.write(f"// Fetched: {datetime.datetime.now()}\n\n")
                    df.write(content)

            return analyze_js_content(js_url, content, beautify=args.beautify)

        # run analysis in parallel
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = {executor.submit(analyze_one, jf): jf for jf in list(js_files)}
            for future in as_completed(futures):
                res = future.result()
                if res:
                    all_results["analysis"].append(res)
                    # only print if there's something to show
                    if res["findings"] or (args.verbose and res["endpoints"]):
                        print_analysis(res, show_endpoints=args.endpoints)

    # ── STEP 4: probe for exposed sensitive files ─────────────────────────
    if args.probe:
        found_files = probe_sensitive_files(
            url, session, threads=args.threads, waf_aware=args.waf_aware
        )
        all_results["sensitive_files"] = found_files

    # ── STEP 5: passive subdomain recon ───────────────────────────────────
    if args.subdomains:
        subs = run_subdomain_recon(domain)
        all_results["subdomains"] = list(subs)

        # optionally scan discovered subdomains for JS too
        if args.scan_subs and subs:
            info(f"Scanning discovered subdomains for JS (first {min(len(subs),10)})...")
            for sub in list(subs)[:10]:
                sub_url = f"https://{sub}"
                sub_js, _, _ = extract_js_from_page(sub_url, session, waf_aware=args.waf_aware)
                if sub_js:
                    success(f"  {sub}: found {len(sub_js)} JS file(s)")
                    all_results["js_files"].extend(list(sub_js))

    # ── build summary numbers ─────────────────────────────────────────────
    total_findings = sum(len(r["findings"]) for r in all_results["analysis"])
    critical = sum(1 for r in all_results["analysis"]
                   for f in r["findings"] if f["severity"] == "critical")
    high     = sum(1 for r in all_results["analysis"]
                   for f in r["findings"] if f["severity"] == "high")
    medium   = sum(1 for r in all_results["analysis"]
                   for f in r["findings"] if f["severity"] == "medium")
    total_score = sum(r["score"] for r in all_results["analysis"])

    all_results["summary"] = {
        "js_files_found":        len(js_files),
        "other_files_found":     len(other_files),
        "total_findings":        total_findings,
        "critical":              critical,
        "high":                  high,
        "medium":                medium,
        "risk_score":            total_score,
        "subdomains_found":      len(all_results["subdomains"]),
        "sensitive_files_found": len(all_results["sensitive_files"]),
    }

    print_summary(all_results["summary"], url)
    return all_results


# ═════════════════════════════════════════════════════════════════════════════
#  SUMMARY
# ═════════════════════════════════════════════════════════════════════════════

def print_summary(s, target):
    """print the per-target summary with a risk rating banner"""
    section_header(f"SCAN SUMMARY: {target}", LEMON)

    # color the score based on severity
    score_color = (FG_CRITICAL if s["risk_score"] >= 200 else
                   FG_HIGH     if s["risk_score"] >= 80  else
                   FG_MEDIUM   if s["risk_score"] >= 20  else FG_SUCCESS)

    rows = [
        ("JS Files Found",       f"{FG_URL}{s['js_files_found']}{RESET}"),
        ("Other Files Found",    f"{FG_MEDIUM}{s['other_files_found']}{RESET}"),
        ("Total Findings",       f"{FG_HIGH}{s['total_findings']}{RESET}"),
        ("Critical",             f"{SEVERITY_BADGE['critical']} {s['critical']} {RESET}"),
        ("High",                 f"{SEVERITY_BADGE['high']} {s['high']} {RESET}"),
        ("Medium",               f"{SEVERITY_BADGE['medium']} {s['medium']} {RESET}"),
        ("Subdomains Found",     f"{FG_SUB}{s['subdomains_found']}{RESET}"),
        ("Sensitive Files Hit",  f"{FG_PROBE}{s['sensitive_files_found']}{RESET}"),
        ("Total Risk Score",     f"{score_color}{s['risk_score']}{RESET}"),
    ]

    for label, value in rows:
        print(f"  {FG_DIM}{label:<24}{RESET}  {value}")

    # give a clear overall verdict
    score = s["risk_score"]
    if score >= 300:
        verdict = f"{SEVERITY_BADGE['critical']} 🔥 CRITICAL RISK — Immediate action required {RESET}"
    elif score >= 100:
        verdict = f"{SEVERITY_BADGE['high']} ⚠  HIGH RISK — Review findings carefully {RESET}"
    elif score >= 30:
        verdict = f"{SEVERITY_BADGE['medium']} ⚡ MEDIUM RISK — Some issues found {RESET}"
    elif score > 0:
        verdict = f"{SEVERITY_BADGE['low']} ℹ  LOW RISK — Minor findings only {RESET}"
    else:
        verdict = f"{FG_SUCCESS}  ✓ CLEAN — No significant findings {RESET}"

    print(f"\n  Overall: {verdict}\n")


# ═════════════════════════════════════════════════════════════════════════════
#  OUTPUT / SAVE
# ═════════════════════════════════════════════════════════════════════════════

def save_output(all_scan_results, output_file, fmt="txt"):
    """
    Save results to disk as either plain text or JSON.
    JSON is better for piping into other tools.
    Text is better for quick human review.
    """
    output_file = os.path.normpath(output_file)

    try:
        if fmt == "json":
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(all_scan_results, f, indent=2, default=str)
        else:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write("JSReaper v1.1 - Scan Report\n")
                f.write(f"Written by @dr34lm\n")
                f.write(f"Platform : {get_platform_info()}\n")
                f.write(f"Generated: {datetime.datetime.now()}\n")
                f.write("=" * 70 + "\n\n")

                for scan in all_scan_results:
                    f.write(f"TARGET: {scan['target']}\n")
                    f.write(f"DOMAIN: {scan['domain']}\n\n")

                    f.write(f"JS FILES ({len(scan['js_files'])}):\n")
                    for jf in scan["js_files"]:
                        f.write(f"  {jf}\n")

                    f.write(f"\nSUBDOMAINS ({len(scan['subdomains'])}):\n")
                    for sub in scan["subdomains"]:
                        f.write(f"  https://{sub}\n")

                    f.write(f"\nSENSITIVE FILES:\n")
                    for sf in scan["sensitive_files"]:
                        f.write(f"  [{sf['status']}] {sf['url']}\n")

                    f.write(f"\nANALYSIS FINDINGS:\n")
                    for res in scan["analysis"]:
                        f.write(f"\n  File: {res['url']}\n")
                        f.write(f"  Risk Score: {res['score']}\n")
                        for fnd in res["findings"]:
                            f.write(
                                f"  [{fnd['severity'].upper():<8}] "
                                f"{fnd['category']} | "
                                f"Line {fnd['line']} | "
                                f"{fnd['match'][:100]}\n"
                            )

                    f.write("\n" + "=" * 70 + "\n\n")

        success(f"Results saved → {output_file}")

    except Exception as e:
        error(f"Could not save output: {e}")


# ═════════════════════════════════════════════════════════════════════════════
#  ARGUMENT PARSER  (the -h output people see)
# ═════════════════════════════════════════════════════════════════════════════

def build_parser():
    parser = argparse.ArgumentParser(
        prog="jsreaper",
        description=(
            "JSReaper v1.1 — JavaScript Recon & Analysis Tool\n"
            "Written by @dr34lm  |  https://x.com/dr34lm\n"
            "For authorized bug bounty and penetration testing use only.\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 WALKTHROUGH — STEP BY STEP EXAMPLES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

 STEP 1 — Just see what JS files are on a target (no analysis):
   jsreaper -u example.com
   jsreaper -u https://example.com
   jsreaper -u http://example.com
   → All three formats work. HTTP/HTTPS is auto-detected.

 STEP 2 — Analyze all JS files for secrets and vulnerabilities:
   jsreaper -u example.com --analyze
   → Reads every JS file and runs 70+ detection patterns.
   → Findings are color-coded: 💀 CRITICAL  🔴 HIGH  🟡 MEDIUM  🔵 LOW

 STEP 3 — Also show the API endpoints hidden in the JS:
   jsreaper -u example.com --analyze --endpoints
   → Extracts every /api/v1/... path and full URL found in JS code.

 STEP 4 — De-minify compressed JS before analyzing (better results):
   jsreaper -u example.com --analyze --beautify
   → Use this on SPAs (React, Vue, Angular) — their bundles are minified.

 STEP 5 — Follow JS import chains to find hidden files:
   jsreaper -u example.com --analyze --deep
   → Recursively follows require() and import statements.

 STEP 6 — Probe for exposed sensitive files (.env, .git, backups etc.):
   jsreaper -u example.com --probe
   → Checks 50+ paths. A single exposed .env = critical report.

 STEP 7 — Run passive subdomain recon:
   jsreaper -u example.com --subdomains
   → Queries crt.sh, HackerTarget, AlienVault OTX.

 STEP 8 — Find subdomains AND scan each one for JS:
   jsreaper -u example.com --subdomains --scan-subs --analyze
   → Full scope expansion in one command.

 STEP 9 — Save all results to a file:
   jsreaper -u example.com --analyze -o results.txt
   jsreaper -u example.com --analyze -o results.json --format json
   → JSON is better for piping into other tools.

 STEP 10 — Download every JS file to disk for manual review:
   jsreaper -u example.com --analyze --dump --dump-dir ./js_files
   → Opens in any editor. Search for: token, key, secret, password.

 STEP 11 — Target behind a WAF (Cloudflare, Akamai etc.):
   jsreaper -u example.com --analyze --waf-aware -t 1
   → Slow mode: random delays, rotating User-Agents, smart retries.

 STEP 12 — Scan multiple targets from a file:
   jsreaper -l scope.txt -t 5 --analyze --probe -o report.json --format json
   → One URL per line in scope.txt. Lines starting with # are skipped.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 POWER COMBOS (most useful in real hunts)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

 Full recon suite — everything at once:
   jsreaper -u example.com --analyze --deep --probe --subdomains --endpoints

 Full stealth scan — slow and quiet against aggressive WAFs:
   jsreaper -u example.com --analyze --waf-aware -t 1 --timeout 30

 Full output — analyze + dump JS + save JSON report:
   jsreaper -u example.com --analyze --beautify --dump --dump-dir ./js -o report.json --format json

 Bulk scope scan — common for HackerOne / Bugcrowd programs:
   jsreaper -l scope.txt -t 5 --analyze --probe --waf-aware -o final.json --format json

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 THREAD LEVELS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   -t 1    Stealth / very slow — best for WAF-protected targets
   -t 3    Default — balanced speed and noise
   -t 5    Faster — fine for most targets
   -t 8    Aggressive — use with caution
   -t 10   Very aggressive — likely to trigger rate limits

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 NOTE: Always use on targets you are authorized to test.
       Written by @dr34lm — https://x.com/dr34lm
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
    )

    # ── target ──────────────────────────────────────────────────────────────
    tg = parser.add_argument_group("Target")
    tg.add_argument("-u", "--url",
                    help="Single target URL. Works with or without http/https prefix.\n"
                         "Examples: example.com  |  https://example.com  |  http://example.com")
    tg.add_argument("-l", "--list",
                    help="File containing one target URL per line.\n"
                         "Lines starting with # are treated as comments and skipped.")

    # ── scan options ─────────────────────────────────────────────────────────
    sg = parser.add_argument_group("Scan Options")
    sg.add_argument("--analyze",
                    action="store_true",
                    help="[CORE] Read and analyze every JS file for secrets, vulns, and endpoints.\n"
                         "Always use this flag — without it the tool only lists files, doesn't inspect them.")
    sg.add_argument("--deep",
                    action="store_true",
                    help="Follow import/require chains inside JS files to find additional JS.\n"
                         "Good for React/Vue/Angular apps that split code into many bundles.")
    sg.add_argument("--probe",
                    action="store_true",
                    help="Probe 50+ common paths for exposed sensitive files.\n"
                         "Checks: .env, .git/config, swagger.json, package.json, backups, and more.")
    sg.add_argument("--subdomains",
                    action="store_true",
                    help="Run passive subdomain recon using crt.sh, HackerTarget, and AlienVault OTX.\n"
                         "No brute force — passive only.")
    sg.add_argument("--scan-subs",
                    action="store_true",
                    help="After finding subdomains, scan each one for JS files too.\n"
                         "Requires --subdomains.")
    sg.add_argument("--endpoints",
                    action="store_true",
                    help="Print all API paths and URLs extracted from JS file contents.\n"
                         "Great for building a wordlist for ffuf or nuclei.")
    sg.add_argument("--js-only",
                    action="store_true",
                    help="Only collect .js files. Skip all other file types.")
    sg.add_argument("--beautify",
                    action="store_true",
                    help="De-minify JS before analyzing. Much better results on minified/bundled code.\n"
                         "Requires jsbeautifier: pip3 install jsbeautifier")
    sg.add_argument("--verbose",
                    action="store_true",
                    help="Show output for all files, including ones with no findings.")

    # ── performance ──────────────────────────────────────────────────────────
    pg = parser.add_argument_group("Performance & Evasion")
    pg.add_argument("-t", "--threads",
                    type=int, default=3,
                    choices=[1, 2, 3, 4, 5, 6, 8, 10],
                    metavar="{1,2,3,4,5,6,8,10}",
                    help="Number of threads (default: 3).\n"
                         "1=stealth, 3=default, 5=fast, 10=aggressive.")
    pg.add_argument("--waf-aware",
                    action="store_true",
                    help="Enable WAF evasion mode.\n"
                         "Adds random delays between requests, rotates User-Agents, retries on block.")
    pg.add_argument("--timeout",
                    type=int, default=15,
                    help="Request timeout in seconds (default: 15).\n"
                         "Increase to 30+ for slow targets.")

    # ── output ───────────────────────────────────────────────────────────────
    og = parser.add_argument_group("Output")
    og.add_argument("-o", "--output",
                    help="Save results to file.\n"
                         "Example: -o results.txt  or  -o results.json")
    og.add_argument("--format",
                    choices=["txt", "json"], default="txt",
                    help="Output format: txt (default) or json.\n"
                         "Use json if you want to pipe results into other tools.")
    og.add_argument("--dump",
                    action="store_true",
                    help="Download and save the raw content of every JS file to disk.\n"
                         "Good for manual review in your editor.")
    og.add_argument("--dump-dir",
                    default="jsreaper_dumps",
                    help="Directory to save dumped JS files (default: jsreaper_dumps/).")

    return parser


# ═════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════

def main():
    # silence the SSL warnings — we're doing security research, self-signed
    # certs are expected and we don't need a warning on every request
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    print(BANNER)

    parser = build_parser()
    args   = parser.parse_args()

    # make sure the user gave us at least one target
    if not args.url and not args.list:
        parser.print_help()
        print(f"\n{FG_CRITICAL}[!] You need to specify a target: -u URL  or  -l targets_file{RESET}")
        sys.exit(1)

    # collect all targets into one list
    targets = []
    if args.url:
        targets.append(args.url)

    if args.list:
        list_path = os.path.normpath(args.list)
        try:
            with open(list_path, "r", encoding="utf-8") as f:
                # skip blank lines and comments
                lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
                targets.extend(lines)
        except FileNotFoundError:
            error(f"Target list file not found: {list_path}")
            sys.exit(1)

    # deduplicate while preserving order (dict trick)
    targets = list(dict.fromkeys(targets))

    # print scan config so the user knows what's about to run
    info(f"Platform  : {get_platform_info()}")
    info(f"Targets   : {len(targets)}")
    info(f"Threads   : {args.threads}  |  WAF-aware: {args.waf_aware}  |  Timeout: {args.timeout}s")
    info(f"Protocol  : HTTP + HTTPS auto-detect enabled")
    if args.analyze:    info("Mode: JS Analysis ON")
    if args.deep:       info("Mode: Deep crawl ON")
    if args.probe:      info("Mode: Sensitive file probe ON")
    if args.subdomains: info("Mode: Subdomain recon ON")
    if args.dump:       info(f"Mode: JS dump ON → {args.dump_dir}{os.sep}")
    print()

    session     = build_session(waf_aware=args.waf_aware)
    all_results = []
    start_time  = time.time()

    for i, target in enumerate(targets, 1):
        if len(targets) > 1:
            print(f"\n{FG_SECTION}[{i}/{len(targets)}] → {target}{RESET}")
        try:
            result = scan_target(target, args, session)
            all_results.append(result)
        except KeyboardInterrupt:
            warn("Ctrl+C detected — saving partial results and exiting...")
            break
        except Exception as e:
            error(f"Scan failed for {target}: {e}")
            if args.verbose:
                import traceback
                traceback.print_exc()

    elapsed = time.time() - start_time
    print(f"\n{FG_SUCCESS}[✓] Done in {elapsed:.1f}s{RESET}")

    # save output if requested
    if args.output and all_results:
        save_output(all_results, args.output, fmt=args.format)

    # aggregate summary when scanning multiple targets
    if len(all_results) > 1:
        section_header(f"AGGREGATE SUMMARY  ({len(all_results)} targets)", LEMON)
        total_js       = sum(r["summary"]["js_files_found"]  for r in all_results)
        total_findings = sum(r["summary"]["total_findings"]  for r in all_results)
        total_critical = sum(r["summary"]["critical"]        for r in all_results)
        total_high     = sum(r["summary"]["high"]            for r in all_results)
        total_score    = sum(r["summary"]["risk_score"]      for r in all_results)
        print(f"  {FG_DIM}JS Files    :{RESET} {FG_URL}{total_js}{RESET}")
        print(f"  {FG_DIM}Findings    :{RESET} {FG_HIGH}{total_findings}{RESET}")
        print(f"  {FG_DIM}Critical    :{RESET} {SEVERITY_BADGE['critical']} {total_critical} {RESET}")
        print(f"  {FG_DIM}High        :{RESET} {SEVERITY_BADGE['high']} {total_high} {RESET}")
        print(f"  {FG_DIM}Total Score :{RESET} {FG_MEDIUM}{total_score}{RESET}")

    # always remind people to stay in scope
    print(f"\n{FG_WAF}  ⚠  Only use JSReaper on targets you are authorized to test.{RESET}")
    print(f"{FG_WAF}  ⚠  Unauthorized use is illegal. Stay in scope.{RESET}")
    print(f"{FG_DIM}  Written by @dr34lm — https://x.com/dr34lm{RESET}\n")


if __name__ == "__main__":
    main()
