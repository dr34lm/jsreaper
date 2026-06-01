#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# ╔══════════════════════════════════════════════════════════════════════╗
# ║                         JSReaper v2.0                               ║
# ║         JavaScript Recon & Analysis Tool for Bug Bounty             ║
# ║                                                                      ║
# ║  Written by @dr34lm                                                  ║
# ║  Twitter/X: https://x.com/dr34lm                                    ║
# ║                                                                      ║
# ║  Built for bug bounty hunters who need deep JS recon fast.          ║
# ║  For educational and research purposes only.                         ║
# ║  Use only on targets you are authorized to test.                     ║
# ╚══════════════════════════════════════════════════════════════════════╝
#
# CHANGELOG:
#   v1.0 - initial release
#   v1.1 - HTTP/HTTPS auto-fallback, lemon banner, rich coloring, cross-platform
#   v2.0 - Burp Suite JS input parsing, version checker, status probe,
#           dynamic terminal layout, cross-file correlation engine,
#           tech fingerprinting + CVE lookup, cleaner findings per domain

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
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse
from collections import defaultdict
import threading

TOOL_VERSION = "2.0"
TOOL_NAME    = "JSReaper"

IS_WINDOWS = platform.system() == "Windows"
IS_MACOS   = platform.system() == "Darwin"
IS_LINUX   = platform.system() == "Linux"

try:
    import requests
    from bs4 import BeautifulSoup
    from colorama import init, Fore, Back, Style
    init(autoreset=True, convert=IS_WINDOWS, strip=False)
except ImportError as e:
    print(f"[!] Missing dependency: {e}")
    print("[*] pip3 install requests beautifulsoup4 colorama jsbeautifier tqdm urllib3")
    sys.exit(1)

try:
    import jsbeautifier
    JS_BEAUTIFIER = True
except ImportError:
    JS_BEAUTIFIER = False

# ═════════════════════════════════════════════════════════════════════════════
#  COLOR SYSTEM
# ═════════════════════════════════════════════════════════════════════════════

LEMON = "\033[38;5;154m"
LIME  = "\033[38;5;118m"
MINT  = "\033[38;5;121m"
GOLD  = "\033[38;5;220m"
GRAY  = "\033[38;5;245m"
RESET = Style.RESET_ALL

C_CRITICAL = "\033[48;5;196m\033[38;5;231m"
C_HIGH     = "\033[48;5;202m\033[38;5;231m"
C_MEDIUM   = "\033[48;5;220m\033[38;5;232m"
C_LOW      = "\033[48;5;33m\033[38;5;231m"
C_INFO     = "\033[48;5;238m\033[38;5;252m"

FG_CRITICAL = "\033[38;5;196m"
FG_HIGH     = "\033[38;5;208m"
FG_MEDIUM   = "\033[38;5;220m"
FG_LOW      = "\033[38;5;75m"
FG_INFO     = "\033[38;5;252m"
FG_SUCCESS  = "\033[38;5;154m"
FG_LABEL    = "\033[38;5;213m"
FG_URL      = "\033[38;5;117m"
FG_RELATION = "\033[38;5;147m"
FG_SECTION  = "\033[38;5;226m"
FG_DIM      = "\033[38;5;242m"
FG_WAF      = "\033[38;5;203m"
FG_PROBE    = "\033[38;5;208m"
FG_SUB      = "\033[38;5;120m"
FG_TECH     = "\033[38;5;159m"
FG_CORR     = "\033[38;5;219m"

# HTTP status code colors
STATUS_COLORS = {
    200: "\033[38;5;154m",   # green  — alive
    201: "\033[38;5;154m",
    204: "\033[38;5;154m",
    301: "\033[38;5;220m",   # gold   — redirect
    302: "\033[38;5;220m",
    304: "\033[38;5;245m",   # gray   — not modified
    400: "\033[38;5;208m",   # orange — bad request
    401: "\033[38;5;208m",   # orange — unauthorized
    403: "\033[38;5;208m",   # orange — forbidden (exists!)
    404: "\033[38;5;242m",   # dim    — not found
    429: "\033[38;5;203m",   # red    — rate limited (WAF?)
    500: "\033[38;5;196m",   # red    — server error
    502: "\033[38;5;196m",
    503: "\033[38;5;203m",
}

STATUS_ICONS = {
    200: "●", 201: "●", 204: "●",
    301: "→", 302: "→", 304: "○",
    400: "✗", 401: "🔒", 403: "🔒",
    404: "✗",
    429: "⚡", 500: "💥", 502: "💥", 503: "⚡",
}

SEVERITY_FG    = {"critical": FG_CRITICAL, "high": FG_HIGH,
                  "medium":   FG_MEDIUM,   "low":  FG_LOW, "info": FG_INFO}
SEVERITY_BADGE = {"critical": C_CRITICAL,  "high": C_HIGH,
                  "medium":   C_MEDIUM,    "low":  C_LOW,  "info": C_INFO}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_ICONS = {"critical": "💀", "high": "🔴", "medium": "🟡", "low": "🔵", "info": "⚪"}

if IS_WINDOWS and "WT_SESSION" not in os.environ:
    SEVERITY_ICONS = {"critical":"[!!!]","high":"[!! ]","medium":"[!  ]","low":"[-  ]","info":"[.  ]"}
    STATUS_ICONS   = defaultdict(lambda: "[?]", {200:"[OK]",301:"[->]",302:"[->]",403:"[FX]",404:"[  ]",500:"[ER]"})

CATEGORY_COLORS = {
    "API Keys & Tokens":           "\033[38;5;213m",
    "AWS Credentials":             "\033[38;5;196m",
    "Authentication & Passwords":  "\033[38;5;203m",
    "OAuth & SSO":                 "\033[38;5;219m",
    "Database Credentials":        "\033[38;5;208m",
    "Cloud & Infrastructure":      "\033[38;5;117m",
    "Sensitive Endpoints & Paths": "\033[38;5;226m",
    "OWASP / Security Issues":     "\033[38;5;203m",
    "High-Impact Indicators":      "\033[38;5;196m",
    "Internal Infrastructure":     "\033[38;5;147m",
    "Hardcoded Usernames":         "\033[38;5;220m",
    "Crypto & Hashing":            "\033[38;5;75m",
    "URLs & Subdomains":           "\033[38;5;120m",
    "Version Control & Debug":     "\033[38;5;245m",
}

# ═════════════════════════════════════════════════════════════════════════════
#  DYNAMIC TERMINAL WIDTH
#  Layout adapts to however wide or narrow the user's terminal is.
#  Min 60, max 120 — anything outside that range looks bad.
# ═════════════════════════════════════════════════════════════════════════════

def term_width():
    """get current terminal width, clamped to sane bounds"""
    try:
        w = shutil.get_terminal_size(fallback=(100, 40)).columns
        return max(60, min(w, 120))
    except Exception:
        return 100

def divider(char="─", color=FG_DIM):
    return f"{color}{char * term_width()}{RESET}"

def section_header(title, color=FG_SECTION):
    w   = term_width()
    pad = max(0, (w - len(title) - 4) // 2)
    with print_lock:
        print(f"\n{color}{'═' * w}")
        print(f"{'═' * pad}  {title}  {'═' * max(0, w - pad - len(title) - 4)}")
        print(f"{'═' * w}{RESET}")

def box_line(text, color=FG_DIM):
    """truncate a line to terminal width so it never wraps"""
    w = term_width() - 4
    if len(text) > w:
        text = text[:w-3] + "..."
    return f"{color}{text}{RESET}"

# ═════════════════════════════════════════════════════════════════════════════
#  BANNER  v2.0
# ═════════════════════════════════════════════════════════════════════════════

def get_banner():
    return f"""
{LEMON} ░░░░░░░░░ ░░░░░░░░░░░░░░░ ░░░░░░░░░  ░░░░░  ░░░░░░░░  ░░░░░░░░░ ░░░░░░░░░
{LEMON} ░░       ░░       ░░    ░░ ░░       ░░   ░░ ░░       ░░        ░░       ░░
{LIME} ░░░░░░░  ░░░░░░░░ ░░░░░░╝  ░░░░░░   ░░░░░░░ ░░░░░░░  ░░░░░░░░  ░░░░░░░░╝
{LIME}      ░░  ╚════░░  ░░   ░░  ░░       ░░   ░░ ░░       ░░        ░░   ░░
{MINT} ░░░░░░░  ░░░░░░░░ ░░    ░░ ░░░░░░░░ ░░   ░░ ░░       ░░░░░░░░░ ░░    ░░
{MINT}  ╚═════╝  ╚══════╝ ╚═╝   ╚═╝╚══════╝  ╚═╝  ╚═╝╚═╝      ╚══════╝  ╚═╝   ╚═╝
{GOLD}
{GOLD}          ⚡  JavaScript Recon & Analysis Tool  v{TOOL_VERSION}
{GRAY}          🌐  Linux | macOS | Windows  —  Python 3.7+
{GRAY}          ✍   Written by @dr34lm  |  Research & Educational Use Only
{RESET}"""

# ═════════════════════════════════════════════════════════════════════════════
#  VERSION CHECKER
# ═════════════════════════════════════════════════════════════════════════════

LATEST_VERSION_URL = "https://raw.githubusercontent.com/dr34lm/jsreaper/main/VERSION"

def check_version():
    """
    Compare local version against GitHub. Tells the user if they're
    running the latest version or if an update is available.
    """
    print(f"\n{FG_SECTION}[~] Checking version...{RESET}")
    print(f"    {FG_DIM}Tool   :{RESET} {FG_SUCCESS}{TOOL_NAME}{RESET}")
    print(f"    {FG_DIM}Version:{RESET} {FG_SUCCESS}v{TOOL_VERSION}{RESET}")
    print(f"    {FG_DIM}Author :{RESET} {FG_URL}@dr34lm  —  https://x.com/dr34lm{RESET}")
    print(f"    {FG_DIM}Purpose:{RESET} Bug bounty recon — research & educational use")
    print(f"    {FG_DIM}OS     :{RESET} {platform.system()} {platform.release()}")
    print(f"    {FG_DIM}Python :{RESET} {platform.python_version()}")

    try:
        resp = requests.get(LATEST_VERSION_URL, timeout=5)
        if resp.status_code == 200:
            latest = resp.text.strip()
            if latest == TOOL_VERSION:
                print(f"    {FG_DIM}Status :{RESET} {FG_SUCCESS}✓ Up to date (v{TOOL_VERSION} is latest){RESET}")
            else:
                print(f"    {FG_DIM}Status :{RESET} {FG_MEDIUM}⚠ Update available: v{latest}  (you have v{TOOL_VERSION}){RESET}")
                print(f"    {FG_DIM}Update :{RESET} {FG_URL}git -C $(which jsreaper | xargs dirname) pull{RESET}")
        else:
            print(f"    {FG_DIM}Status :{RESET} {FG_DIM}Could not check — running v{TOOL_VERSION}{RESET}")
    except Exception:
        print(f"    {FG_DIM}Status :{RESET} {FG_DIM}Offline — running v{TOOL_VERSION}{RESET}")
    print()

# ═════════════════════════════════════════════════════════════════════════════
#  BURP SUITE JS INPUT PARSER
#  Handles all the messy ways Burp Suite exports JS file lists:
#    - one URL per line
#    - all on one line (no separator)
#    - comma separated
#    - space separated
#    - mixed
# ═════════════════════════════════════════════════════════════════════════════

def parse_burp_js_input(raw_text):
    """
    Parse JS URLs from Burp Suite copy-paste in any format.
    Burp sometimes gives you one per line, sometimes all on one line,
    sometimes comma-separated. This handles all of it.

    Returns a clean deduplicated list of URLs.
    """
    # step 1: split on common delimiters — newline, comma, space, pipe
    # but we need to be careful not to break URLs themselves
    raw = raw_text.strip()

    # if it looks like everything is on one line with no separator,
    # split on 'https://' boundaries (keeping the prefix)
    if "\n" not in raw and "," not in raw:
        # split on https:// or http:// boundaries
        parts = re.split(r'(?=https?://)', raw)
    else:
        # split on newlines and commas first
        parts = re.split(r'[\n,]+', raw)

    urls = []
    for part in parts:
        part = part.strip().strip(',').strip()
        # extract any URL-like strings from each part
        found = re.findall(r'https?://[^\s,\'"<>\n]+', part)
        urls.extend(found)

    # deduplicate while preserving order
    seen = set()
    clean = []
    for u in urls:
        u = u.strip().rstrip('/')
        if u and u not in seen:
            seen.add(u)
            clean.append(u)

    return clean


def parse_burp_file(filepath):
    """Read a Burp-exported JS file list from disk and parse it."""
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        return parse_burp_js_input(f.read())

# ═════════════════════════════════════════════════════════════════════════════
#  USER AGENTS
# ═════════════════════════════════════════════════════════════════════════════

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
]

# ═════════════════════════════════════════════════════════════════════════════
#  TECHNOLOGY FINGERPRINTS
#  Detect what stack a target is running — then check for known CVEs.
# ═════════════════════════════════════════════════════════════════════════════

TECH_FINGERPRINTS = {
    "React":          [r'react(?:\.min)?\.js', r'__REACT_DEVTOOLS', r'React\.createElement'],
    "Vue.js":         [r'vue(?:\.min)?\.js', r'__vue__', r'Vue\.component'],
    "Angular":        [r'angular(?:\.min)?\.js', r'ng-version', r'@angular/core'],
    "jQuery":         [r'jquery(?:\.min)?\.js', r'jQuery\.fn\.jquery', r'\$\.ajax'],
    "Next.js":        [r'_next/static', r'__NEXT_DATA__', r'next/router'],
    "Nuxt.js":        [r'_nuxt/', r'__NUXT__'],
    "WordPress":      [r'wp-content', r'wp-includes', r'wp-json'],
    "Laravel":        [r'laravel', r'csrf-token', r'X-CSRF-TOKEN'],
    "Django":         [r'csrfmiddlewaretoken', r'django'],
    "Express.js":     [r'express', r'X-Powered-By.*Express'],
    "GraphQL":        [r'graphql', r'__typename', r'apolloClient'],
    "Webpack":        [r'webpackJsonp', r'__webpack_require__', r'webpack/runtime'],
    "AWS SDK":        [r'aws-sdk', r'AWS\.config', r'amazonaws\.com'],
    "Firebase":       [r'firebase', r'firebaseapp\.com', r'initializeApp'],
    "Stripe":         [r'stripe\.js', r'Stripe\(', r'stripe\.com'],
    "Sentry":         [r'sentry\.io', r'Sentry\.init', r'@sentry/'],
    "Axios":          [r'axios(?:\.min)?\.js', r'axios\.get\(', r'axios\.post\('],
    "Socket.io":      [r'socket\.io', r'io\.connect\('],
}

# Known vulnerable version patterns — basic static check
# Maps tech name → regex to extract version string
VERSION_PATTERNS = {
    "jQuery":  r'jquery[/-]v?(\d+\.\d+\.?\d*)',
    "React":   r'react[/-]v?(\d+\.\d+\.?\d*)',
    "Angular": r'angular[/-]v?(\d+\.\d+\.?\d*)',
    "Vue.js":  r'vue[/-]v?(\d+\.\d+\.?\d*)',
}

# Known risky old versions (simplified — for flagging only, not exploitation)
RISKY_VERSIONS = {
    "jQuery":  {"<1.12.0": "XSS via $.html() — CVE-2015-9251",
                "<3.5.0":  "XSS via jQuery.htmlPrefilter — CVE-2020-11022"},
    "Angular": {"<1.6.0":  "sandbox escape / XSS — multiple CVEs"},
}

# ═════════════════════════════════════════════════════════════════════════════
#  SENSITIVE PATTERNS  (expanded with high-impact indicators)
# ═════════════════════════════════════════════════════════════════════════════

SENSITIVE_PATTERNS = {

    "API Keys & Tokens": [
        (r'api[_\-\s]?key[\s]*[=:]\s*["\']?([A-Za-z0-9_\-]{16,})["\']?',      "high"),
        (r'apikey[\s]*[=:]\s*["\']?([A-Za-z0-9_\-]{16,})["\']?',               "high"),
        (r'api[_\-]?token[\s]*[=:]\s*["\']?([A-Za-z0-9_\-]{16,})["\']?',      "high"),
        (r'access[_\-]?token[\s]*[=:]\s*["\']?([A-Za-z0-9_\-\.]{16,})["\']?', "high"),
        (r'auth[_\-]?token[\s]*[=:]\s*["\']?([A-Za-z0-9_\-\.]{16,})["\']?',   "high"),
        (r'bearer\s+([A-Za-z0-9_\-\.]{20,})',                                   "high"),
        (r'x-api-key[\s]*[=:]\s*["\']?([A-Za-z0-9_\-]{16,})["\']?',           "high"),
    ],

    "AWS Credentials": [
        (r'AKIA[0-9A-Z]{16}',                                                    "critical"),
        (r'aws[_\-]?access[_\-]?key[_\-]?id[\s]*[=:]\s*["\']?([A-Z0-9]{20})["\']?',      "critical"),
        (r'aws[_\-]?secret[_\-]?access[_\-]?key[\s]*[=:]\s*["\']?([A-Za-z0-9/+=]{40})["\']?', "critical"),
        (r'aws[_\-]?session[_\-]?token[\s]*[=:]\s*["\']?([A-Za-z0-9/+=]{100,})["\']?',   "critical"),
        (r'amazonaws\.com',                                                      "info"),
        (r's3\.amazonaws\.com/([A-Za-z0-9_\-\.]+)',                             "medium"),
    ],

    "Authentication & Passwords": [
        (r'password[\s]*[=:]\s*["\']([^"\']{4,})["\']',                        "high"),
        (r'passwd[\s]*[=:]\s*["\']([^"\']{4,})["\']',                          "high"),
        (r'secret[\s]*[=:]\s*["\']([^"\']{8,})["\']',                          "high"),
        (r'client[_\-]?secret[\s]*[=:]\s*["\']?([A-Za-z0-9_\-\.]{16,})["\']?',"critical"),
        (r'private[_\-]?key[\s]*[=:]\s*["\']([^"\']{8,})["\']',               "critical"),
        (r'-----BEGIN (RSA |EC )?PRIVATE KEY-----',                             "critical"),
        (r'jwt[_\-]?secret[\s]*[=:]\s*["\']([^"\']{8,})["\']',                "critical"),
    ],

    "OAuth & SSO": [
        (r'client[_\-]?id[\s]*[=:]\s*["\']([A-Za-z0-9_\-\.]{8,})["\']',      "medium"),
        (r'oauth[_\-]?token[\s]*[=:]\s*["\']?([A-Za-z0-9_\-\.]{16,})["\']?',  "high"),
        (r'refresh[_\-]?token[\s]*[=:]\s*["\']([^"\']{16,})["\']',            "high"),
        (r'redirect[_\-]?uri[\s]*[=:]\s*["\']([^"\']+)["\']',                 "medium"),
    ],

    "Database Credentials": [
        (r'db[_\-]?password[\s]*[=:]\s*["\']([^"\']+)["\']',                  "critical"),
        (r'database[_\-]?url[\s]*[=:]\s*["\']([^"\']+)["\']',                 "high"),
        (r'mongodb(\+srv)?://[^\s"\'<]+',                                       "high"),
        (r'mysql://[^\s"\'<]+',                                                 "high"),
        (r'postgresql://[^\s"\'<]+',                                            "high"),
        (r'redis://[^\s"\'<]+',                                                 "medium"),
        (r'connection[_\-]?string[\s]*[=:]\s*["\']([^"\']+)["\']',            "high"),
    ],

    "Cloud & Infrastructure": [
        (r'firebase[A-Za-z]*[\s]*[=:]\s*["\']([^"\']{10,})["\']',             "high"),
        (r'firebaseConfig\s*=\s*\{([^}]+)\}',                                  "high"),
        (r'google[_\-]?api[_\-]?key[\s]*[=:]\s*["\']([A-Za-z0-9_\-]{30,})["\']', "high"),
        (r'AIza[0-9A-Za-z\-_]{35}',                                             "high"),
        (r'azure[_\-]?key[\s]*[=:]\s*["\']([^"\']{10,})["\']',                "high"),
        (r'sk_live_[A-Za-z0-9]{24,}',                                           "critical"),
        (r'pk_live_[A-Za-z0-9]{24,}',                                           "high"),
        (r'SG\.[A-Za-z0-9_\-\.]{40,}',                                          "high"),
        (r'twilio[_\-]?auth[_\-]?token[\s]*[=:]\s*["\']([A-Za-z0-9]{32})["\']', "high"),
        (r'heroku[_\-]?api[_\-]?key[\s]*[=:]\s*["\']([A-Za-z0-9\-]{36})["\']',  "high"),
        (r'digitalocean[_\-]?token[\s]*[=:]\s*["\']([A-Za-z0-9]{64})["\']',   "high"),
    ],

    "Sensitive Endpoints & Paths": [
        (r'["\']/?admin["\'/]',                 "medium"),
        (r'["\']/?api/v[0-9]+[/"\'a-zA-Z]',    "info"),
        (r'["\']/?internal[/"\'a-zA-Z]',        "medium"),
        (r'["\']/?debug[/"\'a-zA-Z]',           "medium"),
        (r'["\']/?swagger[/"\'a-zA-Z]',         "medium"),
        (r'["\']/?graphql[/"\'a-zA-Z]',         "medium"),
        (r'["\']/?\.git[/"\'a-zA-Z]',           "high"),
        (r'["\']/?\.env[/"\'a-zA-Z]',           "high"),
        (r'["\']/?backup[s]?[/"\'a-zA-Z]',      "medium"),
        (r'["\']/?phpmyadmin[/"\'a-zA-Z]',      "high"),
        (r'/etc/passwd',                         "critical"),
        (r'/etc/shadow',                         "critical"),
    ],

    # High-impact vulnerability INDICATORS (static analysis — not active testing)
    # These flag patterns in JS code that suggest a vulnerability MAY exist.
    # They are indicators for manual follow-up, not confirmed exploits.
    "High-Impact Indicators": [
        # SQL injection indicators — unsanitized input in query strings
        (r'["\']SELECT\s+.+FROM\s+["\']?\s*\+',                       "critical"),
        (r'query\s*[=:+]\s*["\'].*WHERE\s+.*["\']?\s*\+\s*(?:req|param|input|user)', "critical"),
        (r'execute\s*\(\s*["\'].*\+',                                   "high"),
        (r'\.query\s*\(\s*`[^`]*\$\{',                                 "high"),   # template literal in SQL
        # RCE indicators — dangerous function calls with user input
        (r'eval\s*\(\s*(?:req|request|param|input|user|data)',         "critical"),
        (r'child_process',                                              "high"),
        (r'exec\s*\(\s*["\'].*\+',                                     "high"),
        (r'spawn\s*\(',                                                 "medium"),
        (r'require\s*\(\s*(?:req|request|param|user)',                 "critical"),  # dynamic require
        # IDOR indicators — direct object references without authorization checks
        (r'[?&]id\s*=\s*(?:req|request|param|user)\.',                "high"),
        (r'getUserById\s*\(',                                           "medium"),
        (r'\.findById\s*\(\s*req\.',                                   "high"),
        (r'params\.id\b',                                              "medium"),
        # SSRF indicators
        (r'fetch\s*\(\s*(?:req|request|param|user|input)',             "high"),
        (r'axios\.(get|post)\s*\(\s*(?:req|request|param)',           "high"),
        (r'url\s*=\s*req\.',                                           "high"),
        # Path traversal
        (r'\.\./',                                                     "medium"),
        (r'readFile\s*\(\s*(?:req|param|user|input)',                  "high"),
        (r'path\.join\s*\(\s*[^)]*(?:req|param|user)',                "high"),
    ],

    "OWASP / Security Issues": [
        (r'eval\s*\(',                                              "high"),
        (r'innerHTML\s*=',                                          "medium"),
        (r'document\.write\s*\(',                                   "medium"),
        (r'\.dangerouslySetInnerHTML',                              "medium"),
        (r'localStorage\.setItem\s*\(',                             "info"),
        (r'sessionStorage\.setItem\s*\(',                           "info"),
        (r'console\.(log|error|warn|info)\s*\(.*?(pass|key|secret|token|auth)', "medium"),
        (r'debugger;',                                              "info"),
        (r'window\.location\s*=\s*[^;]+\+',                        "medium"),
        (r'cors[\s]*[=:]\s*["\']?\*["\']?',                        "medium"),
        (r'Access-Control-Allow-Origin["\s:]*\*',                   "medium"),
        (r'document\.cookie',                                       "medium"),
        (r'\.src\s*=\s*[^;]*\+',                                   "medium"),
    ],

    "Internal Infrastructure": [
        (r'192\.168\.\d+\.\d+',                         "medium"),
        (r'10\.\d+\.\d+\.\d+',                          "medium"),
        (r'172\.(1[6-9]|2[0-9]|3[01])\.\d+\.\d+',     "medium"),
        (r'localhost:\d+',                               "medium"),
        (r'127\.0\.0\.1',                               "medium"),
        (r'staging\.[a-z0-9\-]+\.[a-z]+',              "info"),
        (r'dev\.[a-z0-9\-]+\.[a-z]+',                  "info"),
        (r'test\.[a-z0-9\-]+\.[a-z]+',                 "info"),
        (r'internal\.[a-z0-9\-]+\.[a-z]+',             "medium"),
    ],

    "Hardcoded Usernames": [
        (r'username[\s]*[=:]\s*["\']([^"\']{3,})["\']',           "medium"),
        (r'admin[\s]*[=:]\s*["\']([^"\']{3,})["\']',              "high"),
        (r'root[\s]*[=:]\s*["\']([^"\']{3,})["\']',               "high"),
        (r'email[\s]*[=:]\s*["\']([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})["\']', "medium"),
    ],

    "Crypto & Hashing": [
        (r'md5\s*\(',    "medium"),
        (r'sha1\s*\(',   "low"),
        (r'btoa\s*\(',   "medium"),
        (r'atob\s*\(',   "medium"),
    ],

    "URLs & Subdomains": [
        (r'https?://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(?:/[^\s"\'<>]*)?', "info"),
        (r'["\']([a-zA-Z0-9\-]+\.[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,})["\']',"info"),
    ],

    "Version Control & Debug": [
        (r'sourceMappingURL\s*=\s*(.+\.map)', "medium"),
        (r'TODO[:\s]',    "info"),
        (r'FIXME[:\s]',   "info"),
        (r'HACK[:\s]',    "info"),
        (r'BUG[:\s]',     "info"),
    ],
}

INTERESTING_EXTENSIONS = [
    ".js", ".mjs", ".jsx", ".ts", ".tsx",
    ".json", ".config.js", ".env",
    ".xml", ".yaml", ".yml", ".toml",
    ".php", ".py", ".rb", ".asp", ".aspx",
    ".sql", ".db", ".bak", ".backup", ".old", ".tmp",
    ".log", ".txt", ".map", ".wasm",
]

WAF_SIGNATURES = {
    "Cloudflare":  ["cloudflare", "cf-ray", "__cfduid"],
    "Akamai":      ["akamai", "x-check-cacheable"],
    "AWS WAF":     ["awswaf", "x-amzn-requestid", "x-amz-cf-id"],
    "Sucuri":      ["sucuri", "x-sucuri-id"],
    "Imperva":     ["imperva", "incap_ses", "visid_incap"],
    "F5 BIG-IP":   ["bigip", "x-cnection"],
    "ModSecurity": ["mod_security", "modsecurity"],
}

COMMON_SENSITIVE_PATHS = [
    "/.env", "/.env.local", "/.env.production", "/.env.backup",
    "/.git/config", "/.git/HEAD",
    "/config.js", "/config.json", "/app.config.js",
    "/webpack.config.js", "/package.json", "/package-lock.json",
    "/robots.txt", "/sitemap.xml",
    "/backup.zip", "/backup.sql", "/db.sql", "/database.sql",
    "/wp-config.php", "/phpinfo.php", "/info.php",
    "/admin/", "/administrator/",
    "/swagger.json", "/swagger.yaml", "/openapi.json", "/api-docs",
    "/graphql", "/graphiql",
    "/.htaccess", "/.htpasswd",
    "/api/v1/", "/api/v2/", "/api/v3/",
    "/actuator", "/actuator/health", "/actuator/env",
    "/metrics", "/health", "/status", "/debug", "/console",
    "/server-status",
]

# ═════════════════════════════════════════════════════════════════════════════
#  PRINT HELPERS
# ═════════════════════════════════════════════════════════════════════════════

print_lock = threading.Lock()

def cprint(msg, color="", prefix=""):
    with print_lock:
        w = term_width() - len(prefix) - 2
        if len(msg) > w:
            msg = msg[:w-3] + "..."
        print(f"{color}{prefix}{msg}{RESET}")

def info(msg):    cprint(msg, FG_LOW,      "[*] ")
def success(msg): cprint(msg, FG_SUCCESS,  "[+] ")
def warn(msg):    cprint(msg, FG_WAF,      "[!] ")
def error(msg):   cprint(msg, FG_CRITICAL, "[-] ")

def get_platform_info():
    return f"{platform.system()} {platform.release()} / Python {platform.python_version()}"

def random_delay(waf_mode=False):
    time.sleep(random.uniform(1.5, 4.0) if waf_mode else random.uniform(0.1, 0.5))

# ═════════════════════════════════════════════════════════════════════════════
#  HTTP HELPERS
# ═════════════════════════════════════════════════════════════════════════════

def build_session(waf_aware=False):
    session = requests.Session()
    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Cache-Control": "max-age=0",
    }
    if waf_aware:
        headers["Referer"] = "https://www.google.com/"
        headers["DNT"] = "1"
    session.headers.update(headers)
    return session

def fetch_url(url, session, timeout=15, waf_aware=False, retries=3):
    for attempt in range(retries):
        try:
            if waf_aware and attempt > 0:
                random_delay(waf_mode=True)
                session = build_session(waf_aware=True)
            resp = session.get(url, timeout=timeout, allow_redirects=True, verify=False)
            session.headers["User-Agent"] = random.choice(USER_AGENTS)
            return resp
        except requests.exceptions.SSLError:
            try:
                return session.get(url, timeout=timeout, allow_redirects=True, verify=False)
            except Exception:
                pass
        except requests.exceptions.ConnectionError:
            if attempt < retries - 1:
                time.sleep(2 ** attempt)
        except requests.exceptions.Timeout:
            if attempt < retries - 1:
                time.sleep(1)
        except Exception:
            pass
    return None

def normalize_url(url):
    url = url.strip()
    url = re.sub(r'^\[.*?\]\(', '', url).rstrip(')')
    if url.startswith("//"):
        url = "https:" + url
    elif url.startswith("ftp://"):
        url = "https://" + url[6:]
    elif not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")

def try_http_fallback(url, session, timeout=10):
    resp = fetch_url(url, session, timeout=timeout)
    if resp is not None:
        return url, resp
    if url.startswith("https://"):
        http_url = "http://" + url[8:]
        info(f"HTTPS failed → retrying HTTP: {http_url}")
        resp = fetch_url(http_url, session, timeout=timeout)
        if resp is not None:
            success(f"HTTP fallback worked: {http_url}")
            return http_url, resp
    return url, None

def get_domain(url):
    return urlparse(url).netloc

def detect_waf(response):
    detected = []
    response_text = response.text.lower() if response.text else ""
    headers_lower = {k.lower(): v.lower() for k, v in response.headers.items()}
    combined = response_text + " " + str(headers_lower)
    for waf_name, sigs in WAF_SIGNATURES.items():
        for sig in sigs:
            if sig.lower() in combined:
                detected.append(waf_name)
                break
    if response.status_code in [403, 406, 429, 503] and not detected:
        detected.append("Unknown WAF/Firewall")
    return list(set(detected))

# ═════════════════════════════════════════════════════════════════════════════
#  STATUS CODE PROBE
#  New feature: check if subdomains/targets are alive before scanning
# ═════════════════════════════════════════════════════════════════════════════

def probe_status(url, session, timeout=8):
    """
    Quick status check on a URL.
    Returns (url, status_code, redirect_url, response_time_ms).
    """
    start = time.time()
    try:
        resp = session.get(url, timeout=timeout, allow_redirects=False, verify=False)
        elapsed = int((time.time() - start) * 1000)
        redirect = resp.headers.get("Location", "") if resp.status_code in [301,302,303,307,308] else ""
        return url, resp.status_code, redirect, elapsed
    except Exception:
        elapsed = int((time.time() - start) * 1000)
        return url, 0, "", elapsed

def print_status_result(url, status, redirect, ms):
    """print one status result with appropriate coloring"""
    color = STATUS_COLORS.get(status, FG_DIM)
    icon  = STATUS_ICONS.get(status, "?") if not isinstance(STATUS_ICONS, defaultdict) else STATUS_ICONS[status]
    ms_color = FG_SUCCESS if ms < 500 else FG_MEDIUM if ms < 2000 else FG_CRITICAL

    # truncate URL to fit terminal
    w      = term_width()
    url_w  = w - 35
    disp   = url[:url_w] + "..." if len(url) > url_w else url

    line = (f"  {color}{icon} [{status:3d}]{RESET}  "
            f"{FG_URL}{disp:<{url_w}}{RESET}  "
            f"{ms_color}{ms:4d}ms{RESET}")

    if redirect:
        redir_w = w - 12
        redir   = redirect[:redir_w] + "..." if len(redirect) > redir_w else redirect
        line += f"  {FG_DIM}→ {redir}{RESET}"

    with print_lock:
        print(line)

def run_status_check(targets, session, threads=5):
    """probe all targets for status codes in parallel"""
    section_header("STATUS CHECK", FG_SECTION)

    # print header row
    w = term_width()
    print(f"  {FG_DIM}{'STATUS':<12}{'URL':<{w-35}}{'TIME':>6}{RESET}")
    print(f"  {FG_DIM}{'─'*12}{'─'*(w-35)}{'─'*6}{RESET}")

    alive  = []
    dead   = []

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(probe_status, t, session): t for t in targets}
        for future in as_completed(futures):
            url, status, redirect, ms = future.result()
            print_status_result(url, status, redirect, ms)
            if status in [200, 201, 204, 301, 302, 403]:
                alive.append(url)
            else:
                dead.append(url)

    print()
    success(f"Alive: {len(alive)}  |  Dead/Unreachable: {len(dead)}")
    return alive, dead

# ═════════════════════════════════════════════════════════════════════════════
#  TECHNOLOGY FINGERPRINTING
# ═════════════════════════════════════════════════════════════════════════════

def fingerprint_technologies(content, url=""):
    """
    Scan JS/HTML content for known tech stack patterns.
    Returns list of detected technologies and any version warnings.
    """
    detected = {}
    for tech, patterns in TECH_FINGERPRINTS.items():
        for pat in patterns:
            if re.search(pat, content, re.IGNORECASE):
                detected[tech] = {"url": url}
                # try to extract version
                if tech in VERSION_PATTERNS:
                    vmatch = re.search(VERSION_PATTERNS[tech], content, re.IGNORECASE)
                    if vmatch:
                        detected[tech]["version"] = vmatch.group(1)
                break
    return detected

def check_tech_risks(detected_techs):
    """
    Cross-reference detected technologies against known risky versions.
    Returns list of risk warnings.
    """
    risks = []
    for tech, info in detected_techs.items():
        version = info.get("version")
        if not version or tech not in RISKY_VERSIONS:
            continue
        # simple version comparison (covers most cases)
        for threshold, note in RISKY_VERSIONS[tech].items():
            try:
                op  = threshold[:1]
                ver = threshold[1:]
                v_parts = [int(x) for x in version.split(".")]
                t_parts = [int(x) for x in ver.split(".")]
                # pad to same length
                while len(v_parts) < len(t_parts): v_parts.append(0)
                while len(t_parts) < len(v_parts): t_parts.append(0)
                if op == "<" and v_parts < t_parts:
                    risks.append({
                        "tech":    tech,
                        "version": version,
                        "note":    note,
                        "severity":"medium"
                    })
            except Exception:
                continue
    return risks

# ═════════════════════════════════════════════════════════════════════════════
#  JS DISCOVERY
# ═════════════════════════════════════════════════════════════════════════════

def extract_js_from_page(url, session, waf_aware=False):
    js_files    = set()
    other_files = set()

    url, resp = try_http_fallback(url, session, timeout=15)
    if not resp:
        error(f"Could not reach: {url}")
        return js_files, other_files, None

    waf = detect_waf(resp)
    if waf:
        warn(f"WAF detected: {', '.join(waf)}")
        if waf_aware:
            warn("WAF-aware mode active — slowing down...")

    if resp.status_code not in [200, 201]:
        warn(f"HTTP {resp.status_code} for {url}")

    soup     = BeautifulSoup(resp.text, "html.parser")
    base_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}"

    for tag in soup.find_all("script", src=True):
        src  = tag["src"]
        full = urljoin(url, src)
        if ".js" in full:
            js_files.add(full)

    for tag in soup.find_all(["link", "a", "iframe", "img"]):
        href = tag.get("href", "") or tag.get("src", "")
        if href:
            full = urljoin(url, href)
            for ext in INTERESTING_EXTENSIONS:
                if ext in full.lower() and ext != ".js":
                    other_files.add(full)

    raw = resp.text
    for pattern in [
        r'src\s*[=:]\s*["\']([^"\']+\.js(?:\?[^"\']*)?)["\']',
        r'import\s+[^"\']*["\']([^"\']+\.js)["\']',
        r'require\s*\(\s*["\']([^"\']+\.js)["\']',
        r'["\']([/a-zA-Z0-9_\-\.]+\.js(?:\?[a-zA-Z0-9=&_\-\.]+)?)["\']',
    ]:
        for match in re.finditer(pattern, raw, re.IGNORECASE):
            path = match.group(1)
            if path.startswith("//"):       full = "https:" + path
            elif path.startswith("/"):      full = base_url + path
            elif path.startswith("http"):   full = path
            else:                           full = urljoin(url, path)
            js_files.add(full)

    return js_files, other_files, resp

# ═════════════════════════════════════════════════════════════════════════════
#  JS CONTENT ANALYSIS
# ═════════════════════════════════════════════════════════════════════════════

def analyze_js_content(url, content, beautify=False, source_domain=""):
    """
    Full analysis of one JS file.
    source_domain is the domain this file belongs to — used in reports
    so findings are always clearly attributed.
    """
    results = {
        "url":           url,
        "source_domain": source_domain or get_domain(url),
        "size":          len(content),
        "findings":      [],
        "endpoints":     [],
        "js_relations":  [],
        "technologies":  {},
        "tech_risks":    [],
        "score":         0,
    }

    if beautify and JS_BEAUTIFIER:
        try:
            content = jsbeautifier.beautify(content)
        except Exception:
            pass

    lines         = content.split("\n")
    seen_findings = set()

    for category, patterns in SENSITIVE_PATTERNS.items():
        for pattern, severity in patterns:
            try:
                for match in re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE):
                    matched_str = match.group(0)[:120]
                    line_num    = content[:match.start()].count("\n") + 1
                    line_ctx    = lines[line_num-1].strip()[:150] if line_num <= len(lines) else ""
                    dedup_key   = hashlib.md5(f"{category}{matched_str}".encode()).hexdigest()
                    if dedup_key in seen_findings:
                        continue
                    seen_findings.add(dedup_key)
                    results["findings"].append({
                        "category":      category,
                        "severity":      severity,
                        "match":         matched_str,
                        "line":          line_num,
                        "context":       line_ctx,
                        "source_domain": results["source_domain"],
                        "source_file":   url,
                    })
                    score_map = {"critical":100,"high":50,"medium":20,"low":5,"info":1}
                    results["score"] += score_map.get(severity, 1)
            except re.error:
                continue

    # endpoints
    for pat in [
        r'["\'](\/?(?:api|v[0-9]+|rest|graphql|endpoint|service)[\/a-zA-Z0-9_\-\.?=&%#@!]+)["\']',
        r'https?://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(?:/[^\s"\'<>]*)?',
    ]:
        for match in re.finditer(pat, content, re.IGNORECASE):
            ep = match.group(1) if match.lastindex else match.group(0)
            if ep not in results["endpoints"] and len(ep) > 3:
                results["endpoints"].append(ep)

    # JS relationships
    for pat in [
        r'(?:import|require)\s*[\(\s]*["\']([^"\']+\.js)["\']',
        r'src\s*[:=]\s*["\']([^"\']+\.js)["\']',
    ]:
        for match in re.finditer(pat, content, re.IGNORECASE):
            rel = match.group(1)
            if rel not in results["js_relations"]:
                results["js_relations"].append(rel)

    # tech fingerprint
    results["technologies"] = fingerprint_technologies(content, url)
    results["tech_risks"]   = check_tech_risks(results["technologies"])

    return results

# ═════════════════════════════════════════════════════════════════════════════
#  CROSS-FILE CORRELATION ENGINE
#  When we have results from multiple JS files, look for patterns that
#  only make sense when you connect the dots across files.
#  e.g. an endpoint found in one file + a key found in another =
#  a much stronger finding than either alone.
# ═════════════════════════════════════════════════════════════════════════════

def correlate_findings(all_analysis):
    """
    Analyze findings across ALL JS files together.
    Looks for:
      - Same secret appearing in multiple files (confirms it's real)
      - Endpoints in one file that match sensitive path patterns in another
      - Key + endpoint combinations that suggest exploitable chains
      - Domain appearing in multiple files (cross-origin references)

    Returns a list of correlation findings.
    """
    correlations = []

    # collect all findings by type across all files
    keys_found     = []  # API keys, tokens, passwords
    endpoints      = []  # API endpoints
    internal_ips   = []  # internal IP references
    db_strings     = []  # database connection info

    for res in all_analysis:
        domain = res.get("source_domain", get_domain(res["url"]))
        for f in res["findings"]:
            sev = f["severity"]
            cat = f["category"]
            if cat in ["API Keys & Tokens", "AWS Credentials",
                       "Authentication & Passwords", "Cloud & Infrastructure"]:
                keys_found.append({**f, "domain": domain, "file": res["url"]})
            if cat == "Sensitive Endpoints & Paths":
                endpoints.append({**f, "domain": domain, "file": res["url"]})
            if cat == "Internal Infrastructure":
                internal_ips.append({**f, "domain": domain, "file": res["url"]})
            if cat == "Database Credentials":
                db_strings.append({**f, "domain": domain, "file": res["url"]})

        for ep in res.get("endpoints", []):
            endpoints.append({"match": ep, "domain": domain, "file": res["url"], "severity": "info"})

    # ── correlation 1: key + endpoint in the same domain ─────────────────
    # a secret + an API endpoint from the same domain is a strong combo
    key_domains = {k["domain"] for k in keys_found}
    ep_domains  = {e["domain"] for e in endpoints if e.get("severity") != "info"}
    shared      = key_domains & ep_domains
    for domain in shared:
        domain_keys = [k for k in keys_found if k["domain"] == domain]
        domain_eps  = [e for e in endpoints if e["domain"] == domain and e.get("severity") != "info"]
        if domain_keys and domain_eps:
            correlations.append({
                "type":        "KEY + ENDPOINT CHAIN",
                "severity":    "critical",
                "domain":      domain,
                "description": (f"Found {len(domain_keys)} credential(s) AND "
                                f"{len(domain_eps)} sensitive endpoint(s) on the same domain. "
                                f"The credentials may provide access to those endpoints."),
                "files":       list({k["file"] for k in domain_keys} | {e["file"] for e in domain_eps}),
                "keys":        [k["match"][:60] for k in domain_keys[:3]],
                "endpoints":   [e["match"][:60] for e in domain_eps[:3]],
            })

    # ── correlation 2: same secret in multiple files ──────────────────────
    # if the same token appears in 2+ JS files it's almost certainly real
    match_counts = defaultdict(list)
    for k in keys_found:
        match_counts[k["match"][:40]].append(k["file"])
    for match_text, files in match_counts.items():
        if len(set(files)) >= 2:
            correlations.append({
                "type":        "SECRET IN MULTIPLE FILES",
                "severity":    "high",
                "domain":      get_domain(files[0]),
                "description": (f"The same secret/token appears in {len(set(files))} different JS files. "
                                f"This strongly suggests it is a real credential, not a placeholder."),
                "files":       list(set(files)),
                "keys":        [match_text],
                "endpoints":   [],
            })

    # ── correlation 3: internal IP + key in same domain ───────────────────
    ip_domains = {i["domain"] for i in internal_ips}
    for domain in key_domains & ip_domains:
        correlations.append({
            "type":        "CREDENTIAL + INTERNAL NETWORK",
            "severity":    "high",
            "domain":      domain,
            "description": (f"Internal IP address(es) AND credential(s) found on the same domain. "
                            f"The credentials may provide access to internal infrastructure."),
            "files":       list({k["file"] for k in keys_found if k["domain"]==domain} |
                                {i["file"] for i in internal_ips if i["domain"]==domain}),
            "keys":        [],
            "endpoints":   [],
        })

    # ── correlation 4: database credentials found anywhere ────────────────
    for db in db_strings:
        correlations.append({
            "type":        "DATABASE ACCESS",
            "severity":    "critical",
            "domain":      db["domain"],
            "description": (f"Database connection string found in JS file. "
                            f"This may provide direct database access."),
            "files":       [db["file"]],
            "keys":        [db["match"][:80]],
            "endpoints":   [],
        })

    return correlations

# ═════════════════════════════════════════════════════════════════════════════
#  PRINT ANALYSIS RESULTS  (per-file, domain-attributed)
# ═════════════════════════════════════════════════════════════════════════════

def print_analysis(results, show_endpoints=True):
    url     = results["url"]
    domain  = results.get("source_domain", get_domain(url))
    findings = sorted(results["findings"], key=lambda x: SEVERITY_ORDER.get(x["severity"],99))
    score    = results["score"]

    score_color = (FG_CRITICAL if score>=200 else FG_HIGH if score>=80 else
                   FG_MEDIUM   if score>=20  else FG_LOW)
    count_color = (FG_CRITICAL if len(findings)>=10 else FG_HIGH if len(findings)>=5 else
                   FG_MEDIUM   if len(findings)>=1  else FG_SUCCESS)

    w = term_width()
    print(f"\n{FG_DIM}{'─'*w}{RESET}")
    # always show which domain this file belongs to
    print(f"  {FG_DIM}Domain :{RESET} {FG_SUB}{domain}{RESET}")
    print(f"  {FG_URL}File   : {url[:w-12]}{RESET}")
    print(f"  {FG_DIM}Size   :{RESET} {results['size']:,} bytes  "
          f"{FG_DIM}Findings:{RESET} {count_color}{len(findings)}{RESET}  "
          f"{FG_DIM}Score:{RESET} {score_color}{score}{RESET}")
    print(f"{FG_DIM}{'─'*w}{RESET}")

    # tech stack
    if results.get("technologies"):
        techs = list(results["technologies"].keys())
        print(f"  {FG_TECH}Tech Stack: {', '.join(techs)}{RESET}")
        for risk in results.get("tech_risks", []):
            print(f"  {FG_MEDIUM}  ⚠ {risk['tech']} v{risk['version']} — {risk['note']}{RESET}")

    if not findings and not results["endpoints"]:
        print(f"  {FG_SUCCESS}✓ Nothing significant found.{RESET}")
        return

    by_cat = defaultdict(list)
    for f in findings:
        by_cat[f["category"]].append(f)

    for cat, cat_findings in by_cat.items():
        cat_color = CATEGORY_COLORS.get(cat, FG_LABEL)
        print(f"\n  {cat_color}▸ {cat}  ({len(cat_findings)}){RESET}")
        for f in cat_findings:
            sev     = f["severity"]
            badge   = SEVERITY_BADGE.get(sev, "")
            fg      = SEVERITY_FG.get(sev, "")
            icon    = SEVERITY_ICONS.get(sev, "")
            sev_tag = f" {sev.upper():<8} "
            # attribute every finding to its domain and file clearly
            print(f"    {badge}{sev_tag}{RESET} {icon} "
                  f"{FG_DIM}L{f['line']:4d}{RESET}  "
                  f"{fg}{f['match'][:w-40]}{RESET}")
            if f["context"] and f["context"].strip() != f["match"].strip():
                ctx = f["context"][:w-16]
                print(f"    {FG_DIM}{'':13}→ {ctx}{RESET}")

    if show_endpoints and results["endpoints"]:
        print(f"\n  {FG_SECTION}▸ Endpoints ({len(results['endpoints'])}){RESET}")
        for ep in results["endpoints"][:30]:
            print(f"    {FG_URL}  ↳ {ep[:w-10]}{RESET}")
        if len(results["endpoints"]) > 30:
            info(f"  ... +{len(results['endpoints'])-30} more endpoints in output file")

    if results["js_relations"]:
        print(f"\n  {FG_RELATION}▸ JS Imports ({len(results['js_relations'])}){RESET}")
        for rel in results["js_relations"][:10]:
            print(f"    {FG_RELATION}  ↳ {rel[:w-10]}{RESET}")

def print_correlations(correlations):
    """print cross-file correlation findings"""
    if not correlations:
        return

    section_header("CROSS-FILE INTELLIGENCE REPORT", FG_CORR)
    print(f"  {FG_CORR}JSReaper analyzed patterns ACROSS multiple JS files{RESET}")
    print(f"  {FG_DIM}and found the following connected findings:{RESET}\n")

    for i, c in enumerate(correlations, 1):
        sev   = c["severity"]
        badge = SEVERITY_BADGE.get(sev, "")
        icon  = SEVERITY_ICONS.get(sev, "")
        w     = term_width()

        print(f"  {badge} {icon} FINDING #{i}: {c['type']} {RESET}")
        print(f"  {FG_DIM}  Domain     :{RESET} {FG_SUB}{c['domain']}{RESET}")
        print(f"  {FG_DIM}  Severity   :{RESET} {SEVERITY_FG[sev]}{sev.upper()}{RESET}")

        # wrap description to terminal width
        desc = c["description"]
        words = desc.split()
        line, lines = [], []
        for word in words:
            if sum(len(w)+1 for w in line) + len(word) > w - 20:
                lines.append(" ".join(line))
                line = [word]
            else:
                line.append(word)
        if line:
            lines.append(" ".join(line))
        for l in lines:
            print(f"  {FG_INFO}  {l}{RESET}")

        if c.get("files"):
            print(f"  {FG_DIM}  Found in   :{RESET}")
            for f in c["files"][:4]:
                print(f"  {FG_URL}    ↳ {f[:w-10]}{RESET}")

        if c.get("keys"):
            print(f"  {FG_DIM}  Credential :{RESET}")
            for k in c["keys"][:2]:
                print(f"  {FG_CRITICAL}    → {k}{RESET}")

        if c.get("endpoints"):
            print(f"  {FG_DIM}  Endpoints  :{RESET}")
            for e in c["endpoints"][:2]:
                print(f"  {FG_SECTION}    → {e}{RESET}")

        print()

# ═════════════════════════════════════════════════════════════════════════════
#  SUBDOMAIN RECON
# ═════════════════════════════════════════════════════════════════════════════

def run_subdomain_recon(domain):
    section_header(f"SUBDOMAIN RECON: {domain}", FG_SECTION)
    subdomains = set()
    session    = build_session()

    sources = [
        ("crt.sh",       f"https://crt.sh/?q=%.{domain}&output=json"),
        ("HackerTarget", f"https://api.hackertarget.com/hostsearch/?q={domain}"),
        ("AlienVault",   f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"),
    ]

    for name, url in sources:
        info(f"Querying {name}...")
        try:
            resp = session.get(url, timeout=20)
            if resp.status_code != 200:
                warn(f"{name} returned {resp.status_code}")
                continue
            if name == "crt.sh":
                for entry in resp.json():
                    for sub in entry.get("name_value","").split("\n"):
                        sub = sub.strip().lstrip("*.")
                        if sub.endswith(domain) and sub != domain:
                            subdomains.add(sub)
            elif name == "HackerTarget":
                if "error" not in resp.text.lower():
                    for line in resp.text.strip().split("\n"):
                        if "," in line:
                            sub = line.split(",")[0].strip()
                            if sub.endswith(domain):
                                subdomains.add(sub)
            elif name == "AlienVault":
                for entry in resp.json().get("passive_dns", []):
                    hn = entry.get("hostname","")
                    if hn.endswith(domain):
                        subdomains.add(hn)
            success(f"{name}: total {len(subdomains)} subdomains")
        except Exception as e:
            warn(f"{name} failed: {e}")

    if subdomains:
        print(f"\n{FG_SUCCESS}  Found {len(subdomains)} subdomains:{RESET}")
        for sub in sorted(subdomains):
            print(f"    {FG_SUB}  ⟫ https://{sub}{RESET}")
    else:
        warn("No subdomains found.")
    return subdomains

# ═════════════════════════════════════════════════════════════════════════════
#  SENSITIVE FILE PROBE
# ═════════════════════════════════════════════════════════════════════════════

def probe_sensitive_files(base_url, session, threads=5, waf_aware=False):
    section_header(f"SENSITIVE FILE PROBE: {base_url}", FG_PROBE)
    found  = []
    domain = get_domain(base_url)

    def check_path(path):
        url  = base_url.rstrip("/") + path
        if waf_aware:
            random_delay(waf_mode=True)
        resp = fetch_url(url, session, timeout=8)
        if resp and resp.status_code in [200,301,302,403]:
            return (url, resp.status_code, len(resp.content), domain)
        return None

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check_path, path): path for path in COMMON_SENSITIVE_PATHS}
        for future in as_completed(futures):
            result = future.result()
            if result:
                url, status, size, dom = result
                color = STATUS_COLORS.get(status, FG_DIM)
                icon  = "🔥" if status==200 else "↩" if status in [301,302] else "🔒"
                sev   = "high" if status==200 else "medium"
                badge = SEVERITY_BADGE.get(sev,"")
                w     = term_width()
                disp  = url[:w-30] + "..." if len(url) > w-30 else url
                print(f"  {badge} {status} {RESET}  {icon}  {color}{disp}{RESET}  {FG_DIM}({size}b){RESET}")
                found.append({"url":url,"status":status,"size":size,"severity":sev,"domain":dom})

    if not found:
        success("No sensitive files found.")
    return found

# ═════════════════════════════════════════════════════════════════════════════
#  CORE SCAN ENGINE
# ═════════════════════════════════════════════════════════════════════════════

def scan_target(url, args, session):
    url    = normalize_url(url)
    domain = get_domain(url)

    section_header(f"TARGET: {url}", LEMON)
    print(f"  {FG_DIM}Domain  :{RESET} {FG_URL}{domain}{RESET}")
    print(f"  {FG_DIM}Time    :{RESET} {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  {FG_DIM}Platform:{RESET} {get_platform_info()}\n")

    all_results = {
        "target": url, "domain": domain,
        "js_files": [], "other_files": [],
        "analysis": [], "subdomains": [],
        "sensitive_files": [], "correlations": [], "summary": {},
    }

    # ── 1. discover JS ────────────────────────────────────────────────────
    info(f"Crawling {url} for JS and interesting files...")
    js_files, other_files, base_resp = extract_js_from_page(url, session, waf_aware=args.waf_aware)

    all_results["js_files"]    = list(js_files)
    all_results["other_files"] = list(other_files)
    success(f"Found {len(js_files)} JS file(s)  |  {len(other_files)} other file(s)")

    if js_files:
        print(f"\n  {FG_SECTION}JavaScript Files:{RESET}")
        for jf in sorted(js_files):
            print(f"    {FG_URL}  ↳ {jf[:term_width()-10]}{RESET}")

    if other_files and not args.js_only:
        print(f"\n  {FG_MEDIUM}Other Files:{RESET}")
        for f in sorted(other_files):
            print(f"    {FG_MEDIUM}  ↳ {f[:term_width()-10]}{RESET}")

    # ── 2. deep crawl ────────────────────────────────────────────────────
    if args.deep:
        info("Deep mode: following JS import chains...")
        extra_js = set()
        for jf in list(js_files)[:10]:
            sub_js, _, _ = extract_js_from_page(jf, session, waf_aware=args.waf_aware)
            extra_js |= sub_js
        new_js = extra_js - js_files
        if new_js:
            success(f"Deep crawl found {len(new_js)} more JS file(s)")
            js_files |= new_js
            all_results["js_files"] = list(js_files)

    # ── 3. analyze JS ────────────────────────────────────────────────────
    if args.analyze and js_files:
        section_header(f"ANALYZING {len(js_files)} JS FILE(S)  [{domain}]", FG_SECTION)

        def analyze_one(js_url):
            if args.waf_aware:
                random_delay(waf_mode=True)
            js_url, resp = try_http_fallback(js_url, session)
            if not resp or not resp.text:
                return None
            content = resp.text
            if args.dump:
                safe_name = re.sub(r'[^\w\-_.]', '_', js_url)[:80]
                dump_dir  = args.dump_dir or "jsreaper_dumps"
                dump_path = os.path.join(dump_dir, safe_name + ".js")
                os.makedirs(dump_dir, exist_ok=True)
                with open(dump_path, "w", encoding="utf-8", errors="ignore") as df:
                    df.write(f"// Source: {js_url}\n// Domain: {domain}\n\n")
                    df.write(content)
            return analyze_js_content(js_url, content, beautify=args.beautify, source_domain=domain)

        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = {executor.submit(analyze_one, jf): jf for jf in list(js_files)}
            for future in as_completed(futures):
                res = future.result()
                if res:
                    all_results["analysis"].append(res)
                    if res["findings"] or (args.verbose and res["endpoints"]):
                        print_analysis(res, show_endpoints=args.endpoints)

        # run cross-file correlation
        if len(all_results["analysis"]) > 1:
            correlations = correlate_findings(all_results["analysis"])
            all_results["correlations"] = correlations
            if correlations:
                print_correlations(correlations)

    # ── 4. sensitive file probe ───────────────────────────────────────────
    if args.probe:
        found_files = probe_sensitive_files(url, session, threads=args.threads, waf_aware=args.waf_aware)
        all_results["sensitive_files"] = found_files

    # ── 5. subdomain recon ────────────────────────────────────────────────
    if args.subdomains:
        subs = run_subdomain_recon(domain)
        all_results["subdomains"] = list(subs)
        if args.scan_subs and subs:
            info(f"Scanning {min(len(subs),10)} subdomains for JS...")
            for sub in list(subs)[:10]:
                sub_url = f"https://{sub}"
                sub_js, _, _ = extract_js_from_page(sub_url, session, waf_aware=args.waf_aware)
                if sub_js:
                    success(f"  {sub}: {len(sub_js)} JS file(s)")
                    all_results["js_files"].extend(list(sub_js))

    # ── summary ───────────────────────────────────────────────────────────
    total_findings = sum(len(r["findings"]) for r in all_results["analysis"])
    critical  = sum(1 for r in all_results["analysis"] for f in r["findings"] if f["severity"]=="critical")
    high      = sum(1 for r in all_results["analysis"] for f in r["findings"] if f["severity"]=="high")
    medium    = sum(1 for r in all_results["analysis"] for f in r["findings"] if f["severity"]=="medium")
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
        "correlations_found":    len(all_results["correlations"]),
    }

    print_summary(all_results["summary"], url)
    return all_results

# ═════════════════════════════════════════════════════════════════════════════
#  SUMMARY
# ═════════════════════════════════════════════════════════════════════════════

def print_summary(s, target):
    section_header(f"SUMMARY: {target}", LEMON)
    score_color = (FG_CRITICAL if s["risk_score"]>=200 else FG_HIGH if s["risk_score"]>=80
                   else FG_MEDIUM if s["risk_score"]>=20 else FG_SUCCESS)
    rows = [
        ("JS Files Found",       f"{FG_URL}{s['js_files_found']}{RESET}"),
        ("Other Files Found",    f"{FG_MEDIUM}{s['other_files_found']}{RESET}"),
        ("Total Findings",       f"{FG_HIGH}{s['total_findings']}{RESET}"),
        ("Critical",             f"{SEVERITY_BADGE['critical']} {s['critical']} {RESET}"),
        ("High",                 f"{SEVERITY_BADGE['high']} {s['high']} {RESET}"),
        ("Medium",               f"{SEVERITY_BADGE['medium']} {s['medium']} {RESET}"),
        ("Correlations Found",   f"{FG_CORR}{s['correlations_found']}{RESET}"),
        ("Subdomains Found",     f"{FG_SUB}{s['subdomains_found']}{RESET}"),
        ("Sensitive Files Hit",  f"{FG_PROBE}{s['sensitive_files_found']}{RESET}"),
        ("Total Risk Score",     f"{score_color}{s['risk_score']}{RESET}"),
    ]
    for label, value in rows:
        print(f"  {FG_DIM}{label:<24}{RESET}  {value}")

    score = s["risk_score"]
    if score >= 300:
        verdict = f"{SEVERITY_BADGE['critical']} 🔥 CRITICAL — Immediate review required {RESET}"
    elif score >= 100:
        verdict = f"{SEVERITY_BADGE['high']} ⚠  HIGH RISK — Review findings carefully {RESET}"
    elif score >= 30:
        verdict = f"{SEVERITY_BADGE['medium']} ⚡ MEDIUM RISK — Some issues found {RESET}"
    elif score > 0:
        verdict = f"{SEVERITY_BADGE['low']} ℹ  LOW RISK — Minor findings {RESET}"
    else:
        verdict = f"{FG_SUCCESS}  ✓ CLEAN {RESET}"
    print(f"\n  Overall: {verdict}\n")

# ═════════════════════════════════════════════════════════════════════════════
#  OUTPUT SAVER
# ═════════════════════════════════════════════════════════════════════════════

def save_output(all_scan_results, output_file, fmt="txt"):
    output_file = os.path.normpath(output_file)
    try:
        if fmt == "json":
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(all_scan_results, f, indent=2, default=str)
        else:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(f"{TOOL_NAME} v{TOOL_VERSION} - Scan Report\n")
                f.write(f"Written by @dr34lm — For research & educational use\n")
                f.write(f"Generated: {datetime.datetime.now()}\n")
                f.write("="*70+"\n\n")
                for scan in all_scan_results:
                    f.write(f"TARGET: {scan['target']}\nDOMAIN: {scan['domain']}\n\n")
                    f.write(f"JS FILES ({len(scan['js_files'])}):\n")
                    for jf in scan["js_files"]:
                        f.write(f"  {jf}\n")
                    f.write(f"\nCORRELATIONS ({len(scan['correlations'])}):\n")
                    for c in scan["correlations"]:
                        f.write(f"  [{c['severity'].upper()}] {c['type']} — {c['domain']}\n")
                        f.write(f"  {c['description']}\n")
                        for fn in c.get("files",[]):
                            f.write(f"    file: {fn}\n")
                    f.write(f"\nSENSITIVE FILES:\n")
                    for sf in scan["sensitive_files"]:
                        f.write(f"  [{sf['status']}] [{sf['domain']}] {sf['url']}\n")
                    f.write(f"\nFINDINGS:\n")
                    for res in scan["analysis"]:
                        if not res["findings"]:
                            continue
                        f.write(f"\n  DOMAIN: {res['source_domain']}\n")
                        f.write(f"  FILE  : {res['url']}\n")
                        f.write(f"  SCORE : {res['score']}\n")
                        for fnd in res["findings"]:
                            f.write(f"  [{fnd['severity'].upper():<8}] {fnd['category']} "
                                    f"| L{fnd['line']} | {fnd['match'][:100]}\n")
                    f.write("\n"+"="*70+"\n\n")
        success(f"Saved → {output_file}")
    except Exception as e:
        error(f"Could not save: {e}")

# ═════════════════════════════════════════════════════════════════════════════
#  CLI ARGUMENT PARSER
# ═════════════════════════════════════════════════════════════════════════════

def build_parser():
    parser = argparse.ArgumentParser(
        prog="jsreaper",
        description=(
            f"{TOOL_NAME} v{TOOL_VERSION} — JavaScript Recon & Analysis Tool\n"
            "Written by @dr34lm  |  https://x.com/dr34lm\n"
            "For research and educational purposes only.\n"
            "Use only on targets you are authorized to test.\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 WALKTHROUGH — STEP BY STEP
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

 CHECK VERSION:
   jsreaper --version

 BURP SUITE INPUT (paste JS URLs directly from Burp):
   jsreaper --burp burp_js_list.txt --analyze
   jsreaper --burp-paste "https://a.com/x.js,https://b.com/y.js" --analyze

 SINGLE TARGET:
   jsreaper -u example.com
   jsreaper -u https://example.com --analyze
   jsreaper -u http://example.com --analyze --endpoints

 STATUS CHECK (check if targets are alive before scanning):
   jsreaper -l targets.txt --status
   jsreaper -u example.com --subdomains --status

 ANALYZE JS FILES:
   jsreaper -u example.com --analyze
   jsreaper -u example.com --analyze --deep --beautify

 CROSS-FILE INTELLIGENCE (auto-enabled with --analyze):
   jsreaper -u example.com --analyze
   → JSReaper automatically correlates findings across all JS files
   → Finds key+endpoint chains, secrets in multiple files, etc.

 SUBDOMAIN SCAN:
   jsreaper -u example.com --subdomains --scan-subs --analyze

 SENSITIVE FILE PROBE:
   jsreaper -u example.com --probe

 SAVE RESULTS:
   jsreaper -u example.com --analyze -o results.txt
   jsreaper -u example.com --analyze -o results.json --format json

 BULK SCAN:
   jsreaper -l scope.txt -t 5 --analyze --probe -o report.json --format json

 WAF-PROTECTED TARGET:
   jsreaper -u example.com --analyze --waf-aware -t 1

 FULL EVERYTHING:
   jsreaper -u example.com --analyze --deep --probe --subdomains --endpoints --status

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 For research and educational purposes only. @dr34lm
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
    )

    tg = parser.add_argument_group("Target")
    tg.add_argument("-u","--url",  help="Single target URL (any format — http/https/bare domain)")
    tg.add_argument("-l","--list", help="File with one target per line")
    tg.add_argument("--burp",      help="File containing JS URLs exported from Burp Suite\n"
                                        "(handles newline, comma, or single-line formats)")
    tg.add_argument("--burp-paste",metavar="TEXT",
                                   help="Paste Burp JS URLs directly as a string argument")

    vg = parser.add_argument_group("Version & Info")
    vg.add_argument("--version","-V", action="store_true",
                    help="Show version info and check for updates")

    sg = parser.add_argument_group("Scan Options")
    sg.add_argument("--analyze",    action="store_true",
                    help="[CORE] Analyze all JS files for secrets, vulns, endpoints.\n"
                         "Also runs cross-file correlation automatically.")
    sg.add_argument("--deep",       action="store_true",
                    help="Follow JS import chains to find additional files")
    sg.add_argument("--probe",      action="store_true",
                    help="Probe for exposed sensitive files (.env, .git, swagger, etc.)")
    sg.add_argument("--subdomains", action="store_true",
                    help="Passive subdomain recon (crt.sh, HackerTarget, AlienVault)")
    sg.add_argument("--scan-subs",  action="store_true",
                    help="Scan discovered subdomains for JS (requires --subdomains)")
    sg.add_argument("--status",     action="store_true",
                    help="Check HTTP status of all targets/subdomains before scanning.\n"
                         "Shows color-coded status codes and response times.")
    sg.add_argument("--endpoints",  action="store_true",
                    help="Show extracted API endpoints from JS files")
    sg.add_argument("--js-only",    action="store_true",
                    help="Only collect .js files, skip other types")
    sg.add_argument("--beautify",   action="store_true",
                    help="De-minify JS before analysis (requires jsbeautifier)")
    sg.add_argument("--verbose",    action="store_true",
                    help="Show all files including those with no findings")

    pg = parser.add_argument_group("Performance & Evasion")
    pg.add_argument("-t","--threads", type=int, default=3,
                    choices=[1,2,3,4,5,6,8,10], metavar="{1,2,3,4,5,6,8,10}",
                    help="Thread count (1=stealth, 3=default, 10=aggressive)")
    pg.add_argument("--waf-aware",  action="store_true",
                    help="WAF evasion: random delays, UA rotation, smart retries")
    pg.add_argument("--timeout",    type=int, default=15,
                    help="Request timeout in seconds (default: 15)")

    og = parser.add_argument_group("Output")
    og.add_argument("-o","--output", help="Save results to file")
    og.add_argument("--format",      choices=["txt","json"], default="txt",
                    help="Output format: txt (default) or json")
    og.add_argument("--dump",        action="store_true",
                    help="Download and save raw JS file contents to disk")
    og.add_argument("--dump-dir",    default="jsreaper_dumps",
                    help="Directory for JS dumps (default: jsreaper_dumps/)")

    return parser

# ═════════════════════════════════════════════════════════════════════════════
#  MAIN
# ═════════════════════════════════════════════════════════════════════════════

def main():
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    print(get_banner())

    parser = build_parser()
    args   = parser.parse_args()

    # version check — early exit
    if args.version:
        check_version()
        sys.exit(0)

    # collect targets from all possible sources
    targets  = []
    js_only_urls = []   # direct JS URLs from Burp — analyzed differently

    if args.url:
        targets.append(args.url)

    if args.list:
        path = os.path.normpath(args.list)
        try:
            with open(path, "r", encoding="utf-8") as f:
                targets.extend([l.strip() for l in f if l.strip() and not l.startswith("#")])
        except FileNotFoundError:
            error(f"File not found: {path}")
            sys.exit(1)

    if args.burp:
        path = os.path.normpath(args.burp)
        try:
            parsed = parse_burp_file(path)
            js_only_urls.extend(parsed)
            info(f"Parsed {len(parsed)} JS URLs from Burp file: {path}")
        except FileNotFoundError:
            error(f"Burp file not found: {path}")
            sys.exit(1)

    if args.burp_paste:
        parsed = parse_burp_js_input(args.burp_paste)
        js_only_urls.extend(parsed)
        info(f"Parsed {len(parsed)} JS URLs from --burp-paste")

    targets = list(dict.fromkeys(targets))

    if not targets and not js_only_urls:
        parser.print_help()
        print(f"\n{FG_CRITICAL}[!] Provide a target: -u URL  |  -l file  |  --burp file  |  --burp-paste text{RESET}")
        sys.exit(1)

    info(f"Platform : {get_platform_info()}")
    info(f"Targets  : {len(targets)}  |  Direct JS URLs (Burp): {len(js_only_urls)}")
    info(f"Threads  : {args.threads}  |  WAF-aware: {args.waf_aware}  |  Timeout: {args.timeout}s")
    if args.analyze:    info("Mode: JS Analysis + Cross-File Correlation ON")
    if args.status:     info("Mode: Status check ON")
    if args.deep:       info("Mode: Deep crawl ON")
    if args.probe:      info("Mode: Sensitive file probe ON")
    if args.subdomains: info("Mode: Subdomain recon ON")
    if args.dump:       info(f"Mode: JS dump ON → {args.dump_dir}{os.sep}")
    print()

    session     = build_session(waf_aware=args.waf_aware)
    all_results = []
    start_time  = time.time()

    # ── handle direct Burp JS URLs ─────────────────────────────────────────
    if js_only_urls and args.analyze:
        section_header(f"ANALYZING {len(js_only_urls)} BURP JS URLs", FG_SECTION)

        # status check on JS URLs if requested
        if args.status:
            run_status_check(js_only_urls, session, threads=args.threads)

        burp_analysis = []

        def analyze_burp(js_url):
            js_url, resp = try_http_fallback(js_url, session)
            if not resp or not resp.text:
                return None
            return analyze_js_content(js_url, resp.text,
                                      beautify=args.beautify,
                                      source_domain=get_domain(js_url))

        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = {executor.submit(analyze_burp, jf): jf for jf in js_only_urls}
            for future in as_completed(futures):
                res = future.result()
                if res:
                    burp_analysis.append(res)
                    if res["findings"] or (args.verbose and res["endpoints"]):
                        print_analysis(res, show_endpoints=args.endpoints)

        # cross-file correlation on Burp results
        if len(burp_analysis) > 1:
            correlations = correlate_findings(burp_analysis)
            if correlations:
                print_correlations(correlations)

        # aggregate summary for burp results
        total_score = sum(r["score"] for r in burp_analysis)
        total_f     = sum(len(r["findings"]) for r in burp_analysis)
        critical    = sum(1 for r in burp_analysis for f in r["findings"] if f["severity"]=="critical")
        high        = sum(1 for r in burp_analysis for f in r["findings"] if f["severity"]=="high")
        print_summary({
            "js_files_found": len(js_only_urls), "other_files_found":0,
            "total_findings": total_f, "critical":critical, "high":high, "medium":0,
            "risk_score": total_score, "subdomains_found":0,
            "sensitive_files_found":0, "correlations_found": len(correlations) if len(burp_analysis)>1 else 0,
        }, "Burp Suite JS Analysis")

        all_results.append({
            "target":"burp_input","domain":"multiple",
            "js_files":js_only_urls,"other_files":[],
            "analysis":burp_analysis,"subdomains":[],
            "sensitive_files":[],"correlations":correlations if len(burp_analysis)>1 else [],
            "summary":{"risk_score":total_score,"total_findings":total_f}
        })

    # ── handle regular targets ──────────────────────────────────────────────
    for i, target in enumerate(targets, 1):
        if len(targets) > 1:
            print(f"\n{FG_SECTION}[{i}/{len(targets)}] → {target}{RESET}")

        # status check on target + its subdomains if requested
        if args.status:
            check_targets = [normalize_url(target)]
            run_status_check(check_targets, session, threads=args.threads)

        try:
            result = scan_target(target, args, session)
            all_results.append(result)

            # status check on discovered subdomains
            if args.status and result.get("subdomains"):
                sub_urls = [f"https://{s}" for s in result["subdomains"]]
                info(f"Status checking {len(sub_urls)} discovered subdomains...")
                run_status_check(sub_urls, session, threads=args.threads)

        except KeyboardInterrupt:
            warn("Ctrl+C — saving partial results...")
            break
        except Exception as e:
            error(f"Scan failed for {target}: {e}")
            if args.verbose:
                import traceback; traceback.print_exc()

    elapsed = time.time() - start_time
    print(f"\n{FG_SUCCESS}[✓] Done in {elapsed:.1f}s{RESET}")

    if args.output and all_results:
        save_output(all_results, args.output, fmt=args.format)

    if len(all_results) > 1:
        section_header(f"AGGREGATE  ({len(all_results)} targets)", LEMON)
        total_js    = sum(len(r.get("js_files",[])) for r in all_results)
        total_f     = sum(r.get("summary",{}).get("total_findings",0) for r in all_results)
        total_crit  = sum(r.get("summary",{}).get("critical",0) for r in all_results)
        total_high  = sum(r.get("summary",{}).get("high",0) for r in all_results)
        total_score = sum(r.get("summary",{}).get("risk_score",0) for r in all_results)
        print(f"  {FG_DIM}JS Files :{RESET} {FG_URL}{total_js}{RESET}")
        print(f"  {FG_DIM}Findings :{RESET} {FG_HIGH}{total_f}{RESET}")
        print(f"  {FG_DIM}Critical :{RESET} {SEVERITY_BADGE['critical']} {total_crit} {RESET}")
        print(f"  {FG_DIM}High     :{RESET} {SEVERITY_BADGE['high']} {total_high} {RESET}")
        print(f"  {FG_DIM}Score    :{RESET} {FG_MEDIUM}{total_score}{RESET}")

    print(f"\n{FG_WAF}  ⚠  For research and educational purposes only.{RESET}")
    print(f"{FG_WAF}  ⚠  Only use on targets you are authorized to test.{RESET}")
    print(f"{FG_DIM}  {TOOL_NAME} v{TOOL_VERSION} by @dr34lm — https://x.com/dr34lm{RESET}\n")

if __name__ == "__main__":
    main()
