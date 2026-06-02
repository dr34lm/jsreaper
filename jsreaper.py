#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# ╔══════════════════════════════════════════════════════════════════════╗
# ║                         JSReaper v3.0                               ║
# ║         JavaScript Security Analysis Tool                           ║
# ║                                                                      ║
# ║  Written by @dr34lm                                                  ║
# ║  https://x.com/dr34lm                                               ║
# ║                                                                      ║
# ║  Focused on finding real security issues in JS files:               ║
# ║    1. Exposed endpoints (with live HTTP status check)               ║
# ║    2. SQL injection parameters                                       ║
# ║    3. Path traversal / LFI indicators                               ║
# ║    4. Remote Code Execution indicators                               ║
# ║    5. Information disclosure (secrets, keys, tokens)                ║
# ║                                                                      ║
# ║  For educational and authorized research use only.                  ║
# ╚══════════════════════════════════════════════════════════════════════╝

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
from urllib.parse import urljoin, urlparse, urlencode
from collections import defaultdict
import threading

TOOL_VERSION       = "3.0"
TOOL_NAME          = "JSReaper"
LATEST_VERSION_URL = "https://raw.githubusercontent.com/dr34lm/jsreaper/main/VERSION"
LATEST_SCRIPT_URL  = "https://raw.githubusercontent.com/dr34lm/jsreaper/main/jsreaper.py"

IS_WINDOWS = platform.system() == "Windows"

# ─────────────────────────────────────────────────────────────────────────────
#  DEPENDENCIES
# ─────────────────────────────────────────────────────────────────────────────

try:
    import requests
    from bs4 import BeautifulSoup
    from colorama import init, Fore, Back, Style
    init(autoreset=True, convert=IS_WINDOWS, strip=False)
except ImportError as e:
    print(f"[!] Missing: {e}")
    print("[*] pip3 install requests beautifulsoup4 colorama urllib3")
    sys.exit(1)

try:
    import jsbeautifier
    HAS_BEAUTIFIER = True
except ImportError:
    HAS_BEAUTIFIER = False

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─────────────────────────────────────────────────────────────────────────────
#  COLORS
# ─────────────────────────────────────────────────────────────────────────────

RESET    = Style.RESET_ALL
WHITE    = "\033[38;5;231m"
DIM      = "\033[38;5;242m"
RED      = "\033[38;5;196m"
ORANGE   = "\033[38;5;208m"
YELLOW   = "\033[38;5;220m"
BLUE     = "\033[38;5;75m"
GREEN    = "\033[38;5;154m"
CYAN     = "\033[38;5;117m"
PURPLE   = "\033[38;5;213m"

BG_RED    = "\033[48;5;196m\033[38;5;231m"
BG_ORANGE = "\033[48;5;202m\033[38;5;231m"
BG_YELLOW = "\033[48;5;220m\033[38;5;232m"
BG_BLUE   = "\033[48;5;33m\033[38;5;231m"
BG_GRAY   = "\033[48;5;238m\033[38;5;252m"

SEV_COLOR = {
    "critical": RED,
    "high":     ORANGE,
    "medium":   YELLOW,
    "low":      BLUE,
    "info":     DIM,
}

SEV_BADGE = {
    "critical": BG_RED,
    "high":     BG_ORANGE,
    "medium":   BG_YELLOW,
    "low":      BG_BLUE,
    "info":     BG_GRAY,
}

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

STATUS_COLOR = {
    200: GREEN, 201: GREEN, 204: GREEN,
    301: YELLOW, 302: YELLOW, 307: YELLOW, 308: YELLOW,
    400: ORANGE, 401: ORANGE, 403: ORANGE,
    404: DIM,
    500: RED, 502: RED, 503: ORANGE,
}

# ─────────────────────────────────────────────────────────────────────────────
#  BANNER
# ─────────────────────────────────────────────────────────────────────────────

def banner():
    v = TOOL_VERSION
    return f"""
{WHITE}      ######    #####    ######    #######    ####    ######    #######   ######
{WHITE}        ##     ##       ##   ##    ##        ##  ##   ##   ##   ##        ##   ##
{WHITE}        ##      ####    ##   ##    #####    ##    ##  ##   ##   #####     ##   ##
{WHITE}        ##          ##  ######     ##       ########  ######    ##        ######
{WHITE}   ##   ##          ##  ## ##      ##       ##    ##  ##        ##        ## ##
{WHITE}    #####       ####    ##  ##     #######  ##    ##  ##        #######   ##  ##
{DIM}
{DIM}          JS Security Analysis Tool  v{v}  |  @dr34lm
{DIM}          Endpoints · SQL · Path Traversal · RCE · Info Disclosure
{RESET}"""

# ─────────────────────────────────────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────────────────────────────────────

print_lock = threading.Lock()

def W():
    try:
        return max(60, min(shutil.get_terminal_size(fallback=(100,40)).columns, 120))
    except Exception:
        return 100

def cp(msg, color=WHITE, pre=""):
    with print_lock:
        w = W() - len(pre) - 2
        if len(str(msg)) > w:
            msg = str(msg)[:w-3] + "..."
        print(f"{color}{pre}{msg}{RESET}")

def info(m):    cp(m, BLUE,   "[*] ")
def ok(m):      cp(m, GREEN,  "[+] ")
def warn(m):    cp(m, YELLOW, "[!] ")
def err(m):     cp(m, RED,    "[-] ")

def sep(c="─"):
    with print_lock:
        print(f"{DIM}{c * W()}{RESET}")

def hdr(title, color=WHITE):
    w = W()
    p = max(0, (w - len(title) - 4) // 2)
    with print_lock:
        print(f"\n{color}{'═'*w}")
        print(f"{'═'*p}  {title}  {'═'*max(0, w-p-len(title)-4)}")
        print(f"{'═'*w}{RESET}")

def normalize(url):
    url = url.strip()
    if url.startswith("//"):
        return "https:" + url
    if not url.startswith(("http://", "https://")):
        return "https://" + url
    return url.rstrip("/")

def domain_of(url):
    return urlparse(url).netloc

def get_platform():
    return f"{platform.system()} {platform.release()} / Python {platform.python_version()}"

# ─────────────────────────────────────────────────────────────────────────────
#  USER AGENTS
# ─────────────────────────────────────────────────────────────────────────────

UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
]

def make_session(waf=False):
    s = requests.Session()
    s.headers.update({
        "User-Agent": random.choice(UAS),
        "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
    })
    if waf:
        s.headers["Referer"] = "https://www.google.com/"
    return s

def fetch(url, session, timeout=12, retries=2, allow_redirects=True):
    for attempt in range(retries):
        try:
            r = session.get(url, timeout=timeout, verify=False,
                           allow_redirects=allow_redirects)
            session.headers["User-Agent"] = random.choice(UAS)
            return r
        except requests.exceptions.SSLError:
            try:
                return session.get(url, timeout=timeout, verify=False,
                                  allow_redirects=allow_redirects)
            except Exception:
                pass
        except Exception:
            if attempt < retries - 1:
                time.sleep(1)
    return None

def fetch_with_fallback(url, session, timeout=12):
    """Try HTTPS first, fall back to HTTP if it fails."""
    r = fetch(url, session, timeout=timeout)
    if r is not None:
        return url, r
    if url.startswith("https://"):
        http = "http://" + url[8:]
        r = fetch(http, session, timeout=timeout)
        if r is not None:
            return http, r
    return url, None

# ─────────────────────────────────────────────────────────────────────────────
#  WHAT MAKES A FILE A LIBRARY vs APP CODE
#  We don't analyse library files for app-specific vulnerabilities.
#  A developer cannot fix jQuery's internals.
# ─────────────────────────────────────────────────────────────────────────────

LIBRARY_NAMES = {
    "jquery", "bootstrap", "aos", "swiper", "toastr", "lodash", "underscore",
    "moment", "axios", "react", "vue", "angular", "d3", "chart", "leaflet",
    "three", "gsap", "slick", "select2", "datatables", "fullcalendar",
    "highlight", "prism", "codemirror", "tinymce", "ckeditor", "socket.io",
    "popper", "modernizr", "normalize", "lazysizes", "svg-loader",
    "magnific-popup", "nice-select", "polyfill", "core-js", "regenerator",
    "babel", "webpack", "fontawesome", "materialize", "bulma", "sweetalert",
    "animate", "waypoints", "isotope", "masonry", "lightbox", "fancybox",
    "owl-carousel", "splide", "glide", "plugin", "vendor", "vendors",
}

LIBRARY_URL_HINTS = [
    "node_modules", "node_vendors", "/vendor/", "/vendors/",
    "/lib/", "/libs/", "/dist/", "/cdn/",
]

def is_library(url, content_head=""):
    fname = url.split("/")[-1].lower()
    # strip hash suffixes like -3bfe1920e4fc94cca843
    clean = re.sub(r"[-_~][a-f0-9]{6,}", "", fname)
    clean = re.sub(r"[-_.](?:v?\d[\d.]*|min|bundle|esm|cjs|umd)", "", clean)
    clean = clean.replace(".js","").replace(".chunk","").strip("-_~.")

    for lib in LIBRARY_NAMES:
        if lib in clean or clean in lib:
            return True, f"known library: {lib}"

    url_l = url.lower()
    for hint in LIBRARY_URL_HINTS:
        if hint in url_l:
            return True, f"vendor path: {hint}"

    # content-based: ACE editor, webpack vendor bundle
    if content_head:
        sigs = [
            r"Ace \(Ajax\.org Cloud9 Editor\)",
            r"webpackJsonp.*node_vendors",
            r"This file is part of (jQuery|Bootstrap|Vue)",
            r"@license.*MIT.*(jquery|bootstrap|react|vue|angular)",
            r"Leaflet - a JS library for",
            r"Copyright.*Bootstrap",
        ]
        for sig in sigs:
            if re.search(sig, content_head[:2000], re.IGNORECASE):
                return True, "library content signature"

    return False, ""

# ─────────────────────────────────────────────────────────────────────────────
#  CORE ANALYSIS — THE FOUR THINGS WE LOOK FOR
# ─────────────────────────────────────────────────────────────────────────────

def extract_endpoints(content, base_url):
    """
    Extract URL endpoints and their parameters from JS content.
    Only returns endpoints that look like real API/app routes —
    not every string that contains a slash.
    """
    found = {}   # endpoint -> {params, method, line, context}
    seen  = set()
    lines = content.split("\n")
    base  = f"{urlparse(base_url).scheme}://{urlparse(base_url).netloc}"

    def add(ep, params, method, line_num, ctx):
        ep = ep.strip().rstrip("/")
        if not ep or len(ep) < 3 or len(ep) > 150:
            return
        # must look like a path — starts with / or http
        if not (ep.startswith("/") or ep.startswith("http")):
            return
        # skip pure file extensions
        if re.match(r'^/[^/]+\.(jpg|png|gif|svg|css|woff|ttf|ico|mp4|mp3)$', ep, re.I):
            return
        key = ep.lower()
        if key in seen:
            # merge params
            if ep in found:
                found[ep]["params"] = list(set(found[ep]["params"] + params))
            return
        seen.add(key)
        found[ep] = {
            "params":  list(set(params)),
            "method":  method,
            "line":    line_num,
            "context": ctx[:100],
        }

    def line_of(pos):
        return content[:pos].count("\n") + 1

    def ctx_at(pos):
        ln = line_of(pos)
        return lines[ln-1].strip()[:120] if ln <= len(lines) else ""

    # ── Pattern 1: fetch() calls ──────────────────────────────────────────
    for m in re.finditer(
        r'fetch\s*\(\s*["\']([^"\']{3,100})["\']',
        content, re.IGNORECASE
    ):
        ep = m.group(1)
        # look for body params nearby
        nearby = content[m.start():min(m.start()+300, len(content))]
        bm = re.search(r'body\s*:\s*JSON\.stringify\s*\(\s*\{([^}]{0,200})\}', nearby)
        params = list(set(re.findall(r'(\w+)\s*:', bm.group(1)))) if bm else []
        method = "POST" if bm else "GET"
        add(ep, params, method, line_of(m.start()), ctx_at(m.start()))

    # ── Pattern 2: fetch() with template literal ──────────────────────────
    for m in re.finditer(r'fetch\s*\(\s*`([^`]{3,100})`', content, re.IGNORECASE):
        raw = m.group(1)
        params = re.findall(r'\$\{(\w+)\}', raw)
        ep = re.sub(r'\$\{[^}]+\}', '*', raw)
        add(ep, params, "GET", line_of(m.start()), ctx_at(m.start()))

    # ── Pattern 3: axios calls ────────────────────────────────────────────
    for m in re.finditer(
        r'axios\.(get|post|put|delete|patch)\s*\(\s*["\']([^"\']{3,100})["\']',
        content, re.IGNORECASE
    ):
        method = m.group(1).upper()
        ep     = m.group(2)
        nearby = content[m.start():min(m.start()+250, len(content))]
        bm     = re.search(r'\{([^}]{0,200})\}', nearby)
        params = list(set(re.findall(r'(\w+)\s*:', bm.group(1)))) if bm else []
        add(ep, params, method, line_of(m.start()), ctx_at(m.start()))

    # ── Pattern 4: XMLHttpRequest ─────────────────────────────────────────
    for m in re.finditer(
        r'\.open\s*\(\s*["\']([A-Z]+)["\'],\s*["\']([^"\']{3,100})["\']',
        content, re.IGNORECASE
    ):
        add(m.group(2), [], m.group(1).upper(), line_of(m.start()), ctx_at(m.start()))

    # ── Pattern 5: URL with query string ─────────────────────────────────
    for m in re.finditer(
        r'["\'](\/?[a-zA-Z0-9_\-/]+\?[a-zA-Z0-9_=&%+\-]{3,100})["\']',
        content, re.IGNORECASE
    ):
        full = m.group(1)
        if "?" in full:
            path, qs = full.split("?", 1)
            params = re.findall(r'(\w+)=', qs)
            add(path, params, "GET", line_of(m.start()), ctx_at(m.start()))

    # ── Pattern 6: URL constructor — new URL("/path/".concat(...)) ────────
    for m in re.finditer(
        r'new\s+URL\s*\(\s*["\']([^"\']{3,80})["\']',
        content, re.IGNORECASE
    ):
        ep = m.group(1)
        add(ep, [], "GET", line_of(m.start()), ctx_at(m.start()))

    # ── Pattern 7: string path + concat/variable ─────────────────────────
    for m in re.finditer(
        r'["\'](\/?(?:api|v\d+|admin|rest|graphql|internal|backend)[\/\w\-\.]+)["\']',
        content, re.IGNORECASE
    ):
        ep = m.group(1)
        # only if it looks like a real API path
        if ep.count("/") >= 2 or re.search(r'/v\d+/', ep):
            add(ep, [], "GET", line_of(m.start()), ctx_at(m.start()))

    # ── Pattern 8: route definitions ─────────────────────────────────────
    for m in re.finditer(
        r'(?:path|route)\s*:\s*["\']([^"\']{2,80})["\']',
        content, re.IGNORECASE
    ):
        ep = m.group(1)
        params = re.findall(r':(\w+)', ep)
        if ep.startswith("/"):
            add(ep, params, "GET", line_of(m.start()), ctx_at(m.start()))

    # ── Pattern 9: URLSearchParams / FormData ────────────────────────────
    for m in re.finditer(
        r'(?:searchParams|formData|params|data)\.(?:append|set)\s*\(\s*["\'](\w+)["\']',
        content, re.IGNORECASE
    ):
        param_name = m.group(1)
        # find nearby URL
        nearby = content[max(0, m.start()-200):m.start()]
        um = re.search(r'["\']([/?][^"\']{2,60})["\']', nearby)
        ep = um.group(1) if um else "(unknown)"
        add(ep, [param_name], "POST", line_of(m.start()), ctx_at(m.start()))

    return found


def find_sqli_indicators(content, base_url):
    """
    Find SQL injection indicators in JS.
    Only flags code where user-controlled data flows into a SQL query.
    A SELECT statement alone is NOT a finding — it needs + concatenation or
    template literal injection to be meaningful.
    """
    findings = []
    lines    = content.split("\n")
    seen     = set()

    # user-controlled input sources we look for near SQL keywords
    USER_INPUT = r'(?:req\.|request\.|params\.|query\.|body\.|input|search|filter|order|sort|user)'

    patterns = [
        # Template literal with user input in SQL context
        (r'\.query\s*\(\s*`[^`]{0,60}\$\{[^}]*' + USER_INPUT,
         "SQL query using template literal with user-controlled input — classic SQLi vector",
         "critical"),

        # String concatenation building a SQL query
        (r'(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)\s[^;"\n]{0,50}\+\s*' + USER_INPUT,
         "SQL keyword with string concatenation and user input — SQLi indicator",
         "critical"),

        # execute() or query() called with concatenated user input
        (r'(?:execute|query)\s*\(\s*["\'][^"\']*["\'\s]*\+\s*' + USER_INPUT,
         "SQL execute/query with string concatenation from user input",
         "high"),

        # ORDER BY parameter directly from user input (common SQLi)
        (r'(?:order|sort|orderby|order_by)\s*[=:]\s*' + USER_INPUT,
         "ORDER BY/sort parameter comes from user input — SQL injection risk",
         "high"),

        # LIKE clause with user input
        (r'LIKE\s+["\']%["\']?\s*\+\s*' + USER_INPUT,
         "SQL LIKE clause with user-controlled input",
         "high"),
    ]

    for pattern, description, severity in patterns:
        try:
            for m in re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE):
                matched = m.group(0)[:150]
                line_num = content[:m.start()].count("\n") + 1
                line_ctx = lines[line_num-1].strip()[:150] if line_num <= len(lines) else ""
                key = hashlib.md5(matched.encode()).hexdigest()
                if key in seen:
                    continue
                seen.add(key)
                findings.append({
                    "type":        "SQL Injection",
                    "severity":    severity,
                    "description": description,
                    "match":       matched,
                    "line":        line_num,
                    "context":     line_ctx,
                })
        except re.error:
            continue

    return findings


def find_path_traversal(content, base_url):
    """
    Find path traversal and LFI indicators in JS.
    Only flags when user-controlled input reaches file system functions.
    """
    findings = []
    lines    = content.split("\n")
    seen     = set()

    USER_INPUT = r'(?:req\.|request\.|params\.|query\.|body\.|input|file|path|filename|template|page|include|load)'

    patterns = [
        # readFile with user input
        (r'(?:readFile|readFileSync|createReadStream)\s*\([^)]{0,60}' + USER_INPUT,
         "File read with user-controlled path — path traversal / LFI",
         "critical"),

        # path.join with user input
        (r'path\.(?:join|resolve)\s*\([^)]{0,80}' + USER_INPUT,
         "path.join() with user input — path traversal risk",
         "high"),

        # __dirname + user input
        (r'(?:__dirname|__filename)\s*\+\s*(?:req\.|params\.|query\.|input)',
         "__dirname concatenated with user input — path traversal",
         "high"),

        # sendFile or download with user input
        (r'(?:sendFile|download|res\.download)\s*\([^)]{0,60}' + USER_INPUT,
         "File send/download with user-controlled path",
         "high"),

        # require() with user input (also RCE risk)
        (r'require\s*\(\s*(?:req\.|request\.|params\.|query\.|input)',
         "Dynamic require() with user input — path traversal AND potential RCE",
         "critical"),
    ]

    for pattern, description, severity in patterns:
        try:
            for m in re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE):
                matched  = m.group(0)[:150]
                line_num = content[:m.start()].count("\n") + 1
                line_ctx = lines[line_num-1].strip()[:150] if line_num <= len(lines) else ""
                key = hashlib.md5(matched.encode()).hexdigest()
                if key in seen:
                    continue
                seen.add(key)
                findings.append({
                    "type":        "Path Traversal / LFI",
                    "severity":    severity,
                    "description": description,
                    "match":       matched,
                    "line":        line_num,
                    "context":     line_ctx,
                })
        except re.error:
            continue

    return findings


def find_rce_indicators(content, base_url):
    """
    Find Remote Code Execution indicators in JS.
    Only flags eval/exec/spawn patterns where user input reaches them.
    """
    findings = []
    lines    = content.split("\n")
    seen     = set()

    USER_INPUT = r'(?:req\.|request\.|params\.|query\.|body\.|input|user|cmd|command|exec)'

    patterns = [
        # eval() with user input — the clearest RCE indicator
        (r'eval\s*\(\s*(?:req\.|request\.|params\.|query\.|body\.|input|user)',
         "eval() called with user-controlled input — direct RCE",
         "critical"),

        # new Function() with user input
        (r'new\s+Function\s*\([^)]{0,60}' + USER_INPUT,
         "new Function() with user input — code injection / RCE",
         "critical"),

        # child_process exec/spawn with user input
        (r'(?:exec|execSync|spawn|spawnSync)\s*\([^)]{0,60}' + USER_INPUT,
         "child_process exec/spawn with user-controlled command — OS command injection",
         "critical"),

        # child_process imported at all (flag the import, lower severity)
        (r'require\s*\(\s*["\']child_process["\']',
         "child_process module imported — check if user input reaches exec/spawn",
         "medium"),

        # vm.runInNewContext or similar Node.js sandbox escapes
        (r'vm\s*\.\s*(?:runInNewContext|runInThisContext|Script)',
         "vm module usage — potential sandbox escape if user input reaches it",
         "medium"),

        # setTimeout/setInterval with string (eval-like)
        (r'(?:setTimeout|setInterval)\s*\(\s*(?:req\.|params\.|query\.|input)',
         "setTimeout/setInterval with user input string — eval-equivalent RCE",
         "high"),
    ]

    for pattern, description, severity in patterns:
        try:
            for m in re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE):
                matched  = m.group(0)[:150]
                line_num = content[:m.start()].count("\n") + 1
                line_ctx = lines[line_num-1].strip()[:150] if line_num <= len(lines) else ""
                key = hashlib.md5(matched.encode()).hexdigest()
                if key in seen:
                    continue
                seen.add(key)
                findings.append({
                    "type":        "RCE Indicator",
                    "severity":    severity,
                    "description": description,
                    "match":       matched,
                    "line":        line_num,
                    "context":     line_ctx,
                })
        except re.error:
            continue

    return findings


def find_info_disclosure(content, base_url):
    """
    Find genuine information disclosure — credentials, keys, tokens
    with specific formats that cannot be false positives.
    Only patterns where the FORMAT itself is proof of authenticity.
    """
    findings = []
    lines    = content.split("\n")
    seen     = set()

    patterns = [
        # AWS — AKIA prefix is globally unique
        (r'(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}',
         "AWS Access Key ID — unique format, near-zero false positives", "critical"),

        # AWS secret — variable name + 40-char base64
        (r'aws[_\-]?secret[_\-]?(?:access[_\-]?)?key\s*[=:]\s*["\']([A-Za-z0-9/+=]{40})["\']',
         "AWS Secret Access Key", "critical"),

        # Stripe live secret — sk_live_ prefix
        (r'sk_live_[0-9a-zA-Z]{24,}',
         "Stripe Live Secret Key — active payment credential", "critical"),

        # Stripe restricted key
        (r'rk_live_[0-9a-zA-Z]{24,}',
         "Stripe Restricted Key — active payment credential", "critical"),

        # SendGrid — SG. + two base64 blocks
        (r'SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}',
         "SendGrid API Key", "critical"),

        # GitHub tokens — all have unique prefixes
        (r'gh[pousr]_[A-Za-z0-9]{36,}',
         "GitHub Personal Access Token", "critical"),

        (r'github_pat_[A-Za-z0-9_]{82,}',
         "GitHub Fine-Grained Personal Access Token", "critical"),

        # Google API key — AIza prefix
        (r'AIza[0-9A-Za-z\-_]{35}',
         "Google API Key", "critical"),

        # Google OAuth token
        (r'ya29\.[0-9A-Za-z\-_]{40,}',
         "Google OAuth Access Token — live token", "critical"),

        # Slack webhook — very specific URL format
        (r'https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{20,}',
         "Slack Webhook URL — can post messages to Slack", "critical"),

        # Slack token
        (r'xox[baprs]-[0-9]{8,12}-[0-9A-Za-z\-]{10,}',
         "Slack API Token", "critical"),

        # Private keys — PEM format is globally unique
        (r'-----BEGIN\s+(?:RSA\s+|EC\s+|OPENSSH\s+|DSA\s+)?PRIVATE KEY-----',
         "Private Key (PEM format) — hardcoded in JS", "critical"),

        # GCP service account JSON
        (r'"type"\s*:\s*"service_account"',
         "Google Cloud Service Account JSON key", "critical"),

        # Shopify tokens
        (r'shpat_[A-Za-z0-9]{32}',
         "Shopify Admin API Access Token", "critical"),

        # OpenAI key
        (r'sk-[A-Za-z0-9]{48}',
         "OpenAI API Key", "critical"),

        # NPM token
        (r'npm_[A-Za-z0-9]{36,}',
         "NPM Access Token", "critical"),

        # JWT — three base64url parts, starts with eyJ (base64 of '{')
        (r'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9._\-]{10,}\.[A-Za-z0-9_\-]{10,}',
         "JSON Web Token (JWT) — may be a live session/auth token", "high"),

        # Database connection strings with credentials
        (r'mongodb(?:\+srv)?://[A-Za-z0-9_\-\.]+:[A-Za-z0-9_\-\.!@#$%]{4,}@[^\s"\'<]{8,}',
         "MongoDB connection string with credentials", "critical"),

        (r'mysql://[A-Za-z0-9_\-\.]+:[A-Za-z0-9_\-\.!@#$%]{4,}@[^\s"\'<]{8,}',
         "MySQL connection string with credentials", "critical"),

        (r'postgresql://[A-Za-z0-9_\-\.]+:[A-Za-z0-9_\-\.!@#$%]{4,}@[^\s"\'<]{8,}',
         "PostgreSQL connection string with credentials", "critical"),

        # URL with embedded credentials
        (r'https?://[A-Za-z0-9_\-\.]+:[A-Za-z0-9_\-\.!@#$%]{6,}@[A-Za-z0-9\-\.]+\.[a-z]{2,}',
         "URL with embedded credentials (user:password@host)", "critical"),

        # Source map reference — information disclosure if accessible
        (r'//[#@]\s*sourceMappingURL=(\S+\.map)',
         "Source map reference — if accessible, exposes full unminified source code", "medium"),

        # Internal IPs hardcoded
        (r'["\'](?:192\.168|10\.\d+|172\.(?:1[6-9]|2\d|3[01]))\.\d+\.\d+["\']',
         "Internal/private IP address hardcoded in JS", "medium"),

        # Firebase config block
        (r'firebaseConfig\s*=\s*\{[^}]{50,}\}',
         "Firebase configuration block — contains project credentials", "high"),
    ]

    for pattern, description, severity in patterns:
        try:
            for m in re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE):
                matched  = m.group(0)[:150]
                line_num = content[:m.start()].count("\n") + 1
                line_ctx = lines[line_num-1].strip()[:150] if line_num <= len(lines) else ""

                # skip if it's clearly a placeholder
                if re.search(
                    r'(?:example|placeholder|your[_\-]?key|insert[_\-]?here|'
                    r'xxxx|1234|abcd|test123|changeme)',
                    matched, re.IGNORECASE
                ):
                    continue

                key = hashlib.md5(matched.encode()).hexdigest()
                if key in seen:
                    continue
                seen.add(key)

                findings.append({
                    "type":        "Information Disclosure",
                    "severity":    severity,
                    "description": description,
                    "match":       matched,
                    "line":        line_num,
                    "context":     line_ctx,
                })
        except re.error:
            continue

    return findings


# ─────────────────────────────────────────────────────────────────────────────
#  LIVE ENDPOINT PROBE
#  Actually request each discovered endpoint and show the real HTTP status.
#  This is the only way to know if an endpoint actually exists.
# ─────────────────────────────────────────────────────────────────────────────

def probe_endpoint(url, session, timeout=8):
    """Probe a URL and return (status, size, redirect, ms)."""
    t = time.time()
    try:
        r = session.get(url, timeout=timeout, verify=False, allow_redirects=False)
        ms    = int((time.time() - t) * 1000)
        redir = r.headers.get("Location","") if r.status_code in [301,302,303,307,308] else ""
        return r.status_code, len(r.content), redir, ms
    except Exception:
        return 0, 0, "", int((time.time()-t)*1000)


# ─────────────────────────────────────────────────────────────────────────────
#  JS FILE CRAWLER
# ─────────────────────────────────────────────────────────────────────────────

def crawl_js_files(url, session):
    """Crawl a page and return set of JS file URLs."""
    js_files = set()
    url, resp = fetch_with_fallback(url, session)
    if not resp:
        return js_files, None

    try:
        soup = BeautifulSoup(resp.text, "html.parser")
    except Exception:
        return js_files, resp

    base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"

    # script src tags
    for tag in soup.find_all("script", src=True):
        src = tag.get("src","")
        if src:
            full = urljoin(url, src)
            if ".js" in full.split("?")[0]:
                js_files.add(full)

    # regex scan of raw HTML for any .js reference
    for pat in [
        r'src\s*[=:]\s*["\']([^"\']+\.js(?:\?[^"\']*)?)["\']',
        r'require\s*\(\s*["\']([^"\']+\.js)["\']',
        r'import\s+[^"\']*["\']([^"\']+\.js)["\']',
    ]:
        try:
            for m in re.finditer(pat, resp.text, re.IGNORECASE):
                path = m.group(1)
                if path.startswith("//"):      full = "https:" + path
                elif path.startswith("/"):     full = base + path
                elif path.startswith("http"):  full = path
                else:                          full = urljoin(url, path)
                if ".js" in full.split("?")[0]:
                    js_files.add(full)
        except re.error:
            continue

    return js_files, resp


# ─────────────────────────────────────────────────────────────────────────────
#  PRINT FINDINGS
# ─────────────────────────────────────────────────────────────────────────────

def print_findings(findings, file_url, domain):
    """Print all findings for one JS file, sorted by severity."""
    if not findings:
        return

    w = W()
    fname = file_url.split("/")[-1]

    sorted_f = sorted(findings, key=lambda x: SEV_ORDER.get(x["severity"],9))

    for f in sorted_f:
        sev    = f["severity"]
        badge  = SEV_BADGE.get(sev,"")
        color  = SEV_COLOR.get(sev, WHITE)
        sev_l  = f" {sev.upper():<8} "

        print(f"  {badge}{sev_l}{RESET}  "
              f"{CYAN}{f['type']:<25}{RESET}  "
              f"{DIM}L{f['line']:4d}  {fname[:20]}{RESET}")
        print(f"    {color}{f['description']}{RESET}")
        if f.get("match"):
            print(f"    {DIM}match  : {f['match'][:w-14]}{RESET}")
        if f.get("context") and f["context"].strip() != f.get("match","").strip():
            print(f"    {DIM}context: {f['context'][:w-14]}{RESET}")
        print()


def print_endpoints_table(probed, domain):
    """Print probed endpoints with their live HTTP status codes."""
    if not probed:
        return

    w = W()
    hdr("LIVE ENDPOINT STATUS CHECK", CYAN)
    print(f"  {DIM}{'STATUS':<8} {'MS':>5}  {'ENDPOINT':<45} {'PARAMS'}{RESET}")
    print(f"  {DIM}{'─'*8} {'─'*5}  {'─'*45} {'─'*20}{RESET}")

    # sort: 200 first, then 401/403, then others
    order = lambda r: (0 if r["status"]==200 else 1 if r["status"] in [401,403] else 2 if r["status"]==500 else 3)
    for r in sorted(probed, key=order):
        status = r["status"]
        sc     = STATUS_COLOR.get(status, DIM)
        icon   = "●" if status==200 else "🔒" if status in [401,403] else "↩" if status in [301,302,307,308] else "💥" if status==500 else "✗"
        ms_s   = f"{r['ms']}ms" if r['ms'] > 0 else "n/a"
        ep     = r["endpoint"][:43]
        params = ",".join(r["params"][:5]) if r["params"] else "-"

        print(f"  {sc}{icon} {status if status>0 else 'err':<6}{RESET} "
              f"{DIM}{ms_s:>5}{RESET}  "
              f"{sc}{ep:<45}{RESET} "
              f"{DIM}{params[:25]}{RESET}")

        if r.get("redirect"):
            print(f"  {DIM}         → {r['redirect'][:w-14]}{RESET}")

    print()

    # generate test cases for interesting endpoints
    interesting = [r for r in probed if r["status"] in [200, 401, 403, 500]]
    if interesting:
        print(f"  {YELLOW}{'─'*min(w-2,68)}")
        print(f"  ENDPOINTS WORTH TESTING  ({len(interesting)} responded){RESET}\n")

        IDOR_PARAMS    = {"id","user_id","uid","account_id","device_id","item_id","order_id","record_id","doc_id"}
        REDIRECT_PARAMS = {"redirect","return_url","next","url","callback","goto","return","destination"}
        FILE_PARAMS    = {"file","path","filename","template","page","include","load","dir","folder"}
        INJECT_PARAMS  = {"search","query","q","filter","where","sort","order","cmd","command","input","keyword"}

        for r in interesting:
            sc = GREEN if r["status"]==200 else YELLOW if r["status"] in [401,403] else RED
            print(f"  {sc}▸ HTTP {r['status']}  {r['full_url'][:w-20]}{RESET}")

            if r["params"]:
                print(f"    {DIM}Parameters: {', '.join(r['params'][:8])}{RESET}")
                base = r["full_url"]

                for p in r["params"]:
                    pl = p.lower()
                    if pl in IDOR_PARAMS:
                        print(f"    {YELLOW}→ IDOR: {base}?{p}=1  then try ?{p}=2, ?{p}=100, ?{p}=9999{RESET}")
                    if pl in REDIRECT_PARAMS:
                        print(f"    {YELLOW}→ Open redirect: {base}?{p}=https://evil.com{RESET}")
                    if pl in FILE_PARAMS:
                        print(f"    {YELLOW}→ Path traversal: {base}?{p}=../../../etc/passwd{RESET}")
                        print(f"    {YELLOW}→ LFI: {base}?{p}=php://filter/convert.base64-encode/resource=index{RESET}")
                    if pl in INJECT_PARAMS:
                        print(f"    {YELLOW}→ SQLi: {base}?{p}=test'{RESET}")
                        print(f"    {YELLOW}→ XSS:  {base}?{p}=%22%3E%3Cscript%3Ealert(1)%3C%2Fscript%3E{RESET}")
            else:
                if r["status"] == 200:
                    print(f"    {DIM}→ Try: {r['full_url']}?id=1 / ?debug=true / ?admin=true{RESET}")
            print()


# ─────────────────────────────────────────────────────────────────────────────
#  MAIN SCAN
# ─────────────────────────────────────────────────────────────────────────────

def scan(target_url, args, session):
    target_url = normalize(target_url)
    domain     = domain_of(target_url)

    hdr(f"TARGET: {domain}", WHITE)
    print(f"  {DIM}URL     : {target_url}")
    print(f"  {DIM}Time    : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  {DIM}Platform: {get_platform()}{RESET}\n")

    # ── Step 1: crawl for JS files ─────────────────────────────────────────
    info(f"Crawling {target_url} for JS files...")

    if args.burp_paste:
        from jsreaper import parse_burp_js_input
        js_files = set(parse_burp_js_input(args.burp_paste))
        info(f"Using {len(js_files)} JS URLs from --burp-paste")
    elif args.burp:
        js_files = set(parse_burp_file(args.burp))
        info(f"Using {len(js_files)} JS URLs from Burp file")
    else:
        js_files, _ = crawl_js_files(target_url, session)

    if not js_files:
        warn("No JS files found on this target.")
        return {}

    ok(f"Found {len(js_files)} JS file(s)")
    for jf in sorted(js_files):
        print(f"  {CYAN}  ↳ {jf[:W()-10]}{RESET}")
    print()

    # ── Step 2: analyse each JS file ──────────────────────────────────────
    hdr(f"ANALYSING {len(js_files)} JS FILE(S)", WHITE)

    all_findings  = []
    all_endpoints = {}
    lib_count     = 0
    app_count     = 0

    def analyse_one(js_url):
        js_url, resp = fetch_with_fallback(js_url, session)
        if not resp or not resp.text:
            return None

        content = resp.text

        # beautify if requested
        if args.beautify and HAS_BEAUTIFIER:
            try:
                content = jsbeautifier.beautify(content)
            except Exception:
                pass

        # dump to disk if requested
        if args.dump:
            safe = re.sub(r'[^\w\-_.]', '_', js_url)[:80]
            os.makedirs(args.dump_dir, exist_ok=True)
            with open(os.path.join(args.dump_dir, safe+".js"), "w",
                      encoding="utf-8", errors="ignore") as df:
                df.write(content)

        lib, lib_reason = is_library(js_url, content[:2000])
        size = len(content)

        return {
            "url":       js_url,
            "content":   content,
            "size":      size,
            "is_lib":    lib,
            "lib_reason":lib_reason,
        }

    results = []
    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        futs = {ex.submit(analyse_one, jf): jf for jf in js_files}
        for fut in as_completed(futs):
            r = fut.result()
            if r:
                results.append(r)

    for res in results:
        fname = res["url"].split("/")[-1]
        w     = W()

        if res["is_lib"]:
            lib_count += 1
            print(f"  {DIM}⊘ {fname:<50} LIBRARY — {res['lib_reason']} (skipped){RESET}")
            continue

        app_count += 1
        print(f"\n  {WHITE}▸ {fname}{RESET}  {DIM}({res['size']:,} bytes){RESET}")
        sep()

        content = res["content"]

        # run all four analyses
        ep_found  = extract_endpoints(content, res["url"])
        sqli      = find_sqli_indicators(content, res["url"])
        path_t    = find_path_traversal(content, res["url"])
        rce       = find_rce_indicators(content, res["url"])
        info_disc = find_info_disclosure(content, res["url"])

        # accumulate findings
        file_findings = sqli + path_t + rce + info_disc
        for f in file_findings:
            f["source_file"] = res["url"]
            f["domain"]      = domain
        all_findings.extend(file_findings)

        # accumulate endpoints
        for ep, meta in ep_found.items():
            if ep not in all_endpoints:
                all_endpoints[ep] = meta
                all_endpoints[ep]["source_file"] = res["url"]

        # print findings for this file
        if file_findings:
            print_findings(file_findings, res["url"], domain)
        else:
            print(f"  {DIM}  No SQL/path/RCE/disclosure findings in this file.{RESET}\n")

        # show endpoints found
        if ep_found:
            print(f"  {CYAN}  {len(ep_found)} endpoint(s) extracted from this file:{RESET}")
            for ep, meta in list(ep_found.items())[:20]:
                params = f"  [{','.join(meta['params'][:4])}]" if meta["params"] else ""
                print(f"    {CYAN}↳ {meta['method']:<5} {ep[:W()-20]}{DIM}{params}{RESET}")
            print()

    print(f"\n  {DIM}Libraries skipped: {lib_count}  |  App files analysed: {app_count}{RESET}\n")

    # ── Step 3: probe endpoints live ──────────────────────────────────────
    if all_endpoints and not args.no_probe:
        info(f"Probing {min(len(all_endpoints),30)} endpoint(s) live...")
        probed = []

        def probe_one(ep, meta):
            full = f"https://{domain}{ep}" if ep.startswith("/") else ep
            status, size, redir, ms = probe_endpoint(full, session)
            return {
                "endpoint": ep,
                "full_url": full,
                "status":   status,
                "size":     size,
                "redirect": redir,
                "ms":       ms,
                "params":   meta["params"],
                "method":   meta["method"],
            }

        ep_items = list(all_endpoints.items())[:30]
        with ThreadPoolExecutor(max_workers=5) as ex:
            futs = {ex.submit(probe_one, ep, meta): ep for ep, meta in ep_items}
            for fut in as_completed(futs):
                probed.append(fut.result())

        print_endpoints_table(probed, domain)

    # ── Step 4: summary ───────────────────────────────────────────────────
    hdr(f"SUMMARY: {domain}", WHITE)

    crit  = [f for f in all_findings if f["severity"]=="critical"]
    high  = [f for f in all_findings if f["severity"]=="high"]
    med   = [f for f in all_findings if f["severity"]=="medium"]

    print(f"  {DIM}JS files found    :{RESET} {len(js_files)}")
    print(f"  {DIM}App files analysed:{RESET} {app_count}")
    print(f"  {DIM}Libraries skipped :{RESET} {lib_count}")
    print(f"  {DIM}Endpoints found   :{RESET} {len(all_endpoints)}")
    print(f"  {DIM}Total findings    :{RESET} {len(all_findings)}")
    print(f"  {SEV_BADGE['critical']} CRITICAL {RESET}: {len(crit)}")
    print(f"  {SEV_BADGE['high']} HIGH     {RESET}: {len(high)}")
    print(f"  {SEV_BADGE['medium']} MEDIUM   {RESET}: {len(med)}")
    print()

    if not all_findings:
        print(f"  {GREEN}  No SQL/path/RCE/disclosure findings in the JS files analysed.{RESET}")
        print(f"  {DIM}  This means the JS files do not contain these vulnerability patterns.")
        print(f"  {DIM}  The endpoints found above are worth testing manually in Burp Suite.{RESET}")

    # save output
    if args.output:
        save(all_findings, all_endpoints, domain, args.output, args.format)

    return {
        "domain":    domain,
        "findings":  all_findings,
        "endpoints": all_endpoints,
    }


def save(findings, endpoints, domain, path, fmt):
    try:
        if fmt == "json":
            data = {"domain": domain, "findings": findings,
                    "endpoints": {k: v for k,v in endpoints.items()}}
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, default=str)
        else:
            with open(path, "w", encoding="utf-8") as f:
                f.write(f"JSReaper v{TOOL_VERSION} — @dr34lm\n")
                f.write(f"Target: {domain}\n")
                f.write(f"Generated: {datetime.datetime.now()}\n")
                f.write("="*70+"\n\n")
                f.write(f"FINDINGS ({len(findings)}):\n\n")
                for fi in sorted(findings, key=lambda x: SEV_ORDER.get(x["severity"],9)):
                    f.write(f"[{fi['severity'].upper()}] {fi['type']}\n")
                    f.write(f"  Description: {fi['description']}\n")
                    f.write(f"  File: {fi.get('source_file','')}\n")
                    f.write(f"  Line: {fi.get('line','')}\n")
                    f.write(f"  Match: {fi.get('match','')[:120]}\n\n")
                f.write(f"ENDPOINTS ({len(endpoints)}):\n\n")
                for ep, meta in endpoints.items():
                    params = ",".join(meta["params"]) if meta["params"] else "-"
                    f.write(f"  {meta['method']:<6} {ep}  [{params}]\n")
        ok(f"Saved → {path}")
    except Exception as e:
        err(f"Could not save: {e}")


# ─────────────────────────────────────────────────────────────────────────────
#  BURP INPUT PARSER
# ─────────────────────────────────────────────────────────────────────────────

def parse_burp_js_input(raw):
    """Parse JS URLs from Burp Suite export — handles all formats."""
    raw = raw.strip()
    if "\n" not in raw and "," not in raw:
        parts = re.split(r'(?=https?://)', raw)
    else:
        parts = re.split(r'[\n,]+', raw)
    urls = []
    seen = set()
    for part in parts:
        for u in re.findall(r'https?://[^\s,\'"<>\n]+', part):
            u = u.strip().rstrip("/")
            if u and u not in seen:
                seen.add(u)
                urls.append(u)
    return urls

def parse_burp_file(filepath):
    with open(os.path.normpath(filepath), "r", encoding="utf-8", errors="ignore") as f:
        return parse_burp_js_input(f.read())


# ─────────────────────────────────────────────────────────────────────────────
#  VERSION CHECK / UPDATE
# ─────────────────────────────────────────────────────────────────────────────

def check_version(session):
    print(f"\n{DIM}[~] Checking version...{RESET}")
    print(f"    {DIM}Tool   :{RESET} {WHITE}{TOOL_NAME}{RESET}")
    print(f"    {DIM}Version:{RESET} {GREEN}v{TOOL_VERSION}{RESET}")
    print(f"    {DIM}Author :{RESET} @dr34lm  —  https://x.com/dr34lm")
    print(f"    {DIM}Purpose:{RESET} Security research & educational use")
    print(f"    {DIM}OS     :{RESET} {platform.system()} {platform.release()}")
    print(f"    {DIM}Python :{RESET} {platform.python_version()}")
    try:
        r = session.get(LATEST_VERSION_URL, timeout=5)
        if r.status_code == 200:
            latest = r.text.strip()
            if latest == TOOL_VERSION:
                print(f"    {DIM}Status :{RESET} {GREEN}✓ Up to date (v{TOOL_VERSION} is latest){RESET}")
            else:
                print(f"    {DIM}Status :{RESET} {YELLOW}⚠ Update available: v{latest}  →  run: jsreaper --update{RESET}")
        else:
            print(f"    {DIM}Status :{RESET} {DIM}Could not check — running v{TOOL_VERSION}{RESET}")
    except Exception:
        print(f"    {DIM}Status :{RESET} {DIM}Offline — running v{TOOL_VERSION}{RESET}")
    print()


def self_update(session):
    print(f"\n{DIM}[~] Checking for update...{RESET}")
    try:
        vr = session.get(LATEST_VERSION_URL, timeout=10)
        if vr.status_code != 200:
            err("Could not reach GitHub.")
            return
        latest = vr.text.strip()
        print(f"  Current: v{TOOL_VERSION}  |  Latest: v{latest}")
        if latest == TOOL_VERSION:
            ok(f"Already up to date (v{TOOL_VERSION}).")
            return
        try:
            ans = input(f"\n  Update v{TOOL_VERSION} → v{latest}? [y/N]: ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            print()
            return
        if ans not in ("y","yes"):
            return
        info("Downloading...")
        sr = session.get(LATEST_SCRIPT_URL, timeout=30)
        if sr.status_code != 200:
            err(f"Download failed (HTTP {sr.status_code})")
            return
        content = sr.text
        if len(content) < 1000 or "def main()" not in content:
            err("Downloaded file looks invalid — aborting.")
            return
        script = os.path.realpath(sys.argv[0])
        backup = script + ".bak"
        import shutil as _sh
        _sh.copy2(script, backup)
        ok(f"Backup: {backup}")
        with open(script, "w", encoding="utf-8") as f:
            f.write(content)
        try:
            os.chmod(script, 0o755)
        except Exception:
            pass
        ok(f"Updated to v{latest} ✓")
    except Exception as e:
        err(f"Update failed: {e}")


# ─────────────────────────────────────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────────────────────────────────────

def build_parser():
    p = argparse.ArgumentParser(
        prog="jsreaper",
        description=(
            f"JSReaper v{TOOL_VERSION} — JavaScript Security Analysis\n"
            "Written by @dr34lm  |  https://x.com/dr34lm\n"
            "Finds: Exposed Endpoints · SQL Injection · Path Traversal · RCE · Info Disclosure\n"
            "For authorized research and educational use only.\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 EXAMPLES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

 Scan a target (crawls the page for JS, then analyses all files):
   jsreaper -u https://example.com

 Scan JS files you found in Burp Suite (paste directly):
   jsreaper --burp-paste "https://x.com/a.js,https://x.com/b.js"

 Scan from a Burp Suite saved JS list file:
   jsreaper --burp js_files.txt

 Save results:
   jsreaper -u https://example.com -o results.txt
   jsreaper -u https://example.com -o results.json --format json

 Faster scan (more threads):
   jsreaper -u https://example.com -t 8

 WAF-protected target (slow, rotating user-agents):
   jsreaper -u https://example.com --waf-aware

 De-minify JS before analysing (better results on SPAs):
   jsreaper -u https://example.com --beautify

 Dump all JS files to disk for manual review:
   jsreaper -u https://example.com --dump --dump-dir ./js_files

 Skip live endpoint probing:
   jsreaper -u https://example.com --no-probe

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 WHAT IT FINDS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

 1. ENDPOINTS — Every API endpoint found in JS, probed live
    for HTTP status (200/401/403/500 = worth testing)

 2. SQL INJECTION — User-controlled input in SQL queries,
    template literals with db calls, ORDER BY from params

 3. PATH TRAVERSAL / LFI — readFile/sendFile/require with
    user input, path.join with user-controlled variables

 4. RCE — eval()/new Function()/exec()/spawn() with user
    input, dynamic require(), child_process usage

 5. INFO DISCLOSURE — AWS keys (AKIA format), Stripe live
    keys (sk_live_), GitHub tokens (ghp_), JWTs, private
    keys (PEM), database URLs with credentials, Firebase
    configs, Slack webhooks, and more — all format-verified

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
    )

    tg = p.add_argument_group("Target")
    tg.add_argument("-u","--url",        help="Target URL to crawl for JS files")
    tg.add_argument("-l","--list",       help="File with one target URL per line")
    tg.add_argument("--burp",            help="Burp Suite JS file list (file path)")
    tg.add_argument("--burp-paste",      metavar="TEXT",
                                         help="Paste JS URLs directly (comma/newline separated)")

    vg = p.add_argument_group("Version & Updates")
    vg.add_argument("--version","-V",   action="store_true", help="Show version and check for updates")
    vg.add_argument("--update",         action="store_true", help="Update to latest version from GitHub")

    sg = p.add_argument_group("Scan Options")
    sg.add_argument("--beautify",       action="store_true",
                    help="De-minify JS before analysing (requires jsbeautifier)")
    sg.add_argument("--no-probe",       action="store_true",
                    help="Skip live HTTP probing of discovered endpoints")
    sg.add_argument("--waf-aware",      action="store_true",
                    help="Add random delays and rotate user-agents (for WAF-protected targets)")
    sg.add_argument("--timeout",        type=int, default=12,
                    help="Request timeout in seconds (default: 12)")

    pg = p.add_argument_group("Performance")
    pg.add_argument("-t","--threads",   type=int, default=5,
                    choices=[1,2,3,4,5,6,8,10], metavar="{1-10}",
                    help="Thread count (default: 5)")

    og = p.add_argument_group("Output")
    og.add_argument("-o","--output",    help="Save results to file")
    og.add_argument("--format",         choices=["txt","json"], default="txt",
                    help="Output format: txt (default) or json")
    og.add_argument("--dump",           action="store_true",
                    help="Save raw JS file contents to disk")
    og.add_argument("--dump-dir",       default="jsreaper_dumps",
                    help="Directory for dumped JS files (default: jsreaper_dumps/)")

    return p


# ─────────────────────────────────────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main():
    print(banner())

    parser = build_parser()
    args   = parser.parse_args()

    session = make_session(waf=args.waf_aware if hasattr(args,'waf_aware') else False)

    if args.version:
        check_version(session)
        sys.exit(0)

    if args.update:
        self_update(session)
        sys.exit(0)

    # collect targets
    targets = []
    if args.url:
        targets.append(args.url)
    if args.list:
        try:
            with open(os.path.normpath(args.list), "r", encoding="utf-8") as f:
                targets.extend([l.strip() for l in f if l.strip() and not l.startswith("#")])
        except FileNotFoundError:
            err(f"File not found: {args.list}")
            sys.exit(1)

    # burp inputs work as direct JS analysis without a target URL
    if args.burp or args.burp_paste:
        if not targets:
            targets.append("burp://input")   # placeholder

    if not targets:
        parser.print_help()
        print(f"\n{RED}[!] Provide a target: -u URL  or  -l file  or  --burp file{RESET}")
        sys.exit(1)

    targets = list(dict.fromkeys(targets))
    all_results = []
    start = time.time()

    for i, target in enumerate(targets, 1):
        if len(targets) > 1:
            print(f"\n{WHITE}[{i}/{len(targets)}] → {target}{RESET}")
        try:
            r = scan(target, args, session)
            all_results.append(r)
        except KeyboardInterrupt:
            warn("Interrupted.")
            break
        except Exception as e:
            import traceback
            err(f"Scan failed for {target}: {e}")
            traceback.print_exc()

    elapsed = time.time() - start
    ok(f"Done in {elapsed:.1f}s")
    print(f"\n{DIM}  JSReaper v{TOOL_VERSION} by @dr34lm — for authorized research only{RESET}\n")


if __name__ == "__main__":
    main()
