<div align="center">

```
     ██╗███████╗██████╗ ███████╗ █████╗ ██████╗ ███████╗██████╗ 
     ██║██╔════╝██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗
     ██║███████╗██████╔╝█████╗  ███████║██████╔╝█████╗  ██████╔╝
 ██  ██║╚════██║██╔══██╗██╔══╝  ██╔══██║██╔═══╝ ██╔══╝  ██╔══██╗
 ╚█████╔╝███████║██║  ██║███████╗██║  ██║██║     ███████╗██║  ██║
  ╚════╝ ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝
```

# JSReaper v1.1

**JavaScript Recon & Analysis Tool for Bug Bounty Hunters**

[![Python](https://img.shields.io/badge/Python-3.7%2B-brightgreen?style=flat-square&logo=python)](https://python.org)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-brightgreen?style=flat-square)](https://github.com)
[![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)](LICENSE)
[![BugBounty](https://img.shields.io/badge/Purpose-Bug%20Bounty-orange?style=flat-square)](https://hackerone.com)
[![Authorized](https://img.shields.io/badge/Use-Authorized%20Targets%20Only-red?style=flat-square)](https://github.com)

> **For authorized use only. Only run on targets you have explicit permission to test.**

</div>

---

## What is JSReaper?

Developers make mistakes in JavaScript files every single day. They leave API keys, AWS credentials, internal endpoints, database URLs, authentication tokens, and sensitive logic directly in their frontend JavaScript code — exposed to anyone who looks.

**JSReaper automates finding all of it.**

It crawls your target, discovers every JavaScript file, reads the content of each one, and runs 70+ detection patterns across 12 categories to surface secrets, vulnerabilities, and sensitive endpoints — all colour-coded by severity so you know exactly what to focus on first.

Built specifically for bug bounty hunters. Works on Linux, macOS, and Windows.

---

## Features

| Feature | Description |
|---|---|
| **Smart JS Discovery** | Extracts JS files from `<script>` tags, HTML attributes, inline regex patterns, and raw source |
| **HTTP + HTTPS Auto-Detect** | Automatically tries HTTPS first, falls back to HTTP — works with any URL format |
| **Secret Detection** | 70+ patterns: API keys, AWS credentials (`AKIA...`), Stripe live keys, Firebase configs, OAuth tokens, JWT secrets, DB connection strings, and more |
| **OWASP Analysis** | Detects `eval()`, XSS sinks (`innerHTML`, `document.write`), open redirects, CORS `*`, insecure storage, DOM-based XSS vectors |
| **Endpoint Extraction** | Pulls every API path, internal URL, and route from JS content |
| **JS Relationship Mapping** | Tracks `import`/`require` chains between files to reveal how they connect |
| **Deep Crawl** | Follows JS imports recursively to find hidden files not linked from the main page |
| **Subdomain Recon** | Passive discovery via crt.sh, HackerTarget, and AlienVault OTX |
| **Sensitive File Probe** | Checks 50+ paths for exposed `.env`, `.git/config`, `swagger.json`, backups, phpinfo, Spring Boot actuators, and more |
| **WAF Detection & Evasion** | Identifies Cloudflare, Akamai, AWS WAF, Imperva, Sucuri, F5, ModSecurity — then evades with random delays and UA rotation |
| **Rich Colour Output** | Every severity level, category, and result type gets its own distinct colour — critical findings are impossible to miss |
| **Risk Scoring** | Each JS file gets a weighted risk score so you prioritise your manual review |
| **Multi-Target** | Scan a single URL or a list of hundreds of targets from a file |
| **Threaded** | Configurable thread count (1–10) for speed vs. stealth control |
| **JS Beautifier** | De-minifies obfuscated/minified JS before analysis for cleaner results |
| **Output Formats** | Save results as `.txt` or structured `.json` |
| **JS Dump** | Download and save raw JS file contents to disk for offline review |
| **Cross-Platform** | Runs on Linux, macOS, and Windows (Python 3.7+) |

---

## Installation

### Linux / macOS

```bash
# 1. Clone the repo
git clone https://github.com/YOURUSERNAME/jsreaper.git
cd jsreaper

# 2. Run the installer (handles dependencies + makes jsreaper global)
chmod +x install.sh
./install.sh

# 3. Use from anywhere
jsreaper -h
```

### Windows

```powershell
# 1. Clone the repo
git clone https://github.com/YOURUSERNAME/jsreaper.git
cd jsreaper

# 2. Install dependencies
pip install requests beautifulsoup4 colorama jsbeautifier tqdm urllib3

# 3. Run directly
python jsreaper.py -h

# Optional: add to PATH so you can call it from anywhere
# Add the jsreaper folder to your System Environment Variables > PATH
```

### Manual Install (any OS)

```bash
pip3 install requests beautifulsoup4 colorama jsbeautifier tqdm urllib3
python3 jsreaper.py -h
```

### Requirements

- Python 3.7 or higher
- pip3 / pip

---

## Usage

### Basic Syntax

```
jsreaper -u <target> [options]
jsreaper -l <targets_file> [options]
```

### The URL field is flexible — all of these work:

```bash
jsreaper -u example.com
jsreaper -u https://example.com
jsreaper -u http://example.com
jsreaper -u www.example.com
```

The tool automatically tries HTTPS first. If that fails, it retries with HTTP. No need to think about it.

---

## Examples

```bash
# Basic — just discover all JS files on a target
jsreaper -u example.com

# Core use case — find and fully analyze all JS files
jsreaper -u https://example.com --analyze

# Full recon suite — JS analysis + subdomain recon + sensitive file probe
jsreaper -u https://example.com --analyze --subdomains --probe

# Deep crawl — follow JS imports recursively to find hidden files
jsreaper -u https://example.com --analyze --deep --endpoints

# Save results to a file
jsreaper -u https://example.com --analyze -o results.txt

# Save as JSON (great for piping into other tools)
jsreaper -u https://example.com --analyze -o results.json --format json

# Dump every JS file to disk for offline manual review
jsreaper -u https://example.com --analyze --dump --dump-dir ./target_js

# De-minify compressed JS before analyzing (better results on minified code)
jsreaper -u https://example.com --analyze --beautify

# Stealth mode — slow, WAF-aware, single thread
jsreaper -u https://example.com --analyze --waf-aware -t 1

# Aggressive scan — 8 threads (use with caution, may trigger WAF)
jsreaper -u https://example.com --analyze -t 8

# Bulk scan — scan a full program scope from a file
jsreaper -l scope.txt -t 5 --analyze --probe -o report.json --format json

# Full subdomain sweep — find subs, then scan each one's JS
jsreaper -u https://example.com --subdomains --scan-subs --analyze

# Everything at once — the full blast
jsreaper -u https://example.com --analyze --deep --probe --subdomains --endpoints --beautify -o full_report.json --format json
```

---

## All Flags

### Target
| Flag | Description |
|---|---|
| `-u URL` | Single target. Accepts `example.com`, `http://`, `https://`, or `www.` |
| `-l FILE` | File containing one target per line (lines starting with `#` are skipped) |

### Scan Options
| Flag | Description |
|---|---|
| `--analyze` | **The main engine** — reads every JS file and hunts for secrets, vulnerabilities, and endpoints |
| `--deep` | Follow `import`/`require` chains inside JS files to find even more JS recursively |
| `--probe` | Check 50+ paths for sensitive exposed files (`.env`, `.git`, `swagger.json`, backups, etc.) |
| `--subdomains` | Passive subdomain recon via crt.sh, HackerTarget, and AlienVault OTX |
| `--scan-subs` | After finding subdomains, scan each one for JS too (pair with `--subdomains`) |
| `--endpoints` | Print all API paths and URLs extracted from inside JS files |
| `--js-only` | Skip non-JS file types, focus on `.js` only |
| `--beautify` | De-minify compressed JS before scanning — much cleaner results on minified code |
| `--verbose` | Show all files scanned, even ones with zero findings |

### Performance & Evasion
| Flag | Description |
|---|---|
| `-t 1` to `-t 10` | Thread count. `1` = stealth, `3` = default, `10` = aggressive |
| `--waf-aware` | Enables WAF evasion: random delays, User-Agent rotation, smart retries |
| `--timeout N` | Seconds to wait per request (default: 15) |

### Output
| Flag | Description |
|---|---|
| `-o FILE` | Save results to file e.g. `-o results.txt` |
| `--format txt` | Plain text output (default) |
| `--format json` | Structured JSON — pipe into other tools or scripts |
| `--dump` | Download and save the raw content of every JS file it finds |
| `--dump-dir DIR` | Where to save dumped JS files (default: `jsreaper_dumps/`) |

---

## What JSReaper Hunts For

### Secrets & Credentials (12 Categories, 70+ Patterns)

**API Keys & Tokens**
Generic API keys, access tokens, auth tokens, Bearer tokens, x-api-key headers

**AWS Credentials**
Access Key IDs (`AKIA...`), secret access keys, session tokens, S3 bucket references

**Authentication & Passwords**
Hardcoded passwords, `passwd` fields, secrets, private keys (including PEM blocks), JWT secrets, client secrets

**OAuth & SSO**
Client IDs, OAuth tokens, refresh tokens, redirect URIs

**Database Credentials**
DB passwords, connection strings, MongoDB URIs, MySQL/PostgreSQL/Redis URLs

**Cloud & Infrastructure**
Firebase configs, Google API keys (`AIza...`), Azure keys, Stripe live keys (`sk_live_...`), SendGrid keys (`SG....`), Twilio auth tokens, Heroku keys, DigitalOcean tokens

**Sensitive Endpoints & Paths**
`/admin`, `/debug`, `/internal`, `/.git`, `/.env`, `/swagger`, `/graphql`, `/phpmyadmin`, `/etc/passwd`

### OWASP Vulnerability Indicators

| Issue | Indicator | Severity |
|---|---|---|
| Code Injection | `eval()` usage | High |
| XSS (DOM) | `innerHTML =`, `document.write()` | Medium |
| XSS (React) | `.dangerouslySetInnerHTML` | Medium |
| XSS (DOM) | `.src = ... +` (dynamic src) | Medium |
| Open Redirect | `window.location = ... +` | Medium |
| CORS Misconfiguration | `Access-Control-Allow-Origin: *` | Medium |
| Insecure Storage | `localStorage.setItem`, `sessionStorage.setItem` | Info |
| Sensitive Logging | `console.log(password/token/key)` | Medium |
| Cookie Manipulation | `document.cookie` | Medium |
| Debug Code | `debugger;` statements | Info |

### Internal Infrastructure
Private IP ranges (192.168.x.x, 10.x.x.x, 172.16-31.x.x), localhost references, staging/dev/test subdomains

### Source Map Leakage
`.map` file references — these often expose the full original unminified source code of the application

### Sensitive Exposed Files (50+ paths probed)
`.env` variants, `.git/config`, `.git/HEAD`, `package.json`, `webpack.config.js`, `swagger.json`, `openapi.json`, phpinfo, database dumps, backup archives, Spring Boot actuator endpoints (`/actuator/env`, `/actuator/health`), server status pages, and more.

---

## Understanding the Output

### Severity Levels

| Level | Colour | Score | What it means |
|---|---|---|---|
| `CRITICAL` | Red background | 100 pts | Immediate risk — AWS keys, private keys, Stripe live keys, DB credentials |
| `HIGH` | Orange background | 50 pts | API tokens, OAuth secrets, hardcoded passwords, exposed git config |
| `MEDIUM` | Gold background | 20 pts | XSS sinks, CORS misconfigs, internal IPs, admin endpoints |
| `LOW` | Blue background | 5 pts | Weak crypto, minor info leaks |
| `INFO` | Gray background | 1 pt | Endpoints, URLs, general references |

### Risk Score

Every JS file gets a **Risk Score** — a weighted total of all findings by severity. The higher the score, the more urgently it needs manual review.

| Score | Rating |
|---|---|
| 300+ | 🔥 Critical Risk — Immediate action required |
| 100–299 | ⚠ High Risk — Review findings carefully |
| 30–99 | ⚡ Medium Risk — Some issues found |
| 1–29 | ℹ Low Risk — Minor findings only |
| 0 | ✓ Clean — No significant findings |

---

## Colour Guide

The terminal output uses a full colour system so you can read results at a glance:

- 🟩 **Lemon green** — successful operations, clean files, tool banner
- 🔴 **Red background** — CRITICAL findings
- 🟠 **Orange background** — HIGH findings  
- 🟡 **Gold background** — MEDIUM findings
- 🔵 **Blue background** — LOW findings
- ⚪ **Gray background** — INFO findings
- 🔵 **Pale cyan** — File URLs and paths
- 🟣 **Purple/pink** — Category headers
- 🔵 **Lavender** — JS relationship imports
- 🟡 **Bright yellow** — Section headers
- 🟠 **Salmon/orange** — WAF warnings and probe hits
- 🟢 **Pale green** — Subdomains

---

## Workflow: How Pro Hunters Use This

### Step 1: Quick discovery
```bash
jsreaper -u https://target.com
```
See what JS files are exposed before committing to a full scan.

### Step 2: Analyze all JS
```bash
jsreaper -u https://target.com --analyze --endpoints
```
Read and analyze every JS file. Look at the risk score and critical/high findings first.

### Step 3: Expand the attack surface
```bash
jsreaper -u https://target.com --subdomains --scan-subs --analyze
```
Find subdomains, then scan their JS too. Many programs have dev/staging subdomains with secrets still in the code.

### Step 4: Check for exposed files
```bash
jsreaper -u https://target.com --probe
```
Probe for `.env`, `.git`, swagger docs, backups. A single exposed `.env` can be a critical finding.

### Step 5: Go deep on interesting targets
```bash
jsreaper -u https://target.com --analyze --deep --beautify --dump --dump-dir ./target_js
```
De-minify and dump all JS to disk. Use `--deep` to follow import chains. Review the dumped files manually in your editor for logic flaws.

### Step 6: Bulk scan the whole scope
```bash
jsreaper -l scope.txt -t 5 --analyze --probe --waf-aware -o final_report.json --format json
```
Run the full pipeline against every in-scope domain.

---

## Tips & Tricks

**Target returns 403 on everything?**
```bash
jsreaper -u https://target.com --analyze --waf-aware -t 1
```
Slow down and rotate User-Agents.

**Minified JS giving messy output?**
```bash
jsreaper -u https://target.com --analyze --beautify
```
Always use `--beautify` on modern SPAs — webpack bundles are unreadable without it.

**Want to review JS files manually?**
```bash
jsreaper -u https://target.com --analyze --dump --dump-dir ./js_files
```
Open the dumped files in VS Code or any editor. Search for keywords like `secret`, `token`, `key`, `password`.

**Building a wordlist of endpoints from JS?**
```bash
jsreaper -u https://target.com --analyze --endpoints -o endpoints.txt
```
Feed `endpoints.txt` into tools like `ffuf` or `nuclei` for further testing.

**WAF blocking you completely?**
Add `--timeout 30 --waf-aware -t 1` and let it run slow. Some WAFs only rate-limit, they don't fully block.

---

## Similar Tools

JSReaper was inspired by and improves upon:

- [LinkFinder](https://github.com/GerbenJavado/LinkFinder) — endpoint extraction from JS
- [SecretFinder](https://github.com/m4ll0k/SecretFinder) — secret detection in JS
- [JSParser](https://github.com/nahamsec/JSParser) — JS file parsing
- [truffleHog](https://github.com/trufflesecurity/trufflehog) — secret scanning

JSReaper combines all of the above into a single unified tool with subdomain recon, file probing, WAF evasion, rich coloured output, cross-platform support, and a proper risk scoring system.

---

## Contributing

Pull requests are welcome. Some things that would make this even better:

- More secret patterns (new services, custom patterns)
- Active CORS misconfiguration testing
- GraphQL introspection detection
- Integration with `waybackurls` / `gau` for historical JS files
- Integration with `nuclei` templates
- HTML report output format

---

## Legal Notice

JSReaper is a security research tool intended exclusively for:

- **Authorized bug bounty programs** (HackerOne, Bugcrowd, Intigriti, YesWeHack, etc.)
- **Penetration testing** with written authorization from the target organization
- **Security research** on assets you own or control

**Unauthorized use against systems you do not own or have explicit written permission to test is illegal** under the Computer Fraud and Abuse Act (CFAA, USA), the Computer Misuse Act (UK), and equivalent laws in virtually every country worldwide.

The author assumes zero liability for any misuse of this tool. Stay in scope. Stay legal.

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">

Made for the bug bounty community. Hunt responsibly.

**⭐ Star this repo if JSReaper helped you find a bug!**

</div>
