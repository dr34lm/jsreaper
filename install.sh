#!/bin/bash
# JSReaper Installer
# Makes jsreaper callable from anywhere on your system

set -e

GREEN='\033[0;32m'
CYAN='\033[0;36m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${RED}"
echo "     ██╗███████╗██████╗ ███████╗ █████╗ ██████╗ ███████╗██████╗ "
echo "     ██║██╔════╝██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗"
echo "     ██║███████╗██████╔╝█████╗  ███████║██████╔╝█████╗  ██████╔╝"
echo "██   ██║╚════██║██╔══██╗██╔══╝  ██╔══██║██╔═══╝ ██╔══╝  ██╔══██╗"
echo "╚█████╔╝███████║██║  ██║███████╗██║  ██║██║     ███████╗██║  ██║"
echo " ╚════╝ ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝"
echo -e "${YELLOW}          Installer v1.0${NC}"
echo ""

# Check Python 3
echo -e "${CYAN}[*] Checking Python 3...${NC}"
if ! command -v python3 &>/dev/null; then
    echo -e "${RED}[-] Python 3 not found. Install it first: sudo apt install python3${NC}"
    exit 1
fi
PY_VER=$(python3 --version 2>&1)
echo -e "${GREEN}[+] Found: $PY_VER${NC}"

# Install dependencies
echo -e "${CYAN}[*] Installing Python dependencies...${NC}"
pip3 install requests beautifulsoup4 colorama jsbeautifier tqdm fake-useragent urllib3 --break-system-packages 2>/dev/null || \
pip3 install requests beautifulsoup4 colorama jsbeautifier tqdm fake-useragent urllib3 --user
echo -e "${GREEN}[+] Dependencies installed${NC}"

# Copy script to /usr/local/bin
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_SRC="$SCRIPT_DIR/jsreaper.py"

if [ ! -f "$SCRIPT_SRC" ]; then
    echo -e "${RED}[-] jsreaper.py not found in current directory${NC}"
    exit 1
fi

echo -e "${CYAN}[*] Installing jsreaper to /usr/local/bin...${NC}"
sudo cp "$SCRIPT_SRC" /usr/local/bin/jsreaper
sudo chmod +x /usr/local/bin/jsreaper

# Make sure the shebang works
sudo sed -i '1s|.*|#!/usr/bin/env python3|' /usr/local/bin/jsreaper

echo -e "${GREEN}[+] Installed to /usr/local/bin/jsreaper${NC}"
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════╗"
echo -e "║  JSReaper installed successfully!            ║"
echo -e "║  You can now run it from anywhere:           ║"
echo -e "║                                              ║"
echo -e "║  jsreaper -u https://example.com --analyze   ║"
echo -e "║  jsreaper --help                             ║"
echo -e "╚══════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${RED}  Only use JSReaper on targets you are authorized to test.${NC}"
echo -e "${RED}  Unauthorized use is illegal and unethical.${NC}"
echo ""
