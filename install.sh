#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
# AI Recon Agent - Auto Installer
# Tested on: Kali Linux, Ubuntu 22.04, Debian 12
# ═══════════════════════════════════════════════════════════════
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err() { echo -e "${RED}[-]${NC} $1"; }
info() { echo -e "${BLUE}[*]${NC} $1"; }

echo -e "${BLUE}"
cat << 'EOF'
╔══════════════════════════════════════════════╗
║     AI RECON AGENT - INSTALLER               ║
╚══════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# ─── Check OS ──────────────────────────────────
if [[ "$OSTYPE" != "linux-gnu"* ]]; then
    warn "This installer is designed for Linux. Proceed with caution on other systems."
fi

# ─── Check root ────────────────────────────────
if [ "$EUID" -ne 0 ]; then
    warn "Not running as root. Some installs may fail."
    warn "Run with: sudo bash install.sh"
fi

# ─── Install Go ─────────────────────────────────
install_go() {
    if command -v go &>/dev/null; then
        GO_VER=$(go version | awk '{print $3}')
        log "Go already installed: $GO_VER"
    else
        info "Installing Go..."
        GO_VERSION="1.22.3"
        ARCH=$(uname -m)
        if [ "$ARCH" == "x86_64" ]; then
            GOARCH="amd64"
        elif [ "$ARCH" == "aarch64" ]; then
            GOARCH="arm64"
        else
            GOARCH="amd64"
        fi
        
        wget -q "https://go.dev/dl/go${GO_VERSION}.linux-${GOARCH}.tar.gz" -O /tmp/go.tar.gz
        rm -rf /usr/local/go
        tar -C /usr/local -xzf /tmp/go.tar.gz
        rm /tmp/go.tar.gz

        # Add to PATH
        export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
        echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc

        log "Go installed: $(go version)"
    fi
    
    export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
}

# ─── Install Go tools ───────────────────────────
install_go_tools() {
    info "Installing Go-based tools..."
    export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin

    declare -A TOOLS=(
        ["subfinder"]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        ["httpx"]="github.com/projectdiscovery/httpx/cmd/httpx@latest"
        ["nuclei"]="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        ["katana"]="github.com/projectdiscovery/katana/cmd/katana@latest"
        ["assetfinder"]="github.com/tomnomnom/assetfinder@latest"
        ["waybackurls"]="github.com/tomnomnom/waybackurls@latest"
        ["gau"]="github.com/lc/gau/v2/cmd/gau@latest"
        ["hakrawler"]="github.com/hakluke/hakrawler@latest"
    )

    for tool in "${!TOOLS[@]}"; do
        if command -v "$tool" &>/dev/null; then
            log "$tool already installed"
        else
            info "Installing $tool..."
            if go install -v "${TOOLS[$tool]}" 2>/dev/null; then
                log "$tool installed ✓"
            else
                err "Failed to install $tool"
            fi
        fi
    done
}

# ─── Install system packages ─────────────────────
install_system_packages() {
    info "Installing system packages..."
    
    if command -v apt-get &>/dev/null; then
        apt-get update -qq
        apt-get install -y -qq \
            python3 python3-pip curl wget git \
            nikto sqlmap ruby ruby-dev build-essential \
            libssl-dev libffi-dev libxml2-dev \
            nmap 2>/dev/null || warn "Some system packages failed to install"
        log "System packages installed"
    elif command -v yum &>/dev/null; then
        yum install -y python3 python3-pip curl wget git nmap 2>/dev/null
    fi
}

# ─── Install wpscan ───────────────────────────────
install_wpscan() {
    if command -v wpscan &>/dev/null; then
        log "wpscan already installed"
    else
        info "Installing wpscan..."
        if command -v gem &>/dev/null; then
            gem install wpscan 2>/dev/null && log "wpscan installed ✓" || warn "wpscan install failed"
        else
            warn "Ruby gems not available - wpscan skipped"
            info "Alternative: docker pull wpscanteam/wpscan"
        fi
    fi
}

# ─── Install amass ────────────────────────────────
install_amass() {
    if command -v amass &>/dev/null; then
        log "amass already installed"
    else
        info "Installing amass..."
        if command -v snap &>/dev/null; then
            snap install amass 2>/dev/null && log "amass installed via snap ✓" || true
        fi
        
        if ! command -v amass &>/dev/null; then
            # Try apt
            apt-get install -y amass 2>/dev/null || true
        fi
        
        if ! command -v amass &>/dev/null; then
            warn "amass not installed - manual install required"
            info "Try: go install -v github.com/owasp-amass/amass/v4/...@master"
        fi
    fi
}

# ─── Update nuclei templates ──────────────────────
update_nuclei_templates() {
    if command -v nuclei &>/dev/null; then
        info "Updating nuclei templates..."
        nuclei -update-templates 2>/dev/null || warn "nuclei template update failed"
        log "nuclei templates updated"
    fi
}

# ─── Create results directory ─────────────────────
setup_dirs() {
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    mkdir -p "$SCRIPT_DIR/results"
    log "Created results/ directory"
}

# ─── Verify installs ──────────────────────────────
verify_tools() {
    echo ""
    echo "═══════════════════════════════════════════"
    echo "  TOOL VERIFICATION"
    echo "═══════════════════════════════════════════"
    
    TOOLS=("subfinder" "assetfinder" "amass" "httpx" "katana" "gau" 
           "waybackurls" "hakrawler" "nuclei" "nikto" "wpscan" "sqlmap" "python3")
    
    INSTALLED=0
    MISSING=0
    
    for tool in "${TOOLS[@]}"; do
        if command -v "$tool" &>/dev/null; then
            echo -e "  ${GREEN}✓${NC} $tool"
            ((INSTALLED++))
        else
            echo -e "  ${RED}✗${NC} $tool (not found)"
            ((MISSING++))
        fi
    done
    
    echo "═══════════════════════════════════════════"
    echo -e "  Installed: ${GREEN}$INSTALLED${NC} | Missing: ${RED}$MISSING${NC}"
    echo "═══════════════════════════════════════════"
    echo ""
}

# ─── Main ─────────────────────────────────────────
main() {
    install_go
    install_system_packages
    install_go_tools
    install_amass
    install_wpscan
    update_nuclei_templates
    setup_dirs
    verify_tools

    echo -e "${GREEN}"
    echo "══════════════════════════════════════════════"
    echo "  Installation Complete!"
    echo "══════════════════════════════════════════════"
    echo -e "${NC}"
    echo "  Usage:"
    echo "    python3 agent.py -t example.com"
    echo "    python3 agent.py -t example.com --no-exploit"
    echo "    python3 agent.py -t example.com -v"
    echo ""
    echo "  Options:"
    echo "    -t TARGET     Target domain"
    echo "    -o OUTPUT     Custom output directory"
    echo "    --no-exploit  Recon only, skip exploitation"
    echo "    --skip-recon  Skip subdomain enumeration"
    echo "    -v            Verbose output"
    echo ""
}

main "$@"
