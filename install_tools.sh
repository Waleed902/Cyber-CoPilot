#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════
#  Cyber-CoPilot — Universal Tool Installer
#  Supports: Kali · Ubuntu · Debian · Fedora · Arch · macOS · WSL
#  Run as:   bash install_tools.sh [--all | --minimal | --category]
# ══════════════════════════════════════════════════════════════════════

# ── Settings ─────────────────────────────────────────────────────────
# Do NOT use set -e. We handle errors per-tool so one failure doesn't
# stop the entire installation.
set -o pipefail

# ── CRLF self-repair ─────────────────────────────────────────────────
# If this script lives on a Windows/VMware shared folder it will have
# \r\n line endings.  Bash tolerates most of them, but heredocs and
# anything written to ~/.zshrc silently inherit the \r bytes, breaking
# shell aliases and functions.  Detect + re-exec a clean copy.
# NOTE: We use $'\r' (ANSI-C quoting) — not '\r' — to match the
# actual carriage-return byte.  grep -P is NOT required.
if grep -q $'\r' "$0" 2>/dev/null; then
    _clean=$(mktemp /tmp/install_tools.XXXXXX.sh)
    tr -d '\r' < "$0" > "$_clean"
    chmod +x "$_clean"
    exec bash "$_clean" "$@"
fi

SCRIPT_VERSION="2.1.0"
TOOLS_DIR="${TOOLS_DIR:-$HOME/tools}"
LOG_FILE="/tmp/cyber-copilot-install-$(date +%Y%m%d-%H%M%S).log"
# Resolve the project directory (where this script lives)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$SCRIPT_DIR"
VENV_DIR="$PROJECT_DIR/.venv"   # may be relocated by detect_shared_folder()
IS_SHARED_FS=false
INSTALLED=0
FAILED=0
SKIPPED=0
START_TIME=$(date +%s)

# ── Terminal Colors ──────────────────────────────────────────────────
if [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    MAGENTA='\033[0;35m'
    CYAN='\033[0;36m'
    BOLD='\033[1m'
    DIM='\033[2m'
    NC='\033[0m'
else
    RED='' GREEN='' YELLOW='' BLUE='' MAGENTA='' CYAN='' BOLD='' DIM='' NC=''
fi

# ── Logging Functions ────────────────────────────────────────────────
_log()  { echo "[$(date +%H:%M:%S)] $*" >> "$LOG_FILE"; }
ok()    { echo -e "  ${GREEN}✓${NC} $1"; _log "OK: $1"; ((INSTALLED++)); }
warn()  { echo -e "  ${YELLOW}⚠${NC} $1"; _log "WARN: $1"; }
info()  { echo -e "  ${CYAN}▸${NC} $1"; _log "INFO: $1"; }
err()   { echo -e "  ${RED}✗${NC} $1"; _log "FAIL: $1"; ((FAILED++)); }
skip()  { echo -e "  ${DIM}○${NC} ${DIM}$1${NC}"; _log "SKIP: $1"; ((SKIPPED++)); }
header(){ echo -e "\n${BOLD}${BLUE}━━ $1 ━━${NC}"; _log "SECTION: $1"; }

command_exists() { command -v "$1" &>/dev/null; }

# ══════════════════════════════════════════════════════════════════════
# PLATFORM DETECTION
# ══════════════════════════════════════════════════════════════════════

detect_platform() {
    OS="unknown"
    DISTRO="unknown"
    PKG_MGR="unknown"
    PKG_INSTALL=""
    PKG_UPDATE=""
    ARCH=$(uname -m)
    IS_WSL=false
    IS_ARM=false

    # Architecture
    case "$ARCH" in
        aarch64|arm64) IS_ARM=true ;;
        armv7l|armhf)  IS_ARM=true ;;
    esac

    # Operating System
    case "$(uname -s)" in
        Linux)
            OS="linux"
            # Check WSL
            if grep -qi microsoft /proc/version 2>/dev/null || \
               grep -qi wsl /proc/version 2>/dev/null; then
                IS_WSL=true
            fi

            # Detect distro
            if [ -f /etc/os-release ]; then
                source /etc/os-release
                DISTRO="${ID,,}"
            elif [ -f /etc/lsb-release ]; then
                source /etc/lsb-release
                DISTRO="${DISTRIB_ID,,}"
            fi

            # Package manager detection (order matters)
            if command_exists apt-get; then
                PKG_MGR="apt"
                PKG_INSTALL="apt-get install -y -qq"
                PKG_UPDATE="apt-get update -qq"
            elif command_exists dnf; then
                PKG_MGR="dnf"
                PKG_INSTALL="dnf install -y -q"
                PKG_UPDATE="dnf check-update -q"
            elif command_exists yum; then
                PKG_MGR="yum"
                PKG_INSTALL="yum install -y -q"
                PKG_UPDATE="yum check-update -q"
            elif command_exists pacman; then
                PKG_MGR="pacman"
                PKG_INSTALL="pacman -S --noconfirm --needed"
                PKG_UPDATE="pacman -Sy --noconfirm"
            elif command_exists apk; then
                PKG_MGR="apk"
                PKG_INSTALL="apk add --no-cache"
                PKG_UPDATE="apk update"
            elif command_exists zypper; then
                PKG_MGR="zypper"
                PKG_INSTALL="zypper install -y -q"
                PKG_UPDATE="zypper refresh"
            fi
            ;;
        Darwin)
            OS="macos"
            DISTRO="macos"
            if command_exists brew; then
                PKG_MGR="brew"
                PKG_INSTALL="brew install"
                PKG_UPDATE="brew update"
            else
                PKG_MGR="none"
            fi
            ;;
        MINGW*|MSYS*|CYGWIN*)
            OS="windows"
            DISTRO="windows"
            if command_exists choco; then
                PKG_MGR="choco"
                PKG_INSTALL="choco install -y --no-progress"
                PKG_UPDATE="echo"
            elif command_exists scoop; then
                PKG_MGR="scoop"
                PKG_INSTALL="scoop install"
                PKG_UPDATE="scoop update"
            elif command_exists winget; then
                PKG_MGR="winget"
                PKG_INSTALL="winget install --accept-package-agreements --accept-source-agreements -e --id"
                PKG_UPDATE="echo"
            else
                PKG_MGR="none"
            fi
            ;;
    esac
}

# ══════════════════════════════════════════════════════════════════════
# PRIVILEGE DETECTION
# ══════════════════════════════════════════════════════════════════════

detect_privileges() {
    SUDO=""
    CAN_SUDO=false
    IS_ROOT=false

    if [[ "$OS" == "windows" ]]; then
        # On Windows, no sudo needed for user-space package managers
        SUDO=""
        return
    fi

    if [[ $EUID -eq 0 ]]; then
        IS_ROOT=true
        SUDO=""
        return
    fi

    # Check if sudo is available and user has sudo privileges
    if command_exists sudo; then
        # Test if we can sudo without password (NOPASSWD) or if cached
        if sudo -n true 2>/dev/null; then
            CAN_SUDO=true
            SUDO="sudo"
        else
            # Prompt once for sudo password; if it fails, continue without
            echo -e "${YELLOW}⚠ Root access needed for system packages.${NC}"
            if sudo -v 2>/dev/null; then
                CAN_SUDO=true
                SUDO="sudo"
                # Keep sudo alive in background
                (while true; do sudo -n true; sleep 55; kill -0 "$$" || exit; done 2>/dev/null &)
            else
                warn "sudo authentication failed — will skip system packages"
                SUDO=""
            fi
        fi
    elif command_exists doas; then
        SUDO="doas"
        CAN_SUDO=true
    else
        warn "No sudo/doas found — will only install user-space tools"
    fi
}

# ══════════════════════════════════════════════════════════════════════
# SHARED / NETWORK FILESYSTEM DETECTION
# ══════════════════════════════════════════════════════════════════════

detect_shared_folder() {
    IS_SHARED_FS=false

    if [[ "$OS" != "linux" && "$OS" != "macos" ]]; then
        return
    fi

    # Detect VMware HGFS, VirtualBox vboxsf, NFS, CIFS/SMB, 9p (QEMU)
    local fs_type
    fs_type=$(df -T "$PROJECT_DIR" 2>/dev/null | awk 'NR==2{print $2}')
    case "$fs_type" in
        vmhgfs*|fuse.vmhgfs*|vboxsf|cifs|nfs*|9p|smbfs)
            IS_SHARED_FS=true
            ;;
    esac

    # Fallback: check common VMware shared folder mount points
    if [[ "$IS_SHARED_FS" == "false" && "$PROJECT_DIR" == /mnt/hgfs/* ]]; then
        IS_SHARED_FS=true
    fi

    if [[ "$IS_SHARED_FS" == "true" ]]; then
        # Move venv to local filesystem for speed + cross-platform compat
        VENV_DIR="$HOME/.venvs/cyber-copilot"
        mkdir -p "$(dirname "$VENV_DIR")"
        warn "Shared/network filesystem detected ($fs_type)"
        info "Venv will be placed on local disk: $VENV_DIR"
        info "This avoids slow I/O + cross-platform venv corruption"
    fi
}

# ══════════════════════════════════════════════════════════════════════
# PACKAGE INSTALLATION (cross-platform)
# ══════════════════════════════════════════════════════════════════════

# Map package names across distros
get_pkg_name() {
    local tool="$1"

    # Package name differences across distros
    case "$PKG_MGR" in
        apt)
            case "$tool" in
                ncat)               echo "" ;;  # ncat is part of nmap on Debian/Kali
                rpcclient)          echo "" ;;  # included with samba-common-bin / smbclient
                arpspoof)           echo "dsniff" ;;  # arpspoof is part of dsniff
                wireshark-cli)      echo "wireshark-common" ;;  # correct package name on Debian/Kali
                python3-full)       echo "python3-venv" ;;  # python3-full doesn't exist everywhere; python3-venv is what we actually need
                dnsutils)           echo "bind9-dnsutils" ;;  # dnsutils is a transitional pkg on newer Kali/Debian
                snmpcheck)          echo "snmpcheck" ;;
                redis-tools)        echo "redis-tools" ;;
                *)                  echo "$tool" ;;
            esac
            ;;
        dnf|yum)
            case "$tool" in
                dnsutils)       echo "bind-utils" ;;
                netcat-openbsd) echo "nmap-ncat" ;;
                netcat-traditional) echo "" ;;  # skip
                ncat)           echo "" ;;  # included with nmap
                python3-pip)    echo "python3-pip" ;;
                python3-full)   echo "python3" ;;
                build-essential) echo "gcc make" ;;
                libpcap-dev)    echo "libpcap-devel" ;;
                wireshark-cli)  echo "wireshark-cli" ;;
                tshark)         echo "" ;;  # included with wireshark
                smbclient)      echo "samba-client" ;;
                rpcclient)      echo "" ;;  # included with samba-client
                ldap-utils)     echo "openldap-clients" ;;
                wordlists)      echo "" ;;  # Kali-specific
                arpspoof)       echo "dsniff" ;;
                snmpcheck)      echo "" ;;
                redis-tools)    echo "redis" ;;
                pipx)           echo "pipx" ;;
                *)              echo "$tool" ;;
            esac
            ;;
        pacman)
            case "$tool" in
                dnsutils)       echo "bind" ;;
                netcat-openbsd) echo "openbsd-netcat" ;;
                netcat-traditional) echo "" ;;
                ncat)           echo "nmap" ;;
                python3-pip)    echo "python-pip" ;;
                python3-full)   echo "python" ;;
                build-essential) echo "base-devel" ;;
                libpcap-dev)    echo "libpcap" ;;
                wireshark-cli)  echo "wireshark-cli" ;;
                tshark)         echo "" ;;
                smbclient)      echo "smbclient" ;;
                rpcclient)      echo "" ;;
                ldap-utils)     echo "openldap" ;;
                john-data)      echo "" ;;
                wordlists)      echo "" ;;
                arpspoof)       echo "dsniff" ;;
                snmpcheck)      echo "" ;;
                redis-tools)    echo "redis" ;;
                pipx)           echo "python-pipx" ;;
                *)              echo "$tool" ;;
            esac
            ;;
        brew)
            case "$tool" in
                dnsutils)       echo "" ;;  # macOS has dig built-in
                netcat-openbsd) echo "netcat" ;;
                netcat-traditional) echo "" ;;
                ncat)           echo "nmap" ;;
                python3-pip)    echo "" ;;  # included with python
                python3-full)   echo "python@3" ;;
                build-essential) echo "" ;;  # Xcode CLT handles this
                libpcap-dev)    echo "" ;;  # macOS has it
                wireshark-cli)  echo "wireshark" ;;
                tshark)         echo "" ;;
                smbclient)      echo "" ;;
                rpcclient)      echo "" ;;
                ldap-utils)     echo "" ;;
                john-data)      echo "" ;;
                wordlists)      echo "" ;;
                pipx)           echo "pipx" ;;
                arpspoof)       echo "" ;;
                responder)      echo "" ;;  # pip install
                enum4linux)     echo "" ;;
                radare2)        echo "radare2" ;;
                *)              echo "$tool" ;;
            esac
            ;;
        choco)
            case "$tool" in
                nmap)           echo "nmap" ;;
                python3-pip)    echo "python3" ;;
                python3-full)   echo "" ;;
                curl)           echo "curl" ;;
                wget)           echo "wget" ;;
                git)            echo "git" ;;
                jq)             echo "jq" ;;
                wireshark-cli)  echo "wireshark" ;;
                *)              echo "" ;;  # most tools unavailable on choco
            esac
            ;;
        *)
            echo "$tool"
            ;;
    esac
}

# Check if a system package is installed
pkg_is_installed() {
    local pkg="$1"
    case "$PKG_MGR" in
        apt)    dpkg -s "$pkg" &>/dev/null 2>&1 ;;
        dnf|yum) rpm -q "$pkg" &>/dev/null ;;
        pacman) pacman -Qi "$pkg" &>/dev/null ;;
        brew)   brew list "$pkg" &>/dev/null ;;
        apk)    apk info -e "$pkg" &>/dev/null ;;
        choco)  choco list --local-only "$pkg" &>/dev/null ;;
        scoop)  scoop list "$pkg" &>/dev/null 2>&1 ;;
        *)      return 1 ;;
    esac
}

# Install a system package
install_pkg() {
    local pkg="$1"
    local mapped_name
    mapped_name=$(get_pkg_name "$pkg")

    # Skip if mapped to empty (not available on this platform)
    if [[ -z "$mapped_name" ]]; then
        skip "$pkg (not available on $DISTRO/$PKG_MGR)"
        return 0
    fi

    # Handle multi-package mappings (e.g., "gcc make")
    for name in $mapped_name; do
        if pkg_is_installed "$name" || command_exists "$name"; then
            ok "$name (already installed)"
            continue
        fi

        if [[ "$PKG_MGR" == "none" ]]; then
            skip "$name (no package manager found)"
            continue
        fi

        info "Installing $name ..."
        local install_cmd="$PKG_INSTALL"
        [[ -n "$SUDO" ]] && install_cmd="$SUDO $PKG_INSTALL"

        # Retry install up to 2 times (handles transient lock/network issues)
        local inst_ok=false
        for _try in 1 2; do
            if $install_cmd "$name" >> "$LOG_FILE" 2>&1; then
                inst_ok=true
                break
            fi
            [[ $_try -lt 2 ]] && sleep 2
        done
        if [[ "$inst_ok" == "true" ]]; then
            ok "$name"
        else
            err "Failed: $name (see $LOG_FILE)"
        fi
    done
}

# ── Batch install: collect packages, install in one apt-get call ──
# This is MUCH faster than one-by-one because apt resolves deps only once.
batch_install_category() {
    local category_label="$1"
    shift
    local tools=("$@")

    echo -e "\n  ${DIM}── ${category_label} ──${NC}"

    local need_install=()

    for pkg in "${tools[@]}"; do
        local mapped_name
        mapped_name=$(get_pkg_name "$pkg")

        if [[ -z "$mapped_name" ]]; then
            skip "$pkg (not available on $DISTRO/$PKG_MGR)"
            continue
        fi

        for name in $mapped_name; do
            if pkg_is_installed "$name" || command_exists "$name"; then
                ok "$name (already installed)"
            else
                need_install+=("$name")
            fi
        done
    done

    if [[ ${#need_install[@]} -eq 0 ]]; then
        return
    fi

    info "Batch installing ${#need_install[@]} packages: ${need_install[*]}"
    local install_cmd="$PKG_INSTALL"
    [[ -n "$SUDO" ]] && install_cmd="$SUDO $PKG_INSTALL"

    if $install_cmd "${need_install[@]}" >> "$LOG_FILE" 2>&1; then
        for name in "${need_install[@]}"; do ok "$name"; done
    else
        # Batch failed because at least one package is broken/missing. Install one by one.
        for name in "${need_install[@]}"; do
            if $install_cmd "$name" >> "$LOG_FILE" 2>&1; then
                ok "$name"
            else
                err "Failed: $name (see $LOG_FILE)"
            fi
        done
    fi
}

# Install via pip (with fallbacks)
pip_install() {
    local pkg="$1"
    local desc="${2:-$1}"

    # Check if already installed
    if command_exists "$pkg" || python3 -c "import $pkg" 2>/dev/null; then
        ok "$desc (already installed)"
        return 0
    fi

    info "pip install $desc ..."

    # Try multiple strategies
    if pip3 install -q --break-system-packages "$pkg" >> "$LOG_FILE" 2>&1; then
        ok "$desc"
    elif pip3 install -q --user "$pkg" >> "$LOG_FILE" 2>&1; then
        ok "$desc (user)"
    elif pip3 install -q "$pkg" >> "$LOG_FILE" 2>&1; then
        ok "$desc"
    elif command_exists pipx; then
        pipx install "$pkg" >> "$LOG_FILE" 2>&1 && ok "$desc (pipx)" || err "Failed: $desc"
    else
        err "Failed: $desc"
    fi
}

# ══════════════════════════════════════════════════════════════════════
# BANNER
# ══════════════════════════════════════════════════════════════════════

show_banner() {
    clear 2>/dev/null || true
    echo ""
    echo -e "${CYAN}   ██████╗██╗   ██╗██████╗ ███████╗██████╗        ${MAGENTA}██████╗ ██████╗ ██████╗ ██╗██╗      ██████╗ ████████╗${NC}"
    echo -e "${CYAN}  ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗      ${MAGENTA}██╔════╝██╔═══██╗██╔══██╗██║██║     ██╔═══██╗╚══██╔══╝${NC}"
    echo -e "${CYAN}  ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝█████╗${MAGENTA}██║     ██║   ██║██████╔╝██║██║     ██║   ██║   ██║${NC}"
    echo -e "${CYAN}  ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗╚════╝${MAGENTA}██║     ██║   ██║██╔═══╝ ██║██║     ██║   ██║   ██║${NC}"
    echo -e "${CYAN}  ╚██████╗   ██║   ██████╔╝███████╗██║  ██║      ${MAGENTA}╚██████╗╚██████╔╝██║     ██║███████╗╚██████╔╝   ██║${NC}"
    echo -e "${CYAN}   ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝      ${MAGENTA} ╚═════╝ ╚═════╝ ╚═╝     ╚═╝╚══════╝ ╚═════╝    ╚═╝${NC}"
    echo ""
    echo -e "  ${DIM}Universal Tool Installer ${SCRIPT_VERSION}${NC}"
    echo ""
}

show_system_info() {
    local wsl_tag=""
    [[ "$IS_WSL" == "true" ]] && wsl_tag=" (WSL)"
    local arm_tag=""
    [[ "$IS_ARM" == "true" ]] && arm_tag=" [ARM]"
    local priv_tag="${RED}no root${NC}"
    [[ "$IS_ROOT" == "true" ]] && priv_tag="${GREEN}root${NC}"
    [[ "$CAN_SUDO" == "true" && "$IS_ROOT" == "false" ]] && priv_tag="${YELLOW}sudo${NC}"

    local fs_tag=""
    [[ "$IS_SHARED_FS" == "true" ]] && fs_tag="  ${YELLOW}[shared FS]${NC}"

    echo -e "  ${BOLD}┌─────────────────────────────────────────────────┐${NC}"
    echo -e "  ${BOLD}│${NC}  ${CYAN}OS${NC}         ${BOLD}${OS^}${NC}${wsl_tag}${arm_tag}"
    echo -e "  ${BOLD}│${NC}  ${CYAN}Distro${NC}     ${BOLD}${DISTRO^}${NC}"
    echo -e "  ${BOLD}│${NC}  ${CYAN}Arch${NC}       ${BOLD}${ARCH}${NC}"
    echo -e "  ${BOLD}│${NC}  ${CYAN}PkgMgr${NC}     ${BOLD}${PKG_MGR}${NC}"
    echo -e "  ${BOLD}│${NC}  ${CYAN}Privs${NC}      ${priv_tag}"
    echo -e "  ${BOLD}│${NC}  ${CYAN}Tools Dir${NC}  ${BOLD}${TOOLS_DIR}${NC}"
    echo -e "  ${BOLD}│${NC}  ${CYAN}Venv${NC}       ${BOLD}${VENV_DIR}${NC}${fs_tag}"
    echo -e "  ${BOLD}│${NC}  ${CYAN}Log${NC}        ${DIM}${LOG_FILE}${NC}"
    echo -e "  ${BOLD}└─────────────────────────────────────────────────┘${NC}"
    echo ""
}

# ══════════════════════════════════════════════════════════════════════
# INSTALLATION CATEGORIES
# ══════════════════════════════════════════════════════════════════════

install_system_packages() {
    header "SYSTEM PACKAGES ($PKG_MGR)"

    if [[ "$PKG_MGR" == "none" ]]; then
        warn "No package manager found. Skipping system packages."
        warn "Install Homebrew (macOS) or Chocolatey (Windows) first."
        return
    fi

    # Prevent interactive prompts during apt installs (e.g. wireshark license)
    export DEBIAN_FRONTEND=noninteractive

    # Wait for any existing apt/dpkg lock (e.g. unattended-upgrades)
    if [[ "$PKG_MGR" == "apt" ]]; then
        local lock_wait=0
        while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || \
              fuser /var/lib/apt/lists/lock >/dev/null 2>&1; do
            if [[ $lock_wait -eq 0 ]]; then
                info "Waiting for apt/dpkg lock to be released..."
            fi
            sleep 2
            ((lock_wait+=2))
            if [[ $lock_wait -ge 120 ]]; then
                warn "apt lock held for >120s — proceeding anyway"
                break
            fi
        done
    fi

    # Update package lists (only for relevant managers)
    if [[ "$PKG_MGR" =~ ^(apt|dnf|yum|pacman|apk|zypper|brew)$ ]]; then
        info "Updating package lists..."
        local update_cmd="$PKG_UPDATE"
        [[ -n "$SUDO" ]] && update_cmd="$SUDO $PKG_UPDATE"

        # Retry apt-get update up to 3 times
        local attempt=0
        local update_ok=false
        while [[ $attempt -lt 3 ]]; do
            if $update_cmd >> "$LOG_FILE" 2>&1; then
                update_ok=true
                break
            fi
            ((attempt++))
            [[ $attempt -lt 3 ]] && sleep 3
        done
        if [[ "$update_ok" != "true" ]]; then
            warn "Package update failed after 3 attempts (continuing anyway)"
        fi
    fi

    # Core build tools
    local CORE_TOOLS=(
        curl wget jq git make gcc build-essential
        python3-pip python3-full pipx unzip default-jdk
    )

    # Network tools
    local NET_TOOLS=(
        nmap netcat-openbsd netcat-traditional ncat socat
        dnsutils whois tcpdump
        wireshark-cli tshark
        sslscan
        tor proxychains4 proxychains
        ettercap-text-only bettercap
    )

    # Security tools (apt/dnf packages)
    local SEC_TOOLS=(
        gobuster sqlmap hydra nikto whatweb feroxbuster
        dnsrecon dnsenum fierce
        hashcat john john-data
        masscan wafw00f amass radare2 gdb
        smbclient rpcclient ldap-utils
        responder enum4linux smbmap snmpcheck redis-tools
        powershell-empire zaproxy foremost sshuttle sliver
    )

    # Kali-specific
    local KALI_TOOLS=()
    if [[ "$DISTRO" == "kali" ]]; then
        KALI_TOOLS=(wordlists arpspoof exploitdb anonsurf kali-anonsurf)
    fi

    # Batch install per category — one apt-get call each (MUCH faster)
    batch_install_category "Core Tools"    "${CORE_TOOLS[@]}"
    batch_install_category "Network Tools" "${NET_TOOLS[@]}"
    batch_install_category "Security Tools" "${SEC_TOOLS[@]}"

    if [[ ${#KALI_TOOLS[@]} -gt 0 ]]; then
        batch_install_category "Kali-Specific" "${KALI_TOOLS[@]}"
    fi
}

install_go_tools() {
    header "GO TOOLS (ProjectDiscovery Suite + Others)"

    # Install Go if missing
    if ! command_exists go; then
        info "Go not found — installing..."

        local GO_VER="1.22.5"
        local GO_ARCH="amd64"
        [[ "$IS_ARM" == "true" ]] && GO_ARCH="arm64"

        if [[ "$OS" == "macos" ]]; then
            if [[ "$PKG_MGR" == "brew" ]]; then
                brew install go >> "$LOG_FILE" 2>&1 && ok "Go (brew)" || err "Failed to install Go"
            else
                local pkg="go${GO_VER}.darwin-${GO_ARCH}.tar.gz"
                wget -q "https://go.dev/dl/${pkg}" -O /tmp/go.tar.gz
                $SUDO rm -rf /usr/local/go
                $SUDO tar -C /usr/local -xzf /tmp/go.tar.gz
                ok "Go ${GO_VER}"
            fi
        elif [[ "$OS" == "linux" ]]; then
            local pkg="go${GO_VER}.linux-${GO_ARCH}.tar.gz"
            wget -q "https://go.dev/dl/${pkg}" -O /tmp/go.tar.gz || {
                err "Failed to download Go. Install manually: https://go.dev/dl/"
                return
            }
            $SUDO rm -rf /usr/local/go
            $SUDO tar -C /usr/local -xzf /tmp/go.tar.gz
            ok "Go ${GO_VER}"
        elif [[ "$OS" == "windows" ]]; then
            if [[ "$PKG_MGR" == "choco" ]]; then
                choco install golang -y >> "$LOG_FILE" 2>&1 && ok "Go (choco)" || err "Failed to install Go"
            elif [[ "$PKG_MGR" == "scoop" ]]; then
                scoop install go >> "$LOG_FILE" 2>&1 && ok "Go (scoop)" || err "Failed to install Go"
            else
                warn "Install Go manually: https://go.dev/dl/"
                return
            fi
        fi
    else
        ok "Go $(go version 2>/dev/null | awk '{print $3}' || echo 'installed')"
    fi

    # Ensure Go paths are set
    export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
    export GOPATH="${GOPATH:-$HOME/go}"

    # Persist Go PATH
    local SHELL_RC="$HOME/.bashrc"
    [[ -f "$HOME/.zshrc" ]] && SHELL_RC="$HOME/.zshrc"
    if ! grep -q 'go/bin' "$SHELL_RC" 2>/dev/null; then
        echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> "$SHELL_RC"
        info "Added Go to PATH in $SHELL_RC"
    fi

    if ! command_exists go; then
        err "Go is still not accessible. Skipping Go tools."
        return
    fi

    local GO_TOOLS=(
        "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest|subfinder"
        "github.com/projectdiscovery/httpx/cmd/httpx@latest|httpx"
        "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest|nuclei"
        "github.com/projectdiscovery/alterx/cmd/alterx@latest|alterx"
        "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest|naabu"
        "github.com/projectdiscovery/dnsx/cmd/dnsx@latest|dnsx"
        "github.com/projectdiscovery/katana/cmd/katana@latest|katana"
        "github.com/projectdiscovery/chaos-client/cmd/chaos@latest|chaos"
        "github.com/ffuf/ffuf/v2@latest|ffuf"
        "github.com/lc/gau/v2/cmd/gau@latest|gau"
        "github.com/jaeles-project/gospider@latest|gospider"
        "github.com/tomnomnom/assetfinder@latest|assetfinder"
        "github.com/tomnomnom/waybackurls@latest|waybackurls"
        "github.com/hakluke/hakrawler@latest|hakrawler"
        "github.com/ropnop/kerbrute@latest|kerbrute"
        "github.com/jpillora/chisel@latest|chisel"
        "github.com/owasp-amass/amass/v4/...@master|amass"
        "github.com/hahwul/dalfox/v2@latest|dalfox"
        "github.com/haccer/subjack@latest|subjack"
        "github.com/rverton/webanalyze/cmd/webanalyze@latest|webanalyze"
        "github.com/trufflesecurity/trufflehog/v3@latest|trufflehog"
        "github.com/zricethezav/gitleaks/v8@latest|gitleaks"
        "github.com/assetnote/kiterunner/cmd/kr@latest|kr"
        "github.com/liamg/traitor@latest|traitor"
    )

    # ── Parallel Go installs (huge speed boost) ──
    local go_pids=()      # background PIDs
    local go_tools=()     # tool names (parallel to pids)
    local go_tmpfiles=()  # per-tool log files

    for entry in "${GO_TOOLS[@]}"; do
        local pkg="${entry%|*}"
        local tool="${entry#*|}"
        if command_exists "$tool"; then
            ok "$tool (already installed)"
        else
            info "go install $tool ..."
            local tmplog="/tmp/go-install-${tool}.log"
            go install "$pkg" > "$tmplog" 2>&1 &
            go_pids+=("$!")
            go_tools+=("$tool")
            go_tmpfiles+=("$tmplog")
        fi
    done

    # Wait for all parallel Go installs to finish
    if [[ ${#go_pids[@]} -gt 0 ]]; then
        info "Waiting for ${#go_pids[@]} parallel Go installs..."
        for i in "${!go_pids[@]}"; do
            if wait "${go_pids[$i]}"; then
                ok "${go_tools[$i]}"
                # Ensure binary is globally available even if installed via sudo
                if [[ -f "$GOPATH/bin/${go_tools[$i]}" ]]; then
                    if [[ -n "$SUDO" ]]; then
                        $SUDO cp "$GOPATH/bin/${go_tools[$i]}" /usr/local/bin/ 2>/dev/null || true
                    fi
                    # Symlink kr to kiterunner if it was kiterunner
                    if [[ "${go_tools[$i]}" == "kr" && -n "$SUDO" ]]; then
                        $SUDO ln -sf /usr/local/bin/kr /usr/local/bin/kiterunner 2>/dev/null || true
                    elif [[ "${go_tools[$i]}" == "kr" ]]; then
                        ln -sf "$GOPATH/bin/kr" "$GOPATH/bin/kiterunner" 2>/dev/null || true
                    fi
                fi
            else
                err "Failed: ${go_tools[$i]}"
            fi
            cat "${go_tmpfiles[$i]}" >> "$LOG_FILE" 2>/dev/null
            rm -f "${go_tmpfiles[$i]}"
        done
    fi

    # Update nuclei templates
    if command_exists nuclei; then
        info "Updating nuclei templates..."
        nuclei -update-templates -silent >> "$LOG_FILE" 2>&1 && ok "Nuclei templates updated" || warn "Nuclei template update failed"
    fi
}

install_python_tools() {
    header "PYTHON TOOLS (pip)"

    # Ensure pip3 is available
    if ! command_exists pip3 && ! command_exists pip; then
        warn "pip not found. Trying to install..."
        if command_exists python3; then
            python3 -m ensurepip --upgrade >> "$LOG_FILE" 2>&1 || true
            python3 -m pip install --upgrade pip >> "$LOG_FILE" 2>&1 || true
        fi
    fi

    if ! command_exists pip3 && ! command_exists pip; then
        err "pip is not available. Skipping Python tools."
        return
    fi

    # Alias pip3/pip
    if ! command_exists pip3; then
        pip3() { pip "$@"; }
    fi

    local PIP_TOOLS=(
        arjun           # parameter discovery
        dirsearch       # web directory brute-force
        wafw00f         # WAF detection
        shodan          # Shodan CLI
        pyjwt           # JWT library
        impacket        # Windows/AD attack suite
        playwright      # headless browser automation
        fpdf2           # PDF generation
        matplotlib      # Charts for reports
        pwntools        # Binary exploit dev
        ropgadget       # ROP chain generator
        certipy-ad      # AD CS exploitation
        netexec         # CrackMapExec successor
        bloodhound      # BloodHound Python ingestor
        volatility3     # Memory forensics
        donpapi         # DPAPI creds extractor
        tornet          # IP Rotation (Tor)
        mitmproxy       # Proxy / intercept
        lsassy          # AD lateral movement
        coercer         # AD forced authentication
        mitm6           # IPv6 DNS poisoning
        sprayhound      # AD password spraying
        plumhound       # BloodHound reporting
        roadrecon       # Azure AD recon
        villain         # C2 Framework
        sublist3r       # Subdomain enumeration
        wfuzz           # Web fuzzer
        pacu            # AWS exploitation framework
        scoutsuite      # Multi-cloud security auditing
        prowler         # Cloud security assessments
        awscli          # AWS command line interface
        inql            # GraphQL scanner
        pip-audit       # Python dependency scanner
        pwncat-cs       # Reverse shell handler
        angr            # Binary analysis framework
        enum4linux-ng   # Next-gen enum4linux
    )

    for pkg in "${PIP_TOOLS[@]}"; do
        pip_install "$pkg"
    done

    # Persist ~/.local/bin in PATH (pip user installs)
    local SHELL_RC="$HOME/.bashrc"
    [[ -f "$HOME/.zshrc" ]] && SHELL_RC="$HOME/.zshrc"
    if ! grep -q '\.local/bin' "$SHELL_RC" 2>/dev/null; then
        echo 'export PATH=$PATH:$HOME/.local/bin' >> "$SHELL_RC"
        info "Added ~/.local/bin to PATH in $SHELL_RC"
    fi

    # Install Playwright browser binaries after the package is installed
    if command_exists playwright || python3 -c "import playwright" 2>/dev/null; then
        info "Installing Playwright Chromium browser binary..."
        python3 -m playwright install chromium >> "$LOG_FILE" 2>&1 \
            && ok "Playwright Chromium binary" \
            || warn "Playwright Chromium install failed — run: python3 -m playwright install chromium"
    fi
}

install_ruby_tools() {
    header "RUBY TOOLS"

    if ! command_exists gem; then
        if [[ "$PKG_MGR" == "apt" ]]; then
            info "Installing Ruby..."
            $SUDO $PKG_INSTALL ruby-full >> "$LOG_FILE" 2>&1 && ok "Ruby" || {
                warn "Ruby not installed. Skipping Ruby tools."
                return
            }
        elif [[ "$PKG_MGR" == "brew" ]]; then
            brew install ruby >> "$LOG_FILE" 2>&1 && ok "Ruby" || { warn "Ruby not installed"; return; }
        else
            warn "gem not found. Install Ruby for evil-winrm / wpscan."
            return
        fi
    fi

    local GEMS=(evil-winrm wpscan)
    for gem_name in "${GEMS[@]}"; do
        if command_exists "$gem_name"; then
            ok "$gem_name (already installed)"
        else
            info "gem install $gem_name ..."
            if [[ -n "$SUDO" ]]; then
                $SUDO gem install "$gem_name" --quiet >> "$LOG_FILE" 2>&1 && ok "$gem_name" || err "Failed: $gem_name"
            else
                gem install "$gem_name" --user-install --quiet >> "$LOG_FILE" 2>&1 && ok "$gem_name" || err "Failed: $gem_name"
            fi
        fi
    done
}

install_github_tools() {
    header "GITHUB CLONE TOOLS"

    mkdir -p "$TOOLS_DIR"

    clone_and_setup() {
        local repo="$1"
        local name="$2"
        local post_cmd="${3:-}"
        local dest="$TOOLS_DIR/$(basename "$repo")"

        if [[ -d "$dest" ]]; then
            ok "$name (already cloned)"
            return
        fi

        info "Cloning $repo ..."
        # GIT_TERMINAL_PROMPT=0 prevents git from asking for credentials on
        # private/deleted repos — it will just fail immediately instead of blocking.
        if GIT_TERMINAL_PROMPT=0 git clone -q --depth 1 "https://github.com/$repo" "$dest" >> "$LOG_FILE" 2>&1; then
            ok "$name"
            if [[ -n "$post_cmd" ]]; then
                (cd "$dest" && eval "$post_cmd" >> "$LOG_FILE" 2>&1) || warn "$name post-install failed"
            fi
        else
            err "Failed to clone: $name (repo may be private/deleted)"
        fi
    }

    # Wrapper script creator
    make_wrapper() {
        local script_path="$1"
        local wrapper_name="$2"
        local target_dir="/usr/local/bin"

        [[ "$OS" == "macos" ]] && target_dir="/usr/local/bin"

        if [[ -f "$script_path" ]]; then
            local wrapper="#!/usr/bin/env bash\npython3 \"$script_path\" \"\$@\""
            if [[ -n "$SUDO" || "$IS_ROOT" == "true" ]]; then
                echo -e "$wrapper" | $SUDO tee "$target_dir/$wrapper_name" > /dev/null
                $SUDO chmod +x "$target_dir/$wrapper_name" && info "Wrapper: $wrapper_name → $target_dir"
            else
                local user_bin="$HOME/.local/bin"
                mkdir -p "$user_bin"
                echo -e "$wrapper" > "$user_bin/$wrapper_name"
                chmod +x "$user_bin/$wrapper_name" && info "Wrapper: $wrapper_name → $user_bin"
            fi
        fi
    }

    # XSStrike
    clone_and_setup "s0md3v/XSStrike" "XSStrike" \
        "pip3 install -q --break-system-packages -r requirements.txt 2>/dev/null || pip3 install -q -r requirements.txt 2>/dev/null || true"
    make_wrapper "$TOOLS_DIR/XSStrike/xsstrike.py" "xsstrike"

    # commix
    clone_and_setup "commixproject/commix" "commix" \
        "pip3 install -q --break-system-packages -r requirements.txt 2>/dev/null || true"
    make_wrapper "$TOOLS_DIR/commix/commix.py" "commix"

    # CloudFlair
    clone_and_setup "christophetd/CloudFlair" "CloudFlair" \
        "pip3 install -q --break-system-packages -r requirements.txt 2>/dev/null || true"
    make_wrapper "$TOOLS_DIR/CloudFlair/cloudflair.py" "cloudflair"

    # Whisker (AD Shadow Credentials — .NET)
    clone_and_setup "eladshamir/Whisker" "Whisker" ""

    # CMSeeK
    clone_and_setup "Tuhinshubhra/CMSeeK" "CMSeeK" \
        "pip3 install -q --break-system-packages -r requirements.txt 2>/dev/null || true"
    make_wrapper "$TOOLS_DIR/CMSeeK/cmseek.py" "cmseek"

    # WPSeku — REMOVED: repo m4ll0k/WPSeku is deleted/private, clone blocks on credentials
    # clone_and_setup "m4ll0k/WPSeku" "WPSeku" ...

    # WPProbe — REMOVED: repo theInfection/WPProbe does not exist
    # clone_and_setup "theInfection/WPProbe" "WPProbe" ...

    # gqlmap (Local)
    if [[ -f "$PROJECT_DIR/gqlmap/gqlmap.py" ]]; then
        info "Setting up local gqlmap..."
        chmod +x "$PROJECT_DIR/gqlmap/gqlmap.py"
        if [[ -n "$SUDO" || "$IS_ROOT" == "true" ]]; then
            $SUDO ln -sf "$PROJECT_DIR/gqlmap/gqlmap.py" /usr/local/bin/gqlmap
        else
            mkdir -p "$HOME/.local/bin"
            ln -sf "$PROJECT_DIR/gqlmap/gqlmap.py" "$HOME/.local/bin/gqlmap"
        fi
        ok "gqlmap (local)"
    else
        warn "Local gqlmap not found in project directory"
    fi

    # jwt_tool
    clone_and_setup "ticarpi/jwt_tool" "jwt_tool" \
        "pip3 install -q --break-system-packages -r requirements.txt 2>/dev/null || true"
    make_wrapper "$TOOLS_DIR/jwt_tool/jwt_tool.py" "jwt_tool"

    # Gopherus
    clone_and_setup "tarunkant/Gopherus" "Gopherus" \
        "chmod +x gopherus.py"
    make_wrapper "$TOOLS_DIR/Gopherus/gopherus.py" "gopherus"

    # Corsy
    clone_and_setup "s0md3v/Corsy" "Corsy" \
        "pip3 install -q --break-system-packages -r requirements.txt 2>/dev/null || true"
    make_wrapper "$TOOLS_DIR/Corsy/corsy.py" "corsy"

    # graphql-cop
    clone_and_setup "doyensec/graphql-cop" "graphql-cop" \
        "pip3 install -q --break-system-packages -r requirements.txt 2>/dev/null || true"
    make_wrapper "$TOOLS_DIR/graphql-cop/graphql-cop.py" "graphql-cop"

    # tplmap
    clone_and_setup "epinna/tplmap" "tplmap" \
        "pip3 install -q --break-system-packages -r requirements.txt 2>/dev/null || true"
    make_wrapper "$TOOLS_DIR/tplmap/tplmap.py" "tplmap"

    # PetitPotam
    clone_and_setup "topotam/PetitPotam" "PetitPotam" ""
    make_wrapper "$TOOLS_DIR/PetitPotam/PetitPotam.py" "petitpotam"

    # PEASS-ng
    clone_and_setup "carlospolop/PEASS-ng" "PEASS-ng" ""
    
    # Cloud_enum
    clone_and_setup "initstring/cloud_enum" "cloud_enum" \
        "pip3 install -q --break-system-packages -r requirements.txt 2>/dev/null || true"
    make_wrapper "$TOOLS_DIR/cloud_enum/cloud_enum.py" "cloud_enum"

    # Seatbelt
    clone_and_setup "GhostPack/Seatbelt" "Seatbelt" ""

    # Certify
    clone_and_setup "GhostPack/Certify" "Certify" ""

    # ODAT
    clone_and_setup "quentinhardy/odat" "odat" \
        "pip3 install -q --break-system-packages -r requirements.txt 2>/dev/null || true"
    make_wrapper "$TOOLS_DIR/odat/odat.py" "odat"

    # phpggc
    clone_and_setup "ambionics/phpggc" "phpggc" ""
    make_wrapper "$TOOLS_DIR/phpggc/phpggc" "phpggc"

    # msolspray
    clone_and_setup "dafthack/MSOLSpray" "msolspray" \
        "pip3 install -q --break-system-packages -r requirements.txt 2>/dev/null || true"
    make_wrapper "$TOOLS_DIR/msolspray/msolspray.py" "msolspray"

    # pupy
    clone_and_setup "n1nj4sec/pupy" "pupy" "git submodule init && git submodule update"
    
    # havoc
    clone_and_setup "HavocFramework/Havoc" "havoc" "echo 'Havoc cloned; requires manual compilation.'"

    # ysoserial
    if [ ! -f "$TOOLS_DIR/ysoserial/ysoserial-all.jar" ]; then
        info "Downloading ysoserial..."
        mkdir -p "$TOOLS_DIR/ysoserial"
        wget -q "https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar" -O "$TOOLS_DIR/ysoserial/ysoserial-all.jar"
        echo '#!/bin/bash' > "$TOOLS_DIR/ysoserial/ysoserial"
        echo "java -jar $TOOLS_DIR/ysoserial/ysoserial-all.jar \"\$@\"" >> "$TOOLS_DIR/ysoserial/ysoserial"
        chmod +x "$TOOLS_DIR/ysoserial/ysoserial"
        make_wrapper "$TOOLS_DIR/ysoserial/ysoserial" "ysoserial"
    fi

    # sharphound
    if [ ! -f "$TOOLS_DIR/sharphound/SharpHound.exe" ]; then
        info "Downloading SharpHound..."
        mkdir -p "$TOOLS_DIR/sharphound"
        wget -q "https://github.com/BloodHoundAD/BloodHound/raw/master/Collectors/SharpHound.exe" -O "$TOOLS_DIR/sharphound/SharpHound.exe"
    fi

    # pspy
    if [ ! -f "$TOOLS_DIR/pspy/pspy64" ]; then
        info "Downloading pspy..."
        mkdir -p "$TOOLS_DIR/pspy"
        wget -q "https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64" -O "$TOOLS_DIR/pspy/pspy64"
        chmod +x "$TOOLS_DIR/pspy/pspy64"
        make_wrapper "$TOOLS_DIR/pspy/pspy64" "pspy64"
    fi

    # rustscan
    if ! command_exists rustscan; then
        info "Downloading rustscan..."
        wget -q "https://github.com/RustScan/RustScan/releases/download/2.0.0/rustscan_2.0.0_amd64.deb" -O /tmp/rustscan.deb
        if [[ -n "$SUDO" ]]; then
            $SUDO dpkg -i /tmp/rustscan.deb 2>/dev/null || true
            $SUDO apt-get install -f -y 2>/dev/null || true
        fi
        rm -f /tmp/rustscan.deb
    fi

    # jadx
    if ! command_exists jadx; then
        info "Downloading jadx..."
        mkdir -p "$TOOLS_DIR/jadx"
        wget -q "https://github.com/skylot/jadx/releases/download/v1.4.7/jadx-1.4.7.zip" -O /tmp/jadx.zip
        unzip -q /tmp/jadx.zip -d "$TOOLS_DIR/jadx" 2>/dev/null || true
        rm -f /tmp/jadx.zip
        make_wrapper "$TOOLS_DIR/jadx/bin/jadx" "jadx"
    fi

    # gowitness (precompiled binary)
    if ! command_exists gowitness; then
        info "Downloading gowitness..."
        wget -q "https://github.com/sensepost/gowitness/releases/download/2.5.1/gowitness-2.5.1-linux-amd64" -O "$TOOLS_DIR/gowitness"
        chmod +x "$TOOLS_DIR/gowitness"
        make_wrapper "$TOOLS_DIR/gowitness" "gowitness"
    fi

    # aquatone (precompiled binary)
    if ! command_exists aquatone; then
        info "Downloading aquatone..."
        wget -q "https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip" -O /tmp/aquatone.zip
        unzip -q /tmp/aquatone.zip aquatone -d "$TOOLS_DIR" 2>/dev/null || true
        rm -f /tmp/aquatone.zip
        chmod +x "$TOOLS_DIR/aquatone"
        make_wrapper "$TOOLS_DIR/aquatone" "aquatone"
    fi
}

install_metasploit() {
    header "METASPLOIT FRAMEWORK"

    if command_exists msfconsole; then
        ok "Metasploit (already installed)"
        return
    fi

    case "$OS" in
        linux)
            info "Installing Metasploit..."
            if curl -fsSL https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb \
                > /tmp/msfinstall 2>> "$LOG_FILE"; then
                chmod 755 /tmp/msfinstall
                /tmp/msfinstall >> "$LOG_FILE" 2>&1 && ok "Metasploit" || err "Metasploit install failed (see $LOG_FILE)"
            else
                err "Failed to download Metasploit installer"
            fi
            ;;
        macos)
            if [[ "$PKG_MGR" == "brew" ]]; then
                brew install metasploit >> "$LOG_FILE" 2>&1 && ok "Metasploit (brew)" || err "Metasploit failed"
            else
                warn "Install Metasploit manually: https://metasploit.com/download"
            fi
            ;;
        windows)
            warn "Download Metasploit for Windows: https://metasploit.com/download"
            ;;
    esac
}

install_ligolo() {
    header "LIGOLO-NG (Tunneling/Pivoting)"

    if command_exists ligolo-proxy || command_exists ligolo; then
        ok "ligolo-ng (already installed)"
        return
    fi

    if [[ "$OS" == "windows" ]]; then
        warn "Download ligolo-ng for Windows: https://github.com/nicocha30/ligolo-ng/releases"
        return
    fi

    info "Installing ligolo-ng..."

    local LIGOLO_ARCH="amd64"
    [[ "$IS_ARM" == "true" ]] && LIGOLO_ARCH="arm64"
    local LIGOLO_OS="linux"
    [[ "$OS" == "macos" ]] && LIGOLO_OS="darwin"

    # Get latest version
    local LIGOLO_VER
    LIGOLO_VER=$(curl -s https://api.github.com/repos/nicocha30/ligolo-ng/releases/latest 2>/dev/null \
        | grep '"tag_name"' | head -1 | sed -E 's/.*"(v[^"]+)".*/\1/')
    LIGOLO_VER="${LIGOLO_VER:-v0.7.2}"

    local url="https://github.com/nicocha30/ligolo-ng/releases/download/${LIGOLO_VER}/ligolo-ng_proxy_${LIGOLO_VER#v}_${LIGOLO_OS}_${LIGOLO_ARCH}.tar.gz"

    if wget -q "$url" -O /tmp/ligolo.tar.gz >> "$LOG_FILE" 2>&1; then
        tar -xzf /tmp/ligolo.tar.gz -C /tmp/ >> "$LOG_FILE" 2>&1
        # Binary name varies between versions
        local bin_file
        bin_file=$(find /tmp/ -maxdepth 1 -name '*proxy*' -type f 2>/dev/null | head -1)
        if [[ -n "$bin_file" && -f "$bin_file" ]]; then
            $SUDO mv "$bin_file" /usr/local/bin/ligolo-proxy 2>/dev/null || mv "$bin_file" "$HOME/.local/bin/ligolo-proxy" 2>/dev/null
            chmod +x /usr/local/bin/ligolo-proxy 2>/dev/null || chmod +x "$HOME/.local/bin/ligolo-proxy" 2>/dev/null
            ok "ligolo-ng ${LIGOLO_VER}"
        else
            err "ligolo-ng binary not found after extraction"
        fi
        rm -f /tmp/ligolo.tar.gz
    else
        err "Failed to download ligolo-ng"
    fi
}

install_feroxbuster() {
    header "FEROXBUSTER (Fast Content Discovery)"

    if command_exists feroxbuster; then
        ok "feroxbuster (already installed)"
        return
    fi

    if [[ "$OS" == "linux" ]]; then
        # Try apt first (available on Kali/Ubuntu repos)
        if [[ "$PKG_MGR" == "apt" ]]; then
            $SUDO $PKG_INSTALL feroxbuster >> "$LOG_FILE" 2>&1 && ok "feroxbuster (apt)" && return
        fi
        # Fallback: official install script
        info "Installing feroxbuster via official script..."
        if curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh \
            | bash -s "$HOME/.local/bin" >> "$LOG_FILE" 2>&1; then
            ok "feroxbuster"
            mkdir -p "$HOME/.local/bin"
            export PATH="$PATH:$HOME/.local/bin"
        else
            err "feroxbuster install failed — try: cargo install feroxbuster"
        fi
    elif [[ "$OS" == "macos" ]]; then
        if [[ "$PKG_MGR" == "brew" ]]; then
            brew install feroxbuster >> "$LOG_FILE" 2>&1 && ok "feroxbuster (brew)" || err "feroxbuster failed"
        else
            warn "Install feroxbuster: https://github.com/epi052/feroxbuster/releases"
        fi
    else
        warn "Download feroxbuster: https://github.com/epi052/feroxbuster/releases"
    fi
}

install_searchsploit() {
    header "SEARCHSPLOIT (ExploitDB)"

    if command_exists searchsploit; then
        ok "searchsploit (already installed)"
        return
    fi

    case "$PKG_MGR" in
        apt)
            $SUDO $PKG_INSTALL exploitdb >> "$LOG_FILE" 2>&1 && ok "searchsploit (apt)" && return
            ;;
    esac

    # Fallback: pip
    pip_install "searchsploit" "searchsploit (pip)"
}

# ══════════════════════════════════════════════════════════════════════
# PATH FIXUP
# ══════════════════════════════════════════════════════════════════════

# ══════════════════════════════════════════════════════════════════════
# PYTHON VENV & REQUIREMENTS
# ══════════════════════════════════════════════════════════════════════

setup_venv() {
    header "PYTHON VIRTUAL ENVIRONMENT"

    local req_file="$PROJECT_DIR/requirements.txt"

    # Check Python3 is available
    if ! command_exists python3; then
        err "python3 not found — cannot create virtual environment"
        return 1
    fi

    # ── Cross-platform venv detection ──
    # A venv created on Windows has Scripts/ (no bin/). On Linux it has bin/ (no Scripts/).
    # If the existing venv was created on a different OS, delete it and recreate.
    local need_create=false
    if [[ -d "$VENV_DIR" ]]; then
        if [[ "$OS" == "linux" || "$OS" == "macos" ]]; then
            if [[ ! -f "$VENV_DIR/bin/activate" ]]; then
                warn "Existing venv was created on Windows (Scripts/ layout) — incompatible with Linux"
                info "Removing cross-platform venv and recreating..."
                rm -rf "$VENV_DIR"
                need_create=true
            else
                ok "Virtual environment already exists at $VENV_DIR"
            fi
        elif [[ "$OS" == "windows" ]]; then
            if [[ ! -f "$VENV_DIR/Scripts/activate" ]]; then
                warn "Existing venv was created on Linux (bin/ layout) — incompatible with Windows"
                info "Removing cross-platform venv and recreating..."
                rm -rf "$VENV_DIR"
                need_create=true
            else
                ok "Virtual environment already exists at $VENV_DIR"
            fi
        else
            ok "Virtual environment already exists at $VENV_DIR"
        fi
    else
        need_create=true
    fi

    if [[ "$need_create" == "true" ]]; then
        info "Creating virtual environment at $VENV_DIR ..."
        python3 -m venv --system-site-packages "$VENV_DIR" >> "$LOG_FILE" 2>&1
        if [[ $? -eq 0 ]]; then
            ok "Virtual environment created"
        else
            err "Failed to create venv (python3 -m venv may not be available)"
            warn "Try: sudo apt install python3-venv  OR  python3-full"
            return 1
        fi
    fi

    # Activate the venv for the rest of this script
    if [[ -f "$VENV_DIR/bin/activate" ]]; then
        source "$VENV_DIR/bin/activate"
        ok "Activated venv (Linux/macOS)"
    elif [[ -f "$VENV_DIR/Scripts/activate" ]]; then
        source "$VENV_DIR/Scripts/activate"
        ok "Activated venv (Windows/Git Bash)"
    else
        err "No activate script found in $VENV_DIR — venv may be corrupt"
        return 1
    fi

    # Verify the venv is actually working (python3 should point to the venv)
    local venv_python
    venv_python=$(python3 -c "import sys; print(sys.prefix)" 2>/dev/null)
    if [[ "$venv_python" != *".venv"* && "$venv_python" != *"$VENV_DIR"* ]]; then
        warn "Venv activation did not update python3 path (sys.prefix=$venv_python)"
        warn "Falling back to direct venv python..."
        # Use the venv's python directly
        if [[ -f "$VENV_DIR/bin/python3" ]]; then
            alias python3="$VENV_DIR/bin/python3"
            export PATH="$VENV_DIR/bin:$PATH"
        elif [[ -f "$VENV_DIR/Scripts/python.exe" ]]; then
            export PATH="$VENV_DIR/Scripts:$PATH"
        fi
    fi

    # Upgrade pip inside the venv
    # Use 'python3 -m pip' to guarantee we hit the venv's pip, not the system one.
    info "Upgrading pip inside venv..."
    python3 -m pip install --upgrade pip >> "$LOG_FILE" 2>&1 && ok "pip upgraded" || warn "pip upgrade failed"

    # ── Fix CRLF line endings in requirements.txt ──
    # If the file was edited on Windows it may have \r\n, which breaks bash parsing.
    if [[ -f "$req_file" ]] && grep -qP '\r' "$req_file" 2>/dev/null; then
        info "Fixing CRLF line endings in requirements.txt..."
        sed -i 's/\r$//' "$req_file"
    fi

    # Install requirements.txt
    if [[ -f "$req_file" ]]; then
        info "Installing requirements.txt ..."
        python3 -m pip install -r "$req_file" >> "$LOG_FILE" 2>&1
        if [[ $? -eq 0 ]]; then
            ok "requirements.txt installed ($(wc -l < "$req_file" | tr -d ' ') packages)"
        else
            err "Some packages in requirements.txt failed (see $LOG_FILE)"
            # Retry line-by-line for partial success
            warn "Retrying packages individually..."
            while IFS= read -r line; do
                # Skip comments and empty lines; strip \r for CRLF safety
                line=$(echo "$line" | tr -d '\r' | sed 's/#.*//' | xargs)
                [[ -z "$line" ]] && continue
                python3 -m pip install "$line" >> "$LOG_FILE" 2>&1 && ok "  $line" || err "  Failed: $line"
            done < "$req_file"
        fi
    else
        warn "No requirements.txt found at $req_file"
    fi

    # Create .env template if it doesn't exist
    local env_file="$PROJECT_DIR/.env"
    if [[ ! -f "$env_file" ]]; then
        info "Creating .env template..."
        {
            printf '# ══════════════════════════════════════════════════════════════════\n'
            printf '#  Cyber-CoPilot Environment Configuration\n'
            printf '#  Fill in your API keys below and save.\n'
            printf '# ══════════════════════════════════════════════════════════════════\n'
            printf '\n'
            printf '# LongCat API\n'
            printf 'LONGCAT_API_KEY=\n'
            printf 'LONGCAT_MODEL=\n'
            printf '\n'
            printf '# NVIDIA API (default provider)\n'
            printf 'NVIDIA_API_KEY=\n'
            printf 'NVIDIA_MODEL=stepfun-ai/step-3.7-flash\n'
            printf '\n'
            printf '# OpenRouter API (alternative)\n'
            printf 'OPENROUTER_API_KEY=\n'
            printf 'OPENROUTER_MODEL=anthropic/claude-3.5-sonnet\n'
            printf '\n'
            printf '# OpenAI API (alternative)\n'
            printf 'OPENAI_API_KEY=\n'
            printf 'OPENAI_MODEL=gpt-4\n'
            printf '\n'
            printf '# Default provider: nvidia | longcat | openrouter | openai | modelscope\n'
            printf 'DEFAULT_PROVIDER=nvidia\n'
            printf '\n'
            printf '# Optional: Shodan API key for OSINT\n'
            printf 'SHODAN_API_KEY=\n'
            printf '\n'
            printf '# Optional: Bug Bounty mode (aggressive exploitation)\n'
            printf '# BUGBOUNTY_MODE=true\n'
        } > "$env_file"
        ok ".env template created at $env_file"
        warn "Edit $env_file and add your API keys before running!"
    else
        ok ".env already exists"
    fi
}

# ══════════════════════════════════════════════════════════════════════
# FYP ALIAS SETUP
# ══════════════════════════════════════════════════════════════════════

setup_alias() {
    header "FYP QUICK-START ALIAS"

    # ── Thorough cleanup of ALL old fyp aliases from ALL shell RCs ──
    # This handles directory changes (e.g., project moved from ~/Desktop to /mnt/hgfs).
    local rc_files=()
    [[ -f "$HOME/.bashrc" ]] && rc_files+=("$HOME/.bashrc")
    [[ -f "$HOME/.zshrc" ]] && rc_files+=("$HOME/.zshrc")
    [[ -f "$HOME/.bash_profile" ]] && rc_files+=("$HOME/.bash_profile")

    for rc in "${rc_files[@]}"; do
        if grep -q "alias fyp=" "$rc" 2>/dev/null || grep -q "Cyber-CoPilot FYP" "$rc" 2>/dev/null; then
            info "Removing old fyp alias from $rc ..."
            # Remove the comment header + alias line + any trailing blank
            sed -i '/# ── Cyber-CoPilot FYP Quick Start ──/d' "$rc" 2>/dev/null || true
            sed -i '/alias fyp=/d' "$rc" 2>/dev/null || true
            # Clean up stale blank lines left behind (consecutive empty lines → one)
            sed -i '/^$/N;/^\n$/d' "$rc" 2>/dev/null || true
        fi
    done

    # Determine which shell RC to write the NEW alias into
    local SHELL_RC="$HOME/.bashrc"
    [[ -f "$HOME/.zshrc" ]] && SHELL_RC="$HOME/.zshrc"
    local EXTRA_RC=""
    [[ "$OS" == "macos" && -f "$HOME/.bash_profile" ]] && EXTRA_RC="$HOME/.bash_profile"

    # Build activation path (Linux vs Windows/Git Bash)
    local ACTIVATE_PATH="$VENV_DIR/bin/activate"
    [[ -f "$VENV_DIR/Scripts/activate" ]] && ACTIVATE_PATH="$VENV_DIR/Scripts/activate"

    # The alias: cd to project, activate venv, show status
    # IMPORTANT: Do NOT use heredocs here!  If this script has CRLF endings
    # (VMware shared folder) the heredoc closing delimiter gets a \r appended
    # and bash can never match it — the variable silently stays empty.
    # Direct printf is 100% CRLF-safe.
    {
        printf '\n# ── Cyber-CoPilot FYP Quick Start ──\n'
        printf "alias fyp='cd \"%s\" && source \"%s\"" "$PROJECT_DIR" "$ACTIVATE_PATH"
        printf ' && echo -e "\\033[0;36m"'
        printf ' && echo "  ██████╗ ██╗   ██╗██████╗"'
        printf ' && echo " ██╔════╝  ██║ ██╔╝██╔══██╗"'
        printf ' && echo " ██║       ████╔╝  ██████╔╝"'
        printf ' && echo " ██║       ╚██╔╝   ██╔═══╝"'
        printf ' && echo " ╚██████╗   ██║    ██║"'
        printf ' && echo "  ╚═════╝   ╚═╝    ╚═╝"'
        printf ' && echo -e "\\033[0m"'
        printf ' && echo -e "\\033[1;32m  ✓ Cyber-CoPilot environment activated\\033[0m"'
        printf ' && echo -e "\\033[0;36m  📂 %s\\033[0m"' "$PROJECT_DIR"
        printf ' && echo -e "\\033[0;33m  💡 Run: python3 main.py\\033[0m"'
        printf " && echo \"\"'\n"
    } >> "$SHELL_RC"
    ok "Alias 'fyp' added to $SHELL_RC"

    # Also add to extra RC if needed (macOS .bash_profile)
    if [[ -n "$EXTRA_RC" ]]; then
        {
            printf '\n# ── Cyber-CoPilot FYP Quick Start ──\n'
            printf "alias fyp='cd \"%s\" && source \"%s\"" "$PROJECT_DIR" "$ACTIVATE_PATH"
            printf ' && echo -e "\\033[0;36m"'
            printf ' && echo "  ██████╗ ██╗   ██╗██████╗"'
            printf ' && echo " ██╔════╝  ██║ ██╔╝██╔══██╗"'
            printf ' && echo " ██║       ████╔╝ ██████╔╝"'
            printf ' && echo " ██║       ╚██╔╝  ██╔═══╝"'
            printf ' && echo " ╚██████╗   ██║   ██║"'
            printf ' && echo "  ╚═════╝   ╚═╝   ╚═╝"'
            printf ' && echo -e "\\033[0m"'
            printf ' && echo -e "\\033[1;32m  ✓ Cyber-CoPilot environment activated\\033[0m"'
            printf ' && echo -e "\\033[0;36m  📂 %s\\033[0m"' "$PROJECT_DIR"
            printf ' && echo -e "\\033[0;33m  💡 Run: python3 main.py\\033[0m"'
            printf " && echo \"\"'\n"
        } >> "$EXTRA_RC"
        ok "Alias also added to $EXTRA_RC"
    fi

    # Fish shell support
    if command_exists fish; then
        local FISH_CONFIG="$HOME/.config/fish/config.fish"
        mkdir -p "$HOME/.config/fish" 2>/dev/null || true
        if [[ -f "$FISH_CONFIG" ]]; then
            # Use strict markers to safely delete the block even with nested 'end' statements
            sed -i '/# === CYBER-COPILOT FYP ALIAS BEGIN ===/,/# === CYBER-COPILOT FYP ALIAS END ===/d' "$FISH_CONFIG" 2>/dev/null || true
            # Clean up old legacy style just in case
            sed -i '/# ── Cyber-CoPilot FYP Quick Start ──/d' "$FISH_CONFIG" 2>/dev/null || true
        fi
        {
            printf '\n# === CYBER-COPILOT FYP ALIAS BEGIN ===\n'
            printf 'function fyp\n'
            printf '    cd "%s"\n' "$PROJECT_DIR"
            printf '    if test -f "%s.fish"\n' "$ACTIVATE_PATH"
            printf '        source "%s.fish"\n' "$ACTIVATE_PATH"
            printf '    end\n'
            printf '    set_color cyan\n'
            printf '    echo "  ██████╗ ██╗   ██╗██████╗"\n'
            printf '    echo " ██╔════╝  ██║ ██╔╝██╔══██╗"\n'
            printf '    echo " ██║       ████╔╝ ██████╔╝"\n'
            printf '    echo " ██║       ╚██╔╝  ██╔═══╝"\n'
            printf '    echo " ╚██████╗   ██║   ██║"\n'
            printf '    echo "  ╚═════╝   ╚═╝   ╚═╝"\n'
            printf '    set_color normal\n'
            printf '    set_color -o green; echo "  ✓ Cyber-CoPilot environment activated"; set_color normal\n'
            printf '    set_color cyan; echo "  📂 %s"; set_color normal\n' "$PROJECT_DIR"
            printf '    set_color yellow; echo "  💡 Run: python3 main.py"; set_color normal\n'
            printf '    echo ""\n'
            printf 'end\n'
            printf '# === CYBER-COPILOT FYP ALIAS END ===\n'
        } >> "$FISH_CONFIG"
        ok "Function 'fyp' added to $FISH_CONFIG"
    fi

    # Also create/update PowerShell function for Windows users
    if [[ "$OS" == "windows" ]] || [[ "$IS_WSL" == "true" ]]; then
        local PS_PROFILE_DIR="$HOME/Documents/PowerShell"
        [[ ! -d "$PS_PROFILE_DIR" ]] && PS_PROFILE_DIR="$HOME/Documents/WindowsPowerShell"

        if [[ -d "$PS_PROFILE_DIR" ]] || mkdir -p "$PS_PROFILE_DIR" 2>/dev/null; then
            local PS_PROFILE="$PS_PROFILE_DIR/Microsoft.PowerShell_profile.ps1"
            if [[ -f "$PS_PROFILE" ]]; then
                info "Removing old PowerShell fyp function..."
                sed -i '/# === CYBER-COPILOT FYP ALIAS BEGIN ===/,/# === CYBER-COPILOT FYP ALIAS END ===/d' "$PS_PROFILE" 2>/dev/null || true
                # Cleanup legacy
                sed -i '/# Cyber-CoPilot FYP Quick Start/,/^}/d' "$PS_PROFILE" 2>/dev/null || true
            fi
            {
                printf '\n# === CYBER-COPILOT FYP ALIAS BEGIN ===\n'
                printf 'function fyp {\n'
                printf '    Set-Location "%s"\n' "$PROJECT_DIR"
                printf '    if (Test-Path "%s/Scripts/Activate.ps1") {\n' "$VENV_DIR"
                printf '        & "%s/Scripts/Activate.ps1"\n' "$VENV_DIR"
                printf '    }\n'
                printf '    Write-Host "✓ Cyber-CoPilot environment activated" -ForegroundColor Green\n'
                printf '    Write-Host "  📂 %s" -ForegroundColor Cyan\n' "$PROJECT_DIR"
                printf '    Write-Host "  💡 Run: python main.py" -ForegroundColor Yellow\n'
                printf '}\n'
                printf '# === CYBER-COPILOT FYP ALIAS END ===\n'
            } >> "$PS_PROFILE"
            ok "PowerShell function 'fyp' written to $PS_PROFILE"
        fi
    fi

    echo ""
    info "Usage:  Type ${BOLD}fyp${NC} in any terminal to jump into the project"
    info "  fyp          → activates venv + cd to project"
    info "  python3 main.py  → start Cyber-CoPilot"
}

# ══════════════════════════════════════════════════════════════════════
# PATH FIXUP
# ══════════════════════════════════════════════════════════════════════

fixup_path() {
    header "PATH CONFIGURATION"

    local paths_to_add=(
        "$HOME/go/bin"
        "/usr/local/go/bin"
        "$HOME/.local/bin"
    )

    local SHELL_RC="$HOME/.bashrc"
    [[ -f "$HOME/.zshrc" ]] && SHELL_RC="$HOME/.zshrc"

    for p in "${paths_to_add[@]}"; do
        if [[ -d "$p" && ":$PATH:" != *":$p:"* ]]; then
            echo "export PATH=\$PATH:$p" >> "$SHELL_RC"
            export PATH="$PATH:$p"
            ok "Added $p to PATH"
        fi
    done

    info "Shell config: $SHELL_RC"
}

# ══════════════════════════════════════════════════════════════════════
# FINAL SUMMARY
# ══════════════════════════════════════════════════════════════════════

show_summary() {
    local END_TIME=$(date +%s)
    local ELAPSED=$(( END_TIME - START_TIME ))
    local MINS=$(( ELAPSED / 60 ))
    local SECS=$(( ELAPSED % 60 ))

    echo ""
    echo -e "${BOLD}${BLUE}══════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${GREEN}  ✓ INSTALLATION COMPLETE${NC}"
    echo -e "${BOLD}${BLUE}══════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${GREEN}✓ Installed:${NC}  ${BOLD}${INSTALLED}${NC}"
    echo -e "  ${RED}✗ Failed:${NC}     ${BOLD}${FAILED}${NC}"
    echo -e "  ${DIM}○ Skipped:${NC}    ${BOLD}${SKIPPED}${NC}"
    echo -e "  ${CYAN}⏱ Duration:${NC}  ${BOLD}${MINS}m ${SECS}s${NC}"
    echo ""
    echo -e "  ${CYAN}Key Locations:${NC}"
    echo -e "    Project:       ${BOLD}$PROJECT_DIR${NC}"
    echo -e "    Virtual env:   ${BOLD}$VENV_DIR${NC}"
    echo -e "    Go tools:      ${BOLD}$HOME/go/bin${NC}"
    echo -e "    Cloned tools:  ${BOLD}$TOOLS_DIR${NC}"
    echo -e "    Full log:      ${BOLD}$LOG_FILE${NC}"
    echo ""

    if [[ $FAILED -gt 0 ]]; then
        echo -e "  ${YELLOW}⚠ $FAILED tool(s) failed. Check the log for details:${NC}"
        echo -e "    ${DIM}grep 'FAIL:' $LOG_FILE${NC}"
        echo ""
    fi

    echo -e "  ${CYAN}Quick Start:${NC}"
    echo -e "    ${YELLOW}⚠ Open a NEW terminal${NC} (or run: ${BOLD}source ~/.zshrc${NC})"
    echo -e "    ${BOLD}${GREEN}fyp${NC}                → activate env + cd to project"
    echo -e "    ${BOLD}python3 main.py${NC}    → launch Cyber-CoPilot"
    echo ""
    echo -e "  ${CYAN}Or manually:${NC}"
    echo -e "    1. ${BOLD}source ~/.bashrc${NC}  (or ${BOLD}source ~/.zshrc${NC})"
    echo -e "    2. ${BOLD}fyp${NC}"
    echo -e "    3. ${BOLD}python3 main.py${NC}"
    echo ""
}

# ══════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════

main() {
    # Initialize log
    echo "Cyber-CoPilot Tool Installer v${SCRIPT_VERSION}" > "$LOG_FILE"
    echo "Started: $(date)" >> "$LOG_FILE"

    # Detect environment
    detect_platform
    detect_privileges
    detect_shared_folder

    # Show UI
    show_banner
    show_system_info

    # Parse arguments
    local MODE="all"
    for arg in "$@"; do
        case "$arg" in
            --minimal)  MODE="minimal" ;;
            --all)      MODE="all" ;;
            --go)       MODE="go" ;;
            --python)   MODE="python" ;;
            --apt|--pkg) MODE="system" ;;
            --ruby)     MODE="ruby" ;;
            --github)   MODE="github" ;;
            --help|-h)
                echo "Usage: bash install_tools.sh [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --all       Install everything (default)"
                echo "  --minimal   Core tools only (nmap, subfinder, httpx, nuclei, ffuf)"
                echo "  --go        Go tools only"
                echo "  --python    Python tools only"
                echo "  --pkg       System packages only"
                echo "  --ruby      Ruby gems only"
                echo "  --github    GitHub clone tools only"
                echo "  -h, --help  Show this help"
                exit 0
                ;;
        esac
    done

    case "$MODE" in
        all)
            install_system_packages
            install_go_tools
            # setup_venv MUST run BEFORE install_python_tools so that
            # the venv is activated and pip installs go into the venv,
            # not the system Python.
            setup_venv
            install_python_tools
            install_ruby_tools
            install_github_tools
            install_searchsploit
            install_feroxbuster
            install_metasploit
            install_ligolo
            setup_alias
            fixup_path
            ;;
        minimal)
            header "MINIMAL INSTALL (Core tools only)"
            for pkg in nmap curl wget jq git python3-pip; do install_pkg "$pkg"; done
            install_go_tools  # subfinder, httpx, nuclei, ffuf are all Go
            setup_venv
            pip_install "dirsearch"
            setup_alias
            fixup_path
            ;;
        go)      install_go_tools; fixup_path ;;
        python)  install_python_tools ;;
        system)  install_system_packages ;;
        ruby)    install_ruby_tools ;;
        github)  install_github_tools ;;
        venv)    setup_venv; setup_alias ;;
    esac

    show_summary
}

# Run
main "$@"
