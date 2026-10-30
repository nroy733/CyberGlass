#!/usr/bin/env bash
# ==============================================================================
# 🛡️ CYBERGLASS — Universal Offline Installer for Linux & macOS
# ==============================================================================
# Supports:
#   - Linux: Ubuntu, Debian, RHEL, CentOS, Rocky, Alma, Fedora, Arch, Alpine
#   - macOS: Apple Silicon (M1/M2/M3/M4, arm64) & Intel (x86_64)
# Operates in 100% self-hosted, air-gapped dark sites with zero internet access.
# Bundles all dependencies — no external network required.
# ==============================================================================

set -euo pipefail

# Default settings
DEFAULT_ROOT_PREFIX="/opt/cyberglass"
DEFAULT_USER_PREFIX="$HOME/.cyberglass"
INSTALL_PREFIX=""
IS_USER_MODE=0
PORT="9401"
ACTION="install"
ENABLE_SERVICE=1

# Color definitions (if terminal supports it)
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    CYAN='\033[0;36m'
    BOLD='\033[1m'
    NC='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    CYAN=''
    BOLD=''
    NC=''
fi

print_banner() {
    printf "${CYAN}${BOLD}"
    cat << 'EOF'
   ______      __                 ________                 
  / ____/_  __/ /_  ___  _____   / ____/ /___ ___________  
 / /   / / / / __ \/ _ \/ ___/  / / __/ / __ `/ ___/ ___/  
/ /___/ /_/ / /_/ /  __/ /     / /_/ / / /_/ (__  |__  )   
\____/\__, /_.___/\___/_/      \____/_/\__,_/____/____/    
     /____/                                                
  >> NEXT-GEN AIR-GAP SIEM & DATA FUSION PLATFORM <<
  >> Universal Offline Installer for Linux & macOS <<
EOF
    printf "${NC}\n"
}

log_info() {
    printf "${GREEN}[INFO]${NC} %s\n" "$1"
}

log_warn() {
    printf "${YELLOW}[WARN]${NC} %s\n" "$1"
}

log_error() {
    printf "${RED}[ERROR]${NC} %s\n" "$1" >&2
}

log_step() {
    printf "\n${BLUE}${BOLD}==>${NC} %s\n" "$1"
}

usage() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS]

Options:
    --prefix <DIR>       Custom installation directory (default: /opt/cyberglass or ~/.cyberglass)
    --user               Install in current user's home directory without requiring root/sudo
    --port <PORT>        REST & Search Gateway listen port (default: 9401)
    --no-service         Skip system service registration (standalone binary only)
    --uninstall          Uninstall CyberGlass from the system
    -h, --help           Show this help message

Examples:
    # Standard Linux installation (systemd service as root):

    # Non-root / Portable macOS or Linux install (no sudo required):

    # Custom directory on storage mount:
    sudo ./install.sh --prefix /data/cyberglass
EOF
    exit 0
}

# Parse command line arguments
while [ $# -gt 0 ]; do
    case "$1" in
        --prefix)
            INSTALL_PREFIX="$2"
            shift 2
            ;;
        --user)
            IS_USER_MODE=1
            shift
            ;;
        --port)
            PORT="$2"
            shift 2
            ;;
        --no-service)
            ENABLE_SERVICE=0
            shift
            ;;
        --uninstall)
            ACTION="uninstall"
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            log_error "Unknown option: $1"
            usage
            ;;
    esac
done

# Detect Operating System and CPU Architecture
detect_platform() {
    OS="$(uname -s)"
    ARCH="$(uname -m)"

    case "$OS" in
        Linux*)
            PLATFORM_OS="linux"
            ;;
        Darwin*)
            PLATFORM_OS="darwin"
            ;;
        *)
            log_error "Unsupported operating system: $OS. CyberGlass runs on Linux, macOS, and Windows."
            exit 1
            ;;
    esac

    case "$ARCH" in
        x86_64|amd64)
            PLATFORM_ARCH="x86_64"
            ;;
        aarch64|arm64)
            PLATFORM_ARCH="arm64"
            ;;
        *)
            log_error "Unsupported CPU architecture: $ARCH"
            exit 1
            ;;
    esac

    log_info "Detected Platform: ${BOLD}${PLATFORM_OS}-${PLATFORM_ARCH}${NC}"
}

# Determine default installation path based on root vs user
determine_prefix() {
    if [ -n "$INSTALL_PREFIX" ]; then
        return
    fi

    if [ "$IS_USER_MODE" -eq 1 ]; then
        INSTALL_PREFIX="$DEFAULT_USER_PREFIX"
    else
        if [ "$(id -u)" -eq 0 ]; then
            INSTALL_PREFIX="$DEFAULT_ROOT_PREFIX"
        else
            log_warn "Running as non-root user. Defaulting to user-mode install in $DEFAULT_USER_PREFIX"
            IS_USER_MODE=1
            INSTALL_PREFIX="$DEFAULT_USER_PREFIX"
        fi
    fi
}

# Locate binary in current package
find_binary() {
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    
    # Check potential binary locations in the offline package
    CANDIDATES="
        $SCRIPT_DIR/bin/cyberglass-server
        $SCRIPT_DIR/cyberglass-server
        $SCRIPT_DIR/target/release/cyberglass-server
        $SCRIPT_DIR/target/debug/cyberglass-server
    "

    BINARY_SRC=""
    for cand in $CANDIDATES; do
        if [ -f "$cand" ]; then
            BINARY_SRC="$cand"
            break
        fi
    done

    if [ -z "$BINARY_SRC" ]; then
        log_error "Could not find cyberglass-server binary in the installer package ($SCRIPT_DIR)."
        log_error "Please ensure you have the complete distribution package or build from source."
        exit 1
    fi

    log_info "Found CyberGlass executable: $BINARY_SRC"
}

do_install() {
    print_banner
    detect_platform
    determine_prefix
    find_binary

    log_step "Preparing Installation Target: $INSTALL_PREFIX"
    mkdir -p "$INSTALL_PREFIX/bin"
    mkdir -p "$INSTALL_PREFIX/config"
    mkdir -p "$INSTALL_PREFIX/data"
    mkdir -p "$INSTALL_PREFIX/index"
    mkdir -p "$INSTALL_PREFIX/wal"
    mkdir -p "$INSTALL_PREFIX/rules"
    mkdir -p "$INSTALL_PREFIX/ontology"
    mkdir -p "$INSTALL_PREFIX/models"
    mkdir -p "$INSTALL_PREFIX/logs"

    log_step "Installing CyberGlass Server Binary"
    cp -f "$BINARY_SRC" "$INSTALL_PREFIX/bin/cyberglass-server"
    chmod 755 "$INSTALL_PREFIX/bin/cyberglass-server"
    log_info "Binary installed to $INSTALL_PREFIX/bin/cyberglass-server"

    # Install collector agent if present in bundle
    if [ -f "$SCRIPT_DIR/bin/cyberglass-collector" ]; then
        cp -f "$SCRIPT_DIR/bin/cyberglass-collector" "$INSTALL_PREFIX/bin/"
        chmod 755 "$INSTALL_PREFIX/bin/cyberglass-collector"
        log_info "Collector agent installed to $INSTALL_PREFIX/bin/cyberglass-collector"
    fi

    log_step "Configuring Environment & Rules"
    CONFIG_SRC="$SCRIPT_DIR/config/cyberglass.toml"
    if [ ! -f "$CONFIG_SRC" ]; then
        CONFIG_SRC="$SCRIPT_DIR/cyberglass.toml"
    fi

    if [ -f "$CONFIG_SRC" ]; then
        cp -f "$CONFIG_SRC" "$INSTALL_PREFIX/config/cyberglass.toml"
    else
        cat > "$INSTALL_PREFIX/config/cyberglass.toml" << EOF
[node]
name = "cyberglass-airgap-1"
role = "all"
log_level = "info"
log_format = "json"

[rest]
listen_addr = "0.0.0.0:$PORT"

[index]
memory_budget = 536870912
commit_interval_seconds = 5

[ai.local]
default_model = "phi-4-mini-q4"
EOF
    fi

    # Copy rules if present
    if [ -d "$SCRIPT_DIR/rules" ]; then
        cp -rf "$SCRIPT_DIR/rules/"* "$INSTALL_PREFIX/rules/" 2>/dev/null || true
    fi

    # Create launch wrapper script
    cat > "$INSTALL_PREFIX/bin/cyberglass" << EOF
#!/bin/sh
export CYBERGLASS_HOME="$INSTALL_PREFIX"
export CYBERGLASS_CONFIG="$INSTALL_PREFIX/config/cyberglass.toml"
exec "$INSTALL_PREFIX/bin/cyberglass-server" --home "$INSTALL_PREFIX" "\$@"
EOF
    chmod 755 "$INSTALL_PREFIX/bin/cyberglass"

    # Register System Service
    if [ "$ENABLE_SERVICE" -eq 1 ]; then
        register_service
    fi

    # Symlink to /usr/local/bin if root
    if [ "$IS_USER_MODE" -eq 0 ] && [ "$(id -u)" -eq 0 ]; then
        mkdir -p /usr/local/bin
        ln -sf "$INSTALL_PREFIX/bin/cyberglass" /usr/local/bin/cyberglass
        log_info "CLI symlinked to /usr/local/bin/cyberglass"
    fi

    printf "\n${GREEN}${BOLD}✔ CyberGlass Installation Successfully Completed!${NC}\n"
    printf "====================================================================\n"
    printf "  • Root Directory : %s\n" "$INSTALL_PREFIX"
    printf "  • Config File    : %s/config/cyberglass.toml\n" "$INSTALL_PREFIX"
    printf "  • REST & Search  : http://localhost:%s\n" "$PORT"
    printf "  • CLI Command    : %s/bin/cyberglass\n" "$INSTALL_PREFIX"
    printf "====================================================================\n"
    if [ "$ENABLE_SERVICE" -eq 1 ]; then
        if [ "$PLATFORM_OS" = "linux" ]; then
            printf "  • Start service  : sudo systemctl start cyberglass\n"
            printf "  • Check status   : sudo systemctl status cyberglass\n"
        elif [ "$PLATFORM_OS" = "darwin" ]; then
            printf "  • Status/Logs    : tail -f %s/logs/stdout.log\n" "$INSTALL_PREFIX"
        fi
    else
        printf "  • Manual Start   : %s/bin/cyberglass\n" "$INSTALL_PREFIX"
    fi
    printf "\n"
}

register_service() {
    log_step "Registering System Service"

    if [ "$PLATFORM_OS" = "linux" ]; then
        if command -v systemctl >/dev/null 2>&1 && [ "$(id -u)" -eq 0 ]; then
            SERVICE_FILE="/etc/systemd/system/cyberglass.service"
            cat > "$SERVICE_FILE" << EOF
[Unit]
Description=CyberGlass SIEM & Data Fusion Platform
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_PREFIX
Environment=CYBERGLASS_HOME=$INSTALL_PREFIX
Environment=CYBERGLASS_CONFIG=$INSTALL_PREFIX/config/cyberglass.toml
ExecStart=$INSTALL_PREFIX/bin/cyberglass-server --home $INSTALL_PREFIX
Restart=always
RestartSec=5s
LimitNOFILE=65536
LimitNPROC=65536

[Install]
WantedBy=multi-user.target
EOF
            chmod 644 "$SERVICE_FILE"
            systemctl daemon-reload
            systemctl enable cyberglass >/dev/null 2>&1 || true
            log_info "systemd service registered at $SERVICE_FILE"
        else
            log_warn "systemd not detected or running non-root. Service registration skipped."
        fi

    elif [ "$PLATFORM_OS" = "darwin" ]; then
        # macOS launchd plist
        if [ "$IS_USER_MODE" -eq 1 ]; then
            PLIST_DIR="$HOME/Library/LaunchAgents"
        else
            PLIST_DIR="/Library/LaunchDaemons"
        fi

        mkdir -p "$PLIST_DIR"
        PLIST_FILE="$PLIST_DIR/com.cyberglass.server.plist"

        cat > "$PLIST_FILE" << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.cyberglass.server</string>
    <key>ProgramArguments</key>
    <array>
        <string>__INSTALL_PREFIX__/bin/cyberglass-server</string>
        <string>--home</string>
        <string>__INSTALL_PREFIX__</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <key>CYBERGLASS_HOME</key>
        <string>__INSTALL_PREFIX__</string>
        <key>CYBERGLASS_CONFIG</key>
        <string>__INSTALL_PREFIX__/config/cyberglass.toml</string>
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>__INSTALL_PREFIX__/logs/stdout.log</string>
    <key>StandardErrorPath</key>
    <string>__INSTALL_PREFIX__/logs/stderr.log</string>
</dict>
</plist>
EOF
        # Replace placeholder with actual path
        sed -i '' "s|__INSTALL_PREFIX__|$INSTALL_PREFIX|g" "$PLIST_FILE" 2>/dev/null || \
            sed -i "s|__INSTALL_PREFIX__|$INSTALL_PREFIX|g" "$PLIST_FILE"
        log_info "macOS launchd plist installed to $PLIST_FILE"
        if [ "$IS_USER_MODE" -eq 1 ]; then
            launchctl unload "$PLIST_FILE" 2>/dev/null || true
            launchctl load "$PLIST_FILE" 2>/dev/null || true
        fi
    fi
}

do_uninstall() {
    print_banner
    determine_prefix
    log_step "Uninstalling CyberGlass from $INSTALL_PREFIX"

    if [ -f "/etc/systemd/system/cyberglass.service" ]; then
        systemctl stop cyberglass 2>/dev/null || true
        systemctl disable cyberglass 2>/dev/null || true
        rm -f "/etc/systemd/system/cyberglass.service"
        systemctl daemon-reload 2>/dev/null || true
        log_info "systemd service removed"
    fi

    rm -f /usr/local/bin/cyberglass
    rm -rf "$INSTALL_PREFIX"

    printf "${GREEN}✔ CyberGlass has been completely uninstalled.${NC}\n"
}

if [ "$ACTION" = "uninstall" ]; then
    do_uninstall
else
    do_install
fi