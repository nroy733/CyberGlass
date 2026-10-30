#!/usr/bin/env bash
# =============================================================================
# CyberGlass Agent Deployment Script
# Installs and configures the CyberGlass Scripted Input Agent
# =============================================================================
set -euo pipefail

AGENT_BINARY="cg-agent"
AGENT_USER="cyberglass"
AGENT_GROUP="cyberglass"
CONFIG_DIR="/etc/cyberglass"
DATA_DIR="/var/lib/cyberglass/agent"
LOG_DIR="/var/log/cyberglass"
SERVICE_FILE="/etc/systemd/system/cyberglass-agent.service"
SERVER_URL="${CYBERGLASS_SERVER_URL:-http://localhost:9401}"

echo "=============================================="
echo "  CyberGlass Agent Deployment"
echo "=============================================="

# Detect OS
OS="$(uname -s)"
case "${OS}" in
    Linux*)     PLATFORM=linux;;
    Darwin*)    PLATFORM=macos;;
    *)          PLATFORM="unknown:${OS}"
esac

echo "[1/6] Detecting platform: ${PLATFORM}"

# Create system user if on Linux
if [[ "${PLATFORM}" == "linux" ]]; then
    echo "[2/6] Creating system user ${AGENT_USER}..."
    if ! id "${AGENT_USER}" &>/dev/null; then
        useradd --system --create-home --shell /usr/sbin/nologin "${AGENT_USER}" || true
    fi
fi

# Create directories
echo "[3/6] Creating directories..."
mkdir -p "${CONFIG_DIR}"
mkdir -p "${DATA_DIR}"
mkdir -p "${LOG_DIR}"
mkdir -p /usr/local/bin

if [[ "${PLATFORM}" == "linux" ]]; then
    chown -R "${AGENT_USER}:${AGENT_GROUP}" "${CONFIG_DIR}" "${DATA_DIR}" "${LOG_DIR}"
fi

# Install binary
echo "[4/6] Installing agent binary..."
if [[ -f "./target/debug/${AGENT_BINARY}" ]]; then
    cp "./target/debug/${AGENT_BINARY}" "/usr/local/bin/${AGENT_BINARY}"
elif [[ -f "./target/release/${AGENT_BINARY}" ]]; then
    cp "./target/release/${AGENT_BINARY}" "/usr/local/bin/${AGENT_BINARY}"
else
    echo "ERROR: Agent binary not found. Build with: cargo build --bin cg-agent"
    exit 1
fi
chmod +x "/usr/local/bin/${AGENT_BINARY}"

# Install config
echo "[5/6] Installing configuration..."
if [[ ! -f "${CONFIG_DIR}/agent.toml" ]]; then
    cp "./crates/cg-agent/agent.toml.example" "${CONFIG_DIR}/agent.toml"
    # Set server URL from env if provided
    if [[ -n "${SERVER_URL}" ]]; then
        sed -i "s|^server = .*|server = \"${SERVER_URL}\"|" "${CONFIG_DIR}/agent.toml"
    fi
fi

if [[ "${PLATFORM}" == "linux" ]]; then
    chown "${AGENT_USER}:${AGENT_GROUP}" "${CONFIG_DIR}/agent.toml"
fi

# Install systemd service
if [[ "${PLATFORM}" == "linux" ]]; then
    echo "[6/6] Installing systemd service..."
    cat > "${SERVICE_FILE}" <<EOF
[Unit]
Description=CyberGlass Scripted Input Agent
After=network.target

[Service]
Type=simple
User=${AGENT_USER}
Group=${AGENT_GROUP}
ExecStart=/usr/local/bin/${AGENT_BINARY} --config ${CONFIG_DIR}/agent.toml
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
WorkingDirectory=${DATA_DIR}

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    echo ""
    echo "=============================================="
    echo "  Deployment Complete!"
    echo "=============================================="
    echo ""
    echo "Binary:   /usr/local/bin/${AGENT_BINARY}"
    echo "Config:   ${CONFIG_DIR}/agent.toml"
    echo "Data:     ${DATA_DIR}"
    echo "Logs:     ${LOG_DIR}"
    echo "Service:  cyberglass-agent"
    echo ""
    echo "To start:  sudo systemctl enable --now cyberglass-agent"
    echo "To test:   ${AGENT_BINARY} --config ${CONFIG_DIR}/agent.toml"
    echo ""
else
    echo ""
    echo "=============================================="
    echo "  Deployment Complete (macOS/other)!"
    echo "=============================================="
    echo ""
    echo "Binary:   /usr/local/bin/${AGENT_BINARY}"
    echo "Config:   ${CONFIG_DIR}/agent.toml"
    echo ""
    echo "To run:   ${AGENT_BINARY} --config ${CONFIG_DIR}/agent.toml"
    echo ""
fi