# 🚀 CyberGlass Deployment & Cross-Platform Installation

CyberGlass can be deployed on Linux, macOS, or Windows from a self-contained archive, including in disconnected environments.

---

## 1. Operating System Support Matrix

| OS / Platform | Architecture | Service Manager | Packaging Format |
|---|---|---|---|
| **Linux (RHEL / Fedora / Rocky / Ubuntu / Debian)** | `x86_64`, `aarch64` | `systemd` | Standalone Tarball (`.tar.gz`); RPM on RPM-based distributions |
| **macOS (Sonoma / Sequoia / Monterey)** | `arm64` (Apple Silicon), `x86_64` | `launchd` | Standalone Tarball (`.tar.gz`) |
| **Windows Server / Windows 11** | `x86_64` | Windows Service / CLI | Standalone Zip (`.zip`) |
| **CyberGlass Containers (OCI)** | `x86_64`, `aarch64` | Docker / Podman / K8s | Offline OCI Image (`docker-compose.yml`) |

---

## 2. Installation on Linux & macOS (POSIX Installer)

The POSIX installer `install.sh` automatically detects whether it is running on Linux (using `systemd`) or macOS (using `launchd`), and whether it is invoked as root or unprivileged user.

```bash
# 1. Unpack release archive in cyberglass environment
tar -xzf cyberglass-v0.2.0-linux-x86_64.tar.gz
cd cyberglass-v0.2.0-linux-x86_64

# 2. Production installation as root (systemd / launchd daemon):
sudo ./install.sh

# 3. Non-root user mode installation (portable, no sudo needed):
./install.sh --user
```

On RPM-based distributions, install the native package instead:

```bash
sudo rpm -Uvh cyberglass-v0.2.0-linux-x86_64.rpm
sudo systemctl enable --now cyberglass
```

The RPM installs the server under `/opt/cyberglass`, configuration under
`/etc/cyberglass`, and creates the `cyberglass` service account. To build both
Linux artifacts on a Linux host with Rust and `rpmbuild` installed, run:

```bash
bash scripts/package.sh
```

Pass `--no-rpm` to create only the tarball, or `--version VERSION` to override
the version read from the Cargo workspace.

### Linux systemd Commands
```bash
sudo systemctl status cyberglass
sudo systemctl restart cyberglass
sudo journalctl -u cyberglass -f
```

### macOS launchd Commands
```bash
# Start service:
launchctl load ~/Library/LaunchAgents/com.cyberglass.server.plist

# Stop service:
launchctl unload ~/Library/LaunchAgents/com.cyberglass.server.plist
```

---

## 3. Installation on Windows (PowerShell Installer)

```powershell
# 1. Extract the release archive
Expand-Archive -Path .\cyberglass-v0.1.0-windows-x86_64.zip -DestinationPath C:\CyberGlass

# 2. Run the offline installer (Standard)
cd C:\CyberGlass\cyberglass-v0.1.0-windows-x86_64
powershell -ExecutionPolicy Bypass -File .\install.ps1

# 3. Production Install (with Background Service & Firewall rules)
powershell -ExecutionPolicy Bypass -File .\install.ps1 -Prefix "C:\Program Files\CyberGlass" -Service -Firewall
```

> [!TIP]
> For a full walkthrough covering zero-install portable execution, Windows Defender Firewall, Windows Service management, and sample PowerShell health queries, refer to the dedicated **[Windows Installation Guide](windows-installation-guide.md)**.

---
