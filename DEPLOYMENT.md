# 🌐 CYBERGLASS — Cross-Platform CyberGlass Deployment Guide

> **Deploy anywhere: Linux, macOS, or Windows — on bare-metal, virtualized, containerized, or 100% disconnected cyberglass environments.**

---

## 1. Supported Operating Systems & Architectures

| Operating System | Architectures | Target Triple | Init / Service System |
|---|---|---|---|
| **Linux (All Distros)**<br>*(RHEL, Rocky, Alma, Ubuntu, Debian, Alpine, SUSE)* | `x86_64` (64-bit Intel/AMD)<br>`aarch64` (ARM64 / Graviton) | `x86_64-unknown-linux-musl`<br>`aarch64-unknown-linux-musl` | `systemd`, `OpenRC`, or manual |
| **macOS (Darwin)**<br>*(Sonoma, Ventura, Monterey, etc.)* | `arm64` (Apple Silicon M1/M2/M3/M4)<br>`x86_64` (Intel Mac) | `aarch64-apple-darwin`<br>`x86_64-apple-darwin` | `launchd` (LaunchAgents / LaunchDaemons) |
| **Windows**<br>*(Server 2016-2025, Windows 10/11)* | `x86_64` (64-bit) | `x86_64-pc-windows-msvc` | Windows Service or Task Scheduler |
| **Containers** | Any OCI-compatible runtime | Docker, Podman, Kubernetes, containerd | OCI Runtime |

---

## 2. Linux Installation (100% Offline / cyberglass)

### Option A: Standard Install (with `systemd` service)
Requires `sudo` or root privileges. Installs into `/opt/cyberglass` and registers the `cyberglass.service` daemon.

```bash
# 1. Unpack the cyberglass archive on your offline machine
tar -xzf cyberglass-v0.2.0-linux-x86_64.tar.gz
cd cyberglass-v0.2.0-linux-x86_64

# 2. Run the offline installer
sudo ./install.sh

# 3. Start and verify the service
sudo systemctl start cyberglass
sudo systemctl status cyberglass
```

On RPM-based distributions, install the native package instead:

```bash
sudo rpm -Uvh cyberglass-v0.2.0-linux-x86_64.rpm
sudo systemctl enable --now cyberglass
```

### Option B: Non-Root / Portable Install (No `sudo` required)
Installs into `$HOME/.cyberglass` without altering system-level files:

```bash
./install.sh --user

# Start CyberGlass:
~/.cyberglass/bin/cyberglass
```

### Option C: Custom Storage Directory
For large SAN/NAS/NVMe mount points:

```bash
sudo ./install.sh --prefix /data/cyberglass --port 9401
```

---

## 3. macOS Installation (Apple Silicon & Intel)

The installer automatically detects Apple Silicon (`arm64` M-series) versus Intel (`x86_64`) and sets up `launchd` for automatic background management.

### Option A: User Mode (Recommended for macOS workstations / laptops)
No `sudo` needed. Configures `~/Library/LaunchAgents`:

```zsh
# 1. Extract package
tar -xzf cyberglass-v0.1.0-darwin-arm64.tar.gz
cd cyberglass-v0.1.0-darwin-arm64

# 2. Run user install
./install.sh --user
```

### Option B: System Daemon
```zsh
sudo ./install.sh
```

---

## 4. Windows Installation

### Option A: Automated PowerShell Install
Open PowerShell (as Administrator or standard user):

```powershell
# 1. Extract the zip archive
Expand-Archive .\cyberglass-v0.1.0-windows-x86_64.zip -DestinationPath .\cyberglass
cd .\cyberglass\cyberglass-v0.1.0-windows-x86_64

# 2. Run the offline installer (Standard User)
powershell -ExecutionPolicy Bypass -File .\install.ps1

# 3. Production Install (with Windows Task/Service & Firewall rules)
powershell -ExecutionPolicy Bypass -File .\install.ps1 -Prefix "C:\Program Files\CyberGlass" -Service -Firewall
```

### Option B: Direct Portable Execution (Zero Install)
```powershell
# Run directly out of the extracted directory without installing anything:
.\bin\cyberglass-server.exe --home .
```

> [!NOTE]
> For detailed instructions on Windows Server service management, Windows Defender Firewall rules, PowerShell diagnostics, and event log ingestion, see the dedicated **[Windows Installation Guide](docs/windows-installation-guide.md)**.

---

## 5. Docker / Podman CyberGlass Container Deployment

For environments running OCI container runtimes on offline servers:

### 1. Build and Export the Image on a Connected Machine:
```bash
docker build -t cyberglass:v0.1.0 .
docker save cyberglass:v0.1.0 -o cyberglass-cyberglass-v0.1.0.tar
```

### 2. Load and Run on Disconnected CyberGlass Host:
```bash
# Transfer cyberglass-cyberglass-v0.1.0.tar via physical media, then:
docker load -i cyberglass-cyberglass-v0.1.0.tar

# Run with docker-compose:
docker compose up -d
```

---

## 6. Verification and Health Checking

Once running on any OS:

```bash
# 1. Check system health and active engines
curl http://localhost:9401/api/v1/health

# 2. Ingest a test security event
curl -X POST http://localhost:9401/api/v1/ingest \
  -H "Content-Type: application/json" \
  -d '{"src_ip": "10.0.0.50", "user": "test_user", "action": "failure"}'

# 3. Query indexed logs via CyberQL
curl -X POST http://localhost:9401/api/v1/query \
  -H "Content-Type: application/json" \
  -d '{"query": "source=\"main\" | head 10"}'

# 4. View discovered CyberGlass Ontology Knowledge Graph entities
curl http://localhost:9401/api/v1/entities
```
