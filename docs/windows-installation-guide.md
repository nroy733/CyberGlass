# CyberGlass Windows Installation & Deployment Guide

This comprehensive guide details how to install, configure, operate, and maintain **CyberGlass** on **Microsoft Windows** and **Windows Server** operating systems in secure, cyberglass, or dark environments.

---

## 📋 Table of Contents

1. [Overview & Windows Architecture](#1-overview--windows-architecture)
2. [System Requirements & Prerequisites](#2-system-requirements--prerequisites)
3. [CyberGlass Transfer & Integrity Verification](#3-cyberglass-transfer--integrity-verification)
4. [Method 1: Automated Offline PowerShell Installer (`install.ps1`)](#4-method-1-automated-offline-powershell-installer-installps1)
5. [Method 2: Standalone / Portable Mode (Zero-Install)](#5-method-2-standalone--portable-mode-zero-install)
6. [Method 3: Windows Background Service (24/7 SIEM Daemon)](#6-method-3-windows-background-service-247-siem-daemon)
7. [Windows Defender Firewall Configuration](#7-windows-defender-firewall-configuration)
8. [Accessing the Interactive Web UI](#8-accessing-the-interactive-web-ui)
9. [Post-Installation Verification & Health Checks](#9-post-installation-verification--health-checks)
10. [Forwarding Windows Events to CyberGlass](#10-forwarding-windows-events-to-cyberglass)
11. [Troubleshooting & Maintenance](#11-troubleshooting--maintenance)

---

## 1. Overview & Windows Architecture

CyberGlass is engineered natively in **Rust** as a single self-contained binary executable (`cyberglass-server.exe`). Unlike legacy SIEM solutions, CyberGlass has:
- **Zero Runtime Dependencies**: No JVM, Python, .NET Runtime, or MSVC redistributable installs required.
- **Zero GC Latency**: Predictable, lockless memory allocation with zero garbage-collection pause spikes.
- **True CyberGlass Readiness**: 100% offline startup, built-in Ed25519 offline licensing, and built-in MITRE ATT&CK threat intelligence.
- **Dual Communication Plane**: High-throughput **gRPC** (Port `9400`) and a user-friendly **REST API / CyberQL Gateway** (Port `9401`).

```
                    +----------------------------------------------------+
                    |             Windows Host / Windows Server          |
                    +----------------------------------------------------+
                                              |
                   +--------------------------+--------------------------+
                   |                                                     |
            [ Port 9400: gRPC ]                                   [ Port 9401: REST ]
       (High-Throughput Protobuf)                            (CyberQL API / Web Gateway)
                   |                                                     |
                   v                                                     v
    +----------------------------------------------------------------------------+
    |                    CyberGlass Server (cyberglass-server.exe)               |
    |                                                                            |
    |  +--------------------+  +---------------------+  +---------------------+  |
    |  | Ingest Pipeline    |  | Tantivy Full-Text   |  | Apache Arrow        |  |
    |  | (Syslog 1514, API) |  | Inverted Index      |  | Columnar Lake       |  |
    |  +--------------------+  +---------------------+  +---------------------+  |
    |  +--------------------+  +---------------------+  +---------------------+  |
    |  | CyberQL Query      |  | Sigma & Threshold   |  | CyberGlass Ontology |  |
    |  | Pipeline Engine    |  | Detection Engine    |  | Knowledge Graph     |  |
    |  +--------------------+  +---------------------+  +---------------------+  |
    +----------------------------------------------------------------------------+
                               |                    |
                               v                    v
                   [ Write-Ahead Log (WAL) ]    [ Tiered Data Storage ]
```

---

## 2. System Requirements & Prerequisites

### Supported Windows Operating Systems
- **Windows Server**: 2016, 2019, 2022, 2025 (Standard / Datacenter, 64-bit).
- **Windows Workstation**: Windows 11 (all versions), Windows 10 (Build 19041+ / 20H2+, 64-bit).

### Hardware Sizing Guidelines

| Deployment Tier | Daily Ingestion | CPU Cores | RAM | Storage Subsystem |
|---|---|---|---|---|
| **Evaluation / POC** | < 25 GB / day (~1,000 EPS) | 4 vCPU | 8 GB | Standard SSD / HDD |
| **Mid-Market General** | 25 - 250 GB / day (~10,000 EPS) | 8 - 16 vCPU | 32 GB | NVMe SSD (WAL + Hot Tier) |
| **High-Throughput SOC** | 250 GB - 2 TB / day (100,000+ EPS) | 32+ vCPU | 64 - 128 GB | Dedicated NVMe Array (PCIe 4.0) |

### Network Port Allocation

| Port | Protocol | Purpose | Direction |
|---|---|---|---|
| **9400** | TCP | CyberGlass High-Speed General gRPC API | Inbound |
| **9401** | TCP | CyberGlass REST API & CyberQL Search Gateway | Inbound |
| **1514** | TCP | Syslog Network Ingestion (RFC 3164 / 5424) | Inbound |
| **1514** | UDP | Syslog Network Ingestion (RFC 3164 / 5424) | Inbound |

### Windows Prerequisites
- **PowerShell**: Version 5.1 (built into Windows 10/Server) or PowerShell 7+ (Core).
- **Administrative Privileges**: Required only if registering as a background Windows Service / Scheduled Task or creating Firewall rules. For non-admin user-space testing, no elevated privileges are needed.

---

## 3. CyberGlass Transfer & Integrity Verification

In secure and disconnected environments, transport the installation archive via approved cyberglass transfer media (encrypted USB, DVD, or cross-domain diode).

### Step 1: Package Files
- `cyberglass-v0.1.0-windows-x86_64.zip`

### Step 2: Verify Cryptographic SHA-256 Hash
Open PowerShell and verify the archive integrity:

```powershell
Get-FileHash -Algorithm SHA256 .\cyberglass-v0.1.0-windows-x86_64.zip
```

### Step 3: Unpack Archive
Extract the package to your staging folder:

```powershell
Expand-Archive -Path .\cyberglass-v0.1.0-windows-x86_64.zip -DestinationPath C:\CyberGlass-Stage
cd C:\CyberGlass-Stage\cyberglass-v0.1.0-windows-x86_64
```

---

## 4. Method 1: Automated Offline Windows Installer (`install.bat` / `install.ps1`)

The included Windows installer automatically locates the binary, configuration, and rules regardless of what directory you run it from (`installer\`, package root, or staging directory).

### Quickest Way: Using `install.bat` (Bypasses PowerShell Execution Policy Automatically)
Windows batch scripts (`.bat`) are not subject to PowerShell execution policy restrictions. Simply run:

```cmd
# Standard User Install:
.\install.bat
```

### Option A: Standard Per-User Installation (PowerShell)
Installs into `%LOCALAPPDATA%\CyberGlass` (e.g. `C:\Users\<User>\AppData\Local\CyberGlass`):

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

### Option B: Production Installation (Administrator Recommended)
Installs into `C:\Program Files\CyberGlass`, registers an automatic background service, and opens firewall ports:

```powershell
# Open PowerShell as Administrator:
powershell -ExecutionPolicy Bypass -File .\install.ps1 `
    -Prefix "C:\Program Files\CyberGlass" `
    -Service `
    -Firewall
```

### Installer Parameters Reference

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-Prefix` | String | `%LOCALAPPDATA%\CyberGlass` | Target destination directory |
| `-Port` | String | `9401` | REST & Search Gateway port |
| `-Service` | Switch | `False` | Automatically registers a persistent Windows Background Task |
| `-Firewall` | Switch | `False` | Creates Windows Defender inbound firewall rules (requires Admin) |
| `-Uninstall`| Switch | `False` | Removes background service and uninstalls directory |
| `-Help` | Switch | `False` | Displays parameter documentation |

### Directory Hierarchy Created

```
C:\Program Files\CyberGlass\
├── bin\
│   ├── cyberglass-server.exe     # Native high-performance SIEM engine
│   └── cyberglass.bat            # Environment and launcher script
├── config\
│   ├── cyberglass.toml           # General cluster & storage configuration
├── data\                         # Apache Arrow / Parquet tiered columnar segments
├── index\                        # Tantivy full-text inverted indexes
├── wal\                          # Append-only Write-Ahead Log
├── rules\                        # Sigma YAML and CyberQL detection rules
├── ontology\                     # CyberGlass Ontology knowledge graph storage
├── models\                       # Local LLMs (GGUF) and embeddings
└── logs\                         # Application telemetry and audit logs
```

---

## 5. Method 2: Standalone / Portable Mode (Zero-Install)

CyberGlass can be run entirely portable without modifying system environment variables or registry settings. This is ideal for forensic triage kits, incident response field laptops, or secure cyberglass USB drives.

### Launching with a Custom Home Directory
Specify `--home` to place configured data under a dedicated path. The
administrator bootstrap password is stored in the `data` subdirectory:

Start the server in one PowerShell window:

```powershell
.\cyberglass-server.exe --home "D:\IncidentResponse\CyberGlassData"
```

Keep that window running. In a **second PowerShell window**, replace the
example path below with the same home directory passed to `--home`, then copy
the generated password:

```powershell
$passwordFile = 'D:\IncidentResponse\CyberGlassData\data\initial-admin-password'
if (-not (Test-Path -LiteralPath $passwordFile -PathType Leaf)) {
    throw "Password file not found: $passwordFile. Check the server's --home path and startup log."
}
Set-Clipboard -Value ((Get-Content -LiteralPath $passwordFile -Raw).Trim())
```

The `D:\IncidentResponse\CyberGlassData` path is an example, not a folder
created by the installer. If you installed to the default per-user location,
use:

```powershell
$passwordFile = Join-Path $env:LOCALAPPDATA 'CyberGlass\data\initial-admin-password'
if (-not (Test-Path -LiteralPath $passwordFile -PathType Leaf)) {
    throw "Password file not found: $passwordFile. Check the server's home directory and startup log."
}
Set-Clipboard -Value ((Get-Content -LiteralPath $passwordFile -Raw).Trim())
```

Run the clipboard command from an interactive Windows session; clipboard access
may be unavailable in Server Core or a remote session without clipboard
redirection. If `Set-Clipboard` is unavailable, use `clip.exe` instead:
`Get-Content -LiteralPath $passwordFile -Raw | clip.exe`.

### Launching in Ephemeral In-Memory Mode
For a volatile demonstration, where external event indexes and alert state are
not persisted:

```powershell
.\cyberglass-server.exe --in-memory
```

`--in-memory` does not mean the entire application leaves no disk data. The
configured data directory is still used for administrator bootstrap credentials,
internal indexes, authentication signing material, and other configured state.

### Verifying Configuration Syntax Before Starting
```powershell
.\cyberglass-server.exe --config .\config\cyberglass.toml --check-config
```

---

## 6. Method 3: Windows Background Service (24/7 SIEM Daemon)

For 24/7 continuous log collection and detection on Windows Server, CyberGlass is managed via the dedicated service manager script: `installer\service\cyberglass-service.ps1`.

### Registering and Starting the Background Service
Run in an elevated PowerShell session:

```powershell
# 1. Register the task to start on system boot
powershell -ExecutionPolicy Bypass -File .\installer\service\cyberglass-service.ps1 `
    -Action install `
    -Prefix "C:\Program Files\CyberGlass"

# 2. Start the service
powershell -ExecutionPolicy Bypass -File .\installer\service\cyberglass-service.ps1 `
    -Action start
```

### Checking Service Status
```powershell
powershell -ExecutionPolicy Bypass -File .\installer\service\cyberglass-service.ps1 `
    -Action status
```
*Output:*
```
Task Name   : CyberGlassSIEM
Task State  : Running
Process     : Running (PID: 4820, WorkingSet: 42.15 MB)
```

### Stopping or Restarting the Service
```powershell
# Stop:
powershell -ExecutionPolicy Bypass -File .\installer\service\cyberglass-service.ps1 -Action stop

# Restart:
powershell -ExecutionPolicy Bypass -File .\installer\service\cyberglass-service.ps1 -Action restart
```

### Unregistering the Service
```powershell
powershell -ExecutionPolicy Bypass -File .\installer\service\cyberglass-service.ps1 -Action uninstall
```

---

## 7. Windows Defender Firewall Configuration

To allow external log sources, forwarders, SIEM collectors, and SOC analyst browsers to reach CyberGlass, configure inbound Windows Firewall rules.

### Automated Setup
Include the `-Firewall` switch when running `install.ps1`:
```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1 -Firewall
```

### Manual PowerShell Commands
In an Administrator PowerShell prompt, run:

```powershell
# Port 9400: High-performance gRPC API
New-NetFirewallRule -DisplayName "CyberGlass gRPC Service (9400)" `
    -Direction Inbound -LocalPort 9400 -Protocol TCP -Action Allow

# Port 9401: REST API & CyberQL Search Gateway
New-NetFirewallRule -DisplayName "CyberGlass REST Gateway (9401)" `
    -Direction Inbound -LocalPort 9401 -Protocol TCP -Action Allow

# Port 1514: Syslog TCP Ingestion
New-NetFirewallRule -DisplayName "CyberGlass Syslog TCP Listener (1514)" `
    -Direction Inbound -LocalPort 1514 -Protocol TCP -Action Allow

# Port 1514: Syslog UDP Ingestion
New-NetFirewallRule -DisplayName "CyberGlass Syslog UDP Listener (1514)" `
    -Direction Inbound -LocalPort 1514 -Protocol UDP -Action Allow
```

---

## 8. Accessing the Interactive Web UI

CyberGlass embeds a zero-dependency, dark-themed Single Page Application (SPA) directly inside the server binary for 100% cyberglass compliance:

### 1. Launching via One-Click Script
Run `start.bat` from your installation or repo directory:
```cmd
.\start.bat
```
This boots the CyberGlass server and automatically opens `http://localhost:9401` in your default browser.

### 2. Manual Browser Access
Navigate to:
- **`http://localhost:9401/`** or **`http://localhost:9401/ui`**

### Web UI Features:
- 🔍 **CyberQL Search**: Interactive search console with pipe-based queries, autocomplete examples, and structured data grid.
- 🕸️ **Ontology Knowledge Graph**: HTML5 canvas graph visualizer showing discovered entities (hosts, accounts, IPs, domains) and dynamic risk scores.
- 🚨 **Alerts & Sigma**: Real-time sliding-window detection feed with MITRE ATT&CK technique tags.
- 📥 **Ingestion Lab**: Test parser engine with Windows Event Logs, Syslog RFC 5424, and CEF payloads.
- 🤖 **AI Threat Hunter**: Direct chat with the built-in offline security intelligence agent.
- 📊 **Cluster & Metrics**: Real-time health, EPS telemetry, and storage tier distribution.

### First Login

1. Start CyberGlass and open `http://localhost:9401/ui`. If the server is not
   running, the sign-in form cannot authenticate you.
2. The initial username is `admin`, unless `CYBERGLASS_ADMIN_USERNAME` was
   configured in the environment used to launch the server.
3. If `CYBERGLASS_ADMIN_PASSWORD` was configured before startup, use that
   password. Otherwise, use the generated password file at
   `<node.data_dir>\initial-admin-password`.
   - With the supplied `config\cyberglass.toml`, `node.data_dir` is
     `/var/lib/cyberglass`; on Windows this resolves to
     `C:\var\lib\cyberglass\initial-admin-password`.
   - With `--home "D:\IncidentResponse\CyberGlassData"`, use
     `D:\IncidentResponse\CyberGlassData\data\initial-admin-password`.
   - For a custom configuration, check `node.data_dir` in the configuration
     actually loaded by the process.
4. Open a **second PowerShell window** while the server is running. Set the
   password-file path for the same installation, verify that it exists, and
   copy it to the clipboard. For the default per-user installer location:

   ```powershell
   $passwordFile = Join-Path $env:LOCALAPPDATA 'CyberGlass\data\initial-admin-password'
   if (-not (Test-Path -LiteralPath $passwordFile -PathType Leaf)) {
       throw "Password file not found: $passwordFile. Check the server's home directory and startup log."
   }
   Set-Clipboard -Value ((Get-Content -LiteralPath $passwordFile -Raw).Trim())
   ```

   For a server started with `--home`, set `$passwordFile` to
   `<that-home>\data\initial-admin-password` instead. Do not copy the example
   `D:\IncidentResponse\CyberGlassData` path unless that is the home directory
   you actually used. If clipboard access is unavailable in the session, use
   `Get-Content -LiteralPath $passwordFile -Raw | clip.exe` from an interactive
   Windows desktop session.

5. Paste the password into the login form. Store it in an approved password
   manager and protect the file. Do not delete the file unless a securely
   managed `CYBERGLASS_ADMIN_PASSWORD` is configured for subsequent starts.
   The environment variable overrides the file and must contain at least 12
   characters.

The initial administrator and server sessions are currently held in memory.
Sign in again after each server restart. If the password file is missing and
no password environment variable is configured, startup generates a new
initial password. A server launched with `--in-memory` still uses the
configured data directory for administrative and internal state.

---

## 9. Post-Installation Verification & Health Checks

Verify your CyberGlass instance using built-in PowerShell REST queries:

### 1. Health Status Check
```powershell
Invoke-RestMethod -Uri "http://localhost:9401/api/v1/health" | Format-List
```
*Expected Response:*
```
status    : healthy
version   : 0.1.0
uptime_s  : 142
node_id   : cg-node-01
services  : @{ingest=UP; index=UP; query=UP; detection=UP; ontology=UP; ai=UP}
```

### 2. Ingesting a Test Security Event (Windows Event Log 4624)
Send a test authentication event via REST:

```powershell
$body = @{
    source = "windows_security"
    source_type = "WinEventLog:Security"
    raw = "EventID=4624 LogonType=10 TargetUserName=sec_admin IpAddress=192.168.1.50 Status=Success"
} | ConvertTo-Json

Invoke-RestMethod -Uri "http://localhost:9401/api/v1/ingest" -Method Post -Body $body -ContentType "application/json"
```

### 3. Querying Events with CyberQL
Execute a CyberQL-compatible pipeline search over the ingested data:

```powershell
$queryBody = @{
    query = 'source="windows_security" | stats count by TargetUserName'
} | ConvertTo-Json

$results = Invoke-RestMethod -Uri "http://localhost:9401/api/v1/query" -Method Post -Body $queryBody -ContentType "application/json"
$results.rows | Format-Table
```

### 4. Viewing MITRE ATT&CK & Detection Rules
```powershell
$rules = Invoke-RestMethod -Uri "http://localhost:9401/api/v1/rules"
$rules | Select-Object id, name, severity, mitre_techniques
```

---

## 10. Forwarding Windows Events to CyberGlass

To stream security events from domain controllers and endpoints into CyberGlass:

### Option A: Syslog Stream (NXLog / Winlogbeat / Fluentbit)
Configure your Windows log agent to ship Syslog formatted logs to port `1514`:

*NXLog Configuration Snippet (`nxlog.conf`):*
```conf
<Output out_cyberglass>
    Module      om_tcp
    Host        192.168.1.10
    Port        1514
    Exec        to_syslog_ietf();
</Output>
```

### Option B: Direct HTTP / REST Ingestion
Forwarders can POST batches directly to `/api/v1/ingest` in JSON format.

---

## 11. Troubleshooting & Maintenance

### 1. ExecutionPolicy Restriction
**Symptom:** PowerShell displays `File install.ps1 cannot be loaded because running scripts is disabled on this system.`  
**Resolution:** Run `install.bat` instead, or run PowerShell with the bypass argument:
```cmd
# Option 1: Use the batch launcher (never blocked by ExecutionPolicy)
.\install.bat

# Option 2: PowerShell bypass flag
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

### 2. "Could not find cyberglass-server.exe" Error
**Symptom:** The installer cannot find the pre-compiled binary when run from subdirectories.  
**Resolution:** The updated installer now automatically scans parent directories, the root workspace, and `target\debug` / `target\release` trees. Ensure you have extracted the package or compiled the server via `cargo build -p cg-server`.

### 2. Port Binding Conflicts
**Symptom:** Server outputs `Address already in use (os error 10048)`.  
**Resolution:** Check what service is occupying the port:
```powershell
Get-NetTCPConnection -LocalPort 9401 -ErrorAction SilentlyContinue | Select-Object OwningProcess
```
Change the listen port in `config\cyberglass.toml` or pass `-Port <NEW_PORT>` to `install.ps1`.

### 3. Logs & Diagnostics
Application logs are written to:
- `%CYBERGLASS_HOME%\logs\`
- Console STDOUT / STDERR when executed interactively via `cyberglass.bat`.

### 4. Login Troubleshooting
**Symptom:** The sign-in form reports an invalid username or password.

1. Confirm the server is running and the browser is using its REST address,
   normally `http://localhost:9401/ui`.
2. Confirm the username is `admin`, or the value of
   `CYBERGLASS_ADMIN_USERNAME` in the server process environment.
3. Check whether `CYBERGLASS_ADMIN_PASSWORD` is set. When set, it takes
   precedence over the generated password file. Otherwise, read the file under
   the active `node.data_dir`; with `--home`, this is
   `<home>\data\initial-admin-password`.
4. If the file is absent, review startup logs for the generated password
   location and copy the new file's contents. Do not use a password from a
   different installation or `--home` directory.
5. Five failed attempts lock the account for 15 minutes by default. Wait for
   the lockout to expire before trying again.

**Symptom:** Login succeeds but later requests return 401.  
**Resolution:** Sign in again after restarting the server; session records are
currently in memory and do not persist across restarts.

### 5. Clean Uninstallation
To remove CyberGlass cleanly from the host:
```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1 -Prefix "C:\Program Files\CyberGlass" -Uninstall
```

---

*For further operational details, consult the [Architecture Guide](architecture.md) and [CyberQL Reference](cyberql-reference.md).*
