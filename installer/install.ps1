# ==============================================================================
# 🛡️ CYBERGLASS — Offline Installer for Windows
# ==============================================================================
param(
    [string]$Prefix = "$env:LOCALAPPDATA\CyberGlass",
    [string]$Port = "9401",
    [switch]$Service,
    [switch]$Firewall,
    [switch]$Uninstall,
    [switch]$Help
)

if ($Help) {
    Write-Host @"
Usage: .\install.ps1 [OPTIONS]  (or .\install.bat [OPTIONS])

Options:
    -Prefix <PATH>   Installation directory (default: %LOCALAPPDATA%\CyberGlass)
    -Port <PORT>     REST & Search Gateway listen port (default: 9401)
    -Service         Register as a persistent Windows background service / scheduled task
    -Firewall        Configure Windows Defender Firewall rules for gRPC, REST, and Syslog ports
    -Uninstall       Uninstall CyberGlass from this machine
    -Help            Show this help text
"@
    exit 0
}

$ErrorActionPreference = "Stop"

Write-Host @"
   ______      __                 ________                 
  / ____/_  __/ /_  ___  _____   / ____/ /___ ___________  
 / /   / / / / __ \/ _ \/ ___/  / / __/ / __ `/ ___/ ___/  
/ /___/ /_/ / /_/ /  __/ /     / /_/ / / /_/ (__  |__  )   
\____/\__, /_.___/\___/_/      \____/_/\__,_/____/____/    
     /____/                                                
   >> NEXT-GEN AIR-GAP SIEM & DATA FUSION PLATFORM <<
   >> Windows Offline Installer <<
"@ -ForegroundColor Cyan

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if ($Uninstall) {
    Write-Host "Uninstalling CyberGlass from $Prefix..." -ForegroundColor Yellow
    try {
        Unregister-ScheduledTask -TaskName "CyberGlassSIEM" -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
        Write-Host "[OK] Removed background service task 'CyberGlassSIEM'." -ForegroundColor Green
    } catch {}

    if (Test-Path $Prefix) {
        Remove-Item -Path $Prefix -Recurse -Force
    }
    Write-Host "[OK] CyberGlass uninstalled successfully." -ForegroundColor Green
    exit 0
}

Write-Host "[+] Preparing target directories at $Prefix..." -ForegroundColor Green
@("bin", "config", "data", "index", "wal", "rules", "ontology", "models", "logs") | ForEach-Object {
    $dir = Join-Path $Prefix $_
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
}

# Resolve candidate search roots (script root, current dir, parent repos)
$scriptDir = $PSScriptRoot
$currentDir = (Get-Location).Path

$searchRoots = @(
    $scriptDir,
    $currentDir,
    (Split-Path -Parent $scriptDir),
    (Split-Path -Parent $currentDir),
    (Join-Path $scriptDir ".."),
    (Join-Path $currentDir "..")
) | Where-Object { $_ -and (Test-Path $_) } | ForEach-Object { (Resolve-Path $_).Path } | Select-Object -Unique

# Resolve the expected release version from the package or workspace manifest.
$expectedVersion = $null
$versionFile = Join-Path $scriptDir "VERSION"
if (Test-Path -LiteralPath $versionFile -PathType Leaf) {
    $expectedVersion = (Get-Content -LiteralPath $versionFile -Raw).Trim()
} else {
    foreach ($root in $searchRoots) {
        $manifestPath = Join-Path $root "Cargo.toml"
        if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
            continue
        }

        $manifest = Get-Content -LiteralPath $manifestPath -Raw
        $workspacePackage = [regex]::Match(
            $manifest,
            '(?ms)^\[workspace\.package\]\s*(.*?)(?=^\[|\z)'
        )
        $versionMatch = [regex]::Match(
            $workspacePackage.Groups[1].Value,
            '(?m)^\s*version\s*=\s*"([^"]+)"'
        )
        if ($versionMatch.Success) {
            $expectedVersion = $versionMatch.Groups[1].Value
            break
        }
    }
}

# 1. Binary Discovery
$binaryCandidates = @()
foreach ($root in $searchRoots) {
    $binaryCandidates += (Join-Path $root "bin\cyberglass-server.exe")
    $binaryCandidates += (Join-Path $root "cyberglass-server.exe")
    $binaryCandidates += (Join-Path $root "target\release\cyberglass-server.exe")
}

$binarySrc = $binaryCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1

if (-not $binarySrc) {
    Write-Error "Could not find a packaged or release cyberglass-server.exe. Build with 'cargo build --release --bin cyberglass-server' or use the release bundle."
    exit 1
}

$binaryVersion = & $binarySrc --version
if ($LASTEXITCODE -ne 0) {
    throw "Could not read the server version from '$binarySrc'."
}
if ($expectedVersion -and $binaryVersion -ne "cyberglass-server $expectedVersion") {
    throw "Refusing to install '$binaryVersion'; expected workspace/package version $expectedVersion."
}

Write-Host "[+] Found server binary: $binarySrc" -ForegroundColor Green
Write-Host "[+] Verified server version: $binaryVersion" -ForegroundColor Green
Copy-Item -Path $binarySrc -Destination (Join-Path $Prefix "bin\cyberglass-server.exe") -Force

# 2. Configuration Discovery
$configCandidates = @()
foreach ($root in $searchRoots) {
    $configCandidates += (Join-Path $root "config\cyberglass.toml")
    $configCandidates += (Join-Path $root "cyberglass.toml")
}

$configSrc = $configCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if ($configSrc) {
    Write-Host "[+] Installing configuration from: $configSrc" -ForegroundColor Green
    Copy-Item -Path $configSrc -Destination (Join-Path $Prefix "config\cyberglass.toml") -Force
} else {
    Write-Warning "No cyberglass.toml configuration found. A default config will be generated at startup."
}

# 3. Detection Rules Discovery
$rulesCandidates = @()
foreach ($root in $searchRoots) {
    $rulesCandidates += (Join-Path $root "rules")
}
$rulesSrc = $rulesCandidates | Where-Object { (Test-Path $_) -and (Get-ChildItem -Path $_ -ErrorAction SilentlyContinue) } | Select-Object -First 1
if ($rulesSrc) {
    Write-Host "[+] Installing detection rules from: $rulesSrc" -ForegroundColor Green
    Copy-Item -Path "$rulesSrc\*" -Destination (Join-Path $Prefix "rules") -Recurse -Force -ErrorAction SilentlyContinue
}

# Create launch helper script
$batchLauncher = @"
@echo off
set CYBERGLASS_HOME=$Prefix
set CYBERGLASS_CONFIG=$Prefix\config\cyberglass.toml
"%~dp0cyberglass-server.exe" --home "$Prefix" %*
"@
Set-Content -Path (Join-Path $Prefix "bin\cyberglass.bat") -Value $batchLauncher -Force

$uiLauncher = @"
@echo off
set CYBERGLASS_HOME=$Prefix
set CYBERGLASS_CONFIG=$Prefix\config\cyberglass.toml
echo Starting CyberGlass Server and launching Web UI...
start "" http://localhost:$Port
"%~dp0cyberglass-server.exe" --home "$Prefix" %*
"@
Set-Content -Path (Join-Path $Prefix "bin\cyberglass-ui.bat") -Value $uiLauncher -Force
Set-Content -Path (Join-Path $Prefix "start.bat") -Value $uiLauncher -Force

# Add to user PATH
$binPath = Join-Path $Prefix "bin"
$currentPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($currentPath -notlike "*$binPath*") {
    [Environment]::SetEnvironmentVariable("Path", "$binPath;$currentPath", "User")
    Write-Host "[+] Added $binPath to User PATH." -ForegroundColor Green
}

# Optional Service Registration
if ($Service) {
    Write-Host "[+] Registering CyberGlass as persistent background service..." -ForegroundColor Green
    $taskName = "CyberGlassSIEM"
    $exePath = Join-Path $Prefix "bin\cyberglass-server.exe"
    $action = New-ScheduledTaskAction -Execute $exePath -Argument "`"--home `"$Prefix`"`""
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit 0

    if ($isAdmin) {
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
        Write-Host "[OK] Registered Windows Task '$taskName' to run at system startup as SYSTEM." -ForegroundColor Green
    } else {
        $trigger = New-ScheduledTaskTrigger -AtLogOn
        $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -RunLevel Highest
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
        Write-Host "[OK] Registered Windows Task '$taskName' to run at user logon for $env:USERNAME." -ForegroundColor Green
    }
}

# Optional Firewall Rules
if ($Firewall) {
    if ($isAdmin) {
        Write-Host "[+] Configuring Windows Defender Firewall rules..." -ForegroundColor Green
        try {
            New-NetFirewallRule -DisplayName "CyberGlass gRPC Service (9400)" -Direction Inbound -LocalPort 9400 -Protocol TCP -Action Allow -ErrorAction SilentlyContinue | Out-Null
            New-NetFirewallRule -DisplayName "CyberGlass REST & Gateway (9401)" -Direction Inbound -LocalPort 9401 -Protocol TCP -Action Allow -ErrorAction SilentlyContinue | Out-Null
            New-NetFirewallRule -DisplayName "CyberGlass Syslog TCP (1514)" -Direction Inbound -LocalPort 1514 -Protocol TCP -Action Allow -ErrorAction SilentlyContinue | Out-Null
            New-NetFirewallRule -DisplayName "CyberGlass Syslog UDP (1514)" -Direction Inbound -LocalPort 1514 -Protocol UDP -Action Allow -ErrorAction SilentlyContinue | Out-Null
            Write-Host "[OK] Firewall rules created for ports 9400, 9401, 1514 (TCP/UDP)." -ForegroundColor Green
        } catch {
            Write-Warning "Could not set firewall rules: $_"
        }
    } else {
        Write-Warning "Firewall rules require Administrator privileges. Skipping -Firewall."
    }
}

Write-Host "`n[SUCCESS] CyberGlass is installed and ready for air-gapped operations!" -ForegroundColor Green
Write-Host "===================================================================="
Write-Host "  Directory : $Prefix"
Write-Host "  Start Cmd : $(Join-Path $Prefix 'bin\cyberglass.bat')"
Write-Host "  Web API   : http://localhost:$Port"
Write-Host "====================================================================`n"