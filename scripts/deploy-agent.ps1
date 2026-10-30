# =============================================================================
# CyberGlass Agent Deployment Script (PowerShell / Windows)
# =============================================================================
$ErrorActionPreference = "Stop"

$AGENT_BINARY = "cg-agent.exe"
$CONFIG_DIR = "C:\ProgramData\CyberGlass\agent"
$DATA_DIR = "C:\ProgramData\CyberGlass\agent\data"
$LOG_DIR = "C:\ProgramData\CyberGlass\logs"
$SERVER_URL = $env:CYBERGLASS_SERVER_URL -or "http://localhost:9401"

Write-Host "==============================================" -ForegroundColor Cyan
Write-Host "  CyberGlass Agent Deployment (Windows)" -ForegroundColor Cyan
Write-Host "==============================================" -ForegroundColor Cyan

# Create directories
Write-Host "[1/4] Creating directories..."
New-Item -ItemType Directory -Path $CONFIG_DIR -Force | Out-Null
New-Item -ItemType Directory -Path $DATA_DIR -Force | Out-Null
New-Item -ItemType Directory -Path $LOG_DIR -Force | Out-Null

# Install binary
Write-Host "[2/4] Installing agent binary..."
$debugPath = Join-Path -Path ".\target\debug" -ChildPath $AGENT_BINARY
$releasePath = Join-Path -Path ".\target\release" -ChildPath $AGENT_BINARY
$installPath = Join-Path -Path "C:\Program Files\CyberGlass" -ChildPath $AGENT_BINARY

if (Test-Path $debugPath) {
    Copy-Item $debugPath $installPath -Force
} elseif (Test-Path $releasePath) {
    Copy-Item $releasePath $installPath -Force
} else {
    Write-Error "Agent binary not found. Build with: cargo build --bin cg-agent --release"
}

New-Item -ItemType Directory -Path "C:\Program Files\CyberGlass" -Force | Out-Null

# Install config
Write-Host "[3/4] Installing configuration..."
$configPath = Join-Path -Path $CONFIG_DIR -ChildPath "agent.toml"
if (-not (Test-Path $configPath)) {
    Copy-Item ".\crates\cg-agent\agent.toml.example" $configPath -Force
    # Replace server URL
    (Get-Content $configPath) | ForEach-Object {
        $_ -replace '^server = .*', "server = `"${SERVER_URL}`""
    } | Set-Content $configPath
}

# Create NSSM service or scheduled task
Write-Host "[4/4] Creating service..."
$serviceScript = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/tasks/...">
  <RegistrationInfo>
    <Date>$(Get-Date -Format o)</Date>
    <Author>CyberGlass</Author>
  </RegistrationInfo>
  <Triggers>
    <BootTrigger>
      <Enabled>true</Enabled>
    </BootTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>"${installPath}"</Command>
      <Arguments>--config "${configPath}"</Arguments>
      <WorkingDirectory>${DATA_DIR}</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"@

$taskXmlPath = Join-Path -Path $env:TEMP -ChildPath "cyberglass-agent.xml"
$serviceScript | Out-File -FilePath $taskXmlPath -Encoding Unicode
schtasks /Create /TN "CyberGlassAgent" /XML "$taskXmlPath" /F 2>$null || Write-Warning "Failed to create scheduled task (may already exist)"

Write-Host ""
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host "  Deployment Complete!" -ForegroundColor Cyan
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Binary:   $installPath"
Write-Host "Config:   $configPath"
Write-Host "Data:     $DATA_DIR"
Write-Host "Logs:     $LOG_DIR"
Write-Host ""
Write-Host "To run:   $installPath --config `"$configPath`""
Write-Host ""