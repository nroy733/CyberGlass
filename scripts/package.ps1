# ==============================================================================
# 🛡️ CYBERGLASS — Air-Gap Distribution Packager for Windows
# ==============================================================================
param(
    [string]$Target = "windows-x86_64",
    [string]$Version = "0.1.0"
)

$ErrorActionPreference = "Stop"

$distDir = "dist"
$packageName = "cyberglass-v$Version-$Target"
$stagingDir = Join-Path $distDir $packageName

Write-Host "==> Packaging CyberGlass for target: $Target" -ForegroundColor Cyan

# Locate binary
$binSrc = "target\release\cyberglass-server.exe"

if (-not (Test-Path $binSrc)) {
    Write-Host "Compiling release binary..." -ForegroundColor Yellow
    cargo build --release --bin cyberglass-server
}

if (-not (Test-Path $binSrc)) {
    throw "Release binary was not produced at $binSrc."
}

# Rebuild the staging tree from scratch so stale or debug artifacts cannot
# inflate the distribution archive. Do this after the release binary is ready
# so a failed build does not destroy a previous package.
if (Test-Path $stagingDir) {
    Remove-Item -Path $stagingDir -Recurse -Force
}

# Create directory tree
@("bin", "config", "rules") | ForEach-Object {
    $dir = Join-Path $stagingDir $_
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
}

Copy-Item -Path $binSrc -Destination (Join-Path $stagingDir "bin\cyberglass-server.exe") -Force

# Copy configuration & detection rules
Copy-Item -Path "config\cyberglass.toml" -Destination (Join-Path $stagingDir "config\cyberglass.toml") -Force
if (Test-Path "rules") {
    Copy-Item -Path "rules\*" -Destination (Join-Path $stagingDir "rules") -Recurse -Force
}

# Copy documentation
Copy-Item -Path "docs" -Destination (Join-Path $stagingDir "docs") -Recurse -Force
Copy-Item -Path "DEPLOYMENT.md" -Destination (Join-Path $stagingDir "DEPLOYMENT.md") -Force
Copy-Item -Path "README.md" -Destination (Join-Path $stagingDir "README.md") -Force
Copy-Item -Path "LICENSE" -Destination (Join-Path $stagingDir "LICENSE") -Force

# Copy installers
Copy-Item -Path "installer\install.ps1" -Destination (Join-Path $stagingDir "install.ps1") -Force
Copy-Item -Path "installer\install.sh" -Destination (Join-Path $stagingDir "install.sh") -Force

# Quick-start README
$readme = @"
================================================================================
🛡️ CYBERGLASS SIEM & DATA FUSION PLATFORM — AIR-GAP DISTRIBUTION
================================================================================
Target Platform: $Target
Version: $Version

To install on Windows:
    powershell -ExecutionPolicy Bypass -File .\install.ps1

To run directly from this folder without installing:
    .\bin\cyberglass-server.exe --home .

Search & REST Gateway Web UI will be available at:
    http://localhost:9401
================================================================================
"@
Set-Content -Path (Join-Path $stagingDir "README.txt") -Value $readme -Force

# Create ZIP archive
$zipPath = Join-Path $distDir "$packageName.zip"
if (Test-Path $zipPath) {
    Remove-Item -Path $zipPath -Force
}

Compress-Archive -Path "$stagingDir\*" -DestinationPath $zipPath -Force
Write-Host "==> Distribution archive created successfully: $zipPath" -ForegroundColor Green
