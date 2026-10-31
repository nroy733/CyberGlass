# ==============================================================================
# 🛡️ CYBERGLASS — Air-Gap Distribution Packager for Windows
# ==============================================================================
param(
    [string]$Target = "windows-x86_64",
    [string]$Version = ""
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($Version)) {
    $workspaceManifest = Get-Content -Path "Cargo.toml" -Raw
    $workspacePackage = [regex]::Match(
        $workspaceManifest,
        '(?ms)^\[workspace\.package\]\s*(.*?)(?=^\[|\z)'
    )
    $versionMatch = [regex]::Match($workspacePackage.Groups[1].Value, '(?m)^\s*version\s*=\s*"([^"]+)"')
    if (-not $versionMatch.Success) {
        throw "Could not read workspace package version from Cargo.toml."
    }
    $Version = $versionMatch.Groups[1].Value
}

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

$binaryVersion = & $binSrc --version
if ($LASTEXITCODE -ne 0 -or $binaryVersion -ne "cyberglass-server $Version") {
    throw "Release binary version '$binaryVersion' does not match package version '$Version'. Rebuild the release binary before packaging."
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
