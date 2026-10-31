$ErrorActionPreference = "Stop"

$installer = Join-Path $PSScriptRoot "installer\install.ps1"
if (-not (Test-Path -LiteralPath $installer -PathType Leaf)) {
    throw "Canonical installer not found: $installer"
}

& $installer @args
if (-not $?) {
    exit 1
}
