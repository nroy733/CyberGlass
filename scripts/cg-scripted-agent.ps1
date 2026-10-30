<#
.SYNOPSIS
    CyberGlass Scripted Input Agent for Windows PowerShell
    Modifiable, deployable data onboarding agent without compilation.

.DESCRIPTION
    Runs commands on an interval or tails files, forwarding structured telemetry
    to CyberGlass via the REST API or HTTP Event Collector (HEC).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\cg-scripted-agent.ps1 -Server "http://localhost:9401" -Script "Get-Service | Where-Object Status -eq 'Running'" -Interval 30
#>

param (
    [string]$Server = "http://localhost:9401",
    [string]$Token = "",
    [string]$Script = "",
    [int]$Interval = 30,
    [string]$Tail = "",
    [string]$Source = "$env:COMPUTERNAME-ps-agent",
    [string]$SourceType = "json",
    [string]$Index = "main",
    [ValidateSet("rest", "hec")]
    [string]$Mode = "rest",
    [switch]$Once
)

Write-Host "==============================================" -ForegroundColor Cyan
Write-Host "  CyberGlass Scripted Input Agent (PowerShell)" -ForegroundColor Cyan
Write-Host "  Server : $Server" -ForegroundColor Cyan
Write-Host "  Host   : $env:COMPUTERNAME" -ForegroundColor Cyan
Write-Host "  Index  : $Index" -ForegroundColor Cyan
Write-Host "==============================================" -ForegroundColor Cyan

function Send-CyberGlassEvent {
    param([string]$RawContent)
    
    if ([string]::IsNullOrWhiteSpace($RawContent)) { return }

    try {
        if ($Mode -eq "hec") {
            $hecUrl = "$($Server.TrimEnd('/'))/services/collector/event"
            $headers = @{ "Content-Type" = "application/json" }
            if ($Token) { $headers["Authorization"] = "Bearer $Token" }
            $body = @{
                event = $RawContent
                source = $Source
                sourcetype = $SourceType
                index = $Index
                time = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
            } | ConvertTo-Json -Depth 4
            $resp = Invoke-RestMethod -Uri $hecUrl -Method Post -Headers $headers -Body $body -TimeoutSec 10
        } else {
            $restUrl = "$($Server.TrimEnd('/'))/api/v1/ingest"
            $headers = @{ "Content-Type" = "application/json" }
            if ($Token) { $headers["Authorization"] = "Bearer $Token" }
            $body = @{
                source = $Source
                source_type = $SourceType
                index = $Index
                raw = $RawContent
            } | ConvertTo-Json -Depth 4
            $resp = Invoke-RestMethod -Uri $restUrl -Method Post -Headers $headers -Body $body -TimeoutSec 10
        }
        $timeStr = (Get-Date).ToString("HH:mm:ss")
        Write-Host "[$timeStr] Ingested $($RawContent.Length) bytes -> $($resp.status)" -ForegroundColor Green
    } catch {
        Write-Warning "Failed sending event: $_"
    }
}

if ($Tail) {
    Write-Host "[*] Following file: $Tail" -ForegroundColor Yellow
    Get-Content -Path $Tail -Wait -Tail 0 | ForEach-Object {
        Send-CyberGlassEvent -RawContent $_
    }
} elseif ($Script) {
    Write-Host "[*] Executing script every $Interval seconds: $Script" -ForegroundColor Yellow
    do {
        try {
            $output = Invoke-Expression $Script | Out-String
            if (-not [string]::IsNullOrWhiteSpace($output)) {
                $payload = @{
                    host = $env:COMPUTERNAME
                    command = $Script
                    timestamp = [DateTime]::UtcNow.ToString("o")
                    output = $output.Trim()
                } | ConvertTo-Json -Compress
                Send-CyberGlassEvent -RawContent $payload
            }
        } catch {
            Write-Warning "Script execution error: $_"
        }
        if (-not $Once) { Start-Sleep -Seconds $Interval }
    } while (-not $Once)
} else {
    Write-Host "[*] Sending Windows OS telemetry sample..." -ForegroundColor Yellow
    $os = Get-CimInstance Win32_OperatingSystem
    $sample = @{
        host = $env:COMPUTERNAME
        os = $os.Caption
        version = $os.Version
        total_memory_mb = [math]::Round($os.TotalVisibleMemorySize / 1024)
        free_memory_mb = [math]::Round($os.FreePhysicalMemory / 1024)
        timestamp = [DateTime]::UtcNow.ToString("o")
        heartbeat = $true
    } | ConvertTo-Json -Compress
    Send-CyberGlassEvent -RawContent $sample
    Write-Host "[+] Sample delivered." -ForegroundColor Green
}
