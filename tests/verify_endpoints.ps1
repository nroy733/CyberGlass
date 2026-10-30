# Verification script for CyberGlass REST endpoints
$ErrorActionPreference = 'Stop'

Write-Host "=== 1. UI Endpoint ===" -ForegroundColor Cyan
$ui = Invoke-WebRequest -Uri 'http://localhost:9401/ui' -UseBasicParsing
Write-Host "UI Status: $($ui.StatusCode) | Content Length: $($ui.Content.Length) bytes"

Write-Host "`n=== 2. Users (RBAC) ===" -ForegroundColor Cyan
$usersResp = Invoke-RestMethod -Uri 'http://localhost:9401/api/v1/auth/users'
Write-Host "User Count: $($usersResp.users.Count)"
foreach ($u in $usersResp.users) {
    Write-Host "  - User: $($u.username) | FullName: $($u.full_name) | Roles: $($u.roles -join ', ') | Active: $($u.is_active)"
}

Write-Host "`n=== 3. Roles (RBAC) ===" -ForegroundColor Cyan
$rolesResp = Invoke-RestMethod -Uri 'http://localhost:9401/api/v1/auth/roles'
Write-Host "Roles Count: $($rolesResp.roles.Count)"
foreach ($r in $rolesResp.roles) {
    Write-Host "  - Role: $($r.name) | SystemRole: $($r.is_system) | Perms: $($r.permissions.Count)"
}

Write-Host "`n=== 4. Dashboards ===" -ForegroundColor Cyan
$dashboardsResp = Invoke-RestMethod -Uri 'http://localhost:9401/api/v1/dashboards'
Write-Host "Dashboards Count: $($dashboardsResp.dashboards.Count)"
foreach ($d in $dashboardsResp.dashboards) {
    Write-Host "  - Dashboard: $($d.name) (ID: $($d.id)) | Widgets: $($d.widgets.Count)"
}

Write-Host "`n=== 5. Internal Logs (cg_internal) ===" -ForegroundColor Cyan
$intLogs = Invoke-RestMethod -Uri 'http://localhost:9401/api/v1/internal/logs?index=cg_internal&limit=5'
Write-Host "Internal logs count: $($intLogs.Count)"

Write-Host "`n=== 6. Agent Script Download ===" -ForegroundColor Cyan
$agentScript = Invoke-WebRequest -Uri 'http://localhost:9401/api/v1/agent/script?type=python' -UseBasicParsing
Write-Host "Python Agent Script Length: $($agentScript.Content.Length) bytes"

Write-Host "`n=== 7. REST Ingest ===" -ForegroundColor Cyan
$ingestPayload = @{
    source = "endpoint-agent-win01"
    source_type = "winevent"
    index = "security"
    event = @{
        event_id = 4624
        message = "An account was successfully logged on"
        user = "jdoe"
        ip = "192.168.1.55"
        logon_type = 10
    }
} | ConvertTo-Json
$ingestResp = Invoke-RestMethod -Uri 'http://localhost:9401/api/v1/ingest' -Method Post -Body $ingestPayload -ContentType 'application/json'
Write-Host "Ingest Status: $($ingestResp.status) | Event ID: $($ingestResp.event_id)"

Write-Host "`n=== 8. HEC Ingest ===" -ForegroundColor Cyan
$hecPayload = @{
    time = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    host = "win-dc-01.corp"
    source = "ActiveDirectory"
    sourcetype = "ad:audit"
    index = "main"
    event = "User admin authenticated successfully via Kerberos"
} | ConvertTo-Json
$hecHeaders = @{ "Authorization" = "Bearer 4c8928e4-b7e9-4e78-9eb4-cb01dc8a24aa" }
$hecResp = Invoke-RestMethod -Uri 'http://localhost:9401/services/collector' -Method Post -Headers $hecHeaders -Body $hecPayload -ContentType 'application/json'
Write-Host "HEC Response: $($hecResp.text) | Code: $($hecResp.code) | Accepted: $($hecResp.accepted)"

Write-Host "`n=== 9. CyberQL Query Search (Internal Index) ===" -ForegroundColor Cyan
$queryPayload = @{
    query = "index=cg_internal | head 10"
    time_range = @{ preset = "24h" }
} | ConvertTo-Json
$queryResp = Invoke-RestMethod -Uri 'http://localhost:9401/api/v1/query' -Method Post -Body $queryPayload -ContentType 'application/json'
Write-Host "Query Status: $($queryResp.status) | Events Matched: $($queryResp.stats.events_matched)"
Write-Host "Sample Internal Event: $($queryResp.results[0]._raw)"

Write-Host "`n=== 10. AI Threat Hunter Chat (Local) ===" -ForegroundColor Cyan
$aiPayload = @{
    message = "Analyze potential pass-the-hash or lateral movement indicators in event 4624 logon type 10"
    provider = "local"
} | ConvertTo-Json
$aiResp = Invoke-RestMethod -Uri 'http://localhost:9401/api/v1/ai/chat' -Method Post -Body $aiPayload -ContentType 'application/json'
Write-Host "AI Response Provider: $($aiResp.provider)"
if ($aiResp.response) {
    Write-Host "AI Reply preview: $($aiResp.response.Substring(0, [Math]::Min(180, $aiResp.response.Length)))..."
}

Write-Host "`n=== ALL VERIFICATION CHECKS PASSED SUCCESSFULLY ===" -ForegroundColor Green
