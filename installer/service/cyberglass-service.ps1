# ==============================================================================
# 🛡️ CYBERGLASS — Windows Background Service Manager
# ==============================================================================
param(
    [ValidateSet("install", "start", "stop", "restart", "status", "uninstall")]
    [string]$Action = "status",
    [string]$Prefix = "$env:LOCALAPPDATA\CyberGlass",
    [string]$TaskName = "CyberGlassSIEM"
)

$ErrorActionPreference = "Stop"

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

switch ($Action) {
    "install" {
        $exePath = Join-Path $Prefix "bin\cyberglass-server.exe"
        if (-not (Test-Path $exePath)) {
            Write-Error "CyberGlass binary not found at: $exePath"
            exit 1
        }

        Write-Host "[+] Creating Scheduled Task '$TaskName' for background execution..." -ForegroundColor Green
        $taskAction = New-ScheduledTaskAction -Execute $exePath -Argument "--home `"$Prefix`""
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit 0

        if ($isAdmin) {
            $trigger = New-ScheduledTaskTrigger -AtStartup
            $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
            Register-ScheduledTask -TaskName $TaskName -Action $taskAction -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
            Write-Host "[OK] Task registered successfully to start on system boot as SYSTEM." -ForegroundColor Green
        } else {
            $trigger = New-ScheduledTaskTrigger -AtLogOn
            $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -RunLevel Highest
            Register-ScheduledTask -TaskName $TaskName -Action $taskAction -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
            Write-Host "[OK] Task registered successfully to start on user logon for $env:USERNAME." -ForegroundColor Green
        }
    }

    "start" {
        Write-Host "[+] Starting background task '$TaskName'..." -ForegroundColor Green
        Start-ScheduledTask -TaskName $TaskName
        Start-Sleep -Seconds 2
        Get-ScheduledTask -TaskName $TaskName | Select-Object TaskName, State
    }

    "stop" {
        Write-Host "[+] Stopping background task '$TaskName'..." -ForegroundColor Yellow
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        # Gracefully kill running server process if still present
        Get-Process -Name "cyberglass-server" -ErrorAction SilentlyContinue | Stop-Process -Force
        Write-Host "[OK] CyberGlass service stopped." -ForegroundColor Green
    }

    "restart" {
        & $PSCommandPath -Action stop -TaskName $TaskName -Prefix $Prefix
        Start-Sleep -Seconds 2
        & $PSCommandPath -Action start -TaskName $TaskName -Prefix $Prefix
    }

    "status" {
        try {
            $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
            $proc = Get-Process -Name "cyberglass-server" -ErrorAction SilentlyContinue
            Write-Host "Task Name   : $($task.TaskName)" -ForegroundColor Cyan
            Write-Host "Task State  : $($task.State)" -ForegroundColor Cyan
            if ($proc) {
                Write-Host "Process     : Running (PID: $($proc.Id), WorkingSet: $([math]::Round($proc.WorkingSet64 / 1MB, 2)) MB)" -ForegroundColor Green
            } else {
                Write-Host "Process     : Not running" -ForegroundColor Yellow
            }
        } catch {
            Write-Host "[-] Task '$TaskName' is not registered." -ForegroundColor Yellow
        }
    }

    "uninstall" {
        Write-Host "[+] Unregistering background task '$TaskName'..." -ForegroundColor Yellow
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        Get-Process -Name "cyberglass-server" -ErrorAction SilentlyContinue | Stop-Process -Force
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
        Write-Host "[OK] Background task '$TaskName' unregistered." -ForegroundColor Green
    }
}
