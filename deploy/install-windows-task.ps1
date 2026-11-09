<#
.SYNOPSIS
    Run NetGuard in the background at logon on Windows (Task Scheduler).

.DESCRIPTION
    Registers a scheduled task that starts `python -m netguard serve` when you
    log in, restarts it if it crashes, and keeps its database in this folder.
    Run from an elevated PowerShell if you want --sniff (packet capture needs
    admin rights and Npcap).

.EXAMPLE
    .\deploy\install-windows-task.ps1
    .\deploy\install-windows-task.ps1 -Sniff
    .\deploy\install-windows-task.ps1 -Uninstall
#>
param(
    [switch]$Sniff,
    [switch]$Uninstall,
    [string]$TaskName = "NetGuard"
)

if ($Uninstall) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Write-Host "Removed scheduled task '$TaskName'."
    return
}

$repo = Split-Path -Parent $PSScriptRoot
$python = (Get-Command pythonw.exe -ErrorAction SilentlyContinue).Source
if (-not $python) { $python = (Get-Command python.exe).Source }

# --reload: the task restarts itself when NetGuard's files change, so it
# never keeps running an old version after an update.
$arguments = "-m netguard serve --reload"
if ($Sniff) { $arguments += " --sniff" }

$action   = New-ScheduledTaskAction -Execute $python -Argument $arguments -WorkingDirectory $repo
$trigger  = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
            -RestartCount 5 -RestartInterval (New-TimeSpan -Minutes 1) `
            -ExecutionTimeLimit ([TimeSpan]::Zero)
$level    = if ($Sniff) { "Highest" } else { "Limited" }
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel $level

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
    -Settings $settings -Principal $principal -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName

Write-Host "NetGuard is running in the background and will start at every logon."
Write-Host "Dashboard: http://localhost:8000/"
Write-Host "Remove with: .\deploy\install-windows-task.ps1 -Uninstall"
