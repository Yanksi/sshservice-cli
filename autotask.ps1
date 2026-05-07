$scriptPath = $PSScriptRoot
$scriptFilePy = Join-Path -Path $scriptPath -ChildPath "cscs-keygen.py"

$pyOutput = & uv run $scriptFilePy --once

# Match the validity line specifically — earlier digits (chmod 600, ports in
# URLs, digits in usernames/paths) would otherwise be picked up by a bare \d+.
$timeMatch = [regex]::Match(($pyOutput -join "`n"), 'valid for (\d+) seconds')
if (-not $timeMatch.Success) {
    Write-Error "Could not parse remaining validity from cscs-keygen.py output:`n$pyOutput"
    exit 1
}
$timeleft = [int]$timeMatch.Groups[1].Value

$timeleft = $timeleft + 10 # delay by 10 seconds

$scriptFile = Join-Path -Path $scriptPath -ChildPath "autotask.ps1"

$task_path = "\Utils\"
$task_name = "CSCSAutoKey"

# findout if task "Utils\CSCSAutoKey" exists
try {
    $task = Get-ScheduledTask -TaskPath $task_path -TaskName $task_name -ErrorAction Stop
    $task_exists = $true
} catch {
    $task_exists = $false
}

if ($task_exists) {
    $task = Get-ScheduledTask -TaskPath $task_path -TaskName $task_name
    $trigger = $task.Triggers[0]
    # set the start boundary of the trigger to one day after the current time
    $trigger.StartBoundary = (Get-Date).AddSeconds($timeleft).ToString("yyyy-MM-ddTHH:mm:ss")
    Set-ScheduledTask -TaskPath $task_path -TaskName $task_name -Trigger $trigger
} else {
    $STAct = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "$scriptFile"
    $STrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds($timeleft).ToString("yyyy-MM-ddTHH:mm:ss")
    $STSet = $STSet = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -RunOnlyIfNetworkAvailable -StartWhenAvailable
    Register-ScheduledTask -TaskName $task_name -Action $STAct -Trigger $STrigger -TaskPath $task_path -Settings $STSet
}

# # press any key to exit
# $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")