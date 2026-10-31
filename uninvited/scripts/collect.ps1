# Read-only inventory for Uninvited. Writes one JSON document to -OutPath.
# Collects: scheduled tasks, auto-start services, startup-folder items, processes,
# Modern Standby enter/exit events, sleep/hibernate wake events, wake-armed devices.
param(
    [Parameter(Mandatory = $true)][string]$OutPath,
    [int]$Days = 30
)

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$out = [ordered]@{ errors = @() }

function Add-Err([string]$where, $err) {
    $script:out.errors += ("{0}: {1}" -f $where, $err.Exception.Message)
}

function To-Iso($dt) {
    if ($null -eq $dt) { return $null }
    try {
        $d = [datetime]$dt
        if ($d.Year -lt 2000) { return $null }
        return $d.ToUniversalTime().ToString('o')
    } catch { return $null }
}

# --- machine ---------------------------------------------------------------
try {
    $cs = Get-CimInstance Win32_ComputerSystem
    $os = Get-CimInstance Win32_OperatingSystem
    $out.machine = [ordered]@{
        manufacturer = $cs.Manufacturer
        model        = $cs.Model
        os           = $os.Caption
        osVersion    = $os.Version
        lastBoot     = To-Iso $os.LastBootUpTime
    }
} catch { Add-Err 'machine' $_ }

# --- scheduled tasks -------------------------------------------------------
$tasks = @()
try {
    foreach ($t in Get-ScheduledTask) {
        $actions = @()
        foreach ($a in $t.Actions) {
            $cls = $a.CimClass.CimClassName
            if ($cls -eq 'MSFT_TaskExecAction') {
                $actions += [ordered]@{ type = 'exec'; execute = $a.Execute; arguments = $a.Arguments; workdir = $a.WorkingDirectory }
            } elseif ($cls -eq 'MSFT_TaskComHandlerAction') {
                $actions += [ordered]@{ type = 'com'; classId = $a.ClassId; data = $a.Data }
            } else {
                $actions += [ordered]@{ type = [string]$cls }
            }
        }
        $triggers = @()
        foreach ($tr in $t.Triggers) {
            $kind = ([string]$tr.CimClass.CimClassName) -replace '^MSFT_Task', '' -replace 'Trigger$', ''
            $triggers += [ordered]@{
                type     = $kind
                enabled  = [bool]$tr.Enabled
                start    = $tr.StartBoundary
                interval = $tr.Repetition.Interval
                delay    = $tr.Delay
            }
        }
        $info = $null
        $thirdParty = -not $t.TaskPath.StartsWith('\Microsoft\')
        if ($thirdParty -or $t.Settings.WakeToRun) {
            try {
                $i = Get-ScheduledTaskInfo -TaskPath $t.TaskPath -TaskName $t.TaskName -ErrorAction Stop
                $info = [ordered]@{
                    lastRun    = To-Iso $i.LastRunTime
                    nextRun    = To-Iso $i.NextRunTime
                    lastResult = $i.LastTaskResult
                    missedRuns = $i.NumberOfMissedRuns
                }
            } catch { }
        }
        $tasks += [ordered]@{
            path        = $t.TaskPath
            name        = $t.TaskName
            state       = [string]$t.State
            author      = $t.Author
            description = $t.Description
            wakeToRun   = [bool]$t.Settings.WakeToRun
            hidden      = [bool]$t.Settings.Hidden
            runAs       = $t.Principal.UserId
            runLevel    = [string]$t.Principal.RunLevel
            actions     = $actions
            triggers    = $triggers
            info        = $info
        }
    }
} catch { Add-Err 'tasks' $_ }
$out.tasks = $tasks

# --- auto-start services ---------------------------------------------------
$svcs = @()
try {
    foreach ($s in Get-CimInstance Win32_Service -Filter "StartMode='Auto'") {
        $svcs += [ordered]@{
            name        = $s.Name
            displayName = $s.DisplayName
            description = $s.Description
            state       = $s.State
            pathName    = $s.PathName
            startName   = $s.StartName
            processId   = $s.ProcessId
            delayed     = $s.DelayedAutoStart
        }
    }
} catch { Add-Err 'services' $_ }
$out.services = $svcs

# --- startup folders -------------------------------------------------------
$startup = @()
try {
    $shell = New-Object -ComObject WScript.Shell
    $folders = @(
        @{ scope = 'user'; path = [Environment]::GetFolderPath('Startup') },
        @{ scope = 'machine'; path = [Environment]::GetFolderPath('CommonStartup') }
    )
    foreach ($f in $folders) {
        if (-not $f.path -or -not (Test-Path -LiteralPath $f.path)) { continue }
        foreach ($item in Get-ChildItem -LiteralPath $f.path -Force -File) {
            if ($item.Name -ieq 'desktop.ini') { continue }
            $target = $null; $lnkArgs = $null
            if ($item.Extension -ieq '.lnk') {
                try { $sc = $shell.CreateShortcut($item.FullName); $target = $sc.TargetPath; $lnkArgs = $sc.Arguments } catch { }
            }
            $startup += [ordered]@{
                scope     = $f.scope
                folder    = $f.path
                file      = $item.FullName
                name      = $item.BaseName
                target    = $target
                arguments = $lnkArgs
            }
        }
    }
} catch { Add-Err 'startup' $_ }
$out.startupFolder = $startup

# --- processes (for "what it costs right now") -----------------------------
$procs = @()
try {
    foreach ($p in Get-Process) {
        $path = $null
        try { $path = $p.Path } catch { }
        $procs += [ordered]@{ id = $p.Id; name = $p.ProcessName; path = $path; ws = $p.WorkingSet64 }
    }
} catch { Add-Err 'processes' $_ }
$out.processes = $procs

# --- Modern Standby enter (506) / exit (507) -------------------------------
$since = (Get-Date).AddDays(-$Days)
$standby = @()
try {
    $events = Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-Power'; Id = 506, 507; StartTime = $since } -ErrorAction Stop
    foreach ($e in $events) {
        $x = [xml]$e.ToXml()
        $d = [ordered]@{}
        foreach ($n in $x.Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
        $reasonText = $null
        if ($e.Message -match 'Reason:\s*(.+?)\.?\s*$') { $reasonText = $Matches[1].Trim() }
        $standby += [ordered]@{ id = $e.Id; time = To-Iso $e.TimeCreated; reasonText = $reasonText; data = $d }
    }
} catch {
    if ($_.Exception.Message -notmatch 'No events were found') { Add-Err 'standby' $_ }
}
$out.standby = $standby

# --- classic sleep / hibernate wakes (Power-Troubleshooter 1) --------------
$wakes = @()
try {
    $events = Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Power-Troubleshooter'; Id = 1; StartTime = $since } -ErrorAction Stop
    foreach ($e in $events) {
        $x = [xml]$e.ToXml()
        $d = [ordered]@{}
        foreach ($n in $x.Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
        $source = $null
        if ($e.Message -match 'Wake Source:\s*(.+?)\s*$') { $source = $Matches[1].Trim() }
        $wakes += [ordered]@{ time = To-Iso $e.TimeCreated; source = $source; data = $d }
    }
} catch {
    if ($_.Exception.Message -notmatch 'No events were found') { Add-Err 'wakes' $_ }
}
$out.sleepWakes = $wakes

# --- how far back the System log goes ---------------------------------------
try { $out.logStart = To-Iso ((Get-WinEvent -LogName System -MaxEvents 1 -Oldest -ErrorAction Stop).TimeCreated) } catch { Add-Err 'logStart' $_ }

# --- devices allowed to wake the PC ----------------------------------------
try {
    $out.wakeArmed = @(powercfg /devicequery wake_armed 2>$null | Where-Object { $_ -and $_.Trim() -and $_.Trim() -ne 'NONE' } | ForEach-Object { $_.Trim() })
} catch { Add-Err 'wakeArmed' $_ }

# --- "Allow wake timers" setting of the active power plan --------------------
try {
    $q = (powercfg /q SCHEME_CURRENT SUB_SLEEP RTCWAKE 2>$null) -join "`n"
    $vals = [regex]::Matches($q, '0x([0-9a-fA-F]{8})') | ForEach-Object { [Convert]::ToInt32($_.Groups[1].Value, 16) }
    if ($vals.Count -ge 2) { $out.wakeTimers = [ordered]@{ ac = $vals[$vals.Count - 2]; dc = $vals[$vals.Count - 1] } }
} catch { Add-Err 'wakeTimers' $_ }

$out.collectedAt = (Get-Date).ToUniversalTime().ToString('o')
$out | ConvertTo-Json -Depth 8 -Compress | Out-File -LiteralPath $OutPath -Encoding utf8
