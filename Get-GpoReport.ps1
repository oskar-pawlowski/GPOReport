#Requires -Version 5.1
<#
    GPO reporting toolkit - a library, not a script. Dot-source it, then call the functions.

        . .\Get-GpoReport.ps1

        $json = Export-GpoInventory -Domain ad.net -Path C:\Reports\gpo.json -ThrottleLimit 12
        $json | ConvertTo-GpoCsv
        $json | ConvertTo-GpoHtml

    Export-GpoInventory   collects every GPO in parallel -> raw JSON
    ConvertTo-GpoCsv      raw JSON -> flat CSV        (offline)
    ConvertTo-GpoHtml     raw JSON -> standalone HTML (offline)

    Design rules, so the run never looks frozen:
      * the progress bar is refreshed on every poll tick, not only when a GPO finishes;
      * a status line is printed every -StatusInterval seconds, in case the progress bar
        is not rendered (some hosts) or the window is scrolled away;
      * every phase announces itself before it starts, including the slow ones
        (Get-GPO enumeration, JSON serialisation);
      * a stuck GPO is killed after -TimeoutSeconds and recorded as an error,
        so the run always terminates.
#>

# ---------------------------------------------------------------------------
# Runspace worker. Deliberately primitive input: a GUID string, never a live
# GPMC object - those evaluate lazily over COM and are not thread-safe.
# Returns only what has to be parsed from the XML report.
# ---------------------------------------------------------------------------
$script:GpoWorker = {
    param([string]$Id, [string]$Domain, [int]$MaxSettings)

    function Get-XText {
        param($Node, [string]$Name)
        if (-not $Node) { return $null }
        $child = $Node.SelectSingleNode("*[local-name()='$Name']")
        if ($child) { return $child.InnerText }
        return $null
    }

    function Get-XNodes {
        param($Node, [string]$Name)
        if (-not $Node) { return @() }
        return @($Node.SelectNodes("*[local-name()='$Name']"))
    }

    function Add-XSetting {
        # Generic flattener: any element with a name attribute or a <Name> child is a setting.
        param($Node, [string]$Scope, [string]$Extension, $Acc, [int]$Max, [int]$Depth = 0)
        if (-not $Node -or $Depth -gt 12) { return }

        foreach ($child in $Node.ChildNodes) {
            if ($child.NodeType -ne [System.Xml.XmlNodeType]::Element) { continue }
            if ($Max -gt 0 -and $Acc.Count -ge $Max) { return }

            $name = $null; $state = $null; $value = $null

            foreach ($attr in $child.Attributes) {
                switch ($attr.LocalName) {
                    'name'   { $name  = $attr.Value }
                    'status' { $state = $attr.Value }
                    'action' { $state = $attr.Value }
                }
            }
            foreach ($grand in $child.ChildNodes) {
                if ($grand.NodeType -ne [System.Xml.XmlNodeType]::Element) { continue }
                if     ($grand.LocalName -eq 'Name' -and -not $name -and $grand.InnerText.Trim()) { $name  = $grand.InnerText.Trim() }
                elseif ($grand.LocalName -eq 'State')                                             { $state = $grand.InnerText }
                elseif (-not $value -and $grand.LocalName -match '^(Setting[A-Za-z]*|Value|Number|Member)$') { $value = $grand.InnerText }
            }

            if ($name) {
                if ($value) {
                    $value = ($value -replace '\s+', ' ').Trim()
                    if ($value.Length -gt 200) { $value = $value.Substring(0, 200) + '...' }
                }
                [void]$Acc.Add([pscustomobject]@{
                    Scope = $Scope; Extension = $Extension; Category = $child.LocalName
                    Name  = $name;  State     = $state;     Value    = $value
                })
            }
            else {
                Add-XSetting -Node $child -Scope $Scope -Extension $Extension -Acc $Acc -Max $Max -Depth ($Depth + 1)
            }
        }
    }

    $links    = New-Object System.Collections.ArrayList
    $apply    = New-Object System.Collections.ArrayList
    $deny     = New-Object System.Collections.ArrayList
    $deleg    = New-Object System.Collections.ArrayList
    $settings = New-Object System.Collections.ArrayList
    $exts     = New-Object System.Collections.ArrayList
    $failure  = $null

    try {
        $xmlText = $null
        for ($attempt = 1; $attempt -le 3; $attempt++) {
            try   { $xmlText = Get-GPOReport -Guid $Id -ReportType Xml -Domain $Domain -ErrorAction Stop; break }
            catch { if ($attempt -eq 3) { throw }; Start-Sleep -Seconds $attempt }
        }
        $root = ([xml]$xmlText).DocumentElement

        foreach ($link in (Get-XNodes $root 'LinksTo')) {
            $somPath = Get-XText $link 'SOMPath'
            $type    = 'OU'
            if     ($somPath -eq $Domain)       { $type = 'Domain' }
            elseif ($somPath -notmatch '[\\/]') { $type = 'Site' }
            [void]$links.Add([pscustomobject]@{
                SomName  = Get-XText $link 'SOMName'
                SomPath  = $somPath
                SomType  = $type
                Enabled  = ((Get-XText $link 'Enabled')    -match '^(?i)true|1$')
                Enforced = ((Get-XText $link 'NoOverride') -match '^(?i)true|1$')
            })
        }

        $sd    = $root.SelectSingleNode("*[local-name()='SecurityDescriptor']")
        $perms = $sd.SelectSingleNode("*[local-name()='Permissions']")
        foreach ($perm in (Get-XNodes $perms 'TrusteePermissions')) {
            $trusteeNode = $perm.SelectSingleNode("*[local-name()='Trustee']")
            $trustee     = Get-XText $trusteeNode 'Name'
            if (-not $trustee) { $trustee = Get-XText $trusteeNode 'SID' }
            if (-not $trustee) { continue }

            $type   = Get-XText $perm.SelectSingleNode("*[local-name()='Type']")     'PermissionType'
            $access = Get-XText $perm.SelectSingleNode("*[local-name()='Standard']") 'GPOGroupedAccessEnum'
            $entry  = [pscustomobject]@{ Trustee = $trustee.Trim(); Permission = $access; Type = $type }

            if ($access -match '(?i)apply group policy') {
                if ($type -match '(?i)deny') { [void]$deny.Add($entry) } else { [void]$apply.Add($entry) }
            }
            else { [void]$deleg.Add($entry) }
        }

        if ($MaxSettings -ge 0) {
            foreach ($scope in @('Computer', 'User')) {
                $scopeNode = $root.SelectSingleNode("*[local-name()='$scope']")
                foreach ($extData in (Get-XNodes $scopeNode 'ExtensionData')) {
                    $extName = Get-XText $extData 'Name'
                    if (-not $extName) { $extName = 'Unknown extension' }
                    $before = $settings.Count
                    Add-XSetting -Node $extData.SelectSingleNode("*[local-name()='Extension']") `
                                 -Scope $scope -Extension $extName -Acc $settings -Max $MaxSettings
                    [void]$exts.Add([pscustomobject]@{ Scope = $scope; Extension = $extName; SettingCount = $settings.Count - $before })
                }
            }
        }
    }
    catch { $failure = $_.Exception.Message }

    [pscustomobject]@{
        Links             = $links.ToArray()
        SecurityFiltering = $apply.ToArray()
        DeniedFiltering   = $deny.ToArray()
        Delegation        = $deleg.ToArray()
        Extensions        = $exts.ToArray()
        Settings          = $settings.ToArray()
        Failure           = $failure
    }
}

function Export-GpoInventory {
    <#
    .SYNOPSIS
        Collects every GPO in the domain in parallel and writes one raw JSON file.
    .DESCRIPTION
        Four visible phases: enumerate, read properties, collect reports in parallel, serialise.
        Progress and a periodic status line are emitted throughout, and any GPO that exceeds
        -TimeoutSeconds is abandoned rather than hanging the run.
    .PARAMETER ThrottleLimit
        Concurrent runspaces. Get-GPOReport is latency-bound: 8-16 is the sweet spot.
    .PARAMETER MaxSettingsPerGpo
        Cap on flattened settings per GPO. 0 = unlimited (large JSON, slow to serialise),
        -1 = skip settings entirely (fastest).
    .PARAMETER StatusInterval
        Seconds between printed status lines. 0 turns them off.
    .EXAMPLE
        Export-GpoInventory -Path C:\Reports\gpo.json -ThrottleLimit 12
    .OUTPUTS
        System.String - the path of the JSON that was written.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$Domain         = 'ad.net',
        [ValidateRange(1, 64)][int]$ThrottleLimit  = 8,
        [int]$MaxSettingsPerGpo = 250,
        [ValidateRange(10, 3600)][int]$TimeoutSeconds = 180,
        [int]$StatusInterval    = 15,
        [string]$NameFilter     = '*'
    )

    $clock  = [System.Diagnostics.Stopwatch]::StartNew()
    $stamp  = { '[{0:hh\:mm\:ss}]' -f $clock.Elapsed }
    $say    = { param($Message, $Colour = 'Gray') Write-Host ("{0} {1}" -f (& $stamp), $Message) -ForegroundColor $Colour }

    & $say "Loading the GroupPolicy module..." 'Cyan'
    Import-Module GroupPolicy -ErrorAction Stop -Verbose:$false

    # --- phase 1: enumerate ----------------------------------------------
    & $say "Enumerating GPOs in $Domain (this one call can take a while, no progress is possible)..." 'Cyan'
    $gpos = @(Get-GPO -All -Domain $Domain -ErrorAction Stop |
              Where-Object { $_.DisplayName -like $NameFilter } | Sort-Object DisplayName)
    if ($gpos.Count -eq 0) { throw "No GPOs matched '$NameFilter' in domain '$Domain'." }
    & $say "$($gpos.Count) GPO(s) found." 'Green'

    # --- phase 2: metadata, single-threaded on purpose --------------------
    & $say "Reading GPO properties..." 'Cyan'
    $queue = New-Object System.Collections.ArrayList
    $index = 0
    foreach ($gpo in $gpos) {
        $index++
        Write-Progress -Id 1 -Activity 'Reading GPO properties' -Status ("{0}/{1} - {2}" -f $index, $gpos.Count, $gpo.DisplayName) `
                       -PercentComplete (($index / [double]$gpos.Count) * 100)

        $created = $null; $modified = $null; $owner = $null; $wmi = $null
        $computerVersion = 0; $userVersion = 0
        try {
            if ($gpo.CreationTime)     { $created  = $gpo.CreationTime.ToString('s') }
            if ($gpo.ModificationTime) { $modified = $gpo.ModificationTime.ToString('s') }
            $owner           = [string]$gpo.Owner
            $computerVersion = [int]$gpo.Computer.DSVersion
            $userVersion     = [int]$gpo.User.DSVersion
            if ($gpo.WmiFilter) { $wmi = [string]$gpo.WmiFilter.Name }
        }
        catch { }

        [void]$queue.Add([pscustomobject]@{
            Name = [string]$gpo.DisplayName; Id = [string]$gpo.Id; Domain = [string]$gpo.DomainName
            Owner = $owner; Description = [string]$gpo.Description; GpoStatus = [string]$gpo.GpoStatus
            CreationTime = $created; ModificationTime = $modified
            ComputerVersion = $computerVersion; UserVersion = $userVersion; WmiFilterName = $wmi
        })
    }
    Write-Progress -Id 1 -Activity 'Reading GPO properties' -Completed
    & $say "Properties read." 'Green'

    # --- phase 3: parallel reports ----------------------------------------
    & $say "Collecting reports on $ThrottleLimit runspace(s). Timeout per GPO: ${TimeoutSeconds}s." 'Cyan'
    $iss = [initialsessionstate]::CreateDefault()
    $iss.ImportPSModule('GroupPolicy')
    $pool = [runspacefactory]::CreateRunspacePool($iss)
    $pool.SetMinRunspaces(1)      | Out-Null
    $pool.SetMaxRunspaces($ThrottleLimit) | Out-Null
    $pool.ThreadOptions = 'ReuseThread'
    $pool.Open()

    $workerText = $script:GpoWorker.ToString()
    $records    = New-Object System.Collections.ArrayList
    $active     = New-Object System.Collections.ArrayList
    $total      = $queue.Count
    $submitted  = 0
    $done       = 0
    $failures   = 0
    $timeouts   = 0
    $lastStatus = $clock.Elapsed.TotalSeconds

    try {
        while ($done -lt $total) {

            # keep the pool fed
            while ($active.Count -lt $ThrottleLimit -and $submitted -lt $total) {
                $item  = $queue[$submitted]
                $shell = [powershell]::Create()
                $shell.RunspacePool = $pool
                [void]$shell.AddScript($workerText).AddArgument($item.Id).AddArgument($Domain).AddArgument($MaxSettingsPerGpo)
                [void]$active.Add([pscustomobject]@{
                    Item    = $item
                    Shell   = $shell
                    Handle  = $shell.BeginInvoke()
                    Started = $clock.Elapsed
                })
                $submitted++
            }

            # harvest finished and kill stuck ones
            for ($i = $active.Count - 1; $i -ge 0; $i--) {
                $job     = $active[$i]
                $running = ($clock.Elapsed - $job.Started).TotalSeconds
                $result  = $null
                $problem = $null

                if ($job.Handle.IsCompleted) {
                    try     { $result = @($job.Shell.EndInvoke($job.Handle))[0] }
                    catch   { $problem = $_.Exception.Message }
                    if (-not $result -and -not $problem) { $problem = 'worker returned nothing' }
                }
                elseif ($running -gt $TimeoutSeconds) {
                    $problem  = "timed out after $([int]$running)s"
                    $timeouts++
                    try { $job.Shell.Stop() } catch { }
                }
                else { continue }

                if ($problem) { $failures++ }
                if ($result -and $result.Failure) { $problem = $result.Failure; $failures++ }

                $item = $job.Item
                [void]$records.Add([pscustomobject]@{
                    Name              = $item.Name
                    Id                = $item.Id
                    Domain            = $item.Domain
                    Owner             = $item.Owner
                    Description       = $item.Description
                    GpoStatus         = $item.GpoStatus
                    CreationTime      = $item.CreationTime
                    ModificationTime  = $item.ModificationTime
                    ComputerVersion   = $item.ComputerVersion
                    UserVersion       = $item.UserVersion
                    WmiFilterName     = $item.WmiFilterName
                    LinkCount         = $(if ($result) { @($result.Links).Count } else { 0 })
                    IsLinked          = $(if ($result) { @($result.Links).Count -gt 0 } else { $false })
                    Links             = $(if ($result) { @($result.Links) } else { @() })
                    SecurityFiltering = $(if ($result) { @($result.SecurityFiltering) } else { @() })
                    DeniedFiltering   = $(if ($result) { @($result.DeniedFiltering) } else { @() })
                    Delegation        = $(if ($result) { @($result.Delegation) } else { @() })
                    Extensions        = $(if ($result) { @($result.Extensions) } else { @() })
                    Settings          = $(if ($result) { @($result.Settings) } else { @() })
                    SettingCount      = $(if ($result) { @($result.Settings).Count } else { 0 })
                    IsEmpty           = (($item.ComputerVersion -eq 0) -and ($item.UserVersion -eq 0))
                    DurationSeconds   = [Math]::Round($running, 2)
                    HasError          = [bool]$problem
                    Error             = $problem
                })

                try { $job.Shell.Dispose() } catch { }
                $active.RemoveAt($i)
                $done++
            }

            # --- feedback, every single tick ---------------------------------
            $elapsed = $clock.Elapsed
            $eta     = 'calculating'
            if ($done -ge 3) {
                $eta = '{0:hh\:mm\:ss}' -f [timespan]::FromSeconds(($elapsed.TotalSeconds / $done) * ($total - $done))
            }
            $slowest = $active | Sort-Object Started | Select-Object -First 1
            $current = 'idle'
            if ($slowest) {
                $current = '{0} ({1}s)' -f $slowest.Item.Name, [int]($elapsed - $slowest.Started).TotalSeconds
            }

            Write-Progress -Id 1 -Activity "Collecting GPO reports from $Domain" `
                           -Status ("{0}/{1} done | {2} running | {3} queued | {4:hh\:mm\:ss} elapsed | ETA {5} | oldest: {6}" -f `
                                    $done, $total, $active.Count, ($total - $submitted), $elapsed, $eta, $current) `
                           -PercentComplete (($done / [double]$total) * 100)

            if ($StatusInterval -gt 0 -and ($elapsed.TotalSeconds - $lastStatus) -ge $StatusInterval) {
                $lastStatus = $elapsed.TotalSeconds
                & $say ("{0}/{1} done, {2} running, {3} failed - ETA {4} - oldest in flight: {5}" -f `
                        $done, $total, $active.Count, $failures, $eta, $current)
            }

            if ($active.Count -gt 0 -or $submitted -lt $total) { Start-Sleep -Milliseconds 200 }
        }
    }
    finally {
        foreach ($job in $active) { try { $job.Shell.Stop(); $job.Shell.Dispose() } catch { } }
        $pool.Close(); $pool.Dispose()
        Write-Progress -Id 1 -Activity 'Collecting GPO reports' -Completed
    }

    $collectSeconds = $clock.Elapsed.TotalSeconds
    & $say "All $total GPO(s) collected ($failures failed, $timeouts timed out)." 'Green'

    # --- phase 4: serialise -----------------------------------------------
    $settingTotal = ($records | Measure-Object -Property SettingCount -Sum).Sum
    & $say "Serialising $total record(s) / $settingTotal setting(s) to JSON - the slow part, no progress possible..." 'Cyan'

    $report = [pscustomobject]@{
        Metadata = [pscustomobject]@{
            Domain          = $Domain
            GeneratedOn     = (Get-Date).ToString('s')
            GeneratedBy     = "$env:USERDOMAIN\$env:USERNAME"
            ComputerName    = $env:COMPUTERNAME
            DurationSeconds = [Math]::Round($clock.Elapsed.TotalSeconds, 1)
            ThrottleLimit   = $ThrottleLimit
            GpoCount        = $records.Count
            ErrorCount      = $failures
            SettingCount    = $settingTotal
        }
        Gpos = @($records | Sort-Object Name)
    }

    $folder = Split-Path -Parent $Path
    if ($folder -and -not (Test-Path -LiteralPath $folder)) { New-Item -ItemType Directory -Path $folder -Force | Out-Null }
    [System.IO.File]::WriteAllText($Path, ($report | ConvertTo-Json -Depth 12), (New-Object System.Text.UTF8Encoding($false)))

    $sizeMb  = (Get-Item -LiteralPath $Path).Length / 1MB
    $slowest = $records | Sort-Object DurationSeconds -Descending | Select-Object -First 3

    Write-Host ''
    & $say "Done. $($records.Count) GPO(s) in $([Math]::Round($clock.Elapsed.TotalSeconds,1))s" 'Green'
    Write-Host ("  collection {0:n1}s ({1:n2}s per GPO on {2} workers), JSON {3:n1} MB" -f `
                $collectSeconds, ($collectSeconds / $records.Count), $ThrottleLimit, $sizeMb)
    Write-Host ("  slowest: {0}" -f (($slowest | ForEach-Object { '{0} ({1}s)' -f $_.Name, $_.DurationSeconds }) -join ', '))
    if ($failures) { Write-Warning ("$failures GPO(s) failed - filter the JSON on HasError, or check the HTML error table.") }
    Write-Host ("  -> $Path") -ForegroundColor Cyan
    Write-Host ''

    return $Path
}

function ConvertTo-GpoCsv {
    <#
    .SYNOPSIS
        Flattens the raw JSON into CSV. Offline - no domain access needed.
    .PARAMETER Scope
        PerLink (default, one row per link), PerGpo (one row per GPO), Settings (one row per setting).
    .EXAMPLE
        $json | ConvertTo-GpoCsv -Scope Settings
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('FullName')][string]$Path,
        [string]$Destination,
        [ValidateSet('PerLink', 'PerGpo', 'Settings')][string]$Scope = 'PerLink',
        [string]$Delimiter = ','
    )
    process {
        if (-not (Test-Path -LiteralPath $Path)) { throw "JSON not found: $Path" }
        Write-Host ("Parsing {0:n1} MB of JSON (ConvertFrom-Json is slow on big files, please wait)..." -f ((Get-Item -LiteralPath $Path).Length / 1MB)) -ForegroundColor Cyan
        $report = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
        if (-not $Destination) { $Destination = [System.IO.Path]::ChangeExtension($Path, $null) + "_$Scope.csv" }

        $rows = foreach ($gpo in @($report.Gpos)) {
            $applyText = (@($gpo.SecurityFiltering) | ForEach-Object { $_.Trustee }) -join '; '
            $denyText  = (@($gpo.DeniedFiltering)   | ForEach-Object { $_.Trustee }) -join '; '

            switch ($Scope) {
                'PerGpo' {
                    [pscustomobject]@{
                        Name = $gpo.Name; Id = $gpo.Id; GpoStatus = $gpo.GpoStatus
                        LinkCount = $gpo.LinkCount
                        Links     = (@($gpo.Links) | ForEach-Object { $_.SomPath }) -join '; '
                        Enforced  = (@($gpo.Links | Where-Object { $_.Enforced }) | ForEach-Object { $_.SomPath }) -join '; '
                        SecurityFiltering = $applyText; DeniedFiltering = $denyText
                        WmiFilter = $gpo.WmiFilterName; SettingCount = $gpo.SettingCount
                        Extensions = (@($gpo.Extensions) | ForEach-Object { '{0}:{1}' -f $_.Scope, $_.Extension }) -join '; '
                        IsEmpty = $gpo.IsEmpty; Owner = $gpo.Owner
                        CreationTime = $gpo.CreationTime; ModificationTime = $gpo.ModificationTime
                        DurationSeconds = $gpo.DurationSeconds; HasError = $gpo.HasError; Error = $gpo.Error
                    }
                }
                'Settings' {
                    foreach ($setting in @($gpo.Settings)) {
                        [pscustomobject]@{
                            Gpo = $gpo.Name; Id = $gpo.Id; Scope = $setting.Scope
                            Extension = $setting.Extension; Category = $setting.Category
                            Setting = $setting.Name; State = $setting.State; Value = $setting.Value
                        }
                    }
                }
                default {
                    $links = @($gpo.Links)
                    if ($links.Count -eq 0) { $links = @([pscustomobject]@{ SomName = '(not linked)'; SomPath = ''; SomType = ''; Enabled = $false; Enforced = $false }) }
                    foreach ($link in $links) {
                        [pscustomobject]@{
                            Name = $gpo.Name; Id = $gpo.Id; GpoStatus = $gpo.GpoStatus
                            LinkTarget = $link.SomName; LinkPath = $link.SomPath; LinkType = $link.SomType
                            LinkEnabled = $link.Enabled; LinkEnforced = $link.Enforced
                            SecurityFiltering = $applyText; DeniedFiltering = $denyText
                            WmiFilter = $gpo.WmiFilterName; SettingCount = $gpo.SettingCount
                            IsEmpty = $gpo.IsEmpty; Owner = $gpo.Owner
                            CreationTime = $gpo.CreationTime; ModificationTime = $gpo.ModificationTime
                            HasError = $gpo.HasError; Error = $gpo.Error
                        }
                    }
                }
            }
        }

        $rows | Export-Csv -LiteralPath $Destination -NoTypeInformation -Encoding UTF8 -Delimiter $Delimiter
        Write-Host "$(@($rows).Count) row(s) -> $Destination" -ForegroundColor Green
        return $Destination
    }
}

function ConvertTo-GpoHtml {
    <#
    .SYNOPSIS
        Renders the raw JSON as one self-contained HTML file. Offline - no domain access needed.
    .EXAMPLE
        $json | ConvertTo-GpoHtml -MaxSettingsShown 50
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('FullName')][string]$Path,
        [string]$Destination,
        [int]$MaxSettingsShown = 100,
        [switch]$NoSettings
    )
    process {
        if (-not (Test-Path -LiteralPath $Path)) { throw "JSON not found: $Path" }
        Write-Host ("Parsing {0:n1} MB of JSON (ConvertFrom-Json is slow on big files, please wait)..." -f ((Get-Item -LiteralPath $Path).Length / 1MB)) -ForegroundColor Cyan
        $report = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
        if (-not $Destination) { $Destination = [System.IO.Path]::ChangeExtension($Path, 'html') }

        $esc  = { param($t) if ($null -eq $t) { '' } else { ([string]$t) -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;' } }
        $meta = $report.Metadata
        $gpos = @($report.Gpos)

        $css = @'
<style>
 :root{--bg:#f6f7f9;--card:#fff;--line:#e2e5ea;--ink:#1d2430;--mut:#6b7482;--warn:#c47f00;--bad:#c0392b;--ok:#1e8449}
 *{box-sizing:border-box}
 body{margin:0;padding:24px;background:var(--bg);color:var(--ink);font:14px/1.5 "Segoe UI",system-ui,sans-serif}
 h1{margin:0 0 4px;font-size:22px} h2{font-size:16px;margin:28px 0 10px}
 .sub{color:var(--mut);font-size:12px;margin-bottom:18px}
 .tiles{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:22px}
 .tile{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 16px;min-width:118px}
 .tile b{display:block;font-size:22px;line-height:1.2}
 .tile span{color:var(--mut);font-size:11px;text-transform:uppercase;letter-spacing:.04em}
 input#q{width:340px;max-width:100%;padding:8px 10px;border:1px solid var(--line);border-radius:8px;margin-bottom:12px}
 table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden}
 th,td{padding:7px 10px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top;font-size:13px}
 th{background:#eef1f5;cursor:pointer;user-select:none;white-space:nowrap;position:sticky;top:0}
 tr:hover td{background:#f9fbff}
 .pill{display:inline-block;padding:1px 7px;border-radius:999px;font-size:11px;border:1px solid var(--line)}
 .bad{color:var(--bad);font-weight:600} .warn{color:var(--warn)} .ok{color:var(--ok)} .mut{color:var(--mut)}
 details{background:var(--card);border:1px solid var(--line);border-radius:10px;margin:8px 0;padding:10px 14px}
 summary{cursor:pointer;font-weight:600}
 .small{font-size:12px;color:var(--mut)}
</style>
'@
        $js = @'
<script>
function filterRows(){var q=document.getElementById("q").value.toLowerCase(),r=document.querySelectorAll("#main tbody tr");
 for(var i=0;i<r.length;i++){r[i].style.display=r[i].innerText.toLowerCase().indexOf(q)>-1?"":"none";}}
function sortTable(n){var t=document.getElementById("main"),rows=Array.prototype.slice.call(t.tBodies[0].rows);
 var d=t.getAttribute("data-dir")==="asc"?-1:1;t.setAttribute("data-dir",d===1?"asc":"desc");
 rows.sort(function(a,b){var x=a.cells[n].innerText.trim(),y=b.cells[n].innerText.trim();
 var nx=parseFloat(x),ny=parseFloat(y);if(!isNaN(nx)&&!isNaN(ny)){return (nx-ny)*d;}return x.localeCompare(y)*d;});
 for(var i=0;i<rows.length;i++){t.tBodies[0].appendChild(rows[i]);}}
</script>
'@

        $sb = New-Object System.Text.StringBuilder
        [void]$sb.AppendLine('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">')
        [void]$sb.AppendLine(('<title>GPO report - {0}</title>' -f (& $esc $meta.Domain)))
        [void]$sb.AppendLine($css + '</head><body>')
        [void]$sb.AppendLine(('<h1>Group Policy report - {0}</h1>' -f (& $esc $meta.Domain)))
        [void]$sb.AppendLine(('<div class="sub">{0} &middot; {1} on {2} &middot; {3}s with {4} workers</div>' -f `
            (& $esc $meta.GeneratedOn), (& $esc $meta.GeneratedBy), (& $esc $meta.ComputerName), $meta.DurationSeconds, $meta.ThrottleLimit))

        [void]$sb.AppendLine('<div class="tiles">')
        foreach ($tile in @(
            @{ L = 'GPOs';           V = $gpos.Count },
            @{ L = 'Unlinked';       V = @($gpos | Where-Object { -not $_.IsLinked }).Count },
            @{ L = 'Empty';          V = @($gpos | Where-Object { $_.IsEmpty }).Count },
            @{ L = 'Fully disabled'; V = @($gpos | Where-Object { $_.GpoStatus -eq 'AllSettingsDisabled' }).Count },
            @{ L = 'WMI filtered';   V = @($gpos | Where-Object { $_.WmiFilterName }).Count },
            @{ L = 'Errors';         V = @($gpos | Where-Object { $_.HasError }).Count })) {
            [void]$sb.AppendLine(('<div class="tile"><b>{0}</b><span>{1}</span></div>' -f $tile.V, $tile.L))
        }
        [void]$sb.AppendLine('</div>')

        [void]$sb.AppendLine('<h2>Overview</h2><input id="q" onkeyup="filterRows()" placeholder="Filter: GPO, OU, group, WMI filter...">')
        [void]$sb.AppendLine('<table id="main"><thead><tr>')
        $headers = @('GPO', 'Status', 'Links', 'Security filtering', 'WMI filter', 'Settings', 'Created', 'Modified')
        for ($h = 0; $h -lt $headers.Count; $h++) { [void]$sb.AppendLine(('<th onclick="sortTable({0})">{1}</th>' -f $h, $headers[$h])) }
        [void]$sb.AppendLine('</tr></thead><tbody>')

        $row = 0
        foreach ($gpo in $gpos) {
            $row++
            if (($row % 20) -eq 0) {
                Write-Progress -Id 2 -Activity 'Rendering HTML' -Status ("{0}/{1}" -f $row, $gpos.Count) -PercentComplete (($row / [double]$gpos.Count) * 100)
            }
            $linkText = '<span class="bad">not linked</span>'
            if (@($gpo.Links).Count) {
                $linkText = (@($gpo.Links) | ForEach-Object {
                    $flags = @()
                    if ($_.Enforced)     { $flags += 'enforced' }
                    if (-not $_.Enabled) { $flags += 'link disabled' }
                    $suffix = ''
                    if ($flags.Count) { $suffix = ' <span class="pill warn">' + ($flags -join ', ') + '</span>' }
                    (& $esc $_.SomPath) + $suffix
                }) -join '<br>'
            }

            $applyText = '<span class="warn">none</span>'
            if (@($gpo.SecurityFiltering).Count) { $applyText = (@($gpo.SecurityFiltering) | ForEach-Object { & $esc $_.Trustee }) -join '<br>' }
            if (@($gpo.DeniedFiltering).Count)   { $applyText += '<br><span class="bad">deny: ' + ((@($gpo.DeniedFiltering) | ForEach-Object { & $esc $_.Trustee }) -join ', ') + '</span>' }

            $nameCell = & $esc $gpo.Name
            if ($gpo.HasError) { $nameCell += ' <span class="pill bad">error</span>' }
            if ($gpo.IsEmpty)  { $nameCell += ' <span class="pill warn">empty</span>' }
            $statusClass = 'warn'
            if ($gpo.GpoStatus -eq 'AllSettingsEnabled') { $statusClass = 'ok' }

            [void]$sb.AppendLine(('<tr><td>{0}<div class="small">{1}</div></td><td class="{2}">{3}</td><td>{4}</td><td>{5}</td><td>{6}</td><td>{7}</td><td>{8}</td><td>{9}</td></tr>' -f `
                $nameCell, (& $esc $gpo.Id), $statusClass, (& $esc $gpo.GpoStatus), $linkText, $applyText,
                (& $esc $gpo.WmiFilterName), $gpo.SettingCount, (& $esc $gpo.CreationTime), (& $esc $gpo.ModificationTime)))
        }
        [void]$sb.AppendLine('</tbody></table>')

        if (-not $NoSettings) {
            [void]$sb.AppendLine('<h2>Settings detail</h2>')
            foreach ($gpo in $gpos) {
                $settings = @($gpo.Settings)
                if ($settings.Count -eq 0) { continue }
                [void]$sb.AppendLine(('<details><summary>{0} <span class="small">({1} setting(s))</span></summary>' -f (& $esc $gpo.Name), $settings.Count))
                [void]$sb.AppendLine('<table><thead><tr><th>Scope</th><th>Extension</th><th>Category</th><th>Setting</th><th>State</th><th>Value</th></tr></thead><tbody>')
                $shown = 0
                foreach ($setting in $settings) {
                    if ($MaxSettingsShown -gt 0 -and $shown -ge $MaxSettingsShown) { break }
                    $shown++
                    [void]$sb.AppendLine(('<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td></tr>' -f `
                        (& $esc $setting.Scope), (& $esc $setting.Extension), (& $esc $setting.Category),
                        (& $esc $setting.Name), (& $esc $setting.State), (& $esc $setting.Value)))
                }
                if ($settings.Count -gt $shown) { [void]$sb.AppendLine(('<tr><td colspan="6" class="mut">... {0} more in the JSON</td></tr>' -f ($settings.Count - $shown))) }
                [void]$sb.AppendLine('</tbody></table></details>')
            }
        }

        $failed = @($gpos | Where-Object { $_.HasError })
        if ($failed.Count) {
            [void]$sb.AppendLine('<h2>Collection errors</h2><table><thead><tr><th>GPO</th><th>Message</th></tr></thead><tbody>')
            foreach ($gpo in $failed) {
                [void]$sb.AppendLine(('<tr><td>{0}</td><td class="bad">{1}</td></tr>' -f (& $esc $gpo.Name), (& $esc $gpo.Error)))
            }
            [void]$sb.AppendLine('</tbody></table>')
        }

        Write-Progress -Id 2 -Activity 'Rendering HTML' -Completed
        [void]$sb.AppendLine($js + '</body></html>')
        [System.IO.File]::WriteAllText($Destination, $sb.ToString(), (New-Object System.Text.UTF8Encoding($false)))
        Write-Host "HTML -> $Destination" -ForegroundColor Green
        return $Destination
    }
}
