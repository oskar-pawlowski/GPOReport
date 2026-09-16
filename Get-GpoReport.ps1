#Requires -Version 5.1
<#
    GPO reporting toolkit - a library, not a script. Dot-source it, then call the functions.

        . .\Get-GpoReport.ps1

        $json = Export-GpoInventory -Domain ad.net -Path C:\Reports\gpo.json -ThrottleLimit 8
        $json | ConvertTo-GpoCsv
        $json | ConvertTo-GpoHtml

    Export-GpoInventory   collects every GPO in parallel -> raw JSON
    ConvertTo-GpoCsv      raw JSON -> flat CSV           (offline)
    ConvertTo-GpoHtml     raw JSON -> standalone HTML    (offline)

    Requires the GroupPolicy module (RSAT GPMC) and read access to the GPOs.
#>

# ---------------------------------------------------------------------------
# Runspace worker: everything that touches one GPO. Self-contained on purpose -
# it is executed inside a runspace that shares nothing with this session.
# ---------------------------------------------------------------------------
$script:GpoWorker = {
    param([object]$Gpo, [string]$Domain, [int]$MaxSettings)

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
        # Generic flattener: any element carrying a name attribute or a <Name> child is a setting.
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

    $errors   = New-Object System.Collections.ArrayList
    $links    = New-Object System.Collections.ArrayList
    $apply    = New-Object System.Collections.ArrayList
    $deny     = New-Object System.Collections.ArrayList
    $deleg    = New-Object System.Collections.ArrayList
    $settings = New-Object System.Collections.ArrayList
    $exts     = New-Object System.Collections.ArrayList

    try {
        # Get-GPOReport is the expensive call - retry it, transient DC/SYSVOL failures are common.
        $xmlText = $null
        for ($attempt = 1; $attempt -le 3; $attempt++) {
            try   { $xmlText = Get-GPOReport -Guid $Gpo.Id -ReportType Xml -Domain $Domain -ErrorAction Stop; break }
            catch { if ($attempt -eq 3) { throw }; Start-Sleep -Seconds $attempt }
        }
        $root = ([xml]$xmlText).DocumentElement

        # --- links -------------------------------------------------------
        foreach ($link in (Get-XNodes $root 'LinksTo')) {
            $somPath = Get-XText $link 'SOMPath'
            $type    = 'OU'
            if     ($somPath -eq $Domain)        { $type = 'Domain' }
            elseif ($somPath -notmatch '[\\/]')  { $type = 'Site' }
            [void]$links.Add([pscustomobject]@{
                SomName  = Get-XText $link 'SOMName'
                SomPath  = $somPath
                SomType  = $type
                Enabled  = ((Get-XText $link 'Enabled')    -match '^(?i)true|1$')
                Enforced = ((Get-XText $link 'NoOverride') -match '^(?i)true|1$')
            })
        }

        # --- filtering / delegation --------------------------------------
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

        # --- settings -----------------------------------------------------
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
    catch { [void]$errors.Add($_.Exception.Message) }

    $created  = $null; $modified = $null
    if ($Gpo.CreationTime)     { $created  = $Gpo.CreationTime.ToString('s') }
    if ($Gpo.ModificationTime) { $modified = $Gpo.ModificationTime.ToString('s') }

    $computerVersion = 0; $userVersion = 0
    try { $computerVersion = [int]$Gpo.Computer.DSVersion } catch { }
    try { $userVersion     = [int]$Gpo.User.DSVersion }     catch { }

    [pscustomobject]@{
        Name              = [string]$Gpo.DisplayName
        Id                = [string]$Gpo.Id
        Domain            = [string]$Gpo.DomainName
        Owner             = [string]$Gpo.Owner
        Description       = [string]$Gpo.Description
        GpoStatus         = [string]$Gpo.GpoStatus
        CreationTime      = $created
        ModificationTime  = $modified
        ComputerVersion   = $computerVersion
        UserVersion       = $userVersion
        WmiFilterName     = $(if ($Gpo.WmiFilter) { [string]$Gpo.WmiFilter.Name } else { $null })
        LinkCount         = $links.Count
        IsLinked          = ($links.Count -gt 0)
        Links             = $links.ToArray()
        SecurityFiltering = $apply.ToArray()
        DeniedFiltering   = $deny.ToArray()
        Delegation        = $deleg.ToArray()
        Extensions        = $exts.ToArray()
        Settings          = $settings.ToArray()
        SettingCount      = $settings.Count
        IsEmpty           = (($computerVersion -eq 0) -and ($userVersion -eq 0))
        HasError          = ($errors.Count -gt 0)
        Errors            = $errors.ToArray()
    }
}

function Export-GpoInventory {
    <#
    .SYNOPSIS
        Collects every GPO in the domain in parallel and writes one raw JSON file.
    .PARAMETER ThrottleLimit
        Concurrent runspaces. Get-GPOReport is latency-bound, so 8-16 is the sweet spot.
    .PARAMETER MaxSettingsPerGpo
        Cap on flattened settings per GPO (0 = unlimited, -1 = skip settings entirely).
    .EXAMPLE
        Export-GpoInventory -Domain ad.net -Path C:\Reports\gpo.json -ThrottleLimit 12 -Verbose
    .OUTPUTS
        System.String - the path of the JSON that was written.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$Domain            = 'ad.net',
        [ValidateRange(1, 64)][int]$ThrottleLimit = 8,
        [int]$MaxSettingsPerGpo    = 0,
        [string]$NameFilter        = '*'
    )

    $started = Get-Date
    Import-Module GroupPolicy -ErrorAction Stop -Verbose:$false

    Write-Verbose "Enumerating GPOs in $Domain ..."
    $gpos = @(Get-GPO -All -Domain $Domain -ErrorAction Stop |
              Where-Object { $_.DisplayName -like $NameFilter } | Sort-Object DisplayName)
    if ($gpos.Count -eq 0) { throw "No GPOs matched '$NameFilter' in domain '$Domain'." }
    Write-Verbose "$($gpos.Count) GPO(s) to process on $ThrottleLimit runspace(s)."

    $iss = [initialsessionstate]::CreateDefault()
    $iss.ImportPSModule('GroupPolicy')
    $pool = [runspacefactory]::CreateRunspacePool(1, $ThrottleLimit, $iss, $Host)
    $pool.Open()

    $jobs    = New-Object System.Collections.ArrayList
    $records = New-Object System.Collections.ArrayList

    try {
        foreach ($gpo in $gpos) {
            $shell = [powershell]::Create()
            $shell.RunspacePool = $pool
            [void]$shell.AddScript($script:GpoWorker.ToString()).AddArgument($gpo).AddArgument($Domain).AddArgument($MaxSettingsPerGpo)
            [void]$jobs.Add([pscustomobject]@{
                Name   = $gpo.DisplayName
                Id     = [string]$gpo.Id
                Shell  = $shell
                Handle = $shell.BeginInvoke()
                Done   = $false
            })
        }

        $done = 0
        while ($done -lt $jobs.Count) {
            foreach ($job in $jobs) {
                if ($job.Done -or -not $job.Handle.IsCompleted) { continue }

                try {
                    $record = @($job.Shell.EndInvoke($job.Handle))[0]
                    if (-not $record) { throw 'worker returned nothing' }
                }
                catch {
                    $record = [pscustomobject]@{
                        Name = $job.Name; Id = $job.Id; HasError = $true
                        Errors = @($_.Exception.Message); Links = @(); SecurityFiltering = @()
                        DeniedFiltering = @(); Delegation = @(); Extensions = @(); Settings = @()
                        SettingCount = 0; LinkCount = 0; IsLinked = $false; IsEmpty = $false
                    }
                }
                finally { $job.Shell.Dispose(); $job.Done = $true }

                [void]$records.Add($record)
                $done++

                $elapsed = (Get-Date) - $started
                $eta     = 'n/a'
                if ($done -gt 2) { $eta = '{0:mm\:ss}' -f [timespan]::FromSeconds(($elapsed.TotalSeconds / $done) * ($jobs.Count - $done)) }
                Write-Progress -Activity "Collecting GPOs from $Domain ($ThrottleLimit workers)" `
                               -Status ("{0}/{1} done - {2:mm\:ss} elapsed - ETA {3} - {4}" -f $done, $jobs.Count, $elapsed, $eta, $job.Name) `
                               -PercentComplete (($done / [double]$jobs.Count) * 100)
            }
            if ($done -lt $jobs.Count) { Start-Sleep -Milliseconds 150 }
        }
    }
    finally {
        foreach ($job in $jobs) { try { $job.Shell.Dispose() } catch { } }
        $pool.Close(); $pool.Dispose()
        Write-Progress -Activity 'Collecting GPOs' -Completed
    }

    $duration = (Get-Date) - $started
    $failed   = @($records | Where-Object { $_.HasError })

    $report = [pscustomobject]@{
        Metadata = [pscustomobject]@{
            Domain          = $Domain
            GeneratedOn     = (Get-Date).ToString('s')
            GeneratedBy     = "$env:USERDOMAIN\$env:USERNAME"
            ComputerName    = $env:COMPUTERNAME
            DurationSeconds = [Math]::Round($duration.TotalSeconds, 1)
            ThrottleLimit   = $ThrottleLimit
            GpoCount        = $records.Count
            ErrorCount      = $failed.Count
        }
        Gpos = @($records | Sort-Object Name)
    }

    $folder = Split-Path -Parent $Path
    if ($folder -and -not (Test-Path -LiteralPath $folder)) { New-Item -ItemType Directory -Path $folder -Force | Out-Null }
    [System.IO.File]::WriteAllText($Path, ($report | ConvertTo-Json -Depth 12), (New-Object System.Text.UTF8Encoding($false)))

    Write-Host ("{0} GPO(s) in {1:n1}s ({2:n2}s each, {3} workers), {4} error(s) -> {5}" -f `
        $records.Count, $duration.TotalSeconds, ($duration.TotalSeconds / $records.Count), $ThrottleLimit, $failed.Count, $Path) -ForegroundColor Cyan
    if ($failed.Count) { Write-Warning ("Failed: " + (($failed | Select-Object -First 5 -ExpandProperty Name) -join ', ')) }

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
                        HasError = $gpo.HasError
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
                            HasError = $gpo.HasError
                        }
                    }
                }
            }
        }

        $rows | Export-Csv -LiteralPath $Destination -NoTypeInformation -Encoding UTF8 -Delimiter $Delimiter
        Write-Verbose "$(@($rows).Count) row(s) -> $Destination"
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

        foreach ($gpo in $gpos) {
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
                [void]$sb.AppendLine(('<tr><td>{0}</td><td class="bad">{1}</td></tr>' -f (& $esc $gpo.Name), (& $esc (@($gpo.Errors) -join ' | '))))
            }
            [void]$sb.AppendLine('</tbody></table>')
        }

        [void]$sb.AppendLine($js + '</body></html>')
        [System.IO.File]::WriteAllText($Destination, $sb.ToString(), (New-Object System.Text.UTF8Encoding($false)))
        Write-Verbose "HTML -> $Destination"
        return $Destination
    }
}
