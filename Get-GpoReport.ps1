#Requires -Version 5.1
<#
.SYNOPSIS
    Collects a full Group Policy inventory for a single AD domain into JSON,
    and converts that JSON into CSV and HTML reports.

.DESCRIPTION
    Stage 1  Get-GpoInventory   -> GpoReport.json   (canonical data, batched + resumable)
    Stage 2  ConvertTo-GpoCsv   -> GpoReport.csv    (flat table, offline)
    Stage 3  ConvertTo-GpoHtml  -> GpoReport.html   (styled, self-contained, offline)

    Per GPO it records: identity, owner, status, creation/modification dates,
    AD/SYSVOL versions, WMI filter, every link (path, enabled, enforced),
    security filtering (Apply / Deny), delegation, and a flattened settings list.

    Built for ~500 GPOs: batch checkpoints, per-GPO try/catch, retries,
    nested progress bars and a written error log.

.EXAMPLE
    .\Get-GpoReport.ps1 -Domain ad.net -OutputFolder C:\Reports\GPO

.EXAMPLE
    .\Get-GpoReport.ps1 -Resume          # continue an interrupted run

.EXAMPLE
    . .\Get-GpoReport.ps1                # dot-source, then call functions manually
    ConvertTo-GpoHtml -JsonPath C:\Reports\GPO\GpoReport.json

.NOTES
    Version: 1.0
    Requires: RSAT GroupPolicy module, read rights on all GPOs.
#>

[CmdletBinding()]
param(
    [string]$Domain            = 'ad.net',
    [string]$OutputFolder      = (Join-Path $env:USERPROFILE 'Documents\GpoReport'),
    [int]   $BatchSize         = 25,
    [int]   $MaxSettingsPerGpo = 400,
    [switch]$Resume,
    [switch]$IncludeRawXml,
    [switch]$SkipSettings
)

$ErrorActionPreference = 'Stop'
$script:GpoToolVersion = '1.0'
$script:GpoLogFile     = $null

#region ---------------------------------------------------------- helpers

function Write-GpoLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO','WARN','ERROR','OK')][string]$Level = 'INFO'
    )
    $stamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $line  = '{0} [{1,-5}] {2}' -f $stamp, $Level, $Message

    switch ($Level) {
        'ERROR' { Write-Host $line -ForegroundColor Red }
        'WARN'  { Write-Host $line -ForegroundColor Yellow }
        'OK'    { Write-Host $line -ForegroundColor Green }
        default { Write-Host $line -ForegroundColor Gray }
    }

    if ($script:GpoLogFile) {
        try { Add-Content -LiteralPath $script:GpoLogFile -Value $line -Encoding UTF8 } catch { }
    }
}

function Invoke-GpoRetry {
    <# Runs a scriptblock with linear back-off. Rethrows the last error. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][scriptblock]$Script,
        [int]$Retries      = 3,
        [int]$DelaySeconds = 2,
        [string]$Activity  = 'operation'
    )
    for ($attempt = 1; $attempt -le $Retries; $attempt++) {
        try {
            return & $Script
        }
        catch {
            if ($attempt -ge $Retries) { throw }
            Write-GpoLog -Level WARN -Message ("Retry {0}/{1} for {2}: {3}" -f $attempt, $Retries, $Activity, $_.Exception.Message)
            Start-Sleep -Seconds ($DelaySeconds * $attempt)
        }
    }
}

function Test-GpoPrerequisite {
    [CmdletBinding()]
    param([string]$Domain)

    if (-not (Get-Module -ListAvailable -Name GroupPolicy)) {
        throw "GroupPolicy module not found. Install RSAT: Add-WindowsCapability -Online -Name Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0"
    }
    Import-Module GroupPolicy -ErrorAction Stop -Verbose:$false | Out-Null

    try   { $null = Get-GPO -All -Domain $Domain -ErrorAction Stop | Select-Object -First 1 }
    catch { throw "Cannot query GPOs in '$Domain'. Check domain name, connectivity and permissions. $($_.Exception.Message)" }

    Write-GpoLog -Level OK -Message "Prerequisites OK (GroupPolicy module, domain '$Domain' reachable)."
}

function ConvertTo-GpoBool {
    param($Value)
    if ($null -eq $Value) { return $false }
    return ([string]$Value) -match '^(?i)\s*(true|1|yes|enabled)\s*$'
}

function Get-XmlChildText {
    <# Namespace-safe child element text. Avoids the XmlElement.Name collision. #>
    param([System.Xml.XmlNode]$Node, [string]$LocalName)
    if ($null -eq $Node) { return $null }
    $child = $Node.SelectSingleNode("*[local-name()='$LocalName']")
    if ($null -eq $child) { return $null }
    return $child.InnerText
}

function Get-XmlChildNode {
    param([System.Xml.XmlNode]$Node, [string]$LocalName)
    if ($null -eq $Node) { return @() }
    return @($Node.SelectNodes("*[local-name()='$LocalName']"))
}

function Get-GpoNodeName {
    param([System.Xml.XmlNode]$Node)
    if ($Node.Attributes) {
        foreach ($attr in $Node.Attributes) {
            if ($attr.LocalName -eq 'name' -and $attr.Value) { return $attr.Value }
        }
    }
    foreach ($child in $Node.ChildNodes) {
        if ($child.NodeType -eq [System.Xml.XmlNodeType]::Element -and $child.LocalName -eq 'Name') {
            $text = $child.InnerText
            if ($text -and $text.Trim()) { return $text.Trim() }
        }
    }
    return $null
}

function Get-GpoNodeState {
    param([System.Xml.XmlNode]$Node)
    if ($Node.Attributes) {
        foreach ($attr in $Node.Attributes) {
            if ($attr.LocalName -in @('state','status','action') -and $attr.Value) { return $attr.Value }
        }
    }
    foreach ($child in $Node.ChildNodes) {
        if ($child.NodeType -eq [System.Xml.XmlNodeType]::Element -and $child.LocalName -eq 'State') {
            return $child.InnerText
        }
    }
    return $null
}

function Get-GpoNodeValue {
    param([System.Xml.XmlNode]$Node, [int]$MaxLength = 300)
    $value = $null
    foreach ($child in $Node.ChildNodes) {
        if ($child.NodeType -ne [System.Xml.XmlNodeType]::Element) { continue }
        if ($child.LocalName -match '^(Setting[A-Za-z]*|Value|Number|Member|Path)$') {
            $value = $child.InnerText
            break
        }
    }
    if (-not $value -and $Node.Attributes) {
        foreach ($attr in $Node.Attributes) {
            if ($attr.LocalName -eq 'value') { $value = $attr.Value; break }
        }
    }
    if (-not $value) { return $null }
    $value = ($value -replace '\s+', ' ').Trim()
    if ($value.Length -gt $MaxLength) { $value = $value.Substring(0, $MaxLength) + '...' }
    return $value
}

#endregion

#region ---------------------------------------------------------- parsers

function Get-GpoLinkInfo {
    [CmdletBinding()]
    param([System.Xml.XmlNode]$GpoNode, [string]$Domain)

    $links = New-Object System.Collections.ArrayList
    foreach ($link in (Get-XmlChildNode -Node $GpoNode -LocalName 'LinksTo')) {
        if ($null -eq $link) { continue }

        $somPath = Get-XmlChildText -Node $link -LocalName 'SOMPath'
        $somName = Get-XmlChildText -Node $link -LocalName 'SOMName'

        $somType = 'OU'
        if ($somPath -eq $Domain)                    { $somType = 'Domain' }
        elseif ($somPath -match '(?i)^sites?[\\/]')  { $somType = 'Site'   }
        elseif ($somPath -notmatch '[\\/]')          { $somType = 'Site'   }

        [void]$links.Add([pscustomobject]@{
            SomName  = $somName
            SomPath  = $somPath
            SomType  = $somType
            Enabled  = ConvertTo-GpoBool (Get-XmlChildText -Node $link -LocalName 'Enabled')
            Enforced = ConvertTo-GpoBool (Get-XmlChildText -Node $link -LocalName 'NoOverride')
        })
    }
    return $links.ToArray()
}

function Get-GpoFilteringInfo {
    <# Returns Apply / Deny / Delegation trustee lists from the report XML. #>
    [CmdletBinding()]
    param([System.Xml.XmlNode]$GpoNode)

    $apply      = New-Object System.Collections.ArrayList
    $deny       = New-Object System.Collections.ArrayList
    $delegation = New-Object System.Collections.ArrayList

    $sd = $GpoNode.SelectSingleNode("*[local-name()='SecurityDescriptor']")
    if ($null -eq $sd) {
        return [pscustomobject]@{ Apply = @(); Deny = @(); Delegation = @() }
    }

    $permsRoot = $sd.SelectSingleNode("*[local-name()='Permissions']")
    foreach ($perm in (Get-XmlChildNode -Node $permsRoot -LocalName 'TrusteePermissions')) {

        $trusteeNode = $perm.SelectSingleNode("*[local-name()='Trustee']")
        $trustee     = Get-XmlChildText -Node $trusteeNode -LocalName 'Name'
        if (-not $trustee) { $trustee = Get-XmlChildText -Node $trusteeNode -LocalName 'SID' }
        if (-not $trustee) { continue }

        $typeNode = $perm.SelectSingleNode("*[local-name()='Type']")
        $permType = Get-XmlChildText -Node $typeNode -LocalName 'PermissionType'

        $stdNode  = $perm.SelectSingleNode("*[local-name()='Standard']")
        $access   = Get-XmlChildText -Node $stdNode -LocalName 'GPOGroupedAccessEnum'

        $entry = [pscustomobject]@{
            Trustee    = $trustee.Trim()
            Permission = $access
            Type       = $permType
        }

        if ($access -match '(?i)apply group policy') {
            if ($permType -match '(?i)deny') { [void]$deny.Add($entry) } else { [void]$apply.Add($entry) }
        }
        else {
            [void]$delegation.Add($entry)
        }
    }

    return [pscustomobject]@{
        Apply      = ($apply      | Sort-Object Trustee -Unique)
        Deny       = ($deny       | Sort-Object Trustee -Unique)
        Delegation = ($delegation | Sort-Object Trustee, Permission -Unique)
    }
}

function Add-GpoSetting {
    <# Recursive, namespace-agnostic flattener for one ExtensionData block. #>
    [CmdletBinding()]
    param(
        [System.Xml.XmlNode]$Node,
        [string]$Scope,
        [string]$Extension,
        [System.Collections.ArrayList]$Accumulator,
        [int]$MaxSettings = 0,
        [int]$Depth       = 0
    )
    if ($null -eq $Node) { return }
    if ($Depth -gt 14)   { return }
    if ($MaxSettings -gt 0 -and $Accumulator.Count -ge $MaxSettings) { return }

    foreach ($child in $Node.ChildNodes) {
        if ($child.NodeType -ne [System.Xml.XmlNodeType]::Element) { continue }
        if ($MaxSettings -gt 0 -and $Accumulator.Count -ge $MaxSettings) { return }

        $name = Get-GpoNodeName -Node $child
        if ($name) {
            [void]$Accumulator.Add([pscustomobject]@{
                Scope     = $Scope
                Extension = $Extension
                Category  = $child.LocalName
                Name      = $name
                State     = Get-GpoNodeState -Node $child
                Value     = Get-GpoNodeValue -Node $child
            })
            # a named node is a leaf setting - do not explode its internals
        }
        else {
            Add-GpoSetting -Node $child -Scope $Scope -Extension $Extension `
                           -Accumulator $Accumulator -MaxSettings $MaxSettings -Depth ($Depth + 1)
        }
    }
}

function Get-GpoSettingInfo {
    [CmdletBinding()]
    param([System.Xml.XmlNode]$GpoNode, [int]$MaxSettings = 0)

    $settings   = New-Object System.Collections.ArrayList
    $extensions = New-Object System.Collections.ArrayList

    foreach ($scope in @('Computer','User')) {
        $scopeNode = $GpoNode.SelectSingleNode("*[local-name()='$scope']")
        if ($null -eq $scopeNode) { continue }

        foreach ($extData in (Get-XmlChildNode -Node $scopeNode -LocalName 'ExtensionData')) {
            $extName = Get-XmlChildText -Node $extData -LocalName 'Name'
            if (-not $extName) { $extName = 'Unknown extension' }

            $extNode = $extData.SelectSingleNode("*[local-name()='Extension']")
            $before  = $settings.Count

            Add-GpoSetting -Node $extNode -Scope $scope -Extension $extName `
                           -Accumulator $settings -MaxSettings $MaxSettings

            [void]$extensions.Add([pscustomobject]@{
                Scope        = $scope
                Extension    = $extName
                SettingCount = $settings.Count - $before
            })
        }
    }

    return [pscustomobject]@{
        Settings   = $settings.ToArray()
        Extensions = $extensions.ToArray()
        Truncated  = ($MaxSettings -gt 0 -and $settings.Count -ge $MaxSettings)
    }
}

#endregion

#region ---------------------------------------------------------- collection

function Get-GpoInventory {
    <#
    .SYNOPSIS
        Stage 1. Collects every GPO in the domain and writes GpoReport.json.
    .PARAMETER Resume
        Reuses batch files already present in <OutputFolder>\batches and only
        processes the GPOs that are still missing.
    #>
    [CmdletBinding()]
    param(
        [string]$Domain            = 'ad.net',
        [Parameter(Mandatory)][string]$OutputFolder,
        [int]   $BatchSize         = 25,
        [int]   $MaxSettingsPerGpo = 400,
        [switch]$Resume,
        [switch]$IncludeRawXml,
        [switch]$SkipSettings
    )

    $started = Get-Date

    # --- folders ---------------------------------------------------------
    $batchFolder = Join-Path $OutputFolder 'batches'
    $xmlFolder   = Join-Path $OutputFolder 'xml'
    foreach ($folder in @($OutputFolder, $batchFolder)) {
        if (-not (Test-Path -LiteralPath $folder)) { New-Item -ItemType Directory -Path $folder -Force | Out-Null }
    }
    if ($IncludeRawXml -and -not (Test-Path -LiteralPath $xmlFolder)) {
        New-Item -ItemType Directory -Path $xmlFolder -Force | Out-Null
    }

    $runStamp          = $started.ToString('yyyyMMdd_HHmmss')
    $script:GpoLogFile = Join-Path $OutputFolder ('GpoReport_{0}.log' -f $runStamp)
    $jsonPath          = Join-Path $OutputFolder 'GpoReport.json'
    $errorPath         = Join-Path $OutputFolder 'GpoReport.errors.json'

    Write-GpoLog -Level INFO -Message "=== GPO inventory started (domain: $Domain) ==="
    Test-GpoPrerequisite -Domain $Domain

    # --- enumerate -------------------------------------------------------
    Write-GpoLog -Level INFO -Message 'Enumerating GPOs...'
    $allGpos = @(Invoke-GpoRetry -Activity 'Get-GPO -All' -Script { Get-GPO -All -Domain $Domain } |
                 Sort-Object DisplayName)
    Write-GpoLog -Level OK -Message ("Found {0} GPO(s)." -f $allGpos.Count)
    if ($allGpos.Count -eq 0) { throw "No GPOs returned for domain '$Domain'." }

    # --- resume ----------------------------------------------------------
    $collected = New-Object System.Collections.ArrayList
    $errors    = New-Object System.Collections.ArrayList
    $doneIds   = New-Object 'System.Collections.Generic.HashSet[string]'

    if ($Resume) {
        $batchFiles = @(Get-ChildItem -LiteralPath $batchFolder -Filter 'batch_*.json' -ErrorAction SilentlyContinue |
                        Sort-Object Name)
        foreach ($file in $batchFiles) {
            try {
                $data = Get-Content -LiteralPath $file.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
                foreach ($item in @($data)) {
                    if ($null -eq $item) { continue }
                    [void]$collected.Add($item)
                    [void]$doneIds.Add([string]$item.Id)
                }
            }
            catch {
                Write-GpoLog -Level WARN -Message ("Unreadable batch '{0}' ignored: {1}" -f $file.Name, $_.Exception.Message)
            }
        }
        Write-GpoLog -Level OK -Message ("Resume: {0} GPO(s) restored from {1} batch file(s)." -f $collected.Count, $batchFiles.Count)
    }
    else {
        Get-ChildItem -LiteralPath $batchFolder -Filter 'batch_*.json' -ErrorAction SilentlyContinue |
            Remove-Item -Force -ErrorAction SilentlyContinue
    }

    $pending = @($allGpos | Where-Object { -not $doneIds.Contains([string]$_.Id) })
    if ($pending.Count -eq 0) {
        Write-GpoLog -Level OK -Message 'Nothing left to collect - all GPOs already in batches.'
    }

    # --- batch loop ------------------------------------------------------
    $batchCount = [Math]::Max(1, [Math]::Ceiling($pending.Count / [double]$BatchSize))
    $processed  = 0
    $batchIndex = 0

    for ($offset = 0; $offset -lt $pending.Count; $offset += $BatchSize) {
        $batchIndex++
        $batch     = @($pending[$offset..([Math]::Min($offset + $BatchSize - 1, $pending.Count - 1))])
        $batchItems = New-Object System.Collections.ArrayList

        Write-Progress -Id 1 -Activity ('GPO inventory - {0}' -f $Domain) `
                       -Status ('Batch {0} of {1} ({2} GPO(s) done)' -f $batchIndex, $batchCount, $processed) `
                       -PercentComplete ([Math]::Min(100, ($processed / [double]$pending.Count) * 100))

        foreach ($gpo in $batch) {
            $processed++
            $gpoName = $gpo.DisplayName

            Write-Progress -Id 2 -ParentId 1 -Activity 'Reading GPO' `
                           -Status ('[{0}/{1}] {2}' -f $processed, $pending.Count, $gpoName) `
                           -PercentComplete ([Math]::Min(100, ($processed / [double]$pending.Count) * 100))

            $gpoErrors = New-Object System.Collections.ArrayList
            $links = @(); $filtering = $null; $settingInfo = $null; $xmlPath = $null

            try {
                $reportXml = Invoke-GpoRetry -Activity ("Get-GPOReport '{0}'" -f $gpoName) -Script {
                    Get-GPOReport -Guid $gpo.Id -ReportType Xml -Domain $Domain
                }

                if ($IncludeRawXml) {
                    $safeName = ($gpoName -replace '[\\/:*?"<>|]', '_')
                    $xmlPath  = Join-Path $xmlFolder ('{0}_{1}.xml' -f $safeName, $gpo.Id)
                    [System.IO.File]::WriteAllText($xmlPath, $reportXml, (New-Object System.Text.UTF8Encoding($false)))
                }

                $xml     = [xml]$reportXml
                $gpoNode = $xml.DocumentElement

                $links     = Get-GpoLinkInfo       -GpoNode $gpoNode -Domain $Domain
                $filtering = Get-GpoFilteringInfo  -GpoNode $gpoNode
                if (-not $SkipSettings) {
                    $settingInfo = Get-GpoSettingInfo -GpoNode $gpoNode -MaxSettings $MaxSettingsPerGpo
                }
            }
            catch {
                $message = $_.Exception.Message
                [void]$gpoErrors.Add($message)
                [void]$errors.Add([pscustomobject]@{
                    Gpo       = $gpoName
                    Id        = [string]$gpo.Id
                    Stage     = 'Get-GPOReport'
                    Message   = $message
                    TimeStamp = (Get-Date).ToString('s')
                })
                Write-GpoLog -Level ERROR -Message ("'{0}' failed: {1}" -f $gpoName, $message)
            }

            # security filtering fallback via Get-GPPermission
            if ($filtering -and @($filtering.Apply).Count -eq 0) {
                try {
                    $perms = Get-GPPermission -Guid $gpo.Id -All -Domain $Domain -ErrorAction Stop |
                             Where-Object { $_.Permission -eq 'GpoApply' }
                    if ($perms) {
                        $filtering.Apply = @($perms | ForEach-Object {
                            [pscustomobject]@{ Trustee = $_.Trustee.Name; Permission = 'Apply Group Policy'; Type = 'Allow' }
                        })
                    }
                }
                catch {
                    [void]$gpoErrors.Add("Get-GPPermission fallback failed: $($_.Exception.Message)")
                }
            }

            # --- normalise values (no statements inside the object literal) ---
            $computerDs = 0; $computerSysvol = 0; $userDs = 0; $userSysvol = 0
            try { $computerDs     = [int]$gpo.Computer.DSVersion }     catch { }
            try { $computerSysvol = [int]$gpo.Computer.SysvolVersion } catch { }
            try { $userDs         = [int]$gpo.User.DSVersion }         catch { }
            try { $userSysvol     = [int]$gpo.User.SysvolVersion }     catch { }

            $created  = $null; $modified = $null
            if ($gpo.CreationTime)     { $created  = $gpo.CreationTime.ToString('s') }
            if ($gpo.ModificationTime) { $modified = $gpo.ModificationTime.ToString('s') }

            $wmiName = $null; $wmiDescription = $null
            if ($gpo.WmiFilter) {
                $wmiName        = [string]$gpo.WmiFilter.Name
                $wmiDescription = [string]$gpo.WmiFilter.Description
            }

            $applyList = @(); $denyList = @(); $delegationList = @()
            if ($filtering) {
                $applyList      = @($filtering.Apply)
                $denyList       = @($filtering.Deny)
                $delegationList = @($filtering.Delegation)
            }

            $settingList = @(); $extensionList = @(); $truncated = $false
            if ($settingInfo) {
                $settingList   = @($settingInfo.Settings)
                $extensionList = @($settingInfo.Extensions)
                $truncated     = [bool]$settingInfo.Truncated
            }

            $record = [pscustomobject]@{
                Name                  = $gpoName
                Id                    = [string]$gpo.Id
                Domain                = [string]$gpo.DomainName
                Owner                 = [string]$gpo.Owner
                GpoStatus             = [string]$gpo.GpoStatus
                Description           = [string]$gpo.Description
                CreationTime          = $created
                ModificationTime      = $modified
                ComputerDSVersion     = $computerDs
                ComputerSysvolVersion = $computerSysvol
                UserDSVersion         = $userDs
                UserSysvolVersion     = $userSysvol
                WmiFilterName         = $wmiName
                WmiFilterDescription  = $wmiDescription
                LinkCount             = @($links).Count
                IsLinked              = (@($links).Count -gt 0)
                HasEnabledLink        = (@($links | Where-Object { $_.Enabled }).Count -gt 0)
                Links                 = @($links)
                SecurityFiltering     = $applyList
                DeniedFiltering       = $denyList
                Delegation            = $delegationList
                Extensions            = $extensionList
                Settings              = $settingList
                SettingCount          = $settingList.Count
                SettingsTruncated     = $truncated
                IsEmpty               = (($computerDs -eq 0) -and ($userDs -eq 0))
                RawXmlPath            = $xmlPath
                HasError              = ($gpoErrors.Count -gt 0)
                Errors                = $gpoErrors.ToArray()
            }

            [void]$batchItems.Add($record)
            [void]$collected.Add($record)
        }

        # --- checkpoint ---------------------------------------------------
        try {
            $batchFile = Join-Path $batchFolder ('batch_{0}_{1:d4}.json' -f $runStamp, $batchIndex)
            $batchJson = $batchItems.ToArray() | ConvertTo-Json -Depth 12
            [System.IO.File]::WriteAllText($batchFile, $batchJson, (New-Object System.Text.UTF8Encoding($false)))
            Write-GpoLog -Level OK -Message ("Checkpoint saved: {0} ({1} GPO(s))" -f (Split-Path $batchFile -Leaf), $batchItems.Count)
        }
        catch {
            Write-GpoLog -Level ERROR -Message ("Checkpoint failed for batch {0}: {1}" -f $batchIndex, $_.Exception.Message)
        }
    }

    Write-Progress -Id 2 -Activity 'Reading GPO' -Completed
    Write-Progress -Id 1 -Activity 'GPO inventory' -Completed

    # --- final document ---------------------------------------------------
    $duration = (Get-Date) - $started
    $report = [pscustomobject]@{
        Metadata = [pscustomobject]@{
            Domain          = $Domain
            GeneratedOn     = (Get-Date).ToString('s')
            GeneratedBy     = "$env:USERDOMAIN\$env:USERNAME"
            ComputerName    = $env:COMPUTERNAME
            ToolVersion     = $script:GpoToolVersion
            DurationSeconds = [Math]::Round($duration.TotalSeconds, 1)
            GpoCount        = $collected.Count
            ErrorCount      = $errors.Count
            SettingsSkipped = [bool]$SkipSettings
        }
        Errors = $errors.ToArray()
        Gpos   = ($collected.ToArray() | Sort-Object Name)
    }

    try {
        $json = $report | ConvertTo-Json -Depth 12
        [System.IO.File]::WriteAllText($jsonPath, $json, (New-Object System.Text.UTF8Encoding($false)))
        Write-GpoLog -Level OK -Message "JSON written: $jsonPath"
    }
    catch {
        Write-GpoLog -Level ERROR -Message ("Could not write the final JSON: {0}" -f $_.Exception.Message)
        throw
    }

    if ($errors.Count -gt 0) {
        $errJson = $errors.ToArray() | ConvertTo-Json -Depth 5
        [System.IO.File]::WriteAllText($errorPath, $errJson, (New-Object System.Text.UTF8Encoding($false)))
        Write-GpoLog -Level WARN -Message ("{0} GPO(s) reported errors - see {1}" -f $errors.Count, $errorPath)
    }

    Write-GpoLog -Level OK -Message ("=== Finished in {0:hh\:mm\:ss} ===" -f $duration)
    return $jsonPath
}

#endregion

#region ---------------------------------------------------------- converters

function Import-GpoReport {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$JsonPath)

    if (-not (Test-Path -LiteralPath $JsonPath)) { throw "JSON report not found: $JsonPath" }
    try   { return (Get-Content -LiteralPath $JsonPath -Raw -Encoding UTF8 | ConvertFrom-Json) }
    catch { throw "JSON report is not readable/valid: $($_.Exception.Message)" }
}

function ConvertTo-GpoCsv {
    <#
    .SYNOPSIS
        Stage 2. Flattens GpoReport.json into CSV. Works offline.
    .PARAMETER Scope
        PerLink  - one row per GPO link (unlinked GPOs still get one row). Default.
        PerGpo   - one row per GPO, links joined into a single cell.
        Settings - one row per individual setting.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$JsonPath,
        [string]$CsvPath,
        [ValidateSet('PerLink','PerGpo','Settings')][string]$Scope = 'PerLink',
        [string]$Delimiter = ','
    )

    $report = Import-GpoReport -JsonPath $JsonPath
    if (-not $CsvPath) {
        $CsvPath = [System.IO.Path]::ChangeExtension($JsonPath, $null) + '_' + $Scope + '.csv'
    }

    $gpos = @($report.Gpos)
    $rows = New-Object System.Collections.ArrayList
    $i    = 0

    foreach ($gpo in $gpos) {
        $i++
        if ($i % 25 -eq 0 -or $i -eq $gpos.Count) {
            Write-Progress -Id 3 -Activity "Building CSV ($Scope)" -Status ('{0}/{1}' -f $i, $gpos.Count) `
                           -PercentComplete (($i / [double]$gpos.Count) * 100)
        }

        $applyList = (@($gpo.SecurityFiltering) | ForEach-Object { $_.Trustee }) -join '; '
        $denyList  = (@($gpo.DeniedFiltering)   | ForEach-Object { $_.Trustee }) -join '; '

        switch ($Scope) {
            'PerGpo' {
                [void]$rows.Add([pscustomobject]@{
                    Name              = $gpo.Name
                    Id                = $gpo.Id
                    GpoStatus         = $gpo.GpoStatus
                    LinkCount         = $gpo.LinkCount
                    Links             = (@($gpo.Links) | ForEach-Object { $_.SomPath }) -join '; '
                    EnforcedLinks     = (@($gpo.Links | Where-Object { $_.Enforced }) | ForEach-Object { $_.SomPath }) -join '; '
                    SecurityFiltering = $applyList
                    DeniedFiltering   = $denyList
                    WmiFilter         = $gpo.WmiFilterName
                    SettingCount      = $gpo.SettingCount
                    Extensions        = (@($gpo.Extensions) | ForEach-Object { '{0}:{1}' -f $_.Scope, $_.Extension }) -join '; '
                    IsEmpty           = $gpo.IsEmpty
                    Owner             = $gpo.Owner
                    CreationTime      = $gpo.CreationTime
                    ModificationTime  = $gpo.ModificationTime
                    HasError          = $gpo.HasError
                })
            }
            'Settings' {
                foreach ($setting in @($gpo.Settings)) {
                    [void]$rows.Add([pscustomobject]@{
                        Gpo       = $gpo.Name
                        Id        = $gpo.Id
                        Scope     = $setting.Scope
                        Extension = $setting.Extension
                        Category  = $setting.Category
                        Setting   = $setting.Name
                        State     = $setting.State
                        Value     = $setting.Value
                    })
                }
            }
            default {   # PerLink
                $links = @($gpo.Links)
                if ($links.Count -eq 0) {
                    $links = @([pscustomobject]@{ SomName = '(not linked)'; SomPath = ''; SomType = ''; Enabled = $false; Enforced = $false })
                }
                foreach ($link in $links) {
                    [void]$rows.Add([pscustomobject]@{
                        Name              = $gpo.Name
                        Id                = $gpo.Id
                        GpoStatus         = $gpo.GpoStatus
                        LinkTarget        = $link.SomName
                        LinkPath          = $link.SomPath
                        LinkType          = $link.SomType
                        LinkEnabled       = $link.Enabled
                        LinkEnforced      = $link.Enforced
                        SecurityFiltering = $applyList
                        DeniedFiltering   = $denyList
                        WmiFilter         = $gpo.WmiFilterName
                        SettingCount      = $gpo.SettingCount
                        IsEmpty           = $gpo.IsEmpty
                        Owner             = $gpo.Owner
                        CreationTime      = $gpo.CreationTime
                        ModificationTime  = $gpo.ModificationTime
                        HasError          = $gpo.HasError
                    })
                }
            }
        }
    }
    Write-Progress -Id 3 -Activity 'Building CSV' -Completed

    try {
        $rows.ToArray() | Export-Csv -LiteralPath $CsvPath -NoTypeInformation -Encoding UTF8 -Delimiter $Delimiter
        Write-GpoLog -Level OK -Message ("CSV written ({0} row(s)): {1}" -f $rows.Count, $CsvPath)
    }
    catch {
        Write-GpoLog -Level ERROR -Message ("CSV export failed: {0}" -f $_.Exception.Message)
        throw
    }
    return $CsvPath
}

function ConvertTo-HtmlSafe {
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    return ($Text -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;')
}

function ConvertTo-GpoHtml {
    <#
    .SYNOPSIS
        Stage 3. Renders GpoReport.json as a single self-contained HTML file. Works offline.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$JsonPath,
        [string]$HtmlPath,
        [switch]$NoSettings,
        [int]$MaxSettingsShown = 100
    )

    $report = Import-GpoReport -JsonPath $JsonPath
    if (-not $HtmlPath) { $HtmlPath = [System.IO.Path]::ChangeExtension($JsonPath, 'html') }

    $gpos     = @($report.Gpos)
    $meta     = $report.Metadata
    $unlinked = @($gpos | Where-Object { -not $_.IsLinked })
    $empty    = @($gpos | Where-Object { $_.IsEmpty })
    $disabled = @($gpos | Where-Object { $_.GpoStatus -eq 'AllSettingsDisabled' })
    $wmi      = @($gpos | Where-Object { $_.WmiFilterName })
    $failed   = @($gpos | Where-Object { $_.HasError })

    $css = @'
<style>
 :root{--bg:#f6f7f9;--card:#fff;--line:#e2e5ea;--ink:#1d2430;--mut:#6b7482;--acc:#2f6feb;--warn:#c47f00;--bad:#c0392b;--ok:#1e8449}
 *{box-sizing:border-box}
 body{margin:0;padding:24px;background:var(--bg);color:var(--ink);font:14px/1.5 "Segoe UI",system-ui,sans-serif}
 h1{margin:0 0 4px;font-size:22px} h2{font-size:16px;margin:28px 0 10px}
 .sub{color:var(--mut);font-size:12px;margin-bottom:18px}
 .tiles{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:22px}
 .tile{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 16px;min-width:120px}
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
 details table{margin-top:10px;border:none}
 .small{font-size:12px;color:var(--mut)}
</style>
'@

    $js = @'
<script>
function filterRows(){
  var q=document.getElementById("q").value.toLowerCase();
  var rows=document.querySelectorAll("#main tbody tr");
  for(var i=0;i<rows.length;i++){
    rows[i].style.display = rows[i].innerText.toLowerCase().indexOf(q)>-1 ? "" : "none";
  }
}
function sortTable(n){
  var t=document.getElementById("main"),rows=Array.prototype.slice.call(t.tBodies[0].rows);
  var dir=t.getAttribute("data-dir")==="asc"?-1:1;
  t.setAttribute("data-dir",dir===1?"asc":"desc");
  rows.sort(function(a,b){
    var x=a.cells[n].innerText.trim(),y=b.cells[n].innerText.trim();
    var nx=parseFloat(x),ny=parseFloat(y);
    if(!isNaN(nx)&&!isNaN(ny)){return (nx-ny)*dir;}
    return x.localeCompare(y)*dir;
  });
  for(var i=0;i<rows.length;i++){t.tBodies[0].appendChild(rows[i]);}
}
</script>
'@

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">')
    [void]$sb.AppendLine(('<title>GPO report - {0}</title>' -f (ConvertTo-HtmlSafe $meta.Domain)))
    [void]$sb.AppendLine($css)
    [void]$sb.AppendLine('</head><body>')
    [void]$sb.AppendLine(('<h1>Group Policy report - {0}</h1>' -f (ConvertTo-HtmlSafe $meta.Domain)))
    [void]$sb.AppendLine(('<div class="sub">Generated {0} by {1} on {2} &middot; collection took {3}s &middot; tool v{4}</div>' -f `
        (ConvertTo-HtmlSafe $meta.GeneratedOn), (ConvertTo-HtmlSafe $meta.GeneratedBy),
        (ConvertTo-HtmlSafe $meta.ComputerName), $meta.DurationSeconds, (ConvertTo-HtmlSafe $meta.ToolVersion)))

    [void]$sb.AppendLine('<div class="tiles">')
    $tiles = @(
        @{ Label = 'GPOs';            Value = $gpos.Count },
        @{ Label = 'Unlinked';        Value = $unlinked.Count },
        @{ Label = 'Empty';           Value = $empty.Count },
        @{ Label = 'Fully disabled';  Value = $disabled.Count },
        @{ Label = 'WMI filtered';    Value = $wmi.Count },
        @{ Label = 'Read errors';     Value = $failed.Count }
    )
    foreach ($tile in $tiles) {
        [void]$sb.AppendLine(('<div class="tile"><b>{0}</b><span>{1}</span></div>' -f $tile.Value, $tile.Label))
    }
    [void]$sb.AppendLine('</div>')

    # --- overview table --------------------------------------------------
    [void]$sb.AppendLine('<h2>Overview</h2>')
    [void]$sb.AppendLine('<input id="q" onkeyup="filterRows()" placeholder="Filter: GPO name, OU, group, WMI filter...">')
    [void]$sb.AppendLine('<table id="main"><thead><tr>')
    $headers = @('GPO','Status','Links','Security filtering','WMI filter','Settings','Created','Modified')
    for ($h = 0; $h -lt $headers.Count; $h++) {
        [void]$sb.AppendLine(('<th onclick="sortTable({0})">{1}</th>' -f $h, $headers[$h]))
    }
    [void]$sb.AppendLine('</tr></thead><tbody>')

    $i = 0
    foreach ($gpo in $gpos) {
        $i++
        if ($i % 25 -eq 0 -or $i -eq $gpos.Count) {
            Write-Progress -Id 4 -Activity 'Building HTML' -Status ('{0}/{1}' -f $i, $gpos.Count) `
                           -PercentComplete (($i / [double]$gpos.Count) * 100)
        }

        $linkText = if (@($gpo.Links).Count -eq 0) {
            '<span class="bad">not linked</span>'
        } else {
            (@($gpo.Links) | ForEach-Object {
                $flags = @()
                if ($_.Enforced)   { $flags += 'enforced' }
                if (-not $_.Enabled) { $flags += 'link disabled' }
                $suffix = if ($flags.Count) { ' <span class="pill warn">' + ($flags -join ', ') + '</span>' } else { '' }
                (ConvertTo-HtmlSafe $_.SomPath) + $suffix
            }) -join '<br>'
        }

        $applyText = if (@($gpo.SecurityFiltering).Count -eq 0) {
            '<span class="warn">none</span>'
        } else {
            (@($gpo.SecurityFiltering) | ForEach-Object { ConvertTo-HtmlSafe $_.Trustee }) -join '<br>'
        }
        if (@($gpo.DeniedFiltering).Count -gt 0) {
            $applyText += '<br><span class="bad">deny: ' + ((@($gpo.DeniedFiltering) | ForEach-Object { ConvertTo-HtmlSafe $_.Trustee }) -join ', ') + '</span>'
        }

        $statusClass = if ($gpo.GpoStatus -eq 'AllSettingsEnabled') { 'ok' } else { 'warn' }
        $nameCell    = ConvertTo-HtmlSafe $gpo.Name
        if ($gpo.HasError) { $nameCell += ' <span class="pill bad">read error</span>' }
        if ($gpo.IsEmpty)  { $nameCell += ' <span class="pill warn">empty</span>' }

        [void]$sb.AppendLine('<tr>')
        [void]$sb.AppendLine(('<td>{0}<div class="small">{1}</div></td>' -f $nameCell, (ConvertTo-HtmlSafe $gpo.Id)))
        [void]$sb.AppendLine(('<td class="{0}">{1}</td>' -f $statusClass, (ConvertTo-HtmlSafe $gpo.GpoStatus)))
        [void]$sb.AppendLine(('<td>{0}</td>' -f $linkText))
        [void]$sb.AppendLine(('<td>{0}</td>' -f $applyText))
        [void]$sb.AppendLine(('<td>{0}</td>' -f (ConvertTo-HtmlSafe $gpo.WmiFilterName)))
        [void]$sb.AppendLine(('<td>{0}</td>' -f $gpo.SettingCount))
        [void]$sb.AppendLine(('<td>{0}</td>' -f (ConvertTo-HtmlSafe $gpo.CreationTime)))
        [void]$sb.AppendLine(('<td>{0}</td>' -f (ConvertTo-HtmlSafe $gpo.ModificationTime)))
        [void]$sb.AppendLine('</tr>')
    }
    [void]$sb.AppendLine('</tbody></table>')

    # --- settings detail --------------------------------------------------
    if (-not $NoSettings) {
        [void]$sb.AppendLine('<h2>Settings detail</h2>')
        foreach ($gpo in $gpos) {
            $settings = @($gpo.Settings)
            if ($settings.Count -eq 0) { continue }

            [void]$sb.AppendLine('<details>')
            [void]$sb.AppendLine(('<summary>{0} <span class="small">({1} setting(s))</span></summary>' -f `
                (ConvertTo-HtmlSafe $gpo.Name), $settings.Count))
            [void]$sb.AppendLine('<table><thead><tr><th>Scope</th><th>Extension</th><th>Category</th><th>Setting</th><th>State</th><th>Value</th></tr></thead><tbody>')

            $shown = 0
            foreach ($setting in $settings) {
                if ($MaxSettingsShown -gt 0 -and $shown -ge $MaxSettingsShown) { break }
                $shown++
                [void]$sb.AppendLine(('<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td></tr>' -f `
                    (ConvertTo-HtmlSafe $setting.Scope), (ConvertTo-HtmlSafe $setting.Extension),
                    (ConvertTo-HtmlSafe $setting.Category), (ConvertTo-HtmlSafe $setting.Name),
                    (ConvertTo-HtmlSafe $setting.State), (ConvertTo-HtmlSafe $setting.Value)))
            }
            if ($settings.Count -gt $shown) {
                [void]$sb.AppendLine(('<tr><td colspan="6" class="mut">... {0} more setting(s) in the JSON</td></tr>' -f ($settings.Count - $shown)))
            }
            [void]$sb.AppendLine('</tbody></table></details>')
        }
    }

    # --- errors -----------------------------------------------------------
    if (@($report.Errors).Count -gt 0) {
        [void]$sb.AppendLine('<h2>Collection errors</h2><table><thead><tr><th>GPO</th><th>Stage</th><th>Message</th></tr></thead><tbody>')
        foreach ($err in @($report.Errors)) {
            [void]$sb.AppendLine(('<tr><td>{0}</td><td>{1}</td><td class="bad">{2}</td></tr>' -f `
                (ConvertTo-HtmlSafe $err.Gpo), (ConvertTo-HtmlSafe $err.Stage), (ConvertTo-HtmlSafe $err.Message)))
        }
        [void]$sb.AppendLine('</tbody></table>')
    }

    [void]$sb.AppendLine($js)
    [void]$sb.AppendLine('</body></html>')
    Write-Progress -Id 4 -Activity 'Building HTML' -Completed

    try {
        [System.IO.File]::WriteAllText($HtmlPath, $sb.ToString(), (New-Object System.Text.UTF8Encoding($false)))
        Write-GpoLog -Level OK -Message "HTML written: $HtmlPath"
    }
    catch {
        Write-GpoLog -Level ERROR -Message ("HTML export failed: {0}" -f $_.Exception.Message)
        throw
    }
    return $HtmlPath
}

#endregion

#region ---------------------------------------------------------- orchestration

function Invoke-GpoReportSuite {
    [CmdletBinding()]
    param(
        [string]$Domain            = 'ad.net',
        [Parameter(Mandatory)][string]$OutputFolder,
        [int]   $BatchSize         = 25,
        [int]   $MaxSettingsPerGpo = 400,
        [switch]$Resume,
        [switch]$IncludeRawXml,
        [switch]$SkipSettings
    )

    $jsonPath = Get-GpoInventory -Domain $Domain -OutputFolder $OutputFolder -BatchSize $BatchSize `
                                 -MaxSettingsPerGpo $MaxSettingsPerGpo -Resume:$Resume `
                                 -IncludeRawXml:$IncludeRawXml -SkipSettings:$SkipSettings

    $csvPerLink = ConvertTo-GpoCsv  -JsonPath $jsonPath -Scope PerLink
    $csvPerGpo  = ConvertTo-GpoCsv  -JsonPath $jsonPath -Scope PerGpo
    $html       = ConvertTo-GpoHtml -JsonPath $jsonPath

    Write-Host ''
    Write-Host 'Report set complete:' -ForegroundColor Cyan
    Write-Host "  JSON : $jsonPath"
    Write-Host "  CSV  : $csvPerLink"
    Write-Host "  CSV  : $csvPerGpo"
    Write-Host "  HTML : $html"

    return [pscustomobject]@{ Json = $jsonPath; CsvPerLink = $csvPerLink; CsvPerGpo = $csvPerGpo; Html = $html }
}

#endregion

# Dot-sourced ( . .\Get-GpoReport.ps1 ) -> only load the functions.
# Executed directly                      -> run the whole suite.
if ($MyInvocation.InvocationName -ne '.') {
    Invoke-GpoReportSuite -Domain $Domain -OutputFolder $OutputFolder -BatchSize $BatchSize `
                          -MaxSettingsPerGpo $MaxSettingsPerGpo -Resume:$Resume `
                          -IncludeRawXml:$IncludeRawXml -SkipSettings:$SkipSettings
}
else {
    Write-Host 'GPO report functions loaded: Get-GpoInventory, ConvertTo-GpoCsv, ConvertTo-GpoHtml, Invoke-GpoReportSuite' -ForegroundColor Cyan
}
