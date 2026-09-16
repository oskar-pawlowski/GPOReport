#Requires -Version 5.1
<#
.SYNOPSIS
    GPO inventory built on the ActiveDirectory module + SYSVOL only.
    No GroupPolicy module, no RSAT GPMC, no administrative rights required.

.DESCRIPTION
    Reads everything a standard domain user can already see:

      * GPO objects   -> CN=Policies,CN=System,<domainDN>  (groupPolicyContainer)
      * Links         -> gPLink / gPOptions on the domain, every OU and every site
      * WMI filters   -> CN=SOM,CN=WMIPolicy,CN=System,<domainDN>  (msWMI-Som)
      * Filtering     -> nTSecurityDescriptor, ACEs carrying the
                         "Apply Group Policy" extended right
      * Settings      -> SYSVOL: Registry.pol, GptTmpl.inf, scripts.ini,
                         Preferences\*.xml  (parsed natively)

    Output schema is identical to the GroupPolicy-based script, so the
    ConvertTo-GpoCsv / ConvertTo-GpoHtml converters work unchanged.

    Every phase is timed; timings land in the JSON metadata, in
    GpoReport.performance.json and in the console summary.

.EXAMPLE
    .\Get-GpoReportAD.ps1 -Domain ad.net -OutputFolder C:\Reports\GPO

.EXAMPLE
    .\Get-GpoReportAD.ps1 -SkipSettings          # metadata only, seconds not minutes

.EXAMPLE
    .\Get-GpoReportAD.ps1 -Parallel 8 -Resume    # 8 runspaces, reuse cached SYSVOL scans

.NOTES
    Version : 1.0  (AD-only edition)
    Requires: ActiveDirectory module, read access to SYSVOL (default for Authenticated Users).
#>

[CmdletBinding()]
param(
    [string]$Domain            = 'ad.net',
    [string]$OutputFolder      = (Join-Path $env:USERPROFILE 'Documents\GpoReport'),
    [string]$NameFilter        = '*',
    [int]   $BatchSize         = 25,
    [int]   $MaxSettingsPerGpo = 400,
    [int]   $Parallel          = 1,
    [switch]$Resume,
    [switch]$SkipSettings,
    [string]$ConverterScript
)

$ErrorActionPreference = 'Stop'
$script:GpoToolVersion = '1.0-AD'
$script:GpoLogFile     = $null
$script:SidCache       = @{}
$script:Phases         = New-Object System.Collections.ArrayList

#region ---------------------------------------------------------- infrastructure

function Write-GpoLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO','WARN','ERROR','OK')][string]$Level = 'INFO'
    )
    $line = '{0} [{1,-5}] {2}' -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'), $Level, $Message
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

function Measure-GpoPhase {
    <# Times a scriptblock, records the result, returns whatever the block returned. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Script
    )
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $result = & $Script
        $sw.Stop()
        [void]$script:Phases.Add([pscustomobject]@{
            Phase   = $Name
            Seconds = [Math]::Round($sw.Elapsed.TotalSeconds, 2)
            Status  = 'OK'
        })
        Write-GpoLog -Level OK -Message ('{0} - {1:n2}s' -f $Name, $sw.Elapsed.TotalSeconds)
        return $result
    }
    catch {
        $sw.Stop()
        [void]$script:Phases.Add([pscustomobject]@{
            Phase   = $Name
            Seconds = [Math]::Round($sw.Elapsed.TotalSeconds, 2)
            Status  = 'FAILED: ' + $_.Exception.Message
        })
        throw
    }
}

function Invoke-GpoRetry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][scriptblock]$Script,
        [int]$Retries      = 3,
        [int]$DelaySeconds = 2,
        [string]$Activity  = 'operation'
    )
    for ($attempt = 1; $attempt -le $Retries; $attempt++) {
        try { return & $Script }
        catch {
            if ($attempt -ge $Retries) { throw }
            Write-GpoLog -Level WARN -Message ("Retry {0}/{1} for {2}: {3}" -f $attempt, $Retries, $Activity, $_.Exception.Message)
            Start-Sleep -Seconds ($DelaySeconds * $attempt)
        }
    }
}

function Test-AdPrerequisite {
    [CmdletBinding()]
    param([string]$Domain)

    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        throw "ActiveDirectory module not found. Install RSAT-AD-PowerShell (no admin rights needed if it is already present on the workstation image)."
    }
    Import-Module ActiveDirectory -ErrorAction Stop -Verbose:$false | Out-Null

    try   { $adDomain = Get-ADDomain -Identity $Domain -ErrorAction Stop }
    catch { throw "Cannot reach domain '$Domain': $($_.Exception.Message)" }

    $sysvol = "\\$($adDomain.DNSRoot)\SYSVOL\$($adDomain.DNSRoot)\Policies"
    $sysvolOk = $false
    try { $sysvolOk = Test-Path -LiteralPath $sysvol } catch { $sysvolOk = $false }
    if (-not $sysvolOk) {
        Write-GpoLog -Level WARN -Message "SYSVOL path '$sysvol' is not reachable - settings parsing will be skipped."
    }

    Write-GpoLog -Level OK -Message ("Prerequisites OK - domain {0}, DN {1}, SYSVOL reachable: {2}" -f $adDomain.DNSRoot, $adDomain.DistinguishedName, $sysvolOk)
    return [pscustomobject]@{ AdDomain = $adDomain; SysvolRoot = $sysvol; SysvolAvailable = $sysvolOk }
}

#endregion

#region ---------------------------------------------------------- AD readers

function ConvertTo-GpoStatusText {
    <# groupPolicyContainer 'flags': bit0 = user side disabled, bit1 = computer side disabled. #>
    param([int]$Flags)
    switch ($Flags) {
        0       { 'AllSettingsEnabled' }
        1       { 'UserSettingsDisabled' }
        2       { 'ComputerSettingsDisabled' }
        3       { 'AllSettingsDisabled' }
        default { "Unknown($Flags)" }
    }
}

function ConvertTo-CanonicalPath {
    <# CN=X,OU=A,OU=B,DC=ad,DC=net  ->  ad.net/B/A/X #>
    param([string]$DistinguishedName)
    if (-not $DistinguishedName) { return $null }

    $parts  = $DistinguishedName -split '(?<!\\),'
    $domain = @()
    $path   = @()
    foreach ($part in $parts) {
        $trimmed = $part.Trim()
        if ($trimmed -match '^DC=(.+)$')          { $domain += $Matches[1] }
        elseif ($trimmed -match '^(OU|CN)=(.+)$') { $path   += ($Matches[2] -replace '\\,', ',') }
    }
    [array]::Reverse($path)
    $result = ($domain -join '.')
    if ($path.Count -gt 0) { $result += '/' + ($path -join '/') }
    return $result
}

function ConvertFrom-GpLink {
    <#
      gPLink looks like: [LDAP://cn={GUID},cn=policies,cn=system,DC=ad,DC=net;0][LDAP://...;2]
      flag bits: 1 = link disabled, 2 = enforced.
      Links are stored lowest-precedence-first, so the LAST entry wins.
    #>
    param([string]$GpLink)

    $parsed = New-Object System.Collections.ArrayList
    if (-not $GpLink) { return $parsed.ToArray() }

    $linkMatches = [regex]::Matches($GpLink, '\[LDAP://(?<dn>[^;\]]+);(?<flag>\d+)\]')
    $total       = $linkMatches.Count
    for ($i = 0; $i -lt $total; $i++) {
        $dn   = $linkMatches[$i].Groups['dn'].Value
        $flag = [int]$linkMatches[$i].Groups['flag'].Value
        $guid = $null
        $guidMatch = [regex]::Match($dn, '\{[0-9A-Fa-f\-]{36}\}')
        if ($guidMatch.Success) { $guid = $guidMatch.Value.ToUpper() }
        if (-not $guid) { continue }

        [void]$parsed.Add([pscustomobject]@{
            GpoId     = $guid
            Enabled   = (($flag -band 1) -eq 0)
            Enforced  = (($flag -band 2) -eq 2)
            LinkOrder = $total - $i      # 1 = highest precedence on this container
        })
    }
    return $parsed.ToArray()
}

function Get-GpoLinkMap {
    <# Returns @{ '{GUID}' = @(link objects) } plus the container inventory. #>
    [CmdletBinding()]
    param([string]$Server, [string]$DomainDN, [string]$ConfigDN)

    $map        = @{}
    $containers = New-Object System.Collections.ArrayList

    $sources = @()
    $sources += ,@{ Base = $DomainDN; Label = 'Domain/OU' }
    if ($ConfigDN) { $sources += ,@{ Base = "CN=Sites,$ConfigDN"; Label = 'Site' } }

    foreach ($source in $sources) {
        try {
            $objects = Invoke-GpoRetry -Activity ("gPLink scan of {0}" -f $source.Base) -Script {
                Get-ADObject -LDAPFilter '(gPLink=*)' -SearchBase $source.Base -Server $Server `
                             -Properties gPLink, gPOptions, name, objectClass -ErrorAction Stop
            }
        }
        catch {
            Write-GpoLog -Level WARN -Message ("Could not scan '{0}' for links: {1}" -f $source.Base, $_.Exception.Message)
            continue
        }

        foreach ($object in @($objects)) {
            $links = ConvertFrom-GpLink -GpLink ([string]$object.gPLink)
            if ($links.Count -eq 0) { continue }

            $somType = 'OU'
            if ($object.objectClass -eq 'domainDNS')   { $somType = 'Domain' }
            elseif ($object.objectClass -eq 'site')    { $somType = 'Site'   }
            elseif ($source.Label -eq 'Site')          { $somType = 'Site'   }

            $somPath = ConvertTo-CanonicalPath -DistinguishedName $object.DistinguishedName
            if ($somType -eq 'Site') { $somPath = 'Sites/' + $object.name }

            $blocked = ((([int]$object.gPOptions) -band 1) -eq 1)

            [void]$containers.Add([pscustomobject]@{
                Name               = [string]$object.name
                Path               = $somPath
                Type               = $somType
                DistinguishedName  = [string]$object.DistinguishedName
                LinkCount          = $links.Count
                BlockedInheritance = $blocked
            })

            foreach ($link in $links) {
                $entry = [pscustomobject]@{
                    SomName            = [string]$object.name
                    SomPath            = $somPath
                    SomType            = $somType
                    Enabled            = $link.Enabled
                    Enforced           = $link.Enforced
                    LinkOrder          = $link.LinkOrder
                    BlockedInheritance = $blocked
                }
                if (-not $map.ContainsKey($link.GpoId)) { $map[$link.GpoId] = New-Object System.Collections.ArrayList }
                [void]$map[$link.GpoId].Add($entry)
            }
        }
    }

    return [pscustomobject]@{ Map = $map; Containers = $containers.ToArray() }
}

function Get-WmiFilterMap {
    [CmdletBinding()]
    param([string]$Server, [string]$DomainDN)

    $map = @{}
    try {
        $filters = Get-ADObject -LDAPFilter '(objectClass=msWMI-Som)' `
                                -SearchBase "CN=SOM,CN=WMIPolicy,CN=System,$DomainDN" -Server $Server `
                                -Properties 'msWMI-Name', 'msWMI-Parm1', 'msWMI-Parm2', 'Name' -ErrorAction Stop
    }
    catch {
        Write-GpoLog -Level WARN -Message ("WMI filter container unreadable: {0}" -f $_.Exception.Message)
        return $map
    }

    foreach ($filter in @($filters)) {
        $key = ([string]$filter.Name).ToUpper()
        $map[$key] = [pscustomobject]@{
            Name        = [string]$filter.'msWMI-Name'
            Description = [string]$filter.'msWMI-Parm1'
            Query       = [string]$filter.'msWMI-Parm2'
        }
    }
    Write-GpoLog -Level INFO -Message ("{0} WMI filter(s) found." -f $map.Count)
    return $map
}

function Resolve-GpoTrustee {
    param($IdentityReference)
    if ($null -eq $IdentityReference) { return $null }
    $key = $IdentityReference.Value
    if ($script:SidCache.ContainsKey($key)) { return $script:SidCache[$key] }

    $name = $key
    if ($IdentityReference -is [System.Security.Principal.SecurityIdentifier]) {
        try { $name = $IdentityReference.Translate([System.Security.Principal.NTAccount]).Value } catch { $name = $key }
    }
    $script:SidCache[$key] = $name
    return $name
}

function Get-GpoAclInfo {
    <# Apply / Deny / Delegation from the raw nTSecurityDescriptor. #>
    [CmdletBinding()]
    param($SecurityDescriptor)

    $apply      = New-Object System.Collections.ArrayList
    $deny       = New-Object System.Collections.ArrayList
    $delegation = New-Object System.Collections.ArrayList
    $seen       = @{}

    if ($null -eq $SecurityDescriptor) {
        return [pscustomobject]@{ Apply = @(); Deny = @(); Delegation = @(); Owner = $null }
    }

    $applyGuid    = [guid]'edacfd8f-ffb3-11d1-b41d-00a0c968f939'   # Apply Group Policy extended right
    $extendedBit  = [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight

    foreach ($ace in $SecurityDescriptor.Access) {
        $trustee = Resolve-GpoTrustee -IdentityReference $ace.IdentityReference
        if (-not $trustee) { continue }

        $isApply = ($ace.ObjectType -eq $applyGuid) -and (($ace.ActiveDirectoryRights -band $extendedBit) -eq $extendedBit)

        if ($isApply) {
            $entry = [pscustomobject]@{
                Trustee    = $trustee
                Permission = 'Apply Group Policy'
                Type       = [string]$ace.AccessControlType
                Inherited  = [bool]$ace.IsInherited
            }
            if ($ace.AccessControlType -eq 'Deny') { [void]$deny.Add($entry) } else { [void]$apply.Add($entry) }
            continue
        }

        $rights = [string]$ace.ActiveDirectoryRights
        $key    = '{0}|{1}|{2}' -f $trustee, $rights, $ace.AccessControlType
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true

        [void]$delegation.Add([pscustomobject]@{
            Trustee    = $trustee
            Permission = $rights
            Type       = [string]$ace.AccessControlType
            Inherited  = [bool]$ace.IsInherited
        })
    }

    $owner = $null
    try { $owner = [string]$SecurityDescriptor.Owner } catch { }

    return [pscustomobject]@{
        Apply      = ($apply | Sort-Object Trustee -Unique)
        Deny       = ($deny  | Sort-Object Trustee -Unique)
        Delegation = $delegation.ToArray()
        Owner      = $owner
    }
}

function Get-CseNameMap {
    <# Client-side extension GUID -> friendly name. Unknown GUIDs are reported verbatim. #>
    return @{
        '{35378EAC-683F-11D2-A89A-00C04FBBCFA2}' = 'Administrative Templates (Registry)'
        '{827D319E-6EAC-11D2-A4EA-00C04F79F83A}' = 'Security Settings'
        '{42B5FAAE-6536-11D2-AE5A-0000F87571E3}' = 'Scripts'
        '{25537BA6-77A8-11D2-9B6C-0000F8080861}' = 'Folder Redirection'
        '{C6DC5466-785A-11D2-84D0-00C04FB169F7}' = 'Software Installation'
        '{3610EDA5-77EF-11D2-8DC5-00C04FA31A66}' = 'Disk Quota'
        '{B1BE8D72-6EAC-11D2-A4EA-00C04F79F83A}' = 'EFS Recovery'
        '{A2E30F80-D7DE-11D2-BBDE-00C04F86AE3B}' = 'Internet Explorer Maintenance'
        '{0ACDD40C-75AC-47AB-BAA0-BF6DE7E7FE63}' = 'Wireless Network (802.11)'
        '{B587E2B1-4D59-4E7E-AED9-22B9DF11D053}' = 'Wired Network (802.3)'
        '{BEE07A6A-EC9F-4659-B8C9-0B1937907C83}' = 'Preferences: Registry'
        '{5794DAFD-BE60-433F-88A2-1A31939AC01F}' = 'Preferences: Drive Maps'
        '{17D89FEC-5C44-4972-B12D-241CAEF74509}' = 'Preferences: Local Users and Groups'
        '{91FBB303-0CD5-4055-BF42-E512A681B325}' = 'Preferences: Services'
        '{0E28E245-9368-4853-AD84-6DA3BA35BB75}' = 'Preferences: Environment'
        '{C418DD9D-0D14-4EFB-8FBF-CFE535C8FAC7}' = 'Preferences: Shortcuts'
        '{7150F9BF-48AD-4DA4-A49C-29EF4A8369BA}' = 'Preferences: Files'
        '{6232C319-91AC-4931-9385-E70C2B099F0E}' = 'Preferences: Folders'
        '{74EE6C03-5363-4554-B161-627540339CAB}' = 'Preferences: Ini Files'
        '{AADCED64-746C-4633-A97C-D61349046527}' = 'Preferences: Scheduled Tasks'
        '{E62688F0-25FD-4C90-BFF5-F508B9D2E31F}' = 'Preferences: Power Options'
        '{E5094040-C46C-4115-B030-04FB2E545B00}' = 'Preferences: Regional Options'
        '{E47248BA-94CC-49C4-BBB5-9EB7F05183D0}' = 'Preferences: Internet Settings'
        '{BC75B1ED-5833-4858-9BB8-CBF0B166DF9D}' = 'Preferences: Printers'
        '{728EE579-943C-4519-9EF7-AB56765798ED}' = 'Preferences: Data Sources'
        '{3A0DBA37-F8B2-4356-83DE-3E90BD5C261F}' = 'Preferences: Network Options'
    }
}

function Get-CseList {
    <# gPCMachineExtensionNames = [{CSE}{TOOL}][{CSE}{TOOL}{TOOL}] ... #>
    param([string]$ExtensionNames, [string]$Scope, [hashtable]$NameMap)

    $result = New-Object System.Collections.ArrayList
    if (-not $ExtensionNames) { return $result.ToArray() }

    foreach ($group in [regex]::Matches($ExtensionNames, '\[(?<body>[^\]]+)\]')) {
        $guids = [regex]::Matches($group.Groups['body'].Value, '\{[0-9A-Fa-f\-]{36}\}')
        if ($guids.Count -eq 0) { continue }
        $cse  = $guids[0].Value.ToUpper()
        $name = $cse
        if ($NameMap.ContainsKey($cse)) { $name = $NameMap[$cse] }
        [void]$result.Add([pscustomobject]@{ Scope = $Scope; Extension = $name; SettingCount = 0; Cse = $cse })
    }
    return $result.ToArray()
}

#endregion

#region ---------------------------------------------------------- SYSVOL parsers
# Everything below is self-contained (no module calls) so it can be injected into runspaces.

function Read-PolString {
    param([byte[]]$Bytes, [ref]$Position)
    $sb = New-Object System.Text.StringBuilder
    while ($Position.Value + 1 -lt $Bytes.Length) {
        $code = [System.BitConverter]::ToUInt16($Bytes, $Position.Value)
        $Position.Value += 2
        if ($code -eq 0) { break }
        [void]$sb.Append([char]$code)
    }
    return $sb.ToString()
}

function ConvertTo-PolTypeName {
    param([uint32]$Type)
    switch ($Type) {
        0       { 'REG_NONE' }
        1       { 'REG_SZ' }
        2       { 'REG_EXPAND_SZ' }
        3       { 'REG_BINARY' }
        4       { 'REG_DWORD' }
        7       { 'REG_MULTI_SZ' }
        11      { 'REG_QWORD' }
        default { "REG_TYPE_$Type" }
    }
}

function Read-GpoRegistryPol {
    <#
      MS-GPREG binary layout:
      "PReg" + version(4) then repeated  [ key\0 ; value\0 ; type(4) ; size(4) ; data ]
      All text is UTF-16LE.
    #>
    param([string]$Path, [string]$Scope, [int]$Limit = 0)

    $settings = New-Object System.Collections.ArrayList
    $bytes    = [System.IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -lt 8) { return $settings.ToArray() }
    if ([System.Text.Encoding]::ASCII.GetString($bytes, 0, 4) -ne 'PReg') {
        throw "Not a Registry.pol file (bad signature): $Path"
    }

    $pos = 8
    while ($pos + 1 -lt $bytes.Length) {
        if ($Limit -gt 0 -and $settings.Count -ge $Limit) { break }

        if ([System.BitConverter]::ToUInt16($bytes, $pos) -ne 0x5B) { $pos += 2; continue }   # '['
        $pos += 2

        $posRef = [ref]$pos
        $key    = Read-PolString -Bytes $bytes -Position $posRef
        $pos    = $posRef.Value
        $pos   += 2                                                                           # ';'

        $posRef = [ref]$pos
        $value  = Read-PolString -Bytes $bytes -Position $posRef
        $pos    = $posRef.Value
        $pos   += 2                                                                           # ';'

        if ($pos + 4 -gt $bytes.Length) { break }
        $type = [System.BitConverter]::ToUInt32($bytes, $pos); $pos += 4
        $pos += 2                                                                             # ';'
        if ($pos + 4 -gt $bytes.Length) { break }
        $size = [System.BitConverter]::ToUInt32($bytes, $pos); $pos += 4
        $pos += 2                                                                             # ';'

        if ($size -gt 0 -and $pos + $size -le $bytes.Length) {
            $data = New-Object byte[] $size
            [System.Array]::Copy($bytes, $pos, $data, 0, $size)
        } else {
            $data = New-Object byte[] 0
        }
        $pos += [int]$size
        $pos += 2                                                                             # ']'

        $decoded = $null
        switch ($type) {
            1  { $decoded = [System.Text.Encoding]::Unicode.GetString($data).TrimEnd([char]0) }
            2  { $decoded = [System.Text.Encoding]::Unicode.GetString($data).TrimEnd([char]0) }
            4  { if ($data.Length -ge 4) { $decoded = [System.BitConverter]::ToUInt32($data, 0) } }
            11 { if ($data.Length -ge 8) { $decoded = [System.BitConverter]::ToUInt64($data, 0) } }
            7  { $decoded = (([System.Text.Encoding]::Unicode.GetString($data)).Trim([char]0) -split "`0") -join ' | ' }
            default {
                if ($data.Length -gt 0) {
                    $take    = [Math]::Min(32, $data.Length)
                    $decoded = (($data[0..($take - 1)] | ForEach-Object { '{0:x2}' -f $_ }) -join ' ')
                    if ($data.Length -gt $take) { $decoded += ' ...' }
                }
            }
        }

        $state = 'Configured'
        if ($value -like '**del.*' -or $value -eq '**delvals.') { $state = 'Delete' }

        [void]$settings.Add([pscustomobject]@{
            Scope     = $Scope
            Extension = 'Administrative Templates (Registry)'
            Category  = $key
            Name      = $(if ($value) { $value } else { '(default)' })
            State     = ('{0} / {1}' -f $state, (ConvertTo-PolTypeName -Type $type))
            Value     = [string]$decoded
        })
    }
    return $settings.ToArray()
}

function Read-GpoIniFile {
    param([string]$Path)
    $result  = [ordered]@{}
    $section = '(root)'
    foreach ($line in [System.IO.File]::ReadAllLines($Path)) {
        $trimmed = $line.Trim()
        if (-not $trimmed -or $trimmed.StartsWith(';') -or $trimmed.StartsWith('#')) { continue }
        if ($trimmed -match '^\[(.+)\]$') {
            $section = $Matches[1]
            if (-not $result.Contains($section)) { $result[$section] = [ordered]@{} }
            continue
        }
        $idx = $trimmed.IndexOf('=')
        if ($idx -lt 1) { continue }
        if (-not $result.Contains($section)) { $result[$section] = [ordered]@{} }
        $result[$section][$trimmed.Substring(0, $idx).Trim()] = $trimmed.Substring($idx + 1).Trim()
    }
    return $result
}

function Read-GpoGptTmpl {
    param([string]$Path, [string]$Scope, [int]$Limit = 0)

    $settings = New-Object System.Collections.ArrayList
    $ini      = Read-GpoIniFile -Path $Path
    foreach ($section in $ini.Keys) {
        foreach ($key in $ini[$section].Keys) {
            if ($Limit -gt 0 -and $settings.Count -ge $Limit) { return $settings.ToArray() }
            $raw = [string]$ini[$section][$key]
            if ($raw.Length -gt 300) { $raw = $raw.Substring(0, 300) + '...' }
            [void]$settings.Add([pscustomobject]@{
                Scope     = $Scope
                Extension = 'Security Settings'
                Category  = $section
                Name      = $key
                State     = 'Configured'
                Value     = $raw
            })
        }
    }
    return $settings.ToArray()
}

function Read-GpoScriptsIni {
    param([string]$Path, [string]$Scope, [int]$Limit = 0)

    $settings = New-Object System.Collections.ArrayList
    $ini      = Read-GpoIniFile -Path $Path
    foreach ($section in $ini.Keys) {
        foreach ($key in $ini[$section].Keys) {
            if ($Limit -gt 0 -and $settings.Count -ge $Limit) { return $settings.ToArray() }
            [void]$settings.Add([pscustomobject]@{
                Scope     = $Scope
                Extension = 'Scripts'
                Category  = $section
                Name      = $key
                State     = 'Configured'
                Value     = [string]$ini[$section][$key]
            })
        }
    }
    return $settings.ToArray()
}

function Get-GppNodeValue {
    param([System.Xml.XmlNode]$Node, [int]$MaxLength = 250)
    $props = $Node.SelectSingleNode("*[local-name()='Properties']")
    if ($null -eq $props -or $null -eq $props.Attributes) { return $null }

    $pairs = @()
    $count = 0
    foreach ($attr in $props.Attributes) {
        if ($attr.LocalName -eq 'action') { continue }
        $pairs += ('{0}={1}' -f $attr.LocalName, $attr.Value)
        $count++
        if ($count -ge 6) { break }
    }
    if ($pairs.Count -eq 0) { return $null }
    $text = $pairs -join '; '
    if ($text.Length -gt $MaxLength) { $text = $text.Substring(0, $MaxLength) + '...' }
    return $text
}

function Read-GpoGppXml {
    param([string]$Path, [string]$Scope, [int]$Limit = 0)

    $settings = New-Object System.Collections.ArrayList
    $xml      = New-Object System.Xml.XmlDocument
    $xml.PreserveWhitespace = $false
    $xml.Load($Path)

    $root      = $xml.DocumentElement
    if ($null -eq $root) { return $settings.ToArray() }
    $extension = 'Preferences: ' + $root.LocalName

    $queue = New-Object System.Collections.Queue
    $queue.Enqueue($root)
    while ($queue.Count -gt 0) {
        if ($Limit -gt 0 -and $settings.Count -ge $Limit) { break }
        $node = $queue.Dequeue()

        foreach ($child in $node.ChildNodes) {
            if ($child.NodeType -ne [System.Xml.XmlNodeType]::Element) { continue }
            if ($child.LocalName -eq 'Properties' -or $child.LocalName -eq 'Filters') { continue }

            $name = $null
            if ($child.Attributes) {
                foreach ($attr in $child.Attributes) {
                    if ($attr.LocalName -eq 'name') { $name = $attr.Value; break }
                }
            }

            if ($name) {
                $state = $null
                foreach ($attr in $child.Attributes) {
                    if ($attr.LocalName -eq 'status') { $state = $attr.Value; break }
                }
                $props = $child.SelectSingleNode("*[local-name()='Properties']")
                if ($props -and $props.Attributes) {
                    foreach ($attr in $props.Attributes) {
                        if ($attr.LocalName -eq 'action') { $state = ('action={0}' -f $attr.Value); break }
                    }
                }
                [void]$settings.Add([pscustomobject]@{
                    Scope     = $Scope
                    Extension = $extension
                    Category  = $child.LocalName
                    Name      = $name
                    State     = $state
                    Value     = Get-GppNodeValue -Node $child
                })
            }
            else {
                $queue.Enqueue($child)
            }
        }
    }
    return $settings.ToArray()
}

function Get-GpoSysvolSetting {
    <#
      One recursive directory walk per GPO, then dispatch by file name.
      Returns settings, per-extension counts, file/byte totals and non-fatal errors.
    #>
    param([string]$Path, [int]$MaxSettings = 400)

    $settings = New-Object System.Collections.ArrayList
    $errors   = New-Object System.Collections.ArrayList
    $bytes    = 0
    $files    = @()

    try   { $files = @(Get-ChildItem -LiteralPath $Path -Recurse -File -Force -ErrorAction Stop) }
    catch { [void]$errors.Add("SYSVOL walk failed: $($_.Exception.Message)") }

    foreach ($file in $files) {
        if ($MaxSettings -gt 0 -and $settings.Count -ge $MaxSettings) { break }
        $bytes += $file.Length

        $scope = 'Unknown'
        if     ($file.FullName -match '(?i)\\Machine\\') { $scope = 'Computer' }
        elseif ($file.FullName -match '(?i)\\User\\')    { $scope = 'User' }

        $remaining = 0
        if ($MaxSettings -gt 0) { $remaining = $MaxSettings - $settings.Count }

        try {
            $parsed = @()
            switch -Regex ($file.Name) {
                '^(?i)registry\.pol$'      { $parsed = Read-GpoRegistryPol -Path $file.FullName -Scope $scope -Limit $remaining }
                '^(?i)gpttmpl\.inf$'       { $parsed = Read-GpoGptTmpl    -Path $file.FullName -Scope $scope -Limit $remaining }
                '^(?i)(ps)?scripts\.ini$'  { $parsed = Read-GpoScriptsIni -Path $file.FullName -Scope $scope -Limit $remaining }
                '(?i)\.xml$' {
                    if ($file.FullName -match '(?i)\\Preferences\\') {
                        $parsed = Read-GpoGppXml -Path $file.FullName -Scope $scope -Limit $remaining
                    }
                }
            }
            foreach ($item in @($parsed)) { [void]$settings.Add($item) }
        }
        catch {
            [void]$errors.Add(("{0}: {1}" -f $file.Name, $_.Exception.Message))
        }
    }

    $extensions = @($settings | Group-Object Scope, Extension | ForEach-Object {
        $parts = $_.Name -split ', ', 2
        [pscustomobject]@{ Scope = $parts[0]; Extension = $parts[1]; SettingCount = $_.Count }
    })

    return [pscustomobject]@{
        Settings   = $settings.ToArray()
        Extensions = $extensions
        Truncated  = ($MaxSettings -gt 0 -and $settings.Count -ge $MaxSettings)
        FileCount  = $files.Count
        ByteCount  = $bytes
        Errors     = $errors.ToArray()
    }
}

#endregion

#region ---------------------------------------------------------- SYSVOL phase

function Invoke-SysvolScan {
    <# Sequential or runspace-parallel SYSVOL scanning, with checkpoint cache. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Targets,     # objects with Id, Name, Path
        [int]$MaxSettings  = 400,
        [int]$Parallel     = 1,
        [int]$BatchSize    = 25,
        [string]$CachePath
    )

    $results = @{}

    # --- resume from checkpoint ------------------------------------------
    if ($CachePath -and (Test-Path -LiteralPath $CachePath)) {
        try {
            $cached = Get-Content -LiteralPath $CachePath -Raw -Encoding UTF8 | ConvertFrom-Json
            foreach ($property in $cached.PSObject.Properties) { $results[$property.Name] = $property.Value }
            Write-GpoLog -Level OK -Message ("Resume: {0} cached SYSVOL scan(s) reused." -f $results.Count)
        }
        catch {
            Write-GpoLog -Level WARN -Message ("SYSVOL cache unreadable, starting fresh: {0}" -f $_.Exception.Message)
        }
    }

    $pending = @($Targets | Where-Object { -not $results.ContainsKey($_.Id) })
    if ($pending.Count -eq 0) { return $results }
    Write-GpoLog -Level INFO -Message ("SYSVOL scan: {0} GPO folder(s) to read, parallelism {1}." -f $pending.Count, $Parallel)

    $done = 0
    $save = {
        param($Path, $Data)
        if (-not $Path) { return }
        try {
            $json = $Data | ConvertTo-Json -Depth 12
            [System.IO.File]::WriteAllText($Path, $json, (New-Object System.Text.UTF8Encoding($false)))
        }
        catch { Write-GpoLog -Level WARN -Message ("Checkpoint write failed: {0}" -f $_.Exception.Message) }
    }

    if ($Parallel -le 1) {
        # ---------------- sequential ---------------------------------------
        foreach ($target in $pending) {
            $done++
            Write-Progress -Id 2 -ParentId 1 -Activity 'Reading SYSVOL' `
                           -Status ('[{0}/{1}] {2}' -f $done, $pending.Count, $target.Name) `
                           -PercentComplete (($done / [double]$pending.Count) * 100)
            try   { $results[$target.Id] = Get-GpoSysvolSetting -Path $target.Path -MaxSettings $MaxSettings }
            catch { $results[$target.Id] = [pscustomobject]@{ Settings = @(); Extensions = @(); Truncated = $false; FileCount = 0; ByteCount = 0; Errors = @($_.Exception.Message) } }

            if ($BatchSize -gt 0 -and ($done % $BatchSize) -eq 0) { & $save $CachePath $results }
        }
    }
    else {
        # ---------------- runspace pool ------------------------------------
        $functionNames = @('Read-PolString','ConvertTo-PolTypeName','Read-GpoRegistryPol','Read-GpoIniFile',
                           'Read-GpoGptTmpl','Read-GpoScriptsIni','Get-GppNodeValue','Read-GpoGppXml','Get-GpoSysvolSetting')
        $preamble = New-Object System.Text.StringBuilder
        foreach ($functionName in $functionNames) {
            $definition = (Get-Command $functionName -CommandType Function).Definition
            [void]$preamble.AppendLine(('function {0} {{{1}}}' -f $functionName, $definition))
        }
        $body = $preamble.ToString() + "`nGet-GpoSysvolSetting -Path `$args[0] -MaxSettings `$args[1]"

        $pool = [runspacefactory]::CreateRunspacePool(1, $Parallel)
        $pool.ApartmentState = 'MTA'
        $pool.Open()

        $jobs = New-Object System.Collections.ArrayList
        try {
            foreach ($target in $pending) {
                $shell = [powershell]::Create()
                $shell.RunspacePool = $pool
                [void]$shell.AddScript($body).AddArgument($target.Path).AddArgument($MaxSettings)
                [void]$jobs.Add([pscustomobject]@{
                    Id     = $target.Id
                    Name   = $target.Name
                    Shell  = $shell
                    Handle = $shell.BeginInvoke()
                })
            }

            while ($done -lt $jobs.Count) {
                Start-Sleep -Milliseconds 200
                foreach ($job in $jobs) {
                    if ($job.Handle -and $job.Handle.IsCompleted -and -not $results.ContainsKey($job.Id)) {
                        try {
                            $output = $job.Shell.EndInvoke($job.Handle)
                            $value  = @($output)[0]
                            if ($null -eq $value) {
                                $value = [pscustomobject]@{ Settings = @(); Extensions = @(); Truncated = $false; FileCount = 0; ByteCount = 0; Errors = @('empty result') }
                            }
                            $results[$job.Id] = $value
                        }
                        catch {
                            $results[$job.Id] = [pscustomobject]@{ Settings = @(); Extensions = @(); Truncated = $false; FileCount = 0; ByteCount = 0; Errors = @($_.Exception.Message) }
                        }
                        finally { $job.Shell.Dispose() }

                        $done++
                        Write-Progress -Id 2 -ParentId 1 -Activity ('Reading SYSVOL ({0} runspaces)' -f $Parallel) `
                                       -Status ('[{0}/{1}] {2}' -f $done, $jobs.Count, $job.Name) `
                                       -PercentComplete (($done / [double]$jobs.Count) * 100)
                        if ($BatchSize -gt 0 -and ($done % $BatchSize) -eq 0) { & $save $CachePath $results }
                    }
                }
            }
        }
        finally {
            foreach ($job in $jobs) { try { $job.Shell.Dispose() } catch { } }
            $pool.Close(); $pool.Dispose()
        }
    }

    Write-Progress -Id 2 -Activity 'Reading SYSVOL' -Completed
    & $save $CachePath $results
    return $results
}

#endregion

#region ---------------------------------------------------------- main

function Get-GpoInventoryFromAd {
    [CmdletBinding()]
    param(
        [string]$Domain            = 'ad.net',
        [Parameter(Mandatory)][string]$OutputFolder,
        [string]$NameFilter        = '*',
        [int]   $BatchSize         = 25,
        [int]   $MaxSettingsPerGpo = 400,
        [int]   $Parallel          = 1,
        [switch]$Resume,
        [switch]$SkipSettings
    )

    $started = Get-Date
    if (-not (Test-Path -LiteralPath $OutputFolder)) { New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null }

    $runStamp          = $started.ToString('yyyyMMdd_HHmmss')
    $script:GpoLogFile = Join-Path $OutputFolder ('GpoReportAD_{0}.log' -f $runStamp)
    $jsonPath          = Join-Path $OutputFolder 'GpoReport.json'
    $errorPath         = Join-Path $OutputFolder 'GpoReport.errors.json'
    $perfPath          = Join-Path $OutputFolder 'GpoReport.performance.json'
    $cachePath         = Join-Path $OutputFolder 'sysvol_cache.json'
    if (-not $Resume -and (Test-Path -LiteralPath $cachePath)) { Remove-Item -LiteralPath $cachePath -Force }

    Write-GpoLog -Level INFO -Message "=== GPO inventory (AD-only mode) started - domain $Domain ==="

    # --- phase 0: prerequisites ------------------------------------------
    $context  = Measure-GpoPhase -Name '0. Prerequisites' -Script { Test-AdPrerequisite -Domain $Domain }
    $adDomain = $context.AdDomain
    $server   = $adDomain.DNSRoot
    $domainDN = $adDomain.DistinguishedName
    $configDN = "CN=Configuration,$domainDN"
    try { $configDN = (Get-ADRootDSE -Server $server).configurationNamingContext } catch { }

    $errors = New-Object System.Collections.ArrayList

    # --- phase 1: GPO objects (one LDAP round trip) ----------------------
    $gpoObjects = Measure-GpoPhase -Name '1. LDAP: groupPolicyContainer objects' -Script {
        Invoke-GpoRetry -Activity 'GPO query' -Script {
            Get-ADObject -LDAPFilter '(objectClass=groupPolicyContainer)' `
                         -SearchBase "CN=Policies,CN=System,$domainDN" -Server $server `
                         -Properties displayName, gPCFileSysPath, flags, versionNumber, whenCreated, whenChanged,
                                     gPCMachineExtensionNames, gPCUserExtensionNames, gPCWQLFilter,
                                     nTSecurityDescriptor, Name -ErrorAction Stop
        }
    }
    $gpoObjects = @($gpoObjects | Where-Object { $_.displayName -like $NameFilter } | Sort-Object displayName)
    Write-GpoLog -Level OK -Message ("{0} GPO object(s) after filter '{1}'." -f $gpoObjects.Count, $NameFilter)
    if ($gpoObjects.Count -eq 0) { throw "No GPOs found in CN=Policies,CN=System,$domainDN" }

    # --- phase 2: links ---------------------------------------------------
    $linkData = Measure-GpoPhase -Name '2. LDAP: gPLink scan (domain, OUs, sites)' -Script {
        Get-GpoLinkMap -Server $server -DomainDN $domainDN -ConfigDN $configDN
    }
    $linkMap = $linkData.Map

    # --- phase 3: WMI filters --------------------------------------------
    $wmiMap = Measure-GpoPhase -Name '3. LDAP: WMI filters' -Script {
        Get-WmiFilterMap -Server $server -DomainDN $domainDN
    }

    # --- phase 4: ACL parsing (in memory) --------------------------------
    $cseMap  = Get-CseNameMap
    $aclData = @{}
    Measure-GpoPhase -Name '4. Security descriptors + SID resolution' -Script {
        $index = 0
        foreach ($object in $gpoObjects) {
            $index++
            if (($index % 20) -eq 0 -or $index -eq $gpoObjects.Count) {
                Write-Progress -Id 1 -Activity 'Parsing security descriptors' `
                               -Status ('{0}/{1} - {2} unique SID(s) cached' -f $index, $gpoObjects.Count, $script:SidCache.Count) `
                               -PercentComplete (($index / [double]$gpoObjects.Count) * 100)
            }
            try   { $aclData[[string]$object.Name] = Get-GpoAclInfo -SecurityDescriptor $object.nTSecurityDescriptor }
            catch {
                $aclData[[string]$object.Name] = $null
                [void]$errors.Add([pscustomobject]@{
                    Gpo = [string]$object.displayName; Id = [string]$object.Name
                    Stage = 'SecurityDescriptor'; Message = $_.Exception.Message; TimeStamp = (Get-Date).ToString('s')
                })
            }
        }
        Write-Progress -Id 1 -Activity 'Parsing security descriptors' -Completed
    } | Out-Null

    # --- phase 5: SYSVOL --------------------------------------------------
    $sysvolResults = @{}
    if (-not $SkipSettings -and $context.SysvolAvailable) {
        $targets = @($gpoObjects | ForEach-Object {
            [pscustomobject]@{ Id = [string]$_.Name; Name = [string]$_.displayName; Path = [string]$_.gPCFileSysPath }
        } | Where-Object { $_.Path })

        $sysvolResults = Measure-GpoPhase -Name ('5. SYSVOL parsing ({0} runspace(s))' -f $Parallel) -Script {
            Invoke-SysvolScan -Targets $targets -MaxSettings $MaxSettingsPerGpo -Parallel $Parallel `
                              -BatchSize $BatchSize -CachePath $cachePath
        }
    }
    else {
        Write-GpoLog -Level WARN -Message 'SYSVOL phase skipped - settings will be empty (CSE list still reported).'
    }

    # --- phase 6: assemble ------------------------------------------------
    $records = Measure-GpoPhase -Name '6. Assemble records' -Script {
        $list  = New-Object System.Collections.ArrayList
        $index = 0

        foreach ($object in $gpoObjects) {
            $index++
            Write-Progress -Id 1 -Activity 'Assembling report' -Status ('{0}/{1}' -f $index, $gpoObjects.Count) `
                           -PercentComplete (($index / [double]$gpoObjects.Count) * 100)

            $id        = [string]$object.Name
            $gpoErrors = New-Object System.Collections.ArrayList

            $version    = 0
            try { $version = [int]$object.versionNumber } catch { }
            $computerDs = $version -band 0xFFFF
            $userDs     = ($version -shr 16) -band 0xFFFF

            $links = @()
            if ($linkMap.ContainsKey($id.ToUpper())) { $links = @($linkMap[$id.ToUpper()].ToArray()) }

            $acl = $null
            if ($aclData.ContainsKey($id)) { $acl = $aclData[$id] }

            $applyList = @(); $denyList = @(); $delegationList = @(); $owner = $null
            if ($acl) {
                $applyList      = @($acl.Apply)
                $denyList       = @($acl.Deny)
                $delegationList = @($acl.Delegation)
                $owner          = $acl.Owner
            }

            $wmiName = $null; $wmiDescription = $null; $wmiQuery = $null
            $wmiMatch = [regex]::Match([string]$object.gPCWQLFilter, '\{[0-9A-Fa-f\-]{36}\}')
            if ($wmiMatch.Success) {
                $wmiKey = $wmiMatch.Value.ToUpper()
                if ($wmiMap.ContainsKey($wmiKey)) {
                    $wmiName        = $wmiMap[$wmiKey].Name
                    $wmiDescription = $wmiMap[$wmiKey].Description
                    $wmiQuery       = $wmiMap[$wmiKey].Query
                }
                else { $wmiName = $wmiKey }
            }

            $cseList = @()
            $cseList += Get-CseList -ExtensionNames ([string]$object.gPCMachineExtensionNames) -Scope 'Computer' -NameMap $cseMap
            $cseList += Get-CseList -ExtensionNames ([string]$object.gPCUserExtensionNames)    -Scope 'User'     -NameMap $cseMap

            $settingList = @(); $extensionList = $cseList; $truncated = $false
            $fileCount   = 0;  $byteCount     = 0
            if ($sysvolResults.ContainsKey($id)) {
                $scan = $sysvolResults[$id]
                $settingList = @($scan.Settings)
                $truncated   = [bool]$scan.Truncated
                $fileCount   = [int]$scan.FileCount
                $byteCount   = [int]$scan.ByteCount
                if (@($scan.Extensions).Count -gt 0) { $extensionList = @($scan.Extensions) }
                foreach ($message in @($scan.Errors)) {
                    [void]$gpoErrors.Add($message)
                    [void]$errors.Add([pscustomobject]@{
                        Gpo = [string]$object.displayName; Id = $id
                        Stage = 'SYSVOL'; Message = $message; TimeStamp = (Get-Date).ToString('s')
                    })
                }
            }

            $created  = $null; $modified = $null
            if ($object.whenCreated) { $created  = ([datetime]$object.whenCreated).ToString('s') }
            if ($object.whenChanged) { $modified = ([datetime]$object.whenChanged).ToString('s') }

            [void]$list.Add([pscustomobject]@{
                Name                  = [string]$object.displayName
                Id                    = $id
                Domain                = $server
                Owner                 = $owner
                GpoStatus             = ConvertTo-GpoStatusText -Flags ([int]$object.flags)
                Description           = $null
                CreationTime          = $created
                ModificationTime      = $modified
                ComputerDSVersion     = $computerDs
                ComputerSysvolVersion = $computerDs
                UserDSVersion         = $userDs
                UserSysvolVersion     = $userDs
                WmiFilterName         = $wmiName
                WmiFilterDescription  = $wmiDescription
                WmiFilterQuery        = $wmiQuery
                LinkCount             = $links.Count
                IsLinked              = ($links.Count -gt 0)
                HasEnabledLink        = (@($links | Where-Object { $_.Enabled }).Count -gt 0)
                Links                 = $links
                SecurityFiltering     = $applyList
                DeniedFiltering       = $denyList
                Delegation            = $delegationList
                Extensions            = $extensionList
                Settings              = $settingList
                SettingCount          = $settingList.Count
                SettingsTruncated     = $truncated
                IsEmpty               = (($computerDs -eq 0) -and ($userDs -eq 0))
                SysvolPath            = [string]$object.gPCFileSysPath
                SysvolFileCount       = $fileCount
                SysvolBytes           = $byteCount
                RawXmlPath            = $null
                SourceMode            = 'ActiveDirectory+SYSVOL'
                HasError              = ($gpoErrors.Count -gt 0)
                Errors                = $gpoErrors.ToArray()
            })
        }
        Write-Progress -Id 1 -Activity 'Assembling report' -Completed
        return $list.ToArray()
    }

    # --- phase 7: write ---------------------------------------------------
    $duration = (Get-Date) - $started
    $report = [pscustomobject]@{
        Metadata = [pscustomobject]@{
            Domain          = $server
            Mode            = 'ActiveDirectory+SYSVOL'
            GeneratedOn     = (Get-Date).ToString('s')
            GeneratedBy     = "$env:USERDOMAIN\$env:USERNAME"
            ComputerName    = $env:COMPUTERNAME
            ToolVersion     = $script:GpoToolVersion
            DurationSeconds = [Math]::Round($duration.TotalSeconds, 1)
            GpoCount        = @($records).Count
            ErrorCount      = $errors.Count
            SettingsSkipped = [bool]$SkipSettings
            Parallelism     = $Parallel
            UniqueTrustees  = $script:SidCache.Count
            Phases          = $script:Phases.ToArray()
        }
        Containers = $linkData.Containers
        Errors     = $errors.ToArray()
        Gpos       = @($records)
    }

    Measure-GpoPhase -Name '7. Write JSON' -Script {
        $json = $report | ConvertTo-Json -Depth 12
        [System.IO.File]::WriteAllText($jsonPath, $json, (New-Object System.Text.UTF8Encoding($false)))
    } | Out-Null

    if ($errors.Count -gt 0) {
        $errorJson = $errors.ToArray() | ConvertTo-Json -Depth 5
        [System.IO.File]::WriteAllText($errorPath, $errorJson, (New-Object System.Text.UTF8Encoding($false)))
        Write-GpoLog -Level WARN -Message ("{0} issue(s) recorded - see {1}" -f $errors.Count, $errorPath)
    }

    $perfJson = $script:Phases.ToArray() | ConvertTo-Json -Depth 5
    [System.IO.File]::WriteAllText($perfPath, $perfJson, (New-Object System.Text.UTF8Encoding($false)))

    Show-GpoPerformanceSummary -Records $records -Duration $duration
    Write-GpoLog -Level OK -Message "JSON written: $jsonPath"
    return $jsonPath
}

function Show-GpoPerformanceSummary {
    [CmdletBinding()]
    param([object[]]$Records, [timespan]$Duration)

    $totalSettings = ($Records | Measure-Object -Property SettingCount -Sum).Sum
    $totalFiles    = ($Records | Measure-Object -Property SysvolFileCount -Sum).Sum
    $totalBytes    = ($Records | Measure-Object -Property SysvolBytes -Sum).Sum
    $perGpo        = 0
    if (@($Records).Count -gt 0) { $perGpo = $Duration.TotalSeconds / @($Records).Count }

    Write-Host ''
    Write-Host 'Phase timings' -ForegroundColor Cyan
    $script:Phases.ToArray() | Format-Table Phase, Seconds, Status -AutoSize | Out-Host

    Write-Host 'Throughput' -ForegroundColor Cyan
    Write-Host ('  GPOs              : {0}'            -f @($Records).Count)
    Write-Host ('  Total runtime     : {0:n1} s'       -f $Duration.TotalSeconds)
    Write-Host ('  Per GPO           : {0:n3} s'       -f $perGpo)
    Write-Host ('  Settings parsed   : {0}'            -f $totalSettings)
    Write-Host ('  SYSVOL files read : {0}'            -f $totalFiles)
    Write-Host ('  SYSVOL bytes read : {0:n1} MB'      -f ($totalBytes / 1MB))
    Write-Host ('  Unique trustees   : {0} (SID cache hits saved ~{1} LSA lookups)' -f $script:SidCache.Count, [Math]::Max(0, ($Records.Count * 5 - $script:SidCache.Count)))
    Write-Host ''
}

#endregion

if ($MyInvocation.InvocationName -ne '.') {
    $json = Get-GpoInventoryFromAd -Domain $Domain -OutputFolder $OutputFolder -NameFilter $NameFilter `
                                   -BatchSize $BatchSize -MaxSettingsPerGpo $MaxSettingsPerGpo `
                                   -Parallel $Parallel -Resume:$Resume -SkipSettings:$SkipSettings

    # Reuse the converters from the GroupPolicy edition when available - identical schema.
    if (-not $ConverterScript) {
        $candidate = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'Get-GpoReport.ps1'
        if (Test-Path -LiteralPath $candidate) { $ConverterScript = $candidate }
    }
    if ($ConverterScript -and (Test-Path -LiteralPath $ConverterScript)) {
        . $ConverterScript
        ConvertTo-GpoCsv  -JsonPath $json -Scope PerLink | Out-Null
        ConvertTo-GpoCsv  -JsonPath $json -Scope PerGpo  | Out-Null
        ConvertTo-GpoHtml -JsonPath $json               | Out-Null
        Write-Host "CSV and HTML generated via $ConverterScript" -ForegroundColor Cyan
    }
    else {
        Write-Host "JSON only: $json" -ForegroundColor Cyan
        Write-Host 'Point -ConverterScript at Get-GpoReport.ps1 to also get CSV and HTML.' -ForegroundColor Gray
    }
}
else {
    Write-Host 'AD-only GPO functions loaded: Get-GpoInventoryFromAd, Invoke-SysvolScan, Get-GpoSysvolSetting, Read-GpoRegistryPol' -ForegroundColor Cyan
}
