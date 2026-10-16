[CmdletBinding(DefaultParameterSetName = 'Deploy')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Deploy')]
    [ValidatePattern('^MS=[A-Za-z0-9-]+$')]
    [string]$VerificationTxtValue,
    [Parameter(ParameterSetName = 'Deploy')]
    [switch]$Apply,
    [Parameter(ParameterSetName = 'CheckOnly')]
    [switch]$CheckOnly
)

$ErrorActionPreference = 'Stop'

function Read-LeafNamedTxtRecords {
    param([System.Collections.IDictionary]$Source)
    $records = [Collections.Generic.List[object]]::new()
    $names = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    if (-not $Source.Contains('namedTxtRecords')) { return $records.ToArray() }
    foreach ($record in @($Source.namedTxtRecords)) {
        $name = [string]$record.name
        $values = @($record.values | ForEach-Object { [string]$_ })
        if ($name.Length -gt 253 -or $name -notmatch '^[A-Za-z0-9_](?:[A-Za-z0-9_.-]*[A-Za-z0-9_])?$' -or $name.Contains('..') -or -not $names.Add($name)) { throw 'Invalid or duplicate non-apex TXT owner name.' }
        if ($values.Count -eq 0 -or @($values | Sort-Object -CaseSensitive -Unique).Count -ne $values.Count) { throw 'Named TXT values must be complete, non-empty, and unique.' }
        foreach ($value in $values) {
            if ([string]::IsNullOrWhiteSpace($value) -or [Text.Encoding]::UTF8.GetByteCount($value) -gt 255 -or $value -match '[\r\n]') { throw 'Each named TXT value must be one non-empty string of at most 255 UTF-8 bytes.' }
        }
        if ($name -ieq '_dmarc' -and ($values.Count -ne 1 -or $values[0] -notmatch '^v=DMARC1;\s*p=(none|quarantine|reject)(;|$)')) { throw 'DMARC must be one reviewed policy value with a valid version and policy.' }
        $records.Add([ordered]@{ name = $name.ToLowerInvariant(); values = $values })
    }
    return $records.ToArray()
}

function Test-LeafNamedTxtValues {
    param($Current, [string[]]$Desired)
    if (-not $Current) { return $false }
    $values = @($Current.Records | ForEach-Object { [string]::Join('', [string[]]$_.Value) } | Sort-Object -CaseSensitive)
    return @(Compare-Object $values @($Desired | Sort-Object -CaseSensitive) -CaseSensitive).Count -eq 0
}

if ($CheckOnly) {
    $valid = @{ namedTxtRecords = @(@{ name = '_dmarc'; values = @('v=DMARC1; p=none') }) }
    $records = @(Read-LeafNamedTxtRecords $valid)
    if ($records.Count -ne 1 -or @(Read-LeafNamedTxtRecords @{}).Count -ne 0) { throw 'Named TXT parsing failed.' }
    $current = [pscustomobject]@{ Records = @([pscustomobject]@{ Value = @('v=DMARC1; ', 'p=none') }) }
    if (-not (Test-LeafNamedTxtValues $current @('v=DMARC1; p=none')) -or (Test-LeafNamedTxtValues $current @('v=DMARC1; p=reject'))) { throw 'Named TXT comparison must preserve exact record values and join DNS string segments.' }
    foreach ($invalid in @(
        @{ namedTxtRecords = @(@{ name = '@'; values = @('value') }) },
        @{ namedTxtRecords = @(@{ name = '_dmarc'; values = @('invalid') }) },
        @{ namedTxtRecords = @(@{ name = '_test'; values = @('A' * 256) }) },
        @{ namedTxtRecords = @(@{ name = '_same'; values = @('one') }, @{ name = '_SAME'; values = @('two') }) }
    )) {
        $rejected = $false
        try { $null = Read-LeafNamedTxtRecords $invalid } catch { $rejected = $true }
        if (-not $rejected) { throw 'Invalid named TXT input was accepted.' }
    }
    'PASS: optional named TXT, duplicate/conflict detection, DNS segmentation, and DMARC shape; no target inputs or cloud access.'
    return
}

$repo = Split-Path $PSScriptRoot -Parent
$requiredPrivatePath = 'private/dns'
git -C $repo check-ignore --quiet -- $requiredPrivatePath
if ($LASTEXITCODE -ne 0) { throw 'Deployment evidence must be ignored.' }
$tracked = @(git -C $repo ls-files -- .env private)
if ($LASTEXITCODE -ne 0 -or $tracked.Count) { throw 'Private paths must be untracked.' }
$recordsPath = Join-Path $repo 'private/dns/records.json'
git -C $repo check-ignore --quiet -- private/dns/records.json
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $recordsPath)) { throw 'Private DNS desired-state file is missing or not ignored.' }
$recordSource = [IO.File]::ReadAllText($recordsPath) | ConvertFrom-Json -AsHashtable
$namedTxtRecords = @(Read-LeafNamedTxtRecords $recordSource)
if ([int]$recordSource.ttl -ne 3600) { throw 'CSV DNS records must use the reviewed 3600-second TTL.' }
$mxRecordInputs = @($recordSource.mxRecords | ForEach-Object { [ordered]@{ preference = [int]$_.preference; exchange = [string]$_.exchange } })
$cnameRecords = @($recordSource.cnameRecords | ForEach-Object { [ordered]@{ name = [string]$_.name; canonicalName = [string]$_.canonicalName } })
$apexTxtInputs = @($recordSource.apexTxtValues | ForEach-Object { [string]$_ } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
if (-not $mxRecordInputs.Count -or -not $cnameRecords.Count -or -not $apexTxtInputs.Count) { throw 'Private DNS desired state must include MX, CNAME, and apex TXT records.' }
if (@($cnameRecords | ForEach-Object name | Sort-Object -Unique).Count -ne $cnameRecords.Count) { throw 'Duplicate CNAME owner names in private DNS desired state.' }
if (@($namedTxtRecords | Where-Object { $_.name -in @($cnameRecords | ForEach-Object name) }).Count -gt 0) { throw 'A CNAME cannot share an owner name with a named TXT set.' }
foreach ($record in $mxRecordInputs) { if ($record.preference -lt 0 -or $record.preference -gt 65535 -or [string]::IsNullOrWhiteSpace($record.exchange)) { throw 'Invalid MX record in private DNS desired state.' } }
foreach ($record in $cnameRecords) { if ([string]::IsNullOrWhiteSpace($record.name) -or [string]::IsNullOrWhiteSpace($record.canonicalName)) { throw 'Invalid CNAME record in private DNS desired state.' } }

$settings = @{}
$required = @('TARGET_TENANT_ID', 'TARGET_SUBSCRIPTION_ID', 'TARGET_WORKLOAD', 'TARGET_LOCATION', 'TARGET_REGION_CODE', 'TARGET_INSTANCE', 'TARGET_DNS_ZONE_NAME')
foreach ($line in [IO.File]::ReadAllLines((Join-Path $repo '.env'))) {
    $match = [regex]::Match($line, '^\s*(?<key>[A-Z][A-Z0-9_]*)\s*=\s*(?<value>.*)$')
    if (-not $match.Success -or $match.Groups['key'].Value -notin $required) { continue }
    $key = $match.Groups['key'].Value
    if ($settings.ContainsKey($key)) { throw 'Duplicate required target setting.' }
    $settings[$key] = $match.Groups['value'].Value.Trim().Trim([char[]]@([char]34, [char]39))
}
foreach ($key in $required) {
    if ([string]::IsNullOrWhiteSpace($settings[$key])) { throw 'Required private target setting is missing.' }
}
if ($settings.TARGET_LOCATION -eq 'swedencentral' -and $settings.TARGET_REGION_CODE -ne 'swc' -or $settings.TARGET_LOCATION -eq 'germanywestcentral' -and $settings.TARGET_REGION_CODE -ne 'gwc' -or $settings.TARGET_LOCATION -notin @('swedencentral', 'germanywestcentral')) {
    throw 'Target region or CAF naming code violates the approved region policy.'
}
foreach ($key in @('TARGET_TENANT_ID', 'TARGET_SUBSCRIPTION_ID')) {
    $parsed = [guid]::Empty
    if (-not [guid]::TryParse($settings[$key], [ref]$parsed) -or $parsed -eq [guid]::Empty) { throw 'Invalid private target identity.' }
    $settings[$key] = $parsed.ToString()
}
if ($settings.TARGET_WORKLOAD -ne 'infra') { throw 'Foundation deployment requires TARGET_WORKLOAD=infra.' }

$context = Get-AzContext
if (-not $context -or $context.Tenant.Id -ne $settings.TARGET_TENANT_ID -or $context.Subscription.Id -ne $settings.TARGET_SUBSCRIPTION_ID) {
    throw 'Authenticate explicitly to the configured target tenant and subscription before deployment.'
}
$subscription = @(Get-AzSubscription -SubscriptionId $settings.TARGET_SUBSCRIPTION_ID -TenantId $settings.TARGET_TENANT_ID -DefaultProfile $context)
if ($subscription.Count -ne 1 -or $subscription[0].State -ne 'Enabled') { throw 'Target subscription is not uniquely verified and enabled.' }
$providerStates = @(Get-AzResourceProvider -ProviderNamespace Microsoft.Network -DefaultProfile $context | Select-Object -ExpandProperty RegistrationState -Unique)
if ($providerStates.Count -ne 1 -or $providerStates[0] -ne 'Registered') { throw 'Microsoft.Network must be Registered before deployment.' }
$locations = @(Get-AzLocation -DefaultProfile $context)
if (@($locations | Where-Object Location -eq $settings.TARGET_LOCATION).Count -ne 1) { throw 'Selected region is not in the subscription location catalog.' }

$resourceGroupName = 'rg-{0}-{1}-{2}' -f $settings.TARGET_WORKLOAD, $settings.TARGET_REGION_CODE, $settings.TARGET_INSTANCE
$existingTxtValues = @()
$existingGroup = Get-AzResourceGroup -Name $resourceGroupName -DefaultProfile $context -ErrorAction SilentlyContinue
$existingZone = $null
$existingTxtSet = $null
$existingMxSet = $null
$existingCnameSets = @{}
$existingNamedTxtSets = @{}
if ($existingGroup) {
    $existingZone = Get-AzDnsZone -ResourceGroupName $resourceGroupName -Name $settings.TARGET_DNS_ZONE_NAME -DefaultProfile $context -ErrorAction SilentlyContinue
    if ($existingZone) {
        Import-Module Az.Dns -MinimumVersion 2.0.0
        $existingTxtSet = Get-AzDnsRecordSet -ResourceGroupName $resourceGroupName -ZoneName $settings.TARGET_DNS_ZONE_NAME -RecordType TXT -Name '@' -DefaultProfile $context -ErrorAction SilentlyContinue
        $existingMxSet = Get-AzDnsRecordSet -ResourceGroupName $resourceGroupName -ZoneName $settings.TARGET_DNS_ZONE_NAME -RecordType MX -Name '@' -DefaultProfile $context -ErrorAction SilentlyContinue
        if ($existingTxtSet) { $existingTxtValues = @($existingTxtSet.Records | ForEach-Object Value | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) }
        foreach ($record in $cnameRecords) {
            $existingCnameSets[$record.name] = Get-AzDnsRecordSet -ResourceGroupName $resourceGroupName -ZoneName $settings.TARGET_DNS_ZONE_NAME -RecordType CNAME -Name $record.name -DefaultProfile $context -ErrorAction SilentlyContinue
        }
        foreach ($record in $namedTxtRecords) {
            $currentSet = Get-AzDnsRecordSet -ResourceGroupName $resourceGroupName -ZoneName $settings.TARGET_DNS_ZONE_NAME -RecordType TXT -Name $record.name -DefaultProfile $context -ErrorAction SilentlyContinue
            if ($currentSet -and -not (Test-LeafNamedTxtValues $currentSet $record.values)) { throw 'An existing named TXT set conflicts with reviewed desired state; no deployment performed.' }
            $existingNamedTxtSets[$record.name] = $currentSet
        }
    }
}
$existingMxRecords = if ($existingMxSet) { @($existingMxSet.Records | ForEach-Object { [ordered]@{ preference = [int]$_.Preference; exchange = [string]$_.Exchange } }) } else { @() }
$mxByKey = @{}
foreach ($record in $existingMxRecords) { $mxByKey[('{0}|{1}' -f $record.preference, $record.exchange)] = $record }
foreach ($record in $mxRecordInputs) { $mxByKey[('{0}|{1}' -f $record.preference, $record.exchange)] = $record }
$mxRecords = @($mxByKey.Keys | Sort-Object | ForEach-Object { $mxByKey[$_] })
$verificationTxtValues = @(@($existingTxtValues) + $apexTxtInputs + $VerificationTxtValue | Select-Object -Unique)
$parameters = @{
    resourceGroupName = $resourceGroupName
    location = $settings.TARGET_LOCATION
    zoneName = $settings.TARGET_DNS_ZONE_NAME
    verificationTxtValues = $verificationTxtValues
    mxRecords = $mxRecords
    cnameRecords = $cnameRecords
    namedTxtRecords = $namedTxtRecords
    tags = @{ workload = 'infra'; 'managed-by' = 'bicep' }
}
if ($existingGroup -and $existingZone) {
    if ($existingZone.Tags.workload -ne 'infra' -or $existingZone.Tags.'managed-by' -ne 'bicep') { throw 'Existing zone tags differ from the expected owned state; no deployment performed.' }
    $desiredTxtValues = @(@($existingTxtValues) + $apexTxtInputs + $VerificationTxtValue | Select-Object -Unique)
    $txtAdded = @($desiredTxtValues | Where-Object { $_ -notin $existingTxtValues })
    $plannedCreates = 0
    $plannedModifications = 0
    if ($txtAdded.Count -gt 0 -or ($existingTxtSet -and [int]$existingTxtSet.Ttl -ne [int]$recordSource.ttl)) {
        if ($existingTxtSet) {
            $desiredTxtSet = $existingTxtSet
            $desiredTxtSet.Records = @($existingTxtSet.Records | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_.Value) })
            foreach ($value in $txtAdded) { $desiredTxtSet = Add-AzDnsRecordConfig -RecordSet $desiredTxtSet -Value $value }
            $desiredTxtSet.Ttl = [int]$recordSource.ttl
            Set-AzDnsRecordSet -RecordSet $desiredTxtSet -WhatIf -Confirm:$false *>$null
            $plannedModifications++
        } else {
            $txtConfigs = @($desiredTxtValues | ForEach-Object { New-AzDnsRecordConfig -Value $_ })
            New-AzDnsRecordSet -Name '@' -ZoneName $settings.TARGET_DNS_ZONE_NAME -ResourceGroupName $resourceGroupName -RecordType TXT -Ttl ([int]$recordSource.ttl) -DnsRecords $txtConfigs -DefaultProfile $context -WhatIf -Confirm:$false *>$null
            $plannedCreates++
        }
    }

    $currentMxKeys = @($existingMxSet.Records | ForEach-Object { '{0}|{1}' -f [int]$_.Preference, [string]$_.Exchange })
    $newMxRecords = @($mxRecordInputs | Where-Object { ('{0}|{1}' -f $_.preference, $_.exchange) -notin $currentMxKeys })
    if ($newMxRecords.Count -gt 0 -or ($existingMxSet -and [int]$existingMxSet.Ttl -ne [int]$recordSource.ttl)) {
        if ($existingMxSet) {
            $desiredMxSet = $existingMxSet
            foreach ($record in $newMxRecords) { $desiredMxSet = Add-AzDnsRecordConfig -RecordSet $desiredMxSet -Exchange $record.exchange -Preference $record.preference }
            $desiredMxSet.Ttl = [int]$recordSource.ttl
            Set-AzDnsRecordSet -RecordSet $desiredMxSet -WhatIf -Confirm:$false *>$null
            $plannedModifications++
        } else {
            $mxConfigs = @($mxRecords | ForEach-Object { New-AzDnsRecordConfig -Exchange $_.exchange -Preference $_.preference })
            New-AzDnsRecordSet -Name '@' -ZoneName $settings.TARGET_DNS_ZONE_NAME -ResourceGroupName $resourceGroupName -RecordType MX -Ttl ([int]$recordSource.ttl) -DnsRecords $mxConfigs -DefaultProfile $context -WhatIf -Confirm:$false *>$null
            $plannedCreates++
        }
    }

    foreach ($record in $cnameRecords) {
        $currentSet = $existingCnameSets[$record.name]
        if ($currentSet) {
            if (@($currentSet.Records).Count -ne 1 -or [string]$currentSet.Records[0].Cname -ne $record.canonicalName) { throw 'An existing CNAME conflicts with private desired state; no deployment performed.' }
            if ([int]$currentSet.Ttl -ne [int]$recordSource.ttl) {
                $currentSet.Ttl = [int]$recordSource.ttl
                Set-AzDnsRecordSet -RecordSet $currentSet -WhatIf -Confirm:$false *>$null
                $plannedModifications++
            }
        } else {
            $cnameConfig = New-AzDnsRecordConfig -Cname $record.canonicalName
            New-AzDnsRecordSet -Name $record.name -ZoneName $settings.TARGET_DNS_ZONE_NAME -ResourceGroupName $resourceGroupName -RecordType CNAME -Ttl ([int]$recordSource.ttl) -DnsRecords @($cnameConfig) -DefaultProfile $context -WhatIf -Confirm:$false *>$null
            $plannedCreates++
        }
    }

    foreach ($record in $namedTxtRecords) {
        $currentSet = $existingNamedTxtSets[$record.name]
        if ($currentSet) {
            if ([int]$currentSet.Ttl -ne [int]$recordSource.ttl) {
                $currentSet.Ttl = [int]$recordSource.ttl
                Set-AzDnsRecordSet -RecordSet $currentSet -WhatIf -Confirm:$false *>$null
                $plannedModifications++
            }
        } else {
            $configs = @($record.values | ForEach-Object { New-AzDnsRecordConfig -Value $_ })
            New-AzDnsRecordSet -Name $record.name -ZoneName $settings.TARGET_DNS_ZONE_NAME -ResourceGroupName $resourceGroupName -RecordType TXT -Ttl ([int]$recordSource.ttl) -DnsRecords $configs -DefaultProfile $context -WhatIf -Confirm:$false *>$null
            $plannedCreates++
        }
    }

    $willChange = ($plannedCreates + $plannedModifications) -gt 0
    $summary = [pscustomobject]@{
        PreviewStatus = 'Succeeded'
        ChangeCount = $plannedCreates + $plannedModifications
        CreateCount = $plannedCreates
        MutationCount = $plannedCreates + $plannedModifications
        ApplyRequested = $Apply.IsPresent
        NoChange = -not $willChange
        RegistrarChanged = $false
    }
    if (-not $Apply -or -not $willChange) { $summary; return }
    $latestTxtSet = Get-AzDnsRecordSet -ResourceGroupName $resourceGroupName -ZoneName $settings.TARGET_DNS_ZONE_NAME -RecordType TXT -Name '@' -DefaultProfile $context -ErrorAction Stop
    $latestTxtValues = @($latestTxtSet.Records | ForEach-Object Value | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
    if ((Compare-Object @($existingTxtValues | Sort-Object -Unique) $latestTxtValues) -or $latestTxtSet.Etag -ne $existingTxtSet.Etag) { throw 'Apex TXT values changed after preview; no deployment performed.' }
    $latestMxSet = Get-AzDnsRecordSet -ResourceGroupName $resourceGroupName -ZoneName $settings.TARGET_DNS_ZONE_NAME -RecordType MX -Name '@' -DefaultProfile $context -ErrorAction SilentlyContinue
    if (($null -eq $latestMxSet) -ne ($null -eq $existingMxSet) -or ($existingMxSet -and $latestMxSet.Etag -ne $existingMxSet.Etag)) { throw 'MX records changed after preview; no deployment performed.' }
    foreach ($record in $cnameRecords) {
        $latestSet = Get-AzDnsRecordSet -ResourceGroupName $resourceGroupName -ZoneName $settings.TARGET_DNS_ZONE_NAME -RecordType CNAME -Name $record.name -DefaultProfile $context -ErrorAction SilentlyContinue
        $initialSet = $existingCnameSets[$record.name]
        if (($null -eq $latestSet) -ne ($null -eq $initialSet) -or ($initialSet -and $latestSet.Etag -ne $initialSet.Etag)) { throw 'A CNAME record changed after preview; no deployment performed.' }
    }
    foreach ($record in $namedTxtRecords) {
        $latestSet = Get-AzDnsRecordSet -ResourceGroupName $resourceGroupName -ZoneName $settings.TARGET_DNS_ZONE_NAME -RecordType TXT -Name $record.name -DefaultProfile $context -ErrorAction SilentlyContinue
        $initialSet = $existingNamedTxtSets[$record.name]
        if (($null -eq $latestSet) -ne ($null -eq $initialSet) -or ($initialSet -and $latestSet.Etag -ne $initialSet.Etag)) { throw 'A named TXT record changed after preview; no deployment performed.' }
    }
    $dnsTemplate = Join-Path $repo 'private/dns/zone.swc.json'
    az bicep build --file (Join-Path $repo 'infra/dns/zone.bicep') --outfile $dnsTemplate
    if ($LASTEXITCODE -ne 0) { throw 'Current DNS Bicep module compilation failed.' }
    $dnsParameters = @{
        zoneName = $settings.TARGET_DNS_ZONE_NAME
        verificationTxtValues = @($latestTxtValues + $apexTxtInputs + $VerificationTxtValue | Select-Object -Unique)
        mxRecords = $mxRecords
        cnameRecords = $cnameRecords
        namedTxtRecords = $namedTxtRecords
        tags = $existingZone.Tags
    }
    $deploymentName = 'shared-dns-{0}' -f [guid]::NewGuid().ToString('N')
    New-AzResourceGroupDeployment -Name $deploymentName -ResourceGroupName $resourceGroupName -TemplateFile $dnsTemplate -TemplateParameterObject $dnsParameters -DefaultProfile $context -ErrorAction Stop | Out-Null
    $readback = Get-AzDnsRecordSet -ResourceGroupName $resourceGroupName -ZoneName $settings.TARGET_DNS_ZONE_NAME -RecordType TXT -Name '@' -DefaultProfile $context -ErrorAction Stop
    $readbackValues = @($readback.Records | ForEach-Object Value | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $mxReadback = Get-AzDnsRecordSet -ResourceGroupName $resourceGroupName -ZoneName $settings.TARGET_DNS_ZONE_NAME -RecordType MX -Name '@' -DefaultProfile $context -ErrorAction Stop
    if (@($verificationTxtValues | Where-Object { $_ -notin $readbackValues }).Count -gt 0 -or [int]$readback.Ttl -ne [int]$recordSource.ttl) { throw 'Deployment returned, but apex TXT values or TTL failed readback.' }
    foreach ($record in $mxRecords) {
        if (-not @($mxReadback.Records | Where-Object { [int]$_.Preference -eq $record.preference -and [string]$_.Exchange -eq $record.exchange }).Count) { throw 'Deployment returned, but an MX record failed readback.' }
    }
    if ([int]$mxReadback.Ttl -ne [int]$recordSource.ttl) { throw 'Deployment returned, but MX TTL failed readback.' }
    foreach ($record in $cnameRecords) {
        $readbackCname = Get-AzDnsRecordSet -ResourceGroupName $resourceGroupName -ZoneName $settings.TARGET_DNS_ZONE_NAME -RecordType CNAME -Name $record.name -DefaultProfile $context -ErrorAction Stop
        if ([int]$readbackCname.Ttl -ne [int]$recordSource.ttl -or [string]$readbackCname.Records[0].Cname -ne $record.canonicalName) { throw 'Deployment returned, but a CNAME record failed readback.' }
    }
    foreach ($record in $namedTxtRecords) {
        $readbackNamed = Get-AzDnsRecordSet -ResourceGroupName $resourceGroupName -ZoneName $settings.TARGET_DNS_ZONE_NAME -RecordType TXT -Name $record.name -DefaultProfile $context -ErrorAction Stop
        if ([int]$readbackNamed.Ttl -ne [int]$recordSource.ttl -or -not (Test-LeafNamedTxtValues $readbackNamed $record.values)) { throw 'Deployment returned, but a named TXT set failed readback.' }
    }
    $summary | Add-Member -NotePropertyName Deployed -NotePropertyValue $true
    $summary | Add-Member -NotePropertyName VerificationTxtPresent -NotePropertyValue $true
    $summary | Add-Member -NotePropertyName Ttl -NotePropertyValue ([int]$readback.Ttl)
    $summary | Add-Member -NotePropertyName TxtRecordCount -NotePropertyValue $readbackValues.Count
    $summary | Add-Member -NotePropertyName MxRecordCount -NotePropertyValue @($mxReadback.Records).Count
    $summary | Add-Member -NotePropertyName CnameRecordCount -NotePropertyValue $cnameRecords.Count
    $summary | Add-Member -NotePropertyName NamedTxtRecordCount -NotePropertyValue $namedTxtRecords.Count
    $summary
    return
}
$compiledPath = Join-Path $repo 'private/dns/main.swedencentral.json'
az bicep build --file (Join-Path $repo 'infra/main.bicep') --outfile $compiledPath
if ($LASTEXITCODE -ne 0) { throw 'Current Bicep template compilation failed.' }
$whatIfName = 'shared-infrastructure-preview-{0}' -f [guid]::NewGuid().ToString('N')
$preview = Get-AzSubscriptionDeploymentWhatIfResult -Name $whatIfName -Location $settings.TARGET_LOCATION -TemplateFile $compiledPath -TemplateParameterObject $parameters -ResultFormat FullResourcePayloads -ValidationLevel Provider -DefaultProfile $context -ErrorAction Stop
$changes = @($preview.Changes)
$mutations = @($changes | Where-Object ChangeType -ne 'NoChange')
$creates = @($changes | Where-Object ChangeType -eq 'Create')
$apexTxtOnly = $mutations.Count -eq 1 -and $mutations[0].ChangeType -eq 'Modify' -and @($mutations[0].RelativeResourceId, $mutations[0].FullyQualifiedResourceId | Where-Object { [string]$_ -match '(?i)Microsoft\.Network/dnsZones/.+/TXT(?:/|$)' }).Count -gt 0
$expectedFoundationCreates = 3 + $mxRecords.Count + $cnameRecords.Count + $namedTxtRecords.Count
$foundationCreateOnly = $mutations.Count -eq $expectedFoundationCreates -and $creates.Count -eq $expectedFoundationCreates
if ($mutations.Count -gt 0 -and -not $apexTxtOnly -and -not $foundationCreateOnly) {
    $changeSummary = @($changes | Group-Object { [string]$_.ChangeType } | ForEach-Object { '{0}={1}' -f $_.Name, $_.Count }) -join ','
    $apexTxtPathMatches = @($mutations | Where-Object { @($_.RelativeResourceId, $_.FullyQualifiedResourceId | Where-Object { [string]$_ -match '(?i)Microsoft\.Network/dnsZones/.+/TXT(?:/|$)' }).Count -gt 0 }).Count
    $propertySummary = if ($changes.Count) { @($changes[0].PSObject.Properties.Name) -join ',' } else { 'none' }
    throw "Fresh what-if rejected; no deployment performed. ChangeTypes=$changeSummary; ApexTxtPathMatches=$apexTxtPathMatches; Properties=$propertySummary"
}
$summary = [pscustomobject]@{
    DeploymentName = 'shared-infrastructure'
    PreviewStatus = [string]$preview.Status
    ChangeCount = $changes.Count
    CreateCount = $creates.Count
    MutationCount = $mutations.Count
    ApplyRequested = $Apply.IsPresent
    NoChange = $mutations.Count -eq 0
    RegistrarChanged = $false
}
if (-not $Apply -or $mutations.Count -eq 0) { $summary; return }

New-AzSubscriptionDeployment -Name 'shared-infrastructure' -Location $settings.TARGET_LOCATION -TemplateFile $compiledPath -TemplateParameterObject $parameters -DefaultProfile $context -ErrorAction Stop | Out-Null
$zone = Get-AzDnsZone -ResourceGroupName $resourceGroupName -Name $settings.TARGET_DNS_ZONE_NAME -DefaultProfile $context -ErrorAction Stop
$txt = Get-AzDnsRecordSet -ResourceGroupName $resourceGroupName -ZoneName $settings.TARGET_DNS_ZONE_NAME -RecordType TXT -Name '@' -DefaultProfile $context -ErrorAction Stop
if ($VerificationTxtValue -notin @($txt.Records | ForEach-Object Value)) { throw 'Deployment returned, but the requested apex TXT value did not read back.' }
foreach ($record in $namedTxtRecords) {
    $readbackNamed = Get-AzDnsRecordSet -ResourceGroupName $resourceGroupName -ZoneName $settings.TARGET_DNS_ZONE_NAME -RecordType TXT -Name $record.name -DefaultProfile $context -ErrorAction Stop
    if ([int]$readbackNamed.Ttl -ne [int]$recordSource.ttl -or -not (Test-LeafNamedTxtValues $readbackNamed $record.values)) { throw 'Fresh foundation deployment returned, but a named TXT set failed readback.' }
}
$summary | Add-Member -NotePropertyName Deployed -NotePropertyValue $true
$summary | Add-Member -NotePropertyName NameServerCount -NotePropertyValue @($zone.NameServers).Count
$summary