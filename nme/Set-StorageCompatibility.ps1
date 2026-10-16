#requires -Version 7.6
[CmdletBinding()]
param([switch]$CheckOnly, [switch]$Apply)

$ErrorActionPreference = 'Stop'
if ($CheckOnly -and $Apply) { throw 'Offline checks cannot apply a storage exception.' }
$repo = Split-Path $PSScriptRoot -Parent
. (Join-Path $repo 'identity/Target.ps1')

function Assert-NmePrivateStorage($Storage, [string]$GroupId) {
    $prefix = $GroupId + '/providers/Microsoft.Storage/storageAccounts/'
    if ($Storage.ResourceType -ne 'Microsoft.Storage/storageAccounts' -or -not ([string]$Storage.ResourceId).StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) -or $Storage.Name -notmatch '^dps[a-z0-9]{13}$') { throw 'The resource is not the dedicated NMe data-protection storage account.' }
    if ($Storage.Properties.publicNetworkAccess -ne 'Disabled' -or $Storage.Properties.allowBlobPublicAccess -ne $false -or $Storage.Properties.supportsHttpsTrafficOnly -ne $true) { throw 'NMe storage must remain private, HTTPS-only, and unavailable to anonymous blob access.' }
}

function Assert-NmeExceptionWindow([string]$Approved, [string]$Expires, [int]$MaximumDays) {
    try {
        $approvedAt = [datetimeoffset]::Parse($Approved, [Globalization.CultureInfo]::InvariantCulture)
        $expiresAt = [datetimeoffset]::Parse($Expires, [Globalization.CultureInfo]::InvariantCulture)
    } catch { throw 'The private exception timestamps are invalid.' }
    if ($MaximumDays -lt 1 -or $approvedAt.Offset -ne [timespan]::Zero -or $expiresAt.Offset -ne [timespan]::Zero -or $approvedAt -gt [datetimeoffset]::UtcNow -or $expiresAt -le [datetimeoffset]::UtcNow -or $expiresAt -le $approvedAt -or $expiresAt -gt $approvedAt.AddDays($MaximumDays)) { throw 'The private exception is expired, future-dated, or exceeds its documented window. Automatic renewal is prohibited.' }
}

if ($CheckOnly) {
    Test-LeafTargetGuards
    $group = '/subscriptions/example/resourceGroups/nme'
    $probe = @{ ResourceType = 'Microsoft.Storage/storageAccounts'; ResourceId = $group + '/providers/Microsoft.Storage/storageAccounts/dps0000000000000'; Name = 'dps0000000000000'; Properties = @{ publicNetworkAccess = 'Disabled'; allowBlobPublicAccess = $false; supportsHttpsTrafficOnly = $true } }
    Assert-NmePrivateStorage $probe $group
    foreach ($change in @('Scope', 'PublicAccess', 'AnonymousBlobs')) {
        $invalid = $probe | ConvertTo-Json -Depth 6 | ConvertFrom-Json -AsHashtable
        switch ($change) {
            Scope { $invalid.ResourceId = $invalid.ResourceId.Replace('/resourceGroups/nme/', '/resourceGroups/other/') }
            PublicAccess { $invalid.Properties.publicNetworkAccess = 'Enabled' }
            AnonymousBlobs { $invalid.Properties.allowBlobPublicAccess = $true }
        }
        $rejected = $false
        try { Assert-NmePrivateStorage $invalid $group } catch { $rejected = $true }
        if (-not $rejected) { throw 'An unsafe storage exception target was accepted.' }
    }
    $now = [datetimeoffset]::UtcNow
    Assert-NmeExceptionWindow $now.AddMinutes(-1).ToString('o') $now.AddHours(1).ToString('o') 1
    foreach ($expires in @($now.AddMinutes(-1), $now.AddDays(2))) {
        $rejected = $false
        try { Assert-NmeExceptionWindow $now.AddMinutes(-2).ToString('o') $expires.ToString('o') 1 } catch { $rejected = $true }
        if (-not $rejected) { throw 'An expired or overlong exception was accepted.' }
    }
    [pscustomobject]@{ OfflineChecksPassed = $true; StorageOnlyScopeChecked = $true; PrivateAccessGuardsPassed = $true; ExpiryGuardsPassed = $true; AzureCallsMade = $false }
    return
}

$settings = Read-LeafPrivateTarget $repo
Import-Module Az.Accounts -MinimumVersion 5.3.3 -ErrorAction Stop
Import-Module Az.Resources -ErrorAction Stop
Import-Module Az.Storage -ErrorAction Stop
$context = Get-AzContext
Assert-LeafTargetContext $settings $context
$desired = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'desired.json') -Raw | ConvertFrom-Json -AsHashtable
$plan = Get-Content -LiteralPath (Join-Path $repo 'private/nme/installation-plan.json') -Raw | ConvertFrom-Json -AsHashtable
$guide = Get-Content -LiteralPath (Join-Path $repo 'private/nme-governance.json') -Raw | ConvertFrom-Json -AsHashtable -Depth 100
if ($plan.deploymentSucceeded -ne $true -or $plan.vendorTemplateSha256 -ne $desired.installation.templateSha256 -or $plan.resourceGroupName -notmatch '^rg-nme-swc-[0-9]{1,3}$') { throw 'The installed vendor package or dedicated workload group is unverified.' }
if ($guide.scope.individualResourceSupported -ne $true -or $guide.validity.reapplicationResetsFullWindow -ne $false -or $guide.validity.fullWindowsPerTrackedResourceOrGroup -ne 1 -or [int]$guide.validity.fullWindowDays -lt 1) { throw 'The stored guidance does not establish the selected finite, resource-only exception.' }
$groupId = '/subscriptions/' + $settings.TARGET_SUBSCRIPTION_ID + '/resourceGroups/' + $plan.resourceGroupName
$accounts = @(Get-AzResource -ResourceGroupName $plan.resourceGroupName -ResourceType 'Microsoft.Storage/storageAccounts' -ExpandProperties -DefaultProfile $context)
if ($accounts.Count -ne 1) { throw 'The NMe data-protection account is missing or ambiguous.' }
$storage = $accounts[0]
Assert-NmePrivateStorage $storage $groupId
$beforeTags = @{}
foreach ($key in $storage.Tags.Keys) { $beforeTags[$key] = $storage.Tags[$key] }

$names = @('TARGET_NME_STORAGE_EXCEPTION_TAG_NAME', 'TARGET_NME_STORAGE_EXCEPTION_TAG_VALUE', 'TARGET_NME_STORAGE_EXCEPTION_APPROVED_UTC', 'TARGET_NME_STORAGE_EXCEPTION_EXPIRES_UTC')
$inputs = @{}
foreach ($line in [IO.File]::ReadAllLines((Join-Path $repo '.env'))) {
    $entry = [regex]::Match($line, '^\s*(?<key>TARGET_[A-Z0-9_]+)\s*=\s*(?<value>.*)$')
    if (-not $entry.Success -or $entry.Groups['key'].Value -notin $names) { continue }
    $key = $entry.Groups['key'].Value
    if ($inputs.ContainsKey($key)) { throw 'Duplicate private NMe exception input.' }
    $inputs[$key] = $entry.Groups['value'].Value.Trim().Trim([char]34, [char]39)
}
$newInputs = $inputs.Count -eq 0
if ($newInputs) {
    if ($beforeTags.ContainsKey([string]$guide.tagDefinitions.security.name)) { throw 'An existing security exception has no reviewed expiry record; a fresh window is not assumed.' }
    $now = [datetimeoffset]::UtcNow
    $inputs = @{
        TARGET_NME_STORAGE_EXCEPTION_TAG_NAME = [string]$guide.tagDefinitions.security.name
        TARGET_NME_STORAGE_EXCEPTION_TAG_VALUE = [string]$guide.tagDefinitions.security.value
        TARGET_NME_STORAGE_EXCEPTION_APPROVED_UTC = $now.ToString('o')
        TARGET_NME_STORAGE_EXCEPTION_EXPIRES_UTC = $now.AddDays([int]$guide.validity.fullWindowDays).ToString('o')
    }
}
if ($inputs.Count -ne $names.Count -or $inputs.TARGET_NME_STORAGE_EXCEPTION_TAG_NAME -cne [string]$guide.tagDefinitions.security.name -or $inputs.TARGET_NME_STORAGE_EXCEPTION_TAG_VALUE -cne [string]$guide.tagDefinitions.security.value) { throw 'Private exception inputs are incomplete or differ from the reviewed security-only mechanism.' }
foreach ($name in $names) {
    if ([string]::IsNullOrWhiteSpace($inputs[$name]) -or $inputs[$name] -match '[\r\n"''=]') { throw 'A private exception input cannot be safely recorded as dotenv data.' }
}
Assert-NmeExceptionWindow $inputs.TARGET_NME_STORAGE_EXCEPTION_APPROVED_UTC $inputs.TARGET_NME_STORAGE_EXCEPTION_EXPIRES_UTC ([int]$guide.validity.fullWindowDays)
$tagName = $inputs.TARGET_NME_STORAGE_EXCEPTION_TAG_NAME
$tagValue = $inputs.TARGET_NME_STORAGE_EXCEPTION_TAG_VALUE
if ($beforeTags.ContainsKey($tagName) -and $beforeTags[$tagName] -cne $tagValue) { throw 'The existing storage security tag conflicts with the reviewed exception.' }
if (-not $Apply) {
    [pscustomobject]@{ Mode = 'Preview'; ResourceOnlyScope = $true; PrivateNetworkingPreserved = $true; ExceptionTagRequired = -not $beforeTags.ContainsKey($tagName); SharedKeyChangeRequired = $storage.Properties.allowSharedKeyAccess -ne $true; ExistingExpiryPreserved = -not $newInputs; AzureChangesMade = $false }
    return
}

if ($newInputs) {
    $lines = @('') + @($names | ForEach-Object { $_ + '=' + $inputs[$_] })
    [IO.File]::AppendAllText((Join-Path $repo '.env'), ([string]::Join([Environment]::NewLine, $lines) + [Environment]::NewLine), [Text.UTF8Encoding]::new($false))
}
Assert-LeafTargetContext $settings (Get-AzContext)
$changed = $false
if (-not $beforeTags.ContainsKey($tagName)) {
    $null = Update-AzTag -ResourceId $storage.ResourceId -Operation Merge -Tag @{ $tagName = $tagValue } -DefaultProfile $context
    $changed = $true
}
$tagReadback = Get-AzResource -ResourceId $storage.ResourceId -ExpandProperties -DefaultProfile $context
if ($tagReadback.Tags[$tagName] -cne $tagValue) { throw 'The storage-only exception tag was not read back; key access was not changed.' }
Assert-NmePrivateStorage $tagReadback $groupId
foreach ($key in $beforeTags.Keys) {
    if ($tagReadback.Tags[$key] -cne $beforeTags[$key]) { throw 'An unrelated pre-existing storage tag changed; key access was not changed.' }
}
if ($tagReadback.Properties.allowSharedKeyAccess -ne $true) {
    Assert-LeafTargetContext $settings (Get-AzContext)
    $null = Set-AzStorageAccount -ResourceGroupName $plan.resourceGroupName -Name $storage.Name -AllowSharedKeyAccess $true -DefaultProfile $context
    $changed = $true
}
$after = Get-AzResource -ResourceId $storage.ResourceId -ExpandProperties -DefaultProfile $context
Assert-NmePrivateStorage $after $groupId
if ($after.Properties.allowSharedKeyAccess -ne $true -or $after.Tags[$tagName] -cne $tagValue) { throw 'The approved storage authentication compatibility change did not persist.' }
[pscustomobject]@{ Mode = if ($changed) { 'Applied' } else { 'NoChange' }; StorageOnlyScope = $true; PrivateNetworkingPreserved = $true; SharedKeyAccessVerified = $true; OriginalExpiryPreserved = $true; AutomaticRenewalEnabled = $false; AzureChangesMade = $changed }