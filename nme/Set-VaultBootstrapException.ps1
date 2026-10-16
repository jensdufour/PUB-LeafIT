#requires -Version 7.6
[CmdletBinding()]
param([switch]$CheckOnly, [switch]$Apply)

$ErrorActionPreference = 'Stop'
if ($CheckOnly -and $Apply) { throw 'Offline checks cannot apply a vault exception.' }
$repo = Split-Path $PSScriptRoot -Parent
. (Join-Path $repo 'identity/Target.ps1')

function Assert-NmeVaultException($Vault, [string]$GroupId, [string]$TenantId) {
    if ($Vault.type -ne 'Microsoft.KeyVault/vaults' -or -not ([string]$Vault.id).StartsWith($GroupId + '/providers/Microsoft.KeyVault/vaults/', [StringComparison]::OrdinalIgnoreCase) -or $Vault.properties.tenantId -ne $TenantId) { throw 'The vault does not belong to the verified NMe target.' }
    if ($Vault.properties.publicNetworkAccess -ne 'Disabled' -or $Vault.properties.enableRbacAuthorization -ne $true -or @($Vault.properties.privateEndpointConnections).Count -ne 1) { throw 'The NMe vault must retain private access, RBAC, and its existing private endpoint.' }
    if ($Vault.properties.privateEndpointConnections[0].properties.privateLinkServiceConnectionState.status -ne 'Approved') { throw 'The NMe vault private endpoint is not approved.' }
}

function Assert-NmeVaultExceptionWindow([string]$Approved, [string]$Expires, [int]$MaximumDays) {
    try {
        $approvedAt = [datetimeoffset]::Parse($Approved, [Globalization.CultureInfo]::InvariantCulture)
        $expiresAt = [datetimeoffset]::Parse($Expires, [Globalization.CultureInfo]::InvariantCulture)
    } catch { throw 'The private vault exception timestamps are invalid.' }
    if ($MaximumDays -lt 1 -or $approvedAt.Offset -ne [timespan]::Zero -or $expiresAt.Offset -ne [timespan]::Zero -or $approvedAt -gt [datetimeoffset]::UtcNow -or $expiresAt -le [datetimeoffset]::UtcNow -or $expiresAt -le $approvedAt -or $expiresAt -gt $approvedAt.AddDays($MaximumDays)) { throw 'The vault exception is expired, future-dated, or exceeds its documented window. Automatic renewal is prohibited.' }
}

if ($CheckOnly) {
    Test-LeafTargetGuards
    $group = '/subscriptions/example/resourceGroups/nme'
    $sample = @{ type = 'Microsoft.KeyVault/vaults'; id = $group + '/providers/Microsoft.KeyVault/vaults/example'; properties = @{ tenantId = 'example-tenant'; publicNetworkAccess = 'Disabled'; enableRbacAuthorization = $true; privateEndpointConnections = @(@{ properties = @{ privateLinkServiceConnectionState = @{ status = 'Approved' } } }) } }
    Assert-NmeVaultException $sample $group 'example-tenant'
    foreach ($field in @('Scope', 'Tenant', 'PublicAccess')) {
        $invalid = $sample | ConvertTo-Json -Depth 10 | ConvertFrom-Json -AsHashtable
        switch ($field) {
            Scope { $invalid.id = $invalid.id.Replace('/resourceGroups/nme/', '/resourceGroups/other/') }
            Tenant { $invalid.properties.tenantId = 'different-tenant' }
            PublicAccess { $invalid.properties.publicNetworkAccess = 'Enabled' }
        }
        $rejected = $false
        try { Assert-NmeVaultException $invalid $group 'example-tenant' } catch { $rejected = $true }
        if (-not $rejected) { throw 'An unsafe vault exception target was accepted.' }
    }
    $now = [datetimeoffset]::UtcNow
    Assert-NmeVaultExceptionWindow $now.AddMinutes(-1).ToString('o') $now.AddHours(1).ToString('o') 1
    foreach ($expires in @($now.AddMinutes(-1), $now.AddDays(2))) {
        $rejected = $false
        try { Assert-NmeVaultExceptionWindow $now.AddMinutes(-2).ToString('o') $expires.ToString('o') 1 } catch { $rejected = $true }
        if (-not $rejected) { throw 'An expired or overlong vault exception was accepted.' }
    }
    [pscustomobject]@{ OfflineChecksPassed = $true; VaultOnlyScopeChecked = $true; PrivateAccessGuardsPassed = $true; ExpiryGuardsPassed = $true; AzureCallsMade = $false }
    return
}

$settings = Read-LeafPrivateTarget $repo
Import-Module Az.Accounts -MinimumVersion 5.3.3 -ErrorAction Stop
Import-Module Az.Resources -ErrorAction Stop
$context = Get-AzContext
Assert-LeafTargetContext $settings $context
$plan = Get-Content -LiteralPath (Join-Path $repo 'private/nme/installation-plan.json') -Raw | ConvertFrom-Json -AsHashtable
$desired = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'desired.json') -Raw | ConvertFrom-Json -AsHashtable
$guide = Get-Content -LiteralPath (Join-Path $repo 'private/nme-governance.json') -Raw | ConvertFrom-Json -AsHashtable -Depth 100
if ($plan.deploymentSucceeded -ne $true -or $plan.vendorTemplateSha256 -ne $desired.installation.templateSha256 -or $plan.resourceGroupName -notmatch '^rg-nme-swc-[0-9]{1,3}$') { throw 'The NMe vendor installation is unverified.' }
if ($guide.scope.individualResourceSupported -ne $true -or $guide.validity.reapplicationResetsFullWindow -ne $false -or $guide.validity.fullWindowsPerTrackedResourceOrGroup -ne 1 -or [int]$guide.validity.fullWindowDays -lt 1) { throw 'The finite resource-only exception contract is unverified.' }
$groupId = '/subscriptions/' + $settings.TARGET_SUBSCRIPTION_ID + '/resourceGroups/' + $plan.resourceGroupName
$vaults = @(Get-AzResource -ResourceGroupName $plan.resourceGroupName -ResourceType 'Microsoft.KeyVault/vaults' -DefaultProfile $context)
if ($vaults.Count -ne 1) { throw 'The NMe vault is missing or ambiguous.' }
$path = $vaults[0].ResourceId + '?api-version=2024-11-01'
$response = Invoke-AzRestMethod -Method GET -Path $path -DefaultProfile $context
if ($response.StatusCode -ne 200) { throw 'The NMe vault cannot be read; absence or compliance is not assumed.' }
$vault = ConvertFrom-Json -InputObject $response.Content -AsHashtable -Depth 40
Assert-NmeVaultException $vault $groupId $settings.TARGET_TENANT_ID
$beforeTags = @{}
foreach ($key in $vault.tags.Keys) { $beforeTags[$key] = $vault.tags[$key] }
$names = @('TARGET_NME_VAULT_EXCEPTION_TAG_NAME', 'TARGET_NME_VAULT_EXCEPTION_TAG_VALUE', 'TARGET_NME_VAULT_EXCEPTION_APPROVED_UTC', 'TARGET_NME_VAULT_EXCEPTION_EXPIRES_UTC')
$inputs = @{}
foreach ($line in [IO.File]::ReadAllLines((Join-Path $repo '.env'))) {
    $entry = [regex]::Match($line, '^\s*(?<key>TARGET_[A-Z0-9_]+)\s*=\s*(?<value>.*)$')
    if (-not $entry.Success -or $entry.Groups['key'].Value -notin $names) { continue }
    $key = $entry.Groups['key'].Value
    if ($inputs.ContainsKey($key)) { throw 'Duplicate private vault exception input.' }
    $inputs[$key] = $entry.Groups['value'].Value.Trim().Trim([char]34, [char]39)
}
$newInputs = $inputs.Count -eq 0
if ($newInputs) {
    if ($beforeTags.ContainsKey([string]$guide.tagDefinitions.security.name)) { throw 'An existing vault exception has no reviewed expiry record; a new window is not assumed.' }
    $now = [datetimeoffset]::UtcNow
    $inputs = @{
        TARGET_NME_VAULT_EXCEPTION_TAG_NAME = [string]$guide.tagDefinitions.security.name
        TARGET_NME_VAULT_EXCEPTION_TAG_VALUE = [string]$guide.tagDefinitions.security.value
        TARGET_NME_VAULT_EXCEPTION_APPROVED_UTC = $now.ToString('o')
        TARGET_NME_VAULT_EXCEPTION_EXPIRES_UTC = $now.AddDays([int]$guide.validity.fullWindowDays).ToString('o')
    }
}
if ($inputs.Count -ne $names.Count -or $inputs.TARGET_NME_VAULT_EXCEPTION_TAG_NAME -cne [string]$guide.tagDefinitions.security.name -or $inputs.TARGET_NME_VAULT_EXCEPTION_TAG_VALUE -cne [string]$guide.tagDefinitions.security.value) { throw 'The private vault exception inputs are incomplete or differ from the reviewed mechanism.' }
foreach ($name in $names) {
    if ([string]::IsNullOrWhiteSpace($inputs[$name]) -or $inputs[$name] -match '[\r\n"''=]') { throw 'A private vault exception input is invalid dotenv data.' }
}
Assert-NmeVaultExceptionWindow $inputs.TARGET_NME_VAULT_EXCEPTION_APPROVED_UTC $inputs.TARGET_NME_VAULT_EXCEPTION_EXPIRES_UTC ([int]$guide.validity.fullWindowDays)
$tagName = $inputs.TARGET_NME_VAULT_EXCEPTION_TAG_NAME
$tagValue = $inputs.TARGET_NME_VAULT_EXCEPTION_TAG_VALUE
if ($beforeTags.ContainsKey($tagName) -and $beforeTags[$tagName] -cne $tagValue) { throw 'The existing vault security tag conflicts with the reviewed exception.' }
$changeRequired = -not $beforeTags.ContainsKey($tagName)
if (-not $Apply) {
    [pscustomobject]@{ Mode = 'Preview'; VaultOnlyScope = $true; PrivateNetworkingPreserved = $true; ExceptionTagRequired = $changeRequired; ExistingExpiryPreserved = -not $newInputs; AzureChangesMade = $false }
    return
}
if ($newInputs) {
    $lines = @('') + @($names | ForEach-Object { $_ + '=' + $inputs[$_] })
    [IO.File]::AppendAllText((Join-Path $repo '.env'), ([string]::Join([Environment]::NewLine, $lines) + [Environment]::NewLine), [Text.UTF8Encoding]::new($false))
}
Assert-LeafTargetContext $settings (Get-AzContext)
if ($changeRequired) { $null = Update-AzTag -ResourceId $vault.id -Operation Merge -Tag @{ $tagName = $tagValue } -DefaultProfile $context }
$afterResponse = Invoke-AzRestMethod -Method GET -Path $path -DefaultProfile $context
if ($afterResponse.StatusCode -ne 200) { throw 'The vault-only exception could not be read back.' }
$after = ConvertFrom-Json -InputObject $afterResponse.Content -AsHashtable -Depth 40
Assert-NmeVaultException $after $groupId $settings.TARGET_TENANT_ID
if ($after.tags[$tagName] -cne $tagValue) { throw 'The vault-only exception tag did not persist.' }
foreach ($key in $beforeTags.Keys) {
    if ($after.tags[$key] -cne $beforeTags[$key]) { throw 'A pre-existing vault tag changed unexpectedly.' }
}
[pscustomobject]@{ Mode = if ($changeRequired) { 'Applied' } else { 'NoChange' }; VaultOnlyScope = $true; PrivateNetworkingPreserved = $true; OriginalExpiryPreserved = $true; AutomaticRenewalEnabled = $false; AzureChangesMade = $changeRequired }