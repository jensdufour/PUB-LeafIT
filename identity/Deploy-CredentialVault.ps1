#requires -Version 7.6
[CmdletBinding()]
param(
    [ValidateSet('Preview', 'Apply', 'Verify')][string]$Mode = 'Preview',
    [switch]$CheckOnly
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
. (Join-Path $PSScriptRoot 'Target.ps1')
$template = Join-Path $PSScriptRoot 'keyvault/resources.bicep'
$officerRole = 'b86a8fe4-44ce-4948-aee5-eccb2c155cd7'

function Read-LeafCredentialVaultInputs {
    param([string]$Text)
    $keys = @('TARGET_IDENTITY_RESOURCE_GROUP', 'TARGET_IDENTITY_KEY_VAULT_NAME', 'TARGET_IDENTITY_KEY_VAULT_OPERATOR_ID', 'TARGET_IDENTITY_KEY_VAULT_CLIENT_IPV4', 'TARGET_IDENTITY_CREDENTIAL_VM_ID', 'TARGET_IDENTITY_CREDENTIAL_VM_INSTANCE_ID', 'TARGET_IDENTITY_KEY_VAULT_LOCATION')
    $inputs = @{}
    foreach ($line in $Text -split '\r?\n') {
        $entry = [regex]::Match($line, '^\s*(?<key>TARGET_[A-Z0-9_]+)\s*=\s*(?<value>.*)$')
        if (-not $entry.Success -or $entry.Groups['key'].Value -cnotin $keys) { continue }
        $key = $entry.Groups['key'].Value
        if ($inputs.ContainsKey($key)) { throw 'DuplicateCredentialVaultInput' }
        $inputs[$key] = $entry.Groups['value'].Value.Trim().Trim([char]34, [char]39)
    }
    foreach ($key in $keys) { if ([string]::IsNullOrWhiteSpace($inputs[$key])) { throw 'MissingCredentialVaultInput' } }
    if ($inputs.TARGET_IDENTITY_RESOURCE_GROUP -cnotmatch '^rg-identity-swc-[0-9]{3}$' -or $inputs.TARGET_IDENTITY_KEY_VAULT_NAME -cnotmatch '^kv-identity-swc-[0-9]{3}(?:-[a-z0-9]{1,4})?$' -or $inputs.TARGET_IDENTITY_KEY_VAULT_LOCATION -cne 'swedencentral') { throw 'CredentialVaultCafNameAndRegionRequired' }
    foreach ($key in @('TARGET_IDENTITY_KEY_VAULT_OPERATOR_ID', 'TARGET_IDENTITY_CREDENTIAL_VM_INSTANCE_ID')) {
        $identifier = [guid]::Empty
        if (-not [guid]::TryParseExact($inputs[$key], 'D', [ref]$identifier) -or $identifier -eq [guid]::Empty) { throw 'InvalidCredentialVaultIdentity' }
    }
    $address = [Net.IPAddress]::None
    $textAddress = $inputs.TARGET_IDENTITY_KEY_VAULT_CLIENT_IPV4
    if (-not [Net.IPAddress]::TryParse($textAddress, [ref]$address) -or $address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or $address.ToString() -cne $textAddress -or $textAddress -match '^(0\.|10\.|127\.|169\.254\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.|198\.(18|19)\.|22[4-9]\.|2[3-5][0-9]\.)') { throw 'OneExactPublicIpv4Required' }
    return $inputs
}

function Get-LeafCredentialVaultHash {
    param([string]$Text)
    return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($Text)))
}

function Test-LeafCredentialVaultProperties {
    param($Vault, $Inputs, [string]$TenantId)
    $properties = $Vault.properties
    $rules = @($properties.networkAcls.ipRules | Where-Object { $null -ne $_ })
    return $Vault.location -ceq 'swedencentral' -and $Vault.tags['managed-by'] -ceq 'bicep' -and $Vault.tags.workload -ceq 'identity' -and $properties.provisioningState -ceq 'Succeeded' -and $properties.tenantId -ieq $TenantId -and $properties.sku.name -ieq 'standard' -and $properties.enableRbacAuthorization -ceq $true -and $properties.enableSoftDelete -ceq $true -and $properties.enablePurgeProtection -ceq $true -and $properties.softDeleteRetentionInDays -eq 90 -and -not $properties.enabledForDeployment -and -not $properties.enabledForDiskEncryption -and -not $properties.enabledForTemplateDeployment -and $properties.publicNetworkAccess -ceq 'Enabled' -and $properties.networkAcls.defaultAction -ceq 'Deny' -and $properties.networkAcls.bypass -ceq 'None' -and $rules.Count -eq 1 -and $rules[0].value -cin @($Inputs.TARGET_IDENTITY_KEY_VAULT_CLIENT_IPV4, ($Inputs.TARGET_IDENTITY_KEY_VAULT_CLIENT_IPV4 + '/32')) -and @($properties.networkAcls.virtualNetworkRules | Where-Object { $null -ne $_ }).Count -eq 0 -and @($properties.accessPolicies | Where-Object { $null -ne $_ }).Count -eq 0
}

function Get-LeafCredentialVaultChanges {
    param($Result, [string]$VaultId, [string]$PrincipalId, [string]$RoleId)
    if ([string]$Result.Status -cne 'Succeeded') { throw 'SuccessfulVaultWhatIfRequired' }
    $changes = @(foreach ($change in @($Result.Changes | Where-Object { [string]$_.ChangeType -cne 'Ignore' })) {
        $after = $null
        $before = $null
        if ($null -ne $change.After) {
            if ($change.After -is [Collections.IDictionary]) { $after = $change.After }
            else { $after = $change.After.ToString() | ConvertFrom-Json -AsHashtable -Depth 70 -DateKind String }
        }
        if ($null -ne $change.Before) {
            if ($change.Before -is [Collections.IDictionary]) { $before = $change.Before }
            else { $before = $change.Before.ToString() | ConvertFrom-Json -AsHashtable -Depth 70 -DateKind String }
        }
        [pscustomobject]@{ ResourceId = [string]$change.FullyQualifiedResourceId; ChangeType = [string]$change.ChangeType; Before = $before; After = $after }
    })
    $vaultChanges = @($changes | Where-Object ResourceId -IEQ $VaultId)
    $roleChanges = @($changes | Where-Object { $_.ResourceId -imatch ('^' + [regex]::Escape($VaultId) + '/providers/Microsoft\.Authorization/roleAssignments/[a-f0-9-]{36}$') })
    if ($changes.Count -ne 2 -or $vaultChanges.Count -ne 1 -or $roleChanges.Count -ne 1) { throw 'OnlyExactVaultAndScopedRoleMayChange' }
    foreach ($change in $changes) { if ($change.ChangeType -cne 'Create' -or $null -ne $change.Before) { throw 'OnlyAbsentVaultAndScopedRoleMayBeCreated' } }
    $role = $roleChanges[0].After
    if ($role.properties.principalId -ine $PrincipalId -or $role.properties.roleDefinitionId -ine $RoleId -or ($role.properties.Contains('principalType') -and $role.properties.principalType -cne 'User')) { throw 'OnlyConfiguredUserSecretsOfficerRoleAllowed' }
    return $changes
}

if ($CheckOnly) {
    if ($Mode -cne 'Preview') { throw 'OfflineChecksCannotApply' }
    $identifier = [guid]::NewGuid().ToString()
    $text = "TARGET_IDENTITY_RESOURCE_GROUP=rg-identity-swc-999`nTARGET_IDENTITY_KEY_VAULT_NAME=kv-identity-swc-999`nTARGET_IDENTITY_KEY_VAULT_OPERATOR_ID=$identifier`nTARGET_IDENTITY_KEY_VAULT_CLIENT_IPV4=203.0.113.8`nTARGET_IDENTITY_CREDENTIAL_VM_ID=/SYNTHETIC-VM-REFERENCE`nTARGET_IDENTITY_CREDENTIAL_VM_INSTANCE_ID=$identifier`nTARGET_IDENTITY_KEY_VAULT_LOCATION=swedencentral"
    $fixture = Read-LeafCredentialVaultInputs $text
    $checks = 1
    foreach ($bad in @('10.0.0.1', '127.1', '100.64.0.1', '203.0.113.8/24', '::1', '0.0.0.0', '224.0.0.1', 'example.com', '*')) {
        $rejected = $false
        try { $null = Read-LeafCredentialVaultInputs ($text.Replace('203.0.113.8', $bad)) } catch { $rejected = $true }
        if (-not $rejected) { throw 'BroadOrInvalidVaultNetworkFixtureAccepted' }
        $checks++
    }
    foreach ($bad in @(($text + "`nTARGET_IDENTITY_KEY_VAULT_NAME=kv-identity-swc-999"), $text.Replace('swedencentral', 'westeurope'), $text.Replace($identifier, 'not-an-identity'), $text.Replace('kv-identity-swc-999', 'vault'), $text.Replace('TARGET_IDENTITY_KEY_VAULT_CLIENT_IPV4=203.0.113.8', ''))) {
        $rejected = $false
        try { $null = Read-LeafCredentialVaultInputs $bad } catch { $rejected = $true }
        if (-not $rejected) { throw 'InvalidVaultInputFixtureAccepted' }
        $checks++
    }
    $vaultId = '/SYNTHETIC-VAULT-REFERENCE'
    $roleId = '/SYNTHETIC-ROLE-REFERENCE'
    $roleChange = @{ FullyQualifiedResourceId = $vaultId + '/providers/Microsoft.Authorization/roleAssignments/' + $identifier; ChangeType = 'Create'; After = @{ properties = @{ principalId = $identifier; roleDefinitionId = $roleId; principalType = 'User' } } }
    $valid = @{ Status = 'Succeeded'; Changes = @(@{ FullyQualifiedResourceId = $vaultId; ChangeType = 'Create' }, $roleChange) }
    $null = Get-LeafCredentialVaultChanges $valid $vaultId $identifier $roleId
    $withIgnored = @{ Status = 'Succeeded'; Changes = @($valid.Changes) + @(@{ FullyQualifiedResourceId = '/SYNTHETIC-EXISTING-REFERENCE'; ChangeType = 'Ignore' }) }
    if (@(Get-LeafCredentialVaultChanges $withIgnored $vaultId $identifier $roleId).Count -ne 2) { throw 'IgnoredExistingResourcesMustNotBecomeMutationCandidates' }
    $checks++
    $omittedPrincipalType = $valid | ConvertTo-Json -Depth 15 | ConvertFrom-Json -AsHashtable
    $null = $omittedPrincipalType.Changes[1].After.properties.Remove('principalType')
    $null = Get-LeafCredentialVaultChanges $omittedPrincipalType $vaultId $identifier $roleId
    $checks++
    foreach ($bad in @('Delete', 'Modify', 'Unrelated', 'Owner', 'DifferentPrincipal', 'WrongPrincipalType', 'FailedWhatIf')) {
        $copy = $valid | ConvertTo-Json -Depth 15 | ConvertFrom-Json -AsHashtable
        switch ($bad) {
            'Delete' { $copy.Changes[0].ChangeType = 'Delete' }
            'Modify' { $copy.Changes[0].ChangeType = 'Modify' }
            'Unrelated' { $copy.Changes[0].FullyQualifiedResourceId = '/SYNTHETIC-UNRELATED-REFERENCE' }
            'Owner' { $copy.Changes[1].After.properties.roleDefinitionId = '/SYNTHETIC-OWNER-REFERENCE' }
            'DifferentPrincipal' { $copy.Changes[1].After.properties.principalId = [guid]::NewGuid().ToString() }
            'WrongPrincipalType' { $copy.Changes[1].After.properties.principalType = 'ServicePrincipal' }
            'FailedWhatIf' { $copy.Status = 'Failed' }
        }
        $rejected = $false
        try { $null = Get-LeafCredentialVaultChanges $copy $vaultId $identifier $roleId } catch { $rejected = $true }
        if (-not $rejected) { throw 'ExpandedVaultDeploymentFixtureAccepted' }
        $checks++
    }
    $vault = @{ location = 'swedencentral'; tags = @{ 'managed-by' = 'bicep'; workload = 'identity' }; properties = @{ provisioningState = 'Succeeded'; tenantId = $identifier; sku = @{ name = 'standard' }; enableRbacAuthorization = $true; enableSoftDelete = $true; enablePurgeProtection = $true; softDeleteRetentionInDays = 90; enabledForDeployment = $false; enabledForDiskEncryption = $false; enabledForTemplateDeployment = $false; publicNetworkAccess = 'Enabled'; networkAcls = @{ defaultAction = 'Deny'; bypass = 'None'; ipRules = @(@{ value = '203.0.113.8/32' }); virtualNetworkRules = @() }; accessPolicies = @() } }
    if (-not (Test-LeafCredentialVaultProperties $vault $fixture $identifier)) { throw 'ExactVaultStateFixtureNotAccepted' }
    foreach ($bad in @('Network', 'Address', 'ExtraAddress', 'Bypass', 'Rbac', 'Purge', 'Retention', 'Tenant', 'TemplateAccess', 'Owner', 'Pending')) {
        $copy = $vault | ConvertTo-Json -Depth 15 | ConvertFrom-Json -AsHashtable
        switch ($bad) {
            'Network' { $copy.properties.networkAcls.defaultAction = 'Allow' }
            'Address' { $copy.properties.networkAcls.ipRules[0].value = '0.0.0.0/0' }
            'ExtraAddress' { $copy.properties.networkAcls.ipRules += @{ value = '203.0.113.9/32' } }
            'Bypass' { $copy.properties.networkAcls.bypass = 'AzureServices' }
            'Rbac' { $copy.properties.enableRbacAuthorization = $false }
            'Purge' { $copy.properties.enablePurgeProtection = $false }
            'Retention' { $copy.properties.softDeleteRetentionInDays = 7 }
            'Tenant' { $copy.properties.tenantId = [guid]::NewGuid().ToString() }
            'TemplateAccess' { $copy.properties.enabledForTemplateDeployment = $true }
            'Owner' { $copy.tags['managed-by'] = 'another-owner' }
            'Pending' { $copy.properties.provisioningState = 'RegisteringDns' }
        }
        if (Test-LeafCredentialVaultProperties $copy $fixture $identifier) { throw 'VaultSecurityDriftFixtureAccepted' }
        $checks++
    }
    $null = $vault.properties.Remove('accessPolicies')
    $null = $vault.properties.networkAcls.Remove('virtualNetworkRules')
    if (-not (Test-LeafCredentialVaultProperties $vault $fixture $identifier)) { throw 'OmittedEmptyVaultArraysMustBeAccepted' }
    Import-Module Az.Resources -ErrorAction Stop
    $nativeVault = [Microsoft.Azure.Management.Resources.Models.WhatIfChange]::new()
    $nativeVault.ResourceId = $vaultId
    $nativeVault.ChangeType = 'Create'
    $nativeRole = [Microsoft.Azure.Management.Resources.Models.WhatIfChange]::new()
    $nativeRole.ResourceId = $roleChange.FullyQualifiedResourceId
    $nativeRole.ChangeType = 'Create'
    $nativeRole.After = [Newtonsoft.Json.Linq.JObject]::Parse(($roleChange.After | ConvertTo-Json -Depth 15))
    $nativeChanges = @([Microsoft.Azure.Commands.ResourceManager.Cmdlets.SdkModels.Deployments.PSWhatIfChange]::new($nativeVault), [Microsoft.Azure.Commands.ResourceManager.Cmdlets.SdkModels.Deployments.PSWhatIfChange]::new($nativeRole))
    $null = Get-LeafCredentialVaultChanges @{ Status = 'Succeeded'; Changes = $nativeChanges } $vaultId $identifier $roleId
    $checks += 2
    [pscustomobject]@{ Status = 'CredentialVaultOfflineChecksPassed'; Checks = $checks; CloudRequests = 0; SecretValuesRequested = $false }
    return
}

$settings = Read-LeafPrivateTarget $repo
$inputs = Read-LeafCredentialVaultInputs ([IO.File]::ReadAllText((Join-Path $repo '.env')))
$context = Get-AzContext
Assert-LeafTargetContext $settings $context
if ($context.Account.Type -cne 'User') { throw 'ExistingTargetUserSessionRequired' }
$group = $inputs.TARGET_IDENTITY_RESOURCE_GROUP
$groupId = '/subscriptions/' + $settings.TARGET_SUBSCRIPTION_ID + '/resourceGroups/' + $group
$vmId = $inputs.TARGET_IDENTITY_CREDENTIAL_VM_ID
if (-not $vmId.StartsWith($groupId + '/providers/Microsoft.Compute/virtualMachines/', [StringComparison]::OrdinalIgnoreCase) -or ($vmId -split '/')[-1] -cnotmatch '^vm-identity-swc-[0-9]{3}-sync$') { throw 'OriginalIdentityMemberInConfiguredGroupRequired' }
$parameters = @{ vaultName = $inputs.TARGET_IDENTITY_KEY_VAULT_NAME; location = $inputs.TARGET_IDENTITY_KEY_VAULT_LOCATION; operatorPrincipalId = $inputs.TARGET_IDENTITY_KEY_VAULT_OPERATOR_ID; allowedIpv4Addresses = @($inputs.TARGET_IDENTITY_KEY_VAULT_CLIENT_IPV4) }
$vaultId = $groupId + '/providers/Microsoft.KeyVault/vaults/' + $parameters.vaultName
$roleId = '/subscriptions/' + $settings.TARGET_SUBSCRIPTION_ID + '/providers/Microsoft.Authorization/roleDefinitions/' + $officerRole
$folder = Join-Path $repo 'private/identity/keyvault'
$planPath = Join-Path $folder 'plan.json'
$sourceHash = (Get-FileHash -LiteralPath $template -Algorithm SHA256).Hash
$inputHash = Get-LeafCredentialVaultHash (($inputs.Keys | Sort-Object | ForEach-Object { $_ + '=' + $inputs[$_] }) -join "`n")

function Read-LeafCredentialVaultArm {
    param([string]$Id, [string]$Version, [switch]$AllowMissing)
    $response = Invoke-AzRestMethod -Method GET -Path ($Id + '?api-version=' + $Version) -DefaultProfile $context -ErrorAction Stop
    if ($AllowMissing -and $response.StatusCode -eq 404) { return $null }
    if ($response.StatusCode -ne 200) { throw 'CredentialVaultMetadataUnreadable' }
    return $response.Content | ConvertFrom-Json -AsHashtable -Depth 30 -DateKind String
}

function Save-LeafCredentialVaultPlan {
    $temporary = $planPath + '.' + [guid]::NewGuid().ToString('N') + '.tmp'
    try { [IO.File]::WriteAllText($temporary, ($plan | ConvertTo-Json -Depth 30), [Text.UTF8Encoding]::new($false)); [IO.File]::Move($temporary, $planPath, $true) }
    finally { if (Test-Path -LiteralPath $temporary) { [IO.File]::Delete($temporary) } }
}

try {
    $vm = Get-AzVM -ResourceGroupName $group -Name ($vmId -split '/')[-1] -DefaultProfile $context -ErrorAction Stop
    if ($vm.Id -ine $vmId -or [string]$vm.VmId -ine $inputs.TARGET_IDENTITY_CREDENTIAL_VM_INSTANCE_ID -or $vm.Tags['managed-by'] -cne 'bicep') { throw 'OriginalIdentityMemberBindingMismatch' }
    $operator = Get-AzADUser -SignedIn -ErrorAction Stop
    if ($operator.Id -ine $parameters.operatorPrincipalId -or $operator.UserPrincipalName -ine $context.Account.Id) { throw 'ConfiguredVaultOperatorMustBeSignedInUser' }
    $provider = Get-AzResourceProvider -ProviderNamespace Microsoft.KeyVault -DefaultProfile $context -ErrorAction Stop
    if ($provider.RegistrationState -cne 'Registered' -or '2025-05-01' -notin @($provider.ResourceTypes | Where-Object ResourceTypeName -CEQ vaults).ApiVersions) { throw 'PinnedKeyVaultProviderApiNotReady' }
    $vault = Read-LeafCredentialVaultArm $vaultId '2025-05-01' -AllowMissing
    if ($vault -and ($vault.tags['managed-by'] -cne 'bicep' -or $vault.tags.workload -cne 'identity')) { throw 'UnownedExistingVaultCannotBeAdopted' }
    $privateTargetHash = Get-LeafCredentialVaultHash ($settings.TARGET_TENANT_ID + '/' + $settings.TARGET_SUBSCRIPTION_ID)
    $plan = if (Test-Path -LiteralPath $planPath) { Get-Content -LiteralPath $planPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String } else { $null }
    if (($Mode -cne 'Preview' -or $plan) -and (-not $plan -or $plan.sourceHash -cne $sourceHash -or $plan.inputHash -cne $inputHash -or $plan.targetHash -cne $privateTargetHash -or $plan.vaultId -ine $vaultId)) { throw 'MatchingPrivateCredentialVaultPreviewRequired' }
    if ($vault -and (-not $plan -or $plan.status -cnotin @('Applying', 'AppliedAwaitingVerification', 'Verified'))) { throw 'ExistingVaultWithoutMatchingCreationReceiptCannotBeAdopted' }
    $ready = $false
    if ($vault -and $plan -and $plan.vaultId -ieq $vaultId -and $plan.roleAssignmentId -and (Test-LeafCredentialVaultProperties $vault $inputs $settings.TARGET_TENANT_ID)) {
        if (-not $plan.roleAssignmentId.StartsWith($vaultId + '/providers/Microsoft.Authorization/roleAssignments/', [StringComparison]::OrdinalIgnoreCase)) { throw 'ScopedVaultRoleReadbackRequired' }
        $role = Read-LeafCredentialVaultArm $plan.roleAssignmentId '2022-04-01' -AllowMissing
        $ready = $role -and $role.properties.principalId -ieq $parameters.operatorPrincipalId -and $role.properties.roleDefinitionId -ieq $roleId -and $role.properties.principalType -ceq 'User' -and $role.properties.scope -ieq $vaultId
    }
    if ($ready) {
        $plan.status = 'Verified'
        Save-LeafCredentialVaultPlan
        [pscustomobject]@{ Status = 'NoChange'; VaultAndScopedRoleVerified = $true; FirewallExactClientOnly = $true; SecretValuesRequested = $false; CloudChanges = 0 }
        return
    }
    if ($Mode -ceq 'Verify') { throw 'CredentialVaultReadbackDoesNotMatchDesiredState' }
    if ($vault) { throw 'ExistingVaultDriftRequiresSeparateReviewNoMutation' }
    $compiledJson = (& az bicep build --file $template --stdout 2>$null) -join "`n"
    if ($LASTEXITCODE -ne 0 -or (Get-FileHash -LiteralPath $template -Algorithm SHA256).Hash -cne $sourceHash) { throw 'CredentialVaultSourceChangedDuringCompile' }
    $compiledTemplate = $compiledJson | ConvertFrom-Json -AsHashtable -Depth 70
    $whatIf = Get-AzResourceGroupDeploymentWhatIfResult -ResourceGroupName $group -TemplateObject $compiledTemplate -TemplateParameterObject $parameters -Mode Incremental -ResultFormat FullResourcePayloads -DefaultProfile $context -ErrorAction Stop
    $changes = @(Get-LeafCredentialVaultChanges $whatIf $vaultId $parameters.operatorPrincipalId $roleId)
    $signature = Get-LeafCredentialVaultHash (ConvertTo-Json -InputObject @($changes | Sort-Object ResourceId) -Depth 70 -Compress)
    if ($Mode -ceq 'Preview') {
        if ($plan -and $plan.status -ceq 'Applying') { throw 'PreviousVaultApplyNeedsReadbackBeforeNewPreview' }
        $null = [IO.Directory]::CreateDirectory($folder)
        $plan = @{ status = 'Previewed'; createdUtc = [DateTimeOffset]::UtcNow.ToString('o'); sourceHash = $sourceHash; inputHash = $inputHash; targetHash = $privateTargetHash; vaultId = $vaultId; signature = $signature; roleAssignmentId = @($changes | Where-Object ResourceId -INE $vaultId)[0].ResourceId; changes = @($changes | Select-Object ResourceId, ChangeType) }
        Save-LeafCredentialVaultPlan
        [pscustomobject]@{ Status = 'CredentialVaultPreviewReady'; Resources = $changes.Count; Creates = @($changes | Where-Object ChangeType -EQ Create).Count; Modifies = @($changes | Where-Object ChangeType -EQ Modify).Count; ExistingVmGroupOnly = $true; FirewallExactClientOnly = $true; SecretValuesRequested = $false; CloudChanges = 0 }
        return
    }
    if ($plan.status -cne 'Previewed' -or [DateTimeOffset]::UtcNow -gt [DateTimeOffset]::Parse($plan.createdUtc).AddMinutes(30) -or $plan.signature -cne $signature) { throw 'FreshUnchangedVaultPreviewRequired' }
    Assert-LeafTargetContext $settings (Get-AzContext)
    $freshInputs = Read-LeafCredentialVaultInputs ([IO.File]::ReadAllText((Join-Path $repo '.env')))
    $freshHash = Get-LeafCredentialVaultHash (($freshInputs.Keys | Sort-Object | ForEach-Object { $_ + '=' + $freshInputs[$_] }) -join "`n")
    if ($freshHash -cne $inputHash -or (Get-FileHash -LiteralPath $template -Algorithm SHA256).Hash -cne $sourceHash) { throw 'CredentialVaultInputsOrSourceChangedNoApply' }
    $plan.status = 'Applying'
    Save-LeafCredentialVaultPlan
    $deployment = New-AzResourceGroupDeployment -Name 'identity-credential-vault' -ResourceGroupName $group -TemplateObject $compiledTemplate -TemplateParameterObject $parameters -Mode Incremental -DefaultProfile $context -ErrorAction Stop
    if ($deployment.ProvisioningState -cne 'Succeeded') { throw 'CredentialVaultApplyNotConfirmed' }
    $plan.status = 'AppliedAwaitingVerification'
    Save-LeafCredentialVaultPlan
    [pscustomobject]@{ Status = 'CredentialVaultAppliedVerifyNext'; ExistingVmGroupOnly = $true; SecretValuesRequested = $false; CredentialValuesStored = 0 }
} catch {
    $safe = [string]$_.Exception.Message
    if ($safe -notmatch '^[A-Za-z]+$') { $safe = 'CredentialVaultOperationStoppedInspectPrivatePlanBeforeRetry' }
    throw $safe
}