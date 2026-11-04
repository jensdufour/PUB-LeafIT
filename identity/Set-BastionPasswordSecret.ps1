#requires -Version 7.6
[CmdletBinding()]
param(
    [ValidateSet('Preview', 'Apply', 'Readback')][string]$Mode = 'Preview',
    [switch]$CheckOnly
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
. (Join-Path $PSScriptRoot 'Target.ps1')
$source = Join-Path $PSScriptRoot 'keyvault/secret.bicep'

function Assert-LeafPasswordTemplate {
    param($Template)
    $resources = @($Template.resources)
    $versionExpression = "[last(split(reference(resourceId('Microsoft.KeyVault/vaults/secrets', parameters('vaultName'), parameters('secretName')), '2025-05-01').secretUriWithVersion, '/'))]"
    if ($Template.parameters.Count -ne 3 -or $Template.parameters.secretValue.type -cne 'securestring' -or $Template.parameters.vaultName.type -cne 'string' -or $Template.parameters.secretName.type -cne 'string' -or $Template.outputs.Count -ne 1 -or $Template.outputs.versionId.type -cne 'string' -or $Template.outputs.versionId.value -cne $versionExpression -or $resources.Count -ne 1 -or $resources[0].type -cne 'Microsoft.KeyVault/vaults/secrets' -or $resources[0].apiVersion -cne '2025-05-01' -or $resources[0].name -cne "[format('{0}/{1}', parameters('vaultName'), parameters('secretName'))]" -or $resources[0].properties.value -cne "[parameters('secretValue')]" -or $resources[0].properties.contentType -cne 'text/plain' -or $resources[0].properties.attributes.enabled -cne $true) { throw 'OnlyOneSecurePasswordSecretTemplateAllowed' }
}

function Read-LeafPasswordSelector {
    param([string]$Text)
    $entries = [regex]::Matches($Text, '(?m)^[ \t]*TARGET_IDENTITY_BASTION_PASSWORD_SECRET_NAME[ \t]*=[ \t]*(?<value>[^\r\n]*)')
    if ($entries.Count -ne 1) { throw 'OnePrivateBastionPasswordSecretSelectorRequired' }
    $name = $entries[0].Groups['value'].Value.Trim().Trim([char]34, [char]39)
    if ($name -cnotmatch '^[A-Za-z0-9-]{1,127}$') { throw 'ValidBastionPasswordSecretSelectorRequired' }
    return $name
}

function Assert-LeafPasswordDeploymentId {
    param([string]$Id, [string]$GroupId)
    if ($Id -cnotmatch ('^' + [regex]::Escape($GroupId) + '/providers/Microsoft\.Resources/deployments/identity-password-[a-f0-9]{32}$')) { throw 'ExactOneUsePasswordDeploymentRequired' }
}

function Test-LeafPasswordVaultBinding {
    param($Original, $Current)
    foreach ($key in @('vaultId', 'inputHash', 'targetHash', 'roleAssignmentId', 'sourceHash', 'publicIntentPlanHash')) {
        if ([string]::IsNullOrWhiteSpace([string]$Original[$key]) -or $Original[$key] -cne $Current[$key]) { return $false }
    }
    return $Current.status -ceq 'Verified'
}

function Get-LeafPasswordDeploymentVersion {
    param($Deployment, [string]$ExpectedId, [string]$VaultName, [string]$SecretName)
    if ($Deployment.id -ine $ExpectedId -or $Deployment.properties.provisioningState -cne 'Succeeded' -or $Deployment.properties.parameters.vaultName.value -cne $VaultName -or $Deployment.properties.parameters.secretName.value -cne $SecretName -or $Deployment.properties.outputs.Count -ne 1 -or $Deployment.properties.outputs.versionId.type -ine 'string' -or [string]$Deployment.properties.outputs.versionId.value -cnotmatch '^[a-f0-9]{32}$') { throw 'ExactSubmittedPasswordDeploymentReadbackRequired' }
    return [string]$Deployment.properties.outputs.versionId.value
}

function Set-LeafPasswordRequestContent {
    param([Net.Http.HttpRequestMessage]$Request, $Template, [string]$VaultName, [string]$SecretName, [Security.SecureString]$Password)
    $pointer = [IntPtr]::Zero
    $plain = $body = $document = $null
    try {
        if (-not $Password -or $Password.Length -eq 0) { throw 'NonemptyMaskedPasswordRequired' }
        Assert-LeafPasswordTemplate $Template
        $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
        $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
        $document = @{ properties = @{ mode = 'Incremental'; template = $Template; parameters = @{ vaultName = @{ value = $VaultName }; secretName = @{ value = $SecretName }; secretValue = @{ value = $plain } } } }
        $body = $document | ConvertTo-Json -Depth 50 -Compress
        $Request.Content = [Net.Http.StringContent]::new($body, [Text.Encoding]::UTF8, 'application/json')
    } finally {
        if ($pointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
        $plain = $body = $document = $null
    }
}

function Get-LeafPasswordVersionHash {
    param($Metadata, [string]$ExpectedId, [string]$ExpectedVaultName, [string]$ExpectedSecretName)
    if ($Metadata.id -ine $ExpectedId -or $Metadata.properties.attributes.enabled -cne $true -or $Metadata.properties.contentType -cne 'text/plain' -or -not [string]::IsNullOrEmpty([string]$Metadata.properties.value)) { throw 'ExactEnabledPasswordMetadataOnlyRequired' }
    $uri = [uri]$Metadata.properties.secretUriWithVersion
    if (-not $uri.IsAbsoluteUri -or $uri.Scheme -cne 'https' -or $uri.Host -cne ($ExpectedVaultName + '.vault.azure.net') -or $uri.Port -ne 443 -or $uri.Query -or $uri.Fragment -or $uri.UserInfo -or $uri.AbsolutePath -cnotmatch ('^/secrets/' + [regex]::Escape($ExpectedSecretName) + '/[a-f0-9]{32}$')) { throw 'ExactUnsignedSecretVersionReferenceRequired' }
    return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($uri.AbsoluteUri)))
}

function Read-LeafPasswordArmMetadata {
    param([string]$Id, [string]$Version, [switch]$AllowMissing)
    try { $response = Invoke-AzRestMethod -Method GET -Path ($Id + '?api-version=' + $Version) -DefaultProfile $context -ErrorAction Stop }
    catch { throw 'PasswordSecretManagementMetadataReadStopped' }
    if ($AllowMissing -and $response.StatusCode -eq 404) { return $null }
    if ($response.StatusCode -ne 200) { throw 'PasswordSecretManagementMetadataUnreadable' }
    return $response.Content | ConvertFrom-Json -AsHashtable -Depth 40 -DateKind String
}

function Save-LeafPasswordState {
    param($State, [string]$Path, [switch]$CreateOnly)
    $data = [Text.UTF8Encoding]::new($false).GetBytes(($State | ConvertTo-Json -Depth 15))
    $stream = [IO.File]::Open($Path, $(if ($CreateOnly) { [IO.FileMode]::CreateNew } else { [IO.FileMode]::Create }), [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $stream.Write($data, 0, $data.Length); $stream.Flush($true) } finally { $stream.Dispose() }
}

if ($CheckOnly) {
    if ($Mode -cne 'Preview') { throw 'PasswordOfflineChecksCannotSubmit' }
    $compiled = (& az bicep build --file $source --stdout 2>$null) -join "`n"
    if ($LASTEXITCODE -ne 0) { throw 'PasswordTemplateCompilationFailed' }
    $template = $compiled | ConvertFrom-Json -AsHashtable -Depth 50
    Assert-LeafPasswordTemplate $template
    $checks = 1
    foreach ($bad in @('PlainParameter', 'ExtraResource', 'Output', 'DifferentValue', 'DifferentType', 'PasswordOutput')) {
        $copy = $template | ConvertTo-Json -Depth 50 | ConvertFrom-Json -AsHashtable -Depth 50
        switch ($bad) {
            'PlainParameter' { $copy.parameters.secretValue.type = 'string' }
            'ExtraResource' { $copy.resources += $copy.resources[0] }
            'Output' { $copy.outputs = @{ unexpected = @{ type = 'string'; value = 'NON_CREDENTIAL_OUTPUT_FIXTURE' } } }
            'DifferentValue' { $copy.resources[0].properties.value = 'NON_CREDENTIAL_LITERAL_FIXTURE' }
            'DifferentType' { $copy.resources[0].type = 'Microsoft.KeyVault/vaults' }
            'PasswordOutput' { $copy.outputs.versionId.value = "[parameters('secretValue')]" }
        }
        $rejected = $false
        try { Assert-LeafPasswordTemplate $copy } catch { $rejected = $true }
        if (-not $rejected) { throw 'UnsafePasswordTemplateFixtureAccepted' }
        $checks++
    }
    $password = ConvertTo-SecureString 'NON_CREDENTIAL_PASSWORD_FIXTURE_ONLY' -AsPlainText -Force
    $request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Put, 'https://management.azure.com/SYNTHETIC-DEPLOYMENT-REFERENCE')
    try {
        Set-LeafPasswordRequestContent $request $template 'kv-example' 'example-password' $password
        $payload = $request.Content.ReadAsStringAsync().GetAwaiter().GetResult() | ConvertFrom-Json -AsHashtable -Depth 50
        if ($payload.properties.parameters.secretValue.value -cne 'NON_CREDENTIAL_PASSWORD_FIXTURE_ONLY' -or $payload.properties.template.parameters.secretValue.type -cne 'securestring' -or $payload.properties.mode -cne 'Incremental') { throw 'ProtectedPasswordRequestFixtureFailed' }
        $checks++
    } finally { $request.Dispose(); $password.Dispose(); $payload = $null }
    $metadata = @{ id = '/SYNTHETIC-SECRET-REFERENCE'; properties = @{ attributes = @{ enabled = $true }; contentType = 'text/plain'; secretUriWithVersion = 'https://kv-example.vault.azure.net/secrets/example-password/' + ('a' * 32) } }
    if ((Get-LeafPasswordVersionHash $metadata $metadata.id 'kv-example' 'example-password') -cnotmatch '^[A-F0-9]{64}$') { throw 'PasswordVersionHashFixtureFailed' }
    foreach ($bad in @('DifferentResource', 'DifferentHost', 'UnsignedQueryRequired', 'Disabled', 'RawValue')) {
        $copy = $metadata | ConvertTo-Json -Depth 15 | ConvertFrom-Json -AsHashtable
        switch ($bad) {
            'DifferentResource' { $copy.id = '/SYNTHETIC-OTHER-REFERENCE' }
            'DifferentHost' { $copy.properties.secretUriWithVersion = $copy.properties.secretUriWithVersion.Replace('kv-example.', 'other-example.') }
            'UnsignedQueryRequired' { $copy.properties.secretUriWithVersion += '?NON_CREDENTIAL_QUERY_FIXTURE' }
            'Disabled' { $copy.properties.attributes.enabled = $false }
            'RawValue' { $copy.properties.value = 'NON_CREDENTIAL_UNEXPECTED_VALUE_FIXTURE' }
        }
        $rejected = $false
        try { $null = Get-LeafPasswordVersionHash $copy $metadata.id 'kv-example' 'example-password' } catch { $rejected = $true }
        if (-not $rejected) { throw 'UnsafePasswordMetadataFixtureAccepted' }
        $checks++
    }
    $deploymentId = '/SYNTHETIC-GROUP-REFERENCE/providers/Microsoft.Resources/deployments/identity-password-' + ('b' * 32)
    Assert-LeafPasswordDeploymentId $deploymentId '/SYNTHETIC-GROUP-REFERENCE'
    $deployment = @{ id = $deploymentId; properties = @{ provisioningState = 'Succeeded'; parameters = @{ vaultName = @{ value = 'kv-example' }; secretName = @{ value = 'example-password' } }; outputs = @{ versionId = @{ type = 'String'; value = 'a' * 32 } } } }
    if ((Get-LeafPasswordDeploymentVersion $deployment $deploymentId 'kv-example' 'example-password') -cne ('a' * 32)) { throw 'PasswordDeploymentVersionFixtureFailed' }
    foreach ($bad in @('Deployment', 'Vault', 'Secret', 'Version', 'Pending')) {
        $copy = $deployment | ConvertTo-Json -Depth 20 | ConvertFrom-Json -AsHashtable
        switch ($bad) {
            'Deployment' { $copy.id = '/SYNTHETIC-OTHER-DEPLOYMENT' }
            'Vault' { $copy.properties.parameters.vaultName.value = 'other-vault' }
            'Secret' { $copy.properties.parameters.secretName.value = 'other-secret' }
            'Version' { $copy.properties.outputs.versionId.value = 'NON_CREDENTIAL_BAD_VERSION' }
            'Pending' { $copy.properties.provisioningState = 'Accepted' }
        }
        $rejected = $false
        try { $null = Get-LeafPasswordDeploymentVersion $copy $deploymentId 'kv-example' 'example-password' } catch { $rejected = $true }
        if (-not $rejected) { throw 'UnboundPasswordDeploymentFixtureAccepted' }
        $checks++
    }
    foreach ($bad in @('/SYNTHETIC-OTHER-GROUP/providers/Microsoft.Resources/deployments/identity-password-' + ('b' * 32), ($deploymentId + '/extra'))) {
        $rejected = $false
        try { Assert-LeafPasswordDeploymentId $bad '/SYNTHETIC-GROUP-REFERENCE' } catch { $rejected = $true }
        if (-not $rejected) { throw 'UnboundPasswordDeploymentIdFixtureAccepted' }
        $checks++
    }
    if ((Read-LeafPasswordSelector 'TARGET_IDENTITY_BASTION_PASSWORD_SECRET_NAME=example-password') -cne 'example-password') { throw 'PasswordSelectorFixtureFailed' }
    foreach ($bad in @('', "TARGET_IDENTITY_BASTION_PASSWORD_SECRET_NAME=example-password`nTARGET_IDENTITY_BASTION_PASSWORD_SECRET_NAME=other-password", 'TARGET_IDENTITY_BASTION_PASSWORD_SECRET_NAME=bad/name')) {
        $rejected = $false
        try { $null = Read-LeafPasswordSelector $bad } catch { $rejected = $true }
        if (-not $rejected) { throw 'AmbiguousPasswordSelectorFixtureAccepted' }
        $checks++
    }
    $binding = @{ status = 'Verified'; vaultId = '/SYNTHETIC-VAULT-REFERENCE'; inputHash = 'SYNTHETIC-INPUT-HASH'; targetHash = 'SYNTHETIC-TARGET-HASH'; roleAssignmentId = '/SYNTHETIC-ROLE-REFERENCE'; sourceHash = 'SYNTHETIC-SOURCE-HASH'; publicIntentPlanHash = 'SYNTHETIC-ORIGINAL-PLAN-HASH' }
    if (-not (Test-LeafPasswordVaultBinding $binding $binding)) { throw 'StablePasswordVaultBindingFixtureFailed' }
    foreach ($key in @('status', 'vaultId', 'inputHash', 'targetHash', 'roleAssignmentId', 'sourceHash', 'publicIntentPlanHash')) {
        $copy = $binding | ConvertTo-Json -Depth 10 | ConvertFrom-Json -AsHashtable
        $copy[$key] = 'SYNTHETIC-DIFFERENT-BINDING'
        if (Test-LeafPasswordVaultBinding $binding $copy) { throw 'PostPromptVaultRetargetFixtureAccepted' }
        $checks++
    }
    [pscustomobject]@{ Status = 'PasswordSecretOfflineChecksPassed'; Checks = $checks; CloudRequests = 0; RealCredentialsUsed = $false }
    return
}

try {
    $settings = Read-LeafPrivateTarget $repo
    $context = Get-AzContext
    Assert-LeafTargetContext $settings $context
    $verified = & (Join-Path $PSScriptRoot 'Deploy-CredentialVault.ps1') -Mode Verify
    if ($verified.Status -cne 'NoChange' -or $verified.PublicNetworkDisabled -cne $true -or $verified.VaultAndScopedRoleVerified -cne $true) { throw 'VerifiedUnchangedPrivateVaultRequired' }
    $folder = Join-Path $repo 'private/identity/keyvault'
    $vaultPlan = Get-Content -LiteralPath (Join-Path $folder 'private-intent-plan.json') -Raw | ConvertFrom-Json -AsHashtable -DateKind String
    $vaultId = [string]$vaultPlan.vaultId
    $vaultName = ($vaultId -split '/')[-1]
    $groupId = $vaultId.Substring(0, $vaultId.IndexOf('/providers/Microsoft.KeyVault/', [StringComparison]::OrdinalIgnoreCase))
    $group = ($groupId -split '/')[-1]
    $secretName = Read-LeafPasswordSelector ([IO.File]::ReadAllText((Join-Path $repo '.env')))
    $secretId = $vaultId + '/secrets/' + $secretName
    $sourceHash = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
    $bindingHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($settings.TARGET_TENANT_ID + '/' + $settings.TARGET_SUBSCRIPTION_ID + '/' + $secretId)))
    $previewPath = Join-Path $folder 'password-preview.json'
    $intentPath = Join-Path $folder 'password-intent.json'
    $intent = if (Test-Path -LiteralPath $intentPath) { Get-Content -LiteralPath $intentPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String } else { $null }
    if ($intent -and ($intent.bindingHash -cne $bindingHash -or $intent.sourceHash -cne $sourceHash)) { throw 'ExistingPasswordIntentMustNotBeRetargeted' }
    $metadata = Read-LeafPasswordArmMetadata $secretId '2025-05-01' -AllowMissing
    if ($intent) {
        Assert-LeafPasswordDeploymentId $intent.deploymentId $groupId
        $deployment = Read-LeafPasswordArmMetadata $intent.deploymentId '2022-09-01' -AllowMissing
        if ($metadata -and $deployment.properties.provisioningState -ceq 'Succeeded') {
            $version = Get-LeafPasswordDeploymentVersion $deployment $intent.deploymentId $vaultName $secretName
            $versionHash = Get-LeafPasswordVersionHash $metadata $secretId $vaultName $secretName
            $expectedVersionHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes('https://' + $vaultName + '.vault.azure.net/secrets/' + $secretName + '/' + $version)))
            if ($expectedVersionHash -cne $versionHash -or ($intent.versionHash -and $intent.versionHash -cne $versionHash)) { throw 'PasswordSecretVersionChangedNoOverwrite' }
            $intent.status = 'Verified'
            $intent['versionHash'] = $versionHash
            Save-LeafPasswordState $intent $intentPath
            [pscustomobject]@{ Status = 'NoChange'; PasswordSecretMetadataVerified = $true; SecretValueRead = $false; CredentialIdentityVerified = $false; PublicAccessChanged = $false; CloudChanges = 0 }
            return
        }
        [pscustomobject]@{ Status = 'PasswordSubmissionNeedsReadbackNoReplay'; DeploymentFound = [bool]$deployment; SecretMetadataFound = [bool]$metadata; PasswordPromptRepeated = $false; CloudChanges = 0 }
        return
    }
    if ($metadata) { throw 'ExistingPasswordSecretCannotBeOverwrittenOrAdopted' }
    if ($Mode -ceq 'Readback') { throw 'NoPasswordSubmissionIntentExists' }
    $compiled = (& az bicep build --file $source --stdout 2>$null) -join "`n"
    if ($LASTEXITCODE -ne 0 -or (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash -cne $sourceHash) { throw 'PasswordTemplateCompilationOrSourceCheckFailed' }
    $template = $compiled | ConvertFrom-Json -AsHashtable -Depth 50
    Assert-LeafPasswordTemplate $template
    if ($Mode -ceq 'Preview') {
        $validation = @(Test-AzResourceGroupDeployment -ResourceGroupName $group -TemplateObject $template -TemplateParameterObject @{ vaultName = $vaultName; secretName = $secretName; secretValue = 'NON_CREDENTIAL_TEMPLATE_VALIDATION_ONLY' } -Mode Incremental -DefaultProfile $context -ErrorAction Stop)
        if ($validation.Count) { throw 'PasswordSecretArmValidationFailedNoCredentialPrompt' }
        $preview = @{ status = 'Previewed'; createdUtc = [DateTimeOffset]::UtcNow.ToString('o'); bindingHash = $bindingHash; sourceHash = $sourceHash; deploymentId = $groupId + '/providers/Microsoft.Resources/deployments/identity-password-' + [guid]::NewGuid().ToString('N') }
        Save-LeafPasswordState $preview $previewPath
        [pscustomobject]@{ Status = 'PrivatePasswordWritePreviewReady'; Resources = 1; RealPasswordRequested = $false; ArmValidationPassed = $true; PublicAccessChanged = $false; CloudChanges = 0 }
        return
    }
    $preview = Get-Content -LiteralPath $previewPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String
    if ($preview.bindingHash -cne $bindingHash -or $preview.sourceHash -cne $sourceHash -or [DateTimeOffset]::UtcNow -gt [DateTimeOffset]::Parse($preview.createdUtc).AddMinutes(30)) { throw 'FreshMatchingPasswordPreviewRequired' }
    Assert-LeafPasswordDeploymentId $preview.deploymentId $groupId
    $password = $secureToken = $token = $client = $handler = $request = $response = $null
    $pointer = [IntPtr]::Zero
    try {
        $password = Read-Host 'Existing VM/Bastion password to store (hidden; no password reset)' -AsSecureString
        if (-not $password -or $password.Length -eq 0) { throw 'NonemptyMaskedPasswordRequired' }
        Assert-LeafTargetContext $settings (Get-AzContext)
        $fresh = & (Join-Path $PSScriptRoot 'Deploy-CredentialVault.ps1') -Mode Verify
        $freshContext = Get-AzContext
        $freshVaultPlan = Get-Content -LiteralPath (Join-Path $folder 'private-intent-plan.json') -Raw | ConvertFrom-Json -AsHashtable -DateKind String
        if ($fresh.Status -cne 'NoChange' -or $fresh.PublicNetworkDisabled -cne $true -or $fresh.VaultAndScopedRoleVerified -cne $true -or -not (Test-LeafPasswordVaultBinding $vaultPlan $freshVaultPlan) -or $freshContext.Account.Id -ine $context.Account.Id -or (Read-LeafPasswordSelector ([IO.File]::ReadAllText((Join-Path $repo '.env')))) -cne $secretName -or (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash -cne $sourceHash -or [DateTimeOffset]::UtcNow -gt [DateTimeOffset]::Parse($preview.createdUtc).AddMinutes(30) -or (Read-LeafPasswordArmMetadata $secretId '2025-05-01' -AllowMissing)) { throw 'PasswordTargetChangedOrPreviewExpiredNoSubmit' }
        $token = Get-AzAccessToken -ResourceUrl 'https://management.azure.com/' -TenantId $settings.TARGET_TENANT_ID -DefaultProfile $context -ErrorAction Stop
        $secureToken = $token.Token
        if ($secureToken -isnot [Security.SecureString] -or $token.TenantId -ine $settings.TARGET_TENANT_ID -or $token.ExpiresOn -le [DateTimeOffset]::UtcNow) { throw 'CurrentOpaqueTargetArmTokenRequired' }
        $handler = [Net.Http.HttpClientHandler]::new()
        $handler.AllowAutoRedirect = $false
        $handler.UseCookies = $false
        $client = [Net.Http.HttpClient]::new($handler, $true)
        $handler = $null
        $client.Timeout = [TimeSpan]::FromSeconds(180)
        $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureToken)
        $client.DefaultRequestHeaders.Authorization = [Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer', [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer))
        $request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Put, ('https://management.azure.com' + $preview.deploymentId + '?api-version=2022-09-01'))
        $request.Headers.IfNoneMatch.Add([Net.Http.Headers.EntityTagHeaderValue]::Any)
        Set-LeafPasswordRequestContent $request $template $vaultName $secretName $password
        $intent = @{ status = 'SubmittingNoReplay'; bindingHash = $bindingHash; sourceHash = $sourceHash; deploymentId = $preview.deploymentId; requestedUtc = [DateTimeOffset]::UtcNow.ToString('o') }
        Save-LeafPasswordState $intent $intentPath -CreateOnly
        $response = $client.SendAsync($request, [Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
        if ([int]$response.StatusCode -notin @(200, 201, 202)) { throw 'PasswordSubmissionNotAcceptedInspectIntentNoReplay' }
        $intent.status = 'AcceptedAwaitingReadback'
        Save-LeafPasswordState $intent $intentPath
        [pscustomobject]@{ Status = 'PasswordSubmittedReadbackRequired'; SecureArmParameterUsed = $true; PasswordPersistedLocally = $false; PasswordValueReturned = $false; CredentialIdentityVerified = $false; PublicAccessChanged = $false }
    } finally {
        if ($pointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
        if ($response) { $response.Dispose() }; if ($request) { $request.Dispose() }; if ($client) { $client.Dispose() }; if ($handler) { $handler.Dispose() }
        if ($password) { $password.Dispose() }; if ($secureToken) { $secureToken.Dispose() }
        $password = $secureToken = $token = $null
    }
} catch {
    $safe = [string]$_.Exception.Message
    if ($safe -notmatch '^[A-Za-z]+$') { $safe = 'PrivatePasswordOperationStoppedInspectIntentBeforeRetry' }
    throw $safe
}