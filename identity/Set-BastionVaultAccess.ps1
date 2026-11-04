#requires -Version 7.6
[CmdletBinding()]
param(
    [ValidateSet('Preview', 'Open', 'Close', 'Readback')][string]$Mode = 'Preview',
    [switch]$CheckOnly
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
. (Join-Path $PSScriptRoot 'Target.ps1')

function ConvertTo-LeafVaultWindowCanonical {
    param($Value)
    if ($Value -is [Collections.IDictionary]) {
        $copy = [Collections.Generic.SortedDictionary[string, object]]::new([StringComparer]::Ordinal)
        foreach ($key in $Value.PSBase.Keys) { $copy.Add([string]$key, (ConvertTo-LeafVaultWindowCanonical $Value[$key])) }
        return $copy
    }
    if ($Value -is [array]) { return ,@($Value | ForEach-Object { ConvertTo-LeafVaultWindowCanonical $_ }) }
    return $Value
}

function Get-LeafVaultWindowHash {
    param($Value)
    return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes((ConvertTo-LeafVaultWindowCanonical $Value | ConvertTo-Json -Depth 80 -Compress))))
}

function New-LeafVaultWindowAcl {
    param([string]$Address)
    $parsed = [Net.IPAddress]::None
    if (-not [Net.IPAddress]::TryParse($Address, [ref]$parsed) -or $parsed.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or $parsed.ToString() -cne $Address -or $Address -match '^(0\.|10\.|127\.|169\.254\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.|22[4-9]\.|2[3-5][0-9]\.)') { throw 'ExactPublicClientIpv4Required' }
    return @{ defaultAction = 'Deny'; bypass = 'None'; ipRules = @(@{ value = $Address + '/32' }); virtualNetworkRules = @() }
}

function Get-LeafVaultWindowNetworkHash {
    param($Acl)
    foreach ($key in $Acl.PSBase.Keys) { if ($key -cnotin @('defaultAction', 'bypass', 'ipRules', 'virtualNetworkRules')) { throw 'UnreviewedVaultNetworkProperty' } }
    $rules = @(foreach ($rule in @($Acl.ipRules | Where-Object { $null -ne $_ })) {
        $address = [Net.IPAddress]::None
        $value = [string]$rule.value
        if ([Net.IPAddress]::TryParse($value, [ref]$address) -and $address.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork -and $address.ToString() -ceq $value) { $value += '/32' }
        @{ value = $value }
    })
    return Get-LeafVaultWindowHash @{ defaultAction = $Acl.defaultAction; bypass = $Acl.bypass; ipRules = $rules; virtualNetworkRules = @($Acl.virtualNetworkRules | Where-Object { $null -ne $_ }) }
}

function Test-LeafVaultWindowExclusion {
    param($Definition)
    $clauses = @($Definition.properties.policyRule['if']['allOf'] | Where-Object { $_ -is [Collections.IDictionary] -and $_.Contains('not') })
    $matches = @($clauses | ForEach-Object { $_['not']['anyOf'] } | Where-Object {
        $_ -is [Collections.IDictionary] -and (([string]$_['field'] -replace '\s', '') -ieq "[concat('tags[',parameters('AllowedTagName'),']')]") -and (([string]$_['equals'] -replace '\s', '') -ieq "[parameters('AllowedTagValue')]")
    })
    return $matches.Count -eq 1
}

if ($CheckOnly) {
    if ($Mode -cne 'Preview') { throw 'VaultWindowChecksCannotOpenAccess' }
    $acl = New-LeafVaultWindowAcl '203.0.113.8'
    if ($acl.defaultAction -cne 'Deny' -or $acl.bypass -cne 'None' -or $acl.ipRules.Count -ne 1 -or $acl.ipRules[0].value -cne '203.0.113.8/32') { throw 'ExactClientWindowAclFixtureFailed' }
    $checks = 1
    foreach ($bad in @('*', '0.0.0.0/0', '10.0.0.1', '127.1', '::1', '100.64.0.1', '224.0.0.1')) {
        $rejected = $false
        try { $null = New-LeafVaultWindowAcl $bad } catch { $rejected = $true }
        if (-not $rejected) { throw 'BroadClientWindowFixtureAccepted' }
        $checks++
    }
    $definition = @{ properties = @{ policyRule = @{ 'if' = @{ allOf = @(@{ not = @{ anyOf = @(@{ field = "[concat('tags[', parameters('AllowedTagName'), ']')]"; equals = "[parameters('AllowedTagValue')]" }) } }) } } } }
    if (-not (Test-LeafVaultWindowExclusion $definition)) { throw 'ExactDocumentedExclusionFixtureNotRecognized' }
    $definition.properties.policyRule['if'].allOf[0].not.anyOf[0].equals = 'UNREVIEWED_NON_CREDENTIAL_VALUE'
    if (Test-LeafVaultWindowExclusion $definition) { throw 'DifferentPolicyExclusionFixtureAccepted' }
    $checks += 2
    if ((Get-LeafVaultWindowHash ([ordered]@{ second = 2; first = @{ value = 1 } })) -cne (Get-LeafVaultWindowHash ([ordered]@{ first = @{ value = 1 }; second = 2 }))) { throw 'NetworkMetadataOrderingMustNotChangeFingerprint' }
    $checks++
    $equivalent = @{ defaultAction = 'Deny'; bypass = 'None'; ipRules = @(@{ value = '203.0.113.8' }) }
    if ((Get-LeafVaultWindowNetworkHash $acl) -cne (Get-LeafVaultWindowNetworkHash $equivalent)) { throw 'EquivalentHostPrefixAndOmittedArraysMustMatch' }
    $equivalent.ipRules += @{ value = '203.0.113.9' }
    if ((Get-LeafVaultWindowNetworkHash $acl) -ceq (Get-LeafVaultWindowNetworkHash $equivalent)) { throw 'AdditionalVaultNetworkRuleMustNotBeNormalizedAway' }
    $checks += 2
    [pscustomobject]@{ Status = 'VaultWindowOfflineChecksPassed'; Checks = $checks; CloudRequests = 0; SecretValuesRequested = $false }
    return
}

function Read-LeafVaultWindowArm {
    param([string]$Id, [string]$Version)
    try { $response = Invoke-AzRestMethod -Method GET -Path ($Id + '?api-version=' + $Version) -DefaultProfile $context -ErrorAction Stop } catch { throw 'VaultWindowMetadataReadStopped' }
    if ($response.StatusCode -ne 200) { throw 'VaultWindowMetadataUnreadable' }
    return $response.Content | ConvertFrom-Json -AsHashtable -Depth 80 -DateKind String
}

function Send-LeafVaultWindowPatch {
    param([string]$Id, [string]$Version, $Body)
    Assert-LeafTargetContext $settings (Get-AzContext)
    try { $response = Invoke-AzRestMethod -Method PATCH -Path ($Id + '?api-version=' + $Version) -Payload ($Body | ConvertTo-Json -Depth 35 -Compress) -DefaultProfile $context -ErrorAction Stop } catch { throw 'VaultWindowMutationStoppedInspectStateBeforeRetry' }
    if ($response.StatusCode -notin @(200, 201, 202)) { throw 'VaultWindowMutationNotAcceptedInspectState' }
}

function Save-LeafVaultWindowState {
    $temporary = $statePath + '.tmp'
    [IO.File]::WriteAllText($temporary, ($state | ConvertTo-Json -Depth 40), [Text.UTF8Encoding]::new($false))
    [IO.File]::Move($temporary, $statePath, $true)
}

try {
    $settings = Read-LeafPrivateTarget $repo
    $context = Get-AzContext
    Assert-LeafTargetContext $settings $context
    $folder = Join-Path $repo 'private/identity/keyvault'
    $review = Get-Content -LiteralPath (Join-Path $folder 'vault-window-review.json') -Raw | ConvertFrom-Json -AsHashtable -Depth 40 -DateKind String
    $plan = Get-Content -LiteralPath (Join-Path $folder 'private-intent-plan.json') -Raw | ConvertFrom-Json -AsHashtable -DateKind String
    if ($review.vaultId -ine $plan.vaultId -or $review.tenantId -ine $settings.TARGET_TENANT_ID -or $review.subscriptionId -ine $settings.TARGET_SUBSCRIPTION_ID -or ($Mode -cnotin @('Close', 'Readback') -and $review.sourceHash -cne (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash)) { throw 'MatchingExactVaultWindowReviewRequired' }
    $inputs = @{}
    $keys = @('TARGET_IDENTITY_VAULT_WINDOW_TAG_NAME', 'TARGET_IDENTITY_VAULT_WINDOW_TAG_VALUE')
    foreach ($line in [IO.File]::ReadLines((Join-Path $repo '.env'))) {
        $entry = [regex]::Match($line, '^\s*(?<key>TARGET_[A-Z0-9_]+)\s*=\s*(?<value>.*)$')
        if (-not $entry.Success -or $entry.Groups['key'].Value -cnotin $keys) { continue }
        if ($inputs.ContainsKey($entry.Groups['key'].Value)) { throw 'DuplicateVaultWindowTagInput' }
        $inputs[$entry.Groups['key'].Value] = $entry.Groups['value'].Value.Trim().Trim([char]34, [char]39)
    }
    foreach ($key in $keys) { if ($Mode -cnotin @('Close', 'Readback') -and [string]::IsNullOrWhiteSpace($inputs[$key])) { throw 'ReviewedVaultWindowTagInputsRequired' } }
    $tagName = $inputs.TARGET_IDENTITY_VAULT_WINDOW_TAG_NAME
    $tagValue = $inputs.TARGET_IDENTITY_VAULT_WINDOW_TAG_VALUE
    if ($Mode -cnotin @('Close', 'Readback') -and (Get-LeafVaultWindowHash $inputs) -cne $review.tagInputsHash) { throw 'VaultWindowTagInputsChanged' }
    $statePath = Join-Path $folder 'vault-window-state.json'
    $lock = [IO.File]::Open((Join-Path $folder 'vault-window.lock'), [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    try {
        $state = if (Test-Path -LiteralPath $statePath) { Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json -AsHashtable -Depth 40 -DateKind String } else { $null }
        $vault = Read-LeafVaultWindowArm $review.vaultId '2025-05-01'
        if ($vault.properties.tenantId -ine $settings.TARGET_TENANT_ID -or $vault.tags['managed-by'] -cne 'bicep' -or $vault.tags.workload -cne 'identity') { throw 'ExactIdentityOwnedVaultRequired' }
        if ($Mode -ceq 'Readback') {
            [pscustomobject]@{ Status = 'VaultWindowMetadataReadback'; PublicNetworkDisabled = $vault.properties.publicNetworkAccess -ceq 'Disabled'; OwnedWindowStatePresent = [bool]$state; PendingAction = $(if ($state.pendingAction -cin @('DisablePublic', 'RestoreNetwork', 'RemoveTag')) { $state.pendingAction } else { 'None' }); SecretValuesRequested = $false; CloudChanges = 0 }
            return
        }
        if ($Mode -ceq 'Close') {
            if (-not $state -or $state.vaultId -ine $review.vaultId) { throw 'OwnedVaultWindowStateRequiredForCleanup' }
            if ($vault.properties.publicNetworkAccess -cne 'Disabled') {
                if ($state.pendingAction -ceq 'DisablePublic') { [pscustomobject]@{ Status = 'VaultClosurePendingReadbackNoReplay'; PublicNetworkDisabled = $false; SecretValuesRequested = $false }; return }
                $state['pendingAction'] = 'DisablePublic'; Save-LeafVaultWindowState
                Send-LeafVaultWindowPatch $review.vaultId '2025-05-01' @{ properties = @{ publicNetworkAccess = 'Disabled' } }
                $vault = Read-LeafVaultWindowArm $review.vaultId '2025-05-01'
            }
            if ($vault.properties.publicNetworkAccess -cne 'Disabled') { [pscustomobject]@{ Status = 'VaultClosurePendingReadbackNoReplay'; PublicNetworkDisabled = $false; SecretValuesRequested = $false }; return }
            if ($state.pendingAction -ceq 'DisablePublic') { $state.pendingAction = $null; Save-LeafVaultWindowState }
            $currentNetworkHash = Get-LeafVaultWindowNetworkHash $vault.properties.networkAcls
            if ($currentNetworkHash -cne $state.originalNetworkHash -and $currentNetworkHash -cne $state.openNetworkHash) { throw 'VaultClosedButConcurrentNetworkChangeNeedsReview' }
            if ($currentNetworkHash -cne $state.originalNetworkHash) {
                if ($state.pendingAction -ceq 'RestoreNetwork') { [pscustomobject]@{ Status = 'VaultPrivateNetworkRestorePendingNoReplay'; PublicNetworkDisabled = $true; SecretValuesRequested = $false }; return }
                $state['pendingAction'] = 'RestoreNetwork'; Save-LeafVaultWindowState
                Send-LeafVaultWindowPatch $review.vaultId '2025-05-01' @{ properties = @{ publicNetworkAccess = 'Disabled'; networkAcls = $state.originalNetworkAcls } }
                $vault = Read-LeafVaultWindowArm $review.vaultId '2025-05-01'
            }
            if ((Get-LeafVaultWindowNetworkHash $vault.properties.networkAcls) -cne $state.originalNetworkHash) { [pscustomobject]@{ Status = 'VaultPrivateNetworkRestorePendingNoReplay'; PublicNetworkDisabled = $true; SecretValuesRequested = $false }; return }
            if ($state.pendingAction -ceq 'RestoreNetwork') { $state.pendingAction = $null; Save-LeafVaultWindowState }
            if ((Get-LeafVaultWindowHash $inputs) -cne $state.tagInputsHash) { throw 'VaultPrivateOriginalExceptionInputsRequiredForTagCleanup' }
            if ($vault.tags.ContainsKey($tagName)) {
                if ($vault.tags[$tagName] -cne $tagValue) { throw 'ChangedVaultExceptionTagMustNotBeRemoved' }
                if ($state.pendingAction -ceq 'RemoveTag') { [pscustomobject]@{ Status = 'VaultPrivateTagRemovalPendingNoReplay'; PublicNetworkDisabled = $true; SecretValuesRequested = $false }; return }
                $state['pendingAction'] = 'RemoveTag'; Save-LeafVaultWindowState
                Send-LeafVaultWindowPatch ($review.vaultId + '/providers/Microsoft.Resources/tags/default') '2021-04-01' @{ operation = 'Delete'; properties = @{ tags = @{ $tagName = $tagValue } } }
                $vault = Read-LeafVaultWindowArm $review.vaultId '2025-05-01'
            }
            if ($vault.tags.ContainsKey($tagName)) { [pscustomobject]@{ Status = 'VaultPrivateTagRemovalPendingNoReplay'; PublicNetworkDisabled = $true; SecretValuesRequested = $false }; return }
            if ($vault.properties.publicNetworkAccess -cne 'Disabled' -or (Get-LeafVaultWindowNetworkHash $vault.properties.networkAcls) -cne $state.originalNetworkHash) { throw 'VaultWindowCleanupReadbackMismatch' }
            $state['pendingAction'] = $null
            $state.status = 'Closed'
            $state['closedUtc'] = [DateTimeOffset]::UtcNow.ToString('o')
            Save-LeafVaultWindowState
            [pscustomobject]@{ Status = 'VaultWindowClosed'; PublicNetworkDisabled = $true; OriginalNetworkRulesRestored = $true; TemporaryExceptionTagAbsent = $true; SecretValuesRequested = $false }
            return
        }
        if ($state) { throw 'ExistingVaultWindowMustNotBeReplayed' }
        if ([DateTimeOffset]::UtcNow -gt [DateTimeOffset]::Parse($review.reviewedUtc).AddMinutes(30)) { throw 'FreshVaultWindowReviewRequired' }
        $definition = Read-LeafVaultWindowArm $review.definitionId '2023-04-01'
        $assignment = Read-LeafVaultWindowArm $review.assignmentId '2023-04-01'
        $initiative = Read-LeafVaultWindowArm $review.initiativeId '2023-04-01'
        if ((Get-LeafVaultWindowHash $definition.properties) -cne $review.definitionHash -or (Get-LeafVaultWindowHash $assignment.properties) -cne $review.assignmentHash -or (Get-LeafVaultWindowHash $initiative.properties) -cne $review.initiativeHash -or -not (Test-LeafVaultWindowExclusion $definition)) { throw 'ReviewedVaultExceptionPolicyChanged' }
        $verification = & (Join-Path $PSScriptRoot 'Deploy-CredentialVault.ps1') -Mode Verify
        if ($verification.Status -cne 'NoChange' -or $verification.PublicNetworkDisabled -cne $true) { throw 'VerifiedPrivateVaultRequiredBeforeWindow' }
        $operator = Get-AzADUser -SignedIn -ErrorAction Stop
        if ($operator.Id -ine $review.operatorId -or $operator.UserPrincipalName -ine $context.Account.Id) { throw 'ReviewedVaultPickerOperatorRequired' }
        $address = Invoke-RestMethod -Uri 'https://api4.ipify.org?format=json' -ErrorAction Stop
        if ([string]$address.ip -cne $review.clientIpv4) { throw 'ReviewedVaultWindowClientChanged' }
        $acl = New-LeafVaultWindowAcl $review.clientIpv4
        if ($vault.properties.publicNetworkAccess -cne 'Disabled' -or $vault.tags.ContainsKey($tagName) -or $vault.properties.networkAcls.defaultAction -cne 'Deny' -or $vault.properties.networkAcls.bypass -cne 'None') { throw 'ExactPrivateVaultWithoutPriorExceptionRequired' }
        if ($Mode -ceq 'Preview') {
            [pscustomobject]@{ Status = 'VaultWindowPreviewReady'; OneVaultOnly = $true; CurrentClientIpv4Only = $true; ExistingSecretRolesUnchanged = $true; RequestedSeconds = 60; AutomaticExpiry = $false; ExplicitCloseRequired = $true; CloudChanges = 0; SecretValuesRequested = $false }
            return
        }
        $state = @{ status = 'OpeningNoReplay'; vaultId = $review.vaultId; originalNetworkAcls = $vault.properties.networkAcls; originalNetworkHash = Get-LeafVaultWindowNetworkHash $vault.properties.networkAcls; openNetworkHash = Get-LeafVaultWindowNetworkHash $acl; tagInputsHash = Get-LeafVaultWindowHash $inputs; requestedUtc = [DateTimeOffset]::UtcNow.ToString('o'); requestedCloseUtc = [DateTimeOffset]::UtcNow.AddSeconds(60).ToString('o'); automaticExpiry = $false }
        Save-LeafVaultWindowState
        Send-LeafVaultWindowPatch ($review.vaultId + '/providers/Microsoft.Resources/tags/default') '2021-04-01' @{ operation = 'Merge'; properties = @{ tags = @{ $tagName = $tagValue } } }
        Send-LeafVaultWindowPatch $review.vaultId '2025-05-01' @{ properties = @{ publicNetworkAccess = 'Enabled'; networkAcls = $acl } }
        $vault = Read-LeafVaultWindowArm $review.vaultId '2025-05-01'
        if ($vault.properties.publicNetworkAccess -cne 'Enabled' -or $vault.tags[$tagName] -cne $tagValue -or (Get-LeafVaultWindowNetworkHash $vault.properties.networkAcls) -cne (Get-LeafVaultWindowNetworkHash $acl)) { throw 'VaultWindowOpenReadbackMismatchCloseBeforeRetry' }
        $state.status = 'Open'
        Save-LeafVaultWindowState
        [pscustomobject]@{ Status = 'VaultWindowOpen'; CurrentClientIpv4Only = $true; DefaultDenyNoBypass = $true; SecretRolesUnchanged = $true; AutomaticExpiry = $false; ExplicitCloseRequired = $true; SecretValuesRequested = $false }
    } finally { $lock.Dispose() }
} catch {
    $safe = [string]$_.Exception.Message
    if ($safe -notmatch '^[A-Za-z]+$') { $safe = 'VaultWindowStoppedInspectStateAndCloseBeforeRetry' }
    throw $safe
}