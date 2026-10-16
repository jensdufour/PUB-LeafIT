#requires -Version 7.6
[CmdletBinding()]
param([switch]$Apply, [switch]$VerifyOnly, [switch]$CheckOnly)

$ErrorActionPreference = 'Stop'
if ($Apply -and $VerifyOnly) { throw 'Choose apply or read-only verification, not both.' }
$repo = Split-Path $PSScriptRoot -Parent
. (Join-Path $repo 'identity/Target.ps1')
$brand = Get-Content -LiteralPath (Join-Path $repo 'branding/brand.json') -Raw | ConvertFrom-Json

function Get-LeafSubscriptionBrandName {
    param([string]$CurrentName, [string]$PreviousName, [string]$Name)
    if ([string]::IsNullOrWhiteSpace($CurrentName) -or [string]::IsNullOrWhiteSpace($PreviousName) -or [string]::IsNullOrWhiteSpace($Name)) { throw 'Valid current and brand names are required.' }
    if ($PreviousName -ieq $Name) { return $CurrentName }
    return [regex]::Replace($CurrentName, [regex]::Escape($PreviousName), [Text.RegularExpressions.MatchEvaluator]{ param($matchValue) $Name }, [Text.RegularExpressions.RegexOptions]::IgnoreCase)
}

function Test-LeafSubscriptionWritePending {
    param($PreviousReport)
    return [bool]($PreviousReport -and -not $PreviousReport.Verified -and ($PreviousReport.WriteAttempted -or $PreviousReport.PriorUnverifiedWrite))
}

if ($CheckOnly) {
    Test-LeafTargetGuards
    if ((Get-LeafSubscriptionBrandName 'Previous+Co showcase' 'Previous+Co' 'LeafIT') -cne 'LeafIT showcase') { throw 'The label must replace only literal previous-brand text.' }
    if ((Get-LeafSubscriptionBrandName 'LeafIT showcase' 'Previous+Co' 'LeafIT') -cne 'LeafIT showcase') { throw 'An already branded label must be NoChange.' }
    if ((Get-LeafSubscriptionBrandName 'LeafIT showcase' 'LeafIT' 'LeafIT') -cne 'LeafIT showcase') { throw 'A fresh already named tenant must remain NoChange.' }
    if (-not (Test-LeafSubscriptionWritePending ([pscustomobject]@{ WriteAttempted = $true; Verified = $false }))) { throw 'An unverified write must block another rename.' }
    if (-not (Test-LeafSubscriptionWritePending ([pscustomobject]@{ WriteAttempted = $false; PriorUnverifiedWrite = $true; Verified = $false }))) { throw 'A blocked apply must retain the earlier unverified-write guard.' }
    if (Test-LeafSubscriptionWritePending ([pscustomobject]@{ WriteAttempted = $true; PriorUnverifiedWrite = $true; Verified = $true })) { throw 'Verified convergence must clear the pending-write guard.' }
    [pscustomobject]@{ OfflineChecksPassed = $true; LiteralReplacement = $true; ConvergedLabelNoChange = $true; TenantAccess = $false }
    return
}

$settings = Read-LeafPrivateTarget $repo
if (-not $settings.ContainsKey('TARGET_PREVIOUS_ORGANIZATION_NAME')) { throw 'The reviewed private previous organization name is required.' }
Import-Module Az.Accounts -MinimumVersion 5.3.3 -ErrorAction Stop
$context = Get-AzContext
Assert-LeafTargetContext $settings $context
$privateRoot = Join-Path $repo 'private/branding'
[void][IO.Directory]::CreateDirectory($privateRoot)
$verificationPath = Join-Path $privateRoot 'subscription-name-verification.json'
$previousReport = if (Test-Path -LiteralPath $verificationPath) { Get-Content -LiteralPath $verificationPath -Raw | ConvertFrom-Json } else { $null }
$report = [ordered]@{ TimeUtc = [DateTimeOffset]::UtcNow.ToString('o'); ApplyRequested = $Apply.IsPresent; VerifyOnly = $VerifyOnly.IsPresent; TargetVerified = $false; Status = 'Started'; WriteAttempted = $false; PriorUnverifiedWrite = (Test-LeafSubscriptionWritePending $previousReport); RenameAccepted = $false; Verified = $false }
$path = '/subscriptions/' + $settings.TARGET_SUBSCRIPTION_ID

function Get-LeafSubscriptionReadback {
    Assert-LeafTargetContext $settings (Get-AzContext)
    $response = Invoke-AzRestMethod -Method GET -Path ($path + '?api-version=2022-12-01') -DefaultProfile $context -ErrorAction Stop
    if ($response.StatusCode -ne 200) { throw 'Subscription readback failed.' }
    $subscription = $response.Content | ConvertFrom-Json
    if ($subscription.subscriptionId -ne $settings.TARGET_SUBSCRIPTION_ID -or $subscription.tenantId -ne $settings.TARGET_TENANT_ID) { throw 'Subscription readback does not match the configured target.' }
    return $subscription
}

try {
    $before = Get-LeafSubscriptionReadback
    $report.TargetVerified = $true
    $desired = Get-LeafSubscriptionBrandName $before.displayName $settings.TARGET_PREVIOUS_ORGANIZATION_NAME $brand.name
    $pending = $desired -cne $before.displayName
    $report.BeforeDisplayName = $before.displayName
    $report.DesiredDisplayName = $desired
    if ($VerifyOnly) {
        $report.Verified = -not $pending
        $report.Status = if ($pending) { 'PendingOrNotApplied' } else { 'NoChange' }
        [pscustomobject]@{ Mode = 'ReadOnlyVerification'; Status = $report.Status; TargetVerified = $true; DisplayLabelConverged = -not $pending; AzureChangesPerformed = $false }
        return
    }
    if (-not $Apply) {
        $report.Status = 'Preview'
        [pscustomobject]@{ Mode = 'Preview'; WouldRenameDisplayLabel = $pending; TargetVerified = $true; AzureChangesPerformed = $false }
        return
    }
    if ($pending) {
        if ($report.PriorUnverifiedWrite) { throw 'An earlier unverified rename exists. Use read-only verification and inspect current state; do not submit the write again.' }
        $snapshot = 'subscription-name-before-' + [DateTimeOffset]::UtcNow.ToString('yyyyMMddTHHmmssfffffffZ') + '.json'
        [IO.File]::WriteAllText((Join-Path $privateRoot $snapshot), ($report | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
        $latest = Get-LeafSubscriptionReadback
        if ($latest.displayName -cne $before.displayName) { throw 'The subscription label changed after planning.' }
        $report.WriteAttempted = $true
        $body = @{ subscriptionName = $desired } | ConvertTo-Json -Compress
        $response = Invoke-AzRestMethod -Method POST -Path ($path + '/providers/Microsoft.Subscription/rename?api-version=2021-10-01') -Payload $body -DefaultProfile $context -ErrorAction Stop
        if ($response.StatusCode -ne 200) { throw 'The subscription rename was not confirmed.' }
        $result = $response.Content | ConvertFrom-Json
        if ($result.subscriptionId -ne $settings.TARGET_SUBSCRIPTION_ID) { throw 'The rename response does not match the target.' }
        $report.RenameAccepted = $true
    }
    $after = Get-LeafSubscriptionReadback
    if ($after.state -cne $before.state -or ($after.subscriptionPolicies | ConvertTo-Json -Compress) -cne ($before.subscriptionPolicies | ConvertTo-Json -Compress)) { throw 'Unrelated subscription settings differ from the plan.' }
    if ($after.displayName -cne $desired) {
        $report.Status = 'AcceptedPendingReadback'
        [pscustomobject]@{ Mode = 'Apply'; Status = $report.Status; TargetVerified = $true; DisplayLabelConverged = $false; RepeatWriteAllowed = $false; ResourceChangesPerformed = $false }
        return
    }
    $report.Verified = $true
    $report.Status = if ($pending) { 'AppliedAndVerified' } else { 'NoChange' }
    [pscustomobject]@{ Mode = 'Apply'; Status = $report.Status; TargetVerified = $true; SubscriptionIdAndTenantPreserved = $true; SubscriptionStateAndPoliciesPreserved = $true; ResourceChangesPerformed = $false }
} catch {
    $report.Status = 'StoppedInspectBeforeRetry'
    $report.FailureType = $_.Exception.GetType().Name
    throw 'Subscription label update stopped. Inspect private evidence and current target state before retrying; no automatic rollback or blind write retry is performed.'
} finally {
    $name = if ($VerifyOnly) { 'subscription-name-readback.json' } elseif ($Apply) { 'subscription-name-verification.json' } else { 'subscription-name-plan.json' }
    [IO.File]::WriteAllText((Join-Path $privateRoot $name), ($report | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
}