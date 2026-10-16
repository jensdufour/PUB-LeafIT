[CmdletBinding()]
param(
    [switch]$Apply,
    [switch]$CheckOnly
)

$ErrorActionPreference = 'Stop'

function Read-TargetSettings([string]$Text) {
    $required = @('TARGET_TENANT_ID', 'TARGET_SUBSCRIPTION_ID', 'TARGET_LOCATION', 'TARGET_REGION_CODE')
    $settings = @{}
    foreach ($line in $Text -split '\r?\n') {
        $field = [regex]::Match($line, '^\s*(?<key>[A-Z][A-Z0-9_]*)\s*=\s*(?<value>.*)$')
        if (-not $field.Success -or $field.Groups['key'].Value -notin $required) { continue }
        $key = $field.Groups['key'].Value
        if ($settings.ContainsKey($key)) { throw 'Duplicate required target setting.' }
        $settings[$key] = $field.Groups['value'].Value.Trim().Trim([char[]]@([char]34, [char]39))
    }
    foreach ($key in $required) {
        if ([string]::IsNullOrWhiteSpace($settings[$key])) { throw 'Required target setting is missing.' }
    }
    foreach ($key in @('TARGET_TENANT_ID', 'TARGET_SUBSCRIPTION_ID')) {
        $parsed = [guid]::Empty
        if (-not [guid]::TryParse($settings[$key], [ref]$parsed) -or $parsed -eq [guid]::Empty) { throw 'Invalid target identity.' }
        $settings[$key] = $parsed.ToString()
    }
    $regions = @{ swedencentral = 'swc'; germanywestcentral = 'gwc' }
    if (-not $regions.ContainsKey($settings.TARGET_LOCATION) -or $settings.TARGET_REGION_CODE -ne $regions[$settings.TARGET_LOCATION]) {
        throw 'Target location or naming code does not match the approved region policy.'
    }
    return $settings
}

function Assert-TargetContext($Settings, $Context) {
    if (-not $Context -or $Context.Tenant.Id -ne $Settings.TARGET_TENANT_ID -or $Context.Subscription.Id -ne $Settings.TARGET_SUBSCRIPTION_ID) {
        throw 'Authenticate explicitly to the configured target tenant and subscription before running this script.'
    }
}

function Get-RegistrationAction([string]$State, [bool]$ApplyRequested) {
    switch ($State) {
        'Registered' { return 'NoChange' }
        'Registering' { return 'InProgress' }
        'NotRegistered' { if ($ApplyRequested) { return 'Register' }; return 'WouldRegister' }
        default { throw 'Provider registration state is unknown or conflicting; no request sent.' }
    }
}

if ($CheckOnly) {
    $sample = "TARGET_TENANT_ID=$([guid]::NewGuid())`nTARGET_SUBSCRIPTION_ID=$([guid]::NewGuid())`nTARGET_LOCATION=swedencentral`nTARGET_REGION_CODE=swc"
    $settings = Read-TargetSettings $sample
    $context = [pscustomobject]@{ Tenant = @{ Id = $settings.TARGET_TENANT_ID }; Subscription = @{ Id = $settings.TARGET_SUBSCRIPTION_ID } }
    Assert-TargetContext $settings $context
    foreach ($invalid in @($sample.Replace('swedencentral', 'westeurope'), $sample.Replace('swedencentral', 'northeurope'), $sample.Replace('TARGET_REGION_CODE=swc', 'TARGET_REGION_CODE=gwc'), ($sample + "`nTARGET_LOCATION=swedencentral"), $sample.Replace($settings.TARGET_TENANT_ID, 'invalid'))) {
        $rejected = $false
        try { $null = Read-TargetSettings $invalid } catch { $rejected = $true }
        if (-not $rejected) { throw 'Invalid-input check failed.' }
    }
    $null = Read-TargetSettings ($sample.Replace('swedencentral', 'germanywestcentral').Replace('TARGET_REGION_CODE=swc', 'TARGET_REGION_CODE=gwc'))
    foreach ($member in @('Tenant', 'Subscription')) {
        $wrong = [pscustomobject]@{ Tenant = @{ Id = $settings.TARGET_TENANT_ID }; Subscription = @{ Id = $settings.TARGET_SUBSCRIPTION_ID } }
        $wrong.$member.Id = [guid]::NewGuid().ToString()
        $rejected = $false
        try { Assert-TargetContext $settings $wrong } catch { $rejected = $true }
        if (-not $rejected) { throw 'Wrong-context check failed.' }
    }
    if ((Get-RegistrationAction 'NotRegistered' $false) -ne 'WouldRegister' -or (Get-RegistrationAction 'NotRegistered' $true) -ne 'Register' -or (Get-RegistrationAction 'Registered' $true) -ne 'NoChange' -or (Get-RegistrationAction 'Registering' $true) -ne 'InProgress') { throw 'Registration decision check failed.' }
    $rejected = $false
    try { $null = Get-RegistrationAction 'Unregistering' $true } catch { $rejected = $true }
    if (-not $rejected) { throw 'Conflicting-state check failed.' }
    'PASS: Target input, context, region, preview, repeat-apply, and in-progress checks passed without cloud access.'
    return
}

$repo = Split-Path $PSScriptRoot -Parent
git -C $repo check-ignore --quiet -- .env
if ($LASTEXITCODE -ne 0) { throw 'Private configuration must be ignored.' }
$tracked = @(git -C $repo ls-files -- .env)
if ($LASTEXITCODE -ne 0 -or $tracked.Count) { throw 'Private configuration must be untracked.' }
$settings = Read-TargetSettings ([IO.File]::ReadAllText((Join-Path $repo '.env')))
Import-Module Az.Accounts -MinimumVersion 5.3.3
Import-Module Az.Resources -MinimumVersion 9.0.3
$context = Get-AzContext
Assert-TargetContext $settings $context

try {
    $subscription = @(Get-AzSubscription -SubscriptionId $settings.TARGET_SUBSCRIPTION_ID -TenantId $settings.TARGET_TENANT_ID -DefaultProfile $context)
    if ($subscription.Count -ne 1 -or $subscription[0].TenantId -ne $settings.TARGET_TENANT_ID -or $subscription[0].State -ne 'Enabled') { throw 'Target subscription ownership or state check failed.' }
    $locations = @(Get-AzLocation -DefaultProfile $context)
    if (@($locations | Where-Object Location -eq $settings.TARGET_LOCATION).Count -ne 1) { throw 'Selected region is unavailable to this subscription; no automatic fallback.' }
    $providerNamespace = 'Microsoft.Network'
    $states = @(Get-AzResourceProvider -ProviderNamespace $providerNamespace -DefaultProfile $context | Select-Object -ExpandProperty RegistrationState -Unique)
    if ($states.Count -ne 1) { throw 'Provider registration state is missing or ambiguous.' }
    $before = [string]$states[0]
    $action = Get-RegistrationAction $before $Apply.IsPresent
    if ($action -eq 'Register') {
        Assert-TargetContext $settings (Get-AzContext)
        $null = Register-AzResourceProvider -ProviderNamespace $providerNamespace -DefaultProfile $context
        $states = @(Get-AzResourceProvider -ProviderNamespace $providerNamespace -DefaultProfile $context | Select-Object -ExpandProperty RegistrationState -Unique)
        if ($states.Count -ne 1 -or $states[0] -notin @('Registered', 'Registering')) { throw 'Registration request did not reach a valid state; inspect before retrying.' }
    }
    [pscustomobject]@{ ProviderNamespace = $providerNamespace; Before = $before; Action = $action; After = [string]$states[0]; Ready = $states[0] -eq 'Registered' }
} catch {
    $status = $_.Exception.Response.StatusCode
    $detail = if ($status) { "HTTP $([int]$status)" } else { $_.Exception.GetType().Name }
    throw "Provider prerequisites stopped ($detail); identity values suppressed. Verify provider state before retrying."
}