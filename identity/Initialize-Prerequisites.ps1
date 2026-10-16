[CmdletBinding()]
param([switch]$Apply, [switch]$CheckOnly, [switch]$PublicIpFeature)

$ErrorActionPreference = 'Stop'
$namespaces = @('Microsoft.Compute', 'Microsoft.Automation', 'Microsoft.RecoveryServices')
$featureNamespace = 'Microsoft.Network'
$featureName = 'AllowBringYourOwnPublicIpAddress'
function Test-RegistrationRequired {
    param([ValidateSet('NotRegistered', 'Registered', 'Registering', 'Pending')][string]$State, [bool]$ApplyRequested)
    return ($State -eq 'NotRegistered' -and $ApplyRequested)
}
if ($CheckOnly) {
    if ($Apply) { throw 'Offline checks cannot apply changes.' }
    if ($namespaces.Count -ne 3 -or 'Microsoft.Network' -in $namespaces) { throw 'Unexpected provider scope.' }
    foreach ($state in @('Registered', 'Registering', 'Pending')) {
        if ((Test-RegistrationRequired $state $true) -or (Test-RegistrationRequired $state $false)) { throw 'Ready or pending registration must not be resent.' }
    }
    if (-not (Test-RegistrationRequired 'NotRegistered' $true) -or (Test-RegistrationRequired 'NotRegistered' $false)) { throw 'Registration requires an explicit Apply request.' }
    if ($featureNamespace -ne 'Microsoft.Network' -or $featureName -ne 'AllowBringYourOwnPublicIpAddress') { throw 'Unexpected opt-in feature scope.' }
    'PASS: registration is limited to the three approved identity workload providers.'
    'PASS: the named public-IP feature is opt-in; read-only, ready and pending states never register.'
    return
}
$repo = Split-Path $PSScriptRoot -Parent
git -C $repo check-ignore --quiet -- .env
if ($LASTEXITCODE -ne 0) { throw 'Private configuration must be ignored.' }
$tracked = @(git -C $repo ls-files -- .env private)
if ($LASTEXITCODE -ne 0 -or $tracked.Count) { throw 'Private configuration must be untracked.' }
$settings = @{}
foreach ($line in [IO.File]::ReadAllLines((Join-Path $repo '.env'))) {
    $entry = [regex]::Match($line, '^\s*(?<key>TARGET_(?:TENANT_ID|SUBSCRIPTION_ID))\s*=\s*(?<value>.*)$')
    if (-not $entry.Success) { continue }
    $key = $entry.Groups['key'].Value
    if ($settings.ContainsKey($key)) { throw 'Duplicate private target identity.' }
    $settings[$key] = $entry.Groups['value'].Value.Trim().Trim([char]34, [char]39)
}
$context = Get-AzContext
if (-not $context -or $context.Tenant.Id -ne $settings.TARGET_TENANT_ID -or $context.Subscription.Id -ne $settings.TARGET_SUBSCRIPTION_ID) {
    throw 'Authenticate explicitly in the configured target; this script never signs in or switches context.'
}
if ($PublicIpFeature) {
    $features = @(Get-AzProviderFeature -ProviderNamespace $featureNamespace -FeatureName $featureName -DefaultProfile $context)
    if ($features.Count -ne 1) { throw 'Feature readback is ambiguous.' }
    $sent = Test-RegistrationRequired $features[0].RegistrationState $Apply.IsPresent
    if ($sent) {
        Register-AzProviderFeature -ProviderNamespace $featureNamespace -FeatureName $featureName -DefaultProfile $context | Out-Null
        $features = @(Get-AzProviderFeature -ProviderNamespace $featureNamespace -FeatureName $featureName -DefaultProfile $context)
        if ($features.Count -ne 1) { throw 'Feature readback is ambiguous.' }
    }
    Test-RegistrationRequired $features[0].RegistrationState $false | Out-Null
    [pscustomobject]@{
        Namespace = $featureNamespace
        Feature = $featureName
        RegistrationState = $features[0].RegistrationState
        RequestSent = $sent
        Ready = ($features[0].RegistrationState -eq 'Registered')
        NoChange = -not $sent
    }
    return
}
foreach ($namespace in $namespaces) {
    $states = @(Get-AzResourceProvider -ProviderNamespace $namespace -DefaultProfile $context | ForEach-Object RegistrationState | Sort-Object -Unique)
    if ($states.Count -ne 1 -or $states[0] -notin @('Registered', 'Registering', 'NotRegistered')) { throw 'Unexpected provider registration state.' }
    $sent = $false
    if (Test-RegistrationRequired $states[0] $Apply.IsPresent) {
        Register-AzResourceProvider -ProviderNamespace $namespace -DefaultProfile $context | Out-Null
        $sent = $true
        $states = @(Get-AzResourceProvider -ProviderNamespace $namespace -DefaultProfile $context | ForEach-Object RegistrationState | Sort-Object -Unique)
        if ($states.Count -ne 1) { throw 'Provider readback is ambiguous.' }
    }
    [pscustomobject]@{
        Namespace = $namespace
        RegistrationState = $states[0]
        RequestSent = $sent
        Ready = ($states[0] -eq 'Registered')
        NoChange = -not $sent
    }
}