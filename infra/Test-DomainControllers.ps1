[CmdletBinding()]
param([switch]$CheckOnly)

$ErrorActionPreference = 'Stop'

function Test-BrusselsSchedule {
    param([datetimeoffset]$UtcTime)
    $zone = [TimeZoneInfo]::FindSystemTimeZoneById('Romance Standard Time')
    $local = [TimeZoneInfo]::ConvertTime($UtcTime, $zone)
    $weekday = $local.DayOfWeek -notin @([DayOfWeek]::Saturday, [DayOfWeek]::Sunday)
    return $weekday -and $local.Hour -ge 6 -and $local.Hour -lt 18
}

if ($CheckOnly) {
    foreach ($case in @(
        @{ time = '2026-01-05T05:00:00Z'; expected = $true },
        @{ time = '2026-07-06T04:00:00Z'; expected = $true },
        @{ time = '2026-07-06T16:00:00Z'; expected = $false },
        @{ time = '2026-07-05T06:00:00Z'; expected = $false }
    )) {
        if ((Test-BrusselsSchedule ([datetimeoffset]$case.time)) -ne $case.expected) {
            throw 'Brussels weekday/DST schedule check failed.'
        }
    }
    'PASS: Brussels weekday operating window, winter and summer offsets.'
    return
}

$repo = Split-Path $PSScriptRoot -Parent
git -C $repo check-ignore --quiet -- .env
if ($LASTEXITCODE -ne 0) { throw 'Private configuration must be ignored.' }
$tracked = @(git -C $repo ls-files -- .env private)
if ($LASTEXITCODE -ne 0 -or $tracked.Count) { throw 'Private inputs and evidence must be untracked.' }
$settings = @{}
foreach ($line in [IO.File]::ReadAllLines((Join-Path $repo '.env'))) {
    $entry = [regex]::Match($line, '^\s*(?<key>TARGET_[A-Z0-9_]+)\s*=\s*(?<value>.*)$')
    if (-not $entry.Success) { continue }
    $key = $entry.Groups['key'].Value
    if ($settings.ContainsKey($key)) { throw 'Duplicate private target input.' }
    $settings[$key] = $entry.Groups['value'].Value.Trim().Trim([char]34, [char]39)
}
foreach ($key in @('TARGET_TENANT_ID', 'TARGET_SUBSCRIPTION_ID', 'TARGET_LOCATION', 'TARGET_REGION_CODE')) {
    if ([string]::IsNullOrWhiteSpace($settings[$key])) { throw 'Required private target input is absent.' }
}
if ($settings.TARGET_LOCATION -ne 'swedencentral' -or $settings.TARGET_REGION_CODE -ne 'swc') {
    throw 'This approved DC plan requires Sweden Central; a different region needs a fresh review.'
}
$context = Get-AzContext
if (-not $context -or $context.Tenant.Id -ne $settings.TARGET_TENANT_ID -or $context.Subscription.Id -ne $settings.TARGET_SUBSCRIPTION_ID) {
    throw 'Use the existing authenticated private target context; no automatic sign-in or switch is allowed.'
}
$scope = '/subscriptions/' + $settings.TARGET_SUBSCRIPTION_ID
function Get-TargetArmJson {
    param([string]$Path)
    $response = Invoke-AzRestMethod -Path $Path -Method GET -DefaultProfile $context
    if ($response.StatusCode -ne 200) { throw 'Target read-only ARM request failed.' }
    return ($response.Content | ConvertFrom-Json -Depth 80)
}
$providers = Get-TargetArmJson ($scope + '/providers?api-version=2021-04-01')
$providerStatus = @(foreach ($namespace in @('Microsoft.Compute', 'Microsoft.Network', 'Microsoft.Automation', 'Microsoft.RecoveryServices')) {
    $provider = @($providers.value | Where-Object namespace -eq $namespace)
    [pscustomobject]@{ Namespace = $namespace; Registered = ($provider.Count -eq 1 -and $provider[0].registrationState -eq 'Registered') }
})
$skuResults = @()
$next = $scope + "/providers/Microsoft.Compute/skus?api-version=2021-07-01&`$filter=location eq 'swedencentral'"
do {
    $page = Get-TargetArmJson $next
    $skuResults += @($page.value | Where-Object { $_.resourceType -eq 'virtualMachines' -and $_.name -eq 'Standard_B2s_v2' })
    $next = $page.nextLink
} while ($next)
if ($skuResults.Count -ne 1) { throw 'The approved VM SKU was not uniquely found; no automatic size fallback.' }
$sku = $skuResults[0]
$zoneInfo = @($sku.locationInfo | Where-Object location -eq 'swedencentral')
$versions = Get-TargetArmJson ($scope + '/providers/Microsoft.Compute/locations/swedencentral/publishers/MicrosoftWindowsServer/artifacttypes/vmimage/offers/WindowsServer/skus/2025-datacenter-azure-edition-core-smalldisk/versions?api-version=2024-03-01')
$usage = Get-TargetArmJson ($scope + '/providers/Microsoft.Compute/locations/swedencentral/usages?api-version=2024-03-01')
$familyUsage = @($usage.value | Where-Object { $_.name.value -eq $sku.family })
$regionalUsage = @($usage.value | Where-Object { $_.name.value -eq 'cores' })
[pscustomobject]@{
    TargetContextMatches = $true
    Providers = $providerStatus
    VmSize = $sku.name
    Zones = @($zoneInfo | ForEach-Object zones)
    Restrictions = @($sku.restrictions | Select-Object type, reasonCode, values)
    Windows2025CoreSmallDiskImageFound = (@($versions).Count -gt 0)
    FamilyQuotaSufficient = if ($familyUsage.Count -eq 1) { ($familyUsage[0].limit - $familyUsage[0].currentValue) -ge 4 } else { $null }
    RegionalQuotaSufficient = if ($regionalUsage.Count -eq 1) { ($regionalUsage[0].limit - $regionalUsage[0].currentValue) -ge 4 } else { $null }
    AllocationCapacityVerified = $false
}