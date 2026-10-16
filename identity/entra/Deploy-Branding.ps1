#requires -Version 7.6
[CmdletBinding()]
param(
    [switch]$Apply,
    [switch]$NameOnly,
    [switch]$CheckOnly
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
. (Join-Path $repo 'identity/Target.ps1')
$brand = Get-Content -LiteralPath (Join-Path $repo 'branding/brand.json') -Raw | ConvertFrom-Json -AsHashtable
$desired = @{
    backgroundColor = $brand.palette.mist
    signInPageText = $brand.name + ' | ' + $brand.descriptor
    usernameHintText = ' '
}
$images = @(
    @{ Property = 'bannerLogo'; File = 'branding/exports/entra/banner.png'; MaxBytes = 10000 },
    @{ Property = 'headerLogo'; File = 'branding/exports/entra/banner.png'; MaxBytes = 10000 },
    @{ Property = 'squareLogo'; File = 'branding/exports/entra/square-light.png'; MaxBytes = 10000 },
    @{ Property = 'squareLogoDark'; File = 'branding/exports/entra/square-dark.png'; MaxBytes = 10000 },
    @{ Property = 'favicon'; File = 'branding/exports/entra/favicon.png'; MaxBytes = 5000 },
    @{ Property = 'backgroundImage'; File = 'branding/exports/entra/background.png'; MaxBytes = 300000 }
)
foreach ($image in $images) {
    $file = Get-Item -LiteralPath (Join-Path $repo $image.File)
    if ($file.Length -eq 0 -or $file.Length -gt $image.MaxBytes) { throw 'An Entra image is missing or exceeds its documented API limit.' }
    $image.Hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
}

function Get-LeafBrandingPatch {
    param($Current, [System.Collections.IDictionary]$Desired)
    $patch = @{}
    foreach ($key in $Desired.Keys) {
        $before = if ($Current) { [string]$Current.$key } else { '' }
        $same = if ($key -eq 'backgroundColor') { $before -eq $Desired[$key] } else { $before -ceq $Desired[$key] }
        if (-not $same) { $patch[$key] = $Desired[$key] }
    }
    return $patch
}

if ($CheckOnly) {
    Test-LeafTargetGuards
    $fixture = [pscustomobject]@{ backgroundColor = $desired.backgroundColor.ToLowerInvariant(); signInPageText = $desired.signInPageText; usernameHintText = ' ' }
    if ((Get-LeafBrandingPatch $fixture $desired).Count -ne 0) { throw 'Matching branding must be a no-op.' }
    $fixture.signInPageText = 'Different branding'
    $patch = Get-LeafBrandingPatch $fixture $desired
    if ($patch.Count -ne 1 -or -not $patch.ContainsKey('signInPageText')) { throw 'Only changed owned properties may be patched.' }
    if ((Get-LeafBrandingPatch $null $desired).Count -ne 3 -or $images.Count -ne 6) { throw 'The clean-tenant branding contract is incomplete.' }
    foreach ($initialName in @('Example Labs', "Example's New Tenant", $brand.name.ToLowerInvariant(), $null)) {
        $organizationFixture = [pscustomobject]@{ displayName = $initialName; technicalNotificationMails = @('admin@example.com') }
        $namePatch = Get-LeafBrandingPatch $organizationFixture @{ displayName = $brand.name }
        if ($namePatch.Count -ne 1 -or -not $namePatch.ContainsKey('displayName') -or $namePatch.displayName -cne $brand.name) { throw 'Name verification must detect any nonmatching initial name without a previous-brand input.' }
    }
    $organizationFixture.displayName = $brand.name
    if ((Get-LeafBrandingPatch $organizationFixture @{ displayName = $brand.name }).Count) { throw 'A converged organization name must be NoChange.' }
    [pscustomobject]@{ OfflineChecksPassed = $true; ImagesValidated = $images.Count; OrganizationNameCasesValidated = 5; PreviousOrganizationNameRequired = $false; ApiVersion = 'v1.0'; TenantAccess = $false }
    return
}

$settings = Read-LeafPrivateTarget $repo
$privateRoot = Join-Path $repo 'private/branding'
[void][IO.Directory]::CreateDirectory($privateRoot)
$session = $null
$report = [ordered]@{ TimeUtc = [DateTimeOffset]::UtcNow.ToString('o'); ApplyRequested = $Apply.IsPresent; NameOnly = $NameOnly.IsPresent; TargetVerified = $false; OrganizationNameChanged = $false; DefaultCreated = $false; ChangedProperties = @(); EnglishPropertiesChanged = @(); ImagesUploaded = @(); Verified = $false; Status = 'Started' }

function Get-LeafBrandingImageHash {
    param([string]$Property, [string]$BrandingId)
    if ($BrandingId -notin @('0', 'default')) { throw 'The default branding ID is unexpected.' }
    $temporary = Join-Path $privateRoot ('entra-current-' + $Property + '-' + [guid]::NewGuid().ToString('N') + '.png')
    try {
        $null = Invoke-LeafTargetGraph -Settings $settings -Path ($basePath + '/localizations/' + $BrandingId + '/' + $Property) -OutputFilePath $temporary -AllowNotFound
        if ((Test-Path -LiteralPath $temporary) -and (Get-Item -LiteralPath $temporary).Length -gt 0) {
            return (Get-FileHash -LiteralPath $temporary -Algorithm SHA256).Hash
        }
        return $null
    } finally {
        if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force }
    }
}

try {
    $session = Connect-LeafTargetGraph $settings
    $report.TargetVerified = $true
    $organizationPath = '/v1.0/organization/' + $settings.TARGET_TENANT_ID + '?$select=id,displayName,verifiedDomains,privacyProfile,technicalNotificationMails,marketingNotificationEmails,securityComplianceNotificationMails,securityComplianceNotificationPhones'
    $organization = Invoke-LeafTargetGraph -Settings $settings -Path $organizationPath
    if ($organization.id -ne $settings.TARGET_TENANT_ID) { throw 'The organization-name target does not match private inputs.' }
    $namePending = (Get-LeafBrandingPatch $organization @{ displayName = $brand.name }).Count -gt 0
    $report.DesiredOrganizationName = $brand.name
    $report.OrganizationNameMatches = -not $namePending
    $report.ManualNameChangeRequired = $namePending
    if ($NameOnly) {
        $report.Verified = -not $namePending
        $report.Status = if ($namePending) { 'BlockedReadOnlyOrganizationName' } else { 'NoChange' }
        [pscustomobject]@{ Mode = 'ReadOnlyNameVerification'; Status = $report.Status; DesiredOrganizationName = $brand.name; OrganizationNameMatches = -not $namePending; ManualNameChangeRequired = $namePending; SupportedGraphNameWrite = $false; TenantChanged = $false }
        return
    }
    $basePath = '/v1.0/organization/' + $settings.TARGET_TENANT_ID + '/branding'
    $current = Invoke-LeafTargetGraph -Settings $settings -Path $basePath -AllowNotFound
    $localizations = @(Get-LeafTargetGraphCollection -Settings $settings -Path ($basePath + '/localizations'))
    $english = @($localizations | Where-Object id -eq 'en-US')
    if (-not $current -and $english.Count -gt 0) { throw 'Branding state is inconsistent; inspect it before creating anything.' }
    $patch = Get-LeafBrandingPatch $current $desired
    $englishPatch = if ($english.Count -eq 1) { Get-LeafBrandingPatch $english[0] $desired } else { @{} }
    $imagePlan = @(foreach ($image in $images) {
        $hash = if ($current) { Get-LeafBrandingImageHash -Property $image.Property -BrandingId $current.id } else { $null }
        [pscustomobject]@{ Property = $image.Property; Action = if ($hash -eq $image.Hash) { 'NoChange' } else { 'WouldUpload' }; DesiredHash = $image.Hash; BeforeHash = $hash }
    })
    $plan = [ordered]@{
        TimeUtc = $report.TimeUtc
        TargetVerified = $true
        OrganizationNameWouldChange = $namePending
        DefaultAction = if ($current) { 'Existing' } else { 'WouldCreateViaEnglishLocalization' }
        PropertyChanges = @($patch.Keys | Sort-Object)
        EnglishPropertyChanges = @($englishPatch.Keys | Sort-Object)
        ImageChanges = $imagePlan
        ExistingOtherLocalizationsPreserved = @($localizations | Where-Object { $_.id -notin @('0', 'default', 'en-US') }).Count
    }
    [IO.File]::WriteAllText((Join-Path $privateRoot 'entra-plan.json'), ($plan | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
    $pendingImages = @($imagePlan | Where-Object Action -eq 'WouldUpload')
    if (-not $Apply) {
        $report.Status = 'Preview'
        [pscustomobject]@{ Mode = 'Preview'; OrganizationNameWouldChange = $namePending; WouldCreateDefault = -not [bool]$current; PropertyChanges = $patch.Count; EnglishPropertyChanges = $englishPatch.Count; ImageUploads = $pendingImages.Count; OtherLocalizationsPreserved = $plan.ExistingOtherLocalizationsPreserved; TenantChanged = $false }
        return
    }
    $hasChanges = -not $current -or $patch.Count -gt 0 -or $englishPatch.Count -gt 0 -or $pendingImages.Count -gt 0
    if ($hasChanges) {
        $snapshot = [ordered]@{ TimeUtc = $report.TimeUtc; DefaultExisted = [bool]$current; OwnedProperties = @{}; EnglishOwnedProperties = @{}; ImageHashes = $imagePlan }
        foreach ($key in $desired.Keys) { $snapshot.OwnedProperties[$key] = if ($current) { $current.$key } else { $null } }
        foreach ($key in $desired.Keys) { $snapshot.EnglishOwnedProperties[$key] = if ($english.Count -eq 1) { $english[0].$key } else { $null } }
        $snapshotName = 'entra-before-' + [DateTimeOffset]::UtcNow.ToString('yyyyMMddTHHmmssfffffffZ') + '.json'
        [IO.File]::WriteAllText((Join-Path $privateRoot $snapshotName), ($snapshot | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
    }
    if (-not $current) {
        $bootstrap = @{ id = 'en-US' }
        foreach ($key in $desired.Keys) { $bootstrap[$key] = $desired[$key] }
        $null = Invoke-LeafTargetGraph -Settings $settings -Path ($basePath + '/localizations') -Method POST -Body $bootstrap
        $report.DefaultCreated = $true
        $current = Invoke-LeafTargetGraph -Settings $settings -Path $basePath
        if (-not $current -or $current.id -notin @('0', 'default')) { throw 'Default branding creation was not confirmed; no blind create retry is permitted.' }
    }
    if ($patch.Count -gt 0) {
        $null = Invoke-LeafTargetGraph -Settings $settings -Path $basePath -Method PATCH -Body $patch
        $report.ChangedProperties = @($patch.Keys | Sort-Object)
    }
    if ($englishPatch.Count -gt 0) {
        $null = Invoke-LeafTargetGraph -Settings $settings -Path ($basePath + '/localizations/en-US') -Method PATCH -Body $englishPatch
        $report.EnglishPropertiesChanged = @($englishPatch.Keys | Sort-Object)
    }
    foreach ($item in $pendingImages) {
        $image = $images | Where-Object Property -eq $item.Property
        $null = Invoke-LeafTargetGraph -Settings $settings -Path ($basePath + '/localizations/' + $current.id + '/' + $item.Property) -Method PUT -InputFilePath (Join-Path $repo $image.File)
        $report.ImagesUploaded += $item.Property
    }
    $after = Invoke-LeafTargetGraph -Settings $settings -Path $basePath
    if ((Get-LeafBrandingPatch $after $desired).Count -ne 0) { throw 'Owned branding property readback differs from the definition.' }
    $englishAfter = @(Get-LeafTargetGraphCollection -Settings $settings -Path ($basePath + '/localizations') | Where-Object id -eq 'en-US')
    if ($englishAfter.Count -eq 1 -and (Get-LeafBrandingPatch $englishAfter[0] $desired).Count -ne 0) { throw 'Owned English branding overrides differ from the definition.' }
    foreach ($image in $images) {
        if ((Get-LeafBrandingImageHash -Property $image.Property -BrandingId $after.id) -ne $image.Hash) { throw 'A branding image readback differs from the source. Inspect provider normalization before retrying.' }
    }
    $report.Verified = $true
    $report.Status = if ($hasChanges) { 'AppliedAndVerified' } else { 'NoChange' }
    [pscustomobject]@{ Mode = 'Apply'; Status = $report.Status; OrganizationNameChanged = $report.OrganizationNameChanged; DefaultCreated = $report.DefaultCreated; PropertiesChanged = $report.ChangedProperties.Count; EnglishPropertiesChanged = $report.EnglishPropertiesChanged.Count; ImagesUploaded = $report.ImagesUploaded.Count; ReadbackVerified = $true }
} catch {
    $report.Status = 'StoppedInspectBeforeRetry'
    throw
} finally {
    $reportFile = if ($NameOnly) { 'organization-name-verification.json' } else { 'entra-verification.json' }
    [IO.File]::WriteAllText((Join-Path $privateRoot $reportFile), ($report | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
    Disconnect-LeafTargetGraph $session
}