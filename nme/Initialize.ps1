#requires -Version 7.6
[CmdletBinding()]
param([switch]$CheckOnly, [switch]$RegisterProviders, [switch]$Apply, [switch]$Verify)

$ErrorActionPreference = 'Stop'
if (@($CheckOnly, $RegisterProviders, $Apply, $Verify | Where-Object { $_ }).Count -gt 1) { throw 'Choose offline checks, provider registration, installation, or verification separately.' }
$repo = Split-Path $PSScriptRoot -Parent
. (Join-Path $repo 'identity/Target.ps1')
$desired = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'desired.json') -Raw | ConvertFrom-Json -AsHashtable
$brandPath = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot $desired.brandSource))
$brand = Get-Content -LiteralPath $brandPath -Raw | ConvertFrom-Json -AsHashtable
$assetsGuide = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot $desired.brandAssetsGuide))
if (-not (Test-Path -LiteralPath $assetsGuide) -or [string]::IsNullOrWhiteSpace($brand.name) -or $brand.palette.green -notmatch '^#[0-9A-Fa-f]{6}$') { throw 'The shared brand definition or asset guide is invalid.' }
if ($desired.workload -ne 'nme' -or $desired.location -ne 'swedencentral' -or $desired.installation.publisher -ne 'nerdio' -or $desired.installation.offer -ne 'nerdio_wvd_manager' -or $desired.installation.resourceGroupMustBeEmpty -ne $true) { throw 'NMe installation differs from the selected Marketplace scope.' }
if ($desired.access.publicManagementPortal -ne $true -or $desired.access.appServiceAuthenticationEnabled -ne $false -or $desired.hardening.parameters.MakeAppServicePrivate -ne $false -or $desired.hardening.parameters.CssaStorageAccount -ne 'Private' -or $desired.hardening.parameters.SkipDNS -ne $false -or $desired.hardening.azureRunbookExecutionMode -ne 'Inline Script') { throw 'The selected public-portal/private-backend contract is inconsistent.' }
if ($desired.cost.acceptGovernanceDownsizing -ne $true -or $desired.cost.preserveRecommendedSizingWithExemption -ne $false -or $desired.cost.automaticScaleBackUp -ne $false) { throw 'Demo downsizing must remain accepted without a sizing exemption or scale-back-up loop.' }

function Get-NmeTemplateArtifact($Product) {
    if ($Product.publisherId -ne $desired.installation.publisher -or $Product.offerId -ne $desired.installation.offer -or $Product.productType -ne 'AzureApplication' -or $Product.isStopSell) { throw 'The catalog returned a different or unavailable Marketplace product.' }
    $plans = @($Product.plans | Where-Object { $_.planId -eq $desired.installation.plan })
    if ($plans.Count -ne 1 -or $plans[0].planType -ne 'SolutionTemplate' -or $plans[0].planArtifactsVersion -ne $desired.installation.version -or $plans[0].isStopSell) { throw 'The Marketplace plan or version differs from the reviewed vendor package.' }
    $artifacts = @($plans[0].artifacts | Where-Object { $_.name -eq 'DefaultTemplate' })
    if ($artifacts.Count -ne 1 -or $desired.installation.templateSha256 -notmatch '^[0-9A-Fa-f]{64}$') { throw 'The vendor template artifact or reviewed hash is missing or ambiguous.' }
    $uri = [uri]$artifacts[0].uri
    if (-not $uri.IsAbsoluteUri -or $uri.Scheme -ne 'https' -or $uri.UserInfo -or $uri.Fragment) { throw 'The Marketplace template artifact must use an absolute HTTPS URI without embedded credentials.' }
    return $uri
}

function Assert-NmeNetworkSeparation([string]$Cidr, [string[]]$ExistingCidrs) {
    $network = [Net.IPNetwork]::Parse($Cidr)
    foreach ($existingCidr in $ExistingCidrs) {
        $existing = [Net.IPNetwork]::Parse($existingCidr)
        if ($network.Contains($existing.BaseAddress) -or $existing.Contains($network.BaseAddress)) { throw 'The vendor private network overlaps an existing VNet; review explicit network inputs before installation.' }
    }
}

function Assert-NmePreviewScope($Preview, [string]$GroupId) {
    if ($Preview.Error -or $Preview.Status -ne 'Succeeded') { throw 'Azure did not produce a successful NMe deployment preview; inspect private/nme/what-if.json.' }
    foreach ($change in $Preview.Changes) {
        if ($change.ChangeType -in @('Ignore', 'NoChange')) { continue }
        $resourceId = [string]$change.FullyQualifiedResourceId
        if ($change.ChangeType -eq 'Delete' -or ($resourceId -ne $GroupId -and -not $resourceId.StartsWith($GroupId + '/', [StringComparison]::OrdinalIgnoreCase))) { throw 'The NMe preview includes deletion or a mutation outside its dedicated resource group.' }
    }
}

function Get-NmePortalConfiguration([uri]$AppUri, [string]$Address) {
    $parsedAddress = $null
    if ($AppUri.Scheme -ne 'https' -or $AppUri.Port -ne 443 -or $AppUri.Host -notmatch '^[a-z0-9-]+\.azurewebsites\.net$' -or $AppUri.UserInfo -or $AppUri.Query -or $AppUri.Fragment -or -not [Net.IPAddress]::TryParse($Address, [ref]$parsedAddress)) { throw 'The management app HTTPS target or ARM-reported inbound address is invalid.' }
    return [string]::Join("`n", @(
        ('url = "{0}"' -f $AppUri.AbsoluteUri),
        ('resolve = "{0}:443:{1}"' -f $AppUri.Host, $Address)
    ))
}

if ($CheckOnly) {
    Test-LeafTargetGuards
    $probe = @{ publisherId = $desired.installation.publisher; offerId = $desired.installation.offer; productType = 'AzureApplication'; plans = @(@{ planId = $desired.installation.plan; planType = 'SolutionTemplate'; planArtifactsVersion = $desired.installation.version; artifacts = @(@{ name = 'DefaultTemplate'; uri = 'https://example.invalid/mainTemplate.json' }) }) }
    if ((Get-NmeTemplateArtifact $probe).Host -ne 'example.invalid') { throw 'The vendor artifact selection check failed.' }
    foreach ($change in @('PlanType', 'Version', 'Uri')) {
        $invalid = $probe | ConvertTo-Json -Depth 8 | ConvertFrom-Json -AsHashtable
        switch ($change) {
            PlanType { $invalid.plans[0].planType = 'SaaS' }
            Version { $invalid.plans[0].planArtifactsVersion = 'unreviewed' }
            Uri { $invalid.plans[0].artifacts[0].uri = 'http://example.invalid/mainTemplate.json' }
        }
        $rejected = $false
        try { $null = Get-NmeTemplateArtifact $invalid } catch { $rejected = $true }
        if (-not $rejected) { throw 'An invalid vendor package was accepted.' }
    }
    Assert-NmeNetworkSeparation '10.200.0.0/16' @('10.201.0.0/16')
    foreach ($existingCidr in @('10.200.1.0/24', '10.0.0.0/8')) {
        $rejected = $false
        try { Assert-NmeNetworkSeparation '10.200.0.0/16' @($existingCidr) } catch { $rejected = $true }
        if (-not $rejected) { throw 'An overlapping private network was accepted.' }
    }
    $probeGroup = '/subscriptions/example/resourceGroups/nme'
    $probePreview = @{ Status = 'Succeeded'; Changes = @(@{ ChangeType = 'Create'; FullyQualifiedResourceId = $probeGroup + '/providers/Microsoft.Web/sites/example' }) }
    Assert-NmePreviewScope $probePreview $probeGroup
    foreach ($change in @(
        @{ ChangeType = 'Create'; FullyQualifiedResourceId = '/subscriptions/example/resourceGroups/other/providers/Microsoft.Web/sites/example' },
        @{ ChangeType = 'Delete'; FullyQualifiedResourceId = $probeGroup + '/providers/Microsoft.Web/sites/example' },
        @{ ChangeType = 'Create'; ResourceId = $probeGroup + '/providers/Microsoft.Web/sites/example' }
    )) {
        $rejected = $false
        try { Assert-NmePreviewScope @{ Status = 'Succeeded'; Changes = @($change) } $probeGroup } catch { $rejected = $true }
        if (-not $rejected) { throw 'An unsafe or unrecognized deployment preview was accepted.' }
    }
    $probeConfig = Get-NmePortalConfiguration 'https://example.azurewebsites.net/' '192.0.2.1'
    if ($probeConfig.Split("`n").Count -ne 2 -or $probeConfig -notmatch '(?m)^resolve = "example\.azurewebsites\.net:443:192\.0\.2\.1"$') { throw 'The TLS-verified portal transport configuration is malformed.' }
    $rejected = $false
    try { $null = Get-NmePortalConfiguration 'http://example.azurewebsites.net/' '192.0.2.1' } catch { $rejected = $true }
    if (-not $rejected) { throw 'An insecure management app request was accepted.' }
    [pscustomobject]@{ OfflineChecksPassed = $true; SharedBrandName = $brand.name; SharedBrandResolved = $true; PublicPortalPreserved = $true; PrivateBackendsSelected = $true; VendorPackageGuardsPassed = $true; NetworkOverlapGuardsPassed = $true; DeploymentScopeGuardsPassed = $true; PortalTransportGuardsPassed = $true; AzureCallsMade = $false }
    return
}

$settings = Read-LeafPrivateTarget $repo
Import-Module Az.Accounts -MinimumVersion 5.3.3 -ErrorAction Stop
Import-Module Az.Resources -ErrorAction Stop
$context = Get-AzContext
Assert-LeafTargetContext $settings $context
$subscriptions = @(Get-AzSubscription -TenantId $settings.TARGET_TENANT_ID -SubscriptionId $settings.TARGET_SUBSCRIPTION_ID -DefaultProfile $context)
if ($subscriptions.Count -ne 1 -or $subscriptions[0].TenantId -ne $settings.TARGET_TENANT_ID -or $subscriptions[0].Id -ne $settings.TARGET_SUBSCRIPTION_ID -or $subscriptions[0].State -ne 'Enabled') { throw 'The target subscription ownership or enabled state is unverified.' }
$inputs = @{}
$keys = @('TARGET_LOCATION', 'TARGET_REGION_CODE', 'TARGET_INSTANCE', 'TARGET_NME_RESOURCE_GROUP_NAME', 'TARGET_NME_RESOURCE_NAME_PREFIX', 'TARGET_NME_INSTALLATION_ID')
foreach ($line in [IO.File]::ReadAllLines((Join-Path $repo '.env'))) {
    $entry = [regex]::Match($line, '^\s*(?<key>TARGET_[A-Z0-9_]+)\s*=\s*(?<value>.*)$')
    if (-not $entry.Success -or $entry.Groups['key'].Value -notin $keys) { continue }
    $key = $entry.Groups['key'].Value
    if ($inputs.ContainsKey($key)) { throw 'Duplicate NMe target input.' }
    $inputs[$key] = $entry.Groups['value'].Value.Trim().Trim([char]34, [char]39)
}
if ($inputs.TARGET_LOCATION -ne $desired.location -or $inputs.TARGET_REGION_CODE -ne 'swc' -or $inputs.TARGET_INSTANCE -notmatch '^[0-9]{1,3}$') { throw 'Private region or naming inputs differ from the approved NMe placement.' }
$groupName = if ($inputs.TARGET_NME_RESOURCE_GROUP_NAME) { $inputs.TARGET_NME_RESOURCE_GROUP_NAME } else { 'rg-nme-{0}-{1}' -f $inputs.TARGET_REGION_CODE, $inputs.TARGET_INSTANCE }
if ($groupName -notmatch '^rg-nme-swc-[0-9]{1,3}$') { throw 'The NMe group must match the reviewed CAF workload/region/instance convention.' }
$prefix = if ($inputs.TARGET_NME_RESOURCE_NAME_PREFIX) { $inputs.TARGET_NME_RESOURCE_NAME_PREFIX } else { $brand.name.ToLowerInvariant() }
if ($prefix -notmatch '^[a-z][a-z0-9-]{0,5}[a-z0-9]$') { throw 'The installer prefix must be 2-7 lowercase characters so the vendor-generated Key Vault name fits its limit.' }
$groupPath = '/subscriptions/' + $settings.TARGET_SUBSCRIPTION_ID + '/resourceGroups/' + $groupName + '?api-version=2024-03-01'
$groupResponse = Invoke-AzRestMethod -Method GET -Path $groupPath -DefaultProfile $context
if ($groupResponse.StatusCode -notin @(200, 404)) { throw 'The NMe group could not be read; absence is not assumed.' }
$groupExists = $groupResponse.StatusCode -eq 200
$resourceCount = if ($groupExists) { @(Get-AzResource -ResourceGroupName $groupName -DefaultProfile $context).Count } else { 0 }
$installed = -not [string]::IsNullOrWhiteSpace($inputs.TARGET_NME_INSTALLATION_ID)
$privateRoot = Join-Path $repo 'private/nme'
[void][IO.Directory]::CreateDirectory($privateRoot)
if ($Verify) {
    if (-not $groupExists -or $resourceCount -eq 0) { throw 'No deployed NMe resources are available to verify.' }
    $resources = @(Get-AzResource -ResourceGroupName $groupName -ExpandProperties -DefaultProfile $context)
    $web = @($resources | Where-Object ResourceType -eq 'Microsoft.Web/sites')
    $sql = @($resources | Where-Object ResourceType -eq 'Microsoft.Sql/servers')
    $vault = @($resources | Where-Object ResourceType -eq 'Microsoft.KeyVault/vaults')
    $storage = @($resources | Where-Object ResourceType -eq 'Microsoft.Storage/storageAccounts')
    if ($web.Count -ne 1 -or $sql.Count -ne 1 -or $vault.Count -ne 1 -or $storage.Count -ne 1) { throw 'The installed core NMe resources are missing or ambiguous.' }
    $vaultResponse = Invoke-AzRestMethod -Method GET -Path ($vault[0].ResourceId + '?api-version=2023-07-01') -DefaultProfile $context
    $authResponse = Invoke-AzRestMethod -Method GET -Path ($web[0].ResourceId + '/config/authsettingsV2?api-version=2024-04-01') -DefaultProfile $context
    $configResponse = Invoke-AzRestMethod -Method GET -Path ($web[0].ResourceId + '/config/web?api-version=2024-04-01') -DefaultProfile $context
    $sqlAuthResponse = Invoke-AzRestMethod -Method GET -Path ($sql[0].ResourceId + '/azureADOnlyAuthentications/Default?api-version=2023-08-01') -DefaultProfile $context
    foreach ($response in @($vaultResponse, $authResponse, $configResponse, $sqlAuthResponse)) {
        if ($response.StatusCode -ne 200) { throw 'An installed NMe access setting could not be read; it is not assumed compliant.' }
    }
    $vaultProperties = (ConvertFrom-Json -InputObject $vaultResponse.Content -AsHashtable).properties
    $authProperties = (ConvertFrom-Json -InputObject $authResponse.Content -AsHashtable).properties
    $webConfig = (ConvertFrom-Json -InputObject $configResponse.Content -AsHashtable).properties
    $sqlAuth = (ConvertFrom-Json -InputObject $sqlAuthResponse.Content -AsHashtable).properties
    $endpoints = @($resources | Where-Object ResourceType -eq 'Microsoft.Network/privateEndpoints')
    $endpointStates = @($endpoints | ForEach-Object { $_.Properties.privateLinkServiceConnections | ForEach-Object { $_.properties.privateLinkServiceConnectionState.status } })
    $portalConfig = Get-NmePortalConfiguration ([uri]('https://' + $web[0].Properties.defaultHostName + '/')) $web[0].Properties.inboundIpAddress
    $curlResult = $portalConfig | & curl.exe --config - --proto '=https' --output (Join-Path $privateRoot 'initialization.html') --max-time 60 --silent --write-out '%{http_code}' 2>&1
    $curlExitCode = $LASTEXITCODE
    $status = [ordered]@{
        timeUtc = [datetimeoffset]::UtcNow.ToString('o')
        targetVerified = $true
        publicManagementPortal = $web[0].Properties.publicNetworkAccess -eq 'Enabled'
        httpsOnly = $web[0].Properties.httpsOnly -eq $true
        appServiceAuthenticationDisabled = $authProperties.platform.enabled -eq $false
        ftpDisabled = $webConfig.ftpsState -eq 'Disabled'
        appHasPrivateVnetIntegration = -not [string]::IsNullOrWhiteSpace([string]$web[0].Properties.virtualNetworkSubnetId)
        sqlPublicAccessDisabled = $sql[0].Properties.publicNetworkAccess -eq 'Disabled'
        sqlEntraOnly = $sqlAuth.azureADOnlyAuthentication -eq $true
        vaultPublicAccessDisabled = $vaultProperties.publicNetworkAccess -eq 'Disabled'
        storagePublicAccessDisabled = $storage[0].Properties.publicNetworkAccess -eq 'Disabled'
        storageSharedKeyAccessAllowed = $storage[0].Properties.allowSharedKeyAccess -ne $false
        privateEndpointCount = $endpoints.Count
        privateEndpointsApproved = $endpointStates.Count -ge 4 -and @($endpointStates | Where-Object { $_ -ne 'Approved' }).Count -eq 0
        portalHttpStatus = if ($curlExitCode -eq 0) { [int]($curlResult -join '').Trim() } else { $null }
        portalTransportExitCode = $curlExitCode
        tlsVerificationEnabled = $true
        installationIdConfigured = $installed
        azureChangesMade = $false
    }
    [IO.File]::WriteAllText((Join-Path $privateRoot 'verification.json'), ($status | ConvertTo-Json -Depth 6), [Text.UTF8Encoding]::new($false))
    [pscustomobject]@{ Mode = 'Verification'; PublicPortalPreserved = $status.publicManagementPortal; PrivateCoreBackends = $status.sqlPublicAccessDisabled -and $status.vaultPublicAccessDisabled -and $status.storagePublicAccessDisabled; SqlEntraOnly = $status.sqlEntraOnly; PrivateEndpointsApproved = $status.privateEndpointsApproved; PortalHttpStatus = $status.portalHttpStatus; VendorStorageKeyAccessBlocked = -not $status.storageSharedKeyAccessAllowed; AzureChangesMade = $false }
    return
}
$plan = [ordered]@{
    timeUtc = [datetimeoffset]::UtcNow.ToString('o')
    targetVerified = $true
    location = $desired.location
    resourceGroupName = $groupName
    groupExists = $groupExists
    existingResourceCount = $resourceCount
    proposedInstallerPrefix = $prefix
    installationIdConfigured = $installed
    sharedBrandName = $brand.name
    brandDescriptor = $brand.descriptor
    brandColor = $brand.palette.green
    brandAssetsGuide = 'branding/README.md'
    installerPrefixConstraintsReviewed = $false
    nmePortalBrandingCapabilityVerified = $false
    desiredStateSha256 = (Get-FileHash -LiteralPath (Join-Path $PSScriptRoot 'desired.json') -Algorithm SHA256).Hash
    azureChangesMade = $false
}
[IO.File]::WriteAllText((Join-Path $privateRoot 'installation-plan.json'), ($plan | ConvertTo-Json -Depth 6), [Text.UTF8Encoding]::new($false))
if ($resourceCount -gt 0) { throw 'The NMe group is not empty. Inspect the existing installation; do not replay Marketplace bootstrap.' }
if ($installed) { throw 'An installation ID is already configured. Inspect that installation instead of creating another.' }
$productPath = '/subscriptions/' + $settings.TARGET_SUBSCRIPTION_ID + '/providers/Microsoft.Marketplace/products/' + $desired.installation.publisher + '.' + $desired.installation.offer + '?api-version=2025-05-01&includeServiceInstructionTemplates=true'
$productResponse = Invoke-AzRestMethod -Method GET -Path $productPath -DefaultProfile $context
if ($productResponse.StatusCode -ne 200) { throw 'Subscription-scoped Marketplace product discovery failed; installation was not attempted.' }
$product = ConvertFrom-Json -InputObject $productResponse.Content -AsHashtable -Depth 100
$artifactUri = Get-NmeTemplateArtifact $product
$packageRoot = Join-Path $privateRoot 'marketplace'
[void][IO.Directory]::CreateDirectory($packageRoot)
$templatePath = Join-Path $packageRoot 'mainTemplate.json'
try { Invoke-WebRequest -Uri $artifactUri -OutFile $templatePath -TimeoutSec 60 } catch { throw 'The vendor template could not be downloaded; installation was not attempted.' }
$templateHash = (Get-FileHash -LiteralPath $templatePath -Algorithm SHA256).Hash
if ($templateHash -ne $desired.installation.templateSha256) { throw 'The downloaded vendor template differs from the reviewed hash; installation was not attempted.' }
$template = Get-Content -LiteralPath $templatePath -Raw | ConvertFrom-Json -AsHashtable -Depth 100
foreach ($name in @('location', 'appName', 'configurePrivateEndpoints', 'privateWebApp', '_artifactsLocation', '_artifactsLocationSasToken')) {
    if (-not $template.parameters.Contains($name)) { throw 'The vendor template parameter contract has changed.' }
}
$plan.marketplacePlan = $desired.installation.plan
$plan.marketplaceVersion = $desired.installation.version
$plan.vendorTemplateSha256 = $templateHash
$plan.vendorTemplateVerified = $true
$plan.installerPrefixConstraintsReviewed = $true
[IO.File]::WriteAllText((Join-Path $privateRoot 'installation-plan.json'), ($plan | ConvertTo-Json -Depth 6), [Text.UTF8Encoding]::new($false))
$providerChanges = $false
$providers = @(foreach ($namespace in @('Microsoft.Web', 'Microsoft.Sql', 'Microsoft.KeyVault', 'Microsoft.Insights', 'Microsoft.Automation', 'Microsoft.OperationalInsights', 'Microsoft.Storage', 'Microsoft.Network')) {
    $states = @(Get-AzResourceProvider -ProviderNamespace $namespace -DefaultProfile $context | Select-Object -ExpandProperty RegistrationState -Unique)
    if ($states.Count -ne 1 -or $states[0] -notin @('Registered', 'Registering', 'NotRegistered')) { throw 'A required NMe resource provider has an unknown registration state.' }
    if ($RegisterProviders -and $states[0] -eq 'NotRegistered') {
        Assert-LeafTargetContext $settings (Get-AzContext)
        $null = Register-AzResourceProvider -ProviderNamespace $namespace -DefaultProfile $context
        $providerChanges = $true
        $states = @(Get-AzResourceProvider -ProviderNamespace $namespace -DefaultProfile $context | Select-Object -ExpandProperty RegistrationState -Unique)
    }
    [pscustomobject]@{ Namespace = $namespace; State = if ($states.Count -eq 1) { $states[0] } else { 'Unknown' } }
})
[IO.File]::WriteAllText((Join-Path $privateRoot 'providers.json'), ($providers | ConvertTo-Json -Depth 4), [Text.UTF8Encoding]::new($false))
$providersReady = @($providers | Where-Object State -ne 'Registered').Count -eq 0
if ($RegisterProviders -or -not $providersReady) {
    [pscustomobject]@{ Mode = if ($RegisterProviders) { 'ProviderRegistration' } else { 'PrerequisitesRequired' }; ProvidersReady = $providersReady; PendingProviders = @($providers | Where-Object State -eq 'Registering' | ForEach-Object Namespace); UnregisteredProviders = @($providers | Where-Object State -eq 'NotRegistered' | ForEach-Object Namespace); AzureChangesMade = $providerChanges }
    return
}

$existingCidrs = @(foreach ($network in @(Get-AzResource -ResourceType 'Microsoft.Network/virtualNetworks' -ExpandProperties -DefaultProfile $context)) {
    if (-not $network.Properties.addressSpace.addressPrefixes) { throw 'An existing VNet address space could not be verified.' }
    $network.Properties.addressSpace.addressPrefixes
})
Assert-NmeNetworkSeparation $template.parameters.privateEndpointsVnetCidr.defaultValue $existingCidrs
$compiledPath = Join-Path $privateRoot 'main.json'
& az bicep build --file (Join-Path $PSScriptRoot 'main.bicep') --outfile $compiledPath
if ($LASTEXITCODE -ne 0) { throw 'The Marketplace composition could not be compiled.' }
$source = [UriBuilder]::new($artifactUri)
$source.Query = ''
$deploymentParameters = @{
    resourceGroupName = $groupName
    location = $desired.location
    namePrefix = $prefix
    artifactsLocation = $source.Uri.AbsoluteUri
    artifactsLocationSasToken = if ($artifactUri.Query) { ConvertTo-SecureString $artifactUri.Query -AsPlainText -Force } else { [securestring]::new() }
}
$arguments = @{ Name = 'nme-bootstrap'; Location = $desired.location; TemplateFile = $compiledPath; TemplateParameterObject = $deploymentParameters; DefaultProfile = $context; SkipTemplateParameterPrompt = $true }
try { $preview = Get-AzSubscriptionDeploymentWhatIfResult @arguments -ResultFormat ResourceIdOnly } catch { throw 'The Azure NMe deployment preview failed; no deployment was submitted.' }
[IO.File]::WriteAllText((Join-Path $privateRoot 'what-if.json'), ($preview | ConvertTo-Json -Depth 50), [Text.UTF8Encoding]::new($false))
$groupId = '/subscriptions/' + $settings.TARGET_SUBSCRIPTION_ID + '/resourceGroups/' + $groupName
Assert-NmePreviewScope $preview $groupId
if (-not $Apply) {
    [pscustomobject]@{ Mode = 'Preview'; TargetVerified = $true; SharedBrandName = $brand.name; VendorTemplateVerified = $true; MarketplaceVersion = $desired.installation.version; PrivateNetworkOverlapChecked = $true; PlannedChanges = @($preview.Changes).Count; AzureChangesMade = $false }
    return
}
Assert-LeafTargetContext $settings (Get-AzContext)
try { $deployment = New-AzSubscriptionDeployment @arguments } catch { throw 'The NMe deployment failed or its result is unknown. Inspect the existing nme-bootstrap deployment before any retry.' }
if ($deployment.ProvisioningState -ne 'Succeeded') { throw 'The NMe bootstrap did not complete successfully; do not replay into its partially populated group.' }
$appUrl = [uri]$deployment.Outputs.appUrl.Value
if ($appUrl.Scheme -ne 'https' -or $appUrl.Host -notmatch '\.azurewebsites\.net$') { throw 'The vendor deployment returned an unexpected application URL.' }
$plan.azureChangesMade = $true
$plan.deploymentSucceeded = $true
$plan.appUrl = $appUrl.AbsoluteUri
$plan.initializationCompleted = $false
[IO.File]::WriteAllText((Join-Path $privateRoot 'installation-plan.json'), ($plan | ConvertTo-Json -Depth 6), [Text.UTF8Encoding]::new($false))
[pscustomobject]@{ Mode = 'MarketplaceDeployed'; VendorTemplateVerified = $true; PublicPortalSelected = $true; PrivateBackendsSelected = $true; InitializationCompleted = $false; AzureChangesMade = $true }