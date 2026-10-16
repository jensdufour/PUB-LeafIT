#requires -Version 7.6
[CmdletBinding()]
param([switch]$Apply, [switch]$Verify, [switch]$CheckOnly, [switch]$ConnectGraph)

$ErrorActionPreference = 'Stop'
if (@($Apply, $Verify, $CheckOnly | Where-Object { $_ }).Count -gt 1 -or ($CheckOnly -and $ConnectGraph)) { throw 'Choose offline checks, preview, apply, or verification separately.' }
$repo = Split-Path $PSScriptRoot -Parent
. (Join-Path $repo 'identity/Target.ps1')
$desired = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'desired.json') -Raw | ConvertFrom-Json -AsHashtable

function Test-NmeAliasJson($Left, $Right, [switch]$WebAuthentication) {
    if ($WebAuthentication) {
        $Left = ConvertTo-Json -InputObject $Left -Depth 40 | ConvertFrom-Json -AsHashtable
        $Right = ConvertTo-Json -InputObject $Right -Depth 40 | ConvertFrom-Json -AsHashtable
        foreach ($webState in @($Left, $Right)) {
            $webState.redirectUris = @($webState.redirectUris | Sort-Object -CaseSensitive)
            if ($webState.ContainsKey('redirectUriSettings')) { $webState.redirectUriSettings = @($webState.redirectUriSettings | Sort-Object -Property uri -CaseSensitive) }
        }
    }
    return [Text.Json.Nodes.JsonNode]::DeepEquals(
        [Text.Json.Nodes.JsonNode]::Parse((ConvertTo-Json -InputObject $Left -Depth 40 -Compress)),
        [Text.Json.Nodes.JsonNode]::Parse((ConvertTo-Json -InputObject $Right -Depth 40 -Compress)))
}

function Get-NmeAliasDesiredState($Source, [string]$Label, [string]$Zone, [string]$DefaultHost, [string]$VerificationId, $Web) {
    $hostName = $Label + '.' + $Zone
    if ($Label -notmatch '^[a-z][a-z0-9-]{0,61}[a-z0-9]$' -or $hostName.Length -gt 64 -or $Zone -notmatch '^(?:[a-z0-9-]+\.)+[a-z]{2,63}$' -or $DefaultHost -notmatch '^[a-z0-9-]+\.azurewebsites\.net$' -or $VerificationId -notmatch '^[a-fA-F0-9]{64}$' -or [int]$Source.ttl -ne 3600) { throw 'Invalid custom-domain, management-host, verification, or TTL input.' }
    $records = ConvertTo-Json -InputObject $Source -Depth 40 | ConvertFrom-Json -AsHashtable
    $cname = @($records.cnameRecords | Where-Object name -IEQ $Label)
    $txtName = 'asuid.' + $Label
    $txt = @($records.namedTxtRecords | Where-Object name -IEQ $txtName)
    if ($cname.Count -gt 1 -or ($cname.Count -eq 1 -and $cname[0].canonicalName -ine $DefaultHost) -or @($records.namedTxtRecords | Where-Object name -IEQ $Label).Count -or @($records.cnameRecords | Where-Object name -IEQ $txtName).Count) { throw 'Private DNS contains a conflicting alias owner or target.' }
    if ($txt.Count -gt 1 -or ($txt.Count -eq 1 -and -not (Test-NmeAliasJson @($txt[0].values) @($VerificationId)))) { throw 'Private DNS contains a conflicting domain-verification record.' }
    if (-not $cname.Count) { $records.cnameRecords = @($records.cnameRecords) + @(@{ name = $Label; canonicalName = $DefaultHost }) }
    if (-not $txt.Count) { $records.namedTxtRecords = @($records.namedTxtRecords | Where-Object { $null -ne $_ }) + @(@{ name = $txtName; values = @($VerificationId) }) }
    $proposedWeb = ConvertTo-Json -InputObject $Web -Depth 40 | ConvertFrom-Json -AsHashtable
    $redirects = @($proposedWeb.redirectUris)
    if (('https://' + $DefaultHost + '/signin-oidc') -cnotin $redirects) { throw 'The Entra application is not bound to this management app.' }
    if ($proposedWeb.ContainsKey('redirectUriSettings') -and (@($proposedWeb.redirectUriSettings).Count -ne $redirects.Count -or @(Compare-Object @($redirects | Sort-Object -CaseSensitive) @($proposedWeb.redirectUriSettings | ForEach-Object uri | Sort-Object -CaseSensitive) -CaseSensitive).Count)) { throw 'Redirect metadata must match the complete existing URI collection.' }
    foreach ($uri in @(('https://' + $hostName + '/'), ('https://' + $hostName + '/signin-oidc'))) {
        if ($uri -cnotin $redirects) {
            $redirects += $uri
            if ($proposedWeb.ContainsKey('redirectUriSettings')) { $proposedWeb.redirectUriSettings += @{ uri = $uri; index = $null } }
        }
    }
    $proposedWeb.redirectUris = $redirects
    return @{ Records = $records; Web = $proposedWeb; HostName = $hostName }
}

function Test-NmeAliasCertificate($Certificate, [string]$HostName, [string]$ServerFarmId) {
    if (-not $Certificate) { return $true }
    $properties = $Certificate.properties
    return $properties.canonicalName -ieq $HostName -and
        ([string]::IsNullOrWhiteSpace($properties.serverFarmId) -or $properties.serverFarmId -ieq $ServerFarmId) -and
        [string]::IsNullOrWhiteSpace($properties.keyVaultId) -and
        (-not $properties.thumbprint -or ($properties.subjectName -ieq $HostName -and @($properties.hostNames).Count -eq 1 -and $HostName -iin @($properties.hostNames)))
}

if ($CheckOnly) {
    $null = Test-LeafTargetGuards
    $source = @{ ttl = 3600; cnameRecords = @(@{ name = 'autodiscover'; canonicalName = 'example.invalid' }); apexTxtValues = @('v=spf1 -all'); mxRecords = @(@{ preference = 0; exchange = 'example.invalid' }) }
    $web = @{ redirectUris = @('https://example.azurewebsites.net/', 'https://example.azurewebsites.net/signin-oidc', 'https://retained.example.com/'); homePageUrl = 'https://retained.example.com/'; implicitGrantSettings = @{ enableIdTokenIssuance = $true; enableAccessTokenIssuance = $false }; logoutUrl = $null }
    $web.redirectUriSettings = @($web.redirectUris | ForEach-Object { @{ uri = $_; index = $null } })
    $plan = Get-NmeAliasDesiredState $source 'nerdio' 'example.com' 'example.azurewebsites.net' ('A' * 64) $web
    if ($plan.Records.cnameRecords.Count -ne 2 -or $plan.Records.namedTxtRecords.Count -ne 1 -or $plan.Web.redirectUris.Count -ne 5 -or -not (Test-NmeAliasJson $source.cnameRecords[0] $plan.Records.cnameRecords[0]) -or -not (Test-NmeAliasJson $web.implicitGrantSettings $plan.Web.implicitGrantSettings) -or $plan.Web.homePageUrl -cne $web.homePageUrl -or $source.ContainsKey('namedTxtRecords') -or $web.redirectUris.Count -ne 3) { throw 'Alias planning changed an unrelated field or its inputs.' }
    $repeat = Get-NmeAliasDesiredState $plan.Records 'nerdio' 'example.com' 'example.azurewebsites.net' ('A' * 64) $plan.Web
    if (-not (Test-NmeAliasJson $plan $repeat)) { throw 'Repeated alias planning is not NoChange.' }
    if ($plan.Web.redirectUriSettings.Count -ne 5 -or -not (Test-NmeAliasJson $web.redirectUriSettings[0] $plan.Web.redirectUriSettings[0])) { throw 'Existing redirect metadata was changed or new metadata was omitted.' }
    $reordered = ConvertTo-Json -InputObject $plan.Web -Depth 40 | ConvertFrom-Json -AsHashtable
    $reordered.redirectUris = @($reordered.redirectUris | Sort-Object -Descending)
    $reordered.redirectUriSettings = @($reordered.redirectUriSettings | Sort-Object -Property uri -Descending)
    if (-not (Test-NmeAliasJson $plan.Web $reordered -WebAuthentication)) { throw 'Equivalent redirect collections were treated as ordered lists.' }
    $reordered.redirectUriSettings[0].index = 'unrelated-change'
    if (Test-NmeAliasJson $plan.Web $reordered -WebAuthentication) { throw 'Changed per-URI authentication metadata was accepted.' }
    $certificateProbe = @{ properties = @{ canonicalName = 'nerdio.example.com'; subjectName = 'nerdio.example.com'; hostNames = @('nerdio.example.com'); thumbprint = 'B' * 40; serverFarmId = $null; keyVaultId = $null } }
    if (-not (Test-NmeAliasCertificate $certificateProbe 'nerdio.example.com' '/example/plan')) { throw 'A matching native managed certificate without the omitted plan field was rejected.' }
    foreach ($field in @('canonicalName', 'subjectName', 'serverFarmId', 'keyVaultId')) {
        $invalidCertificate = ConvertTo-Json -InputObject $certificateProbe -Depth 10 | ConvertFrom-Json -AsHashtable
        $invalidCertificate.properties[$field] = 'unrelated'
        if (Test-NmeAliasCertificate $invalidCertificate 'nerdio.example.com' '/example/plan') { throw 'An unrelated managed certificate was accepted.' }
    }
    foreach ($kind in @('CnameConflict', 'TxtConflict', 'OwnerConflict', 'WrongApp', 'InvalidLabel', 'InvalidVerification')) {
        $invalidSource = ConvertTo-Json -InputObject $plan.Records -Depth 40 | ConvertFrom-Json -AsHashtable
        $invalidWeb = ConvertTo-Json -InputObject $web -Depth 40 | ConvertFrom-Json -AsHashtable
        $label = 'nerdio'; $verificationId = 'A' * 64
        switch ($kind) {
            CnameConflict { $invalidSource.cnameRecords[-1].canonicalName = 'other.azurewebsites.net' }
            TxtConflict { $invalidSource.namedTxtRecords[0].values = @('B' * 64) }
            OwnerConflict { $invalidSource.namedTxtRecords += @{ name = 'nerdio'; values = @('unrelated') } }
            WrongApp { $invalidWeb.redirectUris = @('https://other.azurewebsites.net/signin-oidc') }
            InvalidLabel { $label = '../other' }
            InvalidVerification { $verificationId = 'invalid' }
        }
        $rejected = $false
        try { $null = Get-NmeAliasDesiredState $invalidSource $label 'example.com' 'example.azurewebsites.net' $verificationId $invalidWeb } catch { $rejected = $true }
        if (-not $rejected) { throw "An unsafe alias fixture was accepted: $kind." }
    }
    $compiled = & az bicep build --file (Join-Path $PSScriptRoot 'custom-domain.bicep') --stdout --no-restore
    if ($LASTEXITCODE -ne 0) { throw 'Alias Bicep compilation failed.' }
    $template = ($compiled -join "`n") | ConvertFrom-Json -AsHashtable
    if ($template.resources.Count -ne 2 -or @($template.resources | Where-Object { $_.type -notin @('Microsoft.Web/sites/hostNameBindings', 'Microsoft.Web/certificates') -or -not $_.condition }).Count) { throw 'The alias template exceeds its conditional binding/certificate scope.' }
    [pscustomobject]@{ OfflineChecksPassed = $true; ConflictsRejected = $true; ExistingDnsAndRedirectsPreserved = $true; RepeatNoChange = $true; BicepCompiled = $true; CloudAccess = $false }
    return
}

$settings = Read-LeafPrivateTarget $repo
Import-Module Az.Accounts -MinimumVersion 5.3.3 -ErrorAction Stop
Import-Module Az.Resources -ErrorAction Stop
Import-Module Az.Dns -MinimumVersion 2.0.0 -ErrorAction Stop
$context = Get-AzContext
Assert-LeafTargetContext $settings $context
$envPath = Join-Path $repo '.env'
$envHash = (Get-FileHash -LiteralPath $envPath -Algorithm SHA256).Hash
$inputs = @{}
foreach ($line in [IO.File]::ReadAllLines($envPath)) {
    $entry = [regex]::Match($line, '^\s*(?<key>TARGET_(?:NME_RESOURCE_GROUP_NAME|REGION_CODE|INSTANCE))\s*=\s*(?<value>.*)$')
    if (-not $entry.Success) { continue }
    $key = $entry.Groups['key'].Value
    if ($inputs.ContainsKey($key)) { throw 'Duplicate private alias-target input.' }
    $inputs[$key] = $entry.Groups['value'].Value.Trim().Trim([char]34, [char]39)
}
if ($inputs.TARGET_REGION_CODE -ne 'swc' -or $inputs.TARGET_INSTANCE -notmatch '^[0-9]{1,3}$') { throw 'The private NMe naming/region inputs are invalid.' }
$groupName = if ($inputs.TARGET_NME_RESOURCE_GROUP_NAME) { $inputs.TARGET_NME_RESOURCE_GROUP_NAME } else { 'rg-nme-swc-' + $inputs.TARGET_INSTANCE }
if ($groupName -notmatch '^rg-nme-swc-[0-9]{1,3}$') { throw 'The NMe group violates the reviewed naming contract.' }
$dnsGroup = 'rg-infra-swc-' + $inputs.TARGET_INSTANCE
$privateRoot = Join-Path $repo 'private/nme/custom-domain'
git -C $repo check-ignore --quiet -- $privateRoot
if ($LASTEXITCODE -ne 0) { throw 'Custom-domain evidence must be ignored.' }
[void][IO.Directory]::CreateDirectory($privateRoot)
$installation = Get-Content -LiteralPath (Join-Path $repo 'private/nme/installation-plan.json') -Raw | ConvertFrom-Json -AsHashtable
if ($installation.resourceGroupName -ne $groupName -or $installation.deploymentSucceeded -ne $true) { throw 'A matching, deployed NMe installation is required.' }
$webApps = @(Get-AzResource -ResourceGroupName $groupName -ResourceType Microsoft.Web/sites -ExpandProperties -DefaultProfile $context)
if ($webApps.Count -ne 1 -or $webApps[0].Properties.defaultHostName -ne ([uri]$installation.appUrl).Host) { throw 'The installed management app is missing, ambiguous, or differs from the deployment.' }
$siteId = $webApps[0].ResourceId

function Read-NmeAliasArm([string]$Path, [switch]$AllowNotFound) {
    Assert-LeafTargetContext $settings (Get-AzContext)
    if (-not $Path.StartsWith('/subscriptions/' + $settings.TARGET_SUBSCRIPTION_ID + '/', [StringComparison]::OrdinalIgnoreCase) -or $Path.Contains('..')) { throw 'The alias ARM read is outside the verified target.' }
    try { $response = Invoke-AzRestMethod -Method GET -Path ($Path + '?api-version=2024-04-01') -DefaultProfile $context -ErrorAction Stop } catch { throw 'The alias ARM read failed; inspect the current target before retrying.' }
    if ($AllowNotFound -and $response.StatusCode -eq 404) { return $null }
    if ($response.StatusCode -ne 200) { throw "The alias ARM read returned HTTP $($response.StatusCode); absence is not assumed." }
    return ConvertFrom-Json -InputObject $response.Content -AsHashtable -Depth 40 -DateKind String
}

$site = Read-NmeAliasArm $siteId
if ($site.location.Replace(' ', '').ToLowerInvariant() -ne $desired.location -or $site.properties.state -ne 'Running' -or $site.properties.publicNetworkAccess -ne 'Enabled' -or $site.properties.httpsOnly -ne $true) { throw 'The existing public HTTPS management app does not meet alias prerequisites.' }
$servicePlan = Read-NmeAliasArm $site.properties.serverFarmId
if ($servicePlan.sku.tier -notin @('Basic', 'Standard', 'Premium', 'PremiumV2', 'PremiumV3', 'PremiumV4', 'Isolated', 'IsolatedV2')) { throw 'The existing App Service tier does not support the selected custom-domain certificate.' }
$zone = Get-AzDnsZone -Name $settings.TARGET_DNS_ZONE_NAME -ResourceGroupName $dnsGroup -DefaultProfile $context
if ($zone.Tags.workload -ne 'infra' -or $zone.Tags.'managed-by' -ne 'bicep') { throw 'The shared public DNS zone is not owned by the foundation workflow.' }
$graphSession = $null
try {
    if ($ConnectGraph) { $graphSession = Connect-LeafTargetGraph -Settings $settings -RefreshFromAzure }
    if ((Get-MgContext).TenantId -ne $settings.TARGET_TENANT_ID) { throw 'Use -ConnectGraph to reuse the verified target Azure session; no interactive sign-in is performed.' }
    $organization = Invoke-LeafTargetGraph -Settings $settings -Path '/v1.0/organization?$select=id'
    if (@($organization.value).Count -ne 1 -or $organization.value[0].id -ne $settings.TARGET_TENANT_ID) { throw 'The Graph organization does not match the target.' }
    $brand = Get-Content -LiteralPath ([IO.Path]::GetFullPath((Join-Path $PSScriptRoot $desired.brandSource))) -Raw | ConvertFrom-Json -AsHashtable
    $filter = [uri]::EscapeDataString("displayName eq '" + ($brand.name + ' NMe').Replace("'", "''") + "'")
    $applications = @(Get-LeafTargetGraphCollection -Settings $settings -Path ('/v1.0/applications?$select=id,appId,displayName,web&$filter=' + $filter))
    if ($applications.Count -ne 1) { throw 'The installed NMe Entra application is missing or ambiguous.' }
    $application = $applications[0]
    $applicationPath = '/v1.0/applications/' + $application.id + '?$select=id,appId,displayName,web'
    $recordsPath = Join-Path $repo 'private/dns/records.json'
    $recordsText = [IO.File]::ReadAllText($recordsPath)
    $recordsHash = (Get-FileHash -LiteralPath $recordsPath -Algorithm SHA256).Hash
    $source = $recordsText | ConvertFrom-Json -AsHashtable
    $label = [string]$desired.access.customDomainLabel
    $alias = Get-NmeAliasDesiredState $source $label $settings.TARGET_DNS_ZONE_NAME $site.properties.defaultHostName $site.properties.customDomainVerificationId $application.web
    $bindingPath = $siteId + '/hostNameBindings/' + $alias.HostName
    $certificateName = 'cert-nme-swc-{0}-{1}' -f $inputs.TARGET_INSTANCE, $label
    $certificatePath = '/subscriptions/' + $settings.TARGET_SUBSCRIPTION_ID + '/resourceGroups/' + $groupName + '/providers/Microsoft.Web/certificates/' + $certificateName
    $binding = Read-NmeAliasArm $bindingPath -AllowNotFound
    $certificate = Read-NmeAliasArm $certificatePath -AllowNotFound
    if (-not (Test-NmeAliasCertificate $certificate $alias.HostName $site.properties.serverFarmId)) { throw 'An existing certificate name belongs to another hostname or App Service plan.' }
    if ($binding -and $binding.properties.sslState -ne 'Disabled' -and (-not $certificate -or $binding.properties.sslState -ne 'SniEnabled' -or $binding.properties.thumbprint -ine $certificate.properties.thumbprint)) { throw 'The alias already has an unrelated TLS binding; it will not be replaced.' }
    $dnsBefore = @(Get-AzDnsRecordSet -ZoneName $settings.TARGET_DNS_ZONE_NAME -ResourceGroupName $dnsGroup -DefaultProfile $context)
    $expectedDnsChanges = 0; $expectedDnsCreates = 0
    foreach ($record in @(@{ name = $label; type = 'CNAME' }, @{ name = 'asuid.' + $label; type = 'TXT' })) {
        $current = @($dnsBefore | Where-Object Name -IEQ $record.name)
        if ($current.Count -gt 1 -or ($current.Count -eq 1 -and [string]$current[0].RecordType -ine $record.type)) { throw 'The public alias owner already has a conflicting DNS record.' }
        if (-not $current.Count) { $expectedDnsChanges++; $expectedDnsCreates++; continue }
        if ($record.type -eq 'CNAME' -and (@($current[0].Records).Count -ne 1 -or $current[0].Records[0].Cname.TrimEnd('.') -ine $site.properties.defaultHostName)) { throw 'The public alias points to another target; it will not be overwritten.' }
        if ($record.type -eq 'TXT') {
            $values = @($current[0].Records | ForEach-Object { [string]::Join('', [string[]]$_.Value) })
            if (-not (Test-NmeAliasJson $values @($site.properties.customDomainVerificationId))) { throw 'The public domain-verification TXT conflicts with the management app.' }
        }
        if ([int]$current[0].Ttl -ne [int]$source.ttl) { $expectedDnsChanges++ }
    }
    $registrationChanges = -not (Test-NmeAliasJson $application.web $alias.Web -WebAuthentication)
    $secured = $binding -and $certificate -and $binding.properties.sslState -eq 'SniEnabled' -and $binding.properties.thumbprint -ieq $certificate.properties.thumbprint
    $summary = [ordered]@{ Mode = if ($Apply) { 'Apply' } elseif ($Verify) { 'Verify' } else { 'Preview' }; TargetVerified = $true; DnsChanges = $expectedDnsChanges; RedirectUrisToAdd = @($alias.Web.redirectUris).Count - @($application.web.redirectUris).Count; HostnameToCreate = -not [bool]$binding; ManagedCertificateToCreate = -not [bool]$certificate; TlsBindingNeeded = -not [bool]$secured; NoChange = $expectedDnsChanges -eq 0 -and -not $registrationChanges -and [bool]$secured; ExistingHostnamePreserved = $true; CloudChangesMade = $false }
    [IO.File]::WriteAllText((Join-Path $privateRoot 'preview.json'), ($summary | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
    if (-not $Apply -and -not $Verify) { [pscustomobject]$summary; return }

    function Invoke-NmeAliasDeployment([ValidateSet('Hostname', 'Certificate', 'Secure')][string]$Stage, [string]$Thumbprint = '') {
        Assert-LeafTargetContext $settings (Get-AzContext)
        if ($Stage -eq 'Secure' -and $Thumbprint -notmatch '^[a-fA-F0-9]{40}$') { throw 'A valid issued certificate is required before enabling TLS.' }
        $templatePath = Join-Path $privateRoot 'custom-domain.json'
        $null = & az bicep build --file (Join-Path $PSScriptRoot 'custom-domain.bicep') --outfile $templatePath --no-restore
        if ($LASTEXITCODE -ne 0) { throw 'Current custom-domain Bicep compilation failed.' }
        $parameters = @{ webAppName = $site.name; hostName = $alias.HostName; location = $site.location; serverFarmId = $site.properties.serverFarmId; certificateName = $certificateName; stage = $Stage; certificateThumbprint = $Thumbprint }
        $preview = Get-AzResourceGroupDeploymentWhatIfResult -ResourceGroupName $groupName -TemplateFile $templatePath -TemplateParameterObject $parameters -ResultFormat FullResourcePayloads -DefaultProfile $context
        if ($preview.Status -ne 'Succeeded' -or $preview.Error) { throw 'The alias stage did not produce a successful preview.' }
        $allowedId = if ($Stage -eq 'Certificate') { $certificatePath } else { $bindingPath }
        foreach ($change in @($preview.Changes | Where-Object ChangeType -NotIn @('NoChange', 'Ignore'))) {
            if ($change.ChangeType -notin @('Create', 'Modify') -or $change.FullyQualifiedResourceId -ine $allowedId) { throw 'The alias preview contains an unrelated operation or deletion.' }
        }
        $null = New-AzResourceGroupDeployment -Name ('nme-domain-' + $Stage.ToLowerInvariant()) -ResourceGroupName $groupName -TemplateFile $templatePath -TemplateParameterObject $parameters -DefaultProfile $context
        $summary.CloudChangesMade = $true
    }

    if ($Apply) {
        if ($registrationChanges) {
            $freshApplication = Invoke-LeafTargetGraph -Settings $settings -Path $applicationPath
            if (-not (Test-NmeAliasJson $freshApplication.web $application.web -WebAuthentication)) { throw 'Application authentication settings changed after preview; no write performed.' }
            [IO.File]::WriteAllText((Join-Path $privateRoot ('web-before-' + [guid]::NewGuid().ToString('N') + '.json')), (ConvertTo-Json -InputObject $application.web -Depth 40), [Text.UTF8Encoding]::new($false))
            $null = Invoke-LeafTargetGraph -Settings $settings -Path ('/v1.0/applications/' + $application.id) -Method PATCH -Body @{ web = $alias.Web }
            $readbackApplication = Invoke-LeafTargetGraph -Settings $settings -Path $applicationPath
            if (-not (Test-NmeAliasJson $readbackApplication.web $alias.Web -WebAuthentication)) { throw 'The redirect update did not preserve the complete intended web authentication settings.' }
            $summary.CloudChangesMade = $true
        }
        if (-not (Test-NmeAliasJson $source $alias.Records)) {
            if ((Get-FileHash -LiteralPath $recordsPath -Algorithm SHA256).Hash -ne $recordsHash) { throw 'Private DNS desired state changed after preview.' }
            [IO.File]::WriteAllText((Join-Path $privateRoot ('dns-before-' + [guid]::NewGuid().ToString('N') + '.json')), $recordsText, [Text.UTF8Encoding]::new($false))
            [IO.File]::WriteAllText($recordsPath, (ConvertTo-Json -InputObject $alias.Records -Depth 40), [Text.UTF8Encoding]::new($false))
        }
        $apex = @($dnsBefore | Where-Object { $_.Name -eq '@' -and [string]$_.RecordType -eq 'TXT' })
        $verificationValues = @($apex.Records | ForEach-Object { [string]::Join('', [string[]]$_.Value) } | Where-Object { $_ -cmatch '^MS=[A-Za-z0-9-]+$' } | Select-Object -Unique)
        if ($verificationValues.Count -ne 1) { throw 'A unique existing Entra verification TXT is required; none will be invented.' }
        $dnsPreview = & (Join-Path $repo 'infra/Deploy-Foundation.ps1') -VerificationTxtValue $verificationValues[0]
        if ($dnsPreview.PreviewStatus -ne 'Succeeded' -or $dnsPreview.MutationCount -ne $expectedDnsChanges -or $dnsPreview.CreateCount -ne $expectedDnsCreates) { throw 'Foundation DNS preview includes unexpected changes; no DNS deployment performed.' }
        $dnsResult = & (Join-Path $repo 'infra/Deploy-Foundation.ps1') -VerificationTxtValue $verificationValues[0] -Apply
        if ($dnsResult.Deployed) { $summary.CloudChangesMade = $true }
        if (-not $binding) { Invoke-NmeAliasDeployment 'Hostname'; $binding = Read-NmeAliasArm $bindingPath }
        if (-not $certificate) { Invoke-NmeAliasDeployment 'Certificate'; $certificate = Read-NmeAliasArm $certificatePath }
        if (-not $certificate.properties.thumbprint) {
            $summary.Status = 'CertificatePendingOrFailedInspectBeforeRetry'
            [pscustomobject]$summary
            return
        }
        if ($binding.properties.sslState -ne 'SniEnabled' -or $binding.properties.thumbprint -ine $certificate.properties.thumbprint) { Invoke-NmeAliasDeployment 'Secure' $certificate.properties.thumbprint }
    } elseif (-not $summary.NoChange) { throw 'The custom domain is not converged; verification performs no changes.' }

    $binding = Read-NmeAliasArm $bindingPath
    $readbackApplication = Invoke-LeafTargetGraph -Settings $settings -Path $applicationPath
    if ($binding.properties.sslState -ne 'SniEnabled' -or $binding.properties.thumbprint -ine $certificate.properties.thumbprint -or -not (Test-NmeAliasJson $readbackApplication.web $alias.Web -WebAuthentication)) { throw 'The custom-domain TLS binding or complete web authentication settings failed readback.' }
    $resolved = @(Resolve-DnsName -Name $alias.HostName -Type CNAME -DnsOnly -ErrorAction Stop | Where-Object Type -EQ CNAME)
    if (@($resolved | Where-Object { $_.Name -ieq $alias.HostName -and $_.NameHost.TrimEnd('.') -ieq $site.properties.defaultHostName }).Count -ne 1) { throw 'Public DNS has not converged to the expected direct CNAME.' }
    foreach ($hostName in @($alias.HostName, $site.properties.defaultHostName)) {
        $request = [string]::Join("`n", @(
            ('url = "https://{0}/"' -f $hostName),
            ('resolve = "{0}:443:{1}"' -f $hostName, $site.properties.inboundIpAddress)
        ))
        $headers = $request | & curl.exe --config - --proto '=https' --output NUL --dump-header - --silent --max-time 60
        $exitCode = $LASTEXITCODE
        $headerText = [string]::Join("`n", [string[]]@($headers))
        $status = [regex]::Matches($headerText, '(?m)^HTTP/\S+\s+(\d{3})')
        $location = [regex]::Match($headerText, '(?im)^location:\s*(.+)$')
        if ($exitCode -ne 0 -or -not $status.Count -or $status[-1].Groups[1].Value -ne '302' -or -not $location.Success) { throw "An existing or custom portal failed its TLS-verified sign-in redirect check (transport exit $exitCode)." }
        $login = [uri]$location.Groups[1].Value.Trim()
        $query = [Web.HttpUtility]::ParseQueryString($login.Query)
        if ($login.Scheme -ne 'https' -or $login.Host -ne 'login.microsoftonline.com' -or -not $login.AbsolutePath.StartsWith('/' + $settings.TARGET_TENANT_ID + '/', [StringComparison]::OrdinalIgnoreCase) -or $query['client_id'] -ne $application.appId -or $query['redirect_uri'] -cnotin @(('https://' + $hostName + '/'), ('https://' + $hostName + '/signin-oidc'))) { throw 'The portal sign-in redirect does not match the target tenant, application, and registered hostname.' }
        $headers = $null; $headerText = $null; $login = $null; $query = $null
    }
    $siteAfter = Read-NmeAliasArm $siteId
    foreach ($field in @('defaultHostName', 'serverFarmId', 'publicNetworkAccess', 'httpsOnly', 'virtualNetworkSubnetId')) {
        if (-not (Test-NmeAliasJson $site.properties[$field] $siteAfter.properties[$field])) { throw 'An unrelated management-app property changed during alias deployment.' }
    }
    if ((Get-FileHash -LiteralPath $envPath -Algorithm SHA256).Hash -ne $envHash) { throw 'Private target inputs changed during alias deployment.' }
    $summary.Status = 'Verified'
    $summary.PublicCnameVerified = $true
    $summary.TlsAndTargetSignInVerified = $true
    $summary.DefaultUrlVerified = $true
    $summary.AuthenticatedBrowserAcceptance = 'NotRun'
    [IO.File]::WriteAllText((Join-Path $privateRoot 'verification.json'), ($summary | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
    [pscustomobject]$summary
} finally {
    Disconnect-LeafTargetGraph $graphSession
}