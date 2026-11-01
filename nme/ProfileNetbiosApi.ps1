#requires -Version 7.6
[CmdletBinding()]
param([switch]$CheckOnly)

function Save-LeafNmeState {
    param($State, [string]$Path)
    $temporary = $Path + '.' + [guid]::NewGuid().ToString('N') + '.tmp'
    $stream = $null
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $State -Depth 12 -Compress -WarningAction Stop))
        $stream = [IO.File]::Open($temporary, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
        $stream.Dispose(); $stream = $null
        [IO.File]::Move($temporary, $Path, $true)
    } finally {
        if ($stream) { $stream.Dispose() }
        if ([IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) }
    }
}

function Assert-LeafNmeRestTokenClaims {
    param($Claims, [string]$TenantId, [string]$ClientId, [string]$ResourceAppId)
    if ($Claims -isnot [Collections.IDictionary] -or $Claims.tid -isnot [string] -or $Claims.azp -isnot [string] -or $Claims.aud -isnot [string] -or $Claims.ver -isnot [string] -or $Claims.tid -ne $TenantId -or $Claims.azp -ne $ClientId -or $Claims.aud -ne $ResourceAppId -or $Claims.ver -cne '2.0') { throw 'ExactNmeTargetClientAudienceRequired' }
    if ($Claims.roles -isnot [array] -or $Claims.roles.Count -ne 1 -or $Claims.roles[0] -isnot [string] -or $Claims.roles[0] -cne 'RestClient') { throw 'ExactApprovedRestClientRoleRequired' }
    if (($Claims.exp -isnot [int] -and $Claims.exp -isnot [long]) -or [DateTimeOffset]::FromUnixTimeSeconds($Claims.exp) -le [DateTimeOffset]::UtcNow.AddMinutes(2)) { throw 'UnexpiredNmeTokenRequired' }
}

function Get-LeafNmeRestConnection {
    param([Parameter(Mandatory)][string]$RepositoryRoot)
    $ErrorActionPreference = 'Stop'
    . (Join-Path $RepositoryRoot 'identity/Target.ps1')
    $settings = Read-LeafPrivateTarget $RepositoryRoot
    Assert-LeafTargetContext $settings (Get-AzContext)
    $context = Get-MgContext
    if (-not $context -or $context.TenantId -ne $settings.TARGET_TENANT_ID) { throw 'RetainedTargetGraphSessionRequired' }
    $inputs = @{}
    foreach ($line in [IO.File]::ReadAllLines((Join-Path $RepositoryRoot '.env'))) {
        $entry = [regex]::Match($line, '^\s*(?<key>TARGET_NME_API_(?:CLIENT_ID|CERTIFICATE_THUMBPRINT))\s*=\s*(?<value>.*)$')
        if (-not $entry.Success) { continue }
        $key = $entry.Groups['key'].Value
        if ($inputs.ContainsKey($key)) { throw 'DuplicatePrivateApiClientInput' }
        $inputs[$key] = $entry.Groups['value'].Value.Trim().Trim([char]34, [char]39)
    }
    $journal = Get-Content -LiteralPath (Join-Path $RepositoryRoot 'private/nme/rest-api-client.json') -Raw | ConvertFrom-Json -AsHashtable -DateKind String
    if ($journal.phase -cne 'Ready' -or $journal.applicationRoleVerified -ne $true -or $inputs.TARGET_NME_API_CLIENT_ID -ne $journal.clientId -or $inputs.TARGET_NME_API_CERTIFICATE_THUMBPRINT -ne $journal.certificateThumbprint) { throw 'PreviouslyVerifiedCertificateApiClientRequired' }
    $brand = Get-Content -LiteralPath (Join-Path $RepositoryRoot 'branding/brand.json') -Raw | ConvertFrom-Json -AsHashtable
    $filter = [uri]::EscapeDataString("displayName eq '" + ($brand.name + ' NMe').Replace("'", "''") + "'")
    $applications = @(Get-LeafTargetGraphCollection -Settings $settings -Path ('/v1.0/applications?$filter=' + $filter + '&$select=appId,api,identifierUris,appRoles'))
    if ($applications.Count -ne 1) { throw 'OneInstalledNmeApiApplicationRequired' }
    $resource = $applications[0]
    $roles = @($resource.appRoles | Where-Object { $_.value -eq 'RestClient' -and $_.isEnabled -eq $true -and 'Application' -in $_.allowedMemberTypes })
    if ($roles.Count -ne 1 -or $resource.api.requestedAccessTokenVersion -ne 2 -or ('api://' + $resource.appId) -notin @($resource.identifierUris)) { throw 'ReviewedNmeApiRoleAudienceAndVersionRequired' }
    $bindingText = @($settings.TARGET_TENANT_ID, $settings.TARGET_SUBSCRIPTION_ID, $resource.appId, $roles[0].id, ($brand.name + ' NMe REST client')) -join "`n"
    if ([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($bindingText))) -cne $journal.bindingSha256) { throw 'ApiClientTargetBindingChanged' }
    $installation = Get-Content -LiteralPath (Join-Path $RepositoryRoot 'private/nme/installation-plan.json') -Raw | ConvertFrom-Json -AsHashtable
    $baseUri = [uri]$installation.appUrl
    if ($installation.deploymentSucceeded -ne $true -or $baseUri.Scheme -cne 'https' -or $baseUri.Port -ne 443 -or $baseUri.Query -or $baseUri.Fragment -or $baseUri.UserInfo -or $baseUri.Host -notlike '*.azurewebsites.net') { throw 'ReviewedInstalledNmeHttpsOriginRequired' }
    $certificate = $result = $payload = $claims = $client = $null
    try {
        $certificate = Get-Item -LiteralPath ('Cert:\CurrentUser\My\' + $journal.certificateThumbprint) -ErrorAction Stop
        if (-not $certificate.HasPrivateKey -or $certificate.NotAfter.ToUniversalTime() -le [DateTime]::UtcNow.AddDays(7)) { throw 'OwnedValidCertificateRequired' }
        $assemblies = @([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GetName().Name -eq 'Microsoft.Identity.Client' -and $_.GetType('Microsoft.Identity.Client.ConfidentialClientApplicationBuilder', $false) })
        if (-not $assemblies.Count) { throw 'AlreadyInstalledNativeIdentityClientRequired' }
        $builderType = $assemblies[0].GetType('Microsoft.Identity.Client.ConfidentialClientApplicationBuilder', $true)
        $builder = $builderType.GetMethod('Create', [type[]]@([string])).Invoke($null, [object[]]@([string]$journal.clientId))
        $client = $builder.WithAuthority('https://login.microsoftonline.com/' + $settings.TARGET_TENANT_ID).WithCertificate($certificate).Build()
        try { $result = $client.AcquireTokenForClient([string[]]@('api://' + $resource.appId + '/.default')).ExecuteAsync().GetAwaiter().GetResult() } catch { throw 'NativeNmeCertificateAuthenticationStoppedNoRawError' }
        if ([string]::IsNullOrWhiteSpace($result.AccessToken)) { throw 'ProtectedNmeTokenRequired' }
        $payload = $result.AccessToken.Split('.')[1].Replace('-', '+').Replace('_', '/')
        $payload = $payload.PadRight($payload.Length + (4 - $payload.Length % 4) % 4, '=')
        $claims = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload)) | ConvertFrom-Json -AsHashtable
        Assert-LeafNmeRestTokenClaims $claims $settings.TARGET_TENANT_ID $journal.clientId $resource.appId
        return [pscustomobject]@{ BaseUri = $baseUri; AccessToken = [Net.NetworkCredential]::new('', $result.AccessToken).SecurePassword; ExpiresUtc = $result.ExpiresOn; TenantClientAudienceAndRoleVerified = $true; ResourceAppId = $resource.appId; TargetClientBindingSha256 = $journal.bindingSha256 }
    } finally {
        $claims = $payload = $result = $client = $null
        if ($certificate) { $certificate.Dispose() }
    }
}

function Invoke-LeafNmeRestRead {
    param([Parameter(Mandatory)]$Connection, [Parameter(Mandatory)][string]$Path)
    if ($Connection.TenantClientAudienceAndRoleVerified -ne $true -or $Connection.AccessToken -isnot [securestring] -or $Path -cnotin @('/swagger/v1/swagger.json', '/api/v1/workspace')) { throw 'ExplicitSupportedNmeReadRequired' }
    $uri = [uri]::new($Connection.BaseUri, $Path)
    if ($uri.Scheme -cne 'https' -or $uri.Host -cne $Connection.BaseUri.Host -or $uri.Port -ne 443) { throw 'VerifiedNmeReadOriginRequired' }
    try { $response = Invoke-WebRequest -Method GET -Uri $uri -Authentication Bearer -Token $Connection.AccessToken -MaximumRedirection 0 -SkipHttpErrorCheck -ErrorAction Stop } catch { throw 'NmeReadTransportStoppedNoRawResponse' }
    if ($response.StatusCode -ne 200 -or [Text.Encoding]::UTF8.GetByteCount($response.Content) -gt 8388608) { throw 'BoundedSuccessfulNmeReadRequired' }
    try { return ConvertFrom-Json -InputObject $response.Content -AsHashtable -Depth 80 -DateKind String -ErrorAction Stop } catch { throw 'NmeReadJsonRequiredNoRawBody' }
}

if ($CheckOnly) {
    $tenant = [guid]::NewGuid().ToString(); $client = [guid]::NewGuid().ToString(); $resource = [guid]::NewGuid().ToString()
    $claims = @{ tid = $tenant; azp = $client; aud = $resource; ver = '2.0'; roles = @('RestClient'); exp = [DateTimeOffset]::UtcNow.AddHours(1).ToUnixTimeSeconds() }
    Assert-LeafNmeRestTokenClaims $claims $tenant $client $resource
    foreach ($field in @('tid', 'azp', 'aud', 'ver', 'roles', 'exp')) {
        $changed = $claims.Clone(); $changed[$field] = if ($field -ceq 'roles') { @('RestClient', 'NON_CREDENTIAL_UNAPPROVED_ROLE') } elseif ($field -ceq 'exp') { $false } else { 'NON_CREDENTIAL_CHANGED_FIXTURE' }
        $rejected = $false; try { Assert-LeafNmeRestTokenClaims $changed $tenant $client $resource } catch { $rejected = $true }
        if (-not $rejected) { throw 'ChangedNmeTokenMetadataFixtureAccepted' }
    }
    $path = Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString('N') + '.json')
    try { Save-LeafNmeState @{ state = 'fixture' } $path; if ((Get-Content -LiteralPath $path -Raw | ConvertFrom-Json).state -cne 'fixture') { throw 'AtomicStateRoundTripFixtureFailed' } } finally { if ([IO.File]::Exists($path)) { [IO.File]::Delete($path) } }
    [pscustomobject]@{ Status = 'OfflineChecksPassed'; ChecksPassed = 8; CloudCalls = 0; CredentialReads = 0 }
}