#requires -Version 7.6
[CmdletBinding()]
param(
    [switch]$Connect,
    [switch]$Interactive,
    [switch]$UseAzureSession,
    [switch]$CheckOnly
)

$ErrorActionPreference = 'Stop'
if ($Interactive -and $UseAzureSession) { throw 'Choose explicit interactive authentication or reuse of the verified Azure session, not both.' }
$repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
. (Join-Path $repo 'identity/Target.ps1')

function Get-LeafExchangeConnection {
    param($Settings, [object[]]$Connections)
    foreach ($connection in $Connections) {
        if ($null -eq $connection -or $connection -is [array] -or -not $connection.PSObject.Properties['TenantID'] -or -not $connection.PSObject.Properties['State']) {
            throw 'An Exchange connection record is malformed; no target can be inferred.'
        }
    }
    $active = @($Connections | Where-Object State -eq 'Connected')
    if (@($active | Where-Object { $_.TenantID -ne $Settings.TARGET_TENANT_ID }).Count -gt 0) {
        throw 'An Exchange connection to a different tenant exists; no automatic switch or disconnect is permitted.'
    }
    if ($active.Count -gt 1) { throw 'Exchange target connection is ambiguous; retain one explicitly verified connection.' }
    if ($active.Count -eq 1) { return $active[0] }
    return $null
}

function Assert-LeafExchangeOrganization {
    param($Settings, $Organization, [object[]]$AcceptedDomains)
    if ($null -eq $Organization -or @($Organization).Count -ne 1) { throw 'Exchange organization readback is absent or ambiguous.' }
    $value = [string]$Organization.ExternalDirectoryOrganizationId
    $guidAvailable = -not [string]::IsNullOrWhiteSpace($value)
    if ($guidAvailable) {
        $parsed = [guid]::Empty
        if (-not [guid]::TryParse($value, [ref]$parsed) -or $parsed.ToString() -ne $Settings.TARGET_TENANT_ID) {
            throw 'The returned Exchange organization ID differs from the target; no fallback is permitted.'
        }
    }
    Assert-LeafExchangeAcceptedDomain $Settings $AcceptedDomains
    return [pscustomobject]@{ OrganizationGuidReturned = $guidAvailable; AuthoritativeAcceptedDomainVerified = $true }
}

function Assert-LeafExchangeAcceptedDomain {
    param($Settings, [object[]]$AcceptedDomains)
    $acceptedMatches = @($AcceptedDomains | Where-Object { $_.DomainName.ToString() -ieq $Settings.TARGET_DNS_ZONE_NAME -and $_.DomainType.ToString() -eq 'Authoritative' })
    if ($acceptedMatches.Count -ne 1) { throw 'The expected authoritative accepted domain is absent or ambiguous in Exchange.' }
}

function Get-LeafExchangeAuthenticationMode {
    param($Settings, [bool]$InteractiveRequested, [bool]$AzureSessionRequested)
    if ($InteractiveRequested) { return 'NativeExchangeEdgeBetaDeviceSignIn' }
    if ($AzureSessionRequested) { return 'AzureSessionExchangeAccessToken' }
    if ($Settings.TARGET_NAMING_CLIENT_ID -and $Settings.TARGET_NAMING_CERTIFICATE_THUMBPRINT) { return 'NamingCertificate' }
    return 'ExplicitAuthenticationRequired'
}

function Assert-LeafExchangeAccessToken {
    param($Settings, $Token)
    if (-not $Token -or $Token.TenantId -ne $Settings.TARGET_TENANT_ID -or $Token.Token -isnot [securestring] -or [DateTimeOffset]$Token.ExpiresOn -le [DateTimeOffset]::UtcNow.AddMinutes(2)) {
        throw 'A current secure Exchange access token for the verified target is required.'
    }
}

function Get-LeafEdgeBetaExecutable {
    if (-not $IsWindows) { throw 'The selected Edge Beta sign-in path requires Windows.' }
    $candidates = @(
        (Join-Path ${env:ProgramFiles(x86)} 'Microsoft/Edge Beta/Application/msedge.exe'),
        (Join-Path $env:ProgramFiles 'Microsoft/Edge Beta/Application/msedge.exe'),
        (Join-Path $env:LOCALAPPDATA 'Microsoft/Edge Beta/Application/msedge.exe')
    )
    $installed = @($candidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf })
    if ($installed.Count -eq 0) { throw 'Microsoft Edge Beta is required for the selected tenant sign-in; no default-browser fallback is permitted.' }
    return $installed[0]
}

if ($CheckOnly) {
    Test-LeafTargetGuards
    $settings = @{ TARGET_TENANT_ID = [guid]::NewGuid().ToString(); TARGET_DNS_ZONE_NAME = 'example.com' }
    $namingFixture = $settings.Clone()
    $namingFixture.TARGET_NAMING_CLIENT_ID = [guid]::NewGuid().ToString()
    $namingFixture.TARGET_NAMING_CERTIFICATE_THUMBPRINT = 'A' * 40
    if ((Get-LeafExchangeAuthenticationMode $settings $false $false) -cne 'ExplicitAuthenticationRequired' -or (Get-LeafExchangeAuthenticationMode $namingFixture $false $false) -cne 'NamingCertificate' -or (Get-LeafExchangeAuthenticationMode $namingFixture $true $false) -cne 'NativeExchangeEdgeBetaDeviceSignIn') { throw 'Native Exchange authentication routing is invalid.' }
    $token = [pscustomobject]@{ TenantId = $settings.TARGET_TENANT_ID; Token = ConvertTo-SecureString 'synthetic-not-a-token' -AsPlainText -Force; ExpiresOn = [DateTimeOffset]::UtcNow.AddMinutes(30) }
    Assert-LeafExchangeAccessToken $settings $token
    foreach ($invalidToken in @(
        [pscustomobject]@{ TenantId = [guid]::NewGuid().ToString(); Token = $token.Token; ExpiresOn = $token.ExpiresOn },
        [pscustomobject]@{ TenantId = $token.TenantId; Token = $token.Token; ExpiresOn = [DateTimeOffset]::UtcNow.AddMinutes(-1) },
        [pscustomobject]@{ TenantId = $token.TenantId; Token = 'not-secure'; ExpiresOn = $token.ExpiresOn }
    )) {
        $rejected = $false
        try { Assert-LeafExchangeAccessToken $settings $invalidToken } catch { $rejected = $true }
        if (-not $rejected) { throw 'An unsafe Exchange access-token fixture was accepted.' }
    }
    if ($null -ne (Get-LeafExchangeConnection $settings @())) { throw 'An absent connection must not be treated as authenticated.' }
    $fixture = [pscustomobject]@{ State = 'Connected'; TenantID = $settings.TARGET_TENANT_ID }
    if (-not (Get-LeafExchangeConnection $settings @($fixture))) { throw 'A matching target connection was rejected.' }
    $invalidCases = @(
        @{ Connections = @($fixture, $fixture) },
        @{ Connections = @([pscustomobject]@{ State = 'Connected'; TenantID = [guid]::NewGuid().ToString() }) }
    )
    foreach ($case in $invalidCases) {
        $rejected = $false
        try { $null = Get-LeafExchangeConnection $settings $case.Connections } catch { $rejected = $true }
        if (-not $rejected) { throw 'An ambiguous or wrong-tenant Exchange connection was accepted.' }
    }
    $accepted = [pscustomobject]@{ DomainName = 'example.com'; DomainType = 'Authoritative' }
    Assert-LeafExchangeAcceptedDomain $settings @($accepted)
    $organization = [pscustomobject]@{ ExternalDirectoryOrganizationId = $settings.TARGET_TENANT_ID }
    $null = Assert-LeafExchangeOrganization $settings $organization @($accepted)
    $withoutGuid = Assert-LeafExchangeOrganization $settings ([pscustomobject]@{ Name = 'Synthetic organization' }) @($accepted)
    if ($withoutGuid.OrganizationGuidReturned -or -not $withoutGuid.AuthoritativeAcceptedDomainVerified) { throw 'Missing optional organization GUID must require authoritative domain readback.' }
    foreach ($invalid in @(
        @{ Organization = [pscustomobject]@{ ExternalDirectoryOrganizationId = [guid]::NewGuid().ToString() }; Domains = @($accepted) },
        @{ Organization = [pscustomobject]@{ ExternalDirectoryOrganizationId = 'invalid' }; Domains = @($accepted) },
        @{ Organization = $organization; Domains = @() },
        @{ Organization = $organization; Domains = @($accepted, $accepted) },
        @{ Organization = $organization; Domains = @([pscustomobject]@{ DomainName = 'other.example.com'; DomainType = 'Authoritative' }) }
    )) {
        $rejected = $false
        try { $null = Assert-LeafExchangeOrganization $settings $invalid.Organization $invalid.Domains } catch { $rejected = $true }
        if (-not $rejected) { throw 'Wrong or unverified Exchange organization state was accepted.' }
    }
    [pscustomobject]@{ OfflineConnectionChecksPassed = $true; InteractiveBrowser = 'Microsoft Edge Beta'; TenantAccess = $false }
    return
}

$settings = Read-LeafPrivateTarget $repo
Import-Module Az.Accounts -MinimumVersion 5.3.3 -ErrorAction Stop
Import-Module ExchangeOnlineManagement -MinimumVersion 3.9.2 -ErrorAction Stop
$context = Get-AzContext
Assert-LeafTargetContext $settings $context
$connection = Get-LeafExchangeConnection $settings @(Get-ConnectionInformation)
if (-not $Connect) {
    [pscustomobject]@{ Mode = 'Preview'; TargetAzureContextVerified = $true; TargetExchangeConnected = [bool]$connection; NativeExchangeSignInRequired = -not [bool]$connection; TenantChanged = $false }
    return
}

$created = $false
$authentication = 'ExistingVerifiedExchangeConnection'
$stage = 'ExistingConnection'
try {
    if (-not $connection) {
        $mode = Get-LeafExchangeAuthenticationMode $settings $Interactive.IsPresent $UseAzureSession.IsPresent
        if ($mode -ne 'NamingCertificate' -and $context.Account.Type -ne 'User') { throw 'This authentication mode requires an explicitly authenticated target user.' }
        $stage = 'NativeExchangeSignInRequired'
        if ($mode -eq 'NamingCertificate') {
            $stage = 'NamingCertificate'
            $certificate = Get-Item -LiteralPath ('Cert:/CurrentUser/My/' + $settings.TARGET_NAMING_CERTIFICATE_THUMBPRINT) -ErrorAction Stop
            if (-not $certificate.HasPrivateKey -or $certificate.NotAfter -le [DateTime]::Now.AddMinutes(5)) { throw 'The naming certificate is unavailable or expired.' }
            $graphSession = Connect-LeafTargetGraph $settings
            try {
                $organization = Invoke-LeafTargetGraph -Settings $settings -Path '/v1.0/organization?$select=id,verifiedDomains'
                if (@($organization.value).Count -ne 1 -or $organization.value[0].id -ne $settings.TARGET_TENANT_ID) { throw 'The naming certificate tenant is not verified.' }
                $initial = @($organization.value[0].verifiedDomains | Where-Object { $_.isInitial -and $_.name.EndsWith('.onmicrosoft.com', [StringComparison]::OrdinalIgnoreCase) })
                if ($initial.Count -ne 1) { throw 'The native Exchange organization domain is missing or ambiguous.' }
                $null = Connect-ExchangeOnline -AppId $settings.TARGET_NAMING_CLIENT_ID -CertificateThumbprint $settings.TARGET_NAMING_CERTIFICATE_THUMBPRINT -Organization $initial[0].name -ShowBanner:$false -ErrorAction Stop
            } finally { Disconnect-LeafTargetGraph $graphSession }
            $authentication = 'NamingCertificate'
        } elseif ($UseAzureSession) {
            $stage = 'AzureSessionExchangeAccessToken'
            $token = Get-AzAccessToken -ResourceUrl 'https://outlook.office365.com/' -TenantId $settings.TARGET_TENANT_ID -DefaultProfile $context -ErrorAction Stop
            Assert-LeafExchangeAccessToken $settings $token
            $tokenText = $null
            try {
                $tokenText = [Net.NetworkCredential]::new('', $token.Token).Password
                $null = Connect-ExchangeOnline -AccessToken $tokenText -UserPrincipalName $context.Account.Id -ShowBanner:$false -ErrorAction Stop
            } finally {
                $tokenText = $null
                $token = $null
            }
            $authentication = 'AzureSessionExchangeAccessToken'
        } elseif ($Interactive) {
            $stage = 'NativeExchangeEdgeBetaDeviceSignIn'
            $browser = Get-LeafEdgeBetaExecutable
            $null = Start-Process -FilePath $browser -ArgumentList @('--new-window', 'https://microsoft.com/devicelogin') -ErrorAction Stop
            $null = Connect-ExchangeOnline -Device -UserPrincipalName $context.Account.Id -ShowBanner:$false -ErrorAction Stop
            $authentication = 'NativeExchangeEdgeBetaDeviceSignIn'
        } else {
            throw 'Choose -Connect -UseAzureSession for explicit token reuse or -Connect -Interactive for native device sign-in. No passwords or device codes belong in chat.'
        }
        $created = $true
        $stage = 'VerifyConnection'
        $connection = Get-LeafExchangeConnection $settings @(Get-ConnectionInformation)
        if (-not $connection) { throw 'The Exchange target connection was not confirmed.' }
    }
    $stage = 'ReadAcceptedDomain'
    $acceptedDomains = @(Get-AcceptedDomain -ErrorAction Stop)
    Assert-LeafExchangeAcceptedDomain $settings $acceptedDomains
    $stage = 'ReadOrganization'
    $organizationRead = $false
    try { $organization = Get-OrganizationConfig -ErrorAction Stop; $organizationRead = $true } catch {
        $namingConnection = $authentication -eq 'NamingCertificate' -or ($settings.TARGET_NAMING_CLIENT_ID -and $connection.AppId -eq $settings.TARGET_NAMING_CLIENT_ID)
        if (-not $namingConnection) { throw }
    }
    $organizationProof = if ($organizationRead) {
        Assert-LeafExchangeOrganization $settings $organization $acceptedDomains
    } else {
        if ($connection.TenantID -ne $settings.TARGET_TENANT_ID) { throw 'Native Exchange connection metadata no longer matches the target.' }
        [pscustomobject]@{ OrganizationGuidReturned = $false; AuthoritativeAcceptedDomainVerified = $true }
    }
    $privateRoot = Join-Path $repo 'private/collaboration'
    [void][IO.Directory]::CreateDirectory($privateRoot)
    $evidence = [ordered]@{ TimeUtc = [DateTimeOffset]::UtcNow.ToString('o'); TargetVerified = $true; ConnectionCreated = $created; Authentication = $authentication; OrganizationReadbackVerified = $true; OrganizationConfigReadSucceeded = $organizationRead; VerificationMethod = if ($organizationRead) { 'NativeOrganizationAndAcceptedDomain' } else { 'NativeConnectionTenantAndAcceptedDomain' }; OrganizationGuidReturned = $organizationProof.OrganizationGuidReturned; AuthoritativeAcceptedDomainVerified = $organizationProof.AuthoritativeAcceptedDomainVerified; TenantSettingsChanged = $false }
    [IO.File]::WriteAllText((Join-Path $privateRoot 'exchange-session.json'), ($evidence | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
    [pscustomobject]@{ TargetExchangeConnected = $true; ConnectionCreated = $created; OrganizationReadbackVerified = $true; PermissionOrRoleAssignmentCmdletsUsed = $false; TenantSettingsChanged = $false }
} catch {
    $failureType = $_.Exception.GetType().Name
    $detail = [string]$_.Exception.Message
    foreach ($value in $settings.Values) { $detail = $detail.Replace([string]$value, '<target>') }
    $detail = $detail -replace '(?i)[a-z0-9_-]{20,}\.[a-z0-9_-]{20,}\.[a-z0-9_-]{10,}', '<token>' -replace '(?i)[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', '<id>' -replace '(?i)[a-z0-9._%+-]+@[a-z0-9.-]+', '<account>' -replace '(?i)[a-z0-9-]+\.onmicrosoft\.com', '<initial-domain>'
    if ($detail.Length -gt 500) { $detail = $detail.Substring(0, 500) }
    $privateRoot = Join-Path $repo 'private/collaboration'
    [void][IO.Directory]::CreateDirectory($privateRoot)
    $failure = [ordered]@{ TimeUtc = [DateTimeOffset]::UtcNow.ToString('o'); Stage = $stage; FailureType = $failureType; SanitizedDetail = $detail; TenantSettingsChanged = $false; ConsentGranted = $false }
    [IO.File]::WriteAllText((Join-Path $privateRoot 'exchange-session-failure.json'), ($failure | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
    if ($created) { $null = Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue }
    throw "Exchange target connection stopped at $stage ($failureType): $detail. No tenant settings or consent changed."
}