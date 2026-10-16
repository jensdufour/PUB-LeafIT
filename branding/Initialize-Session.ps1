#requires -Version 7.6
[CmdletBinding()]
param([switch]$Apply, [switch]$Connect, [switch]$CheckOnly)

$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
. (Join-Path $repo 'identity/Target.ps1')
$definition = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'permissions.json') -Raw | ConvertFrom-Json -AsHashtable
$brand = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'brand.json') -Raw | ConvertFrom-Json

function Test-LeafNamingPermissionDefinition {
    param($Definition)
    $allowed = @{
        '00000003-0000-0000-c000-000000000000' = @('Organization.ReadWrite.All', 'Group.ReadWrite.All', 'Application.Read.All', 'Sites.ReadWrite.All', 'DeviceManagementServiceConfig.ReadWrite.All')
        '00000002-0000-0ff1-ce00-000000000000' = @('Exchange.ManageAsApp')
        '00000003-0000-0ff1-ce00-000000000000' = @('Sites.FullControl.All')
    }
    if ($Definition.schemaVersion -ne 1 -or $Definition.doesNotAuthorizeSecurityLicenseOrDeviceChanges -ne $true -or $Definition.certificateLifetimeMonths -ne 6) { throw 'The naming bootstrap definition is invalid.' }
    if (@($Definition.resources).Count -ne $allowed.Count) { throw 'The naming resource catalog is incomplete.' }
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($resource in $Definition.resources) {
        if (-not $allowed.ContainsKey($resource.appId) -or -not $seen.Add($resource.appId) -or (($resource.applicationPermissions | Sort-Object) -join '|') -cne (($allowed[$resource.appId] | Sort-Object) -join '|')) { throw 'An unreviewed or duplicate naming permission was requested.' }
    }
    if ((($Definition.directoryRoles | Sort-Object) -join '|') -cne ((@('Exchange Recipient Administrator', 'SharePoint Administrator') | Sort-Object) -join '|')) { throw 'Only the reviewed service roles are permitted.' }
}

function Get-LeafMissingAppRoles {
    param([object[]]$Desired, [object[]]$Current)
    return @($Desired | Where-Object { $desiredRole = $_; @($Current | Where-Object { $_.resourceId -eq $desiredRole.resourceId -and $_.appRoleId -eq $desiredRole.appRoleId }).Count -eq 0 })
}

function Set-LeafNamingPrivateInputs {
    param([string]$ClientId, [string]$Thumbprint, [string]$PreviousName)
    $path = Join-Path $repo '.env'
    $text = [IO.File]::ReadAllText($path)
    $before = $text
    $values = @{ TARGET_NAMING_CLIENT_ID = $ClientId; TARGET_NAMING_CERTIFICATE_THUMBPRINT = $Thumbprint }
    if (-not [string]::IsNullOrWhiteSpace($PreviousName)) { $values.TARGET_PREVIOUS_ORGANIZATION_NAME = $PreviousName }
    foreach ($key in $values.Keys) {
        $pattern = '(?m)^[\t ]*' + $key + '[\t ]*=[^\r\n]*'
        $entries = [regex]::Matches($text, $pattern)
        if ($entries.Count -gt 1) { throw 'A private naming input is duplicated.' }
        $line = $key + '=' + $values[$key]
        if ($entries.Count) { $text = [regex]::Replace($text, $pattern, [Text.RegularExpressions.MatchEvaluator]{ param($matchValue) $line }) } else { $text = $text.TrimEnd("`r", "`n") + [Environment]::NewLine + $line + [Environment]::NewLine }
    }
    $null = Read-LeafTargetSettings $text
    if ([IO.File]::ReadAllText($path) -cne $before) { throw 'Private inputs changed while naming credentials were being prepared.' }
    if ($text -cne $before) { [IO.File]::WriteAllText($path, $text, [Text.UTF8Encoding]::new($false)) }
}

function Connect-LeafNamingCertificateGraph {
    if (-not $settings.TARGET_NAMING_CLIENT_ID -or -not $settings.TARGET_NAMING_CERTIFICATE_THUMBPRINT) { throw 'Run the approved naming bootstrap before unattended connection.' }
    $existing = Get-MgContext
    if ($existing -and $existing.TenantId -ne $settings.TARGET_TENANT_ID) { throw 'An unrelated Graph context must not be switched.' }
    if ($existing) { $null = Disconnect-MgGraph -ErrorAction Stop }
    $null = Connect-MgGraph -ClientId $settings.TARGET_NAMING_CLIENT_ID -TenantId $settings.TARGET_TENANT_ID -CertificateThumbprint $settings.TARGET_NAMING_CERTIFICATE_THUMBPRINT -ContextScope Process -NoWelcome -ErrorAction Stop
    $organization = Invoke-LeafTargetGraph -Settings $settings -Path '/v1.0/organization?$select=id'
    if (@($organization.value).Count -ne 1 -or $organization.value[0].id -ne $settings.TARGET_TENANT_ID) { throw 'Certificate-authenticated target readback failed.' }
}

Test-LeafNamingPermissionDefinition $definition
if ($CheckOnly) {
    Test-LeafTargetGuards
    $desired = @([pscustomobject]@{ resourceId = 'resource'; appRoleId = 'role' })
    if (@(Get-LeafMissingAppRoles $desired @()).Count -ne 1 -or @(Get-LeafMissingAppRoles $desired $desired).Count) { throw 'App-role comparison must be idempotent.' }
    $invalid = $definition | ConvertTo-Json -Depth 10 | ConvertFrom-Json -AsHashtable
    $invalid.resources[0].applicationPermissions += 'Directory.ReadWrite.All'
    $rejected = $false
    try { Test-LeafNamingPermissionDefinition $invalid } catch { $rejected = $true }
    if (-not $rejected) { throw 'An unreviewed directory-wide permission was accepted.' }
    [pscustomobject]@{ OfflineChecksPassed = $true; DuplicateGrantsAvoided = $true; PermissionAllowlistEnforced = $true; TenantAccess = $false }
    return
}

$settings = Read-LeafPrivateTarget $repo
Assert-LeafTargetContext $settings (Get-AzContext)
$privateRoot = Join-Path $repo 'private/branding'
[void][IO.Directory]::CreateDirectory($privateRoot)
$report = [ordered]@{ TimeUtc = [DateTimeOffset]::UtcNow.ToString('o'); TargetVerified = $false; ApplyRequested = $Apply.IsPresent; Status = 'Started'; Stage = 'Preflight'; ApplicationCreated = $false; CertificateCreated = $false; AddedPermissions = @(); AddedDirectoryRoles = @(); Verified = $false }
$appName = $brand.name + $definition.applicationNameSuffix
$appDescription = 'Repository-managed naming automation; permissions and ownership are defined in branding/permissions.json.'

try {
    if ($Connect -and -not $Apply) { Connect-LeafNamingCertificateGraph } elseif ($Apply) { $null = Connect-LeafTargetGraph -Settings $settings -RefreshFromAzure } else { $null = Connect-LeafTargetGraph $settings }
    $report.TargetVerified = $true
    $escapedName = $appName.Replace("'", "''")
    $apps = @(Get-LeafTargetGraphCollection -Settings $settings -Path ("/v1.0/applications?`$filter=displayName eq '" + $escapedName + "'&`$select=id,appId,displayName,description,signInAudience"))
    if ($apps.Count -gt 1) { throw 'The dedicated naming app is ambiguous.' }
    if ($apps.Count -eq 1 -and ($apps[0].description -cne $appDescription -or $apps[0].signInAudience -cne 'AzureADMyOrg')) { throw 'An unrelated same-name app must not be adopted automatically.' }
    if ($settings.TARGET_NAMING_CLIENT_ID -and ($apps.Count -ne 1 -or $apps[0].appId -ne $settings.TARGET_NAMING_CLIENT_ID)) { throw 'The configured naming app does not match the uniquely resolved owned definition.' }
    if (-not $Apply -and -not $Connect) {
        $report.Status = 'Preview'
        [pscustomobject]@{ Mode = 'Preview'; DedicatedApplicationExists = $apps.Count -eq 1; CertificateConfigured = [bool]$settings.TARGET_NAMING_CERTIFICATE_THUMBPRINT; RequestedApplicationPermissions = @($definition.resources.applicationPermissions).Count; RequestedDirectoryRoles = $definition.directoryRoles; TenantWritesPerformed = $false }
        return
    }
    if ($Apply) {
        if (-not $IsWindows) { throw 'The native certificate bootstrap requires the Windows current-user certificate store.' }
        $report.Stage = 'Application'
        if (-not $apps.Count) {
            $app = Invoke-LeafTargetGraph -Settings $settings -Method POST -Path '/v1.0/applications' -Body @{ displayName = $appName; signInAudience = 'AzureADMyOrg'; description = $appDescription }
            if (-not $app.id -or -not $app.appId) { throw 'App creation was not confirmed. Re-read the app catalog before any retry.' }
            $report.ApplicationCreated = $true
        } else { $app = $apps[0] }
        $app = Invoke-LeafTargetGraph -Settings $settings -Path ('/v1.0/applications/' + $app.id + '?$select=id,appId,displayName,keyCredentials,requiredResourceAccess')
        $principals = @(Get-LeafTargetGraphCollection -Settings $settings -Path ("/v1.0/servicePrincipals?`$filter=appId eq '" + $app.appId + "'&`$select=id,appId,appOwnerOrganizationId"))
        if ($principals.Count -gt 1) { throw 'The naming service principal is ambiguous.' }
        $principal = if ($principals.Count) { $principals[0] } else { Invoke-LeafTargetGraph -Settings $settings -Method POST -Path '/v1.0/servicePrincipals' -Body @{ appId = $app.appId } }
        if (-not $principal.id -or $principal.appOwnerOrganizationId -ne $settings.TARGET_TENANT_ID) { throw 'The naming service principal is not owned by the target.' }
        $report.Stage = 'Certificate'
        $certificate = if ($settings.TARGET_NAMING_CERTIFICATE_THUMBPRINT) { Get-Item -LiteralPath ('Cert:/CurrentUser/My/' + $settings.TARGET_NAMING_CERTIFICATE_THUMBPRINT) -ErrorAction SilentlyContinue } else { $null }
        if (-not $certificate -or -not $certificate.HasPrivateKey -or $certificate.NotAfter -le [DateTime]::Now.AddDays(30)) {
            $createdCertificate = New-SelfSignedCertificate -Subject ('CN=' + $appName) -CertStoreLocation 'Cert:/CurrentUser/My' -NotAfter ([DateTime]::Now.AddMonths($definition.certificateLifetimeMonths)) -KeyAlgorithm RSA -KeyLength 2048 -KeySpec KeyExchange -KeyExportPolicy NonExportable -Provider 'Microsoft Enhanced RSA and AES Cryptographic Provider' -ErrorAction Stop
            $certificate = Get-Item -LiteralPath ('Cert:/CurrentUser/My/' + $createdCertificate.Thumbprint)
            $report.CertificateCreated = $true
            Set-LeafNamingPrivateInputs $app.appId $certificate.Thumbprint
            $settings = Read-LeafPrivateTarget $repo
        }
        if (-not $certificate.HasPrivateKey -or $certificate.NotAfter -le [DateTime]::Now.AddDays(7)) { throw 'The naming certificate is missing its private key or needs renewal.' }
        if (-not $settings.TARGET_PREVIOUS_ORGANIZATION_NAME) {
            $organizationBefore = Invoke-LeafTargetGraph -Settings $settings -Path '/v1.0/organization?$select=id,displayName'
            if (@($organizationBefore.value).Count -ne 1 -or $organizationBefore.value[0].id -ne $settings.TARGET_TENANT_ID -or [string]::IsNullOrWhiteSpace($organizationBefore.value[0].displayName)) { throw 'The source organization name could not be discovered safely.' }
            Set-LeafNamingPrivateInputs $app.appId $certificate.Thumbprint $organizationBefore.value[0].displayName
            $settings = Read-LeafPrivateTarget $repo
        }
        $identifier = [Convert]::ToBase64String($certificate.GetCertHash())
        if (@($app.keyCredentials | Where-Object customKeyIdentifier -EQ $identifier).Count -eq 0) {
            $keys = @($app.keyCredentials)
            if (@($keys | Where-Object { -not $_.key }).Count) { throw 'Existing public keys cannot be preserved from readback; do not replace the key collection.' }
            $keys += @{ type = 'AsymmetricX509Cert'; usage = 'Verify'; key = [Convert]::ToBase64String($certificate.RawData); customKeyIdentifier = $identifier; displayName = 'Repository-managed naming certificate'; startDateTime = $certificate.NotBefore.ToUniversalTime().ToString('o'); endDateTime = $certificate.NotAfter.ToUniversalTime().ToString('o') }
            $null = Invoke-LeafTargetGraph -Settings $settings -Method PATCH -Path ('/v1.0/applications/' + $app.id) -Body @{ keyCredentials = $keys }
        }
        $keyReadback = Invoke-LeafTargetGraph -Settings $settings -Path ('/v1.0/applications/' + $app.id + '?$select=id,keyCredentials')
        if (@($keyReadback.keyCredentials | Where-Object customKeyIdentifier -EQ $identifier).Count -ne 1) { throw 'The naming public-key readback is incomplete.' }
        $report.Stage = 'Permissions'
        $desiredRoles = @()
        $resources = @{}
        foreach ($resource in $definition.resources) {
            $resolved = @(Get-LeafTargetGraphCollection -Settings $settings -Path ("/v1.0/servicePrincipals?`$filter=appId eq '" + $resource.appId + "'&`$select=id,appId,appRoles"))
            if ($resolved.Count -ne 1) { throw 'A required first-party service principal is missing or ambiguous.' }
            $resources[$resource.appId] = $resolved[0]
            foreach ($value in $resource.applicationPermissions) {
                $role = @($resolved[0].appRoles | Where-Object { $_.value -ceq $value -and $_.isEnabled -and $_.allowedMemberTypes -contains 'Application' })
                if ($role.Count -ne 1) { throw 'A reviewed service application permission is unavailable.' }
                $desiredRoles += [pscustomobject]@{ resourceId = $resolved[0].id; appRoleId = $role[0].id; Permission = $value }
            }
        }
        $assignmentPath = '/v1.0/servicePrincipals/' + $principal.id + '/appRoleAssignments'
        $current = @(Get-LeafTargetGraphCollection -Settings $settings -Path $assignmentPath)
        foreach ($grant in @(Get-LeafMissingAppRoles $desiredRoles $current)) {
            $null = Invoke-LeafTargetGraph -Settings $settings -Method POST -Path $assignmentPath -Body @{ principalId = $principal.id; resourceId = $grant.resourceId; appRoleId = $grant.appRoleId }
            $report.AddedPermissions += $grant.Permission
        }
        $current = @(Get-LeafTargetGraphCollection -Settings $settings -Path $assignmentPath)
        if (@(Get-LeafMissingAppRoles $desiredRoles $current).Count) { throw 'Application-permission readback is incomplete.' }
        $report.Stage = 'ServiceRoles'
        foreach ($roleName in $definition.directoryRoles) {
            $roleDefinitions = @(Get-LeafTargetGraphCollection -Settings $settings -Path ("/v1.0/roleManagement/directory/roleDefinitions?`$filter=displayName eq '" + $roleName + "'&`$select=id,displayName"))
            if ($roleDefinitions.Count -ne 1) { throw 'A required service role is missing or ambiguous.' }
            $existingRoles = @(Get-LeafTargetGraphCollection -Settings $settings -Path ("/v1.0/roleManagement/directory/roleAssignments?`$filter=principalId eq '" + $principal.id + "'"))
            if (@($existingRoles | Where-Object { $_.roleDefinitionId -eq $roleDefinitions[0].id -and $_.directoryScopeId -eq '/' }).Count -eq 0) {
                $null = Invoke-LeafTargetGraph -Settings $settings -Method POST -Path '/v1.0/roleManagement/directory/roleAssignments' -Body @{ principalId = $principal.id; roleDefinitionId = $roleDefinitions[0].id; directoryScopeId = '/' }
                $report.AddedDirectoryRoles += $roleName
            }
            $roleReadback = @(Get-LeafTargetGraphCollection -Settings $settings -Path ("/v1.0/roleManagement/directory/roleAssignments?`$filter=principalId eq '" + $principal.id + "'"))
            if (@($roleReadback | Where-Object { $_.roleDefinitionId -eq $roleDefinitions[0].id -and $_.directoryScopeId -eq '/' }).Count -ne 1) { throw 'A service-role assignment was not confirmed by readback.' }
        }
        $report.Verified = $true
        $report.Status = if ($report.ApplicationCreated -or $report.CertificateCreated -or $report.AddedPermissions.Count -or $report.AddedDirectoryRoles.Count) { 'AppliedAndVerified' } else { 'NoChange' }
    }
    if ($Connect) {
        $settings = Read-LeafPrivateTarget $repo
        if ($Apply) { Connect-LeafNamingCertificateGraph }
        $report.Status = if ($Apply) { $report.Status } else { 'Connected' }
    }
    [pscustomobject]@{ Mode = if ($Apply) { 'Bootstrap' } else { 'Connect' }; Status = $report.Status; TargetVerified = $true; AddedApplicationPermissions = $report.AddedPermissions; AddedServiceRoles = $report.AddedDirectoryRoles; CertificatePrivateKeyExported = $false; SecurityLicenseOrDeviceChangesPerformed = $false }
} catch {
    $report.Status = 'StoppedInspectBeforeRetry'
    $report.FailureType = $_.Exception.GetType().Name
    $failure = [regex]::Match([string]$_.Exception.Message, 'HTTP (?<status>\d+); (?<code>[A-Za-z0-9_.-]+)')
    $report.HttpStatus = if ($failure.Success) { $failure.Groups['status'].Value } else { 'Unknown' }
    $report.ErrorCode = if ($failure.Success) { $failure.Groups['code'].Value } else { 'Unknown' }
    throw ('Naming bootstrap stopped at ' + $report.Stage + ' (HTTP ' + $report.HttpStatus + '; ' + $report.ErrorCode + '); inspect private status before retrying. Identifiers and credential details suppressed.')
} finally {
    [IO.File]::WriteAllText((Join-Path $privateRoot 'naming-session.json'), ($report | ConvertTo-Json -Depth 10), [Text.UTF8Encoding]::new($false))
}