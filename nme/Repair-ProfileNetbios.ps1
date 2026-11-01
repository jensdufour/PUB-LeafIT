#description: Correct only Azure Files AD NetBIOS metadata to the verified existing domain value.
#tags: ChatGPT, AzureFiles, ActiveDirectory
#execution mode: Individual
<#
Variables:
{
    "Operation": {
        "Description": "Preview or apply the approved one-field metadata correction.",
        "IsRequired": true,
        "DefaultValue": "Preview"
    },
    "ExpectedTenantId": {
        "Description": "Privately verified target tenant.",
        "IsRequired": true
    },
    "ExpectedSubscriptionId": {
        "Description": "Privately verified target subscription.",
        "IsRequired": true
    },
    "AccountId": {
        "Description": "Exact existing profile storage account resource ID.",
        "IsRequired": true
    },
    "ExpectedStorageSid": {
        "Description": "Verified existing AD storage computer SID.",
        "IsRequired": true
    },
    "ExpectedDomainSid": {
        "Description": "Verified existing AD domain SID.",
        "IsRequired": true
    },
    "BeforeNetbios": {
        "Description": "Existing storage metadata value; never rename the domain.",
        "IsRequired": true
    },
    "DesiredNetbios": {
        "Description": "Correct NetBIOS name read from the existing DCs.",
        "IsRequired": true
    },
    "PreviewStateSha256": {
        "Description": "Exact baseline hash returned by the approved Preview run.",
        "IsRequired": false
    }
}
#>

$ErrorActionPreference = 'Stop'
$VerbosePreference = $DebugPreference = $ProgressPreference = 'SilentlyContinue'

function ConvertFrom-LeafNmeJson {
    param([string]$Text)
    if ([Text.Encoding]::UTF8.GetByteCount($Text) -gt 1048576) { throw 'BoundedMetadataJsonRequired' }
    if ((Get-Command ConvertFrom-Json).Parameters.ContainsKey('AsHashtable')) { return ,(ConvertFrom-Json -InputObject $Text -AsHashtable -NoEnumerate) }
    Add-Type -AssemblyName System.Web.Extensions -ErrorAction Stop
    $serializer = New-Object System.Web.Script.Serialization.JavaScriptSerializer
    $serializer.MaxJsonLength = 1048576
    $serializer.RecursionLimit = 100
    return ,$serializer.DeserializeObject($Text)
}

function ConvertTo-LeafNmeCanonical {
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [Collections.IDictionary]) {
        $copy = [ordered]@{}
        foreach ($key in @($Value.Keys | Sort-Object -CaseSensitive)) { $copy[[string]$key] = ConvertTo-LeafNmeCanonical $Value[$key] }
        return $copy
    }
    if ($Value -is [array]) { return ,@($Value | ForEach-Object { ConvertTo-LeafNmeCanonical $_ }) }
    return $Value
}

function Get-LeafNmeStateHash {
    param($Snapshot)
    $text = ConvertTo-Json -InputObject (ConvertTo-LeafNmeCanonical $Snapshot) -Depth 32 -Compress -WarningAction Stop
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($text)))).Replace('-', '') } finally { $sha.Dispose() }
}

function Copy-LeafNmeMetadata {
    param($Value)
    return ,(ConvertFrom-LeafNmeJson (ConvertTo-Json -InputObject $Value -Depth 32 -Compress -WarningAction Stop))
}

function New-LeafNmeNetbiosBody {
    param($Authentication, [string]$Desired)
    if ($Authentication.directoryServiceOptions -cne 'AD' -or $Authentication.defaultSharePermission -cne 'None' -or $Authentication.activeDirectoryProperties.accountType -cne 'Computer' -or $Desired -cnotmatch '^[A-Za-z0-9][A-Za-z0-9-]{0,14}$') { throw 'ExactExistingAdComputerMetadataRequired' }
    $copy = Copy-LeafNmeMetadata $Authentication
    $copy.activeDirectoryProperties.netBiosDomainName = $Desired
    return @{ properties = @{ azureFilesIdentityBasedAuthentication = $copy } }
}

function Get-LeafNmeStableAccount {
    param($Account)
    $copy = Copy-LeafNmeMetadata $Account
    foreach ($field in @('etag', 'systemData')) { [void]$copy.Remove($field) }
    [void]$copy.properties.Remove('provisioningState')
    return $copy
}

function Invoke-LeafNmeMetadataRead {
    param([string]$Path)
    $reply = Invoke-AzRestMethod -Method GET -Path $Path -ErrorAction Stop
    if ($reply.StatusCode -ne 200 -or [Text.Encoding]::UTF8.GetByteCount($reply.Content) -gt 1048576) { throw 'BoundedMetadataReadRequired' }
    return ,(ConvertFrom-LeafNmeJson $reply.Content)
}

function Get-LeafNmeProfileState {
    $account = Invoke-LeafNmeMetadataRead ($AccountId + '?api-version=2025-01-01')
    $share = Invoke-LeafNmeMetadataRead ($AccountId + '/fileServices/default/shares/profiles?api-version=2025-01-01')
    $roles = Invoke-LeafNmeMetadataRead ($AccountId + '/fileServices/default/fileshares/profiles/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&$filter=atScope()')
    if ($roles.nextLink) { throw 'CompleteRoleBaselineRequired' }
    if ($account.id -ine $AccountId -or ($account.location -replace ' ', '').ToLowerInvariant() -cne 'swedencentral' -or $account.kind -cne 'FileStorage' -or $account.sku.name -cne 'PremiumV2_LRS' -or $account.properties.allowSharedKeyAccess -ne $false -or $account.properties.publicNetworkAccess -cne 'Disabled' -or $account.properties.minimumTlsVersion -cne 'TLS1_2' -or $account.properties.supportsHttpsTrafficOnly -ne $true -or $account.properties.networkAcls.defaultAction -cne 'Deny' -or $account.properties.networkAcls.bypass -cne 'None' -or $share.id -ine ($AccountId + '/fileServices/default/shares/profiles')) { throw 'ExactProtectedProfileStorageRequired' }
    return @{ account = Get-LeafNmeStableAccount $account; share = $share; roles = @($roles.value | Sort-Object id) }
}

function Test-LeafNmeNetbiosRepair {
    $source = [IO.File]::ReadAllText($PSCommandPath)
    $metadata = [regex]::Match($source, '(?s)<#\s*Variables:\s*(?<json>\{.*?\})\s*#>')
    if (-not $metadata.Success) { throw 'NmeAzureVariableMetadataRequired' }
    $variables = ConvertFrom-LeafNmeJson $metadata.Groups['json'].Value
    if ($variables.Count -ne 9 -or $variables.Operation.DefaultValue -cne 'Preview' -or @($variables.Keys | Where-Object { $_ -cnotmatch '^[A-Za-z0-9_]{1,30}$' }).Count) { throw 'NmeAzureVariableContractRejected' }
    foreach ($variable in $variables.Values) { if ($variable.Keys -contains 'Type' -or $variable.Keys -notcontains 'Description' -or $variable.Keys -notcontains 'IsRequired') { throw 'NmeAzureVariableMetadataRejected' } }
    $auth = @{ directoryServiceOptions = 'AD'; defaultSharePermission = 'None'; activeDirectoryProperties = @{ accountType = 'Computer'; netBiosDomainName = 'OLD'; domainName = 'example.invalid'; domainSid = 'S-1-5-21-1-2-3'; azureStorageSid = 'S-1-5-21-1-2-3-1000'; samAccountName = 'fixture$' } }
    $body = New-LeafNmeNetbiosBody $auth 'NEW'
    if ($body.Keys.Count -ne 1 -or $body.properties.Keys.Count -ne 1 -or $auth.activeDirectoryProperties.netBiosDomainName -cne 'OLD' -or $body.properties.azureFilesIdentityBasedAuthentication.activeDirectoryProperties.netBiosDomainName -cne 'NEW') { throw 'SingleFieldCloneFixtureFailed' }
    $normalized = Copy-LeafNmeMetadata $body.properties.azureFilesIdentityBasedAuthentication
    $normalized.activeDirectoryProperties.netBiosDomainName = 'OLD'
    if ((Get-LeafNmeStateHash $normalized) -cne (Get-LeafNmeStateHash $auth)) { throw 'OtherAdMetadataChanged' }
    $checks = 3
    foreach ($field in @('domainSid', 'azureStorageSid', 'samAccountName', 'accountType')) {
        $changed = Copy-LeafNmeMetadata $normalized; $changed.activeDirectoryProperties[$field] = 'NON_SECRET_CHANGED_FIXTURE'
        if ((Get-LeafNmeStateHash $changed) -ceq (Get-LeafNmeStateHash $auth)) { throw 'ChangedIdentityFixtureAccepted' }; $checks++
    }
    $left = @{ beta = 2; alpha = @(@{ value = 1 }) }; $right = @{ alpha = @(@{ value = 1 }); beta = 2 }
    if ((Get-LeafNmeStateHash $left) -cne (Get-LeafNmeStateHash $right)) { throw 'CanonicalHashFixtureFailed' }; $checks++
    $Operation = 'Preview'
    $ExpectedTenantId = '00000000-0000-0000-0000-000000000001'
    $ExpectedSubscriptionId = '00000000-0000-0000-0000-000000000002'
    $AccountId = '/subscriptions/' + $ExpectedSubscriptionId + '/resourceGroups/rg-fixture/providers/Microsoft.Storage/storageAccounts/fixtureprofile'
    $ExpectedStorageSid = $auth.activeDirectoryProperties.azureStorageSid
    $ExpectedDomainSid = $auth.activeDirectoryProperties.domainSid
    $BeforeNetbios = 'OLD'; $DesiredNetbios = 'NEW'
    $fixtureAccount = @{ id = $AccountId; location = 'swedencentral'; kind = 'FileStorage'; sku = @{ name = 'PremiumV2_LRS' }; properties = @{ azureFilesIdentityBasedAuthentication = $auth; allowSharedKeyAccess = $false; publicNetworkAccess = 'Disabled'; minimumTlsVersion = 'TLS1_2'; supportsHttpsTrafficOnly = $true; networkAcls = @{ defaultAction = 'Deny'; bypass = 'None' } } }
    $fixtureContext = @{ Tenant = @{ Id = $ExpectedTenantId }; Subscription = @{ Id = $ExpectedSubscriptionId }; Account = @{ Type = 'ServicePrincipal' }; Environment = @{ Name = 'AzureCloud'; ResourceManagerUrl = 'https://management.azure.com/' } }
    $reads = @{ count = 0 }
    function Get-AzContext { return $fixtureContext }
    function Invoke-AzRestMethod {
        param([string]$Method, [string]$Path)
        if ($Method -cne 'GET') { throw 'PreviewMutationRejected' }
        $value = switch ($Path) {
            ($AccountId + '?api-version=2025-01-01') { $fixtureAccount }
            ($AccountId + '/fileServices/default/shares/profiles?api-version=2025-01-01') { @{ id = $AccountId + '/fileServices/default/shares/profiles' } }
            ($AccountId + '/fileServices/default/fileshares/profiles/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&$filter=atScope()') { @{ value = @() } }
            default { throw 'UnselectedMetadataRouteRejected' }
        }
        $reads.count++
        return @{ StatusCode = 200; Content = ConvertTo-Json -InputObject $value -Depth 16 -Compress }
    }
    $nativeOutput = & ([scriptblock]::Create($source)) -TenantGroupName group-fixture -TenantName name-fixture
    $nativeResult = ConvertFrom-LeafNmeJson -Text $nativeOutput
    $expectedInputs = @{ ExpectedTenantId = $ExpectedTenantId; ExpectedSubscriptionId = $ExpectedSubscriptionId; AccountId = $AccountId; ExpectedStorageSid = $ExpectedStorageSid; ExpectedDomainSid = $ExpectedDomainSid; BeforeNetbios = $BeforeNetbios; DesiredNetbios = $DesiredNetbios }
    if ($nativeResult.Status -cne 'PreviewReady' -or $nativeResult.PatchRequests -ne 0 -or $nativeResult.FieldChanges -ne 1 -or $nativeResult.RuntimeInputsSha256 -cne (Get-LeafNmeStateHash $expectedInputs) -or $reads.count -ne 3) { throw 'NmeInheritedInputInvocationFailed' }; $checks++
    [pscustomobject]@{ Status = 'OfflineChecksPassed'; ChecksPassed = $checks; NmeInheritedInputInvocationVerified = $true; CloudActions = 0; CredentialReads = 0; DcNetbiosWrites = 0 }
}

if ('-CheckOnly' -in $args) { Test-LeafNmeNetbiosRepair; return }
$stage = 'ExactNmeContext'
$patchRequests = 0
$inputHash = $null
try {
    foreach ($name in @('Operation', 'ExpectedTenantId', 'ExpectedSubscriptionId', 'AccountId', 'ExpectedStorageSid', 'ExpectedDomainSid', 'BeforeNetbios', 'DesiredNetbios')) {
        $value = Get-Variable -Name $name -ValueOnly -ErrorAction Stop
        if ($value -isnot [string] -or [string]::IsNullOrWhiteSpace($value)) { throw 'ExplicitInheritedNmeInputsRequired' }
    }
    if ($Operation -cnotin @('Preview', 'Apply')) { throw 'ExplicitNmeOperationRequired' }
    $inputHash = Get-LeafNmeStateHash @{ ExpectedTenantId = $ExpectedTenantId; ExpectedSubscriptionId = $ExpectedSubscriptionId; AccountId = $AccountId; ExpectedStorageSid = $ExpectedStorageSid; ExpectedDomainSid = $ExpectedDomainSid; BeforeNetbios = $BeforeNetbios; DesiredNetbios = $DesiredNetbios }
    $context = Get-AzContext -ErrorAction Stop
    if (-not $context -or $context.Tenant.Id -ine $ExpectedTenantId -or $context.Subscription.Id -ine $ExpectedSubscriptionId -or $context.Account.Type -cne 'ServicePrincipal' -or $context.Environment.Name -cne 'AzureCloud' -or $context.Environment.ResourceManagerUrl -cne 'https://management.azure.com/') { throw 'ExistingNmeTargetContextRequired' }
    if ($AccountId -inotmatch ('^/subscriptions/' + [regex]::Escape($ExpectedSubscriptionId) + '/resourceGroups/[A-Za-z0-9._()-]+/providers/Microsoft.Storage/storageAccounts/[a-z0-9]{3,24}$') -or $ExpectedStorageSid -cnotmatch '^S-1-5-21-\d+-\d+-\d+-\d+$' -or $ExpectedDomainSid -cnotmatch '^S-1-5-21-\d+-\d+-\d+$' -or $DesiredNetbios -cnotmatch '^[A-Za-z0-9][A-Za-z0-9-]{0,14}$') { throw 'ExplicitVerifiedMetadataInputsRequired' }
    $stage = 'ProtectedStatePreview'
    $before = Get-LeafNmeProfileState
    $auth = $before.account.properties.azureFilesIdentityBasedAuthentication
    if ($auth.activeDirectoryProperties.azureStorageSid -cne $ExpectedStorageSid -or $auth.activeDirectoryProperties.domainSid -cne $ExpectedDomainSid) { throw 'ExistingAdComputerIdentityChanged' }
    $body = New-LeafNmeNetbiosBody $auth $DesiredNetbios
    $baseline = Copy-LeafNmeMetadata $before
    $baseline.account.properties.azureFilesIdentityBasedAuthentication.activeDirectoryProperties.netBiosDomainName = $BeforeNetbios
    $baselineHash = Get-LeafNmeStateHash $baseline
    if ($Operation -ceq 'Preview') {
        [pscustomobject]@{ Status = 'PreviewReady'; RuntimeInputsSha256 = $inputHash; PreviewStateSha256 = $baselineHash; FieldChanges = $(if ($auth.activeDirectoryProperties.netBiosDomainName -ieq $DesiredNetbios) { 0 } else { 1 }); DcNetbiosWrites = 0; PatchRequests = 0; CredentialReads = 0 } | ConvertTo-Json -Compress
        return
    }
    if ($PreviewStateSha256 -cnotmatch '^[A-F0-9]{64}$' -or $PreviewStateSha256 -cne $baselineHash) { throw 'ExactApprovedNmePreviewStateRequired' }
    if ($auth.activeDirectoryProperties.netBiosDomainName -ieq $DesiredNetbios) {
        [pscustomobject]@{ Status = 'NoChange'; RuntimeInputsSha256 = $inputHash; PatchRequests = 0; DcNetbiosWrites = 0; CredentialReads = 0 } | ConvertTo-Json -Compress
        return
    }
    if ($auth.activeDirectoryProperties.netBiosDomainName -cne $BeforeNetbios) { throw 'ExpectedExistingNetbiosMetadataChanged' }
    $stage = 'OneFieldMetadataPatch'
    $again = Get-LeafNmeProfileState
    if ((Get-LeafNmeStateHash $again) -cne (Get-LeafNmeStateHash $before)) { throw 'ConcurrentStorageChangeDoNotSubmit' }
    $patchRequests = 1
    $reply = Invoke-AzRestMethod -Method PATCH -Path ($AccountId + '?api-version=2025-01-01') -Payload (ConvertTo-Json -InputObject $body -Depth 16 -Compress -WarningAction Stop) -ErrorAction Stop
    if ($reply.StatusCode -ne 200) { throw 'MetadataSubmissionUnknownDoNotReplay' }
    $stage = 'FullPreservationReadback'
    $after = Get-LeafNmeProfileState
    if ($after.account.properties.azureFilesIdentityBasedAuthentication.activeDirectoryProperties.netBiosDomainName -ine $DesiredNetbios) { throw 'MetadataReadbackPendingDoNotReplay' }
    $normalized = Copy-LeafNmeMetadata $after
    $normalized.account.properties.azureFilesIdentityBasedAuthentication.activeDirectoryProperties.netBiosDomainName = $BeforeNetbios
    if ((Get-LeafNmeStateHash $normalized) -cne $baselineHash) { throw 'UnrelatedStorageOrRoleChangeDetected' }
    [pscustomobject]@{ Status = 'VerifiedOneFieldMetadataRepair'; RuntimeInputsSha256 = $inputHash; AccountShareRolesPreserved = $true; DefaultSharePermissionNone = $true; PatchRequests = 1; DcNetbiosWrites = 0; CredentialReads = 0; KeyOperations = 0 } | ConvertTo-Json -Compress
} catch {
    [pscustomobject]@{ Status = $(if ($patchRequests) { 'UncertainOutcomeDoNotReplay' } else { 'Stopped' }); RuntimeInputsSha256 = $inputHash; Stage = $stage; PatchRequests = $patchRequests; DcNetbiosWrites = 0; CredentialReads = 0; RawErrorReturned = $false } | ConvertTo-Json -Compress
    throw 'NmeNetbiosMetadataRepairStoppedInspectTaskBeforeAnyRetry'
} finally {
    $reply = $context = $null
}