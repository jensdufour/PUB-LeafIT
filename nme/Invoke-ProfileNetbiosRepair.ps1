#requires -Version 7.6
[CmdletBinding(PositionalBinding = $false)]
param([ValidateSet('Prepare', 'UpdateSource', 'Preview', 'Apply', 'Readback')][string]$Mode = 'Prepare', [ValidateSet('Preview', 'Apply')][string]$ReadOperation = 'Preview', [switch]$OperatorApproved, [switch]$CheckOnly)

$ErrorActionPreference = $WarningPreference = 'Stop'
$VerbosePreference = $DebugPreference = $ProgressPreference = 'SilentlyContinue'
$repo = Split-Path $PSScriptRoot -Parent
$prefix = 'private/avd/profile-nme-netbios-execution'

function Get-LeafNetbiosExecutionHash {
    param([string]$Text)
    return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes(($Text -replace '\r\n', "`n"))))
}

function Get-LeafNetbiosInputHash {
    param($Inputs)
    $sorted = [ordered]@{}
    foreach ($key in $Inputs.Keys | Sort-Object -CaseSensitive) { $sorted[$key] = $Inputs[$key] }
    return Get-LeafNetbiosExecutionHash (ConvertTo-Json -InputObject $sorted -Compress)
}

function New-LeafNetbiosRunBody {
    param($Inputs, [string]$Operation, [string]$PreviewHash)
    $required = @('ExpectedTenantId', 'ExpectedSubscriptionId', 'AccountId', 'ExpectedStorageSid', 'ExpectedDomainSid', 'BeforeNetbios', 'DesiredNetbios')
    if ($Operation -cnotin @('Preview', 'Apply') -or $Inputs.Count -ne $required.Count) { throw 'ExactNetbiosExecutionInputsRequired' }
    $bindings = [ordered]@{ Operation = @{ value = $Operation; isSecure = $false } }
    foreach ($name in $required) {
        if ($Inputs[$name] -isnot [string] -or [string]::IsNullOrWhiteSpace($Inputs[$name])) { throw 'ExplicitPrivateRuntimeInputRequired' }
        $bindings[$name] = @{ value = $Inputs[$name]; isSecure = $false }
    }
    if ($Operation -ceq 'Apply') {
        if ($PreviewHash -cnotmatch '^[A-F0-9]{64}$') { throw 'VerifiedNmePreviewHashRequired' }
        $bindings.PreviewStateSha256 = @{ value = $PreviewHash; isSecure = $false }
    } elseif ($PreviewHash) { throw 'PreviewMustNotCarryApplyHash' }
    return [ordered]@{ subscriptionId = $Inputs.ExpectedSubscriptionId; minutesToWait = 30; paramsBindings = $bindings }
}

function Invoke-LeafNetbiosRunApi {
    param($Connection, [string]$Method, [int]$Id, $Body)
    if ($Id -lt 1 -or $Method -cnotin @('GET', 'POST', 'PATCH') -or $Connection.TenantClientAudienceAndRoleVerified -cne $true -or $Connection.AccessToken -isnot [securestring] -or $Connection.ExpiresUtc -le [DateTimeOffset]::UtcNow.AddMinutes(2)) { throw 'OwnedNmeExecutionRouteRequired' }
    $path = if ($Method -ceq 'POST') { '/api/v1/scripted-actions/' + $Id + '/execution' } elseif ($Method -ceq 'PATCH') { '/api/v1/scripted-actions/' + $Id } else { '/api/v1/job/' + $Id }
    $uri = [uri]::new($Connection.BaseUri, $path)
    if ($uri.Scheme -cne 'https' -or $uri.Host -cne $Connection.BaseUri.Host -or $uri.Port -ne 443) { throw 'ExactNmeExecutionOriginRequired' }
    $request = @{ Method = $Method; Uri = $uri; Authentication = 'Bearer'; Token = $Connection.AccessToken; MaximumRedirection = 0; SkipHttpErrorCheck = $true; ErrorAction = 'Stop' }
    if ($Method -ceq 'PATCH' -and ($Body -isnot [Collections.IDictionary] -or $Body.Count -ne 1 -or $Body.script -isnot [string] -or [Text.Encoding]::UTF8.GetByteCount($Body.script) -gt 32768)) { throw 'SourceOnlyOwnedActionUpdateRequired' }
    if ($Method -cin @('POST', 'PATCH')) { $request.ContentType = 'application/json'; $request.Body = ConvertTo-Json -InputObject $Body -Depth 5 -Compress -WarningAction Stop }
    try { $response = Invoke-WebRequest @request } catch { throw 'NmeExecutionTransportUncertainDoNotReplay' }
    if ($response.StatusCode -ne 200 -or [Text.Encoding]::UTF8.GetByteCount($response.Content) -gt 65536) { throw 'NmeExecutionResponseUncertainDoNotReplay' }
    $document = ConvertFrom-Json -InputObject $response.Content -AsHashtable -DateKind String
    if ($Method -ceq 'PATCH') {
        if (($document.job.id -isnot [int] -and $document.job.id -isnot [long]) -or $document.job.id -le 0) { throw 'OwnedSourceUpdateJobRequired' }
        return $document
    }
    $job = $document
    if (($job.id -isnot [int] -and $job.id -isnot [long]) -or $job.id -le 0 -or $job.jobStatus -cnotin @('Pending', 'Running', 'Completed', 'Failed', 'Cancelled') -or ($Method -ceq 'GET' -and $job.id -ne $Id)) { throw 'ExactOwnedNmeJobRequired' }
    return $job
}

if ($CheckOnly) {
    $inputs = @{ ExpectedTenantId = '00000000-0000-0000-0000-000000000001'; ExpectedSubscriptionId = '00000000-0000-0000-0000-000000000002'; AccountId = 'NON_CREDENTIAL_ACCOUNT_FIXTURE'; ExpectedStorageSid = 'NON_CREDENTIAL_STORAGE_SID_FIXTURE'; ExpectedDomainSid = 'NON_CREDENTIAL_DOMAIN_SID_FIXTURE'; BeforeNetbios = 'OLD'; DesiredNetbios = 'NEW' }
    $body = New-LeafNetbiosRunBody $inputs 'Preview'
    if ($body.paramsBindings.Count -ne 8 -or $body.paramsBindings.Operation.value -cne 'Preview' -or $body.Contains('adConfigId')) { throw 'PreviewBodyFixtureFailed' }
    $checks = 1
    $hash = 'A' * 64
    $apply = New-LeafNetbiosRunBody $inputs 'Apply' $hash
    if ($apply.paramsBindings.Count -ne 9 -or $apply.paramsBindings.PreviewStateSha256.value -cne $hash) { throw 'ApplyBodyFixtureFailed' }; $checks++
    foreach ($variant in @('MissingInput', 'ExtraInput', 'InvalidOperation', 'MissingHash', 'PreviewHash')) {
        $changed = $inputs.Clone(); $operation = 'Apply'; $previewHash = $hash
        switch ($variant) {
            MissingInput { [void]$changed.Remove('AccountId') }
            ExtraInput { $changed.Extra = 'NON_CREDENTIAL_EXTRA_FIXTURE' }
            InvalidOperation { $operation = 'Other' }
            MissingHash { $previewHash = '' }
            PreviewHash { $operation = 'Preview' }
        }
        $rejected = $false
        try { $null = New-LeafNetbiosRunBody $changed $operation $previewHash } catch { $rejected = $true }
        if (-not $rejected) { throw 'InvalidExecutionBodyAccepted' }; $checks++
    }
    $orderedInputs = [ordered]@{}
    foreach ($key in $inputs.Keys | Sort-Object -Descending) { $orderedInputs[$key] = $inputs[$key] }
    if ((Get-LeafNetbiosInputHash $inputs) -cne (Get-LeafNetbiosInputHash $orderedInputs)) { throw 'CanonicalRuntimeInputHashFixtureFailed' }; $checks++
    $calls = @{ count = 0 }
    function Invoke-WebRequest {
        param($Method, $Uri, $Authentication, $Token, $MaximumRedirection, $SkipHttpErrorCheck, $ErrorAction, $ContentType, $Body)
        if ($Authentication -cne 'Bearer' -or $Token -isnot [securestring] -or $MaximumRedirection -ne 0 -or $SkipHttpErrorCheck -ne $true) { throw 'ProtectedExecutionTransportFixtureFailed' }
        if (($Method -ceq 'POST' -and $Uri.AbsolutePath -cne '/api/v1/scripted-actions/1/execution') -or ($Method -ceq 'GET' -and $Uri.AbsolutePath -cne '/api/v1/job/1') -or ($Method -ceq 'PATCH' -and $Uri.AbsolutePath -cne '/api/v1/scripted-actions/1')) { throw 'ExactExecutionRouteFixtureFailed' }
        $calls.count++
        return @{ StatusCode = 200; Content = $(if ($Method -ceq 'PATCH') { '{"job":{"id":1},"payload":null}' } else { '{"id":1,"jobStatus":"Completed"}' }) }
    }
    $connection = @{ BaseUri = [uri]'https://fixture.azurewebsites.net/'; TenantClientAudienceAndRoleVerified = $true; AccessToken = ConvertTo-SecureString 'NON_CREDENTIAL_OPAQUE_FIXTURE' -AsPlainText -Force; ExpiresUtc = [DateTimeOffset]::UtcNow.AddHours(1) }
    try {
        $null = Invoke-LeafNetbiosRunApi $connection 'POST' 1 $body
        $null = Invoke-LeafNetbiosRunApi $connection 'GET' 1
        if ($calls.count -ne 2) { throw 'ActualExecutionTransportFixtureFailed' }; $checks++
        $updated = Invoke-LeafNetbiosRunApi $connection 'PATCH' 1 @{ script = '# NON_CREDENTIAL_PUBLIC_SOURCE_FIXTURE' }
        if ($updated.job.id -ne 1 -or $calls.count -ne 3) { throw 'SourceOnlyUpdateFixtureFailed' }; $checks++
    } finally { $connection.AccessToken.Dispose() }
    [pscustomobject]@{ Status = 'OfflineChecksPassed'; ChecksPassed = $checks; ActualMockedTransportVerified = $true; CloudActions = 0; CredentialReads = 0; DcNetbiosWrites = 0 }
    return
}

if (($Mode -cin @('UpdateSource', 'Preview', 'Apply') -and -not $OperatorApproved) -or ($OperatorApproved -and $Mode -cnotin @('UpdateSource', 'Preview', 'Apply'))) { throw 'ExplicitNmeExecutionApprovalRequired' }
. (Join-Path $repo 'identity/Target.ps1')
. (Join-Path $repo 'nme/ProfileNetbiosApi.ps1')
$settings = Read-LeafPrivateTarget $repo
Assert-LeafTargetContext $settings (Get-AzContext)
$proofRelative = if ($Mode -ceq 'UpdateSource') { 'private/avd/profile-nme-netbios-stored-source-verification.json' } else { 'private/avd/profile-nme-netbios-stored-source-bindings-verification.json' }
$paths = @('private/avd/profile-smb-acl-netbios-repair-preview.json', $proofRelative, 'private/avd/profile-nme-netbios-successor-registration-route-recovery-result.json', ($prefix + '-prepared.json'), ($prefix + '-preview-intent.json'), ($prefix + '-preview-job.json'), ($prefix + '-preview-result.json'), ($prefix + '-apply-intent.json'), ($prefix + '-apply-job.json'), ($prefix + '-apply-result.json'), ($prefix + '-source-update-intent.json'), ($prefix + '-source-update-result.json'))
foreach ($path in @('.env') + $paths) { git -C $repo check-ignore --quiet -- $path; if ($LASTEXITCODE -ne 0) { throw 'IgnoredPrivateExecutionPathsRequired' }; $tracked = @(git -C $repo ls-files -- $path); if ($LASTEXITCODE -ne 0 -or $tracked.Count) { throw 'UntrackedPrivateExecutionPathsRequired' } }
$preview = Get-Content -LiteralPath (Join-Path $repo $paths[0]) -Raw | ConvertFrom-Json -AsHashtable -DateKind String
$proof = Get-Content -LiteralPath (Join-Path $repo $paths[1]) -Raw | ConvertFrom-Json -AsHashtable -DateKind String
$registered = Get-Content -LiteralPath (Join-Path $repo $paths[2]) -Raw | ConvertFrom-Json -AsHashtable -DateKind String
$verifiedSourcePath = if ($Mode -ceq 'UpdateSource') { 'private/avd/profile-nme-netbios-runbook-before-binding-digest.ps1' } else { 'nme/Repair-ProfileNetbios.ps1' }
if ($proof.owner -cne 'nme.profile-netbios.stored-source-verification' -or $proof.exactStoredSourceVerified -cne $true -or $proof.registrationJobStatusObserved -cne 'Completed' -or $proof.actionId -ne $registered.actionId -or $proof.registrationResultSha256 -cne (Get-FileHash -LiteralPath (Join-Path $repo $paths[2])).Hash -or $proof.rawLocalSourceSha256 -cne (Get-FileHash -LiteralPath (Join-Path $repo $verifiedSourcePath)).Hash -or $preview.fieldChangeCount -ne 1 -or $preview.nativeSidComputerAndCifsSpnVerified -cne $true -or $preview.proposedDelta.path -cne 'properties.azureFilesIdentityBasedAuthentication.activeDirectoryProperties.netBiosDomainName') { throw 'VerifiedOwnerNativeSingleFieldProofRequired' }
$inputs = [ordered]@{ ExpectedTenantId = $settings.TARGET_TENANT_ID; ExpectedSubscriptionId = $settings.TARGET_SUBSCRIPTION_ID; AccountId = $preview.accountId; ExpectedStorageSid = $preview.currentAuthentication.activeDirectoryProperties.azureStorageSid; ExpectedDomainSid = $preview.currentAuthentication.activeDirectoryProperties.domainSid; BeforeNetbios = $preview.proposedDelta.before; DesiredNetbios = $preview.proposedDelta.after }
$binding = [ordered]@{ sourceProofSha256 = (Get-FileHash -LiteralPath (Join-Path $repo $paths[1])).Hash; metadataPreviewSha256 = (Get-FileHash -LiteralPath (Join-Path $repo $paths[0])).Hash; runnerSourceSha256 = (Get-FileHash -LiteralPath $PSCommandPath).Hash; runbookSourceSha256 = (Get-FileHash -LiteralPath (Join-Path $repo 'nme/Repair-ProfileNetbios.ps1')).Hash; privateInputsSha256 = (Get-FileHash -LiteralPath (Join-Path $repo '.env')).Hash; inputsSha256 = Get-LeafNetbiosInputHash $inputs; actionId = $proof.actionId }
$preparedPath = Join-Path $repo ($prefix + '-prepared.json')
if ($Mode -ceq 'UpdateSource') {
    $updateIntentPath = Join-Path $repo ($prefix + '-source-update-intent.json')
    $updateResultPath = Join-Path $repo ($prefix + '-source-update-result.json')
    if ((Test-Path -LiteralPath $updateIntentPath) -or (Test-Path -LiteralPath $updateResultPath) -or (Test-Path -LiteralPath $preparedPath) -or (Test-Path -LiteralPath (Join-Path $repo ($prefix + '-preview-intent.json')))) { throw 'SourceUpdateOrExecutionIntentExistsDoNotReplay' }
    $source = [IO.File]::ReadAllText((Join-Path $repo 'nme/Repair-ProfileNetbios.ps1')) -replace '\r\n', "`n"
    $session = $connection = $null
    try {
        $session = Connect-LeafTargetGraph -Settings $settings
        $connection = Get-LeafNmeRestConnection -RepositoryRoot $repo
        $schema = Invoke-LeafNmeRestRead -Connection $connection -Path '/swagger/v1/swagger.json'
        if ($schema.paths['/api/v1/scripted-actions/{id}'].patch.requestBody.content['application/json'].schema['$ref'] -cne '#/components/schemas/ScriptedActionUpdate') { throw 'SupportedOwnedSourceUpdateRequired' }
        Save-LeafNmeState ([ordered]@{ schemaVersion = 1; owner = 'nme.profile-netbios.source-update'; binding = $binding; priorSourceSha256 = $proof.canonicalSourceSha256; newCanonicalSourceSha256 = Get-LeafNetbiosExecutionHash $source; actionId = $proof.actionId; updateRequests = 1; runRequests = 0; status = 'SourceUpdateIntentDoNotReplay' }) $updateIntentPath
        $updated = Invoke-LeafNetbiosRunApi $connection 'PATCH' $proof.actionId @{ script = $source }
        Save-LeafNmeState ([ordered]@{ schemaVersion = 1; owner = 'nme.profile-netbios.source-update'; binding = $binding; actionId = $proof.actionId; jobId = $updated.job.id; payloadSourceMatches = ($null -ne $updated.payload -and (Get-LeafNetbiosExecutionHash $updated.payload.script) -ceq (Get-LeafNetbiosExecutionHash $source)); updateRequests = 1; runRequests = 0; status = 'AcceptedSourceUpdateRequiresIndependentReadback' }) $updateResultPath
        [pscustomobject]@{ Status = 'AcceptedOwnedNmeSourceUpdate'; UpdateRequests = 1; RunRequests = 0; IndependentSourceAndJobReadbackRequired = $true; StorageMetadataChanges = 0 }
    } finally { if ($connection -and $connection.AccessToken -is [securestring]) { $connection.AccessToken.Dispose() }; Disconnect-LeafTargetGraph $session }
    return
}
if ($Mode -ceq 'Prepare') {
    if (Test-Path -LiteralPath $preparedPath) { throw 'ExistingExecutionPreparationMustRemainImmutable' }
    Save-LeafNmeState ([ordered]@{ schemaVersion = 1; owner = 'nme.profile-netbios.execution'; binding = $binding; inputs = $inputs; previewBody = New-LeafNetbiosRunBody $inputs 'Preview'; dcNetbiosWrites = 0; originalUnknownActionMustNotRun = $true; runRequests = 0 }) $preparedPath
    [pscustomobject]@{ Status = 'NmePreviewInputsPreparedPrivately'; ExactStoredSourceVerified = $true; RequiredRuntimeBindings = 8; CloudRunRequests = 0; DcNetbiosWrites = 0; CredentialReads = 0 }
    return
}
$prepared = Get-Content -LiteralPath $preparedPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String
foreach ($field in $binding.Keys) { if ($binding[$field] -cne $prepared.binding[$field]) { throw 'PreparedExecutionBindingChanged' } }
$operation = if ($Mode -ceq 'Readback') { $ReadOperation } else { $Mode }
$intentPath = Join-Path $repo ($prefix + '-' + $operation.ToLowerInvariant() + '-intent.json')
$jobPath = Join-Path $repo ($prefix + '-' + $operation.ToLowerInvariant() + '-job.json')
$connection = $session = $null
try {
    $session = Connect-LeafTargetGraph -Settings $settings
    $connection = Get-LeafNmeRestConnection -RepositoryRoot $repo
    $schema = Invoke-LeafNmeRestRead -Connection $connection -Path '/swagger/v1/swagger.json'
    if ($schema.paths['/api/v1/scripted-actions/{id}/execution'].post.requestBody.content['application/json'].schema['$ref'] -cne '#/components/schemas/RunbookScriptedActionRun') { throw 'InstalledOwnerExecutionContractChanged' }
    if ($Mode -ceq 'Readback') {
        $record = Get-Content -LiteralPath $jobPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String
        if ($record.binding.inputsSha256 -cne $binding.inputsSha256 -or $record.binding.actionId -ne $binding.actionId -or $record.operation -cne $operation) { throw 'ExactOwnedExecutionJobRequired' }
        $job = Invoke-LeafNetbiosRunApi $connection 'GET' $record.job.id
        [pscustomobject]@{ Status = 'OwnedNmeExecutionJobRead'; Operation = $operation; JobStatus = $job.jobStatus; RunRequests = 0; FixedRuntimeResultStillRequired = $true }
        return
    }
    if ((Test-Path -LiteralPath $intentPath) -or (Test-Path -LiteralPath $jobPath)) { throw 'ExecutionIntentOrJobExistsDoNotResubmit' }
    $previewHash = $null
    if ($Mode -ceq 'Apply') {
        $accepted = Get-Content -LiteralPath (Join-Path $repo ($prefix + '-preview-result.json')) -Raw | ConvertFrom-Json -AsHashtable -DateKind String
        if ($accepted.owner -cne 'nme.profile-netbios.fixed-result' -or $accepted.operation -cne 'Preview' -or $accepted.binding.inputsSha256 -cne $binding.inputsSha256 -or $accepted.result.Status -cne 'PreviewReady' -or $accepted.result.FieldChanges -ne 1 -or $accepted.result.PatchRequests -ne 0 -or $accepted.runtimeBindingsVerified -cne $true) { throw 'ExactAcceptedNmePreviewRequiredBeforeApply' }
        $previewHash = $accepted.result.PreviewStateSha256
    }
    $body = New-LeafNetbiosRunBody $inputs $Mode $previewHash
    Save-LeafNmeState ([ordered]@{ schemaVersion = 1; owner = 'nme.profile-netbios.execution'; operation = $Mode; binding = $binding; bodySha256 = Get-LeafNetbiosExecutionHash (ConvertTo-Json -InputObject $body -Depth 5 -Compress); status = 'RunIntentDoNotReplay'; runRequests = 1; dcNetbiosWrites = 0 }) $intentPath
    $job = Invoke-LeafNetbiosRunApi $connection 'POST' $proof.actionId $body
    Save-LeafNmeState ([ordered]@{ schemaVersion = 1; owner = 'nme.profile-netbios.execution'; operation = $Mode; binding = $binding; job = $job; body = $body; runRequests = 1; status = 'AcceptedRunNeedsFixedResultReadback' }) $jobPath
    [pscustomobject]@{ Status = 'AcceptedOwnerNativeNmeRun'; Operation = $Mode; JobStatus = $job.jobStatus; RunRequests = 1; MetadataPatchAllowed = ($Mode -ceq 'Apply'); DcNetbiosWrites = 0; FixedResultReadbackRequired = $true }
} finally {
    if ($connection -and $connection.AccessToken -is [securestring]) { $connection.AccessToken.Dispose() }
    Disconnect-LeafTargetGraph $session
}