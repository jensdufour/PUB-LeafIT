#requires -Version 7.6
[CmdletBinding(PositionalBinding = $false)]
param([switch]$Register, [switch]$Readback, [switch]$RefreshPreview, [switch]$PreTransportRecovery, [switch]$OperatorApproved, [switch]$CheckOnly)

$ErrorActionPreference = $WarningPreference = 'Stop'
$VerbosePreference = $DebugPreference = $ProgressPreference = 'SilentlyContinue'
$repo = Split-Path $PSScriptRoot -Parent
$originalPrefix = 'private/avd/profile-nme-netbios-successor-registration'
$prefix = $originalPrefix + $(if ($PreTransportRecovery) { '-route-recovery' } else { '' })
$sourcePath = Join-Path $repo 'nme/Repair-ProfileNetbios.ps1'
$actionName = 'Repair - Profile AD NetBIOS (Verified Inputs)'

function Get-LeafNetbiosTextHash {
    param([string]$Text)
    return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes(($Text -replace '\r\n', "`n"))))
}

function New-LeafNetbiosActionDefinition {
    param([string]$Text)
    $tokens = $syntax = $null
    $ast = [Management.Automation.Language.Parser]::ParseInput($Text, [ref]$tokens, [ref]$syntax)
    $block = [regex]::Match($Text, '(?s)<#\s*Variables:\s*(?<json>\{.*?\})\s*#>')
    if ($syntax.Count -or $ast.ParamBlock -or -not $block.Success -or [Text.Encoding]::UTF8.GetByteCount($Text) -gt 32768) { throw 'TestedInheritedInputSourceRequired' }
    $variables = ConvertFrom-Json -InputObject $block.Groups['json'].Value -AsHashtable
    if ($variables.Count -ne 9 -or $variables.Operation.DefaultValue -cne 'Preview') { throw 'ExactNineVariablePreviewContractRequired' }
    return [ordered]@{ name = $actionName; script = $Text -replace '\r\n', "`n"; executionEnvironment = 'AzureAutomation'; executionMode = 'Individual'; executionTimeout = 30; tags = @('ChatGPT', 'AzureFiles', 'ActiveDirectory'); description = 'Unassigned source-verified successor. Preview before the one-field repair; never rename the DC domain.' }
}

function Assert-LeafNetbiosRegisteredSource {
    param($Payload, $Definition)
    if ($Payload -isnot [Collections.IDictionary] -or $Payload.id -is [bool] -or ($Payload.id -isnot [int] -and $Payload.id -isnot [long]) -or $Payload.id -le 0 -or $Payload.name -cne $Definition.name -or $Payload.executionEnvironment -cne 'AzureAutomation' -or $Payload.executionMode -cne 'Individual' -or $Payload.executionTimeout -ne 30 -or $Payload.script -isnot [string] -or (Get-LeafNetbiosTextHash $Payload.script) -cne (Get-LeafNetbiosTextHash $Definition.script)) { throw 'ExactStoredSuccessorSourceRequired' }
}

function Invoke-LeafNetbiosRegistrationApi {
    param($Connection, [ValidateSet('GET', 'POST')][string]$Method, [string]$Path, $Body)
    $allowed = ($Method -ceq 'POST' -and $Path -ceq '/api/v1/scripted-actions') -or ($Method -ceq 'GET' -and $Path -cmatch '^/api/v1/job/[1-9][0-9]*$')
    if (-not $allowed -or $Connection.TenantClientAudienceAndRoleVerified -cne $true -or $Connection.AccessToken -isnot [securestring] -or $Connection.ExpiresUtc -le [DateTimeOffset]::UtcNow.AddMinutes(2)) { throw 'ExactNmeRegistrationRouteRequired' }
    $uri = [uri]::new($Connection.BaseUri, $Path)
    if ($uri.Scheme -cne 'https' -or $uri.Host -cne $Connection.BaseUri.Host -or $uri.Port -ne 443) { throw 'VerifiedNmeOriginRequired' }
    $request = @{ Method = $Method; Uri = $uri; Authentication = 'Bearer'; Token = $Connection.AccessToken; MaximumRedirection = 0; SkipHttpErrorCheck = $true; ErrorAction = 'Stop' }
    if ($Method -ceq 'POST') { $request.ContentType = 'application/json'; $request.Body = ConvertTo-Json -InputObject $Body -Depth 8 -Compress -WarningAction Stop }
    try { $reply = Invoke-WebRequest @request } catch { throw 'RegistrationTransportUnknownDoNotReplay' }
    if ($reply.StatusCode -ne 200) { throw ('RegistrationHttp' + [int]$reply.StatusCode + 'InspectBeforeAnyRetry') }
    if ([Text.Encoding]::UTF8.GetByteCount($reply.Content) -gt 65536) { throw 'BoundedOwnedRegistrationResponseRequired' }
    return ConvertFrom-Json -InputObject $reply.Content -AsHashtable -DateKind String -Depth 15
}

function Test-LeafNetbiosPreTransportGuard {
    param([string]$Text)
    $tokens = $syntax = $null
    $ast = [Management.Automation.Language.Parser]::ParseInput($Text, [ref]$tokens, [ref]$syntax)
    $function = @($ast.EndBlock.Statements | Where-Object { $_ -is [Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -ceq 'Invoke-LeafNetbiosRegistrationApi' })
    if ($syntax.Count -or $function.Count -ne 1) { throw 'ExactArchivedTransportFunctionRequired' }
    return & {
        param([string]$FunctionText)
        . ([scriptblock]::Create($FunctionText))
        $calls = @{ count = 0 }
        function Invoke-WebRequest { $calls.count++; throw 'UnexpectedArchivedTransport' }
        $connection = @{ BaseUri = [uri]'https://fixture.azurewebsites.net/'; TenantClientAudienceAndRoleVerified = $true; AccessToken = ConvertTo-SecureString 'NON_CREDENTIAL_OPAQUE_FIXTURE' -AsPlainText -Force; ExpiresUtc = [DateTimeOffset]::UtcNow.AddHours(1) }
        try {
            $rejected = $false
            try { $null = Invoke-LeafNetbiosRegistrationApi $connection 'POST' '/api/v1/scripted-actions' @{} } catch { $rejected = $_.Exception.Message -ceq 'ExactNmeRegistrationRouteRequired' }
            return $rejected -and $calls.count -eq 0
        } finally { $connection.AccessToken.Dispose() }
    } $function[0].Extent.Text
}

if ($CheckOnly) {
    $definition = New-LeafNetbiosActionDefinition ([IO.File]::ReadAllText($sourcePath))
    $payload = $definition | ConvertTo-Json -Depth 5 | ConvertFrom-Json -AsHashtable
    $payload.id = 1
    Assert-LeafNetbiosRegisteredSource $payload $definition
    $checks = 1
    foreach ($field in @('id', 'name', 'script', 'executionEnvironment', 'executionMode', 'executionTimeout')) {
        $changed = $payload | ConvertTo-Json -Depth 5 | ConvertFrom-Json -AsHashtable
        $changed[$field] = if ($field -ceq 'id') { $true } elseif ($field -ceq 'executionTimeout') { 31 } else { 'CHANGED_NON_CREDENTIAL_FIXTURE' }
        $rejected = $false
        try { Assert-LeafNetbiosRegisteredSource $changed $definition } catch { $rejected = $true }
        if (-not $rejected) { throw 'MutatedRegistrationFixtureAccepted' }; $checks++
    }
    if ((Get-LeafNetbiosTextHash "one`r`ntwo") -cne (Get-LeafNetbiosTextHash "one`ntwo")) { throw 'CanonicalSourceHashFixtureFailed' }; $checks++
    $transport = @{ calls = 0 }
    $connection = @{ BaseUri = [uri]'https://fixture.azurewebsites.net/'; TenantClientAudienceAndRoleVerified = $true; AccessToken = ConvertTo-SecureString 'NON_CREDENTIAL_OPAQUE_FIXTURE' -AsPlainText -Force; ExpiresUtc = [DateTimeOffset]::UtcNow.AddHours(1) }
    function Invoke-WebRequest {
        param($Method, $Uri, $Authentication, $Token, $MaximumRedirection, $SkipHttpErrorCheck, $ErrorAction, $ContentType, $Body)
        if ($Authentication -cne 'Bearer' -or $Token -isnot [securestring] -or $MaximumRedirection -ne 0 -or $SkipHttpErrorCheck -ne $true) { throw 'ProtectedNativeTransportFixtureFailed' }
        $transport.calls++
        $document = if ($Method -ceq 'POST') { @{ job = @{ id = 1 }; payload = $payload } } else { @{ id = 1; jobStatus = 'Completed' } }
        if ($Method -ceq 'POST' -and ($ContentType -cne 'application/json' -or (ConvertFrom-Json -InputObject $Body).name -cne $definition.name)) { throw 'ExactSourceBodyFixtureFailed' }
        return @{ StatusCode = 200; Content = ConvertTo-Json -InputObject $document -Depth 8 -Compress }
    }
    try {
        $created = Invoke-LeafNetbiosRegistrationApi $connection 'POST' '/api/v1/scripted-actions' $definition
        Assert-LeafNetbiosRegisteredSource $created.payload $definition
        if ($created.job.id -ne 1) { throw 'RegistrationPostFixtureFailed' }; $checks++
        $job = Invoke-LeafNetbiosRegistrationApi $connection 'GET' '/api/v1/job/1'
        if ($job.id -ne 1 -or $job.jobStatus -cne 'Completed') { throw 'RegistrationGetFixtureFailed' }; $checks++
        foreach ($route in @(@('POST', '/api/v1/job/1'), @('GET', '/api/v1/scripted-actions'), @('POST', '/api/v1/scripted-actions/1/execution'), @('GET', '/api/v1/job/0'))) {
            $rejected = $false
            try { $null = Invoke-LeafNetbiosRegistrationApi $connection $route[0] $route[1] $definition } catch { $rejected = $true }
            if (-not $rejected -or $transport.calls -ne 2) { throw 'UnapprovedRegistrationRouteFixtureAccepted' }; $checks++
        }
    } finally { $connection.AccessToken.Dispose() }
    $source = [IO.File]::ReadAllText($PSCommandPath)
    $grouped = '$allowed = ($Method -ceq ''POST'' -and $Path -ceq ''/api/v1/scripted-actions'') -or ($Method -ceq ''GET'' -and $Path -cmatch ''^/api/v1/job/[1-9][0-9]*$'')'
    $legacy = '$allowed = $Method -ceq ''POST'' -and $Path -ceq ''/api/v1/scripted-actions'' -or $Method -ceq ''GET'' -and $Path -cmatch ''^/api/v1/job/[1-9][0-9]*$'''
    if (-not (Test-LeafNetbiosPreTransportGuard $source.Replace($grouped, $legacy))) { throw 'ArchivedPreTransportRejectionFixtureFailed' }; $checks++
    if (Test-LeafNetbiosPreTransportGuard $source) { throw 'WorkingTransportIncorrectlyClearedForReplay' }; $checks++
    [pscustomobject]@{ Status = 'OfflineChecksPassed'; ChecksPassed = $checks; MockedNativeTransportVerified = $true; CloudCalls = 0; RunRequests = 0; CredentialReads = 0 }
    return
}

if (($Register -and $Readback) -or ($RefreshPreview -and ($Register -or $Readback -or $OperatorApproved)) -or ($OperatorApproved -and -not $Register) -or ($Register -and -not $OperatorApproved)) { throw 'OneExplicitRegistrationOperationRequired' }
. (Join-Path $repo 'identity/Target.ps1')
. (Join-Path $repo 'nme/ProfileNetbiosApi.ps1')
$settings = Read-LeafPrivateTarget $repo
Assert-LeafTargetContext $settings (Get-AzContext)
foreach ($path in @('.env', ($prefix + '-preview.json'), ($prefix + '-intent.json'), ($prefix + '-result.json'))) {
    git -C $repo check-ignore --quiet -- $path
    if ($LASTEXITCODE -ne 0) { throw 'IgnoredPrivateRegistrationPathsRequired' }
    $tracked = @(git -C $repo ls-files -- $path)
    if ($LASTEXITCODE -ne 0 -or $tracked.Count) { throw 'UntrackedPrivateRegistrationPathsRequired' }
}
$definition = New-LeafNetbiosActionDefinition ([IO.File]::ReadAllText($sourcePath))
$binding = [ordered]@{ sourceSha256 = Get-LeafNetbiosTextHash $definition.script; registrationSourceSha256 = (Get-FileHash -LiteralPath $PSCommandPath).Hash; restSourceSha256 = (Get-FileHash -LiteralPath (Join-Path $repo 'nme/ProfileNetbiosApi.ps1')).Hash; privateInputsSha256 = (Get-FileHash -LiteralPath (Join-Path $repo '.env')).Hash; targetSha256 = Get-LeafNetbiosTextHash ($settings.TARGET_TENANT_ID + "`n" + $settings.TARGET_SUBSCRIPTION_ID) }
if ($PreTransportRecovery) {
    $oldIntentPath = Join-Path $repo ($originalPrefix + '-intent.json')
    $oldPreviewPath = Join-Path $repo ($originalPrefix + '-preview.json')
    $archivePath = Join-Path $repo ($originalPrefix + '-before-route-guard-fix.ps1')
    foreach ($path in @($oldIntentPath, $oldPreviewPath, $archivePath)) { git -C $repo check-ignore --quiet -- $path; if ($LASTEXITCODE -ne 0) { throw 'IgnoredRecoveryEvidenceRequired' } }
    $oldIntent = Get-Content -LiteralPath $oldIntentPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String
    $oldPreview = Get-Content -LiteralPath $oldPreviewPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String
    if ($oldIntent.owner -cne 'nme.profile-netbios.successor-registration' -or $oldIntent.status -cne 'SubmitIntentDoNotReplay' -or $oldIntent.runRequests -ne 0 -or $oldIntent.binding.registrationSourceSha256 -cne (Get-FileHash -LiteralPath $archivePath).Hash -or $oldIntent.previewSha256 -cne (Get-FileHash -LiteralPath $oldPreviewPath).Hash -or (Test-Path -LiteralPath (Join-Path $repo ($originalPrefix + '-result.json')))) { throw 'ExactPreTransportStoppedAttemptRequired' }
    foreach ($field in $binding.Keys) { if ($field -cne 'registrationSourceSha256' -and $binding[$field] -cne $oldIntent.binding[$field]) { throw 'RecoveryTargetDefinitionOrPrivateInputsChanged' } }
    $oldSource = [IO.File]::ReadAllText($archivePath)
    if (-not (Test-LeafNetbiosPreTransportGuard $oldSource)) { throw 'UnknownOrSubmittedRegistrationMustNotReplay' }
    $tokens = $syntax = $null
    $oldAst = [Management.Automation.Language.Parser]::ParseInput($oldSource, [ref]$tokens, [ref]$syntax)
    $posts = @($oldAst.FindAll({ param($node) $node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -ceq 'Invoke-LeafNetbiosRegistrationApi' -and $node.CommandElements.Count -eq 5 -and $node.CommandElements[2] -is [Management.Automation.Language.StringConstantExpressionAst] -and $node.CommandElements[2].Value -ceq 'POST' -and $node.CommandElements[3].Value -ceq '/api/v1/scripted-actions' }, $true))
    if ($syntax.Count -or $posts.Count -ne 1) { throw 'ExactArchivedRejectedPostRouteRequired' }
}
$previewPath = Join-Path $repo ($prefix + '-preview.json')
$intentPath = Join-Path $repo ($prefix + '-intent.json')
$resultPath = Join-Path $repo ($prefix + '-result.json')
if (-not $Register -and -not $Readback) {
    if (Test-Path -LiteralPath $previewPath) {
        if (-not $RefreshPreview -or (Test-Path -LiteralPath $intentPath) -or (Test-Path -LiteralPath $resultPath)) { throw 'ExistingRegistrationPreviewMustRemainImmutable' }
        $prior = Get-Content -LiteralPath $previewPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String
        foreach ($field in $binding.Keys) { if ($field -cne 'registrationSourceSha256' -and $binding[$field] -cne $prior.binding[$field]) { throw 'UnsubmittedPreviewTargetOrDefinitionChanged' } }
        if ($prior.owner -cne 'nme.profile-netbios.successor-registration' -or $prior.runRequests -ne 0 -or (Get-LeafNetbiosTextHash (ConvertTo-Json -InputObject $prior.definition -Depth 5 -Compress)) -cne (Get-LeafNetbiosTextHash (ConvertTo-Json -InputObject $definition -Depth 5 -Compress))) { throw 'UnsubmittedPreviewDefinitionChanged' }
        $archive = $previewPath + '.' + (Get-FileHash -LiteralPath $previewPath).Hash + '.archive'
        git -C $repo check-ignore --quiet -- $archive
        if ($LASTEXITCODE -ne 0 -or (Test-Path -LiteralPath $archive)) { throw 'NewIgnoredPreviewArchiveRequired' }
        [IO.File]::Copy($previewPath, $archive, $false)
        if ((Get-FileHash -LiteralPath $previewPath).Hash -cne (Get-FileHash -LiteralPath $archive).Hash) { throw 'ExactPreviewArchiveRequired' }
    } elseif ($RefreshPreview) { throw 'ExistingUnsubmittedPreviewRequired' }
    $historicalIntentPath = Join-Path $repo 'private/avd/profile-nme-netbios-registration-intent.json'
    $historicalIntentHash = if (Test-Path -LiteralPath $historicalIntentPath) { (Get-FileHash -LiteralPath $historicalIntentPath).Hash } else { $null }
    Save-LeafNmeState ([ordered]@{ schemaVersion = 1; owner = 'nme.profile-netbios.successor-registration'; binding = $binding; definition = $definition; historicalUnresolvedIntentSha256 = $historicalIntentHash; originalAttemptMustNotReplay = $true; assignments = @(); schedules = @(); runRequests = 0 }) $previewPath
    [pscustomobject]@{ Status = 'UnassignedSuccessorDefinitionPreview'; StoredSourceVerificationRequired = $true; CloudMutationRequests = 0; RunRequests = 0 }
    return
}
$preview = Get-Content -LiteralPath $previewPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String
if ((ConvertTo-Json -InputObject $binding -Compress) -cne (ConvertTo-Json -InputObject $preview.binding -Compress)) { throw 'FrozenRegistrationBindingChanged' }
if ($Register -and (Test-Path -LiteralPath $intentPath)) { throw 'RegistrationIntentExistsDoNotResubmit' }
if ($Register -and (Test-Path -LiteralPath $resultPath)) { throw 'RegistrationAlreadyHasOutcomeDoNotResubmit' }
$connection = $session = $null
try {
    $session = Connect-LeafTargetGraph -Settings $settings
    $connection = Get-LeafNmeRestConnection -RepositoryRoot $repo
    $schema = Invoke-LeafNmeRestRead -Connection $connection -Path '/swagger/v1/swagger.json'
    if ($schema.paths['/api/v1/scripted-actions'].post.requestBody.content['application/json'].schema['$ref'] -cne '#/components/schemas/ScriptedActionCreate' -or -not $schema.paths['/api/v1/job/{jobId}'].get) { throw 'InstalledRegistrationContractChanged' }
    if ($Readback) {
        $result = Get-Content -LiteralPath $resultPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String
        if ($result.jobId -is [bool] -or ($result.jobId -isnot [int] -and $result.jobId -isnot [long]) -or $result.jobId -le 0) { throw 'OwnedRegistrationJobIdRequired' }
        $job = Invoke-LeafNetbiosRegistrationApi $connection 'GET' ('/api/v1/job/' + $result.jobId)
        if ($job.id -ne $result.jobId -or $job.jobStatus -cnotin @('Pending', 'Running', 'Completed', 'Failed', 'Cancelled')) { throw 'ExactRegistrationJobReadbackRequired' }
        [pscustomobject]@{ Status = 'RegistrationJobMetadataRead'; JobStatus = $job.jobStatus; StoredSourceVerifiedAtSubmission = $result.storedSourceVerified; RunRequests = 0 }
        return
    }
    Save-LeafNmeState ([ordered]@{ schemaVersion = 1; owner = 'nme.profile-netbios.successor-registration'; binding = $binding; previewSha256 = (Get-FileHash -LiteralPath $previewPath).Hash; historicalAttemptNeverReplayed = $true; registerRequests = 1; runRequests = 0; status = 'SubmitIntentDoNotReplay' }) $intentPath
    $reply = Invoke-LeafNetbiosRegistrationApi $connection 'POST' '/api/v1/scripted-actions' $definition
    if ($reply.job.id -is [bool] -or ($reply.job.id -isnot [int] -and $reply.job.id -isnot [long]) -or $reply.job.id -le 0) { throw 'OwnedRegistrationJobRequired' }
    $result = [ordered]@{ schemaVersion = 1; owner = 'nme.profile-netbios.successor-registration'; binding = $binding; actionId = $null; jobId = $reply.job.id; storedSourceVerified = $false; status = 'AcceptedRegistrationNeedsStoredSourceAndTerminalJobReadback'; registerRequests = 1; runRequests = 0 }
    Save-LeafNmeState $result $resultPath
    if ($null -ne $reply.payload) {
        Assert-LeafNetbiosRegisteredSource $reply.payload $definition
        $result.actionId = $reply.payload.id; $result.storedSourceVerified = $true
        Save-LeafNmeState $result $resultPath
    }
    [pscustomobject]@{ Status = 'AcceptedUnassignedSuccessorRegistration'; StoredSourceVerified = $result.storedSourceVerified; TerminalJobReadbackRequired = $true; RegisterRequests = 1; RunRequests = 0; StorageMetadataWrites = 0 }
} finally {
    if ($connection -and $connection.AccessToken -is [securestring]) { $connection.AccessToken.Dispose() }
    Disconnect-LeafTargetGraph $session
}