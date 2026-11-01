#requires -Version 7.6
[CmdletBinding(PositionalBinding = $false)]
param([ValidateSet('Preview', 'Apply')][string]$Operation = 'Preview', [switch]$WorkerHealth, [switch]$CheckOnly)

$ErrorActionPreference = $WarningPreference = 'Stop'
$VerbosePreference = $DebugPreference = $ProgressPreference = 'SilentlyContinue'
$repo = Split-Path $PSScriptRoot -Parent
$prefix = 'private/avd/profile-nme-netbios-execution'

function Get-LeafNetbiosResultProjectionSource {
    return @'
param([string]$PacketName)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
function ReadWorkerSetting([string]$Name) {
    foreach ($key in @($Name, ('APPSETTING_' + $Name), $Name.Replace(':', '__'), ('APPSETTING_' + $Name.Replace(':', '__')))) {
        $value = [Environment]::GetEnvironmentVariable($key)
        if ($value) { return $value }
    }
    return $null
}
function ConvertTo-LeafNetbiosFixedResult {
    param([string]$Text, [string]$InputHash)
    if ($Text.Length -gt 1048576 -or $InputHash -cnotmatch '^[A-F0-9]{64}$') { throw 'BoundedFixedResultRequired' }
    $found = @()
    foreach ($match in [regex]::Matches($Text, '\{[^{}\r\n]*"Status"[^{}\r\n]*\}')) {
        try { $candidate = ConvertFrom-Json -InputObject $match.Value -ErrorAction Stop } catch { continue }
        if ($candidate.RuntimeInputsSha256 -cne $InputHash) { continue }
        $allowed = @('Status', 'RuntimeInputsSha256', 'PreviewStateSha256', 'FieldChanges', 'DcNetbiosWrites', 'PatchRequests', 'CredentialReads', 'AccountShareRolesPreserved', 'DefaultSharePermissionNone', 'KeyOperations', 'RawErrorReturned', 'Stage')
        if (@($candidate.PSObject.Properties.Name | Where-Object { $_ -cnotin $allowed }).Count) { throw 'UnallowlistedFixedResultField' }
        if ($candidate.Status -cnotin @('PreviewReady', 'VerifiedOneFieldMetadataRepair', 'NoChange', 'Stopped', 'UncertainOutcomeDoNotReplay')) { throw 'FixedResultStatusRequired' }
        foreach ($name in @('DcNetbiosWrites', 'CredentialReads', 'PatchRequests')) {
            $value = $candidate.$name
            if (($value -isnot [int] -and $value -isnot [long]) -or $value -lt 0 -or $value -gt 1 -or ($name -cne 'PatchRequests' -and $value -ne 0)) { throw 'ZeroWriteCounterContractRequired' }
        }
        if ($candidate.Status -ceq 'PreviewReady' -and ($candidate.PreviewStateSha256 -cnotmatch '^[A-F0-9]{64}$' -or ($candidate.FieldChanges -isnot [int] -and $candidate.FieldChanges -isnot [long]) -or $candidate.FieldChanges -notin @(0, 1) -or $candidate.PatchRequests -ne 0)) { throw 'FixedPreviewContractRequired' }
        if ($candidate.Status -ceq 'VerifiedOneFieldMetadataRepair' -and ($candidate.AccountShareRolesPreserved -cne $true -or $candidate.DefaultSharePermissionNone -cne $true -or $candidate.PatchRequests -ne 1 -or $candidate.KeyOperations -ne 0)) { throw 'VerifiedOneFieldContractRequired' }
        if ($candidate.Status -ceq 'NoChange' -and $candidate.PatchRequests -ne 0) { throw 'NoChangeContractRequired' }
        if ($candidate.Status -cin @('Stopped', 'UncertainOutcomeDoNotReplay') -and ($candidate.RawErrorReturned -cne $false -or $candidate.Stage -cnotin @('ExactNmeContext', 'ProtectedStatePreview', 'OneFieldMetadataPatch', 'FullPreservationReadback'))) { throw 'FixedStoppedContractRequired' }
        $found += $candidate
    }
    if ($found.Count -gt 1) { throw 'OneMatchingFixedResultRequired' }
    if ($found.Count -eq 1) { return $found[0] }
    return $null
}
$packetPath = $packet = $response = $tasks = $null
$stage = 'ReadPacket'
try {
    if ($PacketName -cnotmatch '^[a-f0-9]{32}$') { throw 'PacketRejected' }
    $packetPath = Join-Path $env:HOME ('data\leafit-nme-bootstrap\' + $PacketName + '.json')
    try { $packet = ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($packetPath)) } finally { if (Test-Path -LiteralPath $packetPath) { Remove-Item -LiteralPath $packetPath -Force } }
    $stage = 'ValidateTarget'
    $tenant = ReadWorkerSetting 'Deployment:TenantId'
    $hostName = $env:WEBSITE_SITE_NAME + '.azurewebsites.net'
    $origin = [uri]$packet.Origin
    if ($tenant -ine $packet.TenantId -or $origin.Scheme -cne 'https' -or $origin.Host -ine $hostName -or $origin.Port -ne 443 -or $origin.Query -or $origin.UserInfo -or $origin.Fragment -or $packet.JobId -lt 1 -or $packet.ExpectedInputsSha256 -cnotmatch '^[A-F0-9]{64}$' -or [datetimeoffset]::Parse($packet.ExpiresUtc) -le [datetimeoffset]::UtcNow -or [datetimeoffset]::Parse($packet.ExpiresUtc) -gt [datetimeoffset]::UtcNow.AddMinutes(5)) { throw 'TargetRejected' }
    $stage = 'ReadApi'
    if ($packet.WorkerHealth -eq $true) {
        if ($packet.AppId -inotmatch '^/subscriptions/[a-f0-9-]{36}/resourceGroups/[A-Za-z0-9._()-]+/providers/Microsoft.Web/sites/[A-Za-z0-9-]+$' -or $packet.AppId.Split('/')[-1] -ine $env:WEBSITE_SITE_NAME) { throw 'ExactNativeAppRequired' }
        $uri = 'https://management.azure.com' + $packet.AppId + '/continuouswebjobs?api-version=2024-04-01'
        $response = Invoke-WebRequest -Uri $uri -Method GET -Headers @{ Authorization = 'Bearer ' + $packet.AccessToken } -UseBasicParsing -MaximumRedirection 0 -TimeoutSec 60 -ErrorAction Stop
        $native = ConvertFrom-Json -InputObject $response.Content
        $jobs = @($native.value)
        if ($jobs.Count -gt 16) { throw 'NativeJobBudgetRejected' }
        $selected = @($jobs | Where-Object { $_.properties.name -ceq 'provision' -or ($_.name -split '/')[-1] -ceq 'provision' })
        if ($selected.Count -ne 1 -or $selected[0].properties.status -cnotin @('Running', 'Stopped', 'Starting', 'Initializing', 'PendingRestart')) { throw 'ExactProvisionStatusRequired' }
        @{ Success = $true; JobId = $packet.JobId; ProvisionStatus = [string]$selected[0].properties.status; WebJobCount = $jobs.Count; RawTaskDataReturned = $false; WorkerStateChanges = 0 } | ConvertTo-Json -Compress
        return
    }
    $uri = 'https://' + $hostName + '/api/v1/job/' + [int]$packet.JobId + '/tasks'
    $response = Invoke-WebRequest -Uri $uri -Method GET -Headers @{ Authorization = 'Bearer ' + $packet.AccessToken } -UseBasicParsing -MaximumRedirection 0 -TimeoutSec 60 -ErrorAction Stop
    $parsed = ConvertFrom-Json -InputObject $response.Content
    $tasks = @($parsed)
    if ($tasks.Count -lt 1 -or $tasks.Count -gt 16) { throw 'TaskBudgetRejected' }
    $stage = 'ProjectFixedResult'
    $results = @()
    foreach ($task in $tasks) {
        if ($task.status -cnotin @('Cancelled', 'Running', 'Success', 'Failed')) { throw 'TaskMetadataRejected' }
        $value = ConvertTo-LeafNetbiosFixedResult ([string]$task.resultPlain) $packet.ExpectedInputsSha256
        if ($null -ne $value) { $results += @{ TaskId = $task.id; TaskStatus = $task.status; Result = $value } }
    }
    if ($results.Count -ne 1) { throw 'OneFixedResultRequired' }
    @{ Success = $true; JobId = $packet.JobId; TaskId = $results[0].TaskId; TaskStatus = $results[0].TaskStatus; RuntimeBindingsVerified = $true; Result = $results[0].Result; RawTaskDataReturned = $false } | ConvertTo-Json -Depth 6 -Compress
} catch {
    @{ Success = $false; Stage = $stage; Reason = 'FixedProjectionStopped'; RawTaskDataReturned = $false } | ConvertTo-Json -Compress
    exit 1
} finally { $packet = $response = $tasks = $results = $null }
'@
}

if ($CheckOnly) {
    $source = Get-LeafNetbiosResultProjectionSource
    $tokens = $syntax = $null
    $ast = [Management.Automation.Language.Parser]::ParseInput($source, [ref]$tokens, [ref]$syntax)
    $definition = @($ast.EndBlock.Statements | Where-Object { $_ -is [Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -ceq 'ConvertTo-LeafNetbiosFixedResult' })
    if ($syntax.Count -or $definition.Count -ne 1 -or $source -match 'Get-AzStorageAccountKey|Set-Acl|Read-Host|Start-Sleep|Get-ChildItem') { throw 'FixedProjectionSourceRejected' }
    . ([scriptblock]::Create($definition[0].Extent.Text))
    $inputHash = 'A' * 64
    $fixture = @{ Status = 'PreviewReady'; RuntimeInputsSha256 = $inputHash; PreviewStateSha256 = 'B' * 64; FieldChanges = 1; DcNetbiosWrites = 0; CredentialReads = 0; PatchRequests = 0 }
    $result = ConvertTo-LeafNetbiosFixedResult (ConvertTo-Json -InputObject $fixture -Compress) $inputHash
    if ($result.Status -cne 'PreviewReady') { throw 'FixedPreviewProjectionFixtureFailed' }
    $checks = 1
    foreach ($variant in @('WrongHash', 'ExtraField', 'BooleanCounter', 'PreviewPatch', 'InvalidStatus')) {
        $changed = $fixture.Clone()
        switch ($variant) {
            WrongHash { $changed.RuntimeInputsSha256 = 'C' * 64 }
            ExtraField { $changed.Unexpected = 'NON_CREDENTIAL_FIELD_NOT_RETURNED' }
            BooleanCounter { $changed.PatchRequests = $false }
            PreviewPatch { $changed.PatchRequests = 1 }
            InvalidStatus { $changed.Status = 'Other' }
        }
        $accepted = $false
        try { $accepted = $null -ne (ConvertTo-LeafNetbiosFixedResult (ConvertTo-Json -InputObject $changed -Compress) $inputHash) } catch { $accepted = $false }
        if ($accepted) { throw 'InvalidFixedResultFixtureAccepted' }; $checks++
    }
    if ($null -ne (ConvertTo-LeafNetbiosFixedResult 'NON_CREDENTIAL_UNRELATED_OUTPUT' $inputHash)) { throw 'UnrelatedOutputFixtureAccepted' }; $checks++
    & {
        param([string]$Runbook)
        $ExpectedTenantId = '00000000-0000-0000-0000-000000000001'; $ExpectedSubscriptionId = '00000000-0000-0000-0000-000000000002'
        $AccountId = '/subscriptions/' + $ExpectedSubscriptionId + '/resourceGroups/rg-fixture/providers/Microsoft.Storage/storageAccounts/fixtureprofile'
        $ExpectedStorageSid = 'S-1-5-21-1-2-3-1000'; $ExpectedDomainSid = 'S-1-5-21-1-2-3'; $BeforeNetbios = 'OLD'; $DesiredNetbios = 'NEW'
        $authentication = @{ directoryServiceOptions = 'AD'; defaultSharePermission = 'None'; activeDirectoryProperties = @{ accountType = 'Computer'; netBiosDomainName = 'OLD'; domainSid = $ExpectedDomainSid; azureStorageSid = $ExpectedStorageSid; domainName = 'example.invalid'; samAccountName = 'fixture$' } }
        $nativeState = @{ patches = 0; account = @{ id = $AccountId; location = 'swedencentral'; kind = 'FileStorage'; sku = @{ name = 'PremiumV2_LRS' }; properties = @{ azureFilesIdentityBasedAuthentication = $authentication; allowSharedKeyAccess = $false; publicNetworkAccess = 'Disabled'; minimumTlsVersion = 'TLS1_2'; supportsHttpsTrafficOnly = $true; networkAcls = @{ defaultAction = 'Deny'; bypass = 'None' } } } }
        function Get-AzContext { return @{ Tenant = @{ Id = $ExpectedTenantId }; Subscription = @{ Id = $ExpectedSubscriptionId }; Account = @{ Type = 'ServicePrincipal' }; Environment = @{ Name = 'AzureCloud'; ResourceManagerUrl = 'https://management.azure.com/' } } }
        function Invoke-AzRestMethod {
            param([string]$Method, [string]$Path, [string]$Payload)
            if ($Method -ceq 'PATCH') {
                if ($Path -cne ($AccountId + '?api-version=2025-01-01')) { throw 'UnselectedNativePatchFixture' }
                $body = ConvertFrom-Json -InputObject $Payload -AsHashtable
                if ($body.Count -ne 1 -or $body.properties.Count -ne 1 -or $body.properties.azureFilesIdentityBasedAuthentication.activeDirectoryProperties.netBiosDomainName -cne 'NEW') { throw 'OneFieldNativePatchFixtureFailed' }
                $nativeState.patches++
                $nativeState.account.properties.azureFilesIdentityBasedAuthentication = $body.properties.azureFilesIdentityBasedAuthentication
                return @{ StatusCode = 200; Content = '{}' }
            }
            if ($Method -cne 'GET') { throw 'UnexpectedNativeWriterFixture' }
            $value = switch ($Path) {
                ($AccountId + '?api-version=2025-01-01') { $nativeState.account }
                ($AccountId + '/fileServices/default/shares/profiles?api-version=2025-01-01') { @{ id = $AccountId + '/fileServices/default/shares/profiles' } }
                ($AccountId + '/fileServices/default/fileshares/profiles/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&$filter=atScope()') { @{ value = @() } }
                default { throw 'UnselectedNativeReadFixture' }
            }
            return @{ StatusCode = 200; Content = ConvertTo-Json -InputObject $value -Depth 20 -Compress }
        }
        $Operation = 'Preview'
        $preview = & ([scriptblock]::Create($Runbook)) -TenantGroupName group-fixture | ConvertFrom-Json -AsHashtable
        $PreviewStateSha256 = $preview.PreviewStateSha256
        $Operation = 'Apply'
        $applied = & ([scriptblock]::Create($Runbook)) -TenantGroupName group-fixture | ConvertFrom-Json -AsHashtable
        if ($applied.Status -cne 'VerifiedOneFieldMetadataRepair' -or $applied.PatchRequests -ne 1 -or $nativeState.patches -ne 1 -or $applied.AccountShareRolesPreserved -cne $true) { throw 'ActualNativeOneFieldApplyFixtureFailed' }
        $repeat = & ([scriptblock]::Create($Runbook)) -TenantGroupName group-fixture | ConvertFrom-Json -AsHashtable
        if ($repeat.Status -cne 'NoChange' -or $repeat.PatchRequests -ne 0 -or $nativeState.patches -ne 1) { throw 'ActualNativeNoChangeFixtureFailed' }
    } ([IO.File]::ReadAllText((Join-Path $repo 'nme/Repair-ProfileNetbios.ps1')))
    $checks += 2
    [pscustomobject]@{ Status = 'OfflineChecksPassed'; ChecksPassed = $checks; ActualServerProjectionVerified = $true; RawTaskDataReturned = $false; CloudCalls = 0 }
    return
}

. (Join-Path $repo 'identity/Target.ps1')
. (Join-Path $repo 'nme/ProfileNetbiosApi.ps1')
. (Join-Path $repo 'nme/PrivateWorker.ps1')
$settings = Read-LeafPrivateTarget $repo
$context = Get-AzContext
Assert-LeafTargetContext $settings $context
$jobPath = Join-Path $repo ($prefix + '-' + $Operation.ToLowerInvariant() + '-job.json')
$resultPath = Join-Path $repo ($prefix + '-' + $Operation.ToLowerInvariant() + $(if ($WorkerHealth) { '-worker-health.json' } else { '-result.json' }))
foreach ($path in @('.env', $jobPath, $resultPath, 'private/nme/installation-plan.json')) { git -C $repo check-ignore --quiet -- $path; if ($LASTEXITCODE -ne 0) { throw 'IgnoredResultEvidenceRequired' }; $tracked = @(git -C $repo ls-files -- $path); if ($LASTEXITCODE -ne 0 -or $tracked.Count) { throw 'UntrackedResultEvidenceRequired' } }
if (Test-Path -LiteralPath $resultPath) { throw 'ExistingFixedResultMustRemainImmutable' }
$record = Get-Content -LiteralPath $jobPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String
$prepared = Get-Content -LiteralPath (Join-Path $repo ($prefix + '-prepared.json')) -Raw | ConvertFrom-Json -AsHashtable -DateKind String
if ($record.owner -cne 'nme.profile-netbios.execution' -or $record.operation -cne $Operation -or $record.binding.inputsSha256 -cne $prepared.binding.inputsSha256 -or $record.binding.actionId -ne $prepared.binding.actionId -or $record.binding.privateInputsSha256 -cne (Get-FileHash -LiteralPath (Join-Path $repo '.env')).Hash -or $record.binding.runbookSourceSha256 -cne (Get-FileHash -LiteralPath (Join-Path $repo 'nme/Repair-ProfileNetbios.ps1')).Hash) { throw 'ExactOwnedExecutionResultBindingRequired' }
$connection = $session = $packet = $worker = $null
$packetPath = $sourcePath = $null
try {
    $session = Connect-LeafTargetGraph -Settings $settings
    $connection = Get-LeafNmeRestConnection -RepositoryRoot $repo
    $tokens = $syntax = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $repo 'nme/Invoke-ProfileNetbiosRepair.ps1'), [ref]$tokens, [ref]$syntax)
    $reader = @($ast.EndBlock.Statements | Where-Object { $_ -is [Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -ceq 'Invoke-LeafNetbiosRunApi' })
    if ($syntax.Count -or $reader.Count -ne 1) { throw 'ExactNativeJobReaderRequired' }
    . ([scriptblock]::Create($reader[0].Extent.Text))
    $job = Invoke-LeafNetbiosRunApi $connection 'GET' $record.job.id
    if (-not $WorkerHealth -and $job.jobStatus -cnotin @('Completed', 'Failed', 'Cancelled')) { throw 'ExecutionStillPendingDoNotResubmit' }
    $installation = Get-Content -LiteralPath (Join-Path $repo 'private/nme/installation-plan.json') -Raw | ConvertFrom-Json -AsHashtable
    $sites = @(Get-AzResource -ResourceGroupName $installation.resourceGroupName -ResourceType 'Microsoft.Web/sites' -ExpandProperties -DefaultProfile $context | Where-Object { $_.Properties.defaultHostName -ieq $connection.BaseUri.Host })
    if ($sites.Count -ne 1) { throw 'ExactExistingNmeSiteRequired' }
    $hosts = @($sites[0].Properties.enabledHostNames | Where-Object { $_ -cmatch '^[a-z0-9-]+\.scm\.azurewebsites\.net$' })
    $address = $null
    if ($hosts.Count -ne 1 -or -not [Net.IPAddress]::TryParse([string]$sites[0].Properties.inboundIpAddress, [ref]$address)) { throw 'ExistingNativeWorkerEndpointRequired' }
    $worker = @{ Settings = $settings; Context = $context; Host = $hosts[0]; Address = $address.ToString() }
    $packetName = [guid]::NewGuid().ToString('N')
    $packetPath = '/api/vfs/data/leafit-nme-bootstrap/' + $packetName + '.json'
    $sourcePath = '/api/vfs/data/leafit-nme-bootstrap/' + $packetName + '.ps1'
    $packet = @{ TenantId = $settings.TARGET_TENANT_ID; Origin = $connection.BaseUri.GetLeftPart([UriPartial]::Authority); JobId = $record.job.id; ExpectedInputsSha256 = $record.binding.inputsSha256; ExpiresUtc = [DateTimeOffset]::UtcNow.AddMinutes(3).ToString('o'); AccessToken = [Net.NetworkCredential]::new('', $connection.AccessToken).Password }
    if ($WorkerHealth) {
        $nativeToken = Get-AzAccessToken -ResourceUrl 'https://management.azure.com/' -TenantId $settings.TARGET_TENANT_ID -ErrorAction Stop
        if ($nativeToken.TenantId -ine $settings.TARGET_TENANT_ID -or $nativeToken.Token -isnot [securestring]) { throw 'ExactNativeMetadataTokenRequired' }
        $packet.WorkerHealth = $true; $packet.AppId = $sites[0].ResourceId
        $packet.AccessToken = [Net.NetworkCredential]::new('', $nativeToken.Token).Password
        $nativeToken = $null
    }
    $entry = '$path = Join-Path $env:HOME ''data\leafit-nme-bootstrap\' + $packetName + '.ps1''; try { $text = [IO.File]::ReadAllText($path) } finally { if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force } }; & ([scriptblock]::Create($text)) -PacketName ' + $packetName
    $command = 'powershell.exe -NoProfile -NonInteractive -EncodedCommand ' + [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($entry))
    $null = Invoke-NmePrivateWorkerHttp $worker 'PUT' '/api/vfs/data/leafit-nme-bootstrap/'
    $null = Invoke-NmePrivateWorkerHttp $worker 'PUT' $sourcePath (Get-LeafNetbiosResultProjectionSource)
    $null = Invoke-NmePrivateWorkerHttp $worker 'PUT' $packetPath (ConvertTo-Json -InputObject $packet -Depth 5 -Compress)
    $packet.AccessToken = $null
    $response = Invoke-NmePrivateWorkerHttp $worker 'POST' '/api/command' (ConvertTo-Json -InputObject @{ command = $command; dir = 'site\wwwroot' } -Compress) -SensitiveResponse
    if (-not $response.Output -or [Text.Encoding]::UTF8.GetByteCount([string]$response.Output) -gt 16384) { throw 'BoundedFixedWorkerOutputRequired' }
    $result = ConvertFrom-Json -InputObject ([string]$response.Output).Trim() -AsHashtable -Depth 10
    if ($response.ExitCode -ne 0 -or $result.Success -cne $true -or $result.JobId -ne $record.job.id -or $result.RawTaskDataReturned -cne $false) { throw 'OwnedFixedResultProjectionStoppedNoReplay' }
    if (-not $WorkerHealth -and ($result.RuntimeBindingsVerified -cne $true -or $result.Result.RuntimeInputsSha256 -cne $record.binding.inputsSha256)) { throw 'ExactRuntimeInputDigestRequired' }
    if (-not $WorkerHealth -and $result.Result.Status -cin @('PreviewReady', 'VerifiedOneFieldMetadataRepair', 'NoChange') -and ($job.jobStatus -cne 'Completed' -or $result.TaskStatus -cne 'Success')) { throw 'NativeJobAndTaskSuccessRequiredBeforeAcceptance' }
    if ($WorkerHealth) {
        if ($result.ProvisionStatus -cnotin @('Running', 'Stopped', 'Starting', 'Initializing', 'PendingRestart') -or $result.WorkerStateChanges -ne 0) { throw 'FixedProvisionHealthRequired' }
        Save-LeafNmeState ([ordered]@{ schemaVersion = 1; owner = 'nme.profile-netbios.worker-health'; binding = $record.binding; jobId = $record.job.id; provisionStatus = $result.ProvisionStatus; webJobCount = $result.WebJobCount; workerStateChanges = 0; rawNativeDataReturned = $false }) $resultPath
        [pscustomobject]@{ Status = 'ExactNmeWorkerHealthProjectedInsideAzure'; ProvisionStatus = $result.ProvisionStatus; WorkerStateChanges = 0; RawNativeDataReturned = $false; RunRequests = 0 }
        return
    }
    Save-LeafNmeState ([ordered]@{ schemaVersion = 1; owner = 'nme.profile-netbios.fixed-result'; operation = $Operation; binding = $record.binding; jobId = $record.job.id; jobStatus = $job.jobStatus; taskId = $result.TaskId; taskStatus = $result.TaskStatus; runtimeBindingsVerified = $true; result = $result.Result; rawTaskDataReturned = $false; resultReaderSourceSha256 = (Get-FileHash -LiteralPath $PSCommandPath).Hash; runRequests = 0 }) $resultPath
    [pscustomobject]@{ Status = 'OwnedNmeFixedResultRead'; Operation = $Operation; NativeJobStatus = $job.jobStatus; ResultStatus = $result.Result.Status; RuntimeBindingsVerified = $true; RawTaskDataReturned = $false; RunRequests = 0 }
} finally {
    if ($packet) { $packet.AccessToken = $null }
    if ($worker -and $packetPath) { try { $null = Invoke-NmePrivateWorkerHttp $worker 'DELETE' $packetPath } finally { if ($sourcePath) { $null = Invoke-NmePrivateWorkerHttp $worker 'DELETE' $sourcePath } } }
    if ($connection -and $connection.AccessToken -is [securestring]) { $connection.AccessToken.Dispose() }
    Disconnect-LeafTargetGraph $session
}