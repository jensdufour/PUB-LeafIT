#requires -Version 7.6
[CmdletBinding(PositionalBinding = $false)]
param([ValidateSet('Preview', 'Restart', 'Verify')][string]$Mode = 'Preview', [ValidatePattern('^[a-z0-9][a-z0-9-]{0,47}$')][string]$AttemptId = 'after-storage-tags', [switch]$OperatorApproved, [switch]$CheckOnly)

$ErrorActionPreference = $WarningPreference = 'Stop'
$VerbosePreference = $DebugPreference = $ProgressPreference = 'SilentlyContinue'
$repo = Split-Path $PSScriptRoot -Parent

function Get-NmeAppRestartPath {
    param([string]$AppId, [string]$SubscriptionId, [string]$Group, [uri]$Origin)
    $prefix = '/subscriptions/' + $SubscriptionId + '/resourceGroups/' + $Group + '/providers/Microsoft.Web/sites/'
    if (-not $AppId.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) -or $AppId.Substring($prefix.Length) -cnotmatch '^[a-z0-9][a-z0-9-]{1,59}$' -or $Origin.Scheme -cne 'https' -or $Origin.Port -ne 443 -or $Origin.UserInfo -or $Origin.Query -or $Origin.Fragment -or $Origin.AbsolutePath -cne '/' -or $Origin.Host -ine ($AppId.Split('/')[-1] + '.azurewebsites.net')) { throw 'ExactInstalledNmeAppRestartTargetRequired' }
    return $AppId + '/restart?api-version=2024-04-01'
}

function Invoke-NmeAppRestart {
    param([string]$Path, $Context)
    try { $reply = Invoke-AzRestMethod -Method POST -Path $Path -DefaultProfile $Context -ErrorAction Stop } catch { throw 'AppRestartSubmissionUncertainDoNotReplay' }
    if ($reply.StatusCode -notin @(200, 202, 204)) { throw 'AppRestartAcceptanceUnknownDoNotReplay' }
    return [int]$reply.StatusCode
}

function Test-NmeAppHttpsReady {
    param([uri]$Origin)
    $handler = [Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $false
    $handler.UseCookies = $false
    $client = [Net.Http.HttpClient]::new($handler)
    $client.Timeout = [timespan]::FromSeconds(60)
    $request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Head, $Origin)
    $reply = $null
    try {
        $reply = $client.SendAsync($request, [Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
        $status = [int]$reply.StatusCode
        $ready = $status -eq 200
        if ($status -in @(301, 302, 303, 307, 308) -and $reply.Headers.Location) {
            $redirect = [uri]::new($Origin, $reply.Headers.Location)
            $ready = $redirect.Scheme -ceq 'https' -and $redirect.Port -eq 443 -and ($redirect.Host -ieq $Origin.Host -or $redirect.Host -ceq 'login.microsoftonline.com')
        }
        return @{ Ready = $ready; HttpStatus = $status }
    } catch { return @{ Ready = $false; HttpStatus = 0 } } finally { if ($reply) { $reply.Dispose() }; $request.Dispose(); $client.Dispose() }
}

if ($CheckOnly) {
    $subscription = '00000000-0000-0000-0000-000000000001'
    $app = '/subscriptions/' + $subscription + '/resourceGroups/rg-nme-swc-001/providers/Microsoft.Web/sites/fixture-nme-app'
    $origin = [uri]'https://fixture-nme-app.azurewebsites.net/'
    $path = Get-NmeAppRestartPath $app $subscription 'rg-nme-swc-001' $origin
    if ($path -cne ($app + '/restart?api-version=2024-04-01')) { throw 'ExactNativeRestartRouteFixtureFailed' }
    $checks = 1
    foreach ($variant in @('OtherSubscription', 'OtherGroup', 'WrongOrigin', 'Http', 'ChildResource')) {
        $id = $app; $uri = $origin
        switch ($variant) {
            OtherSubscription { $id = $app.Replace($subscription, '00000000-0000-0000-0000-000000000002') }
            OtherGroup { $id = $app.Replace('/rg-nme-swc-001/', '/rg-other/') }
            WrongOrigin { $uri = [uri]'https://other.azurewebsites.net/' }
            Http { $uri = [uri]'http://fixture-nme-app.azurewebsites.net/' }
            ChildResource { $id += '/slots/other' }
        }
        $rejected = $false; try { $null = Get-NmeAppRestartPath $id $subscription 'rg-nme-swc-001' $uri } catch { $rejected = $true }
        if (-not $rejected) { throw 'UnselectedRestartTargetFixtureAccepted' }; $checks++
    }
    $calls = @{ count = 0 }
    $expectedRestartPath = $path
    function Invoke-AzRestMethod { param($Method, $Path, $DefaultProfile); if ($Method -cne 'POST' -or $Path -cne $expectedRestartPath) { throw 'WrongRestartTransportFixture' }; $calls.count++; return @{ StatusCode = 200 } }
    $null = Invoke-NmeAppRestart $path @{}
    if ($calls.count -ne 1) { throw 'OneRestartFixtureFailed' }; $checks++
    [pscustomobject]@{ Status = 'OfflineChecksPassed'; ChecksPassed = $checks; CloudActions = 0; ConfigChanges = 0 }
    return
}

if (($Mode -ceq 'Restart' -and -not $OperatorApproved) -or ($OperatorApproved -and $Mode -cne 'Restart')) { throw 'ExplicitSingleAppRestartApprovalRequired' }
. (Join-Path $repo 'identity/Target.ps1')
$settings = Read-LeafPrivateTarget $repo
$context = Get-AzContext
Assert-LeafTargetContext $settings $context
$installation = Get-Content -LiteralPath (Join-Path $repo 'private/nme/installation-plan.json') -Raw | ConvertFrom-Json -AsHashtable
if ($installation.deploymentSucceeded -cne $true -or $installation.resourceGroupName -cnotmatch '^rg-nme-swc-[0-9]{1,3}$') { throw 'ExistingInstalledNmeWorkloadRequired' }
$sites = @(Get-AzResource -ResourceGroupName $installation.resourceGroupName -ResourceType Microsoft.Web/sites -DefaultProfile $context -ErrorAction Stop)
if ($sites.Count -ne 1) { throw 'OneExistingInstalledAppRequired' }
$origin = [uri]$installation.appUrl
$restartPath = Get-NmeAppRestartPath $sites[0].ResourceId $settings.TARGET_SUBSCRIPTION_ID $installation.resourceGroupName $origin
$intentPath = Join-Path $repo ('private/nme/app-restart-' + $AttemptId + '-intent.json')
$resultPath = Join-Path $repo ('private/nme/app-restart-' + $AttemptId + '-result.json')
$git = (Get-Command git.exe -CommandType Application -ErrorAction Stop).Source
foreach ($path in @('.env', $intentPath, $resultPath)) { & $git -C $repo check-ignore --quiet -- $path; if ($LASTEXITCODE -ne 0) { throw 'IgnoredRestartEvidenceRequired' }; $tracked = @(& $git -C $repo ls-files -- $path); if ($LASTEXITCODE -ne 0 -or $tracked.Count) { throw 'RestartEvidenceMustBeUntracked' } }
if ($Mode -ceq 'Preview') { [pscustomobject]@{ Status = 'OneInstalledNmeAppRestartPreview'; RestartRequests = 0; ConfigChanges = 0; HttpsOriginVerified = $true }; return }
. (Join-Path $repo 'nme/ProfileNetbiosApi.ps1')
$sourceHash = (Get-FileHash -LiteralPath $PSCommandPath).Hash
$envHash = (Get-FileHash -LiteralPath (Join-Path $repo '.env')).Hash
if ($Mode -ceq 'Restart') {
    if ((Test-Path -LiteralPath $intentPath) -or (Test-Path -LiteralPath $resultPath)) { throw 'RestartAttemptExistsDoNotResubmit' }
    Save-LeafNmeState @{ schemaVersion = 1; owner = 'nme.app.restart'; appId = $sites[0].ResourceId; sourceSha256 = $sourceHash; privateInputsSha256 = $envHash; intentUtc = [DateTimeOffset]::UtcNow.ToString('o'); restartRequests = 1; configChanges = 0; status = 'RestartIntentDoNotReplay' } $intentPath
    $status = Invoke-NmeAppRestart $restartPath $context
    Save-LeafNmeState @{ schemaVersion = 1; owner = 'nme.app.restart'; appId = $sites[0].ResourceId; sourceSha256 = $sourceHash; privateInputsSha256 = $envHash; restartRequests = 1; acceptedHttpStatus = $status; configChanges = 0; status = 'AcceptedAwaitingHttpsReadback' } $resultPath
    [pscustomobject]@{ Status = 'SingleNmeAppRestartAccepted'; RestartRequests = 1; ConfigChanges = 0; HttpsVerificationRequired = $true }
    return
}
$intent = Get-Content -LiteralPath $intentPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String
if ($intent.owner -cne 'nme.app.restart' -or $intent.appId -ine $sites[0].ResourceId -or $intent.sourceSha256 -cne $sourceHash -or $intent.privateInputsSha256 -cne $envHash) { throw 'ExactOriginalRestartReadbackRequired' }
$probe = Test-NmeAppHttpsReady $origin
if ($probe.Ready) { Save-LeafNmeState @{ schemaVersion = 1; owner = 'nme.app.restart'; appId = $sites[0].ResourceId; sourceSha256 = $sourceHash; privateInputsSha256 = $envHash; restartRequests = 1; verificationRequests = 1; httpStatus = $probe.HttpStatus; verifiedUtc = [DateTimeOffset]::UtcNow.ToString('o'); configChanges = 0; status = 'HttpsRecovered' } $resultPath }
[pscustomobject]@{ Status = $(if ($probe.Ready) { 'NmeHttpsRecovered' } else { 'NmeHttpsRecoveryPending' }); HttpStatus = $probe.HttpStatus; RestartRequests = 0; ConfigChanges = 0; CredentialsOrResponseBodyReturned = $false }