#requires -Version 7.6
[CmdletBinding()]
param(
    [switch]$OpenSignIn,
    [switch]$CheckOnly
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
. (Join-Path $repo 'identity/Target.ps1')
$definition = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'desired.json') -Raw | ConvertFrom-Json
$brand = Get-Content -LiteralPath (Join-Path $repo 'branding/brand.json') -Raw | ConvertFrom-Json

function New-LeafPilotPreflightReport {
    param([System.Collections.IDictionary]$Checks)
    if ($Checks.Count -eq 0 -or @($Checks.Values | Where-Object { $_ -isnot [bool] }).Count -gt 0) { throw 'Pilot server checks must be explicit Boolean results.' }
    return [ordered]@{
        TimeUtc = [DateTimeOffset]::UtcNow.ToString('o')
        ValidationType = 'ReadOnlyServerPreflight'
        ServerChecks = $Checks
        ServerPreflightPassed = @($Checks.Values | Where-Object { -not $_ }).Count -eq 0
        InteractivePilotSignInVerified = $false
        OutlookSendReceiveVerified = $false
        TeamsClientVerified = $false
        OneDriveClientVerified = $false
        MobileClientVerified = $false
        PilotClientValidated = $false
        BulkApplyAuthorizedByThisCheck = $false
        SignInOpenedInEdgeBeta = $false
    }
}

if ($CheckOnly) {
    Test-LeafTargetGuards
    $ready = New-LeafPilotPreflightReport @{ IdentityMatches = $true; MailboxMatches = $true }
    $blocked = New-LeafPilotPreflightReport @{ IdentityMatches = $true; MailboxMatches = $false }
    if (-not $ready.ServerPreflightPassed -or $blocked.ServerPreflightPassed -or $ready.PilotClientValidated -or $ready.BulkApplyAuthorizedByThisCheck) { throw 'Server metadata must never be treated as completed pilot client validation.' }
    $rejected = $false
    try { $null = New-LeafPilotPreflightReport @{ UnknownState = $null } } catch { $rejected = $true }
    if (-not $rejected) { throw 'Unknown server readiness must not be treated as success.' }
    if (@($definition.managedAliases | Where-Object { $_ -ieq $definition.pilotAlias }).Count -ne 1) { throw 'The pilot must be a unique managed logical alias.' }
    [pscustomobject]@{ OfflineChecksPassed = $true; ServerSuccessCannotAuthorizeBulk = $true; TenantAccess = $false }
    return
}

$settings = Read-LeafPrivateTarget $repo
$null = & (Join-Path $repo 'collaboration/exchange/Initialize-Session.ps1') -Connect
$proofPath = Join-Path $repo 'private/identity/users/verification-pilot.json'
if (-not (Test-Path -LiteralPath $proofPath)) { throw 'Apply and verify the scoped pilot before testing clients.' }
$proof = Get-Content -LiteralPath $proofPath -Raw | ConvertFrom-Json
if (-not $proof.Verified -or [string]::IsNullOrWhiteSpace($proof.ResolvedPilotId)) { throw 'The applied pilot proof is incomplete.' }
$casCommand = Get-Command Get-EXOCASMailbox -ErrorAction Stop
if (-not $casCommand.Parameters.ContainsKey('ExternalDirectoryObjectId') -or -not $casCommand.Parameters.ContainsKey('Properties')) { throw 'The current Exchange session does not expose the required read-only client-settings query.' }
$session = $null
try {
    $session = Connect-LeafTargetGraph $settings
    $expectedAddress = $definition.pilotAlias + '@' + $settings.TARGET_DNS_ZONE_NAME
    $users = @(Get-LeafTargetGraphCollection -Settings $settings -Path '/v1.0/users?$select=id,userPrincipalName,companyName,accountEnabled,assignedLicenses&$top=999' | Where-Object { $_.userPrincipalName -ieq $expectedAddress })
    if ($users.Count -ne 1 -or $users[0].id -ne $proof.ResolvedPilotId) { throw 'The pilot identity is absent, ambiguous, or different from this target apply proof.' }
    $mailboxes = @(Get-EXOMailbox -ExternalDirectoryObjectId $users[0].id -Properties EmailAddresses -ErrorAction Stop)
    $clients = @(Get-EXOCASMailbox -ExternalDirectoryObjectId $users[0].id -Properties OWAEnabled, MAPIEnabled, ActiveSyncEnabled -ErrorAction Stop)
    if ($mailboxes.Count -ne 1 -or $clients.Count -ne 1) { throw 'Pilot mailbox or client-settings readback is absent or ambiguous.' }
    if ($null -eq $clients[0].OWAEnabled) { throw 'Pilot Outlook on the web availability is unknown.' }
    $checks = [ordered]@{
        ExactAppliedPilotResolved = $true
        PilotAccountEnabled = $users[0].accountEnabled -eq $true
        PilotCompanyNameMatches = $users[0].companyName -ceq $brand.name
        PilotRetainsAssignedLicense = @($users[0].assignedLicenses).Count -gt 0
        PrimarySmtpMatchesUpn = [string]$mailboxes[0].PrimarySmtpAddress -ieq $expectedAddress
        OutlookOnTheWebEnabled = $clients[0].OWAEnabled -eq $true
        PilotApplyReadbackVerified = $proof.Verified -eq $true
    }
    $report = New-LeafPilotPreflightReport $checks
    $report.MapiEnabled = if ($null -eq $clients[0].MAPIEnabled) { $null } else { [bool]$clients[0].MAPIEnabled }
    $report.ActiveSyncEnabled = if ($null -eq $clients[0].ActiveSyncEnabled) { $null } else { [bool]$clients[0].ActiveSyncEnabled }
    if ($OpenSignIn -and $report.ServerPreflightPassed) {
        $candidates = @(
            (Join-Path ${env:ProgramFiles(x86)} 'Microsoft/Edge Beta/Application/msedge.exe'),
            (Join-Path $env:ProgramFiles 'Microsoft/Edge Beta/Application/msedge.exe'),
            (Join-Path $env:LOCALAPPDATA 'Microsoft/Edge Beta/Application/msedge.exe')
        )
        $browser = $candidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
        if (-not $browser) { throw 'Microsoft Edge Beta is required; no default browser or security-setting fallback is permitted.' }
        $signIn = 'https://outlook.office.com/owa/?login_hint=' + [uri]::EscapeDataString($expectedAddress)
        $null = Start-Process -FilePath $browser -ArgumentList @('--inprivate', '--new-window', $signIn) -ErrorAction Stop
        $report.SignInOpenedInEdgeBeta = $true
    }
    $evidencePath = Join-Path $repo 'private/identity/users/pilot-client-preflight.json'
    [IO.File]::WriteAllText($evidencePath, ($report | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
    [pscustomobject]@{ ServerPreflightPassed = $report.ServerPreflightPassed; OutlookOnTheWebEnabled = $checks.OutlookOnTheWebEnabled; SignInOpenedInEdgeBeta = $report.SignInOpenedInEdgeBeta; PilotClientValidated = $false; BulkApplyAuthorized = $false; NextAction = 'Complete pilot sign-in and MFA directly in the isolated Edge Beta window, then validate mail, Teams, OneDrive and mobile clients.' }
} finally { Disconnect-LeafTargetGraph $session }