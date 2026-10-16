#requires -Version 7.6
[CmdletBinding()]
param([switch]$Apply, [switch]$ScheduleHostnameRename, [switch]$CheckOnly)

$ErrorActionPreference = 'Stop'
if ($ScheduleHostnameRename -and -not $Apply) { throw 'Scheduling a hostname rename requires explicit apply; default preview never schedules.' }
$repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
. (Join-Path $repo 'identity/Target.ps1')
$brand = Get-Content -LiteralPath (Join-Path $repo 'branding/brand.json') -Raw | ConvertFrom-Json

function Get-LeafSharePointAdminUrl {
    param([string]$RootUrl)
    $uri = [uri]$RootUrl
    $hostMatch = [regex]::Match($uri.Host, '^(?<prefix>[a-z0-9][a-z0-9-]*)\.sharepoint\.com$')
    if ($uri.Scheme -ne 'https' -or $uri.Port -ne 443 -or $uri.UserInfo -or -not $hostMatch.Success -or $hostMatch.Groups['prefix'].Value -match '-(?:admin|my)$') { throw 'A verified ordinary SharePoint Online root URL is required.' }
    return 'https://' + $hostMatch.Groups['prefix'].Value + '-admin.sharepoint.com'
}

function Get-LeafSharePointHostnameGate {
    param([string]$CurrentHost, [string]$Prefix, [string]$ScheduledAt, [bool]$DestinationVerified)
    if (-not $Prefix) { return 'NotRequested' }
    if ($CurrentHost -ieq ($Prefix + '.sharepoint.com')) { return 'NoChange' }
    if (-not $DestinationVerified) { return 'BlockedDestinationDomainNotVerified' }
    if (-not $ScheduledAt) { return 'BlockedMissingMaintenanceWindow' }
    $scheduled = [DateTimeOffset]::Parse($ScheduledAt)
    if ($scheduled -le [DateTimeOffset]::UtcNow.AddHours(24) -or $scheduled -gt [DateTimeOffset]::UtcNow.AddDays(30)) { return 'BlockedScheduleOutsideNativeWindow' }
    return 'RequiresNativeValidation'
}

if ($CheckOnly) {
    Test-LeafTargetGuards
    if ((Get-LeafSharePointAdminUrl 'https://seed.sharepoint.com/') -cne 'https://seed-admin.sharepoint.com') { throw 'Admin URL derivation failed.' }
    foreach ($url in @('http://seed.sharepoint.com/', 'https://seed.sharepoint.com.example.com/', 'https://seed-my.sharepoint.com/', 'https://user@seed.sharepoint.com/')) {
        $rejected = $false
        try { $null = Get-LeafSharePointAdminUrl $url } catch { $rejected = $true }
        if (-not $rejected) { throw 'An unsafe SharePoint target was accepted.' }
    }
    if ((Get-LeafSharePointHostnameGate 'seed.sharepoint.com' '' '' $false) -cne 'NotRequested' -or (Get-LeafSharePointHostnameGate 'leafit.sharepoint.com' 'leafit' '' $false) -cne 'NoChange' -or (Get-LeafSharePointHostnameGate 'seed.sharepoint.com' 'leafit' '' $true) -cne 'BlockedMissingMaintenanceWindow') { throw 'An optional hostname migration must be distinct from a requested migration with missing inputs.' }
    if ((Get-LeafSharePointHostnameGate 'seed.sharepoint.com' 'leafit' ([DateTimeOffset]::UtcNow.AddHours(2).ToString('o')) $true) -cne 'BlockedScheduleOutsideNativeWindow') { throw 'An invalid maintenance window must not pass.' }
    [pscustomobject]@{ OfflineChecksPassed = $true; TargetHostValidated = $true; MissingInputsBlocked = $true; NativeModuleVersion = '16.0.27709.12000'; TenantAccess = $false }
    return
}

$settings = Read-LeafPrivateTarget $repo
Assert-LeafTargetContext $settings (Get-AzContext)
if (-not $settings.TARGET_NAMING_CLIENT_ID -or -not $settings.TARGET_NAMING_CERTIFICATE_THUMBPRINT) { throw 'The reviewed naming certificate bootstrap is required.' }
$privateRoot = Join-Path $repo 'private/collaboration/sharepoint'
[void][IO.Directory]::CreateDirectory($privateRoot)
$report = [ordered]@{ TimeUtc = [DateTimeOffset]::UtcNow.ToString('o'); TargetVerified = $false; ApplyRequested = $Apply.IsPresent; Stage = 'Preflight'; Status = 'Started'; SitesRead = 0; ChangedTitles = 0; HostnameStatus = 'NotRead'; HostnameScheduleSubmitted = $false; NativeModuleVersion = '16.0.27709.12000'; Verified = $false }
$session = $null

try {
    $session = Connect-LeafTargetGraph $settings
    $root = Invoke-LeafTargetGraph -Settings $settings -Path '/v1.0/sites/root?$select=id,webUrl'
    if (-not $root.id -or -not $root.webUrl) { throw 'The current target SharePoint root was not discovered.' }
    $adminUrl = Get-LeafSharePointAdminUrl $root.webUrl
    $module = @(Get-Module -ListAvailable -Name Microsoft.Online.SharePoint.PowerShell | Where-Object Version -EQ ([version]$report.NativeModuleVersion))
    if ($module.Count -ne 1) { throw 'Install the documented pinned native SharePoint module for this execution account.' }
    Import-Module -Name $module[0].Path -UseWindowsPowerShell -ErrorAction Stop -WarningAction SilentlyContinue
    $report.Stage = 'NativeCertificateConnection'
    $compatibilitySessions = @(Get-PSSession -Name WinPSCompatSession -ErrorAction Stop)
    if ($compatibilitySessions.Count -ne 1) { throw 'The native SharePoint compatibility session is ambiguous.' }
    $null = Invoke-Command -Session $compatibilitySessions[0] -ArgumentList $adminUrl, $settings.TARGET_NAMING_CLIENT_ID, $settings.TARGET_TENANT_ID, $settings.TARGET_NAMING_CERTIFICATE_THUMBPRINT -ScriptBlock {
        param($AdminUrl, $ClientId, $TenantId, $Thumbprint)
        $certificate = Get-Item -LiteralPath ('Cert:/CurrentUser/My/' + $Thumbprint) -ErrorAction Stop
        if (-not $certificate.HasPrivateKey -or $certificate.NotAfter -le [DateTime]::Now.AddMinutes(5)) { throw 'The current-user native naming certificate is unavailable or expired.' }
        Connect-SPOService -Url $AdminUrl -ClientId $ClientId -TenantId $TenantId -Certificate $certificate -ErrorAction Stop
    } -ErrorAction Stop
    $report.Stage = 'NativeInventory'
    $tenant = Get-SPOTenant -ErrorAction Stop
    if ($tenant.PSObject.Properties['TenantId'] -and $tenant.TenantId -and [string]$tenant.TenantId -ne $settings.TARGET_TENANT_ID) { throw 'Native SharePoint tenant readback differs from the target.' }
    $sites = @(Get-SPOSite -Limit All -IncludePersonalSite $true -ErrorAction Stop)
    $report.TargetVerified = $true
    $report.SitesRead = $sites.Count
    $rows = @(foreach ($site in $sites) {
        if (-not $settings.TARGET_PREVIOUS_ORGANIZATION_NAME -or $settings.TARGET_PREVIOUS_ORGANIZATION_NAME -ieq $brand.name) { continue }
        $title = [regex]::Replace([string]$site.Title, [regex]::Escape($settings.TARGET_PREVIOUS_ORGANIZATION_NAME), [Text.RegularExpressions.MatchEvaluator]{ param($matchValue) $brand.name }, [Text.RegularExpressions.RegexOptions]::IgnoreCase)
        if ($title -cne [string]$site.Title) {
            if ([string]$site.LockState -ne 'Unlock') { throw 'A matching locked site requires explicit owner review; no unlock is performed.' }
            [pscustomobject]@{ Url = [string]$site.Url; BeforeTitle = [string]$site.Title; DesiredTitle = $title; GroupId = [string]$site.GroupId; Template = [string]$site.Template; LockState = [string]$site.LockState }
        }
    })
    $destinationVerified = $false
    if ($settings.TARGET_SHAREPOINT_DOMAIN_PREFIX) {
        $domains = @(Get-LeafTargetGraphCollection -Settings $settings -Path '/v1.0/domains?$select=id,isVerified')
        $destinationVerified = @($domains | Where-Object { $_.id -ieq ($settings.TARGET_SHAREPOINT_DOMAIN_PREFIX + '.onmicrosoft.com') -and $_.isVerified }).Count -eq 1
    }
    $report.HostnameStatus = Get-LeafSharePointHostnameGate ([uri]$root.webUrl).Host $settings.TARGET_SHAREPOINT_DOMAIN_PREFIX $settings.TARGET_SHAREPOINT_RENAME_AT $destinationVerified
    [IO.File]::WriteAllText((Join-Path $privateRoot 'plan.json'), (@{ TimeUtc = $report.TimeUtc; RootSiteId = $root.id; TitleChanges = $rows; HostnameStatus = $report.HostnameStatus } | ConvertTo-Json -Depth 10), [Text.UTF8Encoding]::new($false))
    if ($Apply) {
        $report.Stage = 'Titles'
        foreach ($row in $rows) {
            Assert-LeafTargetContext $settings (Get-AzContext)
            $before = Get-SPOSite -Identity $row.Url -ErrorAction Stop
            if ([string]$before.Title -cne $row.BeforeTitle -or [string]$before.GroupId -cne $row.GroupId -or [string]$before.LockState -cne $row.LockState) { throw 'A site changed after title planning.' }
            [IO.File]::WriteAllText((Join-Path $privateRoot ('title-before-' + [guid]::NewGuid().ToString('N') + '.json')), ($row | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
            Set-SPOSite -Identity $row.Url -Title $row.DesiredTitle -ErrorAction Stop
            $after = Get-SPOSite -Identity $row.Url -ErrorAction Stop
            if ([string]$after.Title -cne $row.DesiredTitle -or [string]$after.Url -cne $row.Url -or [string]$after.GroupId -cne $row.GroupId -or [string]$after.Template -cne $row.Template -or [string]$after.LockState -cne $row.LockState) { throw 'Site title or preserved identity/settings differ from the plan.' }
            $report.ChangedTitles++
        }
    }
    if ($report.HostnameStatus -eq 'RequiresNativeValidation') {
        $report.Stage = 'NativeHostnamePreview'
        $scheduled = [DateTimeOffset]::Parse($settings.TARGET_SHAREPOINT_RENAME_AT)
        $null = Start-SPOTenantRename -DomainName $settings.TARGET_SHAREPOINT_DOMAIN_PREFIX -ScheduledDateTime $scheduled.LocalDateTime -WhatIf -ErrorAction Stop
        $report.HostnameStatus = 'NativePreviewOnly'
        if ($ScheduleHostnameRename) {
            $intentPath = Join-Path $privateRoot 'hostname-intent.json'
            if (Test-Path -LiteralPath $intentPath) {
                $report.HostnameStatus = 'PendingReadbackNoResubmit'
            } else {
                $intent = @{ TimeUtc = $report.TimeUtc; SourceRootId = $root.id; DestinationPrefix = $settings.TARGET_SHAREPOINT_DOMAIN_PREFIX; ScheduledAt = $settings.TARGET_SHAREPOINT_RENAME_AT; Status = 'IntentBeforeNativeSubmission' }
                [IO.File]::WriteAllText($intentPath, ($intent | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
                $report.Stage = 'NativeHostnameSchedule'
                $null = Start-SPOTenantRename -DomainName $settings.TARGET_SHAREPOINT_DOMAIN_PREFIX -ScheduledDateTime $scheduled.LocalDateTime -Confirm:$false -ErrorAction Stop
                $report.HostnameScheduleSubmitted = $true
                $report.HostnameStatus = 'SubmittedNotConverged'
            }
        }
    } elseif ($ScheduleHostnameRename -and $report.HostnameStatus -ne 'NoChange') { throw 'Hostname inputs/domain readiness do not pass the native scheduling gates.' }
    $report.Verified = $true
    $report.Status = if (-not $Apply) { 'Preview' } elseif ($report.ChangedTitles) { 'AppliedAndVerified' } else { 'NoChange' }
    [pscustomobject]@{ Mode = if ($Apply) { 'Apply' } else { 'Preview' }; Status = $report.Status; NativeTargetVerified = $true; SitesRead = $report.SitesRead; PendingTitleChanges = if ($Apply) { 0 } else { $rows.Count }; ChangedTitles = $report.ChangedTitles; HostnameStatus = $report.HostnameStatus; HostnameScheduled = $report.HostnameScheduleSubmitted; UrlsOrMembershipsChangedByTitleWriter = $false }
} catch {
    $report.Status = 'BlockedOrStopped'
    $report.FailureType = $_.Exception.GetType().Name
    throw ('Native SharePoint automation stopped at ' + $report.Stage + '. Inspect private status; do not retry a scheduling submission blindly. Private target details suppressed.')
} finally {
    $file = if ($Apply) { 'verification.json' } else { 'preview.json' }
    [IO.File]::WriteAllText((Join-Path $privateRoot $file), ($report | ConvertTo-Json -Depth 10), [Text.UTF8Encoding]::new($false))
    Disconnect-LeafTargetGraph $session
}