#requires -Version 7.6
[CmdletBinding()]
param([switch]$Apply, [switch]$Bootstrap, [switch]$ScheduleHostnameRename, [switch]$CheckOnly)

$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
. (Join-Path $repo 'identity/Target.ps1')
if (($Bootstrap -or $ScheduleHostnameRename) -and -not ($Apply -or $CheckOnly)) { throw 'Permission bootstrap and hostname scheduling require explicit apply.' }
$owners = @(
    @{ Name = 'OrganizationName'; Path = 'identity/entra/Deploy-Branding.ps1'; Parameters = @{ NameOnly = $true }; ReadOnly = $true },
    @{ Name = 'EntraSignInBranding'; Path = 'identity/entra/Deploy-Branding.ps1'; Parameters = @{}; ReadOnly = $false },
    @{ Name = 'GroupsAndMail'; Path = 'collaboration/groups/Deploy.ps1'; Parameters = @{}; ReadOnly = $false },
    @{ Name = 'CompanyPortal'; Path = 'endpoint/intune/Deploy-Branding.ps1'; Parameters = @{}; ReadOnly = $false },
    @{ Name = 'SharePoint'; Path = 'collaboration/sharepoint/Deploy.ps1'; Parameters = @{}; ReadOnly = $false },
    @{ Name = 'SubscriptionLabel'; Path = 'infra/Set-SubscriptionName.ps1'; Parameters = @{}; ReadOnly = $false }
)

function Get-LeafNamingSummary {
    param([object[]]$Results, [bool]$ApplyRequested)
    $blocked = @($Results | Where-Object { $_.Status -notin @('NoChange', 'AppliedAndVerified', 'Preview', 'NotRequested') })
    $changed = @($Results | Where-Object Status -EQ 'AppliedAndVerified')
    return [pscustomobject]@{
        Status = if ($blocked.Count) { 'IncompleteWithExplicitBlockers' } elseif (-not $ApplyRequested) { 'Preview' } elseif ($changed.Count) { 'AppliedAndVerified' } else { 'NoChange' }
        AllRequestedSurfacesConverged = $blocked.Count -eq 0 -and $ApplyRequested
        SupportedOwnersChanged = $changed.Count
        BlockedOrUnsupportedSurfaces = $blocked.Count
    }
}

if ($CheckOnly) {
    Test-LeafTargetGuards
    $null = & (Join-Path $PSScriptRoot 'Initialize-Session.ps1') -CheckOnly
    foreach ($owner in $owners) { $null = & (Join-Path $repo $owner.Path) -CheckOnly }
    if (-not (Get-LeafNamingSummary @([pscustomobject]@{ Status = 'NoChange' }) $true).AllRequestedSurfacesConverged) { throw 'A converged owner must be NoChange.' }
    if (-not (Get-LeafNamingSummary @([pscustomobject]@{ Status = 'NoChange' }, [pscustomobject]@{ Status = 'NotRequested' }) $true).AllRequestedSurfacesConverged) { throw 'An unrequested hostname migration must not block the custom-domain workflow.' }
    $blockedFixture = Get-LeafNamingSummary @([pscustomobject]@{ Status = 'NoChange' }, [pscustomobject]@{ Status = 'BlockedMissingReviewedPrefix' }) $true
    if ($blockedFixture.AllRequestedSurfacesConverged -or $blockedFixture.Status -cne 'IncompleteWithExplicitBlockers') { throw 'Blocked surfaces must never be reported as complete.' }
    [pscustomobject]@{ OfflineChecksPassed = $true; ExistingOwnersReused = $owners.Count; FalseCompletionRejected = $true; TenantAccess = $false }
    return
}

$settings = Read-LeafPrivateTarget $repo
Assert-LeafTargetContext $settings (Get-AzContext)
$privateRoot = Join-Path $repo 'private/branding'
[void][IO.Directory]::CreateDirectory($privateRoot)
$report = [ordered]@{ TimeUtc = [DateTimeOffset]::UtcNow.ToString('o'); TargetVerified = $false; ApplyRequested = $Apply.IsPresent; BootstrapRequested = $Bootstrap.IsPresent; HostnameSchedulingRequested = $ScheduleHostnameRename.IsPresent; Status = 'Started'; Results = @(); UntouchedSurfaces = @('ResourceUserAccounts', 'ProtectedAdmin', 'Licenses', 'SecurityPolicies', 'DeviceActions') }

try {
    $connectParameters = @{ Connect = $true }
    if ($Bootstrap) { $connectParameters.Apply = $true }
    $null = & (Join-Path $PSScriptRoot 'Initialize-Session.ps1') @connectParameters
    $report.TargetVerified = $true
    foreach ($owner in $owners) {
        $parameters = $owner.Parameters.Clone()
        if ($Apply -and -not $owner.ReadOnly) { $parameters.Apply = $true }
        if ($owner.Name -eq 'SharePoint' -and $ScheduleHostnameRename) { $parameters.ScheduleHostnameRename = $true }
        try {
            $output = @(& (Join-Path $repo $owner.Path) @parameters)
            $result = @($output | Where-Object { $_.PSObject.Properties['Mode'] } | Select-Object -Last 1)
            if ($result.Count -ne 1) { throw 'The owner did not return one explicit workflow result.' }
            $status = if ($result[0].PSObject.Properties['Status']) { [string]$result[0].Status } else { 'Preview' }
            $report.Results += [pscustomobject]@{ Surface = $owner.Name; Status = $status; Result = $result[0] }
            if ($owner.Name -eq 'SharePoint') { $report.Results += [pscustomobject]@{ Surface = 'SharePointHostname'; Status = [string]$result[0].HostnameStatus } }
        } catch {
            $report.Results += [pscustomobject]@{ Surface = $owner.Name; Status = 'BlockedOrStopped'; FailureType = $_.Exception.GetType().Name }
        }
    }
    $report.Results += [pscustomobject]@{ Surface = 'Microsoft365ThemeAndArbitraryContent'; Status = 'NotImplementedNoFalseCoverage' }
    $summary = Get-LeafNamingSummary $report.Results $Apply.IsPresent
    $report.Status = $summary.Status
    $report.AllRequestedSurfacesConverged = $summary.AllRequestedSurfacesConverged
    [pscustomobject]@{ Mode = if ($Apply) { 'Apply' } else { 'Preview' }; Status = $summary.Status; AllRequestedSurfacesConverged = $summary.AllRequestedSurfacesConverged; SupportedOwnersChanged = $summary.SupportedOwnersChanged; BlockedOrUnsupportedSurfaces = $summary.BlockedOrUnsupportedSurfaces; Results = @($report.Results | Select-Object Surface, Status); ResourceAdminLicenseSecurityOrDeviceChangesPerformed = $false }
} catch {
    $report.Status = 'StoppedAtTargetOrAuthentication'
    $report.FailureType = $_.Exception.GetType().Name
    throw 'Naming workflow stopped at target/authentication preflight. No automatic tenant switch or hidden consent is performed; inspect private workflow status.'
} finally {
    $file = if ($Apply) { 'workflow-verification.json' } else { 'workflow-preview.json' }
    [IO.File]::WriteAllText((Join-Path $privateRoot $file), ($report | ConvertTo-Json -Depth 15), [Text.UTF8Encoding]::new($false))
}