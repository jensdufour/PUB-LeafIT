#requires -Version 7.6
[CmdletBinding()]
param([switch]$Apply, [switch]$CheckOnly, [switch]$ResumeVerifiedStop, [psobject]$PreservedBaseline)

$ErrorActionPreference = 'Stop'
if ($Apply -and $ResumeVerifiedStop) { throw 'Resume verification is read-only; run apply separately after the stop is resolved.' }
$repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
. (Join-Path $repo 'identity/Target.ps1')
$brand = Get-Content -LiteralPath (Join-Path $repo 'branding/brand.json') -Raw | ConvertFrom-Json

function Get-LeafPortalNamePatch {
    param($Current, [string]$Name, [string]$PreviousName)
    $patch = @{}
    if ($Current.isDefaultProfile -and [string]$Current.displayName -cne $Name) { $patch.displayName = $Name }
    if ($PreviousName -and $PreviousName -ine $Name) {
        foreach ($field in @('displayName', 'profileName', 'profileDescription')) {
            $before = [string]$Current.$field
            $after = [regex]::Replace($before, [regex]::Escape($PreviousName), [Text.RegularExpressions.MatchEvaluator]{ param($matchValue) $Name }, [Text.RegularExpressions.RegexOptions]::IgnoreCase)
            if ($after -cne $before -and -not $patch.ContainsKey($field)) { $patch[$field] = $after }
        }
    }
    return $patch
}

function Get-LeafPortalPreservedState {
    param($Current)
    $node = [Text.Json.Nodes.JsonNode]::Parse(($Current | ConvertTo-Json -Depth 30 -Compress))
    foreach ($field in @('@odata.context', 'lastModifiedDateTime', 'displayName', 'profileName', 'profileDescription')) { [void]$node.AsObject().Remove($field) }
    return ,$node
}

function Get-LeafPortalPreservingPayload {
    param($Baseline, [System.Collections.IDictionary]$OwnedFields)
    $payload = @{}
    foreach ($field in @('showConfigurationManagerApps', 'showDisplayNameNextToLogo', 'companyPortalBlockedActions')) {
        if (-not $Baseline.PSObject.Properties[$field]) { throw 'The beta API preservation fields are missing; no name write is safe.' }
        $payload[$field] = $Baseline.$field
    }
    foreach ($field in $OwnedFields.Keys) { $payload[$field] = $OwnedFields[$field] }
    return $payload
}

function Test-LeafPortalAssignments {
    param([object[]]$Before, [object[]]$After)
    if ($null -eq $Before -or $null -eq $After) { return $false }
    $beforeJson = ConvertTo-Json -InputObject @($Before | Sort-Object id) -Depth 20 -Compress
    $afterJson = ConvertTo-Json -InputObject @($After | Sort-Object id) -Depth 20 -Compress
    return [Text.Json.Nodes.JsonNode]::DeepEquals([Text.Json.Nodes.JsonNode]::Parse($beforeJson), [Text.Json.Nodes.JsonNode]::Parse($afterJson))
}

if ($CheckOnly) {
    Test-LeafTargetGuards
    $fixture = [pscustomobject]@{ id = 'synthetic'; displayName = 'Previous Example'; profileName = 'Default'; profileDescription = ''; isDefaultProfile = $true; isFactoryResetDisabled = $true; contactITName = 'Preserve support'; showConfigurationManagerApps = $true; showDisplayNameNextToLogo = $true; companyPortalBlockedActions = @([pscustomobject]@{ platform = 'synthetic' }) }
    $patch = Get-LeafPortalNamePatch $fixture 'LeafIT' 'Previous Example'
    if ($patch.Count -ne 1 -or $patch.displayName -cne 'LeafIT') { throw 'Company Portal must change only the planned brand text.' }
    $after = $fixture.PSObject.Copy()
    $after.displayName = 'LeafIT'
    if ((Get-LeafPortalNamePatch $after 'LeafIT' 'Previous Example').Count -or -not [Text.Json.Nodes.JsonNode]::DeepEquals((Get-LeafPortalPreservedState $fixture), (Get-LeafPortalPreservedState $after))) { throw 'Converged name or preserved-field comparison is invalid.' }
    $after | Add-Member -NotePropertyName '@odata.context' -NotePropertyValue 'synthetic-response-metadata'
    if (-not [Text.Json.Nodes.JsonNode]::DeepEquals((Get-LeafPortalPreservedState $fixture), (Get-LeafPortalPreservedState $after))) { throw 'Response metadata must not be mistaken for a configuration change.' }
    $after.isFactoryResetDisabled = $false
    if ([Text.Json.Nodes.JsonNode]::DeepEquals((Get-LeafPortalPreservedState $fixture), (Get-LeafPortalPreservedState $after))) { throw 'Unrelated enrollment/self-service changes must be detected.' }
    $payload = Get-LeafPortalPreservingPayload $fixture @{ displayName = 'LeafIT' }
    if ($payload.Count -ne 4 -or $payload.ContainsKey('id') -or $payload.displayName -cne 'LeafIT' -or $payload.showConfigurationManagerApps -ne $true -or $payload.showDisplayNameNextToLogo -ne $true -or @($payload.companyPortalBlockedActions).Count -ne 1) { throw 'The beta writer must carry the three observed default-reset fields unchanged with the name update.' }
    $assignment = [pscustomobject]@{ id = 'synthetic-a'; target = @{ groupId = 'synthetic-group' } }
    $otherAssignment = [pscustomobject]@{ id = 'synthetic-b'; target = @{ groupId = 'other-group' } }
    if (-not (Test-LeafPortalAssignments @() @()) -or -not (Test-LeafPortalAssignments @($assignment, $otherAssignment) @($otherAssignment, $assignment))) { throw 'Empty and reordered assignment collections must compare correctly.' }
    if ((Test-LeafPortalAssignments @($assignment) @()) -or (Test-LeafPortalAssignments @($assignment) @($otherAssignment)) -or (Test-LeafPortalAssignments $null @())) { throw 'Missing or changed assignment state must not pass preservation.' }
    [pscustomobject]@{ OfflineChecksPassed = $true; NameOnly = $true; UnrelatedSettingsProtected = $true; ApiVersion = 'beta'; TenantAccess = $false }
    return
}

$settings = Read-LeafPrivateTarget $repo
$privateRoot = Join-Path $repo 'private/endpoint/intune'
$stopPath = Join-Path $privateRoot 'branding-preservation-stop.json'
$stop = if (Test-Path -LiteralPath $stopPath) { Get-Content -LiteralPath $stopPath -Raw | ConvertFrom-Json -DateKind String } else { $null }
if ($Apply -and $stop -and $stop.Status -cne 'ResolvedAfterReadback') {
    throw 'Company Portal writes are paused by a preservation stop. Review the original baseline and obtain an explicit resume decision before clearing this stop.'
}
[void][IO.Directory]::CreateDirectory($privateRoot)
$session = $null
$report = [ordered]@{ TimeUtc = [DateTimeOffset]::UtcNow.ToString('o'); TargetVerified = $false; ApplyRequested = $Apply.IsPresent; ApiVersion = 'beta'; Status = 'Started'; PendingProfileId = $null; ChangedProfileIds = @(); PreservedBaselineRecovery = [bool]$PreservedBaseline; Verified = $false; AssignmentWritesPerformed = $false; DeviceOrPolicyWritesPerformed = $false }

try {
    $session = Connect-LeafTargetGraph $settings
    $report.TargetVerified = $true
    if ($ResumeVerifiedStop) {
        if (-not $stop -or -not $stop.OriginalBaseline -or -not $stop.OriginalBaseline.id) { throw 'The original Portal preservation-stop baseline is required for explicit resume.' }
        $path = '/beta/deviceManagement/intuneBrandingProfiles/' + $stop.OriginalBaseline.id
        $current = Invoke-LeafTargetGraph -Settings $settings -Path $path
        if ($current.id -ne $stop.OriginalBaseline.id -or -not $current.isDefaultProfile -or (Get-LeafPortalNamePatch $current $brand.name $settings.TARGET_PREVIOUS_ORGANIZATION_NAME).Count) { throw 'Current Portal identity or names do not match the reviewed target.' }
        if (-not [Text.Json.Nodes.JsonNode]::DeepEquals((Get-LeafPortalPreservedState $stop.OriginalBaseline), (Get-LeafPortalPreservedState $current))) { throw 'The original unowned Portal settings have not been fully restored.' }
        $assignments = @(Get-LeafTargetGraphCollection -Settings $settings -Path ($path + '/assignments'))
        if ($stop.PSObject.Properties['OriginalAssignments']) {
            $expectedAssignments = @($stop.OriginalAssignments)
        } elseif (@($stop.VerifierErrorClassifications | Where-Object { $_.NullJsonArgument -and $_.AssignmentComparison }).Count -and $assignments.Count -eq 0) {
            $expectedAssignments = @()
        } else {
            throw 'The original assignment proof is unavailable; do not accept a new assignment baseline.'
        }
        if (-not (Test-LeafPortalAssignments $expectedAssignments $assignments)) { throw 'Current Portal assignments do not match the original proof.' }
        $stop.Status = 'ResolvedAfterReadback'
        $stop | Add-Member -NotePropertyName ResumeVerifiedUtc -NotePropertyValue ([DateTimeOffset]::UtcNow.ToString('o')) -Force
        $stop | Add-Member -NotePropertyName OperatorResumeAuthorized -NotePropertyValue $true -Force
        $stop | Add-Member -NotePropertyName OriginalAssignments -NotePropertyValue $expectedAssignments -Force
        [IO.File]::WriteAllText($stopPath, ($stop | ConvertTo-Json -Depth 30), [Text.UTF8Encoding]::new($false))
        $report.Verified = $true
        $report.Status = 'ResolvedAfterReadback'
        [pscustomobject]@{ Mode = 'ReadOnlyResumeVerification'; Status = $report.Status; OriginalSettingsAndAssignmentsVerified = $true; TenantWritesPerformed = $false }
        return
    }
    $profiles = @(Get-LeafTargetGraphCollection -Settings $settings -Path '/beta/deviceManagement/intuneBrandingProfiles')
    if (@($profiles | Where-Object isDefaultProfile -EQ $true).Count -ne 1) { throw 'Exactly one existing default Company Portal profile is required.' }
    if ($PreservedBaseline -and @($profiles | Where-Object { $_.id -eq $PreservedBaseline.id -and $_.isDefaultProfile }).Count -ne 1) { throw 'A preserved baseline must match this target default profile exactly.' }
    $rows = @(foreach ($portalProfile in $profiles) {
        $patch = Get-LeafPortalNamePatch $portalProfile $brand.name $settings.TARGET_PREVIOUS_ORGANIZATION_NAME
        if (-not $portalProfile.isDefaultProfile -and -not $patch.Count) { continue }
        $baseline = $portalProfile
        $recover = [bool]($PreservedBaseline -and $portalProfile.id -eq $PreservedBaseline.id)
        if ($recover) {
            if ([string]$portalProfile.displayName -cne $brand.name) { throw 'Baseline recovery must not overwrite an unrelated current company name.' }
            $oldState = Get-LeafPortalPreservedState $PreservedBaseline
            $currentState = Get-LeafPortalPreservedState $portalProfile
            foreach ($field in @('companyPortalBlockedActions', 'showConfigurationManagerApps', 'showDisplayNameNextToLogo')) { [void]$oldState.AsObject().Remove($field); [void]$currentState.AsObject().Remove($field) }
            if (-not [Text.Json.Nodes.JsonNode]::DeepEquals($oldState, $currentState)) { throw 'Unrelated changes outside the observed beta defaults prevent baseline recovery.' }
            $baseline = $PreservedBaseline
        }
        $path = '/beta/deviceManagement/intuneBrandingProfiles/' + $portalProfile.id
        $assignments = @(Get-LeafTargetGraphCollection -Settings $settings -Path ($path + '/assignments'))
        [pscustomobject]@{ Before = $portalProfile; Preserved = $baseline; Recover = $recover; Patch = $patch; Assignments = $assignments; Path = $path }
    })
    $pending = @($rows | Where-Object { $_.Patch.Count -or $_.Recover })
    if (-not $Apply) {
        $report.Status = 'Preview'
        [pscustomobject]@{ Mode = 'Preview'; Profiles = $rows.Count; NameUpdates = $pending.Count; AssignmentOrPolicyChanges = $false; TenantChanged = $false }
        return
    }
    foreach ($row in $rows) {
        $report.PendingProfileId = $row.Before.id
        if ($row.Patch.Count -or $row.Recover) {
            $snapshot = @{ TimeUtc = $report.TimeUtc; ProfileId = $row.Before.id; Before = $row.Before; PreservationBaseline = $row.Preserved; DesiredOwnedFields = $row.Patch }
            [IO.File]::WriteAllText((Join-Path $privateRoot ('branding-before-' + [guid]::NewGuid().ToString('N') + '.json')), ($snapshot | ConvertTo-Json -Depth 30), [Text.UTF8Encoding]::new($false))
            $latest = Invoke-LeafTargetGraph -Settings $settings -Path $row.Path
            $ownedChanged = @(@('displayName', 'profileName', 'profileDescription') | Where-Object { [string]$row.Before.$_ -cne [string]$latest.$_ })
            if ($ownedChanged.Count -or -not [Text.Json.Nodes.JsonNode]::DeepEquals((Get-LeafPortalPreservedState $row.Before), (Get-LeafPortalPreservedState $latest))) { throw 'Company Portal state changed after planning.' }
            $ownedFields = @{}
            foreach ($field in $row.Patch.Keys) { $ownedFields[$field] = $row.Patch[$field] }
            if ($row.Recover -and -not $ownedFields.ContainsKey('displayName')) { $ownedFields.displayName = [string]$row.Before.displayName }
            $payload = Get-LeafPortalPreservingPayload $row.Preserved $ownedFields
            $null = Invoke-LeafTargetGraph -Settings $settings -Method PATCH -Path $row.Path -Body $payload
            $report.ChangedProfileIds += $row.Before.id
        }
        $after = Invoke-LeafTargetGraph -Settings $settings -Path $row.Path
        foreach ($field in @('displayName', 'profileName', 'profileDescription')) {
            $expected = if ($row.Patch.ContainsKey($field)) { $row.Patch[$field] } else { [string]$row.Before.$field }
            if ([string]$after.$field -cne $expected) { throw 'Company Portal name readback differs from the exact plan.' }
        }
        if (-not [Text.Json.Nodes.JsonNode]::DeepEquals((Get-LeafPortalPreservedState $row.Preserved), (Get-LeafPortalPreservedState $after))) { throw 'An unrelated Company Portal setting changed.' }
        $assignmentsAfter = @(Get-LeafTargetGraphCollection -Settings $settings -Path ($row.Path + '/assignments'))
        if (-not (Test-LeafPortalAssignments $row.Assignments $assignmentsAfter)) { throw 'Company Portal assignments changed during the name update.' }
    }
    $report.PendingProfileId = $null
    $report.Verified = $true
    $report.Status = if ($pending.Count) { 'AppliedAndVerified' } else { 'NoChange' }
    [pscustomobject]@{ Mode = 'Apply'; Status = $report.Status; ProfilesVerified = $rows.Count; ChangedProfiles = $pending.Count; UnrelatedSettingsAndAssignmentsPreserved = $true; DeviceOrPolicyWritesPerformed = $false }
} catch {
    $report.Status = 'StoppedInspectBeforeRetry'
    $report.FailureType = $_.Exception.GetType().Name
    throw 'Company Portal naming stopped; inspect private status and current target state before retrying. No blind write retry is performed.'
} finally {
    $file = if ($Apply) { 'branding-verification.json' } else { 'branding-preview.json' }
    [IO.File]::WriteAllText((Join-Path $privateRoot $file), ($report | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
    Disconnect-LeafTargetGraph $session
}