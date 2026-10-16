#requires -Version 7.6
[CmdletBinding()]
param(
    [switch]$Apply,
    [switch]$NamesOnly,
    [switch]$CheckOnly
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
. (Join-Path $repo 'identity/Target.ps1')
. (Join-Path $repo 'collaboration/exchange/Addresses.ps1')
$brand = Get-Content -LiteralPath (Join-Path $repo 'branding/brand.json') -Raw | ConvertFrom-Json

function Convert-LeafGroupBrandText {
    param([AllowNull()][string]$Text, [string]$PreviousName, [string]$Name)
    if ([string]::IsNullOrWhiteSpace($PreviousName) -or [string]::IsNullOrWhiteSpace($Name)) { throw 'Previous and desired brand names are required.' }
    if ($PreviousName -ieq $Name) { return $Text }
    return [regex]::Replace($Text, [regex]::Escape($PreviousName), [Text.RegularExpressions.MatchEvaluator]{ param($matchValue) $Name }, [Text.RegularExpressions.RegexOptions]::IgnoreCase)
}

function Get-LeafGroupMetadataPatch {
    param($Group, [string]$PreviousName, [string]$Name)
    $patch = @{}
    foreach ($field in @('displayName', 'description')) {
        $value = Convert-LeafGroupBrandText ([string]$Group.$field) $PreviousName $Name
        if ($value -cne [string]$Group.$field) { $patch[$field] = $value }
    }
    if ($patch.Count -and ($Group.onPremisesSyncEnabled -or $Group.isAssignableToRole -or ($Group.mailEnabled -and $Group.groupTypes -notcontains 'Unified'))) {
        throw 'A synchronized, role-assignable, or non-Unified mail group requires its own management owner.'
    }
    return $patch
}

function Resolve-LeafGroupMailPlan {
    param($Group, [object[]]$Recipients, [string]$Domain, [string]$PreviousName, [string]$Name)
    if ($Group.groupTypes -notcontains 'Unified' -or $Group.onPremisesSyncEnabled -or $Group.isAssignableToRole) { throw 'Only cloud-owned, non-role-assignable Microsoft 365 groups are supported.' }
    $resolved = @($Recipients | Where-Object { $_.ExternalDirectoryObjectId -eq $Group.id })
    if ($resolved.Count -ne 1 -or $resolved[0].RecipientTypeDetails -ne 'GroupMailbox' -or $null -eq $resolved[0].IsDirSynced -or $resolved[0].IsDirSynced) { throw 'The group does not resolve to one verified cloud-owned Exchange group mailbox.' }
    $recipient = $resolved[0]
    $primary = [string]$recipient.PrimarySmtpAddress
    if ($primary -notmatch '^[^@\s]+@[^@\s]+$' -or [string]$Group.mail -notmatch '^[^@\s]+@[^@\s]+$') { throw 'The existing group primary address is invalid.' }
    $localPart = Convert-LeafGroupBrandText (([string]$Group.mail).Split('@')[0]) $PreviousName $Name
    $address = $localPart + '@' + $Domain
    if ($primary -ine [string]$Group.mail -and $primary -ine $address) { throw 'The Exchange primary address changed outside the reviewed directory address or planned destination.' }
    $alias = Convert-LeafGroupBrandText ([string]$recipient.Alias) $PreviousName $Name
    if ($alias -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$' -or $localPart -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$') { throw 'The desired group alias or SMTP local part requires separate review.' }
    foreach ($other in $Recipients) {
        if ($other.ExternalDirectoryObjectId -eq $Group.id) { continue }
        if ($other.Alias -ieq $alias -or @($other.EmailAddresses | Where-Object { $_.ToString() -ieq ('smtp:' + $address) }).Count) { throw 'A desired group alias or SMTP address belongs to another recipient.' }
    }
    $before = @($recipient.EmailAddresses | ForEach-Object { $_.ToString() })
    $desired = @(New-LeafPrimaryAddressSet $before $address)
    if (-not (Test-LeafAddressPreservation $before $desired)) { throw 'The planned group addresses would lose an existing address.' }
    return [pscustomobject]@{
        Identity = [string]$recipient.Identity
        BeforePrimary = $primary
        BeforeAlias = [string]$recipient.Alias
        BeforeAddresses = $before
        DesiredPrimary = $address
        DesiredAlias = $alias
        DesiredAddresses = $desired
        Action = if ($primary -ieq $address -and [string]$recipient.Alias -ceq $alias) { 'NoChange' } else { 'WouldUpdate' }
    }
}

function Get-LeafGroupLinks {
    param($Settings, [string]$GroupId)
    $links = @{}
    foreach ($kind in @('members', 'owners')) {
        $links[$kind] = @(Get-LeafTargetGraphCollection -Settings $Settings -Path ('/v1.0/groups/' + $GroupId + '/' + $kind + '?$select=id') | ForEach-Object { [string]$_.id } | Sort-Object)
    }
    return $links
}

if ($CheckOnly) {
    Test-LeafTargetGuards
    $groupId = [guid]::NewGuid().ToString()
    $group = [pscustomobject]@{ id = $groupId; displayName = 'Previous Example Staff'; description = 'previous example collaboration'; mail = 'staff@seed.example.com'; mailEnabled = $true; groupTypes = @('Unified'); onPremisesSyncEnabled = $false; isAssignableToRole = $false }
    $patch = Get-LeafGroupMetadataPatch $group 'Previous Example' 'LeafIT'
    if ($patch.Count -ne 2 -or $patch.displayName -cne 'LeafIT Staff' -or $patch.description -cne 'LeafIT collaboration') { throw 'Literal metadata brand replacement failed.' }
    if ((Convert-LeafGroupBrandText 'Seed+Co group' 'Seed+Co' 'LeafIT') -cne 'LeafIT group') { throw 'Brand names must be treated as literal text.' }
    if ((Convert-LeafGroupBrandText 'LeafIT Staff' 'LeafIT' 'LeafIT') -cne 'LeafIT Staff') { throw 'An already named fresh tenant must not require a different legacy brand.' }
    $converged = $group.PSObject.Copy()
    foreach ($field in $patch.Keys) { $converged.$field = $patch[$field] }
    if ((Get-LeafGroupMetadataPatch $converged 'Previous Example' 'LeafIT').Count) { throw 'Converged metadata must be NoChange.' }
    $recipient = [pscustomobject]@{ ExternalDirectoryObjectId = $groupId; Identity = 'synthetic-group'; RecipientTypeDetails = 'GroupMailbox'; IsDirSynced = $false; PrimarySmtpAddress = 'staff@seed.example.com'; Alias = 'staff'; EmailAddresses = @('SMTP:staff@seed.example.com', 'X500:/o=synthetic/ou=example') }
    $mail = Resolve-LeafGroupMailPlan $group @($recipient) 'example.com' 'Previous Example' 'LeafIT'
    if ($mail.Action -ne 'WouldUpdate' -or $mail.DesiredPrimary -cne 'staff@example.com' -or -not (Test-LeafAddressPreservation $recipient.EmailAddresses $mail.DesiredAddresses)) { throw 'Group mail planning or alias preservation failed.' }
    $recipient.PrimarySmtpAddress = $mail.DesiredPrimary
    $recipient.EmailAddresses = $mail.DesiredAddresses
    if ((Resolve-LeafGroupMailPlan $group @($recipient) 'example.com' 'Previous Example' 'LeafIT').Action -ne 'NoChange') { throw 'A converged group mail plan must be NoChange.' }
    foreach ($kind in @('Synced', 'RoleAssignable', 'OtherRecipient', 'UnknownOwnership', 'Collision', 'ChangedAddress')) {
        $group.onPremisesSyncEnabled = $kind -eq 'Synced'
        $group.isAssignableToRole = $kind -eq 'RoleAssignable'
        $recipient.RecipientTypeDetails = if ($kind -eq 'OtherRecipient') { 'UserMailbox' } else { 'GroupMailbox' }
        $recipient.IsDirSynced = if ($kind -eq 'UnknownOwnership') { $null } else { $false }
        $recipient.PrimarySmtpAddress = if ($kind -eq 'ChangedAddress') { 'different@other.example.com' } else { 'staff@example.com' }
        $recipients = @($recipient)
        if ($kind -eq 'Collision') { $recipients += [pscustomobject]@{ ExternalDirectoryObjectId = [guid]::NewGuid().ToString(); Alias = 'other'; EmailAddresses = @('SMTP:staff@example.com') } }
        $rejected = $false
        try { $null = Resolve-LeafGroupMailPlan $group $recipients 'example.com' 'Previous Example' 'LeafIT' } catch { $rejected = $true }
        if (-not $rejected) { throw ('An unsafe group fixture was accepted: ' + $kind) }
    }
    [pscustomobject]@{ OfflineChecksPassed = $true; LiteralNamesOnly = $true; OldAliasesPreserved = $true; UnsafeRecipientsRejected = $true; TenantAccess = $false }
    return
}

$settings = Read-LeafPrivateTarget $repo
if (-not $settings.ContainsKey('TARGET_PREVIOUS_ORGANIZATION_NAME')) { throw 'Set the reviewed TARGET_PREVIOUS_ORGANIZATION_NAME in ignored .env before planning group migration.' }
$previousName = $settings.TARGET_PREVIOUS_ORGANIZATION_NAME
$privateRoot = Join-Path $repo 'private/collaboration/groups'
[void][IO.Directory]::CreateDirectory($privateRoot)
$session = $null
$report = [ordered]@{ TimeUtc = [DateTimeOffset]::UtcNow.ToString('o'); NamesOnly = $NamesOnly.IsPresent; ApplyRequested = $Apply.IsPresent; TargetVerified = $false; Status = 'Started'; Stage = 'Preflight'; PendingGroupId = $null; CompletedGroupIds = @(); Verified = $false }
$select = 'id,displayName,description,mail,mailNickname,mailEnabled,securityEnabled,groupTypes,proxyAddresses,onPremisesSyncEnabled,isAssignableToRole,membershipRule,visibility'

try {
    $session = Connect-LeafTargetGraph $settings
    $report.TargetVerified = $true
    $domains = @(Get-LeafTargetGraphCollection -Settings $settings -Path '/v1.0/domains?$select=id,isInitial,isVerified')
    $initial = @($domains | Where-Object isInitial -EQ $true)
    if ($initial.Count -ne 1 -or @($domains | Where-Object { $_.id -ieq $settings.TARGET_DNS_ZONE_NAME -and $_.isVerified }).Count -ne 1) { throw 'Initial and destination domain readiness is not verified.' }
    $recipients = @()
    if (-not $NamesOnly) {
        $null = & (Join-Path $repo 'collaboration/exchange/Initialize-Session.ps1') -Connect
        foreach ($parameter in @('EmailAddresses', 'Alias')) { if (-not (Get-Command Set-UnifiedGroup -ErrorAction Stop).Parameters.ContainsKey($parameter)) { throw 'The Exchange session does not expose the required group update parameters.' } }
        $unifiedRecipients = @(Get-UnifiedGroup -ResultSize Unlimited -ErrorAction Stop)
        $allRecipients = @(Get-Recipient -ResultSize Unlimited -ErrorAction Stop)
        $unifiedIds = @($unifiedRecipients | ForEach-Object { [string]$_.ExternalDirectoryObjectId })
        $recipients = @($allRecipients | Where-Object { [string]$_.ExternalDirectoryObjectId -notin $unifiedIds }) + $unifiedRecipients
    }
    $report.Stage = 'Plan'
    $groups = @(Get-LeafTargetGraphCollection -Settings $settings -Path ('/v1.0/groups?$select=' + $select))
    $rows = @(foreach ($group in $groups) {
        $patch = Get-LeafGroupMetadataPatch $group $previousName $brand.name
        $managedMail = $group.mailEnabled -and ([string]$group.mail).EndsWith('@' + $initial[0].id, [StringComparison]::OrdinalIgnoreCase)
        if (-not $managedMail -and $group.mailEnabled -and ([string]$group.mail).EndsWith('@' + $settings.TARGET_DNS_ZONE_NAME, [StringComparison]::OrdinalIgnoreCase)) {
            $managedMail = @($group.proxyAddresses | Where-Object { $_ -like ('smtp:*@' + $initial[0].id) }).Count -gt 0
        }
        if (-not $patch.Count -and ($NamesOnly -or -not $managedMail)) { continue }
        $mail = if (-not $NamesOnly -and $managedMail) { Resolve-LeafGroupMailPlan $group $recipients $settings.TARGET_DNS_ZONE_NAME $previousName $brand.name } else { $null }
        [pscustomobject]@{ Before = $group; MetadataPatch = $patch; Mail = $mail; Links = Get-LeafGroupLinks $settings $group.id }
    })
    $pending = @($rows | Where-Object { $_.MetadataPatch.Count -gt 0 -or ($_.Mail -and $_.Mail.Action -ne 'NoChange') })
    $plan = [ordered]@{ TimeUtc = $report.TimeUtc; TargetVerified = $true; NamesOnly = $NamesOnly.IsPresent; Groups = $rows }
    $suffix = if ($NamesOnly) { 'names' } else { 'all' }
    [IO.File]::WriteAllText((Join-Path $privateRoot ('plan-' + $suffix + '.json')), ($plan | ConvertTo-Json -Depth 16), [Text.UTF8Encoding]::new($false))
    if (-not $Apply) {
        $report.Status = 'Preview'
        [pscustomobject]@{ Mode = 'Preview'; Groups = $rows.Count; MetadataUpdates = @($rows | Where-Object { $_.MetadataPatch.Count }).Count; MailUpdates = @($rows | Where-Object { $_.Mail -and $_.Mail.Action -ne 'NoChange' }).Count; TenantChanged = $false }
        return
    }
    if ($pending.Count) {
        $snapshot = 'before-' + $suffix + '-' + [DateTimeOffset]::UtcNow.ToString('yyyyMMddTHHmmssfffffffZ') + '.json'
        [IO.File]::WriteAllText((Join-Path $privateRoot $snapshot), ($plan | ConvertTo-Json -Depth 16), [Text.UTF8Encoding]::new($false))
    }
    foreach ($row in $rows) {
        $report.PendingGroupId = $row.Before.id
        Assert-LeafTargetContext $settings (Get-AzContext)
        if ($row.Mail -and $row.Mail.Action -ne 'NoChange') {
            $report.Stage = 'Mail'
            $latest = @(Get-UnifiedGroup -Identity $row.Mail.Identity -ErrorAction Stop)
            if ($latest.Count -ne 1 -or [string]$latest[0].ExternalDirectoryObjectId -ne $row.Before.id -or $latest[0].IsDirSynced -ne $false -or [string]$latest[0].PrimarySmtpAddress -ine $row.Mail.BeforePrimary -or [string]$latest[0].Alias -cne $row.Mail.BeforeAlias -or (($row.Mail.BeforeAddresses | Sort-Object -CaseSensitive) -join '|') -cne ((@($latest[0].EmailAddresses | ForEach-Object { $_.ToString() }) | Sort-Object -CaseSensitive) -join '|')) { throw 'Exchange ownership or addresses changed after planning.' }
            Set-UnifiedGroup -Identity $row.Mail.Identity -EmailAddresses $row.Mail.DesiredAddresses -Alias $row.Mail.DesiredAlias -ErrorAction Stop
        }
        $report.Stage = 'Metadata'
        $path = '/v1.0/groups/' + $row.Before.id
        $latestGroup = Invoke-LeafTargetGraph -Settings $settings -Path ($path + '?$select=' + $select)
        if ([string]$latestGroup.displayName -cne [string]$row.Before.displayName -or [string]$latestGroup.description -cne [string]$row.Before.description) { throw 'Group metadata changed after planning.' }
        if ($row.MetadataPatch.Count) { $null = Invoke-LeafTargetGraph -Settings $settings -Path $path -Method PATCH -Body $row.MetadataPatch }
        $report.Stage = 'Readback'
        $after = Invoke-LeafTargetGraph -Settings $settings -Path ($path + '?$select=' + $select)
        if ($after.id -ne $row.Before.id -or (Get-LeafGroupMetadataPatch $after $previousName $brand.name).Count) { throw 'Group metadata readback differs from the desired brand.' }
        foreach ($field in @('displayName', 'description')) {
            $expected = if ($row.MetadataPatch.ContainsKey($field)) { $row.MetadataPatch[$field] } else { [string]$row.Before.$field }
            if ([string]$after.$field -cne $expected) { throw 'An owned group property differs from the exact planned value.' }
        }
        foreach ($field in @('groupTypes', 'mailEnabled', 'securityEnabled', 'onPremisesSyncEnabled', 'isAssignableToRole', 'membershipRule', 'visibility')) {
            if (($row.Before.$field | ConvertTo-Json -Compress) -cne ($after.$field | ConvertTo-Json -Compress)) { throw 'An unrelated group setting changed.' }
        }
        $linksAfter = Get-LeafGroupLinks $settings $row.Before.id
        foreach ($kind in @('members', 'owners')) { if (($row.Links[$kind] -join '|') -cne ($linksAfter[$kind] -join '|')) { throw 'Group membership or ownership changed during migration.' } }
        if ($NamesOnly) {
            foreach ($field in @('mail', 'mailNickname', 'proxyAddresses')) { if (($row.Before.$field | ConvertTo-Json -Compress) -cne ($after.$field | ConvertTo-Json -Compress)) { throw 'A name-only migration changed a mail setting.' } }
        } elseif ($row.Mail) {
            $mailAfter = @(Get-UnifiedGroup -Identity $row.Mail.Identity -ErrorAction Stop)
            if ($mailAfter.Count -ne 1 -or [string]$mailAfter[0].ExternalDirectoryObjectId -ne $row.Before.id -or [string]$mailAfter[0].PrimarySmtpAddress -ine $row.Mail.DesiredPrimary -or [string]$mailAfter[0].Alias -ine $row.Mail.DesiredAlias -or -not (Test-LeafAddressPreservation $row.Mail.BeforeAddresses @($mailAfter[0].EmailAddresses | ForEach-Object { $_.ToString() }))) { throw 'Exchange readback did not preserve aliases or confirm the desired group address.' }
        }
        $report.CompletedGroupIds += $row.Before.id
    }
    $report.PendingGroupId = $null
    $report.Stage = 'Complete'
    $report.Verified = $true
    $report.Status = if ($pending.Count) { 'AppliedAndVerified' } else { 'NoChange' }
    [pscustomobject]@{ Mode = 'Apply'; Status = $report.Status; GroupsVerified = $rows.Count; ChangedGroups = $pending.Count; MembershipsAndOwnersPreserved = $true; PriorAliasesPreserved = $true; ResourceAccountsChanged = $false; TeamsClientAppearanceVerified = $false }
} catch {
    $report.Status = 'StoppedInspectBeforeRetry'
    $report.FailureType = $_.Exception.GetType().Name
    throw 'Group migration stopped. Inspect the private status and current target state before retrying; no automatic rollback or blind write retry is performed.'
} finally {
    $suffix = if ($NamesOnly) { 'names' } else { 'all' }
    $kind = if ($Apply) { 'verification-' } else { 'preview-' }
    [IO.File]::WriteAllText((Join-Path $privateRoot ($kind + $suffix + '.json')), ($report | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
    Disconnect-LeafTargetGraph $session
}