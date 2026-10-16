#requires -Version 7.6
[CmdletBinding()]
param(
    [switch]$Apply,
    [ValidateSet('Pilot', 'All')][string]$Batch = 'Pilot',
    [switch]$PilotClientValidated,
    [switch]$AcceptUnverifiedPilotClients,
    [switch]$CheckOnly
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
. (Join-Path $repo 'identity/Target.ps1')
. (Join-Path $repo 'collaboration/exchange/Addresses.ps1')
$definition = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'desired.json') -Raw | ConvertFrom-Json
$brand = Get-Content -LiteralPath (Join-Path $repo 'branding/brand.json') -Raw | ConvertFrom-Json

function Get-LeafLicenseKeys {
    param($User)
    return @($User.assignedLicenses | ForEach-Object { [string]$_.skuId + ':' + (@($_.disabledPlans | Sort-Object) -join ',') } | Sort-Object)
}

function Get-LeafPilotAcceptanceMode {
    param([bool]$ClientValidated, [bool]$UnverifiedRiskAccepted)
    if ($ClientValidated -and $UnverifiedRiskAccepted) { throw 'Choose verified client acceptance or explicit unverified-client risk acceptance, not both.' }
    if ($ClientValidated) { return 'ClientValidatedByOperator' }
    if ($UnverifiedRiskAccepted) { return 'UnverifiedClientRiskAcceptedByOperator' }
    throw 'Bulk changes require completed pilot client validation or explicit acceptance of the remaining unverified-client risk.'
}

function Resolve-LeafUserPlan {
    param([object[]]$Users, [object[]]$Mailboxes, [object[]]$Recipients, [string[]]$Aliases, [string]$InitialDomain, [string]$Domain, [string]$CompanyName)
    $keys = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $admin = @($Users | Where-Object { $_.displayName -match '(?i)^microsoft[ _-]*(?:365[ _-]*)?admin(?:istrator)?$' })
    if ($admin.Count -ne 1 -or -not $admin[0].userPrincipalName.EndsWith('@' + $InitialDomain, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Resolve exactly one protected Microsoft admin on the initial domain before planning user changes.'
    }
    $rows = [Collections.Generic.List[object]]::new()
    foreach ($alias in $Aliases) {
        if ($alias -notmatch '^[A-Za-z][A-Za-z0-9._-]{0,63}$' -or -not $keys.Add($alias)) { throw 'The managed logical aliases are invalid or duplicated.' }
        $matches = @($Users | Where-Object { $_.userPrincipalName -ieq ($alias + '@' + $InitialDomain) -or $_.userPrincipalName -ieq ($alias + '@' + $Domain) })
        if ($matches.Count -ne 1) { throw 'A managed user is missing or ambiguous. Bootstrap the reviewed persona before retrying; no user is created implicitly.' }
        $user = $matches[0]
        if ($user.id -eq $admin[0].id -or $user.userType -ne 'Member' -or -not $user.accountEnabled -or $user.onPremisesSyncEnabled -or @($user.assignedLicenses).Count -eq 0) {
            throw 'A managed alias resolves to a protected, disabled, synchronized, guest, or unlicensed account.'
        }
        $matchedMailboxes = @($Mailboxes | Where-Object { $_.ExternalDirectoryObjectId -eq $user.id })
        if ($matchedMailboxes.Count -ne 1) { throw 'A managed user does not have one ready Exchange mailbox.' }
        $mailbox = $matchedMailboxes[0]
        if (-not $mailbox.PSObject.Properties['IsDirSynced'] -or -not $mailbox.PSObject.Properties['EmailAddressPolicyEnabled'] -or $null -eq $mailbox.IsDirSynced -or $null -eq $mailbox.EmailAddressPolicyEnabled) {
            throw 'Mailbox synchronization ownership or address-policy status is unknown; no user plan can be inferred.'
        }
        if ($mailbox.RecipientTypeDetails -ne 'UserMailbox' -or $mailbox.IsDirSynced -or $mailbox.EmailAddressPolicyEnabled) {
            throw 'A managed mailbox is not a cloud-owned user mailbox with manually managed email addresses.'
        }
        $address = $alias + '@' + $Domain
        foreach ($recipient in $Recipients) {
            if ($recipient.ExternalDirectoryObjectId -eq $user.id) { continue }
            if (@($recipient.EmailAddresses | Where-Object { $_.ToString() -ieq ('smtp:' + $address) }).Count -gt 0) { throw 'A destination SMTP address belongs to a different recipient.' }
        }
        $patch = @{}
        if ($user.userPrincipalName -ine $address) { $patch.userPrincipalName = $address }
        if ($user.companyName -cne $CompanyName) { $patch.companyName = $CompanyName }
        $rows.Add([pscustomobject]@{
            Key = $alias
            UserId = [string]$user.id
            BeforeUpn = [string]$user.userPrincipalName
            BeforeCompanyName = [string]$user.companyName
            BeforeLicenseKeys = @(Get-LeafLicenseKeys $user)
            MailboxIdentity = [string]$mailbox.Identity
            BeforePrimarySmtp = [string]$mailbox.PrimarySmtpAddress
            BeforeAddresses = @($mailbox.EmailAddresses | ForEach-Object { $_.ToString() })
            DesiredAddress = $address
            GraphPatch = $patch
            MailAction = if ([string]$mailbox.PrimarySmtpAddress -ieq $address) { 'NoChange' } else { 'WouldUpdate' }
        })
    }
    return [pscustomobject]@{ Users = $rows.ToArray(); ProtectedAdmin = $admin[0] }
}

if ($CheckOnly) {
    Test-LeafTargetGuards
    $userId = [guid]::NewGuid().ToString()
    $adminId = [guid]::NewGuid().ToString()
    $license = [pscustomobject]@{ skuId = [guid]::NewGuid().ToString(); disabledPlans = @() }
    $users = @(
        [pscustomobject]@{ id = $userId; displayName = 'Synthetic Employee'; userPrincipalName = 'employee@seed.example.com'; companyName = ''; userType = 'Member'; accountEnabled = $true; onPremisesSyncEnabled = $false; assignedLicenses = @($license) },
        [pscustomobject]@{ id = $adminId; displayName = 'Microsoft Admin'; userPrincipalName = 'admin@seed.example.com'; companyName = ''; userType = 'Member'; accountEnabled = $true; onPremisesSyncEnabled = $false; assignedLicenses = @($license) }
    )
    $mailboxes = @([pscustomobject]@{ ExternalDirectoryObjectId = $userId; Identity = 'synthetic-mailbox'; RecipientTypeDetails = 'UserMailbox'; IsDirSynced = $false; EmailAddressPolicyEnabled = $false; PrimarySmtpAddress = 'employee@seed.example.com'; EmailAddresses = @('SMTP:employee@seed.example.com', 'sip:employee@seed.example.com') })
    $plan = Resolve-LeafUserPlan $users $mailboxes $mailboxes @('employee') 'seed.example.com' 'example.com' 'LeafIT'
    if ($plan.Users.Count -ne 1 -or $plan.Users[0].GraphPatch.Count -ne 2 -or $plan.Users[0].MailAction -ne 'WouldUpdate' -or $plan.ProtectedAdmin.id -ne $adminId) { throw 'A valid user plan was not resolved correctly.' }
    if (-not (Test-LeafAddressPreservation @('SMTP:old@example.com') @('smtp:old@example.com', 'SMTP:new@example.com')) -or (Test-LeafAddressPreservation @('SMTP:old@example.com') @('SMTP:new@example.com'))) { throw 'Old aliases must be retained regardless of SMTP prefix casing.' }
    $beforeAddresses = @('SMTP:old@example.com', 'smtp:employee@example.com', 'sip:old@example.com', 'X500:/o=synthetic/ou=example')
    $updatedAddresses = @(New-LeafPrimaryAddressSet $beforeAddresses 'employee@example.com')
    if (@($updatedAddresses | Where-Object { $_ -cmatch '^SMTP:' }).Count -ne 1 -or $updatedAddresses -cnotcontains 'SMTP:employee@example.com' -or $updatedAddresses -cnotcontains 'smtp:old@example.com' -or -not (Test-LeafAddressPreservation $beforeAddresses $updatedAddresses)) { throw 'Primary SMTP promotion must preserve every prior alias and non-SMTP address.' }
    $duplicateInput = @('SMTP:old@example.com', 'smtp:OLD@example.com', 'smtp:employee@example.com')
    if (@(New-LeafPrimaryAddressSet $duplicateInput 'employee@example.com').Count -ne 2) { throw 'Address promotion must remove case-insensitive duplicates.' }
    $sipBefore = @('SMTP:old@example.com', 'sip:old@example.com', 'X500:/o=synthetic/ou=example')
    $sipAfter = @('smtp:old@example.com', 'SMTP:new@example.com', 'sip:new@example.com', 'X500:/o=synthetic/ou=example')
    if (-not (Test-LeafAddressPreservation $sipBefore $sipAfter 'old@example.com' 'new@example.com') -or (Test-LeafAddressPreservation $sipBefore $sipAfter) -or (Test-LeafAddressPreservation $sipBefore $sipAfter 'different@example.com' 'new@example.com')) { throw 'Only an explicit SIP transition from the prior to desired UPN may replace an old SIP address.' }
    $withoutOldSmtp = @($sipAfter | Where-Object { $_ -ine 'smtp:old@example.com' })
    if (Test-LeafAddressPreservation $sipBefore $withoutOldSmtp 'old@example.com' 'new@example.com') { throw 'Expected SIP alignment must not permit a lost SMTP alias.' }
    $users[0].userPrincipalName = 'employee@example.com'
    $users[0].companyName = 'LeafIT'
    $mailboxes[0].PrimarySmtpAddress = 'employee@example.com'
    $repeat = Resolve-LeafUserPlan $users $mailboxes $mailboxes @('employee') 'seed.example.com' 'example.com' 'LeafIT'
    if ($repeat.Users[0].GraphPatch.Count -ne 0 -or $repeat.Users[0].MailAction -ne 'NoChange') { throw 'A matching user must be a no-op.' }
    foreach ($kind in @('Synced', 'ResourceMailbox', 'UnknownMailboxOwnership', 'Collision', 'ProtectedAdmin', 'MissingUser')) {
        $users[0].onPremisesSyncEnabled = $kind -eq 'Synced'
        $mailboxes[0].RecipientTypeDetails = if ($kind -eq 'ResourceMailbox') { 'RoomMailbox' } else { 'UserMailbox' }
        $mailboxes[0].EmailAddressPolicyEnabled = if ($kind -eq 'UnknownMailboxOwnership') { $null } else { $false }
        $recipients = @($mailboxes)
        if ($kind -eq 'Collision') { $recipients += [pscustomobject]@{ ExternalDirectoryObjectId = [guid]::NewGuid().ToString(); EmailAddresses = @('SMTP:employee@example.com') } }
        $aliases = if ($kind -eq 'ProtectedAdmin') { @('admin') } elseif ($kind -eq 'MissingUser') { @('missing') } else { @('employee') }
        $rejected = $false
        try { $null = Resolve-LeafUserPlan $users $mailboxes $recipients $aliases 'seed.example.com' 'example.com' 'LeafIT' } catch { $rejected = $true }
        if (-not $rejected) { throw ('An unsafe fixture was accepted: ' + $kind) }
    }
    $unique = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($alias in $definition.managedAliases) { if (-not $unique.Add($alias) -or $alias -notmatch '^[A-Za-z][A-Za-z0-9._-]{0,63}$') { throw 'The desired aliases are invalid.' } }
    if (-not $unique.Contains($definition.pilotAlias)) { throw 'The pilot is not in the reviewed catalog.' }
    if ((Get-LeafPilotAcceptanceMode $true $false) -ne 'ClientValidatedByOperator' -or (Get-LeafPilotAcceptanceMode $false $true) -ne 'UnverifiedClientRiskAcceptedByOperator') { throw 'Client validation and unverified-risk acceptance must remain distinct.' }
    foreach ($case in @(@{ Validated = $false; RiskAccepted = $false }, @{ Validated = $true; RiskAccepted = $true })) {
        $rejected = $false
        try { $null = Get-LeafPilotAcceptanceMode $case.Validated $case.RiskAccepted } catch { $rejected = $true }
        if (-not $rejected) { throw 'Missing or contradictory pilot acknowledgement was accepted.' }
    }
    [pscustomobject]@{ OfflineChecksPassed = $true; ManagedLogicalAliases = $unique.Count; OldAliasesPreserved = $true; PilotRequiredBeforeBulk = $true; TenantAccess = $false }
    return
}

$settings = Read-LeafPrivateTarget $repo
$null = & (Join-Path $repo 'collaboration/exchange/Initialize-Session.ps1') -Connect
if (-not (Get-Command Set-Mailbox -ErrorAction Stop).Parameters.ContainsKey('EmailAddresses')) { throw 'The verified Exchange session does not expose the supported EmailAddresses update parameter.' }
$session = $null
$privateRoot = Join-Path $repo 'private/identity/users'
[void][IO.Directory]::CreateDirectory($privateRoot)
$report = [ordered]@{ TimeUtc = [DateTimeOffset]::UtcNow.ToString('o'); Batch = $Batch; ApplyRequested = $Apply.IsPresent; TargetVerified = $false; CompletedKeys = @(); PendingKey = $null; Verified = $false; OperatorPilotClientValidation = $PilotClientValidated.IsPresent; OperatorAcceptedUnverifiedPilotClients = $AcceptUnverifiedPilotClients.IsPresent; PilotAcceptanceMode = 'NotRequiredForPreviewOrNoChange'; Status = 'Started' }

try {
    $session = Connect-LeafTargetGraph $settings
    $report.TargetVerified = $true
    $domains = @(Get-LeafTargetGraphCollection -Settings $settings -Path '/v1.0/domains?$select=id,isInitial,isVerified')
    $initial = @($domains | Where-Object isInitial -eq $true)
    if ($initial.Count -ne 1 -or @($domains | Where-Object { $_.id -eq $settings.TARGET_DNS_ZONE_NAME -and $_.isVerified }).Count -ne 1) { throw 'Initial/custom domain readiness is not verified.' }
    $accepted = @(Get-AcceptedDomain -ErrorAction Stop | Where-Object { $_.DomainName.ToString() -ieq $settings.TARGET_DNS_ZONE_NAME })
    if ($accepted.Count -ne 1 -or $accepted[0].DomainType.ToString() -ne 'Authoritative') { throw 'The destination must be an authoritative accepted Exchange domain.' }
    $users = @(Get-LeafTargetGraphCollection -Settings $settings -Path '/v1.0/users?$select=id,displayName,userPrincipalName,userType,accountEnabled,onPremisesSyncEnabled,companyName,assignedLicenses&$top=999')
    $groups = @(Get-LeafTargetGraphCollection -Settings $settings -Path '/v1.0/groups?$select=id,membershipRule&$top=999')
    $rolesBefore = @(Get-LeafTargetGraphCollection -Settings $settings -Path '/v1.0/roleManagement/directory/roleAssignments?$select=id,principalId,roleDefinitionId,directoryScopeId&$top=999')
    $mailboxes = @(Get-EXOMailbox -ResultSize Unlimited -Properties EmailAddresses, IsDirSynced, EmailAddressPolicyEnabled -ErrorAction Stop)
    $recipients = @(Get-EXORecipient -ResultSize Unlimited -Properties EmailAddresses -ErrorAction Stop)
    $plan = Resolve-LeafUserPlan $users $mailboxes $recipients $definition.managedAliases $initial[0].id $settings.TARGET_DNS_ZONE_NAME $brand.name
    $selected = if ($Batch -eq 'Pilot') { @($plan.Users | Where-Object Key -eq $definition.pilotAlias) } else { @($plan.Users) }
    $pilot = @($plan.Users | Where-Object Key -eq $definition.pilotAlias)
    if ($pilot.Count -ne 1 -or @($rolesBefore | Where-Object principalId -eq $pilot[0].UserId).Count -gt 0) { throw 'The defined pilot must be a uniquely resolved, non-privileged user.' }
    $pending = @($selected | Where-Object { $_.GraphPatch.Count -gt 0 -or $_.MailAction -ne 'NoChange' })
    if ($pending.Count -gt 0 -and @($groups | Where-Object { $_.membershipRule -match '(?i)user\.(userPrincipalName|companyName)' }).Count -gt 0) { throw 'Review dynamic group rules referencing the changed fields before applying; memberships or license assignments must not change implicitly.' }
    $adminMailbox = @($mailboxes | Where-Object ExternalDirectoryObjectId -eq $plan.ProtectedAdmin.id)
    $snapshot = [ordered]@{ TimeUtc = $report.TimeUtc; Batch = $Batch; ResolvedUsers = @($selected); ProtectedAdminUpn = $plan.ProtectedAdmin.userPrincipalName; ProtectedAdminId = $plan.ProtectedAdmin.id; ProtectedAdminMail = @($adminMailbox | ForEach-Object { [string]$_.PrimarySmtpAddress }); RoleAssignments = $rolesBefore }
    [IO.File]::WriteAllText((Join-Path $privateRoot ('plan-' + $Batch.ToLowerInvariant() + '.json')), ($snapshot | ConvertTo-Json -Depth 12), [Text.UTF8Encoding]::new($false))
    if (-not $Apply) {
        $report.Status = 'Preview'
        [pscustomobject]@{ Mode = 'Preview'; CatalogUsers = $plan.Users.Count; SelectedUsers = $selected.Count; MailboxUpdates = @($selected | Where-Object MailAction -ne 'NoChange').Count; UserPropertyUpdates = @($selected | Where-Object { $_.GraphPatch.Count -gt 0 }).Count; ProtectedAdminExcluded = $true; ResourceAccountsExcluded = $true; TenantChanged = $false }
        return
    }
    if ($Batch -eq 'All' -and $pending.Count -gt 0) {
        $pilotFile = Join-Path $privateRoot 'verification-pilot.json'
        $report.PilotAcceptanceMode = Get-LeafPilotAcceptanceMode $PilotClientValidated.IsPresent $AcceptUnverifiedPilotClients.IsPresent
        if (-not (Test-Path -LiteralPath $pilotFile)) { throw 'A verified target-specific pilot API proof is required even when unverified client risk is accepted.' }
        $proof = Get-Content -LiteralPath $pilotFile -Raw | ConvertFrom-Json
        if (-not $proof.Verified -or $proof.ResolvedPilotId -ne $pilot[0].UserId -or $pilot[0].GraphPatch.Count -ne 0 -or $pilot[0].MailAction -ne 'NoChange') { throw 'The saved pilot proof does not match this target and current desired state.' }
    }
    if ($pending.Count -gt 0) {
        $name = 'before-' + $Batch.ToLowerInvariant() + '-' + [DateTimeOffset]::UtcNow.ToString('yyyyMMddTHHmmssfffffffZ') + '.json'
        [IO.File]::WriteAllText((Join-Path $privateRoot $name), ($snapshot | ConvertTo-Json -Depth 12), [Text.UTF8Encoding]::new($false))
    }
    foreach ($row in $selected) {
        $report.PendingKey = $row.Key
        Assert-LeafTargetContext $settings (Get-AzContext)
        if ($row.MailAction -ne 'NoChange') {
            $latestMailbox = @(Get-EXOMailbox -ExternalDirectoryObjectId $row.UserId -Properties EmailAddresses -ErrorAction Stop)
            if ($latestMailbox.Count -ne 1 -or [string]$latestMailbox[0].PrimarySmtpAddress -ine $row.BeforePrimarySmtp -or @(Compare-Object @($row.BeforeAddresses | Sort-Object -CaseSensitive) @($latestMailbox[0].EmailAddresses | ForEach-Object { $_.ToString() } | Sort-Object -CaseSensitive) -CaseSensitive).Count -ne 0) {
                throw 'Mailbox addresses changed after planning; regenerate the plan before replacing the address collection.'
            }
            $addresses = @(New-LeafPrimaryAddressSet $row.BeforeAddresses $row.DesiredAddress)
            Set-Mailbox -Identity $row.MailboxIdentity -EmailAddresses $addresses -ErrorAction Stop
        }
        $mailAfter = @(Get-EXOMailbox -ExternalDirectoryObjectId $row.UserId -Properties EmailAddresses -ErrorAction Stop)
        if ($mailAfter.Count -ne 1 -or [string]$mailAfter[0].PrimarySmtpAddress -ine $row.DesiredAddress -or -not (Test-LeafAddressPreservation $row.BeforeAddresses @($mailAfter[0].EmailAddresses | ForEach-Object { $_.ToString() }))) { throw 'Mailbox readback did not confirm the new primary address and all prior aliases; UPN was not advanced.' }
        if ($row.GraphPatch.Count -gt 0) { $null = Invoke-LeafTargetGraph -Settings $settings -Path ('/v1.0/users/' + $row.UserId) -Method PATCH -Body $row.GraphPatch }
        $userAfter = Invoke-LeafTargetGraph -Settings $settings -Path ('/v1.0/users/' + $row.UserId + '?$select=id,userPrincipalName,companyName,assignedLicenses')
        if ($userAfter.id -ne $row.UserId -or $userAfter.userPrincipalName -ine $row.DesiredAddress -or $userAfter.companyName -cne $brand.name -or @(Compare-Object @($row.BeforeLicenseKeys) @(Get-LeafLicenseKeys $userAfter)).Count -ne 0) { throw 'User readback differs from desired state or existing license assignments.' }
        $mailAfterUpn = @(Get-EXOMailbox -ExternalDirectoryObjectId $row.UserId -Properties EmailAddresses -ErrorAction Stop)
        if ($mailAfterUpn.Count -ne 1 -or [string]$mailAfterUpn[0].PrimarySmtpAddress -ine $row.DesiredAddress -or -not (Test-LeafAddressPreservation $row.BeforeAddresses @($mailAfterUpn[0].EmailAddresses | ForEach-Object { $_.ToString() }) $row.BeforeUpn $row.DesiredAddress)) { throw 'Post-UPN mailbox readback lost an SMTP/other address or has an unexpected SIP transition.' }
        $report.CompletedKeys += $row.Key
    }
    $rolesAfter = @(Get-LeafTargetGraphCollection -Settings $settings -Path '/v1.0/roleManagement/directory/roleAssignments?$select=id,principalId,roleDefinitionId,directoryScopeId&$top=999')
    if (@(Compare-Object @($rolesBefore | Sort-Object id | ConvertTo-Json -Depth 8 -Compress) @($rolesAfter | Sort-Object id | ConvertTo-Json -Depth 8 -Compress)).Count -ne 0) { throw 'Directory role assignments changed during the operation; inspect before proceeding.' }
    $adminAfter = Invoke-LeafTargetGraph -Settings $settings -Path ('/v1.0/users/' + $plan.ProtectedAdmin.id + '?$select=id,userPrincipalName')
    $adminMailAfter = @((Get-EXOMailbox -ResultSize Unlimited -ErrorAction Stop) | Where-Object ExternalDirectoryObjectId -eq $plan.ProtectedAdmin.id | ForEach-Object { [string]$_.PrimarySmtpAddress })
    if ($adminAfter.userPrincipalName -cne $snapshot.ProtectedAdminUpn -or @(Compare-Object @($snapshot.ProtectedAdminMail) $adminMailAfter).Count -ne 0) { throw 'Protected admin identity or primary email changed; stop and inspect.' }
    $report.PendingKey = $null
    $report.Verified = $true
    $report.ResolvedPilotId = $pilot[0].UserId
    $report.Status = if ($pending.Count -eq 0) { 'NoChange' } else { 'AppliedAndVerified' }
    [pscustomobject]@{ Mode = 'Apply'; Batch = $Batch; Status = $report.Status; UsersVerified = $report.CompletedKeys.Count; PriorAliasesAndLicensesPreserved = $true; ProtectedAdminUnchanged = $true; PilotAcceptanceMode = $report.PilotAcceptanceMode; UnverifiedClientsRemainUnverified = $AcceptUnverifiedPilotClients.IsPresent; PilotClientValidationStillRequired = $Batch -eq 'Pilot' }
} catch {
    $report.Status = 'StoppedInspectBeforeRetry'
    throw
} finally {
    $reportName = if ($Apply) { 'verification-' + $Batch.ToLowerInvariant() + '.json' } else { 'preview-' + $Batch.ToLowerInvariant() + '.json' }
    [IO.File]::WriteAllText((Join-Path $privateRoot $reportName), ($report | ConvertTo-Json -Depth 10), [Text.UTF8Encoding]::new($false))
    Disconnect-LeafTargetGraph $session
}