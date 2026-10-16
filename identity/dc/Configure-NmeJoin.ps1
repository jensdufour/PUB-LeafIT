[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', 'JoinPassword', Justification = 'Azure Run Command protectedParameters bind strings; the caller uses a secure ARM parameter and DPAPI at rest, and the value is never printed.')]
[CmdletBinding()]
param(
    [ValidateSet('Preview', 'Apply', 'Verify', 'CheckOnly')][string]$Mode = 'Preview',
    [string]$DomainName,
    [string]$AccountName = 'svc-nme-join',
    [string]$ComputerOuName = 'NMe-Computers',
    [string]$OrganizationName = 'LeafIT',
    [string]$JoinPassword
)

$ErrorActionPreference = 'Stop'

function Get-NmeJoinAccessRules([Security.Principal.SecurityIdentifier]$Sid) {
    $computerClass = [guid]'bf967a86-0de6-11d0-a285-00aa003049e2'
    $allow = [Security.AccessControl.AccessControlType]::Allow
    $descendants = [DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents
    [DirectoryServices.ActiveDirectoryAccessRule]::new($Sid, ([DirectoryServices.ActiveDirectoryRights]::CreateChild -bor [DirectoryServices.ActiveDirectoryRights]::DeleteChild), $allow, $computerClass, [DirectoryServices.ActiveDirectorySecurityInheritance]::All)
    [DirectoryServices.ActiveDirectoryAccessRule]::new($Sid, [DirectoryServices.ActiveDirectoryRights]::GenericRead, $allow, [guid]::Empty, $descendants, $computerClass)
    [DirectoryServices.ActiveDirectoryAccessRule]::new($Sid, [DirectoryServices.ActiveDirectoryRights]::ExtendedRight, $allow, [guid]'00299570-246d-11d0-a768-00aa006e0529', $descendants, $computerClass)
    [DirectoryServices.ActiveDirectoryAccessRule]::new($Sid, ([DirectoryServices.ActiveDirectoryRights]::ReadProperty -bor [DirectoryServices.ActiveDirectoryRights]::WriteProperty), $allow, [guid]'4c164200-20c0-11d0-a768-00aa006e0529', $descendants, $computerClass)
    foreach ($right in @('72e39547-7b18-11d1-adef-00c04fd8d5cd', 'f3a64788-5306-11d1-a9c5-0000f80367c1')) {
        [DirectoryServices.ActiveDirectoryAccessRule]::new($Sid, [DirectoryServices.ActiveDirectoryRights]::Self, $allow, [guid]$right, $descendants, $computerClass)
    }
}

function Test-NmeJoinAccessRule($Actual, $Expected) {
    return $Actual.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -eq $Expected.IdentityReference.Value -and $Actual.AccessControlType -eq $Expected.AccessControlType -and $Actual.ActiveDirectoryRights -eq $Expected.ActiveDirectoryRights -and $Actual.ObjectType -eq $Expected.ObjectType -and $Actual.InheritedObjectType -eq $Expected.InheritedObjectType -and $Actual.InheritanceType -eq $Expected.InheritanceType
}

if ($Mode -eq 'CheckOnly') {
    Add-Type -AssemblyName System.DirectoryServices
    $sid = [Security.Principal.SecurityIdentifier]::new('S-1-5-21-1000-1000-1000-1001')
    $rules = @(Get-NmeJoinAccessRules $sid)
    if ($rules.Count -ne 6 -or @($rules | Where-Object { ($_.ActiveDirectoryRights -band [DirectoryServices.ActiveDirectoryRights]::GenericAll) -eq [DirectoryServices.ActiveDirectoryRights]::GenericAll }).Count) { throw 'Join delegation must remain narrow and computer-scoped.' }
    foreach ($rule in $rules) {
        if (-not (Test-NmeJoinAccessRule $rule $rule) -or $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { throw 'The join delegation comparison check failed.' }
    }
    [pscustomobject]@{ OfflineChecksPassed = $true; DelegatedRuleCount = $rules.Count; DirectoryCallsMade = $false } | ConvertTo-Json -Compress
    return
}

try {
    if ($DomainName -notmatch '^(?=.{1,253}$)[A-Za-z0-9][A-Za-z0-9.-]+\.[A-Za-z]{2,}$' -or $AccountName -notmatch '^svc-[a-z0-9-]{1,16}$' -or $AccountName.Length -gt 20 -or $ComputerOuName -notmatch '^[A-Za-z][A-Za-z0-9 -]{1,62}$') { throw 'Invalid join configuration.' }
    Import-Module ActiveDirectory -WarningAction SilentlyContinue
    $system = Get-CimInstance Win32_ComputerSystem
    $domain = Get-ADDomain -Server localhost
    if ($system.DomainRole -lt 4 -or $system.Domain -ine $DomainName -or $domain.DNSRoot -ine $DomainName) { throw 'The executing guest is not a DC for the selected domain.' }
    $marker = 'Managed by LeafIT identity automation; NMe computer join only.'
    $ouDn = 'OU=' + $ComputerOuName + ',' + $domain.DistinguishedName
    $accountUpn = $AccountName + '@' + $DomainName
    $ou = @(Get-ADOrganizationalUnit -Server localhost -Filter { DistinguishedName -eq $ouDn } -Properties Description)
    $account = @(Get-ADUser -Server localhost -Filter { SamAccountName -eq $AccountName } -Properties Description, MemberOf, AdminCount, PrimaryGroupId, AccountNotDelegated, PasswordNeverExpires, UserPrincipalName)
    if ($ou.Count -gt 1 -or $account.Count -gt 1 -or ($ou.Count -eq 1 -and $ou[0].Description -cne $marker) -or ($account.Count -eq 1 -and ($account[0].Description -cne $marker -or $account[0].UserPrincipalName -ine $accountUpn -or @($account[0].MemberOf).Count -gt 0 -or $account[0].AdminCount -eq 1 -or $account[0].PrimaryGroupId -ne 513))) { throw 'Existing AD objects are ambiguous, privileged, or not owned by this join definition.' }
    $changed = $false
    if ($Mode -eq 'Apply') {
        if ([string]::IsNullOrWhiteSpace($JoinPassword) -or $JoinPassword.Length -lt 32) { throw 'A protected generated join credential is required.' }
        if ($ou.Count -eq 0) {
            New-ADOrganizationalUnit -Server localhost -Name $ComputerOuName -Path $domain.DistinguishedName -Description $marker -ProtectedFromAccidentalDeletion $true
            $changed = $true
        }
        if ($account.Count -eq 0) {
            $secure = ConvertTo-SecureString $JoinPassword -AsPlainText -Force
            New-ADUser -Server localhost -Name $AccountName -SamAccountName $AccountName -UserPrincipalName $accountUpn -Path ('CN=Users,' + $domain.DistinguishedName) -DisplayName ($OrganizationName + ' NMe Domain Join') -Company $OrganizationName -Description $marker -AccountPassword $secure -Enabled $true -AccountNotDelegated $true -PasswordNeverExpires $false -ChangePasswordAtLogon $false
            $secure = $null
            $changed = $true
        }
        $ou = @(Get-ADOrganizationalUnit -Server localhost -Identity $ouDn -Properties Description)
        $account = @(Get-ADUser -Server localhost -Identity $AccountName -Properties Description, MemberOf, AdminCount, PrimaryGroupId, AccountNotDelegated, PasswordNeverExpires, UserPrincipalName)
    }
    $delegationMatches = $false
    $passwordVerified = $false
    if ($ou.Count -eq 1 -and $account.Count -eq 1) {
        if (-not $account[0].Enabled -or -not $account[0].AccountNotDelegated -or $account[0].PasswordNeverExpires) { throw 'The managed join account has an unexpected security state; it was not silently reset.' }
        $aclEntry = [DirectoryServices.DirectoryEntry]::new(('LDAP://localhost/' + $ouDn))
        try {
            $aclEntry.PSBase.Options.SecurityMasks = [DirectoryServices.SecurityMasks]::Dacl
            $acl = $aclEntry.PSBase.ObjectSecurity
            $expected = @(Get-NmeJoinAccessRules $account[0].SID)
            $missing = @(foreach ($rule in $expected) { if (@($acl.Access | Where-Object { Test-NmeJoinAccessRule $_ $rule }).Count -eq 0) { $rule } })
            if ($Mode -eq 'Apply' -and $missing.Count) {
                foreach ($rule in $missing) { $null = $acl.AddAccessRule($rule) }
                $aclEntry.PSBase.ObjectSecurity = $acl
                $aclEntry.PSBase.CommitChanges()
                $aclEntry.PSBase.RefreshCache(@('nTSecurityDescriptor'))
                $acl = $aclEntry.PSBase.ObjectSecurity
                $missing = @(foreach ($rule in $expected) { if (@($acl.Access | Where-Object { Test-NmeJoinAccessRule $_ $rule }).Count -eq 0) { $rule } })
                $changed = $true
            }
            $delegationMatches = $missing.Count -eq 0
        } finally { $aclEntry.PSBase.Dispose() }
        if ($JoinPassword) {
            $options = [DirectoryServices.AuthenticationTypes]::Secure -bor [DirectoryServices.AuthenticationTypes]::Signing -bor [DirectoryServices.AuthenticationTypes]::Sealing
            $entry = [DirectoryServices.DirectoryEntry]::new(('LDAP://' + $env:COMPUTERNAME + '.' + $DomainName + '/RootDSE'), $accountUpn, $JoinPassword, $options)
            try { $null = $entry.PSBase.NativeObject; $passwordVerified = $true } finally { $entry.PSBase.Dispose() }
        }
    }
    if ($Mode -in @('Apply', 'Verify') -and (-not $delegationMatches -or -not $passwordVerified)) { throw 'The join delegation or credential readback is incomplete.' }
    [pscustomobject]@{ Status = if ($Mode -eq 'Preview') { 'Preview' } elseif ($changed) { 'Applied' } else { 'NoChange' }; DomainMatchesTarget = $true; ComputerOuExists = $ou.Count -eq 1; JoinAccountExists = $account.Count -eq 1; DelegationVerified = $delegationMatches; CredentialBindVerified = $passwordVerified; DirectoryChangesMade = $changed; PasswordPrinted = $false } | ConvertTo-Json -Compress
} catch {
    [pscustomobject]@{ Status = 'Stopped'; ErrorType = $_.Exception.GetType().Name; ErrorCommand = [string]$_.InvocationInfo.MyCommand.Name; ErrorLine = $_.InvocationInfo.ScriptLineNumber; DirectoryChangesMayHaveOccurred = $Mode -eq 'Apply'; PasswordPrinted = $false } | ConvertTo-Json -Compress
    exit 1
} finally {
    $JoinPassword = $null
}