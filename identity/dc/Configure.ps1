[CmdletBinding()]
param(
    [Parameter(Mandatory)] [ValidateSet('Forest', 'Replica', 'Inspect')] [string]$Mode,
    [Parameter(Mandatory)] [string]$DomainName,
    [Parameter(Mandatory)] [string]$NetbiosName,
    [Parameter(Mandatory)] [string]$AdminUsername,
    [Parameter(Mandatory)] [string]$DsrmPassword,
    [Parameter(Mandatory)] [string]$AdminPassword
)

$ErrorActionPreference = 'Stop'
try {
    if ($DomainName -notmatch '^(?=.{1,253}$)[A-Za-z0-9][A-Za-z0-9.-]+\.[A-Za-z]{2,}$' -or $NetbiosName -notmatch '^[A-Za-z][A-Za-z0-9-]{0,14}$') { throw 'Invalid domain configuration.' }
    $system = Get-CimInstance Win32_ComputerSystem
    if ($Mode -eq 'Inspect') {
        $shares = @(Get-SmbShare | Where-Object Name -in @('SYSVOL', 'NETLOGON'))
        $services = @(Get-Service NTDS,DNS,DFSR,Netlogon,KDC,ADWS -ErrorAction SilentlyContinue)
        $admin = @()
        $adminQuerySucceeded = $false
        if ($system.DomainRole -ge 4) {
            try {
                Import-Module ActiveDirectory -WarningAction SilentlyContinue
                $admin = @(Get-ADUser -Server localhost -Filter { SamAccountName -eq $AdminUsername })
                $adminQuerySucceeded = $true
            } catch { $adminQuerySucceeded = $false }
        }
        [pscustomobject]@{
            IsDomainController = ($system.DomainRole -ge 4)
            DomainMatchesTarget = ($system.Domain -ieq $DomainName)
            Shares = @($shares | ForEach-Object Name)
            Services = @($services | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Status = [string]$_.Status } })
            AdminQuerySucceeded = $adminQuerySucceeded
            AdminExists = ($admin.Count -eq 1)
            AdminEnabled = ($admin.Count -eq 1 -and $admin[0].Enabled)
        } | ConvertTo-Json -Depth 5 -Compress
        return
    }
    if ($system.DomainRole -ge 4) {
        if ($system.Domain -ine $DomainName) { throw 'Existing domain differs from desired state.' }
        'LEAFIT_PROMOTION_NOCHANGE'
        return
    }
    if ($system.PartOfDomain -and $system.Domain -ine $DomainName) { throw 'Server already belongs to another domain.' }
    $dataDisks = @(Get-Disk | Where-Object { -not $_.IsBoot -and -not $_.IsSystem -and $_.Size -eq 32GB })
    if ($dataDisks.Count -ne 1) { throw 'Expected data disk is not uniquely identified.' }
    $dataDisk = $dataDisks[0]
    if ($dataDisk.PartitionStyle -eq 'RAW') {
        if (Get-Volume -DriveLetter F -ErrorAction SilentlyContinue) { throw 'The required data drive is already occupied.' }
        $dataDisk | Initialize-Disk -PartitionStyle GPT -PassThru | New-Partition -DriveLetter F -UseMaximumSize | Format-Volume -FileSystem NTFS -NewFileSystemLabel ADDS -Confirm:$false | Out-Null
    } else {
        $volume = @(Get-Partition -DiskNumber $dataDisk.Number | Get-Volume | Where-Object { $_.DriveLetter -eq 'F' -and $_.FileSystemLabel -eq 'ADDS' -and $_.FileSystem -eq 'NTFS' })
        if ($volume.Count -ne 1) { throw 'Existing data disk is not the expected AD DS volume; never reformat it.' }
    }
    Install-WindowsFeature AD-Domain-Services,DNS -IncludeManagementTools | Out-Null
    Import-Module ADDSDeployment
    $secureDsrm = ConvertTo-SecureString $DsrmPassword -AsPlainText -Force
    $install = @{
        DomainName = $DomainName
        InstallDns = $true
        DatabasePath = 'F:\NTDS'
        LogPath = 'F:\NTDS'
        SysvolPath = 'F:\SYSVOL'
        SafeModeAdministratorPassword = $secureDsrm
        NoRebootOnCompletion = $true
        Force = $true
        ErrorAction = 'Stop'
    }
    if ($Mode -eq 'Forest') {
        Install-ADDSForest @install -DomainNetbiosName $NetbiosName | Out-Null
    } else {
        $credential = [pscredential]::new(($AdminUsername + '@' + $DomainName), (ConvertTo-SecureString $AdminPassword -AsPlainText -Force))
        Install-ADDSDomainController @install -Credential $credential -NoGlobalCatalog:$false | Out-Null
    }
    'LEAFIT_PROMOTION_REBOOT_REQUIRED'
} catch {
    'LEAFIT_PROMOTION_FAILED'
    exit 1
} finally {
    $DsrmPassword = $null
    $AdminPassword = $null
}