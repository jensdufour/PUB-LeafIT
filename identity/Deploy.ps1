[CmdletBinding()]
param([switch]$Apply, [switch]$CheckOnly, [switch]$ResourcesOnly, [switch]$ExplainPreview, [switch]$DnsOnly, [switch]$OperationsOnly, [switch]$RetireHealthSchedule)

$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
if ($ResourcesOnly -and -not $Apply) { throw 'ResourcesOnly requires an explicit Apply request.' }
if ($DnsOnly -and (-not $Apply -or $ResourcesOnly)) { throw 'DnsOnly requires Apply and cannot be combined with ResourcesOnly.' }
if ($OperationsOnly -and ($ResourcesOnly -or $DnsOnly)) { throw 'OperationsOnly cannot be combined with other apply modes.' }
if ($RetireHealthSchedule -and -not $OperationsOnly) { throw 'Health retirement requires the OperationsOnly migration.' }

function Get-Ipv4Range {
    param([string]$Cidr)
    if ($Cidr -notmatch '^(?<address>\d{1,3}(?:\.\d{1,3}){3})/(?<prefix>\d{1,2})$') { throw 'Invalid IPv4 CIDR.' }
    $addressText = $Matches.address
    $prefix = [int]$Matches.prefix
    $address = $null
    if ($prefix -gt 32 -or -not [Net.IPAddress]::TryParse($addressText, [ref]$address) -or $address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) { throw 'Invalid IPv4 CIDR.' }
    $bytes = $address.GetAddressBytes()
    [array]::Reverse($bytes)
    $number = [uint64][BitConverter]::ToUInt32($bytes, 0)
    $size = [uint64][math]::Pow(2, 32 - $prefix)
    $first = [uint64]([math]::Floor($number / $size) * $size)
    [pscustomobject]@{ First = $first; Last = $first + $size - 1; Prefix = $prefix; IsNetworkAddress = ($number -eq $first) }
}

function Test-ApplicationConsistentRecoveryPoint {
    param([object[]]$RecoveryPoints, [datetime]$MinimumUtc)
    return (@($RecoveryPoints | Where-Object { $_.RecoveryPointType -eq 'AppConsistent' -and $_.RecoveryPointTime -and ([datetime]$_.RecoveryPointTime).ToUniversalTime() -ge $MinimumUtc }).Count -gt 0)
}

function Invoke-ScheduleMigration {
    param([object[]]$Schedules, [object[]]$Bindings, [scriptblock]$Update, [switch]$RetireHealthSchedule)
    $common = @{ ResourceGroupName = $groupName; AutomationAccountName = $accountName; DefaultProfile = $context }
    if (@($Schedules | Where-Object Name -notin @('DcStart', 'DcStop', 'DcHealth')).Count -or @($Bindings | Where-Object { $_.RunbookName -ne 'InvokeDomainControllerSchedule' -or $_.ScheduleName -notin @('DcStart', 'DcStop', 'DcHealth') }).Count) { throw 'Migration includes an unowned schedule or binding.' }
    $healthSchedules = @($Schedules | Where-Object Name -eq 'DcHealth')
    if (($healthSchedules.Count -or @($Bindings | Where-Object ScheduleName -eq 'DcHealth').Count) -and -not $RetireHealthSchedule) { throw 'Legacy Health retirement requires the explicit RetireHealthSchedule switch.' }
    foreach ($schedule in $Schedules) {
        if (@(Get-AzAutomationScheduledRunbook @common -ScheduleName $schedule.Name | Where-Object RunbookName -ne 'InvokeDomainControllerSchedule').Count) { throw 'A schedule is shared with another runbook; migration stopped before changes.' }
    }
    if (@(Get-AzAutomationJob @common -RunbookName 'InvokeDomainControllerSchedule' | Where-Object Status -notin @('Completed', 'Failed', 'Stopped')).Count) { throw 'An existing runbook job is active; migration stopped before changes.' }
    $healthRemoved = $false
    try {
        foreach ($schedule in $Schedules) {
            Set-AzAutomationSchedule @common -Name $schedule.Name -IsEnabled $false | Out-Null
            if ((Get-AzAutomationSchedule @common -Name $schedule.Name).IsEnabled -ne $false) { throw 'A schedule is not confirmed paused.' }
        }
        if (@(Get-AzAutomationJob @common -RunbookName 'InvokeDomainControllerSchedule' | Where-Object Status -notin @('Completed', 'Failed', 'Stopped')).Count) { throw 'A job started during schedule pausing; no bindings changed.' }
        foreach ($binding in $Bindings) { Unregister-AzAutomationScheduledRunbook @common -JobScheduleId $binding.JobScheduleId -Force }
        & $Update
        foreach ($schedule in $healthSchedules) {
            if (@(Get-AzAutomationScheduledRunbook @common -ScheduleName $schedule.Name).Count) { throw 'Health still has a binding; its schedule was not deleted.' }
            Remove-AzAutomationSchedule @common -Name $schedule.Name -Force
            $healthRemoved = $true
        }
        foreach ($name in @('DcStart', 'DcStop')) {
            Set-AzAutomationSchedule @common -Name $name -IsEnabled $true | Out-Null
            if ((Get-AzAutomationSchedule @common -Name $name).IsEnabled -ne $true) { throw 'Power schedule resume readback failed.' }
        }
    } catch {
        foreach ($schedule in $Schedules) {
            if ($schedule.Name -eq 'DcHealth' -and $healthRemoved) { continue }
            try { Set-AzAutomationSchedule @common -Name $schedule.Name -IsEnabled $false | Out-Null } catch { Write-Warning 'A schedule could not be paused; inspect the owned schedules before retrying.' }
        }
        throw 'Schedule migration failed; owned schedules were left paused where possible. Review before retrying.'
    }
}

$dnsCheck = @'
param([string]$ExpectedFirst,[string]$ExpectedSecond)
$ErrorActionPreference = 'Stop'
try {
    $interfaces = @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' | Where-Object {
        @($_.IPAddress | Where-Object { [Net.IPAddress]::Parse($_).AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork }).Count -gt 0
    })
    if ($interfaces.Count -ne 1) { throw 'IPv4-configured interface is ambiguous.' }
    $interfaceIndex = $interfaces[0].InterfaceIndex
    $actual = @(Get-DnsClientServerAddress -InterfaceIndex $interfaceIndex -AddressFamily IPv4 | ForEach-Object ServerAddresses)
    if ($actual.Count -ne 2 -or $actual[0] -ne $ExpectedFirst -or $actual[1] -ne $ExpectedSecond) {
        Set-DnsClientServerAddress -InterfaceIndex $interfaceIndex -ResetServerAddresses
        ipconfig /renew | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'DHCP renewal failed.' }
        $actual = @(Get-DnsClientServerAddress -InterfaceIndex $interfaceIndex -AddressFamily IPv4 | ForEach-Object ServerAddresses)
    }
    if ($actual.Count -ne 2 -or $actual[0] -ne $ExpectedFirst -or $actual[1] -ne $ExpectedSecond) { throw 'Guest DNS lease did not pick up intended Azure NIC settings.' }
    'LEAFIT_DNS_PASS'
} catch { 'LEAFIT_DNS_FAIL'; exit 1 }
'@
function Invoke-GuestDns {
    param([int]$Index)
    $result = Invoke-AzVMRunCommand -ResourceGroupName $groupName -VMName $vmNames[$Index] -CommandId RunPowerShellScript -ScriptString $dnsCheck -Parameter @{ ExpectedFirst = $privateIps[1 - $Index]; ExpectedSecond = $privateIps[$Index] } -DefaultProfile $context
    $message = @($result.Value | ForEach-Object Message) -join "`n"
    if ($message -notmatch '(?m)^LEAFIT_DNS_PASS\s*$' -or $message -match 'LEAFIT_DNS_FAIL') { throw 'Final guest DNS verification failed.' }
}

if ($CheckOnly) {
    if ($Apply) { throw 'Offline checks cannot apply changes.' }
    $network = Get-Ipv4Range '10.60.0.0/16'
    $subnet = Get-Ipv4Range '10.60.0.0/24'
    $hostRange = Get-Ipv4Range '10.60.0.4/32'
    if ($network.First -ne $subnet.First -or $subnet.Last -gt $network.Last -or $hostRange.First -ne $subnet.First + 4) { throw 'IPv4 containment check failed.' }
    $rejected = $false
    try { Get-Ipv4Range '300.1.1.1/24' | Out-Null } catch { $rejected = $true }
    if (-not $rejected) { throw 'Invalid address was accepted.' }
    & (Join-Path $PSScriptRoot 'Initialize-Prerequisites.ps1') -CheckOnly
    & (Join-Path $PSScriptRoot 'Initialize-PrivateInputs.ps1') -CheckOnly
    & (Join-Path $PSScriptRoot 'dc/Invoke-Schedule.ps1') -CheckOnly -VmName1 vm-example-dc1 -VmName2 vm-example-dc2
    $rejected = $false
    try { & (Join-Path $PSScriptRoot 'dc/Invoke-Schedule.ps1') -CheckOnly -VmName1 vm-example-dc1 -VmName2 vm-example-dc1 | Out-Null } catch { $rejected = $true }
    if (-not $rejected) { throw 'The second DC name must reject a duplicate first-DC name.' }
    & {
        $groupName = 'rg-example'
        $accountName = 'aa-example'
        $context = $null
        $script:migrationEvents = [Collections.Generic.List[string]]::new()
        $script:migrationEnabled = @{ DcStart = $true; DcStop = $true; DcHealth = $true }
        $script:migrationForeignBinding = $false
        function Set-AzAutomationSchedule { param($Name, $IsEnabled) $script:migrationEnabled[$Name] = $IsEnabled; $script:migrationEvents.Add($(if ($IsEnabled) { 'Resume:' } else { 'Pause:' }) + $Name) }
        function Get-AzAutomationSchedule { param($Name) [pscustomobject]@{ IsEnabled = $script:migrationEnabled[$Name] } }
        function Get-AzAutomationJob {}
        function Unregister-AzAutomationScheduledRunbook { $script:migrationEvents.Add('Unbind') }
        function Get-AzAutomationScheduledRunbook { if ($script:migrationForeignBinding) { [pscustomobject]@{ RunbookName = 'UnrelatedRunbook' } } }
        function Remove-AzAutomationSchedule { param($Name) $script:migrationEvents.Add('Retire'); $script:migrationEnabled.Remove($Name) }
        $schedules = @('DcStart', 'DcStop', 'DcHealth') | ForEach-Object { [pscustomobject]@{ Name = $_ } }
        $bindings = @($schedules | ForEach-Object { [pscustomobject]@{ RunbookName = 'InvokeDomainControllerSchedule'; ScheduleName = $_.Name; JobScheduleId = [guid]::NewGuid() } })
        $update = { if (@($script:migrationEnabled.Values | Where-Object { $_ }).Count) { throw 'Update ran before every schedule was paused.' }; $script:migrationEvents.Add('Update') }
        $rejected = $false
        try { Invoke-ScheduleMigration -Schedules $schedules -Bindings $bindings -Update $update } catch { $rejected = $true }
        if (-not $rejected -or $script:migrationEvents.Count) { throw 'Health retirement must fail before mutations without explicit approval.' }
        $script:migrationForeignBinding = $true
        $rejected = $false
        try { Invoke-ScheduleMigration -Schedules $schedules -Bindings $bindings -Update $update -RetireHealthSchedule } catch { $rejected = $true }
        if (-not $rejected -or $script:migrationEvents.Count) { throw 'A shared schedule must be rejected before mutations.' }
        $script:migrationForeignBinding = $false
        Invoke-ScheduleMigration -Schedules $schedules -Bindings $bindings -Update $update -RetireHealthSchedule
        if (($script:migrationEvents -join ',') -cne 'Pause:DcStart,Pause:DcStop,Pause:DcHealth,Unbind,Unbind,Unbind,Update,Retire,Resume:DcStart,Resume:DcStop') { throw 'Schedule migration order is unsafe.' }
        $script:migrationEvents.Clear()
        $script:migrationEnabled = @{ DcStart = $true; DcStop = $true; DcHealth = $true }
        $rejected = $false
        try { Invoke-ScheduleMigration -Schedules $schedules -Bindings $bindings -Update { throw 'Simulated update failure.' } -RetireHealthSchedule } catch { $rejected = $true }
        if (-not $rejected -or @($script:migrationEnabled.Values | Where-Object { $_ }).Count -or @($script:migrationEvents | Where-Object { $_ -like 'Resume:*' }).Count) { throw 'A failed migration must leave schedules paused.' }
    }
    'PASS: migration pauses before updates, requires explicit Health retirement, and stays paused on failure.'
    $minimumBackupUtc = [datetime]::UtcNow.AddDays(-1)
    $validPoint = [pscustomobject]@{ RecoveryPointType = 'AppConsistent'; RecoveryPointTime = [datetime]::UtcNow }
    $crashPoint = [pscustomobject]@{ RecoveryPointType = 'CrashConsistent'; RecoveryPointTime = [datetime]::UtcNow }
    $oldPoint = [pscustomobject]@{ RecoveryPointType = 'AppConsistent'; RecoveryPointTime = [datetime]::UtcNow.AddDays(-2) }
    if (-not (Test-ApplicationConsistentRecoveryPoint @($validPoint) $minimumBackupUtc) -or (Test-ApplicationConsistentRecoveryPoint @($crashPoint, $oldPoint) $minimumBackupUtc) -or (Test-ApplicationConsistentRecoveryPoint @() $minimumBackupUtc)) { throw 'Backup consistency gate check failed.' }
    $scheduleZone = [TimeZoneInfo]::FindSystemTimeZoneById('Romance Standard Time')
    foreach ($scheduleDate in @('2026-01-12T06:00:00', '2026-07-13T06:00:00')) {
        $localSchedule = [datetime]::SpecifyKind([datetime]::Parse($scheduleDate), [DateTimeKind]::Unspecified)
        $utcSchedule = [datetimeoffset]::new($localSchedule, $scheduleZone.GetUtcOffset($localSchedule)).UtcDateTime.ToString('o')
        $roundTrip = [TimeZoneInfo]::ConvertTime([datetimeoffset]::Parse($utcSchedule), $scheduleZone)
        if (-not $utcSchedule.EndsWith('Z') -or $roundTrip.Hour -ne 6 -or $roundTrip.Minute -ne 0) { throw 'Schedule UTC serialization changed the Brussels operating hour.' }
    }
    & {
        function Get-CimInstance {
            [pscustomobject]@{ InterfaceIndex = 5; IPAddress = @('10.60.0.4') }
            [pscustomobject]@{ InterfaceIndex = 3; IPAddress = @('fe80::1') }
        }
        $script:dnsResetCount = 0
        function Set-DnsClientServerAddress {
            param([int]$InterfaceIndex, [switch]$ResetServerAddresses)
            if ($InterfaceIndex -ne 5 -or -not $ResetServerAddresses) { throw 'Wrong interface selected.' }
            $script:dnsResetCount++
        }
        function ipconfig { $global:LASTEXITCODE = 0 }
        function Get-DnsClientServerAddress {
            param([int]$InterfaceIndex, [string]$AddressFamily)
            if ($InterfaceIndex -ne 5 -or $AddressFamily -ne 'IPv4') { throw 'Wrong interface queried.' }
            [pscustomobject]@{ ServerAddresses = if ($script:dnsResetCount) { @('10.60.0.5', '10.60.0.4') } else { @('127.0.0.1') } }
        }
        $check = [scriptblock]::Create($dnsCheck)
        foreach ($attempt in 1, 2) {
            $output = & $check -ExpectedFirst '10.60.0.5' -ExpectedSecond '10.60.0.4'
            if ($output -ne 'LEAFIT_DNS_PASS' -or $script:dnsResetCount -ne 1) { throw 'IPv4 interface selection or no-change DNS check failed.' }
        }
    }
    & {
        function Get-CimInstance { [pscustomobject]@{ DomainRole = 5; Domain = 'example.test' } }
        function Get-SmbShare { [pscustomobject]@{ Name = 'SYSVOL' }; [pscustomobject]@{ Name = 'NETLOGON' } }
        function Get-Service { [pscustomobject]@{ Name = 'NTDS'; Status = 'Running' } }
        function Import-Module {}
        function Get-ADUser {}
        function Get-Disk { throw 'Inspect must never enter disk configuration.' }
        $state = & (Join-Path $PSScriptRoot 'dc/Configure.ps1') -Mode Inspect -DomainName 'example.test' -NetbiosName EXAMPLE -AdminUsername exampleadmin -DsrmPassword unused -AdminPassword unused | ConvertFrom-Json
        if (-not $state.IsDomainController -or -not $state.DomainMatchesTarget -or -not $state.AdminQuerySucceeded -or $state.AdminExists -or $state.Shares.Count -ne 2) { throw 'Read-only guest inspection check failed.' }
    }
    $compiled = (az bicep build --file (Join-Path $PSScriptRoot 'dc/resources.bicep') --stdout) -join "`n"
    if ($LASTEXITCODE -ne 0) { throw 'DC module compilation failed.' }
    $template = $compiled | ConvertFrom-Json -AsHashtable -Depth 100
    $resources = if ($template.resources -is [Collections.IDictionary]) { @($template.resources.Values | ForEach-Object { $_ }) } else { @($template.resources) }
    $networkModules = @($resources | Where-Object { $_.type -eq 'Microsoft.Resources/deployments' -and $_.properties.template.outputs.adSubnetId })
    if ($networkModules.Count -ne 1) { throw 'Expected one shared identity network owner.' }
    $networkTemplate = $networkModules[0].properties.template
    $networkResources = if ($networkTemplate.resources -is [Collections.IDictionary]) { @($networkTemplate.resources.Values | ForEach-Object { $_ }) } else { @($networkTemplate.resources) }
    $securityGroups = @($networkResources | Where-Object { $_.type -eq 'Microsoft.Network/networkSecurityGroups' -and $_.name -match '-adds' })
    if ($securityGroups.Count -ne 1) { throw 'Expected exactly one DC subnet NSG.' }
    foreach ($rule in $networkTemplate.variables.domainRules) {
        if ($rule.priority -lt 100 -or $rule.priority -gt 4096) { throw 'NSG priority is outside the Azure range.' }
    }
    if ($template.parameters.adminPassword.type -ine 'securestring') { throw 'VM password must remain a secure ARM parameter.' }
    $publicIps = @($networkResources | Where-Object { $_.type -eq 'Microsoft.Network/publicIPAddresses' })
    if ($publicIps.Count -ne 1 -or $publicIps[0].properties.ContainsKey('ipAddress') -or $publicIps[0].properties.publicIPAddressVersion -ne 'IPv4') { throw 'Expected an Azure-assigned IPv4 egress address, never a BYOIP address.' }
    if ($publicIps[0].sku.name -ne 'Standard' -or $publicIps[0].properties.ContainsKey('publicIPPrefix')) { throw 'Expected a standalone Standard public IP.' }
    $operationsCompiled = (az bicep build --file (Join-Path $PSScriptRoot 'operations/resources.bicep') --stdout) -join "`n"
    if ($LASTEXITCODE -ne 0) { throw 'Operations module compilation failed.' }
    $operationsTemplate = $operationsCompiled | ConvertFrom-Json -AsHashtable -Depth 100
    $operationResources = if ($operationsTemplate.resources -is [Collections.IDictionary]) { @($operationsTemplate.resources.Values | ForEach-Object { $_ }) } else { @($operationsTemplate.resources) }
    $runtimeResources = @($operationResources | Where-Object type -eq 'Microsoft.Automation/automationAccounts/runtimeEnvironments')
    $runbookResources = @($operationResources | Where-Object type -eq 'Microsoft.Automation/automationAccounts/runbooks')
    if ($runtimeResources.Count -ne 1 -or $runtimeResources[0].properties.runtime.version -ne '7.6' -or $runtimeResources[0].properties.defaultPackages.Az -ne '15.1.0' -or $runbookResources.Count -ne 1 -or $runbookResources[0].properties.runbookType -ne 'PowerShell' -or -not $runbookResources[0].properties.runtimeEnvironment) { throw 'Supported runtime selection check failed.' }
    $scheduleActions = @($operationsTemplate.variables.operations | ForEach-Object { $_.action })
    $bindingResources = @($operationResources | Where-Object type -eq 'Microsoft.Automation/automationAccounts/jobSchedules')
    if (($scheduleActions -join ',') -cne 'Start,Stop' -or $bindingResources.Count -ne 1 -or -not $bindingResources[0].properties.parameters.ContainsKey('VmName1') -or -not $bindingResources[0].properties.parameters.ContainsKey('VmName2') -or $bindingResources[0].properties.parameters.ContainsKey('VmNamesJson')) { throw 'Power schedules must use two scalar VM-name parameters and no Health action.' }
    $schedulerActions = @($operationResources | Where-Object type -eq 'Microsoft.Authorization/roleDefinitions' | ForEach-Object { $_.properties.permissions } | ForEach-Object { $_.actions })
    if (@($schedulerActions | Where-Object { $_ -like '*/runCommand/*' }).Count) { throw 'The power scheduler must not have guest-execution permission.' }
    'PASS: two power schedules use scalar VM names without guest-execution permission.'
    'PASS: application-consistent recovery points and the supported runtime definition are required.'
    'PASS: deployment address checks and dependency self-checks.'
    return
}

foreach ($path in @('.env', 'private/')) {
    git -C $repo check-ignore --quiet -- $path
    if ($LASTEXITCODE -ne 0) { throw 'Private inputs and artifacts must be ignored.' }
}
$tracked = @(git -C $repo ls-files -- .env private)
if ($LASTEXITCODE -ne 0 -or $tracked.Count) { throw 'Private configuration must remain untracked.' }
$settings = @{}
foreach ($line in [IO.File]::ReadAllLines((Join-Path $repo '.env'))) {
    $entry = [regex]::Match($line, '^\s*(?<key>TARGET_[A-Z0-9_]+)\s*=\s*(?<value>.*)$')
    if (-not $entry.Success) { continue }
    $key = $entry.Groups['key'].Value
    if ($settings.ContainsKey($key)) { throw 'Duplicate private target setting.' }
    $settings[$key] = $entry.Groups['value'].Value.Trim().Trim([char]34, [char]39)
}
foreach ($key in @('TARGET_TENANT_ID', 'TARGET_SUBSCRIPTION_ID', 'TARGET_LOCATION', 'TARGET_REGION_CODE', 'TARGET_INSTANCE', 'TARGET_AD_DOMAIN_NAME', 'TARGET_AD_NETBIOS_NAME', 'TARGET_VM_ADMIN_USERNAME', 'TARGET_VNET_ADDRESS_PREFIX', 'TARGET_AD_SUBNET_PREFIX', 'TARGET_DC1_PRIVATE_IP', 'TARGET_DC2_PRIVATE_IP', 'TARGET_VM_ADMIN_PASSWORD_DPAPI', 'TARGET_AD_DSRM_PASSWORD_DPAPI')) {
    if ([string]::IsNullOrWhiteSpace($settings[$key])) { throw 'An approved private DC input is missing.' }
}
if ($settings.TARGET_AD_NETBIOS_NAME -ne 'LEAFIT' -or $settings.TARGET_VM_ADMIN_USERNAME -ne 'leafitadmin' -or $settings.TARGET_INSTANCE -notmatch '^[0-9]{1,3}$') { throw 'Private inputs do not match the reviewed naming choices.' }
$context = Get-AzContext
if (-not $context -or $context.Tenant.Id -ne $settings.TARGET_TENANT_ID -or $context.Subscription.Id -ne $settings.TARGET_SUBSCRIPTION_ID) { throw 'Use the retained authenticated target process; this command never signs in or switches context.' }
$zones = @('1', '2')
if (-not $DnsOnly -and -not $OperationsOnly) {
    $preflight = & (Join-Path $repo 'infra/Test-DomainControllers.ps1')
    if (@($preflight.Providers | Where-Object { -not $_.Registered }).Count -or $preflight.FamilyQuotaSufficient -ne $true -or $preflight.RegionalQuotaSufficient -ne $true -or -not $preflight.Windows2025CoreSmallDiskImageFound -or @($preflight.Restrictions).Count) {
        throw 'Provider, image, SKU restriction or quota checks are not ready.'
    }
    if (@($zones | Where-Object { $_ -notin $preflight.Zones }).Count) { throw 'The approved two-zone design is unavailable; review an availability-set alternative before changing placement.' }
}
$networkRange = Get-Ipv4Range $settings.TARGET_VNET_ADDRESS_PREFIX
$subnetRange = Get-Ipv4Range $settings.TARGET_AD_SUBNET_PREFIX
if (-not $networkRange.IsNetworkAddress -or -not $subnetRange.IsNetworkAddress -or $subnetRange.Prefix -gt 29 -or $subnetRange.First -lt $networkRange.First -or $subnetRange.Last -gt $networkRange.Last) { throw 'Private subnet is invalid or outside the VNet.' }
$workloadSubnetPrefix = if ($settings.ContainsKey('TARGET_NME_WORKLOAD_SUBNET_PREFIX')) { $settings.TARGET_NME_WORKLOAD_SUBNET_PREFIX } else { '' }
if ($workloadSubnetPrefix) {
    $workloadRange = Get-Ipv4Range $workloadSubnetPrefix
    if (-not $workloadRange.IsNetworkAddress -or $workloadRange.Prefix -gt 27 -or $workloadRange.First -lt $networkRange.First -or $workloadRange.Last -gt $networkRange.Last -or ($workloadRange.First -le $subnetRange.Last -and $subnetRange.First -le $workloadRange.Last)) { throw 'The selected NMe workload subnet is invalid, overlapping, or outside the identity VNet.' }
}
$privateIps = @($settings.TARGET_DC1_PRIVATE_IP, $settings.TARGET_DC2_PRIVATE_IP)
if ($privateIps[0] -eq $privateIps[1]) { throw 'DC IP addresses must be distinct.' }
foreach ($address in $privateIps) {
    $hostRange = Get-Ipv4Range ($address + '/32')
    if ($hostRange.First -lt $subnetRange.First + 4 -or $hostRange.First -ge $subnetRange.Last) { throw 'A DC IP is outside the subnet or reserved by Azure.' }
}
$namePrefix = 'identity-{0}-{1}' -f $settings.TARGET_REGION_CODE, $settings.TARGET_INSTANCE
$groupName = 'rg-' + $namePrefix
$networkName = 'vnet-' + $namePrefix
$vmNames = @("vm-${namePrefix}-dc1", "vm-${namePrefix}-dc2")
$scope = '/subscriptions/' + $settings.TARGET_SUBSCRIPTION_ID
function Get-ArmRead {
    param([string]$Path, [switch]$AllowMissing, [switch]$Paginate)
    $response = Invoke-AzRestMethod -Method GET -Path $Path -Paginate:$Paginate -DefaultProfile $context
    if ($response.StatusCode -eq 404 -and $AllowMissing) { return $null }
    if ($response.StatusCode -ne 200) { throw 'Target ARM readback failed.' }
    return ($response.Content | ConvertFrom-Json -DateKind String -Depth 80)
}
$ownedGroup = Get-ArmRead ($scope + '/resourceGroups/' + $groupName + '?api-version=2024-03-01') -AllowMissing
if ($ownedGroup -and ($ownedGroup.tags.workload -ne 'identity' -or $ownedGroup.tags.'managed-by' -ne 'bicep')) { throw 'The identity group already exists with different ownership.' }
if ($DnsOnly) {
    if (-not $ownedGroup) { throw 'Owned identity group is missing.' }
    for ($index = 0; $index -lt 2; $index++) {
        $nic = Get-ArmRead ($scope + '/resourceGroups/' + $groupName + '/providers/Microsoft.Network/networkInterfaces/nic-' + $namePrefix + '-dc' + ($index + 1) + '?api-version=2024-05-01')
        $expectedDns = @($privateIps[1 - $index], $privateIps[$index])
        $configuredDns = @($nic.properties.dnsSettings.dnsServers)
        if ([string]::Join(',', $configuredDns) -ne [string]::Join(',', $expectedDns)) { throw 'Azure NIC DNS does not match the reviewed peer-first order.' }
        Invoke-GuestDns $index
        [pscustomobject]@{ Ordinal = $index + 1; GuestDnsMatchesAzureNic = $true }
    }
    return
}
$groupScope = $scope + '/resourceGroups/' + $groupName
$backupScope = $scope + '/resourceGroups/rg-recovery-' + $settings.TARGET_REGION_CODE + '-' + $settings.TARGET_INSTANCE
$artifactDirectory = Join-Path $repo 'private/identity'
[IO.Directory]::CreateDirectory($artifactDirectory) | Out-Null
if (-not $OperationsOnly) {
$networks = @(Get-AzVirtualNetwork -DefaultProfile $context)
foreach ($network in $networks) {
    if ($network.Name -eq $networkName -and $network.ResourceGroupName -eq $groupName) { continue }
    foreach ($prefix in $network.AddressSpace.AddressPrefixes) {
        $existingRange = Get-Ipv4Range $prefix
        if ($networkRange.First -le $existingRange.Last -and $existingRange.First -le $networkRange.Last) { throw 'Desired VNet overlaps another network in the target subscription.' }
    }
}
$existingNetwork = @($networks | Where-Object { $_.Name -eq $networkName -and $_.ResourceGroupName -eq $groupName })
if ($existingNetwork.Count -gt 1) { throw 'Owned network is ambiguous.' }
$dnsStage = 'Azure'
if ($existingNetwork.Count -eq 1) {
    $dns = @($existingNetwork[0].DhcpOptions.DnsServers)
    if ($dns.Count -eq 2 -and -not (Compare-Object $privateIps $dns)) { $dnsStage = 'Both' }
    elseif ($dns.Count -eq 1 -and $dns[0] -eq $privateIps[0]) { $dnsStage = 'Primary' }
    elseif ($dns.Count -gt 0) { throw 'Existing VNet DNS differs; do not overwrite unrelated DNS.' }
}
$imagePath = $scope + '/providers/Microsoft.Compute/locations/swedencentral/publishers/MicrosoftWindowsServer/artifacttypes/vmimage/offers/WindowsServer/skus/2025-datacenter-azure-edition-core-smalldisk/versions?api-version=2024-03-01'
$versionList = @(Get-ArmRead $imagePath)
$imageVersion = $settings.TARGET_DC_IMAGE_VERSION
if (-not $imageVersion) {
    $imageVersion = @($versionList | Where-Object name -match '^\d+\.\d+\.\d+$' | Sort-Object { [version]$_.name } -Descending | Select-Object -First 1 -ExpandProperty name)[0]
}
if ([string]::IsNullOrWhiteSpace($imageVersion) -or $imageVersion -eq 'latest') { throw 'An exact Windows image version is required.' }
$image = Get-ArmRead ($scope + '/providers/Microsoft.Compute/locations/swedencentral/publishers/MicrosoftWindowsServer/artifacttypes/vmimage/offers/WindowsServer/skus/2025-datacenter-azure-edition-core-smalldisk/versions/' + $imageVersion + '?api-version=2024-03-01')
if ($image.properties.hyperVGeneration -ne 'V2' -or $image.properties.osDiskImage.operatingSystem -ne 'Windows') { throw 'Expected Gen2 Windows image is not confirmed.' }
$parameters = @{
    resourceGroupName = $groupName
    location = $settings.TARGET_LOCATION
    namePrefix = $namePrefix
    addressPrefix = $settings.TARGET_VNET_ADDRESS_PREFIX
    subnetPrefix = $settings.TARGET_AD_SUBNET_PREFIX
    workloadSubnetPrefix = $workloadSubnetPrefix
    privateIps = $privateIps
    computerNames = @('LEAFITDC01', 'LEAFITDC02')
    zones = $zones
    imageVersion = $imageVersion
    adminUsername = $settings.TARGET_VM_ADMIN_USERNAME
    adminPassword = [Net.NetworkCredential]::new('', ($settings.TARGET_VM_ADMIN_PASSWORD_DPAPI | ConvertTo-SecureString)).Password
    dnsStage = $dnsStage
    backupGroupName = 'rg-recovery-' + $settings.TARGET_REGION_CODE + '-' + $settings.TARGET_INSTANCE
    enableBackup = $false
    tags = @{ workload = 'identity'; 'managed-by' = 'bicep' }
}
$artifactDirectory = Join-Path $repo 'private/identity'
[IO.Directory]::CreateDirectory($artifactDirectory) | Out-Null
$templatePath = Join-Path $artifactDirectory 'main.json'
az bicep build --file (Join-Path $PSScriptRoot 'main.bicep') --outfile $templatePath
if ($LASTEXITCODE -ne 0) { throw 'Identity Bicep compilation failed.' }
$preview = Get-AzSubscriptionDeploymentWhatIfResult -Location $settings.TARGET_LOCATION -TemplateFile $templatePath -TemplateParameterObject $parameters -DefaultProfile $context
if ($preview.Status -ne 'Succeeded') { throw 'Identity deployment preview failed.' }
$changes = @($preview.Changes | Where-Object ChangeType -notin @('NoChange', 'Ignore'))
$groupScope = $scope + '/resourceGroups/' + $groupName
$backupScope = $scope + '/resourceGroups/' + $parameters.backupGroupName
foreach ($change in $changes) {
    $changedId = [string]$change.FullyQualifiedResourceId
    if ($change.ChangeType -notin @('Create', 'Modify', 'Deploy') -or (-not $changedId.StartsWith($groupScope + '/', [StringComparison]::OrdinalIgnoreCase) -and $changedId -ine $groupScope)) { throw 'Preview includes destructive or unrelated changes.' }
}
[pscustomobject]@{ PreviewSucceeded = $true; ResourceChangeCount = $changes.Count; ApplyRequested = $Apply.IsPresent; ImagePinned = $true; AllocationCapacityVerified = $false }
if ($ExplainPreview) {
    foreach ($change in $changes) {
        [pscustomobject]@{ ChangeType = [string]$change.ChangeType; PropertyPaths = @($change.Delta | ForEach-Object Path) }
    }
}
if (-not $Apply) { return }
if ($settings.ContainsKey('TARGET_DC_IMAGE_VERSION') -and $settings.TARGET_DC_IMAGE_VERSION -ne $imageVersion) { throw 'Pinned image differs from private configuration.' }
if (-not $settings.ContainsKey('TARGET_DC_IMAGE_VERSION')) {
    [IO.File]::AppendAllText((Join-Path $repo '.env'), "`nTARGET_DC_IMAGE_VERSION=$imageVersion`n")
}
function Invoke-OwnedDeployment {
    param([string]$Stage)
    $parameters.dnsStage = $Stage
    if ($parameters.enableBackup) {
        $backupGroup = Get-ArmRead ($backupScope + '?api-version=2024-03-01') -AllowMissing
        if ($backupGroup -and ($backupGroup.tags.workload -ne 'recovery' -or $backupGroup.tags.'managed-by' -ne 'bicep')) { throw 'Existing recovery group has different ownership.' }
    }
    $stagePreview = Get-AzSubscriptionDeploymentWhatIfResult -Location $settings.TARGET_LOCATION -TemplateFile $templatePath -TemplateParameterObject $parameters -DefaultProfile $context
    if ($stagePreview.Status -ne 'Succeeded') { throw 'Stage preview failed.' }
    foreach ($change in @($stagePreview.Changes | Where-Object ChangeType -notin @('NoChange', 'Ignore'))) {
        $changedId = [string]$change.FullyQualifiedResourceId
        $ownedScope = $changedId -ieq $groupScope -or $changedId.StartsWith($groupScope + '/', [StringComparison]::OrdinalIgnoreCase)
        $ownedBackup = $parameters.enableBackup -and ($changedId -ieq $backupScope -or $changedId.StartsWith($backupScope + '/', [StringComparison]::OrdinalIgnoreCase))
        if ($change.ChangeType -notin @('Create', 'Modify', 'Deploy') -or -not ($ownedScope -or $ownedBackup)) { throw 'Stage preview includes destructive or unrelated changes.' }
    }
    $deployment = New-AzSubscriptionDeployment -Name 'leafit-identity' -Location $settings.TARGET_LOCATION -TemplateFile $templatePath -TemplateParameterObject $parameters -DefaultProfile $context
    if ($deployment.ProvisioningState -ne 'Succeeded') { throw 'Identity resource deployment did not succeed.' }
}
Invoke-OwnedDeployment $dnsStage
if ($ResourcesOnly) {
    [pscustomobject]@{ ResourceDeploymentSucceeded = $true; GuestConfigurationAttempted = $false }
    return
}
$configurePath = Join-Path $artifactDirectory 'configure.json'
az bicep build --file (Join-Path $PSScriptRoot 'dc/configure.bicep') --outfile $configurePath
if ($LASTEXITCODE -ne 0) { throw 'Guest promotion Bicep compilation failed.' }
$dsrm = [Net.NetworkCredential]::new('', ($settings.TARGET_AD_DSRM_PASSWORD_DPAPI | ConvertTo-SecureString)).Password
$guestCheck = @'
$ErrorActionPreference = 'Stop'
try {
    $system = Get-CimInstance Win32_ComputerSystem
    if ($system.DomainRole -ge 4) {
        Import-Module ActiveDirectory -WarningAction SilentlyContinue
        $domain = Get-ADDomain -Server localhost
        $shares = @(Get-SmbShare | Where-Object Name -in @('SYSVOL','NETLOGON'))
        $admin = Get-ADUser -Server localhost -Identity leafitadmin
        if ($shares.Count -ne 2 -or -not $admin.Enabled) { throw 'DC readiness incomplete.' }
        [pscustomobject]@{ IsDomainController = $true; Domain = $domain.DNSRoot; Ready = $true } | ConvertTo-Json -Compress
    } else { [pscustomobject]@{ IsDomainController = $false; Domain = $system.Domain; Ready = $false } | ConvertTo-Json -Compress }
} catch { 'LEAFIT_GUEST_CHECK_FAILED'; exit 1 }
'@
function Get-GuestState {
    param([string]$Name)
    $result = Invoke-AzVMRunCommand -ResourceGroupName $groupName -VMName $Name -CommandId RunPowerShellScript -ScriptString $guestCheck -DefaultProfile $context
    $message = @($result.Value | Where-Object Code -like '*/StdOut/*' | ForEach-Object Message) -join "`n"
    if ($message -match 'LEAFIT_GUEST_CHECK_FAILED') { throw 'Guest readiness check failed.' }
    $state = $message.Trim() | ConvertFrom-Json
    if ($state.IsDomainController -and $state.Domain -ine $settings.TARGET_AD_DOMAIN_NAME) { throw 'Existing guest domain does not match desired state.' }
    return $state
}
for ($index = 0; $index -lt 2; $index++) {
    $name = $vmNames[$index]
    $vm = Get-AzVM -ResourceGroupName $groupName -Name $name -Status -DefaultProfile $context
    if (@($vm.Statuses | Where-Object Code -eq 'PowerState/deallocated').Count) { throw 'Existing DC is deallocated; use an explicitly reviewed startup before retrying guest deployment.' }
    $state = Get-GuestState $name
    if (-not $state.IsDomainController) {
        if ($index -eq 1) {
            Invoke-OwnedDeployment 'Primary'
            Restart-AzVM -ResourceGroupName $groupName -Name $name -DefaultProfile $context | Out-Null
        }
        $promotion = New-AzResourceGroupDeployment -Name ('leafit-dc-promotion-' + $index) -ResourceGroupName $groupName -TemplateFile $configurePath -TemplateParameterObject @{
            location = $settings.TARGET_LOCATION
            vmName = $name
            mode = if ($index -eq 0) { 'Forest' } else { 'Replica' }
            domainName = $settings.TARGET_AD_DOMAIN_NAME
            netbiosName = $settings.TARGET_AD_NETBIOS_NAME
            adminUsername = $settings.TARGET_VM_ADMIN_USERNAME
            dsrmPassword = $dsrm
            adminPassword = $parameters.adminPassword
        } -DefaultProfile $context
        if ($promotion.ProvisioningState -ne 'Succeeded') { throw 'Guest promotion deployment failed.' }
        Restart-AzVM -ResourceGroupName $groupName -Name $name -DefaultProfile $context | Out-Null
        $state = Get-GuestState $name
    }
    if (-not $state.IsDomainController -or -not $state.Ready) { throw 'Domain controller readiness is incomplete; stop for operator review.' }
}
Invoke-OwnedDeployment 'Both'
for ($index = 0; $index -lt 2; $index++) {
    Invoke-GuestDns $index
}
$healthCheck = @'
$ErrorActionPreference = 'Stop'
try {
    Import-Module ActiveDirectory
    $domain = Get-ADDomain
    $controllers = @(Get-ADDomainController -Filter *)
    $failures = @(Get-ADReplicationFailure -Target $env:COMPUTERNAME -Scope Server)
    $partners = @(Get-ADReplicationPartnerMetadata -Target $env:COMPUTERNAME -Scope Server)
    $shares = @(Get-SmbShare | Where-Object Name -in @('SYSVOL','NETLOGON'))
    $services = @(Get-Service NTDS,DNS,DFSR,Netlogon,KDC | Where-Object Status -ne Running)
    $srv = @(Resolve-DnsName -Name ('_ldap._tcp.dc._msdcs.'+$domain.DNSRoot) -Type SRV | Where-Object Type -eq SRV)
    if ($controllers.Count -ne 2 -or @($controllers | Where-Object {-not $_.IsGlobalCatalog}).Count -or $failures.Count -or $partners.Count -eq 0 -or @($partners | Where-Object LastReplicationResult -ne 0).Count -or $shares.Count -ne 2 -or $services.Count -or $srv.Count -lt 2) { throw 'AD health incomplete.' }
    'LEAFIT_AD_HEALTH_PASS'
} catch { 'LEAFIT_AD_HEALTH_FAIL'; exit 1 }
'@
foreach ($name in $vmNames) {
    $result = Invoke-AzVMRunCommand -ResourceGroupName $groupName -VMName $name -CommandId RunPowerShellScript -ScriptString $healthCheck -DefaultProfile $context
    $message = @($result.Value | ForEach-Object Message) -join "`n"
    if ($message -notmatch '(?m)^LEAFIT_AD_HEALTH_PASS\s*$' -or $message -match 'LEAFIT_AD_HEALTH_FAIL') { throw 'Initial AD health verification failed; no automatic repair.' }
}
$parameters.enableBackup = $true
Invoke-OwnedDeployment 'Both'
$vaultName = 'rsv-' + $namePrefix
$vault = Get-AzRecoveryServicesVault -ResourceGroupName $parameters.backupGroupName -Name $vaultName -DefaultProfile $context
$backupItems = @(Get-AzRecoveryServicesBackupItem -BackupManagementType AzureVM -WorkloadType AzureVM -VaultId $vault.ID -DefaultProfile $context)
if ($backupItems.Count -ne 2 -or @($backupItems | Where-Object ProtectionStatus -ne Healthy).Count) { throw 'Backup item protection readback is incomplete.' }
foreach ($item in $backupItems) {
    if ($item.LastBackupStatus -ne 'Completed') {
        $job = Backup-AzRecoveryServicesBackupItem -Item $item -VaultId $vault.ID -ExpiryDateTime ([datetime]::UtcNow.AddDays(7)) -DefaultProfile $context
        $completed = Wait-AzRecoveryServicesBackupJob -Job $job -VaultId $vault.ID -Timeout 3600 -DefaultProfile $context
        if ($completed.Status -ne 'Completed') { throw 'Initial AD-aware backup has not completed.' }
    }
    $recoveryPoints = @(Get-AzRecoveryServicesBackupRecoveryPoint -Item $item -VaultId $vault.ID -StartDate ([datetime]::UtcNow.AddDays(-1)) -EndDate ([datetime]::UtcNow) -DefaultProfile $context)
    if (-not (Test-ApplicationConsistentRecoveryPoint $recoveryPoints ([datetime]::UtcNow.AddDays(-1)))) { throw 'A recent application-consistent VM recovery point is not verified; schedules remain unbound.' }
}
} else {
    if (-not $ownedGroup) { throw 'Owned identity group is missing.' }
    $recoveryGroup = Get-ArmRead ($backupScope + '?api-version=2024-03-01')
    if ($recoveryGroup.tags.workload -ne 'recovery' -or $recoveryGroup.tags.'managed-by' -ne 'bicep') { throw 'Recovery group ownership differs.' }
    $vaultPath = $backupScope + '/providers/Microsoft.RecoveryServices/vaults/rsv-' + $namePrefix
    foreach ($name in $vmNames) {
        $vm = Get-ArmRead ($groupScope + '/providers/Microsoft.Compute/virtualMachines/' + $name + '?api-version=2024-03-01')
        if ($vm.properties.provisioningState -ne 'Succeeded') { throw 'Existing VM provisioning is incomplete.' }
        $itemPath = $vaultPath + '/backupFabrics/Azure/protectionContainers/IaasVMContainer;iaasvmcontainerv2;' + $groupName + ';' + $name + '/protectedItems/VM;iaasvmcontainerv2;' + $groupName + ';' + $name
        $item = Get-ArmRead ($itemPath + '?api-version=2025-01-01')
        if ($item.properties.protectionState -ne 'Protected' -or $item.properties.protectionStatus -ne 'Healthy' -or $item.properties.lastBackupStatus -ne 'Completed') { throw 'Existing backup protection is incomplete; operations-only never starts backups.' }
    }
    [pscustomobject]@{ OperationsOnly = $true; ExistingBackupGatePassed = $true; VmConfigurationAttempted = $false; BackupJobStarted = $false }
}
$operationsPath = Join-Path $artifactDirectory 'operations.json'
az bicep build --file (Join-Path $PSScriptRoot 'operations/resources.bicep') --outfile $operationsPath
if ($LASTEXITCODE -ne 0) { throw 'Scheduling template compilation failed.' }
$zone = [TimeZoneInfo]::FindSystemTimeZoneById('Romance Standard Time')
$localNow = [TimeZoneInfo]::ConvertTime([datetimeoffset]::UtcNow, $zone)
$startTimes = @{}
$accountName = 'aa-' + $namePrefix
$existingSchedules = @()
foreach ($operation in @('Start', 'Stop')) {
    $existingSchedule = Get-ArmRead ($groupScope + '/providers/Microsoft.Automation/automationAccounts/' + $accountName + '/schedules/Dc' + $operation + '?api-version=2023-11-01') -AllowMissing
    $hour = if ($operation -eq 'Start') { 6 } else { 18 }
    if ($existingSchedule) {
        $existingSchedules += [pscustomobject]@{ Name = 'Dc' + $operation }
        $existingStart = [TimeZoneInfo]::ConvertTime([datetimeoffset]::Parse($existingSchedule.properties.startTime), $zone)
        if ($existingStart.Hour -ne $hour -or $existingStart.Minute -ne 0 -or $existingSchedule.properties.timeZone -ne 'Europe/Brussels') { throw 'Existing power-schedule timing differs; timing changes require separate review.' }
        $startTimes[$operation] = $existingStart.UtcDateTime.ToString('o')
        continue
    }
    $candidate = [datetime]::SpecifyKind($localNow.Date.AddDays(1).AddHours($hour), [DateTimeKind]::Unspecified)
    while ($candidate.DayOfWeek -in @([DayOfWeek]::Saturday, [DayOfWeek]::Sunday)) { $candidate = $candidate.AddDays(1) }
    $startTimes[$operation] = [datetimeoffset]::new($candidate, $zone.GetUtcOffset($candidate)).UtcDateTime.ToString('o')
}
if ($existingSchedules.Count -notin @(0, 2)) { throw 'Both existing power schedules must be present before migration.' }
$healthSchedule = Get-ArmRead ($groupScope + '/providers/Microsoft.Automation/automationAccounts/' + $accountName + '/schedules/DcHealth?api-version=2023-11-01') -AllowMissing
if ($healthSchedule) {
    if ($existingSchedules.Count -ne 2) { throw 'Legacy Health exists without both power schedules; review ownership before migration.' }
    $existingSchedules += [pscustomobject]@{ Name = 'DcHealth' }
}
$existingBindings = @(if ($existingSchedules.Count) { Get-AzAutomationScheduledRunbook -ResourceGroupName $groupName -AutomationAccountName $accountName -RunbookName 'InvokeDomainControllerSchedule' -DefaultProfile $context })
$legacyHealthPresent = [bool]$healthSchedule -or (@($existingBindings | Where-Object ScheduleName -eq 'DcHealth').Count -gt 0)
$operationParameters = @{
    location = $settings.TARGET_LOCATION
    namePrefix = $namePrefix
    expectedTenantId = $settings.TARGET_TENANT_ID
    expectedSubscriptionId = $settings.TARGET_SUBSCRIPTION_ID
    vmNames = $vmNames
    scheduleStartTimes = $startTimes
    jobScheduleIds = @{ Start = [guid]::NewGuid().ToString(); Stop = [guid]::NewGuid().ToString() }
    configureSchedules = ($existingSchedules.Count -eq 0)
    enableSchedules = $false
    tags = @{ workload = 'identity'; 'managed-by' = 'bicep' }
}
function Invoke-OperationsDeployment {
    param([switch]$PreviewOnly)
    $preview = Get-AzResourceGroupDeploymentWhatIfResult -ResourceGroupName $groupName -TemplateFile $operationsPath -TemplateParameterObject $operationParameters -DefaultProfile $context
    if ($preview.Status -ne 'Succeeded' -or @($preview.Changes | Where-Object ChangeType -eq 'Delete').Count) { throw 'Scheduling preview failed or includes deletion.' }
    if ($PreviewOnly) { return }
    $result = New-AzResourceGroupDeployment -Name 'leafit-dc-operations' -ResourceGroupName $groupName -TemplateFile $operationsPath -TemplateParameterObject $operationParameters -DefaultProfile $context
    if ($result.ProvisioningState -ne 'Succeeded') { throw 'Scheduling deployment failed.' }
}
$operationParameters.enableSchedules = $true
Invoke-OperationsDeployment -PreviewOnly
$operationParameters.enableSchedules = $false
[pscustomobject]@{ SchedulingPreviewSucceeded = $true; ApplyRequested = $Apply.IsPresent; ExistingBindingsToReplace = $existingBindings.Count; LegacyHealthPresent = $legacyHealthPresent; HealthRetirementRequested = $RetireHealthSchedule.IsPresent; VmActionsPlanned = $false }
if (-not $Apply) { return }
$updateSchedules = {
Invoke-OperationsDeployment
$runtimePath = $groupScope + '/providers/Microsoft.Automation/automationAccounts/' + $accountName + '/runtimeEnvironments/DcPowerShell76?api-version=2024-10-23'
$runtime = Get-ArmRead $runtimePath
if ($runtime.properties.runtime.language -ne 'PowerShell' -or $runtime.properties.runtime.version -ne '7.6' -or $runtime.properties.defaultPackages.Az -ne '15.1.0') { throw 'Supported runtime and pinned Az package readback failed; schedules remain unbound.' }
$contentPath = $groupScope + '/providers/Microsoft.Automation/automationAccounts/' + $accountName + '/runbooks/InvokeDomainControllerSchedule/draft/content?api-version=2024-10-23'
$sourceContent = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'dc/Invoke-Schedule.ps1'))
$accessToken = Get-AzAccessToken -ResourceUrl $context.Environment.ResourceManagerUrl -DefaultProfile $context
try {
    $upload = Invoke-WebRequest -Method Put -Uri ($context.Environment.ResourceManagerUrl.TrimEnd('/') + $contentPath) -Authentication Bearer -Token $accessToken.Token -ContentType 'text/plain; charset=utf-8' -Body $sourceContent -SkipHttpErrorCheck
    if ($upload.StatusCode -notin @(200, 202)) { throw 'Runbook draft content upload failed; schedules remain unbound.' }
} finally { $accessToken = $null }
$uploadedContent = Invoke-AzRestMethod -Method GET -Path $contentPath -DefaultProfile $context
if ($uploadedContent.StatusCode -ne 200 -or ($uploadedContent.Content -replace "`r`n", "`n") -cne ($sourceContent -replace "`r`n", "`n")) { throw 'Runbook draft content readback differs or is pending; schedules remain unbound.' }
$linkedRunbook = Get-ArmRead ($groupScope + '/providers/Microsoft.Automation/automationAccounts/' + $accountName + '/runbooks/InvokeDomainControllerSchedule?api-version=2024-10-23')
if ($linkedRunbook.properties.runtimeEnvironment -ne 'DcPowerShell76') { throw 'Imported runbook runtime link differs; schedules remain unbound.' }
Publish-AzAutomationRunbook -ResourceGroupName $groupName -AutomationAccountName $accountName -Name 'InvokeDomainControllerSchedule' -DefaultProfile $context | Out-Null
$runbook = Get-AzAutomationRunbook -ResourceGroupName $groupName -AutomationAccountName $accountName -Name 'InvokeDomainControllerSchedule' -DefaultProfile $context
if ($runbook.State -ne 'Published') { throw 'Schedule runbook publication readback failed.' }
$linkedRunbook = Get-ArmRead ($groupScope + '/providers/Microsoft.Automation/automationAccounts/' + $accountName + '/runbooks/InvokeDomainControllerSchedule?api-version=2024-10-23')
if ($linkedRunbook.properties.runtimeEnvironment -ne 'DcPowerShell76') { throw 'Published runbook runtime link differs; schedules remain unbound.' }
$operationParameters.enableSchedules = $true
Invoke-OperationsDeployment
$bindings = @(Get-AzAutomationScheduledRunbook -ResourceGroupName $groupName -AutomationAccountName $accountName -RunbookName 'InvokeDomainControllerSchedule')
if ($bindings.Count -ne 2 -or (@($bindings | ForEach-Object ScheduleName | Sort-Object) -join ',') -cne 'DcStart,DcStop') { throw 'Expected exactly the two power-schedule bindings before resume.' }
}
if ($existingSchedules.Count) {
    Invoke-ScheduleMigration -Schedules $existingSchedules -Bindings $existingBindings -Update $updateSchedules -RetireHealthSchedule:$RetireHealthSchedule
} else {
    & $updateSchedules
}
$evidence = [ordered]@{
    verifiedUtc = [datetimeoffset]::UtcNow.ToString('o')
    domainControllerCount = 2
    initialAdHealthPassed = $true
    protectedBackupItemCount = 2
    scheduledJobCount = 2
    scheduledColdStartVerified = $false
    forestRecoveryTested = $false
    cleanTenantRebuildVerified = $false
}
[IO.File]::WriteAllText((Join-Path $artifactDirectory 'verification.json'), ($evidence | ConvertTo-Json))
[pscustomobject]@{ ResourceDeploymentSucceeded = $true; DomainControllerCount = 2; InitialAdHealthPassed = $true; ScheduleConfigured = $true; BackupConfigured = $true; ScheduledColdStartVerified = $false; CleanTenantRebuildVerified = $false }