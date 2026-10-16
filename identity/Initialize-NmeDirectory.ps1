#requires -Version 7.6
[CmdletBinding()]
param([switch]$CheckOnly, [switch]$Apply, [switch]$CopyJoinPassword)

$ErrorActionPreference = 'Stop'
if (@($CheckOnly, $Apply, $CopyJoinPassword | Where-Object { $_ }).Count -gt 1) { throw 'Choose offline checks, apply, or local credential copy separately.' }
$repo = Split-Path $PSScriptRoot -Parent
. (Join-Path $PSScriptRoot 'Target.ps1')

function Get-NmeWorkloadPrefix([string]$VnetPrefix, [string[]]$ExistingPrefixes) {
    $network = [Net.IPNetwork]::Parse($VnetPrefix)
    if ($network.BaseAddress.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or $network.PrefixLength -gt 24) { throw 'The existing identity VNet has no automatic /24 workload allocation.' }
    $bytes = $network.BaseAddress.GetAddressBytes()
    [array]::Reverse($bytes)
    $first = [uint64][BitConverter]::ToUInt32($bytes, 0)
    $size = [uint64][math]::Pow(2, 32 - $network.PrefixLength)
    foreach ($offset in 0..([int]($size / 256) - 1)) {
        $candidateBytes = [BitConverter]::GetBytes([uint32]($first + $offset * 256))
        [array]::Reverse($candidateBytes)
        $cidr = [Net.IPAddress]::new($candidateBytes).ToString() + '/24'
        $candidate = [Net.IPNetwork]::Parse($cidr)
        $overlap = $false
        foreach ($existingPrefix in $ExistingPrefixes) {
            $existing = [Net.IPNetwork]::Parse($existingPrefix)
            if ($candidate.Contains($existing.BaseAddress) -or $existing.Contains($candidate.BaseAddress)) { $overlap = $true; break }
        }
        if (-not $overlap) { return $cidr }
    }
    throw 'The existing identity VNet has no free /24 workload subnet.'
}

function Assert-NmeWorkloadPrefix([string]$Prefix, [string]$VnetPrefix, [string[]]$OtherPrefixes) {
    $subnet = [Net.IPNetwork]::Parse($Prefix)
    $network = [Net.IPNetwork]::Parse($VnetPrefix)
    if ($subnet.PrefixLength -ne 24 -or -not $network.Contains($subnet.BaseAddress) -or $network.PrefixLength -gt $subnet.PrefixLength) { throw 'The workload subnet must be an aligned /24 inside the existing identity VNet.' }
    foreach ($otherPrefix in $OtherPrefixes) {
        $other = [Net.IPNetwork]::Parse($otherPrefix)
        if ($subnet.Contains($other.BaseAddress) -or $other.Contains($subnet.BaseAddress)) { throw 'The workload subnet overlaps an existing subnet.' }
    }
}

function Get-NmeMeaningfulNetworkChanges([object[]]$Changes) {
    foreach ($change in $Changes) {
        if ($change.ChangeType -in @('Ignore', 'NoChange')) { continue }
        $metadataOnly = $change.ChangeType -eq 'Modify' -and @($change.Delta).Count -eq 1 -and $change.Delta[0].Path -eq 'properties.privateEndpointVNetPolicies' -and $change.Delta[0].PropertyChangeType -eq 'Delete' -and @($change.Delta[0].Before).Count -eq 0 -and $null -eq $change.Delta[0].After
        if (-not $metadataOnly) { $change }
    }
}

if ($CheckOnly) {
    Test-LeafTargetGuards
    if ((Get-NmeWorkloadPrefix '10.80.0.0/16' @('10.80.0.0/24')) -ne '10.80.1.0/24') { throw 'The first-free workload allocation is incorrect.' }
    Assert-NmeWorkloadPrefix '10.80.1.0/24' '10.80.0.0/16' @('10.80.0.0/24')
    foreach ($invalid in @('10.80.0.0/24', '10.81.1.0/24', '10.80.1.0/25')) {
        $rejected = $false
        try { Assert-NmeWorkloadPrefix $invalid '10.80.0.0/16' @('10.80.0.0/24') } catch { $rejected = $true }
        if (-not $rejected) { throw 'An overlapping, out-of-VNet, or incorrectly sized subnet was accepted.' }
    }
    $emptyProviderDelta = @{ ChangeType = 'Modify'; Delta = @(@{ Path = 'properties.privateEndpointVNetPolicies'; PropertyChangeType = 'Delete'; Before = @(); After = $null }) }
    $subnetDelta = @{ ChangeType = 'Modify'; Delta = @(@{ Path = 'properties.subnets'; PropertyChangeType = 'Array' }) }
    if (@(Get-NmeMeaningfulNetworkChanges @($emptyProviderDelta)).Count -ne 0 -or @(Get-NmeMeaningfulNetworkChanges @($subnetDelta)).Count -ne 1) { throw 'The empty provider-metadata comparison hid a meaningful network change.' }
    $null = & (Join-Path $PSScriptRoot 'dc/Configure-NmeJoin.ps1') -Mode CheckOnly
    foreach ($file in @('network/resources.bicep', 'dc/nme-join.bicep')) {
        $compiled = (& az bicep build --file (Join-Path $PSScriptRoot $file) --stdout) -join "`n"
        if ($LASTEXITCODE -ne 0) { throw 'An NMe foundation definition did not compile.' }
        $template = ConvertFrom-Json -InputObject $compiled -AsHashtable -Depth 100
        if ($file -eq 'dc/nme-join.bicep' -and $template.parameters.joinPassword.type -ine 'securestring') { throw 'The join password is not a protected ARM parameter.' }
    }
    [pscustomobject]@{ OfflineChecksPassed = $true; SubnetOverlapGuardsPassed = $true; DelegationChecksPassed = $true; ProtectedGuestParametersPassed = $true; AzureCallsMade = $false }
    return
}

$target = Read-LeafPrivateTarget $repo
$envPath = Join-Path $repo '.env'
$inputNames = @('TARGET_LOCATION', 'TARGET_REGION_CODE', 'TARGET_INSTANCE', 'TARGET_AD_DOMAIN_NAME', 'TARGET_AD_SUBNET_PREFIX', 'TARGET_VNET_ADDRESS_PREFIX', 'TARGET_DC1_PRIVATE_IP', 'TARGET_DC2_PRIVATE_IP', 'TARGET_NME_WORKLOAD_SUBNET_PREFIX', 'TARGET_NME_JOIN_ACCOUNT_SAM', 'TARGET_NME_JOIN_ACCOUNT_UPN', 'TARGET_NME_JOIN_COMPUTER_OU_NAME', 'TARGET_NME_JOIN_COMPUTER_OU_DN', 'TARGET_NME_JOIN_PASSWORD_DPAPI')
$inputs = @{}
foreach ($line in [IO.File]::ReadAllLines($envPath)) {
    $entry = [regex]::Match($line, '^\s*(?<key>TARGET_[A-Z0-9_]+)\s*=\s*(?<value>.*)$')
    if (-not $entry.Success -or $entry.Groups['key'].Value -notin $inputNames) { continue }
    $key = $entry.Groups['key'].Value
    if ($inputs.ContainsKey($key)) { throw 'Duplicate private NMe directory input.' }
    $inputs[$key] = $entry.Groups['value'].Value.Trim().Trim([char]34, [char]39)
}
if ($CopyJoinPassword) {
    if (-not $IsWindows -or -not $inputs.TARGET_NME_JOIN_PASSWORD_DPAPI) { throw 'The protected join credential is unavailable to this Windows account.' }
    $secure = ConvertTo-SecureString $inputs.TARGET_NME_JOIN_PASSWORD_DPAPI
    Set-Clipboard -Value ([Net.NetworkCredential]::new('', $secure).Password)
    $secure = $null
    [pscustomobject]@{ JoinPasswordCopiedLocally = $true; PasswordPrinted = $false; AzureCallsMade = $false }
    return
}
foreach ($key in @('TARGET_LOCATION', 'TARGET_REGION_CODE', 'TARGET_INSTANCE', 'TARGET_AD_DOMAIN_NAME', 'TARGET_AD_SUBNET_PREFIX', 'TARGET_VNET_ADDRESS_PREFIX', 'TARGET_DC1_PRIVATE_IP', 'TARGET_DC2_PRIVATE_IP')) {
    if ([string]::IsNullOrWhiteSpace($inputs[$key])) { throw 'A required private identity/network input is missing.' }
}
if ($inputs.TARGET_LOCATION -ne 'swedencentral' -or $inputs.TARGET_REGION_CODE -ne 'swc' -or $inputs.TARGET_INSTANCE -notmatch '^[0-9]{1,3}$' -or $inputs.TARGET_AD_DOMAIN_NAME -notmatch '^(?=.{1,253}$)[A-Za-z0-9][A-Za-z0-9.-]+\.[A-Za-z]{2,}$') { throw 'The selected region, naming instance, or AD domain is invalid.' }
Import-Module Az.Accounts -MinimumVersion 5.3.3 -ErrorAction Stop
Import-Module Az.Resources -ErrorAction Stop
Import-Module Az.Compute -ErrorAction Stop
$context = Get-AzContext
Assert-LeafTargetContext $target $context
$namePrefix = 'identity-' + $inputs.TARGET_REGION_CODE + '-' + $inputs.TARGET_INSTANCE
$groupName = 'rg-' + $namePrefix
$scope = '/subscriptions/' + $target.TARGET_SUBSCRIPTION_ID + '/resourceGroups/' + $groupName
$networkName = 'vnet-' + $namePrefix
$networkPath = $scope + '/providers/Microsoft.Network/virtualNetworks/' + $networkName + '?api-version=2024-05-01'
$networkResponse = Invoke-AzRestMethod -Method GET -Path $networkPath -DefaultProfile $context
if ($networkResponse.StatusCode -ne 200) { throw 'The repository-owned AD VNet does not exist or cannot be read.' }
$network = ConvertFrom-Json -InputObject $networkResponse.Content -AsHashtable -Depth 50
$dns = @($network.properties.dhcpOptions.dnsServers)
$privateIps = @($inputs.TARGET_DC1_PRIVATE_IP, $inputs.TARGET_DC2_PRIVATE_IP)
if ($network.location -ne $inputs.TARGET_LOCATION -or $network.tags.workload -ne 'identity' -or $network.tags.'managed-by' -ne 'bicep' -or @($network.properties.addressSpace.addressPrefixes).Count -ne 1 -or $network.properties.addressSpace.addressPrefixes[0] -ne $inputs.TARGET_VNET_ADDRESS_PREFIX -or $dns.Count -ne 2 -or (Compare-Object $dns $privateIps)) { throw 'The existing AD VNet ownership, address space, or dual-DC DNS differs from private inputs.' }
if (@($network.properties.subnets | Where-Object { $_.name -notin @('snet-adds', 'snet-avd') }).Count) { throw 'The identity VNet contains another subnet; its definition must be preserved before this change.' }
$adSubnet = @($network.properties.subnets | Where-Object name -eq 'snet-adds')
$workloadSubnet = @($network.properties.subnets | Where-Object name -eq 'snet-avd')
if ($adSubnet.Count -ne 1 -or $adSubnet[0].properties.addressPrefix -ne $inputs.TARGET_AD_SUBNET_PREFIX) { throw 'The existing DC subnet does not match the private identity definition.' }
$otherPrefixes = @($network.properties.subnets | Where-Object name -ne 'snet-avd' | ForEach-Object { $_.properties.addressPrefix })
$workloadPrefix = if ($inputs.TARGET_NME_WORKLOAD_SUBNET_PREFIX) { $inputs.TARGET_NME_WORKLOAD_SUBNET_PREFIX } elseif ($workloadSubnet.Count -eq 1) { [string]$workloadSubnet[0].properties.addressPrefix } else { Get-NmeWorkloadPrefix $inputs.TARGET_VNET_ADDRESS_PREFIX $otherPrefixes }
Assert-NmeWorkloadPrefix $workloadPrefix $inputs.TARGET_VNET_ADDRESS_PREFIX $otherPrefixes
if ($workloadSubnet.Count -eq 1 -and $workloadSubnet[0].properties.addressPrefix -ne $workloadPrefix) { throw 'The existing workload subnet differs; it will not be resized implicitly.' }
$accountName = if ($inputs.TARGET_NME_JOIN_ACCOUNT_SAM) { $inputs.TARGET_NME_JOIN_ACCOUNT_SAM } else { 'svc-nme-join' }
$ouName = if ($inputs.TARGET_NME_JOIN_COMPUTER_OU_NAME) { $inputs.TARGET_NME_JOIN_COMPUTER_OU_NAME } else { 'NMe-Computers' }
if ($accountName -notmatch '^svc-[a-z0-9-]{1,16}$' -or $accountName.Length -gt 20 -or $ouName -notmatch '^[A-Za-z][A-Za-z0-9 -]{1,62}$') { throw 'The dedicated join account or OU input is invalid.' }
$accountUpn = $accountName + '@' + $inputs.TARGET_AD_DOMAIN_NAME
$ouDn = 'OU=' + $ouName + ',' + (($inputs.TARGET_AD_DOMAIN_NAME -split '\.' | ForEach-Object { 'DC=' + $_ }) -join ',')
if (($inputs.TARGET_NME_JOIN_ACCOUNT_UPN -and $inputs.TARGET_NME_JOIN_ACCOUNT_UPN -ine $accountUpn) -or ($inputs.TARGET_NME_JOIN_COMPUTER_OU_DN -and $inputs.TARGET_NME_JOIN_COMPUTER_OU_DN -ine $ouDn)) { throw 'The existing private join bindings conflict with the selected AD domain.' }
$vmNames = @('vm-{0}-dc1' -f $namePrefix) + @('vm-{0}-dc2' -f $namePrefix)
foreach ($vmName in $vmNames) {
    $vm = Get-AzVM -ResourceGroupName $groupName -Name $vmName -Status -DefaultProfile $context
    if (@($vm.Statuses | Where-Object Code -eq 'PowerState/running').Count -ne 1) { throw 'Both existing DCs must be running for directory setup; their operating schedule is not changed here.' }
}
$brand = Get-Content -LiteralPath (Join-Path $repo 'branding/brand.json') -Raw | ConvertFrom-Json -AsHashtable
$guestPath = Join-Path $PSScriptRoot 'dc/Configure-NmeJoin.ps1'
$inspection = Invoke-AzVMRunCommand -ResourceGroupName $groupName -VMName $vmNames[0] -CommandId RunPowerShellScript -ScriptPath $guestPath -Parameter @{ Mode = 'Preview'; DomainName = $inputs.TARGET_AD_DOMAIN_NAME; AccountName = $accountName; ComputerOuName = $ouName; OrganizationName = $brand.name } -DefaultProfile $context
$inspectionText = @($inspection.Value | ForEach-Object Message) -join "`n"
$inspectionJson = [regex]::Matches($inspectionText, '(?m)^\{[^\r\n]*\}\s*$')
if ($inspectionJson.Count -ne 1) { throw 'The primary DC did not return unambiguous directory inspection.' }
$directoryBefore = ConvertFrom-Json -InputObject $inspectionJson[0].Value -AsHashtable
if ($directoryBefore.Status -ne 'Preview' -or $directoryBefore.DomainMatchesTarget -ne $true) { throw ('The primary DC inspection stopped ({0}; {1}; source line {2}); no new apply was attempted.' -f $directoryBefore.ErrorType, $directoryBefore.ErrorCommand, $directoryBefore.ErrorLine) }
if ($directoryBefore.JoinAccountExists -eq $true -and -not $inputs.TARGET_NME_JOIN_PASSWORD_DPAPI) { throw 'The existing join account has no protected local credential; it will not be reset implicitly.' }
$privateRoot = Join-Path $repo 'private/identity/nme'
[void][IO.Directory]::CreateDirectory($privateRoot)
$networkTemplate = Join-Path $privateRoot 'network.json'
& az bicep build --file (Join-Path $PSScriptRoot 'network/resources.bicep') --outfile $networkTemplate
if ($LASTEXITCODE -ne 0) { throw 'The network-only definition did not compile.' }
$parameters = @{ location = $inputs.TARGET_LOCATION; namePrefix = $namePrefix; addressPrefix = $inputs.TARGET_VNET_ADDRESS_PREFIX; subnetPrefix = $inputs.TARGET_AD_SUBNET_PREFIX; workloadSubnetPrefix = $workloadPrefix; privateIps = $privateIps; dnsStage = 'Both'; tags = $network.tags; manageEgress = $false }
$preview = Get-AzResourceGroupDeploymentWhatIfResult -ResourceGroupName $groupName -TemplateFile $networkTemplate -TemplateParameterObject $parameters -ResultFormat FullResourcePayloads -DefaultProfile $context
[IO.File]::WriteAllText((Join-Path $privateRoot 'network-what-if.json'), ($preview | ConvertTo-Json -Depth 80), [Text.UTF8Encoding]::new($false))
if ($preview.Status -ne 'Succeeded' -or $preview.Error) { throw 'The network-only preview did not succeed.' }
$allowedIds = @(
    ($scope + '/providers/Microsoft.Network/networkSecurityGroups/nsg-' + $namePrefix + '-adds'),
    ($scope + '/providers/Microsoft.Network/networkSecurityGroups/nsg-' + $namePrefix + '-avd'),
    ($scope + '/providers/Microsoft.Network/virtualNetworks/' + $networkName)
)
$changes = @(Get-NmeMeaningfulNetworkChanges @($preview.Changes))
foreach ($change in $changes) {
    if ($change.ChangeType -notin @('Create', 'Modify', 'Deploy') -or $change.FullyQualifiedResourceId -notin $allowedIds) { throw 'The network preview includes an unexpected resource or destructive change.' }
}
$linking = @{ domainName = $inputs.TARGET_AD_DOMAIN_NAME; joinAccountUpn = $accountUpn; computerOuDn = $ouDn; networkResourceId = $network.id; subnetResourceId = $network.id + '/subnets/snet-avd'; fslogixStorageCreated = $false; entraSynchronizationChanged = $false }
if (-not $Apply) {
    [IO.File]::WriteAllText((Join-Path $privateRoot 'linking-preview.json'), ($linking | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
    [pscustomobject]@{ Mode = 'Preview'; ExistingDomainVerified = $true; NetworkOnlyChanges = $changes.Count; WorkloadSubnetExists = $workloadSubnet.Count -eq 1; JoinAccountExists = $directoryBefore.JoinAccountExists; ComputerOuExists = $directoryBefore.ComputerOuExists; AzureResourcesChanged = $false; DirectoryChanged = $false }
    return
}
if (-not $IsWindows) { throw 'Windows DPAPI is required for the delegated join credential.' }
$additions = [ordered]@{ TARGET_NME_WORKLOAD_SUBNET_PREFIX = $workloadPrefix; TARGET_NME_JOIN_ACCOUNT_SAM = $accountName; TARGET_NME_JOIN_ACCOUNT_UPN = $accountUpn; TARGET_NME_JOIN_COMPUTER_OU_NAME = $ouName; TARGET_NME_JOIN_COMPUTER_OU_DN = $ouDn }
if (-not $inputs.TARGET_NME_JOIN_PASSWORD_DPAPI) {
    $random = [byte[]]::new(30)
    [Security.Cryptography.RandomNumberGenerator]::Fill($random)
    $secure = ConvertTo-SecureString ('Aa1!' + [Convert]::ToBase64String($random)) -AsPlainText -Force
    [array]::Clear($random, 0, $random.Length)
    $additions.TARGET_NME_JOIN_PASSWORD_DPAPI = $secure | ConvertFrom-SecureString
} else { $secure = ConvertTo-SecureString $inputs.TARGET_NME_JOIN_PASSWORD_DPAPI }
$lines = @($additions.Keys | Where-Object { -not $inputs.ContainsKey($_) } | ForEach-Object { $_ + '=' + $additions[$_] })
if ($lines.Count) { [IO.File]::AppendAllText($envPath, ([Environment]::NewLine + [string]::Join([Environment]::NewLine, $lines) + [Environment]::NewLine), [Text.UTF8Encoding]::new($false)) }
Assert-LeafTargetContext $target (Get-AzContext)
if ($changes.Count) {
    $deployment = New-AzResourceGroupDeployment -Name 'identity-nme-network' -ResourceGroupName $groupName -TemplateFile $networkTemplate -TemplateParameterObject $parameters -SkipTemplateParameterPrompt -DefaultProfile $context
    if ($deployment.ProvisioningState -ne 'Succeeded') { throw 'The workload subnet deployment did not complete.' }
}
$guestTemplate = Join-Path $privateRoot 'join.json'
& az bicep build --file (Join-Path $PSScriptRoot 'dc/nme-join.bicep') --outfile $guestTemplate
if ($LASTEXITCODE -ne 0) { throw 'The protected guest definition did not compile.' }
$joinParameters = @{ location = $inputs.TARGET_LOCATION; vmName = $vmNames[0]; mode = 'Apply'; domainName = $inputs.TARGET_AD_DOMAIN_NAME; accountName = $accountName; computerOuName = $ouName; organizationName = $brand.name; joinPassword = [Net.NetworkCredential]::new('', $secure).Password }
function Read-NmeJoinResult([string]$VmName) {
    $commandPath = $scope + '/providers/Microsoft.Compute/virtualMachines/' + $VmName + '/runCommands/ConfigureNmeJoin?api-version=2024-07-01&$expand=instanceView'
    $commandResponse = Invoke-AzRestMethod -Method GET -Path $commandPath -DefaultProfile $context
    if ($commandResponse.StatusCode -ne 200) { throw 'The delegated directory result could not be read.' }
    $command = (ConvertFrom-Json -InputObject $commandResponse.Content -AsHashtable -Depth 40).properties.instanceView
    $result = ConvertFrom-Json -InputObject ([string]$command.output).Trim() -AsHashtable
    if ($command.exitCode -ne 0 -or $result.DomainMatchesTarget -ne $true -or $result.DelegationVerified -ne $true -or $result.CredentialBindVerified -ne $true) { throw 'The delegated account, OU rights, or password bind did not verify.' }
    return $result
}
try {
    Assert-LeafTargetContext $target (Get-AzContext)
    $guestDeployment = New-AzResourceGroupDeployment -Name 'identity-nme-directory' -ResourceGroupName $groupName -TemplateFile $guestTemplate -TemplateParameterObject $joinParameters -SkipTemplateParameterPrompt -DefaultProfile $context
    if ($guestDeployment.ProvisioningState -ne 'Succeeded') { throw 'The delegated directory setup did not complete.' }
    $result = Read-NmeJoinResult $vmNames[0]
    foreach ($vmName in $vmNames) {
        $joinParameters.vmName = $vmName
        $joinParameters.mode = 'Verify'
        $verifyDeployment = New-AzResourceGroupDeployment -Name ('identity-nme-verify-' + [array]::IndexOf($vmNames, $vmName)) -ResourceGroupName $groupName -TemplateFile $guestTemplate -TemplateParameterObject $joinParameters -SkipTemplateParameterPrompt -DefaultProfile $context
        if ($verifyDeployment.ProvisioningState -ne 'Succeeded') { throw 'The delegated join verification did not complete on both DCs.' }
        $null = Read-NmeJoinResult $vmName
    }
} finally { $secure = $null; $joinParameters.joinPassword = $null }
$networkReadback = Invoke-AzRestMethod -Method GET -Path $networkPath -DefaultProfile $context
if ($networkReadback.StatusCode -ne 200) { throw 'The workload network could not be verified.' }
$afterNetwork = (ConvertFrom-Json -InputObject $networkReadback.Content -AsHashtable -Depth 50).properties
$afterSubnet = @($afterNetwork.subnets | Where-Object name -eq 'snet-avd')
if ($afterSubnet.Count -ne 1 -or $afterSubnet[0].properties.addressPrefix -ne $workloadPrefix -or -not $afterSubnet[0].properties.networkSecurityGroup.id -or -not $afterSubnet[0].properties.natGateway.id -or (Compare-Object @($afterNetwork.dhcpOptions.dnsServers) $privateIps)) { throw 'The workload subnet, NAT, NSG, or inherited DNS did not verify.' }
$linking.directoryVerified = $true
$linking.directoryVerifiedOnBothDcs = $true
$linking.networkVerified = $true
$linking.joinCredentialProtectedLocally = $true
[IO.File]::WriteAllText((Join-Path $privateRoot 'linking.json'), ($linking | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
[pscustomobject]@{ Mode = if ($changes.Count -or $result.DirectoryChangesMade) { 'Applied' } else { 'NoChange' }; ExistingDomainVerified = $true; WorkloadSubnetVerified = $true; DualDcDnsVerified = $true; DelegatedJoinAccountVerified = $true; CredentialBindVerifiedOnBothDcs = $true; DomainControllerVmsRedeployed = $false; SynchronizationChanged = $false; ProfileStorageCreated = $false; PasswordPrinted = $false }