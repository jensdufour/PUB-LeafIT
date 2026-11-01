#requires -Version 7.6
[CmdletBinding(PositionalBinding = $false)]
param([switch]$CheckOnly)

$ErrorActionPreference = $WarningPreference = 'Stop'
$VerbosePreference = $DebugPreference = $ProgressPreference = 'SilentlyContinue'
$repo = Split-Path $PSScriptRoot -Parent

function Test-ExactExistingBastionRule {
    param($Rule, [string]$Destination)
    if (-not $Rule -or $Rule.name -cne 'AllowConnectBastionRdp') { return $false }
    $properties = $Rule.properties
    return $properties.access -ceq 'Allow' -and $properties.direction -ceq 'Inbound' -and $properties.protocol -ceq 'Tcp' -and $properties.sourceAddressPrefix -ceq '168.63.129.16/32' -and $properties.destinationPortRange -ceq '3389' -and $properties.sourcePortRange -ceq '*' -and $properties.destinationAddressPrefix -cin @($Destination, ($Destination + '/32'))
}

if ($CheckOnly) {
    $fixture = @{ name = 'AllowConnectBastionRdp'; properties = @{ access = 'Allow'; direction = 'Inbound'; protocol = 'Tcp'; sourceAddressPrefix = '168.63.129.16/32'; sourcePortRange = '*'; destinationAddressPrefix = '10.0.0.4/32'; destinationPortRange = '3389' } }
    if (-not (Test-ExactExistingBastionRule $fixture '10.0.0.4')) { throw 'ExactExistingRuleFixtureFailed' }
    foreach ($field in @('access', 'direction', 'protocol', 'sourceAddressPrefix', 'destinationAddressPrefix', 'destinationPortRange')) {
        $changed = $fixture | ConvertTo-Json -Depth 5 | ConvertFrom-Json -AsHashtable
        $changed.properties[$field] = 'UNSELECTED_NON_CREDENTIAL_FIXTURE'
        if (Test-ExactExistingBastionRule $changed '10.0.0.4') { throw 'UnselectedAccessRuleFixtureAccepted' }
    }
    [pscustomobject]@{ Status = 'OfflineChecksPassed'; ChecksPassed = 7; CloudChanges = 0; CredentialReads = 0 }
    return
}

. (Join-Path $repo 'identity/Target.ps1')
$settings = Read-LeafPrivateTarget $repo
$context = Get-AzContext
Assert-LeafTargetContext $settings $context
$preview = Get-Content -LiteralPath (Join-Path $repo 'private/avd/profile-smb-acl-netbios-read-preview.json') -Raw | ConvertFrom-Json -AsHashtable -DateKind String
if ($preview.target.tenantId -ine $settings.TARGET_TENANT_ID -or $preview.target.subscriptionId -ine $settings.TARGET_SUBSCRIPTION_ID) { throw 'ExactOriginalTargetRequired' }
$vm = Get-AzVM -ResourceGroupName $preview.vm.resourceGroupName -Name $preview.vm.name -DefaultProfile $context -ErrorAction Stop
if ($vm.Id -ine $preview.vm.id -or [string]$vm.VmId -ine $preview.vm.vmInstanceId -or $vm.Tags['managed-by'] -cne 'bicep' -or $vm.Tags['workload'] -cne 'identity' -or $vm.NetworkProfile.NetworkInterfaces.Count -ne 1) { throw 'ExactOriginalRepositoryMemberRequired' }

function Read-ExistingAccessMetadata {
    param([string]$Id)
    $reply = Invoke-AzRestMethod -Method GET -Path ($Id + '?api-version=2024-05-01') -DefaultProfile $context -ErrorAction Stop
    if ($reply.StatusCode -ne 200 -or [Text.Encoding]::UTF8.GetByteCount($reply.Content) -gt 1048576) { throw 'BoundedSuccessfulAccessMetadataReadRequired' }
    return ConvertFrom-Json -InputObject $reply.Content -AsHashtable -DateKind String -Depth 40
}

$nic = Read-ExistingAccessMetadata $vm.NetworkProfile.NetworkInterfaces[0].Id
if ($nic.properties.ipConfigurations.Count -ne 1 -or $nic.properties.ipConfigurations[0].properties.publicIPAddress) { throw 'OneExistingPrivateNicOnlyRequired' }
$configuration = $nic.properties.ipConfigurations[0].properties
$address = [string]$configuration.privateIPAddress
$subnet = Read-ExistingAccessMetadata $configuration.subnet.id
$rows = @()
foreach ($scope in @(@{ Kind = 'Member'; Id = $nic.properties.networkSecurityGroup.id }, @{ Kind = 'Subnet'; Id = $subnet.properties.networkSecurityGroup.id })) {
    $nsg = Read-ExistingAccessMetadata $scope.Id
    if ($nsg.tags.workload -cne 'identity' -or $nsg.tags['managed-by'] -cne 'bicep') { throw 'ExactRepositoryNsgOwnerRequired' }
    $rule = @($nsg.properties.securityRules | Where-Object { $_.name -ceq 'AllowConnectBastionRdp' })
    if ($rule.Count -gt 1) { throw 'AmbiguousExistingAccessRuleRejected' }
    $denyName = if ($scope.Kind -ceq 'Member') { 'DenyInbound' } else { 'DenyInteractiveManagement' }
    $deny = @($nsg.properties.securityRules | Where-Object { $_.name -ceq $denyName -and $_.properties.access -ceq 'Deny' -and $_.properties.direction -ceq 'Inbound' })
    if ($deny.Count -ne 1) { throw 'OneOriginalManagementDenyRequired' }
    $beforeDeny = $rule.Count -eq 1 -and $rule[0].properties.priority -lt $deny[0].properties.priority
    $rows += @{ Scope = $scope.Kind; OwnedRulePresent = $rule.Count -eq 1; ExactReviewedSourceDestinationAndPort = $rule.Count -eq 1 -and (Test-ExactExistingBastionRule $rule[0] $address); PrecedesOriginalDeny = $beforeDeny }
}
$journalPath = Join-Path $repo 'private/identity/sync/rdp-access.json'
$journal = if (Test-Path -LiteralPath $journalPath) { Get-Content -LiteralPath $journalPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String } else { $null }
$status = Get-AzVM -ResourceGroupName $preview.vm.resourceGroupName -Name $preview.vm.name -Status -DefaultProfile $context -ErrorAction Stop
$ready = $rows.Count -eq 2 -and @($rows | Where-Object { -not $_.ExactReviewedSourceDestinationAndPort -or -not $_.PrecedesOriginalDeny }).Count -eq 0 -and $journal -and -not $journal.pendingOperation
[pscustomobject]@{ Status = 'ExistingWindowsAccessReadOnly'; OriginalMemberRunning = @($status.Statuses | Where-Object { $_.Code -ceq 'PowerState/running' }).Count -eq 1; Rules = $rows; ExistingTargetReceiptPresent = [bool]$journal; PendingRuleOperation = [bool]$journal.pendingOperation; BothOwnedRulesAlreadyReady = [bool]$ready; NetworkChanges = 0; CredentialReads = 0; PrivateResourceIdsOrAddressesReturned = $false }