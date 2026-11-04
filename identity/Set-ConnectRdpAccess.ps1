#requires -Version 7.6
[CmdletBinding()]
param(
    [ValidateSet('Preview','Apply','Verify','Remove')][string]$Mode = 'Preview',
    [switch]$ReconcileClosedState,
    [switch]$CheckOnly
)

$ErrorActionPreference = 'Stop'
if ($ReconcileClosedState -and $Mode -cne 'Preview') { throw 'Closed policy-state reconciliation is read-only Preview only.' }
$repo = Split-Path $PSScriptRoot -Parent
. (Join-Path $PSScriptRoot 'Target.ps1')

function ConvertTo-LeafRdpRuleProperties {
    param([Parameter(Mandatory)]$Properties)
    $result = [ordered]@{}
    foreach ($key in @('description','priority','direction','access','protocol','sourceAddressPrefix','sourcePortRange','destinationAddressPrefix','destinationPortRange','destinationPortRanges')) {
        if ($Properties.Contains($key) -and $null -ne $Properties[$key] -and ($key -ne 'description' -or -not [string]::IsNullOrWhiteSpace($Properties[$key])) -and ($key -ne 'destinationPortRanges' -or @($Properties[$key]).Count)) { $result[$key] = $Properties[$key] }
    }
    foreach ($key in @('sourceAddressPrefix','destinationAddressPrefix')) {
        $parsed = [Net.IPAddress]::None
        if ($result[$key] -and [Net.IPAddress]::TryParse([string]$result[$key], [ref]$parsed) -and $parsed.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) { $result[$key] = $parsed.ToString() + '/32' }
    }
    foreach ($key in @('sourceAddressPrefixes','sourcePortRanges','destinationAddressPrefixes','sourceApplicationSecurityGroups','destinationApplicationSecurityGroups','destinationPortRanges')) {
        if ($key -ne 'destinationPortRanges' -and $Properties[$key]) { throw 'An augmented address, port or application-security-group rule is outside the exact approved exception.' }
    }
    return $result
}

function Test-LeafRdpRuleEqual {
    param($Actual, $Expected)
    $left = [Text.Json.Nodes.JsonNode]::Parse((ConvertTo-Json -InputObject $Actual -Depth 20 -Compress))
    $right = [Text.Json.Nodes.JsonNode]::Parse((ConvertTo-Json -InputObject $Expected -Depth 20 -Compress))
    return [Text.Json.Nodes.JsonNode]::DeepEquals($left, $right)
}

function Get-LeafRdpUnrelatedRules {
    param([object[]]$Rules)
    $records = @(foreach ($rule in @($Rules | Where-Object { $_.name -cnotin @('DenyInbound','DenyInteractiveManagement','AllowConnectBastionRdp') } | Sort-Object name)) {
        $copy = ConvertTo-Json -InputObject $rule -Depth 30 | ConvertFrom-Json -AsHashtable -Depth 30
        $copy.Remove('etag')
        $copy
    })
    return ,$records
}

function Get-LeafRdpNicPreservationValue {
    param([Parameter(Mandatory)]$Properties)
    $copy = ConvertTo-Json -InputObject $Properties -Depth 85 | ConvertFrom-Json -AsHashtable -Depth 85
    foreach ($configuration in @($copy.ipConfigurations)) { $null = $configuration.Remove('etag') }
    return $copy
}

function Assert-LeafRdpUnrelatedPreserved {
    param([object[]]$OriginalRules, [object[]]$CurrentRules)
    if (-not (Test-LeafRdpRuleEqual (Get-LeafRdpUnrelatedRules $OriginalRules) (Get-LeafRdpUnrelatedRules $CurrentRules))) { throw 'UnrelatedRdpSecurityRuleDriftRequiresClosedStateReview' }
}

function Get-LeafConnectRdpPlan {
    param([object[]]$Rules, [ValidateSet('Member','Subnet')][string]$Kind, [string]$PrivateIp, [switch]$Close)
    $address = [Net.IPAddress]::None
    if (-not [Net.IPAddress]::TryParse($PrivateIp, [ref]$address) -or $address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or $address.ToString() -cne $PrivateIp -or $PrivateIp -notmatch '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)') { throw 'The exact private IPv4 destination is required.' }
    $denyName = if ($Kind -ceq 'Member') { 'DenyInbound' } else { 'DenyInteractiveManagement' }
    $deny = @($Rules | Where-Object { $_.name -ceq $denyName })
    $allow = @($Rules | Where-Object { $_.name -ceq 'AllowConnectBastionRdp' })
    if ($deny.Count -ne 1 -or $allow.Count -gt 1) { throw 'The owned deny/exception rule set is absent or ambiguous.' }
    $original = [ordered]@{ priority = 100; direction = 'Inbound'; access = 'Deny'; protocol = if ($Kind -ceq 'Member') { '*' } else { 'Tcp' }; sourceAddressPrefix = '*'; sourcePortRange = '*'; destinationAddressPrefix = '*' }
    if ($Kind -ceq 'Member') { $original.destinationPortRange = '*' } else { $original.destinationPortRanges = @('3389','5985','5986') }
    $currentDeny = ConvertTo-LeafRdpRuleProperties $deny[0].properties
    $expectedCurrent = $original | ConvertTo-Json -Depth 10 | ConvertFrom-Json -AsHashtable
    if ($currentDeny.priority -notin @(100,105,1000)) { throw 'The existing deny priority differs from the reviewed states.' }
    if ($currentDeny.priority -eq 1000) { $original.priority = 1000 }
    $expectedCurrent.priority = $currentDeny.priority
    if (-not (Test-LeafRdpRuleEqual $currentDeny $expectedCurrent)) { throw 'The existing deny rule differs from the approved exact original.' }
    foreach ($rule in $Rules) {
        if ($rule.name -cnotin @($denyName,'AllowConnectBastionRdp') -and $rule.properties.direction -ceq 'Inbound' -and $rule.properties.priority -le 105 -and ($original.priority -ne 1000 -or $rule.properties.access -cne 'Allow')) { throw 'An unrelated early-priority rule prevents the bounded priority change.' }
    }
    $exceptionPriority=100
    if($original.priority -eq 1000){
        $occupied=@($Rules|Where-Object{$_.name -cne 'AllowConnectBastionRdp' -and $_.properties.direction -ceq 'Inbound'}|ForEach-Object{[int]$_.properties.priority})
        if($allow.Count){$exceptionPriority=[int]$allow[0].properties.priority;if($exceptionPriority -lt 100 -or $exceptionPriority -ge 1000 -or $exceptionPriority -in $occupied){throw 'The owned exact RDP allow priority conflicts with existing policy rules.'}}
        else{$free=@(100..999|Where-Object{$_ -notin $occupied}|Select-Object -First 1);if($free.Count -ne 1){throw 'No unused RDP allow priority precedes the preserved policy deny.'};$exceptionPriority=$free[0]}
    }
    $exception = [ordered]@{ description = 'LeafIT temporary Connect setup; remove explicitly after use.'; priority = $exceptionPriority; direction = 'Inbound'; access = 'Allow'; protocol = 'Tcp'; sourceAddressPrefix = '168.63.129.16/32'; sourcePortRange = '*'; destinationAddressPrefix = $PrivateIp + '/32'; destinationPortRange = '3389' }
    if ($allow.Count -and -not (Test-LeafRdpRuleEqual (ConvertTo-LeafRdpRuleProperties $allow[0].properties) $exception)) { throw 'An existing exception is unowned or broader than the approved RDP-only rule.' }
    $desiredDeny = $original | ConvertTo-Json -Depth 10 | ConvertFrom-Json -AsHashtable
    if (-not $Close -and $original.priority -eq 100) { $desiredDeny.priority = 105 }
    return [pscustomobject]@{ DenyName = $denyName; OriginalDeny = $original; CurrentDeny = $currentDeny; DesiredDeny = $desiredDeny; DenyChange = -not (Test-LeafRdpRuleEqual $currentDeny $desiredDeny); ExceptionPresent = $allow.Count -eq 1; Exception = $exception; ExceptionChange = if ($Close) { $allow.Count -eq 1 } else { $allow.Count -eq 0 } }
}

if ($CheckOnly) {
    if (-not (Test-LeafRdpRuleEqual @() @()) -or (Test-LeafRdpRuleEqual @() $null)) { throw 'Empty rule collections must preserve their JSON array shape.' }
    $unchanged = @{ name = 'ExistingRule'; id = 'SYNTHETIC-RULE-REFERENCE'; etag = 'SYNTHETIC-BEFORE'; properties = @{ priority = 120; access = 'Allow'; protocol = 'Tcp' } }
    $metadataOnly = $unchanged | ConvertTo-Json -Depth 10 | ConvertFrom-Json -AsHashtable
    $metadataOnly.etag = 'SYNTHETIC-AFTER'
    if (-not (Test-LeafRdpRuleEqual (Get-LeafRdpUnrelatedRules @($unchanged)) (Get-LeafRdpUnrelatedRules @($metadataOnly)))) { throw 'Provider ETag churn must not be classified as a security-rule change.' }
    $metadataOnly.properties.access = 'Deny'
    if (Test-LeafRdpRuleEqual (Get-LeafRdpUnrelatedRules @($unchanged)) (Get-LeafRdpUnrelatedRules @($metadataOnly))) { throw 'A real unrelated security-rule property change must still stop.' }
    Assert-LeafRdpUnrelatedPreserved @($unchanged) @($unchanged)
    $rejected = $false
    try { Assert-LeafRdpUnrelatedPreserved @($unchanged) @($metadataOnly) } catch { $rejected = $true }
    if (-not $rejected) { throw 'PreOpenUnrelatedRuleDriftMustStopBeforeMutation' }
    $nicBefore = @{ ipConfigurations = @(@{ name = 'primary'; etag = 'SYNTHETIC-BEFORE'; properties = @{ privateIPAddress = '10.44.0.9'; privateIPAllocationMethod = 'Dynamic' } }); enableIPForwarding = $false }
    $nicAfter = $nicBefore | ConvertTo-Json -Depth 15 | ConvertFrom-Json -AsHashtable
    $nicAfter.ipConfigurations[0].etag = 'SYNTHETIC-AFTER'
    if (-not (Test-LeafRdpRuleEqual (Get-LeafRdpNicPreservationValue $nicBefore) (Get-LeafRdpNicPreservationValue $nicAfter))) { throw 'A provider IP-configuration ETag change must not be classified as a NIC security change.' }
    $nicAfter.ipConfigurations[0].properties.privateIPAddress = '10.44.0.10'
    if (Test-LeafRdpRuleEqual (Get-LeafRdpNicPreservationValue $nicBefore) (Get-LeafRdpNicPreservationValue $nicAfter)) { throw 'An actual NIC private-IP change must still stop.' }
    foreach ($kind in @('Member','Subnet')) {
        $name = if ($kind -ceq 'Member') { 'DenyInbound' } else { 'DenyInteractiveManagement' }
        $properties = [ordered]@{ priority = 100; direction = 'Inbound'; access = 'Deny'; protocol = if ($kind -ceq 'Member') { '*' } else { 'Tcp' }; sourceAddressPrefix = '*'; sourcePortRange = '*'; destinationAddressPrefix = '*' }
        if ($kind -ceq 'Member') { $properties.destinationPortRange = '*' } else { $properties.destinationPortRanges = @('3389','5985','5986') }
        $rules = @(@{ name = $name; properties = $properties })
        $plan = Get-LeafConnectRdpPlan $rules $kind '10.44.0.9'
        if (-not $plan.DenyChange -or -not $plan.ExceptionChange -or $plan.DesiredDeny.priority -ne 105 -or $plan.Exception.sourceAddressPrefix -cne '168.63.129.16/32' -or $plan.Exception.destinationAddressPrefix -cne '10.44.0.9/32' -or $plan.Exception.destinationPortRange -cne '3389') { throw 'The exact approved two-rule change was not planned.' }
        $ready = @(@{ name = $name; properties = $plan.DesiredDeny }, @{ name = 'AllowConnectBastionRdp'; properties = $plan.Exception })
        $repeat = Get-LeafConnectRdpPlan $ready $kind '10.44.0.9'
        if ($repeat.DenyChange -or $repeat.ExceptionChange) { throw 'Repeated enable must be NoChange.' }
        $nativeFixture = $ready | ConvertTo-Json -Depth 15 | ConvertFrom-Json -AsHashtable
        if ($kind -ceq 'Member') { $nativeFixture[0].properties.destinationPortRanges = @() }
        $nativeFixture[0].properties.description = $null
        $nativeFixture[1].properties.sourceAddressPrefix = '168.63.129.16'
        $nativeFixture[1].properties.destinationAddressPrefix = '10.44.0.9'
        $nativeFixture[1].properties.destinationPortRanges = @()
        $nativeRepeat = Get-LeafConnectRdpPlan $nativeFixture $kind '10.44.0.9'
        if ($nativeRepeat.DenyChange -or $nativeRepeat.ExceptionChange) { throw 'Native empty collections and equivalent host prefixes must remain NoChange.' }
        $closePlan = Get-LeafConnectRdpPlan $ready $kind '10.44.0.9' -Close
        if (-not $closePlan.ExceptionChange -or $closePlan.DesiredDeny.priority -ne 100 -or -not (Test-LeafRdpRuleEqual $closePlan.DesiredDeny $properties)) { throw 'Removal must restore the exact original deny.' }
        $policyDeny=$properties|ConvertTo-Json -Depth 10|ConvertFrom-Json -AsHashtable
        $policyDeny.priority=1000
        $policyPlan=Get-LeafConnectRdpPlan @(@{name=$name;properties=$policyDeny}) $kind '10.44.0.9'
        if($policyPlan.DenyChange -or -not$policyPlan.ExceptionChange -or $policyPlan.DesiredDeny.priority -ne 1000){throw 'Policy-priority closed state must add only the exact RDP exception without changing its deny.'}
        $policyOpen=@(@{name=$name;properties=$policyDeny},@{name='AllowConnectBastionRdp';properties=$policyPlan.Exception})
        $policyRepeat=Get-LeafConnectRdpPlan $policyOpen $kind '10.44.0.9'
        $policyClose=Get-LeafConnectRdpPlan $policyOpen $kind '10.44.0.9' -Close
        if($policyRepeat.DenyChange -or $policyRepeat.ExceptionChange -or $policyClose.DenyChange -or -not$policyClose.ExceptionChange -or $policyClose.DesiredDeny.priority -ne 1000){throw 'Policy deny must remain exact during zero-write repeat and exception removal.'}
        $otherAllow=@{name='ExistingUnrelatedRdpAllow';properties=@{priority=100;direction='Inbound';access='Allow';protocol='Tcp';sourceAddressPrefix='10.44.0.8/32';sourcePortRange='*';destinationAddressPrefix='10.44.0.9/32';destinationPortRange='3389'}}
        $withOther=@(@{name=$name;properties=$policyDeny},$otherAllow)
        $nextFree=Get-LeafConnectRdpPlan $withOther $kind '10.44.0.9'
        if($nextFree.DenyChange -or $nextFree.Exception.priority -ne 101 -or $otherAllow.properties.priority -ne 100){throw 'Existing allow must remain untouched while the narrow Bastion rule uses the next free priority.'}
        $nextOpen=@($withOther)+@(@{name='AllowConnectBastionRdp';properties=$nextFree.Exception})
        $nextRepeat=Get-LeafConnectRdpPlan $nextOpen $kind '10.44.0.9'
        if($nextRepeat.DenyChange -or $nextRepeat.ExceptionChange){throw 'The next-free-priority RDP rule must converge without another write.'}
        foreach ($bad in @('Source','Destination','Port','Priority','Deny','EarlyRule')) {
            $fixture = $ready | ConvertTo-Json -Depth 15 | ConvertFrom-Json -AsHashtable
            switch ($bad) {
                'Source' { $fixture[1].properties.sourceAddressPrefix = '*' }
                'Destination' { $fixture[1].properties.destinationAddressPrefix = '*' }
                'Port' { $fixture[1].properties.destinationPortRange = '22' }
                'Priority' { $fixture[1].properties.priority = 101 }
                'Deny' { $fixture[0].properties.access = 'Allow' }
                'EarlyRule' { $fixture += @{ name = 'Unrelated'; properties = @{ direction = 'Inbound'; priority = 102 } } }
            }
            $rejected = $false
            try { $null = Get-LeafConnectRdpPlan $fixture $kind '10.44.0.9' } catch { $rejected = $true }
            if (-not $rejected) { throw 'An expanded, conflicting or unowned RDP fixture was accepted.' }
        }
    }
    [pscustomobject]@{ OfflineChecksPassed = $true; ExactSourceDestinationAndRdpOnlyRequired = $true; DenyContentsPreserved = $true; RepeatNoChangeAndExactRemovalVerified = $true; BroadSshAndPriorityConflictsRejected = $true; CloudRequests = 0 }
    return
}

function Invoke-LeafRdpArmRead {
    param([string]$Id, [string]$Version = '2024-05-01', [switch]$AllowMissing)
    try { $response = Invoke-AzRestMethod -Method GET -Path ($Id + '?api-version=' + $Version) -DefaultProfile $context -ErrorAction Stop }
    catch { throw 'The exact RDP target metadata read stopped; no raw response was displayed.' }
    if ($AllowMissing -and $response.StatusCode -eq 404) { return $null }
    if ($response.StatusCode -ne 200) { throw 'The exact RDP target metadata is unreadable.' }
    return $response.Content | ConvertFrom-Json -AsHashtable -Depth 75 -DateKind String
}

function Save-LeafRdpJournal {
    $temporary = $statePath + '.' + [guid]::NewGuid().ToString('N') + '.tmp'
    try { [IO.File]::WriteAllText($temporary, ($journal | ConvertTo-Json -Depth 85), [Text.UTF8Encoding]::new($false)); [IO.File]::Move($temporary, $statePath, $true) }
    finally { if (Test-Path -LiteralPath $temporary) { [IO.File]::Delete($temporary) } }
}

function Set-LeafRdpPrivateInput {
    param([string]$Value)
    $handle = [IO.File]::Open((Join-Path $repo '.env'), [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    try {
        $bytes = [byte[]]::new($handle.Length); $handle.ReadExactly($bytes, 0, $bytes.Length)
        $text = [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
        $pattern = '(?m)^(?<prefix>[ \t]*TARGET_CONNECT_SETUP_RDP_PRIVATE_IP[ \t]*=[ \t]*)(?<value>[^\r\n]*)'
        $entries = [regex]::Matches($text, $pattern)
        if ($entries.Count -gt 1) { throw 'The private RDP desired-state input is ambiguous.' }
        if ($entries.Count) {
            $existing = $entries[0].Groups['value'].Value.Trim().Trim([char]34, [char]39)
            if ($existing -and $existing -cne $privateIp) { throw 'A different private RDP destination is already configured.' }
            $start = $entries[0].Groups['value'].Index; $length = $entries[0].Groups['value'].Length
            $updated = $text.Substring(0, $start) + $Value + $text.Substring($start + $length)
        } else {
            if (-not $Value) { return }
            $updated = $text + $(if ($text.EndsWith("`n")) { '' } else { [Environment]::NewLine }) + 'TARGET_CONNECT_SETUP_RDP_PRIVATE_IP=' + $Value + [Environment]::NewLine
        }
        if ($updated -ceq $text) { return }
        $beforeOther = [regex]::Replace($text, '(?m)^[ \t]*TARGET_CONNECT_SETUP_RDP_PRIVATE_IP[ \t]*=[^\r\n]*(?:\r?\n)?', '').TrimEnd("`r", "`n")
        $afterOther = [regex]::Replace($updated, '(?m)^[ \t]*TARGET_CONNECT_SETUP_RDP_PRIVATE_IP[ \t]*=[^\r\n]*(?:\r?\n)?', '').TrimEnd("`r", "`n")
        if ($beforeOther -cne $afterOther) { throw 'An unrelated private input would change.' }
        $output = [Text.UTF8Encoding]::new($false).GetBytes($updated)
        $handle.Position = 0; $handle.Write($output, 0, $output.Length); $handle.SetLength($output.Length); $handle.Flush($true)
    } finally { $handle.Dispose() }
}

$settings = Read-LeafPrivateTarget $repo
$context = Get-AzContext
Assert-LeafTargetContext $settings $context
$inputs = @{}
foreach ($line in [IO.File]::ReadLines((Join-Path $repo '.env'))) {
    $entry = [regex]::Match($line, '^\s*(?<key>TARGET_(?:REGION_CODE|INSTANCE|CONNECT_SETUP_RDP_PRIVATE_IP))\s*=\s*(?<value>.*)$')
    if (-not $entry.Success) { continue }
    $key = $entry.Groups['key'].Value
    if ($inputs.ContainsKey($key)) { throw 'Duplicate private RDP target input.' }
    $inputs[$key] = $entry.Groups['value'].Value.Trim().Trim([char]34, [char]39)
}
if ($inputs.TARGET_REGION_CODE -cne 'swc' -or $inputs.TARGET_INSTANCE -cnotmatch '^[0-9]{1,3}$') { throw 'The private identity region/instance differs.' }
$prefix = 'identity-' + $inputs.TARGET_REGION_CODE + '-' + $inputs.TARGET_INSTANCE
$groupName = 'rg-' + $prefix
$groupScope = '/subscriptions/' + $settings.TARGET_SUBSCRIPTION_ID + '/resourceGroups/' + $groupName
$root = Join-Path $repo 'private/identity/sync'
$statePath = Join-Path $root 'rdp-access.json'
foreach ($path in @('private/identity/sync/rdp-access.json','private/identity/sync/rdp-access-preview.json','private/identity/sync/rdp-access.lock')) {
    & git -C $repo check-ignore --quiet -- $path
    if ($LASTEXITCODE -ne 0) { throw 'An RDP evidence path is not ignored.' }
    $tracked = @(& git -C $repo ls-files -- $path)
    if ($LASTEXITCODE -ne 0 -or $tracked.Count) { throw 'An RDP evidence path is tracked or cannot be verified.' }
}
[void][IO.Directory]::CreateDirectory($root)
$lock = [IO.File]::Open((Join-Path $root 'rdp-access.lock'), [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
try {
    $dcNames = @(('vm-' + $prefix + '-dc1'), ('vm-' + $prefix + '-dc2'))
    try { $members = @(Get-AzVM -ResourceGroupName $groupName -DefaultProfile $context -ErrorAction Stop | Where-Object { $_.Name -notin $dcNames -and $_.Tags['workload'] -ceq 'identity' -and $_.Tags['managed-by'] -ceq 'bicep' }) }
    catch { throw 'The exact owned member inventory read stopped.' }
    if ($members.Count -ne 1 -or -not ([string]$members[0].Id).StartsWith($groupScope + '/providers/Microsoft.Compute/virtualMachines/', [StringComparison]::OrdinalIgnoreCase) -or $members[0].StorageProfile.OsDisk.OsType -ne 'Windows') { throw 'The exact owned Windows Connect member is absent or ambiguous.' }
    $member = $members[0]
    $nicReferences = @($member.NetworkProfile.NetworkInterfaces)
    if ($nicReferences.Count -ne 1) { throw 'The member NIC binding is ambiguous.' }
    $nic = Invoke-LeafRdpArmRead $nicReferences[0].Id
    $ipConfigurations = @($nic.properties.ipConfigurations)
    if ($ipConfigurations.Count -ne 1 -or $ipConfigurations[0].properties.publicIPAddress -or $ipConfigurations[0].properties.privateIPAllocationMethod -cnotin @('Static','Dynamic')) { throw 'The member must retain exactly one known private-IP allocation and no public IP.' }
    $privateIp = [string]$ipConfigurations[0].properties.privateIPAddress
    if ($inputs.TARGET_CONNECT_SETUP_RDP_PRIVATE_IP -and $inputs.TARGET_CONNECT_SETUP_RDP_PRIVATE_IP -cne $privateIp) { throw 'The saved RDP destination differs from the exact member.' }
    $vnetId = $groupScope + '/providers/Microsoft.Network/virtualNetworks/vnet-' + $prefix
    if ($ipConfigurations[0].properties.subnet.id -ine ($vnetId + '/subnets/snet-adds')) { throw 'The Connect member is not on the reviewed identity subnet.' }
    $subnet = Invoke-LeafRdpArmRead $ipConfigurations[0].properties.subnet.id
    $subnetNsgId = [string]$subnet.properties.networkSecurityGroup.id
    $memberNsgId = [string]$nic.properties.networkSecurityGroup.id
    if ($subnetNsgId -ine ($groupScope + '/providers/Microsoft.Network/networkSecurityGroups/nsg-' + $prefix + '-adds') -or -not $memberNsgId.StartsWith($groupScope + '/providers/Microsoft.Network/networkSecurityGroups/', [StringComparison]::OrdinalIgnoreCase) -or $memberNsgId -ieq $subnetNsgId) { throw 'The exact separate subnet/member NSG bindings differ.' }
    $bastions = @( (Invoke-LeafRdpArmRead ($groupScope + '/providers/Microsoft.Network/bastionHosts')).value | Where-Object { $_.sku.name -ceq 'Developer' -and $_.properties.virtualNetwork.id -ieq $vnetId })
    if ($bastions.Count -ne 1) { throw 'The exact free Developer Bastion/VNet binding is not established.' }
    $binding = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes(($settings.TARGET_TENANT_ID, $member.Id, $nic.id, $subnetNsgId, $memberNsgId, $privateIp -join "`n"))))
    $sourceHash = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash
    $journal = if (Test-Path -LiteralPath $statePath) { Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json -AsHashtable -Depth 90 -DateKind String } else { $null }
    $sourceChanged = $journal -and $journal.sourceSha256 -cne $sourceHash
    if ($journal -and ($journal.bindingSha256 -cne $binding -or ($sourceChanged -and (($Mode -cne 'Verify' -and -not $ReconcileClosedState) -or $journal.pendingOperation)))) { throw 'A changed RDP source permits only exact read-only state reconciliation with no pending operation; no adoption or replay is permitted.' }
    $groups = @()
    foreach ($kind in @('Subnet','Member')) {
        $id = if ($kind -ceq 'Subnet') { $subnetNsgId } else { $memberNsgId }
        $resource = Invoke-LeafRdpArmRead $id
        if ($resource.tags.workload -cne 'identity' -or $resource.tags['managed-by'] -cne 'bicep') { throw 'An RDP target NSG has different ownership.' }
        $plan = Get-LeafConnectRdpPlan @($resource.properties.securityRules) $kind $privateIp -Close:($Mode -ceq 'Remove')
        if ($plan.ExceptionPresent -and -not $journal) { throw 'An existing exception lacks this target-bound receipt; it is not adopted.' }
        $groups += [pscustomobject]@{ Kind = $kind; Id = $id; Resource = $resource; Plan = $plan }
    }
    if ($journal -and $journal.pendingOperation) {
        $pending = $journal.pendingOperation
        $observed = Invoke-LeafRdpArmRead $pending.id -AllowMissing
        $converged = if ($pending.method -ceq 'DELETE') { $null -eq $observed } else { $observed -and (Test-LeafRdpRuleEqual (ConvertTo-LeafRdpRuleProperties $observed.properties) $pending.properties) }
        if (-not $converged) { throw 'An earlier RDP operation is unresolved; inspect the retained intent instead of replaying it.' }
    }
    if ($ReconcileClosedState) {
        if (-not $journal -or $journal.pendingOperation -or $groups.Count -ne 2) { throw 'Exact existing target receipt and no pending writes are required.' }
        foreach($item in $groups){
            if($item.Plan.ExceptionPresent -or $item.Plan.CurrentDeny.priority -ne 1000 -or $item.Plan.DenyChange){throw 'Closed-state reconciliation requires the exact policy deny at 1000 and no RDP allow rule.'}
            $original=@($journal.originalNsgRules|Where-Object{$_.id -ieq $item.Id})
            if($original.Count -ne 1){throw 'The immutable original NSG history is unavailable.'}
        }
        if(-not(Test-LeafRdpRuleEqual (Get-LeafRdpNicPreservationValue $journal.originalNicProperties) (Get-LeafRdpNicPreservationValue $nic.properties))){throw 'Original NIC drift blocks closed-state source reconciliation.'}
        if($sourceChanged){
            $archive=$statePath+'.before-closed-'+[DateTimeOffset]::UtcNow.ToString('yyyyMMddTHHmmssfffffffZ')+'.json'
            [IO.File]::Copy($statePath,$archive,$false)
            if(-not$journal.Contains('sourceVerificationHistory')){$journal.sourceVerificationHistory=@()}
            $journal.sourceVerificationHistory+=@{priorSourceSha256=$journal.sourceSha256;verifiedSourceSha256=$sourceHash;mode='ExactPolicyClosedStateReadback';mutationRequests=0;originalSnapshotPreserved=$true;policyDenyPriorityUnchanged=1000}
            $journal.verificationNsgRules=@($groups|ForEach-Object{@{id=$_.Id;rules=$_.Resource.properties.securityRules}})
            $journal.sourceSha256=$sourceHash;$journal.phase='Closed';$journal.lastVerifiedUtc=[DateTimeOffset]::UtcNow.ToString('o');$journal.lastMutationCount=0
            Save-LeafRdpJournal
        }
        [pscustomobject]@{Mode='Preview';ExactPolicyClosedStateVerified=$true;NsgCount=2;RuleMutationRequests=0;OriginalSnapshotsAndNicPreserved=$true;DenyPriorityUnchanged=1000;SourceMetadataReconciled=$true}
        return
    }
    $changes = @()
    foreach ($item in $groups) {
        if ($Mode -ceq 'Remove' -and $item.Plan.ExceptionChange) { $changes += @{ id = $item.Id + '/securityRules/AllowConnectBastionRdp'; method = 'DELETE'; properties = $null } }
    }
    foreach ($item in $groups) {
        if ($item.Plan.DenyChange) { $changes += @{ id = $item.Id + '/securityRules/' + $item.Plan.DenyName; method = 'PUT'; properties = $item.Plan.DesiredDeny } }
    }
    foreach ($item in $groups) {
        if ($Mode -cne 'Remove' -and $item.Plan.ExceptionChange) { $changes += @{ id = $item.Id + '/securityRules/AllowConnectBastionRdp'; method = 'PUT'; properties = $item.Plan.Exception } }
    }
    $preview = [ordered]@{ bindingSha256 = $binding; sourceSha256 = $sourceHash; mode = $Mode; changes = $changes; source = '168.63.129.16/32'; destination = $privateIp + '/32'; protocol = 'Tcp'; port = '3389'; automaticExpiry = $false; powerOrScheduleChangesAllowed = $false }
    [IO.File]::WriteAllText((Join-Path $root 'rdp-access-preview.json'), ($preview | ConvertTo-Json -Depth 35), [Text.UTF8Encoding]::new($false))
    if ($Mode -ceq 'Preview') { [pscustomobject]@{ PreviewVerified = $true; NsgCount = 2; PlannedRuleMutations = $changes.Count; ExactMemberDestinationOnly = $true; Source = '168.63.129.16/32'; Protocol = 'Tcp'; Port = 3389; ChangesMade = 0; ExplicitRemovalRequired = $true }; return }
    if ($Mode -ceq 'Verify' -and $changes.Count) { throw 'The approved RDP exception has not converged in both NSGs.' }
    if ($Mode -ceq 'Remove' -and -not $journal -and $changes.Count) { throw 'Removal requires the exact owned RDP receipt.' }
    $powerBefore = @()
    foreach ($name in @($member.Name) + $dcNames) {
        try { $status = Get-AzVM -ResourceGroupName $groupName -Name $name -Status -DefaultProfile $context -ErrorAction Stop }
        catch { throw 'The exact existing VM power read stopped.' }
        if ($Mode -ceq 'Apply' -and $name -ceq $member.Name -and @($status.Statuses | Where-Object { $_.Code -cin @('PowerState/running','PowerState/stopped','PowerState/deallocated') }).Count -ne 1) { throw 'The exact Connect member power is unknown or transitional; no power action is permitted.' }
        $powerBefore += ,@($status.Statuses | Where-Object { $_.Code -like 'PowerState/*' } | ForEach-Object { $_.Code })
    }
    if ($Mode -ceq 'Apply' -and $changes.Count -and $journal) {
        foreach ($item in $groups) {
            $baseline = @(if ($journal.verificationNsgRules) { $journal.verificationNsgRules | Where-Object { $_.id -ieq $item.Id } } else { $journal.originalNsgRules | Where-Object { $_.id -ieq $item.Id } })
            if ($baseline.Count -ne 1) { throw 'ExactRdpPreOpenPreservationBaselineRequired' }
            Assert-LeafRdpUnrelatedPreserved @($baseline[0].rules) @($item.Resource.properties.securityRules)
        }
        if (-not (Test-LeafRdpRuleEqual (Get-LeafRdpNicPreservationValue $journal.originalNicProperties) (Get-LeafRdpNicPreservationValue $nic.properties))) { throw 'OriginalNicDriftMustStopBeforeRdpOpening' }
    }
    if ($changes.Count) {
        if (-not $journal) { $journal = [ordered]@{ schemaVersion = 1; bindingSha256 = $binding; sourceSha256 = $sourceHash; originalNsgRules = @($groups | ForEach-Object { @{ id = $_.Id; rules = $_.Resource.properties.securityRules } }); originalNicProperties = $nic.properties; operations = @(); pendingOperation = $null; phase = 'Prepared'; automaticExpiry = $false } }
        $journal.phase = if ($Mode -ceq 'Remove') { 'Closing' } else { 'Opening' }
        Save-LeafRdpJournal
        if ($Mode -ceq 'Apply') { Set-LeafRdpPrivateInput $privateIp }
        foreach ($change in $changes) {
            $journal.pendingOperation = $change
            Save-LeafRdpJournal
            $parameters = @{ Method = $change.method; Path = $change.id + '?api-version=2024-05-01'; DefaultProfile = $context; ErrorAction = 'Stop' }
            if ($change.method -ceq 'PUT') { $parameters.Payload = @{ properties = $change.properties } | ConvertTo-Json -Depth 20 -Compress }
            try { $response = Invoke-AzRestMethod @parameters }
            catch { throw 'The RDP rule request stopped with a retained pending intent; inspect readback before any retry.' }
            if ($response.StatusCode -notin @(200,201,202,204)) { throw 'The RDP rule request was not accepted; its pending intent is retained.' }
            $observed = Invoke-LeafRdpArmRead $change.id -AllowMissing
            $converged = if ($change.method -ceq 'DELETE') { $null -eq $observed } else { $observed -and (Test-LeafRdpRuleEqual (ConvertTo-LeafRdpRuleProperties $observed.properties) $change.properties) }
            if (-not $converged) { throw 'The RDP rule has not converged; inspect its pending intent without another write.' }
            $journal.operations += @{ method = $change.method; id = $change.id; readbackVerified = $true; checkedUtc = [DateTimeOffset]::UtcNow.ToString('o') }
            $journal.pendingOperation = $null
            Save-LeafRdpJournal
        }
    }
    foreach ($item in $groups) {
        $after = Invoke-LeafRdpArmRead $item.Id
        $plan = Get-LeafConnectRdpPlan @($after.properties.securityRules) $item.Kind $privateIp -Close:($Mode -ceq 'Remove')
        if ($plan.DenyChange -or $plan.ExceptionChange) { throw 'RDP readback differs from the exact approved final state.' }
        $original = @(if ($journal -and $journal.verificationNsgRules) { $journal.verificationNsgRules | Where-Object { $_.id -ieq $item.Id } } elseif ($journal) { $journal.originalNsgRules | Where-Object { $_.id -ieq $item.Id } } else { @{ rules = $item.Resource.properties.securityRules } })
        if ($original.Count -ne 1) { throw 'The immutable original NSG rule snapshot is absent or ambiguous.' }
        $beforeOther = Get-LeafRdpUnrelatedRules @($original[0].rules)
        $afterOther = Get-LeafRdpUnrelatedRules @($after.properties.securityRules)
        if (-not (Test-LeafRdpRuleEqual $beforeOther $afterOther)) { throw 'An unrelated NSG rule changed; no preservation claim is made.' }
    }
    $afterNic = Invoke-LeafRdpArmRead $nic.id
    $originalNic = if ($journal) { $journal.originalNicProperties } else { $nic.properties }
    if (-not (Test-LeafRdpRuleEqual (Get-LeafRdpNicPreservationValue $originalNic) (Get-LeafRdpNicPreservationValue $afterNic.properties))) { throw 'The original NIC properties changed; no preservation claim is made.' }
    $powerAfter = @()
    foreach ($name in @($member.Name) + $dcNames) {
        try { $status = Get-AzVM -ResourceGroupName $groupName -Name $name -Status -DefaultProfile $context -ErrorAction Stop }
        catch { throw 'The final exact VM power read stopped.' }
        $powerAfter += ,@($status.Statuses | Where-Object { $_.Code -like 'PowerState/*' } | ForEach-Object { $_.Code })
    }
    if (-not (Test-LeafRdpRuleEqual $powerBefore $powerAfter)) { throw 'VM power changed during the operation; no power-preservation claim is made.' }
    if ($Mode -ceq 'Remove') { Set-LeafRdpPrivateInput '' }
    if ($journal) {
        if ($sourceChanged) {
            if (-not $journal.Contains('sourceVerificationHistory')) { $journal.sourceVerificationHistory = @() }
            $journal.sourceVerificationHistory += @{ priorSourceSha256 = $journal.sourceSha256; verifiedSourceSha256 = $sourceHash; mode = 'ConvergedReadOnlyVerification'; mutationRequests = 0; originalSnapshotPreserved = $true }
            $journal.sourceSha256 = $sourceHash
        }
        $journal.phase = if ($Mode -ceq 'Remove') { 'Closed' } else { 'Open' }; $journal.pendingOperation = $null; $journal.lastVerifiedUtc = [DateTimeOffset]::UtcNow.ToString('o'); $journal.lastMutationCount = $changes.Count; $journal.unrelatedRulesNicAndPowerPreserved = $true; Save-LeafRdpJournal
    }
    [pscustomobject]@{ Mode = $Mode; ExactRdpRulesVerifiedInBothNsgs = $true; RuleMutationRequests = $changes.Count; NoChange = $changes.Count -eq 0; UnrelatedRulesNicAndVmPowerPreserved = $true; SshPublicRdpAndDcRdpNotEnabled = $true; ExplicitRemovalRequired = $Mode -cne 'Remove'; ActualBastionLoginVerified = $false }
} finally { $lock.Dispose() }