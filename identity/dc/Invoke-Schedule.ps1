[CmdletBinding()]
param(
    [ValidateSet('Start', 'Stop')]
    [string]$Action,
    [string]$TenantId,
    [string]$SubscriptionId,
    [string]$ResourceGroupName,
    [ValidatePattern('^vm-[a-z0-9-]+-dc1$')]
    [string]$VmName1,
    [ValidatePattern('^vm-[a-z0-9-]+-dc2$')]
    [string]$VmName2,
    [switch]$CheckOnly
)

$ErrorActionPreference = 'Stop'

function Test-ScheduleWindow {
    param([string]$Operation, [datetimeoffset]$UtcTime)
    $local = [TimeZoneInfo]::ConvertTime($UtcTime, [TimeZoneInfo]::FindSystemTimeZoneById('Romance Standard Time'))
    if ($local.DayOfWeek -in @([DayOfWeek]::Saturday, [DayOfWeek]::Sunday)) { return $false }
    switch ($Operation) {
        'Start' { return $local.Hour -eq 6 }
        'Stop' { return $local.Hour -eq 18 }
    }
    return $false
}

if ($CheckOnly) {
    foreach ($case in @(
        @{ operation = 'Start'; time = '2026-01-05T05:00:00Z'; expected = $true },
        @{ operation = 'Start'; time = '2026-07-06T04:00:00Z'; expected = $true },
        @{ operation = 'Start'; time = '2026-07-06T05:00:00Z'; expected = $false },
        @{ operation = 'Start'; time = '2026-07-05T04:00:00Z'; expected = $false },
        @{ operation = 'Stop'; time = '2026-07-06T16:00:00Z'; expected = $true },
        @{ operation = 'Stop'; time = '2026-01-05T17:00:00Z'; expected = $true },
        @{ operation = 'Stop'; time = '2026-07-05T16:00:00Z'; expected = $false },
        @{ operation = 'Start'; time = '2026-10-26T05:00:00Z'; expected = $true }
    )) {
        if ((Test-ScheduleWindow $case.operation ([datetimeoffset]$case.time)) -ne $case.expected) { throw 'Schedule guard check failed.' }
    }
    'PASS: schedule guards reject weekends and out-of-window starts; winter/summer/DST checks pass.'
    return
}
foreach ($value in @($Action, $TenantId, $SubscriptionId, $ResourceGroupName, $VmName1, $VmName2)) {
    if ([string]::IsNullOrWhiteSpace($value)) { throw 'Explicit action, target, resource group, and two VM names are required.' }
}
foreach ($value in @($TenantId, $SubscriptionId)) {
    $identifier = [guid]::Empty
    if (-not [guid]::TryParse($value, [ref]$identifier) -or $identifier -eq [guid]::Empty) { throw 'Invalid expected target identity.' }
}
if (-not (Test-ScheduleWindow $Action ([datetimeoffset]::UtcNow))) {
    [pscustomobject]@{ Action = $Action; Skipped = $true; Reason = 'OutsideScheduleWindow' }
    return
}
Disable-AzContextAutosave -Scope Process | Out-Null
$connection = Connect-AzAccount -Identity -Tenant $TenantId -Subscription $SubscriptionId
$context = $connection.Context
if ($context.Tenant.Id -ne $TenantId -or $context.Subscription.Id -ne $SubscriptionId) { throw 'Managed identity target mismatch.' }
$names = @($VmName1, $VmName2)
if ($Action -eq 'Stop') { [array]::Reverse($names) }
$failed = 0
foreach ($name in $names) {
    try {
        $vm = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $name -Status -DefaultProfile $context
        $power = @($vm.Statuses | Where-Object Code -like 'PowerState/*' | ForEach-Object Code)
        if ($power.Count -ne 1) { throw 'VM power state is unknown.' }
        switch ($Action) {
            'Start' {
                if ($power[0] -in @('PowerState/deallocated', 'PowerState/stopped')) {
                    Start-AzVM -ResourceGroupName $ResourceGroupName -Name $name -DefaultProfile $context | Out-Null
                } elseif ($power[0] -ne 'PowerState/running') { throw 'VM is in a transitional state.' }
            }
            'Stop' {
                if ($power[0] -in @('PowerState/running', 'PowerState/stopped')) {
                    Stop-AzVM -ResourceGroupName $ResourceGroupName -Name $name -Force -DefaultProfile $context | Out-Null
                } elseif ($power[0] -ne 'PowerState/deallocated') { throw 'VM is in a transitional state.' }
            }
        }
        [pscustomobject]@{ Action = $Action; Succeeded = $true }
    } catch {
        $failed++
        [pscustomobject]@{ Action = $Action; Succeeded = $false; ErrorType = $_.Exception.GetType().Name }
    }
}
if ($failed) { throw 'One or more DC operations failed; operator review required. No automatic AD repair attempted.' }