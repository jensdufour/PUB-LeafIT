#requires -Version 7.6
[CmdletBinding(PositionalBinding = $false)]
param([switch]$Run, [switch]$OperatorApproved, [ValidateSet('initial', 'server-name-shape', 'logon-audit')][string]$Attempt = 'initial', [switch]$CheckOnly)

$ErrorActionPreference = $WarningPreference = 'Stop'
$VerbosePreference = $DebugPreference = $ProgressPreference = 'SilentlyContinue'
$repo = Split-Path $PSScriptRoot -Parent

function Get-LeafProfileSmbClientSource {
    return @'
param([string]$MetadataBase64)
$ErrorActionPreference = 'Stop'
$ProgressPreference = $VerbosePreference = $DebugPreference = 'SilentlyContinue'
function GetClientHash([string]$Text) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text.Trim().ToLowerInvariant())))).Replace('-', '') } finally { $sha.Dispose() }
}
function TestClientServer([string]$Value, [string]$HostName, [string]$Address) {
    $server = $Value.TrimStart([char]92).Split([char]92)[0]
    return $server -ieq $HostName -or $server -ceq $Address
}
try {
    $meta = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($MetadataBase64)) | ConvertFrom-Json
    if ($meta.Nonce -cnotmatch '^[a-f0-9]{32}$' -or $meta.AccountName -cnotmatch '^[a-z0-9]{3,24}$' -or $meta.ComputerSha256 -cnotmatch '^[A-F0-9]{64}$' -or $meta.DomainSha256 -cnotmatch '^[A-F0-9]{64}$') { throw 'MetadataRejected' }
    $system = Get-CimInstance Win32_ComputerSystem -OperationTimeoutSec 5
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $identity.IsSystem -or -not $system.PartOfDomain -or (GetClientHash $system.Name) -cne $meta.ComputerSha256 -or (GetClientHash $system.Domain) -cne $meta.DomainSha256) { throw 'ExactMemberSystemRequired' }
    $configuration = Get-SmbClientConfiguration -ErrorAction Stop
    $hostName = $meta.AccountName + '.file.core.windows.net'
    $rows = @()
    foreach ($name in @('Microsoft-Windows-SMBClient/Connectivity', 'Microsoft-Windows-SMBClient/Security')) {
        $kind = if ($name.EndsWith('/Security')) { 'Security' } else { 'Connectivity' }
        $log = Get-WinEvent -ListLog $name -ErrorAction SilentlyContinue
        if (-not $log) { $rows += @{ Channel = $kind; Available = $false; Enabled = $false; Matches = 0; EventIds = @(); StatusCodes = @() }; continue }
        $events = @(Get-WinEvent -FilterHashtable @{ LogName = $name; StartTime = [datetime]::UtcNow.AddHours(-2) } -MaxEvents 128 -ErrorAction SilentlyContinue)
        $matched = @(); $codes = @(); $fieldNames = @()
        foreach ($event in $events) {
            $xml = [xml]$event.ToXml()
            $data = @($xml.Event.EventData.Data)
            $fieldNames += @($data | ForEach-Object { [string]$_.Name } | Where-Object { $_ -cmatch '^[A-Za-z][A-Za-z0-9]{0,47}$' })
            $server = @($data | Where-Object { $_.Name -in @('ServerName', 'ServerAddress', 'ShareName') } | ForEach-Object { [string]$_.'#text' })
            if (-not @($server | Where-Object { TestClientServer $_ $hostName $meta.PrivateIp }).Count) { continue }
            $matched += [int]$event.Id
            foreach ($field in $data | Where-Object { $_.Name -in @('Status', 'ErrorCode', 'NtStatus', 'Win32Error', 'Reason') }) { $value = [string]$field.'#text'; if ($value -match '^0x[0-9A-Fa-f]{1,8}$') { $codes += $value.ToUpperInvariant() } elseif ($value -match '^\d{1,10}$') { $number = [uint32]::Parse($value); $codes += ('0x{0:X8}' -f $number) } }
        }
        $rows += @{ Channel = $kind; Available = $true; Enabled = [bool]$log.IsEnabled; ExaminedEvents = $events.Count; Matches = $matched.Count; FieldNames = @($fieldNames | Sort-Object -Unique); EventIds = @($matched | Sort-Object -Unique); StatusCodes = @($codes | Sort-Object -Unique) }
    }
    $audit = @{ SelectedAdministratorMatches = 0; LogonTypes = @(); AuthenticationPackages = @(); LogonProcesses = @(); AuditReadSucceeded = $false }
    if ($meta.LogonAudit -eq $true) {
        if ($meta.AdministratorSidSha256 -cnotmatch '^[A-F0-9]{64}$') { throw 'ExactAdministratorAuditScopeRequired' }
        $events = @()
        try { $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4624; StartTime = [datetime]::UtcNow.AddHours(-2) } -MaxEvents 256 -ErrorAction Stop); $audit.AuditReadSucceeded = $true }
        catch { $audit.AuditReadSucceeded = $_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*' }
        foreach ($event in $events) {
            $data = @(([xml]$event.ToXml()).Event.EventData.Data)
            $sid = @($data | Where-Object { $_.Name -ceq 'TargetUserSid' } | ForEach-Object { [string]$_.'#text' })
            if ($sid.Count -ne 1 -or (GetClientHash $sid[0]) -cne $meta.AdministratorSidSha256) { continue }
            $audit.SelectedAdministratorMatches++
            foreach ($field in $data) {
                $value = [string]$field.'#text'
                if ($field.Name -ceq 'LogonType' -and $value -match '^\d{1,2}$') { $audit.LogonTypes += [int]$value }
                elseif ($field.Name -ceq 'AuthenticationPackageName' -and $value -cin @('Kerberos', 'Negotiate', 'NTLM', 'MICROSOFT_AUTHENTICATION_PACKAGE_V1_0')) { $audit.AuthenticationPackages += $value }
                elseif ($field.Name -ceq 'LogonProcessName') { $process = $value.Trim(); if ($process -cin @('Advapi', 'Kerberos', 'NtLmSsp', 'User32', 'seclogo')) { $audit.LogonProcesses += $process } }
            }
        }
        foreach ($field in @('LogonTypes', 'AuthenticationPackages', 'LogonProcesses')) { $audit[$field] = @($audit[$field] | Sort-Object -Unique) }
    }
    'LEAFIT_SMB_CLIENT_METADATA=' + (@{ Status = 'ReadOnlyClientMetadata'; Nonce = $meta.Nonce; ExactMemberSystemVerified = $true; RequireSecuritySignature = [bool]$configuration.RequireSecuritySignature; EnableSecuritySignature = [bool]$configuration.EnableSecuritySignature; EnableInsecureGuestLogons = [bool]$configuration.EnableInsecureGuestLogons; Channels = $rows; LogonAudit = $audit; ConfigurationWrites = 0; CredentialReads = 0; SmbRequests = 0; RawEventsReturned = $false } | ConvertTo-Json -Depth 6 -Compress)
} catch {
    'LEAFIT_SMB_CLIENT_METADATA=' + (@{ Status = 'Stopped'; ErrorType = $_.Exception.GetType().Name; ConfigurationWrites = 0; CredentialReads = 0; SmbRequests = 0; RawEventsReturned = $false } | ConvertTo-Json -Compress)
    exit 1
} finally { if ($identity) { $identity.Dispose() }; $events = $xml = $data = $server = $field = $configuration = $null }
'@
}

if ($CheckOnly) {
    $source = Get-LeafProfileSmbClientSource
    $tokens = $syntax = $null
    $ast = [Management.Automation.Language.Parser]::ParseInput($source, [ref]$tokens, [ref]$syntax)
    $commands = @($ast.FindAll({ param($node) $node -is [Management.Automation.Language.CommandAst] }, $true))
    if ($syntax.Count -or @($commands | Where-Object { $_.GetCommandName() -match '^(Set-|Start-|Stop-|Restart-|Connect-|New-Az|Remove-|Get-AzStorageAccountKey|Get-Acl|Get-ChildItem|Get-Content|klist|cmdkey)' }).Count) { throw 'OnlyClientMetadataGettersPermitted' }
    if ($source -match '\.Message|FormatDescription|ToString\(\).*event') { throw 'RawEventTextMustNotReturn' }
    $matcher = @($ast.EndBlock.Statements | Where-Object { $_ -is [Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -ceq 'TestClientServer' })
    if ($matcher.Count -ne 1) { throw 'ExactServerMatcherRequired' }
    . ([scriptblock]::Create($matcher[0].Extent.Text))
    foreach ($value in @('fixture.file.core.windows.net', '\\fixture.file.core.windows.net', '\\fixture.file.core.windows.net\profiles', '10.0.0.4')) { if (-not (TestClientServer $value 'fixture.file.core.windows.net' '10.0.0.4')) { throw 'NativeServerFieldFixtureRejected' } }
    foreach ($value in @('other.file.core.windows.net', 'fixture.file.core.windows.net.other.invalid', '10.0.0.5')) { if (TestClientServer $value 'fixture.file.core.windows.net' '10.0.0.4') { throw 'UnselectedServerFixtureAccepted' } }
    [pscustomobject]@{ Status = 'OfflineChecksPassed'; ChecksPassed = 10; GuestSourceGetterOnly = $true; CloudActions = 0 }
    return
}

if ($Run -ne $OperatorApproved) { throw 'OneExplicitReadOnlyClientInspectionRequired' }
. (Join-Path $repo 'identity/Target.ps1')
$settings = Read-LeafPrivateTarget $repo
$context = Get-AzContext
Assert-LeafTargetContext $settings $context
$previewPath = Join-Path $repo 'private/avd/profile-smb-acl-netbios-read-preview.json'
$preview = Get-Content -LiteralPath $previewPath -Raw | ConvertFrom-Json -AsHashtable -DateKind String
$vm = Get-AzVM -ResourceGroupName $preview.vm.resourceGroupName -Name $preview.vm.name -ErrorAction Stop
$power = Get-AzVM -ResourceGroupName $preview.vm.resourceGroupName -Name $preview.vm.name -Status -ErrorAction Stop
if ($vm.Id -ine $preview.vm.id -or [string]$vm.VmId -ine $preview.vm.vmInstanceId -or $vm.Tags['managed-by'] -cne 'bicep' -or $preview.target.tenantId -ine $settings.TARGET_TENANT_ID -or $preview.target.subscriptionId -ine $settings.TARGET_SUBSCRIPTION_ID -or @($power.Statuses | Where-Object { $_.Code -ceq 'PowerState/running' }).Count -ne 1) { throw 'ExactAlreadyRunningOriginalMemberRequired' }
if (-not $Run) { [pscustomobject]@{ Status = 'ExactReadOnlySmbClientPreview'; GuestActions = 0; CredentialReads = 0; ConfigChanges = 0 }; return }
$suffix = if ($Attempt -ceq 'initial') { '' } else { '-' + $Attempt }
$intentPath = Join-Path $repo ('private/avd/profile-smb-client-metadata' + $suffix + '-intent.json')
$resultPath = Join-Path $repo ('private/avd/profile-smb-client-metadata' + $suffix + '-result.json')
$git = (Get-Command git.exe -CommandType Application).Source
foreach ($path in @($intentPath, $resultPath)) { & $git -C $repo check-ignore --quiet -- $path; if ($LASTEXITCODE -ne 0) { throw 'IgnoredClientMetadataEvidenceRequired' }; $tracked = @(& $git -C $repo ls-files -- $path); if ($LASTEXITCODE -ne 0 -or $tracked.Count -or (Test-Path -LiteralPath $path)) { throw 'NewClientMetadataIntentDoNotReplay' } }
if ($Attempt -cne 'initial') {
    $old = Get-Content -LiteralPath (Join-Path $repo 'private/avd/profile-smb-client-metadata-result.json') -Raw | ConvertFrom-Json -AsHashtable -DateKind String
    $oldIntent = Get-Content -LiteralPath (Join-Path $repo 'private/avd/profile-smb-client-metadata-intent.json') -Raw | ConvertFrom-Json -AsHashtable -DateKind String
    if ($old.result.Status -cne 'ReadOnlyClientMetadata' -or $old.result.SmbRequests -ne 0 -or $old.result.ConfigurationWrites -ne 0 -or $oldIntent.vmId -ine $vm.Id -or $oldIntent.vmInstanceId -ine $vm.VmId -or $oldIntent.sourceSha256 -cne (Get-FileHash -LiteralPath (Join-Path $repo 'private/avd/profile-smb-client-before-server-name-shape.ps1')).Hash) { throw 'ExactCompletedPreviousReadOnlyMetadataRequired' }
    if ($Attempt -ceq 'logon-audit') { $previous = Get-Content -LiteralPath (Join-Path $repo 'private/avd/profile-smb-client-metadata-server-name-shape-result.json') -Raw | ConvertFrom-Json -AsHashtable -DateKind String; if ($previous.result.Status -cne 'ReadOnlyClientMetadata' -or $previous.result.CredentialReads -ne 0 -or $previous.result.SmbRequests -ne 0) { throw 'CompletedNoCredentialMetadataPredecessorRequired' } }
}
$metadata = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($preview.attempts.Inspect.metadataBase64)) | ConvertFrom-Json -AsHashtable
$metadata.Nonce = [guid]::NewGuid().ToString('N')
if ($Attempt -ceq 'logon-audit') { $metadata.LogonAudit = $true }
$encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $metadata -Compress)))
$source = Get-LeafProfileSmbClientSource
$record = @{ schemaVersion = 1; owner = 'identity.profile-smb-client.metadata'; vmId = $vm.Id; vmInstanceId = $vm.VmId; nonce = $metadata.Nonce; sourceSha256 = (Get-FileHash -LiteralPath $PSCommandPath).Hash; previewSha256 = (Get-FileHash -LiteralPath $previewPath).Hash; guestSourceSha256 = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($source))); status = 'ReadOnlyIntentDoNotReplay'; credentialReads = 0; configurationWrites = 0 }
$bytes = [Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $record -Depth 5 -Compress))
$stream = [IO.File]::Open($intentPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
try { $reply = Invoke-AzVMRunCommand -ResourceGroupName $preview.vm.resourceGroupName -VMName $preview.vm.name -CommandId RunPowerShellScript -ScriptString $source -Parameter @{ MetadataBase64 = $encoded } -DefaultProfile $context -ErrorAction Stop } catch { throw 'ClientMetadataReadStoppedDoNotReplayNoRawError' }
$output = @($reply.Value | ForEach-Object { $_.Message }) -join "`n"
if ([Text.Encoding]::UTF8.GetByteCount($output) -gt 8192) { throw 'BoundedClientMetadataOutputRequired' }
$markers = [regex]::Matches($output, '(?m)^LEAFIT_SMB_CLIENT_METADATA=(?<json>\{[^\r\n]*\})\s*$')
if ($markers.Count -ne 1) { throw 'OneClientMetadataMarkerRequired' }
$result = ConvertFrom-Json -InputObject $markers[0].Groups['json'].Value -AsHashtable -Depth 8 -DateKind String
if ($result.Status -cne 'ReadOnlyClientMetadata' -or $result.Nonce -cne $metadata.Nonce -or $result.ExactMemberSystemVerified -cne $true -or $result.RawEventsReturned -cne $false -or $result.ConfigurationWrites -ne 0 -or $result.CredentialReads -ne 0 -or $result.SmbRequests -ne 0) { throw 'ExactFixedClientMetadataContractRequired' }
[IO.File]::WriteAllText($resultPath, (ConvertTo-Json -InputObject @{ owner = $record.owner; intentSha256 = (Get-FileHash -LiteralPath $intentPath).Hash; result = $result } -Depth 8 -Compress), [Text.UTF8Encoding]::new($false))
[pscustomobject]@{ Status = 'ReadOnlyMemberSmbMetadataVerified'; Channels = $result.Channels; LogonAudit = $result.LogonAudit; RequireSecuritySignature = $result.RequireSecuritySignature; EnableSecuritySignature = $result.EnableSecuritySignature; EnableInsecureGuestLogons = $result.EnableInsecureGuestLogons; ConfigChanges = 0; CredentialReads = 0; SmbRequests = 0; RawEventsReturned = $false }