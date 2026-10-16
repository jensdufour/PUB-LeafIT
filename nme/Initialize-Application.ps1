#requires -Version 7.6
[CmdletBinding()]
param([switch]$CheckOnly, [switch]$ConnectGraph, [switch]$Apply, [switch]$ProbePrivateWorker, [switch]$UsePrivateWorker, [switch]$PublishOnly)

$ErrorActionPreference = 'Stop'
if (($CheckOnly -and ($ConnectGraph -or $Apply -or $ProbePrivateWorker)) -or ($ProbePrivateWorker -and ($ConnectGraph -or $Apply))) { throw 'Choose offline checks, private-worker discovery, or native initialization separately.' }
if ($PublishOnly -and -not $UsePrivateWorker) { throw 'Publish-only resume requires the verified private-worker installation.' }
$repo = Split-Path $PSScriptRoot -Parent
. (Join-Path $repo 'identity/Target.ps1')
. (Join-Path $PSScriptRoot 'PrivateWorker.ps1')

function Read-NmeInitializer([string]$Source, [Collections.IDictionary]$Expected) {
    $tokens = $null
    $parseErrors = $null
    $ast = [Management.Automation.Language.Parser]::ParseInput($Source, [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors.Count) { throw 'The vendor initializer does not parse.' }
    $top = @($ast.EndBlock.Statements)
    $bindings = @{}
    foreach ($name in @('subscriptionId', 'resourceGroupName', 'webAppName', 'sourceUri')) {
        $assignments = @($top | Where-Object { $_ -is [Management.Automation.Language.AssignmentStatementAst] -and $_.Left.Extent.Text -eq ('$' + $name) })
        if ($assignments.Count -ne 1) { throw 'The vendor initializer target binding is missing or ambiguous.' }
        $literal = $assignments[0].Right.Find({ param($node) $node -is [Management.Automation.Language.StringConstantExpressionAst] }, $true)
        if (-not $literal -or $assignments[0].Right.Extent.Text.Trim() -cne $literal.Extent.Text) { throw 'A vendor initializer target binding is not literal data.' }
        $bindings[$name] = $literal.Value
        if ($Expected.Contains($name) -and $bindings[$name] -cne $Expected[$name]) { throw 'The vendor initializer targets a different installation.' }
    }
    $packageUri = [uri]$bindings.sourceUri
    if ($packageUri.Scheme -ne 'https' -or $packageUri.UserInfo -or $packageUri.Fragment -or $packageUri.Host -notmatch '\.blob\.core\.windows\.net$') { throw 'The vendor package URI is not a reviewed HTTPS storage source.' }
    foreach ($name in @('InstallPackage', 'ConfigureSqlServer', 'ConfigureAppCertificate', 'Unlock-KeyVaultNetworkAccess', 'Lock-KeyVaultNetworkAccess')) {
        $functions = @($top | Where-Object { $_ -is [Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -eq $name })
        if ($functions.Count -ne 1) { throw 'The vendor initializer function contract has changed.' }
    }
    return [pscustomobject]@{ Ast = $ast; Source = $Source; PackageUri = $packageUri }
}

function Get-NmeMissingGraphScopes([string[]]$Scopes) {
    foreach ($name in @('Application.ReadWrite.All', 'AppRoleAssignment.ReadWrite.All')) {
        if ($name -notin $Scopes) { $name }
    }
    if ('User.Read' -notin $Scopes -and 'User.Read.All' -notin $Scopes) { 'User.Read' }
}

function Get-NmePublishingSource([string]$Source) {
    $tokens = $null; $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseInput($Source, [ref]$tokens, [ref]$errors)
    if ($errors.Count) { throw 'The adapted native publisher does not parse.' }
    $parts = @(foreach ($statement in $ast.EndBlock.Statements) {
        if ($statement -is [Management.Automation.Language.FunctionDefinitionAst]) { $statement.Extent.Text; continue }
        if ($statement -is [Management.Automation.Language.AssignmentStatementAst] -and $statement.Left.Extent.Text -in @('$sourceUri', '$subscriptionId', '$resourceGroupName', '$webAppName', '$mgmtUri', '$scmUriSuffix')) { $statement.Extent.Text; continue }
        if ($statement -is [Management.Automation.Language.PipelineAst] -and @($statement.PipelineElements | Where-Object { $_ -is [Management.Automation.Language.CommandAst] -and $_.GetCommandName() -eq 'InstallPackage' }).Count -eq 1) { $statement.Extent.Text }
    })
    return [string]::Join("`n", $parts)
}

function Assert-NmePublishingPackageExpiry([uri]$PackageUri) {
    $query = [Web.HttpUtility]::ParseQueryString($PackageUri.Query)
    $expiry = [datetimeoffset]::MinValue
    if (-not $query['se'] -or -not [datetimeoffset]::TryParse($query['se'], [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$expiry) -or $expiry -le [datetimeoffset]::UtcNow.AddMinutes(15)) { throw 'The saved native package URL is expired or lacks enough validity for publishing. Obtain a fresh vendor package before resuming.' }
}

function Convert-NmeExecutionSource($Initializer, [switch]$PrivateWorker) {
    $publish = @($Initializer.Ast.EndBlock.Statements | Where-Object {
        $_ -is [Management.Automation.Language.PipelineAst] -and @($_.PipelineElements | Where-Object { $_ -is [Management.Automation.Language.CommandAst] -and $_.GetCommandName() -eq 'InstallPackage' }).Count -eq 1
    })
    if ($publish.Count -ne 1) { throw 'The native publisher entry point is ambiguous.' }
    $changes = [Collections.Generic.List[object]]::new()
    $auth = @($Initializer.Ast.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Get-AuthInfo' }, $true))
    if ($auth.Count -ne 1) { throw 'The native publishing authentication helper has changed.' }
    $changes.Add(@{ Start = $auth[0].Extent.StartOffset; Length = $auth[0].Extent.EndOffset - $auth[0].Extent.StartOffset; Text = 'function Get-AuthInfo { param($SubscriptionId, $ResourceGroupName, $Name) $header = Get-AuthHeader; if (-not $header.StartsWith("Bearer ")) { throw "Unexpected native ARM authentication header." }; return $header.Substring(7) }' })
    foreach ($command in @($Initializer.Ast.FindAll({ param($node) $node -is [Management.Automation.Language.CommandAst] }, $true))) {
        $name = $command.GetCommandName()
        $replacement = switch ($name) {
            'Connect-MgGraph' { 'Assert-NmeNativeGraph' }
            'Clear-AzContext' { 'Assert-LeafTargetContext $settings (Get-AzContext)' }
            'Connect-AzAccount' { 'Assert-LeafTargetContext $settings (Get-AzContext)' }
            'Set-AzContext' { 'Assert-LeafTargetContext $settings (Get-AzContext)' }
            'Out-GridView' { 'Stop-NmeInteractiveSelection' }
            'Unlock-KeyVaultNetworkAccess' { 'Open-NmeBootstrapVault -KeyVaultName $keyVaultName' }
        }
        if ($replacement) { $changes.Add(@{ Start = $command.Extent.StartOffset; Length = $command.Extent.EndOffset - $command.Extent.StartOffset; Text = $replacement }) }
        if ($PrivateWorker) {
            $privateCommand = switch ($name) {
                'Get-AzKeyVaultCertificate' { 'Get-NmePrivateCertificate' }
                'Get-AzKeyVaultCertificateOperation' { 'Get-NmePrivateCertificateOperation' }
                'Add-AzKeyVaultCertificate' { 'New-NmePrivateCertificate' }
                'Get-AzKeyVaultSecret' { 'Get-NmePrivateCertificateSecret' }
                'ConfigureSqlServer' { 'Invoke-NmePrivateSqlBootstrap' }
            }
            if ($privateCommand) {
                $element = $command.CommandElements[0]
                $changes.Add(@{ Start = $element.Extent.StartOffset; Length = $element.Extent.EndOffset - $element.Extent.StartOffset; Text = $privateCommand })
            }
        }
        if ($name -eq 'Invoke-RestMethod') {
            $parent = $command.Parent
            while ($parent -and $parent -isnot [Management.Automation.Language.FunctionDefinitionAst]) { $parent = $parent.Parent }
            if ($parent -and $parent.Name -in @('Stop-WebAppJob', 'Start-WebAppJob', 'Publish-WebApp')) {
                $element = $command.CommandElements[0]
                $changes.Add(@{ Start = $element.Extent.StartOffset; Length = $element.Extent.EndOffset - $element.Extent.StartOffset; Text = 'Invoke-NmeScmRequest' })
            }
        }
        if ($name -eq 'New-AzKeyVaultCertificatePolicy') {
            for ($index = 0; $index -lt $command.CommandElements.Count - 1; $index++) {
                if ($command.CommandElements[$index] -is [Management.Automation.Language.CommandParameterAst] -and $command.CommandElements[$index].ParameterName -eq 'ValidityInMonths') {
                    $value = $command.CommandElements[$index + 1]
                    if ($value -is [Management.Automation.Language.ConstantExpressionAst] -and $value.Value -gt 1) { $changes.Add(@{ Start = $value.Extent.StartOffset; Length = $value.Extent.EndOffset - $value.Extent.StartOffset; Text = '1' }) }
                }
            }
        }
    }
    foreach ($literal in @($Initializer.Ast.FindAll({ param($node) $node -is [Management.Automation.Language.StringConstantExpressionAst] -and $node.Value -eq 'Basic {0}' }, $true))) {
        $changes.Add(@{ Start = $literal.Extent.StartOffset; Length = $literal.Extent.EndOffset - $literal.Extent.StartOffset; Text = '"Bearer {0}"' })
    }
    foreach ($assignment in @($Initializer.Ast.FindAll({ param($node) $node -is [Management.Automation.Language.AssignmentStatementAst] }, $true))) {
        if ($assignment.Left.Extent.Text -eq '$monthsUntilExpired') { $changes.Add(@{ Start = $assignment.Right.Extent.StartOffset; Length = $assignment.Right.Extent.EndOffset - $assignment.Right.Extent.StartOffset; Text = '1' }) }
        if ($assignment.Left.Extent.Text -match 'ServicePointManager\]::SecurityProtocol$') { $changes.Add(@{ Start = $assignment.Right.Extent.StartOffset; Length = $assignment.Right.Extent.EndOffset - $assignment.Right.Extent.StartOffset; Text = '[Net.SecurityProtocolType]::SystemDefault' }) }
        if ($assignment.Left.Extent.Text -eq '$localIp') { $changes.Add(@{ Start = $assignment.Right.Extent.StartOffset; Length = $assignment.Right.Extent.EndOffset - $assignment.Right.Extent.StartOffset; Text = '$bootstrapCallerIp' }) }
    }
    $source = $Initializer.Source
    foreach ($change in @($changes | Sort-Object Start -Descending)) { $source = $source.Remove($change.Start, $change.Length).Insert($change.Start, $change.Text) }
    $tokens = $null; $errors = $null
    $null = [Management.Automation.Language.Parser]::ParseInput($source, [ref]$tokens, [ref]$errors)
    if ($errors.Count -or $source.Contains('publishxml?') -or $source.Contains('"Basic {0}"')) { throw 'The native authentication compatibility adapter did not validate.' }
    return $source
}

function Invoke-NmeWithRestoration([scriptblock]$Work, [scriptblock]$Restore) {
    try { & $Work } finally { & $Restore }
}

function Restore-NmePrivateBackends([scriptblock]$SqlRestore, [scriptblock]$VaultRestore) {
    $failures = 0
    foreach ($restore in @($SqlRestore, $VaultRestore)) {
        try { & $restore } catch { $failures++ }
    }
    if ($failures) { throw 'A backend restoration operation failed after both private-access restorations were attempted.' }
}

function Get-NmeVaultCallerAddress([string]$Message) {
    $match = [regex]::Match($Message, '(?im)^Client address:\s*(?<address>\d{1,3}(?:\.\d{1,3}){3})\s*$')
    $address = $null
    if (-not $match.Success -or -not [Net.IPAddress]::TryParse($match.Groups['address'].Value, [ref]$address) -or $address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) { throw 'The vault did not report one verifiable caller IPv4 address.' }
    return $address.ToString()
}

function Get-NmePrivateWorkerProbe {
    return @'
$ErrorActionPreference = 'Stop'
function ReadAppSetting([string]$Name) {
    foreach ($key in @($Name, ('APPSETTING_' + $Name), $Name.Replace(':', '__'), ('APPSETTING_' + $Name.Replace(':', '__')))) {
        $value = [Environment]::GetEnvironmentVariable($key)
        if ($value) { return $value }
    }
    return $null
}
function HasPrivateAddress([string]$Name) {
    if (-not $Name) { return $false }
    foreach ($address in [Net.Dns]::GetHostAddresses($Name)) {
        $bytes = $address.GetAddressBytes()
        if ($bytes.Length -eq 4 -and ($bytes[0] -eq 10 -or ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31) -or ($bytes[0] -eq 192 -and $bytes[1] -eq 168))) { return $true }
    }
    return $false
}
$vaultName = ReadAppSetting 'Deployment:KeyVaultName'
$sqlId = ReadAppSetting 'Deployment:SqlServerId'
$vaultHost = if ($vaultName) { $vaultName + '.vault.azure.net' } else { $null }
$sqlHost = if ($sqlId) { ($sqlId -split '/')[-1] + '.database.windows.net' } else { $null }
$result = [ordered]@{
    WorkerReached = $true
    PowerShellVersion = $PSVersionTable.PSVersion.ToString()
    VaultSettingAvailable = [bool]$vaultName
    SqlSettingAvailable = [bool]$sqlId
    ManagedIdentityEndpointAvailable = [bool]$env:IDENTITY_ENDPOINT
    VaultPrivateDns = $false
    SqlPrivateDns = $false
    VaultTcpReachable = $false
    SqlTcpReachable = $false
}
foreach ($item in @(@{ Name = 'Vault'; Host = $vaultHost; Port = 443 }, @{ Name = 'Sql'; Host = $sqlHost; Port = 1433 })) {
    if (-not $item.Host) { continue }
    try {
        $result[$item.Name + 'PrivateDns'] = HasPrivateAddress $item.Host
        $client = [Net.Sockets.TcpClient]::new()
        try { $client.Connect($item.Host, $item.Port); $result[$item.Name + 'TcpReachable'] = $client.Connected } finally { $client.Dispose() }
    } catch { $result[$item.Name + 'TcpReachable'] = $false }
}
$result | ConvertTo-Json -Compress
'@
}

if ($CheckOnly) {
    Test-LeafTargetGuards
    $null = Test-NmePrivateVaultWorker
    $sample = @'
$subscriptionId = 'example-subscription'
$resourceGroupName = 'example-group'
$webAppName = 'example-app'
$sourceUri = 'https://example.blob.core.windows.net/package.zip?example=private'
$mgmtUri = 'https://management.azure.com'
$scmUriSuffix = '.scm.azurewebsites.net'
function InstallPackage { function Get-AuthInfo { 'legacy' }; 'Basic {0}' }
function ConfigureSqlServer {}
function ConfigureAppCertificate { Get-AzKeyVaultCertificate -VaultName 'example' -Name 'nme-app-cert'; New-AzKeyVaultCertificatePolicy -ValidityInMonths 120 }
function Unlock-KeyVaultNetworkAccess {}
function Lock-KeyVaultNetworkAccess {}
Unlock-KeyVaultNetworkAccess -KeyVaultName 'example'
Clear-AzContext -Scope CurrentUser
Connect-MgGraph -TenantId 'example'
ConfigureSqlServer
InstallPackage
'@
    $expected = @{ subscriptionId = 'example-subscription'; resourceGroupName = 'example-group'; webAppName = 'example-app' }
    $null = Read-NmeInitializer $sample $expected
    foreach ($source in @($sample.Replace('example-subscription', 'different-subscription'), $sample.Replace('https://', 'http://'), $sample.Replace('function ConfigureSqlServer {}', ''))) {
        $rejected = $false
        try { $null = Read-NmeInitializer $source $expected } catch { $rejected = $true }
        if (-not $rejected) { throw 'An unsafe or incompatible native initializer was accepted.' }
    }
    if (@(Get-NmeMissingGraphScopes @('Application.ReadWrite.All', 'AppRoleAssignment.ReadWrite.All', 'User.Read.All')).Count -ne 0 -or @(Get-NmeMissingGraphScopes @('Application.ReadWrite.All', 'User.Read')).Count -ne 1) { throw 'Graph bootstrap scope coverage was evaluated incorrectly.' }
    $adapted = Convert-NmeExecutionSource (Read-NmeInitializer $sample $expected)
    if ($adapted -notmatch 'Assert-NmeNativeGraph|Open-NmeBootstrapVault' -or $adapted -match 'ValidityInMonths 120|Connect-MgGraph -TenantId|Clear-AzContext|Unlock-KeyVaultNetworkAccess -KeyVaultName' -or $adapted -notmatch 'Bearer \{0\}') { throw 'Native authentication/certificate adaptation failed.' }
    $privateAdapted = Convert-NmeExecutionSource (Read-NmeInitializer $sample $expected) -PrivateWorker
    if ($privateAdapted -notmatch 'Get-NmePrivateCertificate -VaultName' -or $privateAdapted -notmatch '(?m)^Invoke-NmePrivateSqlBootstrap\s*$' -or $privateAdapted -match 'Get-AzKeyVaultCertificate -VaultName') { throw 'Private native certificate/SQL call routing failed.' }
    $publishingSource = Get-NmePublishingSource $privateAdapted
    if ($publishingSource -notmatch '(?m)^InstallPackage\s*$' -or $publishingSource -match '(?m)^Invoke-NmePrivateSqlBootstrap\s*$|(?m)^Assert-NmeNativeGraph\s*$') { throw 'Publish-only resume included completed setup steps or omitted the native publisher.' }
    $validExpiry = [uri]('https://example.blob.core.windows.net/package.zip?se=' + [uri]::EscapeDataString([datetimeoffset]::UtcNow.AddHours(1).ToString('o')))
    Assert-NmePublishingPackageExpiry $validExpiry
    $rejected = $false
    try { Assert-NmePublishingPackageExpiry ([uri]'https://example.blob.core.windows.net/package.zip?se=2000-01-01T00%3A00%3A00Z') } catch { $rejected = $true }
    if (-not $rejected) { throw 'An expired native package URL was accepted for publishing.' }
    $probe = @{ Restored = $false }
    try { Invoke-NmeWithRestoration { throw 'Expected test failure' } { $probe.Restored = $true } } catch {}
    if (-not $probe.Restored) { throw 'Native failure did not execute restoration.' }
    $restoreProbe = @{ SqlAttempted = $false; VaultAttempted = $false }
    try { Restore-NmePrivateBackends { $restoreProbe.SqlAttempted = $true; throw 'Expected SQL failure' } { $restoreProbe.VaultAttempted = $true } } catch {}
    if (-not $restoreProbe.SqlAttempted -or -not $restoreProbe.VaultAttempted) { throw 'A SQL restoration failure prevented the Key Vault restoration attempt.' }
    $sampleAddress = '192.0.2.1'
    $allowedAddressForms = @($sampleAddress, ($sampleAddress + '/32'))
    if ($allowedAddressForms.Count -ne 2 -or $sampleAddress -notin $allowedAddressForms -or ($sampleAddress + '/32') -notin $allowedAddressForms) { throw 'The caller-only IPv4/CIDR readback guard is incorrect.' }
    if ((Get-NmeVaultCallerAddress "Client address: 192.0.2.1`nCaller: example") -ne $sampleAddress) { throw 'The trusted vault caller address was not extracted correctly.' }
    $rejected = $false
    try { $null = Get-NmeVaultCallerAddress 'Client address: 999.0.0.1' } catch { $rejected = $true }
    if (-not $rejected) { throw 'An invalid vault caller address was accepted.' }
    $workerSource = Get-NmePrivateWorkerProbe
    $workerTokens = $null; $workerErrors = $null
    $null = [Management.Automation.Language.Parser]::ParseInput($workerSource, [ref]$workerTokens, [ref]$workerErrors)
    if ($workerErrors.Count -or $workerSource -match '(?i)Set-Az|New-Az|Remove-Az|Update-Az|Get-AzAccessToken|Authorization|Invoke-RestMethod|Invoke-WebRequest') { throw 'The private-worker discovery script is not a read-only connectivity probe.' }
    [pscustomobject]@{ OfflineChecksPassed = $true; NativeTargetGuardsPassed = $true; PackageSourceGuardsPassed = $true; AuthenticationAdapterPassed = $true; FailureRestorationPassed = $true; AzureCallsMade = $false }
    return
}

$settings = Read-LeafPrivateTarget $repo
Import-Module Az.Accounts -MinimumVersion 5.3.3 -ErrorAction Stop
Import-Module Az.Resources -ErrorAction Stop
$context = Get-AzContext
Assert-LeafTargetContext $settings $context
$privateRoot = Join-Path $repo 'private/nme'
$plan = Get-Content -LiteralPath (Join-Path $privateRoot 'installation-plan.json') -Raw | ConvertFrom-Json -AsHashtable
$desired = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'desired.json') -Raw | ConvertFrom-Json -AsHashtable
$brand = Get-Content -LiteralPath ([IO.Path]::GetFullPath((Join-Path $PSScriptRoot $desired.brandSource))) -Raw | ConvertFrom-Json -AsHashtable
if ($plan.deploymentSucceeded -ne $true -or $plan.initializationCompleted -ne $false -or $plan.vendorTemplateSha256 -ne $desired.installation.templateSha256 -or $plan.resourceGroupName -notmatch '^rg-nme-swc-[0-9]{1,3}$') { throw 'A matching, not-yet-initialized vendor deployment is required.' }
$web = @(Get-AzResource -ResourceGroupName $plan.resourceGroupName -ResourceType 'Microsoft.Web/sites' -ExpandProperties -DefaultProfile $context)
if ($web.Count -ne 1 -or $web[0].Properties.defaultHostName -ne ([uri]$plan.appUrl).Host) { throw 'The management app is missing, ambiguous, or differs from the deployed URL.' }
if ($ProbePrivateWorker) {
    $hosts = @($web[0].Properties.enabledHostNames | Where-Object { $_ -match '\.scm\.azurewebsites\.net$' })
    $inboundAddress = $null
    if ($hosts.Count -ne 1 -or -not [Net.IPAddress]::TryParse([string]$web[0].Properties.inboundIpAddress, [ref]$inboundAddress)) { throw 'The existing SCM endpoint is unverified.' }
    $probeText = Get-NmePrivateWorkerProbe
    $command = 'powershell.exe -NoProfile -NonInteractive -EncodedCommand ' + [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($probeText))
    $bodyPath = Join-Path $privateRoot 'private-worker-probe-request.json'
    [IO.File]::WriteAllText($bodyPath, (@{ command = $command; dir = 'site\wwwroot' } | ConvertTo-Json -Compress), [Text.UTF8Encoding]::new($false))
    $token = Get-AzAccessToken -ResourceUrl $context.Environment.ResourceManagerUrl -TenantId $settings.TARGET_TENANT_ID -DefaultProfile $context
    if ($token.Token -isnot [securestring]) { throw 'The private-worker discovery token is not protected.' }
    $tokenText = [Net.NetworkCredential]::new('', $token.Token).Password
    $request = [string]::Join("`n", @(
        ('url = "https://{0}/api/command"' -f $hosts[0]),
        ('resolve = "{0}:443:{1}"' -f $hosts[0], $inboundAddress),
        'request = "POST"',
        ('header = "Authorization: Bearer {0}"' -f $tokenText),
        'header = "Content-Type: application/json"',
        ('data-binary = "@{0}"' -f $bodyPath.Replace('\', '/'))
    ))
    $resultPath = Join-Path $privateRoot 'private-worker-probe-response.json'
    $result = $request | & curl.exe --config - --proto '=https' --output $resultPath --max-time 120 --silent --write-out '%{http_code}' 2>&1
    $exitCode = $LASTEXITCODE
    $tokenText = $null
    $request = $null
    if ($exitCode -ne 0 -or ($result -join '').Trim() -ne '200') { throw 'The existing App Service private-worker probe failed; no networking or permission changes were made.' }
    $response = Get-Content -LiteralPath $resultPath -Raw | ConvertFrom-Json -AsHashtable
    if ($response.ExitCode -ne 0 -or [string]::IsNullOrWhiteSpace([string]$response.Output)) { throw 'The existing worker did not return successful discovery output.' }
    $discovery = ConvertFrom-Json -InputObject ([string]$response.Output).Trim() -AsHashtable
    if ($discovery.WorkerReached -ne $true) { throw 'The private-worker discovery response is not recognized.' }
    $probeVaults = @(Get-AzResource -ResourceGroupName $plan.resourceGroupName -ResourceType 'Microsoft.KeyVault/vaults' -DefaultProfile $context)
    if ($probeVaults.Count -ne 1) { throw 'The private worker vault is ambiguous.' }
    $probeConnection = @{ Settings = $settings; Context = $context; Host = [string]$hosts[0]; Address = $inboundAddress.ToString(); VaultName = $probeVaults[0].Name }
    if ($discovery.VaultPrivateDns -eq $true -and $discovery.VaultTcpReachable -eq $true) {
        $certificate = Invoke-NmePrivateVaultOperation -Connection $probeConnection -Operation GetCertificate -Name 'nme-app-cert'
        $discovery.DelegatedPrivateCertificateReadVerified = $true
        $discovery.ApplicationCertificateAlreadyPresent = [bool]$certificate
        $certificate = $null
    }
    [IO.File]::WriteAllText((Join-Path $privateRoot 'private-worker-discovery.json'), ($discovery | ConvertTo-Json -Depth 5), [Text.UTF8Encoding]::new($false))
    [pscustomobject]@{ Mode = 'PrivateWorkerDiscovery'; ExistingWorkerReached = $true; VaultPrivateDns = $discovery.VaultPrivateDns; SqlPrivateDns = $discovery.SqlPrivateDns; VaultTcpReachable = $discovery.VaultTcpReachable; SqlTcpReachable = $discovery.SqlTcpReachable; DelegatedPrivateCertificateReadVerified = $discovery.DelegatedPrivateCertificateReadVerified -eq $true; ManagedIdentityAvailable = $discovery.ManagedIdentityEndpointAvailable; ConfigurationChangesMade = $false }
    return
}
$uri = [uri]::new([uri]$plan.appUrl, 'api/nme-installer/install-scripts')
$address = $null
if (-not [Net.IPAddress]::TryParse([string]$web[0].Properties.inboundIpAddress, [ref]$address) -or $uri.Scheme -ne 'https' -or $uri.Host -notmatch '^[a-z0-9-]+\.azurewebsites\.net$') { throw 'The installed management app HTTPS address is unverified.' }
$config = [string]::Join("`n", @(
    ('url = "{0}"' -f $uri.AbsoluteUri),
    ('resolve = "{0}:443:{1}"' -f $uri.Host, $address)
))
$responsePath = Join-Path $privateRoot 'installer-scripts.json'
$expected = @{ subscriptionId = $settings.TARGET_SUBSCRIPTION_ID; resourceGroupName = $plan.resourceGroupName; webAppName = $web[0].Name }
$nativePath = Join-Path $privateRoot 'vendor-initialize.ps1'
if ($PublishOnly) {
    $initializer = Read-NmeInitializer (Get-Content -LiteralPath $nativePath -Raw) $expected
    Assert-NmePublishingPackageExpiry $initializer.PackageUri
} else {
    $result = $config | & curl.exe --config - --proto '=https' --output $responsePath --max-time 60 --silent --write-out '%{http_code}' 2>&1
    if ($LASTEXITCODE -ne 0 -or ($result -join '').Trim() -ne '200') { throw 'The current vendor initializer could not be retrieved over verified HTTPS.' }
    $response = Get-Content -LiteralPath $responsePath -Raw | ConvertFrom-Json -AsHashtable -Depth 100
    if ($response.success -ne $true -or [string]::IsNullOrWhiteSpace([string]$response.data.cloudShellInstallScriptFull)) { throw 'The native installer did not return a successful full-script response.' }
    $initializer = Read-NmeInitializer ([string]$response.data.cloudShellInstallScriptFull) $expected
    [IO.File]::WriteAllText($nativePath, $initializer.Source, [Text.UTF8Encoding]::new($false))
}
Import-Module Microsoft.Graph.Authentication -MinimumVersion 2.37.0 -ErrorAction Stop
$graph = Get-MgContext
if ($graph -and $graph.TenantId -ne $settings.TARGET_TENANT_ID) { throw 'The existing Graph context targets another tenant; no sign-in or context switch was attempted.' }
if ($ConnectGraph) {
    $null = Connect-LeafTargetGraph -Settings $settings -RefreshFromAzure
    $graph = Get-MgContext
}
$missingScopes = @(Get-NmeMissingGraphScopes @($graph.Scopes))
$graphReady = $graph -and $graph.TenantId -eq $settings.TARGET_TENANT_ID -and $missingScopes.Count -eq 0
if ($graphReady) {
    $organization = Invoke-LeafTargetGraph -Settings $settings -Path '/v1.0/organization?$select=id'
    if (@($organization.value).Count -ne 1 -or $organization.value[0].id -ne $settings.TARGET_TENANT_ID) { throw 'The authenticated Graph organization does not match the approved target.' }
}
$executionSource = Convert-NmeExecutionSource $initializer -PrivateWorker:$UsePrivateWorker
if ($PublishOnly) {
    $previousRun = Get-Content -LiteralPath (Join-Path $privateRoot 'native-initialization.json') -Raw | ConvertFrom-Json -AsHashtable
    if ($previousRun.PrivateSqlWorkerVerified -ne $true -or $previousRun.PrivateVaultWorkerVerified -ne $true -or $previousRun.PrivateAccessRestored -ne $true) { throw 'Publish-only resume requires verified private certificate/SQL setup and restored access.' }
    $executionSource = Get-NmePublishingSource $executionSource
}
if (-not $Apply) {
    [pscustomobject]@{ Mode = if ($ConnectGraph) { 'GraphPreflight' } else { 'Preview' }; TargetVerified = $true; CurrentVendorScriptVerified = $true; SharedBrandApplicationName = $brand.name + ' NMe'; GraphBootstrapReady = [bool]$graphReady; MissingGraphScopes = $missingScopes; EntraPublishingSelected = $true; PrivateWorkerSelected = $UsePrivateWorker.IsPresent; TemporaryNetworkAccessSelected = -not $UsePrivateWorker; AzureChangesMade = $false }
    return
}
if (-not $graphReady -or $env:AZUREPS_HOST_ENVIRONMENT) { throw 'A verified local Azure/Graph bootstrap session is required before temporary network access.' }
foreach ($module in @('Microsoft.Graph.Users', 'SqlServer')) {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        $repository = Get-PSRepository -Name PSGallery
        if ($repository.SourceLocation -ne 'https://www.powershellgallery.com/api/v2') { throw 'The expected official PowerShell Gallery source is unverified.' }
        $version = if ($module -eq 'Microsoft.Graph.Users') { (Get-Module Microsoft.Graph.Authentication).Version.ToString() } else { (Find-Module -Name SqlServer -Repository PSGallery).Version.ToString() }
        Install-Module -Name $module -RequiredVersion $version -Repository PSGallery -Scope CurrentUser -Force -AllowClobber
    }
}
foreach ($module in @('Az.KeyVault', 'Az.Sql', 'Az.Websites', 'Az.Automation', 'Microsoft.Graph.Users', 'Microsoft.Graph.Applications', 'SqlServer')) { Import-Module $module -ErrorAction Stop }
$applicationName = $brand.name + ' NMe'
$existingApplications = @(Get-MgApplication -Filter ("displayName eq '" + $applicationName.Replace("'", "''") + "'") -Property Id, AppId, DisplayName, Web)
if ($existingApplications.Count -gt 1 -or ($existingApplications.Count -eq 1 -and ($plan.appUrl.TrimEnd('/') + '/signin-oidc') -notin @($existingApplications[0].Web.RedirectUris))) { throw 'A matching-name application is ambiguous or does not belong to this management URL; it will not be adopted.' }
$resources = @(Get-AzResource -ResourceGroupName $plan.resourceGroupName -ExpandProperties -DefaultProfile $context)
$sql = @($resources | Where-Object ResourceType -eq 'Microsoft.Sql/servers')
$vault = @($resources | Where-Object ResourceType -eq 'Microsoft.KeyVault/vaults')
if ($sql.Count -ne 1 -or $vault.Count -ne 1) { throw 'The initializer backend resources are ambiguous.' }
$sqlPath = $sql[0].ResourceId + '?api-version=2023-08-01'
$vaultPath = $vault[0].ResourceId + '?api-version=2024-11-01'
$vaultBeforeResponse = Invoke-AzRestMethod -Method GET -Path $vaultPath -DefaultProfile $context
if ($vaultBeforeResponse.StatusCode -ne 200 -or $sql[0].Properties.publicNetworkAccess -ne 'Disabled') { throw 'The expected private backend starting state is unverified.' }
$vaultBefore = (ConvertFrom-Json -InputObject $vaultBeforeResponse.Content -AsHashtable).properties
if ($vaultBefore.publicNetworkAccess -ne 'Disabled') { throw 'Key Vault must be private before the approved temporary initialization access.' }
$firewalls = @(Get-AzSqlServerFirewallRule -ResourceGroupName $plan.resourceGroupName -ServerName $sql[0].Name -DefaultProfile $context)
$networkBeforePath = Join-Path $privateRoot 'initialization-network-before.json'
if (Test-Path -LiteralPath $networkBeforePath) {
    $savedNetwork = Get-Content -LiteralPath $networkBeforePath -Raw | ConvertFrom-Json -AsHashtable -Depth 30
    if ($savedNetwork.sqlResourceId -ne $sql[0].ResourceId -or $savedNetwork.vaultResourceId -ne $vault[0].ResourceId -or -not $savedNetwork.Contains('vaultNetworkAcls') -or -not $savedNetwork.Contains('sqlFirewallRules')) { throw 'The original network recovery record does not match this installation.' }
    $vaultBefore.networkAcls = $savedNetwork.vaultNetworkAcls
    $firewalls = @($savedNetwork.sqlFirewallRules | ForEach-Object { [pscustomobject]$_ })
}
$ipResponse = Invoke-RestMethod -Uri 'https://api.ipify.org?format=json' -TimeoutSec 30
if ($ipResponse -is [string]) { $ipResponse = ConvertFrom-Json -InputObject $ipResponse -AsHashtable }
$bootstrapCallerIp = [string]$ipResponse.ip
$callerAddress = $null
if (-not [Net.IPAddress]::TryParse($bootstrapCallerIp, [ref]$callerAddress) -or $callerAddress.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) { throw 'The current public IPv4 address could not be verified for temporary allowlisting.' }
$scmHosts = @($web[0].Properties.enabledHostNames | Where-Object { $_ -match '\.scm\.azurewebsites\.net$' })
if ($scmHosts.Count -ne 1) { throw 'The ARM-reported SCM hostname is ambiguous.' }
$scmHost = [string]$scmHosts[0]
$privateWorkerConnection = $null
if ($UsePrivateWorker) {
    $discovery = Get-Content -LiteralPath (Join-Path $privateRoot 'private-worker-discovery.json') -Raw | ConvertFrom-Json -AsHashtable
    if ($discovery.DelegatedPrivateCertificateReadVerified -ne $true -or $discovery.SqlPrivateDns -ne $true -or $discovery.SqlTcpReachable -ne $true) { throw 'The existing private worker certificate/SQL path has not passed its read-only probe.' }
    $appIdentityResponse = Invoke-AzRestMethod -Method GET -Path ($web[0].ResourceId + '?api-version=2024-04-01') -DefaultProfile $context
    $sqlAdminResponse = Invoke-AzRestMethod -Method GET -Path ($sql[0].ResourceId + '/administrators/ActiveDirectory?api-version=2023-08-01') -DefaultProfile $context
    if ($appIdentityResponse.StatusCode -ne 200 -or $sqlAdminResponse.StatusCode -ne 200) { throw 'The existing private SQL identity could not be verified.' }
    $appIdentity = (ConvertFrom-Json -InputObject $appIdentityResponse.Content -AsHashtable).identity.principalId
    $sqlAdmin = (ConvertFrom-Json -InputObject $sqlAdminResponse.Content -AsHashtable).properties
    if ($sqlAdmin.sid -ne $appIdentity -or $sqlAdmin.tenantId -ne $settings.TARGET_TENANT_ID) { throw 'Private SQL setup requires the existing App Service managed-identity administrator; no new admin is assigned.' }
    $databases = @(Get-AzSqlDatabase -ResourceGroupName $plan.resourceGroupName -ServerName $sql[0].Name -DefaultProfile $context | Where-Object DatabaseName -ne 'master')
    if ($databases.Count -ne 1) { throw 'The private SQL bootstrap database is ambiguous.' }
    $privateWorkerConnection = @{ Settings = $settings; Context = $context; Host = $scmHost; Address = $address.ToString(); VaultName = $vault[0].Name; SqlServerName = $sql[0].Name; DatabaseName = $databases[0].DatabaseName; UserName = $web[0].Name }
}
$bootstrapTemp = Join-Path $privateRoot ('bootstrap-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($bootstrapTemp)
$oldTemp = $env:TEMP
$oldTmp = $env:TMP
$oldSecurityProtocol = [Net.ServicePointManager]::SecurityProtocol
$run = @{ ConfigurationCompleted = $false; PrivateAccessRestored = $false; Stage = 'PreflightCompleted'; ErrorType = $null; ErrorCommand = $null; ErrorLine = $null; FailureMessage = $null; RestorationFailure = $null }
if ($PublishOnly) { $run.PrivateSqlWorkerVerified = $true; $run.PrivateVaultWorkerVerified = $true; $run.PublishingResumed = $true }

function Assert-NmeNativeGraph {
    Assert-LeafTargetContext $settings (Get-AzContext)
    $current = Get-MgContext
    if (-not $current -or $current.TenantId -ne $settings.TARGET_TENANT_ID -or @(Get-NmeMissingGraphScopes @($current.Scopes)).Count) { throw 'The native initializer lost its verified Graph target or bootstrap permissions.' }
}
function Stop-NmeInteractiveSelection { throw 'Unexpected interactive identity/subscription selection was refused.' }
function Open-NmeBootstrapVault([string]$KeyVaultName) {
    Assert-NmeNativeGraph
    if ($KeyVaultName -ne $vault[0].Name) { throw 'The native initializer requested temporary access to a different vault.' }
    if ($UsePrivateWorker) {
        $null = Invoke-NmePrivateVaultOperation -Connection $privateWorkerConnection -Operation GetCertificate -Name 'nme-app-cert'
        $run.PrivateVaultWorkerVerified = $true
        return $false
    }
    $payload = @{ properties = @{ publicNetworkAccess = 'Enabled'; networkAcls = @{ bypass = 'None'; defaultAction = 'Deny'; ipRules = @(@{ value = $bootstrapCallerIp + '/32' }); virtualNetworkRules = @() } } } | ConvertTo-Json -Depth 10 -Compress
    $opened = Invoke-AzRestMethod -Method PATCH -Path $vaultPath -Payload $payload -DefaultProfile $context
    if ($opened.StatusCode -notin @(200, 201, 202)) { throw 'The temporary caller-only Key Vault access request was not accepted.' }
    $readback = Invoke-AzRestMethod -Method GET -Path $vaultPath -DefaultProfile $context
    if ($readback.StatusCode -ne 200) { throw 'Temporary Key Vault access could not be verified.' }
    $properties = (ConvertFrom-Json -InputObject $readback.Content -AsHashtable).properties
    $run.VaultReadbackChecks = @{
        PublicEnabled = $properties.publicNetworkAccess -eq 'Enabled'
        DefaultDeny = $properties.networkAcls.defaultAction -eq 'Deny'
        NoBypass = $properties.networkAcls.bypass -eq 'None'
        SingleCallerRule = @($properties.networkAcls.ipRules).Count -eq 1
        CallerAddressMatches = $properties.networkAcls.ipRules[0].value -in @($bootstrapCallerIp, ($bootstrapCallerIp + '/32'))
    }
    if (@($run.VaultReadbackChecks.Values | Where-Object { $_ -ne $true }).Count) { throw 'The approved temporary Key Vault access did not persist with its caller-only allowlist.' }
    try { $null = Get-AzKeyVaultCertificate -VaultName $KeyVaultName -Name $script:appCertName -DefaultProfile $context -ErrorAction Stop } catch {
        $observedAddress = Get-NmeVaultCallerAddress ([string]$_.Exception.Message)
        if ($observedAddress -eq $bootstrapCallerIp) { throw 'The allowlisted vault caller is still rejected; no network scope was broadened.' }
        $properties.networkAcls.ipRules = @(@{ value = $observedAddress + '/32' })
        $correction = Invoke-AzRestMethod -Method PATCH -Path $vaultPath -Payload (@{ properties = @{ networkAcls = $properties.networkAcls } } | ConvertTo-Json -Depth 10 -Compress) -DefaultProfile $context
        if ($correction.StatusCode -notin @(200, 201, 202)) { throw 'The vault-reported caller-only rule could not be applied.' }
        $correctedResponse = Invoke-AzRestMethod -Method GET -Path $vaultPath -DefaultProfile $context
        if ($correctedResponse.StatusCode -ne 200) { throw 'The vault-reported caller rule could not be verified.' }
        $corrected = (ConvertFrom-Json -InputObject $correctedResponse.Content -AsHashtable).properties
        if ($corrected.publicNetworkAccess -ne 'Enabled' -or $corrected.networkAcls.defaultAction -ne 'Deny' -or $corrected.networkAcls.bypass -ne 'None' -or @($corrected.networkAcls.ipRules).Count -ne 1 -or $corrected.networkAcls.ipRules[0].value -notin @($observedAddress, ($observedAddress + '/32'))) { throw 'The corrected vault caller-only allowlist failed readback.' }
        $run.VaultReportedCallerRuleVerified = $true
    }
    $run.VaultTemporaryAccessVerified = $true
    return $true
}
function Invoke-NmeScmRequest {
    [CmdletBinding()]
    param([uri]$Uri, [Collections.IDictionary]$Headers, [string]$Method = 'POST', [string]$InFile, [string]$ContentType, [int]$TimeoutSec = 900, [switch]$DisableKeepAlive)
    if ($Uri.Scheme -ne 'https' -or $Uri.Host -ne $scmHost -or $Uri.Port -ne 443 -or $Uri.AbsolutePath -notmatch '^/api/(?:publish|jobs/continuous/provision/(?:start|stop))$' -or $Method -ne 'POST' -or [string]$Headers.Authorization -notmatch '^Bearer [^\r\n"]+$') { throw 'An unexpected native publishing request was refused.' }
    $lines = @(
        ('url = "{0}"' -f $Uri.AbsoluteUri),
        ('resolve = "{0}:443:{1}"' -f $Uri.Host, $address),
        'request = "POST"',
        ('header = "Authorization: {0}"' -f $Headers.Authorization)
    )
    if ($DisableKeepAlive) { $lines += 'header = "Connection: close"' }
    if ($ContentType) { $lines += 'header = "Content-Type: ' + $ContentType + '"' }
    if ($InFile) {
        $file = [IO.Path]::GetFullPath($InFile)
        if (-not $file.StartsWith($bootstrapTemp + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'The native publishing file is outside its owned private temporary directory.' }
        $lines += 'data-binary = "@' + $file.Replace('\', '/') + '"'
    }
    $result = ([string]::Join("`n", $lines)) | & curl.exe --config - --proto '=https' --output (Join-Path $bootstrapTemp 'scm-response.json') --max-time $TimeoutSec --silent --write-out '%{http_code}' 2>&1
    $publishExitCode = $LASTEXITCODE
    $publishStatus = ($result -join '').Trim()
    $run.PublishingStage = if ($Uri.AbsolutePath -eq '/api/publish') { 'PackageUpload' } elseif ($Uri.AbsolutePath.EndsWith('/stop')) { 'StopProvisionJob' } else { 'StartProvisionJob' }
    $run.PublishingTransportExitCode = $publishExitCode
    $run.PublishingHttpStatus = if ($publishStatus -match '^\d{3}$') { [int]$publishStatus } else { $null }
    if ($publishExitCode -ne 0 -or $publishStatus -notin @('200', '201', '202', '204')) { throw ('The Entra-authenticated native publishing request failed at {0} (HTTP {1}; transport {2}); basic authentication remains disabled.' -f $run.PublishingStage, $run.PublishingHttpStatus, $publishExitCode) }
}

function Get-NmePrivateCertificate {
    param([string]$VaultName, [string]$Name)
    if ($VaultName -ne $vault[0].Name) { throw 'A native certificate operation targets another vault.' }
    $value = Invoke-NmePrivateVaultOperation -Connection $privateWorkerConnection -Operation GetCertificate -Name $Name
    if ($null -eq $value) { return $null }
    return [pscustomobject]@{ Name = $Name; Id = $value.id; SecretId = $value.sid; Certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new([Convert]::FromBase64String($value.cer)) }
}
function New-NmePrivateCertificate {
    param([string]$VaultName, [string]$Name, $CertificatePolicy)
    if ($VaultName -ne $vault[0].Name -or -not $CertificatePolicy) { throw 'The private certificate create request is invalid.' }
    $value = Invoke-NmePrivateVaultOperation -Connection $privateWorkerConnection -Operation CreateCertificate -Name $Name
    return [pscustomobject]@{ Status = $value.status }
}
function Get-NmePrivateCertificateOperation {
    param([string]$VaultName, [string]$Name)
    if ($VaultName -ne $vault[0].Name) { throw 'The private certificate status request targets another vault.' }
    $value = Invoke-NmePrivateVaultOperation -Connection $privateWorkerConnection -Operation GetCertificateOperation -Name $Name
    return [pscustomobject]@{ Status = $value.status }
}
function Get-NmePrivateCertificateSecret {
    param([string]$VaultName, [string]$Name)
    if ($VaultName -ne $vault[0].Name) { throw 'The private certificate export targets another vault.' }
    $value = Invoke-NmePrivateVaultOperation -Connection $privateWorkerConnection -Operation GetCertificateSecret -Name $Name
    return [pscustomobject]@{ SecretValue = ConvertTo-SecureString ([string]$value.value) -AsPlainText -Force }
}
function Invoke-NmePrivateSqlBootstrap($ServicePrincipal) {
    $clientId = [string]$ServicePrincipal.AppId
    if (-not $clientId) { throw 'The native SQL principal has no verified application client ID.' }
    $value = Invoke-NmePrivateVaultOperation -Connection $privateWorkerConnection -Operation ConfigureSql -ClientId $clientId
    if ($value.SqlConfigured -ne $true) { throw 'The private SQL bootstrap did not complete.' }
    $run.PrivateSqlWorkerVerified = $true
}

$scmToken = Get-AzAccessToken -ResourceUrl $context.Environment.ResourceManagerUrl -TenantId $settings.TARGET_TENANT_ID -DefaultProfile $context
if ($scmToken.Token -isnot [securestring]) { throw 'The native publishing preflight did not receive a protected target token.' }
$scmTokenText = [Net.NetworkCredential]::new('', $scmToken.Token).Password
$scmProbeConfig = [string]::Join("`n", @(
    ('url = "https://{0}/api/deployments"' -f $scmHost),
    ('resolve = "{0}:443:{1}"' -f $scmHost, $address),
    ('header = "Authorization: Bearer {0}"' -f $scmTokenText)
))
$scmProbe = $scmProbeConfig | & curl.exe --config - --proto '=https' --output (Join-Path $bootstrapTemp 'scm-preflight.json') --max-time 60 --silent --write-out '%{http_code}' 2>&1
$scmProbeExit = $LASTEXITCODE
$scmTokenText = $null
$scmProbeConfig = $null
if ($scmProbeExit -ne 0 -or ($scmProbe -join '').Trim() -ne '200') { throw 'Entra-authenticated SCM preflight failed before backend access was opened.' }
$networkBefore = @{ sqlResourceId = $sql[0].ResourceId; vaultResourceId = $vault[0].ResourceId; vaultNetworkAcls = $vaultBefore.networkAcls; sqlFirewallRules = @($firewalls | Select-Object FirewallRuleName, StartIpAddress, EndIpAddress) }
if (-not (Test-Path -LiteralPath $networkBeforePath)) { [IO.File]::WriteAllText($networkBeforePath, ($networkBefore | ConvertTo-Json -Depth 15), [Text.UTF8Encoding]::new($false)) }
$approvalKey = 'TARGET_NME_NATIVE_INITIALIZATION_NETWORK_ACCESS_APPROVED_UTC'
if ([IO.File]::ReadAllText((Join-Path $repo '.env')) -notmatch ('(?m)^\s*' + $approvalKey + '\s*=')) {
    [IO.File]::AppendAllText((Join-Path $repo '.env'), ([Environment]::NewLine + $approvalKey + '=' + [datetimeoffset]::UtcNow.ToString('o') + [Environment]::NewLine), [Text.UTF8Encoding]::new($false))
}
try {
    Invoke-NmeWithRestoration {
        try {
            Assert-NmeNativeGraph
            $env:TEMP = $bootstrapTemp
            $env:TMP = $bootstrapTemp
            if ([IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd([IO.Path]::DirectorySeparatorChar) -ne $bootstrapTemp.TrimEnd([IO.Path]::DirectorySeparatorChar)) { throw 'The native certificate temporary directory could not be isolated.' }
            $run.Stage = 'TemporaryFirewallRestriction'
            if (-not $UsePrivateWorker) { foreach ($rule in $firewalls) { $null = Set-AzSqlServerFirewallRule -ResourceGroupName $plan.resourceGroupName -ServerName $sql[0].Name -FirewallRuleName $rule.FirewallRuleName -StartIpAddress $bootstrapCallerIp -EndIpAddress $bootstrapCallerIp -DefaultProfile $context } }
            $script:appName = $brand.name + ' NMe'
            $script:appCertName = 'nme-app-cert'
            $script:appId = $null
            $script:servicePrincipalObjectId = $null
            $script:splitIdentityTenantId = $null
            $script:azureEnv = 'AzureCloud'
            [IO.File]::WriteAllText((Join-Path $privateRoot 'vendor-configure.ps1'), $executionSource, [Text.UTF8Encoding]::new($false))
            $run.Stage = 'NativeExecution'
            & ([scriptblock]::Create($executionSource)) *> $null
            $run.ConfigurationCompleted = $true
        } catch {
            $run.ErrorType = $_.Exception.GetType().Name
            $run.ErrorCommand = [string]$_.InvocationInfo.MyCommand.Name
            $run.ErrorLine = $_.InvocationInfo.ScriptLineNumber
            $detail = [regex]::Replace([string]$_.Exception.Message, '(?i)https?://[^\s"''<>]+', '[uri]')
            foreach ($value in @((@($settings.Values) + @($plan.resourceGroupName, $web[0].Name, $sql[0].Name, $vault[0].Name)) | Where-Object { $_ } | Sort-Object { ([string]$_).Length } -Descending)) { $detail = $detail.Replace([string]$value, '[target]') }
            $detail = [regex]::Replace($detail, '(?i)\b[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\b|\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b|\b\d{1,3}(?:\.\d{1,3}){3}\b', '[reference]')
            $run.FailureMessage = if ($detail.Length -gt 500) { $detail.Substring(0, 500) } else { $detail }
            throw
        }
    } {
        $env:TEMP = $oldTemp
        $env:TMP = $oldTmp
        [Net.ServicePointManager]::SecurityProtocol = $oldSecurityProtocol
        try {
            Restore-NmePrivateBackends {
                $sqlRestore = Invoke-AzRestMethod -Method PATCH -Path $sqlPath -Payload (@{ properties = @{ publicNetworkAccess = 'Disabled' } } | ConvertTo-Json -Depth 5 -Compress) -DefaultProfile $context
                if ($sqlRestore.StatusCode -notin @(200, 201, 202)) { throw 'SQL private-access restoration was not accepted.' }
            } {
                $vaultRestore = Invoke-AzRestMethod -Method PATCH -Path $vaultPath -Payload (@{ properties = @{ publicNetworkAccess = 'Disabled'; networkAcls = $vaultBefore.networkAcls } } | ConvertTo-Json -Depth 15 -Compress) -DefaultProfile $context
                if ($vaultRestore.StatusCode -notin @(200, 201, 202)) { throw 'Key Vault private-access restoration was not accepted.' }
            }
        } finally {
            foreach ($file in @(Get-ChildItem -LiteralPath $bootstrapTemp -Filter '*.pfx' -File -ErrorAction SilentlyContinue)) { Remove-Item -LiteralPath $file.FullName -Force }
        }
        foreach ($rule in $firewalls) { $null = Set-AzSqlServerFirewallRule -ResourceGroupName $plan.resourceGroupName -ServerName $sql[0].Name -FirewallRuleName $rule.FirewallRuleName -StartIpAddress $rule.StartIpAddress -EndIpAddress $rule.EndIpAddress -DefaultProfile $context }
        $afterRules = @(Get-AzSqlServerFirewallRule -ResourceGroupName $plan.resourceGroupName -ServerName $sql[0].Name -DefaultProfile $context)
        foreach ($rule in $afterRules) {
            if ($rule.FirewallRuleName -notin @($firewalls | ForEach-Object FirewallRuleName) -and $rule.FirewallRuleName -eq $bootstrapCallerIp -and $rule.StartIpAddress -eq $bootstrapCallerIp -and $rule.EndIpAddress -eq $bootstrapCallerIp) { $null = Remove-AzSqlServerFirewallRule -ResourceGroupName $plan.resourceGroupName -ServerName $sql[0].Name -FirewallRuleName $rule.FirewallRuleName -DefaultProfile $context }
        }
        $sqlReadback = Invoke-AzRestMethod -Method GET -Path $sqlPath -DefaultProfile $context
        $vaultReadback = Invoke-AzRestMethod -Method GET -Path $vaultPath -DefaultProfile $context
        if ($sqlReadback.StatusCode -ne 200 -or $vaultReadback.StatusCode -ne 200 -or (ConvertFrom-Json -InputObject $sqlReadback.Content -AsHashtable).properties.publicNetworkAccess -ne 'Disabled' -or (ConvertFrom-Json -InputObject $vaultReadback.Content -AsHashtable).properties.publicNetworkAccess -ne 'Disabled') { throw 'Backend public access is not verified disabled; immediate recovery is required.' }
        $run.PrivateAccessRestored = $true
    }
} catch {
    if (-not $run.ErrorType) {
        $run.ErrorType = $_.Exception.GetType().Name
        $run.ErrorCommand = [string]$_.InvocationInfo.MyCommand.Name
        $run.ErrorLine = $_.InvocationInfo.ScriptLineNumber
    }
    $run.RestorationFailure = if (-not $run.PrivateAccessRestored) { $_.Exception.GetType().Name } else { $null }
}
[IO.File]::WriteAllText((Join-Path $privateRoot 'native-initialization.json'), ($run | ConvertTo-Json -Depth 6), [Text.UTF8Encoding]::new($false))
if (-not $run.PrivateAccessRestored) { throw 'Native initialization stopped without verified backend restoration. Inspect private/nme/native-initialization.json immediately.' }
if (-not $run.ConfigurationCompleted) { throw 'Native initialization stopped; backend private access was restored. Inspect the private stage classification before any retry.' }
$plan.nativeInitializationCompleted = $true
$plan.initializationCompleted = $true
[IO.File]::WriteAllText((Join-Path $privateRoot 'installation-plan.json'), ($plan | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
[pscustomobject]@{ Mode = 'NativeInitialized'; SharedBrandApplicationName = $brand.name + ' NMe'; PrivateAccessRestored = $true; EntraPublishingSelected = $true; RegistrationAndEntitlementVerified = $false; AzureChangesMade = $true }