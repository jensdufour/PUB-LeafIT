#requires -Version 7.6

function Get-NmePrivateVaultWorkerSource {
    return @'
param([string]$PacketName)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
function ReadWorkerSetting([string]$Name) {
    foreach ($key in @($Name, ('APPSETTING_' + $Name), $Name.Replace(':', '__'), ('APPSETTING_' + $Name.Replace(':', '__')))) {
        $value = [Environment]::GetEnvironmentVariable($key)
        if ($value) { return $value }
    }
    return $null
}
$packetPath = $null
$workerStage = 'ReadPacket'
$workerOperation = 'Unknown'
try {
    if ($PacketName -notmatch '^[a-f0-9]{32}$') { throw 'InvalidPacket' }
    $packetPath = Join-Path $env:HOME ('data\leafit-nme-bootstrap\' + $PacketName + '.json')
    try { $packet = [IO.File]::ReadAllText($packetPath) | ConvertFrom-Json } finally { if (Test-Path -LiteralPath $packetPath) { Remove-Item -LiteralPath $packetPath -Force } }
    $workerStage = 'ValidateTarget'
    $workerOperation = [string]$packet.Operation
    $vaultName = ReadWorkerSetting 'Deployment:KeyVaultName'
    $tenantId = ReadWorkerSetting 'Deployment:TenantId'
    if (-not $vaultName -or $vaultName -ne $packet.VaultName -or -not $tenantId -or $tenantId -ne $packet.TenantId -or [datetimeoffset]::Parse($packet.ExpiresUtc) -le [datetimeoffset]::UtcNow) { throw 'WrongTargetOrExpiredPacket' }
    if ($packet.Operation -eq 'ConfigureSql') {
        $sqlId = ReadWorkerSetting 'Deployment:SqlServerId'
        $appName = ReadWorkerSetting 'Deployment:WebAppName'
        $sqlName = ($sqlId -split '/')[-1]
        if (-not $sqlId -or $sqlName -ne $packet.SqlServerName -or $appName -ne $packet.UserName -or $appName -notmatch '^[a-z0-9-]+$' -or $packet.DatabaseName -notmatch '^[a-zA-Z0-9_.-]{1,128}$' -or $packet.ClientId -notmatch '^[a-fA-F0-9-]{36}$' -or -not $env:IDENTITY_ENDPOINT -or -not $env:IDENTITY_HEADER) { throw 'InvalidPrivateSqlTarget' }
        $identityUri = $env:IDENTITY_ENDPOINT + '?api-version=2019-08-01&resource=' + [uri]::EscapeDataString('https://database.windows.net/')
        $workerStage = 'AcquireSqlIdentity'
        $identity = Invoke-RestMethod -Uri $identityUri -Headers @{ 'X-IDENTITY-HEADER' = $env:IDENTITY_HEADER } -Method GET -TimeoutSec 30
        $workerStage = 'BuildSqlConnection'
        $builder = [Data.SqlClient.SqlConnectionStringBuilder]::new()
        $builder['Data Source'] = 'tcp:' + $sqlName + '.database.windows.net,1433'
        $builder['Initial Catalog'] = $packet.DatabaseName
        $builder['Encrypt'] = $true
        $builder['TrustServerCertificate'] = $false
        $builder['Connect Timeout'] = 30
        $connection = [Data.SqlClient.SqlConnection]::new($builder.ConnectionString)
        $connection.AccessToken = $identity.access_token
        try {
            $workerStage = 'OpenPrivateSqlConnection'
            $connection.Open()
            $sid = '0x' + ((([guid]$packet.ClientId).ToByteArray() | ForEach-Object { $_.ToString('X2') }) -join '')
            $query = "IF EXISTS (SELECT 1 FROM sys.database_principals WHERE name = '$appName' AND sid <> $sid) THROW 51000, 'Existing bootstrap user has a different identity', 1; IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = '$appName') CREATE USER [$appName] WITH SID = $sid, TYPE = E; ALTER ROLE db_ddladmin ADD MEMBER [$appName]; ALTER ROLE db_datareader ADD MEMBER [$appName]; ALTER ROLE db_datawriter ADD MEMBER [$appName];"
            $command = $connection.CreateCommand()
            $command.CommandText = $query
            $command.CommandTimeout = 60
            $workerStage = 'ConfigureSqlUser'
            $null = $command.ExecuteNonQuery()
        } finally { $connection.Dispose(); $identity = $null }
        @{ Success = $true; NotFound = $false; Value = @{ SqlConfigured = $true } } | ConvertTo-Json -Compress
        return
    }
    if ($packet.Name -notin @('nme-app-cert', 'nmw-scripted-action-cert') -or $packet.Operation -notin @('GetCertificate', 'CreateCertificate', 'GetCertificateOperation', 'GetCertificateSecret')) { throw 'UnexpectedOperation' }
    if ($packet.AccessToken -notmatch '^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$') { throw 'InvalidTokenFormat' }
    $method = 'GET'
    $relativePath = 'certificates/' + $packet.Name
    $body = $null
    $workerStage = 'BuildVaultRequest'
    switch ($packet.Operation) {
        'CreateCertificate' {
            $method = 'POST'
            $relativePath += '/create'
            $body = @{ policy = @{ key_props = @{ exportable = $true; kty = 'RSA'; key_size = 2048; reuse_key = $true }; secret_props = @{ contentType = 'application/x-pkcs12' }; x509_props = @{ subject = 'CN=' + $packet.Name; validity_months = 1 }; issuer = @{ name = 'Self' } } } | ConvertTo-Json -Depth 10 -Compress
        }
        'GetCertificateOperation' { $relativePath += '/pending' }
        'GetCertificateSecret' { $relativePath = 'secrets/' + $packet.Name }
    }
    $parameters = @{ Uri = 'https://' + $vaultName + '.vault.azure.net/' + $relativePath + '?api-version=2025-07-01'; Method = $method; Headers = @{ Authorization = 'Bearer ' + $packet.AccessToken }; UseBasicParsing = $true; TimeoutSec = 60; ErrorAction = 'Stop' }
    if ($body) { $parameters.Body = $body; $parameters.ContentType = 'application/json' }
    $workerStage = 'InvokeVault'
    try {
        $response = Invoke-WebRequest @parameters
        $value = $response.Content | ConvertFrom-Json
        @{ Success = $true; NotFound = $false; Value = $value } | ConvertTo-Json -Depth 20 -Compress
    } catch {
        $status = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 0 }
        if ($status -eq 404 -and $packet.Operation -eq 'GetCertificate') { @{ Success = $true; NotFound = $true; Value = $null } | ConvertTo-Json -Compress }
        else { @{ Success = $false; HttpStatus = $status; ErrorCode = 'PrivateVaultRequestFailed' } | ConvertTo-Json -Compress }
    }
} catch {
    $reason = [string]$_.Exception.Message
    if ($reason -notin @('InvalidPacket', 'WrongTargetOrExpiredPacket', 'InvalidPrivateSqlTarget', 'UnexpectedOperation', 'InvalidTokenFormat')) { $reason = $_.Exception.GetType().Name }
    @{ Success = $false; ErrorCode = 'PrivateWorkerRequestRejected'; Stage = $workerStage; Operation = $workerOperation; Reason = $reason } | ConvertTo-Json -Compress
} finally {
    if ($packetPath -and (Test-Path -LiteralPath $packetPath)) { Remove-Item -LiteralPath $packetPath -Force }
    $packet = $null
}
'@
}

function Invoke-NmePrivateWorkerHttp {
    param([Collections.IDictionary]$Connection, [ValidateSet('GET', 'POST', 'PUT', 'DELETE')][string]$Method, [string]$Path, [string]$Body, [switch]$SensitiveResponse)
    Assert-LeafTargetContext $Connection.Settings (Get-AzContext)
    if ($Connection.Host -notmatch '^[a-z0-9-]+\.scm\.azurewebsites\.net$' -or ($Path -ne '/api/command' -and $Path -notmatch '^/api/vfs/data/leafit-nme-bootstrap/(?:[a-f0-9]{32}\.(?:json|ps1))?$')) { throw 'The private-worker SCM target is invalid.' }
    $token = Get-AzAccessToken -ResourceUrl $Connection.Context.Environment.ResourceManagerUrl -TenantId $Connection.Settings.TARGET_TENANT_ID -DefaultProfile $Connection.Context
    if ($token.Token -isnot [securestring]) { throw 'The private-worker SCM token is not protected.' }
    $tokenText = [Net.NetworkCredential]::new('', $token.Token).Password
    $lines = @(
        ('url = "https://{0}{1}"' -f $Connection.Host, $Path),
        ('resolve = "{0}:443:{1}"' -f $Connection.Host, $Connection.Address),
        ('request = "{0}"' -f $Method),
        ('header = "Authorization: Bearer {0}"' -f $tokenText),
        'header = "Content-Type: application/json"',
        'header = "If-Match: *"'
    )
    if ($Body) { $lines += 'data-binary = "' + $Body.Replace('\', '\\').Replace('"', '\"').Replace("`r", '\r').Replace("`n", '\n') + '"' }
    $config = [string]::Join("`n", $lines)
    $output = $config | & curl.exe --config - --proto '=https' --max-time 120 --silent --write-out "`n%{http_code}" 2>&1
    $exitCode = $LASTEXITCODE
    $tokenText = $null
    $config = $null
    $lines = $null
    $text = $output -join "`n"
    $separator = $text.LastIndexOf("`n")
    if ($exitCode -ne 0 -or $separator -lt 0) { throw 'The private-worker HTTPS request failed.' }
    $status = [int]$text.Substring($separator + 1).Trim()
    if ($status -eq 409 -and $Method -eq 'PUT' -and $Path -eq '/api/vfs/data/leafit-nme-bootstrap/') {
        $null = Invoke-NmePrivateWorkerHttp -Connection $Connection -Method GET -Path $Path
        return
    }
    if ($status -notin @(200, 201, 204) -and -not ($Method -eq 'DELETE' -and $status -eq 404)) { throw ('The private-worker HTTPS request stopped with HTTP ' + $status + '.') }
    $content = $text.Substring(0, $separator)
    if (-not [string]::IsNullOrWhiteSpace($content) -and -not ($Method -eq 'DELETE')) { return ConvertFrom-Json -InputObject $content -AsHashtable -Depth 50 }
}

function Invoke-NmePrivateVaultOperation {
    param([Collections.IDictionary]$Connection, [ValidateSet('GetCertificate', 'CreateCertificate', 'GetCertificateOperation', 'GetCertificateSecret', 'ConfigureSql')][string]$Operation, [ValidateSet('nme-app-cert', 'nmw-scripted-action-cert')][string]$Name = 'nme-app-cert', [string]$ClientId)
    Assert-LeafTargetContext $Connection.Settings (Get-AzContext)
    $access = Get-AzAccessToken -ResourceUrl 'https://vault.azure.net' -TenantId $Connection.Settings.TARGET_TENANT_ID -DefaultProfile $Connection.Context
    if ($access.Token -isnot [securestring]) { throw 'The private-worker vault token is not protected.' }
    $packetName = [guid]::NewGuid().ToString('N')
    $path = '/api/vfs/data/leafit-nme-bootstrap/' + $packetName + '.json'
    $sourcePath = '/api/vfs/data/leafit-nme-bootstrap/' + $packetName + '.ps1'
    $packet = @{ Operation = $Operation; Name = $Name; VaultName = $Connection.VaultName; TenantId = $Connection.Settings.TARGET_TENANT_ID; ExpiresUtc = [datetimeoffset]::UtcNow.AddMinutes(3).ToString('o'); AccessToken = [Net.NetworkCredential]::new('', $access.Token).Password }
    if ($Operation -eq 'ConfigureSql') {
        $parsedClient = [guid]::Empty
        if (-not [guid]::TryParse($ClientId, [ref]$parsedClient) -or $parsedClient -eq [guid]::Empty -or -not $Connection.SqlServerName -or -not $Connection.DatabaseName -or -not $Connection.UserName) { throw 'The private SQL operation has no verified application/database binding.' }
        $packet.AccessToken = $null
        $packet.ClientId = $parsedClient.ToString()
        $packet.SqlServerName = $Connection.SqlServerName
        $packet.DatabaseName = $Connection.DatabaseName
        $packet.UserName = $Connection.UserName
    }
    $entry = '$sourcePath = Join-Path $env:HOME ''data\leafit-nme-bootstrap\' + $packetName + '.ps1''; try { $source = [IO.File]::ReadAllText($sourcePath) } finally { if (Test-Path -LiteralPath $sourcePath) { Remove-Item -LiteralPath $sourcePath -Force } }; & ([scriptblock]::Create($source)) -PacketName ' + $packetName
    $command = 'powershell.exe -NoProfile -NonInteractive -EncodedCommand ' + [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($entry))
    if ($command.Length -gt 4000) { throw 'The private-worker entry command exceeds its fixed length ceiling.' }
    try {
        $null = Invoke-NmePrivateWorkerHttp -Connection $Connection -Method PUT -Path '/api/vfs/data/leafit-nme-bootstrap/'
        $null = Invoke-NmePrivateWorkerHttp -Connection $Connection -Method PUT -Path $sourcePath -Body (Get-NmePrivateVaultWorkerSource)
        $null = Invoke-NmePrivateWorkerHttp -Connection $Connection -Method PUT -Path $path -Body ($packet | ConvertTo-Json -Depth 5 -Compress)
        $packet.AccessToken = $null
        $response = Invoke-NmePrivateWorkerHttp -Connection $Connection -Method POST -Path '/api/command' -Body (@{ command = $command; dir = 'site\wwwroot' } | ConvertTo-Json -Compress) -SensitiveResponse
        if ($response.ExitCode -ne 0 -or [string]::IsNullOrWhiteSpace([string]$response.Output)) { throw 'The private vault worker did not complete successfully.' }
        $result = ConvertFrom-Json -InputObject ([string]$response.Output).Trim() -AsHashtable -Depth 30
        if ($result.Success -ne $true) { throw ('The private vault operation failed: ' + [string]$result.ErrorCode + '; HTTP ' + [string]$result.HttpStatus + '; stage ' + [string]$result.Stage + '; operation ' + [string]$result.Operation + '; reason ' + [string]$result.Reason + '.') }
        if ($result.NotFound) { return $null }
        return $result.Value
    } finally {
        $packet.AccessToken = $null
        try { $null = Invoke-NmePrivateWorkerHttp -Connection $Connection -Method DELETE -Path $path } finally { $null = Invoke-NmePrivateWorkerHttp -Connection $Connection -Method DELETE -Path $sourcePath }
    }
}

function Test-NmePrivateVaultWorker {
    $source = Get-NmePrivateVaultWorkerSource
    $tokens = $null; $errors = $null
    $null = [Management.Automation.Language.Parser]::ParseInput($source, [ref]$tokens, [ref]$errors)
    if ($errors.Count -or $source -notmatch 'Remove-Item -LiteralPath \$packetPath' -or $source -match 'Start-Sleep|Write-Host|Write-Verbose|Write-Debug|Update-Az|Set-Az') { throw 'The private vault worker source failed its safety checks.' }
    if ($source.IndexOf('Remove-Item -LiteralPath $packetPath') -gt $source.IndexOf('Invoke-WebRequest @parameters')) { throw 'The one-use credential packet is not removed before backend work.' }
    $sample = '{"quote":"value","path":"one\\two"}'
    $encoded = $sample.Replace('\', '\\').Replace('"', '\"')
    if (-not $encoded.Contains('\"quote\"') -or -not $encoded.Contains('one\\\\two')) { throw 'The protected stdin request encoding check failed.' }
    $sampleId = [guid]::Parse('00000000-0000-0000-0000-000000000001')
    $sid = '0x' + (($sampleId.ToByteArray() | ForEach-Object { $_.ToString('X2') }) -join '')
    if ($sid -notmatch '^0x[0-9A-F]{32}$') { throw 'The private SQL identity encoding is invalid.' }
    $builder = [Data.SqlClient.SqlConnectionStringBuilder]::new()
    $builder['Data Source'] = 'tcp:example.database.windows.net,1433'
    $builder['Initial Catalog'] = 'example'
    $builder['Encrypt'] = $true
    $builder['TrustServerCertificate'] = $false
    $builder['Connect Timeout'] = 30
    if (-not $builder.ContainsKey('Data Source') -or -not $builder.ContainsKey('Initial Catalog')) { throw 'The private SQL connection-string keyword check failed.' }
    return $true
}