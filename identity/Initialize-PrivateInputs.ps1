[CmdletBinding()]
param([switch]$Apply, [switch]$CheckOnly)

$ErrorActionPreference = 'Stop'

function New-ProtectedPassword {
    $bytes = [byte[]]::new(30)
    [Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    $password = ConvertTo-SecureString ('Aa1!' + [Convert]::ToBase64String($bytes)) -AsPlainText -Force
    [Array]::Clear($bytes, 0, $bytes.Length)
    return ($password | ConvertFrom-SecureString)
}

if ($CheckOnly) {
    if ($Apply) { throw 'Offline checks cannot apply changes.' }
    if (-not $IsWindows) { throw 'This credential initializer requires Windows DPAPI.' }
    $first = New-ProtectedPassword
    $second = New-ProtectedPassword
    if ($first -eq $second -or ($first | ConvertTo-SecureString).Length -lt 40) { throw 'Protected credential self-check failed.' }
    'PASS: unique strong passwords are generated and DPAPI round-trip succeeds without displaying secrets.'
    return
}

$repo = Split-Path $PSScriptRoot -Parent
foreach ($path in @('.env', 'private/')) {
    git -C $repo check-ignore --quiet -- $path
    if ($LASTEXITCODE -ne 0) { throw 'Private inputs must be ignored.' }
}
$tracked = @(git -C $repo ls-files -- .env private)
if ($LASTEXITCODE -ne 0 -or $tracked.Count) { throw 'Private inputs must be untracked.' }
$envPath = Join-Path $repo '.env'
$original = [IO.File]::ReadAllText($envPath)
$settings = @{}
foreach ($line in [IO.File]::ReadAllLines($envPath)) {
    $entry = [regex]::Match($line, '^\s*(?<key>TARGET_[A-Z0-9_]+)\s*=\s*(?<value>.*)$')
    if (-not $entry.Success) { continue }
    $key = $entry.Groups['key'].Value
    if ($settings.ContainsKey($key)) { throw 'Duplicate private target input.' }
    $settings[$key] = $entry.Groups['value'].Value.Trim().Trim([char]34, [char]39)
}
if ($settings.TARGET_DNS_ZONE_NAME -notmatch '^(?=.{1,240}$)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\.[A-Za-z]{2,}$') {
    throw 'A valid private registered DNS zone input is required.'
}
$defaults = [ordered]@{
    TARGET_AD_DOMAIN_NAME = 'ad.' + $settings.TARGET_DNS_ZONE_NAME.ToLowerInvariant()
    TARGET_AD_NETBIOS_NAME = 'LEAFIT'
    TARGET_VNET_ADDRESS_PREFIX = '10.60.0.0/16'
    TARGET_AD_SUBNET_PREFIX = '10.60.0.0/24'
    TARGET_DC1_PRIVATE_IP = '10.60.0.4'
    TARGET_DC2_PRIVATE_IP = '10.60.0.5'
    TARGET_VM_ADMIN_USERNAME = 'leafitadmin'
}
$missing = @($defaults.Keys | Where-Object { -not $settings.ContainsKey($_) })
foreach ($key in $defaults.Keys) {
    if ($settings.ContainsKey($key) -and [string]::IsNullOrWhiteSpace($settings[$key])) { throw 'An existing private input is empty; do not overwrite it implicitly.' }
}
$secretKeys = @('TARGET_VM_ADMIN_PASSWORD_DPAPI', 'TARGET_AD_DSRM_PASSWORD_DPAPI')
foreach ($key in $secretKeys) {
    if ($settings.ContainsKey($key)) {
        $secure = $settings[$key] | ConvertTo-SecureString
        if ($secure.Length -lt 16) { throw 'An existing protected credential is invalid.' }
    }
}
if ($settings.ContainsKey('TARGET_VM_ADMIN_PASSWORD') -or $settings.ContainsKey('TARGET_AD_DSRM_PASSWORD')) {
    throw 'Existing plaintext credential inputs require explicit migration; no credential replacement performed.'
}
$missingSecrets = @($secretKeys | Where-Object { -not $settings.ContainsKey($_) })
if (-not $Apply) {
    [pscustomobject]@{ MissingDesignInputs = $missing.Count; MissingProtectedCredentials = $missingSecrets.Count; Changed = $false }
    return
}
if (-not $IsWindows) { throw 'Windows DPAPI is required to protect credentials.' }
$additions = @($missing | ForEach-Object { '{0}={1}' -f $_, $defaults[$_] })
foreach ($key in $missingSecrets) { $additions += ('{0}={1}' -f $key, (New-ProtectedPassword)) }
if ($additions.Count) {
    if ([IO.File]::ReadAllText($envPath) -cne $original) { throw 'Private configuration changed during preparation.' }
    $newline = if ($original.Contains("`r`n")) { "`r`n" } else { "`n" }
    $prefix = if ($original.EndsWith("`n")) { '' } else { $newline }
    [IO.File]::AppendAllText($envPath, $prefix + ($additions -join $newline) + $newline)
}
[pscustomobject]@{ AddedDesignInputs = $missing.Count; AddedProtectedCredentials = $missingSecrets.Count; Changed = ($additions.Count -gt 0); CredentialsPrinted = $false }