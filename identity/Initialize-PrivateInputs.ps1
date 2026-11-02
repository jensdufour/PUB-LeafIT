[CmdletBinding()]
param([switch]$Apply, [switch]$CheckOnly, [switch]$ImportVmAdministrator)

$ErrorActionPreference = 'Stop'

function New-ProtectedPassword {
    $bytes = [byte[]]::new(30)
    [Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    $password = ConvertTo-SecureString ('Aa1!' + [Convert]::ToBase64String($bytes)) -AsPlainText -Force
    [Array]::Clear($bytes, 0, $bytes.Length)
    return ($password | ConvertFrom-SecureString)
}

function Test-PrivatePasswordEqual {
    param([Security.SecureString]$First, [Security.SecureString]$Second)
    $firstPointer = $secondPointer = [IntPtr]::Zero
    try {
        $firstPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($First)
        $secondPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Second)
        $difference = $First.Length -bxor $Second.Length
        for ($index = 0; $index -lt [Math]::Max($First.Length, $Second.Length); $index++) {
            $firstCharacter = if ($index -lt $First.Length) { [Runtime.InteropServices.Marshal]::ReadInt16($firstPointer, $index * 2) } else { 0 }
            $secondCharacter = if ($index -lt $Second.Length) { [Runtime.InteropServices.Marshal]::ReadInt16($secondPointer, $index * 2) } else { 0 }
            $difference = $difference -bor ($firstCharacter -bxor $secondCharacter)
        }
        return $difference -eq 0
    } finally {
        if ($firstPointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($firstPointer) }
        if ($secondPointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($secondPointer) }
    }
}

function New-ImportedAdministratorInputs {
    param([string]$Text, [string]$Username, [Security.SecureString]$Password)
    $userEntry = [regex]::Matches($Text, '(?m)^[ \t]*TARGET_VM_ADMIN_USERNAME[ \t]*=[ \t]*(?<value>[^\r\n]*)')
    $passwordEntry = [regex]::Matches($Text, '(?m)^[ \t]*TARGET_VM_ADMIN_PASSWORD_DPAPI[ \t]*=[ \t]*(?<value>[^\r\n]*)')
    if ($userEntry.Count -ne 1 -or $passwordEntry.Count -gt 1 -or $Username -cnotmatch '^[A-Za-z0-9][A-Za-z0-9_.-]{0,19}$' -or $Username -ine $userEntry[0].Groups['value'].Value.Trim().Trim([char]34, [char]39)) { throw 'EnteredUsernameMustMatchConfiguredAdministratorNoRetargeting' }
    if ($null -eq $Password -or $Password.Length -lt 16) { throw 'ExistingAdministratorPasswordMustMeetCurrentSixteenCharacterInputContract' }
    if ([regex]::IsMatch($Text, '(?m)^[ \t]*TARGET_VM_ADMIN_PASSWORD[ \t]*=')) { throw 'LegacyPlaintextInputRequiresSeparateMigration' }
    $existing = $null
    try {
        if ($passwordEntry.Count -eq 1 -and $passwordEntry[0].Groups['value'].Value.Trim()) {
            $existing = ConvertTo-SecureString -String $passwordEntry[0].Groups['value'].Value.Trim().Trim([char]34, [char]39) -ErrorAction Stop
            if (Test-PrivatePasswordEqual $existing $Password) { return @{ Text = $Text; Changed = $false } }
        }
        $protected = ConvertFrom-SecureString -SecureString $Password -ErrorAction Stop
        if ($passwordEntry.Count -eq 1) {
            $value = $passwordEntry[0].Groups['value']
            return @{ Text = $Text.Remove($value.Index, $value.Length).Insert($value.Index, $protected); Changed = $true }
        }
        $newline = if ($Text.Contains("`r`n")) { "`r`n" } else { "`n" }
        return @{ Text = $Text + $(if ($Text.EndsWith("`n")) { '' } else { $newline }) + 'TARGET_VM_ADMIN_PASSWORD_DPAPI=' + $protected + $newline; Changed = $true }
    } finally { if ($existing) { $existing.Dispose() }; $protected = $null }
}

if ($CheckOnly) {
    if ($Apply) { throw 'Offline checks cannot apply changes.' }
    if (-not $IsWindows) { throw 'This credential initializer requires Windows DPAPI.' }
    $first = New-ProtectedPassword
    $second = New-ProtectedPassword
    if ($first -eq $second -or ($first | ConvertTo-SecureString).Length -lt 40) { throw 'Protected credential self-check failed.' }
    $fixturePassword = ConvertTo-SecureString 'NON_CREDENTIAL_PASSWORD_FIXTURE_ONLY' -AsPlainText -Force
    try {
        $fixture = "TARGET_VM_ADMIN_USERNAME=fixtureadmin`r`nUNRELATED_INPUT=preserve`r`nTARGET_VM_ADMIN_PASSWORD_DPAPI=$first`r`n"
        $imported = New-ImportedAdministratorInputs $fixture 'fixtureadmin' $fixturePassword
        $repeat = New-ImportedAdministratorInputs $imported.Text 'fixtureadmin' $fixturePassword
        if (-not $imported.Changed -or $repeat.Changed -or $repeat.Text -cne $imported.Text -or -not $imported.Text.Contains("UNRELATED_INPUT=preserve`r`n") -or $imported.Text.Contains('NON_CREDENTIAL_PASSWORD_FIXTURE_ONLY')) { throw 'ProtectedImportPreservationOrNoChangeFixtureFailed' }
        $rejected = $false
        try { $null = New-ImportedAdministratorInputs $fixture 'otheradmin' $fixturePassword } catch { $rejected = $true }
        if (-not $rejected) { throw 'UnapprovedAdministratorRetargetFixtureAccepted' }
    } finally { $fixturePassword.Dispose(); $fixture = $imported = $repeat = $null }
    'PASS: unique strong passwords are generated and DPAPI round-trip succeeds without displaying secrets.'
    'PASS: existing password import preserves unrelated values, rejects account retargeting and repeats without rewriting ciphertext.'
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
if ($ImportVmAdministrator) {
    if (-not $Apply) { [pscustomobject]@{ Mode = 'ExistingAdministratorImportPreview'; MaskedTerminalInputRequired = $true; PlaintextPersisted = $false; RemotePasswordChanges = 0; Changed = $false }; return }
    if (-not $IsWindows) { throw 'WindowsUserDpapiRequiredForExistingPasswordImport' }
    $usernameInput = $passwordInput = $candidate = $stream = $null
    try {
        $usernameInput = Read-Host 'Existing AD administrator username (sAMAccountName only, input hidden)' -AsSecureString
        $username = [Net.NetworkCredential]::new('', $usernameInput).Password.Trim()
        if ($username -ine $settings.TARGET_VM_ADMIN_USERNAME) { throw 'EnteredUsernameDoesNotMatchExistingConfiguredAdministratorNoChanges' }
        $passwordInput = Read-Host 'Existing administrator password (input hidden)' -AsSecureString
        $candidate = New-ImportedAdministratorInputs $original $username $passwordInput
        if ($candidate.Changed) {
            $stream = [IO.File]::Open($envPath, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
            $bytes = [byte[]]::new($stream.Length)
            $stream.ReadExactly($bytes, 0, $bytes.Length)
            $hasBom = $bytes.Length -ge 3 -and $bytes[0] -eq 239 -and $bytes[1] -eq 187 -and $bytes[2] -eq 191
            $offset = if ($hasBom) { 3 } else { 0 }
            $current = [Text.UTF8Encoding]::new($false, $true).GetString($bytes, $offset, $bytes.Length - $offset)
            if ($current -cne $original) { throw 'PrivateInputsChangedDuringPromptNoWritePerformed' }
            $encoding = [Text.UTF8Encoding]::new($hasBom)
            $output = $encoding.GetPreamble() + $encoding.GetBytes($candidate.Text)
            $stream.Position = 0; $stream.Write($output, 0, $output.Length); $stream.SetLength($output.Length); $stream.Flush($true)
            $stream.Dispose(); $stream = $null
        }
        $verified = [IO.File]::ReadAllText($envPath)
        $repeat = New-ImportedAdministratorInputs $verified $username $passwordInput
        if ($repeat.Changed -or $verified -cne $candidate.Text) { throw 'ProtectedCredentialImportReadbackFailed' }
        [pscustomobject]@{ Mode = if ($candidate.Changed) { 'ProtectedExistingPasswordStored' } else { 'NoChange' }; UsernameMatchedConfiguredAdministrator = $true; PlaintextPersisted = $false; CredentialsPrinted = $false; RemotePasswordChanges = 0; Changed = $candidate.Changed; ExistingSourceBoundPlansRequireRevalidation = $candidate.Changed }
    } finally {
        if ($stream) { $stream.Dispose() }
        if ($usernameInput) { $usernameInput.Dispose() }; if ($passwordInput) { $passwordInput.Dispose() }
        $candidate = $repeat = $username = $current = $verified = $bytes = $output = $null
    }
    return
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