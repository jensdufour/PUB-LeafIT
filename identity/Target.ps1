#requires -Version 7.6

function Read-LeafTargetSettings {
    param([Parameter(Mandatory)][string]$Text)
    $required = @('TARGET_TENANT_ID', 'TARGET_SUBSCRIPTION_ID', 'TARGET_DNS_ZONE_NAME')
    $optional = @('TARGET_PREVIOUS_ORGANIZATION_NAME', 'TARGET_NAMING_CLIENT_ID', 'TARGET_NAMING_CERTIFICATE_THUMBPRINT', 'TARGET_SHAREPOINT_DOMAIN_PREFIX', 'TARGET_SHAREPOINT_RENAME_AT')
    $settings = @{}
    foreach ($line in $Text -split '\r?\n') {
        $entry = [regex]::Match($line, '^\s*(?<key>TARGET_[A-Z0-9_]+)\s*=\s*(?<value>.*)$')
        if (-not $entry.Success -or $entry.Groups['key'].Value -notin ($required + $optional)) { continue }
        $key = $entry.Groups['key'].Value
        if ($settings.ContainsKey($key)) { throw 'Duplicate required target input.' }
        $settings[$key] = $entry.Groups['value'].Value.Trim().Trim([char]34, [char]39)
    }
    foreach ($key in $required) {
        if ([string]::IsNullOrWhiteSpace($settings[$key])) { throw 'Required private target input is missing.' }
    }
    if ($settings.ContainsKey('TARGET_PREVIOUS_ORGANIZATION_NAME') -and ([string]::IsNullOrWhiteSpace($settings.TARGET_PREVIOUS_ORGANIZATION_NAME) -or $settings.TARGET_PREVIOUS_ORGANIZATION_NAME.Length -gt 256 -or $settings.TARGET_PREVIOUS_ORGANIZATION_NAME -match '[\x00-\x1f]')) {
        throw 'The private previous organization name is invalid.'
    }
    foreach ($key in @('TARGET_TENANT_ID', 'TARGET_SUBSCRIPTION_ID', 'TARGET_NAMING_CLIENT_ID')) {
        if (-not $settings.ContainsKey($key)) { continue }
        $parsed = [guid]::Empty
        if (-not [guid]::TryParse($settings[$key], [ref]$parsed) -or $parsed -eq [guid]::Empty) { throw 'Invalid target identity input.' }
        $settings[$key] = $parsed.ToString()
    }
    if ($settings.ContainsKey('TARGET_NAMING_CERTIFICATE_THUMBPRINT') -and $settings.TARGET_NAMING_CERTIFICATE_THUMBPRINT -notmatch '^[a-fA-F0-9]{40}$') { throw 'The private naming certificate thumbprint is invalid.' }
    if ($settings.ContainsKey('TARGET_SHAREPOINT_DOMAIN_PREFIX') -and $settings.TARGET_SHAREPOINT_DOMAIN_PREFIX -notmatch '^[a-z][a-z0-9]{2,47}$') { throw 'The private SharePoint prefix must be a valid onmicrosoft domain prefix.' }
    if ($settings.ContainsKey('TARGET_SHAREPOINT_RENAME_AT')) {
        $scheduled = [DateTimeOffset]::MinValue
        if ($settings.TARGET_SHAREPOINT_RENAME_AT -notmatch '^\d{4}-\d{2}-\d{2}T.+(?:Z|[+-]\d{2}:\d{2})$' -or -not [DateTimeOffset]::TryParse($settings.TARGET_SHAREPOINT_RENAME_AT, [ref]$scheduled)) { throw 'The private SharePoint schedule requires an explicit ISO-8601 time zone.' }
    }
    $domain = $settings.TARGET_DNS_ZONE_NAME.ToLowerInvariant()
    if ($domain.Length -gt 253 -or $domain -notmatch '^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$' -or $domain.EndsWith('.onmicrosoft.com')) {
        throw 'A valid private custom domain is required.'
    }
    $settings.TARGET_DNS_ZONE_NAME = $domain
    return $settings
}

function Assert-LeafTargetContext {
    param([Parameter(Mandatory)]$Settings, $Context)
    if (-not $Context -or $Context.Tenant.Id -ne $Settings.TARGET_TENANT_ID -or $Context.Subscription.Id -ne $Settings.TARGET_SUBSCRIPTION_ID) {
        throw 'Authenticate explicitly to the configured target tenant and subscription; no automatic sign-in or context switch is performed.'
    }
}

function Read-LeafPrivateTarget {
    param([Parameter(Mandatory)][string]$RepositoryRoot)
    foreach ($path in @('.env', 'private/')) {
        git -C $RepositoryRoot check-ignore --quiet -- $path
        if ($LASTEXITCODE -ne 0) { throw 'Private target locations must be ignored.' }
    }
    $tracked = @(git -C $RepositoryRoot ls-files -- .env private)
    if ($LASTEXITCODE -ne 0 -or $tracked.Count) { throw 'Private target locations must be untracked.' }
    return Read-LeafTargetSettings ([IO.File]::ReadAllText((Join-Path $RepositoryRoot '.env')))
}

function Connect-LeafTargetGraph {
    param([Parameter(Mandatory)]$Settings, [switch]$RefreshFromAzure)
    Import-Module Az.Accounts -MinimumVersion 5.3.3 -ErrorAction Stop
    Import-Module Microsoft.Graph.Authentication -MinimumVersion 2.37.0 -ErrorAction Stop
    Assert-LeafTargetContext $Settings (Get-AzContext)
    $existing = Get-MgContext
    if ($existing -and $existing.TenantId -ne $Settings.TARGET_TENANT_ID) {
        throw 'An existing Graph context is not a verified target context. Disconnect it explicitly before proceeding.'
    }
    $created = -not [bool]$existing
    if ($created -or $RefreshFromAzure) {
        $token = Get-AzAccessToken -ResourceUrl 'https://graph.microsoft.com/' -TenantId $Settings.TARGET_TENANT_ID -ErrorAction Stop
        if ($token.TenantId -ne $Settings.TARGET_TENANT_ID -or $token.Token -isnot [securestring]) { throw 'Unexpected target Graph token.' }
        if ($existing -and $RefreshFromAzure) { $null = Disconnect-MgGraph -ErrorAction Stop }
        $null = Connect-MgGraph -AccessToken $token.Token -NoWelcome -ErrorAction Stop
    }
    try {
        $response = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/organization?$select=id' -OutputType PSObject -ErrorAction Stop
        $organizations = @($response.value)
        if ($organizations.Count -ne 1 -or $organizations[0].id -ne $Settings.TARGET_TENANT_ID) { throw 'Graph organization does not match the target.' }
    } catch {
        if ($created) { $null = Disconnect-MgGraph -ErrorAction SilentlyContinue }
        throw 'Target Graph verification failed; no consent, role assignment, or tenant change was performed.'
    }
    return [pscustomobject]@{ CreatedByScript = $created; RefreshedFromVerifiedAzureSession = $RefreshFromAzure.IsPresent }
}

function Disconnect-LeafTargetGraph {
    param($Session)
    if ($Session -and $Session.CreatedByScript) { $null = Disconnect-MgGraph -ErrorAction SilentlyContinue }
}

function Invoke-LeafTargetGraph {
    param(
        [Parameter(Mandatory)]$Settings,
        [Parameter(Mandatory)][string]$Path,
        [ValidateSet('GET', 'POST', 'PATCH', 'PUT', 'DELETE')][string]$Method = 'GET',
        [System.Collections.IDictionary]$Body,
        [string]$InputFilePath,
        [string]$OutputFilePath,
        [switch]$AllowNotFound
    )
    Assert-LeafTargetContext $Settings (Get-AzContext)
    if ($Path -notmatch '^/(?:v1\.0|beta)/' -or $Path.Contains('..') -or $Path.Contains('#')) { throw 'An explicit, relative Graph API path is required.' }
    $parameters = @{
        Method = $Method
        Uri = 'https://graph.microsoft.com' + $Path
        OutputType = 'PSObject'
        Headers = @{ 'Accept-Language' = '0' }
        ErrorAction = 'Stop'
    }
    if ($Body) { $parameters.Body = $Body | ConvertTo-Json -Depth 20 -Compress; $parameters.ContentType = 'application/json' }
    if ($InputFilePath) { $parameters.InputFilePath = $InputFilePath; $parameters.ContentType = 'image/png' }
    if ($OutputFilePath) { $parameters.OutputFilePath = $OutputFilePath }
    try { return Invoke-MgGraphRequest @parameters } catch {
        $status = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 0 }
        if ($AllowNotFound -and $Method -eq 'GET' -and $status -eq 404) { return $null }
        $code = 'Unknown'
        $detail = [string]$_.Exception.Message
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
            try {
                $body = $_.ErrorDetails.Message
                $start = $body.IndexOf('{')
                if ($start -ge 0) {
                    $failure = $body.Substring($start) | ConvertFrom-Json -ErrorAction Stop
                    if ($failure.error) { $code = [string]$failure.error.code; $detail = [string]$failure.error.message }
                }
            } catch { }
        }
        foreach ($value in $Settings.Values) { $detail = $detail.Replace([string]$value, '<target>') }
        $detail = $detail -replace '(?i)[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', '<id>' -replace '(?i)[a-z0-9._%+-]+@[a-z0-9.-]+', '<account>' -replace '(?i)[a-z0-9-]+\.onmicrosoft\.com', '<initial-domain>'
        if ($detail.Length -gt 500) { $detail = $detail.Substring(0, 500) }
        throw "Target Graph request stopped (HTTP $status; $code): $detail. Inspect state before retrying a create."
    }
}

function Get-LeafTargetGraphCollection {
    param([Parameter(Mandatory)]$Settings, [Parameter(Mandatory)][string]$Path)
    $items = [Collections.Generic.List[object]]::new()
    do {
        $response = Invoke-LeafTargetGraph -Settings $Settings -Path $Path
        if (-not $response -or -not $response.PSObject.Properties['value']) { throw 'Expected a complete Graph collection response.' }
        foreach ($item in @($response.value)) { if ($null -ne $item) { $items.Add($item) } }
        $next = $response.'@odata.nextLink'
        if ($next) {
            $uri = [uri]$next
            if ($uri.Scheme -ne 'https' -or $uri.Host -ne 'graph.microsoft.com') { throw 'Untrusted Graph pagination destination.' }
            $Path = $uri.AbsolutePath + $uri.Query
        }
    } while ($next)
    return $items.ToArray()
}

function Test-LeafTargetGuards {
    $tenant = [guid]::NewGuid().ToString()
    $subscription = [guid]::NewGuid().ToString()
    $sample = "TARGET_TENANT_ID=$tenant`nTARGET_SUBSCRIPTION_ID=$subscription`nTARGET_DNS_ZONE_NAME=example.com"
    $settings = Read-LeafTargetSettings $sample
    Assert-LeafTargetContext $settings ([pscustomobject]@{ Tenant = @{ Id = $tenant }; Subscription = @{ Id = $subscription } })
    if ((Read-LeafTargetSettings ($sample + "`nTARGET_PREVIOUS_ORGANIZATION_NAME=Previous Example")).TARGET_PREVIOUS_ORGANIZATION_NAME -cne 'Previous Example') { throw 'The private previous organization name was not parsed.' }
    foreach ($invalid in @($sample.Replace($tenant, 'invalid'), $sample.Replace('example.com', 'example.onmicrosoft.com'), $sample.Replace('example.com', 'bad..example.com'), ($sample + "`nTARGET_TENANT_ID=$tenant"), $sample.Replace('TARGET_DNS_ZONE_NAME=example.com', ''), ($sample + "`nTARGET_PREVIOUS_ORGANIZATION_NAME="))) {
        $rejected = $false
        try { $null = Read-LeafTargetSettings $invalid } catch { $rejected = $true }
        if (-not $rejected) { throw 'An invalid target-input fixture was accepted.' }
    }
    foreach ($property in @('Tenant', 'Subscription')) {
        $wrong = [pscustomobject]@{ Tenant = @{ Id = $tenant }; Subscription = @{ Id = $subscription } }
        $wrong.$property.Id = [guid]::NewGuid().ToString()
        $rejected = $false
        try { Assert-LeafTargetContext $settings $wrong } catch { $rejected = $true }
        if (-not $rejected) { throw 'A wrong target context was accepted.' }
    }
    return 'PASS: private-input parsing and wrong-target guards; no tenant access.'
}