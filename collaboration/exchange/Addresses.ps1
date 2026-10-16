#requires -Version 7.6

function Test-LeafAddressPreservation {
    param([string[]]$Before, [string[]]$After, [string]$BeforeUpn, [string]$DesiredUpn)
    $addresses = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($address in $After) { [void]$addresses.Add($address) }
    foreach ($address in $Before) {
        if ($addresses.Contains($address)) { continue }
        if ($BeforeUpn -and $DesiredUpn -and $address -ieq ('sip:' + $BeforeUpn) -and $addresses.Contains('sip:' + $DesiredUpn)) { continue }
        return $false
    }
    return $true
}

function New-LeafPrimaryAddressSet {
    param([string[]]$Before, [string]$PrimaryAddress)
    if ($PrimaryAddress -notmatch '^[^@\s]+@[^@\s]+$') { throw 'The desired primary SMTP address is invalid.' }
    $addresses = [Collections.Generic.List[string]]::new()
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($address in $Before) {
        if ([string]::IsNullOrWhiteSpace($address)) { throw 'An existing mailbox address is empty.' }
        $value = $address
        if ($address.StartsWith('smtp:', [StringComparison]::OrdinalIgnoreCase)) {
            $smtp = $address.Substring(5)
            if ($smtp -ieq $PrimaryAddress) { continue }
            $value = 'smtp:' + $smtp
        }
        if ($seen.Add($value)) { $addresses.Add($value) }
    }
    $addresses.Add('SMTP:' + $PrimaryAddress)
    return $addresses.ToArray()
}