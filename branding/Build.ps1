#requires -Version 7.6
[CmdletBinding()]
param([switch]$CheckOnly)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $IsWindows) { throw 'Brand generation uses native Windows System.Drawing; use PowerShell 7.6 on Windows.' }
Add-Type -AssemblyName System.Drawing
$brand = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'brand.json') -Raw | ConvertFrom-Json -AsHashtable
if ($brand.name -ne 'LeafIT') { throw 'Unexpected brand identity.' }
foreach ($value in $brand.palette.Values) {
    if ($value -notmatch '^#[A-F0-9]{6}$') { throw 'Palette values must be six-digit RGB hex colors.' }
}
foreach ($dependency in @(
    @{ File = $brand.typography.fontFile; Hash = $brand.typography.fontSha256 },
    @{ File = $brand.typography.licenseFile; Hash = $brand.typography.licenseSha256 }
)) {
    if ((Get-FileHash -LiteralPath (Join-Path $PSScriptRoot $dependency.File) -Algorithm SHA256).Hash -ne $dependency.Hash) {
        throw 'A bundled typography dependency differs from the reviewed source.'
    }
}

$fonts = [Drawing.Text.PrivateFontCollection]::new()
$paths = [Collections.Generic.List[Drawing.Drawing2D.GraphicsPath]]::new()
function New-TextPath {
    param([string]$Text, [single]$Height, [single]$Left = 0, [single]$Top = 0)
    $path = [Drawing.Drawing2D.GraphicsPath]::new()
    $paths.Add($path)
    $path.AddString($Text, $fonts.Families[0], [int][Drawing.FontStyle]::Regular, 100,
        [Drawing.PointF]::new(0, 0), [Drawing.StringFormat]::GenericTypographic)
    $bounds = $path.GetBounds()
    $scale = $Height / $bounds.Height
    $matrix = [Drawing.Drawing2D.Matrix]::new($scale, 0, 0, $scale, $Left - $bounds.X * $scale, $Top - $bounds.Y * $scale)
    try { $path.Transform($matrix) } finally { $matrix.Dispose() }
    return $path
}

function Get-LogoShapes {
    param([string]$Variant, [switch]$SymbolOnly)
    $reversed = $Variant -eq 'reversed'
    $mono = $Variant -eq 'mono'
    @(
        @{ Path = $leaf; Fill = if ($reversed) { 'white' } elseif ($mono) { 'ink' } else { 'green' }; Stroke = $false },
        @{ Path = $fold; Fill = if ($reversed) { 'white' } elseif ($mono) { 'ink' } else { 'blue' }; Stroke = $false },
        @{ Path = $vein; Fill = if ($reversed) { 'blue' } else { 'white' }; Stroke = $true },
        @{ Path = $node; Fill = if ($mono) { 'ink' } else { 'gold' }; Stroke = $false }
    )
    if (-not $SymbolOnly) { @{ Path = $word; Fill = if ($reversed) { 'white' } else { 'ink' }; Stroke = $false } }
}

function ConvertTo-SvgPath {
    param([Drawing.Drawing2D.GraphicsPath]$Path)
    $points = $Path.PathPoints
    $types = $Path.PathTypes
    $builder = [Text.StringBuilder]::new()
    for ($index = 0; $index -lt $points.Length; $index++) {
        $kind = $types[$index] -band 7
        $count = if ($kind -eq 3) { 3 } else { 1 }
        [void]$builder.Append($(switch ($kind) { 0 { 'M' } 1 { 'L' } 3 { 'C' } default { throw 'Unsupported outline segment.' } }))
        for ($offset = 0; $offset -lt $count; $offset++) {
            $point = $points[$index + $offset]
            [void]$builder.Append([string]::Format([Globalization.CultureInfo]::InvariantCulture, '{0:0.###},{1:0.###} ', $point.X, $point.Y))
        }
        $index += $count - 1
        if ($types[$index] -band 128) { [void]$builder.Append('Z') }
    }
    return $builder.ToString().TrimEnd()
}

function Get-LogoSvgBody {
    param([string]$Variant, [switch]$SymbolOnly)
    $elements = foreach ($shape in @(Get-LogoShapes -Variant $Variant -SymbolOnly:$SymbolOnly)) {
        $data = ConvertTo-SvgPath $shape.Path
        $color = $brand.palette[$shape.Fill]
        if ($shape.Stroke) {
            '<path d="{0}" fill="none" stroke="{1}" stroke-width="6" stroke-linecap="round" stroke-linejoin="round"/>' -f $data, $color
        } else {
            '<path d="{0}" fill="{1}" fill-rule="evenodd"/>' -f $data, $color
        }
    }
    return $elements -join "`n"
}

function Write-BrandLogo {
    param([Drawing.Graphics]$Graphics, [string]$Variant, [Drawing.RectangleF]$Box, [switch]$SymbolOnly)
    $width = if ($SymbolOnly) { 96 } else { $wordmarkWidth }
    $scale = [Math]::Min($Box.Width / $width, $Box.Height / 96)
    $state = $Graphics.Save()
    try {
        $Graphics.TranslateTransform($Box.X + ($Box.Width - $width * $scale) / 2, $Box.Y + ($Box.Height - 96 * $scale) / 2)
        $Graphics.ScaleTransform($scale, $scale)
        foreach ($shape in @(Get-LogoShapes -Variant $Variant -SymbolOnly:$SymbolOnly)) {
            $color = [Drawing.ColorTranslator]::FromHtml($brand.palette[$shape.Fill])
            if ($shape.Stroke) {
                $pen = [Drawing.Pen]::new($color, 6)
                $pen.StartCap = $pen.EndCap = [Drawing.Drawing2D.LineCap]::Round
                $pen.LineJoin = [Drawing.Drawing2D.LineJoin]::Round
                try { $Graphics.DrawPath($pen, $shape.Path) } finally { $pen.Dispose() }
            } else {
                $brush = [Drawing.SolidBrush]::new($color)
                try { $Graphics.FillPath($brush, $shape.Path) } finally { $brush.Dispose() }
            }
        }
    } finally { $Graphics.Restore($state) }
}

function Write-BrandText {
    param([Drawing.Graphics]$Graphics, [string]$Text, [single]$Left, [single]$Top, [single]$Height, [string]$Color = 'ink')
    $path = New-TextPath -Text $Text -Height $Height -Left $Left -Top $Top
    $brush = [Drawing.SolidBrush]::new([Drawing.ColorTranslator]::FromHtml($brand.palette[$Color]))
    try { $Graphics.FillPath($brush, $path) } finally { $brush.Dispose() }
}

function Write-BrandPattern {
    param([Drawing.Graphics]$Graphics, [int]$Width, [int]$Height, [switch]$WithLogo)
    $Graphics.Clear([Drawing.ColorTranslator]::FromHtml($brand.palette.white))
    $brushes = @{}
    foreach ($color in @('mist', 'green', 'blue', 'gold')) {
        $brushes[$color] = [Drawing.SolidBrush]::new([Drawing.ColorTranslator]::FromHtml($brand.palette[$color]))
    }
    try {
        $Graphics.FillRectangle($brushes.mist, [single]($Width * 0.62), [single]0, [single]($Width * 0.38), [single]$Height)
        $Graphics.FillPolygon($brushes.green, [Drawing.PointF[]]@(
            [Drawing.PointF]::new($Width * 0.84, 0), [Drawing.PointF]::new($Width, 0),
            [Drawing.PointF]::new($Width, $Height * 0.40), [Drawing.PointF]::new($Width * 0.70, $Height * 0.68)
        ))
        $Graphics.FillPolygon($brushes.blue, [Drawing.PointF[]]@(
            [Drawing.PointF]::new($Width, $Height * 0.49), [Drawing.PointF]::new($Width, $Height),
            [Drawing.PointF]::new($Width * 0.64, $Height), [Drawing.PointF]::new($Width * 0.78, $Height * 0.72)
        ))
        $Graphics.FillPolygon($brushes.gold, [Drawing.PointF[]]@(
            [Drawing.PointF]::new($Width * 0.77, $Height * 0.69), [Drawing.PointF]::new($Width * 0.90, $Height * 0.57),
            [Drawing.PointF]::new($Width * 0.91, $Height * 0.60), [Drawing.PointF]::new($Width * 0.78, $Height * 0.72)
        ))
        if ($WithLogo) {
            Write-BrandLogo -Graphics $Graphics -Variant primary -Box ([Drawing.RectangleF]::new($Width * 0.05, $Height * 0.08, $Width * 0.23, $Height * 0.09))
        }
    } finally { foreach ($brush in $brushes.Values) { $brush.Dispose() } }
}

function Write-BrandBoard {
    param([Drawing.Graphics]$Graphics)
    $Graphics.Clear([Drawing.Color]::White)
    Write-BrandText $Graphics 'LEAFIT / HOUSE IDENTITY' 72 58 19 'green'
    Write-BrandLogo -Graphics $Graphics -Variant primary -Box ([Drawing.RectangleF]::new(60, 145, 720, 170))
    Write-BrandText $Graphics $brand.descriptor 80 354 32
    Write-BrandText $Graphics 'Cloud. Workplace. Security.' 80 410 23
    $brush = [Drawing.SolidBrush]::new([Drawing.ColorTranslator]::FromHtml($brand.palette.green))
    try { $Graphics.FillRectangle($brush, 930, 110, 598, 382) } finally { $brush.Dispose() }
    Write-BrandLogo -Graphics $Graphics -Variant reversed -Box ([Drawing.RectangleF]::new(978, 235, 500, 118))
    $column = 0
    foreach ($color in @('green', 'blue', 'gold', 'ink', 'mist')) {
        $left = 80 + $column * 290
        $brush = [Drawing.SolidBrush]::new([Drawing.ColorTranslator]::FromHtml($brand.palette[$color]))
        try { $Graphics.FillRectangle($brush, $left, 575, 260, 152) } finally { $brush.Dispose() }
        Write-BrandText $Graphics $color.ToUpperInvariant() $left 752 19
        Write-BrandText $Graphics $brand.palette[$color] $left 789 22
        $column++
    }
    Write-BrandText $Graphics 'Source Sans 3' 80 905 53
    Write-BrandText $Graphics 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' 80 1000 23
    Write-BrandText $Graphics 'abcdefghijklmnopqrstuvwxyz 0123456789' 80 1046 23
    Write-BrandLogo -Graphics $Graphics -Variant primary -SymbolOnly -Box ([Drawing.RectangleF]::new(1310, 926, 170, 170))
}

function Get-Luminance {
    param([string]$Hex)
    $components = foreach ($offset in @(1, 3, 5)) {
        $value = [Convert]::ToInt32($Hex.Substring($offset, 2), 16) / 255.0
        if ($value -le 0.04045) { $value / 12.92 } else { [Math]::Pow(($value + 0.055) / 1.055, 2.4) }
    }
    return 0.2126 * $components[0] + 0.7152 * $components[1] + 0.0722 * $components[2]
}

try {
    $fonts.AddFontFile((Join-Path $PSScriptRoot $brand.typography.fontFile))
    if ($fonts.Families.Count -ne 1) { throw 'The bundled font did not load.' }
    $leaf = [Drawing.Drawing2D.GraphicsPath]::new()
    $leaf.AddLine(12, 84, 12, 46)
    $leaf.AddBezier(12, 46, 12, 22, 30, 8, 58, 8)
    $leaf.AddLine(58, 8, 84, 8)
    $leaf.AddLine(84, 8, 84, 34)
    $leaf.AddBezier(84, 34, 84, 64, 66, 84, 38, 84)
    $leaf.CloseFigure()
    $fold = [Drawing.Drawing2D.GraphicsPath]::new()
    $fold.AddLine(48, 8, 84, 8)
    $fold.AddLine(84, 8, 84, 34)
    $fold.AddBezier(84, 34, 84, 48, 80, 60, 70, 70)
    $fold.AddLine(70, 70, 48, 48)
    $fold.CloseFigure()
    $vein = [Drawing.Drawing2D.GraphicsPath]::new()
    $vein.AddLine(28, 68, 66, 28)
    $vein.StartFigure()
    $vein.AddLine(46, 49, 66, 49)
    $node = [Drawing.Drawing2D.GraphicsPath]::new()
    $node.AddEllipse(60, 22, 12, 12)
    foreach ($path in @($leaf, $fold, $vein, $node)) { $paths.Add($path) }
    $word = New-TextPath -Text $brand.name -Height 76 -Left 116 -Top 10
    $wordmarkWidth = [int][Math]::Ceiling($word.GetBounds().Right + 8)

    $assets = @(
        @{ File = 'logos/leafit-wordmark.svg'; Kind = 'wordmark'; Variant = 'primary'; Width = $wordmarkWidth; Height = 96; MaxBytes = 50000 },
        @{ File = 'logos/leafit-wordmark-reversed.svg'; Kind = 'wordmark'; Variant = 'reversed'; Width = $wordmarkWidth; Height = 96; MaxBytes = 50000 },
        @{ File = 'logos/leafit-wordmark-mono.svg'; Kind = 'wordmark'; Variant = 'mono'; Width = $wordmarkWidth; Height = 96; MaxBytes = 50000 },
        @{ File = 'logos/leafit-symbol.svg'; Kind = 'symbol'; Variant = 'primary'; Width = 96; Height = 96; MaxBytes = 50000 },
        @{ File = 'logos/leafit-symbol-reversed.svg'; Kind = 'symbol'; Variant = 'reversed'; Width = 96; Height = 96; MaxBytes = 50000 },
        @{ File = 'exports/entra/banner.png'; Kind = 'wordmark'; Variant = 'primary'; Width = 245; Height = 36; MaxBytes = 10000 },
        @{ File = 'exports/entra/square-light.png'; Kind = 'symbol'; Variant = 'primary'; Width = 240; Height = 240; MaxBytes = 50000 },
        @{ File = 'exports/entra/square-dark.png'; Kind = 'symbol'; Variant = 'reversed'; Width = 240; Height = 240; MaxBytes = 50000 },
        @{ File = 'exports/entra/favicon.png'; Kind = 'symbol'; Variant = 'primary'; Width = 32; Height = 32; MaxBytes = 5000 },
        @{ File = 'exports/entra/background.png'; Kind = 'pattern'; Variant = 'plain'; Width = 1920; Height = 1080; MaxBytes = 300000 },
        @{ File = 'exports/microsoft-365/logo-light.png'; Kind = 'wordmark'; Variant = 'primary'; Width = 200; Height = 48; MaxBytes = 10000 },
        @{ File = 'exports/microsoft-365/logo-dark.png'; Kind = 'wordmark'; Variant = 'reversed'; Width = 200; Height = 48; MaxBytes = 10000 },
        @{ File = 'exports/intune/logo-light.png'; Kind = 'wordmark'; Variant = 'primary'; Width = 600; Height = 160; MaxBytes = 750000 },
        @{ File = 'exports/intune/logo-theme.png'; Kind = 'wordmark'; Variant = 'reversed'; Width = 600; Height = 160; MaxBytes = 750000 },
        @{ File = 'exports/intune/brand-image.png'; Kind = 'pattern'; Variant = 'branded'; Width = 1600; Height = 900; MaxBytes = 1300000 },
        @{ File = 'exports/collaboration/avatar.png'; Kind = 'avatar'; Variant = 'primary'; Width = 512; Height = 512; MaxBytes = 1000000 },
        @{ File = 'exports/collaboration/meeting-background.png'; Kind = 'pattern'; Variant = 'branded'; Width = 1920; Height = 1080; MaxBytes = 1000000 },
        @{ File = 'exports/windows/wallpaper.png'; Kind = 'pattern'; Variant = 'branded'; Width = 3840; Height = 2160; MaxBytes = 4000000 },
        @{ File = 'collateral/letterhead.svg'; Kind = 'letterhead'; Variant = 'primary'; Width = 794; Height = 1123; MaxBytes = 100000 },
        @{ File = 'brand-board.png'; Kind = 'board'; Variant = 'primary'; Width = 1600; Height = 1200; MaxBytes = 1000000 }
    )

    if (-not $CheckOnly) {
        foreach ($asset in $assets) {
            $target = Join-Path $PSScriptRoot $asset.File
            [void][IO.Directory]::CreateDirectory((Split-Path $target -Parent))
            if ($asset.File.EndsWith('.svg')) {
                $body = Get-LogoSvgBody -Variant $asset.Variant -SymbolOnly:($asset.Kind -eq 'symbol')
                $size = 'width="{0}" height="{1}"' -f $asset.Width, $asset.Height
                if ($asset.Kind -eq 'letterhead') {
                    $footer = New-TextPath -Text $brand.descriptor -Height 11 -Left 56 -Top 1065
                    $body = '<rect width="794" height="1123" fill="{0}"/><g transform="translate(52 48) scale(0.60)">{1}</g><rect x="56" y="1036" width="682" height="3" fill="{2}"/><path d="{3}" fill="{4}"/>' -f $brand.palette.white, $body, $brand.palette.gold, (ConvertTo-SvgPath $footer), $brand.palette.ink
                    $size = 'width="210mm" height="297mm"'
                }
                $svg = '<svg xmlns="http://www.w3.org/2000/svg" {0} viewBox="0 0 {1} {2}" role="img" aria-label="LeafIT"><title>LeafIT</title>{3}</svg>' -f $size, $asset.Width, $asset.Height, $body
                [IO.File]::WriteAllText($target, $svg + "`n", [Text.UTF8Encoding]::new($false))
                continue
            }
            $bitmap = [Drawing.Bitmap]::new($asset.Width, $asset.Height, [Drawing.Imaging.PixelFormat]::Format32bppArgb)
            $bitmap.SetResolution(96, 96)
            $graphics = [Drawing.Graphics]::FromImage($bitmap)
            try {
                $graphics.SmoothingMode = [Drawing.Drawing2D.SmoothingMode]::AntiAlias
                $graphics.PixelOffsetMode = [Drawing.Drawing2D.PixelOffsetMode]::HighQuality
                switch ($asset.Kind) {
                    'pattern' { Write-BrandPattern -Graphics $graphics -Width $asset.Width -Height $asset.Height -WithLogo:($asset.Variant -eq 'branded') }
                    'board' { Write-BrandBoard $graphics }
                    default {
                        $graphics.Clear($(if ($asset.Kind -eq 'avatar') { [Drawing.Color]::White } else { [Drawing.Color]::Transparent }))
                        $padding = if ($asset.Kind -eq 'avatar') { $asset.Width * 0.15 } else { 2 }
                        Write-BrandLogo -Graphics $graphics -Variant $asset.Variant -SymbolOnly:($asset.Kind -in @('symbol', 'avatar')) -Box ([Drawing.RectangleF]::new($padding, $padding, $asset.Width - 2 * $padding, $asset.Height - 2 * $padding))
                    }
                }
                $bitmap.Save($target, [Drawing.Imaging.ImageFormat]::Png)
            } finally { $graphics.Dispose(); $bitmap.Dispose() }
        }
    }

    foreach ($pair in @(@('white', 'green'), @('white', 'blue'), @('ink', 'white'), @('ink', 'gold'))) {
        $first = Get-Luminance $brand.palette[$pair[0]]
        $second = Get-Luminance $brand.palette[$pair[1]]
        if (([Math]::Max($first, $second) + 0.05) / ([Math]::Min($first, $second) + 0.05) -lt 4.5) { throw 'An approved text/background pairing fails WCAG AA contrast.' }
    }
    foreach ($asset in $assets) {
        $file = Get-Item -LiteralPath (Join-Path $PSScriptRoot $asset.File)
        if ($file.Length -eq 0 -or $file.Length -gt $asset.MaxBytes) { throw ('Asset exceeds its file-size limit: ' + $asset.File) }
        if ($asset.File.EndsWith('.svg')) {
            $xml = [xml][IO.File]::ReadAllText($file.FullName)
            if ($xml.DocumentElement.NamespaceURI -ne 'http://www.w3.org/2000/svg' -or $xml.svg.viewBox -ne ('0 0 {0} {1}' -f $asset.Width, $asset.Height) -or $xml.SelectNodes('//*[local-name()="path"]').Count -eq 0 -or $xml.SelectNodes('//*[local-name()="text" or local-name()="script" or local-name()="image"]').Count -gt 0) { throw ('Invalid or non-self-contained SVG: ' + $asset.File) }
        } else {
            $image = [Drawing.Bitmap]::new($file.FullName)
            try {
                if ($image.Width -ne $asset.Width -or $image.Height -ne $asset.Height) { throw ('Incorrect image dimensions: ' + $asset.File) }
                $sampledColors = [Collections.Generic.HashSet[int]]::new()
                for ($row = 0; $row -lt 16; $row++) {
                    for ($column = 0; $column -lt 16; $column++) {
                        [void]$sampledColors.Add($image.GetPixel([int](($image.Width - 1) * $column / 15), [int](($image.Height - 1) * $row / 15)).ToArgb())
                    }
                }
                if ($sampledColors.Count -lt 3) { throw ('Blank or incomplete raster asset: ' + $asset.File) }
                if ($asset.Kind -in @('symbol', 'wordmark') -and $image.GetPixel(0, 0).A -ne 0) { throw ('Logo transparency was lost: ' + $asset.File) }
            } finally { $image.Dispose() }
        }
    }
    [pscustomobject]@{ Mode = if ($CheckOnly) { 'CheckOnly' } else { 'BuildAndCheck' }; AssetsValidated = $assets.Count; FontChecksumVerified = $true; OutlinedSvgLogos = $true; TextContrastAA = $true; TenantAccessRequired = $false }
} finally {
    foreach ($path in $paths) { $path.Dispose() }
    $fonts.Dispose()
}