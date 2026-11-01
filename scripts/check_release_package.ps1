# check_release_package.ps1 -- audit a built release artifact before publishing.
#
# Fails when a package carries material that must stay local:
#   boot9.bin / otp.mem / otp_dec.mem / nand_cid.mem / movable.sed / ctrindex.ini
#   any keystone\ctrdevice\* folder
#   console serial numbers or 32-hex key values inside text members
#
# Usage:
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\check_release_package.ps1 `
#       -SevenZip <7z.exe> -Package <zip|exe> [<more>...]
#
# Note: loose keystone\*.key files are reported (they are the public keybase the
# handler reads); pass -AllowLooseKeys to accept them, otherwise they fail the
# audit as well.

param(
    [Parameter(Mandatory = $true)][string]$SevenZip,
    [Parameter(Mandatory = $true)][string[]]$Package,
    [switch]$AllowLooseKeys
)

$ErrorActionPreference = "Stop"
$problems = New-Object System.Collections.Generic.List[string]

# "-Package a,b" arrives as one string when the script is started with -File
$Package = $Package | ForEach-Object { $_ -split ',' } | Where-Object { $_.Trim() } | ForEach-Object { $_.Trim() }

# seeddb.bin is a public seed database and ships on purpose; the rest is per-console
$privateNames = '(?i)(boot9\.bin|otp\.mem|otp_dec\.mem|nand_cid\.mem|movable\.sed|ctrindex\.ini|keystone\.cache)$'

foreach ($pkg in $Package) {
    if (-not (Test-Path -LiteralPath $pkg)) {
        $problems.Add("missing package: $pkg")
        continue
    }
    $tmp = Join-Path $env:TEMP ("pkgchk_" + [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $tmp | Out-Null
    try {
        & $SevenZip x $pkg "-o$tmp" -y 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) {
            $problems.Add("cannot extract: $pkg")
            continue
        }

        $files = Get-ChildItem -LiteralPath $tmp -Recurse -File
        foreach ($f in $files) {
            $rel = $f.FullName.Substring($tmp.Length + 1) -replace '\\', '/'
            if ($rel -match 'ctrdevice/') {
                $problems.Add("$([IO.Path]::GetFileName($pkg)): private folder $rel")
                continue
            }
            if ($rel -match $privateNames) {
                $problems.Add("$([IO.Path]::GetFileName($pkg)): private material $rel")
                continue
            }
            if (-not $AllowLooseKeys -and $rel -match '(?i)\.key$') {
                $problems.Add("$([IO.Path]::GetFileName($pkg)): loose key file $rel")
                continue
            }
            if ($f.Extension -in @('.md', '.txt', '.lua', '.ini', '.ps1', '.bat')) {
                $text = Get-Content -LiteralPath $f.FullName -Raw -ErrorAction SilentlyContinue
                if ($text -match '\b[A-Z]{3}\d{8}\b') {
                    $problems.Add("$([IO.Path]::GetFileName($pkg)): serial-like value in $rel")
                }
                if ($text -match '\b[0-9A-Fa-f]{32}\b') {
                    $problems.Add("$([IO.Path]::GetFileName($pkg)): 32-hex value in $rel")
                }
            }
        }
    } finally {
        Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }
}

if ($problems.Count -gt 0) {
    Write-Host "PACKAGE AUDIT FAILED:"
    $problems | Select-Object -First 40 | ForEach-Object { Write-Host ("  " + $_) }
    if ($problems.Count -gt 40) { Write-Host ("  ... and " + ($problems.Count - 40) + " more") }
    exit 1
}

Write-Host ("package audit OK ({0} package(s))" -f $Package.Count)
exit 0
