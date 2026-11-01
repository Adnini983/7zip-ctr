# check_no_secrets.ps1 -- fail the build if the repository carries material that
# must never be published: console serial numbers, plaintext AES key values,
# or per-console device files.
#
# Usage (from the repository root):
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\check_no_secrets.ps1
#
# Exit code 0 = clean, 1 = leak found (the message lists every hit).

$ErrorActionPreference = "Stop"

# Files we inspect: text that ships in the source tree.
$textExt = @('.md', '.txt', '.lua', '.py', '.ps1', '.yml', '.ini', '.bat', '.cmd', '.sh')
# Directories that legitimately contain hex literals (upstream 7-Zip sources).
$skipDirs = @('CPP/', 'C/', 'Asm/', 'DOC/', 'Lang/', '.git/')

$problems = New-Object System.Collections.Generic.List[string]

# only tracked files matter (untracked local dumps are the user's own business)
$tracked = & git ls-files
if (-not $tracked) { Write-Host "not a git repository"; exit 1 }

foreach ($rel in $tracked) {
    $rel = $rel -replace '\\', '/'

    # 1) never allow per-console device material
    if ($rel -match '(?i)(^|/)(boot9\.bin|otp\.mem|otp_dec\.mem|nand_cid\.mem|movable\.sed|ctrindex\.ini)$') {
        $problems.Add("device material tracked: $rel")
        continue
    }
    if ($rel -match '(?i)(^|/)ctrdevice/' ) {
        $problems.Add("ctrdevice folder tracked: $rel")
        continue
    }
    if ($rel -match '(?i)\.key$') {
        $problems.Add("loose key file tracked: $rel")
        continue
    }

    $ext = [System.IO.Path]::GetExtension($rel).ToLower()
    if ($textExt -notcontains $ext) { continue }
    $skip = $false
    foreach ($d in $skipDirs) { if ($rel.StartsWith($d)) { $skip = $true; break } }
    if ($skip) { continue }

    $lines = @(Get-Content -LiteralPath $rel -ErrorAction SilentlyContinue)
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]

        # 2) console serial numbers (three letters + eight digits)
        foreach ($m in [regex]::Matches($line, '\b[A-Z]{3}\d{8}\b')) {
            $problems.Add(("{0}:{1}: serial-like value '{2}'" -f $rel, ($i + 1), $m.Value))
        }

        # 3) 32-hex key values, unless the line clearly uses a placeholder
        if ($line -match '[<]|占位|placeholder|redacted|XXXX|xxxx') { continue }
        foreach ($m in [regex]::Matches($line, '\b[0-9A-Fa-f]{32}\b')) {
            $problems.Add(("{0}:{1}: 32-hex value '{2}'" -f $rel, ($i + 1), $m.Value))
        }
    }
}

if ($problems.Count -gt 0) {
    Write-Host "SECRET CHECK FAILED:"
    $problems | ForEach-Object { Write-Host ("  " + $_) }
    Write-Host ""
    Write-Host "Replace serial numbers with <serial> and key values with <32 位十六进制>."
    exit 1
}

Write-Host ("secret check OK ({0} tracked files)" -f $tracked.Count)
exit 0
