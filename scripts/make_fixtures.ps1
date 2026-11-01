# Generates tiny synthetic 3DS containers for the CI smoke tests.
# No copyrighted data is involved: every byte is produced here.
#
#   exefs.bin     plaintext ExeFS (one "banner" entry, 0x100 bytes)
#   romfs.bin     plaintext RomFS (IVFC + level-3 metadata, one file "hello.txt")
#   bad_romfs.bin IVFC whose level-3 offsets point far past EOF (must be rejected)
#   trunc_cia.bin CIA header promising sections far beyond EOF (must be rejected)
param([string]$OutDir = "fixtures")

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

function PutU32([byte[]]$buf, [int]$off, [uint32]$v) {
    $b = [BitConverter]::GetBytes($v)
    [Array]::Copy($b, 0, $buf, $off, 4)
}

# ---------------- plaintext ExeFS ----------------
# 10 entries x 0x10 (name[8] + off + size); file data starts at base + 0x200.
$exefs = New-Object byte[] 0x300
[Array]::Copy([Text.Encoding]::ASCII.GetBytes("banner"), 0, $exefs, 0, 6)
PutU32 $exefs 0x08 0            # offset
PutU32 $exefs 0x0C 0x100        # size
for ($i = 0; $i -lt 0x100; $i++) { $exefs[0x200 + $i] = [byte]($i -band 0xFF) }
[IO.File]::WriteAllBytes((Join-Path $OutDir "exefs.bin"), $exefs)

# ---------------- plaintext RomFS ----------------
# layout: IVFC header (0x1000) | level3 header (0x28) | dir meta (0x18) |
#         file meta (0x20 + name) | file data
$dirMetaOff = 0x28
$fileMetaOff = $dirMetaOff + 0x18
$fname = [Text.Encoding]::Unicode.GetBytes("hello.txt")   # UTF-16LE
$fileMetaLen = 0x20 + $fname.Length
$fileDataOff = $fileMetaOff + $fileMetaLen
$payload = [Text.Encoding]::ASCII.GetBytes("HELLO-ROMFS-DATA")
$total = 0x1000 + $fileDataOff + $payload.Length
$rom = New-Object byte[] $total
[Array]::Copy([Text.Encoding]::ASCII.GetBytes("IVFC"), 0, $rom, 0, 4)

$L = 0x1000
PutU32 $rom ($L + 0x00) 0x28          # size of this header
PutU32 $rom ($L + 0x04) 0             # offset dir hash
PutU32 $rom ($L + 0x08) 0             # size dir hash
PutU32 $rom ($L + 0x0C) ([uint32]$dirMetaOff)
PutU32 $rom ($L + 0x10) 0x18          # size dir meta
PutU32 $rom ($L + 0x14) 0             # offset file hash
PutU32 $rom ($L + 0x18) 0             # size file hash
PutU32 $rom ($L + 0x1C) ([uint32]$fileMetaOff)
PutU32 $rom ($L + 0x20) ([uint32]$fileMetaLen)
PutU32 $rom ($L + 0x24) ([uint32]$fileDataOff)

# dir meta @ lv3 + dirMetaOff: parent/sibling/child/file/samehash/nameLen
$dm = $L + $dirMetaOff
PutU32 $rom ($dm + 0x00) ([uint32]4294967295)   # parent
PutU32 $rom ($dm + 0x04) ([uint32]4294967295)   # sibling
PutU32 $rom ($dm + 0x08) ([uint32]4294967295)   # child  (no subdirectories)
PutU32 $rom ($dm + 0x0C) 0            # first file
PutU32 $rom ($dm + 0x10) 0            # same-hash
PutU32 $rom ($dm + 0x14) 0            # root name length

# file meta @ lv3 + fileMetaOff
$fm = $L + $fileMetaOff
PutU32 $rom ($fm + 0x00) ([uint32]4294967295)   # parent
PutU32 $rom ($fm + 0x04) ([uint32]4294967295)   # sibling
[BitConverter]::GetBytes([uint64]0).CopyTo($rom, $fm + 0x08)                       # data offset
[BitConverter]::GetBytes([uint64]$payload.Length).CopyTo($rom, $fm + 0x10)         # size
PutU32 $rom ($fm + 0x18) 0
PutU32 $rom ($fm + 0x1C) ([uint32]$fname.Length)
[Array]::Copy($fname, 0, $rom, $fm + 0x20, $fname.Length)
[Array]::Copy($payload, 0, $rom, $L + $fileDataOff, $payload.Length)
[IO.File]::WriteAllBytes((Join-Path $OutDir "romfs.bin"), $rom)

# ---------------- malformed inputs ----------------
$bad = New-Object byte[] 0x2000
[Array]::Copy([Text.Encoding]::ASCII.GetBytes("IVFC"), 0, $bad, 0, 4)
foreach ($o in @(0x0C, 0x1C, 0x24)) { PutU32 $bad (0x1000 + $o) ([uint32]4294967280) }
[IO.File]::WriteAllBytes((Join-Path $OutDir "bad_romfs.bin"), $bad)

$cia = New-Object byte[] 0x2020
PutU32 $cia 0x00 0x2020      # size_header
PutU32 $cia 0x04 0           # type/version
PutU32 $cia 0x08 0x2000      # cert size
PutU32 $cia 0x0C 0x2000      # ticket size
PutU32 $cia 0x10 0x2000      # tmd size
PutU32 $cia 0x14 0           # meta size
[BitConverter]::GetBytes([uint64]0x40000000).CopyTo($cia, 0x18)   # claims 1 GiB of content
[IO.File]::WriteAllBytes((Join-Path $OutDir "trunc_cia.bin"), $cia)


# expected bytes of the RomFS payload, for "fc /b" after extraction
[IO.File]::WriteAllBytes((Join-Path $OutDir "hello.expected"), $payload)

# plain garbage: IsArc must refuse it
$garbage = New-Object byte[] 4096
for ($i = 0; $i -lt $garbage.Length; $i++) { $garbage[$i] = 0xA5 }
[IO.File]::WriteAllBytes((Join-Path $OutDir "garbage.bin"), $garbage)

Write-Host ("fixtures written to " + (Resolve-Path $OutDir).Path)
