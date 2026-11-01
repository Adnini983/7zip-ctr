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


# ---------------------------------------------------------------- .csu
# Synthetic CTR System Updater package: NCSD -> NCCH (fixed-key crypto) ->
# encrypted RomFS holding CupList + Contents.cnt, so the CI covers the path
# where the expanded .cia items must inherit the RomFS crypto context.
function PutU64([byte[]]$buf, [int]$off, [uint64]$v) {
    [Array]::Copy([BitConverter]::GetBytes($v), 0, $buf, $off, 8)
}
function Align16([int]$n) { [int](($n + 15) -band (-bnot 15)) }

# ---------------------------------------------------------------- AES-CTR
$ZeroKey = New-Object byte[] 16
function AesCtr([byte[]]$data, [byte[]]$ctrBase, [uint64]$off) {
    $out = New-Object byte[] $data.Length
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Mode = [System.Security.Cryptography.CipherMode]::ECB
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::None
    $aes.Key = $script:ZeroKey
    $enc = $aes.CreateEncryptor()

    $c = New-Object byte[] 16
    [Array]::Copy($ctrBase, 0, $c, 0, 16)
    $add = [uint64]($off -shr 4)
    $carry = $add
    for ($i = 15; $i -ge 0 -and $carry -ne 0; $i--) {
        $sum = [uint64]$c[$i] + ($carry -band 0xFF)
        $c[$i] = [byte]($sum -band 0xFF)
        $carry = ($carry -shr 8) + ($sum -shr 8)
    }
    $byteOff = [int]($off -band 15)

    $src = New-Object byte[] 16
    $ks = New-Object byte[] 16
    $pos = 0
    $first = $true
    while ($pos -lt $data.Length) {
        [Array]::Copy($c, 0, $src, 0, 16)
        [void]$enc.TransformBlock($src, 0, 16, $ks, 0)
        $from = if ($first) { $byteOff } else { 0 }
        for ($k = $from; $k -lt 16 -and $pos -lt $data.Length; $k++) {
            $out[$pos] = [byte]($data[$pos] -bxor $ks[$k])
            $pos++
        }
        $first = $false
        # increment the 128-bit big-endian counter by one
        for ($i = 15; $i -ge 0; $i--) {
            if ($c[$i] -eq 0xFF) { $c[$i] = 0 } else { $c[$i]++; break }
        }
    }
    $enc.Dispose(); $aes.Dispose()
    return $out
}

# ---------------------------------------------------------------- payloads
$tid = [uint64]0x000400000FF40002
$CsuPartId = [uint64]0x000400000FF40201      # bit (0x10 << 32) clear -> fixed key is zeroKey

# ctrBase: partition id bytes reversed into [0..7]
$CsuPartIdBytes = [BitConverter]::GetBytes($CsuPartId)
$ctrBase = New-Object byte[] 16
for ($i = 0; $i -lt 8; $i++) { $ctrBase[$i] = $CsuPartIdBytes[7 - $i] }

# the CIA payload we expect to see again after extraction
$ciaLen = 0x400
$cia = New-Object byte[] $ciaLen
for ($i = 0; $i -lt $ciaLen; $i++) { $cia[$i] = [byte](($i * 7 + 3) -band 0xFF) }
PutU32 $cia 0 0x2020          # looks like a CIA header on purpose
PutU32 $cia 8 0x800           # cert size
[IO.File]::WriteAllBytes((Join-Path $OutDir "csu.expected.cia"), $cia)

# CupList: one title id (8 bytes, little endian)
$cupList = New-Object byte[] 8
PutU64 $cupList 0 $tid

# Contents.cnt: "CONT" + entry table at 0xC00 + payload at 0xC00 + entryOffset
$cntEntryOff = 0x800
$cntLen = 0xC00 + $cntEntryOff + $ciaLen
$cnt = New-Object byte[] $cntLen
[Array]::Copy([Text.Encoding]::ASCII.GetBytes("CONT"), 0, $cnt, 0, 4)
PutU32 $cnt 0x04 4                            # version
PutU32 $cnt (0xC00 + 0) ([uint32]$cntEntryOff)
PutU32 $cnt (0xC00 + 4) ([uint32]($cntEntryOff + $ciaLen))
[Array]::Copy($cia, 0, $cnt, (0xC00 + $cntEntryOff), $ciaLen)

# ---------------------------------------------------------------- RomFS
$files = @(
    @{ Name = "CupList";      Data = $cupList },
    @{ Name = "Contents.cnt"; Data = $cnt }
)
$dirMetaOff = 0x28
$fmOff = 0x40
$fmCursor = 0   # file-meta offsets are relative to the table start
$metas = @()
foreach ($f in $files) {
    $nb = [Text.Encoding]::Unicode.GetBytes($f.Name)
    $len = Align16 (0x20 + $nb.Length)
    $m = New-Object byte[] $len
    PutU32 $m 0x00 ([uint32]4294967295)   # parent
    PutU32 $m 0x04 ([uint32]4294967295)   # sibling (filled below)
    PutU64 $m 0x08 0                      # data offset (filled below)
    PutU64 $m 0x10 ([uint64]$f.Data.Length)
    PutU32 $m 0x18 0
    PutU32 $m 0x1C ([uint32]$nb.Length)
    [Array]::Copy($nb, 0, $m, 0x20, $nb.Length)
    $metas += ,@{ Off = $fmCursor; Bytes = $m; Data = $f.Data }
    $fmCursor += $len
}
$fmSize = $fmCursor
$dataStart = $fmOff + $fmSize
$dataCursor = 0
$fmTotal = 0
foreach ($m in $metas) {
    PutU64 $m.Bytes 0x08 ([uint64]$dataCursor)
    $dataCursor += $m.Data.Length
    $fmTotal += $m.Data.Length
}
# sibling chain: file i -> file i+1
for ($i = 0; $i -lt $metas.Count - 1; $i++) {
    PutU32 $metas[$i].Bytes 0x04 ([uint32]$metas[$i + 1].Off)
}

$CsuL = 0x1000
$romLen = $CsuL + $dataStart + $fmTotal
$rom = New-Object byte[] $romLen
[Array]::Copy([Text.Encoding]::ASCII.GetBytes("IVFC"), 0, $rom, 0, 4)
PutU32 $rom ($CsuL + 0x00) 0x28
PutU32 $rom ($CsuL + 0x04) 0
PutU32 $rom ($CsuL + 0x08) 0
PutU32 $rom ($CsuL + 0x0C) ([uint32]$dirMetaOff)
PutU32 $rom ($CsuL + 0x10) 0x18
PutU32 $rom ($CsuL + 0x14) 0
PutU32 $rom ($CsuL + 0x18) 0
PutU32 $rom ($CsuL + 0x1C) ([uint32]$fmOff)
PutU32 $rom ($CsuL + 0x20) ([uint32]$fmSize)
PutU32 $rom ($CsuL + 0x24) ([uint32]$dataStart)

# dir meta (root): no parent/sibling/child, first file = 0
$dm = $CsuL + $dirMetaOff
PutU32 $rom ($dm + 0x00) ([uint32]4294967295)
PutU32 $rom ($dm + 0x04) ([uint32]4294967295)
PutU32 $rom ($dm + 0x08) ([uint32]4294967295)
PutU32 $rom ($dm + 0x0C) 0
PutU32 $rom ($dm + 0x10) 0
PutU32 $rom ($dm + 0x14) 0

foreach ($m in $metas) {
    [Array]::Copy($m.Bytes, 0, $rom, ($CsuL + $fmOff + $m.Off), $m.Bytes.Length)
}
$off = $CsuL + $dataStart
foreach ($m in $metas) {
    [Array]::Copy($m.Data, 0, $rom, $off, $m.Data.Length)
    $off += $m.Data.Length
}

# encrypt the whole RomFS with keyid 1 (c3[8] = 3), key = zeroKey
$c3 = New-Object byte[] 16
[Array]::Copy($ctrBase, 0, $c3, 0, 16)
$c3[8] = 3
$romEnc = AesCtr $rom $c3 ([uint64]0)

# ---------------------------------------------------------------- NCCH
$ncchRomfsOff = 0x1000                     # relative to the NCCH image (0x100 sig + 0x200 hdr)
$ncchLen = $ncchRomfsOff + (Align16 $romEnc.Length)
$ncch = New-Object byte[] $ncchLen
[Array]::Copy([byte[]](1..16 | ForEach-Object { [byte]($_ * 7 -band 0xFF) }), 0, $ncch, 0x00, 16)  # signature
[Array]::Copy([Text.Encoding]::ASCII.GetBytes("NCCH"), 0, $ncch, 0x100, 4)
PutU32 $ncch 0x104 ([uint32]$ncchLen)        # content size
PutU64 $ncch 0x108 $CsuPartId                      # partition id
PutU64 $ncch 0x118 $CsuPartId                      # program id
PutU32 $ncch 0x1A0 0                         # no ExeFS
PutU32 $ncch 0x1A4 0
PutU32 $ncch 0x1B0 ([uint32]($ncchRomfsOff -shr 9))   # romfs offset in media units
PutU32 $ncch 0x1B4 ([uint32](($romEnc.Length + 0x1FF) -shr 9))
$ncch[0x18F] = 0x01                          # flags7: fixed-key crypto
[Array]::Copy($romEnc, 0, $ncch, $ncchRomfsOff, $romEnc.Length)

# ---------------------------------------------------------------- NCSD (.csu)
$ncchBase = 0x4000                           # partition offset in the csu file
$partUnits = [int](($ncchLen + 0x1FF) -shr 9)
$total = $ncchBase + ($partUnits * 0x200)    # pad so the partition stays inside the file
$csu = New-Object byte[] $total
[Array]::Copy($ncch, 0, $csu, $ncchBase, $ncch.Length)
[Array]::Copy([Text.Encoding]::ASCII.GetBytes("NCSD"), 0, $csu, 0x100, 4)
PutU32 $csu 0x104 ([uint32](($csu.Length + 0x1FF) -shr 9))   # media size in units
PutU64 $csu 0x108 $CsuPartId
PutU32 $csu 0x120 ([uint32]($ncchBase -shr 9))               # partition 0 offset
PutU32 $csu 0x124 ([uint32]$partUnits)                       # partition 0 size
PutU64 $csu 0x188 $CsuPartId                                       # partition 0 id
[IO.File]::WriteAllBytes((Join-Path $OutDir "update.csu"), $csu)
Write-Host ("update.csu : {0} bytes (romfs {1}, cia {2})" -f $csu.Length, $romEnc.Length, $ciaLen)

Write-Host ("fixtures written to " + (Resolve-Path $OutDir).Path)
