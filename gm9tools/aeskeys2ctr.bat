@echo off
rem ============================================================
rem  aeskeys2ctr.bat -- convert 3DS AES keys into 7-Zip CTR
rem  "3dskey" folders. Standalone Windows version of aeskeys2ctr.py.
rem  Runs on built-in PowerShell only; NO Python required.
rem
rem  Usage:
rem    aeskeys2ctr.bat <aes_keys.txt | aeskeydb.bin | dir-of-slot0x*.bin>
rem                    [--out <dir>] [--all-pub] [--devkit]
rem
rem  Output (under --out, default "3dskey_out"):
rem    3dskey\          retail publishable  -> copy next to 7z.dll
rem    3dskey_dev\      devkit publishable  -> copy next to 7z.dll
rem    3dskey_private\  console-unique / OTP-derived (DO NOT publish)
rem ============================================================
setlocal EnableExtensions
set "AK2CTR_IN="
set "AK2CTR_OUT=3dskey_out"
set "AK2CTR_ALLPUB=0"
set "AK2CTR_DEVKIT=0"

:parse
if "%~1"=="" goto run
if /i "%~1"=="--out"     (set "AK2CTR_OUT=%~2" & shift & shift & goto parse)
if /i "%~1"=="--all-pub" (set "AK2CTR_ALLPUB=1" & shift & goto parse)
if /i "%~1"=="--devkit"  (set "AK2CTR_DEVKIT=1"  & shift & goto parse)
if not defined AK2CTR_IN (set "AK2CTR_IN=%~1" & shift & goto parse)
shift & goto parse

:run
if not defined AK2CTR_IN (
  echo Usage: aeskeys2ctr.bat ^<aes_keys.txt^|aeskeydb.bin^|dir^> [--out dir] [--all-pub] [--devkit]
  exit /b 1
)

powershell -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Stop'; $src=$env:AK2CTR_IN; $out=$env:AK2CTR_OUT; if(-not $out){$out='3dskey_out'}; $allPub=$env:AK2CTR_ALLPUB -eq '1'; $devkit=$env:AK2CTR_DEVKIT -eq '1'; $pubSlots=@{}; foreach($s in @(0x03,0x18,0x1B,0x25)){$pubSlots[$s]=$true}; foreach($s in 0x2C..0x3F){$pubSlots[$s]=$true}; $keys=New-Object System.Collections.ArrayList; function Add-Key($n,$h,$u){[void]$script:keys.Add(@($n.ToLower(),$h,$u))}; if(Test-Path -LiteralPath $src -PathType Container){ Get-ChildItem -LiteralPath $src -File | Where-Object { $_.Name.ToLower().StartsWith('slot0x') -and $_.Name.ToLower().EndsWith('.bin') } | ForEach-Object { $b=[IO.File]::ReadAllBytes($_.FullName); if($b.Length -ge 16){ $base=$_.BaseName; $unit=''; if($base -match '\.dev'){$unit='dev'}elseif($base -match '\.ret'){$unit='ret'}; $nm=$base -replace '\.dev','' -replace '\.ret',''; $hex=-join($b[0..15]|ForEach-Object{$_.ToString('x2')}); Add-Key $nm $hex $unit } } } else { $ext=[IO.Path]::GetExtension($src).ToLower(); if($ext -eq '.txt'){ Get-Content -LiteralPath $src | ForEach-Object { $l=$_.Trim(); if($l -and -not $l.StartsWith('#') -and $l.Contains('=')){ $p=$l.Split('=',2); Add-Key $p[0].Trim() $p[1].Trim() '' } } } elseif($ext -eq '.bin'){ $b=[IO.File]::ReadAllBytes($src); if($b.Length %% 32 -ne 0){Write-Host 'WARN: aeskeydb.bin size not multiple of 32'}; for($off=0;$off -le $b.Length-32;$off+=32){ $slot=$b[$off]; $tv=$b[$off+1]; $typ=if($tv -ge 32 -and $tv -lt 127){[char]$tv}else{[char]0}; $idb=$b[($off+2)..($off+11)]; $ident=-join($idb|Where-Object{$_ -ne 0}|ForEach-Object{[char]$_}); $ut=$b[$off+14]; $keyB=$b[($off+16)..($off+31)]; $hasKey=$false; foreach($x in $keyB){if($x -ne 0){$hasKey=$true;break}}; if(@('X','Y','N','I') -contains [string]$typ -and $hasKey){ $suffix=@{X='KeyX';Y='KeyY';N='KeyN';I='Iv'}[[string]$typ]; $name='slot0x{0:x2}{1}{2}' -f $slot,$suffix,$ident; $unit=if($ut -eq 1){'dev'}elseif($ut -eq 2){'ret'}else{''}; $hex=-join($keyB|ForEach-Object{$_.ToString('x2')}); Add-Key $name $hex $unit } } } else { Write-Host 'Unrecognized input type'; exit 1 } }; if($keys.Count -eq 0){Write-Host 'No keys found in input.';exit 1}; $pubR=@{};$pubD=@{};$priv=@{}; foreach($k in $keys){ $name=$k[0];$hex=$k[1];$unit=$k[2]; $cls='priv'; $m=[regex]::Match($name,'slot0x([0-9a-f]{2})key([xyn])'); if($m.Success){ $slot=[Convert]::ToInt32($m.Groups[1].Value,16); if($pubSlots.ContainsKey($slot)){$cls='pub'} } else { foreach($p in @('common','nfc','generator','dlp','slot0x03')){ if($name.StartsWith($p)){$cls='pub';break} } }; $u=$unit; if(-not $u){ if($name.StartsWith('common')){$u=if($name.EndsWith('n')){'dev'}else{'ret'}}else{$u='ret'} }; if($cls -eq 'pub'){ if($u -eq 'dev'){$pubD[$name]=$hex}else{$pubR[$name]=$hex} } else {$priv[$name]=$hex} }; if($allPub){foreach($k in $priv.Keys){$pubR[$k]=$priv[$k]};$priv=@{}}; if($devkit){foreach($k in $pubR.Keys){$pubD[$k]=$pubR[$k]};$pubR=@{}}; function Write-Key($dir,$name,$hex){ New-Item -ItemType Directory -Force -Path $dir | Out-Null; $h=[regex]::Replace($hex,'[^0-9a-fA-F]',''); if($h.Length -lt 32){return 0}; $h=$h.Substring(0,32).ToUpper(); [IO.File]::WriteAllText((Join-Path $dir ($name+'.key')), ($name+'='+$h+[char]13+[char]10),(New-Object Text.ASCIIEncoding)); return 1 }; $n=0; foreach($k in $pubR.Keys){$n+=Write-Key (Join-Path $out '3dskey') $k $pubR[$k]}; foreach($k in $pubD.Keys){$n+=Write-Key (Join-Path $out '3dskey_dev') $k $pubD[$k]}; foreach($k in $priv.Keys){$n+=Write-Key (Join-Path $out '3dskey_private') $k $priv[$k]}; Write-Host ('Parsed {0} keys -> {1} written' -f $keys.Count,$n); Write-Host ('  retail publishable : {0}  (-> 3dskey\)' -f $pubR.Count); Write-Host ('  devkit publishable : {0}  (-> 3dskey_dev\)' -f $pubD.Count); Write-Host ('  private (no upload): {0}  (-> 3dskey_private\)' -f $priv.Count); Write-Host ('Output dir: {0}' -f [IO.Path]::GetFullPath($out))"
exit /b %ERRORLEVEL%
