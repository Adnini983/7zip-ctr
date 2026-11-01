7-Zip CTR 26.04-CTR03
=====================

7-Zip CTR is a fork of 7-Zip 26.04 that adds read-only browsing and extraction of
Nintendo 3DS / New Nintendo 3DS containers. Everything else is stock 7-Zip 26.04.

WHAT IT OPENS (READ ONLY)
-------------------------
  .3ds .cci .3dz .csu    NCSD / game-card images -> partitions, ExeFS, RomFS
  .ncch .cxi .cfa .app   NCCH -> ExeFS (.code / banner / icon / logo), RomFS
  .cia                   installable archives -> cert / ticket / tmd / Content_*.cxi / meta
  .cnt                   Contents.cnt (inside a CSU, or extracted standalone)
  .tmd                   CDN title metadata (listing only; content needs a ticket)
  .firm                  FIRM images (sections + RSA-2048 signature state)
  .exefs .romfs .bin     already-decrypted ExeFS / RomFS segments (no key needed)
  nand.bin               your own NAND backup -> TWL / AGB_Save / Firm0 / Firm1 / CTRNAND

KEYS
----
No keys are hard-coded. Put your own material next to 7z.dll:

  keystone\ctraes_retail\    retail AES keys    (one "KeyName=HEX" line per .key file)
  keystone\ctraes_dev\       devkit AES keys
  keystone\ctrdevice\<SN>\   per-console NAND material: boot9.bin, otp.mem, nand_cid.mem, ctrindex.ini
  keystone\pubkey\           FIRM RSA public keys (pubkey.ini + retail/dev_firm_pubkey.bin)
  seeddb.bin                 optional seed database (next to 7z.dll)

All folders are configurable in keystone.ini, or in 7-Zip CTR > Tools (T) > Options (O)
> Keystone tab. Console-unique material (otp, boot9, NAND CID) must be dumped from your
own hardware; it is never distributed with this package.

FILES IN THIS PACKAGE
---------------------
  7zFM.exe        7-Zip CTR File Manager (GUI)
  7z.exe          7-Zip CTR command line
  7z.dll          engine - contains the 3DS handler
  7zG.exe         7-Zip GUI module
  7-zip.dll       Windows shell extension (64-bit)
  7-zip32.dll     Windows shell extension (32-bit host)
  7z.sfx, 7zCon.sfx   SFX modules
  Uninstall.exe   standalone uninstaller
  Lang\           language files (92 languages)
  keystone\       key folders: public AES key subset + FIRM public keys
  keystone.ini    configuration template (leave empty = built-in defaults)
  seeddb.bin      seed database
  License.txt     license texts

TIPS
----
  * 7zFM.exe is self-contained: the 3DS handler is linked into the EXE itself.
    7z.exe loads 7z.dll instead. Keep both in the same folder.
  * Double-click a container, or right-click > Extract.
  * Properties (File > Properties) shows ctrtool-level details: Title ID, title key,
    partition table, ExeFS/RomFS offsets, FIRM signature state, ...
  * To open a NAND backup without a device profile, put boot9.bin, otp.mem,
    nand_cid.mem next to nand.bin; 7zFM will ask retail/devkit and Old/New 3DS,
    the command line takes -unit / -type / -slot.

中文说明
--------
  这是 7-Zip 26.04 的定制分支，新增任天堂 3DS / New3DS 容器的只读浏览与解包。
  * 密钥不内置：把你的密钥放进 7z.dll 同目录的 keystone\ctraes_retail\ 与
    keystone\ctraes_dev\（每个文件一行 KeyName=32位HEX），目录可在 keystone.ini
    或「工具 → 选项 → 密钥库」里改。
  * 打开 nand.bin 需要本机独有材料（boot9 / OTP / NAND CID），放在
    keystone\ctrdevice\<序列号>\ 或直接放在 nand.bin 同目录。
  * 只读：不支持写入、重新加密、导出加密镜像。
  * 详细说明见项目文档 docs\（USAGE / KEYS / EXTRACT_KEYS / NAND / BUILD）。

LICENSE
-------
  GNU LGPL-2.1 (with the unRAR restriction). See License.txt.
  Based on 7-Zip by Igor Pavlov (https://www.7-zip.org/).
  This fork is not an official 7-Zip release.
