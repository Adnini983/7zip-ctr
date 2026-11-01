# 密钥外置机制（docs/KEYS.md）

7-Zip CTR 的 `N3dsHandler` **不硬编码任何 AES 密钥**。
它从 `7z.dll` 同目录下的两个文件夹按名加载文本格式密钥。

## 1. 目录与文件格式

默认目录（相对 `7z.dll` 所在目录，可用 `keystone.ini` 改，见第 2 节）：

```
<7z.dll 所在目录>\
   keystone\
      ctraes_retail\     零售机密钥
      ctraes_dev\        开发机密钥
      ctrdevice\<SN>\   （可选）本机 NAND 设备档案，机器特有、仅本地，见 NAND.md
   keystone.ini          （可选）自定义上面两个密钥目录的位置
```

每个密钥一个文件，纯文本，一行：

```
KeyName=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX   # 32 位十六进制（16 字节）
```

示例 `keystone\ctraes_retail\slot0x2CKeyX.key`：

```
slot0x2CKeyX=510207515507CBB18E243DCB85E23A1D
```

文件名大小写不敏感（handler 会归一化为小写字母数字）。
例如 `slot0x2CKeyX.key`、`slot0x2ckeyx.key`、`SLOT0X2CKEYX.key` 均视为同一个。

## 2. 自定义密钥目录（keystone.ini）

默认目录即上面的 `keystone\ctraes_retail\` 与 `keystone\ctraes_dev\`。
发布包已在 `7z.dll` 同目录附带一份 `keystone.ini` 模板（两个键留空即走默认）。
想把密钥放到别处（例如外置盘、集中管理目录），直接编辑该文件填入路径：

```ini
[Keystone]
RetailCTRAESKeyDir=D:\3ds-keys\retail
DevCTRAESKeyDir=D:\3ds-keys\dev
DeviceDataDir=D:\3ds-keys\ctrdevice
FirmPubKeyDir=D:\3ds-keys\pubkey
Language=zh
```

`[Keystone]` 段一共 5 个键：

| 键 | 作用 | 默认值（相对 `7z.dll` 目录） |
|---|---|---|
| `RetailCTRAESKeyDir` | 零售机 AES 密钥目录 | `keystone\ctraes_retail` |
| `DevCTRAESKeyDir` | 开发机 AES 密钥目录 | `keystone\ctraes_dev` |
| `DeviceDataDir` | 本机 NAND 设备唯一数据目录（boot9 / OTP / NAND CID），见 [NAND.md](NAND.md) | `keystone\ctrdevice` |
| `FirmPubKeyDir` | FIRM RSA-2048 公钥目录（目录内另有独立 `pubkey.ini` 管理，见第 7 节） | `keystone\pubkey` |
| `Language` | 7zFM 里 NAND 裸材料弹窗与错误提示的语种：`zh` 强制中文、`en` 强制英文 | 留空 = 跟随系统 UI 语言（中文系统即中文） |

- 填**绝对路径**（`D:\…`、`\\server\share\…`）直接使用。
- 填**相对路径**时，相对 `7z.dll` 所在目录解析；留空（或删掉该键）
  回落到上表的默认目录。
- 也可以在 `7zFM.exe` 里用「选项 → 密钥库（Keystone）」页直接浏览指定，
  四行路径各有浏览「…」与「打开文件夹」按钮；点「恢复默认值」即恢复默认并清空对应键；
  保存时由程序写回本文件。`Language` 目前只能手改 `keystone.ini`（不在选项页里）。

> `seeddb.bin` 的位置不受本配置影响，始终读取 `7z.dll` 同目录。

## 3. handler 实际读取哪些密钥

| 密钥文件 | 用途 |
|---|---|
| `slot0x2CKeyX.key` | NCCH 原始加密（ncchflag=0），`ctraes_retail` + `ctraes_dev` 各一份 |
| `slot0x%02XKeyX.key` | 其他 NCCH crypto（如 0x18 / 0x1B / 0x25，New3DS 7x/Secure3/4） |
| `common0..common5` | 零售机 common key（ticket 解密 title key） |
| `common0N..common5N` | 开发机 / New3DS common key（dev 用） |
| `slot0x3DKeyX.key` | 零售机 Old3DS title key 派生 |
| `seeddb.bin`（可选，放在 build 目录） | seed 加密 RomFS 派生 keyY |

> 你放入的密钥目录可以远多于上面这些（例如完整的 keyslot 转储），
> handler 只取它需要的那几个，多余的无害。

## 4. seeddb.bin

seed 加密的 RomFS（`ncchflag` 含 seed）需要一个 seed 数据库才能派生
正确的 keyY。`N3dsHandler` 读取与 `7z.dll` 同目录的 `seeddb.bin`
（GodMode9 的 SeedInfo 格式，32 字节 / 条）。

- 零售机的 seeddb.bin 可由 GodMode9 构建：Lua 脚本里就是用
  `fs.key_dump("seeddb.bin")`（`gm9tools\DumpKeysCTR.lua` 会自动做）。
- 社区整理的（如 `ihaveamac/3DS-rom-tools`）同样可用。
- 开发机的 seeddb.bin 目前 GodMode9 仍无法自动导出——
  见 [EXTRACT_KEYS.md](EXTRACT_KEYS.md) 的说明。

## 5. 密钥来源与分类（重要）

本仓库**不附带任何密钥材料**；Release 包仅附带**已在公开研究材料中广泛流传、
无争议的固定 AES 密钥**（common keydata）。其余密钥从已公开的 3DS 研究材料
获取，或按 `gm9tools\` 从自己的实机提取。请严格区分：

| 类别 | 内容 | Release 是否附带 |
|---|---|---|
| common keydata（所有机器相同） | slot0x2C..0x3F 的 KeyX、common0..5 等 | ✅ 附带（已公开） |
| 已泄露固定 key | slot0x03、0x18、0x1B、0x25 等（3dbrew 已公开） | ◐ 视分发策略 |
| console-unique（OTP / movable.sed 派生） | slot0x04..0x2B 的 KeyX、movable.sed、OTP | ❌ 不附带 |

判断依据见 3dbrew「AES key-init」：Boot9 把 keyslot 分为
**console-unique keydata**（0x04..0x2B 的 keyX，每台机器由 OTP 派生）与
**common keydata**（0x2C..0x3F 的 keyX，所有机器相同）。

> 说明：实际零售机上 console-unique 的 keyX 值在机器间碰巧相同
> （任天堂出厂统一 conunique），这些值 3dbrew 也早已公开。
> 但从分发安全角度，本 fork 仍只把 **common keydata** 随 Release 附带，
> 机器特有条目（movable.sed、OTP、0x04..0x2B）留在本地，不随任何公开分发。

## 6. 用工具自动分类与生成

实机导出与转换请用：

- `gm9tools\DumpKeysCTR.lua` —— 在实机 GodMode9 里运行（HOME → Lua scripts…），
  一次写出**最终可用**的 `keystone\` 结构（松散 `.key` 文件，与 `build\keystone\ctraes_*`
  同构；`aes_keys.txt` 只作为输入被转换掉）：AES 密钥（pub/private 已分好）、
  `keystone\pubkey\`（FIRM 公钥）、`keystone\ctrdevice\<SN>\`（boot9/OTP/CID/ctrindex.ini）
  和 `seeddb.bin`，不需要电脑端再转换。
- `gm9tools\DumpKeysCTR.gm9` —— 旧版 GM9Script 版（备用）：只整理 aeskeydb.bin（K: 盘）
  里的密钥到 `pub\` / `priv\`，FIRM 公钥与设备材料需要电脑端 `aeskeys2ctr --boot9` 补齐。
- `gm9tools\aeskeys2ctr.bat`（无需 Python，用系统自带 PowerShell）
  或等价的 `gm9tools\aeskeys2ctr.py` —— 在电脑上把 GodMode9 的
  `aes_keys.txt` / `aeskeydb.bin` / 导出的 `slot0x*.bin`
  转换成 `keystone\ctraes_retail\` 与 `keystone\ctraes_dev\` 文本格式，
  并自动分类；两者参数与输出一致。把生成的整个 `keystone\` 目录
  拷到 `7z.dll` 同目录即可（或在 `keystone.ini` / 「选项 → 密钥库（Keystone）」里指向别处）。

详见 [EXTRACT_KEYS.md](EXTRACT_KEYS.md)。

## 7. FIRM 公钥目录（`keystone\pubkey`）

`.firm` 镜像的 RSA-2048 签名校验（属性页里的 `FIRM Signature`：Valid / Sighax /
Corrupt-missing）需要**任天堂的 FIRM 公钥**——这是**公开的公钥**，不是 AES 密钥，
和 ROM 解密用的密钥是两回事。

目录由 `keystone.ini` 的 `FirmPubKeyDir=` 指定（默认 `keystone\pubkey`），
而**目录内部**由一份独立的 `pubkey.ini` 管理（`[FirmPubKey]` 段）：

```
<7z.dll 所在目录>\
   keystone\pubkey\
      pubkey.ini                目录自己的配置
      retail_firm_pubkey.bin    256B 大端 modulus（boot9 keyslot1 NAND-FIRM @0xB1E0）
      dev_firm_pubkey.bin       256B 大端 modulus（boot9 keyslot1 NAND-FIRM @0xC4E0）
```

`pubkey.ini` 支持两种给法，Hex 优先于 File：

```ini
[FirmPubKey]
RetailFirmPubKeyHex=            ; 512 个十六进制字符（256 字节 modulus），优先级最高
DevFirmPubKeyHex=
RetailFirmPubKeyFile=retail_firm_pubkey.bin
DevFirmPubKeyFile=dev_firm_pubkey.bin
```

加载顺序（任一成功即停止）：

1. `keystone.ini` 的 `RetailFirmPubKeyHex=` / `DevFirmPubKeyHex=`；
2. `keystone.ini` 的 `RetailFirmPubKeyFile=` / `DevFirmPubKeyFile=`；
3. `FirmPubKeyDir` 下 `pubkey.ini` 里的 Hex 键 → File 键；
4. `keystone.ini` 的 `FirmBoot9Path=`（显式给一份 64KB boot9.bin 全路径）；
5. 扫描 `DeviceDataDir` 各设备子目录的 `ctrindex.ini`，用其中的 `boot9=` 定位 boot9.bin；
6. 全部失败 → **不校验签名**，属性页显示 `Not verified (no public key loaded)`（不误判、不影响段挂载）。

> Release 包内 `keystone\pubkey\` 已附带 `pubkey.ini` 与两份公开 modulus；
> 该目录**不得**放 `boot9.bin`——只要 modulus 就够了。
- 也可以自己生成这两个文件（无需手抄 hex）：
  - 实机：`gm9tools\DumpKeysCTR.lua` 会从 boot9 的 `0xB1E0` / `0xC4E0` 各取 256 字节，
    在 `sd:/gm9/out/7zctr-keys/keystone/pubkey/` 下写出两个 modulus + `pubkey.ini`
    （旧版 `DumpKeysCTR.gm9` 写到同名结构，但实机上不可靠）；
  - 电脑端：`gm9tools\aeskeys2ctr.py <input> --boot9 boot9.bin` 生成同样的三个文件。

> 校验结果（type=3 记录）也会并入 `keystone\cache\keystone.cache`，点「重置缓存」可清空重算。
