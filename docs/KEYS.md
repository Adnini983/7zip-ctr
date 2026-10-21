# 密钥外置机制（docs/KEYS.md）

7-Zip CTR 的 `N3dsHandler` **不硬编码任何 AES 密钥**。
它从 `7z.dll` 同目录下的两个文件夹按名加载文本格式密钥。

## 1. 目录与文件格式

```
<7z.dll 所在目录>\
   3dskey\           零售机密钥
   3dskey_dev\       开发机密钥
```

每个密钥一个文件，纯文本，一行：

```
KeyName=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX   # 32 位十六进制（16 字节）
```

示例 `3dskey\slot0x2CKeyX.key`：

```
slot0x2CKeyX=510207515507CBB18E243DCB85E23A1D
```

文件名大小写不敏感（handler 会归一化为小写字母数字）。
例如 `slot0x2CKeyX.key`、`slot0x2ckeyx.key`、`SLOT0X2CKEYX.key` 均视为同一个。

## 2. handler 实际读取哪些密钥

| 密钥文件 | 用途 |
|---|---|
| `slot0x2CKeyX.key` | NCCH 原始加密（ncchflag=0），`3dskey` + `3dskey_dev` 各一份 |
| `slot0x%02XKeyX.key` | 其他 NCCH crypto（如 0x18 / 0x1B / 0x25，New3DS 7x/Secure3/4） |
| `common0..common5` | 零售机 common key（ticket 解密 title key） |
| `common0N..common5N` | 开发机 / New3DS common key（dev 用） |
| `slot0x3DKeyX.key` | 零售机 Old3DS title key 派生 |
| `seeddb.bin`（可选，放在 build 目录） | seed 加密 RomFS 派生 keyY |

> 你放入的 `3dskey` 可以远多于上面这些（例如完整的 keyslot 转储），
> handler 只取它需要的那几个，多余的无害。

## 3. seeddb.bin

seed 加密的 RomFS（`ncchflag` 含 seed）需要一个 seed 数据库才能派生
正确的 keyY。`N3dsHandler` 读取与 `7z.dll` 同目录的 `seeddb.bin`
（GodMode9 的 SeedInfo 格式，32 字节 / 条）。

- 零售机的 seeddb.bin 可由 GodMode9 DumpKeys 生成。
- 社区整理的（如 `ihaveamac/3DS-rom-tools`）同样可用。
- 开发机的 seeddb.bin 目前 GodMode9 仍无法自动导出——
  见 [EXTRACT_KEYS.md](EXTRACT_KEYS.md) 的说明。

## 4. 密钥来源与分类（重要）

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

## 5. 用工具自动分类与生成

实机导出与转换请用：

- `gm9tools\DumpKeysCTR.gm9` —— 在实机 GodMode9 运行，
  把 aeskeydb.bin（K: 盘）里的密钥按可上传 / 不可上传分成
  `pub\` 与 `priv\` 两个目录。
- `gm9tools\aeskeys2ctr.bat`（无需 Python，用系统自带 PowerShell）
  或等价的 `gm9tools\aeskeys2ctr.py` —— 在电脑上把 GodMode9 的
  `aes_keys.txt` / `aeskeydb.bin` / 导出的 `slot0x*.bin`
  转换成 `3dskey\` 与 `3dskey_dev\` 文本格式，并自动分类；两者参数与输出一致。

详见 [EXTRACT_KEYS.md](EXTRACT_KEYS.md)。
