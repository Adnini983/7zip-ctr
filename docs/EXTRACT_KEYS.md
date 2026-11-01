# 实机提取 AES 密钥（docs/EXTRACT_KEYS.md）

本 fork 不打包任何密钥。下面是**从你自己的 3DS / 开发机**提取密钥、
并转成 `keystone\ctraes_retail\` / `keystone\ctraes_dev\` 文本格式的完整流程。

> 只需解密你自己合法拥有的 ROM。请勿把机器特有密钥上传公开仓库。

---

## 前置

- 一台已破解（跑 Luma3DS / GodMode9 payload）的 3DS 或开发机
- GodMode9（`.firm` 放进 `sd:/luma/payloads/`）
- 电脑能读 SD 卡

## 方案总览

有两种互补途径，推荐**都做**：

1. **GodMode9 内置 DumpKeys**（Scripts → DumpKeys）——从固件 / 已加载
   keyslot 生成 `aes_keys.txt` + `seeddb.bin`，覆盖"机器实际能用的密钥"。
2. **`gm9tools\DumpKeysCTR.gm9`**——把我们需要的密钥按
   可上传 / 不可上传分好目录导出。

## 途径 A：GodMode9 内置 DumpKeys（推荐，最全）

1. 启动 3DS，按住组合键进 GodMode9（或用 `luma/payloads`）。
2. 在 GodMode9 里按 HOME → **Scripts** → 选 **DumpKeys**。
3. 脚本运行后，会在 `sd:/gm9out/` 下生成：
   - `aes_keys.txt`（Citra 格式：`slot0x2CKeyX=...` 每行）
   - `seeddb.bin`
4. 把这两个文件拷回电脑。

## 途径 B：`DumpKeysCTR.lua`（推荐：一次产出最终目录，无需电脑端转换）

GodMode9 内置 **Lua 5.4**，`gm9tools\DumpKeysCTR.lua` 用它把「AES 密钥 + FIRM 公钥 +
NAND 设备档案」一次性写成 handler 直接能吃的 `keystone\` 结构：

1. **不需要准备任何密钥文件。** 公共 AES 密钥（slot0x03/0x18/0x1B/0x25/0x2C..0x3F 与
   common 系列）在所有机器上都相同，已经由 `gm9tools/embed_keys.py` 内嵌进
   `DumpKeysCTR.lua`（208 条：114 零售 + 94 开发）。脚本单独一个文件就能产出完整包。
   如果 SD 上恰好有别的密钥库，脚本会**额外合并**（不会覆盖内置值）：
   `0:/gm9/out/aes_keys.txt` → `0:/aeskeydb.bin` → `[K:] AESKEYDB`。
   > 刷新内置密钥：`python gm9tools\embed_keys.py <keystone 目录>`（目录里要有
   > `ctraes_retail\` 和/或 `ctraes_dev\`）。

2. 把 `gm9tools\DumpKeysCTR.lua` 放进 `sd:/gm9/luascripts/`，
   用 **HOME → Lua scripts...** 运行（或在文件浏览器里选中它 → `Execute Lua script`）。
3. 结果在 **`sd:/gm9/out/7zctr-keys/`**（就是 `GM9OUT`，GodMode9 自己的输出目录）：

**输出是松散的 `.key` 文件**（每个密钥一个文本文件，`KeyName=32位HEX`），与
`build\keystone\ctraes_retail\` / `ctraes_dev\` 完全同构 —— handler 只认这种结构，
不读 `aes_keys.txt`。`aes_keys.txt` 只是 GodMode9 内置 DumpKeys 的中间产物：
脚本读它、转成 `.key`，**不会**把它带进输出目录。

```
7zctr-keys/
  keystone/
    ctraes_retail/*.key      零售机 AES 密钥（可上传）
    ctraes_dev/*.key         开发机 AES 密钥（可上传）
    pubkey/
      retail_firm_pubkey.bin FIRM 公钥（boot9 @0xB1E0，256B 大端）
      dev_firm_pubkey.bin    FIRM 公钥（boot9 @0xC4E0）
      pubkey.ini             上面两个文件的配置
    ctrdevice/<序列号>_<单位>/
      boot9.bin otp.mem otp_dec.mem nand_cid.mem ctrindex.ini
  keystone_private/*.key      console-unique 的安全副本（**勿上传**）
  seeddb.bin
  README.txt
  dump.log                    本次运行的全部日志
```

说明：
- 设备目录名带单位后缀，零售机 `<序列号>_retail`、开发机 `<序列号>_dev`（上面的例子里是
  `<serial>_retail`）。
- AES 密钥全部写进**本机单位**对应的目录（零售→`ctraes_retail`，开发→`ctraes_dev`），
  因为 handler 只按 profile 的单位找 keys；console-unique 的那部分另在
  `keystone_private/` 留一份副本，方便你区分"哪些不能传"。
- `seeddb.bin` 取不到时（例如 dev 单元上 GodMode9 无法构建）**只记录并跳过**，
  不影响 NAND/CIA；`dump.log` 里会写明原因。

4. 把 `keystone\`、`keystone_private\`、`seeddb.bin` 直接拷到 `7z.dll` 同目录（合并）即可，
   **不需要任何电脑端转换**：序列号、dev/retail、Old/New 都由脚本从 GodMode9 读取并写进
   `ctrindex.ini`。

> 旧版 `gm9tools\DumpKeysCTR.gm9` 保留作备用（GM9Script 无法切片文件、不能主动申请写权限，
> 在实机上会报 "Cannot open destination file"），现在推荐 Lua 版。

## 电脑端转换（可选）：`aeskeys2ctr`

若你只拿到了 `aes_keys.txt` / `aeskeydb.bin` / `slot0x*.bin`（例如用了旧版 .gm9），用这两个工具把 GodMode9 的输出统一转成 handler 的 `keystone\ctraes_retail\` /
`keystone\ctraes_dev\` 文本格式，并再次按可上传 / 不可上传分类。提供两个等价工具，**二选一**：

- `gm9tools\aeskeys2ctr.bat` —— **无需 Python**，调用系统自带 PowerShell，
  适合没有 Python 环境的 Windows；
- `gm9tools\aeskeys2ctr.py` —— Python 版，逻辑与 BAT 完全一致。

输入可以是：`aes_keys.txt` / `aeskeydb.bin` / 一目录的 `slot0x*.bin`。

若手边有 `boot9.bin`（Lua 版会写进 `keystone\ctrdevice\<SN>\`，旧版 .gm9 放在 `priv\`），加上
`--boot9 <boot9.bin>` 即可同时生成 `keystone\pubkey\` 的三个文件（不带参数时
也会自动在输入目录里找 `boot9.bin`）。这组是**公开公钥**，可随源码/发布包分发。

```bat
rem --- BAT 版（无需 Python）---
gm9tools\aeskeys2ctr.bat <aes_keys.txt> --out <输出目录>

rem 开发机 dump 用 --devkit（pub 全部进 keystone\ctraes_dev\）
gm9tools\aeskeys2ctr.bat <devkit_aes_keys.txt> --out <输出目录> --devkit

rem 可选：确认所有 keyX 与公开值一致时全公开（--all-pub）
gm9tools\aeskeys2ctr.bat <aes_keys.txt> --out <输出目录> --all-pub
```

```bash
# --- Python 版（需要 Python 环境）---
python gm9tools\aeskeys2ctr.py <aes_keys.txt> --out <输出目录>
python gm9tools\aeskeys2ctr.py <devkit_aes_keys.txt> --out <输出目录> --devkit
python gm9tools\aeskeys2ctr.py <aes_keys.txt> --out <输出目录> --all-pub
```

两个工具的参数、分类规则、输出布局**完全一致**（含 `--boot9`），可互换：
`--out` / `--all-pub` / `--devkit` / `--boot9` 行为相同，写出的文件逐字节相同。

输出：

```
<输出目录>\
   keystone\
      ctraes_retail\ 零售机可上传 -> 复制到 7z.dll 同目录
      ctraes_dev\     开发机可上传 -> 复制到 7z.dll 同目录
   keystone_private\  机器特有（勿上传 / 勿分发）
```

## 最终放置

把转换结果复制到 `7z.dll` 同目录：

```
build\7z.dll
build\keystone\ctraes_retail\*.key
build\keystone\ctraes_dev\*.key
build\seeddb.bin       （途径 A 生成的 seeddb，可选）
```

> 7z.dll 换位置时，`keystone\ctraes_retail` / `keystone\ctraes_dev` /
> `seeddb.bin` 要一起搬；也可在 `keystone.ini` 或「选项 → 密钥库（Keystone）」里
> 把目录指到固定位置，免去跟随移动。

---

## 常见问题

**Q：我的 Old3DS XL 开发机 aeskeydb.bin 里没有 common0.key？**
A：GodMode9 的 aeskeydb.bin 是**手动放置**的密钥库，不是机器自动生成的。
common key（0x3D）通常在固件常量里，GodMode9 的 `data/aeskeydb.bin`
或 DumpKeys 的 `aes_keys.txt` 会包含。开发机的 common key 用
`common0N..common5N`（dev / New3DS 集）。

**Q：GodMode9 仍无法导出开发机的 seeddb.bin？**
A：seeddb 的"seed 数据库"主要来自零售机 / 社区整理
（如 `ihaveamac/3DS-rom-tools`）。开发机如果 seeddb 缺失，
通常是因为 seed 加密的标题在开发机上以明文 / 不同加密方式提供。
可先用社区零售机 seeddb.bin 覆盖；开发机专属 seed 暂无法用 GodMode9
自动导出，需要从开发机的 `/ro/sys/seeddb.bin` 手动导出（见途径 B 的
`priv\` 目录）。

**Q：movable.sed / OTP 是干嘛的？**
A：它们是 console-unique key 的来源（每台机器不同）。
`DumpKeysCTR.gm9` 会把 `movable.sed` 导出到 `priv\`。**不要上传**。
这些通常不用于解密 ROM（ROM 用的是 common keydata），但保留它们
可解锁 NAND / SD 数据。

> 若要在本工具里直接挂载本机 NAND 备份，需要单独准备 boot9 / OTP / NAND CID
> 组成的设备档案，放在 `keystone\ctrdevice\<SN>\`，清单与字段见
> [NAND.md](NAND.md)；这些材料同样只留本地，不上传、不分发。

**Q：`K:` 盘是空的？**
A：说明 SD 根目录没有 `aeskeydb.bin`，或 GodMode9 版本未自动挂载。
放入 aeskeydb.bin 后重启 GodMode9，在文件浏览器里应看到 `[K:]`。

## 可上传 / 不可上传清单（最终核对）

上传前核对：`keystone\ctraes_retail\` 与 `keystone\ctraes_dev\` 里**不应出现**下列文件名：

- `slot0x04KeyX` … `slot0x2BKeyX`（console-unique keyX）
- `movable.sed`、`otp.bin` 等派生文件

可以放心上传的：`slot0x03/0x18/0x1B/0x25/0x2C..0x3F` 的 KeyX/KeyY/KeyN、
`common0..5`、`common0N..5N`、nfc 相关等（均为 3dbrew 已公开的固定值）。
