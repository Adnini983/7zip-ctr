# 实机提取 AES 密钥（docs/EXTRACT_KEYS.md）

本 fork 不打包任何密钥。下面是**从你自己的 3DS / 开发机**提取密钥、
并转成 `3dskey\` / `3dskey_dev\` 文本格式的完整流程。

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

## 途径 B：`DumpKeysCTR.gm9`（分好可上传 / 不可上传）

1. 准备 `aeskeydb.bin`：
   - 可用 GodMode9 仓库自带的 `data/aeskeydb.bin`（只含可公开密钥）；
   - 或你自己构建的更全密钥库。
   - 把 `aeskeydb.bin` 放到 SD 卡根目录。
2. 把 `gm9tools\DumpKeysCTR.gm9` 拷到 `sd:/gm9/scripts/`。
3. GodMode9 启动后自动把 aeskeydb.bin 挂载为 **[K:] AESKEYDB** 盘。
4. Scripts → 运行 `DumpKeysCTR.gm9`，结果在
   `sd:/gm9out/7zctr-keys/`：
   - `pub\`  —— 可上传 GitHub
   - `priv\` —— 机器特有（OTP / movable.sed 派生），**勿上传**

## 电脑端转换：`aeskeys2ctr.py`

把 GodMode9 的输出统一转成 handler 的 `3dskey\` / `3dskey_dev\` 文本格式，
并再次按可上传 / 不可上传分类。

```bash
# 输入可以是：aes_keys.txt / aeskeydb.bin / 一目录的 slot0x*.bin
python gm9tools\aeskeys2ctr.py <aes_keys.txt> --out <输出目录>

# 开发机 dump 用 --devkit（pub 全部进 3dskey_dev\）
python gm9tools\aeskeys2ctr.py <devkit_aes_keys.txt> --out <输出目录> --devkit

# 可选：你确认所有 keyX 与公开值一致时可全公开（--all-pub）
python gm9tools\aeskeys2ctr.py <aes_keys.txt> --out <输出目录> --all-pub
```

输出：

```
<输出目录>\
   3dskey\          零售机可上传 -> 复制到 7z.dll 同目录
   3dskey_dev\      开发机可上传 -> 复制到 7z.dll 同目录
   3dskey_private\  机器特有（勿上传 / 勿分发）
```

## 最终放置

把转换结果复制到 `7z.dll` 同目录：

```
build\7z.dll
build\3dskey\*.key
build\3dskey_dev\*.key
build\seeddb.bin       （途径 A 生成的 seeddb，可选）
```

> 7z.dll 换位置时，`3dskey` / `3dskey_dev` / `seeddb.bin` 要一起搬。

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

**Q：`K:` 盘是空的？**
A：说明 SD 根目录没有 `aeskeydb.bin`，或 GodMode9 版本未自动挂载。
放入 aeskeydb.bin 后重启 GodMode9，在文件浏览器里应看到 `[K:]`。

## 可上传 / 不可上传清单（最终核对）

上传前核对：`3dskey\` 与 `3dskey_dev\` 里**不应出现**下列文件名：

- `slot0x04KeyX` … `slot0x2BKeyX`（console-unique keyX）
- `movable.sed`、`otp.bin` 等派生文件

可以放心上传的：`slot0x03/0x18/0x1B/0x25/0x2C..0x3F` 的 KeyX/KeyY/KeyN、
`common0..5`、`common0N..5N`、nfc 相关等（均为 3dbrew 已公开的固定值）。
