# 第三方组件与来源清单（THIRD_PARTY.md）

本仓库是 **7-Zip 26.04 的二次开发分支**。除下列说明的部分外，其余源码来自 7-Zip 官方仓库。
本文件记录每一处外部来源、许可与使用方式，便于分发时履行义务。

> 结论先说：**仓库不含任何 3DS AES 密钥、机器唯一材料（boot9 / OTP / NAND CID / movable.sed）
> 或游戏 ROM**；NAND 设备档案与 `*.key` 由 `.gitignore` 挡住。

---

## 1. 代码

| 来源 | 版本/位置 | 许可 | 我们怎么用 |
|---|---|---|---|
| **7-Zip**（Igor Pavlov） | 26.04，本仓库的绝大部分（`C/`、`CPP/`、`Asm/`、`DOC/`） | **LGPL-2.1**，另含 **unRAR license restriction**（见 `DOC/License.txt`、`DOC/unRarLicense.txt`） | 基础程序；我们新增/修改的文件见第 4 节。分发时保留原作者版权与许可文本 |
| **本项目新增代码** | `CPP/7zip/Archive/N3dsHandler.cpp`、`CPP/7zip/UI/FileManager/KeystonePage*`、`C/Util/7zipInstall|7zipUninstall` 的品牌化改动等 | LGPL-2.1（与上游一致） | 由本项目实现 |

### 仅作「格式/能力参考」，未复制代码

| 项目 | 许可 | 用途 |
|---|---|---|
| [d0k3/GodMode9](https://github.com/d0k3/GodMode9) | GPL-3.0 | 3DS 容器挂载/解包**能力**与结构布局的参考；`N3dsHandler.cpp` 为按 3dbrew 格式文档的独立实现，未引入其源码 |
| [3DSGuy/Project_CTR (ctrtool)](https://github.com/3DSGuy/Project_CTR) | MIT | 属性对话框里技术字段的**命名与含义**参考 |
| [toiry921/CupTheCnt](https://github.com/toiry921/CupTheCnt) | 无许可证 | **仅** Contents.cnt 布局的格式参考（且我们实测修正了其 `+0x800` 为 `+0xC00`） |

> 说明：GPL-3.0 只约束「复制/衍生其代码」。本项目未包含 GodMode9 源码，因此新增代码按
> 7-Zip 的 LGPL-2.1 分发。若将来引入其代码，必须整体改为 GPL-3.0 兼容。

---

## 2. 数据/资源

| 资源 | 许可 | 说明 |
|---|---|---|
| `Lang/`（93 个语言文件） | 随 7-Zip 以 LGPL-2.1 分发，版权归 Igor Pavlov 与**各语种译者** | 基于官方语言包，仅追加了改名串与 `15000–15011` 自定义条目；**文件头译者署名保留** |
| `CPP/7zip/Archive/Icons/*.ico` | 基于 [redbooth/free-file-icons](https://github.com/redbooth/free-file-icons)（MIT）模板改造 | 16 种 3DS 图标为新增，另有 30 个官方图标被重新绘制为多尺寸 |
| `seeddb.bin` | 第三方数据（社区整理，如 ihaveamac/3DS-rom-tools，MIT） | **不入库**；仅由用户自行放置 |
| 测试样本（`.cia` / `.3ds` / `nand.bin`） | 版权归各自权利人 | **不入库**、不随 Release 分发，仅用于本地验证 |

---

## 3. 工具脚本

| 文件 | 说明 |
|---|---|
| `gm9tools/DumpKeysCTR.lua` | 本项目编写的 GodMode9 Lua 脚本（需 GM9 v2.2.0+，实机运行） |
| `gm9tools/aeskeys2ctr.py` / `.bat` | 本项目编写：把 GodMode9 导出转成 `keystone/ctraes_*` 文本格式 |
| `scripts/make_fixtures.ps1` | 本项目编写：CI 用的**合成**容器夹具（不含任何真实数据） |

---

## 4. 相对上游的改动清单

见 [docs/BUILD.md](docs/BUILD.md#相对官方-7-zip-2604-的改动清单)（新增 128 个文件、修改 82 个、无删除）。
按 LGPL-2.1 要求，本仓库以**源码形式**完整提供这些修改。

---

## 5. 分发注意

1. 二进制分发（`Release/*.zip|exe`）必须同时提供**对应源码**（本仓库 + `src.zip`）。
2. 保留 `License.txt`、`DOC/License.txt`、`DOC/unRarLicense.txt` 与 `Lang/` 的译者署名。
3. 不得把用户实机导出的密钥、`keystone/ctrdevice/` 或 `keystone/cache/keystone.cache`
   打进任何公开包。
4. 图标再分发需保留 free-file-icons 的 MIT 声明（见本文件第 2 节）。
