# 7-Zip CTR

在 **7-Zip 26.04** 基础上加入对任天堂 3DS / New Nintendo 3DS 容器格式的只读
挂载与解包支持，把 GodMode9 / ctrtool 的解包能力移植为 7-Zip 的一个 archive
handler（`N3dsHandler`）。**代码中不包含任何硬编码密钥**——所有密钥由用户从
自己的实机提取后放入与 `7z.dll` 同目录的 `3dskey\` 与 `3dskey_dev\` 文件夹。

- **版本**：`26.04-CTR01`
- **构建目标**：Windows x64（`7z.dll` / `7z.exe` / `7zFM.exe` / `7zG.exe` / `7-zip.dll`）
- **许可**：见 [许可](#许可) 一节

---

## 特性状态总览

| 状态 | 说明 |
|---|---|
| ✅ 已实现 | 打开并解密下列容器，7zFM / 7z 可浏览、提取 |
| ◐ 部分实现 | 依赖外置密钥；部分加密类型/样本未覆盖 |
| ❌ 未实现 | 未列入本次目标的写入 / 加密导出 / NAND 整卡 |

### ✅ 已实现

- **容器识别与挂载**：`.3ds` `.cci` `.3dz` `.csu` `.ncch` `.cxi` `.cfa`
  `.cia` `.app` `.firm` `.cnt` `.bin` `.romfs` `.exefs`
- **NCSD**（`.3ds` / `.cci` / `.3dz` / `.csu`）：解析分区表，定位各分区 NCCH
- **NCCH**（`.cxi` / `.cfa` / `.ncch`）：展开 ExeFS 与 RomFS
  - ExeFS：`.code` `banner` `icon` `logo` `resources\…`
  - RomFS：完整目录树（含子目录、长文件名 UTF-16BE）
- **CIA**：`cert` `ticket` `tmd` `Content_*.cxi` `meta` 完整展开
  - 从 ticket 用 common key 解密 **title key**
  - 加密 content 用 title key 做 **AES-CBC** 解密读取
- **NCCH 数据区 AES-CTR 解密**：`slot0x2C` / `slot0x18` / `0x1B` / `0x25`
  + keyscrambler（3DS 硬件密钥生成器，大端字节序）
- **Seed 加密 RomFS**：读取 `seeddb.bin`（SeedInfo 格式）派生 seed keyY
- **Contents.cnt 展开**：正确读取 256 项 CupList，按 16 位补零 title id
  展开为独立 `.cia`（修复了运行时头部越界导致的错误展开）
- **密钥外置**（零硬编码）：
  - `3dskey\`（零售机）
  - `3dskey_dev\`（开发机）
  - 每个文件为文本格式：`KeyName=<32 位 hex>`
- **dev / retail 自动判定**：对 NCCH 数据区用候选 keyX 试解 ExeFS 头，
  能解出者选中并记住单元类型
- **开发机 CTR SystemUpdater `.csu` 全链解密**：ExeFS + RomFS 全部展开

### ◐ 部分实现 / 已知限制

- **密钥必须外置**：程序启动时若缺少 `3dskey\` / `3dskey_dev\` 或对应密钥，
  加密内容无法解密（这是设计，见 [密钥](docs/KEYS.md)）。
- 个别异常 header 的 ROM 可能无法解密，属样本本身问题。
- GM9 密钥提取脚本（`gm9tools\DumpKeysCTR.gm9`）需在实机上运行，无实机无法在此验证。

### ❌ 未实现

- 容器写入 / 重新加密 / 导出。
- NAND / eMMC 整卡镜像挂载。

---

## 快速使用

1. 从你的实机提取密钥（见 [docs/EXTRACT_KEYS.md](docs/EXTRACT_KEYS.md)），
   放入 `7z.dll` 同目录的 `3dskey\` / `3dskey_dev\`。
2. 将 `seeddb.bin`（`3ds\seeddb.bin`，零售机）放在与 `7z.dll` 同目录。
3. 用 `7zFM.exe` 或 `7z.exe` 打开 `.cia` / `.csu` / `.3ds` / `.cci` 等文件。

详细说明见 [docs/USAGE.md](docs/USAGE.md)、[docs/KEYS.md](docs/KEYS.md)、
[docs/EXTRACT_KEYS.md](docs/EXTRACT_KEYS.md)、[docs/BUILD.md](docs/BUILD.md)。

---

## 仓库结构与贡献

```
.
├── CPP/7zip/Archive/N3dsHandler.cpp   # 3DS 容器 archive handler（本项目核心）
├── docs/                              # 使用、密钥、提取、构建文档
├── gm9tools/                          # GM9 实机密钥提取脚本与转换工具
├── .github/workflows/build.yml        # GitHub Actions 云编译
└── ...
```

---

## 参考仓库与资源

本项目移植与参考了以下公开仓库的能力、格式规范与资源。其中**代码均为本项目
独立实现**（按公开的 3DS 格式文档编写），仅在能力范围与格式规范上参考下列项目：

| 仓库 | 用途 | 许可 |
|---|---|---|
| [d0k3/GodMode9](https://github.com/d0k3/GodMode9) | 3DS 容器挂载/解密的**能力参考**（格式规范，代码独立实现） | GPL-3.0 |
| [3DSGuy/Project_CTR (ctrtool)](https://github.com/3DSGuy/Project_CTR) | 文件属性对话框的技术信息字段参考 | MIT |
| [ihaveamac/3DS-rom-tools](https://github.com/ihaveamac/3DS-rom-tools) | `seeddb.bin` 的获取与格式来源 | MIT |
| [redbooth/free-file-icons](https://github.com/redbooth/free-file-icons) | 图标模板资源（已并入 `Archive\Icons`） | MIT |
| [toiry921/CupTheCnt](https://github.com/toiry921/CupTheCnt) | Contents.cnt 格式的**参考**（该仓库无开源协议，仅作格式参考，未引用其代码） | 无协议 |

**密钥合规说明**：本仓库**可上传的公共密钥（common keydata 等）随源码分发**
（见 `3dskey\` 中标记为可上传的部分）；**不可上传的密钥**（各机器唯一的
`movable.sed`、OTP、console-unique 等）**不随仓库分发**，必须由用户从自己的
实机提取（见 [docs/EXTRACT_KEYS.md](docs/EXTRACT_KEYS.md) 与
[gm9tools](gm9tools/)）。

---

## 许可

本项目基于以下开源项目：

### 7-Zip

- 原始项目：
  https://github.com/ip7z/7zip
- 作者：
  Igor Pavlov
- 许可证：
  GNU LGPL-2.1（附带 unRAR license restriction）

本项目主体代码继承 7-Zip 的许可证要求。

### 本项目新增代码

`CPP/7zip/Archive/N3dsHandler.cpp` 等由本项目新增或修改的代码：

- 许可证：GNU LGPL-2.1
- 版权所有：
  7-Zip 原作者 Igor Pavlov 与本项目贡献者

### 其他资源

- 图标资源：
  基于 `redbooth/free-file-icons` 的 MIT 许可资源修改。
- 其他第三方参考项目：
  请见“参考仓库与资源”章节。

完整许可证文本见仓库根目录 `LICENSE.md` 以及 7-Zip 原始源码中的 `DOC/License.txt`。

## 原始项目来源

本项目基于官方 7-Zip 源码修改而来。

- 原始项目：7-Zip
- 原作者：Igor Pavlov
- 官方网站：https://www.7-zip.org/
- 原始 GitHub 仓库：https://github.com/ip7z/7zip

本仓库并非 7-Zip 官方项目，而是基于 7-Zip 源码进行二次开发的个人修改版本。

---

## 致谢

- **代码与文档生成辅助**：部分代码、文档、图标设计和构建脚本由 AI 工具（豆包 / Doubao）辅助生成。
- **用户贡献**：功能需求、测试环境、实机验证以及项目方向由用户提供。
- 感谢 [Igor Pavlov](https://www.7-zip.org/) 与 7-Zip 社区、[GodMode9 项目](https://github.com/d0k3/GodMode9)、
  [ctrtool](https://github.com/3DSGuy/Project_CTR)、[3DS-rom-tools](https://github.com/ihaveamac/3DS-rom-tools)、
  [free-file-icons](https://github.com/redbooth/free-file-icons) 等开源项目。
