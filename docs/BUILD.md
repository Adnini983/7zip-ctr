# 构建说明（docs/BUILD.md）

从源码编译 7-Zip CTR（自编译 7-Zip 26.04 + `N3dsHandler`）。

## 环境

- Windows x64
- **Visual Studio 2022 Build Tools**（含 MSVC x64 工具集）
- 7-Zip 26.04 源码树（本 fork：`src\7zip-26.04\`）

## 源码位置

**克隆下来的仓库根目录本身就是 7-Zip 26.04 源码树**（不是 `src\7zip-26.04\`——那是旧的
本地快照，已废弃，里面没有 NAND/FIRM/选项页等 CTR02 功能）。所有编译命令都在仓库根
目录下执行。

`N3dsHandler.cpp` 已通过 `REGISTER_ARC_I_NO_SIG("3DS", "3ds cci 3dz csu ncch cxi cfa app cia firm cnt bin romfs exefs tmd", …)`
注册为 7-Zip 内置 handler，随 `7z.dll` 一起编译（Fm 版则静态内嵌同一份 handler）。

### 相对官方 7-Zip 26.04 的改动清单

以官方源码为基准：**新增 128 个文件、修改 82 个、无删除**。按功能分组：

| 分组 | 文件 |
|---|---|
| 3DS handler | `CPP\7zip\Archive\N3dsHandler.cpp`（新增，本项目核心） |
| 选项页「密钥库」 | `CPP\7zip\UI\FileManager\KeystonePage{.h,.cpp,.rc}`、`KeystonePage2.rc`、`KeystonePageRes.h`（新增 5 个）；`OptionsDialog.cpp`、`resource.rc`、`FM.mak` 挂载 |
| 注册与图标 | `CPP\7zip\Bundles\Format7zF\{Arc.mak,resource.rc}`、`CPP\7zip\Archive\ArchiveExports.cpp`、`Icons\*.ico`（新增 41 个 3DS 图标，另重制 30 个官方图标） |
| 宿主侧通路 | `UI\Common\OpenArchive.cpp`（`Z7CTR_SRC_PATH`/`Z7CTR_GUI`）、`UI\FileManager\PanelItemOpen.cpp`、`UI\Agent\ArchiveFolderOpen.cpp`、`UI\Console\Main.cpp`（`-unit/-type/-slot`）、`UI\Client7z\Client7z.cpp`、`Common\FileStreams.{h,cpp}` |
| 品牌与版本 | `C\7zVersion.h`、`C\7zVersion.rc`、各 `resource.rc` / `*.manifest` / `AboutDialog.*` / `App.cpp` / `FM.cpp` / `Panel*.cpp` 等改名的 30+ 个文件 |
| 安装器 / 卸载器 | `C\Util\7zipInstall\{7zipInstall.c,resource.rc,manifest,makefile}`、`C\Util\7zipUninstall\{7zipUninstall.c,resource.rc}` |
| 构建 | `CPP\Build.mak`（公共 CFLAGS 追加 `/Y-`，绕开 CI 的 C2855）、`Bundles\Format7zF\build_dll.bat`、`Bundles\Fm\build_fm.bat` |
| 语言包 | `Lang\`（93 个文件：官方 92 语种 + `en.ttt` 模板，已并入改名与署名串） |
| 配置模板 | `keystone.ini`、`pubkey.ini` |
| 文档 / 工具 / CI | `README.md`、`docs\{BUILD,USAGE,KEYS,EXTRACT_KEYS,NAND}.md`、`gm9tools\*`、`.github\workflows\build.yml`、`.gitignore`、`LICENSE.md` |

## 编译步骤

1. 打开 "x64 Native Tools Command Prompt for VS 2022"（或加载 `vcvars64.bat`）。
2. 逐个进入 7-Zip 的工程目录并 nmake（先删除 `x64\resource.res` 以强制重编
   改过版本号/名称的资源，否则 VERSIONINFO 不会更新）：

```bat
call "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
cd CPP\7zip\Bundles\Format7zF   & del /Q x64\resource.res 2>nul & nmake /F makefile   :: -> x64\7z.dll
cd ..\Fm                        & del /Q x64\resource.res 2>nul & nmake /F makefile   :: -> x64\7zFM.exe
cd ..\..\..\UI\Console          & del /Q x64\resource.res 2>nul & nmake /F makefile   :: -> x64\7z.exe
cd ..\GUI                       & del /Q x64\resource.res 2>nul & nmake /F makefile   :: -> x64\7zG.exe
cd ..\Explorer                  & del /Q x64\resource.res 2>nul & nmake /F makefile   :: -> x64\7-zip.dll
```

产物（均在各自的 `x64\` 子目录）：

```
CPP\7zip\Bundles\Format7zF\x64\7z.dll
CPP\7zip\Bundles\Fm\x64\7zFM.exe
CPP\7zip\UI\Console\x64\7z.exe
CPP\7zip\UI\GUI\x64\7zG.exe
CPP\7zip\UI\Explorer\x64\7-zip.dll
```

> 开发中可用仓库外脚本一键构建：先杀残留 7z / 7zFM 进程 → 加载
> vcvars64 → 依次 nmake → 把新产物复制到 `build\`。

## GitHub Actions 云编译

仓库自带 `.github/workflows/build.yml`，push 到 `main` / `master`、提 PR 或
`workflow_dispatch` 手动触发时，在 **windows-2022** 上用 MSVC（vswhere 定位
vcvars64）依次编译：

```
CPP\7zip\Bundles\Format7zF  -> x64\7z.dll     （external codecs，动态加载）
CPP\7zip\Bundles\Fm         -> x64\7zFM.exe  （N3DS handler 静态内嵌）
CPP\7zip\UI\Console         -> x64\7z.exe      （命令行，依赖同目录 7z.dll）
```

三个产物收集进 `out\` 并做存在性校验后，连同仓库自带的 `Lang\` 语言包一起
作为 build artifact 上传（CI 产物开箱即本地化）。
`7zG.exe`（GUI）与 `7-zip.dll`（Explorer 外壳扩展）不在 CI 内编译，需要时按上面
本地步骤补编。CI 产物不含密钥与 `seeddb.bin`（这些按“交付目录”一节另行放置）。

> 云编译前 `build.yml` 会先 `set CL=` 清空 runner 可能注入的命令行标志；
> `CPP\Build.mak` 对 MSVC 统一追加 `/Y-` 关闭预编译头（PCH），各源文件独立编译，
> 从根本上绕开 `error C2855: command-line option '/source-charset' inconsistent
> with precompiled header`（该错误由 `-Yc` 建 PCH 与 `-Yu` 消费两侧字符集不一致
> 触发，与本机环境是否注入 charset 无关）。

## 交付目录

构建成功后把下列文件放一起（7z.dll 与密钥同目录）：

```
build\
   7z.exe  7zFM.exe  7z.dll  7zG.exe  7-zip.dll  7-zip32.dll  7z.sfx  7zCon.sfx
   Uninstall.exe      独立卸载器（C\Util\7zipUninstall 产物，约 115200B）
   readme.txt         从仓库根 readme.txt 复制
   Lang\              多语言（92 个语种）
   keystone\ctraes_retail\  keystone\ctraes_dev\   seeddb.bin
   keystone\pubkey\   （可选）pubkey.ini + retail/dev_firm_pubkey.bin，FIRM 验签用
   keystone.ini       （仓库根自带模板，随交付目录一起复制；键名
                       RetailCTRAESKeyDir=/DevCTRAESKeyDir= 等，留空=默认）
```

> **打包易错点**：`Uninstall.exe` 必须是 `C\Util\7zipUninstall` 的产物（约 115200B，
> 字符串含 `Uninstall 7-Zip CTR`），**不要**把 `7zipInstall.exe`（安装 stub，
> 约 146432B）改名成 `Uninstall.exe`——那会把"卸载"变成启动安装向导。

`Lang\` 直接取自仓库根目录（基于 7-Zip 官方语言包，已并入本项目的改名与
“Adnini983 AI 创作”署名串）；`keystone` / `seeddb` 见
[docs/KEYS.md](KEYS.md) 与 [docs/EXTRACT_KEYS.md](EXTRACT_KEYS.md)。

## 自测

构建后用 7z 命令行验证：

```bat
build\7z.exe l "SystemUpdater_CTR-0_35_0-EU.csu"
```

应看到 `.code`、RomFS、`contents\Contents.cnt` 及按 title id 命名的
多个 `.cia` 子项。再对任一 `.cia` 双击 / `7z l`，确认能解密
`Content_0.cxi`。

NAND 回归（手边有实机备份时；验收只看产物明文，不看退出码）：

```bat
build\7z.exe l "nand.bin"
rem  应列出 TWL / AGB_Save / Firm0 / Firm1 / CTRNAND 共 5 项
build\7z.exe e "nand.bin" "Partition_2_Firm0.bin" -otest -y
rem  抽出的 Firm0 头 4 字节必须是 "FIRM"；TWL 抽出的 0x1FE 必须是 55 AA
```
