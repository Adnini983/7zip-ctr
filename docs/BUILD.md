# 构建说明（docs/BUILD.md）

从源码编译 7-Zip CTR（自编译 7-Zip 26.04 + `N3dsHandler`）。

## 环境

- Windows x64
- **Visual Studio 2022 Build Tools**（含 MSVC x64 工具集）
- 7-Zip 26.04 源码树（本 fork：`src\7zip-26.04\`）

## 源码位置

```
src\7zip-26.04\
   CPP\7zip\Archive\N3dsHandler.cpp   # 3DS handler（唯一新增/改动文件）
```

`N3dsHandler.cpp` 已通过 `REGISTER_ARC_I_NO_SIG("3DS", "3ds cci 3dz csu ncch cxi cfa app cia firm cnt bin romfs exefs tmd", …)`
注册为 7-Zip 内置 handler，随 `7z.dll` 一起编译（Fm 版则静态内嵌同一份 handler）。

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

## 交付目录

构建成功后把下列文件放一起（7z.dll 与密钥同目录）：

```
build\
   7z.exe  7zFM.exe  7z.dll  7zG.exe  7z.sfx  …
   Lang\              多语言（zh-cn/zh-tw 等）
   3dskey\  3dskey_dev\   seeddb.bin
```

`Lang\` 直接取自仓库根目录（基于 7-Zip 官方语言包，已并入本项目的改名与
“Adnini983 AI 创作”署名串）；`3dskey` / `seeddb` 见
[docs/KEYS.md](KEYS.md) 与 [docs/EXTRACT_KEYS.md](EXTRACT_KEYS.md)。

## 自测

构建后用 7z 命令行验证：

```bat
build\7z.exe l "SystemUpdater_CTR-0_35_0-EU.csu"
```

应看到 `.code`、RomFS、`contents\Contents.cnt` 及按 title id 命名的
多个 `.cia` 子项。再对任一 `.cia` 双击 / `7z l`，确认能解密
`Content_0.cxi`。
