# 使用说明（docs/USAGE.md）

7-Zip CTR 是一个自编译的 7-Zip 26.04，内置一个 3DS 容器 handler。
它能像浏览 zip 一样浏览和提取 3DS / New3DS 的加密容器。

## 1. 目录组成

交付目录（`build\`）包含：

```
build\
   7z.exe             命令行
   7zFM.exe           GUI 文件管理器
   7z.dll / 7z32.dll  核心（handler 在 7z.dll）
   7zG.exe / *.sfx
   Lang\             多语言文本（zh-cn/zh-tw/…）
   3dskey\            零售机密钥（从实机提取）
   3dskey_dev\        开发机密钥
   seeddb.bin         可选 seed 数据库
```

> 密钥必须放在 **`7z.dll` 同目录** 的 `3dskey` / `3dskey_dev`。
> 只要 `7z.dll` 换位置，密钥文件夹要跟着放。

## 2. 支持的容器与扩展名

| 扩展名 | 容器 | 展开内容 |
|---|---|---|
| `.3ds` `.cci` `.3dz` | NCSD（游戏卡带镜像） | Partition_0…N / ExeFS / RomFS |
| `.csu` | NCSD（系统更新镜像） | 同上；含 Contents.cnt 展开 |
| `.ncch` `.cxi` `.cfa` `.app` | NCCH | ExeFS（.code/banner/…）/ RomFS |
| `.cia` | CIA（可安装归档） | cert/ticket/tmd/Content_0.cxi/meta |
| `.firm` | FIRM（固件镜像） | 各 processor 的段 |
| `.cnt` | Contents.cnt（CSU 内） | 按 title id 展开的独立 `.cia` |
| `.romfs` `.exefs` `.bin` | 解密后的 RomFS / ExeFS 段 | 直接浏览数据 |

## 3. GUI 用法（7zFM.exe）

1. 双击 `7zFM.exe`。
2. 找到任意 `.3ds` / `.cia` / `.csu` / `.cxi` 文件并**双击**打开。
3. 左侧 / 中间会出现容器的内部结构：
   - `.3ds`：`Partition_0\` → `ExeFS\`（.code 等）+ `RomFS\`（游戏数据）
   - `.cia`：`cert.bin` `ticket.bin` `tmd.bin` `Content_0.cxi` `meta.bin`
   - `.csu`：还会看到 `contents\` 下有按 title id 命名的 `.cia`
4. **双击嵌套容器**（如 `Content_0.cxi`、Contents.cnt 里的 `.cia`）可继续进入并解密。
5. 右键 → **提取**，选目标目录即可把文件解出。

### 查看技术信息（属性）

选中容器后，菜单 **文件 → 属性**（或右键 → 属性）会显示 ctrtool 级明细，
例如：

```
类型      = 3DS
容器      = CIA
Title ID  = C95718FD431D545A
Common Key= 0x0
Ticket ID = 9353C6D4DD73A6D9
Title Key = 30DF2D80ABC591A9AC7A3123B8D3C29F
Content 0 = id=0xC905D5BC size=0x61800
```

对 NCSD / NCCH 还会显示 Media ID、分区数、ExeFS/RomFS 偏移、加密类型等。

## 4. 命令行用法（7z.exe）

```text
# 列出
7z l "game.3ds"
7z l "SystemUpdater_CTR-0_35_0-EU.csu"

# 提取全部
7z x "game.cia" -o"out\"

# 提取单个文件
7z e "game.3ds" "Partition_0/RomFS/data.bin" -o"out\"

# 查看技术信息（-slt 输出属性）
7z l -slt "game.cia"
```

## 5. 常见问题

**Q：打开加密文件时为什么显示"未解密"？**
A：缺少对应密钥。检查 `3dskey`（零售机）或 `3dskey_dev`（开发机）
是否放对了文件、文件名是否如 `slot0x2CKeyX.key`。

**Q：开发机 CSU 打不开 / 解出来是乱码？**
A：确认用 `3dskey_dev\` 的开发机密钥集。handler 会自动用
ExeFS 头试解来区分 dev / retail，但前提是两个密钥集都在。

**Q：Contents.cnt 里没有看到 CIA / 看到 0KB 或 content_xxx？**
A：`.csu` 的 `contents\Contents.cnt` 会被自动展开成
`contents\<titleid>.cia`（16 位补零命名）子项。本版本已修复运行时读取
Contents.cnt 头部越界导致的错误展开——旧版本会把 idx≥128 的条目
误读成 0KB / `content_xxx.cia`，现在与正确解包结果一致（144 项即 144 项）。

**Q：7zFM 打开 CIA 直接闪退 / 卡死？**
A：本版本已修复嵌套 `allFilesMode` 全量提取导致的卡死。
若仍异常，请确认 7z.dll 与 7zFM.exe 版本一致（都来自本 build）。
