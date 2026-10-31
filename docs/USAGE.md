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
   keystone\
      ctraes_retail\ 零售机密钥（从实机提取）
      ctraes_dev\     开发机密钥
      ctrdevice\<SN>\  （可选）本机 NAND 设备档案，仅本地、勿分发，见 NAND.md
      pubkey\         （可选）FIRM 公钥目录：pubkey.ini + retail/dev_firm_pubkey.bin
                      （公开公钥，非 AES 密钥；用于 .firm 签名三态，见 KEYS.md 第 7 节）
      cache\keystone.cache （程序自动生成）统一二进制缓存：设备派生结果 + AES 密钥表，
                          带索引、数据区轻量混淆；含本机密钥，仅本地、不可共享、勿分发
   keystone.ini      （包内已附模板；留空=用上面默认目录，可自定义位置）
   seeddb.bin        可选 seed 数据库
   readme.txt        版本与功能说明（离线可读）
```

> 默认密钥目录为 **`7z.dll` 同目录** 的 `keystone\ctraes_retail` /
> `keystone\ctraes_dev`；只要 `7z.dll` 换位置，密钥文件夹要跟着放。
> 想把密钥放到别处时，在 `keystone.ini`（或「选项 → 密钥库（Keystone）」页）里
> 指定绝对/相对路径，详见 [KEYS.md](KEYS.md#2-自定义密钥目录keystoneini)。

## 2. 支持的容器与扩展名

| 扩展名 | 容器 | 展开内容 |
|---|---|---|
| `.3ds` `.cci` `.3dz` | NCSD（游戏卡带镜像） | Partition_0…N / ExeFS / RomFS |
| `.csu` | NCSD（系统更新镜像） | 同上；含 Contents.cnt 展开 |
| `.ncch` `.cxi` `.cfa` `.app` | NCCH | ExeFS（.code/banner/…）/ RomFS |
| `.cia` | CIA（可安装归档） | cert/ticket/tmd/Content_0.cxi/meta |
| `.firm` | FIRM（固件镜像） | 各 processor 的段 |
| `.cnt` | Contents.cnt（CSU 内或单独抽出） | 内嵌 `.cia` 收进 `Contents/` 子目录，按 16 位 title id 命名 |
| `.tmd` | CDN TMD（NUS 元数据，`tmd.<n>`） | 元数据浏览：title id / 版本 / content 清单（`Contents/`）；需 ticket 才能解密 content |
| `.romfs` `.exefs` `.bin` | 已解密明文 RomFS / ExeFS 段（独立散文件） | 直接浏览并抽取内部文件，**不需要任何密钥** |
| `nand.bin`（本机 NAND 整卡备份） | NAND 型 NCSD | 用 `keystone\ctrdevice\` 档案、或直接把 boot9/OTP/nand_cid 放在 nand.bin 同目录派生密钥，列出 TWL / AGB_Save / Firm0 / Firm1 / CTRNAND，见 [NAND.md](NAND.md) |

### 文件关联

- 安装器本身**不自动**写扩展名关联（与标准 7-Zip 一致）。
- 在「选项 → 7-Zip CTR」标签页勾选需要的类型，点「应用 / 确定」后即写入注册表
  （`HKCR\.<ext>` → 7-Zip CTR 的打开命令，并登记对应图标）。
- 本版本识别的全部扩展名：`3ds cci 3dz csu ncch cxi cfa app cia firm cnt bin
  romfs exefs tmd`。

## 3. GUI 用法（7zFM.exe）

1. 双击 `7zFM.exe`。
2. 找到任意 `.3ds` / `.cia` / `.csu` / `.cxi` 文件并**双击**打开。
3. 左侧 / 中间会出现容器的内部结构：
   - `.3ds`：`Partition_0\` → `ExeFS\`（.code 等）+ `RomFS\`（游戏数据）
   - `.cia`：`cert.bin` `ticket.bin` `tmd.bin` `Content_0.cxi` `meta.bin`
   - `.csu`：`contents\` 下可见 Contents.cnt / CupList 等元文件，展开的 `.cia` 在其
     专用的 `Contents\` 子目录中（CSU 内按 16 位 title id 命名）
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
A：缺少对应密钥。检查 `keystone\ctraes_retail`（零售机）或
`keystone\ctraes_dev`（开发机）是否放对了文件、文件名是否如
`slot0x2CKeyX.key`；目录若自定义过，确认 `keystone.ini` 指向正确。

**Q：开发机 CSU 打不开 / 解出来是乱码？**
A：确认用 `keystone\ctraes_dev\` 的开发机密钥集。handler 会自动用
ExeFS 头试解来区分 dev / retail，但前提是两个密钥集都在。

**Q：Contents.cnt 里没有看到 CIA / 看到 0KB 或 content_xxx？**
A：`.csu` 的 `contents\Contents.cnt` 会被自动展开，内嵌 `.cia` 收进专用的
`Contents\` 子目录（CSU 内按 16 位补零 title id 命名）。本版本已修复运行时读取
Contents.cnt 头部越界导致的错误展开——旧版本会把 idx≥128 的条目误读成 0KB /
`content_xxx.cia`，现在与正确解包结果一致（144 项即 144 项）。
单独抽出的 `Contents.cnt` 也可直接双击打开：handler 从每个 CIA 的 ticket 段
（ticket+0x1DC）读取明文 title id，同样按 16 位补零 `<titleid>.cia` 命名，
不需要同目录的 `CupList`，进入后仍可由下游 CIA handler 解密内容。

**Q：7zFM 打开 CIA 直接闪退 / 卡死？**
A：本版本已修复嵌套 `allFilesMode` 全量提取导致的卡死。
若仍异常，请确认 7z.dll 与 7zFM.exe 版本一致（都来自本 build）。

**Q：打开 `tmd.<n>`（CDN 直抓的散 content）能看到 `Contents/*.content` 清单，但双击或抽取没东西？**
A：这些 `.content` 只是 TMD 里的元数据占位（title id、版本、content 数量与大小），
CDN 散文件外层是 TitleKey-AES-CBC 加密，必须同目录提供 ticket（`.tik` /
`.cetk`），用 common key 解出 TitleKey 才能解密。只有 TMD 时本版本只做**元数据
浏览**，密文不解密、抽取为空。
DSiWare（00048xxx，TWL SRL）本版不实现。

**Q：独立的 `exefs.bin` / `romfs.bin`（从 NCCH 里单独抽出的段）打开还需要什么？**
A：只要它们是**已解密明文**，本版本直接解析，不需要任何密钥、ticket 或配套头文件：
- `exefs.bin`：直接列出 `.code` / `banner` / `icon` / `logo` 等 ExeFS 内文件；
- `romfs.bin`：识别开头 `IVFC` 并整棵遍历 RomFS 目录树。
注意：这里打开的是**明文段本身**，不附带 NCCH exheader、签名等元数据；若是加密态
（未解密的 NCCH 内部段）则本功能不处理，需先在 CIA/NCCH 容器内解密后再抽出。

**Q：打开自己的 NAND 备份（`nand.bin`）看不到分区 / 提示无法打开？**
A：NAND 分区密钥是机器独有的。两种放法任选其一：
1. 在 `keystone\ctrdevice\<SN>\` 登记设备档案（boot9.bin、OTP、NAND CID、ctrindex.ini）；
2. 不登记，直接把 `boot9.bin`、加密 OTP（`otp.mem`/`otp.bin`）或明文 OTP
   （`otp_dec.mem`/`otp_dec.bin`）、`nand_cid.mem`/`nand_cid.bin` 放在
   **nand.bin 同目录**（`.mem`/`.bin` 扩展名都接受）。也可加一个 `ctrindex.ini`
   显式声明单元/型号，跳过询问。

程序先查 `keystone\ctrdevice`，无匹配再回退到 nand.bin 同目录派生并匹配设备。
裸模式（无 ctrindex.ini）下程序无法自判单元/机型：7zFM 会先后弹窗问"零售/开发"和
"Old 3DS / New 3DS（开发为 CTR / SNAKE）"，取消即终止；命令行则必须用
`-unit retail|dev`、`-type ctr|snake`、`-slot 4|5` 指定，缺参或取值非法直接报错退出。
准备清单、字段、弹窗流程与命令行参数见 [NAND.md](NAND.md)。缺材料、材料不全或与这台
机器对不上时，7zFM 会直接弹提示框说明缺什么，命令行返回非零退出码，都不会静默卡住。
TWL（slot0x03）分区由加密 OTP 前 8 字节 + nand_cid 派生，与 CTRNAND 使用同一套设备
材料，无需额外导出。零售单元仅凭明文 `otp_dec` 即可派生 TWL；**开发单元**若只有
`otp_dec`、缺加密 OTP，dev TWL 派不出密钥，此时 CTRNAND/Firm/AGB 照常解密，TWL 以
原始密文列出并在属性窗口注明 TWL 解密失败（详见 NAND.md 2.1.3）。
