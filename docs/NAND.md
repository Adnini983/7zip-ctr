# NAND 备份挂载与设备档案（docs/NAND.md）

本版本可以直接打开你自己机器的 **NAND 整卡备份镜像**（`nand.bin` /
`010101_<SN>_sysnand_000.bin` 等），自动解密并把内部加密系统分区列成可提取
的虚拟镜像。这与解密 ROM 用的 common 密钥是**两套独立材料**：ROM 用公开的
common keydata，而 NAND 分区密钥是**每台机器独有**的，由设备档案在本机派生，
程序内不保存任何机器密钥。

---

## 1. 能解哪些分区

NAND 镜像头部是一张 NCSD 分区表（magic `NCSD` @ `0x100`）。程序按分区的
`fstype` / `crypttype` 判定角色，并用设备档案派生的 normalkey 做 AES-CTR 流式
解密：

| 分区角色 | 派生 slot | 说明 |
|---|---|---|
| `CTRNAND`（Old3DS） | `slot0x04` | 旧版 3DS 系统分区，起始 `0xB930000` |
| `CTRNAND`（New3DS / snake） | `slot0x05` | New3DS 系统分区，起始 `0xB930000` |
| `Firm0` / `Firm1` | `slot0x06` | 两份 FIRM 引导分区（各 4 MiB） |
| `AGB_Save` | `slot0x07` | GBA 虚拟存档区（192 KiB） |
| `TWL`（DSi 兼容区，crypttype=1，分区 0） | `slot0x03` | DSi keyscrambler，由加密 OTP 前 8 字节 + 固定 KeyY + nand_cid 派生（见第 4 节） |

打开镜像后，这些分区以 `Partition_<序号>_<角色>.bin` 的形式列出，提取时在内存中
流式解密，不生成中间密文。

> 匹配方式：程序逐个尝试本地设备档案，用该档案的 CTRNAND normalkey 解 `0xB930000`
> 处的 MBR 扇区，能解出结尾 `55 AA` 引导签名的即认定为本机，因此档案可以放多台
> 机器，互不干扰。

---

## 2. 目录布局

设备档案放在 `7z.dll` 同目录：

```
<7z.dll 所在目录>\
   keystone\
      ctrdevice\
         <设备目录名>\          目录名任意（建议用序列号，如 <序列号>_dev）
            ctrindex.ini       设备档案索引（必需）
            boot9.bin          64 KiB 明文 BootROM 转储（必需）
            otp.mem            原始加密 OTP（256B）：CTRNAND 由 boot9 代解，
                               dev TWL(slot0x03) 直接取其前 8 字节做 KeyX
            otp_dec.mem       已解密 OTP（256B，可选，优先用于 CTRNAND keyinit）
            nand_cid.mem      16 字节 NAND CID 转储（与 nandcidhex 二选一）
            nandcidhex=...     或直接在 ini 里写 CID 的 hex（二选一）
>
> 文件名由 `ctrindex.ini` 的 `optdump`/`optdec`/`nandcidfile` 指定（可写成 `.bin`）；
> 裸模式（2.1 节，无 ini）才自动在 `.mem`/`.bin` 之间回退。
> 注意：dev 机 TWL 的 KeyX 取自**加密 OTP** 前 8 字节，仅有 `otp_dec` 时 dev TWL
> 无法解密（见 2.1.3 降级说明）；`otp_dec` 只用于 CTRNAND 的 keyinit，两者同时存在最稳。
```

多台机器就并列多个 `<设备目录名>` 子目录；不需要的机器不放即可。

> 默认目录是 `7z.dll` 同目录下的 `keystone\ctrdevice\`，可在
> `keystone.ini` 的 `[Keystone]` 段用 `DeviceDataDir=` 改到任意位置
> （绝对路径原样使用，相对路径相对 `7z.dll` 目录解析），也可在
> 7zFM 的「选项 → 密钥库」里用「3DS实机唯一数据路径」设置。
> 这一目录与 `ctraes_retail` / `ctraes_dev` 一样是机器特有材料，
> **不要上传公开仓库、不要随 Release 分发**。

### 2.1 不登记设备时：材料直接放在 nand.bin 同目录

当 `keystone\ctrdevice` 里没有任何设备能解开当前 nand.bin 时，程序会自动到
**nand.bin 所在目录**再找一次本机材料，无需先建设备目录：

- 优先读同目录的 `ctrindex.ini`（格式见第 3 节，可显式声明 `unit=dev`、
  `type=ctr|snake`）；
- 没有 `ctrindex.ini` 时按裸文件自动探测（扩展名 `.mem` 与 `.bin` 都接受，
  按下面顺序回退，不写死单一扩展名）：
  - `boot9.bin`（64 KiB，必需；boot9 转储一律是 `.bin`，不接受其它扩展名）
  - 原始加密 OTP：`otp.mem` → 回退 `otp.bin`（256B）
  - 已解密 OTP：`otp_dec.mem` → 回退 `otp_dec.bin`（256B，优先用于 CTRNAND keyinit）
  - `nand_cid.mem` / `nand_cid.bin`（16 字节 NAND CID）

```
<任意目录>\
   nand.bin
   ctrindex.ini      （可选；不给则进入"裸模式"，由用户指定单元/型号）
   boot9.bin
   otp.mem  /  otp.bin        （加密 OTP，二选一即可）
   otp_dec.mem / otp_dec.bin （明文 OTP，二选一即可，优先）
   nand_cid.mem / nand_cid.bin
```

裸模式下程序无法自行判断单元类型与机型，需要用户明确提供（见下）。
匹配方式与登记设备相同：按指定 slot 解密 CTRNAND 扇区 0 的 MBR，
校验 `0x55AA` 签名，命中即挂载；解不出即判定不匹配。

#### 2.1.1 在 7zFM.exe（图形界面）里：两步询问

材料齐全但缺少设备类型时，程序依次弹出两个询问框，点"取消"即终止、不挂载：

1. **单元类型**：零售（Retail）/ 开发（Devkit）/ 取消；
2. 按上一步分支再问机型：
   - 零售：旧版 3DS/2DS（slot0x04）/ New 3DS/2DS（slot0x05）/ 取消；
   - 开发：CTR 系列（slot0x04）/ SNAKE 系列（slot0x05）/ 取消。

型号选错时该 slot 解不出 `0x55AA`，会提示"材料与这台 nand.bin 不匹配"，
不会静默挂载错误结果。

#### 2.1.2 在 7z.exe（命令行）里：用参数指定

命令行不弹窗，必须用参数把单元/机型告诉程序，缺参或取值非法会直接报错退出：

| 参数 | 取值 | 说明 |
|---|---|---|
| `-unit` | `retail` / `dev` | 零售单元 / 开发单元（必填） |
| `-type` | `ctr` / `snake` | 仅开发单元：CTR 系列 / SNAKE 系列 |
| `-slot` | `4` / `5` | 4 = Old 3DS（CTR），5 = New 3DS（SNAKE） |

等号或空格均可（`-unit=retail`、`-unit retail`）。示例：

```
7z.exe l -unit=retail -slot=5 nand.bin
7z.exe l -unit=dev -type=snake nand.bin
```

> 命令行缺 `-unit`、取值非法（如 `-unit=hacker`）或 slot 与机型对不上时，
> 程序以"数据无效"报错并返回非零退出码，不会挂起等待输入。

**缺件或对不上时的提示**（不会静默失败或卡住）：

- 同目录与 `ctrdevice` 都没有任何材料 → 提示"未找到 3DS 设备密钥材料"；
- 同目录有材料但缺文件 / 派生失败 → 提示"材料不完整，需要 boot9、OTP、nand_cid"；
- 材料都在但解不出 0x55AA → 提示"材料与这台 nand.bin 不匹配，确认属于同一台机器"。

#### 2.1.3 只有明文 OTP（otp_dec）、缺加密 OTP 时的 TWL 降级

- 零售单元（retail）：TWL KeyX 直接取自 `otp_dec[0x8:0x10]`，有明文 OTP 即可，TWL 正常解密。
- 开发单元（devkit）：TWL KeyX 需要**加密 OTP 的前 8 字节**（`otp.mem`/`otp.bin`），仅有
  `otp_dec` 派不出 dev TWL 密钥。此时程序**不再整体报错**：CTRNAND、Firm0/1、AGB_Save
  仍照常解密，TWL 分区以**原始密文**原样列出（不解密），并在 7zFM 的「属性 / Properties」
  备注里注明 "TWL decryption failed: encrypted OTP dump (otp.mem/otp.bin) needed"。
  要解开 dev TWL，需补一份本机的加密 OTP（`otp.mem` 或 `otp.bin`）。

---

## 3. `ctrindex.ini` 字段

`[ctrindex]` 节。下面只列**程序实际读取**的键；其余键（`movable` / `aeskeydb` /
`seeddb`）为本档案格式预留，当前版本暂未使用。

| 键 | 取值 | 说明 |
|---|---|---|
| `type` | `ctr` / `snake` | `ctr`=旧版 3DS（CTRNAND 走 slot0x04）；`snake`=New3DS（走 slot0x05） |
| `unit` | `retail` / `dev` | 许可单元。影响 boot9 keygen 偏移与 OTP 解密密钥位置；开发机填 `dev` |
| `sn` | 序列号文本 | 仅作备注标识，不参与派生 |
| `boot9` | 文件名 | 明文 boot9 转储，默认 `boot9.bin` |
| `optdump` | 文件名 | 原始加密 OTP（256B，**必需**）。CTRNAND 在 `optdec` 为空时用 boot9 内置密钥 CBC 代解；TWL 直接取其前 8 字节做 KeyX |
| `optdec` | 文件名 | 已解密 OTP（256B，可选）。填了则 CTRNAND keyinit 直接用它，跳过 boot9 代解 |
| `nandcidfile` | 文件名 | 16 字节 NAND CID 转储；与 `nandcidhex` 二选一 |
| `nandcidhex` | 32 位 hex | 内联 CID；`nandcidfile` 为空时使用 |

最小可用示例（New3DS 开发机，已提供 `otp_dec.mem` 与 `nand_cid.mem`）：

```ini
[ctrindex]
type=snake
unit=dev
sn=<序列号>
boot9=boot9.bin
optdec=otp_dec.mem
optdump=otp.mem
nandcidfile=nand_cid.mem
nandcidhex=
```

---

## 4. 派生原理（本机计算，不落盘）

1. **OTP 解密**：若只给了原始 `otp.mem`，用 boot9 内存储的 CBC 密钥/IV 解出明文
   OTP；校验魔数 `0FB0ADDE` 与末尾 SHA256 后才接受。
2. **keyinit**：取 `otp_dec[0x90:0xAC]`（0x1C 字节）与 boot9 extdata keygen
   前 0x24 字节拼成种子，SHA256 得 cxy；经 keyscrambler 得 slot0x3f normalkey，
   再以 keygen+36 为 IV、keygen+52 起 64 字节做 CBC 加密得到共享 keyX；最后用
   各 slot 的 keyY（slot0x05 的 keyY 为公开固定值，slot0x04/06/07 取 boot9
   keygen 内偏移）经 keyscrambler 得到 slot0x04–0x07 normalkey。
3. **CTRNAND nonce**：`SHA256(nand_cid)[0:16]`，与 normalkey 一起做 AES-CTR。
4. **TWL（slot0x03）normalkey**：不走 boot9 keyinit，而走 DSi keyscrambler——
   KeyX 由**加密 OTP 前 8 字节**（`otp.mem` 即可，不需要 otp_dec）按低 4 字节 ‖
   固定 `1e4b7aee8bc042af` ‖ 高 4 字节拼成，与固定 DSi KeyY 异或后加 C2，再整体
   ROL42 得 normalkey；TWL nonce = `SHA1(nand_cid)[0:16]` 的字节反转，AES-CTR 采用
   每块反转变体。

派生过程本身只在内存完成；派生结果与 AES 密钥表可写入本机私有的统一缓存
`keystone\cache\keystone.cache`（见第 6 节），原始材料与缓存都不上传、不外发。
TWL 派生只依赖第 5 节已收集的 `otp.mem`（加密）与 `nand_cid.mem`，不需要额外
从实机导出 slot0x03。

---

## 5. 从实机准备这些文件

在已破解、能进 GodMode9（v1.1.8+）的机器上导出。菜单名随 GM9 版本略有差异，
核心是取下面三类材料，最后在本地写成一份设备档案目录。

### 5.1 boot9.bin + otp.mem（GM9 直接导出）

> 省事做法：运行 `gm9tools\DumpKeysCTR.lua`（GodMode9 的 Lua 脚本），它会一次性把
> `boot9.bin`、`otp.mem`、`otp_dec.mem`、`nand_cid.mem` 连同写好的 `ctrindex.ini`
> 放进 `sd:/gm9/out/7zctr-keys/keystone/ctrdevice/<序列号>_<单位>/`（如
> `<序列号>_retail` / `<序列号>_dev`），并顺带导出 FIRM 公钥。
> 把这个目录拷进 `keystone\ctrdevice\` 即可，**不需要手写 ctrindex.ini**。
> 下面 1–4 步是手动流程，效果相同。

1. 启动 GodMode9，进入 `[M:] MEMORY VIRTUAL`。
2. 在 `boot9.bin` 与 `otp.mem` 上按 `L` 同时选中两个文件。
3. 按 `A`，选「Copy to 0:/gm9/out」，关机。
4. 从 SD 卡 `/gm9/out/` 取出：
   - `boot9.bin`（64 KiB，ARM9 BootROM 明文）；
   - `otp.mem`（256B，**原始加密** OTP，必需）：CTRNAND 由 boot9 内置密钥代解，
     TWL(slot0x03) 直接取其前 8 字节做 KeyX，无需自己解。
   - 若你另外能拿到**已解密**的 `otp_dec.mem`（256B），放进来并在 ini 用
     `optdec=` 指定，可跳过 boot9 代解（选填，仅服务 CTRNAND，不能替代 otp.mem）。

### 5.2 NAND CID（16 字节）

计数器 nonce = `SHA256(nand_cid)[0:16]`，这 16 字节二选一提供：

- **首选（离线，不必再开实机）**：之前做 NAND 整卡备份时，`/gm9/out/` 同目录会
  生成一个 `essential.exefs`，NAND CID 打包在其中；把它解出后把 CID 存成
  `nand_cid.mem`（16 字节），或直接把 32 位 hex 写进 ini 的 `nandcidhex=`。
- **实机**：在 GodMode9 的系统信息页可查看 NAND CID；存成 16 字节 `nand_cid.mem`
  或内联 hex 均可。

### 5.3 type / unit 与目录摆放

| 键 | 取值 |
|---|---|
| `type` | `ctr`=旧版/Old3DS（CTRNAND 走 slot0x04）；`snake`=New3DS（走 slot0x05） |
| `unit` | `retail`=零售机；`dev`=开发机（影响 boot9 keygen 偏移与 OTP 解密位） |

把上面文件放进 `keystone\ctrdevice\<序列号目录>\`，并写一份 `ctrindex.ini`
（字段见第 3 节）。最小目录示例：

```
keystone\ctrdevice\<序列号>_dev\
   boot9.bin
   otp.mem            （加密 OTP，必需；TWL KeyX 取自其前 8 字节）
   otp_dec.mem        （可选，明文 OTP，加速 CTRNAND keyinit）
   nand_cid.mem
   ctrindex.ini
```

这些都是**机器独有、可反推身份**的材料：只放在自己电脑的 `keystone\ctrdevice\`
本地目录，**不要上传 GitHub、不要放进 Release、不要发给他人**。

---

## 6. 统一磁盘缓存（本机私有，不可共享）

首次打开 NAND 镜像时，程序对每台设备跑一次 OTP 解密 + keyinit 派生。所有持久化
记录——**设备派生结果**（`Nk[4..7]`、CTRNAND nonce、TWL normalkey / nonce）与
**已加载的零售/开发 AES 密钥表**——都合并写入程序目录下的**同一个文件**
`keystone\cache\keystone.cache`，不再为每台设备、每条密钥单独散落文件。

文件为二进制格式，由记录头索引（记录类型 / 名称 / 目录签名 / 数据偏移与长度）
加数据区组成；数据区整体做轻量 XOR 混淆，用记事本直接打开看不到明文密钥或
十六进制。注意这只是防随手查看的混淆，不是加密。

- 记录类型：`type=2` 设备派生记录，`type=1` AES 密钥记录；每条都带所属源目录
  的「文件大小 + 修改时间」FNV-1a 签名。
- 命中条件：设备目录 / 密钥目录内源文件**没有任何增删改**，签名未变即直接载入，
  跳过重复的 OTP 解密 + keyinit 派生；改动任一源文件，签名失效，下次访问自动重算。
- AES 密钥始终以磁盘上的 `*.key` 为权威来源，缓存仅作本地留痕；目录签名不变时
  跳过重复写入以控制文件体积。
- 点「选项 → 密钥库 → 重置缓存」会删除整个 `keystone.cache`，下次访问重新派生。
- **安全红线**：缓存文件内嵌本机派生密钥与 AES 密钥，**仅限本机使用，不可分享、
  不可上传 GitHub、不可随 Release 分发**；它不替代也不包含 `ctrdevice\` 里的原始
  档案，原始档案仍需自备且同样不上传。

---

## 7. 已知限制与验证状态

- **TWL（slot0x03）分区已解密为整段虚拟镜像**（`Partition_0_TWL.bin`，约 185 MiB），
  但目前只做到分区级解密挂载：解出的 twln（FAT16，DSiWare）/ twlp（FAT12，照片）
  内部目录遍历、以及 DSiWare title 自身的一层加密尚未展开。
- 仅做**只读解密挂载**，不支持写回、重新加密或导出加密镜像。
- **验证状态**：三台实机备份（New3DS dev / SNAKE、Old3DS dev / CTR、零售 New3DS LL）
  × 5 个分区（TWL / AGB_Save / Firm0 / Firm1 / CTRNAND）共 15 对输出，与独立参考实现
  的 SHA-256 **全部逐字节一致**——含零售机的 TWL（slot0x03）派生分支。
