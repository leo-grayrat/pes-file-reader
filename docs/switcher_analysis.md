# FL23 switcher.exe 深度静态逆向报告

分析对象：`game/FL23 switcher.exe`（392,905 字节 = 0x5FEC9，约 384KB）
方法：全程只读静态分析（未执行该程序），可复现脚本见仓库根目录
[switcher_probe.py](../switcher_probe.py)（纯标准库）。

```
python switcher_probe.py all      # 全量
python switcher_probe.py pe       # PE 概览 + overlay + 导入表
python switcher_probe.py sig      # 安装器类型签名扫描
python switcher_probe.py records  # 文件安装记录 + 载荷鉴别
python switcher_probe.py cpk      # 内嵌 CPK/@UTF 表
python switcher_probe.py overlay  # overlay 压缩流边界
python switcher_probe.py urls     # URL / 路径 / 注册表键普查
```

---

## 一、结论速览（证据链分级）

| # | 结论 | 置信度 | 核心证据 |
|---|------|--------|----------|
| 1 | **它是 ClickTeam Install Creator（InstalIt）打包的安装向导，不是本地快速切换器** | 高（确凿） | `InstItClass`@0x26058、`InstallSuccess`@0x264B8、`#InstallDir#`@0x26724、`_inst%d.exe`@0x26AFC、`http://www.clickteam.com`@0x100E、Welcome/License/Directory 向导文案、2009 年编译时间戳 |
| 2 | **"切换"= 用内嵌载荷覆写目标目录中恰好两个文件：`data\dt18_all.cpk` 与 `download\08_smkdb_ulk.cpk`** | 高（确凿） | 5 条文件安装记录全部指向这两个路径（见 §四） |
| 3 | **它不具备任何联网能力；此前"联网下载安装器"的表述不成立** | 高（确凿） | 导入表无 wininet.dll / urlmon.dll / ws2_32.dll；全文件唯二 URL 为 clickteam 品牌串与脚本文案 `www.pessmokepatch.com`（展示用） |
| 4 | **"Downloading files, please wait." 只是 Install Creator 释放内嵌载荷时的通用进度页文案，不代表网络下载** | 高 | 该串出现在 5 套变体脚本的相同位置（各流 +0x4EA 附近），与网络无关 |
| 5 | **程序内不含原版 PES2021 exe，也不含获取原版数据的 URL；经该工具无可行路径拿到原版** | 高 | 全文件仅一个完整 PE（自身 @0x0）；无 `dt18` 之外的数据引用；无下载类 URL |
| 6 | 两个高熵块（70,380B / 48,680B）含 `WESYS` 标记，部分可嵌套 zlib 解出多语言文本数据库；剩余内容疑似 Install Creator 私有打包格式，未完全还原 | 中 | §五 |

### 对此前判断的修正声明

- **修正**：先前"联网下载安装器"的说法有误。程序无任何网络 API 导入，所有载荷均内嵌于文件本体。"Downloading files, please wait." 是 Install Creator 引擎解压释放内嵌数据时的固定页面文案，被误读为网络下载。
- **确认**："它是一个安装器而非轻量切换器"的定性维持。虽然名字叫 "switcher"，但载体形态就是标准 Install Creator 安装向导（带 Welcome/许可协议/目录选择页面），每次"切换"实际是跑一遍安装流程覆写两个文件。
- **对用户质疑的回应**：用户提示"也可能处于资源切换阶段/观察不充分"——静态证据表明不存在"资源切换阶段"的网络行为；但用户试跑时"文件不够，必须完整游戏目录"的现象与静态证据一致：脚本内存在条件判断，校验失败即显示
  `ERROR! SP Football Life 2023 was not found in the selected directory.`

---

## 二、程序类型判定

### 2.1 排除法（签名扫描 `sig` 子命令）

| 候选类型 | 签名 | 结果 |
|----------|------|------|
| Inno Setup | `Inno Setup Setup Data` / `zlb\x1a` | 未命中 |
| NSIS | `NullsoftInst` | 未命中 |
| 7-Zip SFX / 归档 | `7z\xbc\xaf'\x1c` | 未命中 |
| CAB / ZIP / MSI(OLE2) | `MSCF` / `PK\x03\x04` / OLE2 魔数 | 未命中 |
| 嵌套完整 PE | MZ+PE 双头 | 仅 @0x0（自身） |

### 2.2 命中证据（ClickTeam Install Creator / InstalIt 引擎）

| 证据 | 偏移 | 说明 |
|------|------|------|
| `InstItClass` | 0x26058 | InstalIt 窗口类名（.rdata） |
| `InstallSuccess` | 0x264B8 | InstalIt 完成标记 |
| `#InstallDir#` | 0x26724 | InstalIt 脚本路径占位符 |
| `_inst%d.exe` | 0x26AFC | 自释放临时安装器命名模式 |
| `http://www.clickteam.com` | 0x100E | 引擎品牌（.text 内引擎代码段） |
| `(http://www.clickteam.com/pub` | 0x1469D | 同上 |
| `ICLaunch` / `DllRegisterServer` | 0x2609C 附近 | InstalIt 接口 |
| 版本资源 | 0x2EAB4 | `FL Switcher Install Program`，ProductVersion `2, 0, 0, 36` |

### 2.3 PE 概览

- PE32（magic 0x10B），machine 0x014C（x86），ImageBase 0x1000
- 编译时间戳 0x4B22B474（2009-12-11）——ClickTeam InstalIt 引擎的年代，外壳非近年产物
- 4 节：.text/.rdata/.data/.rsrc；节数据止于 0x2F000
- **overlay（覆盖数据）= 0x2F000 ~ 0x5FEC9，共 200,393 字节，占全文件 51%** —— 全部"切换内容"都在这里

### 2.4 导入表 = 行为能力清单（关键）

| 类别 | 证据 |
|------|------|
| **无任何网络能力** | 不导入 wininet.dll、urlmon.dll、ws2_32.dll、winhttp.dll |
| 本地文件操作 | KERNEL32: `CopyFileA`、`MoveFileA`、`MoveFileExA`、`DeleteFileA`、`CreateProcessA`、`WinExec`、`CreateDirectoryA` |
| 注册表 | ADVAPI32: `RegCreateKeyExA`、`RegSetValueExA`、`RegDeleteKeyA` 等（卸载登记用） |
| 目录选择 | SHELL32: `SHBrowseForFolderA`、`SHGetPathFromIDListA`（向导"选择游戏目录"页） |
| UI | USER32/GDI32/COMCTL32（向导界面） |

**推论**：程序在物理上不可能发起网络下载；它对目标目录的全部影响只能是复制/替换本地文件。

---

## 三、内嵌结构清单（384KB 全过一遍）

### 3.1 overlay 总体布局

- 头部为条目目录结构（含条目计数与偏移表），随后是 24 条 **zlib 流**（魔数 `78 DA`/`78 9C`），流间以条目头（含校验和/尺寸/标志）分隔。
- 结构：`24B 条目头` + `zlib 流` 交替；`overlay` 子命令可复现全部边界。

### 3.2 逐流清单（文件绝对偏移，`zlib`/`script`/`records` 子命令可复现）

| 偏移 | 解压尺寸 | 内容 |
|------|---------:|------|
| 0x2F013 | ~1.7KB | 引擎初始化脚本：创建 `#InstallDir#\FL_2023 start.exe`（安装后的启动器） |
| **0x2F99C** | 3,684B | **变体 1 向导脚本："Football Life gamplay V2 (default)"** |
| 0x2FFA3 | 170B | 卸载注册键 `...\Uninstall\FL Switcher` |
| 0x3000F | 98B | 文件安装记录 → `data\dt18_all.cpk`（258,296B） |
| **0x3006A** | 3,681B | **变体 2 向导脚本："Football Life gamplay (first version)"** |
| 0x30668 | 170B | 卸载注册键（同上） |
| 0x306D4 | 98B | 文件安装记录 → `data\dt18_all.cpk`（258,296B） |
| **0x30730** | 3,688B | **变体 3 向导脚本："Standard PES 21 gameplay"** |
| 0x30D27 | 170B | 卸载注册键 |
| 0x30D93 | 98B | 文件安装记录 → `data\dt18_all.cpk`（84,216B） |
| **0x30DF1** | 3,849B | **变体 4 向导脚本："Classics in Exhibition and Edit modes"** |
| 0x3141E | 170B | 卸载注册键 |
| 0x3148A | 106B | 文件安装记录 → `download\08_smkdb_ulk.cpk`（3,248B） |
| **0x314F4** | 3,796B | **变体 5 向导脚本："Classics in Master League and BAL"** |
| 0x31B6E 区 | 170B | 卸载注册键 |
| 0x31B7A | 106B | 文件安装记录 → `download\08_smkdb_ulk.cpk`（53,392B） |
| **0x31BE3** | 258,296B | **玩法 CPK（明文 CRI CPK）**：9 个 `constant_*.bin` 常数表 + 236 个 AI 脚本 `.o` |
| 0x42E79 / 0x42E9C / 0x42EB4 | 92/45/2,383B | 小配置块（无可辨识字符串） |
| **0x42F9D** | 70,380B | 高熵块（`WESYS` 标记），内嵌多段嵌套 zlib |
| 0x5408C | 3,248B | **smkdb CPK（明文）**：仅含 `smkdb.txt`；构建路径泄露 `C:/Users/GIA00/Desktop/SMK/2017/patch/SMK_Extra1`，`(c)CRIsmkdb` |
| 0x54355 | 1,691B | 小配置块 |
| **0x54411** | 48,680B | 高熵块（`WESYS` 标记）；嵌套 zlib @+97 解出 1,135,212B——多语言国家名文本数据库 |

### 3.3 玩法 CPK（0x31BE3）内容要点

标准 CPK 头 + @UTF 表（`cpk` 子命令可复现）：

- `common/match/constant/` 下 9 个常数表：`constant_match.bin`、`constant_player.bin`、`constant_team.bin`、`constant_positionCK.bin`、`constant_positionPK.bin` 等 —— **这些正是比赛引擎参数**
- 236 个 AI 行为脚本字节码 `.o`：`pesSmart.o`、`ballplayerDribble.o`、`ballplayerPass.o`、`ballplayerShoot.o`、`cameraInplay.o`、`teamEmotion.o`、`Dribbling.o`、`Crossing.o`、`Corner_kick.o` 等
- 另有 `cpk_dat/common/match/team_action/team_id_01090.bin` 类球队动作表

### 3.4 五套变体脚本的公共特征

- 均含向导页面：`Welcome`（`<b><fontsize=16>Welcome to SmokePatch</font></b>` 富文本）、许可协议、目录选择
- 默认安装目录：`#Program Files#\SP Football Life 2023`
- 均含错误文案：`ERROR! SP Football Life 2023 was not found in the selected directory.`
- 均含文案 `Downloading files, please wait.`（即"释放内嵌载荷"进度页，见结论 #4）

---

## 四、切换机制还原

### 4.1 文件安装记录（`records` 子命令输出）

记录结构：98B（dt18 型）/ 106B（smkdb 型），字段：+0=u32:1、+4=u16 类型（0x5E=dt18 / 0x66=smkdb）、+6=u16 标志、+22=u32 载荷解压尺寸、尾部为 NUL 结尾目标相对路径。

| 记录偏移 | 目标路径 | 类型 | 标志 | 载荷尺寸 | 归属变体 |
|----------|----------|------|------|---------:|----------|
| 0x3000F | `data\dt18_all.cpk` | 0x5E | 0 | 258,296 | 变体 1（V2 默认） |
| 0x306D4 | `data\dt18_all.cpk` | 0x5E | 1 | 258,296 | 变体 2（first version） |
| 0x30D93 | `data\dt18_all.cpk` | 0x5E | 1 | 84,216 | 变体 3（**Standard PES 21 gameplay**） |
| 0x3148A | `download\08_smkdb_ulk.cpk` | 0x66 | 0 | 3,248 | 变体 4（Classics Exh/Edit） |
| 0x31B7A | `download\08_smkdb_ulk.cpk` | 0x66 | 1 | 53,392 | 变体 5（Classics ML/BAL） |

### 4.2 机制结论

1. **全部五套变体只写两个文件**，从不触碰任何 `.exe`。所谓"切换玩法"：
   - 变体 1~3：把内嵌的玩法 CPK 覆写到 `<游戏目录>\data\dt18_all.cpk`（PES2021 的比赛参数+AI 脚本容器）。变体 3（Standard）的载荷尺寸仅 84,216B，明显小于魔改版的 258,296B，**疑为**更接近原版参数的精简/还原版（其实体未定位，见 §五，暂无法实证）。
   - 变体 4~5：把 SmokePatch 数据库变体覆写到 `<游戏目录>\download\08_smkdb_ulk.cpk`（Classics 球队/阵容数据）。
2. **"完整游戏目录"校验**：向导脚本在"下一步"时执行条件判断，失败即显示 §3.4 的 ERROR 文案。被校验的具体文件名**编译为 InstalIt 字节码条件，静态字符串表中不可见**；但从安装记录可逆推：它至少需要 `data\` 与 `download\` 目录存在（否则无处写），且以识别 `SP Football Life 2023` 安装的某个标志文件为准。384KB 内无显式校验文件清单可提取，这是该结论的诚实边界。
3. **切到 "Standard PES 21 gameplay" 具体改什么**：仅覆写 `data\dt18_all.cpk` 一个文件（84,216B 版本），`download\08_smkdb_ulk.cpk` 不动、任何 exe 不动。

### 4.3 原版获取路径评估

| 路径 | 可行性 | 依据 |
|------|--------|------|
| 从 switcher 内直接提取原版 exe | **不可行** | 文件内仅自身一个 PE，无任何其它 exe |
| 找下载 URL 单文件获取 | **不可行** | 无网络导入表；全文件无资源下载 URL（仅品牌串） |
| 提取已明文还原的玩法 CPK（0x31BE3，258,296B）作为玩法参数参考 | **可行** | 明文 CPK，`switcher_probe.py cpk` 可列出其内容；但**它只是数据容器，不能替代原版 exe**；且它是 SmokePatch 魔改版而非 Standard 版 |
| 原版 exe 本身 | 需另谋他途（完整游戏安装/官方补丁渠道），与本工具无关 | —— |

---

## 五、未完全还原的部分（诚实边界）

- **0x42F9D（70,380B）与 0x54411（48,680B）**：带 `WESYS` 风格标记的高熵块，非标准 CPK/zlib 封装。0x54411 内嵌套 zlib 可解出 1.1MB 多语言文本（国家名等）；其余部分疑为 Install Creator 私有打包/加密格式，未进一步还原——与玩法切换机制无关，不阻塞结论。
- **变体 3（Standard）的 84,216B 载荷实体未定位**：24 条流中唯一明文 CPK 载荷是 258,296B（变体 1/2 共用），84,216B 与任何已识别流的解压尺寸均不匹配，疑藏于上述 WESYS 高熵块（70,380B 块尺寸最接近）。因此"Standard 版是否真为还原版参数"目前只能推测（尺寸显著更小），无法实证。
- **校验清单**：如 §4.2-2 所述，条件编译为字节码，无法静态枚举完整文件清单。
- 92B/45B/2,383B/1,691B 小流无可辨识字符串，判定为配置/元数据块。

---

## 六、复现方式

```
cd d:\File\Git\pes-file-reader
python switcher_probe.py all > _tmp_probe_out.txt   # 全量报告（编码为终端默认）
python switcher_probe.py records                     # 文件安装记录与载荷鉴别
python switcher_probe.py cpk                         # 内嵌 CPK 文件清单
```

脚本特点：纯标准库（os/re/sys/zlib/struct）、对目标文件只读打开、不执行任何可执行文件、无副作用产物。
