# 交接文档 v3（2026-08-29）

> 本文档取代 v2（`HANDOFF_v2.md`，2026-08-28），补全 v2 之后 5 个提交的新进展，
> 并校正任务列表/子代理状态。v2 中已详述的加密层、文件外壳、BL/ML 与回放的可读成果
> 不再重复，仅在本档末尾给出导航与增量。

## 一、项目目标（不变）

逆向 PES2021 三类存档（回放 `rep/REPLAY*`、大师联赛 `ML*`、一球成名 `BL*`），
最终做出外置解析器与修改器。约定不变：`examples/` 只读、大数据不入 git、
简体中文、勤提交。

## 二、总体进度一览（v3 更新）

| 层次 | 状态 | 说明 |
|---|---|---|
| 加密层 | ✅ 100% | MT19937+链式滚动密钥，roundtrip 逐字节还原，`tests/test_roundtrip.py` 固化 |
| 文件外壳 | ✅ 100% | 320 加密头 + 208 文件头 + desc/logo/data/serial，长度公式零误差 |
| BL/ML 结构 | ◐ 约 60% | 球队、赛事、赛程日历、用户球员已解；**资金盲扫路线已关闭**，对阵双方未解 |
| 回放结构 | ◐ 约 45% | 名单/帧网格/事件区已解；**248B 高熵 blob 已排除标准压缩与强加密**，编码方式未定 |
| 修改器实操 | ☐ 未开始 | 需真实游戏环境；头部哈希区是否需重算未验证 |
| BAL 编辑器偏移提取 | ❌ 已止损 | dnlib 可读 IL 但偏移被 Reactor 动态加密，静态提取成本过高（见五.3） |

## 三、v2 之后的增量提交（本次重点）

v2 覆盖到 `dcf091f`（社区成果归档 + v2 交接）。其后 5 个提交（旧→新）：

| commit | 内容 | 产物 |
|---|---|---|
| `ca6c8da` | 归档 implyingrigged 社区 EDIT 存档格式文档 + BAL 编辑器混淆复勘 | `docs/community_edit_file.md` |
| `ad767ab` | 探针16 确认后段大带差分为 float 噪声，**关闭资金盲扫路线** | `bl_ml_probe16.py` |
| `abbe386` | gitignore 排除 dotnet 缓存与第三方逆向工具目录 | `.gitignore` 更新 |
| `9f71dbe` | **BAL 编辑器反编译终判：止损** | 无新文件（结论性提交） |
| `c999f78` | 回放 blob 编码检测：排除 zlib/gzip/deflate，发现明文计数器与跨帧相关性 | `replay_zlib.py` + `docs/replay_structure.md` 第六节 |

另有未入库脚本 `exe_xref.py`（见五.5）。

## 四、可读成果（不变，简述）

全部可由 `python decode_dump.py` 重新生成，报告在 `docs/decoded_content.md`：
700 支球队全量名单、72 条赛事中文全名、生涯赛程日历（13000 槽位）、
用户球员（BL=达里奥·埃苏戈 ID 143939 / ML=阿莱克斯·弗格森）、
回放 50 场首发 1100 名球员 + 帧网格（660 帧 × 8112 字节）。
详见 v2 第三节，此处不重复。

## 五、v2 之后的新进展详述

### 5.1 社区 EDIT 存档格式归档（`ca6c8da`）

`docs/community_edit_file.md`：从 implyingrigged.info（Wayback 2022-05-22 快照，直连 403）
抓取 PES2021 **EDIT 存档**（`EDIT00000000`，非 ML/BL）完整二进制格式，交叉验证用
GitHub `kickoffsage/pes2021-transfer-tool`（MIT）。

要点：
- EDIT 存档 = Header(0x7C) + Player(240B/条,4830) + Team(588B/条,210) + Manager + Competition
  + Stadium + Team-Player 表 + Game Plan 等区段链。
- Player entry：26 项能力值（**7 位封装、范围 [40,99]**）+ 身高/体重/年龄/位置/技能掩码，
  名字在 +0x36。
- **对本项目的启示**：字段语义/单位/命名可直接复用到 ML/BL 用户球员记录的语义标注；
  但**偏移不能照搬**（EDIT 的 Player 名字在 +0x36，BL 用户球员名字在 +0x08/+0x44/+0x82，
  序列化布局不同）。Team-Player 表（球队 ID + 40 球员 ID）是「对阵双方」线索的旁证。

### 5.2 资金盲扫路线关闭（`ad767ab`）

`bl_ml_probe16.py`：对后段大带（0x500000~EOF，重点 0xCAAC90 起 float 稀疏表）
做跨进度 ML 档差分（ML0↔ML13 等 4 对），找金额候选（int32，量级 1e3~1e7，单位=100 欧元）。

结论：
- 后段差分按 float32 读呈连续分布、按 int32 读无金额量级聚簇 → **差分是 float 噪声，
  非金额整数**。
- 结合此前 probe14/15 已穷举 0x500000 之前零命中 → **动态余额盲定位不可行，正式关闭此路线**。

剩余路线（需外部输入）：
1. 玩家提供游戏内显示的账户余额/转会预算/工资预算三值，×100 后全量检索，三值相邻命中即钉死；
2. 同一存档在「模拟比赛日推进」前后做 diff，优先扫 4 字节有符号整型变化（需能在游戏内推进赛程）。

### 5.3 BAL 编辑器反编译终判：止损（`9f71dbe`）

尝试反编译社区工具 **BAL Career Editor 1.1**（.NET 程序）以提取它使用的存档偏移常量。
用 dnlib 能读到 IL 代码，但**偏移常量被 Reactor 混淆器动态加密**——常量在运行时才解密，
静态读取只能拿到加密形式。静态提取成本过高，**止损放弃此路线**。
副产品：`.gitignore` 增补 dotnet 缓存（`.dotnet-home/`）与第三方逆向工具目录（`tools/`）。

### 5.4 回放 blob 编码检测（`c999f78`，最新工作）

`replay_zlib.py`：对事件流槽内 **248B 高熵 blob**（全 660 帧 6614 个）做编码探测。
结论已写入 `docs/replay_structure.md` 第六节：

1. **非 zlib/gzip/deflate**：blob 首字节分布均匀，`zlib.decompress`（三种 wbits）前 40 个全失败。
2. **非强加密**：首 4 字节存在**明文递增计数器**（槽12 跨 660 帧，第 2 字节单调递增，
   相邻步长 0×432 / +1×105 / -1×105）——强加密不可能保留此模式。
3. **相邻帧强相关**：同槽跨帧 blob 异或熵 3.87，显著低于本体熵 5.6。
4. **推断**：blob ≈ 「明文计数/时间戳头 + 运动数据（经轻度线性变换或 delta 编码，
   非标准压缩、非强加密）」。

下一步：剥掉头字段后对余下 ~240B 做同槽跨帧差分/异或，观察是否有 float32 坐标/速度
的低字节相关性；或反汇编写出例程 0x01FDC500 后续逻辑（见 `docs/exe_analysis.md` 第六节）。

### 5.5 `exe_xref.py`（未入库）

根目录有未提交脚本 `exe_xref.py`：对 `game/FL_2023.exe` 做字符串→代码引用反查，
定位 ML 资金字段的读写例程。思路是找 .text 段里 rip-relative 引用
`MLBudgetSetting`/`MLSeasonSalary`/`MLAccounting*` 等字符串 RVA 的指令，
顺藤追到存档写出例程。**已写就但未提交、未记录运行结果**，接手者可先跑一次看是否产出有用 xref。

## 六、关键事实与教训（继承 v2 + 更新）

1. **金额单位 = 100 欧元**（社区运行时实证，`docs/community_findings.md`）。
2. **存档布局 ≠ 内存布局 ≠ EDIT 存档布局**：社区工具偏移不能直接照搬到 ML/BL；
   字段集合/语义/单位可用，具体偏移必须在存档上重新对拍（5.1 再次印证）。
3. **全库球员资料不在存档内**（多脚本 + exe 交叉证伪）：来自外部
   `cpk_dat/common/etc/pesdb/Player.bin` 等 28 张表，存档里只有球员 ID。
4. **盲扫已证明不可行**（5.2 终判）：资金定位必须走"游戏内真实数值 ×100 精确对拍"
   或"赛程推进前后差分"路线，不要再做量级窗口盲扫。
5. **社区生态优先**：所有重大突破都来自站在社区既有成果上（pesXdecrypter、EconomyScaler、
   CT 表、implyingrigged EDIT 文档），而非从零硬扫。
6. **.NET 混淆工具（Reactor）会动态加密常量**：静态反编译 .NET 编辑器提取偏移的路走不通，
   遇到同类工具不要重复尝试。

## 七、未解项与推荐路线（v3 优先级）

1. **回放 248B blob 编码**（最高优先级，纯数据侧可推进）：按 5.4 下一步，
   剥头后同槽跨帧差分/异或，找 float32 坐标相关性。这是回放语义还原的最后壁垒。
2. **资金动态余额**（需外部输入）：按 5.2 剩余路线，需玩家提供游戏内数值或赛程推进差分。
3. **对阵双方字段**：赛事表参赛实体以列表形式出现、非成对；可结合球队数组队号与
   回放名单魔数标记（`2CBDFFFD` 主 / `247AFFFE` 客）交叉；EDIT 文档的 Team-Player 表
   结构（5.1）是旁证。
4. **修改器实操**：改 data 后重新加密闭环已成立，但头部 +0x30~0x50 的 32 字节哈希区
   是否需重算未经游戏实测；回放每场该区域必变，需实验设计。
5. **`exe_xref.py` 跑通**（5.5）：若能定位资金字段读写例程，可反推存档偏移，
   绕过盲扫。先提交脚本再跑。
6. **可选支线**：用社区球队/球员 ID 合集把赛事表、回放中的数字 ID 批量翻译成名称。

## 八、仓库导航（v3 全量）

纳入版本控制的文件（`git ls-files`）：

- **核心工具**：`pes_decrypt.py`（加解密）、`export_data.py`（批量导出）、
  `decode_dump.py`（可读内容报告生成）、`tests/test_roundtrip.py`（6 条还原断言）
- **BL/ML 探针**：`bl_ml_analyze.py`、`bl_ml_probe3~16.py`、`probe2.py`
- **回放探针**：`replay_analyze.py`（12 子命令）、`replay_zlib.py`（blob 编码检测）
- **exe/切换器探针**：`exe_probe.py`、`switcher_probe.py`
- **早期探查**：`probe.py`、`analyze.py`、`check_bl_ml.py`
- **未入库脚本**：`exe_xref.py`（exe 字符串→代码引用反查，5.5）
- **文档**：`README.md`、`docs/` 下 9 份（见下）
- **第三方**：`third_party/pesXdecrypter/`（C 源码 + 编译产物 + NOTICE.md）

`docs/` 目录：

| 文档 | 内容 |
|---|---|
| `HANDOFF.md` / `HANDOFF_v2.md` / **`HANDOFF_v3.md`** | 三版交接文档（本档最新） |
| `bl_ml_structure.md` | BL/ML data 结构（已成稿，含三档结论与修改器注意） |
| `replay_structure.md` | REPLAY data 结构（含第六节 blob 编码检测结论） |
| `exe_analysis.md` | 游戏 exe 静态分析（主密钥锚点/常数命中/Lua 键池/外部球员库） |
| `switcher_analysis.md` | 切换器分析 |
| `community_findings.md` | 社区成果归档（EconomyScaler/CT 表/金额单位实证） |
| `community_edit_file.md` | 社区 EDIT 存档格式（implyingrigged，5.1） |
| `decoded_content.md` | 可读解码内容报告（`decode_dump.py` 生成） |

不入库（`.gitignore`）：`examples/`、`decoded/`、`game/`、`resources/`、`tools/`、
`.arts/`、`.codeartsdoer/`、`.dotnet-home/`、`__pycache__/`、`.merkle-snapshot.json`。

## 九、提交历史要点

初版 6 提交（924e761~631fa45）→ v1 交接；beeed55~dcf091f 共 7 提交 → v2 交接；
本阶段（v2 之后）5 提交：

- `ca6c8da` 社区 EDIT 文档归档 + BAL 编辑器混淆复勘
- `ad767ab` 探针16 关闭资金盲扫路线
- `abbe386` gitignore 排除 dotnet/工具目录
- `9f71dbe` BAL 编辑器反编译终判止损
- `c999f78` 回放 blob 编码检测（最新）

提交信息风格：纯中文简短说明（无冒号前缀），与既有提交保持一致。

## 十、子代理与任务列表状态（重要）

**子代理在本对话已废**：此前组建的 team-mate 子代理（BL/ML逆向工程师、REPLAY逆向工程师）
在本环境空转（1~3 秒无输出返回），实际工作均由 leader 自己完成。后续工作不要再依赖
这些子代理 session。

**任务列表已严重过时**：`read-team-task` 显示任务 2/3 仍为 in_progress、任务 4（README）
仍为 pending，但实际上 `bl_ml_structure.md`/`replay_structure.md`/`README.md` 均已提交。
任务列表停留在很早的状态，不可信。后续若要重启任务跟踪，建议清空旧任务重建。