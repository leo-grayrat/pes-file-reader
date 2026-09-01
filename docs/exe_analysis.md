# 游戏 exe 静态分析报告（任务 #8）

> 分析对象：`game/` 目录下 PES2021（mod 版）游戏本体与随附 dll。
> 方法：**纯只读静态分析**（只读 mmap 读取，绝不执行/加载/修改任何二进制）。
> 工具：仓库 `exe/exe_probe.py`（纯标准库），所有结论可用
> `python exe/exe_probe.py all` 复现。
> 分析日期：2026-08-27。

---

## 一、文件清单

| 文件 | 大小（字节） | 说明 |
|---|---:|---|
| `game/FL_2023.exe` | 458,910,720 | 游戏主程序（x86-64），文件名被 mod 改为 `FL_2023` |
| `game/amd_ags_x64.dll` | 111,616 | AMD AGS 图形扩展 |
| `game/AnselSDK64.dll` | 667,664 | NVIDIA Ansel 截图 SDK |
| `game/sdkencryptedappticket64.dll` | 796,960 | Steam 加密票据库 |

### PE 概览（FL_2023.exe）

- 架构 x86-64，ImageBase `0x140000000`，TimeDateStamp `0x5F5ED4BF`（2020-09-14，与 PES2021 原版时期吻合）。
- 节表异常：主节名为 `.trace`（约 37 MB 代码+数据合并节），另有 `.xtext`/`.xcode`/`.xtls`/`.sxdata` 等
  非标准节名，且 `.impdata` 的 VirtualSize 巨大（`0x17C3D94F`）——为 **mod/破解壳改动痕迹**，
  与"mod 版、核心内容未大改"的说法一致。
- 内部字符串多处出现官方构建路径 `d:\pes2021\patch10100\pes21\sdk\...`
  → 确认底版为 **PES2021 Data Pack/patch 1.01.00**。
- 导入表 40 个 DLL；文件 I/O 相关：
  - `kernel32.dll`：CreateFileA/W、ReadFile、WriteFile、SetFilePointer、GetFileSize(Ex)、
    MapViewOfFile、FlushFileBuffers、DeleteFileA/W、FindFirstFile* 等 22 项；
  - `api-ms-win-crt-stdio`：fopen/_wfopen/fread/fwrite/fclose；
  - `ntdll.dll`：NtReadFile/NtWriteFile。

---

## 二、主密钥锚点搜索（最高价值目标）

以 `pes_decrypt.py` 的 `MASTERKEY_PES21`（64 字节）做全文件模式搜索：

| 变体 | 命中 |
|---|---:|
| 完整 64 字节原始序列 | **0** |
| 前/后 32 字节 | **0** |
| 按 4 / 8 字节反转（字节序变体） | **0** |
| 16 字节分段（正序+反序，共 8 段） | **0** |

**结论：主密钥未以连续字节块形式存在于 exe 中。**
推测：加密走 MT19937 `init_by_array`，密钥以拆分立即数/展开常量形式内联在代码里，
或被 mod 有意移除/替换。**无法通过密钥锚点直接圈定加密函数区域**；
但存档布局常数命中（见下）仍可圈定"存档写出"相关函数。
数据侧加密验证请继续以 `pes_decrypt.py`（roundtrip 已测）为基准。

---

## 三、已知结构常数搜索命中表

（全部为小端 `<I` 4 字节立即数搜索；计数为全文件命中数，`>1M` 视为噪声常数。）

| 常数 | 含义 | 命中数 | 判定 |
|---|---|---:|---|
| 5,383,087 (0x5223AF) | 回放文件总大小 | 0 | 存疑（运行期求和计算，不落立即数） |
| **5,368,928 (0x51EC60)** | 回放 data 块大小 | **2（均为代码立即数）** | **交叉验证成立** |
| **5,368,848 (0x51EC10)** | 回放负载长度 (data−0x50) | 1 处代码 + 1 处噪声 | **交叉验证成立**（见 0x01409300） |
| 13,157 | 回放 logo 块大小 | 25（全部为动画名/哈希巧合） | 噪声，不采信 |
| 1680 (0x690) | 球队记录步长 | 35,709（<I>）/19,483（<H>） | 存疑（噪声，不可判定） |
| 788 (0x314) | 赛事表记录步长 | 数千~17,833 | 存疑（噪声） |
| 160 (0xA0) | 回放名单步长 | 20,635 | 存疑（噪声） |
| 700 | 球队数 | 32,908 | 存疑（噪声） |
| 76 | 赛事条数 | 3,511 | 存疑（噪声） |
| 320 / 208 | 加密头/文件头尺寸 | 113,143 / 14,643 | 存疑（噪声） |
| **0x11F2C0** | 球队数组尾 (0x100+700×0x690) | **5** | **数值成立，归属存疑**（见下） |
| 0x1F1E30 | 赛事表基址候选 | **0** | 存疑（疑为运行期计算或 mod 改动） |
| 596 (0x254) | 比赛日记录步长 | 2,611（<I>）/5,788（<H>） | 存疑（噪声） |
| 713 / 1473 | 比赛日记录数 | 4,435 / 11,261 | 存疑（噪声） |
| 0x345408 / 0x3299B0 | 比赛日数组基址（存档内偏移） | **4 / 0** | 存疑（4 处命中均在数据节、无字符串上下文、非代码立即数，无法定向；疑运行期计算） |
| 2020 / 2021 | 赛季起始年 | 163 / 39 | 存疑（噪声，无法定向） |

### 3.1 高价值命中详情

**① 0x51EC60（回放 data 块）两处代码立即数** —— 与数据侧 50/50 结论对上：

- 文件偏移 `0x01FB6358`（RVA `0x01FB6D58`）：`mov edx, 0x51EC60; lea rcx,[rsp+60h]; call …`
  —— 以 0x51EC60 为尺寸参数构造对象（疑似回放缓冲分配/写出准备）。
- 文件偏移 `0x01FDC56A`（RVA `0x01FDCF6A`）：同型 `mov edx, 0x51EC60` 调用；
  紧随其后 `mov r9d, 0x3AA0`（15,008）与 `mov edx, 0x51B1C0`（5,353,920）再次调用，
  且 `0x3AA0 + 0x51B1C0 = 0x51EC60` 精确闭合 → **回放 data 块被拆分为
  "前 0x3AA0 名单/头部区 + 后 0x51B1C0 事件流主体"两段处理**。
  数据侧已知名单区自 0x80 起、步长 0xA0，0x3AA0 足以容纳名单+全名表（约 0x4000 前），
  与 `docs/replay_structure.md` 二.1~二.3 的分区边界方向一致。

**② 0x51EC10（回放负载长度）出现在"按类型返回存档块大小"的分派函数**：

- 文件偏移 `0x014092D0` 起（RVA `0x01409D00`）：`cmp edi, 0x31; ja default`
  + 跳转表，每个 case 形如 `mov r8d, SIZE; jmp common`。
  即 **入参为存档类型编号（0~0x31），返回该类型的块大小**。提取到的 SIZE 集合：

  ```
  0x5F6E80(6,254,208)  0x4F88(20,360)    0x51EC10(5,368,848) ← 回放 payload
  0xA7C808(10,995,720) 0x35960(219,488)  0x2AABB0(2,796,464)
  0xAABB0(699,312)     0x40081(262,273)  0xABA1(43,937)
  0x3994(14,740)       0x304(772)        0x980(2,432)
  0x500000(5,242,880)  0x31274(201,332)  0x4A858(305,240)
  0x40001(262,145)
  ```

  数据侧可用已解密样本的 `descSize/dataSize` 与各值逐一比对，
  反推 ML/BL/EDIT/系统存档各自的类型编号（**这是把"类型字段 +0x00 = 10/11/13"
  与块大小绑定的最短路径**）。

**③ 0x11F2C0（球队数组尾偏移）5 处命中**：

- `0x03148DEC/0x03148DFC/0x03148E1C`（.trace 内）与 `0x036D7A20/0x036D7A28`（.data1 内）
  均为 **(u32 起, u32 止, u64 指针) 成对区间描述表**，例如
  `[0x11F2C0, 0x11F3A0) → ptr`（区间宽 0xE0）。
- 数值 `0x11F2C0 = 0x100 + 700×0x690` 与数据侧结论一致 → **数值层面交叉验证成立**；
  但相邻区间（0x11B6E0、0x11F3A0、0x11F541…）与已知存档边界对不上号，
  该表更可能是某内存缓冲的分段描述而非存档布局表 → **归属存疑**。

---

## 四、字符串锚点与普查

全文件提取 ASCII 串 2,659,521 条、UTF-16LE 串 834 条（主题过滤结果可用
`python exe/exe_probe.py strings` 复现）。重点命中：

| 字符串 | 位置（文件偏移） | 意义 |
|---|---|---|
| `RECORD_REPLAY` / `record_replay` | 0x0258DD80 等 | 回放录制功能标签 |
| `REPLAY_STATUS` / `REPLAY_CUT` / `REPLAY_MOMENT` | 0x02650108~0x02650140 | 回放状态机键 |
| `matchSchedule` | 0x02689140 | UI 层赛程表键（与 `teamName_home/away`、`emblemCompe` 同组） |
| `score_fixtures` | 0x026869FE / 0x0272004E | 赛程/比分视图键 |
| `editSaveData`（4 处） | 0x028D505C 等 | **EDIT 存档数据对象标识** |
| `gmPlanSaveData` | 0x0261AB96 | 计划类存档对象 |
| `Edit/Save/EditDataSaveProcess`、`Edit/Load/EditDataLoadProcess` | 0x028E01B5 附近 | **EDIT 存/读流程入口标识** |
| `Common/AutoSave/*`、`CmnTeamDataSaveIdle`、`CmnSystemSaveIdle` | 0x028BB000~0x028BC30B | 自动保存/队伍数据/系统存档任务单元 |
| `ML/MLBudgetSetting`、`ML/MLBudgetReport`、`ML/MLSeasonSalary`、`ML/Accounting/MLAccountingTransferFeeDetail`、`ML/Accounting/MLAccountingSalaryDetail`、`Common/CmnFinanceReport`、`Common/CmnTransferMarket` | 0x02658000~0x0265AD68 | **ML 资金/工资/转会费的类与路径标识** |

### 4.1 Lua 键名池（存档字段的"名字典"）

文件偏移 `0x028346F8` 附近的 Lua 常量池包含一组**比赛结果记录字段键**
（与存档内赛事记录字段直接相关）：

```
gamemode  team  team_id  player_id  player_overall  strength
play_time  rating  scorer  win_lose  match_time  stadium_id
weather  time_zone  match_skip  season_num  competition_id
fixture  proceed  return  opponent_pid  is_random  team_power …
```

`0x028C34F0` / `0x028D5418` 附近为模式分支键：
`competition | league | masterleague | become | compe | editSaveData`。

注意：未找到 `ML%08d` / `REPLAY%08d` 等文件名模板（0 命中）——
存档文件名（`REPLAY00000000` 等）很可能由 Lua 侧或字符串拼接生成，
mod 也可能改动了保存路径逻辑。

---

## 五、交叉验证结论汇总

| 数据侧已确认结论 | exe 内证据 | 判定 |
|---|---|---|
| 回放 data 块 = 5,368,928 (0x51EC60) | 2 处代码立即数（含 0x3AA0+0x51B1C0 拆分闭合） | **交叉验证成立** |
| 回放负载长度 = 0x51EC10 (data−0x50) | 出现在"按类型返回块大小"分派函数 | **交叉验证成立** |
| 球队数组尾 = 0x11F2C0 | 5 处命中（成对区间表内） | 数值成立，**归属存疑** |
| 球队步长 0x690 / 赛事步长 0x314 / 条数 700、76 | 命中数万级噪声 | **存疑（无法判定，需反汇编定向）** |
| 赛事表基址 0x1F1E30 | 0 命中 | **存疑（疑运行期计算或 mod 改动）** |
| 回放总大小 5,383,087 | 0 命中 | 存疑（运行期求和，正常） |
| 主密钥 64 字节 | 任何变体 0 命中 | **存疑（拆分内联或 mod 移除）** |
| 底版 = PES2021 patch 1.01.00 | 官方构建路径字符串多处 | **交叉验证成立** |
| 比赛日步长 596/条数 713、1473/基址 0x345408、0x3299B0 | 噪声，或仅数据节命中（无代码立即数） | **存疑（未找到对应立即数）** |
| 存档 data 块内无全库球员资料（负结论） | 球员库在外部 `cpk_dat/common/etc/pesdb/Player.bin` | **交叉验证成立**（见第七节） |

---

## 六、给数据侧逆向的线索清单（可直接转交）

1. **回放写出例程（最强锚点）**：文件偏移 `0x01FDC500~0x01FDC600`（RVA `0x01FDCF00` 附近）。
   特征：`mov edx, 0x51EC60` → call → `mov r9d, 0x3AA0` + `mov edx, 0x51B1C0` → call。
   - 常数：`0x51EC60`（总）、`0x3AA0`=15,008（头部/名单段）、`0x51B1C0`=5,353,920（事件流）。
   - 验证方法：在解密后的回放 data 里，`0x3AA0` 应覆盖 0x80 头 + 名单数组(0xA0 步长)
     + 全名/队名表；若数据侧实测名单区尾部 > 0x3AA0，则以实测修正，并把差值回灌此处复核。
2. **存档类型→块大小分派函数**：文件偏移 `0x014092D0`（RVA `0x01409D00`），
   结构 `cmp 类型,0x31 → 跳转表 → mov r8d, SIZE`。
   - 验证方法：拿各样本（ML/BL/EDIT/REPLAY/系统）解密后的
     `dataSize`（或 `dataSize−0x50`）与第三节 SIZE 集合匹配，即可建立
     "类型编号 ↔ 存档块大小"映射，反推 +0x00 类型字段（10/11/13）的完整字典。
3. **赛事记录字段名映射**：第四节 4.1 的 Lua 键池
   （`season_num/competition_id/fixture/player_id/team_id/player_overall/scorer/…`）
   可作为赛事表（0x1F1E30 区）字段切分的语义参照。
4. **资金字段语义参照**：`MLBudgetSetting / MLBudgetReport / MLSeasonSalary /
   MLAcountingTransferFeeDetail / MLAcountingSalaryDetail / CmnFinanceReport`
   （偏移 0x0265AB60~0x0265AD68）——定位资金/工资/转会费字段时，
   优先找"预算-报告-赛季工资-转会费明细"四元组结构。
5. **EDIT 存档入口标识**：`editSaveData`（4 处）与
   `Edit/Save/EditDataSaveProcess`、`Edit/Load/EditDataLoadProcess`；
   `Common/AutoSave/*`、`CmnTeamDataSaveIdle`、`CmnSystemSaveIdle`
   为队伍/系统存档任务入口。
6. **负面结论（避免走弯路）**：主密钥与文件名模板（`ML%08d`/`REPLAY%08d`）
   在 exe 中均无连续命中，不要再以“搜密钥/搜文件名模板”定位加密与写出函数；
   应沿第 1、2 条锚点做静态反汇编。
7. **外部球员数据库（突破口）**：见第七节，加载路径与完整表清单已确认。
8. **资金字段定位入口**：见第七节 7.2，`MLBudgetSetting/MLBudgetReport/MLSeasonSalary`
   及收支表 UI 键 `d_budget_transfer/d_budget_salary/budget_difference`；
   exe 中未找到“余额”数值字段名，动态余额只能在存档结构中盲定位。
9. **比赛日常数对拍结果**：596(0x254)/713/1473/0x345408/0x3299B0 均无定向命中，
   2020/2021 命中数在噪声级，数据侧应以存档内实测为准，不依赖 exe 侧立即数。

---

## 七、外部球员数据库与资金动态（数据侧对拍补充）

### 7.1 外部球员数据库加载路径（负结论交叉验证成立，下一步突破口）

exe 内确认球员/球队/赛事全库不在存档中，而是从 CPK 包内加载：

- 加载根路径：**`cpk_dat/common/etc/pesdb/`**（文件偏移 `0x02979A1B` 与 `0x028B9D4F` 两处）。
- 相关类/流程：`ProcessEditDataLoad::CreateReloadPesdb`（EDIT 载入时重建球员库）、
  `UtilityPesdb@process`（RTTI，偏移 `0x03668F3B`）。
- **表清单（pesdb 目录下 .bin 文件，见偏移 0x028B9D53 附近字符串池）**：
  `Player.bin`（球员主表）、`PlayerAssignment.bin`、`PlayerWeekly.bin`、
  `PlayerDeleteList.bin`、`SpecialPlayerAssignment.bin`、`Team.bin`、`TeamWeekly.bin`、
  `Competition.bin`、`CompetitionEntry.bin`、`CompetitionKind.bin`、
  `CompetitionRegulation.bin`、`Country.bin`、`Stadium.bin`、`StadiumOrder.bin`、
  `StadiumOrderInConfederation.bin`、`StadiumWeight.bin`、`Tactics.bin`、
  `TacticsFormation.bin`、`Coach.bin`、`CoachDeleteList.bin`、`Derby.bin`、
  `Ball.bin`、`BallCondition.bin`、`Boots.bin`、`Glove.bin`、
  `MyclubCoach.bin`、`MyclubTactics.bin`、`MyclubTacticsFormation.bin`、
  `InstallVersionPlayer[1~6].bin`（安装分片球员表）。
- **给数据侧的含义**：存档中的球员只有 ID/短名引用，全库字段（能力值/身高/年龄等）
  需从 `Player.bin` 获取；后续若需解存档球员字段语义，应把 `Player.bin`
  （可从游戏 CPK 解包或社区工具提取）纳入对照，存档记录内 5~6 位整数与球员 ID 的映射即可在 Player.bin 中验证。
- 验证方法：用 CPK 解包工具打开游戏数据包，确认存在 `common/etc/pesdb/Player.bin`；
  或以 `python exe/exe_probe.py consts` 复现字符串命中（确定性结果）。
- 另注：同区还发现 `WE-PES 2014`、`TmpdbMenuStack`/`TmpdbProcessStack` 等遗留标识，
  说明该子系统历史悠久，表格式大概率与 PES2017~2021 一脉相承。

### 7.2 资金动态余额线索（仍未直接定位，提供全部已知入口）

- ML 财务类标识（偏移 0x0265AB60~0x0265AD68）：
  `ML/MLBudgetSetting`、`ML/MLBudgetReport`、`ML/MLSeasonSalary`、
  `ML/Accounting/MLAccountingTransferFeeDetail`、`ML/Accounting/MLAccountingSalaryDetail`、
  `Common/CmnFinanceReport`、`AccountingPayment::CreateObject*` 系列。
- 收支表（balance sheet）UI 键（偏移 0x026AB75A 附近，`cpk_dat/common/menu/general/budgetReport.bin` 配套）：
  `budget_headline`、`budget_value`、`budget_difference`、`d_budget_transfer`、
  `d_budget_salary`、`balance_headline`、`d_balance_transfer`、`d_balance_salary`、
  `balance_item_empty` —— 确认游戏内存在“转会费/工资”两列收支与差额视图，
  其数据源即存档内待定位的动态余额字段。
- ML 子菜单键：`salary | market | negomenu | training | skilltraining | youthtraining`，
  可作为赛程推进逻辑（比赛日数组）与财务模块的关联参照。
- **结论**：exe 中无 “balance/余额” 数值字段名（均为 UI 键），动态余额字段只能在
  存档结构中通过“转会/赛季推进前后差值比对”盲定位；建议数据侧用同一存档在“模拟比赛日推进”
  前后的两个版本做 diff，优先扫描 4 字节有符号整型变化。

## 八、复现方式

```powershell
python exe/exe_probe.py pe        # PE 概览 + 导入表
python exe/exe_probe.py key       # 主密钥锚点（含全部变体）
python exe/exe_probe.py consts    # 结构常数 + 字符串锚点（低命中常数附 hex 转储）
python exe/exe_probe.py strings   # 全量字符串主题普查
python exe/exe_probe.py ctx --off 0x01FB6358 0x01FDC56A --radius 64   # 指定偏移深挖
python exe/exe_probe.py all       # 以上全部
```

脚本只读打开目标文件、不产生任何写操作；全部输出为确定性结果，可重复验证。
