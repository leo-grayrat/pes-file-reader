# PES2021 存档逆向（pes-file-reader）

对《实况足球 2021》（eFootball PES 2021 SEASON UPDATE，Patch 1.07.00）的三类存档做
**探索性逆向分析**：破解 exe，还原游戏读取/处理存档的具体方式，途中挖掘社区未知的
隐藏机制。目标文件：

- **大师联赛存档** `ML000000*`（约 19.7 MB）
- **一球成名存档** `BL000000*`（约 19.5 MB）
- **编辑数据** `EDIT00000000`（约 11 MB）
- **回放存档** `rep/REPLAY000000*`（50 个样本，各 5,383,087 字节）

三类存档均无后缀、整体加密。**加密层已 100% 闭环**：
MT19937 流加密 + 链式滚动密钥，每文件独立密钥；加解密对称，
`decrypt → encrypt` roundtrip 可逐字节还原（`tests/test_roundtrip.py` 固化）。
算法与 PES2021 主密钥来自公开项目
[the4chancup/pesXdecrypter](https://github.com/the4chancup/pesXdecrypter)，详见
[third_party/pesXdecrypter/NOTICE.md](third_party/pesXdecrypter/NOTICE.md)。

> 工作进展与历史背景见 [docs/HANDOFF_v3.md](docs/HANDOFF_v3.md)（最新交接文档）。

## 当前进展一览

| 层 | 状态 | 说明 |
|---|---|---|
| 加密层 | ✅ 100% | MT19937 + 链式滚动密钥，roundtrip 逐字节还原 |
| 文件外壳 | ✅ 100% | 320B 加密头 + 208B 文件头 + desc/logo/data/serial，长度公式零误差 |
| encHeader | ✅ 100% | 四段 SHA-512 摘要 + 随机 salt → 折叠派生 rolling_key；serial = Windows SID 绑定 |
| exe 装载管线 | ✅ 主体 | 存档类型 7/8/9 分派、数据容器 → 运行时表批量同步（变体 A/B/C） |
| EDIT / ML 结构 | ✅ 主体 | 队块/阵容/赛程/事件表已解；`core/pesfile.py` 导出 CSV+JSON |
| **ML 动态机制** | ✅ 主体 | **每周掷骰分档 → 成长公式 → 赛季结算**（隐藏机制，见下） |
| 回放结构 | 🔶 部分 | 名单/帧网格/事件区已解；248B blob 编码未定 |
| 修改器实操 | ⭕ 未开始 | 需真实游戏环境；头部哈希是否需重算未验证 |

**ML 动态隐藏机制（社区未知，本仓首次披露）**：
- 每周给每名球员掷 d100，按位置/能力分类的 11 档加权表分档，两个比值 + 模式位打包进槽；
- 赛季结算时读回打包槽作"训练因子"，套**成长系数表**（每项能力一条曲线，
  `+1500 → 0 → -1800`，**峰值后为负 = 老球员掉能力**，系数表 tag 已与 CT 字典全映射）；
- 训练焦点对象（8 分类桶 + 上限 21，每周清零退回）；82 周一赛季结构。

详细结论见 [docs/exe-save-layout.md](docs/exe-save-layout.md)（exe 侧唯一文档，全部
结论 = **代码位置 + 真实存档数据**双证据）。

## 存档文件结构

```
加密文件 = 320 字节加密头(EncryptionHeader)
         + 208 字节文件头(FileHeader)
         + description + logo + data + serial
```

解密后的 FileHeader 关键字段（小端）：

| 偏移 | 字段 | 说明 |
|------|------|------|
| +64 | `dataSize` | data 块字节数 |
| +68 | `logoSize` | logo 块字节数 |
| +72 | `descSize` | description 块字节数 |
| +76 | `serialLength` | serial 字符数（实际占 `serialLength × 2` 字节） |
| +144 | `fileTypeString` | 类型标识：`REPLAY` / `BL` / `ML` / `EDIT`（32 字节，NUL 填充） |
| +176 | `gameVersionString` | `eFootball PES 2021 SEASON UPDATE`（32 字节） |

故文件总长 = `320 + 208 + descSize + logoSize + dataSize + serialLength × 2`。

## 仓库结构

```
pes-file-reader/
├── core/                         # ★ 核心 Python 模块
│   ├── pes_decrypt.py            # 解密/加密器（MASTERKEY_PES21 + MT19937）
│   ├── pesfile.py                # 存档结构解析器（EDIT/ML，CLI 导出 CSV+JSON）
│   ├── app.py                    # 只读浏览 UI（本地服务 + ui/index.html）
│   ├── edit_player_abilities.py  # EDIT 240B 能力值/隐藏机制解码
│   ├── ct_fieldmap.py            # 社区 Cheat Table → 字段字典（outputs/pes_player_fieldmap.md）
│   └── ...                       # 分析/探针/导出脚本
├── exe/                          # ★ exe 逆向工具族（capstone，flat 口径）
│   ├── exe_dis_func.py           # 反汇编 + xref
│   ├── exe_aobscan.py            # CT AOB 字节签名定位
│   ├── exe_pe_const.py           # PE 段感知常量解析（段映射/RIP 目标）
│   ├── exe_struct_fields.py      # 从拷贝代码反推 struct 布局
│   ├── exe_table_map.py          # 批量表同步函数 → 表清单
│   └── ...                       # 反汇编/扫描/探测工具
├── bl_ml/ replay/ probe/        # 历史探针脚本（可复现当时结论）
├── cpk/                          # CPK 解包/扫描（dt10/dt11/dt16）
├── tools/                        # 第三方逆向工具（dnSpy 等，不入库）
├── resources/                    # 目标 exe + 社区 CT + 游戏资源
├── outputs/                      # 解析/导出产物（CSV、报告、字段字典）
├── ui/index.html                 # 只读浏览 UI 前端
├── docs/
│   ├── HANDOFF_v3.md             # 最新交接文档
│   ├── exe-save-layout.md        # ★ exe 侧结构/机制主文档（含 ML 隐藏机制）
│   ├── bl_ml_structure.md        # BL/ML data 结构
│   ├── replay_structure.md       # REPLAY data 结构
│   ├── community_*.md            # 社区逆向成果归档
│   └── ...
├── tests/test_roundtrip.py       # 解密→加密 roundtrip 测试（unittest）
├── third_party/pesXdecrypter/    # 原版 C 源码 + 编译产物 + NOTICE
├── examples/                     # 原始加密存档（只读，不入库，需自备）
└── decoded/                      # 解密中间产物（不入库，由导出脚本生成）
```

说明：

- `examples/` 与 `decoded/` 已 `.gitignore`，**不入 git**。克隆后需自行放入存档样例
  （根目录放 `BL*`/`ML*`/`EDIT*`，回放放 `rep/REPLAY*`），缺样本时相关测试自动跳过。
- 逆向结论统一以 **exe 代码位置 + 真实存档数据**双证据为准（项目铁律），不做猜测式结论。

## 环境要求

- Python 3（本机验证于 3.13），核心解析仅标准库；exe 工具需
  `pip install capstone`（`resources/Patch 1.07.00/.../PES2021.exe` 为分析目标）。
- 可选：MinGW gcc（仅当需要重新编译 C 工具时）。

## 用法

### 1. 解密存档

```powershell
python core\pes_decrypt.py examples\BL00000000        # 打印文件头摘要/熵校验
python core\pes_decrypt.py                            # 默认解密 examples\rep\REPLAY00000000
```

作为模块：`decrypt()` / `encrypt()` 互为逆操作，见脚本 docstring。

### 2. 解析存档结构

```powershell
python core\pesfile.py                 # 解析 decoded/ 下全部 EDIT/ML/BL → outputs/*.csv
python core\pesfile.py --decrypt       # 先解密 examples/ 到 decoded/ 再解析
python core\pesfile.py EDIT ML0        # 只解析指定存档（ML0 = ML00000000）
```

### 3. 只读浏览 UI

```powershell
python core\app.py                     # 启动本地服务，浏览器打开 ui/index.html
```

### 4. exe 逆向工具示例

```powershell
python exe\exe_dis_func.py "<exe路径>" 0x012E40E0 0x012E40E1 xref   # 反查调用者
python exe\exe_aobscan.py --file aob_sigs.txt --around 6            # CT AOB 定位
python exe\exe_pe_const.py --rip 0x1533156 0x10102d2                # 段感知常量
```

> 注：`resources/` 下的目标 exe 与游戏本体需自行准备（不入库）。exe 工具按
> "flat 文件偏移即地址" 口径反汇编；绝对常量解析需用 `exe_pe_const.py`（段映射）。

### 5. 运行测试

```powershell
python -m unittest discover tests
```

## 文档索引

| 文档 | 内容 |
|------|------|
| [docs/HANDOFF_v3.md](docs/HANDOFF_v3.md) | 最新交接（进展、约定、结论） |
| [docs/exe-save-layout.md](docs/exe-save-layout.md) | **exe 侧主文档**：装载管线 / 加密头 / ML 动态机制 / 字段图 |
| [docs/bl_ml_structure.md](docs/bl_ml_structure.md) | BL/ML data 结构 |
| [docs/replay_structure.md](docs/replay_structure.md) | REPLAY data 结构 |
| [docs/community_findings.md](docs/community_findings.md) | 社区逆向成果归档 |
| [third_party/pesXdecrypter/NOTICE.md](third_party/pesXdecrypter/NOTICE.md) | 第三方源码来源与许可 |

## 约定

- `examples/` 目录**只读**，任何分析一律不改动原始样例。
- 结论 = exe 代码位置 + 真实存档数据双证据；无法验证处如实标注"未展开/负结果"。
- 修改器实操验证（解密 → 改 data → 加密 → 游戏能读）时，注意 data 头部
  `+0x30~0x50` 的 32 字节哈希区是否需同步更新（目前观察游戏似乎不校验）。
