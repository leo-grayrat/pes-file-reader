# PES2021 存档逆向 — 工作交接

> 本文档记录截至被打断时的进展，供后续接手者快速续上。

## 目标

探索性逆向 PES2021（实况足球2021）存档文件，最终做出**外置解析器甚至修改器**。三类存档位于 `examples/`：

- **回放** `rep/REPLAY0000000*`：50 个，各 5,383,087 字节
- **大师联赛** `ML0000000*`：4 个，约 19.7 MB
- **一球成名** `BL0000000*`：4 个，约 19.5 MB

均无后缀。

## 约定与指令

- **只读分析，绝不修改 `examples/` 下任何样例文件**；改动只发生在仓库里新建的脚本/文档/第三方源码上。
- **勤提交 git**，按阶段及时 commit。
- 交流用简体中文；主动、连续、详细汇报进展。
- 技术栈决策：**直接编译原版 C 源码**（`the4chancup/pesXdecrypter`，public domain）作为正式工具，Python 版保留作对拍。
- `examples/`（约 426.3 MB，58 个文件）和 `decoded/`（解密中间产物）均不入 git（已加 `.gitignore`）。

## 关键发现

### 加密层（已完全破解）

1. 三类存档都是 **MT19937 流加密 + 链式滚动密钥**，每文件独立密钥（解释了"50 个回放样本零恒定字节、熵≈8.0"）。
2. **PES2021 主密钥（64 字节）** 在公开项目 `the4chancup/pesXdecrypter` 的 `src/masterkey.c` 里（`MasterKeyPes21`）。
3. 文件结构：`320 字节加密头 + 208 字节文件头(FileHeader) + description + logo + data + serial`。
4. 解密后 `fileTypeString` 分别为 `REPLAY`/`BL`/`ML`，`gameVersionString = "eFootball PES 2021 SEASON UPDATE"`，块大小校验零误差。
5. 加解密对称，`decrypt→encrypt` roundtrip 逐字节还原 → **修改器技术闭环成立**。

### BL/ML data 块结构（初步逆向，已验证）

**头部前 0x100 字节**：

| 偏移 | 值 | 说明 |
|------|-----|------|
| `+0x00` | 11 / 10 / 13 | 类型标识（BL / ML / REPLAY） |
| `+0x04` | 80 | 固定 |
| `+0x08` | 0x015B6D44 | BL/ML 相同，疑似格式版本常量 |
| `+0x0C` | 10702 | 固定 |
| `+0x10` / `+0x14` | 700 / 700 | **球队记录数** |
| `+0x20` | 98 | 固定 |
| `+0x30~0x50` | 每存档不同 | 32 字节哈希/校验（diff 验证；游戏似乎不校验） |
| `+0x50` | 0x194000 | 疑似区块偏移指针，指向 data 内另一区块 |
| `+0x98` | "ARS" | 字符残留，疑似签名/版本串残余 |

**球队记录数组**：

- 从 `0x100` 开始，每条 `0x690 (1680)` 字节，共 700 条。
- 队名/助威口号在记录内 `+0x55` 处（如 `GUNNERS` / `SOB ON THE TYNE` / `CHELSEA` / `LCFC FOXES` 等英超队口号，明文 ASCII）。
- 球队区结束于 `0x100 + 0x690*700 = 0x11F2C0`，其后是大量 `0` padding。

**其他**：

- `0x194000` 处有结构化数据（`01 03 09 02 01 FF...` 模式，疑似阵型/战术/球衣编号表）。
- data 尾部是 `FF...FF` 填充 + `00 00 00 00 09 83 E8 82`。
- 样本 diff：BL0 vs BL1 变化 7.08%，ML0 vs ML13 变化 8.77%；变化点呈 `0x690` 周期（每条球队记录内 `+0x33F~+0x34C` 附近有动态字段，疑似球队赛季状态）；头部 `+0x30~0x50` 哈希区全变。

### 环境

本机有 gcc/g++ 13.2 (MinGW-W64)、cmake 4.3、ninja、Python 3.13。`git clone` 走 127.0.0.1 代理失败，但 `webfetch` 访问 `raw.githubusercontent.com` / `api.github.com` 可用。

## 已完成

已完成并提交 git（5 个 commit：`924e761`, `e5ad1c2`, `760e74b`, `f16b5a1`, `321e365`）：

1. **探查脚本** `probe.py` / `analyze.py` / `check_bl_ml.py`：确认三类存档整体加密。
2. **Python 解密器** `pes_decrypt.py`：完整复刻 MT19937+链式密钥算法，含 `decrypt()` 和 `encrypt()`，roundtrip 逐字节验证通过。
3. **导出脚本** `export_data.py`：将样本解密后的 data 块导出到 `decoded/`；当前 `decoded/` 共 27 个 `.data`（8 个 BL/ML + 19 个回放），`_headers.json` 只保留 7 个关键样本（BL00000000/01、ML00000000/13、REPLAY00000000/01/02）的头信息。
4. **编译原版 C 工具**（`third_party/pesXdecrypter/`）：落盘全部 8 个源文件 + `NOTICE.md`，用 `gcc -DUSE_PES21_MASTER_KEY -O2` 编译出 `decrypter.exe` / `encrypter.exe`；两处最小适配（`MasterKeyZero` 补 extern、`writeFileDir` 用 Windows API `GetFileAttributesA`/`CreateDirectoryA`）；实测解密结果与 Python 版逐字节一致。
5. **BL/ML 逆向初步**：`bl_ml_analyze.py` + `probe2.py`，已摸清头部结构、球队记录布局（0x100 起、0x690 步长、700 条、队名在 +0x55）。

## 进行中（被打断处）

正在做 **BL/ML data 结构逆向**。刚跑完 `probe2.py`，拿到了 `0x194000` 偏移处内容、球队区结束后的 padding、data 尾部等线索。

**下一步本要**：

- 深化球员数据区定位（球队区之后 / `0x194000` 指向的区块）
- 整理 `docs/bl_ml_structure.md` 结构文档
- 完善 `bl_ml_analyze.py` 加记录切分功能

## 待完成

- **BL/ML 逆向收尾**：`docs/bl_ml_structure.md` + 球员/资金/赛程字段定位。
- **REPLAY 回放 data 逆向**：`replay_analyze.py` + `docs/replay_structure.md`，三样本 diff 找固定区/动态区、参赛两队/比分/事件流。
- **README.md**：汇总项目目标、算法与密钥来源、解密/编译用法、三类存档结构进展。
- **修改器实操验证**：解密→改 data→加密→游戏能读（注意头部 `+0x30~0x50` 哈希是否需更新）。

## 相关文件 / 目录

```
pes-file-reader/
├── .gitignore                    # 排除 .arts/ .codeartsdoer/ __pycache__/ decoded/ examples/ .merkle-snapshot.json
├── probe.py                      # 回放文件初探（hexdump/字符串/diff）
├── analyze.py                    # 熵分析 + 全样本共识分析
├── check_bl_ml.py                # BL/ML 加密验证
├── pes_decrypt.py                # ★ Python 解密/加密器（含 MASTERKEY_PES21、MT19937、decrypt/encrypt）
├── export_data.py                # 导出解密 data 块到 decoded/（支持命令行过滤子集）
├── bl_ml_analyze.py              # ★ BL/ML 结构逆向分析（头部/字符串/diff，待深化记录切分）
├── probe2.py                     # 补充探测（头部偏移指针、0x194000、球员区）
├── third_party/pesXdecrypter/    # ★ 原版 C 源码 + 编译产物
│   ├── NOTICE.md                 # 来源/许可/本地适配改动说明
│   ├── decrypter.exe             # 编译产物（PES2021 版）
│   ├── encrypter.exe             # 编译产物
│   └── src/                      # crypt.c/h masterkey.c/h mt19937ar.c/h decrypter.c encrypter.c
├── decoded/                      # 解密中间产物（不入库）：BL/ML/REPLAY 的 .data + _headers.json
├── examples/                     # 原始存档（不入库）
└── （待创建）
    ├── docs/bl_ml_structure.md
    ├── replay_analyze.py
    ├── docs/replay_structure.md
    └── README.md
```

## 继续工作的建议入口

1. 先完成 `docs/bl_ml_structure.md`（基于已发现的头部/球队记录结构）。
2. 再启动 REPLAY 逆向：用 `pes_decrypt.py` 或 `decrypter.exe` 解密 `examples/rep/REPLAY0000000*`，三样本 diff 找固定区/动态区。
3. 最后写 `README.md`。