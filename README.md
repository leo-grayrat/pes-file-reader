# PES2021 存档逆向（pes-file-reader）

对《实况足球 2021》（eFootball PES 2021 SEASON UPDATE）的三类存档文件进行探索性逆向分析，
最终目标是做出**外置解析器与修改器**：

- **回放存档** `rep/REPLAY000000*`（50 个样本，各 5,383,087 字节）
- **大师联赛存档** `ML000000*`（约 19.7 MB）
- **一球成名存档** `BL000000*`（约 19.5 MB）

三类文件均无后缀、整体加密。加密层已完全破解：
**MT19937 流加密 + 链式滚动密钥**，每文件独立密钥；加解密对称，`decrypt → encrypt` roundtrip 可逐字节还原，
修改器技术闭环成立。算法与 PES2021 主密钥来自公开项目
[the4chancup/pesXdecrypter](https://github.com/the4chancup/pesXdecrypter)，详见
[third_party/pesXdecrypter/NOTICE.md](third_party/pesXdecrypter/NOTICE.md)。

> 工作进展与历史背景见 [docs/HANDOFF.md](docs/HANDOFF.md)。

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
| +144 | `fileTypeString` | 类型标识：`REPLAY` / `BL` / `ML`（32 字节，NUL 填充） |
| +176 | `gameVersionString` | `eFootball PES 2021 SEASON UPDATE`（32 字节） |

故文件总长 = `320 + 208 + descSize + logoSize + dataSize + serialLength × 2`。

## 仓库结构

```
pes-file-reader/
├── pes_decrypt.py                # ★ Python 解密/加密器（MASTERKEY_PES21 + MT19937 + decrypt/encrypt）
├── export_data.py                # 批量导出解密后的 data 块到 decoded/
├── bl_ml_analyze.py              # BL/ML data 结构逆向分析（头部/字符串/diff）
├── bl_ml_probe3~6.py             # BL/ML 结构进阶探查（区块定位、记录切分等）
├── replay_analyze.py             # 回放（REPLAY）结构分析（多样本 diff、固定区/动态区）
├── probe.py / probe2.py          # 探查脚本（hexdump、熵、偏移指针等）
├── analyze.py / check_bl_ml.py   # 熵分析、加密验证
├── tests/
│   └── test_roundtrip.py         # 解密→加密 roundtrip 与文件头一致性测试（unittest）
├── third_party/pesXdecrypter/    # 原版 C 源码 + 本地编译产物
│   ├── NOTICE.md                 # 来源/许可/本地适配改动说明
│   ├── decrypter.exe             # 编译产物（PES2021 版）
│   ├── encrypter.exe             # 编译产物（PES2021 版）
│   └── src/                      # crypt.c/h masterkey.c/h mt19937ar.c/h decrypter.c encrypter.c
├── docs/
│   ├── HANDOFF.md                # 工作交接文档（进展、约定、已验证结论）
│   ├── bl_ml_structure.md        # BL/ML data 结构文档（已成稿）
│   └── replay_structure.md       # REPLAY data 结构文档（已成稿）
├── examples/                     # 原始加密存档样例（只读，不入库，需自备）
└── decoded/                      # 解密中间产物（不入库，由 export_data.py 生成）
```

说明：

- `examples/`（约 350 MB）与 `decoded/` 均已加入 `.gitignore`，**不入 git**。
  克隆仓库后需自行把存档样例放入 `examples/`（根目录放 `BL*`/`ML*`，回放放 `examples/rep/REPLAY*`），
  测试在样本缺失时会自动跳过。
- `third_party/pesXdecrypter` 源码许可：`crypt.*`、`masterkey.*`、`decrypter.c`、`encrypter.c` 为
  public domain（unlicense）；`mt19937ar.c/h` 为 BSD-3（原作者 T. Nishimura & M. Matsumoto）。
  本地做了三处最小编译适配（不影响算法逻辑），详见 [NOTICE.md](third_party/pesXdecrypter/NOTICE.md)。

## 环境要求

- Python 3（本机验证于 3.13），**仅使用标准库**，无第三方依赖。
- 可选：MinGW gcc（仅当需要重新编译 C 工具时）。

## 用法

### 1. Python 解密器 `pes_decrypt.py`

解密单个存档并打印文件头摘要、data 熵等校验信息：

```powershell
python pes_decrypt.py examples\BL00000000          # 指定文件
python pes_decrypt.py                              # 默认解密 examples\rep\REPLAY00000000
```

作为模块使用时，`decrypt()` / `encrypt()` 互为逆操作：

```python
import pes_decrypt as p

blob = open("examples/BL00000000", "rb").read()
r = p.decrypt(blob)            # 解密，返回 encHeader/fileHeader/description/logo/data/serial 各块
print(r["hdr"]["dataSize"])    # 文件头字段
open("BL00000000.mod", "wb").write(p.encrypt(r))   # 重新加密回完整文件（逐字节可逆）
```

### 2. 批量导出 `export_data.py`

把 `examples/` 下所有 BL/ML/REPLAY 样本解密后的 data 块导出到 `decoded/`，
头信息汇总写入 `decoded/_headers.json`：

```powershell
python export_data.py                              # 全量导出
python export_data.py BL00000000 rep/REPLAY00000000   # 只导出指定子集（相对 examples 的路径）
```

### 3. C 工具 `third_party/pesXdecrypter/`

参数格式（见源码 `decrypter.c` / `encrypter.c`）：

```powershell
# 解密：输入存档文件 + 输出目录（可选第 3 参数为自定义 64 字节主密钥文件）
third_party\pesXdecrypter\decrypter.exe examples\ML00000000 out_dir [master_key_file]

# 加密：输入目录 + 输出存档文件（可选第 3 参数同上）
third_party\pesXdecrypter\encrypter.exe out_dir ML00000000.enc [master_key_file]
```

解密后输出目录包含 6 个块：`encryptHeader.dat`、`header.dat`、`description.dat`、
`logo.png`、`data.dat`、`version.txt`，其中 `data.dat` 即明文存档主体。

如需重新编译（MinGW，须带 `-DUSE_PES21_MASTER_KEY`）：

```powershell
gcc -DUSE_PES21_MASTER_KEY -O2 -o decrypter.exe src/crypt.c src/masterkey.c src/mt19937ar.c src/decrypter.c
gcc -DUSE_PES21_MASTER_KEY -O2 -o encrypter.exe src/crypt.c src/masterkey.c src/mt19937ar.c src/encrypter.c
```

### 4. 运行测试

在仓库根目录执行（样本缺失时相应用例自动跳过）：

```powershell
python -m unittest discover tests
# 或
python tests\test_roundtrip.py
```

## 文档索引

| 文档 | 状态 |
|------|------|
| [docs/HANDOFF.md](docs/HANDOFF.md) | 工作交接（进展、约定、已验证结论） |
| [docs/bl_ml_structure.md](docs/bl_ml_structure.md) | BL/ML data 结构（已成稿） |
| [docs/replay_structure.md](docs/replay_structure.md) | REPLAY data 结构（已成稿） |
| [third_party/pesXdecrypter/NOTICE.md](third_party/pesXdecrypter/NOTICE.md) | 第三方源码来源与许可 |

## 约定

- `examples/` 目录**只读**，任何分析一律不改动原始样例。
- 修改器实操验证（解密 → 改 data → 加密 → 游戏能读）时，注意 data 头部 `+0x30~0x50` 的
  32 字节哈希区是否需要同步更新（目前观察游戏似乎不校验）。
