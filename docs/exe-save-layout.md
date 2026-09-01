# PES2021 存档结构 —— 正版 1.07.00 exe 逆向实证

目标文件：`resources/Patch 1.07.00/eFootball PES 2021/PES2021.exe`
（468,030,464 字节；构建路径 `d:\pes2021\patch10700\...` 证实为官方 1.07.00，非模组改版）

本文所有结论都有**代码位置 + 真实存档数据**两重证据，不用"大概是"。

---

## 0. 回答那个问题：已知密钥到底能不能帮上 exe 逆向？

**能，但不是靠密钥的字节，是靠它背后的算法。**

| 之前的做法 | 结果 |
|---|---|
| 拿 64 字节主密钥去 exe 里全段搜（含 32/16/8/4 字节切分、正序倒序各种变体） | **0 命中**（`exe_key_hunt.py`，已入库） |
| 假设密钥被编译器拆成若干段内联进代码 | **证伪**（8 字节块 0 命中，4 字节块唯一命中是噪声，无聚类） |

因为这是官方未改版 exe，"模组把密钥抹掉了"这个解释不成立。真实原因是：

> **主密钥从不以常量形式存在于 exe 中 —— 它是在运行时作为数据（64 字节，喂给 `std::seed_seq`）传进来的。**

但密钥的**算法**必然在 exe 里。于是改用算法常量当"鱼钩"去钓代码：

| 常量 | 含义 | exe 中命中数 |
|---|---|---|
| `1664525` (0x0019660D) | `init_by_array` 的 LCG 乘子 | **1 处**（0x14151B4） |
| `1566083941` (0x5D588B65) | `init_by_array` 的 LCG 增量 | **1 处**（0x141522F） |
| `1812433253` (0x6C078965) | `init_genrand` 乘子 | 14 处 |
| `0x9908B0DF` | MT19937 MATRIX_A | 6 处 |

两个 LCG 常量在 468MB 里**各只出现一次**，且相距仅 123 字节 → 一次锁定
MSVC `std::mt19937` + `std::seed_seq` 实现区 **`0x1414CE0 ~ 0x1415400`**。

再从这一区反查 `call rel32` 交叉引用（扫 1,727,092 个 `E8` 字节，期望误报 0.6），
得到 14 个调用点 —— 存档加解密例程就在其中。

**方法论沉淀**：解不出"数据"时，改解"算法"。密码学常量在二进制里极其稀有，
是比任何字符串都可靠的定位锚点。

---

## 1. 定位到的函数（文件偏移，flat image 口径）

| 偏移 | 大小 | 身份 | 判定依据 |
|---|---|---|---|
| `0x140FC30` | 341B | **`crypt_stream`** | 逐指令与 `pes_decrypt.py` 完全一致（见 §2） |
| `0x140F92D` | 229B | **`crypt_header`** | 从 `input[256:320]` 取 64B、`r9d=0x140`(320) |
| `0x140FEA5` | 227B | `crypt_header` 的加密侧对应物 | 与上一项结构同构 |
| `0x14115F0` | 1513B | **存档解密主流程** | 含 `add r14, 0xD0`(208)、`0x40`(64)、`0x10`(16) |
| `0x1412C1A` | 1089B | **存档加密主流程** | 5 个 `crypt_stream` 调用，块序号 xor 0/1/2/3 |
| `0x1414CE0` | — | `mt19937::genrand_int32` | 被 `crypt_stream` 循环调用 |
| `0x1415110` | — | `seed_seq` 初始化（`init_by_array`） | `crypt_stream` prologue 内调用 |
| `0x140DFF0` | — | `reverse_longs` / `xor_repeating_blocks` | `crypt_header` 内带 `r8d=0x40`(64) 调用两次 |

---

## 2. `crypt_stream` 逐指令验证（`0x140FC30`）

### 签名

```
rcx = key   (const void*, 64 字节)
rdx = out   (void*)
r8  = in    (const void*)
r9  = len   (字节数)
```

### prologue 里的三个决定性常量

```asm
0x140FC40: mov rax,[rip+0x2102da9] ; xor rax,rsp ; mov [rsp+0xa20],rax   ; /GS cookie
0x140FC67: mov r8d, 0x9C0          ; 624×4 = 2496  → MT19937 状态数组大小
0x140FC75: call 0x15A2F50          ; memset(mt_state, 0, 0x9C0)
0x140FC7A: mov r8d, 0x10           ; key 长度 = 16 × uint32 = 64 字节主密钥
0x140FC80: mov dword [rsp+0xA00], 0x271   ; mti = 625 = N+1
0x140FC8B: mov rdx, rbx            ; rdx = 第1参数 key
0x140FC93: call 0x1415110          ; init_by_array(mt, key, 16)
```

### 主循环 —— 与 `pes_decrypt.py` 一字不差

```asm
0x140FCA5: lea rcx,[rsp+0x40] ; mov ebx,4
0x140FCAA: call 0x1414CE0     ; 预热：c0..c3 = 4 × genrand_int32()
0x140FCBA: jne  0x140FCA5     ;   ↳ 存于 rsp+0xA10 / +0xA14 / +0xA18 / +0xA1C

0x140FCE0: shr rbx, 2         ; 迭代次数 = len >> 2
0x140FD10: mov r11d,[r12+r15] ; 读 input[i]
0x140FD19: call 0x1414CE0     ; c4 = genrand_int32()
0x140FD1E: xor edi, r14d      ; ┐
0x140FD25: xor edi, ebp       ; │
0x140FD27: xor edi, esi       ; │ out = c4 ^ c3 ^ c2 ^ c1 ^ c0 ^ input[i]
0x140FD29: xor edi, eax       ; │
0x140FD2B: xor edi, r11d      ; ┘
0x140FD2E: mov [r15-4], edi   ; 写回
0x140FD38: ror edi, 0xF       ; c0 = ror(c1, 15)
0x140FD3D: rol r14d, 0xB      ; c1 = rol(c2, 11)
0x140FD43: rol ebp, 7         ; c2 = rol(c3, 7)
0x140FD46: ror esi, 0xD       ; c3 = ror(c4, 13)
```

对照 `pes_decrypt.py:136-162`：

```python
outv = (c4 ^ c3 ^ c2 ^ c1 ^ c0 ^ inv) & 0xffffffff
c0 = ror(c1, 15); c1 = rol(c2, 11); c2 = rol(c3, 7); c3 = ror(c4, 13)
```

**完全一致。** 密钥轮转是"链式滚动"的（每轮丢弃 c0、补入新 c4），这也是
对称函数能同时用于加解密的原因。

### 尾部（`len & 3` 的余数字节）

```asm
0x140FD62: and r13d, 3
0x140FD7C: call 0x15A2F38   ; memcpy(栈缓冲, src, rem)
0x140FD86: call 0x1414CE0   ; 再取一个 c
0x140FD8B~FD9A: 四次 xor    ; 与 c0..c3 异或
0x140FD9C: xor [rsp+0x20], eax
0x140FDA9: call 0x15A2F38   ; memcpy 写回
```

即不足 4 字节的尾部单独走一次"复制 → 异或 → 复制回"，与 Python 实现的
`rv.to_bytes(4,"little")[:rem]` 语义等价。

---

## 3. `crypt_header` —— 320 字节加密头（`0x140F92D`）

```asm
0x140F8C2: movups xmm0,[rcx+0x120]   ; 读 input[288:304]
0x140F8CE: movups xmm1,[rcx+0x130]   ; 读 input[304:320]
...
0x140F934: movups xmm0,[rbx+0x100]   ; 读 input[256:272]
0x140F945: movups xmm1,[rbx+0x110]   ; 读 input[272:288]
0x140F917: mov r9d, 0x140            ; len = 320
0x140F92F: call 0x140FC30            ; crypt_stream
```

4 次 16 字节读取覆盖 `input[256:320]` 共 64 字节 —— 正是
`header_key = input_[256:256+64]`（`pes_decrypt.py:166`）。**实证吻合。**

---

## 4. 存档整体布局（exe + 8 个真实存档双重验证）

```
偏移 0                                                    偏移 end
├── 加密头 ENCRYPTION HEADER ── 320 B ──────────────────────┤
│   crypt_header: header_key = input[256:320] (64B)         │
│                 → crypt_stream(header_key, input, 320)    │
│   [0:64]    rolling_key 种子                              │
│   [64:320]  与 rolling_key 循环异或 → 最终 rolling_key     │
├── 文件头 FILE HEADER ── 208 B ────────────────────────────┤
│   crypt_stream(rolling_key ⊕ 208, blob[320:528], 208)     │
│   ⊕208 由 0x1412BA6 的 `xor rax, 0xD0` 实证               │
│   长度 208 由 0x14115F8 的 `add r14, 0xD0` 实证           │
├── desc   ── 384 B，写死 ─────────────────────────────────┤  块序号 ⊕0
├── logo   ── 变长（文件头 logoSize）────────────────────── ┤  块序号 ⊕1
├── data   ── 变长（文件头 dataSize）────────────────────── ┤  块序号 ⊕2
└── serial ── serialLength × 2 B（UTF-16）─────────────────┘  块序号 ⊕3
```

**每块的密钥变换**：把 64 字节 rolling_key 按 8 字节一组，逐 qword 与块编号异或。
- 文件头：xor `0xD0` = 208（用了它自己的长度，不是序号）
- desc / logo / data / serial：xor `0` / `1` / `2` / `3`

`0x1412E1F` 的 `add r9, r9`（长度 ×2）实证 serial 按 UTF-16 计长。

### 文件头 208B 字段（`parse_file_header`）

| 偏移 | 长度 | 字段 | 实测值（EDIT00000000） |
|---|---|---|---|
| 0 | 64 | mysteryData = **reverse_longs(主密钥)**，见 §5 | 所有存档相同（常量） |
| 64 | 4 | dataSize | 10,995,800 |
| 68 | 4 | logoSize | 14,235 |
| 72 | 4 | descSize | **384**（恒为 384，见下） |
| 76 | 4 | serialLength | 45（字符数，非字节数） |
| 80 | 64 | hash | 未解（见 §6，已排除简单哈希） |
| 144 | 32 | fileTypeString | `"BL"` / `"EDIT"` / `"ML"` |
| 176 | 32 | gameVersionString | `"eFootball PES 2021 SEASON UPDATE"` |

**exe 独立印证**：解密主流程 0x14115F0 的文件头基址 = `rbp+0x90`，exe 内每一处访存
都精确对应上表偏移 —— 不依赖任何 Python 实现：

```asm
cmp dword [rbp+0xD8], 0x180   ; 文件头+72 = descSize 必须 == 384
lea rcx, [rbp+0x120]          ; 文件头+144 = fileTypeString
lea rcx, [rbp+0x140]          ; 文件头+176 = gameVersionString
mov [rbp+0xD0] = dataSize     ; 文件头+64
```

该校验函数在 `0x140F200`（全 exe 仅 `0x141161B` 一处调用），先比文件头[0:64]与调用者
传入的 64 字节（即 reverse_longs 主密钥），再比 descSize==384、fileType、gameVersion。

---

## 5. 四块各自的语义（本轮新确认）

用 `exe_validate_layout.py` 在 8 个存档上实测：

| 存档 | 总长 | desc | logo | data | serial | Σ+528 == 总长 |
|---|---|---|---|---|---|---|
| BL00000000 | 19,564,292 | 384 | 16,145 | 19,547,145 | 90 | ✅ 差 +0 |
| BL00000001 | 19,563,862 | 384 | 16,145 | 19,546,715 | 90 | ✅ |
| BL00000002 | 19,537,735 | 384 | 16,145 | 19,520,588 | 90 | ✅ |
| BL00000003 | 19,535,847 | 384 | 16,145 | 19,518,700 | 90 | ✅ |
| EDIT00000000 | 11,011,037 | 384 | 14,235 | 10,995,800 | 90 | ✅ |
| ML00000000 | 19,759,699 | 384 | 16,284 | 19,742,413 | 90 | ✅ |
| ML00000001 | 19,759,485 | 384 | 16,284 | 19,742,199 | 90 | ✅ |
| ML00000002 | 19,628,604 | 384 | 16,284 | 19,611,318 | 90 | ✅ |
| ML00000013 | 19,759,442 | 384 | 16,284 | 19,742,156 | 90 | ✅ |

### mysteryData（64 B，固定）= reverse_longs(主密钥)，密钥校验副本

前 8 字节：`f8 24 77 43 66 d8 61 90` = `MASTERKEY_PES21[0:8]` 的逐字节镜像。
实证：`reverse_longs(mysteryData, MASTERKEY_PES21)` 输出与文件头[0:64] **逐字节相等**。

它是解密后明文存在文件头里的**主密钥变换副本**，游戏在加载时校验它是否等于
`reverse_longs(MASTERKEY)`，不等则视为"非本版本密钥加密 / 损坏"而拒绝 —— 这正解释了
PES 各年主密钥不同会导致老存档无法加载的机制。注意它不泄露主密钥（单向变换，
且解密文件头本身就需要主密钥，不能反推）。

### desc（384 B，固定）= 存档在游戏内显示的名字

UTF-8 字符串，其后全部填零（零字节占比 96.9%）。

| 存档 | desc 内容 |
|---|---|
| BL00000000~03 | `一球成名 01` ~ `一球成名 04` |
| EDIT00000000 | `编辑数据` |
| ML00000000~13 | `大师联赛 01` ~ `大师联赛 20` |

**exe 侧证据**：`0x1412C5D: mov r9d, 0x180`（= 384）写死，且源地址是结构内的
内联缓冲（`lea r8,[rsi+0x20]`）而非指针 —— 与"定长内联"一致。
`pes_decrypt.py` 一直把它当变长字段读，实测恒为 384，可视为常量。

### logo（变长）= 缩略图
14~16 KB，三个存档类型各自固定（BL 16145 / EDIT 14235 / ML 16284），
随存档内容变化很小 —— 是游戏内存档列表显示的预览图。内部结构待解。

### data（变长）= 主数据
占文件 99.9% 以上，是项目既往工作（球队块、事件表、赛程、球员库…）的全部载体。

### serial = **Windows 用户 SID（UTF-16）**

全部 8 个存档的 serial 均为：

```
S-1-5-21-1435437277-1052317143-1964327295-500
```

这是标准 Windows 安全标识符格式 `S-1-5-21-<3×32位>-<RID>`，
末尾 `-500` 是**内置 Administrator 账户**的 RID。

**exe 侧证据**：

| 检索项 | 结果 |
|---|---|
| 导入 `ConvertSidToStringSidW` | ✅ 找到（0x339E52E） |
| `GetTokenInformation` / `OpenProcessToken` | ❌ 无 |
| `LookupAccountSidW` | ❌ 无 |
| 字面量 `"S-1-5"` / `"S-1-5-21"`（ASCII 与 UTF-16） | ❌ 无 |

游戏不自己拼 SID 字符串，而是拿一个 SID 结构交给 `ConvertSidToStringSidW`
转成宽字符串写进存档 —— 这正是 serial 块的来源。

**对照实验**：本机当前用户 SID 为
`S-1-5-21-1986812235-1236317143-1875118348-1001`（`-1001` = 首个普通用户），
与存档里的 `-500` 不同 ⇒ 这批存档并非在当前账户下生成。
结论：serial 绑定的是**创建存档时的 Windows 账户**，这就是存档不能跨账户/跨机器
直接通用的机制。

---

## 6. 待解

### hash[80:144]（64 B）—— 已做哪些排除

实测：9 个存档全部非零、各不同、高熵；解密主流程 0x14115F0 对其**零访存**
（加载时不参与校验）；加密流程后段有 `call 0x140F3A0`（尚未确认是否算此 hash）。

穷举碰撞（共 ~700 组合）均未命中，已排除：

- 无密钥：sha512/sha384/sha256/sha3/blake2b 作用于 `data` / `desc+logo+data` /
  `desc+logo+data+serial` / `blob[528:]` 密文 / `logo+data` / `data+serial` /
  `blob 整个文件` / `blob[:528]+data密文` 等
- 带密钥拼接：以上数据分别前/后接 `mysteryData` / `rolling_key` / `MASTERKEY_PES21` /
  `encHeader[0:64]` / `serial` / `fileHeader[0:80]` / `fileHeader[144:208]` / `desc`
- HMAC（sha512/sha256/sha1）以上述密钥作用于上述数据
- 拼接结构：前 16/20/32 或 后 32 字节不等于任何 MD5/SHA1/SHA256 输出

候选方向（未验证）：

- 输入可能是 data 的**带 salt 子串 / 分块链式哈希**，salt 未知
- hash 段可能是**加密的随机 nonce**（每次保存重算，仅作版本/防篡改标记，不参与加载校验）
- 计算点在 `0x140F3A0`（加密侧），应反汇编确认其输入输出

### 其余待解

- logo 块的图像编码（尺寸/格式/调色板）
- gameVersionString 已确认参与校验（0x140F200 比 gameVersionString 与常量串）
- serial 不匹配时游戏的具体行为（拒绝加载 / 提示 / 只读）

复现脚本（均已入库）：

```bash
python exe_mt_hunt.py    "<exe>"          # 常量鱼钩定位 MT19937
python exe_xref_mt.py    "<exe>"          # 反查谁调用了 MT19937
python exe_dis_callers.py "<exe>" 0x140FC93 ...   # 调用点 → 所属函数 + 常量指纹
python exe_dis_func.py   "<exe>" 0x140FC30 0x140FDE6 xref   # 反汇编 + 反查调用者
python exe_validate_layout.py examples    # 在真实存档上核对布局
```

> 需要 capstone：`pip install capstone`（本项目用隔离 venv，
> `C:\Users\34788\.workbuddy\binaries\python\envs\default\Scripts\python.exe`）
