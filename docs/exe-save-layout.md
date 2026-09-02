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
| `0x140DFF0` | — | **`xor_repeating_blocks`** | 保存侧 `0x1412B77` 以 `r8d=0x100`(256) 调用，折叠摘要表成 rolling_key；`crypt_header` 内另以 `r8d=0x40`(64) 调用两次 |
| `0x140E160` | — | **一次性 SHA-512 便捷函数** | 8 个 `movabs` 装载标准 SHA-512 IV（见 §7.2），ctx 大小 `0xD0`(208) |

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
│   明文内容（见 §8.1）：                                    │
│   [0:64]/[64:128]/[128:192]/[192:256]                     │
│       = SHA-512(desc) / SHA-512(logo)                     │
│         / SHA-512(data) / SHA-512(serial)                 │
│   [256:320] = 随机 salt（= header_key 源，明文透传）       │
│   rolling_key 基 = 上述四项摘要 ^ salt 折叠（见 §8.3）     │
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
| 80 | 64 | hash | **64 B 随机 nonce**：`CryptGenRandom`，仅防篡改标记，加载不校验（见 §6） |
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

### logo（变长）= 缩略图（标准 PNG，已解，见 §8）
14~16 KB，三个存档类型各自固定（BL 16145 / EDIT 14235 / ML 16284），
随存档内容变化很小 —— 是游戏内存档列表显示的预览图。内部结构：**标准 PNG**，
228×128、8-bit、RGB 真彩（无 alpha）、无隔行；IHDR/sBIT/IDAT×2/IEND；
IDAT zlib 解压恰为 128×(228×3+1)=87680 字节。`probe_logo.py` 已抽取三个
`outputs/logo_*.png` 供肉眼核验。

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

## 6. 已解 / 待解

### hash[80:144]（64 B）= **CryptGenRandom 生成的随机 nonce**（已解）

**结论：这不是哈希，是 64 字节密码学随机数，作防篡改 / 版本标记，加载时不校验。**

#### exe 实证（存档构造区 `build_save`，明文文件头在 `[rbp+0x40]`）

文件头明文缓冲 `fileHeader[0:208]` 位于 `[rbp+0x40]`，故 `hash` 区 = `[rbp+0x40+0x50]`
= `[rbp+0x90]`（偏移 80）。填充分三段式 —— CAPI `CryptoAPI` 标准 RNG 用法：

```asm
0x1412962: mov r9d, 1
0x1412968: xor r8d, r8d
0x141296B: xor edx, edx
0x141296D: lea rcx, [rsp+0x40]        ; &hProv
0x1412972: call [rip+0x1120c98]       ; CryptAcquireContext(&hProv, NULL, NULL, 1)
0x1412978: test eax, eax
0x141297A: je 0x14129a0               ; 失败则跳过（hash 留零）
0x141297C: lea r8, [rbp+0x90]         ; r8 = &fileHeader[80]  ← hash 区
0x1412983: mov edx, 0x40              ; rdx = 64
0x1412988: mov rcx, [rsp+0x40]        ; rcx = hProv
0x141298D: call [rip+0x1120cc5]       ; CryptGenRandom(hProv, 64, &fileHeader[80])
0x1412993: xor edx, edx
0x1412995: mov rcx, [rsp+0x40]
0x141299A: call [rip+0x1120c78]       ; CryptReleaseContext(hProv, 0)
```

`CryptGenRandom(hProv, DWORD cbBuffer, BYTE* pbData)` 的 x64 快调约定正是
`rcx=hProv, rdx=cbBuffer=64, r8=pbData=&hash` —— 与反汇编逐参数吻合；前后
`CryptAcquireContext` / `CryptReleaseContext` 是 CAPI 取 CSP 句柄的标准开合。
三个 IAT 槽（`0x1412972/0x141298D/0x141299A` → `0x2533610/0x2533658/0x2533618`）
经 `exe_import_rng.py` 定位，属 **advapi32**（`CryptGenRandom` 现代 Windows 由
`cryptsp.dll` 承载、自 `advapi32` 转发）。因本 exe 被加壳/保护，**导入名字符串已
被剥离**（裸搜 `CryptGenRandom`、导入表名字字段均取不到），故 API 身份由**调用签名**
唯一确定，而非字符串。

#### 为什么此前 ~700 种哈希碰撞全失败 —— 因为它根本不是哈希

| 观测 | 随机 nonce 解释 |
|---|---|
| 9 个存档各不同、非零、高熵 | 每次保存 `CryptGenRandom` 现抽 64 B |
| 解密主流程 0x14115F0 对其零访存 | 仅写入、不参与加载校验 |
| sha512/sha384/sha256/sha3/blake2b/HMAC 共 ~700 组合全落空 | 内容无确定输入可重算 |
| 加密主流程 `0x1412C1A` 内无哈希调用 | 随机数在更上层 `build_save` 生成，加密只负责 XOR |

> 纠错记录：加密主流程之前的 `0x140F3A0`/`0x140F290` 早前被误判为"可能算此 hash"，
> 实则为 MSVC `std::string`/`std::wstring` 成员方法（小字符串优化 + memcpy，被
> `build_save` 用于拼 fileType/gameVersion 字符串），与哈希无关，已排除。

### 其余待解

- **encHeader 内部结构** → 已解，见 §8.1（= 四块 SHA-512 摘要表 256B + 随机 salt 64B）、
  §7.1（摘要表就是加载期完整性校验的比对目标，59/59 样本实测）。
  ⚠️ 旧版"encHeader = 192B 随机 + 64B 固定常量 + 64B 随机 tail"已被推翻，见 §8.2。
- **serial 全貌** → 已解，见 §8.4（UTF-16LE Windows SID，绑定创建存档的账户）
- **保存侧摘要写入路径** → 已解，见 §7.2（`0x140E160` 一次性 SHA-512，唯一调用者 `0x1412B21`；
  摘要写出后经 `0x140DFF0` 折叠成 rolling_key，与 `pes_decrypt.py` 逐步互逆）
- serial 不匹配时游戏的具体行为（拒绝加载 / 提示 / 只读）—— **仍为开放项**：机制上 = SID 账户校验（跨账户/跨机不通用），但 exe 只调 `ConvertSidToStringSidW` 转串、未做 `LookupAccountSidW` 反查，校验/拒绝逻辑在更上层或数据层，本轮未在 exe 内定位
- gameVersionString 已确认参与校验（0x140F200 比 gameVersionString 与常量串）

---

## 7. 加载期完整性层：每块 SHA-512（本轮新解，**修正"data 可能压缩"的猜测**）

`decrypt_main`（`0x14115F0`）在逐块解密后，对**每块明文内容**现算 SHA-512 摘要。
这是加载期**完整性校验**，不是压缩——故 `data` 解密后即为明文，我们此前用社区 wiki
法直接在其上解出球员 240B / 球队 / 事件等结构完全成立。

### 证据链（文件偏移，flat image 口径）

1. `decrypt_main` 块循环内调用位缓冲喂入器 `0x1413950` 与初始化器 `0x1413cb0`，
   并以 `0x1413DF0` 作为每块处理回调（`call rsi` / `call r14`）：
   ```asm
   0x14118FE: call 0x1413950        ; 喂入器(ctx, 源缓冲, 长度, 回调=0x1413DF0)
   0x1411911: call 0x1413cb0        ; 初始化器(ctx, 0x1413DF0)
   ```
2. `0x1413DF0` = **SHA-512 压缩函数**。判定依据（代码层，与混淆的常量池无关）：
   - 消息扩展 `σ0 = ROTR1 ^ ROTR8 ^ SHR7`、`σ1 = ROTR19 ^ ROTR61 ^ SHR6`（64-bit 字，
     `ror rax,1` / `ror r8,8` / `shr rcx,7` 与 `ror rcx,0x13(19)` / `rol rax,3(=ROTR61)` / `shr rdx,6`）。
   - 80 轮压缩主体（8 个工作变量 a..h，`add r9,[rbx+r13-8]` 加 K[t]，`not/and` 实现 Ch）。
   - 消息块 **128 字节 = 1024 bit**（SHA-512 块长）；`shr rdi,7; inc rdi` 即 `(长度-1)>>7+1`
     算块数；`bswap` 大端装载 64-bit 字（SHA-512 大端消息序）。
   - K 常量表基址 `0x14144BF: lea r13,[rip+0x153513a]`，其 K[0] 小端字节省
     `22 ae 28 d7 98 2f 8a 42` = **`0x428a2f98d728ae22`**，精确命中标准 SHA-512 K[0]。
3. `0x1413950`（喂入器）：取 `[rcx+0xc0] & 0x7f` 为位窗口内位位置（0x7f=127 印证 128B
   分块），把源缓冲按 128B 拷入 `ctx+0x40` 位窗口，每满一块 `call r14`（=0x1413DF0）。
4. `0x1413cb0`（初始化器）：`mov byte [r8+rcx+0x40],0x80` 初始化窗口，`bswap` 转大端，
   拷入首块后 `call rsi`（=0x1413DF0）。

### 语义结论

| 项 | 说明 |
|---|---|
| 作用 | 加载时对每块（desc/logo/data/serial）明文算 SHA-512，与存档内存储的每块摘要比对，不匹配则视为损坏/被篡改而拒绝 |
| 与 `hash[80:144]` 分工 | `hash[80:144]` 是**保存时** `CryptGenRandom` 现抽的随机 nonce（不参与加载校验）；逐块 SHA-512 是**加载时**对明文内容算的摘要，二者独立、互不等价 |
| 对 `data` 的含义 | `data` 解密后为明文，SHA-512 仅做完整性验证；之后的球员/球队/事件等结构化解析由下游函数进行 |
| **比对目标位置** | **已定位** = `encHeader[0:256]`，四块各 64 B，顺序 desc→logo→data→serial（见 §7.1，59 样本实测） |

### 7.1 期望摘要表 = encHeader 前 256 字节（本轮定位，59/59 样本实测）

`decrypt_main` 里 memcmp 的第二参数 `[rbp+0x160] + i*64` 究竟指向文件何处，此前未定位。
本轮从**数据侧**直接闭合：把每块明文算出标准 SHA-512，去存档里搜这 64 字节。

```
encHeader 明文（320 B）
┌────────────┬─────────────────────────────────────────┐
│ [0:64]     │ SHA-512(desc  明文)                      │
│ [64:128]   │ SHA-512(logo  明文)                      │
│ [128:192]  │ SHA-512(data  明文)                      │
│ [192:256]  │ SHA-512(serial 明文)  ← 曾误判为"固定常量"，见 §8.2 │
│ [256:320]  │ salt：每存档随机，= header_key 源         │
└────────────┴─────────────────────────────────────────┘
```

`exe/probe_block_hashes.py` 在 **59 个样本**（BL×4 / EDIT×1 / ML×4 / REPLAY×50）上逐块核对，
四块摘要**全部一致，零例外**（`outputs/block_hashes_all.txt`）。

这条结论有三重意义：

1. **完整性层完全闭合** —— 不只知道"算了 SHA-512"，还知道摘要存在哪、什么顺序。
2. **解密正确性的独立证明** —— 若 `pes_decrypt.py` 有任何一处解错，四块明文必错、
   摘要必不匹配。59/59 全过 ⇒ 解密实现逐字节正确，这是比任何自测都强的外部验证。
3. **直接推翻 §8.2 的"全局固定常量"结论** —— 见下节。

> 附注：`[rbp+0x160]` 在 0x14115F0 起的这段里只被读、从未被写。原因是 0x14115F0
> 并非函数入口（首条指令即 `lea ecx,[rbp-0x10]`，无 prologue），它只是外层解密函数
> 体中间的**块循环**，`rbp` 指向的是**调用者**的帧 —— 故 `[rbp+0x160]` 是外层函数的
> 局部摘要表，由外层从 encHeader 拷入。这也解释了为何喂入器 `0x1413950` 的三个调用者
> （`0x14107AE` / `0x14109EE` / `0x14118FE`）里**不含加密主流程**：摘要在更上层的
> `build_save` 算好后传入，加/解密主流程只负责比对与 XOR。

### 7.2 保存侧闭环：谁算摘要、写到哪、怎么变密钥（本轮新解）

§7.1 解决了"加载时跟谁比"，本节解决**"保存时谁写的"**。

#### 一次性 SHA-512 便捷函数 `0x140E160`

`0x1413DF0`（压缩）全 exe 只有 **1 处**直接调用 —— `0x140E2C1`，落在 `0x140E160` 起的这个函数里。
它一次算完整条消息的摘要（`0x140E2C1` 压缩整块 → `0x140E2DC` memcpy 余尾 → `0x140E2ED` final
→ `0x140E300` 输出 64 B）。

**身份铁证：8 个 `movabs` 装载的 IV 与标准 SHA-512 逐位相等**（偏移量 flat image）：

```asm
0x140E1E2: movabs rax, 0x6a09e667f3bcc908   ; IV[0]
0x140E1F4: movabs rcx, 0xbb67ae8584caa73b   ; IV[1]
0x140E206: movabs rdx, 0x3c6ef372fe94f82b   ; IV[2]
0x140E210: movabs r8,  0xa54ff53a5f1d36f1   ; IV[3]
0x140E21A: movabs r9,  0x510e527fade682d1   ; IV[4]
0x140E224: movabs r10, 0x9b05688c2b3e6c1f   ; IV[5]
0x140E22E: movabs r11, 0x1f83d9abfb41bd6b   ; IV[6]
0x140E238: movabs r12, 0x5be0cd19137e2179   ; IV[7]
0x140E1EC: mov qword [rbp+0x38], 0xd0       ; ctx 大小 208 = 64 状态+128 缓冲+16 长度
```

这补上了 §7 只靠"旋转模式"定性的最后一环：**K 表虽被壳混淆，IV 却是明文立即数**
（编译器内联进代码，壳没混淆到代码区的立即数）。配合 K[0] 明文可读，
**游戏用的就是标准 SHA-512，无任何自定义常数** —— 这也是 `probe_block_hashes.py`
能直接用 `hashlib.sha512` 一击命中的根本原因。

#### 保存路径 `0x1412B21`（紧邻加密主流程之前）

`0x140E160` 全 exe 只有 **1 个**调用者：`0x1412B21`，落在 `0x1412C1A`（加密主流程）之前 249 字节处。
逐段对照 `pes_decrypt.py`：

```asm
0x1412B1A: lea rcx,[rbp+0x110]   ; out（摘要 64 B）
0x1412B21: call 0x140E160        ; ★ SHA-512 → [rbp+0x110]
0x1412B2B: lea rdx,[rbp+0x110]
0x1412B32: mov rcx, r14          ; 文件句柄
0x1412B35: call 0x140FDF0        ; 写出这 64 B

0x1412B3A~62: movaps ×4          ; [rbp-0x40..-0x01] ← [rbp+0x110] 的 64 B（rolling_key 初值）
0x1412B66: mov r8d, 0x100        ; 256 字节
0x1412B6C: lea rdx,[rbp+0x150]   ; 源 = +0x40 起的后续 256 B（另三条摘要 + salt）
0x1412B73: lea rcx,[rbp-0x40]    ; 目标就地折叠
0x1412B77: call 0x140DFF0        ; ★ xor_repeating_blocks(out, in, 256)

0x1412BA6: xor rax, 0xd0         ; 文件头密钥 = rolling_key ^ 208（逐 qword）
0x1412C06: mov r9d, 0xd0         ; 长度 208
```

| exe 保存侧 | `pes_decrypt.py` 读取侧 |
|---|---|
| `sha512` → `[rbp+0x110]`（encHeader 明文 320 B 的头部） | `enc_header = crypt_header(blob[:320], mk)` |
| `movaps` ×4 → `[rbp-0x40]` | `rolling_key = bytearray(enc_header[:64])` |
| `xor_repeating_blocks(rcx=[rbp-0x40], rdx=[rbp+0x150], 0x100)` | `xor_repeating_blocks(rolling_key, enc_header[64:320], 256)` |
| `xor rax, 0xd0` 逐 qword | `xor_with_long_param(rolling_key, intermediate, FILE_HEADER_SIZE)` |

**写入侧与读取侧逐步互逆，加解密链条至此两头都闭合。**

#### 顺带纠正：§7 旧版对 `0x1413A20` 的判断是错的

旧版称"`0x1413A20` / `0x1413B60` 等同区间函数是 SHA-512 辅助，其调用者集中在
`0x1416xxx`–`0x1431xxx`（反序列化模块）"。实测 **`0x1413A20` 不是哈希函数**：
它内部是 `mov word ptr [rdx+rcx*2], ax`（2 字节宽字符）、SSO 阈值 `cmp qword [rbx+0x18], 8`、
越界即抛异常 —— 是 **MSVC `std::wstring` 的插入/追加**。`0x1413B60` 同理是 `std::string` 赋值
（构造 `std::string` 对象：`[+0]=缓冲, [+0x10]=size, [+0x18]=capacity`）。

这是**第二次**把 MSVC 字符串成员方法误判为哈希（第一次是 §6 记录过的 `0x140F3A0`/`0x140F290`）。
判据要记住：**SHA-512 的识别特征是 64 位旋转 + 80 轮 + 128 B 分块**，
不是"跟哈希函数地址相近"。`0x1413A20` 有 30 个调用者，正因为它只是个通用字符串工具。

> 另：`0x1412C1A`（加密主流程）与 `0x14115F0`（解密主流程）**都没有直接调用者**
> （全 exe 扫 `E8` 命中 0），二者都经**间接分派**进入 —— 与 §7 末尾记录一致。
> 故 `build_save` 的最外层入口在纯静态下不可达（保护器混淆 + 虚分派）。

### 常量池被壳混淆（顺带发现）

磁盘上 SHA-512 K 表**被壳部分混淆**：K[0] 明文可读、K[1] 起低 32 位乱（高 32 位仍对）。
这与 `.ecode`/`.data1` 打包壳一致，也是为什么朴素字节签名扫不到 SHA-512——算法身份只能由
代码层旋转模式唯一确定，不能靠常量表。

### 结构化解析器位置（data 的球员/球队/事件怎么被读）

调用 SHA-512 辅助（0x1413A20 / 0x1413B60 等同区间函数）的调用者集中在 **`0x1416xxx`–`0x1431xxx`**
（xref 命中数十处），即一整个**存档数据反序列化模块**：每个调用点对应一种块的解析函数。
`data` 的球员/球队/事件解析由该模块的编排函数驱动，下游接我们已用社区 wiki 法解出的
240B 球员、球队块、事件表等结构。该编排函数经**间接调用**进入 `decrypt_main`
（直接的 `E8` 调用为零命中），故接驳点需沿虚表/间接分派追，本轮未继续下钻。

---

## 8. encHeader 内部结构与 serial 全貌（本轮新解）

外层布局 §4/§5 已把 encHeader 当 320 字节黑盒。本轮用 `probe_encheader.py`
在 **59 个真实存档**（BL×4 / EDIT×1 / ML×4 / REPLAY×50，全 Patch 1.07.00）
上逐字节拆解 `decrypt()` 返回的 encHeader（注意：`crypt_stream` 是自逆函数，
`crypt_header` 套一次即还原**明文本体**，故 encHeader 三段差异 = 明文本身的差异，
可直接反映结构，不是 keystream 造成的伪差）。

### 8.1 encHeader 320B 明文四段布局（本轮更正：三段 → 四段）

> **本节已按 §7.1 的新证据重写。** 旧版把 encHeader 描述为"192B 随机 + 64B 固定常量
> + 64B 随机 tail"，其中"固定常量"一项是**误判**，真实语义是 **SHA-512(serial)**。

```
encHeader（明文，320B）
┌─────────────┬────────┬───────────────────────────────────────────────┐
│ [0:64]      │ 64B    │ SHA-512(desc 明文)     ← 完整性摘要 #0         │
├─────────────┼────────┼───────────────────────────────────────────────┤
│ [64:128]    │ 64B    │ SHA-512(logo 明文)     ← 完整性摘要 #1         │
├─────────────┼────────┼───────────────────────────────────────────────┤
│ [128:192]   │ 64B    │ SHA-512(data 明文)     ← 完整性摘要 #2         │
├─────────────┼────────┼───────────────────────────────────────────────┤
│ [192:256]   │ 64B    │ SHA-512(serial 明文)   ← 完整性摘要 #3         │
│             │        │ ★旧版误判为"全局固定常量"，见 §8.2            │
├─────────────┼────────┼───────────────────────────────────────────────┤
│ [256:320]   │ 64B    │ salt：每存档随机，= header_key 源（明文透传，   │
│             │        │ 不参与 crypt_header 加密；见 §3/§4）           │
└─────────────┴────────┴───────────────────────────────────────────────┘
```

- `[0:256]` 前三项（desc/logo/data 摘要）：每存档不同 —— desc 是存档名+赛季信息、
  logo 是缩略图 PNG、data 是主数据，三者内容各异。
- `[192:256]`（serial 摘要）：**全部 59 样本逐字节相同**，因为所有样本的 serial
  都是同一个 SID 字符串（§8.4）。
- `[256:320]`：每存档随机的 salt。

**是否暗藏主密钥副本**：否。`[0:64]` ≠ `reverse_longs(MASTERKEY)`（它就是 desc 的
SHA-512），全段无 ≥4 字节连续可打印文本 ⇒ encHeader **不**像 fileHeader 那样再存一份
主密钥校验副本（§5 的 mysteryData）。

### 8.2 「全局固定常量」翻案 —— 它是 SHA-512(serial)，不是常量

旧版（本仓库 2026-09-01 的结论）断言 `[192:256]` 是"**64 字节全局固定常量**"，
并说"2⁻⁵¹² 三档巧合可排除""逻辑上必为真·常量"。**这个推理链本身没错，
但结论错了** —— 它观测到的现象完全属实，只是归因错了：

```
5b 0b bd b5 56 e2 98 31 b6 d7 f9 46 fe b4 c4 c7
a0 23 65 10 84 4d bb 4a 26 ec 15 d0 56 ff fa 10
48 d9 d4 13 7d 05 73 ed 99 25 51 4f e9 26 43 cd
b1 e6 90 7c 79 40 4c e4 58 5f 99 dc 2b e4 cd 86
```

这 64 字节确实是常量 —— 但它是 **`SHA-512("S-1-5-21-1435437277-1052317143-1964327295-500")`
的 UTF-16LE 编码输入的摘要**。因为全部样本由同一台机器的同一个 Administrator 账户创建，
serial 恒等，故其摘要也恒等。

**旧版"已排除的假说"全部失效的原因一目了然**：它们全都在拿**主密钥**做输入
（`crypt_stream(mk,…)`、`SHA512(mk)`、`SHA512("PES2021")`、`SHA512("")` …），
而真正的输入是 **serial**。方向错了，再怎么穷举也不会中。

**教训（值得记住）**：在二进制里观测到"某字段恒定不变"，
只能推出"**它的输入不变**"，推不出"它是常量本身"。
区分这两者的唯一办法是**找到产生它的函数**——本轮是先从 exe 定位到
"每块算了 SHA-512"（§7），再回到数据侧算出摘要去搜，才闭合的。
若顺序反过来（先盯字节、后找函数），就会像旧版一样在错误的输入空间里穷举。

### 8.3 rolling_key 基与固定常量的关系

`decrypt()` 中 `rolling_key` 基（`pes_decrypt.py:199-200`，对应 `crypt.c:106-107`）：

```
rolling_key[k] = encHeader[k] ^ encHeader[64+k] ^ encHeader[128+k]
                 ^ encHeader[192+k] ^ encHeader[256+k]      (k = 0..63)
```

按 §8.1 的新语义，这个公式的**真实含义**是：

```
rolling_key[k] = SHA512(desc)[k] ^ SHA512(logo)[k] ^ SHA512(data)[k]
                 ^ SHA512(serial)[k] ^ salt[k]                    (k = 0..63)
```

即**把四块摘要折叠成一个 64 字节值，再用随机 salt 扰动**。
这是一个相当讲究的设计，一条数据同时承担两个职责：

| 职责 | 说明 |
|---|---|
| 完整性校验 | 加载时逐块重算比对（§7.1） |
| 密钥派生 | 四摘要折叠后作为 rolling_key 基，再用 salt 保证每存档唯一 |

由此得到一个重要推论：**内容绑定密钥**。改动任何一块的内容（比如改一个球员的能力值），
该块的 SHA-512 就变 ⇒ 折叠出的 rolling_key 也变 ⇒ 四块全部要重新加密，且 encHeader
前 256 字节要重写。这就是为什么存档修改器必须整体重算、无法做局部 patch。

（旧版说 `[192:256]` 贡献"固定偏置"，措辞本身仍成立 —— 因为 serial 不变，
其摘要确实是固定偏置；但它**不是**独立的常量字段。二者不破坏每存档密钥唯一性，
因 salt 与另外三条摘要均每存档变，实测 BL/EDIT/ML 三档各不同，H≈5.6–5.8。）

### 8.4 serial 全貌（UTF-16LE Windows 机器 SID）

`serial`（§5 已知 = SID）本轮补全：

- 编码：**UTF-16LE**，长度 `serialLength=45` 字符 = **90 字节**，**无 null 终止**
  （末 2 字节为 `"-500"` 的 `2d 00 35 00`）。
- 全部样本值一致（同机创建）：
  ```
  S-1-5-21-1435437277-1052317143-1964327295-500
  ```
  标准 SID 格式 `S-1-5-21-<3×32位域>-<RID>`，末位 RID `500` = 内置 Administrator 账户。
- **绑定创建存档的 Windows 账户**，是存档不能跨账户/跨机器直接通用的机制。
- serial 与 `[192:256]` **不是两个独立字段，而是输入与输出的关系**：
  serial 是 per-install 业务字段（同机同值），`[192:256]` 是它的 SHA-512（故同样同值）。
  **旧版称二者"独立"是错的**。
- 推论：只要换一台机器（或换一个 Windows 账户）创建存档，serial 就会变，
  `[192:256]` 也会随之改变 —— 本仓库 59 个样本全部同机创建，才呈现为"全局常量"。

### 8.5 复现脚本

```bash
python probe/probe_logo.py        # 抽三个 outputs/logo_*.png 并验 IHDR/IDAT 长度
python probe/probe_encheader.py   # encHeader 结构、逐字节差异检测、rolling_key 基、
                                  # 是否暗藏主密钥副本 / 可打印串、BL 全 320B hex dump
python exe/probe_block_hashes.py --all      # ★核对四块 SHA-512 摘要表（59 样本，秒级）
python exe/probe_block_hashes.py --search BL00000000
                                  # 盲搜模式：算出每块 SHA-512，去全部明文区里找它落在哪
                                  # （本轮就是用它定位到 encHeader[0:256] 的）
```

复现脚本（均已入库）：

```bash
python exe_mt_hunt.py    "<exe>"          # 常量鱼钩定位 MT19937
python exe_xref_mt.py    "<exe>"          # 反查谁调用了 MT19937
python exe_dis_callers.py "<exe>" 0x140FC93 ...   # 调用点 → 所属函数 + 常量指纹
python exe_dis_func.py   "<exe>" 0x140FC30 0x140FDE6 xref   # 反汇编 + 反查调用者
python exe_import_rng.py "<exe>"          # 定位 hash 区三个 IAT 调用（CryptGenRandom 三连）
python exe_validate_layout.py examples    # 在真实存档上核对布局
# —— 本轮 §7（SHA-512 完整性层）——
python exe_dis_func.py   "<exe>" 0x14115F0 0x1411BD9 xref   # 解密主流程：找调用者(间接,0命中)
python exe_dis_func.py   "<exe>" 0x1413DF0 0x1414600       # SHA-512 压缩函数(0x1413DF0)
python exe_dis_func.py   "<exe>" 0x1413950 0x1413A20 xref   # 位缓冲喂入器 + 其调用者(xref)
python exe_dis_func.py   "<exe>" 0x1413950 0x1413DF1 xref   # SHA-512 三件套调用者 → 反序列化模块 0x1416xxx~0x1431xxx
# —— 本轮 §7.2（保存侧闭环）——
python exe_dis_func.py   "<exe>" 0x140E100 0x140E250 xref   # 反查 sha512 便捷函数 → 唯一调用者 0x1412B21
python exe_dis_func.py   "<exe>" 0x1412AA0 0x1412C20        # 保存侧：算摘要 → 写出 → 折叠 → xor 0xD0
python exe_dis_func.py   "<exe>" 0x140E1C0 0x140E340        # 标准 SHA-512 的 8 个 IV 立即数（明文）
python exe_dis_func.py   "<exe>" 0x1412C1A 0x1412C1B xref   # 加密主流程调用者：0 命中（间接分派）
```

> 需要 capstone：`pip install capstone`（本项目用隔离 venv，
> `C:\Users\34788\.workbuddy\binaries\python\envs\default\Scripts\python.exe`）
