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

- logo 块的图像编码（尺寸/格式/调色板）
- serial 不匹配时游戏的具体行为（拒绝加载 / 提示 / 只读）
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
| **比对目标位置** | 待定（可能在 fileHeader 某字段或各块尾部摘要），本轮未定位 |

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
```

> 需要 capstone：`pip install capstone`（本项目用隔离 venv，
> `C:\Users\34788\.workbuddy\binaries\python\envs\default\Scripts\python.exe`）
