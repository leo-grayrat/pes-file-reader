#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""encHeader（320B 加密头）深度结构分析 —— 此前未解的部分。

核心事实（来自 pes_decrypt）：
  decrypt() 返回的 encHeader 已经是 320B 明文本体
  （crypt_stream 是自逆函数，crypt_header 套一次即还原明文；[256:320] 明文透传）。
  因此 encHeader 在三档存档间的差异 = 明文本身的差异，可直接反映结构。

  rolling_key 基 = encHeader[:64] XOR_repeating encHeader[64:320]
    = encHeader[k] ^ encHeader[64+k] ^ encHeader[128+k] ^ encHeader[192+k] ^ encHeader[256+k]   (k=0..63)

本脚本逐字节/分区域检视，判断：
  (1) 哪些偏移是「全局常量」（三档相同）→ 固定 schema 字段（魔数/版本/类型标签）
  (2) 各区域熵值 → 是否高熵随机材料
  (3) rolling_key 基是否也是每存档随机
  (4) 明文里是否暗藏 reverse_longs(masterkey) 副本 或 可打印字符串
纯只读。
"""
import os, math, struct
from pes_decrypt import decrypt, MASTERKEY_PES21

EX_DIR = "examples"
SAVES = ["BL00000000", "EDIT00000000", "ML00000000"]

def clean(b):
    return "".join(chr(x) if 32 <= x < 127 else "." for x in b)

def shannon(b):
    if not b: return 0.0
    c = {}
    for x in b: c[x] = c.get(x, 0) + 1
    n = len(b)
    return -sum((v / n) * math.log2(v / n) for v in c.values())

def variety(b):
    return len(set(b)) / len(b) if b else 0.0

def reverse_longs(src):
    out = bytearray(64)
    for i in range(8):
        for j in range(8):
            out[i*8+j] = src[i*8+7-j]
    return bytes(out)

def rolling_key_base(eh):
    rk = bytearray(eh[:64])
    for i in range(256):
        rk[i & 63] ^= eh[64 + i]
    return bytes(rk)

def main():
    data = {}
    for name in SAVES:
        blob = open(os.path.join(EX_DIR, name), "rb").read()
        r = decrypt(blob)
        data[name] = r["encHeader"]

    print("=" * 72)
    print("A. 逐字节全局常量检测（三档同偏移若全相等 = 固定 schema 字段）")
    print("=" * 72)
    const_offsets = []
    for i in range(320):
        vals = [data[n][i] for n in SAVES]
        if all(v == vals[0] for v in vals):
            const_offsets.append((i, vals[0]))
    print(f"  全局常量偏移数: {len(const_offsets)} / 320")
    if const_offsets:
        # 按区域归组打印
        for i, v in const_offsets:
            region = "[0:256]" if i < 256 else "[256:320]"
            print(f"    off {i:3d} ({region}) = 0x{v:02X} '{chr(v) if 32<=v<127 else '.'}'")
    else:
        print("    [0:256] 与 [256:320] 均无任何全局常量偏移 → 整段是每存档材料，无共享 schema 字段")

    print()
    print("=" * 72)
    print("B. 分区域熵（每存档独立）")
    print("=" * 72)
    regions = [("[0:64]",  slice(0,64)),
               ("[64:256]", slice(64,256)),
               ("[0:256]",  slice(0,256)),
               ("[256:320]",slice(256,320)),
               ("[0:320]",  slice(0,320))]
    header = f"  {'region':10s} | " + " | ".join(f"{n:>10s}" for n in SAVES) + " | note"
    print(header)
    for label, sl in regions:
        ent = [f"{shannon(data[n][sl]):.3f}" for n in SAVES]
        var = [f"{variety(data[n][sl]):.3f}" for n in SAVES]
        print(f"  {label:10s} | H=" + " | H=".join(f"{e:>8s}" for e in ent) + " | 字节种类=" + "/".join(var))
    print("  注：H≈8.0 且 种类≈1.0 ⇒ 高熵随机材料；明显偏低 ⇒ 含固定/结构化内容")

    print()
    print("=" * 72)
    print("C. rolling_key 基（解密后续所有块的种子）结构")
    print("=" * 72)
    rks = {n: rolling_key_base(data[n]) for n in SAVES}
    for n in SAVES:
        rk = rks[n]
        print(f"  {n}: {rk.hex()}")
        print(f"        H={shannon(rk):.3f} 字节种类={variety(rk):.3f} 可读={clean(rk)!r}")
    # 三档 rolling_key 是否相同？
    same = all(rks[n] == rks[SAVES[0]] for n in SAVES)
    print(f"  → 三档 rolling_key 基: {'全部相同（异常！）' if same else '各档不同（符合每存档独立密钥）'}")

    print()
    print("=" * 72)
    print("D. 是否暗藏 reverse_longs(masterkey) 副本 / 可打印字符串")
    print("=" * 72)
    rlm = reverse_longs(MASTERKEY_PES21)
    print(f"  reverse_longs(masterkey): {rlm.hex()}")
    for n in SAVES:
        eh = data[n]
        hit = rlm in eh  # 64 字节连续匹配
        # 也查 [0:64] 是否等于 rlm
        eq64 = eh[:64] == rlm
        print(f"  {n}: 整段含 rlm 副本={hit}; [0:64]==rlm={eq64}; [0:64]={eh[:64].hex()}")
    # 可打印字符串扫描（连续 >=4 可打印）
    print("  可打印片段扫描（>=4 连续可打印）:")
    any_str = False
    for n in SAVES:
        eh = data[n]
        runs = []
        cur = ""
        for x in eh:
            if 32 <= x < 127:
                cur += chr(x)
            else:
                if len(cur) >= 4: runs.append(cur)
                cur = ""
        if len(cur) >= 4: runs.append(cur)
        if runs:
            any_str = True
            print(f"    {n}: {runs}")
    if not any_str:
        print("    三档均无 >=4 字节连续可打印字符串 → 无文本型 schema 字段")

    print()
    print("=" * 72)
    print("E. FULL HEX DUMP（BL，320B 明文）")
    print("=" * 72)
    eh = data["BL00000000"]
    for off in range(0, 320, 16):
        chunk = eh[off:off+16]
        hexs = " ".join(f"{b:02x}" for b in chunk)
        print(f"  {off:04d}  {hexs:<47s}  {clean(chunk)}")

if __name__ == "__main__":
    main()
