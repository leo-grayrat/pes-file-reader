#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bl_ml_probe38: 在解密后的 EDIT 数据库 (decoded/EDIT00000000.data) 中
1) 确认球员表 (stride=240, 从 0x7C 起) 的 ID 方案
2) 找名字字符串表 (zlib 流 / ASCII 人名)
"""
import struct, os, re, zlib

BASE = os.path.dirname(os.path.abspath(__file__))
EDIT = os.path.join(BASE, "decoded", "EDIT00000000.data")
b = open(EDIT, "rb").read()
N = len(b)
STRIDE = 240
PLAYER_BASE = 0x7C

print(f"EDIT data size = {N}")

# ---- 1) 球员表 ID 方案 ----
print("\n== 球员表前 30 条记录首 u32 (从 0x7C 起, stride 240) ==")
ids = []
for k in range(30):
    o = PLAYER_BASE + k * STRIDE
    if o + 4 > N:
        break
    v = struct.unpack_from("<I", b, o)[0]
    ids.append(v)
    print(f"  #{k:3d} @0x{o:x} id0={v} (0x{v:x})")
# 看是否连续递增
diffs = [ids[i + 1] - ids[i] for i in range(len(ids) - 1)]
print("首条差值序列(前10):", diffs[:10])

# 检查从 0x7C 起连续 stride-240 且 id0 落在 [1, 30000] 的段长度
def run_low_ids(lo, hi):
    best = 0; best_start = -1; cur = 0; start = -1
    off = PLAYER_BASE
    while off + STRIDE <= N:
        v = struct.unpack_from("<I", b, off)[0]
        if lo <= v <= hi:
            if cur == 0:
                start = off
            cur += 1
        else:
            if cur > best:
                best = cur; best_start = start
            cur = 0
        off += STRIDE
    if cur > best:
        best = cur; best_start = start
    return best, best_start

cnt, sbase = run_low_ids(1, 40000)
print(f"\nstride-240 且 id0∈[1,40000] 的最长连续段: count={cnt} @ {hex(sbase) if sbase>=0 else 'none'}")
if sbase >= 0:
    last = struct.unpack_from("<I", b, sbase + (cnt - 1) * STRIDE)[0]
    print(f"  该段 id 范围: {struct.unpack_from('<I',b,sbase)[0]} .. {last}")

# ---- 2) zlib 流 (字符串表) ----
print("\n== 扫描 zlib 流 (78 9c / 78 da) ==")
zlibs = []
for sig in (b"\x78\x9c", b"\x78\xda", b"\x78\x01"):
    pos = 0
    while True:
        pos = b.find(sig, pos)
        if pos < 0:
            break
        try:
            d = zlib.decompressobj()
            out = d.decompress(b[pos:pos + 5_000_000])
            if len(out) > 100:
                zlibs.append((pos, len(out), sig))
        except Exception:
            pass
        pos += 1
print(f"找到 {len(zlibs)} 个可读 zlib 流")
for pos, ln, sig in zlibs[:10]:
    print(f"  @0x{pos:x} decompressed={ln}")

# ---- 3) ASCII 人名-like 串 (First Last / 大写词) ----
print("\n== ASCII 大写人名候选 (含空格, 长度4-30) ==")
pat = re.compile(rb"[A-Z][a-z]{1,20}([ .'-][A-Z][a-z]{1,20}){1,3}")
hits = []
for m in pat.finditer(b):
    hits.append((m.start(), m.group().decode("latin1")))
print(f"候选数: {len(hits)}")
seen = set()
for off, t in hits[:40]:
    if t in seen:
        continue
    seen.add(t)
    print(f"  @0x{off:x} {t!r}")
