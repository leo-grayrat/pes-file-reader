#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""REPLAY 248B blob 三探：hex 直视 + 头部计数器验证 + 运动区 float32 轨迹。

结论性验证脚本。纯只读。
"""
import math, struct

SEG_OFF = 0x3AA0
EVT_FRAME = 8112
EVT_TBL = 4112
BLOB_OFF_IN_SLOT = 52
BLOB_LEN = 248


def load(name):
    with open(f"decoded/{name}.data", "rb") as f:
        return f.read()


def slot_starts(area):
    out = []
    for j in range(2, len(area) - 1):
        if area[j] == 1 and area[j - 1] == 0 and area[j - 2] == 0 and 2 <= area[j + 1] <= 40:
            out.append(j)
    return out


def main():
    b = load("REPLAY00000000")
    assert len(b) == 0x51EC60, len(b)
    ev = b[SEG_OFF:]

    blobs = []
    for k in range(660):
        area = ev[k * EVT_FRAME + EVT_TBL: k * EVT_FRAME + EVT_FRAME]
        m12 = None
        for m in slot_starts(area):
            if area[m + 1] == 12:
                m12 = m
                break
        if m12 is None:
            continue
        blob = area[m12 + BLOB_OFF_IN_SLOT: m12 + BLOB_OFF_IN_SLOT + BLOB_LEN]
        if len(blob) == BLOB_LEN:
            blobs.append(blob)

    # ===== 1. 帧0 blob 原始 hex 直视 =====
    print("=== 1. 帧0 blob 原始 hex（248B, 16/行）===")
    bb = blobs[0]
    for i in range(0, BLOB_LEN, 16):
        chunk = bb[i:i + 16]
        hexs = " ".join(f"{x:02X}" for x in chunk)
        asc = "".join(chr(x) if 32 <= x < 127 else "." for x in chunk)
        print(f"  +{i:3d}: {hexs:<48}  {asc}")

    # ===== 2. 头部计数器验证：奇数位（header 内）逐帧增量 =====
    # 取 header = blob[0:144]（偶数位随机、奇数位计数器）
    print("\n=== 2. 头部奇数位计数器逐帧增量（帧0→1→2→3 的奇数字节）===")
    HDR = 144
    print("  帧0 奇数字节:", " ".join(f"{blobs[0][o]:02X}" for o in range(1, HDR, 2)))
    print("  帧1 奇数字节:", " ".join(f"{blobs[1][o]:02X}" for o in range(1, HDR, 2)))
    incs = [blobs[1][o] - blobs[0][o] for o in range(1, HDR, 2)]
    print("  帧0→1 增量:", " ".join(f"{d:+d}" for d in incs))

    # 全局：奇数位 b1 跨 660 帧是否单调（确认是计数器而非噪声）
    col = [bl[1] for bl in blobs]
    mono_up = sum(1 for i in range(1, len(col)) if col[i] >= col[i - 1])
    print(f"  b1(头部第1个计数器) 跨帧 单调不减占比 = {100*mono_up/(len(col)-1):.0f}%  (0={col[0]} ... 659={col[-1]})")

    # ===== 3. 运动区 float32 轨迹（blob[144:192] = 12 float32）=====
    print("\n=== 3. 运动区 blob[144:192] 12×float32 逐帧轨迹（前 14 帧）===")
    mot = [bl[144:192] for bl in blobs]
    for k in range(14):
        fs = [struct.unpack("<f", mot[k][i:i + 4])[0] for i in range(0, 48, 4)]
        print(f"  帧{k:2d}: " + " ".join(f"{v:9.3f}" for v in fs))

    # 每列统计
    print("\n  运动区每列 min/max/mean/std/均|Δ|(平滑度):")
    for i in range(0, 48, 4):
        vals = [struct.unpack("<f", mot[k][i:i + 4])[0] for k in range(len(mot)) if math.isfinite(struct.unpack("<f", mot[k][i:i + 4])[0])]
        if not vals:
            print(f"    +{144+i}: 非有限"); continue
        mn, mx, mean = min(vals), max(vals), sum(vals)/len(vals)
        std = (sum((v-mean)**2 for v in vals)/len(vals))**0.5
        ds = []
        for k in range(1, len(mot)):
            a = struct.unpack("<f", mot[k-1][i:i+4])[0]; c = struct.unpack("<f", mot[k][i:i+4])[0]
            if math.isfinite(a) and math.isfinite(c): ds.append(abs(a-c))
        md = sum(ds)/len(ds) if ds else 1e9
        print(f"    +{144+i}: min={mn:8.2f} max={mx:8.2f} mean={mean:8.2f} std={std:7.2f} |Δ|={md:7.3f}")

    # ===== 4. 零填充尾验证 =====
    print("\n=== 4. 尾零填充 blob[192:248] ===")
    tail = blobs[0][192:248]
    print(f"  帧0 尾 56B = {tail.hex(' ')}  (全零={all(x==0 for x in tail)})")
    allzero = sum(1 for bl in blobs if all(x == 0 for x in bl[192:248]))
    print(f"  全 660 帧尾 56B 全零占比 = {100*allzero/len(blobs):.0f}%")


if __name__ == "__main__":
    main()
