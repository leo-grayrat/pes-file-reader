#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""REPLAY 248B blob 二探：精确界定头部长度 + 运动体 float32 字段布局。

与 probe_replay_blob.py 的区别：
  - 逐字节跨帧 XOR 熵曲线 → 精确找出「随机头 / 结构化体」分界（H）。
  - body 按 float32(LE) 网格逐列报 min/max/mean/std 与相邻帧 |Δ| 均值，
    识别连续「坐标/姿态」区（平滑低 Δ 且值域合理）。
  - 打印若干帧 body 的 uint16 / float32 网格，肉眼核对结构。
纯只读。
"""
import math, struct
from collections import Counter

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


def entropy(b):
    c = Counter(b)
    n = len(b)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


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
    print(f"槽12 blob 序列帧数 = {len(blobs)}")

    # ===== A. 逐字节跨帧 XOR 熵（找头/体分界 H）=====
    L = len(blobs[0])
    xent = []
    for off in range(L):
        col_xor = []
        for i in range(1, len(blobs)):
            col_xor.append(blobs[i][off] ^ blobs[i - 1][off])
        xent.append(entropy(col_xor))
    print("\n=== A. 逐字节跨帧 XOR 熵（低=结构化/平滑，高≈随机）===")
    # 打印每 4 字节一组的平均，找突变点
    for s in range(0, L, 4):
        seg = xent[s:s + 4]
        print(f"  +{s:3d}: " + " ".join(f"{x:.2f}" for x in seg))
    # 找首个「连续 4 字节 XOR 熵 < 4.0」的起点（头结束、体开始）
    H = None
    for s in range(0, L - 4):
        if all(xent[s:s + 4]) and all(x < 4.0 for x in xent[s:s + 4]):
            # 确认这是持续的结构区，而非孤立噪声
            if all(x < 4.0 for x in xent[s:s + 24]):
                H = s
                break
    print(f"  推断头部长度 H = {H}（首个持续低熵起点）")

    # ===== B. body 按 float32 网格逐列轨迹 =====
    # 用全 blob 作为体（H 未知时退化为 0）；先按 H=0 全量、再标明
    H = H or 0
    body = [bl[H:] for bl in blobs]
    BL = len(body[0])
    print(f"\n=== B. body(头部后 {BL}B) float32(LE) 逐列轨迹 ===")
    cols = []
    for i in range(0, BL - 3, 4):
        vals = []
        for fr in body:
            v = struct.unpack("<f", fr[i:i + 4])[0]
            if math.isfinite(v):
                vals.append(v)
        if not vals:
            cols.append((i, None))
            continue
        mn, mx, mean = min(vals), max(vals), sum(vals) / len(vals)
        # std
        std = (sum((v - mean) ** 2 for v in vals) / len(vals)) ** 0.5
        # 相邻帧 |Δ|
        ds = []
        for fr_i in range(1, len(body)):
            a = struct.unpack("<f", body[fr_i - 1][i:i + 4])[0]
            c = struct.unpack("<f", body[fr_i][i:i + 4])[0]
            if math.isfinite(a) and math.isfinite(c):
                ds.append(abs(a - c))
        md = sum(ds) / len(ds) if ds else 1e9
        plaus = sum(1 for v in vals if abs(v) < 300) / len(vals)
        cols.append((i, (mn, mx, mean, std, md, plaus)))
    # 标出连续「平滑 + 合理」的坐标区
    print("  off   min     max    mean    std    |Δ|    plaus%   标记")
    run = []
    for i, c in cols:
        if c is None:
            tag = "NaN"
            print(f"  +{H+i:3d}:  (非有限)")
            continue
        mn, mx, mean, std, md, plaus = c
        coord = (md < 5.0 and plaus > 0.8)
        tag = "COORD?" if coord else ""
        print(f"  +{H+i:3d}: {mn:7.2f} {mx:7.2f} {mean:7.2f} {std:6.2f} {md:6.3f} {100*plaus:6.1f}  {tag}")
        run.append((i, coord))

    # ===== C. 头部 uint16 / 抽帧打印 =====
    print(f"\n=== C. 头部(前 {H}B) 按 uint16(LE) 抽 6 帧 ===")
    for k in (0, 1, 2, 3, 100, 659):
        hb = blobs[k][:H] if H else blobs[k][:16]
        ws = [struct.unpack("<H", hb[j:j + 2])[0] for j in range(0, len(hb) - 1, 2)]
        print(f"  帧{k:3d}: " + " ".join(f"{w:6d}" for w in ws))

    # ===== D. 运动体前若干 float32 组逐帧轨迹（看是否平滑位置）=====
    print("\n=== D. 平滑坐标组逐帧轨迹（前 12 帧）===")
    smooth_cols = [i for i, coord in run if coord][:6]
    for i in smooth_cols:
        traj = [struct.unpack("<f", body[k][i:i + 4])[0] for k in range(12)]
        print(f"  +{H+i:3d}: " + " ".join(f"{v:7.2f}" for v in traj))


if __name__ == "__main__":
    main()
