#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""REPLAY blob 五探：10 槽 × 660 帧，区分全局/逐实体字段，反推量化坐标 (x,y) 轴与比例尺。

上一轮只看了槽12，把 (191,2296,537,203) 误当常量模板；本轮抽全部 10 槽，
发现这些偏移其实是逐实体的（每个槽值不同）。据此：
  (A) 逐偏移：同帧跨槽的极差均值 → 全局(≈0)/逐实体(大)。
  (B) 逐实体偏移两两配对 (x,y)：各向同性过滤（两轴比例尺须一致 → 真坐标判据），
      假设场地 105×68m，则 w/h≈1.544 且 w/105≈h/68。
  (C) 最佳候选对：frame0 的 10 槽散点，肉眼看是否像阵型。
纯只读。
"""
import struct

SEG_OFF = 0x3AA0
EVT_FRAME = 8112
EVT_TBL = 4112
BLOB_OFF_IN_SLOT = 52
BLOB_LEN = 248
STRUCT_OFF = 144          # blob 内结构化区起点
N_U16 = 24               # 48B = 24×u16


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

    blobs = {f: {} for f in range(660)}
    for f in range(660):
        area = ev[f * EVT_FRAME + EVT_TBL: f * EVT_FRAME + EVT_FRAME]
        for m in slot_starts(area):
            sl = area[m + 1]
            if 12 <= sl <= 21:
                blob = area[m + BLOB_OFF_IN_SLOT: m + BLOB_OFF_IN_SLOT + BLOB_LEN]
                if len(blob) == BLOB_LEN:
                    us = [struct.unpack("<H", blob[STRUCT_OFF + 2 * i: STRUCT_OFF + 2 * i + 2])[0]
                          for i in range(N_U16)]
                    blobs[f][sl] = us
    print(f"有效帧 = {sum(1 for f in range(660) if blobs[f])}；每帧槽数示例 = {[len(blobs[f]) for f in range(3)]}")

    # ===== (A) 全局 vs 逐实体 =====
    print("\n=== (A) 24 个 u16：同帧跨槽极差均值（大=逐实体）===")
    spread = []
    for i in range(N_U16):
        diffs = []
        for f in range(660):
            if len(blobs[f]) >= 2:
                vals = [blobs[f][sl][i] for sl in blobs[f]]
                diffs.append(max(vals) - min(vals))
        spread.append((i, sum(diffs) / len(diffs) if diffs else 0))
    global_offs = [i for i, s in spread if s < 50]
    ent_offs = [i for i, s in spread if s >= 50]
    print(f"  全局字段偏移: {global_offs}   逐实体字段偏移: {ent_offs}")
    for i, s in spread:
        print(f"    +{STRUCT_OFF+2*i:3d} (u16#{i:2d}): 跨槽极差均值={s:7.1f}  {'全局' if s<50 else '实体'}")

    # ===== (B) 各向同性 (x,y) 配对 =====
    print("\n=== (B) (x,y) 坐标轴对称候选：各向同性过滤（|w/105 - h/68|/均值 < 12%）===")
    pts = {i: [] for i in ent_offs}
    for f in range(660):
        for sl in blobs[f]:
            for i in ent_offs:
                pts[i].append(blobs[f][sl][i])
    rng = {i: (min(pts[i]), max(pts[i])) for i in ent_offs}
    pairs = []
    for a in range(len(ent_offs)):
        for c in range(a + 1, len(ent_offs)):
            i, j = ent_offs[a], ent_offs[c]
            xmn, xmx = rng[i]
            ymn, ymx = rng[j]
            w, h = xmx - xmn, ymx - ymn
            if w <= 0 or h <= 0:
                continue
            sx, sy = w / 105.0, h / 68.0
            if abs(sx - sy) / ((sx + sy) / 2) < 0.12:
                pairs.append((i, j, w / h, w, h, sx, sy, xmn, xmx, ymn, ymx))
    pairs.sort(key=lambda p: abs(p[2] - 1.544))
    print(f"  各向同性 (x,y) 候选对 = {len(pairs)}")
    for i, j, ar, w, h, sx, sy, xmn, xmx, ymn, ymx in pairs[:15]:
        print(f"    u16#{i:2d}(+{STRUCT_OFF+2*i:3d})×u16#{j:2d}(+{STRUCT_OFF+2*j:3d}): "
              f"aspect={ar:.3f}(球场1.544) scale_x={sx:.0f} scale_y={sy:.0f} uint16/m  "
              f"x∈[{xmn},{xmx}] y∈[{ymn},{ymx}]")

    # ===== (C) 连续×连续配对：u16#4(x 候选) 与连续偏移配对，frame0 散点看阵型 =====
    continuous = [0, 2, 4, 5, 7, 8, 9, 10, 12, 14, 18, 22, 23]
    print("\n=== (C) 连续×连续配对 frame0 散点（u16#4 当 x，找是否像阵型）===")
    for j in continuous:
        if j == 4:
            continue
        row = [f"槽{sl}:({blobs[0][sl][4]},{blobs[0][sl][j]})" for sl in sorted(blobs[0])]
        print(f"  u16#4×u16#{j}(+{STRUCT_OFF+2*j:3d}): " + "  ".join(row))

    # ===== (D) 众数集中度：每个偏移是否连续坐标(低集中)还是离散状态(高集中/双峰)=====
    print("\n=== (D) 24 偏移的离散度（全局 mode 占比 + 主峰[min,max] + 是否双峰）===")
    from collections import Counter
    for i in ent_offs:
        vals = pts[i]
        mn, mx = min(vals), max(vals)
        c = Counter(vals)
        mode_v, mode_n = c.most_common(1)[0]
        frac_mode = mode_n / len(vals)
        # 次峰占比（看双峰）
        sec_n = c.most_common(2)[1][1] if len(c) > 1 else 0
        bimodal = sec_n / len(vals) > 0.10   # 次峰>10% → 双峰
        note = "双峰" if bimodal else ("单峰集中" if frac_mode > 0.5 else "较连续")
        print(f"    u16#{i:2d}(+{STRUCT_OFF+2*i:3d}): 量程[{mn},{mx}] 主峰值={mode_v}(占{100*frac_mode:.0f}%) "
              f"次峰占{100*sec_n/len(vals):.0f}% → {note}")


if __name__ == "__main__":
    main()
