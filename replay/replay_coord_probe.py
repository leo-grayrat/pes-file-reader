#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
replay_coord_probe.py —— 槽12 blob 的 float32 时间序列分析。
目标：从跨帧变化的 4B 位置中找出 (x,y,z) 坐标三元组与朝向/速度字段。
"""
import os, struct, sys
from collections import Counter

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEC = os.path.join(BASE, "decoded")
SEG_OFF = 0x3AA0
EVT_TBL = 4112
EVT_FRAME = 0x1FB0
EVT_NF = 660
BLOB_OFF = 52
BLOB_LEN = 300 - BLOB_OFF

def slot_marks(area):
    marks = []
    for j in range(2, len(area) - 1):
        if area[j] == 0x01 and area[j-1] == 0 and area[j-2] == 0 \
           and 2 <= area[j+1] <= 40:
            marks.append(j)
    return marks

def main():
    path = os.path.join(DEC, sys.argv[1] if len(sys.argv) > 1 else "rep_REPLAY00000000.data")
    b = open(path, "rb").read()
    ev = b[SEG_OFF:]

    # 收集槽12 的 blob（全部帧）
    blobs = []
    for k in range(EVT_NF):
        area = ev[k*EVT_FRAME + EVT_TBL : k*EVT_FRAME + EVT_FRAME]
        for m in slot_marks(area):
            if area[m+1] == 12:
                blob = area[m + BLOB_OFF : m + BLOB_OFF + BLOB_LEN]
                if len(blob) == BLOB_LEN:
                    blobs.append(blob)
                break
    NF = len(blobs)
    print(f"槽12 blob 帧数: {NF}")

    # 每个 4B 位置的时间序列统计
    NW = BLOB_LEN // 4
    pos_stats = []
    for j in range(NW):
        series = [struct.unpack_from("<f", blobs[k], j*4)[0] for k in range(NF)]
        valid = [x for x in series if abs(x) < 1e4]
        if not valid:
            pos_stats.append((j, 0, 0, 0.0, 0.0))
            continue
        rng = max(valid) - min(valid)
        # 相邻帧增量统计
        deltas = []
        for k in range(1, NF):
            a, c = series[k-1], series[k]
            if abs(a) < 1e4 and abs(c) < 1e4:
                deltas.append(c - a)
        if deltas:
            maxd = max(abs(d) for d in deltas)
            meand = sum(abs(d) for d in deltas) / len(deltas)
        else:
            maxd = meand = 0.0
        # 值域是否落在球场尺度 ±70
        in70 = sum(1 for x in valid if abs(x) <= 70) / len(valid)
        pos_stats.append((j, len(valid), rng, maxd, in70))

    print(f"\n{'4B位':>5} {'有效':>4} {'值域':>9} {'最大帧差':>9} {'|±70|内':>7}  判读")
    for j, nv, rng, maxd, in70 in pos_stats:
        tag = ""
        if in70 > 0.9 and maxd <= 2.0 and rng > 0.001:
            tag = "**候选坐标**"
        elif in70 < 0.5 and nv > 0:
            tag = "非坐标(大值)"
        if tag or (j < 0x30):
            print(f"{j*4:5d}(0x{j*4:03X}) {nv:4d} {rng:9.3f} {maxd:9.3f} {in70:6.1%}  {tag}")

    # 候选坐标位置的时间轨迹（每 10 帧采一个）
    print(f"\n=== 候选 4B 位置 float 轨迹（每 10 帧采样，共 {min(NF,70)} 帧）===")
    cands = [j for j, nv, rng, maxd, in70 in pos_stats if in70 > 0.9 and maxd <= 2.0 and rng > 0.001]
    for j in cands[:10]:
        seq = [struct.unpack_from("<f", blobs[k], j*4)[0] for k in range(0, min(NF,70), 10)]
        print(f"  +0x{j*4:03X}: " + " ".join(f"{x:7.2f}" for x in seq))

    # 三元组检查：连续 3 个候选位置是否构成 (x,y,z)
    if len(cands) >= 3:
        print(f"\n=== 候选位置: {[hex(j*4) for j in cands]} ===")
        print("检查连续三元组 (x,y,z) 的几何合理性（帧0/帧30/帧60 对比）:")
        for t in range(3):
            k = t * 30
            if k >= NF:
                break
            triplets = []
            for j in cands:
                triplets.append(struct.unpack_from("<f", blobs[k], j*4)[0])
            print(f"  帧{k}: " + " ".join(f"[{j*4:#05x}={x:7.2f}]" for j, x in zip(cands, triplets)))

if __name__ == "__main__":
    main()
