#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
probe_frame_layout.py — 在 decoded 回放数据里定位「256x16B 状态表 ([0,0,0,1.0]x4 float32)」，
并探测逐帧 stride，验证 ReplayFrame(8112B) 是否为序列化帧单元。

只读 decoded/rep_REPLAY00000000.data。
"""
import os
import struct

PATH = "decoded/rep_REPLAY00000000.data"
# [0,0,0,1.0] 四个 float32 LE: 0,0,0,1.0
MARK = bytes([0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0x80,0x3F])
MARK2 = bytes([0,0,0x80,0x3F])  # 单 float32 1.0


def runs_of(data, marker, min_run):
    """返回连续出现 marker 的 (start, run_count) 列表。"""
    out = []
    i = 0
    n = len(data)
    ml = len(marker)
    while True:
        j = data.find(marker, i)
        if j < 0:
            break
        # 数连续重复
        run = 0
        k = j
        while data[k:k+ml] == marker and k + ml <= n:
            run += 1
            k += ml
        if run >= min_run:
            out.append((j, run))
        i = k if k > j else j + 1
    return out


def main():
    with open(PATH, "rb") as f:
        data = f.read()
    size = len(data)
    print("文件: %s  大小=%d (0x%X)" % (PATH, size, size))

    # 1) 找 256x marker 的长连续块
    runs = runs_of(data, MARK, 64)  # 至少 64 个连续 (=1024B) 才算候选
    print("\n=== [0,0,0,1.0]x4 连续块 (>=64 个=1024B) ===")
    for start, run in runs:
        print("  off=0x%X (%d)  run=%d  (=%d B)" % (start, start, run, run*16))

    # 2) 全文件统计 marker 出现次数（分布）
    cnt = 0
    i = 0
    positions = []
    while True:
        j = data.find(MARK, i)
        if j < 0:
            break
        cnt += 1
        if len(positions) < 20:
            positions.append(j)
        i = j + 1
    print("\nmarker 全文件出现 %d 次；前 20 个偏移: %s" % (cnt, [hex(p) for p in positions]))

    # 3) 探测逐帧 stride：若帧是定长 F，则状态表（若存在）在每个帧内同偏移出现
    #    用 marker 的偏移做差分，看是否有规律间距
    if len(positions) >= 3:
        diffs = [positions[k+1]-positions[k] for k in range(len(positions)-1)]
        from collections import Counter
        c = Counter(diffs)
        print("\nmarker 相邻偏移差 top5:", c.most_common(5))

    # 4) 文件大小 vs 候选帧数
    print("\n=== 帧尺寸候选 ===")
    for F in (8112, 8096, 8192, 0x1fb0, size//660, size//661):
        if F > 0:
            q, r = divmod(size, F)
            print("  stride=%d (0x%X): %d 帧, 余 %d" % (F, F, q, r))

    # 5) 头部 256B 概览（找帧边界/魔数）
    print("\n=== 头部 0x80 字节 ===")
    print("  " + data[:0x80].hex())


if __name__ == "__main__":
    main()
