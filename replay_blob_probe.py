#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
replay_blob_probe.py —— 回放事件区「球员槽 blob」跨帧差分探查。
背景（replay_analyze 已证）：事件流 = 660帧×8112B；帧内 +4112 起 4000B 事件区；
事件区含 ~10 个球员槽包（标记 01 XX，槽号 12~21，间距 300B）；
槽 = 12B 头 + 20×i16(40B) + 约 248B 高熵 blob。
本探针：对固定槽号的 blob 做相邻帧差分/异或，找 float32 坐标信号。
"""
import os, struct, sys
from collections import Counter

BASE = os.path.dirname(os.path.abspath(__file__))
DEC = os.path.join(BASE, "decoded")
SEG_OFF = 0x3AA0
EVT_TBL = 4112
EVT_FRAME = 0x1FB0
EVT_NF = 660
SLOT_STRIDE = 300
BLOB_OFF = 52      # 槽头12B + 20×i16(40B) 之后
BLOB_LEN = 300 - BLOB_OFF

def u16(b, o): return struct.unpack_from("<H", b, o)[0]
def u32(b, o): return struct.unpack_from("<I", b, o)[0]

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
    print(f"样本: {os.path.basename(path)}, 事件流 0x{len(ev):X}")

    # 收集每帧槽 12（若存在）的 blob
    blobs = []   # (frame, slot_pos_in_area, blob)
    for k in range(EVT_NF):
        area = ev[k*EVT_FRAME + EVT_TBL : k*EVT_FRAME + EVT_FRAME]
        for m in slot_marks(area):
            if area[m+1] == 12:
                blob = area[m + BLOB_OFF : m + BLOB_OFF + BLOB_LEN]
                if len(blob) == BLOB_LEN:
                    blobs.append((k, m, blob))
                break
    print(f"槽12 每帧出现数: {len(blobs)}/{EVT_NF}")

    # 1) 相邻帧 blob XOR 与字节级差分统计
    n = min(len(blobs), 200)
    xor_zero = 0; diff_total = 0; diff_cnt = 0
    i16_changes = Counter()
    for i in range(1, n):
        f0, _, a = blobs[i-1]
        f1, _, c = blobs[i]
        xr = bytes(x ^ y for x, y in zip(a, c))
        xor_zero += sum(1 for x in xr if x == 0)
        # 字节级有符号差（环绕）
        for x, y in zip(a, c):
            d = (y - x + 256) % 256
            if d > 128: d -= 256
            diff_total += abs(d); diff_cnt += 1
        # i16 视角差分（blob 按 i16 拆）
        for j in range(0, BLOB_LEN - 1, 2):
            va = struct.unpack_from("<h", a, j)[0]
            vc = struct.unpack_from("<h", c, j)[0]
            if va != vc:
                i16_changes[abs(vc - va) >> 8] += 1
    print(f"相邻帧 blob 逐字节 XOR==0 占比: {xor_zero/((n-1)*BLOB_LEN):.1%} "
          f"(均值绝对差 {diff_total/diff_cnt:.1f}/字节)")

    # 2) float32 视角：同位置 float 差值
    print(f"\n=== float32 视角（4B 对齐，相邻帧同位置差值）===")
    fdiff = []
    for i in range(1, min(n, 60)):
        _, _, a = blobs[i-1]
        _, _, c = blobs[i]
        for j in range(0, BLOB_LEN - 3, 4):
            va = struct.unpack_from("<f", a, j)[0]
            vc = struct.unpack_from("<f", c, j)[0]
            d = vc - va
            if abs(d) < 1e6:   # 滤掉 NaN/Inf/异常
                fdiff.append((j, d))
    small = [d for _, d in fdiff if abs(d) < 50]
    print(f"4B 位置总数: {len(fdiff)}, |d|<50 的: {len(small)} "
          f"({100*len(small)/len(fdiff):.1f}%)")
    if small:
        print(f"  |d|<50 的范围: {min(small):.2f} .. {max(small):.2f}, "
              f"中位 {sorted(small)[len(small)//2]:.3f}")
        # 每个 4B 槽位的平均 |d|
        pos_stat = {}
        for j, d in fdiff:
            if abs(d) < 50:
                pos_stat.setdefault(j, []).append(abs(d))
        tops = sorted(pos_stat.items(), key=lambda kv: -len(kv[1]))[:8]
        print(f"  变化集中的 4B 位置 top8: "
              f"{[(hex(j), len(v), round(sum(v)/len(v),3)) for j, v in tops]}")

    # 3) 单帧 blob 内部：4B 对齐 float 值域
    _, _, a = blobs[0]
    floats = [struct.unpack_from("<f", a, j)[0] for j in range(0, BLOB_LEN-3, 4)]
    valid = [x for x in floats if abs(x) < 1e4]
    print(f"\n帧{blobs[0][0]} 槽12 blob 内 4B float（|v|<1e4）: {len(valid)}/{len(floats)}")
    if valid:
        print(f"  min={min(valid):.2f} max={max(valid):.2f} 前8={[round(x,2) for x in valid[:8]]}")
        # 看是否有球场坐标特征（|x|<52.5, |y|<34, |z| 无约束）
        court = [x for x in valid if abs(x) <= 60]
        print(f"  落在 ±60（球场尺度）的: {len(court)}/{len(valid)}")

    # 4) blob 内结构：高熵区在哪些 4B 位置（跨帧恒定 vs 变化）
    print(f"\n=== blob 内 4B 槽位跨帧稳定性（前 60 帧）===")
    stab = []
    for j in range(0, BLOB_LEN - 3, 4):
        vals = set()
        for i in range(min(60, n)):
            _, _, blob = blobs[i]
            vals.add(struct.unpack_from("<I", blob, j)[0])
        stab.append((j, len(vals)))
    stable = [j for j, v in stab if v <= 2]
    print(f"跨 60 帧几乎不变(≤2 值)的 4B 位置: {len(stable)}/{len(stab)}")
    if stable:
        print(f"  stable 位置: {[hex(j) for j in stable[:20]]}")

if __name__ == "__main__":
    main()
