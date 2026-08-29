#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bl_ml_probe37: 在解密后的 EDIT 数据库 (decoded/EDIT00000000.data) 中
定位 PES2021 球员记录阵列 (Player.bin 结构):
  - 每条 240 字节, 首字段 u32 = 球员 ID (>= 0x100000 = 1048576)
  - 第 2 字段常用 u32 同为 id 或版本
通过扫描 stride-240 且首 u32 落在数据库 ID 区间的连续段来定位。
"""
import struct, os

BASE = os.path.dirname(os.path.abspath(__file__))
EDIT = os.path.join(BASE, "decoded", "EDIT00000000.data")
STRIDE = 240
DB_ID_MIN = 0x100000      # 1048576
DB_ID_MAX = 0x100000 + 300000

b = open(EDIT, "rb").read()
N = len(b)
print(f"EDIT data size = {N} ({N/1024/1024:.2f} MB)")


def scan_stride_240():
    """扫描所有 stride=240 起点, 找首 u32 落在 DB ID 区间的连续阵列"""
    candidates = []  # (base_off, count)
    # 起点按 4 字节对齐尝试
    for start in range(0, N - STRIDE, 4):
        # 从 start 起, 每 240 字节取首 u32, 看是否连续落在 DB ID 区间
        cnt = 0
        off = start
        while off + STRIDE <= N:
            v = struct.unpack_from("<I", b, off)[0]
            if DB_ID_MIN <= v <= DB_ID_MAX:
                cnt += 1
                off += STRIDE
            else:
                break
        if cnt >= 20:
            candidates.append((start, cnt))
    candidates.sort(key=lambda c: -c[1])
    return candidates


print("== 扫描 stride=240 的数据库球员记录阵列 ==")
cands = scan_stride_240()
print(f"候选阵列(连续>=20条): {len(cands)}")
for base, cnt in cands[:15]:
    first = struct.unpack_from("<I", b, base)[0]
    last = struct.unpack_from("<I", b, base + (cnt - 1) * STRIDE)[0]
    print(f"  base={hex(base)}  count={cnt}  id范围={first}..{last} (0x{first:x}..0x{last:x})")

if cands:
    base, cnt = cands[0]
    print(f"\n== 取最大阵列 @ {hex(base)}, 前 5 条记录 ==")
    for k in range(5):
        off = base + k * STRIDE
        rec = b[off:off + STRIDE]
        id0, id1 = struct.unpack_from("<II", rec, 0)
        # 在记录内找可读 ASCII 串 (名字)
        runs = []
        cur = bytearray(); s = 0
        for i, x in enumerate(rec):
            if 32 <= x < 127:
                if not cur: s = i
                cur.append(x)
            else:
                if len(cur) >= 2:
                    runs.append((s, bytes(cur).decode("latin1")))
                cur = bytearray()
        if len(cur) >= 2:
            runs.append((s, bytes(cur).decode("latin1")))
        print(f"  rec#{k} id={id0} (0x{id0:x}) id2={id1}  ascii:{runs[:8]}")

    # 导出该阵列前 500 条 (id, 以及记录内所有 ascii 串) 供人工核对
    out = os.path.join(BASE, "outputs", "edit_player_sample.csv")
    with open(out, "w", encoding="utf-8") as f:
        f.write("row,player_id,id2,ascii_runs\n")
        for k in range(min(cnt, 500)):
            off = base + k * STRIDE
            rec = b[off:off + STRIDE]
            id0, id1 = struct.unpack_from("<II", rec, 0)
            runs = []
            cur = bytearray()
            for i, x in enumerate(rec):
                if 32 <= x < 127:
                    cur.append(x)
                else:
                    if len(cur) >= 2:
                        runs.append(cur.decode("latin1"))
                    cur = bytearray()
            if len(cur) >= 2:
                runs.append(cur.decode("latin1"))
            joined = "|".join(runs)
            f.write(f"{k},{id0},{id1},{joined}\n")
    print(f"\n导出样例 -> {out}")
