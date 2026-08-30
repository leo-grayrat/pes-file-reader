#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""analyze_teamblock.py -- 跨 700 队对 ML 队块(0x690)做逐偏移方差分析,
定位未知区(0x280..0x690)里的候选枚举/数值字段, 重点找 per-player 动态数组。
"""
import os, struct, collections
BASE = os.path.dirname(os.path.abspath(__file__))
DEC = os.path.join(BASE, "decoded")
TB_OFF = 0x100
TB_SIZE = 0x690
N_TEAMS = 700


def load_blocks(stem):
    b = open(os.path.join(DEC, stem + ".data"), "rb").read()
    blocks = [b[TB_OFF + r * TB_SIZE: TB_OFF + r * TB_SIZE + TB_SIZE] for r in range(N_TEAMS)]
    return b, blocks


def variance_report(blocks, lo, hi, label):
    """对 [lo,hi) 区间按对齐 u32 逐偏移做跨队方差分析。"""
    print(f"\n===== {label}: 队块 +0x{lo:X}..+0x{hi:X} (逐偏移 u32 方差) =====")
    rows = []
    for off in range(lo, hi, 4):
        vals = [struct.unpack_from("<I", blk, off)[0] for blk in blocks]
        c = collections.Counter(vals)
        distinct = len(c)
        mx = max(vals); mn = min(vals)
        # 候选: 非纯常量, 且 distinct 落在"枚举/小数值"区间
        if distinct == 1:
            kind = "const"
        elif distinct <= 64:
            kind = "ENUM?"
        elif mx - mn <= 0xFFFF and distinct <= 400:
            kind = "smallint?"
        else:
            kind = "wide"
        rows.append((off, distinct, mn, mx, kind, c.most_common(3)))
    # 打印非 const 的, 按 distinct 升序(枚举优先)
    nonconst = [r for r in rows if r[4] != "const"]
    nonconst.sort(key=lambda r: r[1])
    print(f"  总偏移={len(rows)} 非const={len(nonconst)}")
    for off, distinct, mn, mx, kind, top in nonconst[:60]:
        top_s = ", ".join(f"0x{v:08X}({cnt})" for v, cnt in top)
        print(f"  +0x{off:04X} d={distinct:4d} [{mn:>10},{mx:>10}] {kind:9s} top: {top_s}")
    return rows


def dump_region(blocks, team, lo, hi, stride, label):
    blk = blocks[team]
    print(f"\n--- {label}: team#{team} +0x{lo:X}..+0x{hi:X} stride {stride} ---")
    for off in range(lo, hi, stride):
        chunk = blk[off:off + stride]
        if stride == 16:
            u = struct.unpack_from("<4I", chunk, 0)
            asc = "".join(chr(c) if 32 <= c < 127 else "." for c in chunk)
            print(f"  +0x{off:04X}: {list(u)}  {asc}")
        elif stride == 8:
            u = struct.unpack_from("<2I", chunk, 0)
            print(f"  +0x{off:04X}: {list(u)}")
        else:
            asc = "".join(chr(c) if 32 <= c < 127 else "." for c in chunk)
            print(f"  +0x{off:04X}: {chunk.hex()}  {asc}")


def find_perplayer_array(blocks, lo, hi, max_entries, field_strides):
    """在 [lo,hi) 里找: 跨队一致、且每个队内沿某 stride 有 N 项(类似枚举/小整数)的数组。
    用 team#0 的 squad 数(33)作参照: 期望前 ~33 项有数据, 其余为 0/填充。"""
    print(f"\n===== per-player 数组扫描 +0x{lo:X}..+0x{hi:X} =====")
    blk0 = blocks[0]
    # 先找 team#0 阵容数
    squad = []
    for k in range(60):
        pid = struct.unpack_from("<I", blk0, 0xA0 + k * 8)[0]
        if pid == 0 or pid == 0xFFFFFFFF:
            break
        squad.append(pid)
    n0 = len(squad)
    print(f"  team#0 阵容数={n0}")
    for es in field_strides:
        # 候选字段: 每个 entry 取第 0 字节(condition 类枚举)
        cand = []
        for off in range(lo, hi - es * max_entries, es):
            vals = [blk0[off + i * es] for i in range(max_entries)]
            # 前 n0 项非全0 且都小(<=31), 其后多为 0
            head = vals[:n0]
            tail = vals[n0:]
            if all(0 <= v <= 31 for v in head) and sum(head) > 0 and sum(1 for v in tail if v != 0) <= max(2, len(tail)//4):
                cand.append((off, head, tail))
        if cand:
            print(f"  stride={es}: 命中 {len(cand)} 个候选(取前 5)")
            for off, head, tail in cand[:5]:
                print(f"    +0x{off:04X} head[:n0]={head} tail[:8]={tail[:8]}")


def main():
    b, blocks = load_blocks("ML00000000")
    # 1) 全块 u32 方差(确认已知字段位置)
    variance_report(blocks, 0, 0x690, "FULL")
    # 2) 重点未知区
    variance_report(blocks, 0x280, 0x690, "UNKNOWN 0x280..0x690")
    # 3) dump team#0 未知区两种 stride 供肉眼判读
    dump_region(blocks, 0, 0x280, 0x620, 16, "team#0 region@+0x280 stride16 (60*16=960)")
    dump_region(blocks, 0, 0x280, 0x690, 8, "team#0 region@+0x280 stride8")
    # 4) per-player 数组扫描
    find_perplayer_array(blocks, 0x280, 0x690, max_entries=60,
                         field_strides=[8, 12, 16, 20, 24, 32])


if __name__ == "__main__":
    main()
