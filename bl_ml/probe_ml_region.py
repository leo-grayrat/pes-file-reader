#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""probe_ml_region.py -- 映射 ML 未知区[0x2D7900,0x12A72FD]的常量填充表边界,
收集非常量(活跃)条目; 并解码队块#0 阵容区(@+0xA0 stride 8)的 (id, paired_u32)。
"""
import os, struct, csv, collections
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEC = os.path.join(BASE, "decoded")
OUT = os.path.join(BASE, "outputs")

LO, HI = 0x2D7900, 0x12A72FD


def load_edit_ids():
    s = set()
    p = os.path.join(OUT, "parsed_edit_players_EDIT00000000.csv")
    if os.path.exists(p):
        with open(p, encoding="utf-8") as f:
            for r in csv.DictReader(f):
                try:
                    s.add(int(r["player_id"]))
                except (ValueError, KeyError):
                    pass
    return s


def main():
    ids = load_edit_ids()
    b = open(os.path.join(DEC, "ML00000000.data"), "rb").read()
    a = struct.unpack_from("<%dI" % ((HI - LO) // 4), b, LO)
    n = len(a)
    # 找常量填充 run (>=50 条)
    runs = []
    i = 0
    while i < n:
        v = a[i]
        j = i
        while j < n and a[j] == v:
            j += 1
        if j - i >= 50:
            runs.append((LO + i * 4, LO + j * 4, v, j - i))
        i = j
    print(f"未知区常量填充表(>=50条): {len(runs)} 张")
    for st, en, v, cnt in runs[:20]:
        print(f"  0x{st:X}..0x{en:X}  值=0x{v:08X} 条数={cnt}  (~{cnt*4}B)")
    # 第一张大表: 收集非常量条目
    if runs:
        st, en, v, cnt = runs[0]
        vals = collections.Counter()
        samples = []
        for off in range(st, en, 4):
            x = struct.unpack_from("<I", b, off)[0]
            if x != v:
                vals[x] += 1
                if len(samples) < 20:
                    samples.append((off, x))
        print(f"\n表#0 (0x{st:X}, 默认0x{v:08X}) 非常量条目数={sum(vals.values())}")
        print(f"  非常量值 TOP10: {vals.most_common(10)}")
        print(f"  样本(off,val): {samples}")


def dump_squad():
    ids = load_edit_ids()
    b = open(os.path.join(DEC, "ML00000000.data"), "rb").read()
    off = 0x100 + 0xA0  # team#0 阵容区起点(推测)
    print(f"\n=== Team#0 阵容区 @0x{0x100 + 0xA0:X} stride 8 ===")
    rows = []
    for k in range(60):
        o = off + k * 8
        pid = struct.unpack_from("<I", b, o)[0]
        paired = struct.unpack_from("<I", b, o + 4)[0]
        if pid == 0 or pid == 0xFFFFFFFF:
            break
        nm = "EDIT" if pid in ids else "?"
        rows.append((k, pid, paired, nm))
    for k, pid, paired, nm in rows:
        print(f"  [{k:2}] pid={pid}({nm}) paired=0x{paired:08X} ({paired})")


if __name__ == "__main__":
    main()
    dump_squad()
