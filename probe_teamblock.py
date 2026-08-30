#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""probe_teamblock.py -- 完整 dump 一个 ML 队块(0x690)并判读, 以及队块尾之后的区域,
看 ML 球员动态数据是否内嵌在队块(阵容+动态字段)还是独立成表。
"""
import os, struct
BASE = os.path.dirname(os.path.abspath(__file__))
DEC = os.path.join(BASE, "decoded")
EDIT_IDS = None


def load_edit_ids():
    s = set()
    import csv
    p = os.path.join(BASE, "outputs", "parsed_edit_players_EDIT00000000.csv")
    if os.path.exists(p):
        with open(p, encoding="utf-8") as f:
            for r in csv.DictReader(f):
                try:
                    s.add(int(r["player_id"]))
                except (ValueError, KeyError):
                    pass
    return s


def dump(stem, off, nbytes, tag):
    global EDIT_IDS
    b = open(os.path.join(DEC, stem + ".data"), "rb").read()
    rec = b[off:off + nbytes]
    print(f"\n=== {tag} @0x{off:X} ({nbytes}B) ===")
    # u32 视图
    u32 = [struct.unpack_from("<I", rec, i * 4)[0] for i in range(nbytes // 4)]
    print("u32[0:24]:", u32[:24])
    if EDIT_IDS is not None:
        hits = [(i * 4, v) for i, v in enumerate(u32) if v in EDIT_IDS]
        print(f"其中 EDIT id 命中: {len(hits)} ->", hits[:12])
    # 名字区(0x5E4 相对队块)在此 dump 里需加 off
    nm_off = 0x5E4
    if off + nm_off + 64 <= len(b):
        name = b[off + nm_off:off + nm_off + 64].split(b"\x00")[0]
        print(f"name(@+0x5E4)={name!r}")


def main():
    global EDIT_IDS
    EDIT_IDS = load_edit_ids()
    print(f"EDIT ids={len(EDIT_IDS)}")
    # 队块 #0
    dump("ML00000000", 0x100, 0x690, "TeamBlock#0")
    # 队块尾之后(未知区起点附近)各 dump 一块
    for o in (0x2D7900, 0x2D7A00, 0x2D8000, 0x2D9000):
        dump("ML00000000", o, 0x200, f"region@0x{o:X}")


if __name__ == "__main__":
    main()
