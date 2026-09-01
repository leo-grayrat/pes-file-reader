#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""probe_livedata.py -- 探查 0xC00000 附近的小整数数组区(疑似 per-player 状态/表单/成长):
(1) 该区是否含 EDIT id(决定能否关联到球员)
(2) 数值分布(0-7? 0-100? 是否带 stride)
(3) dump 样本
"""
import os, struct, collections
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEC = os.path.join(BASE, "decoded")
OUT = os.path.join(BASE, "outputs")


def load_edit_ids():
    s = set()
    import csv
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
    d = open(os.path.join(DEC, "ML00000000.data"), "rb").read()
    # 候选大段
    regions = [(0xC1C6EF, 0xC1FAD4, "u8[0,7]max"), (0xC4910B, 0xC50820, "u8[0,100]max")]
    for LO, HI, tag in regions:
        seg = d[LO:HI]
        # EDIT id 命中
        a = struct.unpack_from("<%dI" % (len(seg)//4), seg, 0)
        idhits = [i*4 for i, v in enumerate(a) if v in ids]
        # u8 分布
        dist = collections.Counter(seg)
        nonzero = sum(1 for v in seg if v != 0)
        in7 = sum(1 for v in seg if 0 <= v <= 7)
        in100 = sum(1 for v in seg if 0 <= v <= 100)
        print(f"\n=== {tag} 0x{LO:X}..0x{HI:X} ({len(seg)}B) ===")
        print(f"  EDIT id 命中: {len(idhits)}  (若>0 可关联到球员)")
        print(f"  u8: 非零={nonzero}  in[0,7]={in7}  in[0,100]={in100}")
        print(f"  值分布 TOP8: {dist.most_common(8)}")
        # 首 64 字节 u8
        print(f"  u8[0:64]: {list(seg[:64])}")
        # 首 32 u16
        u16 = [struct.unpack_from("<H", seg, j)[0] for j in range(0, 64, 2)]
        print(f"  u16[0:32]: {u16}")
        # 首 16 u32
        u32 = [struct.unpack_from("<I", seg, j)[0] for j in range(0, 64, 4)]
        print(f"  u32[0:16]: {u32}")


if __name__ == "__main__":
    main()
