#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""probe_ml_chain.py -- 探查 0x320000 附近的球员关联/链记录结构:
(1) 找 'e5 07' 标签(u16 0x07E5)间距 -> 记录长
(2) dump 一条完整记录(到下一个标签或 FFFF 终止)
(3) 统计该区记录数 / 是否含 player_id 链
"""
import os, struct, collections
BASE = os.path.dirname(os.path.abspath(__file__))
DEC = os.path.join(BASE, "decoded")
TB_OFF = 0x100
TB_SIZE = 0x690
N_TEAMS = 700


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


def in_teamblock(off):
    if TB_OFF <= off < TB_OFF + N_TEAMS * TB_SIZE:
        return (off - TB_OFF) // TB_SIZE
    return None


def main():
    ids = load_edit_ids()
    d = open(os.path.join(DEC, "ML00000000.data"), "rb").read()
    LO, HI = 0x320000, 0x340000
    # 找 e5 07 标签(小端 u16=0x07E5)
    tags = []
    i = LO
    while i + 1 < HI:
        if d[i] == 0xE5 and d[i+1] == 0x07:
            tags.append(i)
        i += 1
    print(f"0x{LO:X}..0x{HI:X} 'e5 07' 标签数={len(tags)}")
    gaps = collections.Counter(tags[i+1]-tags[i] for i in range(len(tags)-1))
    print(f"  标签间距 TOP10: {gaps.most_common(10)}")
    if tags:
        # 找最常见间距作为记录长
        rs, _ = gaps.most_common(1)[0]
        print(f"  推测记录长={rs}B")
        # dump 第一条完整记录
        t0 = tags[0]
        t1 = t0 + rs if (t0+rs) in tags else (tags[1] if len(tags) > 1 else t0+512)
        rec = d[t0: t1]
        print(f"\n  记录 @0x{t0:X} (len={len(rec)}):")
        # u32 视图(前 32 个)
        u = [struct.unpack_from("<I", rec, j)[0] for j in range(0, min(len(rec), 128), 4)]
        print(f"  u32[0:32]: {u}")
        # 统计记录内 player_id 命中
        pidhits = [(j, struct.unpack_from("<I", rec, j)[0]) for j in range(0, len(rec)-3, 4) if struct.unpack_from("<I", rec, j)[0] in ids]
        print(f"  记录内 EDIT id 命中 {len(pidhits)}: {pidhits[:20]}")


if __name__ == "__main__":
    main()
