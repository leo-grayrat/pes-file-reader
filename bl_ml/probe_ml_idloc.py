#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""probe_ml_idloc.py -- 决定性测试: ML 里 EDIT 球员 id 出现在哪里?
(A) 全文件 EDIT-id u32 命中总数 + 位置分布(队块阵容区 vs 外部)
(B) 0x280..0x380 位掩码区是否跨队常量
(C) diff team#0 块 ML00000000 vs ML00000001, 找动态字节
(D) 队块外命中按 stride 聚类, 探查可能的全局 per-player 表
"""
import os, sys, csv, array, collections, struct
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEC = os.path.join(BASE, "decoded")
OUT = os.path.join(BASE, "outputs")
TB_OFF = 0x100
TB_SIZE = 0x690
N_TEAMS = 700


def load_edit_ids(tag="EDIT00000000"):
    s = set()
    p = os.path.join(OUT, f"parsed_edit_players_{tag}.csv")
    if os.path.exists(p):
        with open(p, encoding="utf-8") as f:
            for r in csv.DictReader(f):
                try:
                    s.add(int(r["player_id"]))
                except (ValueError, KeyError):
                    pass
    return s


def teamblock_region(off):
    """返回 off 落在哪个队块(及块内偏移), 或 None(队块外)。"""
    if TB_OFF <= off < TB_OFF + N_TEAMS * TB_SIZE:
        r = (off - TB_OFF) // TB_SIZE
        if 0 <= r < N_TEAMS:
            return r, off - TB_OFF - r * TB_SIZE
    return None


def main():
    ids = load_edit_ids()
    print(f"EDIT id 集合={len(ids)}")
    # 载入两个 ML 文件
    data = {}
    arr = {}
    for stem in ("ML00000000", "ML00000001"):
        d = open(os.path.join(DEC, stem + ".data"), "rb").read()
        data[stem] = d
        a = array.array("I"); a.frombytes(d[:len(d)//4*4]); arr[stem] = a
    for stem in ("ML00000000", "ML00000001"):
        d = data[stem]; a = arr[stem]
        hits = [i*4 for i, v in enumerate(a) if v in ids]
        in_block = [h for h in hits if teamblock_region(h)]
        out_block = [h for h in hits if not teamblock_region(h)]
        print(f"\n[{stem}] 总命中={len(hits)}  队块内={len(in_block)}  队块外={len(out_block)}")
        # 队块内再细分: 是否都在 +0xA0 阵容区(0xA0..0x280)
        in_squad = [h for h in in_block if 0xA0 <= teamblock_region(h)[1] < 0x280]
        print(f"  队块内-阵容区(0xA0..0x280)={len(in_squad)}  队块内-其他={len(in_block)-len(in_squad)}")
        # 队块外命中: 按 64B 桶聚合, 看分布
        if out_block:
            buckets = collections.Counter(h // 0x10000 for h in out_block)
            print(f"  队块外命中分布(按64KB桶, TOP8): {buckets.most_common(8)}")
            # 队块外命中是否构成某 stride 链
            pos = sorted(out_block)
            gaps = collections.Counter((pos[i]-pos[i-1]) for i in range(1, len(pos)))
            print(f"  队块外命中间隔 TOP8: {gaps.most_common(8)}")

    # (B) 0x280..0x380 跨队常量?
    d0 = data["ML00000000"]
    ref = d0[TB_OFF + 0x280: TB_OFF + 0x380]
    same = sum(1 for r in range(N_TEAMS)
               if d0[TB_OFF + r*TB_SIZE + 0x280: TB_OFF + r*TB_SIZE + 0x380] == ref)
    print(f"\n(B) 0x280..0x380 与队#0 相同的队数: {same}/{N_TEAMS}  (若=700 即全局常量表)")
    # 0x4F0..0x518 (顺序计数区) 跨队常量?
    ref2 = d0[TB_OFF + 0x4F0: TB_OFF + 0x51C]
    same2 = sum(1 for r in range(N_TEAMS)
                if d0[TB_OFF + r*TB_SIZE + 0x4F0: TB_OFF + r*TB_SIZE + 0x51C] == ref2)
    print(f"    0x4F0..0x51C 与队#0 相同的队数: {same2}/{N_TEAMS}")

    # (C) diff team#0 块 ML00000000 vs ML00000001
    b0 = d0[TB_OFF: TB_OFF + TB_SIZE]
    b1 = data["ML00000001"][TB_OFF: TB_OFF + TB_SIZE]
    diffs = [o for o in range(TB_SIZE) if b0[o] != b1[o]]
    print(f"\n(C) team#0 块 ML0 vs ML1 不同字节数: {len(diffs)}/{TB_SIZE}")
    if diffs:
        # 按 4 对齐聚合
        du = sorted(set(o // 4 * 4 for o in diffs))
        print(f"    不同 u32 偏移(前40): {[hex(x) for x in du[:40]]}")
        # 看 0xA0 阵容区是否相同(若相同说明两个存档同一批球员)
        squad_same = all(b0[0xA0+k*8:0xA0+k*8+8] == b1[0xA0+k*8:0xA0+k*8+8] for k in range(60))
        print(f"    阵容区(0xA0,60项) 是否两文件相同: {squad_same}")


if __name__ == "__main__":
    main()
