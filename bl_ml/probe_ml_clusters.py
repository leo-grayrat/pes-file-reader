#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""probe_ml_clusters.py -- 对队块外 EDIT-id 命中做最大等差聚类, 定位真实表(stride/base/extent),
并 dump 记录内容判读字段(condition/合约/成长/训练/引用)。
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


def in_teamblock(off):
    if TB_OFF <= off < TB_OFF + N_TEAMS * TB_SIZE:
        return (off - TB_OFF) // TB_SIZE
    return None


def maximal_runs(offs, stride, minlen=50):
    """offs 已排序; 返回所有连续 gap==stride 的最大段 [(base,count,end)]。"""
    runs = []
    i = 0
    n = len(offs)
    while i < n:
        j = i
        while j + 1 < n and offs[j+1] - offs[j] == stride:
            j += 1
        if j - i + 1 >= minlen:
            base = offs[i]; end = offs[j]
            runs.append((base, j - i + 1, end))
        i = j + 1
    return runs


def main():
    ids = load_edit_ids()
    stem = sys.argv[1] if len(sys.argv) > 1 else "ML00000000"
    d = open(os.path.join(DEC, stem + ".data"), "rb").read()
    a = array.array("I"); a.frombytes(d[:len(d)//4*4])
    hits = sorted(h*4 for h, v in enumerate(a) if v in ids)
    ext = [h for h in hits if in_teamblock(h) is None]
    print(f"{stem}: 队块外命中={len(ext)}")
    for S in (16, 20, 12, 24, 40, 112, 164, 32):
        runs = maximal_runs(ext, S, minlen=50)
        runs.sort(key=lambda r: -r[1])
        total = sum(r[1] for r in runs)
        print(f"\n--- stride={S}B: 最大段数={len(runs)} 覆盖命中={total} ---")
        for base, cnt, end in runs[:6]:
            print(f"    base=0x{base:X} count={cnt} end=0x{end:X} size={cnt*S}B")


if __name__ == "__main__":
    main()
