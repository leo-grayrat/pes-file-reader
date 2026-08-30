#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""probe_ml_tables.py -- 对每个候选 stride，找 ML/BL 中最大的 player_id 等差数列链，
定位疑似球员实例/注册/合约表，dump 原始字节辅助判读。

用法:
  python probe_ml_tables.py ML00000000            # 自动扫常用 stride
  python probe_ml_tables.py ML00000000 112 164 380 312  # 指定 stride
"""
import os, sys, csv, array, collections, struct
BASE = os.path.dirname(os.path.abspath(__file__))
DEC = os.path.join(BASE, "decoded")
OUT = os.path.join(BASE, "outputs")


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


def largest_chain(hit_offsets, stride):
    posset = set(hit_offsets)
    best = (0, 0, 0)  # (base, end, count)
    for st in hit_offsets:
        if (st - stride) in posset:
            continue
        cnt = 1
        cur = st
        while (cur + stride) in posset:
            cur += stride
            cnt += 1
        if cnt > best[2]:
            best = (st, cur, cnt)
    return best


def main():
    stem = sys.argv[1] if len(sys.argv) > 1 else "ML00000000"
    strides = [int(x) for x in sys.argv[2:]] or [16, 20, 24, 32, 40, 108, 112, 124,
                                                 152, 164, 284, 312, 360, 380, 132, 192]
    ids = load_edit_ids()
    path = os.path.join(DEC, stem + ".data")
    data = open(path, "rb").read()
    n = len(data) // 4
    a = array.array("I")
    a.frombytes(data[:n * 4])
    hits = [i * 4 for i, v in enumerate(a) if v in ids]
    print(f"{stem}: size={len(data)} edit_ids={len(ids)} hit_offsets={len(hits)}")
    results = []
    for S in strides:
        base, end, cnt = largest_chain(hits, S)
        if cnt >= 20:
            results.append((cnt, S, base, end))
    results.sort(reverse=True)
    print(f"{'cnt':>7} {'stride':>7} {'base':>12} {'end':>12} {'size':>10}")
    for cnt, S, base, end in results:
        size = cnt * S
        print(f"{cnt:>7} {S:>7} 0x{base:>10X} 0x{end:>10X} {size:>10}")
    # dump 样本：取记录数最多的两条
    for cnt, S, base, end in results[:2]:
        print(f"\n--- 样本 stride={S} base=0x{base:X} cnt={cnt} ---")
        for k in range(min(3, cnt)):
            o = base + k * S
            rec = data[o:o + S]
            pid = struct.unpack_from("<I", rec, 0)[0]
            # 尝试把偏移 4 起的 u32 也打印
            extra = [struct.unpack_from("<I", rec, j)[0] for j in range(4, min(S, 32), 4)]
            print(f"  rec#{k} @0x{o:X} pid={pid} rec={rec[:32].hex()} u32@4..={extra}")


if __name__ == "__main__":
    main()
