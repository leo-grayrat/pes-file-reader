#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""probe_ml_players.py -- 在 ML/BL 存档中用 EDIT 球员 id 簇定位球员实例表 base/stride。

思路：EDIT 球员 id 是全局唯一的 u32。ML/BL 球员实例记录若以 player_id 起头（固定偏移），
则文件中所有该字段出现的位置构成等差数列，公差=记录步长(stride)。扫描全文件 uint32，
统计命中 EDIT id 的位置，取最常见间隔作为 stride 候选，再聚链求表 base 与记录数。
"""
import os, sys, csv, array, collections
BASE = os.path.dirname(os.path.abspath(__file__))
DEC = os.path.join(BASE, "decoded")
OUT = os.path.join(BASE, "outputs")


def load_edit_ids(tag="EDIT00000000"):
    s = set()
    p = os.path.join(OUT, f"parsed_edit_players_{tag}.csv")
    if not os.path.exists(p):
        return s
    with open(p, encoding="utf-8") as f:
        for r in csv.DictReader(f):
            try:
                s.add(int(r["player_id"]))
            except (ValueError, KeyError):
                pass
    return s


def scan(path, ids):
    data = open(path, "rb").read()
    n = len(data) // 4
    a = array.array("I")
    a.frombytes(data[:n * 4])
    hits = [i for i, v in enumerate(a) if v in ids]
    total = len(hits)
    print(f"[scan] {os.path.basename(path)} size={len(data)} uint32={n} "
          f"edit_ids={len(ids)} hits={total}")
    if not hits:
        print("  无命中，该存档不含 EDIT id 簇")
        return
    gaps = collections.Counter()
    for i in range(1, total):
        g = (hits[i] - hits[i - 1]) * 4  # 字节间隔
        if 16 <= g <= 8192:
            gaps[g] += 1
    print("  间隔(字节) TOP10:", gaps.most_common(10))
    if not gaps:
        return
    stride, _ = gaps.most_common(1)[0]
    posset = set(h * 4 for h in hits)
    best = (0, 0, 0)
    for h in hits:
        st = h * 4
        if st not in posset or (st - stride) in posset:
            continue  # 只从链头开始
        cnt = 1
        cur = st
        while (cur + stride) in posset:
            cur += stride
            cnt += 1
        if cnt > best[2]:
            best = (st, cur, cnt)
    base, endoff, cnt = best
    print(f"  候选 stride={stride}B  表 base=0x{base:X}  end=0x{endoff:X} "
          f"记录数≈{cnt}  表大小≈{cnt * stride}B")
    for k in range(min(3, cnt)):
        o = base + k * stride
        print(f"    rec#{k} @0x{o:X} id={a[o // 4]:#010x}({a[o // 4]}) "
              f"bytes={data[o:o + 24].hex()}")


def main():
    stems = sys.argv[1:] or ["ML00000000", "BL00000000"]
    ids = load_edit_ids()
    print(f"EDIT id 集合大小: {len(ids)}")
    for stem in stems:
        p = os.path.join(DEC, stem + ".data")
        if not os.path.exists(p):
            print(f"[skip] {stem}: 未找到")
            continue
        scan(p, ids)


if __name__ == "__main__":
    main()
