#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""解析 ML 存档中的注册球员 ID 配对表（u32 reg_id / db_id 交错），并与事件表 f2_hi 做覆盖度核验。

仅处理已解密的存档 decoded/ML00000000.data（用户自有样例，不涉及加密包）。
"""
import struct
import csv
import os

BASE = os.path.dirname(os.path.abspath(__file__))
DEC = os.path.join(BASE, "decoded")
OUT = os.path.join(BASE, "outputs")
os.makedirs(OUT, exist_ok=True)

def load(fn):
    return open(os.path.join(DEC, fn), "rb").read()

def find_clusters(b, lo=10000, hi=60000, min_run=8):
    """返回连续 u32 落在 [lo,hi] 的簇 [(start_off, count)]"""
    n = len(b)
    cands = []
    run = 0
    start =  rownull = 0
    i = 0
    runs = []
    while i + 4 <= n:
        v = struct.unpack_from("<I", b, i)[0]
        if lo <= v <= hi:
            if run == 0:
                start = i
            run += 1
        else:
            if run >= min_run:
                runs.append((start, run))
            run = 0
        i += 4
    if run >= min_run:
        runs.append((start, run))
    return runs

def parse_cluster(b, start, count):
    vals = [struct.unpack_from("<I", b, start + 4*k)[0] for k in range(count)]
    a = vals[0::2]   # 偶数位
    c = vals[1::2]   # 奇数位
    def monotonic(seq):
        ok = True
        for i in range(1, len(seq)):
            if seq[i] < seq[i-1]:
                ok = False
                break
        return ok
    return a, c, monotonic(a), monotonic(c)

def main():
    fn = "ML00000000.data"
    b = load(fn)
    runs = find_clusters(b)
    print(f"[{fn}] clusters>=8: {len(runs)}")
    reg_ids = set()
    db_ids = set()
    rows = []
    for (s, cnt) in runs:
        a, c, ma, mc = parse_cluster(b, s, cnt)
        rows.append((hex(s), cnt, ma, mc, len(a), len(c)))
        # 两种取值都收集（先不预设哪一个是 reg / db）
        reg_ids.update(a)
        db_ids.update(c)
    # 报告
    for r in rows[:20]:
        print("  off=%s count=%d  a_mono=%s c_mono=%s  |a|=%d |c|=%d" % r)
    print(f"合并 A(偶数位)集合大小={len(reg_ids)}  C(奇数位)集合大小={len(db_ids)}")
    union = reg_ids | db_ids
    print(f"两者并集={len(union)}")

    # 与事件表对比
    evt_path = os.path.join(OUT, "event_table_clean.csv")
    if os.path.exists(evt_path):
        f2 = []
        with open(evt_path, newline="") as f:
            rd = csv.DictReader(f)
            for row in rd:
                try:
                    f2.append(int(row["f2_hi(player_id)"]))
                except (KeyError, ValueError):
                    pass
        print(f"\n事件表 f2_hi 条数={len(f2)}  范围[{min(f2)},{max(f2)}]")
        in_a = sum(1 for x in f2 if x in reg_ids)
        in_c = sum(1 for x in f2 if x in db_ids)
        print(f"落在 A(偶数位)集合: {in_a}/{len(f2)}")
        print(f"落在 C(奇数位)集合: {in_c}/{len(f2)}")
        # 展示若干命中样例
        hit_a = [x for x in f2 if x in reg_ids][:10]
        hit_c = [x for x in f2 if x in db_ids][:10]
        print("  f2_hi 命中 A 样例:", hit_a)
        print("  f2_hi 命中 C 样例:", hit_c)

    # 导出注册表
    with open(os.path.join(OUT, "reg_ids_ML0.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["offset", "cluster_count", "kind", "id"])
        for (s, cnt) in runs:
            a, c, _, _ = parse_cluster(b, s, cnt)
            for x in a:
                w.writerow([hex(s), cnt, "even", x])
            for x in c:
                w.writerow([hex(s), cnt, "odd", x])
    print("\n已导出 outputs/ 注册表候选 reg_ids_ML0.csv")

if __name__ == "__main__":
    main()
