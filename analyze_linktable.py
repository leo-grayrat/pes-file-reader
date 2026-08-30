#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""选项 C：深挖 596B 'e5 07' 关联记录的头字段(h3/h4/h5/h7)与 entry 区语义。
不靠拍脑袋布局，逐字节重推 + 全量统计。"""
import os, struct, csv

DEC = "decoded"
OUT = "outputs"
TAG = "ML00000000"

def u32(b, o): return struct.unpack_from("<I", b, o)[0]

def load_edit_ids():
    s = set()
    p = os.path.join(OUT, "parsed_edit_players_EDIT00000000.csv")
    if os.path.exists(p):
        with open(p, encoding="utf-8") as f:
            for r in csv.DictReader(f):
                try: s.add(int(r["player_id"]))
                except (ValueError, KeyError): pass
    return s

def main():
    b = open(os.path.join(DEC, TAG + ".data"), "rb").read()
    ids = load_edit_ids()
    print(f"[*] file size={len(b)}  edit_ids={len(ids)}  min={min(ids)} max={max(ids)}")

    tags = [i for i in range(len(b) - 1) if b[i] == 0xE5 and b[i + 1] == 0x07]
    recs = []
    for i in range(len(tags) - 1):
        if tags[i + 1] - tags[i] == 596:
            o = tags[i]
            hdr = [u32(b, o + j * 4) for j in range(8)]
            recs.append((o, hdr))
    print(f"[*] 596B records: {len(recs)}")

    # ---- 头字段全量统计 ----
    cols = list(zip(*[h for _, h in recs]))
    names = ["h0", "h1", "h2(count)", "h3", "h4", "h5", "h6", "h7"]
    print("\n=== 头字段统计 (min/const?/distinct/∈edit_ids/∈edit_ids%) ===")
    for name, col in zip(names, cols):
        cmin, cmax = min(col), max(col)
        distinct = len(set(col))
        in_ids = sum(1 for x in col if x in ids)
        const = (distinct == 1)
        print(f"  {name:12s} min={cmin:>12} max={cmax:>12} distinct={distinct:>6} "
              f"in_edit_ids={in_ids:>5}({100*in_ids/len(col):.1f}%) constant={const}")

    # h2(count) 分布
    from collections import Counter
    print("\n  h2(count) 分布:", dict(Counter(cols[2]).most_common(12)))

    # ---- 重推 entry 区布局 ----
    # entry 区 = [+0x20, +0x254) = 564 字节。尝试 entry size ∈ {8,12,16,24,32}，
    # 把每条记录从 +0x20 起读 count 项，看哪个 size 下“首个 u32 ∈ EDIT ids”最干净。
    print("\n=== entry 区布局探测 (按 h2=count 项数解析) ===")
    for esz in (8, 12, 16, 24, 32):
        ok = 0
        total_entries = 0
        id_entries = 0
        for o, hdr in recs[:2000]:
            cnt = hdr[2]
            base = o + 32
            # 越界保护
            if base + cnt * esz > o + 596:
                continue
            eid = 0
            for k in range(cnt):
                a = u32(b, base + k * esz)
                if a in ids:
                    eid += 1
            total_entries += cnt
            id_entries += eid
            if eid >= max(1, cnt * 0.7):
                ok += 1
        print(f"  esz={esz:2d}: 前2000条中 {ok} 条 entry首字段≥70%∈EDITids; "
              f"entry总数={total_entries} 命中EDIT={id_entries}({100*id_entries/max(1,total_entries):.1f}%)")

    # ---- 逐字节 dump 第一条记录（含 u32/u16/u8）----
    o0 = recs[0][0]
    print(f"\n=== record[0] @ {o0:#x} 原始 596B ===")
    chunk = b[o0:o0 + 596]
    # u32 视图前 24 个 (96B)
    print("  u32[0..23] (前96B):")
    for j in range(0, 24, 4):
        vals = [u32(chunk, (j + k) * 4) for k in range(4)]
        print("   ", f"+{j*4:#04x}", vals)
    # 把 entry 区(从+0x20起)按 8B 和 12B 两种试读
    print("\n  entry 区 8B/项 (a,val) 前 10 项:")
    for k in range(10):
        a = u32(chunk, 32 + k * 8); v = u32(chunk, 32 + k * 8 + 4)
        print(f"    [{k:2d}] a={a:>10} val={v:>10} a∈edit={a in ids}")
    print("  entry 区 12B/项 (a,val,flag) 前 8 项:")
    for k in range(8):
        a = u32(chunk, 32 + k * 12); v = u32(chunk, 32 + k * 12 + 4); f = u32(chunk, 32 + k * 12 + 8)
        print(f"    [{k:2d}] a={a:>10} val={v:>10} flag={f:>10} a∈edit={a in ids}")

    # ---- h3/h4/h7 是否互相引用或引用其他记录 ----
    # 若 h3 是某记录在其 record 数组里的索引，或 h3 本身是另一个 EDIT id 命名空间...
    print("\n=== h3/h4 与 entry 首字段的关联 ===")
    # 收集所有 record 的 h3/h4
    all_h3 = set(cols[3]); all_h4 = set(cols[4])
    # entry 首字段(按 8B) 是否落在 h3/h4 集合
    hit_h3 = 0; hit_h4 = 0; nent = 0
    for o, hdr in recs[:3000]:
        cnt = hdr[2]; base = o + 32
        if base + cnt * 8 > o + 596: continue
        for k in range(cnt):
            a = u32(b, base + k * 8)
            nent += 1
            if a in all_h3: hit_h3 += 1
            if a in all_h4: hit_h4 += 1
    print(f"  entry首字段(8B)命中 h3 集合: {hit_h3}/{nent}  命中 h4 集合: {hit_h4}/{nent}")

    # h3 是否等于某 record 在“所有 596B 记录列表”里的偏移/序号?
    # 试: h3 是否等于某 entry 的 c 字段(第3个u32, 12B布局)
    print("\n  检查 h3 是否出现在 12B-entry 的 c(第3 u32) 字段:")
    hitc = 0; nc = 0
    for o, hdr in recs[:3000]:
        cnt = hdr[2]; base = o + 32
        if base + cnt * 12 > o + 596: continue
        for k in range(cnt):
            c = u32(b, base + k * 12 + 8)
            nc += 1
            if c in all_h3: hitc += 1
    print(f"    12B-entry 的 c 字段命中 h3 集合: {hitc}/{nc}")

if __name__ == "__main__":
    main()
