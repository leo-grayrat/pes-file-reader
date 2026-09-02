#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
probe_sched_layout.py — 给赛程表做字节级占用热图，定出「596 B 里哪些偏移真的落盘」。

背景：exe 的拷贝赋值代码给出了赛程条目的字段图（docs/exe-save-layout.md §7.6），
但那是**内存对象**的布局。内存对象里的运行时缓存字段完全可能不落盘，
所以不能直接拿字段图当存档字段表用。这里反过来问数据：

  1. 赛程表在存档里到哪结束（§7.5 的容量上限 13000 是否吃满）；
  2. 596 个字节偏移里，每一个的取值种类 / 非零率是多少；
  3. 哪些偏移恒为 0（= 内存里有、存档里不落盘），哪些是真正的信息位。

只读：仅读取已解密的 .data 副本。

用法：
  python probe_sched_layout.py                     # 全部 ML 存档，输出热图摘要
  python probe_sched_layout.py --full              # 逐偏移完整列表
  python probe_sched_layout.py --file ML00000000   # 只看一个存档
"""
import os
import struct
import sys
from collections import Counter

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEC = os.path.join(BASE, "decoded")

SCHED_BASE = 0x3299B0
SCHED_STRIDE = 0x254
SCHED_CAP = 13000            # §7.5 从 exe 读到的容量上限
OFF_SEQ, OFF_DATE, OFF_ROUND = 0x150, 0x158, 0x160

# §7.6 字段图给出的显式字段（偏移, 宽度, 备注）
FIELDMAP = [
    (0x00, 2, ""),
    (0x04, 4, "位域 12+2+1 bit"),
    (0x08, 4, ""),
    (0x0C, 4, ""),
    (0x10, 1, ""),
    (0x11, 1, ""),
    (0x12, 2, ""),
    (0x14, 4, "14 bit 子对象"),
    (0x18, 4, "14 bit 子对象"),
    (0x1C, 1, ""), (0x1D, 1, ""), (0x1E, 1, ""),
    (0x1F, 1, ""), (0x20, 1, ""), (0x21, 1, ""),
]


def u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def scan_entries(b):
    """切出赛程表的条目列表，并定位表的真实末尾。"""
    entries = []
    last_nonempty = -1
    for i in range(SCHED_CAP):
        o = SCHED_BASE + i * SCHED_STRIDE
        if o + SCHED_STRIDE > len(b):
            break
        e = b[o:o + SCHED_STRIDE]
        entries.append(e)
        if any(e):
            last_nonempty = i
    return entries, last_nonempty


def classify(e):
    """把一条条目分类：空 / 哨兵 / 有日期的场次 / 其它非空。"""
    if not any(e):
        return "zero"
    seq = u32(e, OFF_SEQ)
    y = u16(e, OFF_DATE)
    rnd = u32(e, OFF_ROUND)
    if seq == 0xFFFFFFFF or seq == 0xFFFF:
        return "sentinel"
    if 1990 <= y <= 2100 and rnd < 1000:
        return "match"
    return "other"


def probe(path, full=False):
    b = open(path, "rb").read()
    name = os.path.basename(path)
    entries, last = scan_entries(b)
    kinds = Counter(classify(e) for e in entries)

    print("  %s" % name)
    print("      表内槽位 %d（上限 %d），最后一条非全零在 #%d（表尾 0x%X）"
          % (len(entries), SCHED_CAP, last,
             SCHED_BASE + (last + 1) * SCHED_STRIDE if last >= 0 else SCHED_BASE))
    print("      条目分类：场次 %d / 哨兵 %d / 其它非空 %d / 全零 %d"
          % (kinds["match"], kinds["sentinel"], kinds["other"], kinds["zero"]))

    # 只用「像场次」的条目做热图，避免空槽把统计冲淡
    live = [e for e in entries if classify(e) == "match"]
    if not live:
        print("      （无场次条目，跳过热图）")
        return None

    # 逐偏移统计取值种类与非零率
    stats = []
    for off in range(SCHED_STRIDE):
        col = Counter(e[off] for e in live)
        nz = len(live) - col.get(0, 0)
        stats.append((len(col), nz))

    used = [o for o, (k, nz) in enumerate(stats) if k > 1 or nz > 0]
    dead = [o for o, (k, nz) in enumerate(stats) if k == 1 and nz == 0]
    print("      596 字节中：有信息 %d 个偏移，恒为 0 的 %d 个偏移"
          % (len(used), len(dead)))

    # 把有信息的偏移压成连续区间，便于看结构
    runs = []
    for o in used:
        if runs and o == runs[-1][1] + 1:
            runs[-1][1] = o
        else:
            runs.append([o, o])
    print("      有信息区间：%s"
          % ", ".join("0x%X-0x%X" % (a, b_) if a != b_ else "0x%X" % a
                      for a, b_ in runs))

    if full:
        print("      逐偏移（种类 / 非零数，共 %d 条场次）：" % len(live))
        for o in used:
            k, nz = stats[o]
            print("        +0x%03X  种类=%-4d 非零=%d" % (o, k, nz))
    return {"live": live, "stats": stats, "used": set(used), "n": len(live)}


def check_fieldmap(agg, total):
    """把字段图的显式字段与实测占用对照。"""
    print()
    print("字段图 vs 存档实测（§7.6 的显式字段是否落盘）")
    print("-" * 70)
    print("  %-8s %-5s %-10s %-24s %s" % ("偏移", "宽度", "落盘?", "取值种类(按字节)", "备注"))
    for off, width, note in FIELDMAP:
        kinds = [agg[off + k][0] for k in range(width)]
        nz = sum(agg[off + k][1] for k in range(width))
        on = "是" if nz else "否(恒 0)"
        print("  +0x%03X   %-5d %-10s %-24s %s"
              % (off, width, on, ",".join(str(k) for k in kinds), note))
    # 批量区
    blk_used = sum(1 for o in range(0x24, 0x254) if agg[o][1] > 0)
    print("  +0x024~+0x253（批量区 544+16 B）：其中 %d 个字节偏移有非零值" % blk_used)
    print("  （已解出的 seq=+0x150 / date=+0x158 / round=+0x160 都在这段）")


def main():
    full = "--full" in sys.argv
    only = None
    if "--file" in sys.argv:
        only = sys.argv[sys.argv.index("--file") + 1]
    files = sorted(f for f in os.listdir(DEC)
                   if f.startswith("ML") and f.endswith(".data"))
    if only:
        files = [f for f in files if only in f]
    if not files:
        print("decoded/ 下没有匹配的 ML*.data")
        return 1

    print("赛程表字节级占用热图（基址 0x%X，步长 0x%X=%d，上限 %d 条）"
          % (SCHED_BASE, SCHED_STRIDE, SCHED_STRIDE, SCHED_CAP))
    print("=" * 78)
    agg = [Counter() for _ in range(SCHED_STRIDE)]
    total = 0
    for f in files:
        r = probe(os.path.join(DEC, f), full)
        if r:
            total += r["n"]
            for e in r["live"]:
                for o in range(SCHED_STRIDE):
                    agg[o][e[o]] += 1
    print("=" * 78)
    if not total:
        print("没有可用场次条目")
        return 0
    aggs = [(len(c), total - c.get(0, 0)) for c in agg]
    check_fieldmap(aggs, total)
    return 0


if __name__ == "__main__":
    sys.exit(main())
