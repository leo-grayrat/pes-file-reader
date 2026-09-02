#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
probe_sched_ids.py — 在赛程条目 596 B 里用「取值分布」反查球队 ID 字段与内部子数组。

上一步 probe_sched_layout.py 的热图告出两件事：
  * +0x00~+0x14B 整段密集有值，+0x14C~+0x163 是标量区（seq/date/round 在此）；
  * +0x164~+0x253 = 15 × 16 B 的子数组（周期严整）。

球队 ID 有很强的指纹：取值种类多（几十~几百）、值域落在球队表容量内（≤750/1300）、
同一条里成对出现且互不相等、并且**同一轮次的各场比赛球队互不重复**。
这里就按这些指纹在所有 u16 / u32 位置上扫一遍，让数据自己指认。

只读：仅读取已解密的 .data 副本。

用法：
  python probe_sched_ids.py                 # 扫全部 ML 存档
  python probe_sched_ids.py --dump 8        # 额外 hexdump 前 8 条场次
  python probe_sched_ids.py --sub           # 详解 +0x164 起的 15×16B 子数组
"""
import os
import struct
import sys
from collections import Counter, defaultdict

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEC = os.path.join(BASE, "decoded")

SCHED_BASE = 0x3299B0
SCHED_STRIDE = 0x254
SCHED_CAP = 13000
OFF_SEQ, OFF_DATE, OFF_ROUND = 0x150, 0x158, 0x160

SUB_BASE, SUB_STRIDE, SUB_N = 0x164, 0x10, 15   # 热图推出的内部子数组

TEAM_MAX = 1300          # §7.5 相关表容量上限（750 / 1300 两档）


def u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def load_matches(path):
    """取出「像真实场次」的条目。"""
    b = open(path, "rb").read()
    out = []
    for i in range(SCHED_CAP):
        o = SCHED_BASE + i * SCHED_STRIDE
        if o + SCHED_STRIDE > len(b):
            break
        e = b[o:o + SCHED_STRIDE]
        if not any(e):
            continue
        seq = u32(e, OFF_SEQ)
        if seq in (0xFFFF, 0xFFFFFFFF):
            continue
        y = u16(e, OFF_DATE)
        if 1990 <= y <= 2100 and u32(e, OFF_ROUND) < 1000:
            out.append((i, e))
    return out


def id_candidates(matches, width=2):
    """按 ID 指纹给每个对齐位置打分。"""
    step = width
    n = len(matches)
    rows = []
    for off in range(0, SCHED_STRIDE - width + 1, step):
        vals = [u16(e, off) if width == 2 else u32(e, off) for _, e in matches]
        c = Counter(vals)
        kinds = len(c)
        mx = max(vals)
        nz = n - c.get(0, 0)
        # ID 指纹：取值多样、值域不离谱、非零占比高
        if kinds >= 20 and mx <= TEAM_MAX and nz >= n * 0.5:
            rows.append((off, kinds, min(v for v in vals if v), mx, nz))
    return rows


def pair_check(matches, off_a, off_b, width=2):
    """检查两个位置是否像「主队/客队」：极少相等、且同轮不重复。"""
    rd = lambda e, o: u16(e, o) if width == 2 else u32(e, o)
    same = 0
    per_round = defaultdict(list)
    for _, e in matches:
        a, b_ = rd(e, off_a), rd(e, off_b)
        if a == b_:
            same += 1
        per_round[(u16(e, OFF_DATE), u32(e, OFF_ROUND))].append((a, b_))
    # 同一 (年,轮) 里球队重复出现次数
    dup = 0
    tot = 0
    for _, lst in per_round.items():
        seen = Counter()
        for a, b_ in lst:
            seen[a] += 1
            seen[b_] += 1
        tot += sum(seen.values())
        dup += sum(v - 1 for v in seen.values() if v > 1)
    return same, dup, tot


def show_sub(matches, limit=4):
    """把 +0x164 起的 15×16B 子数组摊开看。"""
    print("      子数组 +0x%X 起，%d × %d B：" % (SUB_BASE, SUB_N, SUB_STRIDE))
    for k in range(min(limit, len(matches))):
        i, e = matches[k]
        print("        #%d seq=%d round=%d" % (i, u32(e, OFF_SEQ), u32(e, OFF_ROUND)))
        for s in range(SUB_N):
            o = SUB_BASE + s * SUB_STRIDE
            chunk = e[o:o + SUB_STRIDE]
            if not any(chunk):
                continue
            print("          [%2d] +0x%03X  %s" %
                  (s, o, " ".join("%02X" % c for c in chunk)))
    # 每个 slot 的占用率
    occ = []
    for s in range(SUB_N):
        o = SUB_BASE + s * SUB_STRIDE
        used = sum(1 for _, e in matches if any(e[o:o + SUB_STRIDE]))
        occ.append(used)
    print("      各 slot 非空条目数（共 %d 场）：%s" % (len(matches), occ))
    # slot 内首 2 字节的取值分布
    first = Counter()
    for _, e in matches:
        for s in range(SUB_N):
            o = SUB_BASE + s * SUB_STRIDE
            v = u16(e, o)
            if v:
                first[v] += 1
    print("      slot 首 2 字节取值 top10：%s" % first.most_common(10))


def main():
    dump = 0
    if "--dump" in sys.argv:
        dump = int(sys.argv[sys.argv.index("--dump") + 1])
    want_sub = "--sub" in sys.argv

    files = sorted(f for f in os.listdir(DEC)
                   if f.startswith("ML") and f.endswith(".data"))
    print("赛程条目 ID 字段反查（基址 0x%X 步长 0x%X，球队值域上限 %d）"
          % (SCHED_BASE, SCHED_STRIDE, TEAM_MAX))
    print("=" * 78)

    agg16 = defaultdict(lambda: [0, 0, 0])   # off -> [出现次数, 最大种类, 最大值]
    for f in files:
        path = os.path.join(DEC, f)
        matches = load_matches(path)
        print("  %s：场次 %d" % (f, len(matches)))
        if not matches:
            continue
        cand = id_candidates(matches, 2)
        print("      u16 位置里像 ID 的：%d 个" % len(cand))
        for off, kinds, lo, hi, nz in cand[:24]:
            print("        +0x%03X  种类=%-4d 值域=%d~%d  非零=%d/%d"
                  % (off, kinds, lo, hi, nz, len(matches)))
            r = agg16[off]
            r[0] += 1
            r[1] = max(r[1], kinds)
            r[2] = max(r[2], hi)
        if dump:
            print("      前 %d 条场次的头 0x30 字节：" % dump)
            for i, e in matches[:dump]:
                print("        #%-5d %s" % (i, " ".join("%02X" % c for c in e[:0x30])))
        if want_sub:
            show_sub(matches)

    print("=" * 78)
    if agg16:
        print("跨存档一致出现的 ID 候选位置（%d 个存档都命中）：" % len(files))
        for off, (cnt, kinds, hi) in sorted(agg16.items()):
            mark = "★" if cnt == len(files) else " "
            print("  %s +0x%03X  命中 %d/%d 存档，最多 %d 种取值，最大值 %d"
                  % (mark, off, cnt, len(files), kinds, hi))
        # 对最强的候选做成对检验
        strong = [o for o, (c, k, h) in agg16.items() if c == len(files) and k >= 50]
        if len(strong) >= 2:
            print()
            print("对种类≥50 的候选做「主客队」成对检验（用第一个存档）：")
            matches = load_matches(os.path.join(DEC, files[0]))
            for a in range(len(strong)):
                for b_ in range(a + 1, len(strong)):
                    oa, ob = strong[a], strong[b_]
                    same, dup, tot = pair_check(matches, oa, ob, 2)
                    print("  +0x%03X vs +0x%03X：相等 %d 场，同轮重复 %d/%d 次%s"
                          % (oa, ob, same, dup, tot,
                             "   ← 像主客队" if same == 0 else ""))
    else:
        print("没有位置满足 ID 指纹——需要放宽阈值或换值域上限")
    return 0


if __name__ == "__main__":
    sys.exit(main())
