#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
probe_sched_fields.py — 用真实 ML 存档验证「赛程条目 596 B 字段图」。

字段图来自 exe 的拷贝赋值代码（docs/exe-save-layout.md §7.6）。本脚本同时
纠正了一个长期存在的**基址错位**：

  core/pesfile.py 原来用 SCHED_BASE = 0x3299B0，并把 seq/date/round 记在
  +0x150 / +0x158 / +0x160。实际条目起点是 **0x329B00 = 0x3299B0 + 0x150**，
  基址少了 0x150、字段偏移多了 0x150，两个错误刚好抵消，所以 seq/date/round
  读出来是对的，但整条条目的字段对齐是错的 —— 于是拿 exe 字段图（以条目起点
  为原点）去套 0x3299B0 时，+0x14 / +0x18 读到的是**前一条目未使用批量区的
  填充值** 0x07F7FFFF，其低 14 位恒为 0x3FFF=16383，因此表现为「两值永远相等」。

改用正确基址后，字段图逐项吻合：
  +0x00 seq / +0x04 位域 / +0x08 日期(年 u16+月+日) / +0x10 轮次
  +0x14 / +0x18 = 两个球队引用（低 14 位为球队块索引，高 18 位为句柄位）

验证口径（三条独立判据）：
  1. 两个 14 位值的取值种类应是几百量级（球队规模），而非个位数；
  2. 除填充条目（16383）外两值不应相等（球队不自己打自己）；
  3. 低 14 位当作 ML 球队块索引时，应能取出**非空队名**；且同一天同一轮里
     同一支球队不应出现两次。

只读：仅读取已解密的 .data 副本，不写回、不碰原始存档。

用法：
  python probe_sched_fields.py                # 跑 decoded/ 下所有 ML 存档
  python probe_sched_fields.py --dump 12      # 额外打印前 12 场（带队名）
  python probe_sched_fields.py --old          # 用旧基址复现「假失败」
"""
import os
import struct
import sys
from collections import Counter, defaultdict

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEC = os.path.join(BASE, "decoded")

SCHED_BASE = 0x329B00        # 修正后的条目起点（旧值 0x3299B0 少了 0x150）
SCHED_BASE_OLD = 0x3299B0
SCHED_STRIDE = 0x254
SCHED_CAP = 13000            # §7.5 从 exe 读到的容量上限

# 字段图偏移（以条目起点为原点）
OFF_SEQ, OFF_FLAGS, OFF_DATE, OFF_ROUND = 0x00, 0x04, 0x08, 0x10
OFF_A, OFF_B = 0x14, 0x18
MASK14 = 0x3FFF
FILL14 = 0x3FFF              # 未使用槽位填充值 0x07F7FFFF 的低 14 位

# ML 球队块（core/pesfile.py 常量）
TEAM_START, TEAM_STRIDE, TEAM_N = 0x100, 0x690, 700
TEAM_OFF_NAME = 0x5E4


def u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def cstr(b, o, n=64):
    e = b.find(b"\x00", o, o + n)
    if e < 0:
        e = o + n
    return b[o:e].decode("utf-8", "replace").strip()


def team_names(b):
    """ML 球队块索引 -> 队名。"""
    out = {}
    for r in range(TEAM_N):
        o = TEAM_START + r * TEAM_STRIDE
        if o + TEAM_STRIDE > len(b):
            break
        nm = cstr(b, o + TEAM_OFF_NAME)
        if nm:
            out[r] = nm
    return out


def probe(path, base, dump=0):
    b = open(path, "rb").read()
    name = os.path.basename(path)
    names = team_names(b)

    matches = []
    for i in range(SCHED_CAP):
        o = base + i * SCHED_STRIDE
        if o + SCHED_STRIDE > len(b):
            break
        e = b[o:o + SCHED_STRIDE]
        if not any(e):
            continue
        y = u16(e, OFF_DATE)
        if 1990 <= y <= 2100:
            matches.append((i, e))

    if not matches:
        print("  %-22s 无有效场次" % name)
        return None

    a_all = [u32(e, OFF_A) & MASK14 for _, e in matches]
    b_all = [u32(e, OFF_B) & MASK14 for _, e in matches]
    fill = sum(1 for x, y_ in zip(a_all, b_all) if x == FILL14 or y_ == FILL14)
    real = [(i, e) for (i, e), x, y_ in zip(matches, a_all, b_all)
            if x != FILL14 and y_ != FILL14]

    same = 0
    named = 0
    unnamed_ids = Counter()
    per_round = defaultdict(Counter)
    for _, e in real:
        x, y_ = u32(e, OFF_A) & MASK14, u32(e, OFF_B) & MASK14
        if x == y_:
            same += 1
        for t in (x, y_):
            if t in names:
                named += 1
            else:
                unnamed_ids[t] += 1
        key = (u16(e, OFF_DATE), e[OFF_DATE + 2], e[OFF_DATE + 3], e[OFF_ROUND])
        per_round[key][x] += 1
        per_round[key][y_] += 1

    dup = sum(sum(v - 1 for v in c.values() if v > 1) for c in per_round.values())
    slots = sum(sum(c.values()) for c in per_round.values())

    print("  %-22s 场次 %d（填充条 %d，实打实 %d）"
          % (name, len(matches), fill, len(real)))
    print("      +0x14 取值 %d 种，+0x18 取值 %d 种"
          % (len(set(a_all)), len(set(b_all))))
    print("      两值相等 %d 场；索引能取到队名 %d/%d 个（%.1f%%）"
          % (same, named, 2 * len(real),
             100.0 * named / max(1, 2 * len(real))))
    print("      同一天同一轮内球队重复 %d/%d 次" % (dup, slots))
    if unnamed_ids:
        print("      取不到队名的索引 top5：%s" % unnamed_ids.most_common(5))

    for i, e in real[:dump]:
        x, y_ = u32(e, OFF_A) & MASK14, u32(e, OFF_B) & MASK14
        print("        #%-5d seq=%-5d %d-%02d-%02d R%-3d  %-26s vs %-26s"
              % (i, u16(e, OFF_SEQ), u16(e, OFF_DATE), e[OFF_DATE + 2],
                 e[OFF_DATE + 3], e[OFF_ROUND],
                 "%s(%d)" % (names.get(x, "?"), x),
                 "%s(%d)" % (names.get(y_, "?"), y_)))
    return {"real": len(real), "same": same, "named": named,
            "slots_named": 2 * len(real), "dup": dup, "slots": slots}


def main():
    dump = 0
    if "--dump" in sys.argv:
        dump = int(sys.argv[sys.argv.index("--dump") + 1])
    base = SCHED_BASE_OLD if "--old" in sys.argv else SCHED_BASE

    files = sorted(f for f in os.listdir(DEC)
                   if f.startswith("ML") and f.endswith(".data"))
    if not files:
        print("decoded/ 下没有 ML*.data")
        return 1

    print("验证赛程条目字段图（条目起点 0x%X%s，步长 0x%X）"
          % (base, "（旧的错基址）" if base == SCHED_BASE_OLD else "", SCHED_STRIDE))
    print("=" * 78)
    tot = Counter()
    for f in files:
        r = probe(os.path.join(DEC, f), base, dump)
        if r:
            tot.update(r)
    print("=" * 78)
    if not tot["real"]:
        print("没有可用场次")
        return 0
    pct_same = 100.0 * tot["same"] / tot["real"]
    pct_named = 100.0 * tot["named"] / max(1, tot["slots_named"])
    pct_dup = 100.0 * tot["dup"] / max(1, tot["slots"])
    print("合计实打实场次 %d" % tot["real"])
    print("  判据1 两值相等率      %.2f%%（应≈0）" % pct_same)
    print("  判据2 索引取到队名率  %.2f%%（应≈100）" % pct_named)
    print("  判据3 同轮球队重复率  %.2f%%（应≈0）" % pct_dup)
    ok = pct_same < 1.0 and pct_named > 95.0 and pct_dup < 5.0
    print("判定：%s" % ("三条判据全过 ✓ —— +0x14/+0x18 是主客队引用，"
                        "低 14 位即 ML 球队块索引"
                        if ok else "未全过 ✗ —— 仍需修正"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
