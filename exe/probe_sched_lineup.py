#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
probe_sched_lineup.py — 证明赛程条目的批量区是「双方阵容」。

来路：exe 字段图（§7.6）说赛程条目 +0x24 起有 17 轮 × 32 B 的 SIMD 批量区，
当时判定为「无逐字段语义的 POD 段」。改用正确的条目起点 0x329B00 重新 dump
后，这段的结构一览无余：

    +0x024 起 = 2 组 × 17 个 × 16 B slot（0x24 + 2*17*16 = 0x244，
                恰好接上字段图给的 16 B 尾巴，凑满 0x254 = 596）
    每组恒有 11 个有值 slot + 6 个 0xFFFF 空 slot  → 17 = 11 首发 + 6 替补
    slot 内布局 = [u32 squad_index, u32 player_id, u32 0, u32 v3]

本脚本做交叉验证：**组 A 的 11 个 slot 必须全部落在 +0x14 指向的球队块阵容
表里，组 B 的必须全部落在 +0x18 指向的球队里**。球队块阵容表在
core/pesfile.py 已解出：球队块 +0xA0 起 stride 8 = [player_id][squad_index]，
注意赛程 slot 里这一对的**顺序是相反的**（先 squad_index 后 player_id）。

若命中率接近 100%，则：赛程条目 = 场次头 + 主客队引用 + 双方 11 人首发名单，
整条 596 B 的语义就闭合了。

只读：仅读取已解密的 .data 副本。

用法：
  python probe_sched_lineup.py                # 全部 ML 存档
  python probe_sched_lineup.py --dump 3       # 打印前 3 场的两份名单
"""
import os
import struct
import sys
from collections import Counter

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEC = os.path.join(BASE, "decoded")

SCHED_BASE, SCHED_STRIDE, SCHED_CAP = 0x329B00, 0x254, 13000
OFF_SEQ, OFF_DATE, OFF_ROUND = 0x00, 0x08, 0x10
OFF_A, OFF_B = 0x14, 0x18
MASK14, FILL14 = 0x3FFF, 0x3FFF

LINEUP_BASE = 0x24       # 批量区起点
SLOT = 0x10              # 每 slot 16 B
GROUP_N = 17             # 每组 17 slot（11 首发 + 6 替补位）
EMPTY = 0xFFFF           # 空 slot 标记（slot 头 2 字节）

TEAM_START, TEAM_STRIDE, TEAM_N = 0x100, 0x690, 700
TEAM_OFF_NAME, TEAM_SQUAD = 0x5E4, 0xA0


def u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def cstr(b, o, n=64):
    e = b.find(b"\x00", o, o + n)
    if e < 0:
        e = o + n
    return b[o:e].decode("utf-8", "replace").strip()


def load_teams(b):
    """球队块索引 -> (队名, {player_id}, {squad_index})。"""
    out = {}
    for r in range(TEAM_N):
        o = TEAM_START + r * TEAM_STRIDE
        if o + TEAM_STRIDE > len(b):
            break
        pids, idxs = set(), set()
        so = o + TEAM_SQUAD
        for k in range(60):
            pid = u32(b, so + k * 8)
            if pid in (0, 0xFFFFFFFF):
                break
            pids.add(pid)
            idxs.add(u32(b, so + k * 8 + 4))
        out[r] = (cstr(b, o + TEAM_OFF_NAME), pids, idxs)
    return out


def read_group(e, g):
    """取第 g 组（0=主，1=客）的 slot，返回 [(squad_index, player_id, v3)]。"""
    out = []
    for s in range(GROUP_N):
        o = LINEUP_BASE + (g * GROUP_N + s) * SLOT
        if u16(e, o) == EMPTY and u16(e, o + 2) == 0:
            continue
        v0, v1, v3 = u32(e, o), u32(e, o + 4), u32(e, o + 12)
        if v0 == 0 and v1 == 0 and v3 == 0:
            continue
        out.append((v0, v1, v3))
    return out


def probe(path, dump=0):
    b = open(path, "rb").read()
    name = os.path.basename(path)
    teams = load_teams(b)

    n_match = 0
    size_hist = Counter()
    hit_a = miss_a = hit_b = miss_b = 0
    cross = 0            # 落在对方球队阵容里（说明分组反了）
    shown = 0

    for i in range(SCHED_CAP):
        o = SCHED_BASE + i * SCHED_STRIDE
        if o + SCHED_STRIDE > len(b):
            break
        e = b[o:o + SCHED_STRIDE]
        if not any(e):
            continue
        y = u16(e, OFF_DATE)
        if not (1990 <= y <= 2100):
            continue
        ta, tb = u32(e, OFF_A) & MASK14, u32(e, OFF_B) & MASK14
        if ta == FILL14 or tb == FILL14:
            continue
        n_match += 1
        ga, gb = read_group(e, 0), read_group(e, 1)
        size_hist[(len(ga), len(gb))] += 1
        _, pa, ia = teams.get(ta, ("", set(), set()))
        _, pb, ib = teams.get(tb, ("", set(), set()))

        def tally(grp, pids, idxs, other_pids, other_idxs):
            h = m = x = 0
            for si, pid, _ in grp:
                if si in idxs or pid in pids:
                    h += 1
                else:
                    m += 1
                    if si in other_idxs or pid in other_pids:
                        x += 1
            return h, m, x

        h, m, x = tally(ga, pa, ia, pb, ib)
        hit_a += h; miss_a += m; cross += x
        h, m, x = tally(gb, pb, ib, pa, ia)
        hit_b += h; miss_b += m; cross += x

        if shown < dump:
            shown += 1
            print("      #%d seq=%d %d-%02d-%02d R%d  %s vs %s"
                  % (i, u16(e, OFF_SEQ), y, e[OFF_DATE + 2], e[OFF_DATE + 3],
                     e[OFF_ROUND], teams.get(ta, ("?",))[0],
                     teams.get(tb, ("?",))[0]))
            for tag, grp, pids, idxs in (("主", ga, pa, ia), ("客", gb, pb, ib)):
                marks = " ".join(
                    "%d/%d%s" % (si, pid, "" if (si in idxs or pid in pids) else "!")
                    for si, pid, _ in grp)
                print("        %s队 %2d 人 (阵容序号/球员ID): %s"
                      % (tag, len(grp), marks))

    tot_a, tot_b = hit_a + miss_a, hit_b + miss_b
    print("  %-22s 场次 %d" % (name, n_match))
    if not n_match:
        return None
    print("      名单规模分布 top3：%s" % size_hist.most_common(3))
    print("      组A slot 落在 +0x14 球队阵容：%d/%d（%.2f%%）"
          % (hit_a, tot_a, 100.0 * hit_a / max(1, tot_a)))
    print("      组B slot 落在 +0x18 球队阵容：%d/%d（%.2f%%）"
          % (hit_b, tot_b, 100.0 * hit_b / max(1, tot_b)))
    if cross:
        print("      其中落到对方阵容的：%d（分组可能反了）" % cross)
    return {"n": n_match, "hit": hit_a + hit_b, "tot": tot_a + tot_b,
            "cross": cross}


def main():
    dump = 0
    if "--dump" in sys.argv:
        dump = int(sys.argv[sys.argv.index("--dump") + 1])
    files = sorted(f for f in os.listdir(DEC)
                   if f.startswith("ML") and f.endswith(".data"))
    print("验证赛程批量区 = 双方阵容（条目起点 0x%X，名单区 +0x%X，2×%d×%d B）"
          % (SCHED_BASE, LINEUP_BASE, GROUP_N, SLOT))
    print("=" * 78)
    tot = Counter()
    for f in files:
        r = probe(os.path.join(DEC, f), dump)
        if r:
            tot.update(r)
    print("=" * 78)
    if not tot["tot"]:
        print("无数据")
        return 0
    pct = 100.0 * tot["hit"] / tot["tot"]
    print("合计 %d 场，%d 个 slot 引用，落在对应球队阵容内 %.2f%%"
          % (tot["n"], tot["tot"], pct))
    print("判定：%s"
          % ("✓ 批量区确认为双方首发名单（slot +0x00 = 球队阵容内的 player_id）"
             if pct > 90 else
             "✗ 命中率不足，slot +0x00 不是球队阵容内的 player_id"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
