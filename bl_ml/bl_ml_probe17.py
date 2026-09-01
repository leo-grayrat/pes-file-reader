#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bl_ml_probe17.py —— 用 exe 反汇编得到的资金约束，在 ML 球队记录里定位预算字段。

背景（2026-08-29，exe_aob.py + objdump，均为静态分析、无需运行游戏）：
  1. CT 表 AOB `8B 87 F4 CB 6E 01 89 45 C4` 在 FL_2023.exe 命中 RVA 0xEA4C58，
     该处指令为 `mov eax,[rdi+0x16ECBF4]`，即转会预算读取点。
  2. 同一 CT 表导出：薪资预算 = ptrBudget + 0x16ECC08，与转会预算相距 0x14（20 字节）。
  3. 反汇编金额换算 thunk（0x141565f50 -> 0x144af2120）得到 5 路货币汇率表：
     ×12500 / ×100 / ×110 / ×90 / ×430，其中 ×100 为欧元基准档。
     => 结论：存档金额 × 100 = 欧元显示值，即「1 单位 = 100 欧元」。

据此在本仓库已解密的 ML 样本上做三件事：
  A. 扫描球队记录内一段窗口，按「跨样本是否变化」区分静态配置与动态数据；
  B. 标注「相距 0x14（20 字节）的 u32 对」——与内存中转会/薪资预算的间距一致；
  C. 标注「万位整数」字段——与「单位 = 100 欧元」下预算的量级特征吻合。

用法：
  python bl_ml_probe17.py                 # 默认扫描 +0x560~+0x600
  python bl_ml_probe17.py --lo 0x588 --hi 0x5B0
  python bl_ml_probe17.py --team 33       # 额外打印某队完整窗口
"""
import argparse
import os
import struct
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DECODED = os.path.join(BASE, "decoded")

# ---- 已确认的 ML/BL 球队记录布局（docs/bl_ml_structure.md §1.2）----
TEAM_BASE = 0x100
TEAM_STRIDE = 0x690      # 1680
TEAM_COUNT = 700

# 不同进度的 ML 样本（同一存档体系，用于跨样本差分）
ML_SAMPLES = ["ML00000000.data", "ML00000001.data",
              "ML00000002.data", "ML00000013.data"]

# 内存中转会/薪资预算的间距（0x16ECC08 - 0x16ECBF4 = 0x14）
BUDGET_PAIR_GAP = 0x14


def u32(buf, off):
    return struct.unpack_from("<I", buf, off)[0]


def load_samples(names):
    out = []
    for n in names:
        p = os.path.join(DECODED, n)
        if not os.path.isfile(p):
            print("  [跳过] 缺少 %s" % n)
            continue
        with open(p, "rb") as f:
            out.append((n, f.read()))
    return out


def is_round_myriad(v):
    """是否为万位整数（预算字段的量级特征：10000 的倍数且非零）。"""
    return v > 0 and v % 10000 == 0


def scan_window(samples, lo, hi):
    """返回 {offset: (变化队数, 万位整数占比, 示例[(队号, 各样本值)])}。"""
    result = {}
    for off in range(lo, hi, 4):
        changed = 0
        myriad = 0
        total = 0
        examples = []
        for team in range(TEAM_COUNT):
            base = TEAM_BASE + team * TEAM_STRIDE + off
            if base + 4 > len(samples[0][1]):
                break
            vals = [u32(d, base) for _, d in samples]
            total += 1
            if len(set(vals)) > 1:
                changed += 1
                if len(examples) < 6:
                    examples.append((team, vals))
            if is_round_myriad(vals[0]):
                myriad += 1
        result[off] = (changed, myriad, total, examples)
    return result


def main():
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            pass
    ap = argparse.ArgumentParser(description="按 exe 资金约束定位 ML 预算字段")
    ap.add_argument("--lo", type=lambda x: int(x, 0), default=0x560, help="窗口起始偏移")
    ap.add_argument("--hi", type=lambda x: int(x, 0), default=0x600, help="窗口结束偏移")
    ap.add_argument("--team", type=int, default=None, help="额外打印指定队号完整窗口")
    args = ap.parse_args()

    samples = load_samples(ML_SAMPLES)
    if len(samples) < 2:
        print("错误：至少需要 2 个 ML 样本才能做跨样本对比")
        return 1

    print("=" * 78)
    print("ML 球队记录预算字段扫描（约束来自 FL_2023.exe 静态反汇编）")
    print("  样本: %s" % ", ".join(n for n, _ in samples))
    print("  记录: 基址 0x%X，步长 0x%X，共 %d 队" % (TEAM_BASE, TEAM_STRIDE, TEAM_COUNT))
    print("  窗口: +0x%X ~ +0x%X" % (args.lo, args.hi))
    print("  约束: 预算对间距 0x%X（内存实测）；金额单位 = 100 欧元" % BUDGET_PAIR_GAP)

    res = scan_window(samples, args.lo, args.hi)

    print("\n" + "-" * 78)
    print("[A] 跨样本有变化的偏移（动态字段候选，按变化队数降序）")
    dyn = sorted(((o, v) for o, v in res.items() if v[0] > 0),
                 key=lambda kv: -kv[1][0])
    if not dyn:
        print("  窗口内无跨样本变化字段")
    for off, (changed, myriad, total, examples) in dyn[:20]:
        pct = 100.0 * myriad / total if total else 0
        print("  +0x%03X  变化 %d/%d 队  万位整数占比 %5.1f%%" % (off, changed, total, pct))
        for team, vals in examples[:3]:
            print("        队%3d: %s" % (team, " / ".join("%d" % v for v in vals)))

    print("\n" + "-" * 78)
    print("[B] 相距 0x%X 的 u32 对（与内存转会/薪资预算间距一致）" % BUDGET_PAIR_GAP)
    hit_pairs = 0
    for off in res:
        pair = off + BUDGET_PAIR_GAP
        if pair not in res:
            continue
        c1, m1, t1, e1 = res[off]
        c2, m2, t2, e2 = res[pair]
        # 关注：两端都是万位整数，且至少一端跨样本变化
        if m1 == 0 or m2 == 0:
            continue
        if c1 == 0 and c2 == 0:
            continue
        hit_pairs += 1
        print("  +0x%03X (动态%d队, 万位%d/%d)  <--0x%X-->  +0x%03X (动态%d队, 万位%d/%d)" %
              (off, c1, m1, t1, BUDGET_PAIR_GAP, pair, c2, m2, t2))
        for team, vals in (e1 or e2)[:3]:
            print("        队%3d: %s" % (team, " / ".join("%d" % v for v in vals)))
    if hit_pairs == 0:
        print("  未发现同时满足「两端万位整数 + 至少一端动态」的 0x%X 间距对" % BUDGET_PAIR_GAP)

    print("\n" + "-" * 78)
    print("[C] 纯静态的万位整数偏移（跨样本完全不变，疑初始预算/配置）")
    stat = [(o, v) for o, v in res.items() if v[0] == 0 and v[1] > 0]
    for off, (changed, myriad, total, examples) in stat:
        print("  +0x%03X  万位整数 %d/%d 队" % (off, myriad, total))
        if examples:
            vals = [u32(samples[0][1], TEAM_BASE + t * TEAM_STRIDE + off)
                    for t in range(TEAM_COUNT)]
            uniq = {}
            for v in vals:
                uniq[v] = uniq.get(v, 0) + 1
            top = sorted(uniq.items(), key=lambda kv: -kv[1])[:8]
            print("        取值分布: %s" % ", ".join("%d×%d" % (v, c) for v, c in top))

    if args.team is not None:
        print("\n" + "-" * 78)
        print("[D] 队 %d 完整窗口" % args.team)
        for off in range(args.lo, args.hi, 4):
            base = TEAM_BASE + args.team * TEAM_STRIDE + off
            vals = [u32(d, base) for _, d in samples]
            mark = "  动态" if len(set(vals)) > 1 else ""
            print("  +0x%03X: %s%s" % (off, " / ".join("%d" % v for v in vals), mark))
    return 0


if __name__ == "__main__":
    sys.exit(main())
