#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bl_ml_probe18.py —— 用「赛季前 vs 赛季中」强对照，全文件定位 ML 运行时字段。

为什么要换对照方式（对 probe14/15/16 的反思）：
  此前资金定位失败，是因为拿 ML00000000 ↔ ML00000013 做差分——二者进度接近，
  动态字段几乎不变，因而零命中，进而误判「动态余额不在已扫区」。
  而 probe17 发现：ML00000002 在球队记录 +0x598（万位整数簇）处**恒为 0**，
  其余三档有值。这与文档记载的「赛季前存档（BL2/BL3）无赛程表」同型，
  提示 ML00000002 是赛季前存档——赛季未开始，运行时字段尚未初始化。
  赛季前 vs 赛季中才是真正的强对照。

金额约束（来自 FL_2023.exe 静态反汇编，见 exe_aob.py / docs/）：
  存档金额 × 100 = 欧元显示值（欧元档汇率系数 = 100），故预算存储值量级
  约在 1e3 ~ 1e7（对应 10 万 ~ 10 亿欧元）。

筛选模式：
  A 赛季前对照：ML2 ≠ 其余，且其余三档彼此一致（稳定配置/赛季初分配值）
  B 全动态    ：四个样本值两两不同，且都落在金额量级（疑似随进度变化的余额）

用法：
  python bl_ml_probe18.py              # 全文件扫描（约 5 个 u32 槽位，需数十秒）
  python bl_ml_probe18.py --lo 0x500000 --hi 0x600000   # 只扫指定区间
"""
import argparse
import array
import os
import sys

BASE = os.path.dirname(os.path.abspath(__file__))
DECODED = os.path.join(BASE, "decoded")

ML_SAMPLES = ["ML00000000.data", "ML00000001.data",
              "ML00000002.data", "ML00000013.data"]
PRESEASON_IDX = 2          # ML00000002 疑为赛季前存档

AMT_LO = 1000              # 金额下界（存储值）
AMT_HI = 10000000          # 金额上界
SENTINELS = {0x00000000, 0xFFFFFFFF, 0x00FFFFFF, 0x0000FFFF, 0xFFFF0000}

CLUSTER_GAP = 0x10000      # 结果聚类间隔（64KB 桶）


def load_arr(name):
    path = os.path.join(DECODED, name)
    with open(path, "rb") as f:
        d = f.read()
    a = array.array("I")
    a.frombytes(d[:len(d) // 4 * 4])
    return a


def in_amount_range(v):
    return AMT_LO <= v <= AMT_HI and v not in SENTINELS


def cluster(offsets, gap=CLUSTER_GAP):
    """把偏移量聚成区间，返回 [(start, end, count)]。"""
    out = []
    for off in sorted(offsets):
        if out and off - out[-1][1] <= gap:
            out[-1][1] = off
            out[-1][2] += 1
        else:
            out.append([off, off, 1])
    return [tuple(x) for x in out]


def main():
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            pass
    ap = argparse.ArgumentParser(description="赛季前 vs 赛季中全文件对照扫描")
    ap.add_argument("--lo", type=lambda x: int(x, 0), default=0, help="起始偏移")
    ap.add_argument("--hi", type=lambda x: int(x, 0), default=0, help="结束偏移（0=到末尾）")
    args = ap.parse_args()

    arrs = []
    for n in ML_SAMPLES:
        p = os.path.join(DECODED, n)
        if not os.path.isfile(p):
            print("错误：缺少 %s" % n)
            return 1
        arrs.append(load_arr(n))
        print("  载入 %s（%d 个 u32 槽位）" % (n, len(arrs[-1])))

    n = min(len(a) for a in arrs)
    lo = max(0, args.lo // 4)
    hi = n if args.hi == 0 else min(n, args.hi // 4)
    print("  扫描范围: 偏移 0x%X ~ 0x%X（%d 个 u32 槽位）" % (lo * 4, hi * 4, hi - lo))

    pre = arrs[PRESEASON_IDX]
    others = [arrs[i] for i in range(len(arrs)) if i != PRESEASON_IDX]
    a0, a1 = others[0], others[1]
    a2 = others[2] if len(others) > 2 else others[1]

    hits_a = []      # 赛季前对照命中
    hits_b = []      # 全动态命中
    for i in range(lo, hi):
        vp = pre[i]
        v0, v1, v2 = a0[i], a1[i], a2[i]
        # 模式 A：赛季前三档一致稳定，赛季前不同，且赛季中值落在金额量级
        if v0 == v1 == v2 and v0 != vp and in_amount_range(v0):
            hits_a.append((i * 4, v0, vp))
            continue
        # 模式 B：四档两两不同，且前三者都在金额量级
        vals = (v0, v1, vp, v2)
        if len(set(vals)) == 4 and all(in_amount_range(v) for v in (v0, v1, v2)):
            hits_b.append((i * 4, v0, v1, vp, v2))

    print("\n" + "=" * 78)
    print("[模式 A] 赛季前三档一致、赛季前(ML2)不同，且值在金额量级：%d 处" % len(hits_a))
    if hits_a:
        print("  聚类分布（间隔 0x%X）：" % CLUSTER_GAP)
        for start, end, cnt in cluster([h[0] for h in hits_a])[:25]:
            print("    0x%08X ~ 0x%08X  %d 处" % (start, end, cnt))
        print("  样例（前 12 处，格式：偏移  赛季中值 / ML2值）：")
        for off, v, vp in hits_a[:12]:
            print("    0x%08X  %10d / %-10d  (欧元 %d / %d)"
                  % (off, v, vp, v * 100, vp * 100))

    print("\n" + "=" * 78)
    print("[模式 B] 四档两两不同且均落在金额量级：%d 处" % len(hits_b))
    if hits_b:
        print("  聚类分布（间隔 0x%X）：" % CLUSTER_GAP)
        for start, end, cnt in cluster([h[0] for h in hits_b])[:25]:
            print("    0x%08X ~ 0x%08X  %d 处" % (start, end, cnt))
        print("  样例（前 12 处，格式：偏移  ML0 / ML1 / ML2 / ML13）：")
        for off, v0_, v1_, vp_, v2_ in hits_b[:12]:
            print("    0x%08X  %10d / %-10d / %-10d / %-10d"
                  % (off, v0_, v1_, vp_, v2_))
    return 0


if __name__ == "__main__":
    sys.exit(main())
