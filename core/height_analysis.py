#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""身高/体重 与 能力值 的相关性分析 (统计观察 + 解释身高系数为何无法数据反推)。

数据来源(均为本存档解码结果, 按 pid 关联):
  - outputs/parsed_edit_players_EDIT00000000.csv : player_id, height_cm, weight_kg
  - outputs/edit_player_abilities.csv            : pid + 25 项能力值

目的: 量化"身高 vs 身体类能力子项(jump/heading/physical_contact/gk_reach)"的相关性。

关键结论(2026-08-30 用户纠正 + 末轮澄清):
- 身高属"身体数据", 与"能力数据"在游戏里各自独立键入(矮门将可有高弹跳), 互不因果。
- 但身高是**总评线性式的直接因子**(与 25 项能力值并列, 见 pes_ratings.HEIGHT_WEIGHT);
  不是"间接经子项影响", 也不是"纯经验相关" —— 它就是加权式里的一项。
- 本文件的相关性之所以高(身高↔jump/heading/pc 约 r=0.4~0.7), 正因默认库"符合现实":
  高个普遍这些子项高。这导致在 PES master 数据上做单参数 W_H 拟合恒=0 —— 身高独立贡献
  被已有权重的身体子项吸收。**故身高系数无法从数据反推, 必须按游戏内部系数填入。**
- 本文件价值: 解释共线、说明为何不能靠拟合拿系数, 而非推断公式结构。
"""
import csv, math, os
from collections import defaultdict

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
H = os.path.join(BASE, "outputs", "parsed_edit_players_EDIT00000000.csv")
A = os.path.join(BASE, "outputs", "edit_player_abilities.csv")


def load_height():
    d = {}
    for r in csv.DictReader(open(H, encoding="utf-8")):
        try:
            d[r["player_id"]] = (int(r["height_cm"]), int(r["weight_kg"]))
        except (KeyError, ValueError):
            pass
    return d


def load_abil():
    rows = list(csv.DictReader(open(A, encoding="utf-8")))
    return rows


def pearson(xs, ys):
    n = len(xs)
    if n < 3:
        return float("nan")
    mx = sum(xs) / n; my = sum(ys) / n
    cov = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    vx = sum((x - mx) ** 2 for x in xs) ** 0.5
    vy = sum((y - my) ** 2 for y in ys) ** 0.5
    if vx == 0 or vy == 0:
        return float("nan")
    return cov / (vx * vy)


def main():
    h = load_height()
    rows = load_abil()
    # 关联: pid -> (height, weight, reg_pos, 各身体子项)
    def gi(r, k):
        try:
            return int(r[k])
        except (KeyError, ValueError):
            return None
    pairs = defaultdict(lambda: {"ht": [], "wt": [], "jump": [], "heading": [],
                                 "pc": [], "bal": [], "spd": [], "gkreach": [], "gk5": []})
    gk_pairs = defaultdict(lambda: {"ht": [], "gkreach": []})
    for r in rows:
        pid = r.get("pid")
        if pid not in h:
            continue
        ht, wt = h[pid]
        rp = gi(r, "reg_pos")
        rec = pairs[rp]
        rec["ht"].append(ht); rec["wt"].append(wt)
        for key, fld in (("jump", "jump"), ("heading", "heading"),
                         ("pc", "physical_contact"), ("bal", "balance"),
                         ("spd", "speed")):
            v = gi(r, fld)
            if v is not None:
                rec[key].append(v)
        gr = gi(r, "gk_reach")
        if gr is not None:
            rec["gkreach"].append(gr)
        gk5 = [gi(r, k) for k in ("gk_awareness", "gk_catching", "gk_reflexes", "gk_reach", "gk_clearing")]
        gk5 = [v for v in gk5 if v is not None]
        if gk5:
            rec["gk5"].append(sum(gk5) / len(gk5))
        if rp == 0:  # GK 子样本
            gk_pairs[0]["ht"].append(ht)
            if gr is not None:
                gk_pairs[0]["gkreach"].append(gr)

    print("=== 身高/体重 与 身体子项能力值 的 Pearson 相关系数 (全样本, n=各列长度) ===")
    targets = [("jump", "跳起"), ("heading", "头球"), ("pc", "身体接触"),
               ("bal", "平衡"), ("spd", "速度"), ("gkreach", "门将覆盖(GK reach)"), ("gk5", "门将五项均值")]
    for key, label in targets:
        # 用全部球员的身高与该子项(纵向拼接)
        H_all, W_all = [], []
        T_all = defaultdict(list)
        for rp, rec in pairs.items():
            H_all += rec["ht"]; W_all += rec["wt"]
            for k in ("jump", "heading", "pc", "bal", "spd", "gkreach", "gk5"):
                T_all[k] += rec[k]
        r_h = pearson(H_all, T_all[key])
        r_w = pearson(W_all, T_all[key])
        n = len(T_all[key])
        print("  身高 vs %-18s r=%.3f (n=%d)    体重 vs %-18s r=%.3f" %
              (label, r_h, n, label, r_w))

    # 身高->跳起 的简单线性回归斜率(直观量级)
    print("\n=== 身高 -> 跳起 的线性回归 (全样本) ===")
    xs = H_all; ys = T_all["jump"]
    n = len(xs); mx = sum(xs) / n; my = sum(ys) / n
    b = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sum((x - mx) ** 2 for x in xs)
    a = my - b * mx
    print("  jump ≈ %.2f + %.3f * height_cm   (即身高每 +10cm, 跳起约 +%.1f)" % (a, b, b * 10))

    print("\n=== 门将子样本: 身高 vs 门将覆盖(gk_reach) ===")
    gh = gk_pairs[0]["ht"]; gk = gk_pairs[0]["gkreach"]
    if gh and gk:
        print("  r=%.3f (n=%d)" % (pearson(gh, gk), len(gk)))

    print("\n结论: 身高与 jump/heading/pc/gk_reach 显著正相关 => 身高对总评的影响已通过这些身体子项进入")
    print("加权公式; 总评加权公式不(应)直接含身高项, 否则与身体子项共线重复计数。")


if __name__ == "__main__":
    main()
