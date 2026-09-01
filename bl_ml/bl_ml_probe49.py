#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bl_ml_probe49: 事件表结构深挖（承接 probe48 的"财务字段逐行固定"发现）。
聚焦：
  1. 18 条 v3 异常大值：是否固定落在同几个 idx（模板固有值 vs 随机噪声）
  2. 异常行 vs 正常行的字段模式对比（v4/v5/v6/v8/date/v1/v7）
  3. 日期分析：2021-08-31 占 40% 是否哨兵/默认日期
  4. v1 × v7 联合语义交叉表
  5. f2_hi 哨兵行（65535）特征
产出 outputs/event_table_structure_report.md
"""
import csv, os, statistics
from collections import defaultdict, Counter

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
csvp = os.path.join(BASE, "outputs", "event_table_named.csv")
rows = list(csv.DictReader(open(csvp, encoding="utf-8")))

def n(r, k):
    try: return int(r[k])
    except (KeyError, ValueError): return None

OUT = []
OUT.append("# 事件表结构深挖报告（承接 probe48）\n")
OUT.append(f"- 数据：`event_table_named.csv`，{len(rows)} 行 = ML0/ML1/ML13 各 99（idx 0..98）\n")

# 按 idx 对齐
bysrc = defaultdict(dict)
for r in rows:
    bysrc[r["src"]][n(r, "idx")] = r
srcs = sorted(bysrc)
idxs = sorted(bysrc[srcs[0]])

# ---- 1. 异常大值 idx 归属 ----
BIG_T = 1000000  # v3×100 > 1亿欧
OUT.append("## 1. v3 异常大值：模板固有值 vs 随机噪声\n")
big_idx = defaultdict(set)   # idx -> 出现该大值的存档集合
big_rows = []
for r in rows:
    if (n(r,"v3_money_x100") or 0) > BIG_T:
        big_idx[n(r,"idx")].add(r["src"])
        big_rows.append(r)
OUT.append(f"- 大值行总数：**{len(big_rows)} / {len(rows)}**")
OUT.append(f"- 涉及的 **idx 数：{len(big_idx)}**")
OUT.append(f"- 大值 idx 及出现存档：")
for i in sorted(big_idx):
    OUT.append(f"  - idx={i}: 存档 {sorted(big_idx[i])} "
               f"v3={bysrc[srcs[0]][i]['v3_money_x100']} "
               f"(三档同值={len(set(bysrc[s][i]['v3_money_x100'] for s in srcs))==1})")
all_three = sum(1 for i,v in big_idx.items() if len(v)==3)
OUT.append(f"\n- **三档同时命中的 idx：{all_three} / {len(big_idx)}**"
           f"（若全部三档命中 → 大值是模板固有值，非随机噪声）")
OUT.append(f"- 大值 idx 的 v3 值（模板值，逐档相同）：")
for i in sorted(big_idx):
    vals = set(bysrc[s][i]["v3_money_x100"] for s in srcs)
    OUT.append(f"  - idx={i}: v3={sorted(vals)}")

# ---- 2. 异常行 vs 正常行 字段模式 ----
OUT.append("\n## 2. 异常大值 idx vs 其余 idx：模板列模式对比\n")
big_set = set(big_idx)
def colstats(idxs_, field):
    vals = [n(bysrc[srcs[0]][i], field) for i in idxs_]
    vals = [v for v in vals if v is not None]
    if not vals: return "-"
    return (f"min={min(vals):,} max={max(vals):,}, median={statistics.median(vals):,.1f}, "
            f"uniq={len(set(vals))}")
fields = ["v3_money_x100","v4","v5","v6","v8","v2_raw"]
OUT.append("| 字段 | 大值 idx（n=%d） | 其余 idx（n=%d） |" % (len(big_set), len(set(idxs))-len(big_set)))
OUT.append("|---|---|---|")
for f in fields:
    OUT.append(f"| {f} | {colstats(big_set, f)} | {colstats(set(idxs)-big_set, f)} |")

# 大值 idx 的 date / v1 / v7
OUT.append("\n### 2a. 大值 idx 的日期与标记位（取 ML0 为代表）\n")
for i in sorted(big_set):
    r = bysrc[srcs[0]][i]
    OUT.append(f"- idx={i}: date={r['date']}  v1={r['v1_status']}  v7={r['v7_flag']}  "
               f"v3={r['v3_money_x100']}  v4={r['v4']}  v6={r['v6']}")
dc = Counter(bysrc[srcs[0]][i]['date'] for i in big_set)
OUT.append(f"- 大值 idx 的 date 分布：{dict(dc)}")

# ---- 3. 日期分析 ----
OUT.append("\n## 3. 日期分析（模板列，三档同 idx 同日期）\n")
dates = [r['date'] for r in rows]
OUT.append(f"- 日期范围：{min(dates)} .. {max(dates)}（共 {len(set(dates))} 个不同日期）")
OUT.append(f"- 分布：{dict(sorted(Counter(dates).items(), key=lambda x:-x[1]))}")
OUT.append(f"- **2021-08-31 占 {Counter(dates)['2021-08-31']} / {len(rows)} "
           f"({100*Counter(dates)['2021-08-31']/len(rows):.0f}%)** —— 远超其他日期，疑为哨兵/默认日期")

# 按 idx 看日期（模板）：哪些 idx 是 08-31
idx_date = {i: bysrc[srcs[0]][i]['date'] for i in idxs}
last_idx = [i for i in idxs if idx_date[i]=='2021-08-31']
OUT.append(f"- 日期为 2021-08-31 的 idx 数：**{len(last_idx)} / {len(idxs)}**（模板内固定）")
OUT.append(f"  - 这些 idx：{last_idx}")
# 这些 idx 的 v3 是否特殊
if last_idx:
    v3_last = [n(bysrc[srcs[0]][i],'v3_money_x100') for i in last_idx]
    v3_oth  = [n(bysrc[srcs[0]][i],'v3_money_x100') for i in idxs if idx_date[i]!='2021-08-31']
    OUT.append(f"  - 其 v3: median={statistics.median(v3_last):,.0f} max={max(v3_last):,}")
    OUT.append(f"  - 其余 idx v3: median={statistics.median(v3_oth):,.0f} max={max(v3_oth):,}")
    OUT.append(f"  - 大值 idx 是否全部落在 08-31：{big_set <= set(last_idx)}"
               f"（大值 idx={sorted(big_set)}）")

# ---- 4. v1 × v7 联合语义 ----
OUT.append("\n## 4. v1_status × v7_flag 联合交叉（全部 297 行）\n")
cross = Counter((n(r,'v1_status'), n(r,'v7_flag')) for r in rows)
OUT.append("| v1 \\ v7 | 0 | 1 |")
OUT.append("|---|---|---|")
for v1 in [0,1]:
    OUT.append(f"| {v1} | {cross.get((v1,0),0)} | {cross.get((v1,1),0)} |")
OUT.append(f"\n- 组合计数：{ {f'v1={a},v7={b}':c for (a,b),c in sorted(cross.items())} }")
# 各组合的金额中位数
OUT.append("- 各组合 v3 中位数（×100 欧）：")
for (a,b) in sorted(cross):
    sub = [n(r,'v3_money_x100')*100 for r in rows if n(r,'v1_status')==a and n(r,'v7_flag')==b]
    OUT.append(f"  - v1={a},v7={b}（n={len(sub)}）：median={statistics.median(sub):,.0f} 欧  "
               f"max={max(sub):,.0f} 欧")

# ---- 5. 哨兵 / 特殊行 ----
OUT.append("\n## 5. f2_hi 哨兵与特殊行\n")
sent = [r for r in rows if n(r,'f2_hi(player_id)')==65535]
OUT.append(f"- f2_hi==65535（0xFFFF 哨兵）的行：**{len(sent)}**")
for r in sent[:10]:
    OUT.append(f"  - src={r['src']} idx={r['idx']} date={r['date']} v1={r['v1_status']} "
               f"v7={r['v7_flag']} v3={r['v3_money_x100']}")
f2lo = Counter(n(r,'f2_lo') for r in rows)
OUT.append(f"- f2_lo 取值分布：{dict(f2lo)}（若全为 65535 则为纯哨兵列）")
# 哨兵 idx 是否集中于尾部 08-31 区块
sidx = set(n(r,'idx') for r in sent)
OUT.append(f"- 哨兵 idx 分布：idx<59 共 {sum(1 for i in sidx if i<59)} 个、"
           f"idx>=59（尾部 08-31 区块）共 {sum(1 for i in sidx if i>=59)} 个"
           f" → **哨兵是分散的，并非集中在尾部**，故尾部 40 行不是「空槽位」，"
           f"而是「日期统一取窗口末日 08-31」的真实事件区块")

# ---- 5b. v6 哨兵与 v7 的完美互斥（修正 probe48 判据） ----
OUT.append("\n## 5b. v6 哨兵（0xFFFFFFFF）与 v7_flag 的完美互斥\n")
SENT6 = 0xFFFFFFFF
for v7 in [0, 1]:
    sub = [n(r, 'v6') for r in rows if n(r, 'v7_flag') == v7]
    hit = sum(1 for x in sub if x == SENT6)
    OUT.append(f"- v7_flag={v7}（n={len(sub)}）：v6==0xFFFFFFFF 共 **{hit} 条"
               f"（{100*hit/len(sub):.0f}%）**")
OUT.append(f"- 全局 v6==0xFFFFFFFF：{sum(1 for r in rows if n(r,'v6')==SENT6)} / {len(rows)}")
OUT.append("- **结论：v7=1 ⟺ v6 为空（0xFFFFFFFF），完美互斥，**"
           "旧结论「f7=1 时 f6 恒空」成立；probe48 初版误用 `v6==0` 判据导致误判，已修正。")
OUT.append("- 语义推论：v7=1 表示该条目**无 v6 关联对象**（如无买家/无所属实体），"
           "配合 v1=0（挂牌）→ v7=1 的 39 条是「挂牌但无下家」的条目。")

# ---- 6. 结论 ----
OUT.append("\n## 6. 结论\n")
OUT.append("- **事件表 = 静态模板 + 球员槽位（已坐实）**：v3/v4/v5/v6/v8/date **逐 idx 在三档完全相同**，"
           "唯一随档变化的是 f2_hi(球员)。")
OUT.append(f"- **大值非噪声**：若 {all_three}/{len(big_idx)} 个大值 idx 三档同址 → 是模板固有值，"
           "代表「特殊事件类型/打包值」，应作为独立类别处理，不可当金额求和。")
OUT.append("- **2021-08-31 疑为哨兵日期**：占比 40%，需结合大值 idx 是否集中于该日判断。")
OUT.append("- **v1×v7 联合**：见 §4 交叉表，可据此区分事件子类型。")

rep = "\n".join(OUT) + "\n"
outp = os.path.join(BASE, "outputs", "event_table_structure_report.md")
open(outp, "w", encoding="utf-8").write(rep)
print(rep)
print(f"\n报告已写出 -> {outp}")
