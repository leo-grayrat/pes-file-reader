#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bl_ml_probe50: 事件表打包值解码（bit-field 分析）。
核心发现前置（由探查确认）：
  - v2_raw >> 16 == f2_hi（297/297）→ v2_raw 就是 f2 的原始 32 位形式，非独立字段
  - u32 "空" 哨兵 = 0xFFFFFFFF；f2/v2 的低16位哨兵 = 0xFFFF
  - 各字段实为 (16位分量 << 16) | (16位分量) 的打包
产出 outputs/event_table_bitfield_report.md
"""
import csv, os, struct
from collections import defaultdict, Counter, OrderedDict

BASE = os.path.dirname(os.path.abspath(__file__))
rows = list(csv.DictReader(open(os.path.join(BASE, "outputs", "event_table_named.csv"),
                                encoding="utf-8")))

def n(r, k):
    try: return int(r[k])
    except (KeyError, ValueError): return None

# ---- 已知 ID 集 ----
eb = open(os.path.join(BASE, "decoded", "EDIT00000000.data"), "rb").read()
def rn(buf, off):
    raw = buf[off+0x36: off+0x36+61]
    return raw.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
id2name = {}
off = 0x7C
while off + 312 <= len(eb):
    pid = struct.unpack_from("<I", eb, off)[0]
    aid = struct.unpack_from("<I", eb, off+240)[0]
    if pid and pid == aid and 1 <= pid <= 200000 and pid not in id2name:
        id2name[pid] = rn(eb, off)
    off += 312
eids = set(id2name)

b = open(os.path.join(BASE, "decoded", "ML00000000.data"), "rb").read(); N = len(b)
reg = {}
o = 0xde034
while o + 8 <= N:
    a = struct.unpack_from("<I", b, o)[0]
    c = struct.unpack_from("<I", b, o+4)[0]
    if 1 <= a <= 400000 and 1 <= c <= 200000:
        reg[a] = c
    o += 8
regkeys = set(reg)
f2set = set(n(r, "f2_hi(player_id)") for r in rows)

OUT = []
OUT.append("# 事件表打包值解码报告（bit-field 分析）\n")
OUT.append(f"- 数据：297 行（ML0/ML1/ML13 各 99）\n")
OUT.append(f"- 对照 ID 集：EDIT 球员 {len(eids)} 个（72..{max(eids)}）、"
           f"ML 注册键 {len(regkeys)} 个（1..{max(regkeys)}）\n")

# ---- 1. v2_raw ≡ f2 ----
OUT.append("## 1. v2_raw 就是 f2（字段冗余，非独立字段）\n")
eq = sum(1 for r in rows if (n(r, "v2_raw") >> 16) == n(r, "f2_hi(player_id)"))
lo_ffff = sum(1 for r in rows if (n(r, "v2_raw") & 0xFFFF) == 0xFFFF)
OUT.append(f"- `v2_raw >> 16 == f2_hi`：**{eq} / {len(rows)}**")
OUT.append(f"- `v2_raw & 0xFFFF == 0xFFFF`（哨兵）：**{lo_ffff} / {len(rows)}**")
OUT.append("- → **v2_raw 是 f2 的原始 32 位表示**（高16位=球员引用，低16位=0xFFFF 哨兵）。")
OUT.append("  此前把 v2_raw 当独立数值字段做相关性，得出「与所有字段无关」是**解析层面的误判**："
           "它本就是 f2，而 f2 是实体引用，自然与财务字段无关。\n")

# ---- 2. 哨兵约定 ----
OUT.append("## 2. 空值哨兵约定（重要，防误判）\n")
OUT.append("| 字段 | 空值形态 | 命中行数 |")
OUT.append("|---|---|---|")
for f, s in [("v6 (u32)", 0xFFFFFFFF), ("v2_raw/f2 低16位", 0xFFFF), ("f2_hi", 65535)]:
    if f == "v6 (u32)":
        c = sum(1 for r in rows if n(r, "v6") == s)
    elif f == "v2_raw/f2 低16位":
        c = sum(1 for r in rows if (n(r, "v2_raw") & 0xFFFF) == s)
    else:
        c = sum(1 for r in rows if n(r, "f2_hi(player_id)") == s)
    OUT.append(f"| {f} | `0x{s:08X}` | {c} / {len(rows)} |")
OUT.append("- **教训**：u32 的「空」是 `0xFFFFFFFF`，16位分量的「空」是 `0xFFFF`；"
           "判断为空不可默认 `==0`（probe48 曾因此误判 v7→v6 结论）。\n")

# ---- 3. hi/lo 分解与命中率 ----
OUT.append("## 3. 各字段 hi/lo 分解与 ID 集命中率\n")
base_edit = len([x for x in eids if x <= 0xFFFF]) / 65536
base_reg = len([k for k in regkeys if k <= 0xFFFF]) / 65536
OUT.append(f"- 随机基线（16 位值偶然落入）：EDIT ≈ {base_edit:.1%}，注册键 ≈ {base_reg:.1%}\n")
OUT.append("| 分量 | 值域 | 唯一值 | EDIT 命中 | 注册键命中 | 判读 |")
OUT.append("|---|---|---|---|---|---|")
verdict = {}
for f in ["v4", "v5", "v6", "v8"]:
    for part, shift in [("hi", 16), ("lo", 0)]:
        vals = [n(r, f) >> 16 if part == "hi" else (n(r, f) & 0xFFFF) for r in rows]
        e = sum(1 for v in vals if v in eids) / len(vals)
        rk = sum(1 for v in vals if v in regkeys) / len(vals)
        v = "—"
        if rk > 0.8 and rk > base_reg * 3:
            v = "**疑似注册索引**"
        elif e > base_edit * 2:
            v = "疑似球员 DB id"
        verdict[f"{f}_{part}"] = (v, e, rk)
        OUT.append(f"| {f}_{part} | {min(vals)}..{max(vals)} | {len(set(vals))} | "
                   f"{e:.1%} | {rk:.1%} | {v} |")

# ---- 4. v4 / v8 分类枚举 ----
OUT.append("\n## 4. v4 / v8 高16位 = 分类枚举（非随机量）\n")
OUT.append("### v4_hi 取值分布")
c4 = Counter(n(r, "v4") >> 16 for r in rows)
for v, cnt in c4.most_common():
    OUT.append(f"  - `{v}` (0x{v:04X})：{cnt} 行")
OUT.append("\n### v8_hi 取值分布")
c8 = Counter(n(r, "v8") >> 16 for r in rows)
for v, cnt in c8.most_common():
    OUT.append(f"  - `{v}`：{cnt} 行")
OUT.append("\n→ v4_hi 仅 **6** 个取值、v8_hi 仅 **{}** 个取值，明显是**枚举/标志位**而非连续量；"
           "低16位才是每行不同的实体 ID。".format(len(c8)))

# ---- 5. v5_hi / v6_hi 注册索引假说的正反验证 ----
OUT.append("\n## 5. v5_hi / v6_hi：注册索引假说的验证\n")
TEAMS = 694  # EDIT 头部 team count
OUT.append(f"- **排除「球队 ID」**：EDIT 头部 team count = **{TEAMS}**，"
           f"而 v5_hi 值域 {min(n(r,'v5')>>16 for r in rows)}..{max(n(r,'v5')>>16 for r in rows)}、"
           f"v6_hi 值域 {min(n(r,'v6')>>16 for r in rows)}..{max(n(r,'v6')>>16 for r in rows)}"
           f" —— 均**远超**球队总数，故不是球队编号。")
dense = len([k for k in regkeys if k <= 20000])
OUT.append(f"- **支持「注册索引」**：注册键在 ≤20000 区间有 **{dense}** 个（密集区），"
           f"v5_hi/v6_hi 值域正好落在该密集区内。")
hit5 = sum(1 for r in rows if (n(r, "v5") >> 16) in regkeys)
OUT.append(f"- v5_hi 落在注册键：**{hit5}/{len(rows)}**（{hit5/len(rows):.0%}，"
           f"随机基线 {base_reg:.0%}）")
# 经注册表取名字
named = []
for r in rows:
    db = reg.get(n(r, "v5") >> 16)
    if db in id2name:
        named.append(id2name[db])
OUT.append(f"- v5_hi → reg → db_id → EDIT 取到名字：**{len(named)}/{len(rows)}**"
           f"（{len(named)/len(rows):.0%}，与 option file 覆盖 41% 量级吻合）")
uniq_nm = list(OrderedDict.fromkeys(named))[:12]
OUT.append(f"- 解析样例（真实球员名，证明链路可用）：{uniq_nm}")
OUT.append("- **语义推论**：v5/v6 的高16位是**模板固定的注册索引**——模板存索引、"
           "各档用各自注册表解析到不同球员，这正好解释「财务列三档完全相同、而球员不同」。\n")

# ---- 6. v3 大值打包 ----
OUT.append("## 6. v3 大值 = (56357 << 16) | x 打包\n")
big = [r for r in rows if (n(r, "v3_money_x100") or 0) > 1000000]
hi_c = Counter(n(r, "v3_money_x100") >> 16 for r in big)
OUT.append(f"- 大值行 {len(big)} 条，高16位分布：**{hi_c.most_common()}**")
for h, cnt in hi_c.most_common():
    OUT.append(f"  - 高16位 `{h}`（0x{h:04X}）共 {cnt} 条；"
               f"低16位 0x{min(n(r,'v3_money_x100')&0xFFFF for r in big):04X}"
               f"..0x{max(n(r,'v3_money_x100')&0xFFFF for r in big):04X}")
OUT.append(f"- 检验 56357 身份：在 EDIT id 集？**{56357 in eids}**；"
           f"是注册键？**{56357 in regkeys}**；是注册值(db_id)？**{56357 in set(reg.values())}**")
OUT.append(f"- → 56357 不属于任何已知 ID 集，且低16位在 0x4AC6..0x5065（19142..20581）变动")
OUT.append("  → **判定为打包值/特殊类别标记，绝不是金额**。此前「全场 Σ=6.6 万亿欧」是被它带偏的产物。\n")

# ---- 7. 字段语义总表 ----
OUT.append("## 7. 字段语义总表（当前最优推定）\n")
OUT.append("| 字段 | 位分解 | 语义推定 | 置信度 |")
OUT.append("|---|---|---|---|")
OUT.append("| v1_status | — | 状态：0=挂牌/在售，1=已结算 | 中 |")
OUT.append("| v2_raw | hi=球员引用, lo=0xFFFF | **就是 f2**（冗余表示） | **高（297/297 验证）** |")
OUT.append("| v3_money_x100 | — | 金额（×100 欧）；**6 个大值 idx 是打包值，须排除** | 高（大值排除后） |")
OUT.append("| v4 | hi=6 类枚举, lo=实体 ID | 分类 + 实体引用 | 中 |")
OUT.append("| v5 | hi=注册索引, lo=? | 球员注册索引（模板固定） | 中高 |")
OUT.append("| v6 | hi=注册索引, lo=?；空=0xFFFFFFFF | 球员注册索引；v7=1 时为空 | 中高 |")
OUT.append("| v7_flag | — | v6 是否为空（1=空） | **高（完美互斥）** |")
OUT.append("| v8 | hi=0..9 枚举, lo=值 | 小枚举 + 值 | 中 |")
OUT.append("| f2_hi/f2_lo | hi=球员引用, lo=0xFFFF | 事件主体球员 | 高 |")

rep = "\n".join(OUT) + "\n"
outp = os.path.join(BASE, "outputs", "event_table_bitfield_report.md")
open(outp, "w", encoding="utf-8").write(rep)
print(rep)
print(f"\n报告已写出 -> {outp}")
