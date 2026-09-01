#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bl_ml_probe52: EDIT team-player 表解析 + 球员→球队映射 + 事件表关联。
结构（本轮实测确认）：
  - 起始 0x9D4648，定长 284 字节/条，共 694 条
  - 每条: [0] = team_id (u32, 严格递增), [1..] = 该队球员 EDIT db_id 列表,
          遇 0 或非 EDIT id 结束
产出:
  outputs/edit_team_players.csv   球队→球员清单（每队一行，球员用 | 分隔）
  outputs/edit_player_team.csv     球员→球队（一对一）
  outputs/event_table_with_team.csv 事件表 + 各球员引用解析出的 team_id
"""
import csv, os, struct
from collections import defaultdict, Counter

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
eb = open(os.path.join(BASE, "decoded", "EDIT00000000.data"), "rb").read()

# ---- EDIT 球员 id->name ----
def rn(buf, off):
    return buf[off+0x36: off+0x36+61].split(b"\x00", 1)[0].decode("utf-8", errors="replace")

id2name = {}
off = 0x7C
while off + 312 <= len(eb):
    pid = struct.unpack_from("<I", eb, off)[0]
    aid = struct.unpack_from("<I", eb, off+240)[0]
    if pid and pid == aid and 1 <= pid <= 200000 and pid not in id2name:
        id2name[pid] = rn(eb, off)
    off += 312
eids = set(id2name)
print(f"EDIT 有效球员: {len(eids)}")

# ---- team-player 表 ----
TP_START = 0x9D4648
TP_STRIDE = 284
TP_N = 694
NW = TP_STRIDE // 4

teams = []          # (rec_idx, team_id, [player_ids])
for i in range(TP_N):
    o = TP_START + i * TP_STRIDE
    if o + TP_STRIDE > len(eb):
        break
    u = [struct.unpack_from("<I", eb, o + k*4)[0] for k in range(NW)]
    tid = u[0]
    pl = []
    for k in range(1, NW):
        if u[k] in eids:
            pl.append(u[k])
        elif u[k] == 0 and pl:
            break
        elif u[k] != 0 and u[k] not in eids:
            break
    teams.append((i, tid, pl))

nonzero = [t for t in teams if t[2]]
lens = [len(t[2]) for t in nonzero]
print(f"team-player 记录: {len(teams)} 条；有球员: {len(nonzero)}；"
      f"每队人数 min={min(lens)} max={max(lens)} 中位={sorted(lens)[len(lens)//2]}")

# 球员 -> 球队（一名球员可能属多队，记第一个 + 计数）
p2t = {}
for _, tid, pl in teams:
    for p in pl:
        p2t.setdefault(p, tid)
allp = set(p2t)
print(f"映射到球队的球员: {len(allp)} / {len(eids)} = {100*len(allp)/len(eids):.1f}%")

# ---- 导出 1: 球队->球员 ----
out1 = os.path.join(BASE, "outputs", "edit_team_players.csv")
with open(out1, "w", encoding="utf-8", newline="") as f:
    w = csv.writer(f)
    w.writerow(["rec_idx", "team_id", "n_players", "player_ids", "player_names"])
    for i, tid, pl in teams:
        names = [id2name.get(p, "") for p in pl]
        w.writerow([i, tid, len(pl), "|".join(str(p) for p in pl),
                    "|".join(n for n in names)])
print(f"导出 -> {out1}")

# ---- 导出 2: 球员->球队 ----
out2 = os.path.join(BASE, "outputs", "edit_player_team.csv")
with open(out2, "w", encoding="utf-8", newline="") as f:
    w = csv.writer(f)
    w.writerow(["player_id", "player_name", "team_id"])
    for p, t in sorted(p2t.items()):
        w.writerow([p, id2name.get(p, ""), t])
print(f"导出 -> {out2}")

# ---- 关联事件表 ----
rows = list(csv.DictReader(open(os.path.join(BASE, "outputs", "event_table_named_full.csv"),
                                encoding="utf-8")))
# 重新建立各档 reg（用于 v5/v6 注册索引解析）
def load_reg(fn):
    b = open(os.path.join(BASE, "decoded", fn), "rb").read()
    reg = {}
    o = 0xde034
    while o + 8 <= len(b):
        a = struct.unpack_from("<I", b, o)[0]
        c = struct.unpack_from("<I", b, o+4)[0]
        if 1 <= a <= 400000 and 1 <= c <= 200000:
            reg[a] = c
        o += 8
    return reg

regs = {"ML0": load_reg("ML00000000.data"), "ML1": load_reg("ML00000001.data"),
        "ML13": load_reg("ML00000013.data")}

def n_(r, k):
    try: return int(r[k])
    except (KeyError, ValueError): return None

hit_f2 = hit_v5 = hit_v6 = hit_v4 = 0
out_rows = []
for r in rows:
    reg = regs[r["src"]]
    # 各引用解析成 EDIT db_id
    cands = {}
    pid = n_(r, "f2_hi(player_id)") or 0
    if pid and pid != 65535:
        cands["f2"] = pid if pid in eids else reg.get(pid)
    h5 = n_(r, "v5") >> 16
    db5 = reg.get(h5)
    if db5: cands["v5"] = db5
    h6 = n_(r, "v6") >> 16
    if h6 != 65535:
        db6 = reg.get(h6)
        if db6: cands["v6"] = db6
    l4 = n_(r, "v4") & 0xFFFF
    if l4 in eids: cands["v4lo"] = l4
    # 查球队
    t = {}
    for k, db in cands.items():
        if db in p2t:
            t[k] = p2t[db]
    if "f2" in t: hit_f2 += 1
    if "v5" in t: hit_v5 += 1
    if "v6" in t: hit_v6 += 1
    if "v4lo" in t: hit_v4 += 1
    r2 = dict(r)
    r2.update({"team_f2": t.get("f2", ""), "team_v5": t.get("v5", ""),
               "team_v6": t.get("v6", ""), "team_v4lo": t.get("v4lo", ""),
               "team_any": next(iter(t.values()), "") if t else ""})
    out_rows.append(r2)

T = len(rows)
print(f"\n=== 事件表球队关联（{T} 行）===")
print(f"  f2 命中球队: {hit_f2} ({hit_f2/T:.1%})")
print(f"  v5 命中球队: {hit_v5} ({hit_v5/T:.1%})")
print(f"  v6 命中球队: {hit_v6} ({hit_v6/T:.1%})")
print(f"  v4_lo 命中球队: {hit_v4} ({hit_v4/T:.1%})")
any_hit = sum(1 for r in out_rows if r["team_any"])
print(f"  行级至少 1 个球队: {any_hit} ({any_hit/T:.1%})")

out3 = os.path.join(BASE, "outputs", "event_table_with_team.csv")
with open(out3, "w", encoding="utf-8", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(out_rows[0].keys()))
    w.writeheader()
    for r in out_rows:
        w.writerow(r)
print(f"导出 -> {out3}")
