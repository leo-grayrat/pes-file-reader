#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
team_names.py —— 导出 pesdb 队名表（dt10 Team.bin），并生成 EDIT team_id 队名映射。

Team.bin 结构（2026-08-30 实测确认）:
  QWESYS 头 + zlib（@0x10）→ 解压 1,133,680 B
  记录起始 0x100，739 条 × 1532 B（定长）
  +0x70   英文名（UTF-8，null 结尾）
  +0x272  三字码（FIFA 国家码 / 俱乐部缩写）
  记录内**不含 team_id 字段**（前 0x70 全 0，+0x530 段亦无）→ 纯名字表

关键结论：Team.bin 的**记录顺序 ≠ team_id 顺序**（pesdb 第 42 条是 Honduras，
但 EDIT team_id 42 的球员是哥斯达黎加队）。因此不能简单用 team_id 索引取名字。

产出:
  outputs/pesdb_team_names.csv   739 条 pesdb 队名（索引/英文名/三字码）
  outputs/edit_team_names.csv    EDIT team_id → 队名（已验证 + 候选，含置信度标注）
"""
import csv, os, struct, zlib

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TB = os.path.join(BASE, "outputs", "cpk_extract_dt10", "common", "etc", "Team.bin")

# ---------- 1. 解析 Team.bin ----------
raw = open(TB, "rb").read()
out = zlib.decompressobj().decompress(raw[0x10:])
REC, START = 1532, 0x100
NT = (len(out) - START) // REC

def s_at(o, ln):
    return out[o:o+ln].split(b"\x00", 1)[0].decode("utf-8", errors="replace")

teams = []
for i in range(NT):
    o = START + i * REC
    teams.append((i + 1, s_at(o + 0x70, 48), s_at(o + 0x272, 8)))

out1 = os.path.join(BASE, "outputs", "pesdb_team_names.csv")
with open(out1, "w", encoding="utf-8", newline="") as f:
    w = csv.writer(f)
    w.writerow(["pesdb_index", "english_name", "code3"])
    w.writerows(teams)
print(f"pesdb 队名 {len(teams)} 条 -> {out1}")

# ---------- 2. EDIT team 列表 ----------
eb = open(os.path.join(BASE, "decoded", "EDIT00000000.data"), "rb").read()
tids = []
o = 0x9D4648
for i in range(694):
    tids.append(struct.unpack_from("<I", eb, o)[0])
    o += 284

# 已人工验证的锚点: EDIT team_id -> pesdb_index
# （通过队内球员实名核对：国家队段 1:1 成立；俱乐部段由 418/420 锚定）
VERIFIED = {1: 1, 2: 2, 3: 3, 4: 4, 5: 5, 6: 6, 7: 7, 8: 8, 9: 9, 10: 10,
            11: 11, 12: 12, 21: 21, 418: 240, 420: 241}

idx2team = {i + 1: t for i, t in enumerate(teams)}

def nc(pi):
    """按 pesdb 索引取 (英文名, 三字码)。"""
    t = idx2team.get(pi)
    return (t[1], t[2]) if t else ("", "")

out2 = os.path.join(BASE, "outputs", "edit_team_names.csv")
n_ver = n_cand = n_none = 0
with open(out2, "w", encoding="utf-8", newline="") as f:
    w = csv.writer(f)
    w.writerow(["edit_team_id", "team_name", "code3", "pesdb_index", "confidence", "note"])
    for tid in tids:
        if tid in VERIFIED:
            pi = VERIFIED[tid]
            nm, cd = nc(pi)
            w.writerow([tid, nm, cd, pi, "verified", "球员实名核对通过"])
            n_ver += 1
        elif tid <= NT:
            nm, cd = nc(tid)
            w.writerow([tid, nm, cd, tid, "candidate",
                        "1:1 假设，未验证（Team.bin 顺序!=team_id，可能错配）"])
            n_cand += 1
        else:
            w.writerow([tid, "", "", "", "unknown",
                        f"team_id {tid} > pesdb 条目数 {NT}，无候选"])
            n_none += 1
print(f"EDIT team_id {len(tids)} 个 -> {out2}")
print(f"  已验证 {n_ver} / 假设候选 {n_cand} / 无候选 {n_none}")
print()
print("已验证锚点（EDIT team_id -> 队名）:")
for tid, pi in sorted(VERIFIED.items()):
    nm, cd = nc(pi)
    print(f"  {tid:>4} -> [{pi:>3}] {nm} ({cd})")
