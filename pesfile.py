#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""pesfile.py -- PES2021 存档（EDIT / ML / BL）已确认结构 consolidated 解析器。

把散落在 bl_ml_probe*.py 中的已验证结构沉淀为一个可复用模块 + CLI：
  - 读取 decoded/ 下已解密的 .data 块（也可 --decrypt 从 examples/ 现解）
  - 解析 EDIT：球员 240B 表、team-player 映射、队名（来自 team_id_names_final.csv）
  - 解析 ML：700 球队块、动态事件表(0x12A72FD)、赛程表(0x3299B0)
  - 导出 outputs/parsed_*.csv + outputs/parsed_summary.json

所有偏移/步长均来自 docs/bl_ml_structure.md（已交叉验证）。
未解结构（ML↔EDIT 队ID映射、年龄/能力值位域、当前余额）在 JSON 摘要里标记，不做臆测。

用法：
  python pesfile.py                 # 解析 decoded/ 下全部 EDIT/ML/BL，导出 CSV+JSON
  python pesfile.py --decrypt       # 先解密 examples/* 到 decoded/ 再解析
  python pesfile.py EDIT ML0        # 只解析指定存档（EDIT=EDIT00000000, ML0=ML00000000...）
纯标准库。
"""
import os, sys, struct, csv, json, zlib, glob, unicodedata

BASE = os.path.dirname(os.path.abspath(__file__))
DEC = os.path.join(BASE, "decoded")
EXA = os.path.join(BASE, "examples")
OUT = os.path.join(BASE, "outputs")
TEAMNAMES = os.path.join(OUT, "team_id_names_final.csv")

# ---------------- 已确认结构常量 ----------------
# EDIT
EDIT_PLAYER_BASE = 0x7C
EDIT_PLAYER_STRIDE = 312        # 240 data + 72 appearance
EDIT_PLAYER_DATA = 240
EDIT_NAME_OFF = 0x36
EDIT_NAT_OFF = 0x08
EDIT_HT_OFF = 0x0A
EDIT_WT_OFF = 0x0B
TP_START = 0x9D4648
TP_STRIDE = 284
TP_N = 694
# ML
TEAM_START, TEAM_STRIDE, TEAM_N = 0x100, 0x690, 700
TEAM_OFF_NAME, TEAM_OFF_ABBR, TEAM_OFF_STADIUM = 0x5E4, 0x62A, 0x630
TEAM_OFF_BUDGET, TEAM_OFF_SEQ = 0x598, 0x1DC
EVENT_BASE = 0x12A72FD
EVENT_STRIDE = 0x24
EVENT_N = 100                    # 环形缓冲容量（99 真实 + 1 哨兵）
SCHED_BASE = 0x3299B0
SCHED_STRIDE = 0x254
SCHED_OFF_SEQ, SCHED_OFF_DATE, SCHED_OFF_ROUND = 0x150, 0x158, 0x160


# ---------------- 基础工具 ----------------
def u16(b, o): return struct.unpack_from("<H", b, o)[0]
def u32(b, o): return struct.unpack_from("<I", b, o)[0]
def cstr(b, o, n):
    e = b.find(b"\x00", o, o + n)
    if e < 0: e = o + n
    return b[o:e].decode("utf-8", "replace")


def load_team_names():
    """team_id -> (name, confidence)。失败返回空 dict。"""
    d = {}
    if not os.path.exists(TEAMNAMES):
        return d
    with open(TEAMNAMES, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            try:
                d[int(row["team_id"])] = (row["name"].strip(), row["confidence"])
            except (ValueError, KeyError):
                pass
    return d


# ---------------- 解密（可选） ----------------
def decrypt_if_needed(stem):
    """若 decoded/ 无该文件但有 examples/ 同名加密文件，则解密。返回解码后路径。"""
    dec_path = os.path.join(DEC, stem + ".data")
    exa_path = os.path.join(EXA, stem)
    if os.path.exists(dec_path):
        return dec_path
    if os.path.exists(exa_path):
        try:
            import pes_decrypt
        except ImportError:
            sys.stderr.write("pes_decrypt.py 不可导入，跳过解密\n")
            return None
        # 复用 pes_decrypt 的解密能力（兼容其 CLI 形态：尝试函数式入口）
        data = pes_decrypt.decrypt_file(exa_path) if hasattr(pes_decrypt, "decrypt_file") \
            else None
        if data is None:
            sys.stderr.write(f"无法解密 {exa_path}（pes_decrypt 无 decrypt_file 入口）\n")
            return None
        os.makedirs(DEC, exist_ok=True)
        with open(dec_path, "wb") as f:
            f.write(data)
        return dec_path
    return None


# ---------------- EDIT 解析 ----------------
def parse_edit(path):
    b = open(path, "rb").read()
    res = {"file": os.path.basename(path), "size": len(b),
           "header": {}, "players": [], "team_players": [], "warnings": []}
    # 头部计数
    res["header"] = {
        "player_count": u32(b, 0x60),
        "team_count": u32(b, 0x64) & 0xFFFF,
        "stadium_count": u32(b, 0x68) & 0xFFFF,
        "team_player_entries": u32(b, 0x70),
    }
    n = res["header"]["player_count"]
    # 球员表
    players = []
    off = EDIT_PLAYER_BASE
    for i in range(n):
        pid = u32(b, off)
        if pid == 0 or pid == 0xFFFFFFFF:
            off += EDIT_PLAYER_STRIDE
            continue
        name = cstr(b, off + EDIT_NAME_OFF, 61)
        nat = u16(b, off + EDIT_NAT_OFF)
        ht = b[off + EDIT_HT_OFF] if off + EDIT_HT_OFF < len(b) else 0
        wt = b[off + EDIT_WT_OFF] if off + EDIT_WT_OFF < len(b) else 0
        players.append({"id": pid, "name": name, "nat": nat,
                        "height": ht, "weight": wt})
        off += EDIT_PLAYER_STRIDE
    res["players"] = players

    # team-player 表
    tps = []
    for t in range(TP_N):
        o = TP_START + t * TP_STRIDE
        tid = u32(b, o)
        if tid == 0 or tid == 0xFFFFFFFF:
            continue
        pids = []
        for k in range(1, TP_STRIDE // 4):
            v = u32(b, o + k * 4)
            if v == 0 or v == 0xFFFFFFFF:
                break
            pids.append(v)
        tps.append({"team_id": tid, "players": pids})
    res["team_players"] = tps
    return res


# ---------------- ML 解析 ----------------
def _load_edit_ids_for_links():
    s = set()
    p = os.path.join(OUT, "parsed_edit_players_EDIT00000000.csv")
    if os.path.exists(p):
        import csv as _csv
        with open(p, encoding="utf-8") as f:
            for r in _csv.DictReader(f):
                try:
                    s.add(int(r["player_id"]))
                except (ValueError, KeyError):
                    pass
    return s


def parse_ml_linktable(b):
    """解析 ML 队块外的 per-entity 关联/历史链式记录表。
    记录以 u16 小端 0x07E5('e5 07') 为标记, 实测记录长 596B; 每条:
      header = 前 8×u32, 其中 u32[2]=条目数(count);
      之后从 +0x20 起, 16B/条 = [id_u32][0][other_id_u32][val_u32] 的列表
      (第 2 个 u32==0 是分隔符, 用来筛出有效条目)。
    同一球员可在多条记录里作为链接项出现(已验证 45144 出现 14 次)。
    语义 TBD: 疑似转会/球探/关系/历史链接, 非 condition/合约/成长/训练本身。
    """
    ids = _load_edit_ids_for_links()
    tags = [i for i in range(len(b) - 1) if b[i] == 0xE5 and b[i + 1] == 0x07]
    recs = []
    i = 0
    while i < len(tags) - 1:
        gap = tags[i + 1] - tags[i]
        if gap == 596:
            o = tags[i]
            hdr = [u32(b, o + j * 4) for j in range(8)]
            count = hdr[2]
            end = tags[i + 1]
            entries = []
            off = o + 32
            while off + 16 <= end:
                a = u32(b, off); z = u32(b, off + 4)
                c = u32(b, off + 8); v = u32(b, off + 12)
                if z == 0:
                    entries.append((a, c, v))
                off += 16
            recs.append({"off": o, "hdr": hdr, "count": count,
                         "entries": entries,
                         "edit_links": sum(1 for a, c, v in entries if a in ids)})
            i += 1
        else:
            i += 1
    return recs


def parse_ml(path):
    b = open(path, "rb").read()
    res = {"file": os.path.basename(path), "size": len(b),
           "teams": [], "events": [], "schedule": [], "warnings": []}
    # 700 球队块
    teams = []
    for r in range(TEAM_N):
        o = TEAM_START + r * TEAM_STRIDE
        name = cstr(b, o + TEAM_OFF_NAME, 64).strip()
        abbr = cstr(b, o + TEAM_OFF_ABBR, 4).strip()
        stadium = cstr(b, o + TEAM_OFF_STADIUM, 64).strip()
        budget = u32(b, o + TEAM_OFF_BUDGET)
        seq = u32(b, o + TEAM_OFF_SEQ)
        # 阵容表 @+0xA0 stride 8 = [player_id][squad_index]; 读到哨兵(0/0xFFFFFFFF)为止
        squad = []
        so = o + 0xA0
        for k in range(60):
            pid = u32(b, so + k * 8)
            if pid == 0 or pid == 0xFFFFFFFF:
                break
            sidx = u32(b, so + k * 8 + 4)
            squad.append((pid, sidx))
        teams.append({"idx": r, "name": name, "abbr": abbr,
                      "stadium": stadium, "budget_raw": budget,
                      "budget_eur": budget * 100, "ml_seq": seq,
                      "squad": [p for p, _ in squad],
                      "squad_idx": [i for _, i in squad]})
    res["teams"] = teams

    # 动态事件表（环形缓冲）
    events = []
    for i in range(EVENT_N):
        o = EVENT_BASE + i * EVENT_STRIDE
        if o + EVENT_STRIDE > len(b):
            break
        f = [u32(b, o + k * 4) for k in range(9)]
        if all(x == 0xFFFFFFFF for x in f):
            continue  # 整条哨兵
        events.append({"slot": i, "f0": f[0], "f1": f[1], "f2": f[2],
                       "f3": f[3], "f4": f[4], "f5": f[5], "f6": f[6],
                       "f7": f[7], "f8": f[8]})
    res["events"] = events

    # 赛程表
    sched = []
    o = SCHED_BASE
    while o + SCHED_STRIDE <= len(b):
        seq = u32(b, o + SCHED_OFF_SEQ)
        if seq == 0xFFFF:
            break
        y = u16(b, o + SCHED_OFF_DATE)
        mo, d = b[o + SCHED_OFF_DATE + 2], b[o + SCHED_OFF_DATE + 3]
        rnd = u32(b, o + SCHED_OFF_ROUND)
        sched.append({"seq": seq, "year": y, "month": mo, "day": d, "round": rnd})
        o += SCHED_STRIDE
    res["schedule"] = sched
    return res


# ---------------- 导出 ----------------
def _write_csv(path, header, rows):
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)


def export_edit(ed, team_names, tag):
    # 球员
    _write_csv(os.path.join(OUT, f"parsed_edit_players_{tag}.csv"),
               ["player_id", "name", "nationality", "height_cm", "weight_kg"],
               [[p["id"], p["name"], p["nat"], p["height"], p["weight"]]
                for p in ed["players"]])
    # team-player + 队名
    tnm = {}
    for tp in ed["team_players"]:
        tid = tp["team_id"]
        nm, conf = team_names.get(tid, ("", ""))
        tnm[tid] = (nm, conf, len(tp["players"]))
    _write_csv(os.path.join(OUT, f"parsed_edit_teams_{tag}.csv"),
               ["team_id", "team_name", "confidence", "n_players"],
               [[tid, v[0], v[1], v[2]] for tid, v in sorted(tnm.items())])
    _write_csv(os.path.join(OUT, f"parsed_edit_team_players_{tag}.csv"),
               ["team_id", "player_id"],
               [[tp["team_id"], pid] for tp in ed["team_players"]
                for pid in tp["players"]])


def export_ml(ml, tag):
    _write_csv(os.path.join(OUT, f"parsed_ml_teams_{tag}.csv"),
               ["ml_idx", "name_cn", "abbr", "stadium", "budget_raw",
                "budget_eur", "ml_seq"],
               [[t["idx"], t["name"], t["abbr"], t["stadium"],
                 t["budget_raw"], t["budget_eur"], t["ml_seq"]]
                for t in ml["teams"]])
    _write_csv(os.path.join(OUT, f"parsed_ml_team_squads_{tag}.csv"),
               ["ml_idx", "name_cn", "ml_seq", "player_id", "squad_index"],
               [[t["idx"], t["name"], t["ml_seq"], pid, sidx]
                for t in ml["teams"]
                for pid, sidx in zip(t["squad"], t["squad_idx"])])
    _write_csv(os.path.join(OUT, f"parsed_ml_events_{tag}.csv"),
               ["slot", "f0", "f1", "f2", "f3", "f4", "f5", "f6", "f7", "f8"],
               [[e["slot"], e["f0"], e["f1"], e["f2"], e["f3"], e["f4"],
                 e["f5"], e["f6"], e["f7"], e["f8"]] for e in ml["events"]])
    _write_csv(os.path.join(OUT, f"parsed_ml_schedule_{tag}.csv"),
               ["seq", "year", "month", "day", "round"],
               [[s["seq"], s["year"], s["month"], s["day"], s["round"]]
                for s in ml["schedule"]])
    # 队块外 596B 'e5 07' 关联/历史链式记录表
    links = parse_ml_linktable(open(os.path.join(DEC, tag + ".data"), "rb").read())
    _write_csv(os.path.join(OUT, f"parsed_ml_link_records_{tag}.csv"),
               ["rec_idx", "offset_hex", "h0", "h1", "count", "h3", "h4", "h5",
                "h6", "h7", "n_entries", "edit_id_links", "sample_entries"],
               [[ri, f"0x{r['off']:X}", r["hdr"][0], r["hdr"][1], r["count"],
                 r["hdr"][3], r["hdr"][4], r["hdr"][5], r["hdr"][6], r["hdr"][7],
                 len(r["entries"]), r["edit_links"],
                 ";".join(f"{a}:{c}:{v}" for a, c, v in r["entries"][:10])]
                for ri, r in enumerate(links)])


def main():
    args = sys.argv[1:]
    do_decrypt = "--decrypt" in args
    stems = [a for a in args if not a.startswith("--")]
    if not stems:
        # 默认：EDIT + 全部 ML/BL
        stems = ["EDIT00000000"]
        for p in sorted(glob.glob(os.path.join(DEC, "ML*.data"))):
            stems.append(os.path.splitext(os.path.basename(p))[0])

    team_names = load_team_names()
    summary = {"team_names_loaded": len(team_names),
               "saves": {}, "unsolved": [
                   "ML<->EDIT team_id 映射（预算闭合最后缺口，需 Konami ID 主表或存档内映射表）",
                   "EDIT 球员年龄 / 能力值位域布局（EDIT 240B 与 CT ptrPlayer 380B 布局不同）",
                   "当前余额字段（仅初始预算 +0x598 落盘，余额运行时计算）",
               ]}

    files = []
    for stem in stems:
        if do_decrypt:
            p = decrypt_if_needed(stem)
        else:
            p = os.path.join(DEC, stem + ".data")
        if not p or not os.path.exists(p):
            sys.stderr.write(f"[skip] {stem}: 未找到解码文件\n")
            continue
        files.append((stem, p))

    for stem, p in files:
        if stem.startswith("EDIT"):
            ed = parse_edit(p)
            tag = stem
            export_edit(ed, team_names, tag)
            summary["saves"][stem] = {
                "size": ed["size"], "header": ed["header"],
                "players": len(ed["players"]),
                "team_players": len(ed["team_players"]),
                "players_named": sum(1 for x in ed["players"] if x["name"]),
            }
            print(f"[EDIT] {stem}: players={len(ed['players'])} "
                  f"team_players={len(ed['team_players'])} "
                  f"named={sum(1 for x in ed['players'] if x['name'])}")
        elif stem.startswith("ML"):
            ml = parse_ml(p)
            tag = stem
            export_ml(ml, tag)
            summary["saves"][stem] = {
                "size": ml["size"], "teams": len(ml["teams"]),
                "events": len(ml["events"]),
                "schedule_dated": len(ml["schedule"]),
            }
            print(f"[ML]   {stem}: teams={len(ml['teams'])} "
                  f"events={len(ml['events'])} "
                  f"schedule={len(ml['schedule'])}")
        else:
            print(f"[info] {stem}: 未实现解析（BL/REPLAY 见 decode_dump.py）")

    with open(os.path.join(OUT, "parsed_summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
    print(f"\n汇总已写入 outputs/parsed_summary.json "
          f"（team_names_loaded={len(team_names)}）")


if __name__ == "__main__":
    main()
