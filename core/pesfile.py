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

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
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
# ML（队块起始/字段偏移经 exe 装载同步 §7.9 + 数据侧校准 §7.9.1 修正：
#  真队块表从 data+0x50 起；pesfile 旧用 TEAM_START=0x100，使队名/缩写/球场整体读到
#  下一队（块错位），预算因偏移巧合恰好对齐。Squad 为 [squad_index, player_id] @+0x14C。）
TEAM_START, TEAM_STRIDE, TEAM_N = 0x50, 0x690, 700
TEAM_OFF_NAME, TEAM_OFF_ABBR, TEAM_OFF_STADIUM = 0x04, 0x4A, 0x50
TEAM_OFF_BUDGET, TEAM_OFF_SEQ = 0x648, 0x28C
TEAM_OFF_SQUAD = 0x14C
# Squad 槽 = [squad_index u32, player_id u32] stride 8（与赛程 slot [squad_index, player_id,…] 同序）
EVENT_BASE = 0x12A72FD
EVENT_STRIDE = 0x24
EVENT_N = 100                    # 环形缓冲容量（99 真实 + 1 哨兵）
# 赛程表。条目起点经 exe 字段图 + 数据侧三判据校准为 0x329B00
# （旧值 0x3299B0 少了 0x150，字段偏移相应多 0x150，两个错误互相抵消，
#  所以 seq/date/round 读出来是对的，但整条条目的字段对齐是错的，
#  详见 docs/exe-save-layout.md §7.6 / exe/probe_sched_fields.py）
SCHED_BASE = 0x329B00
SCHED_STRIDE = 0x254             # = 596，exe 侧确认的 sizeof
SCHED_CAP = 13000                # exe 侧读到的容量上限
SCHED_OFF_SEQ, SCHED_OFF_FLAGS = 0x00, 0x04
SCHED_OFF_DATE, SCHED_OFF_ROUND = 0x08, 0x10
SCHED_OFF_HOME, SCHED_OFF_AWAY = 0x14, 0x18      # 低 14 位 = 球队块索引
SCHED_TEAM_MASK = 0x3FFF
SCHED_TEAM_FILL = 0x3FFF         # 未使用槽位填充（0x07F7FFFF 的低 14 位）
# 双方名单：+0x24 起 2 组 × 17 slot × 16 B，slot=[squad_index, player_id, 0, x]
SCHED_LINEUP_BASE, SCHED_SLOT, SCHED_GROUP_N = 0x24, 0x10, 17


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


def _load_squad_maps():
    """返回 (player_id->set(ml_idx), ml_idx->队名)。用于把 596B 记录的 h3/h4 反查到队。"""
    import csv as _csv
    import glob as _glob
    p2t = {}; t2n = {}
    cand = _glob.glob(os.path.join(OUT, "parsed_ml_team_squads_*.csv"))
    if cand:
        with open(cand[0], encoding="utf-8") as f:
            for r in _csv.DictReader(f):
                try:
                    pid = int(r["player_id"]); idx = int(r["ml_idx"])
                except (ValueError, KeyError):
                    continue
                p2t.setdefault(pid, set()).add(idx)
                t2n[idx] = r["name_cn"]
    return p2t, t2n


def parse_ml_linktable(b):
    """解析 ML 队块外的 596B 'e5 07' 队际球员链接记录表(选项 C 深挖结果)。

    结构(已全量验证):
      - 标记: u16 小端 0x07E5 出现在每条记录开头; 记录定长 596B。
      - header = 前 8×u32: h0 低16位=0x07E5(高16位为子类型, 120种, 非恒定),
        h1∈{0,1}, h2=count(真实记录 11..30; 另有 count=14098/超大 为碰巧含标记的其他表, 已过滤),
        h3 = 源队注册id, h4 = 目标队注册id(同命名空间, h4⊆h3 100%),
        h5∈小枚举(39种), h6∈{0..1538}(9种), h7 = 每条记录属性(1180种, 可能种子/子类型)。
      - entry 区 = 从 +0x20 起, 16B/条 = [player_a u32][0 分隔符][linktype_c u32][value_v u32];
        仅第2 u32==0 的条目有效。
      - 语义: 每条 = (队h3 → 队h4) 的有向链接, 列出 ~10-20 名球员(player_a),
        各带链接类型 c(全局仅 216 种, ~6.29-6.36M) 与每链接值 v(多为 0xFFFF 哨兵或 4-117 小值/~12800)。
        同一队的各子表(h4不同)球员集合基本不相交(Jaccard≈0.2) -> 非阵容切分, 而是队际球员监控/关系网络。
        列出球员多归第三方队(非 h3/h4 本队阵容)。
      - 这是 ML 的一类"隐藏机制"(队际球员关联网络), 但明确不是 condition/合约/成长/训练。
    """
    ids = _load_edit_ids_for_links()
    p2t, t2n = _load_squad_maps()
    tags = [i for i in range(len(b) - 1) if b[i] == 0xE5 and b[i + 1] == 0x07]
    recs = []
    for i in range(len(tags) - 1):
        if tags[i + 1] - tags[i] != 596:
            continue
        o = tags[i]
        hdr = [u32(b, o + j * 4) for j in range(8)]
        count = hdr[2]
        if not (11 <= count <= 30):   # 过滤碰巧含标记的其他表(噪声)
            continue
        end = tags[i + 1]
        entries = []
        off = o + 32
        while off + 16 <= end:
            a = u32(b, off); z = u32(b, off + 4)
            c = u32(b, off + 8); v = u32(b, off + 12)
            if z == 0:
                entries.append((a, c, v))
            off += 16
        # 用 entry 的 player_a 反查主导队(ml_idx), 解析 h3/h4 队名
        tc = {}
        for a, c, v in entries:
            if a in ids:
                for t in p2t.get(a, ()):
                    tc[t] = tc.get(t, 0) + 1
        dom = max(tc.items(), key=lambda kv: kv[1])[0] if tc else None
        recs.append({"off": o, "hdr": hdr, "count": count,
                     "entries": entries, "edit_links": sum(1 for a, c, v in entries if a in ids),
                     "h3_team": t2n.get(dom, "") if dom is not None else "",
                     "h3_team_idx": dom})
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
        # 阵容表 @+0x14C stride 8 = [squad_index][player_id]（序号在前、ID 在后，
        # 与赛程 slot 字段序一致）；读到哨兵(pid 0 / 0xFFFFFFFF)为止
        squad = []
        so = o + TEAM_OFF_SQUAD
        for k in range(60):
            sidx = u32(b, so + k * 8)
            pid = u32(b, so + k * 8 + 4)
            if pid == 0 or pid == 0xFFFFFFFF:
                break
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

    # 赛程表：每条 596 B = 场次头 + 主客队引用 + 双方 17 人名单
    sched = []
    for i in range(SCHED_CAP):
        o = SCHED_BASE + i * SCHED_STRIDE
        if o + SCHED_STRIDE > len(b):
            break
        if not any(b[o:o + SCHED_STRIDE]):
            continue
        y = u16(b, o + SCHED_OFF_DATE)
        if not (1990 <= y <= 2100):
            continue                          # 空槽 / 哨兵条
        home = u32(b, o + SCHED_OFF_HOME) & SCHED_TEAM_MASK
        away = u32(b, o + SCHED_OFF_AWAY) & SCHED_TEAM_MASK
        if home == SCHED_TEAM_FILL or away == SCHED_TEAM_FILL:
            continue                          # 未使用槽位（填充值）
        lineups = []
        for g in range(2):
            grp = []
            for s in range(SCHED_GROUP_N):
                so = o + SCHED_LINEUP_BASE + (g * SCHED_GROUP_N + s) * SCHED_SLOT
                sidx, pid = u32(b, so), u32(b, so + 4)
                if u16(b, so) == 0xFFFF and u16(b, so + 2) == 0:
                    continue                  # 空位
                if sidx == 0 and pid == 0:
                    continue
                grp.append((sidx, pid))
            lineups.append(grp)
        sched.append({"slot": i,
                      "seq": u16(b, o + SCHED_OFF_SEQ),
                      "year": y,
                      "month": b[o + SCHED_OFF_DATE + 2],
                      "day": b[o + SCHED_OFF_DATE + 3],
                      "round": b[o + SCHED_OFF_ROUND],
                      "flags": u32(b, o + SCHED_OFF_FLAGS),
                      "home": home, "away": away,
                      "home_lineup": lineups[0], "away_lineup": lineups[1]})
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
    tname = {t["idx"]: t["name"] for t in ml["teams"]}
    _write_csv(os.path.join(OUT, f"parsed_ml_schedule_{tag}.csv"),
               ["slot", "seq", "year", "month", "day", "round", "flags_hex",
                "home_idx", "home_name", "away_idx", "away_name",
                "n_home_lineup", "n_away_lineup"],
               [[s["slot"], s["seq"], s["year"], s["month"], s["day"], s["round"],
                 f"0x{s['flags']:08X}",
                 s["home"], tname.get(s["home"], ""),
                 s["away"], tname.get(s["away"], ""),
                 len(s["home_lineup"]), len(s["away_lineup"])]
                for s in ml["schedule"]])
    _write_csv(os.path.join(OUT, f"parsed_ml_schedule_lineups_{tag}.csv"),
               ["slot", "seq", "side", "team_idx", "team_name",
                "squad_index", "player_id"],
               [[s["slot"], s["seq"], side, s[key], tname.get(s[key], ""),
                 sidx, pid]
                for s in ml["schedule"]
                for side, key, lst in (("home", "home", s["home_lineup"]),
                                       ("away", "away", s["away_lineup"]))
                for sidx, pid in lst])
    # 队块外 596B 'e5 07' 队际球员链接记录表
    links = parse_ml_linktable(open(os.path.join(DEC, tag + ".data"), "rb").read())
    _write_csv(os.path.join(OUT, f"parsed_ml_link_records_{tag}.csv"),
               ["rec_idx", "offset_hex", "h3", "h4", "h3_team", "count", "h5",
                "h6", "h7", "n_entries", "edit_id_links", "sample_entries"],
               [[ri, f"0x{r['off']:X}", r["hdr"][3], r["hdr"][4], r.get("h3_team", ""),
                 r["count"], r["hdr"][5], r["hdr"][6], r["hdr"][7],
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
