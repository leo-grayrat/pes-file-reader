#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""app.py -- PES2021 存档浏览器（外置、独立、read-only）本地服务。

把前面几十次提交攒下的全部已逆向结构，统一接到一个只读 UI 里展示：
  - 球员（EDIT 240B 能力值 + 隐藏机制）
  - EDIT 球队 + 阵容映射
  - 大师联赛 700 球队块（中文队名/缩写/球场/预算×100欧/序号）
  - 动态事件表
  - 赛程表
  - 赛事定义表（76，直接解 ML 数据块）

数据来自 decoded/ 已解密块 与 outputs/ 各 CSV（均由 pesfile.py / edit_player_abilities.py 产出）。
纯标准库，不依赖游戏进程，不写回存档。

用法：python app.py [port]   然后浏览器打开 http://localhost:<port>
"""
import os, csv, json, sys, struct
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import build_player_browser as bp   # 复用标签表与字段顺序
import pes_ratings as pr              # PES 2021 位置加权总评(估算)

BASE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(BASE, "outputs")
DEC = os.path.join(BASE, "decoded")
UI = os.path.join(BASE, "ui")


def u16(b, o): return struct.unpack_from("<H", b, o)[0]
def u32(b, o): return struct.unpack_from("<I", b, o)[0]
def cstr(b, o, n):
    e = b.find(b"\x00", o, o + n)
    if e < 0: e = o + n
    return b[o:e].decode("utf-8", "replace").strip()


def csv_rows(name):
    p = os.path.join(OUT, name)
    if not os.path.exists(p):
        return []
    with open(p, encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def load_players():
    """复用 build_player_browser 的紧凑结构：players = [ [pid,name,nat,age,rp,ps,sf,
    wfu,wfa,ir,cond,star,play(13),com[],sk[],ab[25]] ]"""
    src = os.path.join(OUT, "edit_player_abilities.csv")
    players = []
    with open(src, encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            try:
                ab = [int(row[k]) for k in bp.ABIL_ORDER]
            except (KeyError, ValueError):
                continue
            sk = [bp.SKILLS.index(s) for s in (row.get("skills") or "").split(";") if s and s in bp.SKILLS]
            com = [bp.COM_STYLES.index(s) for s in (row.get("com_styles") or "").split(";") if s and s in bp.COM_STYLES]
            def gi(k, d=0):
                v = row.get(k)
                return int(v) if v not in (None, "") else d
            players.append([
                gi("pid"), row.get("name", ""), gi("nat"), gi("age"),
                gi("reg_pos"), gi("play_style"),
                1 if (row.get("stronger_foot") or "").startswith("L") else 0,
                gi("weak_foot_usage", 1), gi("weak_foot_accuracy", 1),
                gi("injury_resistance", 1), gi("conditioning", 1), gi("star_rating"),
                (row.get("playable") or "0" * 13)[:13], com, sk, ab,
                pr.compute_overall({k: int(row[k]) for k in bp.ABIL_ORDER if k in row}, gi("reg_pos")),
            ])
    meta = {
        "source": "EDIT00000000.data -> edit_player_abilities.py",
        "count": len(players),
        "abilities": bp.ABIL_ORDER,
        "abilityLabels": [bp.ABIL_LABEL.get(k, k) for k in bp.ABIL_ORDER],
        "positions": bp.REG_POS_NAMES, "playableOrder": bp.PLAYABLE_ORDER,
        "playStyles": bp.PLAY_STYLES, "skills": bp.SKILLS, "comStyles": bp.COM_STYLES,
        "overallNote": "总评按实况位置加权算法估算（参考 PES master 球员界面；已用 273 名真实球员验证，"
                       "平均与 PES master 相差约 3–7 分）。精确 Konami 权重未公开，属社区近似；"
                       "能力值下限 40（范围 [40,99]）。",
    }
    return {"meta": meta, "players": players}


def parse_competitions():
    p = os.path.join(DEC, "ML00000000.data")
    if not os.path.exists(p):
        return []
    b = open(p, "rb").read()
    base, stride = 0x1F1E30, 0x314
    out = []
    for i in range(140):
        o = base + i * stride
        if o + stride > len(b):
            break
        name = cstr(b, o + 0x2E2, 80)
        if not name:
            continue
        cid = u32(b, o + 0x4C)
        typ = b[o + 0x50]
        yr = u16(b, o + 0x2C8)
        out.append({
            "idx": i, "name": name, "comp_id": cid, "type": typ,
            "season_year": None if yr == 0xFFFF else yr,
            "operable": b[o + 0x1FC],
        })
    return out


def load_ml_squads():
    """大师联赛 700 队块内的阵容（team→player 映射）：join EDIT 库名字。"""
    pid_name = {}
    p = os.path.join(OUT, "parsed_edit_players_EDIT00000000.csv")
    if os.path.exists(p):
        with open(p, encoding="utf-8", newline="") as f:
            for r in csv.DictReader(f):
                try:
                    pid_name[int(r["player_id"])] = r.get("name", "")
                except (KeyError, ValueError):
                    pass
    src = os.path.join(OUT, "parsed_ml_team_squads_ML00000000.csv")
    teams = {}
    if os.path.exists(src):
        with open(src, encoding="utf-8", newline="") as f:
            for r in csv.DictReader(f):
                try:
                    idx = int(r["ml_idx"])
                except (KeyError, ValueError):
                    continue
                t = teams.setdefault(idx, {"ml_idx": idx, "name": r.get("name_cn", ""),
                                           "ml_seq": r.get("ml_seq", ""), "players": []})
                try:
                    pid = int(r["player_id"])
                except (KeyError, ValueError):
                    pid = 0
                t["players"].append({"pid": pid, "idx": r.get("squad_index", ""),
                                     "name": pid_name.get(pid, "")})
    for t in teams.values():
        t["players"].sort(key=lambda x: int(x["idx"]) if str(x["idx"]).isdigit() else 0)
    return {"teams": list(teams.values()),
            "player_name_hits": sum(1 for t in teams.values() for p in t["players"] if p["name"])}


def load_ml_links():
    """596B 'e5 07' 队际球员链接网络；给 h4 也解析队名（h4⊆h3 命名空间）。"""
    src = os.path.join(OUT, "parsed_ml_link_records_ML00000000.csv")
    rows = []
    h3_to_team = {}
    if os.path.exists(src):
        with open(src, encoding="utf-8", newline="") as f:
            for r in csv.DictReader(f):
                h3_to_team[r.get("h3", "")] = r.get("h3_team", "")
                rows.append(r)
    for r in rows:
        r["h4_team"] = h3_to_team.get(r.get("h4", ""), "")
    return rows


DATA = {}
def build():
    DATA["players"] = load_players()
    DATA["edit_teams"] = csv_rows("parsed_edit_teams_EDIT00000000.csv")
    DATA["ml_teams"] = csv_rows("parsed_ml_teams_ML00000000.csv")
    DATA["events"] = csv_rows("event_table_named_full.csv")
    DATA["schedules"] = csv_rows("parsed_ml_schedule_ML00000000.csv")
    DATA["competitions"] = parse_competitions()
    DATA["ml_squads"] = load_ml_squads()
    DATA["ml_links"] = load_ml_links()
    DATA["overview"] = {
        "source": "decoded/ (EDIT+ML) + outputs/*.csv",
        "counts": {
            "球员(EDIT 能力值+隐藏)": DATA["players"]["meta"]["count"],
            "EDIT 球队(已命名)": len(DATA["edit_teams"]),
            "大师联赛球队块": len(DATA["ml_teams"]),
            "动态事件(已命名)": len(DATA["events"]),
            "赛程条目(ML0)": len(DATA["schedules"]),
            "赛事定义表": len(DATA["competitions"]),
            "大师联赛阵容(球员引用)": sum(len(t["players"]) for t in DATA["ml_squads"]["teams"]),
            "队际链接网络(记录)": len(DATA["ml_links"]),
        },
        "unsolved": [
            "ML<->EDIT 球队ID映射（预算闭合缺口，需 Konami ID 主表或存档内映射表）",
            "ML 球员 condition/合约/成长/训练 精确字节偏移—— C 块深层待逆向（队→球员阵容与队际链接网络已解并接入 UI）",
            "当前余额（仅初始预算 +0x598 落盘，余额运行时计算）",
            "Salary / Market Value 存档编码",
        ],
    }


class H(BaseHTTPRequestHandler):
    def _json(self, obj):
        body = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _html(self):
        p = os.path.join(UI, "index.html")
        body = open(p, "rb").read()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0]
        try:
            if path in ("/", "/index.html"):
                self._html()
            elif path == "/api/overview":
                self._json(DATA["overview"])
            elif path == "/api/players":
                self._json(DATA["players"])
            elif path == "/api/edit_teams":
                self._json(DATA["edit_teams"])
            elif path == "/api/ml_teams":
                self._json(DATA["ml_teams"])
            elif path == "/api/events":
                self._json(DATA["events"])
            elif path == "/api/schedules":
                self._json(DATA["schedules"])
            elif path == "/api/competitions":
                self._json(DATA["competitions"])
            elif path == "/api/ml_squads":
                self._json(DATA["ml_squads"])
            elif path == "/api/ml_links":
                self._json(DATA["ml_links"])
            else:
                self.send_error(404)
        except BrokenPipeError:
            pass

    def log_message(self, *a):
        pass


def main():
    build()
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8787
    srv = ThreadingHTTPServer(("127.0.0.1", port), H)
    print("PES2021 存档浏览器已启动: http://localhost:%d" % port)
    print("覆盖区块: " + ", ".join(DATA["overview"]["counts"].keys()))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.shutdown()


if __name__ == "__main__":
    main()
