#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""批量采集 PES master 球员页(compare?id=<pid>)的 25 项能力值 + 总评，用于回归反推位置加权权重。

数据源: https://www.pesmaster.com/pes-2021/compare/?id=<pid>  (slug-less, 返回结构化能力值表)
本脚本只 READ，不写回任何游戏文件。采集到的数据落 outputs/pesmaster_reference.csv。
"""
import csv, re, sys, time, os
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

BASE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(BASE, "outputs")
SRC = os.path.join(OUT, "edit_player_abilities.csv")
DST = os.path.join(OUT, "pesmaster_reference.csv")

# 与 build_player_browser.ABIL_ORDER 对应的 PES master 标签
ABIL_ORDER = ["offensive_awareness", "ball_control", "tight_possession", "low_pass",
              "lofted_pass", "finishing", "place_kicking", "curl", "speed", "acceleration",
              "jump", "physical_contact", "balance", "stamina", "ball_winning", "aggression",
              "gk_awareness", "gk_catching", "gk_reach", "defensive_awareness", "gk_clearing",
              "heading", "dribbling", "gk_reflexes", "kicking_power"]
LABEL2KEY = {
    "Offensive Awareness": "offensive_awareness",
    "Ball Control": "ball_control",
    "Dribbling": "dribbling",
    "Tight Possession": "tight_possession",
    "Low Pass": "low_pass",
    "Lofted Pass": "lofted_pass",
    "Finishing": "finishing",
    "Place Kicking": "place_kicking",
    "Kicking Power": "kicking_power",
    "Curl": "curl",
    "Speed": "speed",
    "Acceleration": "acceleration",
    "Jump": "jump",
    "Physical Contact": "physical_contact",
    "Balance": "balance",
    "Stamina": "stamina",
    "Ball Winning": "ball_winning",
    "Aggression": "aggression",
    "Defensive Awareness": "defensive_awareness",
    "Heading": "heading",
    "GK Awareness": "gk_awareness",
    "GK Catching": "gk_catching",
    "GK Reflexes": "gk_reflexes",
    "GK Reach": "gk_reach",
    "GK Clearing": "gk_clearing",
}
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36"
ROW_RE = re.compile(r"<tr><td>([^<]+)</td><td><span[^>]*>(\d+)</span></td></tr>")


def fetch(pid):
    url = "https://www.pesmaster.com/pes-2021/compare/?id=%s" % pid
    for attempt in range(2):
        req = Request(url, headers={"User-Agent": UA})
        try:
            html = urlopen(req, timeout=25).read().decode("utf-8", "replace")
        except Exception:
            continue
        rows = ROW_RE.findall(html)
        if rows:
            return rows
    return None
    if not rows:
        return None
    data = {}
    overall = None
    for label, val in rows:
        if label == "Overall":
            overall = int(val)
        elif label in LABEL2KEY:
            data[LABEL2KEY[label]] = int(val)
    if overall is None or len(data) < 20:
        return None
    return overall, data


def main():
    per_pos = int(sys.argv[1]) if len(sys.argv) > 1 else 22
    rows = list(csv.DictReader(open(SRC, encoding="utf-8")))
    # 按 reg_pos 分组
    by_pos = {}
    for r in rows:
        try:
            rp = int(r["reg_pos"])
        except (KeyError, ValueError):
            continue
        by_pos.setdefault(rp, []).append(r)

    # 简易档位排序用代理总评(用社区文档化权重，仅用于分层抽样)
    def proxy(r):
        s = 0
        for k in ABIL_ORDER:
            try:
                s += int(r[k])
            except (KeyError, ValueError):
                pass
        return s

    cand = []
    for rp, rs in by_pos.items():
        rs.sort(key=proxy)
        n = len(rs)
        step = max(1, n // per_pos)
        for i in range(0, n, step):
            cand.append((rp, rs[i]["pid"]))
    # 去重
    seen = set()
    cand = [c for c in cand if not (c[1] in seen or seen.add(c[1]))]

    print("候选球员数: %d" % len(cand))
    # 断点续传: 跳过已采集的 pid
    done = set()
    resume = os.path.exists(DST)
    if resume:
        with open(DST, encoding="utf-8", newline="") as f:
            for r in csv.DictReader(f):
                done.add(r["pid"])
    out = open(DST, "a" if resume else "w", encoding="utf-8", newline="")
    w = csv.writer(out)
    if not resume:
        w.writerow(["pid", "reg_pos"] + ABIL_ORDER + ["overall"])
    ok = 0
    for i, (rp, pid) in enumerate(cand):
        if pid in done:
            continue
        rows = fetch(pid)
        if not rows:
            continue
        overall = None
        data = {}
        for label, val in rows:
            if label == "Overall":
                overall = int(val)
            elif label in LABEL2KEY:
                data[LABEL2KEY[label]] = int(val)
        if overall is None or len(data) < 20:
            continue
        w.writerow([pid, rp] + [data.get(k, "") for k in ABIL_ORDER] + [overall])
        done.add(pid)
        ok += 1
        if (i + 1) % 25 == 0:
            print("  进度 %d/%d  已采集 %d" % (i + 1, len(cand), ok))
            out.flush()
        time.sleep(0.12)
    out.close()
    print("完成: 成功采集 %d / %d" % (ok, len(cand)))
    print("输出: %s" % DST)


if __name__ == "__main__":
    main()
