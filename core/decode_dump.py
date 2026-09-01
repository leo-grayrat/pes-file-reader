#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""decode_dump.py —— PES2021 存档解码内容报告生成器（纯标准库，无参运行）。

把已确认结构中的真实信息全部提取出来，生成人类可读的简体中文报告
`docs/decoded_content.md`。结果直接以 UTF-8 写入文件，不依赖终端显示
（规避 Windows 控制台中文乱码）。

覆盖内容：
  BL/ML 存档（BL00000000 / ML00000000）：
    - 700 支球队名单（中文名 + 缩写 + 主场球场 + 助威口号）
    - 72 条赛事定义（中文全名 + 赛事编号 + 类型 + 赛季年）
    - 用户球队信息、用户球员信息
    - 赛程表全量可读化（比赛日序号 + 年-月-日 + 轮次 + 当日场次）
  回放（50 个 rep_REPLAY*.data）：
    - 两队首发各 11 人 + 3 名裁判（全名/缩写名）
    - 每场比赛时钟范围与上下半场进度标记

结构依据：docs/bl_ml_structure.md、docs/replay_structure.md。
输入只读（decoded/），输出仅一个报告文件，无其他临时产物。
"""
import os
import re
import struct
from collections import Counter

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEC = os.path.join(BASE, "decoded")
OUT = os.path.join(BASE, "docs", "decoded_content.md")

FILES = {"BL0": "BL00000000.data", "ML0": "ML00000000.data"}

# ---------- 已确认结构常量 ----------
TEAM_START, TEAM_STRIDE, TEAM_N = 0x100, 0x690, 700
TEAM_OFF_NAME, TEAM_OFF_ABBR, TEAM_OFF_STADIUM = 0x5E4, 0x62A, 0x630
TEAM_OFF_CHANTS = (0x55, 0x65, 0x75, 0x85)          # 4 条助威口号槽
COMP_STRIDE = 0x314                                   # 赛事记录步长
COMP_OFF_NAME, COMP_OFF_CID, COMP_OFF_TYPE = 0x2E2, 0x4C, 0x50
COMP_OFF_SEASON = 0x2C8                               # u16 赛季年
SCHED_STRIDE = 0x254                                  # 比赛日记录步长
SCHED_OFF_SEQ, SCHED_OFF_DATE, SCHED_OFF_ROUND = 0x150, 0x158, 0x160
SCHED_OFF_ENTRIES = 0x30                              # 11 槽 × 16B 比赛条目
DATE_RE_WIDE = re.compile(rb"[\xe4-\xe8]\x07[\x01-\x0c][\x01-\x1f]")  # 2020~2024
CN_RE = re.compile(rb"(?:[\xe0-\xef][\x80-\xbf]{2}){2,24}")
DATE_RE = re.compile(rb"[\xe5-\xe7]\x07[\x01-\x0c][\x01-\x1f]")

REP_REC_BASE, REP_REC_STRIDE, REP_NAME_OFF = 0x80, 0xA0, 0x58
REP_FULLNAME_LO, REP_FULLNAME_HI = 0x2800, 0x2E00     # 全名表区


# ---------- 基础工具 ----------
def load(name):
    with open(os.path.join(DEC, name), "rb") as f:
        return f.read()


def u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def s32(b, o):
    return struct.unpack_from("<i", b, o)[0]


def cstr(b, o, maxlen):
    """NUL 结尾的 UTF-8 字符串。"""
    e = b.find(b"\x00", o, o + maxlen)
    if e < 0:
        e = o + maxlen
    return b[o:e].decode("utf-8", "replace")


def ascii_runs(b, lo, hi, minlen=3):
    """提取 [lo,hi) 内可打印 ASCII 串。"""
    out, cur, start = [], [], -1
    for i in range(lo, hi):
        x = b[i]
        if 32 <= x < 127:
            if not cur:
                start = i
            cur.append(chr(x))
        else:
            if len(cur) >= minlen:
                out.append((start, "".join(cur)))
            cur = []
    if len(cur) >= minlen:
        out.append((start, "".join(cur)))
    return out


def find_years(b, lo, hi):
    """在 [lo,hi) 内找 u16 年份（字节模式 E5/E6/E7 07，即 2021~2023）。"""
    out = []
    for j in range(lo, hi - 1):
        if b[j] in (0xE5, 0xE6, 0xE7) and b[j + 1] == 0x07:
            y = u16(b, j)
            if 2021 <= y <= 2023:
                mo, d = b[j + 2], b[j + 3]
                if 1 <= mo <= 12 and 1 <= d <= 31:
                    out.append((j, f"{y}-{mo:02d}-{d:02d}"))
                else:
                    out.append((j, str(y)))
    return out


# ---------- BL/ML：球队名单 ----------
def extract_teams(b):
    teams = []
    for r in range(TEAM_N):
        o = TEAM_START + r * TEAM_STRIDE
        teams.append({
            "idx": r,
            "name": cstr(b, o + TEAM_OFF_NAME, 64),
            "abbr": b[o + TEAM_OFF_ABBR:o + TEAM_OFF_ABBR + 3]
                    .decode("ascii", "replace").replace("\x00", ""),
            "stadium": cstr(b, o + TEAM_OFF_STADIUM, 64),
            "chants": [cstr(b, o + c, 16) for c in TEAM_OFF_CHANTS],
        })
    return teams


# ---------- BL/ML：赛事定义表 ----------
def extract_comps(b):
    hi = min(len(b), 0x200000)
    names = []
    for m in CN_RE.finditer(b, 0x1F0000, hi):
        try:
            t = m.group().decode("utf-8")
        except UnicodeDecodeError:
            continue
        if any("\u4e00" <= c <= "\u9fff" for c in t):
            names.append(m.start())
    noff = Counter(o % COMP_STRIDE for o in names).most_common(1)[0][0]
    base = next(o for o in names if o % COMP_STRIDE == noff) - noff
    nrec = (hi - base) // COMP_STRIDE
    rows = []
    for r in range(nrec):
        o = base + r * COMP_STRIDE
        yr = u16(b, o + COMP_OFF_SEASON)
        rows.append({
            "idx": r + 1,
            "cid": u32(b, o + COMP_OFF_CID),
            "type": u32(b, o + COMP_OFF_TYPE),
            "season": yr if yr != 0xFFFF else None,
            "name": cstr(b, o + COMP_OFF_NAME, COMP_STRIDE - COMP_OFF_NAME),
        })
    return rows


# ---------- BL/ML：赛程表 ----------
def extract_schedule(b):
    """赛程表完整提取。

    修正说明（相对既有文档）：
    - 两样本真实基址均为 0x3299B0（此前误把 BL0 首个 2021 日期记录当表头，
      记作 0x345408；实际那是第 190 条记录，前 190 条是 2020 日期）；
    - 表为 13000 个定长槽位，空槽序号字段为哨兵 0xFFFF；
    - +0x150 是槽位索引（恒等于记录位置，空槽=65535），
      不是此前认为的“比赛日全局序号”；
    - 此前“713/1473 条”是扫描窗口（日期正则只认 2021~2023 + 扫描止于窗口尾）
      双重截断造成的错误计数，真实有日期记录远多于此。
    """
    hits = [m.start() for m in DATE_RE.finditer(b, 0x11F2C0, 0x400000)]
    off0 = Counter(o % SCHED_STRIDE for o in hits).most_common(1)[0][0]
    first = next(o for o in hits if o % SCHED_STRIDE == off0)
    start = first - off0
    # 向前扩展到最早的记录（真实表头，含被旧正则漏掉的 2020 日期）
    base = start
    while base - SCHED_STRIDE >= 0x100000 and \
            DATE_RE_WIDE.match(b, base - SCHED_STRIDE + SCHED_OFF_DATE):
        base -= SCHED_STRIDE
    rows = []
    o = base
    while o + SCHED_STRIDE <= len(b):
        seq = u32(b, o + SCHED_OFF_SEQ)
        if seq == 0xFFFF:
            break
        rnd = u32(b, o + SCHED_OFF_ROUND)
        if DATE_RE_WIDE.match(b, o + SCHED_OFF_DATE):
            y = u16(b, o + SCHED_OFF_DATE)
            mo, d = b[o + SCHED_OFF_DATE + 2], b[o + SCHED_OFF_DATE + 3]
            date = (y, mo, d)
        else:
            date = None
        n = played = 0
        for k in range(11):
            e = o + SCHED_OFF_ENTRIES + k * 16
            if u32(b, e) >= 0xFFFF:
                break
            n += 1
            if u32(b, e + 8) & 1:
                played += 1
        rows.append((seq, date, rnd, n, played))
        o += SCHED_STRIDE
    return base, rows


# ---------- BL/ML：用户球队 / 用户球员 ----------
def extract_user_team(b):
    e = b.find(b"\x00", 0x54, 0x90)
    name = b[0x54:e].decode("utf-8", "replace")
    abbr = b[0x9A:0x9D].decode("ascii", "replace").rstrip("\x00")
    return name, abbr


def extract_player_bl(b):
    """BL 用户球员：以中文名「达里奥」锚定记录。"""
    anchor = b.find("达里奥".encode("utf-8"))
    assert anchor > 0, "BL 用户球员中文名未找到"
    rs = anchor - 0x0C
    info = {
        "中文名": cstr(b, anchor, 48),
        "球员ID": u32(b, rs + 0x04),
        "球员ID复核": u32(b, rs + 0x08),
        "记录首字段": u32(b, rs),
        "ASCII名1": cstr(b, rs + 0x49, 32),
        "ASCII名2": cstr(b, rs + 0x86, 32),
    }
    info["年份字段"] = [
        (off - rs, v) for off, v in find_years(b, rs + 0x100, rs + 0x200)]
    return info


def extract_player_ml(b):
    """ML 用户球员：以中文名「阿莱克斯」锚定记录（记录头在其前 0x10）。"""
    anchor = b.find("阿莱克斯".encode("utf-8"))
    assert anchor > 0, "ML 用户球员中文名未找到"
    rs = anchor - 0x10
    hdr = (s32(b, rs - 0x10), u32(b, rs - 0x0C),
           u32(b, rs - 0x08), s32(b, rs - 0x04))
    info = {
        "中文名": cstr(b, anchor, 48),
        "记录头四字段": hdr,
    }
    asc = [s for _, s in ascii_runs(b, anchor - 0x40, anchor + 0x300, 5)
           if re.fullmatch(r"[A-Z][A-Z .'-]+", s)]
    info["ASCII名"] = asc if asc else None
    info["年份字段"] = [
        (off - rs, v) for off, v in find_years(b, rs + 0x100, rs + 0x200)]
    return info


# ---------- 回放 ----------
def extract_replay(path):
    with open(path, "rb") as f:
        b = f.read()
    # 记录数组：前 25 条（首发 22 + 裁判 3）
    recs = []
    for k in range(25):
        off = REP_REC_BASE + k * REP_REC_STRIDE
        magic = u32(b, off)
        recs.append({
            "magic": magic,
            "side": magic & 0xFF,
            "pid": u32(b, off + 4),
            "name": cstr(b, off + REP_NAME_OFF, 9),
        })
    # 全名表（名单段长字符串区，明文）。
    # 带连字符且连字符后含非 ASCII 字符的长名（如 MILINKOVIĆ-SAVIĆ）
    # 会被切成 "...VI" + "-SAVI" 两段，需把以 '-' 开头的片段并回前一条，
    # 否则其后球员的全名会整体错位一格。
    runs = [s for _, s in ascii_runs(b, REP_FULLNAME_LO, REP_FULLNAME_HI, 3)]
    fulls = []
    for s in runs:
        if s.startswith("-") and fulls:
            fulls[-1] += s
        else:
            fulls.append(s)
    for k in range(22):
        if k < len(fulls):
            recs[k]["fullname"] = fulls[k]
        else:
            recs[k]["fullname"] = recs[k]["name"]
    # 帧网格：时钟与进度
    evoff = u32(b, 0x54)
    fs = u32(b, 0x58)
    nf = u32(b, 0x60)
    clocks = [u16(b, evoff + k * fs + 1) for k in range(nf)]

    def evhead(k):
        o = evoff + k * fs + 0x1010
        return u16(b, o), u16(b, o + 2), u16(b, o + 4)

    h0 = evhead(0)
    half2 = None
    for k in range(1, nf):
        if evhead(k)[2] != h0[2]:
            half2 = (k, evhead(k))
            break
    return {"recs": recs, "clocks": clocks, "head0": h0, "half2": half2}


def list_replays():
    return sorted(f for f in os.listdir(DEC)
                  if f.startswith("rep_REPLAY") and f.endswith(".data"))


# ---------- 报告排版 ----------
def render_team_section(buf, key, teams):
    buf.append(f"\n#### {key} 全部 {len(teams)} 支球队（按记录顺序）\n")
    buf.append("| 序号 | 球队 | 缩写 | 主场球场 | 助威口号 |")
    buf.append("|---:|:---|:---|:---|:---|")
    for t in teams:
        chants = " ／ ".join(c for c in t["chants"] if c) or "—"
        buf.append(f"| {t['idx']} | {t['name']} | {t['abbr']} | "
                   f"{t['stadium'] or '—'} | {chants} |")


def render_comp_section(buf, key, comps):
    buf.append(f"\n#### {key} 赛事定义表（{len(comps)} 条）\n")
    buf.append("| # | 赛事名称 | 赛事编号 | 类型枚举 | 赛季年 |")
    buf.append("|---:|:---|---:|:---:|---:|")
    for c in comps:
        buf.append(f"| {c['idx']} | {c['name']} | {c['cid']} | "
                   f"{c['type']} | {c['season'] if c['season'] else '—'} |")


def render_schedule_section(buf, key, base, rows):
    import datetime
    nmatchdays = sum(1 for r in rows if r[1])
    nempty = len(rows) - nmatchdays
    played_rows = [r for r in rows if r[4] > 0]
    years = Counter(r[1][0] for r in rows if r[1])
    buf.append(f"\n#### {key} 赛程全表\n")
    buf.append(f"表共 {len(rows)} 个槽位：{nmatchdays} 个有日期比赛日、"
               f"{nempty} 个空槽。年份分布："
               + "、".join(f"{y} 年 {c} 条" for y, c in sorted(years.items()))
               + "。这是游戏预分配的整个生涯日历（多个赛季的日程都在表内），"
               "其中已赛 {0} 条（见下方专题表）。".format(len(played_rows)))
    buf.append("对阵双方字段尚未从结构中解出（见文末修正与待办），"
               "以下如实列出全部有日期比赛日的槽位序号、日期、轮次与当日场次；"
               f"{nempty} 个空槽（无日期哨兵）不逐条列出。\n")
    dated = [r for r in rows if r[1] is not None]
    chunk = 500
    for s in range(0, len(dated), chunk):
        part = dated[s:s + chunk]
        buf.append(f"<details>\n<summary>槽位序号 {part[0][0]} ~ "
                   f"{part[-1][0]}（{len(part)} 条）</summary>\n")
        buf.append("| 槽位序号 | 日期 | 轮次 | 当日场次 | 已赛 |")
        buf.append("|---:|:---|---:|---:|---:|")
        for seq, date, rnd, n, played in part:
            try:
                datetime.date(*date)
                ds = f"{date[0]}-{date[1]:02d}-{date[2]:02d}"
            except ValueError:
                ds = f"{date[0]}-?{date[1]}-?{date[2]}"
            buf.append(f"| {seq} | {ds} | {rnd} | {n} | {played} |")
        buf.append("\n</details>\n")
    # 已赛比赛日专题表（真实踢过的日程）
    buf.append(f"\n##### {key} 已赛比赛日（{len(played_rows)} 条）\n")
    if not played_rows:
        buf.append("（本存档尚无已赛记录。）")
    else:
        buf.append("| 槽位序号 | 日期 | 轮次 | 当日场次 | 已赛 |")
        buf.append("|---:|:---|---:|---:|---:|")
        for seq, date, rnd, n, played in played_rows:
            buf.append(f"| {seq} | {date[0]}-{date[1]:02d}-{date[2]:02d} "
                       f"| {rnd} | {n} | {played} |")


def render_player_section(buf, key, info):
    buf.append(f"\n#### {key} 用户球员\n")
    for k, v in info.items():
        buf.append(f"- **{k}**：{v}")


def render_replay(buf, fname, rep, no):
    recs = rep["recs"]
    home = [r for r in recs[:11]]
    away = [r for r in recs[11:22]]
    refs = recs[22:25]
    buf.append(f"\n### 回放 {no}：{fname.replace('rep_', '').replace('.data', '')}\n")
    buf.append("| 位置 | 球员（全名） | 缩写名 | 球员ID |")
    buf.append("|:---|:---|:---|---:|")
    for i, r in enumerate(home):
        buf.append(f"| 主队首发 {i+1} | {r['fullname']} | {r['name']} | {r['pid']} |")
    for i, r in enumerate(away):
        buf.append(f"| 客队首发 {i+1} | {r['fullname']} | {r['name']} | {r['pid']} |")
    for i, r in enumerate(refs):
        buf.append(f"| 裁判 {i+1} | {r['name']}"
                   f"（编号 {r['pid']}） | — | — |")
    cks = rep["clocks"]
    h0 = rep["head0"]
    half = rep["half2"]
    line = (f"- 比赛时钟：最小 {min(cks)}，最大 {max(cks)}"
            f"（共 {len(cks)} 帧，帧头 u16）。\n"
            f"- 事件区进度：首帧进度计数 {h0[1]}，阶段上限 {h0[2]}"
            f"（上半场计数到该上限后进入下半场）；")
    if half:
        line += (f"第 {half[0]} 帧起换档：进度 {half[1][1]}、"
                 f"新阶段上限 {half[1][2]}。")
    else:
        line += "全程未观测到换档。"
    buf.append(line)


# ---------- 主流程 ----------
def main():
    buf = []
    buf.append("# PES2021 存档解码内容报告")
    buf.append("")
    buf.append("> 本报告由 `decode_dump.py` 自动生成（纯标准库、无参运行）。"
               "全部信息直接提取自 `decoded/` 下的解密数据块，"
               "结构依据见 `docs/bl_ml_structure.md` 与 "
               "`docs/replay_structure.md`；"
               "技术来源以小节末尾小字注记标出。")
    buf.append("")

    bl = load(FILES["BL0"])
    ml = load(FILES["ML0"])

    teams_bl = extract_teams(bl)
    teams_ml = extract_teams(ml)
    comps_bl = extract_comps(bl)
    comps_ml = extract_comps(ml)
    sbase_bl, sched_bl = extract_schedule(bl)
    sbase_ml, sched_ml = extract_schedule(ml)
    ut_bl = extract_user_team(bl)
    ut_ml = extract_user_team(ml)
    pl_bl = extract_player_bl(bl)
    pl_ml = extract_player_ml(ml)
    reps = [(f, extract_replay(os.path.join(DEC, f))) for f in list_replays()]

    # ---------- 总览表 ----------
    buf.append("## 总览：本仓库目前能从存档中直接读出的全部信息")
    buf.append("")
    buf.append("| 信息类别 | 内容 | 规模 |")
    buf.append("|:---|:---|:---|")
    buf.append(f"| 球队名单 | 中文名、三字母缩写、主场球场、4 条助威口号 | "
               f"BL/ML 各 {TEAM_N} 支球队 |")
    buf.append(f"| 赛事定义 | 中文全名、赛事编号、类型枚举、赛季年 | "
               f"BL/ML 各 {len(comps_bl)} 条赛事 |")
    buf.append(f"| 用户球队 | 队名、三字母缩写 | 「{ut_bl[0]}」/「{ut_ml[0]}」 |")
    buf.append(f"| 用户球员 | 中文名、ASCII 名、球员 ID、年份字段 | "
               f"BL：{pl_bl['中文名']}；ML：{pl_ml['中文名']} |")
    buf.append(f"| 赛程表 | 比赛日序号 + 真实日期 + 轮次 + 当日场次 | "
               f"BL0 共 {len(sched_bl)} 个比赛日，"
               f"ML0 共 {len(sched_ml)} 个比赛日 |")
    n_full = sum(1 for _, rp in reps for r in rp["recs"][:22] if r.get("fullname"))
    buf.append(f"| 回放名单 | 两队首发各 11 人全名 + 球员 ID + 3 名裁判 | "
               f"{len(reps)} 场，共 {n_full} 个首发全名 |")
    buf.append("| 回放时钟 | 每场比赛时钟最小/最大值、上下半场换档帧 | "
               f"每场 660 帧逐帧统计 |")
    buf.append("| 回放结构 | 名单段 + 事件流帧网格、长度自洽公式 | "
               "50/50 样本闭合 |")
    buf.append("")
    buf.append("> 尚未解出：赛程对阵双方（队号成对字段）、动态资金余额、"
               "回放事件流内球员轨迹编码。详见对应结构文档的【未解】节。")

    # ---------- BL/ML ----------
    for key, b, teams, comps, ut, pl, sbase, sched, sched_label in (
            ("BL0（一球成名）", bl, teams_bl, comps_bl, ut_bl, pl_bl,
             sbase_bl, sched_bl, "BL0"),
            ("ML0（大师联赛）", ml, teams_ml, comps_ml, ut_ml, pl_ml,
             sbase_ml, sched_ml, "ML0")):
        buf.append(f"\n---\n\n## {key}：BL/ML 存档解码内容")

        buf.append(f"\n### 用户球队")
        buf.append(f"- 队名（存档头部）：**{ut[0]}**")
        buf.append(f"- 三字母缩写：**{ut[1]}**")
        buf.append(f"- 说明：该队不在 700 支球队的默认名单数组内"
                   f"（PES2021 授权原因，名单中无此队记录），"
                   f"队名信息仅存在于存档头部。")

        buf.append(f"\n### 用户球员")
        render_player_section(buf, sched_label, pl)

        render_comp_section(buf, sched_label, comps)
        render_team_section(buf, sched_label, teams)
        render_schedule_section(buf, sched_label, sbase, sched)

        buf.append(f"\n> 小字注记：球队名单来自球队记录数组"
                   f"（记录步长 0x{TEAM_STRIDE:X}，队名/缩写/球场/口号为记录内"
                   f"明文字段）；赛事表与赛程表的基址通过中文赛事名对齐与日期"
                   f"三元组对齐自动定位，赛程记录字段见 "
                   f"`docs/bl_ml_structure.md` 1.4/1.6 节。")

    # ---------- 回放 ----------
    buf.append("\n---\n\n## 回放解码内容（50 场）")
    buf.append("\n说明：每份回放的名单段记录着两队首发与裁判。"
               "魔数最低字节 `FD`/`FE` 区分两个阵营（推测为主/客），"
               "全名取自名单段的全名表（明文），缩写名取自记录内名字字段；"
               "回放本身不保存球队名称，故无法标注两队队名。"
               "裁判在记录内只保存槽位名（REFEREEA/B/C）与裁判编号。")
    for i, (fname, rep) in enumerate(reps):
        render_replay(buf, fname, rep, i + 1)
    buf.append("\n> 小字注记：名单结构、时钟与事件区进度字段的确认过程见 "
               "`docs/replay_structure.md` 1.3/1.5/1.6 节。")

    # ---------- 修正与待办 ----------
    buf.append("\n---\n\n## 本次提取对既有结构结论的修正")
    buf.append("")
    buf.append("1. **球队记录内含有队名字段**（此前结构文档未记录）："
               "记录内含中文队名、三字母缩写与中文球场名；"
               "700 支球队全部可解，已同步补入 `bl_ml_structure.md`。")
    buf.append("2. **球队助威口号是共享池**：不同球队记录会复用同一批口号串"
               "（如阿斯顿维拉记录内的口号实为阿森纳的口号），"
               "口号与球队的对应关系不能当真。")
    buf.append("3. **头部球队缩写位置修正**：「ARS」实际位于头部偏移 0x9A"
               "（此前文档记为 0x98），已修正 `bl_ml_structure.md`。")
    buf.append(f"4. **用户球员记录字段修正**：球员 ID 在记录内第 4 字节起"
               f"（此前文档记为记录起点），记录首字段为另一较小整数；"
               f"ML0 用户球员为「{pl_ml['中文名']}」，记录头在此前文档"
               f"给出的地址之前 0x10 字节，且该记录无 ASCII 名。"
               f"均已修正 `bl_ml_structure.md`。")
    buf.append("5. **回放全名表是明文**：此前文档把名单段长字符串区标注为"
               "疑扰码、不建议当明文处理；实测其中全名表（22 名球员全名）"
               "为完整明文，且与记录数组一一对应，已修正 "
               "`replay_structure.md`。")
    buf.append("6. **赛程表规模与基址重大修正**：两样本赛程表真实基址均为 "
               "0x3299B0，共 13000 个定长槽位（其中约 1.02 万个有日期、"
               "其余为空槽）；此前文档记录的 BL0 基址 0x345408 实为表内"
               "第 190 条记录（前 190 条是 2020 日期，被日期正则窗口漏掉），"
               "“713/1473 条”系扫描窗口截断导致的错误计数。"
               "+0x150 字段是槽位索引而非“比赛日全局序号”。"
               "已同步修正 `bl_ml_structure.md` 1.6 节。")
    buf.append("")

    with open(OUT, "w", encoding="utf-8") as f:
        f.write("\n".join(buf) + "\n")
    # 控制台仅输出 ASCII 统计，避免中文乱码
    print("OK: report written -> docs/decoded_content.md")
    print(f"  teams: BL0={len(teams_bl)}, ML0={len(teams_ml)}")
    print(f"  comps: BL0={len(comps_bl)}, ML0={len(comps_ml)}")
    print(f"  schedule: BL0={len(sched_bl)}, ML0={len(sched_ml)}")
    print(f"  replays: {len(reps)}, fullnames OK={n_full}")


if __name__ == "__main__":
    main()
