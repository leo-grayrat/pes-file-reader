#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""edit_player_abilities.py -- 解码 EDIT 球员 240B 条目里的「能力值 + 隐藏机制」。

字段布局来源：implyingrigged.info/wiki/Pro_Evolution_Soccer_2021/Edit_file
（Player data entry，240B，能力值自 0x0E 起按 7-bit 位打包，LSB-first）。

这版把工具从「复读 EDIT 结构」升级为「读出真正影响玩法的数据」：
  - 25 项能力值（[40,99]）：进攻/防守/速度/体能/GK 全套
  - 隐藏机制：年龄、注册位置、比赛风格、惯用脚、逆足使用/精度、受伤抵抗、
    COM 比赛风格(7-bit 位掩码)、球员技能(41-bit 位掩码)、可踢位置(A/B/C)
验证：全部能力值必须落在 [40,99]；GK 位置球员的 GK 属性应偏高。

产物：outputs/edit_player_abilities.csv（全量 27513 行）
用法：python edit_player_abilities.py
"""
import os, csv, struct

BASE = os.path.dirname(os.path.abspath(__file__))
DEC = os.path.join(BASE, "decoded")
EDIT = os.path.join(DEC, "EDIT00000000.data")
OUT = os.path.join(BASE, "outputs", "edit_player_abilities.csv")

PLAYER_BASE = 0x7C
PLAYER_STRIDE = 312
PLAYER_DATA = 240

def u32(b, o): return struct.unpack_from("<I", b, o)[0]

def rf(entry, byte, bit, length):
    """LSB-first 读 length 位（跨字节）。"""
    start = byte * 8 + bit
    val = 0
    for i in range(length):
        src = start + i
        if (entry[src >> 3] >> (src & 7)) & 1:
            val |= (1 << i)
    return val

# 25 项能力值（7-bit, [40,99]）
ABILITIES = [
    ("offensive_awareness", 0x0E, 0, 7),
    ("ball_control", 0x0E, 7, 7),
    ("tight_possession", 0x10, 0, 7),
    ("low_pass", 0x10, 7, 7),
    ("lofted_pass", 0x11, 6, 7),
    ("finishing", 0x12, 5, 7),
    ("place_kicking", 0x14, 0, 7),
    ("curl", 0x14, 7, 7),
    ("speed", 0x15, 6, 7),
    ("acceleration", 0x16, 5, 7),
    ("jump", 0x18, 0, 7),
    ("physical_contact", 0x18, 7, 7),
    ("balance", 0x19, 6, 7),
    ("stamina", 0x1A, 5, 7),
    ("ball_winning", 0x1C, 0, 7),
    ("aggression", 0x1C, 7, 7),
    ("gk_awareness", 0x1D, 6, 7),
    ("gk_catching", 0x1E, 5, 7),
    ("gk_reach", 0x20, 0, 7),
    ("defensive_awareness", 0x24, 0, 7),
    ("gk_clearing", 0x24, 7, 7),
    ("heading", 0x25, 6, 7),
    ("dribbling", 0x28, 0, 7),
    ("gk_reflexes", 0x2C, 6, 7),
    ("kicking_power", 0x2D, 5, 7),
]

POSITIONS = ["GK", "CB", "LB", "RB", "DMF", "CMF", "LMF", "RMF",
             "AMF", "LWF", "RWF", "SS", "CF"]
PLAY_STYLES = ["None", "Goal Poacher", "Dummy Runner", "Fox in the Box", "Target Man",
               "Creative Playmaker", "Prolific Winger", "Roaming Flank", "Cross Specialist",
               "Classic No. 10", "Hole Player", "Box-to-Box", "The Destroyer", "Orchestrator",
               "Anchor Man", "Offensive Full-back", "Full-back Finisher", "Defensive Full-back",
               "Build Up", "Extra Frontman", "Offensive Goalkeeper", "Defensive Goalkeeper"]
SKILLS = ["Scissors Feint", "Double Touch", "Flip Flap", "Marseille Turn", "Sombrero",
          "Cross Over Turn", "Cut Behind & Turn", "Scotch Move", "Step On Skill Control",
          "Heading", "Long Range Drive", "Chip Shot Control", "Long Range Shooting",
          "Knuckle Shot", "Dipping Shots", "Rising Shots", "Acrobatic Finishing", "Heel Trick",
          "First-time Shot", "One-touch Pass", "Through Passing", "Weighted Pass",
          "Pinpoint Crossing", "Outside Curler", "Rabona", "No Look Pass", "Low Lofted Pass",
          "GK Low Punt", "GK High Punt", "Long Throw", "GK Long Throw", "Penalty Specialist",
          "GK Penalty Saver", "Gamesmanship", "Man Marking", "Track Back", "Interception",
          "Acrobatic Clear", "Captaincy", "Super-sub", "Fighting Spirit"]
COM_STYLES = ["Trickster", "Mazing Run", "Speeding Bullet", "Incisive Run", "Long Ball Expert",
              "Early Cross", "Long Ranger"]

def decode_entry(entry):
    d = {}
    for nm, by, bt, ln in ABILITIES:
        d[nm] = rf(entry, by, bt, ln)
    d["age"] = rf(entry, 0x20, 7, 6)
    d["reg_pos"] = rf(entry, 0x21, 5, 4)
    d["play_style"] = rf(entry, 0x22, 2, 5)
    d["weak_foot_usage"] = rf(entry, 0x0F, 6, 2) + 1
    d["weak_foot_accuracy"] = rf(entry, 0x27, 6, 2) + 1
    d["injury_resistance"] = rf(entry, 0x28, 7, 2) + 1
    d["conditioning"] = rf(entry, 0x1F, 4, 3) + 1
    d["stronger_foot"] = "Left" if rf(entry, 0x2F, 5, 1) else "Right"
    d["star_rating"] = rf(entry, 0x23, 4, 3)
    # 可踢位置（13 个，A/B/C）：9 个在 0x29:5(18bit) + 3 个在 0x2C:0(6bit) + 1 个在 0x2E:4(2bit)
    pp = []
    v1 = rf(entry, 0x29, 5, 18)
    v2 = rf(entry, 0x2C, 0, 6)
    v3 = rf(entry, 0x2E, 4, 2)
    for i in range(9):
        pp.append(v1 >> (i * 2) & 3)
    for i in range(3):
        pp.append(v2 >> (i * 2) & 3)
    pp.append(v3 & 3)
    d["playable"] = "".join(str(x) for x in pp)  # 长度13串，0=C,1=B,2=A
    # 球员技能 41-bit 位掩码
    sk = rf(entry, 0x30, 6, 41)
    d["skills"] = ";".join(SKILLS[i] for i in range(41) if (sk >> i) & 1)
    # COM 比赛风格 7-bit 位掩码
    com = rf(entry, 0x2F, 7, 7)
    d["com_styles"] = ";".join(COM_STYLES[i] for i in range(7) if (com >> i) & 1)
    # 名字
    e = entry[0x36:0x36 + 61].find(b"\x00")
    d["name"] = entry[0x36:0x36 + (e if e >= 0 else 61)].decode("utf-8", "replace")
    d["pid"] = u32(entry, 0)
    d["nat"] = struct.unpack_from("<H", entry, 0x08)[0]
    return d

def main():
    b = open(EDIT, "rb").read()
    n = u32(b, 0x60)
    rows = []
    # 验证统计
    abil_min, abil_max = {a[0]: 127 for a in ABILITIES}, {a[0]: 0 for a in ABILITIES}
    gk_rows = []
    for i in range(n):
        off = PLAYER_BASE + i * PLAYER_STRIDE
        pid = u32(b, off)
        if pid == 0 or pid == 0xFFFFFFFF:
            continue
        entry = b[off:off + PLAYER_DATA]
        d = decode_entry(entry)
        rows.append(d)
        for nm, _, _, _ in ABILITIES:
            v = d[nm]
            if v < abil_min[nm]: abil_min[nm] = v
            if v > abil_max[nm]: abil_max[nm] = v
        if d["reg_pos"] == 0 and len(gk_rows) < 3:
            gk_rows.append(d)

    # 验证输出
    print(f"解码球员数: {len(rows)}")
    print("能力值范围校验（应全部落在 [40,99]）:")
    bad = [nm for nm in abil_min if abil_min[nm] < 40 or abil_max[nm] > 99]
    for nm in abil_min:
        print(f"  {nm:20s} min={abil_min[nm]:3d} max={abil_max[nm]:3d}")
    print("超出 [40,99] 的能力值:", bad if bad else "无 ✓")
    print("\nGK 位置样本（GK 属性应偏高）:")
    for d in gk_rows:
        print(f"  {d['name']!r:24} GKAware={d['gk_awareness']} GKCatch={d['gk_catching']} "
              f"GKReach={d['gk_reach']} GKReflex={d['gk_reflexes']} Age={d['age']}")

    # 全量 CSV
    cols = (["pid", "name", "nat", "age", "reg_pos", "play_style", "stronger_foot",
             "weak_foot_usage", "weak_foot_accuracy", "injury_resistance", "conditioning",
             "star_rating", "playable", "com_styles", "skills"]
            + [a[0] for a in ABILITIES])
    with open(OUT, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(cols)
        for d in rows:
            w.writerow([d.get(c, "") for c in cols])
    print(f"\n全量能力值已写入 {OUT}（{len(rows)} 行）")

if __name__ == "__main__":
    main()
