"""PES 2021 总评(Overall)估算 —— 位置加权算法。

重要事实（来自逆向与社区资料）：
- 实况存档（EDIT 240B）**不存储**总评。权威字段表 implyingrigged.info 仅列出 25 项
  能力值（7-bit 打包 @0x0E，范围 [40,99]）；社区编辑器 Devil Cold52 自述
  "Overall Degrees Not Calculated Correctly. Therefore I use my own formula" ——
  说明总评由游戏按位置加权**现算**，且精确 Konami 权重从未公开，各工具均为近似。
- PES master 球员界面证实：总评随位置变化（同球员 Ronaldo CF=95 / RWF=87 / LMF=85），
  即「按位置加权」的结构正确。

本模块采用社区已文档化的位置加权权重（来源：
github.com/andinoferdi/efootball-pes2021-stats-converter 的 compute_pes_overall，
其自注为 "estimator, not Konami's internal formula"）。

能力值下限统一按 40 处理（implyingrigged.info 字段表确认范围 [40,99]）。

实证验证（2026-08-30，采集 PES master 真实球员页 compare?id=<pid> 共 273 名，
按位置组对照其真实总评）：
- 本模块权重与 PES master 真实总评的平均绝对误差(MAE): FWD≈3.8 / MID≈3.7 /
  DEF≈4.1 / GK≈7.3（GK 样本少、波动大）。
- 曾尝试用 NNLS 回归反推精确权重：因 25 项能力值高度共线、GK 仅 23 样本，
  纯数据拟合会塌成非物理角点解（如 DEF 的 low_pass 权重 0.58、GK 的 gk_clearing
  权重 0.92），属"吸相关性"而非真公式。故保留文档化近似，不接退化的拟合权重。
- 结论：Konami 精确总评权重从未公开，任何工具均为近似；本模块为忠实参考
  PES master 位置加权结构的最佳可用近似，UI 中已如实标注。
"""

# reg_pos 数字码 -> 位置名（与 edit_player_abilities.py 的 REG_POS_NAMES 对应）
REG_POS = {0: "GK", 1: "CB", 2: "LB", 3: "RB", 4: "DMF", 5: "CMF",
           6: "LMF", 7: "RMF", 8: "AMF", 9: "LWF", 10: "RWF", 11: "SS", 12: "CF"}

# reg_pos -> 位置组（权重按组复用）
POS_GROUP = {0: "GK", 1: "DEF", 2: "DEF", 3: "DEF",
             4: "MID", 5: "MID", 6: "MID", 7: "MID", 8: "MID",
             9: "FWD", 10: "FWD", 11: "FWD", 12: "FWD"}

# 各位置组权重（加权平均值，权重和=1）。字段名与 edit_player_abilities.csv 列名一致。
OVERALL_WEIGHTS = {
    "GK": [("gk_awareness", 0.25), ("gk_catching", 0.20), ("gk_reflexes", 0.25),
           ("gk_reach", 0.20), ("gk_clearing", 0.10)],
    "DEF": [("defensive_awareness", 0.23), ("ball_winning", 0.22), ("aggression", 0.10),
            ("speed", 0.10), ("physical_contact", 0.12), ("heading", 0.08),
            ("jump", 0.07), ("low_pass", 0.08)],
    "MID": [("ball_control", 0.12), ("dribbling", 0.10), ("tight_possession", 0.10),
            ("low_pass", 0.18), ("lofted_pass", 0.14), ("offensive_awareness", 0.08),
            ("speed", 0.08), ("acceleration", 0.06), ("stamina", 0.10), ("curl", 0.04)],
    "FWD": [("offensive_awareness", 0.18), ("finishing", 0.18), ("ball_control", 0.10),
            ("dribbling", 0.08), ("speed", 0.10), ("acceleration", 0.10),
            ("kicking_power", 0.10), ("physical_contact", 0.08), ("heading", 0.04),
            ("jump", 0.04)],
}

FLOOR = 40
CEIL = 99


def compute_overall(stats, reg_pos):
    """计算位置加权总评。

    stats: dict，键为能力值字段名(snake_case)，值为 int；缺失按 FLOOR。
    reg_pos: int 0-12（注册位置码）。
    返回: int，钳制在 [FLOOR, CEIL]。
    """
    g = POS_GROUP.get(int(reg_pos), "MID")
    s = w = 0.0
    for k, ww in OVERALL_WEIGHTS[g]:
        try:
            v = int(stats.get(k, FLOOR))
        except (TypeError, ValueError):
            v = FLOOR
        s += v * ww
        w += ww
    val = s / max(w, 1e-9)
    return max(FLOOR, min(CEIL, round(val)))


def position_name(reg_pos):
    return REG_POS.get(int(reg_pos), "?")


def _self_test():
    """用解出的真实巨星数据自测（仅打印，不影响导入）。"""
    import csv
    try:
        rows = {r["pid"]: r for r in csv.DictReader(open("outputs/edit_player_abilities.csv", encoding="utf-8"))}
    except FileNotFoundError:
        return
    # 参考总评取自 PES master（默认库，按注册位置）
    ref = {"7511": (93, "梅西RWF"), "4522": (93, "C罗LWF"), "33185": (89, "诺伊尔GK"),
           "40002": (92, "莱万CF"), "44379": (92, "德布劳内AMF"), "110718": (91, "姆巴佩CF"),
           "40352": (91, "内马尔LWF"), "44840": (87, "范戴克CB")}
    print("位置加权总评自测（公式 vs PES master 参考，差值因本存档为自定义库且权重为社区近似）:")
    for pid, (rov, who) in ref.items():
        if pid not in rows:
            continue
        r = rows[pid]
        stats = {}
        for grp in OVERALL_WEIGHTS.values():
            for k, _ in grp:
                if k in r:
                    stats[k] = int(r[k])
        c = compute_overall(stats, int(r["reg_pos"]))
        print(f"  {who:12s} 公式={c:3d}  PESmaster={rov:3d}  差={c - rov:+d}")


if __name__ == "__main__":
    _self_test()
