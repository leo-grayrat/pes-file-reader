"""PES 2021 总评(Overall)估算 —— 位置加权算法（非负权重 + 熟练度乘子）。

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

建模约束（2026-08-30 用户反馈 + PES 游戏机制，已落实）：
- **只看注册位置(reg_pos)**：总评按球员的注册位置现算，不混入 PES master 界面上
  同球员 13 个位置的独立总评。不同位置总评不同，反映的是"角色契合度"，位置加权结构即此机制。
- **OVR 是能力的非负加权和**：任何能力值增强，总评必增，不存在负相关项（用户明确）。
  因此权重全部 ≥ 0、权重和 = 1；本模块采用社区已文档化的非负权重，绝不做会产出
  负权重/角点解的纯数据拟合（见下方「为什么不做 NNLS 反推」）。
- **身高是总评线性式的直接因子（用户明确，2026-08-30 末轮纠正）**：身高属"身体数据"，
  与 25 项"能力数据"在游戏里是**各自独立键入**的两个输入（矮门将可有高弹跳、高门将可有低
  弹跳，互不因果）——但两者**平级地直接参与同一个线性求和**算出总评。身高不是"经子项间接
  影响"，也不是"经验相关"，它就是加权式里的一个直接项（见 HEIGHT_WEIGHT，与 OVERALL_WEIGHTS
  并列、作为加权平均里的另一项）。系数 HEIGHT_WEIGHT 无法从 PES master 数据反推（默认库里
  身高与跳起/头球/身体接触高度共线，这些子项已带权重，身高的独立贡献被吸收）；真实值请按
  游戏内部系数填入（见 HEIGHT_WEIGHT 注释）。
- **GK = 门将五项 + 跳起**：门将总评主要和门将五项(gk_*)及跳起有关，与余者关系很小
  （见 OVERALL_WEIGHTS["GK"]，jump 取 0.06、门将五项整体缩至 0.94）。
- **A/B/C 熟练度乘子**：存档已解出每个球员 13 个位置的熟练度（playable，0=C/1=B/2=A）。
  注册位置的熟练度作为 ≤1 乘子作用于总评——低熟练度降低该位置评分（用户明确）。
  乘子值见 FAMILIARITY_FACTOR（精确 Konami 罚分未公开，社区近似占位）。
  注意：本工具仅算"注册位置"总评；若某球员被放到非注册位置，其 OVR 应按该位置熟练度
  重新计算（当前 UI 只展示注册位置，符合 PES master 主总评语义）。

为什么不做 NNLS 反推精确权重（2026-08-30 复盘）：
- 曾采集 273 名 PES master 真实球员(compare?id=<pid>)做岭回归/NNLS，结果塌成非物理角点
  （DEF 的 low_pass 权重 0.58、GK 的 gk_clearing 0.92、FWD 的 heading 0.14）——其"更低 MAE"
  是 25 项能力值在数据上高度共线、纯数据拟合吸相关性所致，不是真公式。
- 用户明确指出：游戏里能力值是任意赋的、身体与能力数据独立，所谓"共线"是现实世界数据
  碰巧相关，并非游戏机制。故真公式就是"非负加权 + 熟练度乘子"，直接采用社区文档化的
  非负权重，不再把退化的拟合权重接进代码。真公式 = 非负位置加权 + 身高直接因子 + 熟练度乘子。

实证验证（同上 273 名样本，按注册位置组对照 PES master 真实总评）：
- 本模块权重与 PES master 真实总评的平均绝对误差(MAE): FWD≈3.8 / MID≈3.7 /
  DEF≈4.1 / GK≈7.3（GK 样本少、波动大）。残差主要来自：① 本存档是自定义/修改库，
  与 PES master 默认库数值不同；② 熟练度罚分/同侧对称等动态机制近似。
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
    # GK: 门将五项 + 跳起(依据游戏机制: 门将主要和门将五项及跳起有关, 与余者关系很小)。
    # jump 取 0.06, 门将五项整体按 0.94 缩放, 权重和=1。
    "GK": [("gk_awareness", 0.235), ("gk_catching", 0.188), ("gk_reflexes", 0.235),
           ("gk_reach", 0.188), ("gk_clearing", 0.094), ("jump", 0.060)],
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

# 注册位置熟练度乘子：2=A(满,不罚分) / 1=B / 0=C(低熟练度降分)。
# 精确 Konami 罚分未公开，此处为社区近似占位值；若你有准确罚分可在此替换。
FAMILIARITY_FACTOR = {2: 1.0, 1: 0.96, 0: 0.92}

# 身高对总评的直接线性系数(对 raw cm)。身高是总评加权式里与 25 项能力值**并列**的直接因子
# (用户明确 2026-08-30 末轮: 非间接、非因果于子项, 直接参与同一个线性求和)。
# 实现: 与能力值同一加权平均 —— num += HEIGHT_WEIGHT * height_cm; den += HEIGHT_WEIGHT。
# 数值无法从 PES master 数据反推: 默认库里身高与 jump/heading/physical_contact/gk_reach 高度
# 共线, 这些子项已带权重, 身高的独立贡献被吸收(单参数 W_H 拟合恒=0.0000)。
# => 请填入真实 Konami 系数(或按游戏内部身高表示方式的换算值)。当前 0.0 = 待填(惰性, 填>0 即生效)。
HEIGHT_WEIGHT = 0.0


def compute_overall(stats, reg_pos, fam=None, height_cm=None):
    """计算位置加权总评。

    stats: dict，键为能力值字段名(snake_case)，值为 int；缺失按 FLOOR。
    reg_pos: int 0-12（注册位置码）。
    fam: 注册位置熟练度 0=C/1=B/2=A（可选，默认按 A=不罚分）。
    height_cm: 身高(cm)，可选；作为总评线性式的直接因子参与(见 HEIGHT_WEIGHT)。
    返回: int，钳制在 [FLOOR, CEIL]。

    公式: OVR = 钳制( round( (Σ(w_i·ability_i) + W_H·height) / (Σw_i + W_H) × FAM[fam] ) )
    权重 w_i 全部 ≥ 0（任意能力增强 → 总评必增）；身高项 W_H≥0 同理；熟练度乘子 ≤ 1。
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
    if height_cm is not None and HEIGHT_WEIGHT > 0:
        s += HEIGHT_WEIGHT * float(height_cm)
        w += HEIGHT_WEIGHT
    val = s / max(w, 1e-9)
    if fam is not None:
        val *= FAMILIARITY_FACTOR.get(int(fam), 1.0)
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
