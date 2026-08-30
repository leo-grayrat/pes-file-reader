#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""用 PES master 真实样本, 按位置组反推总评权重。

模型: overall = sum_i w_i * stat_i, 约束 w_i >= 0 且 sum w_i = 1  (非负加权平均值)
求解: 单纯形投影梯度下降 (NNLS on simplex). 纯 Python, 无第三方依赖。
PES 真实权重必为非负 —— 之前无约束 LS 因 25 项共线产生正负相消、权重和≈0、归一化后爆炸,
本实现用非负+和为1约束彻底避免。
"""
import csv, os, math, random
from collections import defaultdict

BASE = os.path.dirname(os.path.abspath(__file__))
REF = os.path.join(BASE, "outputs", "pesmaster_reference.csv")

ABIL_ORDER = ["offensive_awareness", "ball_control", "tight_possession", "low_pass",
              "lofted_pass", "finishing", "place_kicking", "curl", "speed", "acceleration",
              "jump", "physical_contact", "balance", "stamina", "ball_winning", "aggression",
              "gk_awareness", "gk_catching", "gk_reach", "defensive_awareness", "gk_clearing",
              "heading", "dribbling", "gk_reflexes", "kicking_power"]

POS_GROUP = {0: "GK", 1: "DEF", 2: "DEF", 3: "DEF",
             4: "MID", 5: "MID", 6: "MID", 7: "MID", 8: "MID",
             9: "FWD", 10: "FWD", 11: "FWD", 12: "FWD"}

DOC_WEIGHTS = {
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


def mat_T(A):
    return [[A[j][i] for j in range(len(A))] for i in range(len(A[0]))] if A and A[0] else []


def mat_mul(A, B):
    return [[sum(A[i][t] * B[t][j] for t in range(len(B))) for j in range(len(B[0]))] for i in range(len(A))]


def mat_vec(A, v):
    return [sum(A[i][t] * v[t] for t in range(len(v))) for i in range(len(A))]


def proj_simplex(v):
    n = len(v)
    u = sorted(v, reverse=True)
    css = 0.0
    rho = 0
    for i in range(1, n + 1):
        css += u[i - 1]
        if u[i - 1] - (css - 1.0) / i > 0:
            rho = i
    theta = (sum(u[:rho]) - 1.0) / rho if rho > 0 else 0.0
    return [max(0.0, x - theta) for x in v]


def max_eig(XtX, iters=80):
    n = len(XtX)
    v = [random.random() for _ in range(n)]
    norm = math.sqrt(sum(x * x for x in v)) or 1.0
    v = [x / norm for x in v]
    for _ in range(iters):
        v = mat_vec(XtX, v)
        norm = math.sqrt(sum(x * x for x in v)) or 1.0
        if norm == 0:
            break
        v = [x / norm for x in v]
    Xv = mat_vec(XtX, v)
    return sum(Xv[i] * v[i] for i in range(n)) / (sum(v[i] * v[i] for i in range(n)) or 1.0)


def nnls_simplex(X, y, w0=None, lam=0.0, iters=4000):
    """非负+和为1 的投影梯度下降。
    若给定 w0 与 lam>0, 加先验项 lam*||w-w0||^2 (anchored refinement, 保持权重合理不塌角点)。"""
    n = len(y)
    p = len(X[0])
    Xt = mat_T(X)
    XtX = mat_mul(Xt, X)
    Xty = mat_vec(Xt, y)
    L = max_eig(XtX) * 1.05 + lam + 1e-6
    lr = 1.0 / L
    w = list(w0) if w0 else [1.0 / p] * p
    for _ in range(iters):
        g = [2.0 * (sum(XtX[i][t] * w[t] for t in range(p)) - Xty[i]) for i in range(p)]
        if lam:
            g = [g[i] + 2.0 * lam * (w[i] - (w0[i] if w0 else 0.0)) for i in range(p)]
        w = proj_simplex([w[i] - lr * g[i] for i in range(p)])
    return w


def mae_of(w, X, y):
    return sum(abs(sum(w[t] * X[i][t] for t in range(len(w))) - y[i]) for i in range(len(y))) / len(y)


# 各组活跃特征列(下标): 采用社区已确证的"每组相关能力值集合"作为特征,
# 再用 NNLS 在 PES master 真实样本上精调系数 —— 既避免常量列退化/怪异扩散, 又用数据校准权重.
# 约束(依据用户提醒 + PES 机制):
#  - 只看注册位置(reg_pos): 下方按 reg_pos 归组, 不混入 PES master 的 13 位置总评.
#  - GK 主要和门将五项 + 跳起有关, 与余者关系很小 -> GK 活跃特征 = GK5 + jump.
#  - 身高/体重: 不直接进入总评加权公式, 其影响已通过 jump/heading/physical_contact 等
#    身体子项体现(见 height_analysis); 故不列为独立特征, 避免与身体子项共线重复计数.
def _idx(names):
    return [ABIL_ORDER.index(k) for k in names]
GK_IDX = _idx(["gk_awareness", "gk_catching", "gk_reach", "gk_clearing", "gk_reflexes", "jump"])
FWD_IDX = _idx(["offensive_awareness", "finishing", "ball_control", "dribbling", "speed",
                "acceleration", "kicking_power", "physical_contact", "heading", "jump"])
MID_IDX = _idx(["ball_control", "dribbling", "tight_possession", "low_pass", "lofted_pass",
                "offensive_awareness", "speed", "acceleration", "stamina", "curl"])
DEF_IDX = _idx(["defensive_awareness", "ball_winning", "aggression", "speed", "physical_contact",
                "heading", "jump", "low_pass"])
ACTIVE = {"GK": GK_IDX, "FWD": FWD_IDX, "MID": MID_IDX, "DEF": DEF_IDX}


def main():
    rows = list(csv.DictReader(open(REF, encoding="utf-8")))
    groups = defaultdict(list)
    for r in rows:
        try:
            rp = int(r["reg_pos"]); ov = int(r["overall"])
        except (KeyError, ValueError):
            continue
        vec = []
        ok = True
        for k in ABIL_ORDER:
            v = r.get(k, "")
            if v in ("", None):
                ok = False; break
            vec.append(int(v))
        if ok:
            groups[POS_GROUP.get(rp, "MID")].append((vec, ov))

    print("样本按组: " + ", ".join("%s=%d" % (g, len(v)) for g, v in groups.items()))
    new_weights = {}
    for g, data in groups.items():
        idx = ACTIVE[g]
        Xall = [v for v, _ in data]
        yall = [o for _, o in data]
        X = [[vec[i] for i in idx] for vec in Xall]
        # 文档化先验 w0 (在活跃特征上归一化)
        dw = dict(DOC_WEIGHTS[g]); dnorm = sum(dw.values()) or 1.0
        w0 = [dw.get(ABIL_ORDER[idx[t]], 0.0) / dnorm for t in range(len(idx))]
        s0 = sum(w0) or 1.0
        w0 = [x / s0 for x in w0]
        # 扫描 lambda, 选 MAE 最小
        best_w, best_lam, best_mae = None, None, 1e9
        for lam in (0.3, 1.0, 3.0, 10.0, 30.0):
            w = nnls_simplex(X, yall, w0=w0, lam=lam)
            m = mae_of(w, X, yall)
            if m < best_mae:
                best_mae, best_w, best_lam = m, w, lam
        w = best_w
        mae = best_mae
        dfull = [dw.get(ABIL_ORDER[j], 0.0) / dnorm for j in range(25)]
        doc_mae = mae_of([dfull[idx[t]] for t in range(len(idx))], X, yall)
        # 仅保留 > 0.3% 的非零项
        kept = [(ABIL_ORDER[idx[t]], round(max(0.0, w[t]), 4)) for t in range(len(idx)) if w[t] > 0.003]
        s2 = sum(v for _, v in kept) or 1.0
        kept = [(k, round(v / s2, 4)) for k, v in kept]
        new_weights[g] = kept
        print("\n=== %s 组 (n=%d) ===" % (g, len(data)))
        print("  (lambda=%s) 精调权重 MAE=%.2f   文档化权重 MAE=%.2f   %s" %
              (best_lam, mae, doc_mae, "优于文档化" if mae < doc_mae else "未优于文档化"))
        print("  新权重: " + ", ".join("%s=%.3f" % (k, v) for k, v in sorted(kept, key=lambda x: -x[1])))

    out = ["# 由 fit_weights.py 用 PES master 真实样本 NNLS(非负+和为1) 反推",
           "OVERALL_WEIGHTS = {"]
    for g in ("GK", "DEF", "MID", "FWD"):
        items = ", ".join('("%s", %s)' % (k, ("%.4f" % v).rstrip("0").rstrip(".")) for k, v in new_weights[g])
        out.append('    "%s": [%s],' % (g, items))
    out.append("}")
    open(os.path.join(BASE, "pes_ratings_new_weights.py"), "w", encoding="utf-8").write("\n".join(out) + "\n")
    print("\n新权重已写入 pes_ratings_new_weights.py")


if __name__ == "__main__":
    main()
