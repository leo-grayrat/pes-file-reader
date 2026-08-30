#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ml_konami_bridge.py -- 把 ML 球队块(700)的「ML块序号」映射到 EDIT 的 Konami team_id，
闭合 docs/bl_ml_structure.md §2.11.5 所述「+0x598 预算闭合的最后缺口」。

桥接链（语言无关，靠 3 字母缩写码 + 英文名）：
  ML块(r) --码(+0x62A)--> Team.bin(i) --英文名(+0x70)--> team_id_names_final.csv --> Konami team_id

产物：outputs/ml_to_konami.csv
      (ml_idx, ml_name_cn, ml_code, pesdb_idx, teambin_name_en, konami_team_id, konami_name, confidence, method)
纯标准库。"""
import os, re, csv, struct, zlib, unicodedata

BASE = os.path.dirname(os.path.abspath(__file__))
DEC = os.path.join(BASE, "decoded")
TEAMBIN = os.path.join(BASE, "outputs", "cpk_extract_dt10", "common", "etc", "Team.bin")
TEAMNAMES = os.path.join(BASE, "outputs", "team_id_names_final.csv")
OUT = os.path.join(BASE, "outputs", "ml_to_konami.csv")

def u32(b, o): return struct.unpack_from("<I", b, o)[0]
def cstr(b, o, n):
    e = b.find(b"\x00", o, o + n)
    if e < 0: e = o + n
    return b[o:e].decode("utf-8", "replace")

def norm(s):
    s = unicodedata.normalize("NFKD", s)
    s = "".join(c for c in s if not unicodedata.combining(c))
    return re.sub(r"[^a-z0-9]", "", s.lower())

# ---------- 1. ML 块 700 队 ----------
def extract_ml():
    b = open(os.path.join(DEC, "ML00000000.data"), "rb").read()
    TEAM_START, S, N = 0x100, 0x690, 700
    rows = []
    for r in range(N):
        o = TEAM_START + r * S
        cn = cstr(b, o + 0x5E4, 64).strip()
        code = cstr(b, o + 0x62A, 4).strip()
        rows.append((r, cn, code))
    return rows

# ---------- 2. Team.bin 739 队 ----------
def extract_teambin():
    raw = open(TEAMBIN, "rb").read()
    out = zlib.decompressobj().decompress(raw[0x10:])
    REC, START = 1532, 0x100
    NT = (len(out) - START) // REC
    rows = []
    for i in range(1, NT + 1):
        o = START + (i - 1) * REC
        eng = cstr(out, o + 0x70, 64).strip()
        code = cstr(out, o + 0x272, 8).strip()
        rows.append((i, eng, code))
    return rows

# ---------- 3. team_id_names_final.csv ----------
def load_konami():
    d = {}
    with open(TEAMNAMES, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            tid = int(row["team_id"]); nm = row["name"].strip()
            d[norm(nm)] = (tid, nm, row["confidence"])
    return d

def main():
    ml = extract_ml()
    tb = extract_teambin()
    kon = load_konami()

    # Team.bin code -> pesdb_idx（处理重复码）
    code2idx = {}
    for i, eng, code in tb:
        if code:
            code2idx.setdefault(code.upper(), []).append(i)

    # Team.bin english-norm -> pesdb_idx
    en2idx = {}
    for i, eng, code in tb:
        if eng:
            en2idx.setdefault(norm(eng), []).append(i)

    out_rows = []
    n_code = n_name = n_ok = 0
    method_counter = {}
    for r, cn, code in ml:
        pesdb_idx = None; teambin_en = ""; method = ""
        # 优先：码匹配
        if code and code.upper() in code2idx:
            cands = code2idx[code.upper()]
            if len(cands) == 1:
                pesdb_idx = cands[0]; method = "code"
                n_code += 1
            else:
                # 码重复，退而用英文名
                pass
        # 码未命中或重复：用英文名（ML 块无英文名，故只能靠码；这里仅对码重复情形尝试无果）
        if pesdb_idx is None:
            method = "NOMATCH"
        else:
            teambin_en = next((e for i2, e, c in tb if i2 == pesdb_idx), "")
            # Team.bin 英文名 -> Konami team_id
            kn = norm(teambin_en)
            if kn in kon:
                tid, kname, conf = kon[kn]
                out_rows.append((r, cn, code, pesdb_idx, teambin_en, tid, kname, conf, method))
                n_name += 1; n_ok += 1
                method_counter[method] = method_counter.get(method, 0) + 1
            else:
                out_rows.append((r, cn, code, pesdb_idx, teambin_en, "", "", "", method + ":no_konami_name"))
                method_counter[method + ":no_konami_name"] = method_counter.get(method + ":no_konami_name", 0) + 1

    # 没匹配到 pesdb 的 ML 块
    n_unmatched = sum(1 for r, cn, code in ml if not any(o[0] == r for o in out_rows))
    # 写出
    with open(OUT, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["ml_idx", "ml_name_cn", "ml_code", "pesdb_idx",
                    "teambin_name_en", "konami_team_id", "konami_name", "confidence", "method"])
        for row in out_rows:
            w.writerow(row)

    print("=== ML块 -> Konami team_id 桥接诊断 ===")
    print(f"ML 块总数: {len(ml)}")
    print(f"  码命中 Team.bin (唯一): {n_code}")
    print(f"  码命中后英文名->Konami 成功: {n_name}")
    print(f"  最终闭合(Konami team_id 已知): {n_ok}")
    print(f"  未闭合(无 Team.bin 码匹配): {n_unmatched}")
    print(f"方法分布: {method_counter}")
    # 覆盖率
    print(f"覆盖率(已闭合/700): {n_ok}/700 = {100.0*n_ok/700:.1f}%")
    # 列出若干未命中样本
    unmatched = [(r, cn, code) for r, cn, code in ml
                 if not any(o[0] == r for o in out_rows)]
    if unmatched:
        print("未命中样例(前15):")
        for r, cn, code in unmatched[:15]:
            print(f"    [{r:3d}] {cn!r:12} code={code!r}")

if __name__ == "__main__":
    main()
