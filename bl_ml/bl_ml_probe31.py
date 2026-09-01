#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""bl_ml_probe31.py — 重新干净解析四份 ML 存档的事件表（0x12A72FD 区域，步长 0x24），
对字段做正确命名、跨存档统计，并判断「事件表是玩家队专属还是全局」。

字段布局（每记录 9×u32 = 36 字节）：
  v0 : 日期   低16=年(u16) 高8=月 最高8=日
  v1 : 状态组 (已知 85=已结算 / 14=挂牌 / 0=普通)
  v2 : 高16=f2_hi(球员注册ID 1万~6万) ; 低16=f2_lo
  v3 : 金额候选 (×100 欧元)
  v4 : 未知
  v5 : 未知
  v6 : 未知 (f7==1 时恒空)
  v7 : 标志 f7
  v8 : 残值
（以上语义以数据验证为准，本脚本只做统计不臆断）

目标：
  1. 输出干净 CSV（正确表头）outputs/event_table_clean.csv
  2. 每存档：条数 / 日期跨度 / v1分布 / v3金额Σ / f2_hi 唯一ID数 / 跨存档交集
  3. 通过 f2_hi 两两差异判定事件表范围（单一队 vs 全局）
"""
import struct, csv, os

BASE = "decoded"
OUT  = "outputs"
os.makedirs(OUT, exist_ok=True)

SAMPLES = [
    ("ML0",  "ML00000000.data", "in-season"),
    ("ML1",  "ML00000001.data", "in-season"),
    ("ML13", "ML00000013.data", "in-season"),
    ("ML2",  "ML00000002.data", "preseason"),
]
STEP = 0x24

def locate_table(path, need=50):
    if not os.path.exists(path):
        return None
    b = open(path, "rb").read()
    n = len(b)
    cand = set()
    for off in range(0, n - STEP):
        y = struct.unpack_from("<H", b, off)[0]
        mo = b[off + 2]; da = b[off + 3]
        if 2000 <= y <= 2100 and 1 <= mo <= 12 and 1 <= da <= 31:
            cand.add(off)
    for start in sorted(cand):
        cnt = 0; o = start
        while o + 4 <= n:
            y = struct.unpack_from("<H", b, o)[0]; mo = b[o + 2]; da = b[o + 3]
            if not (2000 <= y <= 2100 and 1 <= mo <= 12 and 1 <= da <= 31):
                break
            cnt += 1; o += STEP
        if cnt >= need and abs(start - 0x3299B0) > 0x10000:
            return start
    return None

def parse_table(path):
    start = locate_table(path)
    if start is None:
        return []
    b = open(path, "rb").read()
    recs = []
    off = start
    for _ in range(200):
        if off + STEP > len(b):
            break
        v = struct.unpack_from("<9I", b, off)
        off += STEP
        if v[1] > 0x7FFFFFFF or v[7] > 0x7FFFFFFF:   # 哨兵，停止
            break
        recs.append(v)
    return recs

def main():
    rows = []
    summary = {}
    hi_sets = {}
    for tag, fn, kind in SAMPLES:
        recs = parse_table(os.path.join(BASE, fn))
        n = len(recs)
        if n == 0:
            print(f"[{tag}] {fn}: 无事件表")
            summary[tag] = dict(n=0, kind=kind)
            continue
        v1_dist, v7_dist = {}, {}
        money_all = 0
        money_by_v1 = {}
        f2hi = set(); f2lo = set()
        dates = []
        for i, v in enumerate(recs):
            year = v[0] & 0xFFFF
            mo   = (v[0] >> 16) & 0xFF
            da   = (v[0] >> 24) & 0xFF
            dates.append((year, mo, da))
            v1 = v[1]; v7 = v[7]
            v1_dist[v1] = v1_dist.get(v1, 0) + 1
            v7_dist[v7] = v7_dist.get(v7, 0) + 1
            f2hi.add((v[2] >> 16) & 0xFFFF)
            f2lo.add(v[2] & 0xFFFF)
            if 1000 <= v[3] <= 5_000_000:      # ×100 即 10万~5亿欧元
                money_all += v[3]
                money_by_v1[v1] = money_by_v1.get(v1, 0) + v[3]
            rows.append([tag, kind, i, f"{year:04d}-{mo:02d}-{da:02d}",
                         v1, v[2], v[3], v[4], v[5], v[6], v[7], v[8],
                         (v[2] >> 16) & 0xFFFF, v[2] & 0xFFFF])
        hi_sets[tag] = f2hi
        mn = min(dates); mx = max(dates)
        summary[tag] = dict(n=n, kind=kind, v1=v1_dist, v7=v7_dist,
                           money_eur=money_all*100, money_by_v1={k: val*100 for k,val in money_by_v1.items()},
                           f2hi_n=len(f2hi), f2hi_min=min(f2hi), f2hi_max=max(f2hi),
                           f2lo_vals=sorted(f2lo)[:20], date_min=mn, date_max=mx)
        print(f"[{tag}] n={n} 日期 {mn}..{mx} | v1={v1_dist} | v7={v7_dist}")
        print(f"       f2_hi 唯一ID={len(f2hi)} 范围[{min(f2hi)}-{max(f2hi)}] | 金额Σ≈{money_all*100:,}€")

    # 写干净 CSV
    cp = os.path.join(OUT, "event_table_clean.csv")
    with open(cp, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["src","kind","idx","date","v1_status","v2_raw","v3_money_x100",
                    "v4","v5","v6","v7_flag","v8","f2_hi(player_id)","f2_lo"])
        w.writerows(rows)
    print("写出", cp)

    # 跨存档交集，判定范围
    if hi_sets:
        common = set.intersection(*hi_sets.values())
        union  = set.union(*hi_sets.values())
        print(f"\n跨存档 f2_hi 共同ID数: {len(common)} / 并集 {len(union)}")
        # 若每个存档的 ID 集合都很小且与其它存档高度重叠 -> 玩家队专属
        for tag, s in hi_sets.items():
            print(f"  {tag}: {len(s)} ids, 与他档交集={len(s & union - {0}) if False else 'see above'}")

if __name__ == "__main__":
    main()
