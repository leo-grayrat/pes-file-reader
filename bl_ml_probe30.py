#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""跨存档解析 0x12A72FD 区域的事件表（动态定位起点），导出合并 CSV + 闭合试算。
仅依赖 decoded/ 既有存档，不碰游戏目录。"""
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

STEP = 0x24  # 36 字节 = 9 u32

def locate_table(path, need=50):
    """在存档中定位事件表起点：找日期三元组链式连续 >=need 块的起点（排除赛程表）。"""
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
        if cnt >= need:
            if abs(start - 0x3299B0) > 0x10000:   # 跳过已知赛程表
                return start
    return None

def parse_table(path):
    start = locate_table(path)
    if start is None:
        return []
    b = open(path, "rb").read()
    recs = []
    off = start
    for _ in range(200):   # 容量上限
        if off + STEP > len(b):
            break
        v = struct.unpack_from("<9I", b, off)
        off += STEP
        # 哨兵判定：f1 or f7 为高值异常 -> 视为表末尾哨兵，停止
        if v[1] > 0x7FFFFFFF or v[7] > 0x7FFFFFFF:
            break
        recs.append(v)
    return recs

def is_money(v):
    return 1000 <= v <= 5_000_000  # ×100 即 10万~5亿欧元

def main():
    rows_all = []
    summary = []
    for tag, fn, kind in SAMPLES:
        recs = parse_table(os.path.join(BASE, fn))
        n = len(recs)
        if n == 0:
            summary.append((tag, kind, 0, "-", "-", "-", "-", "-", "-"))
            print(f"[{tag}] {fn}: 无事件表（preseason={kind=='preseason'}）")
            continue
        f1_dist, f7_dist = {}, {}
        f4_all = f4_in = f4_out = 0
        f2hi = set(); money_hits = 0
        for i, v in enumerate(recs):
            f1, f4, f7, f2 = v[1], v[ 4], v[7], v[2]
            f2hi.add((f2 >> 16) & 0xFFFF)
            f1_dist[f1] = f1_dist.get(f1, 0) + 1
            f7_dist[f7] = f7_dist.get(f7, 0) + 1
            if is_money(f4):
                money_hits += 1
                f4_all += f4
                if f1 == 0: f4_in += f4
                else:       f4_out += f4
            rows_all.append([tag, kind, i, v])
        summary.append((tag, kind, n, dict(f1_dist), dict(f7_dist),
                        round(f4_all*100), round(f4_in*100), round(f4_out*100),
                        len(f2hi), money_hits))
        print(f"[{tag}] {fn}: {n} 条 | f1={f1_dist} f7={f7_dist} | "
              f"f4Σ={f4_all*100:,}€ | 金钱命中 {money_hits}/{n}")

    csv_path = os.path.join(OUT, "event_table_all.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["src","kind","idx","date","f1","f2","f3","f4","f5","f6","f7","f8",
                    "f2_hi","f2_lo","f2_lo_is_FFFF"])
        for tag, fn, kind in SAMPLES:
            for i, v in enumerate(parse_table(os.path.join(BASE, fn))):
                ds = f"{v[0]&0xFFFF:04d}-{(v[0]>>16)&0xFF:02d}-{(v[0]>>24)&0xFF:02d}"
                w.writerow([tag, kind, i, ds] + list(v) +
                           [(v[2]>>16)&0xFFFF, v[2]&0xFFFF, (v[2]&0xFFFF)==0xFFFF])
    print("写出", csv_path)

    # 跨存档 f2_hi 交集（识别持续球员）
    hi = {}
    for tag, fn, _ in SAMPLES:
        hi[tag] = set((v[2]>>16)&0xFFFF for v in parse_table(os.path.join(BASE, fn)))
    common = set.intersection(*hi.values()) if hi else set()
    print(f"跨 {len(hi)} 存档共同出现的 f2_hi ID 数: {len(common)}")

if __name__ == "__main__":
    main()
