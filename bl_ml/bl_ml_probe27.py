import struct

FILES = {
    "ML0(in-season)": "decoded/ML00000000.data",
    "ML1(in-season)": "decoded/ML00000001.data",
    "ML13(in-season)": "decoded/ML00000013.data",
    "ML2(preseason)": "decoded/ML00000002.data",
}

def load(path):
    with open(path, "rb") as f:
        return f.read()

def find_table(b, stride=0x24, minlen=20):
    """扫描定长日期表：找连续 N 条、步长 stride、首尾均为合法日期(u16年+u8月+u8日)的段。"""
    n = len(b)
    best = []
    best_off = -1
    for off in range(n - stride):
        y, m, d = struct.unpack_from("<HBB", b, off)
        if not (2000 <= y <= 2100 and 1 <= m <= 12 and 1 <= d <= 31):
            continue
        # 验证后续连续记录
        recs = []
        o = off
        while o + stride <= n:
            yy, mm, dd = struct.unpack_from("<HBB", b, o)
            if not (2000 <= yy <= 2100 and 1 <= mm <= 12 and 1 <= dd <= 31):
                break
            v = struct.unpack_from("<9I", b, o)
            recs.append((o, v))
            o += stride
        if len(recs) >= minlen and len(recs) > len(best):
            best = recs
            best_off = off
    return best_off, best

def analyze(name, b):
    off, recs = find_table(b)
    if not recs:
        print(f"[{name}] 无定长日期表 (offset={off:#x})")
        return
    print(f"\n===== {name} =====")
    print(f"  表起始 offset = {off:#x}, 记录数 = {len(recs)}, 步长=0x{0x24:X}")
    f1 = {}      # +0x04
    f7 = {}      # +0x1C
    f7_f6 = {}   # f7 -> f6(v[6]) 状态
    f2_set = set()
    f3_money = f4_money = 0
    f3_all = []; f4_all = []
    f8_all = []
    for (o, v) in recs:
        y, m, d = v[0] >> 16, (v[0] >> 8) & 0xFF, v[0] & 0xFF
        date = (y, m, d)
        f1[v[1]] = f1.get(v[1], 0) + 1
        f7[v[7]] = f7.get(v[7], 0) + 1
        f7_f6.setdefault(v[7], set()).add(v[6])
        f2_set.add(v[2])
        f3_all.append(v[3]); f4_all.append(v[4]); f8_all.append(v[8])
        if 1000 <= v[3] <= 5_000_000:
            f3_money += 1
        if 1000 <= v[4] <= 5_000_000:
            f4_money += 1
    print(f"  f1(+0x04) 分布: {dict(sorted(f1.items()))}")
    print(f"  f7(+0x1C) 分布: {dict(sorted(f7.items()))}")
    print(f"  f7 -> f6 取值: " + ", ".join(f"f7={k}:{len(v)}vals" for k, v in sorted(f7_f6.items())))
    print(f"  f2(+0x08) 唯一 ID 数: {len(f2_set)}, 最大值={max(f2_set):,} " if f2_set else "  f2 empty")
    print(f"  f3(+0x0C) 金额候选(1e3~5e6): {f3_money}/{len(recs)}")
    print(f"  f4(+0x10) 金额候选(1e3~5e6): {f4_money}/{len(recs)}")
    # 打印前 12 条原始字段，便于肉眼核对
    print("  前 12 条 (date | f1 f2 f3 f4 f5 f6 f7 f8):")
    for i, (o, v) in enumerate(recs[:12]):
        y, m, d = v[0] >> 16, (v[0] >> 8) & 0xFF, v[0] & 0xFF
        print(f"    [{i:3d}] {y:04d}-{m:02d}-{d:02d} | {v[1]:#x} {v[2]:#x} {v[3]:#x} {v[4]:#x} {v[5]:#x} {v[6]:#x} {v[7]:#x} {v[8]:#x}")
    # Σ 闭合尝试：假设 f4 为金额，按 f1 分正负求和（先假设 f1=某值=支出，否则收入）
    for sign_rule in [0, 1]:
        s = sum((v[4] if v[1] == sign_rule else -v[4]) for (o, v) in recs)
        print(f"  Σ f4 (f1=={sign_rule} 视为正): {s:,}  → ×100 = {s*100:,} EUR")
    return recs

for name, path in FILES.items():
    try:
        analyze(name, load(path))
    except FileNotFoundError:
        print(f"[{name}] 文件缺失: {path}")
