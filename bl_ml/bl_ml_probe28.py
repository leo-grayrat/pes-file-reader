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
    n = len(b)
    best = []; best_off = -1
    for off in range(n - stride):
        y = struct.unpack_from("<H", b, off)[0]
        mo = b[off+2]; da = b[off+3]
        if not (2000 <= y <= 2100 and 1 <= mo <= 12 and 1 <= da <= 31):
            continue
        recs = []
        o = off
        while o + stride <= n:
            yy = struct.unpack_from("<H", b, o)[0]
            mm = b[o+2]; dd = b[o+3]
            if not (2000 <= yy <= 2100 and 1 <= mm <= 12 and 1 <= dd <= 31):
                break
            v = struct.unpack_from("<9I", b, o)
            recs.append((o, v))
            o += stride
        if len(recs) >= minlen and len(recs) > len(best):
            best = recs; best_off = off
    return best_off, best

def analyze(name, b):
    off, recs = find_table(b)
    if not recs:
        print(f"[{name}] 无定长日期表")
        return
    print(f"\n===== {name}  (base={off:#x}, n={len(recs)}) =====")
    f1 = {}; f7 = {}; f2hi = {}; f2lo = {}
    f3_all=[]; f4_all=[]; f5_all=[]; f6_all=[]
    dates=[]
    for (o, v) in recs:
        y = struct.unpack_from("<H", b, o)[0]; mo=b[o+2]; da=b[o+3]
        dates.append((y,mo,da))
        f1[v[1]] = f1.get(v[1],0)+1
        f7[v[7]] = f7.get(v[7],0)+1
        f2hi[v[2]>>16] = f2hi.get(v[2]>>16,0)+1
        f2lo[v[2]&0xFFFF] = f2lo.get(v[2]&0xFFFF,0)+1
        f3_all.append(v[3]); f4_all.append(v[4]); f5_all.append(v[5]); f6_all.append(v[6])
    print(f"  日期范围: {dates[0]} .. {dates[-1]} | 末尾递增? {dates[-1]>=dates[0]}")
    print(f"  f1(+0x04): {dict(sorted(f1.items()))}")
    print(f"  f7(+0x1C): {dict(sorted(f7.items()))}")
    print(f"  f2 高16 bits 分布(前6): {dict(sorted(f2hi.items())[:6])}  unique={len(f2hi)}")
    print(f"  f2 低16 bits 分布(前6): {dict(sorted(f2lo.items())[:6])}  unique={len(f2lo)}")
    for lbl, arr, lo, hi in [("f3(+0x0C)",f3_all,1000,5_000_000),("f4(+0x10)",f4_all,1000,5_000_000),("f5(+0x14)",f5_all,1000,5_000_000),("f6(+0x18)",f6_all,1000,5_000_000)]:
        inr=sum(1 for x in arr if lo<=x<=hi)
        print(f"  {lbl}: 量程内 {inr}/{len(arr)} | min={min(arr):,} max={max(arr):,}  (×100≈{min(arr)*100:,}~{max(arr)*100:,})")
    # 方向探索: f1=1 vs 0 时各金额字段均值
    for flag in [0,1]:
        sub=[v for (o,v) in recs if v[1]==flag]
        if not sub: continue
        avg4=sum(v[4] for v in sub)/len(sub)
        avg5=sum(v[5] for v in sub)/len(sub)
        print(f"  f1={flag}: n={len(sub)}, f4均={avg4:,.0f}, f5均={avg5:,.0f}")
    # f7=1 时 f6 是否恒为 0xFFFFFFFF
    bad = [(v[6],v[7]) for (o,v) in recs if v[7]==1]
    print(f"  f7==1 的 f6 取值: {set(bad)}")
    print("  样例 6 条:")
    for i,(o,v) in enumerate(recs[:6]):
        y=struct.unpack_from('<H',b,o)[0]; mo=b[o+2]; da=b[o+3]
        print(f"   [{i}] {y}-{mo:02d}-{da:02d} f1={v[1]} f2={v[2]:#x} f3={v[3]:,} f4={v[4]:,} f5={v[5]:,} f6={v[6]:#x} f7={v[7]} f8={v[8]:,}")

for name, path in FILES.items():
    try:
        analyze(name, load(path))
    except FileNotFoundError:
        print(f"[{name}] 缺失 {path}")
