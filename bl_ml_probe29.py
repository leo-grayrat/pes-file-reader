"""
bl_ml_probe29.py —— 导出 0x12A72FD 动态事件表为 CSV 并做方向统计。
纯存档侧分析，不需游戏目录。
"""
import struct, csv, os

FILES = {
    "ML0": "decoded/ML00000000.data",
}

def parse_table(path):
    b = open(path, "rb").read()
    off = 0x12A72FD
    recs = []
    for i in range(256):
        base = off + i * 0x24
        if base + 0x24 > len(b):
            break
        row = b[  base:base + 0x24]
        y, m, d = struct.unpack_from("<HBB", row, 0)
        if not (2000 <= y <= 2100 and 1 <= m <= 12 and 1 <= d <= 31):
            break
        v = list(struct.unpack_from("<9I", row, 0))
        recs.append((base, y, m, d, v))
    return recs

def main():
    for tag, path in FILES.items():
        recs = parse_table(path)
        out = f"outputs/event_table_{tag}.csv"
        with open(out, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["idx","file_off","date","f1","f2_hi","f2_lo","f3","f4","f5","f6","f7","f8"])
            for i,(base,y,m,d,v) in enumerate(recs):
                w.writerow([i, hex(base), f"{y}-{m:02d}-{d:02d}", v[1], (v[2]>>16)&0xFFFF, v[2]&0xFFFF,
                            v[3], v[4], v[5], v[6], v[7], v[8]])
        print(f"[{tag}] 记录数 {len(recs)} -> {out}")

        # 方向统计：按 f1 分组看 f4（最像金额）
        def stat(key_idx, label):
            vals = [r[4][key_idx] for r in recs if (r[4][key_idx] != 0xFFFFFFFF and r[4][key_idx] < 0x100000000)]
            # 仅看"像一个金额"（>=1000 且 <=5_000_000，×100 即 10万~5亿）
            money = [x for x in vals if 1000 <= x <= 5_000_000]
            if money:
                print(f"  {label}: 候选金额 {len(money)}/{len(vals)}，均值 {sum(money)//len(money):,}，"
                      f"最小 {min(money):,}，最大 {max(money):,}")
            else:
                print(f"  {label}: 无金额候选")
        print("  f1==0 组:")
        sub0 = [r for r in recs if r[4][1] == 0]
        sub1 = [r for r in recs if r[4][1] == 1]
        print(f"    f1=0 记录 {len(sub0)} 条; f1=1 记录 {len(sub1)} 条")
        # 直接对 f4 做金额统计（全集）
        allf4 = [r[4][4] for r in recs if r[4][4] != 0xFFFFFFFF]
        money4 = [x for x in allf4 if 1000 <= x <= 5_000_000]
        print(f"  f4 全量: {len(money4)}/{len(allf4)} 像金额，均值 {sum(money4)//len(money4):,} 元(x100)")
        # f5 是否像 team_id：看取值范围与重复率
        f5 = [r[4][5] for r in recs if r[4][5] != 0xFFFFFFFF]
        print(f"  f5 范围: [{min(f5):,}, {max(f5):,}]  去重 {len(set(f5))}/{len(f5)}")
        f3 = [r[4][3] for r in recs if r[4][3] != 0xFFFFFFFF]
        print(f"  f3 范围: [{min(f3):,}, {max(f3):,}]  去重 {len(set(f3))}/{len(f3)}")

if __name__ == "__main__":
    main()
