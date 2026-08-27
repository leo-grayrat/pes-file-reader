#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""REPLAY(回放) 解密 data 块的结构探查脚本（纯标准库）。

分析内容：
  一、分块熵曲线（找压缩/加密/明文区）
  二、ASCII 与 UTF-16LE 字符串落点
  三、头部前 0x200 的 uint32 字段解读（自洽性检查）
  四、多回放跨样本恒定字节共识 + 差异区分析（bitwise 高效写法）
  五、周期性/步长探测

用法：
  python replay_analyze.py              # 全套分析
  python replay_analyze.py entropy      # 只跑熵分析
  python replay_analyze.py strings      # 只跑字符串分析
  python replay_analyze.py header       # 只跑头部解读
  python replay_analyze.py consensus    # 只跑跨样本共识/差异
  python replay_analyze.py period       # 只跑周期性探测
  python replay_analyze.py tail         # 只跑尾部布局分析
  python replay_analyze.py records      # 只跑记录数组验证
  python replay_analyze.py fields       # 只跑全样本头字段对比
"""
import os
import sys
import math
import struct
from collections import Counter

BASE = os.path.dirname(os.path.abspath(__file__))
DEC = os.path.join(BASE, "decoded")


# ---------- 基础工具 ----------
def list_replays():
    """decoded/ 下所有回放 data 块文件名，按文件名排序。"""
    return sorted(f for f in os.listdir(DEC)
                  if f.startswith("rep_REPLAY") and f.endswith(".data"))


def load(name):
    with open(os.path.join(DEC, name), "rb") as f:
        return f.read()


def u32(b, off):
    return struct.unpack_from("<I", b, off)[0]


def u16(b, off):
    return struct.unpack_from("<H", b, off)[0]


def block_entropy(b, blk=65536):
    """分块香农熵，返回 [(偏移, 熵), ...]。纯 Python 对 5MB 数据做 Counter 足够快。"""
    out = []
    for i in range(0, len(b), blk):
        c = Counter(b[i:i + blk])
        n = sum(c.values())
        e = -sum((v / n) * math.log2(v / n) for v in c.values())
        out.append((i, e))
    return out


def byte_histogram_top(b, top=12):
    """字节直方图前 top 名（判断是否稀疏/结构化数据）。"""
    c = Counter(b)
    n = len(b)
    return [(byte, cnt, 100.0 * cnt / n) for byte, cnt in c.most_common(top)]


def ascii_strings(b, minlen=4, min_alpha=3):
    """提取可打印 ASCII 串（过滤纯数字等伪文本）。"""
    res = []
    cur, start = [], -1
    for i, x in enumerate(b):
        if 32 <= x < 127:
            if not cur:
                start = i
            cur.append(chr(x))
        else:
            if len(cur) >= minlen:
                s = "".join(cur)
                if sum(ch.isalpha() for ch in s) >= min_alpha:
                    res.append((start, s))
            cur = []
    if len(cur) >= minlen:
        s = "".join(cur)
        if sum(ch.isalpha() for ch in s) >= min_alpha:
            res.append((start, s))
    return res


def utf16le_strings(b, minlen=4, min_alpha=3):
    """提取 UTF-16LE 字符串（限定 BMP 常见区）。"""
    res = []
    cur, start = [], -1
    i = 0
    n = len(b) - 1
    while i < n:
        ch = b[i] | (b[i + 1] << 8)
        if 0x20 <= ch < 0x7F or 0xA0 <= ch < 0x2000:
            if not cur:
                start = i
            cur.append(chr(ch) if ch < 0x80 else "?")
            i += 2
        else:
            if len(cur) >= minlen:
                s = "".join(cur)
                if sum(c.isalpha() for c in s) >= min_alpha:
                    res.append((start, s))
            cur = []
            i += 1
    if len(cur) >= minlen:
        s = "".join(cur)
        if sum(c.isalpha() for c in s) >= min_alpha:
            res.append((start, s))
    return res


def hexdump(b, offset=0, length=256, width=16):
    out = []
    for i in range(0, length, width):
        chunk = b[offset + i:offset + i + width]
        if not chunk:
            break
        hexpart = " ".join(f"{x:02X}" for x in chunk)
        asc = "".join(chr(x) if 32 <= x < 127 else "." for x in chunk)
        out.append(f"{offset + i:08X}  {hexpart:<{width * 3}}  {asc}")
    return "\n".join(out)


def diff_runs(a, b, merge_gap=16, limit=None):
    """两文件差异字节合并成 run，merge_gap 以内的小缝隙合并。"""
    n = min(len(a), len(b))
    # 高效差异提取：按 4KB 块先过滤，再细查
    blk = 4096
    runs = []
    i = 0
    while i < n:
        j = min(i + blk, n)
        if a[i:j] != b[i:j]:
            # 块内有差异，逐字节找
            k = i
            while k < j:
                if a[k] != b[k]:
                    s = k
                    while k < j and a[k] != b[k]:
                        k += 1
                    runs.append((s, k))
                else:
                    k += 1
        i = j
    # 合并相距 <= merge_gap 的 run
    merged = []
    for s, e in runs:
        if merged and s - merged[-1][1] <= merge_gap:
            merged[-1][1] = e
        else:
            merged.append([s, e])
    merged = [(s, e) for s, e in merged]
    total = sum(e - s for s, e in merged)
    if limit:
        return merged[:limit], total, n
    return merged, total, n


# ---------- 一、熵分析 ----------
def analyze_entropy(names, blk=65536):
    print("=" * 72)
    print("一、分块熵曲线（块大小 64KB；熵≈8.0 为随机/加密，<6 多为结构化数据）")
    print("=" * 72)
    for name in names:
        b = load(name)
        curve = block_entropy(b, blk)
        # 汇总：各区熵的分布
        hi = [o for o, e in curve if e >= 7.9]
        lo = [(o, e) for o, e in curve if e < 6.0]
        print(f"\n[{name}] size={len(b)} (0x{len(b):X})  块数={len(curve)}")
        print(f"  高熵(>=7.9)块数: {len(hi)}/{len(curve)}")
        if hi:
            print(f"  高熵区范围: 0x{hi[0]:X} ~ 0x{hi[-1] + blk:X}")
        if lo:
            print(f"  低熵(<6.0)块: {[(f'0x{o:X}', round(e, 2)) for o, e in lo[:16]]}")
        # 输出前 12 块与尾 4 块曲线
        print("  前 12 块熵曲线:", " ".join(f"{e:.2f}" for _, e in curve[:12]))
        print("  尾 4 块熵曲线 :", " ".join(f"{e:.2f}" for _, e in curve[-4:]))
        # 头部 0x200 与整体直方图对比
        print(f"  全文件 top 字节: {[(f'{by:02X}', round(pct, 2)) for by, _, pct in byte_histogram_top(b, 8)]}")
    # 更细粒度：对第一个样本前 1MB 用 16KB 块扫一遍，找熵跳变点
    b = load(names[0])
    print(f"\n[{names[0]}] 细粒度(16KB)熵扫描 0x0~0x200000，标注与前一跳变 >=0.8 的位置:")
    prev = None
    for o, e in block_entropy(b[:0x200000], 16384):
        if prev is not None and abs(e - prev) >= 0.8:
            print(f"  熵跳变 @0x{o:X}: {prev:.2f} -> {e:.2f}")
        prev = e


# ---------- 二、字符串 ----------
def analyze_strings(names, maxn=60):
    print("\n" + "=" * 72)
    print("二、ASCII / UTF-16LE 字符串落点")
    print("=" * 72)
    for name in names[:2]:
        b = load(name)
        asc = ascii_strings(b)
        utf = utf16le_strings(b)
        print(f"\n[{name}] ASCII 串 {len(asc)} 条，UTF-16LE {len(utf)} 条")
        print("  -- ASCII 前 %d 条 --" % maxn)
        for off, s in asc[:maxn]:
            print(f"  0x{off:08X}  {s[:80]!r}")
        print("  -- UTF-16LE 前 20 条 --")
        for off, s in utf[:20]:
            print(f"  0x{off:08X}  {s[:80]!r}")
        if asc:
            # 字符串落点分布（按 1MB 分桶）
            buckets = Counter(off >> 20 for off, _ in asc)
            print(f"  ASCII 串按 1MB 分桶: {dict(sorted(buckets.items()))}")


# ---------- 三、头部 uint32 解读 ----------
def analyze_header(names):
    print("\n" + "=" * 72)
    print("三、头部前 0x200 的 uint32 字段解读")
    print("=" * 72)
    for name in names:
        b = load(name)
        size = len(b)
        print(f"\n[{name}] size={size} (0x{size:X})")
        print(hexdump(b, 0, 0x80))
        print("  uint32 字段（前 0x200/4=128 个）：")
        for i in range(0x200 // 4):
            v = u32(b, i * 4)
            note = ""
            if v == size:
                note = "  <-- 等于 data 块大小"
            elif 0 < v <= size and v >= 4096:
                note = f"  (<size, 可能是偏移/长度, 占比 {100.0 * v / size:.1f}%)"
            elif 0 < v < 1000:
                note = "  (小整数，疑似计数/标志)"
            if v != 0 or i < 16 or note:
                print(f"  +{i*4:03X}  {v:12d}  0x{v:08X}{note}")
        # 自洽性检查：头部里是否有值 == 某已知块大小
        print("  自洽性：寻找值等于 (size-0x200)、(size-0x100)、size//块长 等的字段")
        for i in range(0x200 // 4):
            v = u32(b, i * 4)
            for cand, label in [(size - 0x200, "size-0x200"), (size - 0x100, "size-0x100"),
                                (size - 512, "size-512"), (size // 2, "size/2")]:
                if v == cand:
                    print(f"    +{i*4:03X} == {label}")


# ---------- 四、跨样本共识 + 差异 ----------
def analyze_consensus(names):
    print("\n" + "=" * 72)
    print(f"四、跨样本恒定字节共识 + 差异区（{len(names)} 个样本）")
    print("=" * 72)
    n = min(len(load(nm)) for nm in names)
    # bitwise AND / OR 法求“所有样本都相同”的字节：and==or 的位置即恒定
    acc_and = None
    acc_or = None
    for nm in names:
        b = load(nm)[:n]
        if acc_and is None:
            acc_and = bytearray(b)
            acc_or = bytearray(b)
        else:
            # bytearray 按位运算需借助 int 大数（对 5MB 很快）
            ai = int.from_bytes(acc_and, "little") & int.from_bytes(b, "little")
            oi = int.from_bytes(acc_or, "little") | int.from_bytes(b, "little")
            acc_and = ai.to_bytes(n, "little")
            acc_or = oi.to_bytes(n, "little")
    const_mask = bytes(a ^ o for a, o in zip(acc_and, acc_or))  # 0 = 恒定
    const_count = const_mask.count(0)
    print(f"  对齐长度 n={n} (0x{n:X})，恒定字节数={const_count} ({100.0 * const_count / n:.2f}%)")

    # 恒定区/动态区 run
    runs = []
    i = 0
    while i < n:
        if const_mask[i] == 0:
            j = i
            while j < n and const_mask[j] == 0:
                j += 1
            runs.append((i, j, "const"))
            i = j
        else:
            j = i
            while j < n and const_mask[j] != 0:
                j += 1
            runs.append((i, j, "vary"))
            i = j
    consts = [r for r in runs if r[2] == "const"]
    varies = [r for r in runs if r[2] == "vary"]
    print(f"  恒定 run 数={len(consts)}，变化 run 数={len(varies)}")
    print("  前 24 个恒定 run（长度>=16）:")
    shown = 0
    for s, e, _ in consts:
        if e - s >= 16:
            print(f"    [{s:08X}, {e:08X})  len={e - s}")
            shown += 1
            if shown >= 24:
                break
    print("  前 24 个变化 run:")
    for s, e, _ in varies[:24]:
        print(f"    [{s:08X}, {e:08X})  len={e - s}")
    # 变化字节按 64KB 桶分布
    buckets = {}
    for i in range(0, n, 65536):
        buckets[i >> 16] = sum(1 for x in const_mask[i:i + 65536] if x != 0)
    top = sorted(buckets.items(), key=lambda kv: -kv[1])[:8]
    print(f"  变化字节最集中的 64KB 桶（桶号: 变化字节数）: {[(hex(k), v) for k, v in top]}")

    # 两两样本差异率（取前几个样本即可）
    if len(names) >= 2:
        a = load(names[0])
        bb = load(names[1])
        mrun, total, nn = diff_runs(a, bb, merge_gap=16, limit=20)
        print(f"\n  [{names[0]}] vs [{names[1]}]: 差异字节 {total}/{nn} = {100.0 * total / nn:.2f}%")
        for s, e in mrun:
            print(f"    [{s:08X}, {e:08X})  len={e - s}")


# ---------- 五、周期性探测 ----------
def analyze_period(names, max_scan=0x200000):
    print("\n" + "=" * 72)
    print("五、周期性 / 步长探测")
    print("=" * 72)
    if len(names) < 2:
        print("  需要至少 2 个样本")
        return
    a = load(names[0])[:max_scan]
    b = load(names[1])[:max_scan]
    n = len(a)
    # 差异位图
    diffmap = bytearray(x ^ y for x, y in zip(a, b))
    print(f"  扫描范围 0x0~0x{n:X}，候选步长下差异位置模步长的集中度：")
    for stride in (4, 8, 16, 32, 64, 128, 256, 512, 1024, 0x690, 4096):
        mods = Counter(i % stride for i, x in enumerate(diffmap) if x)
        if not mods:
            continue
        total = sum(mods.values())
        top3 = mods.most_common(3)
        conc = 100.0 * sum(c for _, c in top3) / total
        print(f"    步长 {stride:5d}(0x{stride:03X}): 差异总数 {total:7d}, "
              f"top3 余数 {[(m, c) for m, c in top3]} 集中度 {conc:.1f}%")
    # 自相关：文件自身按步长平移比对（前 256KB），找重复结构
    print(f"\n  [{names[0]}] 自相关（平移步长下相同字节占比，范围 0x40000）:")
    seg = a[:0x40000]
    for stride in (64, 128, 256, 512, 1024, 0x690, 4096, 0x10000):
        if stride >= len(seg):
            continue
        x = seg[:-stride]
        y = seg[stride:]
        same = sum(1 for i in range(len(x)) if x[i] == y[i])
        print(f"    步长 {stride:6d}(0x{stride:04X}): 相同占比 {100.0 * same / len(x):.1f}%")
    # 零字节/填充段探测（找大块填充 = 区段边界线索）
    print(f"\n  [{names[0]}] 大块连续同值填充（>=4KB）:")
    b0 = load(names[0])
    i = 0
    found = 0
    while i < len(b0) and found < 20:
        j = i + 1
        while j < len(b0) and b0[j] == b0[i]:
            j += 1
        if j - i >= 4096:
            print(f"    [{i:08X}, {j:08X}) 值=0x{b0[i]:02X} len={j - i}")
            found += 1
        i = j


# ---------- 六、尾部布局 ----------
def analyze_tail(names):
    print("\n" + "=" * 72)
    print("六、尾部布局分析")
    print("=" * 72)
    # 注：外层文件总长 = 320(加密头) + 208(文件头) + descSize + logoSize
    #     + dataSize + serialLength*2（serial 区占字节数 = 头字段 × 2，按字符计长）。
    # 本分析只针对解密后的 data 块，尾部指 data 块自身的末尾。
    for name in names[:3]:
        b = load(name)
        print(f"\n[{name}] size={len(b)} (0x{len(b):X})")
        print("  -- 尾部 0x80 --")
        print("\n".join("  " + ln for ln in hexdump(b, len(b) - 0x80, 0x80).splitlines()))
        # 尾部填充检测：从末尾向前找第一个非 0/非 FF 边界（用反向扫描，纯 Python 但尾部短）
        end = len(b)
        i = end - 1
        while i > 0 and b[i] == 0:
            i -= 1
        print(f"  末尾 0x00 填充: [{i + 1:08X}, {end:08X}) len={end - i - 1}")
        i2 = i
        while i2 > 0 and b[i2] == 0xFF:
            i2 -= 1
        if i2 != i:
            print(f"  其前 0xFF 填充: [{i2 + 1:08X}, {i + 1:08X}) len={i - i2}")
        print("  -- 末尾非零区最后 64 字节 --")
        print("\n".join("  " + ln for ln in hexdump(b, max(0, i2 - 31), 64).splitlines()))


# ---------- 七、记录数组验证 ----------
def analyze_records(names, start=0x80, stride=0xA0, name_off=0x58, name_len=9, count=40):
    """已验证：实体记录从 0x80 起、步长 0xA0，前 2 条 u16 为队伍魔数，
    名字在 +0x58（大写字母，9 字节）。前 22 条为两队首发(11+11)，
    随后 3 条裁判(魔数 FFFF)、其后是空记录。"""
    print("\n" + "=" * 72)
    print(f"七、记录数组验证：起点 0x{start:X}、步长 0x{stride:X}、"
          f"名字段 +0x{name_off:X}、前 {count} 条")
    print("=" * 72)
    for name in names[:2]:
        b = load(name)
        print(f"\n[{name}]")
        magics = Counter()
        for r in range(count):
            off = start + r * stride
            if off + stride > len(b):
                break
            magic = u32(b, off)
            magics[magic] += 1
            raw = b[off + name_off:off + name_off + name_len]
            s = "".join(chr(x) if 32 <= x < 127 else "." for x in raw)
            idv = u32(b, off + 4)
            print(f"  rec#{r:3d} @0x{off:05X}  magic={magic:08X}  "
                  f"id={idv:8d}  name={s!r}")
        print(f"  魔数统计: { {f'{m:08X}': c for m, c in magics.items()} }")
        # 跨样本同位名字对比（同场比赛的回放应同名单）
        if len(names) >= 2:
            b2 = load(names[1])
            same = sum(1 for r in range(count)
                       if b[start + r * stride + name_off:start + r * stride + name_off + name_len]
                       == b2[start + r * stride + name_off:start + r * stride + name_off + name_len])
            print(f"  与 [{names[1]}] 同位名字相同: {same}/{count}")


# ---------- 八、全样本头字段对比 ----------
KEY_OFFS = (0x00, 0x04, 0x08, 0x0C, 0x10, 0x14, 0x20, 0x54, 0x58, 0x60, 0x64)


def analyze_fields(names):
    print("\n" + "=" * 72)
    print(f"八、全样本头部关键字段对比（{len(names)} 个）")
    print("=" * 72)
    rows = []
    for nm in names:
        b = load(nm)
        row = tuple(u32(b, o) for o in KEY_OFFS)
        rows.append((nm, row))
    for nm, row in rows:
        print(f"{nm}  " + "  ".join(f"{v:>10d}" for v in row))
    print("\n各字段取值分布：")
    for ci, off in enumerate(KEY_OFFS):
        vals = Counter(r[1][ci] for r in rows)
        top = vals.most_common(6)
        suffix = " ..." if len(vals) > 6 else ""
        print(f"  +0x{off:02X}: {[(v, c) for v, c in top]}{suffix}")
    # +0x0C 与 +0x10 的相关性检查
    pairs = Counter((r[1][3], r[1][4]) for r in rows)
    print(f"\n(+0x0C, +0x10) 组合: {dict(pairs)}")
    # +0x08 自洽性：是否恒等于 dataSize - 0x50
    sizes = Counter(r[1][2] for r in rows)
    print(f"+0x08 取值: {dict(sizes)}；本 data 块大小 0x51EC60，"
          f"0x51EC60-0x50=0x{0x51EC60 - 0x50:X}，若相等则 +0x08 为负载长度")


def main():
    names = list_replays()
    if not names:
        print("decoded/ 下没有 rep_REPLAY*.data，请先用 export_data.py 或 pes_decrypt.py 解密。")
        return
    print(f"发现 {len(names)} 个回放样本：{names[0]} ~ {names[-1]}\n")
    mode = sys.argv[1] if len(sys.argv) > 1 else "all"
    sample3 = names[:3]  # 熵/字符串/头部用前 3 个样本即可
    if mode in ("all", "entropy"):
        analyze_entropy(sample3)
    if mode in ("all", "strings"):
        analyze_strings(sample3)
    if mode in ("all", "header"):
        analyze_header(sample3[:2])
    if mode in ("all", "consensus"):
        analyze_consensus(names[:5])  # 共识用 5 样本（性能考虑）
    if mode in ("all", "period"):
        analyze_period(names[:2])
    if mode in ("all", "tail"):
        analyze_tail(names)
    if mode in ("all", "records"):
        analyze_records(names)
    if mode in ("all", "fields"):
        analyze_fields(names)


if __name__ == "__main__":
    main()
