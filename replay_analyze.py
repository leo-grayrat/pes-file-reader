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
  python replay_analyze.py boundary     # 只跑 0x3AA0 分段边界验证（50 样本）
  python replay_analyze.py headseg      # 只跑 0x80~0x3AA0 头部/名单段解析
  python replay_analyze.py frames       # 只跑事件流帧网格验证（660×8112）
  python replay_analyze.py events       # 只跑事件区槽结构解析
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


# ---------- 九、0x3AA0 分段边界验证 ----------
SEG_OFF = 0x3AA0          # exe 写出例程：前段（名单/头部）长度 15,008
SEG_HEAD = 0x3AA0         # 头部/名单段字节数（即事件流起点）
SEG_EVT = 0x51B1C0        # 事件流字节数（5,353,920）


def _ent(seg):
    c = Counter(seg)
    n = len(seg)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def analyze_boundary(names):
    """验证 exe 侧锚点：data 块 = 0x3AA0（名单/头部）+ 0x51B1C0（事件流）。
    检查：① 名单数组 + 全名/队名表是否完整落在 0x3AA0 之内；
          ② 0x3AA0 处是否有结构突变（熵/非零密度/跨样本差异率跳变）；
          ③ 头部 +0x54 是否恒等于 0x3AA0（自洽闭环）。"""
    print("\n" + "=" * 72)
    print("九、分段边界验证：事件流起点 = 0x3AA0（exe 写出例程 0x01FDC500 锚点）")
    print("=" * 72)
    n_ok = seg_eq_54 = 0
    last_nonzero, last_string, last_record = [], [], []
    for nm in names:
        b = load(nm)
        if len(b) != SEG_HEAD + SEG_EVT:
            continue
        n_ok += 1
        if u32(b, 0x54) == SEG_HEAD:
            seg_eq_54 += 1
        head = b[:SEG_OFF]
        nz = [i for i, x in enumerate(head) if x]
        last_nonzero.append(nz[-1] if nz else -1)
        last_string.append(max((o + len(s) for o, s in ascii_strings(head)), default=-1))
        # 名单记录数组最后一条非全零记录（0x80 起 0xA0 步长）
        r = 0
        last_rec = -1
        while 0x80 + r * 0xA0 + 0xA0 <= SEG_OFF:
            off = 0x80 + r * 0xA0
            if any(head[off:off + 0xA0]):
                last_rec = off + 0xA0
            r += 1
        last_record.append(last_rec)
    print(f"  样本数 {len(names)}，满足 len == 0x3AA0+0x51B1C0 = 0x51EC60: {n_ok}/{len(names)}")
    print(f"  头部 +0x54 == 0x3AA0(15008): {seg_eq_54}/{n_ok}")
    print(f"  [0,0x3AA0) 内最后非零字节: max=0x{max(last_nonzero):X}  "
          f"min=0x{min(last_nonzero):X}")
    print(f"  [0,0x3AA0) 内最后 ASCII 串结尾: max=0x{max(last_string):X}")
    print(f"  名单数组最后非零记录尾: max=0x{max(last_record):X}")

    # 结构突变：以 0x3AA0 为中心的滑动窗熵 + 非零密度 + 样本0/1 差异率（样本0）
    b0 = load(names[0])
    print(f"\n  [{names[0]}] 以 0x3AA0 为中心的滑动窗（窗宽 0x100，步长 0x40）:")
    print("    窗口起点   熵     非零%   diff%(vs 样本1)")
    b1 = load(names[1]) if len(names) > 1 else None
    for w in range(SEG_OFF - 0x300, SEG_OFF + 0x340, 0x40):
        seg = b0[w:w + 0x100]
        e = _ent(seg)
        nzp = 100.0 * sum(1 for x in seg if x) / len(seg)
        d = ""
        if b1 is not None:
            s2 = b1[w:w + 0x100]
            dp = 100.0 * sum(1 for i in range(len(seg)) if seg[i] != s2[i]) / len(seg)
            d = f"{dp:5.1f}"
        mark = "  <-- 0x3AA0" if w == SEG_OFF else ""
        print(f"    0x{w:05X}   {e:5.2f}  {nzp:5.1f}   {d}{mark}")

    # 事件流起点跨样本首 64 字节对比（前 4 样本）
    print(f"\n  事件流起点（0x3AA0）跨样本首 64 字节:")
    for nm in names[:4]:
        b = load(nm)
        print(f"    [{nm}] {b[SEG_OFF:SEG_OFF + 32].hex(' ').upper()}")
        print(f"    {' ' * len(nm)}  {b[SEG_OFF + 32:SEG_OFF + 64].hex(' ').upper()}")


# ---------- 十、0x80~0x3AA0 头部/名单段解析 ----------
def analyze_headseg(names):
    """名单数组之外还有什么：扫描 [0,0x3AA0) 内的字符串、小结构、跨样本恒定区。"""
    print("\n" + "=" * 72)
    print("十、0x80~0x3AA0 头部/名单段解析（名单之外：替补？教练？元信息？）")
    print("=" * 72)
    b = load(names[0])
    # 1) 区域内字符串（含小写"扰码"串）
    print(f"\n  [{names[0]}] [0x0,0x3AA0) 内可打印 ASCII 串（长度>=3）:")
    for off, s in ascii_strings(b[:SEG_OFF], minlen=3, min_alpha=2)[:60]:
        print(f"    0x{off:05X}  {s[:64]!r}")
    # 2) 名单记录数：统计非零记录条数与魔数分布（全段）
    print(f"\n  [{names[0]}] [0x80,0x3AA0) 内按 0xA0 步长的记录扫描:")
    mags = Counter()
    used = 0
    for r in range((SEG_OFF - 0x80) // 0xA0):
        off = 0x80 + r * 0xA0
        rec = b[off:off + 0xA0]
        if any(rec):
            used += 1
            mags[u32(b, off)] += 1
    print(f"    非零记录数: {used}/{(SEG_OFF - 0x80) // 0xA0}")
    print(f"    魔数分布: { {f'{m:08X}': c for m, c in mags.most_common(12)} }")
    # 3) 记录数组结束后到 0x3AA0 的区域概览（每 0x100 一行摘要）
    arr_end = 0x80 + 40 * 0xA0  # 已知前 40 条覆盖到 0x1980
    print(f"\n  [{names[0]}] 记录数组尾(0x{arr_end:X})至 0x3AA0 的区域摘要（0x100 步长）:")
    for w in range(arr_end, SEG_OFF, 0x100):
        seg = b[w:w + 0x100]
        nz = sum(1 for x in seg if x)
        top = Counter(seg).most_common(1)[0]
        print(f"    0x{w:05X}  非零 {nz:3d}/256  众数字节 {top[0]:02X}x{top[1]}")
    # 4) 跨样本：[0,0x3AA0) 恒定/变化占比（5 样本）
    subs = [load(nm)[:SEG_OFF] for nm in names[:5]]
    nn = SEG_OFF
    acc_a = int.from_bytes(subs[0], "little")
    acc_o = acc_a
    for s in subs[1:]:
        acc_a &= int.from_bytes(s, "little")
        acc_o |= int.from_bytes(s, "little")
    mask = (acc_a ^ acc_o).to_bytes(nn, "little")
    const = mask.count(0)
    print(f"\n  [0,0x3AA0) 5 样本恒定字节占比: {100.0 * const / nn:.2f}%")
    # 变化 run（找随比赛变化的子区 = 元信息候选）
    runs = []
    i = 0
    while i < nn:
        if mask[i] != 0:
            j = i
            while j < nn and mask[j] != 0:
                j += 1
            if j - i >= 8:
                runs.append((i, j))
            i = j
        else:
            i += 1
    print(f"  变化 run(>=8B) 数: {len(runs)}，前 24 个:")
    for s, e in runs[:24]:
        print(f"    [{s:05X}, {e:05X}) len={e - s}")


# ---------- 十一、事件流帧网格验证 ----------
EVT_HDR_OFF = 0x58        # 头部 +0x58 = 帧大小（8112）
EVT_CNT_OFF = 0x60        # 头部 +0x60 = 帧数（660）
EVT_FRAME = 0x1FB0        # 8112 字节/帧（样本实测恒定）
EVT_NF = 660              # 660 帧（样本实测恒定）
EVT_TBL = 4112            # 帧内：16B 帧头 + 256×16B 状态表(至4112) + 4000B 事件区


def analyze_frames(names):
    """事件流 = 660 帧 × 8112 字节（帧头 +0x58/+0x60 给出，50/50 闭合）。
    帧 = 16B 帧头（含时间戳） + 256×16B 状态表 + 4000B 事件区。"""
    print("\n" + "=" * 72)
    print("十一、事件流帧网格验证：+0x58(帧大小) × +0x60(帧数) == 0x51B1C0")
    print("=" * 72)
    ok = 0
    for nm in names:
        b = load(nm)
        if u32(b, EVT_HDR_OFF) * u32(b, EVT_CNT_OFF) == SEG_EVT:
            ok += 1
    print(f"  闭合样本数: {ok}/{len(names)}（帧大小={u32(load(names[0]), EVT_HDR_OFF)}，"
          f"帧数={u32(load(names[0]), EVT_CNT_OFF)}）")
    b0 = load(names[0])
    ev = b0[SEG_OFF:]
    # 帧时间戳：帧头字节 [1:3] 为 u16 时钟，单调递增，步长 5 或 10（疑与回放倍速/暂停有关）。
    steps = Counter((u16(ev, k * EVT_FRAME + 1) - u16(ev, (k - 1) * EVT_FRAME + 1)) & 0xFFFF
                    for k in range(1, EVT_NF))
    print(f"\n  [{names[0]}] 帧头时钟（字节[1:3] u16）相邻步长分布: {dict(steps)}")
    print(f"  帧0 时钟={u16(ev, 1)}(0x{u16(ev, 1):04X})，帧659 时钟={u16(ev, 659 * EVT_FRAME + 1)}"
          f"（总增量 {((u16(ev, 659 * EVT_FRAME + 1) - u16(ev, 1)) & 0xFFFF)}，"
          f"660帧×5=3300 / ×10=6600，与实际增量对照可推平均步长）")
    # 帧内布局抽样：帧头 + 状态表首 2 条 + 事件区头 16B（前 3 帧）
    print("\n  帧内布局抽样（帧头16B / 表首16B / 事件区头16B）:")
    for k in (0, 1, 2):
        fo = k * EVT_FRAME
        print(f"    帧{k:3d} 帧头   : {ev[fo:fo + 16].hex(' ').upper()}")
        print(f"          表首   : {ev[fo + 16:fo + 32].hex(' ').upper()}")
        print(f"          事件区 : {ev[fo + EVT_TBL:fo + EVT_TBL + 16].hex(' ').upper()}")
    # 事件区头模板：+8..+16 是否恒为 01 00 00...
    c = Counter(ev[k * EVT_FRAME + EVT_TBL + 8:k * EVT_FRAME + EVT_TBL + 16]
                for k in range(EVT_NF))
    print(f"  事件区头 +8~+16 模板分布: {c.most_common(2)}")
    # 帧间差异：表区与事件区各自相同占比（帧0 vs 帧1）
    tbl_same = sum(1 for i in range(16, EVT_TBL)
                   if ev[i] == ev[EVT_FRAME + i])
    evt_same = sum(1 for i in range(EVT_TBL, EVT_FRAME)
                   if ev[i] == ev[EVT_FRAME + i])
    print(f"  帧0 vs 帧1：状态表相同 {100.0 * tbl_same / (EVT_TBL - 16):.1f}%，"
          f"事件区相同 {100.0 * evt_same / (EVT_FRAME - EVT_TBL):.1f}%")


# ---------- 十二、事件区槽结构解析 ----------
def _slot_marks(area):
    """槽标记：00 00 01 XX（2<=XX<=40），返回标记偏移列表。"""
    marks = []
    for j in range(2, len(area) - 1):
        if area[j] == 0x01 and area[j - 1] == 0 and area[j - 2] == 0 \
           and 2 <= area[j + 1] <= 40 and area[j + 1] != 1:
            marks.append(j)
    return marks


def analyze_events(names, npack=100):
    """事件区（帧内 +4112 起 4000 字节）内为每帧 ~10 个球员槽包：
    槽标记 01 XX（槽号 12~21），间距恒 300 字节；
    槽 = 12B 头 + 20×i16 小整数（疑动画/姿态码） + 高熵 blob（约150B，疑压缩/加密轨迹）。"""
    print("\n" + "=" * 72)
    print("十二、事件区槽结构解析（前 %d 个槽包）" % npack)
    print("=" * 72)
    b0 = load(names[0])
    ev = b0[SEG_OFF:]
    # 1) 槽数与槽号跨帧统计（样本0 抽样 20 帧）
    print(f"\n  (1) [{names[0]}] 槽数跨帧抽样:")
    for k in range(0, EVT_NF, 66):
        area = ev[k * EVT_FRAME + EVT_TBL:k * EVT_FRAME + EVT_FRAME]
        marks = _slot_marks(area)
        ids = [area[m + 1] for m in marks]
        gaps = [marks[i + 1] - marks[i] for i in range(len(marks) - 1)]
        print(f"    帧{k:3d}: 槽数 {len(marks)}，槽号 {ids}，间距 {Counter(gaps).most_common(2)}")
    # 2) 前 npack 个槽包切分与候选解读（跨帧收集）
    packs = []
    k = 0
    while len(packs) < npack and k < EVT_NF:
        area = ev[k * EVT_FRAME + EVT_TBL:k * EVT_FRAME + EVT_FRAME]
        for m in _slot_marks(area):
            packs.append((k, m, area))
        k += 1
    print(f"\n  (2) 前 {min(npack, len(packs))} 个槽包切分（帧号, 槽号, 12B头, 20×i16 前10个）:")
    print("      槽间距恒 300 字节 → 每槽 = 12B头 + 20×i16(40B) + 约248B 高熵 blob")
    for idx, (fk, m, area) in enumerate(packs[:npack]):
        slot = area[m:]
        sid = slot[1]
        i16s = struct.unpack_from("<10h", slot, 12)
        print(f"    #{idx:3d} 帧{fk:3d} 槽{sid:2d} 头={slot[:12].hex(' ')} "
              f"i16={list(i16s)}")
    # 3) 同一槽跨帧对比（说明 i16 码随帧变化 = 逐帧姿态数据）
    print("\n  (3) 槽 12 跨帧 i16 对比（帧0/1/2）:")
    for fk in (0, 1, 2):
        area = ev[fk * EVT_FRAME + EVT_TBL:fk * EVT_FRAME + EVT_FRAME]
        for m in _slot_marks(area):
            if area[m + 1] == 12:
                i16s = struct.unpack_from("<10h", area, m + 12)
                print(f"    帧{fk}: {list(i16s)}")
                break
    # 4) 跨样本槽结构一致性（前 4 样本帧0）
    print("\n  (4) 跨样本帧0 槽结构:")
    for nm in names[:4]:
        b = load(nm)
        area = b[SEG_OFF + EVT_TBL:SEG_OFF + EVT_FRAME]
        marks = _slot_marks(area)
        print(f"    [{nm[-12:]}] 槽数 {len(marks)}，槽号 {[area[m + 1] for m in marks]}")
    # 5) 事件区头字段统计（样本0 全帧）
    c0 = Counter(u16(ev, k * EVT_FRAME + EVT_TBL) for k in range(EVT_NF))
    c2 = Counter(u16(ev, k * EVT_FRAME + EVT_TBL + 2) for k in range(EVT_NF))
    print(f"\n  (5) 事件区头字段分布（样本0 660 帧）: "
          f"u16@+0 top3={c0.most_common(3)}, u16@+2 top3={c2.most_common(3)}")


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
    if mode in ("all", "boundary"):
        analyze_boundary(names)
    if mode in ("all", "headseg"):
        analyze_headseg(names)
    if mode in ("all", "frames"):
        analyze_frames(names)
    if mode in ("all", "events"):
        analyze_events(names)


if __name__ == "__main__":
    main()
