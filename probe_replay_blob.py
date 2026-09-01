#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""回放事件流槽内 248B 高熵 blob 的内部结构分析（HANDOFF_v3 §7.1 / replay_structure §6 的下一步）。

已知（replay_zlib.py / §6）：
  blob 非 zlib/gzip/deflate、非强加密；首 4 字节含明文递增计数器；相邻帧异或熵 3.87（强相关）。
  推断 = 「明文计数器头 + 运动数据（delta / 轻度线性变换）」。

本脚本对槽 12 跨 660 帧的 blob 序列做：
  (1) 头部计数器分析：确定头长 H（前 H 字节为计数器/标志，之后为运动体）。
  (2) 运动体逐偏移稳定字节（找 float32 指数位 / 固定标志）。
  (3) 运动体跨帧异或熵（验证强相关）。
  (4) 运动体按 float32(LE) / int16(LE) 重解，报值域与"合理坐标"占比。
  (5) 运动体每 4 字节组的跨帧 |delta| 均值（小 delta = 平滑坐标列）。
纯只读。用法：python probe_replay_blob.py
"""
import math, struct
from collections import Counter

SEG_OFF = 0x3AA0
EVT_FRAME = 8112
EVT_TBL = 4112          # 帧内 +0x1010 事件区起点
BLOB_OFF_IN_SLOT = 52   # 槽头12B + 20×i16(40B) = 52，blob 起点
BLOB_LEN = 248         # 槽尾 248B


def load(name):
    with open(f"decoded/{name}.data", "rb") as f:
        return f.read()


def slot_starts(area):
    """返回事件区内所有槽起点 m（area[m]==1, area[m-1]==0, area[m-2]==0, area[m+1]∈[2,40]）。"""
    out = []
    for j in range(2, len(area) - 1):
        if area[j] == 1 and area[j - 1] == 0 and area[j - 2] == 0 and 2 <= area[j + 1] <= 40:
            out.append(j)
    return out


def entropy(b):
    from collections import Counter
    c = Counter(b)
    n = len(b)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def main():
    b = load("REPLAY00000000")
    assert len(b) == 0x51EC60, len(b)
    ev = b[SEG_OFF:]

    # 收集槽 12 跨 660 帧的 blob
    blobs = []
    for k in range(660):
        area = ev[k * EVT_FRAME + EVT_TBL: k * EVT_FRAME + EVT_FRAME]
        m12 = None
        for m in slot_starts(area):
            if area[m + 1] == 12:
                m12 = m
                break
        if m12 is None:
            continue
        blob = area[m12 + BLOB_OFF_IN_SLOT: m12 + BLOB_OFF_IN_SLOT + BLOB_LEN]
        if len(blob) == BLOB_LEN:
            blobs.append(blob)
    print(f"槽12 blob 序列帧数 = {len(blobs)}")
    if not blobs:
        return

    # ---- (1) 头部计数器：逐字节看前 16 字节跨帧 ----
    print("\n=== (1) 头部计数器（前 16 字节，抽 8 帧）===")
    for k in (0, 1, 2, 3, 100, 300, 500, 659):
        if k < len(blobs):
            print(f"  帧{k:3d}: {blobs[k][:16].hex(' ')}")
    # 逐字节 0..7 的跨帧值域与单调性
    print("  逐字节(0..7) 跨帧 min/max/是否单调:")
    for off in range(8):
        col = [bl[off] for bl in blobs]
        mn, mx = min(col), max(col)
        # 单调性：相邻递增/递减占比
        inc = sum(1 for i in range(1, len(col)) if col[i] >= col[i-1])
        dec = sum(1 for i in range(1, len(col)) if col[i] <= col[i-1])
        print(f"    b{off}: min={mn:3d} max={mx:3d} inc%={100*inc/(len(col)-1):.0f} dec%={100*dec/(len(col)-1):.0f}")

    # ---- 确定头长 H：找首个"非单调计数器"的字节 ----
    # 用 b0..b3 通常构成计数器；这里取 H=4（保守），并对 body=blob[4:] 分析
    H = 4
    body = [bl[H:] for bl in blobs]          # 每帧 244 字节
    body_arr = bytes().join(body) if False else body

    # ---- (3) 运动体跨帧异或熵 ----
    print("\n=== (3) 运动体(头部后)跨帧 XOR 熵 ===")
    xors = []
    for i in range(1, len(body)):
        x = bytes(a ^ c for a, c in zip(body[i - 1], body[i]))
        xors.append(entropy(x))
    print(f"  平均跨帧 XOR 熵 = {sum(xors)/len(xors):.3f}（§6 报告 3.87，越低越相关）")
    # 首帧 vs 末帧整体异或熵
    full = bytes(a ^ c for a, c in zip(body[0], body[-1]))
    print(f"  首帧vs末帧 XOR 熵 = {entropy(full):.3f}")

    # ---- (2) 逐偏移稳定字节 ----
    print("\n=== (2) 运动体逐偏移稳定字节（找 float32 指数位 / 固定标志）===")
    L = len(body[0])
    modes = []
    frac_const = []
    for off in range(L):
        col = [fr[off] for fr in body]
        from collections import Counter
        c = Counter(col)
        mode, cnt = c.most_common(1)[0]
        modes.append(mode)
        frac_const.append(cnt / len(col))
    # 报告最稳定的 12 个偏移
    order = sorted(range(L), key=lambda o: -frac_const[o])[:12]
    print("  最稳定偏移(top12): off=模式值(占比%)")
    for o in order:
        print(f"    +{H+o:3d}: 0x{modes[o]:02X} ({100*frac_const[o]:.0f}%)")
    # float32 指数位假设：高字节(LE 第3字节) 多为 0x42/0x43/0xC2/0xC3（值±32..±256）
    exp_bytes = [fr[3] for fr in [fr[4*i:4*(i+1)] for i in range(L//4)] ] if False else None
    # 直接统计每 4 字节组的高字节分布
    hi_counter = {}
    for i in range(0, L - 3, 4):
        hi = bytes([fr[i+3] for fr in body])
        from collections import Counter as C2
        for v in set(hi):
            hi_counter[v] = hi_counter.get(v, 0) + 1
    print("  float32(LE)高字节(第4字节) 取值计数:", dict(sorted(hi_counter.items(), key=lambda kv:-kv[1])[:8]))

    # ---- (4) float32 / int16 重解 ----
    print("\n=== (4) 运动体 float32(LE) / int16(LE) 重解 ===")
    def float_stats(sl_off):
        vals = []
        for fr in body:
            chunk = fr[sl_off:sl_off+4]
            if len(chunk) < 4: continue
            v = struct.unpack("<f", chunk)[0]
            if math.isfinite(v):
                vals.append(v)
        if not vals: return None
        plaus = sum(1 for v in vals if abs(v) < 300)
        return min(vals), max(vals), sum(vals)/len(vals), 100*plaus/len(vals)
    # 在所有 4 字节对齐起点试 float32
    best = None
    for sl in range(0, L - 3, 4):
        s = float_stats(sl)
        if s and (best is None or s[3] > best[1]):
            best = (sl, s[3], s)
    print(f"  float32 最合理起点(对齐): off=+{H+best[0]} 合理坐标占比={best[2][3]:.0f}% min={best[2][0]:.1f} max={best[2][1]:.1f} mean={best[2][2]:.1f}")
    # int16 重解（全偏移）
    def int16_stats(sl_off):
        vals = []
        for fr in body:
            for j in range(sl_off, sl_off+4, 2):
                if j+2 <= len(fr):
                    vals.append(struct.unpack("<h", fr[j:j+2])[0])
        if not vals: return None
        return min(vals), max(vals), sum(vals)/len(vals)
    bi = None
    for sl in range(0, L - 1, 2):
        s = int16_stats(sl)
        if s and (bi is None or (s[1]-s[0]) < (bi[1][1]-bi[1][0])):
            bi = (sl, s)
    print(f"  int16 最窄起点(对齐): off=+{H+bi[0]} min={bi[1][0]} max={bi[1][1]} mean={bi[1][2]:.1f}")

    # ---- (5) 每 4 字节组跨帧 |delta| 均值 ----
    print("\n=== (5) 运动体每 4 字节组跨帧 |delta| 均值（小=平滑坐标列）===")
    deltas = []
    for i in range(0, L - 3, 4):
        ds = []
        for fr_i in range(1, len(body)):
            a = struct.unpack("<f", body[fr_i-1][i:i+4])[0]
            c = struct.unpack("<f", body[fr_i][i:i+4])[0]
            if math.isfinite(a) and math.isfinite(c):
                ds.append(abs(a - c))
        deltas.append((i, sum(ds)/len(ds) if ds else 1e9))
    deltas.sort(key=lambda x: x[1])
    print("  最平滑(小delta)的 10 个 float32 组 (off, 均|Δ|):")
    for o, d in deltas[:10]:
        print(f"    +{H+o:3d}: mean|Δ|={d:.3f}")
    smooth = sum(1 for _, d in deltas if d < 5.0)
    print(f"  float32 组均|Δ|<5.0 的个数 = {smooth} / {len(deltas)}（坐标列特征）")


if __name__ == "__main__":
    main()
