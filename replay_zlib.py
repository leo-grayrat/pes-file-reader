#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
replay_zlib.py —— 回放事件流槽内 248B 高熵 blob 的编码检测

目标：判定 blob 是 zlib/deflate 压缩、gzip、还是自定义加密/delta 编码。
槽结构（docs/replay_structure.md 1.6）：事件区(帧内 +4112 起 4000B)内每帧 ~10 个槽，
每槽 = 12B 头 + 20×i16(40B) + 248B 高熵 blob，槽间距 300B。

用法：python replay_zlib.py
"""
import zlib
import math
import struct
from collections import Counter

SEG_OFF = 0x3AA0
EVT_FRAME = 8112
EVT_TBL = 4112


def load(name):
    with open(f"decoded/{name}.data", "rb") as f:
        return f.read()


def slot_marks(area):
    marks = []
    for j in range(2, len(area) - 1):
        if area[j] == 1 and area[j - 1] == 0 and area[j - 2] == 0 \
           and 2 <= area[j + 1] <= 40:
            marks.append(j)
    return marks


def entropy(blob):
    c = Counter(blob)
    n = len(blob)
    return -sum((cnt / n) * math.log2(cnt / n) for cnt in c.values())


def main():
    b = load("rep_REPLAY00000000")
    ev = b[SEG_OFF:]
    blobs = []
    first_byte = Counter()
    for k in range(660):
        area = ev[k * EVT_FRAME + EVT_TBL:k * EVT_FRAME + EVT_FRAME]
        for m in slot_marks(area):
            blob = area[m + 52:m + 300]
            if len(blob) < 240:
                continue
            blobs.append(blob)
            first_byte[blob[0]] += 1
    print(f"blob 总数 = {len(blobs)}")
    print(f"首字节分布 top12 = {first_byte.most_common(12)}")
    # 0x78 = zlib 魔数
    print(f"其中 0x78 开头的 blob = {first_byte[0x78]} / {len(blobs)}")

    entropies = [entropy(bl) for bl in blobs]
    print(f"blob 熵：平均 {sum(entropies)/len(entropies):.3f}，最小 {min(entropies):.3f}，最大 {max(entropies):.3f}")

    # 尝试解压：zlib / raw-deflate / gzip，用前 40 个 blob 各试一次
    print("\n=== 解压尝试（前 40 个 blob）===")
    ok = {"zlib": 0, "raw": 0, "gzip": 0}
    sample_out = None
    for bl in blobs[:40]:
        for name, wbits in (("zlib", 15), ("raw", -15), ("gzip", 31)):
            try:
                out = zlib.decompress(bl, wbits)
                ok[name] += 1
                if sample_out is None:
                    sample_out = out
            except Exception:
                pass
    for k, v in ok.items():
        print(f"  {k}: 成功 {v}/40")
    if sample_out:
        print(f"  第一个成功解压输出: {len(sample_out)} 字节，前 32 字节 hex = {sample_out[:32].hex(' ')}")

    # 同槽跨帧：槽号 12 跨帧的 blob 首字节 + 差分熵（判断是否流式加密）
    print("\n=== 槽12 跨帧 blob 分析 ===")
    prev = None
    same_bytes = 0
    for k in range(5):
        area = ev[k * EVT_FRAME + EVT_TBL:k * EVT_FRAME + EVT_FRAME]
        m12 = None
        for m in slot_marks(area):
            if area[m + 1] == 12:
                m12 = m
                break
        if m12 is None:
            continue
        blob = area[m12 + 52:m12 + 300]
        print(f"  帧{k}: 首4字节={blob[:4].hex(' ')}, 熵={entropy(blob):.3f}")
        if prev is not None:
            x = bytes(a ^ bb for a, bb in zip(prev, blob))
            print(f"        vs 上一帧异或熵={entropy(x):.3f}")
            same = sum(1 for a, bb in zip(prev, blob) if a == bb)
            same_bytes += same
        prev = blob


if __name__ == "__main__":
    main()