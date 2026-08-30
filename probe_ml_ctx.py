#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""probe_ml_ctx.py -- 取若干已知球员(队#0 阵容前几名), 列出其 id 在 ML 全文件所有出现位置,
dump 上下文(32B前+96B后), 标注是否在队块, 用于肉眼定位 per-player 哈希表记录结构。
"""
import os, sys, array, struct, collections
BASE = os.path.dirname(os.path.abspath(__file__))
DEC = os.path.join(BASE, "decoded")
TB_OFF = 0x100
TB_SIZE = 0x690
N_TEAMS = 700


def in_teamblock(off):
    if TB_OFF <= off < TB_OFF + N_TEAMS * TB_SIZE:
        r = (off - TB_OFF) // TB_SIZE
        return r
    return None


def main():
    stem = sys.argv[1] if len(sys.argv) > 1 else "ML00000000"
    # 队#0 阵容前几名(已知 EDIT id)
    pids = [int(x) for x in sys.argv[2:]] or [45144, 109571, 111207, 109571]
    d = open(os.path.join(DEC, stem + ".data"), "rb").read()
    a = array.array("I"); a.frombytes(d[:len(d)//4*4])
    idset = set(pids)
    # 收集出现位置(按 id)
    occ = collections.defaultdict(list)
    for i, v in enumerate(a):
        if v in idset:
            occ[v].append(i * 4)
    for pid in pids:
        print(f"\n===== player_id={pid}: {len(occ[pid])} 处出现 =====")
        for off in occ[pid]:
            tb = in_teamblock(off)
            loc = f"队块#{tb}(+0x{off-TB_OFF-tb*TB_SIZE:X})" if tb is not None else f"队块外"
            ctx_before = d[off-32:off]
            ctx_after = d[off:off+96]
            au = [struct.unpack_from("<I", ctx_after, j)[0] for j in range(0, 96, 4)]
            print(f"  @0x{off:X} [{loc}]")
            print(f"    before: {ctx_before.hex()}")
            print(f"    rec 0: {struct.unpack_from('<I', d, off)[0]}  after u32: {au}")


if __name__ == "__main__":
    main()
