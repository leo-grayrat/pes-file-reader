#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
probe_block_hashes.py — 定位存档内「逐块 SHA-512 期望摘要表」的物理位置。

背景（docs/exe-save-layout.md §7 + 本轮新证据）：
    decrypt_main(0x14115F0) 对每块（desc/logo/data/serial）明文现算 SHA-512：
        0x14118E0  lea rcx,[rbp+0x2a0] ; call 0x140d660    ; ctx 初始化
        0x14118FE  call 0x1413950                          ; update(喂入器)
        0x1411911  call 0x1413cb0                          ; final(初始化器名,实为收尾)
    随后：
        0x1411916  mov rax,[rbp-0x70]                      ; 块索引 i
        0x141191A  shl rax,6                               ; i × 64
        0x141191E  lea rdx,[rbp+0x160] ; add rdx,rax       ; 期望表 + i*64
        0x1411928  mov r8d,0x40
        0x1411935  call 0x15a2f56                          ; memcmp(ctx, expect+i*64, 64)
    ⇒ 存在一张 4×64 = 256B 的期望摘要表。但 [rbp+0x160] 在整函数内**只被读、从未被写**，
      故它必然来自存档自身（否则无法跨会话防篡改）。

本脚本做的事：在真实存档上算每块的 SHA-512（含常见字节序变体），
在全部明文区域里搜索这 64 字节，定位期望摘要表的物理偏移。

只读：仅读取 examples/，不写任何存档、不执行游戏代码。

用法：
  python exe/probe_block_hashes.py [样本名...]
  默认：BL00000000 EDIT00000000 ML00000000
"""
import hashlib
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE, "core"))
import pes_decrypt as P  # noqa: E402


def sha512_variants(b: bytes) -> dict:
    """标准 SHA-512 摘要 + 常见字节序变体。"""
    d = hashlib.sha512(b).digest()
    return {
        "std": d,
        "rev_all": d[::-1],
        "rev_qwords": b"".join(d[i:i + 8][::-1] for i in range(0, 64, 8)),
    }


def search(needle: bytes, regions: dict) -> list:
    """在若干命名区域里搜 needle，返回 [(区域名, 区内偏移)]。"""
    hits = []
    for name, blob in regions.items():
        start = 0
        while True:
            i = blob.find(needle, start)
            if i < 0:
                break
            hits.append((name, i))
            start = i + 1
    return hits


def verify(d: dict) -> list:
    """按「encHeader[0:256] = 四块 SHA-512 摘要表」逐块核对，返回 [(块名, 是否一致)]。"""
    eh = d["encHeader"]
    blocks = [
        ("desc", d["description"], 0x00),
        ("logo", d["logo"], 0x40),
        ("data", d["data"], 0x80),
        ("serial", d["serial"], 0xC0),
    ]
    out = []
    for name, bdata, off in blocks:
        dig = hashlib.sha512(bdata).digest()
        out.append((name, dig == eh[off:off + 64]))
    return out


DO_SEARCH = False


def main():
    global DO_SEARCH
    DO_SEARCH = "--search" in sys.argv
    args = [a for a in sys.argv[1:] if not a.startswith("--")]

    if "--all" in sys.argv:
        names = []
        for sub in ("", "rep"):
            ex = os.path.join(BASE, "examples", sub)
            if os.path.isdir(ex):
                names += sorted(os.path.join(sub, f) for f in os.listdir(ex)
                                if os.path.isfile(os.path.join(ex, f)))
        names.sort()
    else:
        names = args or ["BL00000000", "EDIT00000000", "ML00000000"]

    print("=%d 个样本；核对规则 encHeader[0:256] == 四块 SHA-512（desc/logo/data/serial）"
          % len(names))
    ok_all = True
    for nm in names:
        path = os.path.join(BASE, "examples", nm)
        if not os.path.exists(path):
            print("!! 缺少样本 %s" % path)
            continue
        if not DO_SEARCH:
            print("%-28s" % nm, end="", flush=True)

        with open(path, "rb") as f:
            blob = f.read()
        d = P.decrypt(blob)
        hdr = d["hdr"]

        # 核对：encHeader[0:256] 是否 == 四块 SHA-512 摘要表
        res = verify(d)
        bad = [n for n, ok in res if not ok]
        if bad:
            ok_all = False
        tag = "ALL-OK" if not bad else "MISMATCH[%s]" % ",".join(bad)

        if not DO_SEARCH:
            print(" %-14s %s" % (tag, d["description"].split(b"\x00")[0].decode("utf-8", "replace")))
            continue

        print("=" * 78)
        print("样本 %s（%d 字节，consumed=%d）"
              % (nm, len(blob), d["consumed"]))
        print("  data=%d logo=%d desc=%d serial=%dB"
              % (hdr["dataSize"], hdr["logoSize"], hdr["descSize"],
                 hdr["serialLength"] * 2))
        print("  摘要核对: %s" % tag)

        if DO_SEARCH:
            blocks = [
                ("desc", d["description"]),
                ("logo", d["logo"]),
                ("data", d["data"]),
                ("serial", d["serial"]),
            ]
            # 搜索区域 = 全部明文（含 encHeader 明文、fileHeader、四块）
            regions = {
                "encHeader": d["encHeader"],
                "fileHeader": d["fileHeader"],
                "desc": d["description"],
                "logo": d["logo"],
                "data": d["data"],
                "serial": d["serial"],
            }
            any_hit = False
            for bname, bdata in blocks:
                for vname, dig in sha512_variants(bdata).items():
                    hits = search(dig, regions)
                    if hits:
                        any_hit = True
                        print("  [命中] SHA512(%s) 变体=%s → %s"
                              % (bname, vname,
                                 ", ".join("%s+0x%X" % (r, o) for r, o in hits)))
            if not any_hit:
                print("  （标准 SHA-512 三种字节序变体在全部明文区中均无命中）")

        # 附加诊断：desc 尾部结构（desc 384B 里除名字外是什么）
        desc = d["description"]
        nz = [i for i, c in enumerate(desc) if c != 0]
        print("  desc: 非零字节 %d 个，末个非零位 0x%X；尾部 256B 非零=%d"
              % (len(nz), nz[-1] if nz else -1, sum(1 for c in desc[128:] if c)))

    print("=" * 78)
    print("全部样本摘要核对：%s" % ("全部一致 ✓" if ok_all else "存在不一致 ✗"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
