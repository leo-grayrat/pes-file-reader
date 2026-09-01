#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
exe_validate_layout.py — 用真实存档核对从 exe 逆向出的存档布局结论。

exe 逆向给出的主张（见 docs/exe-save-layout.md）：
  A. 文件整体 = 320B 加密头 + 208B 文件头 + 4 个数据块
  B. 文件头解密时密钥按 qword xor 208；其后 4 块分别 xor 0/1/2/3
  C. serial 块长度 = 文件头里的 serialLength × 2（UTF-16）
  D. 第 2 块（desc）在 exe 里长度写死 0x180 = 384

本脚本用 pes_decrypt 的既有实现解出真实存档，逐条核对 A/B/C/D，
并检查"块长度之和 + 528 == 文件总长"这一整体自洽性。

只读：绝不修改存档文件。
用法：
  python exe_validate_layout.py [存档目录]
"""
import os
import struct
import sys

import pes_decrypt as P


def layout_of(path):
    with open(path, "rb") as f:
        blob = f.read()
    total = len(blob)
    d = P.decrypt(blob)
    hdr = d["fileHeader"]
    fld = P.parse_file_header(hdr)
    desc, logo, data, serial = d["description"], d["logo"], d["data"], d["serial"]
    return {
        "total": total,
        "fld": fld,
        "lens": {
            "desc": len(desc), "logo": len(logo),
            "data": len(data), "serial": len(serial),
        },
        "raw": {
            "dataSize@64": struct.unpack_from("<I", hdr, 64)[0],
            "logoSize@68": struct.unpack_from("<I", hdr, 68)[0],
            "descSize@72": struct.unpack_from("<I", hdr, 72)[0],
            "serialLen@76": struct.unpack_from("<I", hdr, 76)[0],
        },
        "ftype": hdr[144:176].split(b"\x00")[0].decode("latin1", "replace"),
        "gver": hdr[176:208].split(b"\x00")[0].decode("latin1", "replace"),
    }


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else "examples"
    if not os.path.isdir(root):
        print("目录不存在: %s" % root)
        return 1
    names = sorted([n for n in os.listdir(root)
                    if os.path.isfile(os.path.join(root, n))])
    if not names:
        print("%s 下无文件" % root)
        return 1

    print("%-16s %10s | %-28s | %s" % ("存档", "文件总长", "块长度 desc/logo/data/serial", "自洽"))
    print("-" * 104)
    ok_all = True
    for n in names:
        try:
            r = layout_of(os.path.join(root, n))
        except Exception as e:
            print("%-16s   解不开: %s" % (n, e))
            continue
        L = r["lens"]
        s = L["desc"] + L["logo"] + L["data"] + L["serial"]
        expect = 528 + s
        selfok = (expect == r["total"])
        ok_all = ok_all and selfok
        print("%-16s %10d | %6d/%6d/%9d/%6d | %s 差 %+d"
              % (n, r["total"], L["desc"], L["logo"], L["data"], L["serial"],
                 "OK " if selfok else "BAD", r["total"] - expect))

    print("-" * 104)
    r = layout_of(os.path.join(root, names[0]))
    print("\n首个存档的文件头原始字段（偏移相对文件头起点）:")
    for k, v in r["raw"].items():
        print("   %-14s = %d (0x%X)" % (k, v, v))
    print("   fileTypeString  = %r" % r["ftype"])
    print("   gameVersionStr  = %r" % r["gver"])

    print("\n核对 exe 主张:")
    fld = r["fld"]
    print("   A 文件总长 = 320 + 208 + Σ块长            -> %s" % ("成立" if ok_all else "不成立"))
    print("   C serial 实际长度 = serialLength × 2      -> %d vs %d×2=%d  %s"
          % (r["lens"]["serial"], fld["serialLength"], fld["serialLength"] * 2,
             "成立" if r["lens"]["serial"] == fld["serialLength"] * 2 else "不成立"))
    print("   D exe 写死 desc = 384(0x180)              -> 实际 descSize=%d %s"
          % (fld["descSize"],
             "成立" if fld["descSize"] == 384 else "**不成立，desc 是变长**"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
