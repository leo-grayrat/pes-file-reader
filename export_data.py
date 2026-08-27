#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把 examples 下所有存档解密后的 data 块导出到 decoded/（中间产物，供逆向分析）。"""
import os
import glob
import json
import pes_decrypt as p

BASE = os.path.dirname(os.path.abspath(__file__))
EX_DIR = os.path.join(BASE, "examples")
OUT = os.path.join(BASE, "decoded")
os.makedirs(OUT, exist_ok=True)


def main():
    import sys
    files = []
    files += glob.glob(os.path.join(EX_DIR, "BL*"))
    files += glob.glob(os.path.join(EX_DIR, "ML*"))
    files += glob.glob(os.path.join(EX_DIR, "rep", "REPLAY*"))

    # 可选：只导出指定文件（传相对 examples 的路径，如 BL00000000 rep/REPLAY00000000）
    if len(sys.argv) > 1:
        wanted = set(sys.argv[1:])
        files = [f for f in files if os.path.relpath(f, EX_DIR).replace(os.sep, "_") in wanted
                 or os.path.basename(f) in wanted
                 or os.path.relpath(f, EX_DIR) in wanted]

    headers = {}
    for f in sorted(files):
        blob = open(f, "rb").read()
        r = p.decrypt(blob)
        name = os.path.relpath(f, EX_DIR).replace(os.sep, "_")
        out_path = os.path.join(OUT, name + ".data")
        with open(out_path, "wb") as w:
            w.write(r["data"])
        headers[name] = {
            "fileType": p._clean(r["hdr"]["fileTypeString"]),
            "gameVersion": p._clean(r["hdr"]["gameVersionString"]),
            "dataSize": r["hdr"]["dataSize"],
            "logoSize": r["hdr"]["logoSize"],
            "descSize": r["hdr"]["descSize"],
            "serialLength": r["hdr"]["serialLength"],
        }
        print(f"{name:26s} -> {out_path}  {headers[name]}")

    with open(os.path.join(OUT, "_headers.json"), "w", encoding="utf-8") as w:
        json.dump(headers, w, indent=2, ensure_ascii=False)
    print(f"\n已导出 {len(files)} 个 data 块到 decoded/，头信息写入 decoded/_headers.json")


if __name__ == "__main__":
    main()