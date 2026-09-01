#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""logo 块 = PNG 缩略图（228x128, 8-bit, RGB）。解出并写出确认。

复用 pes_decrypt.decrypt 得 logo 块；解析 IHDR；zlib 解 IDAT 验证；
把三档 logo 原样写出 outputs/logo_*.png 供肉眼核对。
"""
import os, struct, zlib
from pes_decrypt import decrypt

EX_DIR = "examples"
OUT = "outputs"

def ihdr(b):
    assert b[:8] == bytes.fromhex("89504e470d0a1a0a"), "not PNG"
    # 第一个 chunk 应为 IHDR
    ln = struct.unpack_from(">I", b, 8)[0]
    assert b[12:16] == b"IHDR", "first chunk not IHDR"
    w, h = struct.unpack_from(">II", b, 16)
    bitd, colt, comp, filt, inter = b[24], b[25], b[26], b[27], b[28]
    return dict(len=ln, width=w, height=h, bit_depth=bitd, color_type=colt,
                compression=comp, filter=filt, interlace=inter)

def collect_idat(b):
    pos = 8
    idat = b""
    chunks = []
    while pos < len(b):
        ln = struct.unpack_from(">I", b, pos)[0]
        typ = b[pos+4:pos+8]
        data = b[pos+8:pos+8+ln]
        chunks.append((typ.decode("latin1"), ln))
        if typ == b"IDAT":
            idat += data
        pos += 12 + ln
        if typ == b"IEND":
            break
    return idat, chunks

def main():
    os.makedirs(OUT, exist_ok=True)
    for name in ["BL00000000", "EDIT00000000", "ML00000000"]:
        path = os.path.join(EX_DIR, name)
        blob = open(path, "rb").read()
        r = decrypt(blob)
        logo = r["logo"]
        h = ihdr(logo)
        idat, chunks = collect_idat(logo)
        raw = zlib.decompress(idat)
        # RGB 无 alpha: 每行 = width*3 + 1(filter byte)
        expected = h["height"] * (h["width"] * 3 + 1)
        out = os.path.join(OUT, f"logo_{name}.png")
        open(out, "wb").write(logo)
        ct = {0:"灰度",2:"RGB真彩",3:"调色板",4:"灰度+alpha",6:"RGBA"}[h["color_type"]]
        print(f"{name}: {h['width']}x{h['height']} bit{h['bit_depth']} {ct} "
              f"interlace={h['interlace']} chunks={chunks} "
              f"IDAT解压={len(raw)}B(期望{expected}={'OK' if len(raw)==expected else 'MISMATCH'}) "
              f"-> {out}")

if __name__ == "__main__":
    main()
