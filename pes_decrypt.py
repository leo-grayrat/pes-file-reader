#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PES 存档解密器（Python 实现）。

算法与密钥来源于公开项目 the4chancup/pesXdecrypter（public domain / zlib 许可），
本文件仅用于对用户自有存档样例做只读解析与验证。

加密架构（PES2016-2021）：
  文件 = 320 字节加密头 + 208 字节文件头 + description + logo + data + serial
  加密方式 = MT19937 流加密 + 链式滚动密钥
"""
import os
import sys
import struct

BASE = os.path.dirname(os.path.abspath(__file__))
EX_DIR = os.path.join(BASE, "examples")

ENCRYPTION_HEADER_SIZE = 320
FILE_HEADER_SIZE = 208  # PES18+ (含 gameVersionString[32])

# ---- PES2021 主密钥（公开自 pesXdecrypter） ----
MASTERKEY_PES21 = bytes([
    0x90, 0x61, 0xD8, 0x66, 0x43, 0x77, 0x24, 0xF8,
    0x92, 0xBA, 0xB8, 0x71, 0x21, 0xC7, 0x60, 0x63,
    0xF0, 0x91, 0x9A, 0x7D, 0xED, 0x47, 0x80, 0xDE,
    0x51, 0xF5, 0xDD, 0xD1, 0x08, 0xFE, 0x32, 0x84,
    0xF5, 0x09, 0x92, 0x00, 0xB2, 0x3E, 0x88, 0x9F,
    0xEB, 0x24, 0x43, 0x05, 0x58, 0x76, 0x00, 0x22,
    0x9B, 0xFE, 0xEC, 0xF6, 0x50, 0x00, 0x29, 0xD3,
    0x42, 0x75, 0x50, 0xB9, 0xEC, 0xD2, 0xF6, 0x75,
])


# ---- MT19937 (标准实现) ----
N = 624
M = 397
MATRIX_A = 0x9908b0df
UPPER_MASK = 0x80000000
LOWER_MASK = 0x7fffffff


class MT19937:
    def __init__(self):
        self.mt = [0] * N
        self.mti = N + 1

    def init_genrand(self, s):
        self.mt[0] = s & 0xffffffff
        for mti in range(1, N):
            self.mt[mti] = (1812433253 * (self.mt[mti - 1] ^ (self.mt[mti - 1] >> 30)) + mti) & 0xffffffff
        self.mti = N

    def init_by_array(self, init_key, key_length):
        self.init_genrand(19650218)
        i, j = 1, 0
        k = N if N > key_length else key_length
        while k:
            self.mt[i] = (self.mt[i] ^ ((self.mt[i - 1] ^ (self.mt[i - 1] >> 30)) * 1664525)) + init_key[j] + j
            self.mt[i] &= 0xffffffff
            i += 1
            j += 1
            if i >= N:
                self.mt[0] = self.mt[N - 1]
                i = 1
            if j >= key_length:
                j = 0
            k -= 1
        k = N - 1
        while k:
            self.mt[i] = (self.mt[i] ^ ((self.mt[i - 1] ^ (self.mt[i - 1] >> 30)) * 1566083941)) - i
            self.mt[i] &= 0xffffffff
            i += 1
            if i >= N:
                self.mt[0] = self.mt[N - 1]
                i = 1
            k -= 1
        self.mt[0] = 0x80000000

    def genrand_int32(self):
        mag01 = [0x0, MATRIX_A]
        if self.mti >= N:
            if self.mti == N + 1:
                self.init_genrand(5489)
            kk = 0
            while kk < N - M:
                y = (self.mt[kk] & UPPER_MASK) | (self.mt[kk + 1] & LOWER_MASK)
                self.mt[kk] = (self.mt[kk + M] ^ (y >> 1) ^ mag01[y & 1]) & 0xffffffff
                kk += 1
            while kk < N - 1:
                y = (self.mt[kk] & UPPER_MASK) | (self.mt[kk + 1] & LOWER_MASK)
                self.mt[kk] = (self.mt[kk + (M - N)] ^ (y >> 1) ^ mag01[y & 1]) & 0xffffffff
                kk += 1
            y = (self.mt[N - 1] & UPPER_MASK) | (self.mt[0] & LOWER_MASK)
            self.mt[N - 1] = (self.mt[M - 1] ^ (y >> 1) ^ mag01[y & 1]) & 0xffffffff
            self.mti = 0
        y = self.mt[self.mti]
        self.mti += 1
        y ^= (y >> 11)
        y ^= (y << 7) & 0x9d2c5680
        y ^= (y << 15) & 0xefc60000
        y ^= (y >> 18)
        return y & 0xffffffff


# ---- 基础辅助 ----
def rol(a, shift):
    return ((a << shift) | (a >> (32 - shift))) & 0xffffffff


def ror(a, shift):
    return ((a >> shift) | (a << (32 - shift))) & 0xffffffff


def xor_repeating_blocks(output, input_, length):
    """output[i & 63] ^= input_[i]"""
    for i in range(length):
        output[i & 63] ^= input_[i]


def xor_with_long_param(input_, output, param):
    """8 个 uint64 分别 ^= param"""
    for i in range(8):
        v = struct.unpack_from("<Q", input_, 8 * i)[0]
        struct.pack_into("<Q", output, 8 * i, v ^ (param & 0xFFFFFFFFFFFFFFFF))


def reverse_longs(output, input_):
    """8 个 8 字节块各自反转"""
    for i in range(8):
        for j in range(8):
            output[i * 8 + j] = input_[i * 8 + 7 - j]


def crypt_stream(key, input_, length):
    """MT19937 流加密（可逆，加解密同一函数）"""
    mt = MT19937()
    init_key = [struct.unpack_from("<I", key, 4 * i)[0] for i in range(16)]
    mt.init_by_array(init_key, 16)
    c0 = mt.genrand_int32()
    c1 = mt.genrand_int32()
    c2 = mt.genrand_int32()
    c3 = mt.genrand_int32()

    output = bytearray(length)
    n4 = length // 4
    for i in range(n4):
        c4 = mt.genrand_int32()
        inv = struct.unpack_from("<I", input_, 4 * i)[0]
        outv = (c4 ^ c3 ^ c2 ^ c1 ^ c0 ^ inv) & 0xffffffff
        struct.pack_into("<I", output, 4 * i, outv)
        c0 = ror(c1, 15)
        c1 = rol(c2, 11)
        c2 = rol(c3, 7)
        c3 = ror(c4, 13)
    rem = length & 3
    if rem:
        rest = int.from_bytes(input_[length - rem:], "little")
        rv = (rest ^ mt.genrand_int32() ^ c3 ^ c2 ^ c1 ^ c0) & 0xffffffff
        output[length - rem:] = rv.to_bytes(4, "little")[:rem]
    return bytes(output)


def crypt_header(input_, master_key):
    header_key = bytearray(input_[256:256 + 64])
    shuffled_master = bytearray(64)
    reverse_longs(shuffled_master, master_key)
    xor_repeating_blocks(header_key, shuffled_master, 64)
    output = bytearray(crypt_stream(bytes(header_key), input_, ENCRYPTION_HEADER_SIZE))
    output[256:320] = input_[256:320]
    return bytes(output)


def _decrypt_block(rolling_key, fmt_buf, param, blob, pos, length):
    intermediate = bytearray(64)
    xor_with_long_param(rolling_key, intermediate, param)
    return crypt_stream(bytes(intermediate), blob[pos:pos + length], length)


def parse_file_header(hdr):
    return {
        "mysteryData": hdr[0:64],
        "dataSize": struct.unpack_from("<I", hdr, 64)[0],
        "logoSize": struct.unpack_from("<I", hdr, 68)[0],
        "descSize": struct.unpack_from("<I", hdr, 72)[0],
        "serialLength": struct.unpack_from("<I", hdr, 76)[0],
        "hash": hdr[80:144],
        "fileTypeString": hdr[144:176],
        "gameVersionString": hdr[176:208],
    }


def decrypt(blob, master_key=MASTERKEY_PES21):
    enc_header = crypt_header(blob[:ENCRYPTION_HEADER_SIZE], master_key)
    pos = ENCRYPTION_HEADER_SIZE

    rolling_key = bytearray(enc_header[:64])
    xor_repeating_blocks(rolling_key, enc_header[64:64 + 256], 256)

    intermediate = bytearray(64)
    xor_with_long_param(rolling_key, intermediate, FILE_HEADER_SIZE)
    file_header = crypt_stream(bytes(intermediate), blob[pos:pos + FILE_HEADER_SIZE], FILE_HEADER_SIZE)
    pos += FILE_HEADER_SIZE

    hdr = parse_file_header(file_header)

    desc = _decrypt_block(rolling_key, None, 0, blob, pos, hdr["descSize"])
    pos += hdr["descSize"]
    logo = _decrypt_block(rolling_key, None, 1, blob, pos, hdr["logoSize"])
    pos += hdr["logoSize"]
    data = _decrypt_block(rolling_key, None, 2, blob, pos, hdr["dataSize"])
    pos += hdr["dataSize"]
    serial = _decrypt_block(rolling_key, None, 3, blob, pos, hdr["serialLength"] * 2)
    pos += hdr["serialLength"] * 2

    return {
        "encHeader": enc_header,
        "fileHeader": file_header,
        "hdr": hdr,
        "description": desc,
        "logo": logo,
        "data": data,
        "serial": serial,
        "consumed": pos,
    }


def _clean(b):
    return "".join(chr(x) if 32 <= x < 127 else "." for x in b)


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(EX_DIR, "rep", "REPLAY00000000")
    blob = open(path, "rb").read()
    print(f"== 解密 {os.path.basename(path)}  (size={len(blob)}) ==")

    r = decrypt(blob)
    h = r["hdr"]
    print(f"fileTypeString   : {_clean(h['fileTypeString'])!r}")
    print(f"gameVersionString: {_clean(h['gameVersionString'])!r}")
    print(f"dataSize={h['dataSize']}  logoSize={h['logoSize']}  descSize={h['descSize']}  serialLength={h['serialLength']}")
    print(f"consumed={r['consumed']}  (应等于文件大小 {len(blob)}，差={len(blob)-r['consumed']})")
    print(f"description(前128B): {_clean(r['description'][:128])!r}")
    print(f"serial(前128B)     : {_clean(r['serial'][:128])!r}")
    print(f"data 前 64 字节 hex: {r['data'][:64].hex()}")

    # 判断解密的 data 熵是否下降（成功标志）
    def ent(b):
        if not b:
            return 0.0
        c = {}
        for x in b:
            c[x] = c.get(x, 0) + 1
        import math
        n = len(b)
        return -sum((v / n) * math.log2(v / n) for v in c.values())

    print(f"data 熵 = {ent(r['data'][:65536]):.4f} (若 <5 说明解密成功，接近8说明失败)")


if __name__ == "__main__":
    main()