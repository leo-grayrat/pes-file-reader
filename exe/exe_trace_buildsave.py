#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
exe_trace_buildsave.py — 追踪保存侧「4 段摘要写进 encHeader[0:256]」的路径。

背景（承接 2026-09-02 浑元4 的开放项）：
- 7946e7c 已闭合保存侧便捷 SHA-512: 0x140E160 一次性 SHA-512, 唯一调用者 0x1412B21,
  派生 rolling_key (XOR encHeader 256B + salt 再 xor 0xD0)。
- 但「谁把 SHA-512(desc/logo/data/serial) 这 4 个 64B 写进 encHeader[0:256]」仍未定位。
- 读侧 decrypt_main 块循环在 0x1411916 做 memcmp(ctx, expect+i*64, 64); 保存侧应有对称落盘。

做法（纯静态, 只读 mmap, 不执行）:
1. 全 exe 扫 E8 rel32, 确认 0x140E160 调用者计数 (应=1, 在 0x1412B21)。
2. 从 0x1412B21 向前找 build_save 真实函数入口 (prologue: push rbp / endbr64 / sub rsp)。
3. 反汇编 入口 ~ 0x1412C1A (加密主流程前), 高亮关键调用与 'shl ...,6' (×64 = 摘要槽偏移)。

地址口径: flat image, 偏移即地址 (与 exe_dis_func.py 一致)。
"""
import mmap
import os
import struct
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_64

EXE = r"D:/File/Git/pes-file-reader/resources/Patch 1.07.00/eFootball PES 2021/PES2021.exe"

SHA512_ONE_SHOT = 0x140E160   # 一次性 SHA-512 便捷函数
SHA512_FEEDER = 0x1413950     # SHA-512 喂入器 (读侧 3 调用者: 转字符串, 非写 encHeader)
ENC_MAIN = 0x1412C1A          # 加密主流程
SAVE_SHA512_CALL = 0x1412B21  # 0x140E160 唯一调用者


def find_callers(mm, tgt, whole_start=0, whole_end=None):
    """扫 E8 rel32 调用, 返回目标落在 tgt 的调用点列表。"""
    if whole_end is None:
        whole_end = len(mm)
    out = []
    pos = whole_start
    n_e8 = 0
    while True:
        i = mm.find(b"\xE8", pos)
        if i < 0 or i + 5 > len(mm):
            break
        rel = struct.unpack_from("<i", mm, i + 1)[0]
        t = i + 5 + rel
        n_e8 += 1
        if t == tgt:
            out.append(i)
        pos = i + 1
    return out, n_e8


def find_prologue_backward(mm, off, back=0x2000):
    """从 off 向前找函数 prologue。命中: endbr64(f3 0f 1e fa) 或 push rbp(55)+后续,
    或 '48 89 e5'(mov rbp,rsp)。返回最靠后的 prologue 地址。"""
    lo = max(0, off - back)
    seg = mm[lo:off]
    cands = []
    # endbr64
    idx = seg.find(b"\xf3\x0f\x1e\xfa")
    while idx != -1:
        cands.append(lo + idx)
        idx = seg.find(b"\xf3\x0f\x1e\xfa", idx + 1)
    # push rbp ; mov rbp,rsp  -> 55 48 89 e5
    idx = seg.find(b"\x55\x48\x89\xe5")
    while idx != -1:
        cands.append(lo + idx)
        idx = seg.find(b"\x55\x48\x89\xe5", idx + 1)
    # push rbp ; push rbx 类 (41 56 / 53 ...) 较弱, 仅作兜底
    if not cands:
        idx = seg.find(b"\x40\x55")
        while idx != -1:
            cands.append(lo + idx)
            idx = seg.find(b"\x40\x55", idx + 1)
    if not cands:
        return None
    return max(cands)


def main():
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    size = os.path.getsize(EXE)
    with open(EXE, "rb") as f:
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            # 1) 确认 0x140E160 调用者
            callers, n_e8 = find_callers(mm, SHA512_ONE_SHOT)
            print("== 1) 0x140E160 调用者扫描 ==")
            print("  全 exe E8 调用数: %d" % n_e8)
            print("  命中 0x140E160 的调用点: %s" % (["0x%08X" % c for c in callers] or "无"))
            # 顺带看喂入器 0x1413950 调用者
            feeders, _ = find_callers(mm, SHA512_FEEDER)
            print("  顺带 0x1413950 调用点: %s" % (["0x%08X" % c for c in feeders] or "无"))
            print()

            # 2) build_save 入口
            start = find_prologue_backward(mm, SAVE_SHA512_CALL, back=0x3000)
            print("== 2) build_save 入口猜测 ==")
            print("  向前 prologue: %s" % ("0x%08X" % start if start else "未找到"))
            if start is None:
                start = SAVE_SHA512_CALL - 0x300  # 兜底
            end = ENC_MAIN
            print("  反汇编区间: 0x%08X ~ 0x%08X (%d 字节)" % (start, end, end - start))
            print("=" * 78)

            # 3) 反汇编 + 高亮
            code = mm[start:end]
            hl_calls = {SHA512_ONE_SHOT: "SHA512_ONE",
                        SHA512_FEEDER: "SHA512_FEED",
                        ENC_MAIN: "ENC_MAIN",
                        0x140FDF0: "WRITE64",
                        0x140DFF0: "XOR_BLK"}
            n = 0
            for ins in md.disasm(code, start):
                a = ins.address
                raw = mm[a:a + ins.size].hex()
                tag = ""
                # 关键调用
                if ins.mnemonic == "call" and ins.op_str.startswith("0x"):
                    t = int(ins.op_str, 16)
                    if t in hl_calls:
                        tag = "  <<< %s" % hl_calls[t]
                # shl by 6 (×64 摘要槽)
                if ins.mnemonic == "shl" and "6" in ins.op_str:
                    tag += "  <<< *64"
                # 写 encHeader 摘要槽相关: mov [rbp+0x...], 或 lea 到 encHeader
                print("  0x%08X: %-22s %-8s %s%s"
                      % (a, raw, ins.mnemonic, ins.op_str, tag))
                n += 1
            print("  （共 %d 条）" % n)


if __name__ == "__main__":
    sys.exit(main())
