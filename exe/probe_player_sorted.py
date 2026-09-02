#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
probe_player_sorted.py — 验证 exe 反汇编推出的预测：EDIT 球员表按球员 ID 升序排列，
                         ID==0 的空槽排在表尾（游戏用二分查找定位）。

预测来自哪里：
  exe 0x1404A90（EDIT 数据表访问层）反汇编显示 —— 见 docs/exe-save-layout.md §7.4
    sar  rax, 1              取中点（二分查找）
    imul r8,  rax, 0x138     中点偏移 = 索引 × 312（球员条目步长）
    mov  eax, [r8 + rdi]     排序键 = 条目偏移 0 处的 dword，即球员 ID
    cmove eax, ebp           ID==0 时换成 0xFFFFFFFF → 空槽被当作最大值，排到表尾
    movups xmm0,[rbx] ...    命中后按 128 B 批量 SSE 覆写整条

  只有当表**确实有序**时二分查找才成立。所以这是一个可用真实存档否证的硬预测。

适用范围（重要，别踩坑）：
  `PLAYER_BASE=0x7C` / `PLAYER_STRIDE=312` / 计数字段 `0x60` 只对 **EDIT 类存档的 data 块**
  成立。BL / ML / REPLAY 的 data 是另外的布局：
    - BL / ML：0x60 处不是球员计数（实测读出 0），球员数据在别的表里；
    - REPLAY：那个位置根本没有球员表，硬按 312 步长读会读出 ASCII 片段
      （`0x4C412049` = " AL"）和浮点数（`0x3EDB6DB8`），产生**假的"逆序"报告**。
  所以本脚本默认只跑 EDIT 样本；对其他类型显式标注"布局不适用"，而不是算作否证。

只读：只读 decoded/*.data（已解密明文），不写任何文件。

用法：
  python probe_player_sorted.py                # 只跑 EDIT 样本（默认，正确用法）
  python probe_player_sorted.py --all          # 连带跑 BL/ML/REPLAY，仅为展示"不适用"
  python probe_player_sorted.py EDIT00000000
"""
import os
import struct
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEC = os.path.join(BASE, "decoded")

# 来自 core/pesfile.py 的已确认常量
PLAYER_BASE = 0x7C
PLAYER_STRIDE = 312


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def is_edit_layout(name):
    """只有 EDIT 类存档的 data 块用 0x7C/312 球员表布局，见文件头说明。"""
    return os.path.basename(name).upper().startswith("EDIT")


def check(path):
    b = open(path, "rb").read()
    name = os.path.basename(path)
    if not is_edit_layout(name):
        return (name, None, "非 EDIT 布局（BL/ML/REPLAY 的 data 结构不同），不适用本预测")
    count = u32(b, 0x60)
    if count == 0 or count > 100000:
        return (name, None, "球员计数字段异常(%d)，跳过" % count)

    ids = []
    for i in range(count):
        off = PLAYER_BASE + i * PLAYER_STRIDE
        if off + 4 > len(b):
            break
        ids.append(u32(b, off))

    # 按 exe 的比较语义归一化：ID==0 视作 0xFFFFFFFF（空槽排最后）
    keys = [0xFFFFFFFF if v == 0 else v for v in ids]

    n = len(keys)
    desc = [i for i in range(1, n) if keys[i] < keys[i - 1]]
    nz = [v for v in ids if v not in (0, 0xFFFFFFFF)]
    empties = n - len(nz)
    # 非空条目是否全部排在空槽之前
    first_empty = next((i for i, v in enumerate(ids) if v in (0, 0xFFFFFFFF)), n)
    tail_all_empty = all(ids[i] in (0, 0xFFFFFFFF) for i in range(first_empty, n))
    dup = len(nz) - len(set(nz))

    ok = (len(desc) == 0)
    detail = ("条目 %d（非空 %d / 空槽 %d）  逆序处 %d  重复 ID %d  "
              "空槽是否全在尾部 %s" %
              (n, len(nz), empties, len(desc), dup, "是" if tail_all_empty else "否"))
    if desc[:3]:
        detail += "\n      前几处逆序: " + ", ".join(
            "idx %d: 0x%08X < 0x%08X" % (i, keys[i], keys[i - 1]) for i in desc[:3])
    return (name, ok, detail)


def main():
    args = [a for a in sys.argv[1:]]
    show_all = "--all" in args
    args = [a for a in args if not a.startswith("--")]
    if args:
        files = [os.path.join(DEC, a if a.endswith(".data") else a + ".data")
                 for a in args]
    else:
        files = sorted(os.path.join(DEC, f) for f in os.listdir(DEC)
                       if f.endswith(".data") and (show_all or is_edit_layout(f)))

    print("验证预测：EDIT 球员表按球员 ID 升序、空槽(ID=0)排表尾")
    print("依据：exe 0x1404A90 用二分查找 + imul 0x138 步长访问该表")
    print("适用范围：仅 EDIT 类存档（BL/ML/REPLAY 的 data 是别的布局）")
    print("=" * 78)
    n_ok = n_bad = n_na = 0
    for p in files:
        if not os.path.exists(p):
            print("  跳过（不存在）: %s" % p)
            continue
        name, ok, detail = check(p)
        if ok is None:
            print("  %-24s ——  %s" % (name, detail))
            n_na += 1
            continue
        tag = "有序 ✓" if ok else "存在逆序 ✗"
        print("  %-24s %s  %s" % (name, tag, detail))
        n_ok += 1 if ok else 0
        n_bad += 0 if ok else 1
    print("-" * 78)
    print("结论：适用样本 %d 个 —— %d 个有序，%d 个出现逆序；另有 %d 个布局不适用"
          % (n_ok + n_bad, n_ok, n_bad, n_na))
    if n_bad == 0 and n_ok > 0:
        print("→ 预测成立：球员表确实按 ID 升序，与 exe 的二分查找一致。")
    elif n_bad:
        print("→ 预测被否证或表内另有分区语义，需回查反汇编。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
