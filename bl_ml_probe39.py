#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bl_ml_probe39: 验证 EDIT 球员表布局 = data(240) + appearance(72), stride 312。
- 数据条目起始 0x7C, 首 u32 = Player ID, 名字在条目内偏移 0x36 (61B null-term)
- 提取 (player_id, name) 映射并统计
"""
import struct, os

BASE = os.path.dirname(os.path.abspath(__file__))
EDIT = os.path.join(BASE, "decoded", "EDIT00000000.data")
b = open(EDIT, "rb").read()
N = len(b)

DATA = 240
APPEAR = 72
STRIDE = DATA + APPEAR   # 312
BASE_OFF = 0x7C
NAME_OFF = 0x36
NAME_LEN = 61

# 头部玩家计数 (0x60 u16)
n_players_hdr = struct.unpack_from("<H", b, 0x60)[0]
print(f"头部声明的 player entires 数: {n_players_hdr}")
print(f"STRIDE={STRIDE}, 若全为球员则占用 {n_players_hdr*STRIDE} 字节 = {n_players_hdr*STRIDE/1024/1024:.2f} MB")

# 从 BASE_OFF 起, 每 STRIDE 取数据条目首 u32 (player id)
def read_name(off):
    raw = b[off + NAME_OFF: off + NAME_OFF + NAME_LEN]
    z = raw.split(b"\x00", 1)[0]
    return z.decode("latin1", "replace")

print("\n== 前 12 位球员 (stride=312) ==")
ok = 0
ids = []
for k in range(12):
    o = BASE_OFF + k * STRIDE
    if o + DATA > N:
        break
    pid = struct.unpack_from("<I", b, o)[0]
    # appearance 条目紧随 (o+240), 其首 u32 应 = 同 player id
    aid = struct.unpack_from("<I", b, o + DATA)[0]
    name = read_name(o)
    ids.append(pid)
    print(f"  #{k:3d} @0x{o:x} dataID={pid} (0x{pid:x})  appearRef={aid}  name={name!r}")
    if pid != 0 and pid != aid:
        pass

# 统计: 连续 stride-312 且 dataID==appearRef 的段长度 (验证布局)
def count_valid_stride():
    cnt = 0; cur = 0
    off = BASE_OFF
    while off + STRIDE <= N:
        pid = struct.unpack_from("<I", b, off)[0]
        aid = struct.unpack_from("<I", b, off + DATA)[0]
        if pid != 0 and pid == aid:
            cur += 1
        else:
            if cur > cnt:
                cnt = cur
            cur = 0
        off += STRIDE
    if cur > cnt:
        cnt = cur
    return cnt

cv = count_valid_stride()
print(f"\n连续 (dataID==appearRef, 非零) 的最长段: {cv} 位球员")

# 提取全部 (id->name) 映射 (只取 dataID==appearRef 且非零)
mappings = {}
off = BASE_OFF
while off + STRIDE <= N:
    pid = struct.unpack_from("<I", b, off)[0]
    aid = struct.unpack_from("<I", b, off + DATA)[0]
    if pid != 0 and pid == aid and pid not in mappings:
        mappings[pid] = read_name(off)
    off += STRIDE

print(f"提取到 {len(mappings)} 条 (id->name) 映射")
print("样本 (前 15, 按 id 排序):")
for pid in sorted(mappings)[:15]:
    print(f"   id={pid}  name={mappings[pid]!r}")

# 看 id 范围
if mappings:
    print("id 最小/最大:", min(mappings), max(mappings))
    # 导出映射 (前 5000 条) 供核对
    out = os.path.join(BASE, "outputs", "edit_player_names_sample.csv")
    with open(out, "w", encoding="utf-8") as f:
        f.write("player_id,name\n")
        for pid in sorted(mappings)[:5000]:
            f.write(f"{pid},{mappings[pid]}\n")
    print(f"导出样例 -> {out}")
