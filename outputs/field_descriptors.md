# PES2021 球员字段描述符表（exe 实证，380B 运行时对象）

由 `exe/exe_field_desc.py` 从 exe 静态转储（只读，不执行其代码）。

- 查表函数 `0x1407E70`：按 `r8d`(字段 ID) 线性查表，命中后拷描述符给 `rdx`
- 表1 = **122 项 × 0x30**（ID `0x00`~`0x79`）；表2 = **3 项 × 0x28**（ID `0x7A`~`0x7C`）
- 描述符 `+0x18/+0x20/+0x24` = **最小值 / 最大值 / 位宽**（非 312B 记录偏移——
  312B 存档侧位打包由序列化器 `0x1F14670` 独立完成，见 §判定）
- getter 统一形态 `mov eax,[rcx+X]; shr N; and M` ⇒ 从 380B 对象取 `(X, N, 位宽)` 位域

## 表1：122 字段全表

| ID | min | max | 位宽 | 对象偏移 | 位偏移 | 语义 | getter 反汇编 |
|---|---|---|---|---|---|---|---|
| `0x00` | 0 | 4294967295 | 32 | `+0x00` | 0 |  | mov eax, dword ptr [rcx]; mov dword ptr [rdx], eax; 
| `0x01` | 0 | 1 | 1 | `+0x1C` | 31 |  | mov eax, dword ptr [rcx + 0x1c]; shr eax, 0x1f; mov 
| `0x02` | 0 | 1 | 1 | `+0x20` | 31 |  | mov eax, dword ptr [rcx + 0x20]; shr eax, 0x1f; mov 
| `0x03` | 0 | 1 | 1 | `+0x28` | 31 |  | mov eax, dword ptr [rcx + 0x28]; shr eax, 0x1f; mov 
| `0x04` | 0 | 1 | 1 | `+0x2C` | 22 |  | mov eax, dword ptr [rcx + 0x2c]; shr eax, 0x16; and 
| `0x05` | 0 | 1 | 1 | `+0x2C` | 23 |  | mov eax, dword ptr [rcx + 0x2c]; shr eax, 0x17; and 
| `0x06` | 0 | 1 | 1 | `+0x2F` | 0 |  | movzx eax, byte ptr [rcx + 0x2f]; and eax, 1; mov dw
| `0x07` | 0 | 1 | 1 | `+0x2C` | 25 |  | mov eax, dword ptr [rcx + 0x2c]; shr eax, 0x19; and 
| `0x08` | 0 | 1 | 1 | `+0x2C` | 26 |  | mov eax, dword ptr [rcx + 0x2c]; shr eax, 0x1a; and 
| `0x09` | 0 | 1 | 1 | `+0x2C` | 27 |  | mov eax, dword ptr [rcx + 0x2c]; shr eax, 0x1b; and 
| `0x0A` | 0 | 1 | 1 | `+0x2C` | 28 |  | mov eax, dword ptr [rcx + 0x2c]; shr eax, 0x1c; and 
| `0x0B` | 0 | 4294967295 | 32 | `+0x04` | 0 |  | mov eax, dword ptr [rcx + 4]; mov dword ptr [rdx], e
| `0x0C` | 0 | 65535 | 16 | `+0x08` | 0 |  | movzx eax, word ptr [rcx + 8]; mov dword ptr [rdx], 
| `0x0D` | 15 | 50 | 6 | `+0x20` | 7 | 年龄（15~50，6bit） | mov eax, dword ptr [rcx + 0x20]; shr eax, 7; and eax
| `0x0E` | 0 | 31 | 5 | `+0x20` | 13 |  | mov eax, dword ptr [rcx + 0x20]; shr eax, 0xd; and e
| `0x0F` | 0 | 1 | 1 | `+0x2C` | 29 |  | mov eax, dword ptr [rcx + 0x2c]; shr eax, 0x1d; and 
| `0x10` | 100 | 250 | 8 | `+0x0A` | 0 | 身高 cm（100~250，8bit） | movzx eax, byte ptr [rcx + 0xa]; mov dword ptr [rdx]
| `0x11` | 30 | 150 | 8 | `+0x0B` | 0 | 体重 kg（30~150，8bit） | movzx eax, byte ptr [rcx + 0xb]; mov dword ptr [rdx]
| `0x12` | 40 | 99 | 7 | `+0x0E` | 0 | **offensive_awareness** | movzx eax, word ptr [rcx + 0xe]; and eax, 0x7f; mov 
| `0x13` | 40 | 99 | 7 | `+0x0C` | 23 | **ball_control** | mov eax, dword ptr [rcx + 0xc]; shr eax, 0x17; and e
| `0x14` | 40 | 99 | 7 | `+0x28` | 0 | **tight_possession** | mov eax, dword ptr [rcx + 0x28]; and eax, 0x7f; mov 
| `0x15` | 40 | 99 | 7 | `+0x10` | 0 | **low_pass** | mov eax, dword ptr [rcx + 0x10]; and eax, 0x7f; mov 
| `0x16` | 40 | 99 | 7 | `+0x10` | 7 | **lofted_pass** | mov eax, dword ptr [rcx + 0x10]; shr eax, 7; and eax
| `0x17` | 40 | 99 | 7 | `+0x10` | 14 | **finishing** | mov eax, dword ptr [rcx + 0x10]; shr eax, 0xe; and e
| `0x18` | 40 | 99 | 7 | `+0x10` | 21 | **place_kicking** | mov eax, dword ptr [rcx + 0x10]; shr eax, 0x15; and 
| `0x19` | 40 | 99 | 7 | `+0x24` | 14 | **curl** | mov eax, dword ptr [rcx + 0x24]; shr eax, 0xe; and e
| `0x1A` | 40 | 99 | 7 | `+0x14` | 0 | **speed** | mov eax, dword ptr [rcx + 0x14]; and eax, 0x7f; mov 
| `0x1B` | 40 | 99 | 7 | `+0x14` | 7 | **acceleration** | mov eax, dword ptr [rcx + 0x14]; shr eax, 7; and eax
| `0x1C` | 40 | 99 | 7 | `+0x14` | 14 | **jump** | mov eax, dword ptr [rcx + 0x14]; shr eax, 0xe; and e
| `0x1D` | 40 | 99 | 7 | `+0x14` | 21 | **physical_contact** | mov eax, dword ptr [rcx + 0x14]; shr eax, 0x15; and 
| `0x1E` | 40 | 99 | 7 | `+0x2C` | 13 | **balance** | mov eax, dword ptr [rcx + 0x2c]; shr eax, 0xd; and e
| `0x1F` | 40 | 99 | 7 | `+0x18` | 0 | **stamina** | mov eax, dword ptr [rcx + 0x18]; and eax, 0x7f; mov 
| `0x20` | 40 | 99 | 7 | `+0x18` | 7 | **ball_winning** | mov eax, dword ptr [rcx + 0x18]; shr eax, 7; and eax
| `0x21` | 40 | 99 | 7 | `+0x18` | 14 | **aggression** | mov eax, dword ptr [rcx + 0x18]; shr eax, 0xe; and e
| `0x22` | 40 | 99 | 7 | `+0x18` | 21 | **gk_awareness** | mov eax, dword ptr [rcx + 0x18]; shr eax, 0x15; and 
| `0x23` | 40 | 99 | 7 | `+0x24` | 0 | **gk_catching** | mov eax, dword ptr [rcx + 0x24]; and eax, 0x7f; mov 
| `0x24` | 40 | 99 | 7 | `+0x1C` | 0 | **gk_reach** | mov eax, dword ptr [rcx + 0x1c]; and eax, 0x7f; mov 
| `0x25` | 40 | 99 | 7 | `+0x1C` | 7 | **defensive_awareness** | mov eax, dword ptr [rcx + 0x1c]; shr eax, 7; and eax
| `0x26` | 40 | 99 | 7 | `+0x1C` | 14 | **gk_clearing** | mov eax, dword ptr [rcx + 0x1c]; shr eax, 0xe; and e
| `0x27` | 40 | 99 | 7 | `+0x1C` | 21 | **heading** | mov eax, dword ptr [rcx + 0x1c]; shr eax, 0x15; and 
| `0x28` | 40 | 99 | 7 | `+0x24` | 7 | **dribbling** | mov eax, dword ptr [rcx + 0x24]; shr eax, 7; and eax
| `0x29` | 40 | 99 | 7 | `+0x2C` | 6 | **gk_reflexes** | mov eax, dword ptr [rcx + 0x2c]; shr eax, 6; and eax
| `0x2A` | 40 | 99 | 7 | `+0x20` | 0 | **kicking_power** | mov eax, dword ptr [rcx + 0x20]; and eax, 0x7f; mov 
| `0x2B` | 0 | 3 | 2 | `+0x0C` | 30 |  | mov eax, dword ptr [rcx + 0xc]; shr eax, 0x1e; mov d
| `0x2C` | 0 | 3 | 2 | `+0x24` | 30 |  | mov eax, dword ptr [rcx + 0x24]; shr eax, 0x1e; mov 
| `0x2D` | 0 | 7 | 3 | `+0x1C` | 28 |  | mov eax, dword ptr [rcx + 0x1c]; shr eax, 0x1c; and 
| `0x2E` | 0 | 2 | 2 | `+0x28` | 7 |  | mov eax, dword ptr [rcx + 0x28]; shr eax, 7; and eax
| `0x2F` | 0 | 7 | 3 | `+0x20` | 28 |  | mov eax, dword ptr [rcx + 0x20]; shr eax, 0x1c; and 
| `0x30` | 0 | 3 | 2 | `+0x28` | 9 |  | mov eax, dword ptr [rcx + 0x28]; shr eax, 9; and eax
| `0x31` | 0 | 1 | 1 | `+0x2C` | 30 |  | mov eax, dword ptr [rcx + 0x2c]; shr eax, 0x1e; and 
| `0x32` | 0 | 2 | 2 | `+0x28` | 11 |  | mov eax, dword ptr [rcx + 0x28]; shr eax, 0xb; and e
| `0x33` | 0 | 2 | 2 | `+0x28` | 13 |  | mov eax, dword ptr [rcx + 0x28]; shr eax, 0xd; and e
| `0x34` | 0 | 2 | 2 | `+0x28` | 15 |  | mov eax, dword ptr [rcx + 0x28]; shr eax, 0xf; and e
| `0x35` | 0 | 2 | 2 | `+0x28` | 17 |  | mov eax, dword ptr [rcx + 0x28]; shr eax, 0x11; and 
| `0x36` | 0 | 2 | 2 | `+0x28` | 19 |  | mov eax, dword ptr [rcx + 0x28]; shr eax, 0x13; and 
| `0x37` | 0 | 2 | 2 | `+0x28` | 21 |  | mov eax, dword ptr [rcx + 0x28]; shr eax, 0x15; and 
| `0x38` | 0 | 2 | 2 | `+0x28` | 23 |  | mov eax, dword ptr [rcx + 0x28]; shr eax, 0x17; and 
| `0x39` | 0 | 2 | 2 | `+0x28` | 25 |  | mov eax, dword ptr [rcx + 0x28]; shr eax, 0x19; and 
| `0x3A` | 0 | 2 | 2 | `+0x28` | 27 |  | mov eax, dword ptr [rcx + 0x28]; shr eax, 0x1b; and 
| `0x3B` | 0 | 2 | 2 | `+0x28` | 29 |  | mov eax, dword ptr [rcx + 0x28]; shr eax, 0x1d; and 
| `0x3C` | 0 | 2 | 2 | `+0x2C` | 20 |  | mov eax, dword ptr [rcx + 0x2c]; shr eax, 0x14; and 
| `0x3D` | 0 | 2 | 2 | `+0x2C` | 0 |  | mov eax, dword ptr [rcx + 0x2c]; and eax, 3; mov dwo
| `0x3E` | 0 | 2 | 2 | `+0x2C` | 2 |  | mov eax, dword ptr [rcx + 0x2c]; shr eax, 2; and eax
| `0x3F` | 0 | 2 | 2 | `+0x2C` | 4 |  | mov eax, dword ptr [rcx + 0x2c]; shr eax, 4; and eax
| `0x40` | 0 | 31 | 5 | `+0x20` | 18 |  | mov eax, dword ptr [rcx + 0x20]; shr eax, 0x12; and 
| `0x41` | 0 | 1 | 1 | `+0x2C` | 31 |  | mov eax, dword ptr [rcx + 0x2c]; shr eax, 0x1f; mov 
| `0x42` | 0 | 1 | 1 | `+0x30` | 0 |  | mov eax, dword ptr [rcx + 0x30]; and eax, 1; mov dwo
| `0x43` | 0 | 1 | 1 | `+0x30` | 1 |  | mov eax, dword ptr [rcx + 0x30]; shr eax, 1; and eax
| `0x44` | 0 | 1 | 1 | `+0x30` | 2 |  | mov eax, dword ptr [rcx + 0x30]; shr eax, 2; and eax
| `0x45` | 0 | 1 | 1 | `+0x30` | 3 |  | mov eax, dword ptr [rcx + 0x30]; shr eax, 3; and eax
| `0x46` | 0 | 1 | 1 | `+0x30` | 4 |  | mov eax, dword ptr [rcx + 0x30]; shr eax, 4; and eax
| `0x47` | 0 | 1 | 1 | `+0x30` | 5 |  | mov eax, dword ptr [rcx + 0x30]; shr eax, 5; and eax
| `0x48` | 0 | 1 | 1 | `+0x30` | 6 |  | mov eax, dword ptr [rcx + 0x30]; shr eax, 6; and eax
| `0x49` | 0 | 1 | 1 | `+0x30` | 7 |  | mov eax, dword ptr [rcx + 0x30]; shr eax, 7; and eax
| `0x4A` | 0 | 1 | 1 | `+0x30` | 8 |  | mov eax, dword ptr [rcx + 0x30]; shr eax, 8; and eax
| `0x4B` | 0 | 1 | 1 | `+0x30` | 9 |  | mov eax, dword ptr [rcx + 0x30]; shr eax, 9; and eax
| `0x4C` | 0 | 1 | 1 | `+0x30` | 10 |  | mov eax, dword ptr [rcx + 0x30]; shr eax, 0xa; and e
| `0x4D` | 0 | 1 | 1 | `+0x30` | 11 |  | mov eax, dword ptr [rcx + 0x30]; shr eax, 0xb; and e
| `0x4E` | 0 | 1 | 1 | `+0x30` | 12 |  | mov eax, dword ptr [rcx + 0x30]; shr eax, 0xc; and e
| `0x4F` | 0 | 1 | 1 | `+0x30` | 13 |  | mov eax, dword ptr [rcx + 0x30]; shr eax, 0xd; and e
| `0x50` | 0 | 1 | 1 | `+0x30` | 14 |  | mov eax, dword ptr [rcx + 0x30]; shr eax, 0xe; and e
| `0x51` | 0 | 1 | 1 | `+0x30` | 15 |  | mov eax, dword ptr [rcx + 0x30]; shr eax, 0xf; and e
| `0x52` | 0 | 1 | 1 | `+0x32` | 0 |  | movzx eax, word ptr [rcx + 0x32]; and eax, 1; mov dw
| `0x53` | 0 | 1 | 1 | `+0x30` | 17 |  | mov eax, dword ptr [rcx + 0x30]; shr eax, 0x11; and 
| `0x54` | 0 | 1 | 1 | `+0x30` | 18 |  | mov eax, dword ptr [rcx + 0x30]; shr eax, 0x12; and 
| `0x55` | 0 | 1 | 1 | `+0x30` | 19 |  | mov eax, dword ptr [rcx + 0x30]; shr eax, 0x13; and 
| `0x56` | 0 | 1 | 1 | `+0x30` | 20 |  | mov eax, dword ptr [rcx + 0x30]; shr eax, 0x14; and 
| `0x57` | 0 | 1 | 1 | `+0x30` | 21 |  | mov eax, dword ptr [rcx + 0x30]; shr eax, 0x15; and 
| `0x58` | 0 | 1 | 1 | `+0x30` | 22 |  | mov eax, dword ptr [rcx + 0x30]; shr eax, 0x16; and 
| `0x59` | 0 | 1 | 1 | `+0x30` | 23 |  | mov eax, dword ptr [rcx + 0x30]; shr eax, 0x17; and 
| `0x5A` | 0 | 1 | 1 | `+0x33` | 0 |  | movzx eax, byte ptr [rcx + 0x33]; and eax, 1; mov dw
| `0x5B` | 0 | 1 | 1 | `+0x30` | 25 |  | mov eax, dword ptr [rcx + 0x30]; shr eax, 0x19; and 
| `0x5C` | 0 | 1 | 1 | `+0x30` | 26 |  | mov eax, dword ptr [rcx + 0x30]; shr eax, 0x1a; and 
| `0x5D` | 0 | 1 | 1 | `+0x30` | 27 |  | mov eax, dword ptr [rcx + 0x30]; shr eax, 0x1b; and 
| `0x5E` | 0 | 1 | 1 | `+0x30` | 28 |  | mov eax, dword ptr [rcx + 0x30]; shr eax, 0x1c; and 
| `0x5F` | 0 | 1 | 1 | `+0x30` | 29 |  | mov eax, dword ptr [rcx + 0x30]; shr eax, 0x1d; and 
| `0x60` | 0 | 1 | 1 | `+0x30` | 30 |  | mov eax, dword ptr [rcx + 0x30]; shr eax, 0x1e; and 
| `0x61` | 0 | 1 | 1 | `+0x30` | 31 |  | mov eax, dword ptr [rcx + 0x30]; shr eax, 0x1f; mov 
| `0x62` | 0 | 1 | 1 | `+0x34` | 0 |  | movzx eax, word ptr [rcx + 0x34]; and eax, 1; mov dw
| `0x63` | 0 | 1 | 1 | `+0x34` | 1 |  | movzx eax, word ptr [rcx + 0x34]; shr eax, 1; and ea
| `0x64` | 0 | 1 | 1 | `+0x34` | 2 |  | movzx eax, word ptr [rcx + 0x34]; shr eax, 2; and ea
| `0x65` | 0 | 1 | 1 | `+0x34` | 3 |  | movzx eax, word ptr [rcx + 0x34]; shr eax, 3; and ea
| `0x66` | 0 | 1 | 1 | `+0x34` | 4 |  | movzx eax, word ptr [rcx + 0x34]; shr eax, 4; and ea
| `0x67` | 0 | 1 | 1 | `+0x34` | 5 |  | movzx eax, word ptr [rcx + 0x34]; shr eax, 5; and ea
| `0x68` | 0 | 1 | 1 | `+0x34` | 6 |  | movzx eax, word ptr [rcx + 0x34]; shr eax, 6; and ea
| `0x69` | 0 | 1 | 1 | `+0x34` | 7 |  | movzx eax, word ptr [rcx + 0x34]; shr eax, 7; and ea
| `0x6A` | 0 | 1 | 1 | `+0x34` | 8 |  | movzx eax, word ptr [rcx + 0x34]; shr eax, 8; and ea
| `0x6B` | 0 | 1 | 1 | `+0x34` | 9 |  | movzx eax, word ptr [rcx + 0x34]; shr eax, 9; and ea
| `0x6C` | 0 | 1 | 1 | `+0x34` | 10 |  | movzx eax, word ptr [rcx + 0x34]; shr eax, 0xa; and 
| `0x6D` | 0 | 1 | 1 | `+0x34` | 11 |  | movzx eax, word ptr [rcx + 0x34]; shr eax, 0xb; and 
| `0x6E` | 0 | 1 | 1 | `+0x34` | 12 |  | movzx eax, word ptr [rcx + 0x34]; shr eax, 0xc; and 
| `0x6F` | 0 | 1 | 1 | `+0x34` | 13 |  | movzx eax, word ptr [rcx + 0x34]; shr eax, 0xd; and 
| `0x70` | 0 | 1 | 1 | `+0x34` | 14 |  | movzx eax, word ptr [rcx + 0x34]; shr eax, 0xe; and 
| `0x71` | 0 | 7 | 3 | `+0x24` | 21 |  | mov eax, dword ptr [rcx + 0x24]; shr eax, 0x15; and 
| `0x72` | 0 | 15 | 4 | `+0x10` | 28 |  | mov eax, dword ptr [rcx + 0x10]; shr eax, 0x1c; mov 
| `0x73` | 0 | 7 | 3 | `+0x27` | 0 |  | movzx eax, byte ptr [rcx + 0x27]; and eax, 7; mov dw
| `0x74` | 0 | 15 | 4 | `+0x14` | 28 |  | mov eax, dword ptr [rcx + 0x14]; shr eax, 0x1c; mov 
| `0x75` | 0 | 15 | 4 | `+0x18` | 28 |  | mov eax, dword ptr [rcx + 0x18]; shr eax, 0x1c; mov 
| `0x76` | 0 | 31 | 5 | `+0x20` | 23 |  | mov eax, dword ptr [rcx + 0x20]; shr eax, 0x17; and 
| `0x77` | 0 | 7 | 3 | `+0x24` | 27 |  | mov eax, dword ptr [rcx + 0x24]; shr eax, 0x1b; and 
| `0x78` | 0 | 255 | 8 | `+0x0C` | 0 |  | movzx eax, byte ptr [rcx + 0xc]; mov dword ptr [rdx]
| `0x79` | 0 | 255 | 8 | `+0x0D` | 0 |  | movzx eax, byte ptr [rcx + 0xd]; mov dword ptr [rdx]

## 25 项能力（判据：min=40 且 max=99 且 位宽=7）

| # | ID | 对象偏移 | 位偏移 | 能力名 |
|---|---|---|---|---|
| 1 | `0x12` | `+0x0E` | 0 | **offensive_awareness** |
| 2 | `0x13` | `+0x0C` | 23 | **ball_control** |
| 3 | `0x14` | `+0x28` | 0 | **tight_possession** |
| 4 | `0x15` | `+0x10` | 0 | **low_pass** |
| 5 | `0x16` | `+0x10` | 7 | **lofted_pass** |
| 6 | `0x17` | `+0x10` | 14 | **finishing** |
| 7 | `0x18` | `+0x10` | 21 | **place_kicking** |
| 8 | `0x19` | `+0x24` | 14 | **curl** |
| 9 | `0x1A` | `+0x14` | 0 | **speed** |
| 10 | `0x1B` | `+0x14` | 7 | **acceleration** |
| 11 | `0x1C` | `+0x14` | 14 | **jump** |
| 12 | `0x1D` | `+0x14` | 21 | **physical_contact** |
| 13 | `0x1E` | `+0x2C` | 13 | **balance** |
| 14 | `0x1F` | `+0x18` | 0 | **stamina** |
| 15 | `0x20` | `+0x18` | 7 | **ball_winning** |
| 16 | `0x21` | `+0x18` | 14 | **aggression** |
| 17 | `0x22` | `+0x18` | 21 | **gk_awareness** |
| 18 | `0x23` | `+0x24` | 0 | **gk_catching** |
| 19 | `0x24` | `+0x1C` | 0 | **gk_reach** |
| 20 | `0x25` | `+0x1C` | 7 | **defensive_awareness** |
| 21 | `0x26` | `+0x1C` | 14 | **gk_clearing** |
| 22 | `0x27` | `+0x1C` | 21 | **heading** |
| 23 | `0x28` | `+0x24` | 7 | **dribbling** |
| 24 | `0x29` | `+0x2C` | 6 | **gk_reflexes** |
| 25 | `0x2A` | `+0x20` | 0 | **kicking_power** |

（共 25 项 —— 与 PES 的 25 项能力一一对应）

> **定序依据**：本表 ID 0x12~0x2A 的顺序与 EDIT 存档位流顺序
> （`core/fit_weights.py` 的 `ABIL_ORDER`）逐条吻合，且与 docs ⑫⑬ 已实证的
> 「组偏移」100% 对上：low_pass..place_kicking 同在 `+0x10`、
> speed..physical_contact 同在 `+0x14`、stamina..gk_awareness 同在 `+0x18`、
> gk_reach..heading 同在 `+0x1C`、balance/gk_reflexes 同在 `+0x2C`、
> curl/gk_catching/dribbling 同在 `+0x24`。
> 另经已知球员语义校验（莱诺 GK 五项高、非 GK 的 gk_* 恒 40，见 docs ⑪）。

## 2bit 字段组（疑似 13 位置熟练度，待验证）

判据 `位宽=2 且 max=2`：与熟练度取值 `0=C/1=B/2=A` 吻合。
社区已知 13 个可踢位置（`core/build_player_browser.py` 的 `PLAYABLE_ORDER`）：
GK, CB, LB, RB, DMF, CMF, LM, RM, AMF, RWF, SS, CF, LWF。

| # | ID | 对象偏移 | 位偏移 |
|---|---|---|---|
| 1 | `0x2E` | `+0x28` | 7 |
| 2 | `0x32` | `+0x28` | 11 |
| 3 | `0x33` | `+0x28` | 13 |
| 4 | `0x34` | `+0x28` | 15 |
| 5 | `0x35` | `+0x28` | 17 |
| 6 | `0x36` | `+0x28` | 19 |
| 7 | `0x37` | `+0x28` | 21 |
| 8 | `0x38` | `+0x28` | 23 |
| 9 | `0x39` | `+0x28` | 25 |
| 10 | `0x3A` | `+0x28` | 27 |
| 11 | `0x3B` | `+0x28` | 29 |
| 12 | `0x3C` | `+0x2C` | 20 |
| 13 | `0x3D` | `+0x2C` | 0 |
| 14 | `0x3E` | `+0x2C` | 2 |
| 15 | `0x3F` | `+0x2C` | 4 |

（共 15 项，多于 13 —— 哪 13 个对应熟练度需用已知球员的 13 位串反查，
本表只给出候选范围。`+0x28` 的 bit7/9/11/…/29 是 12 个连续 2bit 槽，
形态上最像一组数组式字段。）

## 表2：ID 0x7A~0x7C（0x28 步长，非位域直拷）

| ID | min | max | getter | setter |
|---|---|---|---|---|
| `0x7A` | 20 | 61 | `0x1414087F0`  | `0x1414092D0` |
| `0x7B` | 20 | 61 | `0x141408DA0`  | `0x141409C70` |
| `0x7C` | 20 | 61 | `0x141408DF0`  | `0x141409CD0` |
