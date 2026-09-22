# 380B → 312B 序列化器 case 全表（`0x1F14670`）

由 `exe/exe_field_serialize.py` 从 exe 静态枚举（只读，不执行其代码）。

- 分派：`cmp ebx,0x7c` ⇒ 字段 ID `0x00`~`0x7C`，共 125 项
- 索引表 `RVA 0x1F15444`（off `0x1F14A44`，125×u8）；跳转表 `RVA 0x1F15410`（off `0x1F14A10`，13×u32）
- 唯一 case 分支数：**13**
- 记录指针 `rdi`（312B 目标），源对象 `rsi`（380B）

## 字段 ID → 312B 记录内位置

| ID | case | 模式 | 记录内位置 | 语义（来自描述符表） |
|---|---|---|---|---|
| `0x00` | 0 | ? |  |  |
| `0x01` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x02` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x03` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x04` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x05` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x06` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x07` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x08` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x09` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x0A` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x0B` | 1 | C | rec+0x04 直拷 |  |
| `0x0C` | 2 | C | rec+0x08 直拷 |  |
| `0x0D` | 3 | B | 位偏移 13（经 0xc2d180 打包） | 年龄 |
| `0x0E` | 4 | A | rec+0x20 bit13 w=5 |  |
| `0x0F` | 5 | B | 位偏移 15（经 0xc2d180 打包） |  |
| `0x10` | 6 | B | 位偏移 16（经 0xc2d180 打包） | 身高 cm |
| `0x11` | 7 | B | 位偏移 17（经 0xc2d180 打包） | 体重 kg |
| `0x12` | 12 | B | 位偏移 ?（未取到 r8d 立即数） | **offensive_awareness** |
| `0x13` | 12 | B | 位偏移 ?（未取到 r8d 立即数） | **ball_control** |
| `0x14` | 12 | B | 位偏移 ?（未取到 r8d 立即数） | **tight_possession** |
| `0x15` | 12 | B | 位偏移 ?（未取到 r8d 立即数） | **low_pass** |
| `0x16` | 12 | B | 位偏移 ?（未取到 r8d 立即数） | **lofted_pass** |
| `0x17` | 12 | B | 位偏移 ?（未取到 r8d 立即数） | **finishing** |
| `0x18` | 12 | B | 位偏移 ?（未取到 r8d 立即数） | **place_kicking** |
| `0x19` | 12 | B | 位偏移 ?（未取到 r8d 立即数） | **curl** |
| `0x1A` | 12 | B | 位偏移 ?（未取到 r8d 立即数） | **speed** |
| `0x1B` | 12 | B | 位偏移 ?（未取到 r8d 立即数） | **acceleration** |
| `0x1C` | 12 | B | 位偏移 ?（未取到 r8d 立即数） | **jump** |
| `0x1D` | 12 | B | 位偏移 ?（未取到 r8d 立即数） | **physical_contact** |
| `0x1E` | 12 | B | 位偏移 ?（未取到 r8d 立即数） | **balance** |
| `0x1F` | 12 | B | 位偏移 ?（未取到 r8d 立即数） | **stamina** |
| `0x20` | 12 | B | 位偏移 ?（未取到 r8d 立即数） | **ball_winning** |
| `0x21` | 12 | B | 位偏移 ?（未取到 r8d 立即数） | **aggression** |
| `0x22` | 12 | B | 位偏移 ?（未取到 r8d 立即数） | **gk_awareness** |
| `0x23` | 12 | B | 位偏移 ?（未取到 r8d 立即数） | **gk_catching** |
| `0x24` | 12 | B | 位偏移 ?（未取到 r8d 立即数） | **gk_reach** |
| `0x25` | 12 | B | 位偏移 ?（未取到 r8d 立即数） | **defensive_awareness** |
| `0x26` | 12 | B | 位偏移 ?（未取到 r8d 立即数） | **gk_clearing** |
| `0x27` | 12 | B | 位偏移 ?（未取到 r8d 立即数） | **heading** |
| `0x28` | 12 | B | 位偏移 ?（未取到 r8d 立即数） | **dribbling** |
| `0x29` | 12 | B | 位偏移 ?（未取到 r8d 立即数） | **gk_reflexes** |
| `0x2A` | 12 | B | 位偏移 ?（未取到 r8d 立即数） | **kicking_power** |
| `0x2B` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x2C` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x2D` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x2E` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x2F` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x30` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x31` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x32` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x33` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x34` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x35` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x36` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x37` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x38` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x39` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x3A` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x3B` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x3C` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x3D` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x3E` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x3F` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x40` | 8 | B | 位偏移 64（经 0xc2d180 打包） |  |
| `0x41` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x42` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x43` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x44` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x45` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x46` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x47` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x48` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x49` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x4A` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x4B` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x4C` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x4D` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x4E` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x4F` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x50` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x51` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x52` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x53` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x54` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x55` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x56` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x57` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x58` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x59` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x5A` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x5B` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x5C` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x5D` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x5E` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x5F` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x60` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x61` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x62` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x63` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x64` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x65` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x66` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x67` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x68` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x69` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x6A` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x6B` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x6C` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x6D` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x6E` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x6F` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x70` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x71` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x72` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x73` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x74` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x75` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x76` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x77` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x78` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x79` | 12 | B | 位偏移 ?（未取到 r8d 立即数） |  |
| `0x7A` | 9 | ? |  |  |
| `0x7B` | 10 | B | 位偏移 64（经 0xc2d180 打包） |  |
| `0x7C` | 11 | B | 位偏移 64（经 0xc2d180 打包） |  |

## 各 case 反汇编

```
case 0 [?] 
  movzx eax, dl; mov rbx, qword ptr [rsp + 0x30]; mov rsi, qword ptr [rsp + 0x40]; add rsp, 0x20; pop rdi; ret 
case 1 [C] rec+0x04 直拷
  mov eax, dword ptr [rsi + 0x34]; mov dword ptr [rdi + 4], eax; mov dl, 1; movzx eax, dl; mov rbx, qword ptr [rsp + 0x30]; mov rsi, qword ptr [rsp + 0x40]; add rsp, 0x20; pop rdi; ret 
case 2 [C] rec+0x08 直拷
  movzx eax, word ptr [rsi + 0x144]; mov word ptr [rdi + 8], ax; jmp 0x1f146c8; lea r8, [rsp + 0x38]; mov dword ptr [rsp + 0x38], 0x14; mov edx, 0x2d; mov rcx, rsi; call 0x14c7c80; movzx edx, byte ptr [
case 3 [B] 位偏移 13（经 0xc2d180 打包）
  lea r8, [rsp + 0x38]; mov dword ptr [rsp + 0x38], 0x14; mov edx, 0x2d; mov rcx, rsi; call 0x14c7c80; movzx edx, byte ptr [rsp + 0x38]; mov r8d, 0xd; mov rcx, rdi; call 0xc2d180; movzx edx, al; mov rbx
case 4 [A] rec+0x20 bit13 w=5
  lea r8, [rsp + 0x38]; mov dword ptr [rsp + 0x38], 0xc; xor edx, edx; mov rcx, rsi; call 0x14c7c80; mov eax, dword ptr [rsp + 0x38]; and dword ptr [rdi + 0x20], 0xfffc1fff; and eax, 0x1f; shl eax, 0xd;
case 5 [B] 位偏移 15（经 0xc2d180 打包）
  lea r8, [rsp + 0x38]; mov dword ptr [rsp + 0x38], 0; mov edx, 0x2a; mov rcx, rsi; call 0x14c7c80; mov edx, dword ptr [rsp + 0x38]; mov r8d, 0xf; mov rcx, rdi; call 0xc2d180; movzx edx, al; mov rbx, qw
case 6 [B] 位偏移 16（经 0xc2d180 打包）
  xor ecx, ecx; mov dword ptr [rsp + 0x38], 0; call 0x14c18e0; mov edx, eax; lea r8, [rsp + 0x38]; mov rcx, rsi; call 0x14c7c80; movzx edx, byte ptr [rsp + 0x38]; mov r8d, 0x10; mov rcx, rdi; call 0xc2d
case 7 [B] 位偏移 17（经 0xc2d180 打包）
  mov ecx, 1; mov dword ptr [rsp + 0x38], 0; call 0x14c18e0; mov edx, eax; lea r8, [rsp + 0x38]; mov rcx, rsi; call 0x14c7c80; movzx edx, byte ptr [rsp + 0x38]; mov r8d, 0x11; mov rcx, rdi; call 0xc2d18
case 8 [B] 位偏移 64（经 0xc2d180 打包）
  mov rcx, rsi; call 0x14c1a40; mov r8d, 0x40; mov edx, eax; mov rcx, rdi; call 0xc2d180; jmp 0x1f14843; lea eax, [rbx - 0x33]; cmp eax, 0xc; ja 0x1f148ce; lea ecx, [rbx - 0x33]; cmp ecx, 0xd; je 0x1f14
case 9 [?] 
  mov rcx, rsi; call 0x14c19c0; mov r9d, 0x7a; mov r8d, 0x3d; mov rdx, rax; mov rcx, rdi; call 0x1ef7e60; movzx edx, al; mov rbx, qword ptr [rsp + 0x30]; mov rsi, qword ptr [rsp + 0x40]; add rsp, 0x20; 
case 10 [B] 位偏移 64（经 0xc2d180 打包）
  mov rcx, rsi; call 0x14c1a00; mov r9d, 0x7b; jmp 0x1f14832; mov rcx, rsi; call 0x14c1a20; mov r9d, 0x7c; jmp 0x1f14832; mov rcx, rsi; call 0x14c1a40; mov r8d, 0x40; mov edx, eax; mov rcx, rdi; call 0x
case 11 [B] 位偏移 64（经 0xc2d180 打包）
  mov rcx, rsi; call 0x14c1a20; mov r9d, 0x7c; jmp 0x1f14832; mov rcx, rsi; call 0x14c1a40; mov r8d, 0x40; mov edx, eax; mov rcx, rdi; call 0xc2d180; jmp 0x1f14843; lea eax, [rbx - 0x33]; cmp eax, 0xc; 
case 12 [B] 位偏移 ?（未取到 r8d 立即数）
  lea eax, [rbx - 0x33]; cmp eax, 0xc; ja 0x1f148ce; lea ecx, [rbx - 0x33]; cmp ecx, 0xd; je 0x1f148ce; mov dword ptr [rsp + 0x38], 0; call 0x14c1960; mov edx, eax; lea r8, [rsp + 0x38]; mov rcx, rsi; c
```
