# 社区资源：PES2021 EDIT 存档格式文档（implyingrigged.info）

> 来源：`https://implyingrigged.info/wiki/Pro_Evolution_Soccer_2021/Edit_file`
> （本站直连返回 403，经 Wayback Machine 快照 2022-05-22 抓取原始内容。）
> 补充佐证：GitHub `kickoffsage/pes2021-transfer-tool`（MIT，Python），其 `src/team_utils.py`
> 用同一套偏移读写 EDIT 存档，交叉验证一致。
> 归档日期：2026-08-28。

## 一、这是什么东西

社区（Rigged Wiki / 4chan 杯）逆向的 **EDIT00000000**（EDIT 存档，即球队/球员名单编辑存档，
位于 `Documents\KONAMI\eFootball PES 2021 SEASON UPDATE\%steamid%\save`）的**完整二进制格式文档**。
注意：本文档针对 **EDIT 存档**，非 ML/BL 生涯存档，但字段语义、压缩编码方式、方法论完全可复用。

该文档明确标注：**适用于 PES2020 与 PES2021**。

## 二、EDIT 存档 data.dat 结构（解密后视图）

文件 = 顺序排列的若干区段，各区段条目数由 Header 中的 2 字节计数决定：

```
Header (0x7C)
Player entries            (240 B/条, 0xF0)     ← 0xDE12=4830 条
Player appearance entries (72 B/条, 0x48)      ← 紧随 player entry
Team entries              (588 B/条, 0x24C)    ← 0xD200=210 条
Manager entries                                ← 0xE700=231 条
Competition entries                            ← 0x2E00=46 条
Stadium entries                                ← 0x3700=55 条
Undocumented entries                           ← 0x4F00=79 条
Team-Player table                              ← 0xD200=210 条
Competition entry entries
Team Game Plan entries                         ← 0xD200=210 条
```

### Header 计数表（解密后 data.dat 的前 0x7C，前 0x60 字节文档未标注）

| 偏移 | 长度 | 含义 | 默认值 |
|---|---|---|---|
| +0x60 | 2B | 球员条目数（data+appearance） | 0xDE12 (4830) |
| +0x64 | 2B | 球队条目数 | 0xD200 (210) |
| +0x66 | 2B | 经理条目数 | 0xE700 (231) |
| +0x68 | 2B | 球场条目数 | 0x3700 (55) |
| +0x6A | 2B | 赛事条目数 | 0x2E00 (46) |
| +0x6C | 2B | 未文档化条目数 | 0x4F00 (79) |
| +0x70 | 2B | Team-Player 表条目数 | 0xD200 (210) |
| +0x74 | 2B | Game Plan 条目数 | 0xD200 (210) |

## 三、Player entry 关键字段（240 字节，位级压缩）

能力值一律 **7 位**、范围 **[40, 99]**；身高/体重/年龄为整字节；名字为定长空终止字符串。

| 偏移 | 长度 | 字段 |
|---|---|---|
| +0x00 | 4B | Player ID（>= 1048576） |
| +0x04 | 4B | Commentary Name（引用 player ID） |
| +0x08 | 2B | 国籍/地区（0x0401=Others） |
| +0x0A | 1B | 身高 cm [155,210] |
| +0x0B | 1B | 体重 kg |
| +0x0E~+0x20 | 位段 | 26 项能力值（Offensive Awareness、Ball Control、Finishing、Speed…），7 位封装 |
| +0x1F:4 | 3b | Conditioning |
| +0x20:7 | 6b | 年龄 [15,50] |
| +0x21:5 | 4b | 注册位置（0=GK … 12=CF） |
| +0x22:2 | 5b | Playing Style（0~21 枚举） |
| +0x23:4 | 3b | Star Rating（声誉） |
| +0x2F:5 | 1b | 惯用脚 |
| +0x2F:7 | 7b | COM Playing Style 位掩码 |
| +0x30:6 | 41b | 球员技能位掩码（41 项） |
| +0x36 | 61B | Player Name（空终止字符串） |
| +0x73 | 61B | Print Name (Club)（球衣名，大写） |
| +0xB0 | 64B | Print Name (National Team) |

## 四、Team entry 关键字段（588 字节 = 0x24C）

| 偏移 | 长度 | 字段 |
|---|---|---|
| +0x00 | 4B | Team ID |
| +0x04 | 4B | Manager ID |
| +0x08 | 2B | Team Emblem（0xFFFF=默认） |
| +0x0A | 2B | Home Stadium（引用 Stadium ID） |
| +0x0E | 2B | Team Nationality（0x0401=Others） |
| +0x10 | 2B | Team Callname |
| +0x12+ | 位段 | 球门网/队服颜色（R/G/B 各 6 位） |
| （队名/缩写紧随其后，见 transfer-tool 中 +0x69 (100 字节偏移) 附近 70 字节队名字符串） | | |

## 五、Team-Player Table（球队 ↔ 球员关联）

原文：`Team ID` + 40 个 `Player ID`（4B each）+ 40 个球衣号（2B each）。
transfer-tool 的 `read_team_data` 代码精确对应：

```python
team_id        = read 4B            # 球队 ID
team_player_ids = [read 4B] * 40    # 40 名球员 ID（0 表示空位）
shirt_numbers   = [read 2B] * 40    # 40 个球衣号
skip 40 bytes                        # 其余
```

## 六、对本项目的启示（重要）

1. **方法论库**：社区逆向 PES 存档的通用手法是「Header 计数 + 定长/位段条目链 + 字符串定长块」。
   本项目 BL/ML 的 data 块头部（+0x10/+0x14 = 球队数 700）正是同款计数模式。
2. **能力值/球员属性语义**：26 项能力值 + 身高体重年龄位置的**取值范围与命名**（7 位、40~99、
   位置枚举 0~12、技能掩码 41 项）全部可直接用于 ML/BL 存档用户球员记录的语义标注。
3. **存档布局仍不能直接照搬**：EDIT 的 Player entry 名字在 +0x36，而本项目 BL00000000 用户球员
   记录名字在 +0x08/+0x44/+0x82（见 `docs/community_findings.md` 第四节）——
   印证「EDIT 与 ML/BL 的序列化布局不同，字段语义/单位/命名可复用，偏移必须重新对拍」。
4. **Team-Player Table 是「对阵双方」线索的旁证**：球队→40 球员 ID 的成对表结构说明，
   ML/BL 里的对阵双方（主/客）大概率也是「球队 ID + 球员列表」形态，而非两个裸 ID。

## 七、后续可挖的同类页面

wiki 侧边栏列出其他专属页面：`Team_IDs`、`Tools`、`zlib`、`Tactical`、`Full_Player_Customization` 等。
若需球队/球员/国家 ID→名称对照，或 CPK/存档 zlib 压缩细节，可循 Wayback 抓取对应页面。