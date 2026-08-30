# PES 2021 游戏内对象字段布局（源自社区 Cheat Table）

- 来源：`resources/CT/PES 2021 - v21.1.0 英文版/PES 2021 - v21.1.0.CT`
- 用途：CT 表是社区逆向的**字段字典**（名称+偏移+类型），可用于反解存档/EDIT 记录。
- 注意：这是**运行时对象**布局，与存档/EDIT 的紧凑序列化**不一一对应**，
  但字段语义与相对顺序可作为解读线索（已成功定位 EDIT 的身高/体重，见 §对照）。


## 基址 `ptrBudget`（2 字段）

| 偏移 | 类型 | 字段名 |
|---|---|---|
| `+016ECBF4` | 4 Bytes | Transfer Budget |
| `+16ecc08` | 4 Bytes | Salary Budget |

## 基址 `ptrFocusPoints`（1 字段）

| 偏移 | 类型 | 字段名 |
|---|---|---|
| `+A` | Byte | Focus Points |

## 基址 `ptrPlayer`（128 字段）

| 偏移 | 类型 | 字段名 |
|---|---|---|
| `+0` | Binary | Height (cm) |
| `+1` | Binary | Weight (kg) |
| `+3` | Binary | Stronger Foot |
| `+3` | Binary | Offensive Awareness |
| `+4` | Binary | Defensive Awareness |
| `+4` | Binary | GK Awareness |
| `+5` | Binary | Dribbling |
| `+6` | Binary | Ball Control |
| `+7` | Binary | Registred Position |
| `+8` | Binary | Tight Possession |
| `+8` | Binary | Finishing |
| `+9` | Binary | Low Pass |
| `+A` | Binary | Lofted Pass |
| `+C` | Binary | Heading |
| `+c` | Binary | Ball Winning |
| `+D` | Binary | Aggression |
| `+e` | Binary | Place Kicking |
| `+10` | Binary | Curl |
| `+10` | Binary | GK Catching |
| `+11` | Binary | GK Clearing |
| `+12` | Binary | GK Reflexes |
| `+14` | Binary | Speed |
| `+14` | Binary | GK Reach |
| `+15` | Binary | Physical Contact |
| `+16` | Binary | Balance |
| `+17` | Binary | Form |
| `+18` | Binary | Acceleration |
| `+18` | Binary | Kicking Power |
| `+19` | Binary | Jump |
| `+1A` | Binary | Stamina |
| `+1B` | Binary | Trickster |
| `+1C` | Binary | Age |
| `+1D` | Binary | Playing Style |
| `+1F` | Binary | CF - Center Forward |
| `+1F` | Binary | SS - Second Striker |
| `+1f` | Binary | LWF - Left Wing Forward |
| `+1F` | Binary | Mazing Run |
| `+20` | Binary | RWF - Right Wing Forward |
| `+20` | Binary | AMF - Attacking Midfielder |
| `+20` | Binary | CMF - Center Midfielder |
| `+20` | Binary | DMF - Defensive Midfielder |
| `+21` | Binary | LMF - Left Midfielder |
| `+21` | Binary | RMF - Right Midfielder |
| `+21` | Binary | LB - Left Back |
| `+21` | Binary | CB - Center Back |
| `+22` | Binary | RB - Right Back |
| `+22` | Binary | GK - Goalkeeper |
| `+22` | Binary | Weak Foot Accuracy |
| `+22` | Binary | Injury Resistance |
| `+23` | Binary | Weak Foot Usage |
| `+23` | Binary | Speeding Bullet |
| `+23` | Binary | Incisive Run |
| `+24` | Binary | Scissors Feint |
| `+24` | Binary | Flip Flap |
| `+24` | Binary | Marseille Turn |
| `+24` | Binary | Sombrero |
| `+24` | Binary | Cut Behind &amp; Turn |
| `+24` | Binary | Long Ball Expert |
| `+24` | Binary | Early Cross |
| `+24` | Binary | Long Ranger |
| `+25` | Binary | Scotch Move |
| `+25` | Binary | Heading |
| `+25` | Binary | Long Range Drive |
| `+25` | Binary | Knuckle Shot |
| `+25` | Binary | Acrobatic Finishing |
| `+25` | Binary | Heel Trick |
| `+25` | Binary | First-time Shot |
| `+25` | Binary | One-touch Pass |
| `+26` | Binary | Weighted Pass |
| `+26` | Binary | Pinpoint Crossing |
| `+26` | Binary | Outside Curler |
| `+26` | Binary | Rabona |
| `+26` | Binary | Low Lofted Pass |
| `+26` | Binary | GK Low Punt |
| `+26` | Binary | Long Throw |
| `+26` | Binary | GK Long Throw |
| `+27` | Binary | No Look Pass |
| `+27` | Binary | Gamesmanship |
| `+27` | Binary | Man Marking |
| `+27` | Binary | Track Back |
| `+27` | Binary | Acrobatic Clear |
| `+27` | Binary | Captaincy |
| `+27` | Binary | Super-Sub |
| `+27` | Binary | Fighting Spirit |
| `+28` | Binary | Step On Skill control |
| `+28` | Binary | Chip shot control |
| `+28` | Binary | Dipping Shot |
| `+28` | Binary | Rising Shots |
| `+28` | Binary | GK High Punt |
| `+28` | Binary | Penalty Specialist |
| `+28` | Binary | GK Penalty Saver |
| `+28` | Binary | Interception |
| `+29` | Binary | Double Touch |
| `+29` | Binary | Cross Over Turn |
| `+29` | Binary | Long Range Shooting |
| `+29` | Binary | Through Passing |
| `+30` | 4 Bytes | Player ID |
| `+34` | 4 Bytes | Commentary ID |
| `+38` | String | Player Name |
| `+75` | String | Name on Strip (Club) |
| `+B2` | String | Name on Strip (National Team) |
| `+12C` | 2 Bytes | Team (?) |
| `+12E` | 2 Bytes | League (?) |
| `+138` | 2 Bytes | Year |
| `+13A` | Byte | Month |
| `+13B` | Byte | Day |
| `+13E` | Byte | Affection |
| `+13F` | Binary | Max Affection (?) |
| `+13F` | Binary | Is Listed Player |
| `+143` | Binary | Level |
| `+144` | 2 Bytes | Nationality |
| `+146` | Binary | Stamina Bar |
| `+146` | Binary | Blinking Form Arrow |
| `+147` | Binary | Form Arrow |
| `+148` | Byte | Period Unavailable (days) |
| `+14A` | Binary | Is Transfer Listed |
| `+14A` | Binary | Is Loan Listed |
| `+150` | Binary | Team Role |
| `+151` | Byte | Team Player - Lone Wolf |
| `+152` | Byte | Passion - Composure |
| `+153` | Byte | Technique - Strength |
| `+154` | Byte | Insight - Instinct |
| `+155` | Byte | Impact |
| `+15C` | 4 Bytes | Salary (Euro) |
| `+174` | 4 Bytes | Market Value (Euro) |
| `+178` | Byte | ? |
| `+179` | Byte | ? |
| `+17C` | 8 Bytes | end (start+17C) |


## AOB 签名（aobscanmodule）

| 签名名 |
|---|
| `INJECT_ptrPlayer` |
| `INJECT_ptrPlayerTwo` |
| `INJECT_ClubBudget` |
| `INJECT_TrainingOnEnter` |
| `INJECT_TrainingOnChange` |
| `INJECT_MatchTime` |
| `INJECT_UnlimitedStamina` |
