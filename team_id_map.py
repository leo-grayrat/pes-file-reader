#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
team_id (Konami 球队 ID) -> 队名 映射 (最终版)
来源:
  1) 社区补丁公布的 Konami ID->队名 (ICMP 2021 V1.0 / SoFrench Patch 2023-24)
  2) dt10 Team.bin (739 条, 按联赛排序; 国家队段 team_id 与索引严格 1:1)
验证: 我们的 team_id 418=Saint-Etienne / 420=Troyes 与补丁一致;
      国家队 team_id 1..57 与 Team.bin 1:1 (1=Ireland,57=Latvia)。
Team.bin 是联赛排序, 俱乐部段 team_id != 索引, 故俱乐部只能用补丁名或最佳推测。
"""
import csv, zlib, struct, os

# ---------- 1) 补丁 ID->队名 (高置信) ----------
PATCH = {}
def add(d):
    for tid, name in d.items():
        PATCH[int(tid)] = name

add({"4127":"Arminia Bielefeld","4124":"Augsburg","128":"Bayer Leverkusen","127":"Bayern Munchen",
"126":"Borussia Dortmund","226":"Eintracht Frankfurt","227":"Freiburg","4125":"Hertha Berlin",
"4126":"Hoffenheim","4137":"Koln","5010":"RB Leipzig","436":"Mainz 05","225":"Monchengladbach",
"184":"Schalke 04","231":"Stuttgart","4140":"Union Berlin","185":"Werder Bremen","232":"Wolfsburg"})
add({"2178":"APOEL","2409":"Astana","2075":"Austria Wien","4349":"BATE Borisov","1746":"CFR Cluj",
"1223":"Crvena Zvezda","2531":"CSKA Sofia","4351":"Dudelange","2016":"Dundalk","2094":"Dynamo Brest",
"1206":"FC Slovan Liberec","2008":"Zorya Luhansk","1216":"FCSB","2357":"Ferencvaros","1227":"Goteborg",
"2525":"Hajduk Split","2534":"Hapoel Beer-Sheva","1733":"HJK Helsinki","2526":"HNK Rijeka",
"2126":"Lech Poznan","2078":"LASK","1756":"Legia Warszawa","4355":"Ludogorets","2101":"Maccabi Tel Aviv",
"1702":"Malmo","4345":"Maribor","5242":"Molde","2400":"Oleksandriya","2185":"Omonia","272":"Partizan",
"4326":"Qarabag","1819":"Rapid Wien","1215":"Rosenborg","1586":"Red Bull Salzburg","4344":"Slovan Bratislava",
"2037":"Viktoria Plzen","6014":"Wolfsberger"})
add({"169":"Avispa Fukuoka","168":"Cerezo Osaka","144":"Consadole Sapporo","150":"FC Tokyo","157":"Gamba Osaka",
"146":"Kashima Antlers","149":"Kashiwa Reysol","163":"Kawasaki Frontale","155":"Nagoya Grampus","171":"Oita Trinita",
"170":"Sagan Tosu","159":"Sanfrecce Hiroshima","153":"Shimizu S-Pulse","165":"Shonan Bellmare","1270":"Tokushima Vortis",
"147":"Urawa Red Diamonds","145":"Vegalta Sendai","158":"Vissel Kobe","152":"Yokohama F. Marinos","164":"Yokohama FC"})
add({"2658":"Barcelona SC","5015":"Carabobo","2205":"Caracas","2681":"Cerro Largo","2283":"Club Bolivar",
"1260":"Cerro Porteno","2213":"Club Guarani","2198":"Club Libertad","2214":"Club Nacional","1262":"Nacional Montevideo",
"1261":"Olimpia","2217":"Defensor Sporting","5434":"Delfin","5488":"Deportivo Binacional","2687":"Deportivo Lara",
"2218":"Deportivo Tachira","2212":"El Nacional","2286":"Emelec","5438":"Estudiantes Merida","2659":"Independiente del Valle",
"2358":"LDU Quito","1907":"Macara","2661":"Macara2","1263":"Penarol","2685":"Progreso","2189":"San Jose",
"2502":"The Strongest","1926":"Tigre"})
add({"1099":"Canada","1050":"Congo DR","1104":"El Salvador","1056":"Gabon","1107":"Guatemala",
"1008":"India","1017":"Malaysia","1029":"Syria","1082":"Uganda","1033":"Vietnam"})
add({"1386":"Esperance Tunis","2704":"American Classics","2703":"European Classics","6015":"World Legends",
"6016":"World Myths","6017":"World Stars","6018":"World Symbols","6019":"World Veterans"})
add({"1329":"Brest","407":"Clermont","182":"Lens","213":"Lille","414":"Lorient","181":"Lyon","113":"Marseille",
"112":"Monaco","215":"Montpellier","216":"Nantes","217":"Nice","114":"Paris Saint-Germain","1330":"Reims",
"218":"Rennes","4213":"Strasbourg","221":"Toulouse","413":"Le Havre","4123":"Metz"})
add({"403":"Angers","420":"Troyes","4200":"Amiens","405":"Caen","4370":"Grenoble","211":"Guingamp","4211":"Paris FC",
"5099":"Pau","5100":"Quevilly","4372":"Rodez","1528":"Valenciennes","115":"Bordeaux","209":"Ajaccio","180":"Auxerre",
"418":"Saint-Etienne","5685":"Annecy","210":"Bastia","5097":"Concarneau","4206":"Dunkerque","412":"Laval"})
add({"5687":"Versailles","4212":"Red Star","4972":"Avranches","5213":"Cholet","406":"Chateauroux","5098":"GOAL",
"5442":"Marignane","5686":"Martigues","415":"Nancy","416":"Niort","1910":"Nimes","4210":"Orleans","4373":"Rouen",
"5443":"Villefranche","4974":"Epinal","212":"Le Mans","1328":"Dijon","219":"Sochaux"})
add({"130":"Galatasaray","133":"Olympiacos","134":"Dynamo Kyiv","175":"Sparta Praha","197":"Fenerbahce",
"198":"Panathinaikos","270":"AEK Athens","273":"Besiktas","1203":"Dinamo Zagreb","1212":"PAOK",
"1213":"Maccabi Haifa","1223":"Crvena Zvezda","1224":"Zrinjski Mostar","1232":"Shakhtar Donetsk",
"1304":"Breidablik","1498":"FC Sheriff","1586":"Red Bull Salzburg","1733":"HJK Helsinki","1756":"Legia Warszawa",
"1950":"Young Boys","1958":"Servette","2008":"Zorya Luhansk","2018":"Spartak Trnava","2037":"Viktoria Plzen",
"2054":"Cukaricki","2078":"LASK","2081":"Sturm Graz","2101":"Maccabi Tel-Aviv","2374":"Astana2","2375":"Ferencvarosi",
"2396":"Olimpija Ljubljana","4326":"Qarabag","4344":"Slovan Bratislava","4355":"Ludogorets","4965":"Lugano",
"5189":"Slavia Praha","5242":"Molde","5253":"Bodo/Glimt","5288":"Rakow","5322":"BK Hacken","5901":"TSC Backa Topola",
"5902":"KI Klaksvik","5903":"Ballkani","5904":"Aris Limassol"})

# ---------- 2) Team.bin 名 (pesdb 索引 1..739, 联赛排序) ----------
def load_teambin():
    b=open('outputs/cpk_extract_dt10/common/etc/Team.bin','rb').read()
    out=zlib.decompressobj().decompress(b[0x10:])
    REC=1532; START=0x100; NT=(len(out)-START)//REC
    names={}
    for i in range(1,NT+1):
        o=START+(i-1)*REC
        nm=out[o+0x70:o+0x70+48].split(b'\x00',1)[0].decode('latin1','replace').strip()
        names[i]=nm
    return names, NT
teambin, NT = load_teambin()

# 国家队 ID 集合 (team_id 与 Team.bin 索引 1:1 验证段 1..57, 跳过 25/58 空隙)
NATION_IDS = set(range(1,25)) | set(range(26,58))

# ---------- 3) 读取我们 694 team_id ----------
our=[]
with open('outputs/edit_team_players.csv',encoding='utf-8') as f:
    for r in csv.DictReader(f):
        our.append(int(r['team_id']))

# ---------- 4) 输出带置信度 ----------
os.makedirs('outputs',exist_ok=True)
rows=[]
conf_count={'HIGH':0,'MED':0,'LOW':0}
for t in our:
    if t in PATCH:
        rows.append((t,PATCH[t],'patch','HIGH')); conf_count['HIGH']+=1
    elif t in NATION_IDS and t<=NT:
        rows.append((t,teambin[t],'team_id=pesdb(国家队1:1)','HIGH')); conf_count['HIGH']+=1
    elif t<=NT:
        rows.append((t,teambin[t],'Team.bin推测(俱乐部,可能改链)','MED')); conf_count['MED']+=1
    else:
        rows.append((t,'(补丁新增/EDIT自定义,缺补丁表)','-','LOW')); conf_count['LOW']+=1

with open('outputs/team_id_names_final.csv','w',newline='',encoding='utf-8') as f:
    w=csv.writer(f); w.writerow(['team_id','name','source','confidence'])
    for t,nm,src,c in rows: w.writerow([t,nm,src,c])

print('我们 team_id 总数: %d' % len(our))
print('  高置信(HIGH): %d  (国家队1:1 + 补丁命名)' % conf_count['HIGH'])
print('  中置信(MED):  %d  (<=739 俱乐部, Team.bin推测)' % conf_count['MED'])
print('  低置信(LOW):  %d  (>739 补丁新增/自定义)' % conf_count['LOW'])
print('已写出 outputs/team_id_names_final.csv')
print()
print('=== 高置信队名样例(前 20) ===')
shown=0
for t,nm,src,c in rows:
    if c=='HIGH':
        print('  %5d %-28s [%s]' % (t,nm,src))
        shown+=1
        if shown>=20: break
