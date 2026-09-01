#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""build_player_browser.py -- 把已解码的 EDIT 球员能力值+隐藏机制生成为一个
自包含 HTML 球员浏览器（数据内嵌 JSON，双击即开，read-only，不依赖游戏进程）。

数据源：outputs/edit_player_abilities.csv（edit_player_abilities.py 产出，27513 人）。
布局/标签来源：implyingrigged.info/wiki/Pro_Evolution_Soccer_2021/Edit_file

本工具是「外置于游戏、直接读取存档的独立 UI 工具」的第一块（B=球员检索/筛选 UI）。
真正的存档解码发生在 Python（pesfile.py / edit_player_abilities.py），本 HTML 是展示层。
用法：python build_player_browser.py
"""
import os, csv, json

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(BASE, "outputs", "edit_player_abilities.csv")
OUT = os.path.join(BASE, "outputs", "player_browser.html")

# ---- 与 edit_player_abilities.py / wiki 对齐的标签表 ----
REG_POS_NAMES = ["GK", "CB", "LB", "RB", "DMF", "CMF", "LM", "RM",
                 "AMF", "LWF", "RWF", "SS", "CF"]
# 可踢位置 13 位串的内部顺序（与注册位置顺序在 9-12 不同！）
PLAYABLE_ORDER = ["GK", "CB", "LB", "RB", "DMF", "CMF", "LM", "RM", "AMF",
                  "RWF", "SS", "CF", "LWF"]
PLAY_STYLES = ["None", "Goal Poacher", "Dummy Runner", "Fox in the Box", "Target Man",
              "Creative Playmaker", "Prolific Winger", "Roaming Flank", "Cross Specialist",
              "Classic No. 10", "Hole Player", "Box-to-Box", "The Destroyer", "Orchestrator",
              "Anchor Man", "Offensive Full-back", "Full-back Finisher", "Defensive Full-back",
              "Build Up", "Extra Frontman", "Offensive Goalkeeper", "Defensive Goalkeeper"]
SKILLS = ["Scissors Feint", "Double Touch", "Flip Flap", "Marseille Turn", "Sombrero",
          "Cross Over Turn", "Cut Behind & Turn", "Scotch Move", "Step On Skill Control",
          "Heading", "Long Range Drive", "Chip Shot Control", "Long Range Shooting",
          "Knuckle Shot", "Dipping Shots", "Rising Shots", "Acrobatic Finishing", "Heel Trick",
          "First-time Shot", "One-touch Pass", "Through Passing", "Weighted Pass",
          "Pinpoint Crossing", "Outside Curler", "Rabona", "No Look Pass", "Low Lofted Pass",
          "GK Low Punt", "GK High Punt", "Long Throw", "GK Long Throw", "Penalty Specialist",
          "GK Penalty Saver", "Gamesmanship", "Man Marking", "Track Back", "Interception",
          "Acrobatic Clear", "Captaincy", "Super-sub", "Fighting Spirit"]
COM_STYLES = ["Trickster", "Mazing Run", "Speeding Bullet", "Incisive Run", "Long Ball Expert",
              "Early Cross", "Long Ranger"]
ABIL_ORDER = ["offensive_awareness", "ball_control", "tight_possession", "low_pass", "lofted_pass",
              "finishing", "place_kicking", "curl", "speed", "acceleration", "jump",
              "physical_contact", "balance", "stamina", "ball_winning", "aggression",
              "gk_awareness", "gk_catching", "gk_reach", "defensive_awareness", "gk_clearing",
              "heading", "dribbling", "gk_reflexes", "kicking_power"]
ABIL_LABEL = {
    "offensive_awareness": "进攻意识", "ball_control": "控球", "tight_possession": "紧密控球",
    "low_pass": "地面传球", "lofted_pass": "空中传球", "finishing": "射门", "place_kicking": "定位球",
    "curl": "弧线球", "speed": "速度", "acceleration": "加速", "jump": "弹跳",
    "physical_contact": "身体接触", "balance": "平衡", "stamina": "耐力", "ball_winning": "抢断",
    "aggression": "积极性", "gk_awareness": "GK 意识", "gk_catching": "GK 扑救",
    "gk_reach": "GK 臂展", "defensive_awareness": "防守意识", "gk_clearing": "GK 解围",
    "heading": "头球", "dribbling": "盘带", "gk_reflexes": "GK 反应", "kicking_power": "射门力量",
}

def main():
    if not os.path.exists(SRC):
        raise SystemExit("缺少数据源 %s，请先运行 edit_player_abilities.py" % SRC)
    players = []
    with open(SRC, encoding="utf-8", newline="") as f:
        r = csv.DictReader(f)
        for row in r:
            try:
                ab = [int(row[k]) for k in ABIL_ORDER]
            except (KeyError, ValueError):
                continue
            # 技能 / COM 风格：CSV 里是分号连接的名字串 -> 还原为下标数组
            sk_names = [s for s in (row.get("skills") or "").split(";") if s]
            com_names = [s for s in (row.get("com_styles") or "").split(";") if s]
            sk_idx = [SKILLS.index(s) for s in sk_names if s in SKILLS]
            com_idx = [COM_STYLES.index(s) for s in com_names if s in COM_STYLES]
            rec = [
                int(row["pid"]) if row.get("pid") else 0,
                row.get("name", ""),
                int(row["nat"]) if row.get("nat") else 0,
                int(row["age"]) if row.get("age") else 0,
                int(row["reg_pos"]) if row.get("reg_pos") not in (None, "") else 0,
                int(row["play_style"]) if row.get("play_style") not in (None, "") else 0,
                1 if (row.get("stronger_foot") or "").startswith("L") else 0,
                int(row["weak_foot_usage"]) if row.get("weak_foot_usage") not in (None, "") else 1,
                int(row["weak_foot_accuracy"]) if row.get("weak_foot_accuracy") not in (None, "") else 1,
                int(row["injury_resistance"]) if row.get("injury_resistance") not in (None, "") else 1,
                int(row["conditioning"]) if row.get("conditioning") not in (None, "") else 1,
                int(row["star_rating"]) if row.get("star_rating") not in (None, "") else 0,
                row.get("playable", "0" * 13)[:13],
                com_idx,
                sk_idx,
                ab,
            ]
            players.append(rec)

    meta = {
        "source": "EDIT00000000.data (decoded) -> edit_player_abilities.py",
        "count": len(players),
        "abilities": ABIL_ORDER,
        "abilityLabels": [ABIL_LABEL.get(k, k) for k in ABIL_ORDER],
        "positions": REG_POS_NAMES,
        "playableOrder": PLAYABLE_ORDER,
        "playStyles": PLAY_STYLES,
        "skills": SKILLS,
        "comStyles": COM_STYLES,
    }
    data = {"meta": meta, "players": players}
    js = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    # 防止 </script> 注入
    js = js.replace("<", "\\u003c")

    html = TEMPLATE.replace("__DATA_JSON__", js)
    with open(OUT, "w", encoding="utf-8") as f:
        f.write(html)
    size = os.path.getsize(OUT)
    print("已生成 %s" % OUT)
    print("球员数: %d  文件大小: %.2f MB" % (len(players), size / 1048576.0))


TEMPLATE = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PES2021 球员浏览器（EDIT 能力值 + 隐藏机制）</title>
<style>
  :root{
    --bg:#0e1320; --panel:#161d2e; --panel2:#1d2740; --line:#2a3550;
    --txt:#e6ecf5; --dim:#8b97b0; --accent:#4da3ff; --accent2:#ffcb47;
    --good:#3fbf6f; --mid:#f4b740; --low:#e2603f; --gk:#9b6bff;
  }
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--txt);
    font-family:-apple-system,"Segoe UI","Microsoft YaHei",system-ui,sans-serif;font-size:13px;}
  header{padding:12px 18px;background:linear-gradient(90deg,#13203b,#0e1320);
    border-bottom:1px solid var(--line);display:flex;align-items:baseline;gap:14px;flex-wrap:wrap}
  header h1{font-size:16px;margin:0;color:var(--accent)}
  header .src{color:var(--dim);font-size:11px}
  header .cnt{margin-left:auto;color:var(--accent2);font-weight:600}
  .wrap{display:flex;gap:0;align-items:flex-start}
  /* 筛选面板 */
  .filters{width:280px;flex:0 0 280px;position:sticky;top:0;align-self:flex-start;
    max-height:100vh;overflow:auto;background:var(--panel);border-right:1px solid var(--line);padding:14px}
  .filters h3{font-size:12px;color:var(--accent);margin:14px 0 6px;text-transform:uppercase;letter-spacing:.5px}
  .filters h3:first-child{margin-top:0}
  .fld{margin-bottom:8px}
  .fld label{display:block;color:var(--dim);margin-bottom:3px;font-size:11px}
  select,input[type=text],input[type=number]{width:100%;background:var(--panel2);color:var(--txt);
    border:1px solid var(--line);border-radius:6px;padding:6px 8px;font-size:12px}
  input[type=text]:focus,select:focus{outline:1px solid var(--accent)}
  .row2{display:flex;gap:6px}
  .row2>div{flex:1}
  .chips{display:flex;flex-wrap:wrap;gap:5px;max-height:150px;overflow:auto;padding:4px;
    background:var(--panel2);border:1px solid var(--line);border-radius:6px}
  .chip{padding:3px 7px;border-radius:12px;background:#243152;color:var(--dim);cursor:pointer;
    font-size:11px;border:1px solid transparent;user-select:none}
  .chip.on{background:var(--accent);color:#06101f;border-color:var(--accent);font-weight:600}
  .mode{font-size:11px;color:var(--dim);margin:4px 0}
  .mode b{color:var(--accent2);cursor:pointer}
  /* 结果区 */
  .results{flex:1;min-width:0;padding:12px 16px}
  .rtools{display:flex;gap:10px;align-items:center;margin-bottom:8px;flex-wrap:wrap}
  .rtools .n{color:var(--accent2);font-weight:600}
  table{width:100%;border-collapse:collapse;font-size:12px}
  th,td{padding:6px 8px;text-align:left;border-bottom:1px solid var(--line)}
  th{color:var(--dim);font-weight:600;position:sticky;top:0;background:var(--bg);cursor:pointer;user-select:none}
  tbody tr{cursor:pointer}
  tbody tr:hover{background:var(--panel2)}
  .pos{display:inline-block;min-width:30px;text-align:center;padding:1px 5px;border-radius:4px;
    background:#243152;color:var(--txt);font-weight:600;font-size:11px}
  .pos.GK{background:var(--gk);color:#0e1320}
  .ov{font-weight:700;color:var(--accent2)}
  .badge{display:inline-block;padding:0 5px;border-radius:3px;font-size:10px;margin-right:3px}
  .bA{background:var(--good);color:#06101f}.bB{background:var(--mid);color:#06101f}.bC{background:#3a4767;color:var(--txt)}
  /* 详情弹窗 */
  .mask{position:fixed;inset:0;background:rgba(4,8,16,.72);display:none;align-items:flex-start;
    justify-content:center;padding:30px 12px;overflow:auto;z-index:50}
  .mask.show{display:flex}
  .card{width:680px;max-width:100%;background:var(--panel);border:1px solid var(--line);
    border-radius:12px;padding:18px 20px}
  .card h2{margin:0 0 2px;font-size:19px}
  .card .sub{color:var(--dim);font-size:12px;margin-bottom:12px}
  .close{float:right;cursor:pointer;color:var(--dim);font-size:20px;line-height:1}
  .grid{display:grid;grid-template-columns:1fr 1fr;gap:6px 18px;margin:10px 0}
  .kv{display:flex;justify-content:space-between;border-bottom:1px dashed var(--line);padding:3px 0}
  .kv span:first-child{color:var(--dim)}
  .bars{margin-top:10px}
  .bar{display:flex;align-items:center;gap:8px;margin:4px 0}
  .bar .nm{width:84px;color:var(--dim);font-size:11px;flex:0 0 84px}
  .bar .track{flex:1;height:12px;background:#223; border-radius:6px;overflow:hidden}
  .bar .fill{height:100%;border-radius:6px}
  .bar .v{width:26px;text-align:right;font-weight:600;font-size:11px}
  .secttl{margin:14px 0 4px;color:var(--accent);font-size:12px;font-weight:600;
    text-transform:uppercase;letter-spacing:.5px;border-top:1px solid var(--line);padding-top:10px}
  .tag{display:inline-block;background:#243152;color:var(--txt);padding:2px 7px;border-radius:5px;
    margin:2px 3px 2px 0;font-size:11px}
  .tag.gk{background:var(--gk);color:#0e1320}
  .playpos{display:flex;flex-wrap:wrap;gap:5px}
  .pp{display:flex;align-items:center;gap:4px;background:var(--panel2);border:1px solid var(--line);
    border-radius:6px;padding:3px 7px;font-size:11px}
  .foot{color:var(--dim);font-size:11px;margin-top:14px;border-top:1px solid var(--line);padding-top:8px}
  .clearbtn{background:#2a3550;color:var(--txt);border:1px solid var(--line);border-radius:6px;
    padding:6px 10px;cursor:pointer;font-size:12px}
  .clearbtn:hover{background:#34436a}
</style>
</head>
<body>
<header>
  <h1>PES2021 球员浏览器</h1>
  <span class="src" id="srcLine"></span>
  <span class="cnt" id="cntLine"></span>
</header>
<div class="wrap">
  <aside class="filters">
    <h3>检索条件</h3>
    <div class="fld"><label>姓名（含子串）</label><input type="text" id="fName" placeholder="如 梅西 / Messi"></div>
    <div class="fld"><label>注册位置</label><select id="fPos"></select></div>
    <div class="fld"><label>比赛风格</label><select id="fStyle"></select></div>
    <div class="fld"><label>惯用脚</label><select id="fFoot">
      <option value="-1">全部</option><option value="0">右脚</option><option value="1">左脚</option></select></div>

    <h3>能力值筛选</h3>
    <div class="fld"><label>指定能力值</label><select id="fAbil"></select></div>
    <div class="row2">
      <div class="fld"><label>最低</label><input type="number" id="fMin" min="40" max="99" value="40"></div>
      <div class="fld"><label>最高</label><input type="number" id="fMax" min="40" max="99" value="99"></div>
    </div>

    <h3>隐藏机制</h3>
    <div class="row2">
      <div class="fld"><label>逆足使用 ≥</label><input type="number" id="fWfu" min="1" max="4" value="1"></div>
      <div class="fld"><label>逆足精度 ≥</label><input type="number" id="fWfa" min="1" max="4" value="1"></div>
    </div>
    <div class="row2">
      <div class="fld"><label>抗伤 ≥</label><input type="number" id="fIr" min="1" max="3" value="1"></div>
      <div class="fld"><label>状态 ≥</label><input type="number" id="fCond" min="1" max="8" value="1"></div>
    </div>

    <h3>技能筛选 <span class="mode">匹配：<b id="skMode">任一</b></span></h3>
    <div class="chips" id="skChips"></div>
    <h3>COM 风格 <span class="mode">匹配：<b id="comMode">任一</b></span></h3>
    <div class="chips" id="comChips"></div>

    <div style="margin-top:14px"><button class="clearbtn" id="clearBtn">清空全部条件</button></div>
  </aside>

  <main class="results">
    <div class="rtools">
      <span class="n" id="resN">0 名球员</span>
      <span style="color:var(--dim)">排序</span>
      <select id="sortBy" style="width:auto"></select>
      <span style="color:var(--dim);font-size:11px">（仅渲染前 300 条，请先筛选/排序收敛）</span>
    </div>
    <table>
      <thead><tr>
        <th data-k="name">姓名</th><th data-k="pos">位置</th><th data-k="style">风格</th>
        <th data-k="age">年龄</th><th data-k="ov">总评</th><th>前 3 能力</th>
      </tr></thead>
      <tbody id="tbody"></tbody>
    </table>
  </main>
</div>

<div class="mask" id="mask">
  <div class="card" id="card"></div>
</div>

<script>
const DATA = __DATA_JSON__;
const M = DATA.meta, P = DATA.players;
// 球员数组下标: 0 pid,1 name,2 nat,3 age,4 rp,5 ps,6 sf,7 wfu,8 wfa,9 ir,10 cond,11 star,12 play,13 com,14 sk,15 ab
const $=s=>document.querySelector(s);
const ov=p=>Math.round(p[15].reduce((a,b)=>a+b,0)/p[15].length);

// 初始化下拉
(function(){
  $('#srcLine').textContent='数据源: '+M.source+'  |  '+M.count+' 名球员';
  const pos=document.createElement('select');pos.id='fPos';
  pos.innerHTML='<option value="-1">全部</option>'+M.positions.map((n,i)=>`<option value="${i}">${n}</option>`).join('');
  $('#fPos').replaceWith(pos);
  const st=document.createElement('select');st.id='fStyle';
  st.innerHTML='<option value="-1">全部</option>'+M.playStyles.map((n,i)=>`<option value="${i}">${n}</option>`).join('');
  $('#fStyle').replaceWith(st);
  const ab=document.createElement('select');ab.id='fAbil';
  ab.innerHTML='<option value="-1">不限制</option>'+M.abilities.map((n,i)=>`<option value="${i}">${M.abilityLabels[i]}</option>`).join('');
  $('#fAbil').replaceWith(ab);
  $('#sortBy').innerHTML='<option value="ov">总评(高→低)</option><option value="name">姓名</option>'+
    M.abilities.map((n,i)=>`<option value="a${i}">${M.abilityLabels[i]}(高→低)</option>`).join('')+
    '<option value="ageD">年龄(高→低)</option>';
  // 技能 chips
  $('#skChips').innerHTML=M.skills.map((n,i)=>`<span class="chip" data-i="${i}">${n}</span>`).join('');
  $('#comChips').innerHTML=M.comStyles.map((n,i)=>`<span class="chip" data-i="${i}">${n}</span>`).join('');
})();

const sel={sk:new Set(),com:new Set()};
let skMode='any',comMode='any';
$('#skChips').onclick=e=>{if(e.target.dataset.i!=null){const i=+e.target.dataset.i;sel.sk.has(i)?sel.sk.delete(i):sel.sk.add(i);e.target.classList.toggle('on');run();}};
$('#comChips').onclick=e=>{if(e.target.dataset.i!=null){const i=+e.target.dataset.i;sel.com.has(i)?sel.com.delete(i):sel.com.add(i);e.target.classList.toggle('on');run();}};
$('#skMode').onclick=()=>{skMode=skMode==='any'?'all':'any';$('#skMode').textContent=skMode==='any'?'任一':'全部';run();};
$('#comMode').onclick=()=>{comMode=comMode==='any'?'all':'any';$('#comMode').textContent=comMode==='any'?'任一':'全部';run();};

['fName','fPos','fStyle','fFoot','fAbil','fMin','fMax','fWfu','fWfa','fIr','fCond','sortBy']
  .forEach(id=>{const el=$('#'+id);el.addEventListener('input',run);el.addEventListener('change',run);});
$('#clearBtn').onclick=()=>{
  $('#fName').value='';$('#fPos').value='-1';$('#fStyle').value='-1';$('#fFoot').value='-1';
  $('#fAbil').value='-1';$('#fMin').value=40;$('#fMax').value=99;
  $('#fWfu').value=1;$('#fWfa').value=1;$('#fIr').value=1;$('#fCond').value=1;
  sel.sk.clear();sel.com.clear();skMode='any';comMode='any';
  $('#skMode').textContent='任一';$('#comMode').textContent='任一';
  document.querySelectorAll('.chip.on').forEach(c=>c.classList.remove('on'));run();
};

function filt(){
  const name=$('#fName').value.trim().toLowerCase();
  const pos=+$('#fPos').value, sty=+$('#fStyle').value, foot=+$('#fFoot').value;
  const abi=+$('#fAbil').value, mn=+$('#fMin').value, mx=+$('#fMax').value;
  const wfu=+$('#fWfu').value, wfa=+$('#fWfa').value, ir=+$('#fIr').value, cond=+$('#fCond').value;
  const out=[];
  for(const p of P){
    if(name && !p[1].toLowerCase().includes(name))continue;
    if(pos>=0 && p[4]!==pos)continue;
    if(sty>=0 && p[5]!==sty)continue;
    if(foot>=0 && p[6]!==foot)continue;
    if(abi>=0){const v=p[15][abi];if(v<mn||v>mx)continue;}
    if(p[7]<wfu||p[8]<wfa||p[9]<ir||p[10]<cond)continue;
    if(sel.sk.size){const hs=p[14];const ok=skMode==='all'?([...sel.sk].every(i=>hs.includes(i))):([...sel.sk].some(i=>hs.includes(i)));if(!ok)continue;}
    if(sel.com.size){const hc=p[13];const ok=comMode==='all'?([...sel.com].every(i=>hc.includes(i))):([...sel.com].some(i=>hc.includes(i)));if(!ok)continue;}
    out.push(p);
  }
  return out;
}
function sortLst(a){
  const k=$('#sortBy').value;
  if(k==='name')a.sort((x,y)=>x[1].localeCompare(y[1],'zh'));
  else if(k==='ageD')a.sort((x,y)=>y[3]-x[3]);
  else if(k==='ov')a.sort((x,y)=>ov(y)-ov(x));
  else if(k.startsWith('a')){const i=+k.slice(1);a.sort((x,y)=>y[15][i]-x[15][i]);}
  return a;
}
function run(){
  let a=sortLst(filt());
  $('#resN').textContent=a.length+' 名球员';
  $('#cntLine').textContent='共 '+M.count+' 人 · 命中 '+a.length;
  const tb=$('#tbody');tb.innerHTML='';
  const top=a.slice(0,300);
  for(const p of top){
    const tr=document.createElement('tr');tr.onclick=()=>openDetail(p);
    const top3=[...p[15]].map((v,i)=>[v,i]).sort((x,y)=>y[0]-x[0]).slice(0,3);
    tr.innerHTML=`<td>${p[1]}</td>`+
      `<td><span class="pos ${M.positions[p[4]]}">${M.positions[p[4]]}</span></td>`+
      `<td>${M.playStyles[p[5]]}</td><td>${p[3]}</td>`+
      `<td class="ov">${ov(p)}</td>`+
      `<td>${top3.map(([v,i])=>`<span class="badge bA">${M.abilityLabels[i]} ${v}</span>`).join('')}</td>`;
    tb.appendChild(tr);
  }
}
// 表头排序点击
document.querySelectorAll('th[data-k]').forEach(th=>th.onclick=()=>{
  const k=th.dataset.k;const map={name:'name',pos:'rp',style:'ps',age:'ageD',ov:'ov'};
  if(map[k]){$('#sortBy').value=map[k];run();}
});

function gradeBadge(g){return g===2?'<span class="bA">A</span>':g===1?'<span class="bB">B</span>':'<span class="bC">C</span>';}
function openDetail(p){
  const o=ov(p);
  // 可踢位置
  let pp='';
  for(let i=0;i<13;i++){const g=+p[12][i];const nm=M.playableOrder[i];
    pp+=`<span class="pp">${nm} ${gradeBadge(g)}</span>`;}
  // 技能
  const sk=p[14].map(i=>`<span class="tag">${M.skills[i]}</span>`).join('')||'<span style="color:var(--dim)">无</span>';
  const com=p[13].map(i=>`<span class="tag gk">${M.comStyles[i]}</span>`).join('')||'<span style="color:var(--dim)">无</span>';
  // 能力条
  const bars=M.abilities.map((n,i)=>{const v=p[15][i];const c=v>=85?'var(--good)':v>=75?'var(--accent)':v>=60?'var(--mid)':'var(--low)';
    return `<div class="bar"><div class="nm">${M.abilityLabels[i]}</div><div class="track"><div class="fill" style="width:${v}%;background:${c}"></div></div><div class="v">${v}</div></div>`;}).join('');
  const footTxt=p[6]?'左脚':'右脚';
  $('#card').innerHTML=
    `<span class="close" onclick="closeD()">✕</span>`+
    `<h2>${p[1]}</h2>`+
    `<div class="sub">pid ${p[0]} · 国籍码 ${p[2]} · 总评 ${o} · 球星评级 ${p[11]}</div>`+
    `<div class="grid">`+
      kv('注册位置',M.positions[p[4]])+kv('比赛风格',M.playStyles[p[5]])+
      kv('年龄',p[3])+kv('惯用脚',footTxt)+
      kv('逆足使用',p[7]+' / 4')+kv('逆足精度',p[8]+' / 4')+
      kv('抗伤',p[9]+' / 3')+kv('状态',p[10]+' / 8')+
    `</div>`+
    `<div class="secttl">可踢位置 (全位置默认 C，少数升 B/A)</div><div class="playpos">${pp}</div>`+
    `<div class="secttl">能力值（25 项）</div><div class="bars">${bars}</div>`+
    `<div class="secttl">球员技能 (${p[14].length})</div>${sk}`+
    `<div class="secttl">COM 比赛风格 (${p[13].length})</div>${com}`+
    `<div class="foot">数据来自 EDIT 存档解码（implyingrigged.info 字段表）。本工具 read-only，不写回存档。</div>`;
  $('#mask').classList.add('show');
}
function kv(k,v){return `<div class="kv"><span>${k}</span><span>${v}</span></div>`;}
function closeD(){$('#mask').classList.remove('show');}
$('#mask').onclick=e=>{if(e.target.id==='mask')closeD();};
document.addEventListener('keydown',e=>{if(e.key==='Escape')closeD();});
run();
</script>
</body>
</html>
"""

if __name__ == "__main__":
    main()
