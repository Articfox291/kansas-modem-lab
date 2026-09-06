#!/usr/bin/env python3
"""Build emu_window.html — interactive emulated-run test bench (offline).

Reads sim/chains preset runs + fork results, inlines them as JSON into a
self-contained page: run picker, step slider, play, code highlight, memory
feed, verdict + stop banners, fork 3x3 board, conform mini-table.

Usage: python tools/emu_window.py  (writes emu_window.html at repo root)
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHAINS = ROOT / "sim" / "chains"

RUNS = ["pi_legal", "pi_link", "pi_esmlck", "pi_verify", "link_run",
        "pi_verify_repro"]


def load_run(d):
    p = CHAINS / d
    if not (p / "chain_summary.json").exists():
        return None
    def rows(n):
        f = p / n
        if not f.exists():
            return []
        return [json.loads(l) for l in f.read_text().splitlines() if l.strip()]
    return {"summary": json.loads((p / "chain_summary.json").read_text()),
            "code": rows("chain_code.jsonl"),
            "mem": rows("chain_mem.jsonl")}


def main():
    data = {}
    for r in RUNS:
        v = load_run(r)
        if v:
            data[r] = v
    forks, fdir = [], CHAINS / "pi_verify_fork"
    if (fdir / "fork_results.json").exists():
        frows = json.loads((fdir / "fork_results.json").read_text())
        for row in frows:
            tag = ("c1_%08x_c2_%08x" % (int(row["v1_va"], 16),
                                        int(row["v2_va"], 16)))
            sub = fdir / tag
            code, mem = [], []
            if (sub / "chain_code.jsonl").exists():
                code = [json.loads(l) for l in
                        (sub / "chain_code.jsonl").read_text().splitlines()
                        if l.strip()]
            if (sub / "chain_mem.jsonl").exists():
                mem = [json.loads(l) for l in
                       (sub / "chain_mem.jsonl").read_text().splitlines()
                       if l.strip()]
            forks.append({"row": row, "code": code, "mem": mem})
    data["_forks"] = forks
    # proven conform numbers (interp --conform): legal stock vs patch
    data["_conform"] = [
        {"fn": "legal_sim_rule", "variant": "stock",
         "a0": "0x0", "steps": 25, "note": "25-step HIT-RET, verdict ILLEGAL"},
        {"fn": "legal_sim_rule", "variant": "patch (live on slot A)",
         "a0": "0x1", "steps": 1, "note": "1-step HIT-RET (LI a0,1; JRC ra)"},
    ]
    blob = json.dumps(data).replace("</", "<\\/")
    html = PAGE.replace("__DATA__", blob)
    out = ROOT / "emu_window.html"
    out.write_text(html, encoding="utf-8")
    print(f"wrote {out} ({out.stat().st_size // 1024} KB, "
          f"{len(data) - 2} runs + {len(forks)} forks)")


PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Modem Emu Bench — step the actual runs</title>
<style>
:root{--bg:#0b0e12;--card:#141a24;--line:#2d3849;--txt:#d6dde6;--dim:#8b949e;--acc:#2ea043}
body{background:var(--bg);color:var(--txt);font-family:Consolas,Menlo,monospace;margin:0;padding:16px}
h1{font-size:17px;margin:0 0 2px} .sub{color:var(--dim);font-size:11.5px;margin-bottom:12px}
.grid{display:grid;grid-template-columns:250px 1fr 330px;gap:12px}
.panel{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px}
.panel h3{font-size:12px;margin:0 0 8px;color:#fff}
select,button,input[type=range]{font:inherit}
select{width:100%;background:#0e1319;color:var(--txt);border:1px solid var(--line);border-radius:4px;padding:5px}
button{background:#1c2534;color:var(--txt);border:1px solid var(--line);border-radius:4px;padding:5px 10px;cursor:pointer;margin:2px}
button:hover{border-color:var(--acc)} input[type=range]{width:100%}
#code{max-height:52vh;overflow-y:auto;font-size:11.5px}
.insn{padding:2px 6px;border-radius:3px;white-space:pre;cursor:pointer}
.insn.cur{background:#1f3a2a;border-left:3px solid var(--acc)}
.insn .pc{color:#8fc3ff} .insn.cur .pc{color:#fff}
#mem{max-height:22vh;overflow-y:auto;font-size:11px}
.mr{padding:2px 6px;border-bottom:1px solid #1c2330} .mw{color:#e8c547} .mrd{color:#8fc3ff}
.banner{border-radius:6px;padding:8px;margin:8px 0;font-size:12px}
.b-ok{background:#12341f;border:1px solid #2ea043} .b-bad{background:#3a1717;border:1px solid #c0392b}
table{border-collapse:collapse;font-size:11px;width:100%}
td,th{border:1px solid var(--line);padding:4px 6px;text-align:left}
td.pick{cursor:pointer} td.pick:hover{background:#1f3a2a} td.sel{background:#1f3a2a}
.kv{font-size:11.5px} .kv b{color:#fff} .dim{color:var(--dim);font-size:11px}
#stepinfo{font-size:12px;margin:6px 0}
</style>
</head>
<body>
<h1>Modem Emu Bench</h1>
<div class="sub">Real carved-ROM traces (strict mode) + getItem fork board. No registers banked per step — code, memory feed, verdicts. Data: sim/chains.</div>
<div class="grid">
<div class="panel"><h3>Run</h3>
<select id="run"></select>
<div class="kv" id="runmeta" style="margin-top:8px"></div>
<h3 style="margin-top:12px">Fork board (V1 × V2)</h3>
<table id="fork"></table>
<h3 style="margin-top:12px">Conform (legal)</h3>
<table id="conform"></table>
</div>
<div class="panel"><h3>Trace</h3>
<div>
<button id="prev">◀ prev</button>
<button id="play">▶ play</button>
<button id="next">next ▶</button>
<button id="end">end ⏭</button>
</div>
<input type="range" id="slider" min="0" value="0">
<div id="stepinfo"></div>
<div id="code"></div>
</div>
<div class="panel"><h3>State</h3>
<div id="verdict"></div>
<h3 style="margin-top:10px">Memory feed</h3>
<div id="mem"></div>
<h3 style="margin-top:10px">Gaps</h3>
<div id="gaps" class="dim"></div>
</div>
</div>
<script>
const DATA = __DATA__;
let cur = {key:null, code:[], mem:[], summary:{}, step:0, timer:null};
const $ = id => document.getElementById(id);
function fmtPc(p){ return (typeof p === 'number') ? '0x'+p.toString(16) : String(p); }
function loadRun(key){
  stop();
  let code=[], mem=[], summary={};
  if(key.startsWith('fork:')){
    const f = DATA._forks[+key.slice(5)];
    code=f.code; mem=f.mem;
    summary={stop:f.row.stop, pc:f.row.pc, a0:f.row.a0, steps:f.row.steps,
             gaps:f.row.gaps||[], auto_stubs:[],
             note:'fork V1='+f.row.v1_va+' V2='+f.row.v2_va+' status='+f.row.status};
  } else {
    const r = DATA[key]; code=r.code; mem=r.mem; summary=r.summary;
  }
  cur = {key, code, mem, summary, step:0, timer:null};
  $('slider').max = Math.max(0, code.length-1); $('slider').value = 0;
  render();
}
function render(){
  const n = cur.code.length;
  $('stepinfo').textContent = n ? `step ${cur.step+1}/${n}` : 'no code events';
  let html='';
  cur.code.forEach((c,i)=>{
    html += `<div class="insn${i===cur.step?' cur':''}" data-i="${i}"><span class="pc">${fmtPc(c.pc)}</span>  ${escapeHtml(c.text||'')}</div>`;
  });
  $('code').innerHTML = html;
  document.querySelectorAll('.insn').forEach(el=>{
    el.onclick = ()=>{ stop(); cur.step=+el.dataset.i; $('slider').value=cur.step; render(); };
  });
  const el = document.querySelector('.insn.cur');
  if(el) el.scrollIntoView({block:'nearest'});
  const s = cur.summary;
  const ok = /HIT-RET/.test(s.stop||'');
  $('verdict').innerHTML = `<div class="banner ${ok?'b-ok':'b-bad'}">stop=<b>${escapeHtml(s.stop||'?')}</b><br>a0=<b>${escapeHtml(String(s.a0??'?'))}</b> steps=${s.steps??'?'} pc=${escapeHtml(fmtPc(s.pc))}${s.note?'<br>'+escapeHtml(s.note):''}</div>`;
  let mh='';
  cur.mem.filter(m=>(m.step??0)<=cur.step).slice(-40).forEach(m=>{
    mh += `<div class="mr"><span class="${m.kind==='write'?'mw':'mrd'}">${m.kind}</span> ${m.addr} +${m.size} <span class="dim">${escapeHtml((m.data||'').slice(0,48))}</span></div>`;
  });
  $('mem').innerHTML = mh || '<span class="dim">no memory events yet</span>';
  $('gaps').innerHTML = (s.gaps||[]).map(g=>escapeHtml(g)).join('<br>') || 'none';
  const runMeta = cur.key.startsWith('fork:') ? 'fork trace (real callee bytes)' :
    `code=${cur.code.length} mem=${cur.mem.length} auto_stubs=${JSON.stringify(s.auto_stubs||[])}`;
  $('runmeta').innerHTML = runMeta;
}
function escapeHtml(t){ return String(t).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
function step(d){ if(!cur.code.length) return; cur.step=Math.min(cur.code.length-1,Math.max(0,cur.step+d)); $('slider').value=cur.step; render(); }
function stop(){ if(cur.timer){ clearInterval(cur.timer); cur.timer=null; $('play').textContent='▶ play'; } }
$('prev').onclick=()=>{stop();step(-1)}; $('next').onclick=()=>{stop();step(1)};
$('end').onclick=()=>{stop();cur.step=cur.code.length-1;$('slider').value=cur.step;render()};
$('slider').oninput=e=>{stop();cur.step=+e.target.value;render()};
$('play').onclick=()=>{
  if(cur.timer){ stop(); return; }
  $('play').textContent='⏸ pause';
  cur.timer=setInterval(()=>{ if(cur.step>=cur.code.length-1){stop();return;} cur.step++; $('slider').value=cur.step; render(); },120);
};
// run picker
Object.keys(DATA).filter(k=>!k.startsWith('_')).forEach(k=>{
  const o=document.createElement('option'); o.value=k; o.textContent=k; $('run').appendChild(o);
});
DATA._forks.forEach((f,i)=>{
  const o=document.createElement('option'); o.value='fork:'+i;
  o.textContent=`fork V1=${f.row.v1_va.slice(6)} V2=${f.row.v2_va.slice(6)} [${f.row.status}]`;
  $('run').appendChild(o);
});
$('run').onchange=e=>loadRun(e.target.value);
// fork board
(function(){
  const vs=[...new Set(DATA._forks.map(f=>f.row.v1_va))];
  let h='<tr><th>V1\\V2</th>'+vs.map(v=>`<th>${v.slice(6)}</th>`).join('')+'</tr>';
  vs.forEach(v1=>{
    h+=`<tr><th>${v1.slice(6)}</th>`;
    vs.forEach(v2=>{
      const i=DATA._forks.findIndex(f=>f.row.v1_va===v1&&f.row.v2_va===v2);
      const r=DATA._forks[i].row;
      h+=`<td class="pick" data-i="${i}">${r.status}<br><span class="dim">${escapeHtml(r.stop||'')}</span></td>`;
    });
    h+='</tr>';
  });
  $('fork').innerHTML=h;
  document.querySelectorAll('#fork td.pick').forEach(td=>{
    td.onclick=()=>{ document.querySelectorAll('#fork td').forEach(x=>x.classList.remove('sel')); td.classList.add('sel'); $('run').value='fork:'+td.dataset.i; loadRun('fork:'+td.dataset.i); };
  });
})();
// conform
$('conform').innerHTML='<tr><th>variant</th><th>a0</th><th>steps</th></tr>'+DATA._conform.map(c=>`<tr><td>${c.variant}</td><td>${c.a0}</td><td>${c.steps}</td></tr>`).join('')+
`<tr><td colspan="3" class="dim">stock=ILLEGAL, patch=LEGAL (live on slot A)</td></tr>`;
loadRun($('run').value);
</script>
</body>
</html>""";


if __name__ == "__main__":
    main()
