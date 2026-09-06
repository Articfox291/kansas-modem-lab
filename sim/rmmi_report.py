#!/usr/bin/env python3
import json
from pathlib import Path
import sys
SIM = Path(__file__).resolve().parent
sys.path.insert(0, str(SIM))
from emu_engine import load_cati
cati = load_cati()
items = sorted(((s,e,n) for n,(s,e) in cati.items()))
def resolve(va):
    lo,hi=0,len(items)-1
    while lo<=hi:
        mid=(lo+hi)//2
        s,e,n=items[mid]
        if va<s: hi=mid-1
        elif va>=e: lo=mid+1
        else: return n
    return None
TARGETS = json.loads((SIM/"rmmi_audit.jsonl").read_text().splitlines()[0])  # placeholder
# actually read audit file
import json as J
auds=[J.loads(l) for l in (SIM/"rmmi_audit.jsonl").read_text().splitlines()]
for a in auds:
    print(f"\n### {a['name']} VA={a['va']:#x} size={a['size']} n={a['n']} span={a['span']}")
    print(f" arg-entry (first 16):")
    for reg in ("a0","a1","a2","a3"):
        hits=a.get("arg_hits",{}).get(reg,[])
        if hits:
            print(f"  {reg}: "+"; ".join(f"{v:#x}:{t}" for v,t in hits[:4]))
    if a.get("at_ptr_cands"):
        print(f" AT-text deref cands (entry loads via aX): {a['at_ptr_cands']}")
    if a.get("byte_derefs"):
        for k,v in a["byte_derefs"].items():
            print(f" byte-loads via {k}: "+"; ".join(f"{vv:#x}:{tt}" for vv,tt in v[:4]))
    print(f" parse/string helpers ({len(a['parse_hits'])}):")
    for h in a["parse_hits"][:24]:
        print(f"  {h['at']:#x}: {h['text']} -> {h['target']:#x} {h['name']}")
    print(f" all BALC ({len(a['helpers'])}):")
    for h in a["helpers"][:40]:
        print(f"  {h['at']:#x}: {h['text']} -> {h['target']:#x} {h['name']}")
    print(f" indirect ({len(a['indirect'])}):")
    for b in a["indirect"]:
        print(f"  {b['va']:#x}: {b['op']} {b['text']} regs={b['regs']}")
    print(f" loops-back ({len(a['loops'])}):")
    for lp in a["loops"][:12]:
        print(f"  {lp['at']:#x}: {lp['text']} -> {lp['target']:#x} back={lp['back']}")
    print(f" lenops sample:")
    for v,t in a.get("lenops",[])[:12]:
        print(f"  {v:#x}: {t}")
