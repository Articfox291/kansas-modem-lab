#!/usr/bin/env python3
"""dump one function fully with CATI-resolved calls (local-only)."""
import json, sys
from pathlib import Path
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
        else: return n,s
    return None,None
def dump(name):
    p=SIM/"listings"/f"{name}.jsonl"
    lines=p.read_text().splitlines()
    head=json.loads(lines[0])
    print(f"===== {name} va={head['va']:#x} size={head['size']} n={head['n']} sha={head['sha256'][:12]}")
    for ln in lines[1:]:
        r=json.loads(ln)
        fl=[]
        for t in r["flows"]:
            nm,_=resolve(t)
            fl.append(f"{t:#x}={nm or 'UNK'}")
        extra=f"  => {', '.join(fl)}" if fl else ""
        print(f"  {r['va']:#x} +{r['size']}  {r['text']}{extra}")
if __name__=="__main__":
    for a in sys.argv[1:]:
        dump(a)
