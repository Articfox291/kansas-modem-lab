#!/usr/bin/env python3
"""nv_hw_verdict.py — reproduce caller sweep + strict overflow demo, emit verdict.

Stdlib + local Ghidra (decode_tables) only. No device. New files only under sim/.
Usage: python sim/nv_hw_verdict.py  (writes sim/nv_hw_verdict.json)
"""
import json, struct, sys
from pathlib import Path
SIM_DIR = Path(__file__).resolve().parent
if str(SIM_DIR) not in sys.path:
    sys.path.insert(0, str(SIM_DIR))
from nv_hw_overflow import run_one

ROM = SIM_DIR.parent / "md1work_romonly.bin"
VA_BASE = 0x90000000
HW = 0x919ad648
SW = 0x919ad3de
DISP = 0x90609fca
SEC = 0x917c71fe

def sext(v,bits):
    return v-(1<<bits) if v & (1<<(bits-1)) else v

def sweep():
    data = ROM.read_bytes()
    # BALC32
    balc32 = []
    for val in (0x2A,0x2B):
        idx = data.find(bytes([val]),0)
        while idx>=0:
            if idx%2==1 and idx-1+4<=len(data):
                i=idx-1
                hi=data[i]|(data[i+1]<<8)
                if (hi>>10)==0b001010 and ((hi>>9)&1)==1:
                    lo=data[i+2]|(data[i+3]<<8)
                    v=((lo&1)<<25)|((hi&0x1FF)<<16)|(((lo>>1)&0x7FFF)<<1)
                    tgt=(VA_BASE+i+4+sext(v,26))&0xFFFFFFFF
                    if tgt in (HW,SW,DISP,SEC):
                        balc32.append((VA_BASE+i,tgt))
            idx=data.find(bytes([val]),idx+1)
    # BALC16
    balc16=[]
    for val in (0x38,0x39,0x3A,0x3B):
        idx=data.find(bytes([val]),0)
        while idx>=0:
            if idx%2==1 and idx-1+2<=len(data):
                i=idx-1
                hi=data[i]|(data[i+1]<<8)
                if (hi>>10)==0b001110:
                    v=((hi&1)<<10)|(((hi>>1)&0x1FF)<<1)
                    tgt=(VA_BASE+i+2+sext(v,11))&0xFFFFFFFF
                    if tgt in (HW,SW,DISP,SEC):
                        balc16.append((VA_BASE+i,tgt))
            idx=data.find(bytes([val]),idx+1)
    # VA-bytes (absolute pointers)
    va_hits=[]
    for tgt in (HW,SW):
        pat=struct.pack("<I",tgt)
        idx=0
        while True:
            i=data.find(pat,idx)
            if i<0: break
            va_hits.append((VA_BASE+i,tgt))
            idx=i+1
    return balc32,balc16,va_hits

if __name__ == "__main__":
    balc32,balc16,vah = sweep()
    sim=[]
    for ln in [16,52,64,777,4516]:
        cpu,res,info = run_one(ln)
        # execute RET to show controlled pc
        pc0=cpu.pc
        try:
            text,size,_=cpu._decode_at(pc0)
            npc=cpu.step_once_internal(pc0,text,size)
        except Exception as e:
            npc=f"FAULT:{e}"
        sim.append({"len":ln,"dst":f"{info['dst']:#x}","ra_slot":f"{info['ra_slot']:#x}",
            "ra_slot_val":f"{info['ra_val']:#x}" if isinstance(info['ra_val'],int) else str(info['ra_val']),
            "stop":info['stop'],"steps":info['steps'],"ret_at":f"{info['ret_at']:#x}",
            "npc_after_RET":f"{npc:#x}" if isinstance(npc,int) else str(npc),
            "overwritten":info['overwritten']})
    out={"HW":f"{HW:#x}","SW":f"{SW:#x}","BALC32":[[f"{a:#x}",f"{t:#x}"] for a,t in sorted(balc32)],
         "BALC16":[[f"{a:#x}",f"{t:#x}"] for a,t in sorted(balc16)],
         "VA_bytes_hits":vah,"sim":sim,
         "verdict":"REFUTED (primitive real but unreachable; max reachable len 8/32; see report)"}
    p=SIM_DIR/"nv_hw_verdict.json"
    p.write_text(json.dumps(out,indent=2))
    print(f"wrote {p} BALC32={len(balc32)} BALC16={len(balc16)} VAbytes={len(vah)}")
    for r in sim:
        print(r)
