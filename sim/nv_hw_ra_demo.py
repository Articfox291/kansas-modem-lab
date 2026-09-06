#!/usr/bin/env python3
"""nv_hw_ra_demo.py — show RESTORE.JRC with controlled ra (strict)."""
import sys
from pathlib import Path
SIM_DIR = Path(__file__).resolve().parent
if str(SIM_DIR) not in sys.path:
    sys.path.insert(0, str(SIM_DIR))
from nv_hw_overflow import run_one

for ln in [16,52,64]:
    cpu,res,info = run_one(ln)
    print(f"=== len={ln} pre-RET ra_slot={info['ra_slot']:#x} val={info['ra_val']:#x}" if isinstance(info['ra_val'],int) else f"=== len={ln} ra_slot fault ===")
    # cpu.pc is at RET (0x919ad686). Execute it manually
    pc = cpu.pc
    print(f"  stopped at {pc:#x} ({info['stop']}) ra_cpu={cpu.get('ra'):#x} sp={cpu.get('sp'):#x}")
    try:
        text,size,_ = cpu._decode_at(pc)
    except Exception as e:
        print(f"  decode RET fault: {e}")
        continue
    print(f"  RET insn: {text}")
    try:
        npc = cpu.step_once_internal(pc, text, size)
        print(f"  after RESTORE.JRC: npc={npc:#x} ra={cpu.get('ra'):#x} sp={cpu.get('sp'):#x} s0={cpu.get('s0'):#x}")
        if npc == 0x42424242:
            print(f"  CONTROLLED RA: JRC to attacker 0x42424242 (len {ln} overwrites saved-ra)")
        elif ln==16 and npc == 0xDEAD0000:
            print(f"  SAFE: returns to caller RA_INIT (no overwrite)")
        else:
            print(f"  npc={npc:#x}")
        # try decode at npc (should fault in strict since 0x42424242 unmapped)
        try:
            t2,s2,_ = cpu._decode_at(npc)
            print(f"  decode @npc: {t2}")
        except Exception as e:
            print(f"  decode @npc fault (expected for controlled): {e}")
    except Exception as e:
        print(f"  step fault: {e}")
    print()
