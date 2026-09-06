import json, pathlib
from pathlib import Path
SIM=Path(__file__).resolve().parent
REPO=SIM.parent
import sys
sys.path.insert(0,str(SIM))
from emu_engine import load_cati
cati=load_cati()
# build sorted VA list for nearest-symbol resolution
items=sorted([(v[0],v[1],k) for k,v in cati.items()])
def resolve(va):
    # exact or containing
    import bisect
    # find function containing va
    lo,hi=0,len(items)-1
    for s,e,n in items:
        if s<=va<e:
            return f"{n}+{va-s:#x}"
    # nearest below
    best=None
    for s,e,n in items:
        if s<=va and (best is None or s>best[0]):
            best=(s,e,n)
    if best and va-best[0]<0x1000:
        return f"{best[2]}+{va-best[0]:#x}?"
    return f"unknown_{va:#x}"
names=['sml_Nvram_get_lid_size','sml_init_sml_obj','sml_sec_nvram_get_para','sml_sec_nvram_read_to_data','sml_sec_nvram_read','sml_sec_nvram_read_gblob','sml_sec_nvram_write','sml_sec_nvram_write_with_data','sml_sec_sync_nvram_read_cnf_handler','sml_sec_reload_all_sim_lock_context','sml_reload_sml_context_extend','smu_load_sml_data_from_nvram','cust_sml_nvram_read_error_handler','custom_sml_read_custom_nvram','custom_sml_is_nvram_accessable_check','nvram_external_read_data','nvram_external_write_data','nvram_SW_AES_encrypt_ext','nvram_HW_AES_encrypt_ext','SST_Get_HRID_ciphertext','sml_op12t_is_nv_read']
for n in names:
 p=SIM/("listings/"+n+".jsonl")
 lines=open(p).read().strip().splitlines()
 h=json.loads(lines[0])
 recs=[json.loads(l) for l in lines[1:]]
 print(f"\n===== {n} VA={h['va']:#x} size={h['size']} n={len(recs)} =====")
 # indirect
 for r in recs:
  t=r['text']
  up=t.upper()
  if 'JALRC' in up or 'BRSC' in up or 'JRC' in up or 'JR ' in up or up.startswith('JR'):
   print(f"  INDIRECT {r['va']:#x}: {t}  flows={r['flows']}")
 # BALC resolved
 for r in recs:
  if 'BALC' in r['text'].upper():
   # extract targets from flows or text
   print(f"  CALL {r['va']:#x}: {r['text']} -> {[hex(x)+'='+resolve(x) for x in r['flows']]}")
   # if no flows (MOVE.BALC has target too? flows only for BALC-family absolute? parse shows flows for BALC only, but MOVE.BALC also has flows per decomp? Actually decomp only captures BALC substring, MOVE.BALC contains BALC so also captured. Good.)
 # MUL/ADD
 for r in recs:
  up=r['text'].upper()
  if any(k in up for k in ['MUL','LSA','ADDU','ADDIU','ADD','SLL','SRLV','SUBU','EXT','INS']):
   print(f"  ARITH {r['va']:#x}: {r['text']}")
 # BREAK / mem ops
 for r in recs:
  up=r['text'].upper()
  if 'BREAK' in up or 'LBU' in up or 'LH' in up or 'LW' in up or 'SW' in up or 'SH' in up or 'SB' in up or 'MEMCPY' in up or '90023558' in r['text'] or '90024A2E' in r['text'].upper():
   pass
 # print BREAKs
 for r in recs:
  if 'BREAK' in r['text'].upper():
   print(f"  BREAK {r['va']:#x}: {r['text']}")
