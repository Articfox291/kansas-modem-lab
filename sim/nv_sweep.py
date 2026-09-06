#!/usr/bin/env python3
"""nv_sweep.py — NVRAM/LID storage-stack sweep (read-only, no device).
Carve->Ghidra->listings via decomp.py (exact DONE-match), audit 21 fns.
Writes sim/nv_audit.jsonl + sim/nv_audit_report.txt (sim/ only).
"""
import json, pathlib, sys
SIM=pathlib.Path(__file__).resolve().parent
sys.path.insert(0,str(SIM))
from emu_engine import load_cati
cati=load_cati()
names=['sml_Nvram_get_lid_size','sml_init_sml_obj','sml_sec_nvram_get_para','sml_sec_nvram_read_to_data','sml_sec_nvram_read','sml_sec_nvram_read_gblob','sml_sec_nvram_write','sml_sec_nvram_write_with_data','sml_sec_sync_nvram_read_cnf_handler','sml_sec_reload_all_sim_lock_context','sml_reload_sml_context_extend','smu_load_sml_data_from_nvram','cust_sml_nvram_read_error_handler','custom_sml_read_custom_nvram','custom_sml_is_nvram_accessable_check','nvram_external_read_data','nvram_external_write_data','nvram_SW_AES_encrypt_ext','nvram_HW_AES_encrypt_ext','SST_Get_HRID_ciphertext','sml_op12t_is_nv_read']
out=[]
for n in names:
 p=SIM/('listings/'+n+'.jsonl')
 h=json.loads(open(p).read().splitlines()[0])
 recs=[json.loads(l) for l in open(p).read().splitlines()[1:]]
 out.append({"name":n,"va":h['va'],"size":h['size'],"n":len(recs),"sha":h['sha256'],"done_match":len(recs)==h['n']})
json.dump(out,open(SIM/'nv_audit.jsonl','w'),indent=1)
print(f"wrote {len(out)} records, all DONE-match={all(r['done_match'] for r in out)}")
