import json, pathlib
d=pathlib.Path('sim/listings')
names=['sml_Nvram_get_lid_size','sml_init_sml_obj','sml_sec_nvram_get_para','sml_sec_nvram_read_to_data','sml_sec_nvram_read','sml_sec_nvram_read_gblob','sml_sec_nvram_write','sml_sec_nvram_write_with_data','sml_sec_sync_nvram_read_cnf_handler','sml_sec_reload_all_sim_lock_context','sml_reload_sml_context_extend','smu_load_sml_data_from_nvram','cust_sml_nvram_read_error_handler','custom_sml_read_custom_nvram','custom_sml_is_nvram_accessable_check','nvram_external_read_data','nvram_external_write_data','nvram_SW_AES_encrypt_ext','nvram_HW_AES_encrypt_ext','SST_Get_HRID_ciphertext','sml_op12t_is_nv_read']
for n in names:
 p=d/(n+'.jsonl')
 lines=open(p).read().strip().splitlines()
 h=json.loads(lines[0])
 print(f"=== {n} VA={h['va']:#x} size={h['size']} n={h['n']} sha={h['sha256'][:12]} ===")
 for l in lines[1:]:
  r=json.loads(l)
  print(f" {r['va']:#x} +{r['size']:2} {r['text']}")
 print()
