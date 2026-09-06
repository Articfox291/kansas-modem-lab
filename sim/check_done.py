import pathlib, re
for n in ['sml_sec_nvram_read','sml_sec_nvram_read_to_data','sml_sec_nvram_read_gblob','smu_load_sml_data_from_nvram']:
 p=pathlib.Path('sim/carves')/(f'fn_{n}.log')
 txt=open(p,encoding='utf-8',errors='replace').read()
 m=re.findall(r'DONE n=(\d+)',txt)
 print(n, m)
