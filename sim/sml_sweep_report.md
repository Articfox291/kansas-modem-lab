# SML Verify/Unlock/DB sweep — 36 fns, all via sim/decomp.py exact DONE-match

Pipeline: `python sim/decomp.py --fns <36 names> --max-jvms 3 --timeout 600`
Result: carved 36/36, 33 disassembled + 3 skipped-unchanged (cache sha match),
`36/36 fns exact DONE-match, 4635 total records`, failed=0.
Cache: `sim/listings/<name>.jsonl` (header sha256 = carved bytes), carves in `sim/carves/fn_<name>.bin`.
No device contact (local analyzeHeadless.bat only). Reuse (not redone):
custom_check_link_sml_legal_sim_rule, custom_link_sml_with_rule, sml_Verify,
mot_sml_catkey_verify, sml_catkey_verify, sml_Unlock, sml_is_tfn_otp_on,
sml_crrst_Check, sml_op07_Check (HANDOFF §3e notes apply).

memcmp@0x9005ea10 (11 insn) is early-exit byte loop:
LBUX/LBU + BEQC-continue + SUBU-diff-return, 0=equal. Every use below is a timing oracle.
__wrap_memcpy (165) returns dest; __wrap_memset (4) is a size-guard trampoline to memset —
neither is a verdict; both only move key/blob bytes in RAM.

Verdict legend: STD 1=pass/0=fail; OP07 0=pass/nonzero=fail; HCK 0=pass/nonzero=fail;
DBV 0xF=pass; DBH 1=pass. SMU/L4C handlers are void dispatchers (verdict = cnf payload +
NVRAM writes, gated by BNEIC/BEQIC/BNEZC on sub-verdicts) — every gate is a 1-branch patch point.

## Per-function notes

### smu_sml_verify VA 0x9198ea0e size 466 insns 150
- Convention: void; gates on sml_Verify ret: `MOVE s4,a0` then `BNEIC s4,0x1,fail` (0x9198ea88);
  TFN/lock gates `BNEIC a0,0x1`, penalty gate `BNEIC a0,0x1` + `BNEZC`.
- Crypto: none direct; delegates to sml_Verify + sml_check_tfn_simlock_data_consistency +
  sml_check_penalty_timer_enabled.
- Keys: IMSI via LWPC SMU ctx 0x24ae1600, a1=fp/pw bytes, a2=s5/s6; NCK in fp→sml_Verify args.
- Retry: heaviest SMU retry logic: entry `sml_is_penalty_timer_running==1` → instant fail cnf;
  fail path `smu_start_sml_penalty_timer` + `smu_update_is_sp_veriy_fail(1)` + 2×
  `sml_sec_nvram_write`; success `sml_restore_tfn_retry_count` + update_is_sp_veriy_fail(0);
  pending_password_id query/update pair. All RAM SMU ctx + NVRAM LID backing, no secure store.
- Force: patch sml_Verify→1, or nop penalty gate @0x9198ea2a/0x9198eabe.

### smu_check_sml VA 0x9198e528 size 842 insns 281
- Convention: void; central NCK dispatcher. Key gate: `BALC sml_Check` @0x9198e698,
  then `BNEIC s3,0x1` (0x9198e6e2), `BNEIC a3,0x1`, `BNEIC a0,0x1` chain; crrst gate
  `BNEIC a0,0x1` @0x9198e840.
- Crypto: sml_Check + sml_CheckVisa + smu_check_crrst + multisim-policy; no direct hash.
- Keys: IMSI `smu_query_imsi_with_length`, MNC `sim_query_mnc_num`, ctx s0=LWPC 0x24ae1600
  offs 0x110/0x114/0x129; NCK via s6/a6 → sml_Check a1/a2 (s2/s3), vtable JALRC ra,a4 @0x9198e6e0.
- Retry: `sml_check_penalty_timer_enabled`, pending_password_id_ext query/update,
  `sml_update_legal_service` + `sml_lock_rule_and_status_update_ind` on each leg,
  `smu_nvram_write`. RAM + NVRAM only.
- Force: sml_Check→1 flips all downstream; or patch any single BNEIC.

### smu_check_sml_and_send_security_cnf VA 0x9198f7a6 size 422 insns 136
- Convention: void fan-out; no Check call — routes on gblob/uicc/linksml/sl/op129 predicates
  (`BNEIC/BNEZC` each), ends in `smu_send_security_cnf` / `smu_nvram_write`.
- Crypto: none. Keys: s0=msg, s1=LWPC ctx, lock-rule bytes.
- Retry: `sml_update_is_personalization_done`, `sml_update_legal_service`,
  `sml_lock_rule_and_status_update_ind`, `sml_gblob_lock_rule_always_lock_check`.
- Force: weakest as *gater* — patch `sml_gblob_skip_simme_lock_check→1` (@0x9198f7e8,
  `BNEIC a0,0x1`) short-circuits to personalization-done path.

### smu_update_sml_security_check VA 0x9198ebe0 size 236 insns 83
- Convention: void; `sml_CheckVisa` gate `BNEC a3,a0,fail` (@0x9198ec90, a3=0xff);
  tail `BALC smu_sml_verify` result returned directly (RESTORE.JRC, no test — caller decides).
- Crypto: CheckVisa only. Keys: s0=req (LBU +0/+1/+4, LHU +8 → a0/a1/a2/a3/a4/a6),
  IMSI/MNC queries, sp buffers.
- Retry: `sml_query_sml_lock_rule` entry; op129/sl/op08 branches each end in cnf.
- Force: CheckVisa→0xff, or smu_sml_verify→1.

### smu_update_sml_super_verify VA 0x9198f94c size 216 insns 64
- Convention: void lock-rule router on s1=query_lock_rule, s2=allow_both_sim_unlock:
  `BNEIC s1,0xc/0xd/0xa/0x7` ladder dispatches to op08rsu/op07/op12/sl/smu_check_sml tails.
- Crypto: delegates to smu_sl_check_sml + smu_check_sml. Keys: s0=msg, s3=LWPC ctx.
- Retry: `sml_reload_sml_context_extend`, linksml `BNEIC a0,0x1` @0x9198f9f8.
- Force: single best point — `sml_query_sml_lock_rule` controls whole ladder; forcing the
  `smu_check_sml` leg return (or linksml→1) selects weakest downstream.

### l4c_root_sml_super_verify_req VA 0x91984ca2 size 174 insns 53
- Convention: void; 2-iter loop over s6 bytes (`BNEIC a3,0x1` per slot), then
  update_legal_service + lock_rule_ind + send_security_req / upgrade_service_req.
- Crypto: none. Keys: a2/a3 slot blobs, s4/s5/s0 L4C ctx, gemini_sim_id.
- Retry: none (request builder, no counters).
- Force: loop `BNEIC a3,0x1,skip` @0x91984cc8 — forcing iteration body runs verify for both slots.

### smu_op07_check_sml VA 0x9198f45a size 474 insns 154 — INVERTED family
- Convention: void; **sml_op07_Check 0=pass**. Site1 @0x9198f55e: result NOT tested directly —
  gated by `LBU a3,0xd(sp); BNEIC a3,0x1` + `custom_sml_is_msml_enabled BNEIC 0x1`.
  Site2 @0x9198f5fc: `BNEC zero,a0,fail` @0x9198f600 — nonzero=fail confirmed.
- Crypto: sml_op07_Check ×2 + update_state ×2 + restore_factory_whitelist. No hash.
- Keys: IMSI/MNC, sec_ctx s0 (LWPC), sp+0xd flag byte, s3/s1/s6 buffers; NCK via a1/a2/a5/a6.
- Retry: `sml_update_legal_service` + `lock_rule_ind` + `personalization_done` +
  `pending_password_id` + `smu_nvram_write` + `sml_sec_nvram_write` + mmrr_ready gate.
- Force: patch site2 callee→0 (not 1!); site1 flag byte @sp+0xd→1 also passes without key.

### smu_op08_rsu_check_sml VA 0x91991ed0 size 354 insns 109
- Convention: void; tmp-unlock gate `BEQZC a0,skip` @0x91991fe2, empty-cat gate
  `BNEIC a0,0x1,fail(sends 1)` @0x91991fea; main work in `smu_op08_process_check_sml.isra.7`
  (tail, result untested here) + `smu_op08_rsu_check_sml_locked` loop tail.
- Crypto: revalidate_blob + is_all_cat_empty. Keys: s0=slot, s4=LSA ctx (LWPC 0x24aa2b58),
  s1/s3 msg, JALRC ra,s2/s4 vtable.
- Retry: only restrict_test_network_sim; persistence in locked/process callees.
- Force: empty-cat→1 or tmp-unlock→nonzero skips RSU blob path.

### smu_op12_check_sml VA 0x91993d5c size 524 insns 164
- Convention: void; validity gate `BNEZC a0,fail` @0x91993e38 (checkValidity nonzero=fail);
  empty-cat `BNEIC a0,0x1` @0x91993e8c; main `BALC sml_op12_Check` @0x91993ee8 result in
  s2 tested `BNEZC s2,pass-leg` @0x91993f0a — **1=pass**.
- Crypto: checkValidity + update/get_int_data + is_all_cat_empty. Keys: s0=slot/IMSI/MNC,
  s1=blob ctx (0x114/0x13e), s7=RSU ptr, fp=cat.
- Retry: personalization_done + legal_service + pending_password + nvram_write + mmrr gate.
- Force: sml_op12_Check→1, or checkValidity→0, or empty-cat→1.

### smu_sl_check_sml VA 0x9199486c size 320 insns 109
- Convention: void; `BALC sml_sl_Check` @0x9199491c then `BNEZC a0,fail-leg` @0x91994920 —
  nonzero(1)=pass... wait BNEZC taken means a0!=0 → jump to 0x9199495c (retry++ path?).
  Actually pass legs are the LI 6/7/8/a/c + send path; fail increments s1 and loops.
  Net: **nonzero=pass (1)**, zero=continue/fail. Confirmed by sml_sl_Check LI1 pass.
- Crypto: sml_sl_Check only. Keys: s0=slot, s1=LSA ctx, s2=LWPC, JALRC ra,s1 vtable.
- Retry: pending_password ×2 + personalization_done + mmrr gate; cat retry s1++ `BNEIC s1,0x3`.
- Force: sml_sl_Check→1.

### mot_sml_db_verify VA 0x912dc1f8 size 88 insns 29
- Convention: **0xF=pass** (all callers BEQIC/BNEIC 0xf). Returns validate_db masked byte,
  or 0x14 on magic-mismatch. `BEQZC a0,pass` after memcmp @0x912dc22a.
- Crypto/hash: `dbval_validate_db` + **memcmp(s1, sp+[0x0c,0x03], 2)** — 2-byte magic compare.
- Keys: a0=s1=NVRAM blob ptr; expected magic on stack. RAM only.
- Retry: none. Force: validate_db→0x0f, or memcmp→0.

### mot_sml_db_handler VA 0x912de034 size 1280 insns 430
- Convention: AT dispatcher, returns s0 via giant switch; `LI a0,0x1` single RETVAL-SET
  is a leg code, not global pass. Gates: active_verify `BEQZC fail`, nwscp `BEQZC fail`,
  is_unit_locked result moved-through.
- Crypto: hex validators + **memcmp(sp+0xa4, sp+0xe8, 0x20)** @0x912de500 with
  `MOVZ s0,zero,a0` (pass→0) — 32B hash/key compare, early-exit.
- Keys: s0=AT line (LHU len), ctrl buffers, HCK via get/erase_hck_in_sml, store/request
  handlers, NVRAM reads. All heap/stack RAM.
- Retry: none here (dispatch only). Force: active_verify→0-leg? Actually BEQZC taken=0→fail?
  Check: `BEQZC a0,fail` means 0=fail, nonzero=pass for active_verify here — note active_verify
  returns s1 (0/1?) not a0 directly; handler treats 0 as fail. Patch callee or memcmp→0.

### mot_sml_db_request_handler VA 0x912dcb4a size 1498 insns 471
- Convention: single exit `MOVE a0,s0` (s0=0 success path / -1 fail). Crypto core of MOT DB.
- Crypto: **PKCS5_PBKDF2_HMAC_SHA256** @0x912dcd70 (BNEIC 0x1 fail),
  `dbval_read_processor_uid` + `dbval_read_flash_uid` (device binding),
  `dbval_memcmp_value` @0x912dcfcc. No raw memcmp (uses dbval wrapper).
- Keys: s0=req, stack 0x50-0x90 key mats, flash/processor UIDs, PBKDF out on stack,
  RSU params via mot_sml_db_get_rsu_parameter. Heap ctrl bufs + stack, NVRAM LIDs. RAM only.
- Retry: none. Force: PBKDF→1 + dbval_memcmp_value→0xf path; or UID reads → canned.

### mot_sml_db_active_verify VA 0x912dd1c4 size 182 insns 54
- Convention: returns s1 (1=pass path via `BEQIC a0,0x1` @0x912dd25e after parameter_hash_verify;
  fail legs LI 0x4b/0x4c + mot_sw_ver_expand). Inner db_verify gate `BEQIC a0,0xf`.
- Crypto: mot_sml_db_verify (0xf) + mot_sml_db_parameter_hash_verify (1).
- Keys: s1=a0 blob ptr, ctrl buf 0xbd0, NVRAM LID 0x8c3 read. RAM.
- Retry: none. Force: parameter_hash_verify→1 (single insn LI a0,1).

### mot_sml_db_is_activedb_loaded VA 0x912dd124 size 160 insns 47
- Convention: **1=loaded/pass**, 0=fail. `SEQI s0,a0,0xf; BEQIC a0,0xf,pass`.
- Crypto: mot_sml_db_verify only. Keys: s1=ctrl buf (NVRAM LID 0x8c3 data). RAM.
- Retry: none. Force: db_verify→0xf.

### mot_sml_db_is_unit_locked VA 0x912dd3e6 size 244 insns 76
- Convention: **1=locked / 0=unlocked** (state, not pass). Early fails return 0;
  byte-mismatch leg `LI s0,0x1`; final `LBU a2,0x3f(s0)` range-check `BGEIUC 5` decides.
- Crypto: none (byte compares only). Keys: s1=NVRAM buf (LID 0xef31/0xef2f), 7-unit loop
  checking `==2` bytes @a3+0 step 0x10, lock byte @+0x3f.
- Retry: none. Force: return 0 (unlocked) — `MOVE s0,zero` already the early-exit shape.

### mot_sml_db_get_rsu_parameter VA 0x912dc250 size 1144 insns 353
- Convention: single exit s0 (0=ok). Internal memcmp gate `BNEZC fail` @0x912dc57e.
- Crypto: **memcmp(s1, pcrel-magic, 2)** @0x912dc57a + chained `BNEC/BNEZC` field compares
  (each 2-4B, early-exit oracle chain over RSU blob).
- Keys: s1=blob, s5/s6/s7 cursors, pcrel magic tables (0x92127290...). Stack/heap RAM.
- Retry: none. Force: memcmp→0 opens the whole field ladder.

### mot_sml_db_parameter_hash_verify VA 0x912dc6c8 size 628 insns 194 — STRONGEST DB LINK
- Convention: **1=pass**. Exit s2 (SLTIU s2,a0,0x1 after final memcmp: 0→s2=1 pass).
  `BNEIC a0,0x1` fail on PBKDF; `BEQIC a0,0xf` on dbval_memcmp_value.
- Crypto: processor_uid + flash_uid + **PBKDF2-HMAC-SHA256** + dbval_memcmp_value +
  **memcmp(derived, s4+0x48, 0x20)** @0x912dc926 — 32B derived-key compare, early-exit.
- Keys: s0/s4=param blks, UIDs on stack (sp+0xc/0x10/0x20), PBKDF out sp+..., expected
  s4+0x48. All RAM (ctrl heap + stack). Device-bound via UIDs (not bypassable by RAM freeze alone).
- Retry: none. Force: PBKDF→1 AND memcmp→0 (two points); or UID stubs.

### mot_sml_db_store_handler VA 0x912dc9ea size 352 insns 102
- Convention: returns s1 (0=stored-ok, -1=fail). Gate `BNEC zero,s1,fail-store`.
- Crypto: none direct; calls store_in_bp (which verifies). Keys: s5=a0 store ctx,
  s1/s3/s2/s4 len/ptr quads, global 0x2637b6f8 ptr + 0x6f4 counter (writable RAM globals!).
- Retry: none (store path). Force: store_in_bp→0; or zero the 0x6f4 counter check.

### mot_sml_db_store_in_bp VA 0x912dc93c size 174 insns 49
- Convention: **0=stored-ok / -1=fail** (SLTU/SUBU idiom). Gates: db_verify `BNEIC 0xf`,
  then parameter_hash_verify `BNEIC 0x1`.
- Crypto: both verifies. Keys: s0=a0 ctx, global 0x2637b6f8, NVRAM write LID back.
- Retry: none. Force: db_verify→0xf AND hash_verify→1 — double gate (stronger than single).

### mot_sml_db_check VA 0x912dd982 size 350 insns 104
- Convention: returns s0 (1=pass leg `LI s0,0x1`, 0=fail). Gates: two db_verify sites
  (`SEQI/BNEIC 0xf`), s2/s4 category loop (`BEQIC s2,0x4`, `BNEIC s2,0x3`).
- Crypto: mot_sml_db_verify ×2 only. Keys: s1=NVRAM buf (LID 0x8c3), s4=req cat,
  bytes @s1+0x69/0x6a. RAM.
- Retry: none. Force: db_verify→0xf at either site.

### mot_sml_db_reset_all VA 0x912dd83a size 328 insns 113
- Convention: returns stack flag byte (1=wrote-ok). No verify calls at all —
  straight `nvram_external_reset_data` per LID (0xef31/0xef2f/0xef51/0xef54/0xef50/0xef57/0xef47/0xef58).
- Crypto: none. Keys: none (destructive). Retry: none.
- Force: N/A (it is the weapon — wipes lock DB; modem asserts if protect wiped, per HANDOFF).

### get_hck_from_sml VA 0x912dd4da size 238 insns 73
- Convention: returns stack flag 0xf(sp) (0/1). 7-unit loop `BEQIC a3,0x2` counting s0;
  `BNEIC s0,0x1/0x2` decides memcpy of 0x20B HCK (s5/s3→s6/s3) via __wrap_memcpy.
- Crypto: none. Keys: **HCK bytes**: s1=NVRAM buf+4, s4/s3 cursors (+0x10/+0x66 per unit),
  out via caller ptrs s5/s6. RAM heap+stack. Zeroing loop visible in erase twin.
- Retry: none. Force: loop counter s0 — forcing s0=1/2 selects copy path without valid HCK.

### erase_hck_in_sml VA 0x912dd5c8 size 220 insns 69 — mirror of get
- Convention: returns s1 (1=wrote-ok). Same 7-unit `BEQIC 0x2` loop, then
  `__wrap_memset(buf,0xff?,0x20)` per unit + `nvram_external_write_data` (LID 0xef31).
- Crypto: none. Keys: HCK region s0 buf (+4/+0x9a cursors). RAM+NVRAM.
- Retry: none. Note: the sanctioned HCK wipe primitive — no key needed, just called.

### sml_op12_Check VA 0x905f1d34 size 476 insns 166 — STD 1=pass
- Convention: exits LI 1 (pass @0x905f1d7a/0x905f1d98) vs MOVE 0 (fail). Final
  `memcmp→BNEZC fail / BC pass`.
- Crypto: **memcmp(s3 attacker, s1/s6 expected, len)** @0x905f1f00; snprintf digit-mangling
  loop; GetCode JALRC; Catcode BALC. Early-exit oracle on NCK/IMSI/GID digits.
- Keys: s2=a0 obj, s3=sp+0x48 scratch attacker copy, s1=a6 RSU/IMSI, s7=a3 cat,
  expected via GetCode into sp+0x6c/0xd0. Stack + obj RAM. NCK in s3/a0 at memcmp.
- Retry: none in-leaf (SMU layer owns counters). Force: memcmp→0 or GetCode→canned.

### sml_op08_rsu_Check VA 0x905f2c36 size 316 insns 99 — STD 1=pass
- Convention: LI 1 pass @0x905f2d6e / MOVE 0 fail @0x905f2ca0. `BEQZC a0,pass` after memcmp.
- Crypto: **memcmp(a5 expected-stack, fp len)** @0x905f2d1a; Catcode BALC; ASCII digit
  ladders ("331158" vs "220440" rewrites!) + JALRC GetCode ×2. Byte-early-exit.
- Keys: s2=a0 obj, s5=expected ptr, fp=len, attacker RSU in s6/s7/sp+0x14-0x19. Stack RAM.
- Retry: none in-leaf. Force: memcmp→0.

### sml_op08_rsu_Verify VA 0x905f2e80 size 148 insns 52 — STD 1=pass, HCK 0=pass inside
- Convention: LI 1 + `SB a3,0x2(s1)` marker on pass; MOVE 0 fail. HCK gate
  `BNEZC a0,fail` after cust_sec_hck_verify → **hck 0=pass**.
- Crypto: JALRC GetCode ×2 + **cust_sec_hck_verify** @0x905f2ee0. BE-word @s0+0..3 must be
  nonzero (`BEQC zero,a4,fail`).
- Keys: s0=obj (BE key @+0..3 in regs a3/a4), HCK in @+4 (a3) / +0x14 (a5), out marker @s1+2.
- Retry: marker byte write only; counters upstream. Force: hck_verify→0, or BE-word check.

### sml_sl_Check VA 0x905efd50 size 142 insns 55 — STD 1=pass
- Convention: LI 1 @0x905efd94 / MOVE 0 @0x905efdda. `BNEZC a0,fail` after memcmp;
  Catcode gate `BNEC a0,s1,fail`.
- Crypto: **memcmp(sp+4, s7-derived, s1)** @0x905efdd2; Catcode BALC; JALRC GetCode ×2.
- Keys: s2=a0 obj/cat, s3=GetCode out, attacker in s7/s1, expected on stack sp+4. RAM.
- Retry: none in-leaf. Force: memcmp→0.

### sml_sl_Verify VA 0x905efdde size 122 insns 40 — STD 1=pass, HCK 0=pass inside
- Convention: `LI s0,1; MOVE a0,s0` pass / MOVE 0 fail. HCK gate `BNEZC fail`.
- Crypto: JALRC GetCode + **cust_sec_hck_verify** @0x905efe2a. Same BE-word nonzero gate.
- Keys: a0=obj BE-word @+0..3 (regs), HCK @+4/+0x14. RAM.
- Retry: none. Force: hck_verify→0.

### sml_Check VA 0x905ef6fe size 778 insns 254 — STD 1=pass, 5× memcmp
- Convention: returns s1 (1 pass). `BNEIC a0,0x1` on mot_sml_db_check; memcmp legs
  `BNEZC fail-leg`; final `BNEC zero,a0,fail / BC pass-leg`.
- Crypto: **memcmp ×5** (2B magics @0x905ef836/0x905ef884, 8B blobs @0x905ef8b4/0x905ef8d8,
  final NCK @0x905ef9e8) + GetCode JALRC + mot_sml_db_check (1=pass) + hw_secboot/sbp gates.
  All early-exit; attacker NCK in s3/a0, expected on sp (0x24/0x28/0x34/0x3c/0x44).
- Keys: s0=a0 obj, s2/s3=a1/a2 IMSI/GID in, s4=a6, s6=vtable obj, s5=pass-flag.
  NCK bytes in s3 vs sp buffers at each BALC. Stack+obj RAM.
- Retry: none in-leaf (counters in SMU/sml_Verify object @+8). Force: any one memcmp→0
  advances a leg; final memcmp→0 is sufficient alone; or db_check→1.

### sml_Status VA 0x905ef428 size 206 insns 68 — not a verdict
- Convention: none (status filler). LI 2 error leg; main leg computes
  remaining = total − used×percat mult (table @0x920dc568, DIV) and SBs bytes to out ptrs.
- Crypto: none. Keys: reads lock bytes LBU +0xd/+0xc/+0x0, no key compare.
- Retry: *reports* retry (does not enforce). Force: N/A — patching it only lies to UI.

### __wrap_memcpy VA 0x90023558 size 492 insns 165 / __wrap_memset 14B 4insn / memcmp 34B 11insn
- memcpy: dest-return, cache/PREF/MFC0-guarded fast copy + `memcpy` + `memcpy_no_prefetch`
  fallbacks; moves every NCK/blob/HCK byte above — patch point for snoop, not verdict.
- memset: size-guard (`BLTUC 0x7fff`) then tail to memset — zeroing primitive for key wipe.
- memcmp: THE oracle + THE single-point bypass: `LI a0,0` force = global pass
  (noisy — used by all string compares; prefer per-callsite).

### sml_op12t_validate_dsdb VA 0x905f33c8 size 620 insns 216 — multi-status, STD inside
- Convention: status byte SB @s1 + a0 (2/3/9 file-line codes; 1/2/3 final). Inner
  sml_Verify ×2 use STD 1=pass (`SEQI/BEQC/BNEZC` chain @0x905f35da-0x905f361a).
- Crypto: **memcmp ×3** (4B magic @0x905f340a/0x905f341e, 0xF B @0x905f354a) +
  **CustCHL_Get_Asym_Key + CustCHL_Verify_RSA_Signature** (`BEQZC pass` → 0=fail? actually
  `BEQZC a0,0x905f34e4` means 0 → RSA-fail leg; nonzero → continue) + sml_Verify ×2 +
  sml_Dump ×2 (timing no-op?). RSA is the only asymmetric gate in sweep.
- Keys: s2=a0 DSDB blob (ver/magic @+0x138/0x139 → regs), device secret via
  get_device_secret_key path, IMEI via smu_read_imei_value, NCK via BCD convert +
  stack 0x2c/0x14 + __wrap_memcpy. NVRAM ctrl bufs (0x620/0x8010/0x8016). RAM.
- Retry: none (relock via mot_sml_db_tf_relock on fail legs). Force: RSA-verify→nonzero
  AND memcmp→0 AND sml_Verify→1 — triple gate (strongest STD link with crypto).

### sml_op12t_get_device_secret_key VA 0x905f3354 size 116 insns 38
- Convention: **1=have-key**. `BNEC zero,s4,have-key` after cust_sec_get_device_secret_key;
  copies 0x20B via __wrap_memcpy to caller+4, returns s2.
- Crypto: cust_sec_get_device_secret_key (HW-bound) + kal_set_sensitive_buff_ext +
  memset wipe of ctrl buf. Keys: **the device secret**: s0=ctrl buf, s3=caller out,
  0x20B in s0/s1 → s3+4. Only function that materializes the secret in RAM.
- Retry: none. Force: secret call→nonzero, or s2=1 — but yields zeroed/canned key unless
  HW answers; best snoop point (memcpy site @0x905f33a4), not bypass point.

## Ranked weakest verify links (bypass candidacy, weakest first)

1. memcmp@0x9005ea10 — single global verdict-forcer (LI a0,0) + timing oracle on every
   NCK/IMSI/GID/HCK/DSDB compare (13 call sites across 9 fns, 5 in sml_Check alone).
   Early-exit byte loop proven. Noisy if patched globally; per-callsite BALC→ret0 equivalent.
2. sml_op07 family (sml_op07_Check + smu_op07_check_sml site2) — INVERTED 0=pass is the
   polarity trap (force-1 re-locks); plus site1 sp+0xd flag byte (`BNEIC a3,0x1`) passes
   without any key. Two independent force paths, one is a stack byte.
3. cust_sec_hck_verify gates (sml_sl_Verify, sml_op08_rsu_Verify) — HCK 0=pass inversion
   + BE-word-nonzero pre-check on attacker-visible object bytes; forcing 0 passes.
4. smu_* BNEIC/BNEZC gates (smu_sml_verify/smu_check_sml/smu_op12/sl) — every sub-verdict
   tested by one 4B branch; patching any callee to its pass constant (1, or 0 for op07,
   0xf for db_verify) cascades. smu_check_sml_and_send_security_cnf gblob gate is shallowest.
5. RAM-held retry/counter store — penalty flag, pending_password_id, is_sp_veriy_fail,
   personalization_done, legal_service, object retry @+8, globals 0x2637b6f8/0x6f4:
   all writable RAM + NVRAM LIDs (0xbd0/0x8c3/0xefxx), none in eFuse/RPMB/secure store
   (TFN OTP stubs hardcoded dormant; op12t eFuse gate not on this path). Freezing
   sml_sec_nvram_write/smu_nvram_write = infinite attempts.
6. mot_sml_db_verify (0xF=pass, 2B magic memcmp) + is_activedb_loaded/is_unit_locked —
   thin wrappers; db_verify→0xf or memcmp→0 unlocks active_verify/store_in_bp/check.
   is_unit_locked 1=locked → force 0.
7. sml_Check/sml_op12_Check/sml_sl_Check/sml_op08_rsu_Check — STD 1=pass leaves with
   stack-built expected buffers; NCK in regs (s3/a0) vs sp at BALC; each memcmp→0 suffices.
   sml_Check needs only the FINAL memcmp forced (earlier legs skippable via s5 flag).
8. get/erase_hck_in_sml — 7-unit `==2` loop counter s0/s1 in RAM; forcing the count selects
   the 0x20B HCK memcpy path; erase is an unkeyed wipe primitive.
9. mot_sml_db_store_in_bp double gate (db_verify 0xf AND hash_verify 1) — stronger than
   single-gate siblings; patch both or patch store_handler caller check.
10. mot_sml_db_parameter_hash_verify + request_handler PBKDF2 path — strongest symmetric
    gate (UID-bound PBKDF + 32B compare); needs PBKDF→1 AND memcmp→0 AND UID control.
11. sml_op12t_validate_dsdb RSA path — strongest overall (RSA_verify + 3 memcmps +
    2 sml_Verify 1=pass + relock-on-fail); triple-gate, device-secret + IMEI bound.
    Snoop (not bypass) via get_device_secret_key memcpy site.
