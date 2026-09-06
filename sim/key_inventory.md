# Key / Secret / Certificate Inventory — Kansas lab (XT2513V, MT6835)

Date (UTC): 2026-09-05. Mode: READ-ONLY ONLY. No writes, no key USE, no setprop,
no AT sets, no NCK trials, no reboot. Device REDACTED-SERIAL contacted only via
read-only `getprop` / `dumpsys` / `service list` / `ls -l` / `cat` of
world-readable files / `sha256sum` of world-readable files. All dumps opened
`rb`. Private bytes are NEVER reproduced here — sizes, perms, sha256,
magic/headers, key-IDs and PUBLIC cert parts only.

Sources (all read-only): `HANDOFF.md` / `PICKUP.md` / `sim/hw_target.py` /
`sim/crypto_stubs.py` / `sim/emu_engine.py` (HwOracle OPS) /
`sim/oracle_transport.py` (allowlist) / `tools/parse_mtk_certs.py` /
`tools/verify_mtk_image.py` (via `sim/crypto_stubs.py` + `sim/boot_sim.py`) /
`stock_XT2513V/md1img.img` + `lk.img` / `modem_bak/modem_bak/*` /
`captures/capture/*/props.txt|logcat_all.txt` / `gsi/diag.txt|diag2.txt|atr.txt` /
`sim/esim_sim.py` / `sim/nv_model.py` / `nvram_live/` / live `adb shell`
(read-only, this session).

HwOracle OPS (single source: `sim/emu_engine.py`): `nv_read` (NVRAM/LID record),
`chl_hash` (CustCHL hash passthrough), `chl_mac` (CustCHL MAC verify
passthrough), `efuse_read` (eFuse/OTP bit read), `sml_status` (modem SML status
snapshot, read-only AT `?` forms), `apdu_xfer` (raw eUICC APDU round-trip).
`sim/crypto_stubs.py` router maps silicon-keyed ops onto these; software ops
(`sw_sha256`, `sw_hmac_sha256`, `sw_md5`, `sw_cert2_rsa_sha256`) run locally.

EID (confirm, no re-pull): `89000000000000000000000000000000` — live
`getprop ro.vendor.esimid` + `ro.vendor.hw.esimid` identical this session;
identical in all 3 `captures/capture/*/props.txt` and both oracle transcripts.
IMEI `REDACTED-IMEI` per HANDOFF/PICKUP (fastboot `getvar imei`; Android
telephony shows no IMEI on this GSI). Both are per-device identifiers (values redacted in this copy), never
silicon secrets.

## 1. CERT1 / CERT2 pubkeys — `stock_XT2513V/md1img.img` + `lk.img`

Method (read-only, PUBLIC parts only): `tools/verify_mtk_image.py` DER parse
via `sim/crypto_stubs.py verify_cert2_image` + `sim/boot_sim.py --all` (CERT2
RSA-2048/SHA256 verify, hash + RSA-PSS + pubkey-match). `tools/parse_mtk_certs.py`
run raw on `md1img.img` mis-parses (first entry is `md1rom` payload, not CERT),
so the verified path is the repo-tool CERT parse, not raw `parse_mtk_certs`
stdout. Recorded below: key-IDs (moduli sha256), bits/exponent, OIDs,
types/sizes — never private exponents (not present in image).

### 1a. `stock_XT2513V/md1img.img` (75697504 B, 23 part entries)

Layout: `md1rom` (45,893,712 B @0x0) + `cert1md`/`cert2` triples ×3
(`md1rom`, `md1drdi` 3,752,416 B, `md1dsp` 5,701,632 B); 14 trailing unsigned
containers (`md1_filter*`, `emfilter`, `dbginfo*`, `mddb*`, `mdmlayout`,
`file_map`). CERT1 type `0x02000001` (LK uses `0x02000000`; only CERT2 matters —
same relaxation as `boot_sim.py` / `crypto_stubs.py`). CERT2 dsize 1021 each.
`sw_cert2_rsa_sha256` on stock: `all_ok True` (`md1rom|md1drdi|md1dsp` each
header_hash OK + image_hash OK + CERT1-sig OK + CERT2-sig OK + pubkey-match OK).

- CERT1 root pubkey (eFuse-anchored Motorola PKI, shared across all 3 triples):
  RSA-2048, e=`0x10001`, `sec_level 0` (`sha256`), `sw_id 0`, `img_ver 1`,
  `group 5`, `root_key_ver 0`. Modulus sha256
  `c222c374b8ca5ed9776335bac90f36a1160ed57c16b910a78fa8d9162896fd19`
  (identical idx 1/4/7). OIDs include `2.16.886.2454.1.1` (root key),
  `1.2` (image pubkey), `2.3/2.5/2.9/2.10/3.1/3.2`, RSA `1.1.1/1.1.10/1.1.11`.
  Offsets: `cert1md` @`0x2bc4a50`/`0x2f59d30`/`0x34cae30` (dsize 1781 each).
- CERT1 image pubkey == CERT2 pubkey (per-triple image key, shared across
  `md1rom|md1drdi|md1dsp`): RSA-2048, e=`0x10001`,
  modulus sha256 `13a9c09ae899d3dcccbc4893f39a0db4b8ab6c1dca2c89948ca659fd12bd203a`
  (CERT2 idx 2/5/8 identical; `pubkey_match_ok True`). CERT2 OIDs include
  `2.1` (image hash), `2.4` (header hash), `2.6/2.7/2.8/3.6/4.2`.
  Offsets: `cert2` @`0x2bc5350`/`0x2f5a630`/`0x34cb730` (dsize 1021 each).
- Force-1 live image (`md1work_md1force1-signed.img`, 75697600 B): `md1rom`
  CERT2 dsize 1021→1111 (+90, file +96 padded), bytes @file `0x5df4fa`
  `141e2412`→`01d2e0db` (`LI a0,1; JRC ra`), header/image hashes recomputed,
  re-verify `all_ok True` (dry-run reproduces live byte-identical
  sha `7ed179…` per HANDOFF §3e; `boot_sim --all` confirms calc==stored).

### 1b. `stock_XT2513V/lk.img` (15 entries, 5 signed triples)

Layout: `lk` 1,222,776 B + `cert1`/`cert2` (`lk`, `bl2_ext` 690,736 B, `aee`
936,712 B, `lk_main_dtb` 183,095 B, `lk_dtbo` 246,928 B). CERT1 type strict
`0x02000000` (dsize 1737 each), CERT2 `0x02000002` (dsize 1021 each).
`sec_level 0`/`sha256`, `sw_id 0`, `img_ver 0` throughout.

- CERT1 root pubkey: SAME Motorola root as modem —
  `c222c374b8ca5ed9776335bac90f36a1160ed57c16b910a78fa8d9162896fd19`
  (all 5 `cert1` idx 1/4/7/10/13 identical, e=`0x10001`). Proves single
  Motorola PKI root anchors both LK and modem CERT1 chains; private root stays
  in eFuse (`efuse` sdc28 / `efuseBackup` sdc29, never read here).
- Image keys (TWO distinct LK image keys, not one):
  - Group A (`lk`+`bl2_ext`+`aee`, CERT2 idx 2/5/8): RSA-2048 e=`0x10001`
    mod sha256 `4f117a51d30b9f23c63f4cba565211bd2c1ed37a1c849f31993af814ba93481e`.
    CERT1 group OIDs `2.5`=4 (`lk`), 0 (`bl2_ext`/`aee`).
  - Group B (`lk_main_dtb`+`lk_dtbo`, CERT2 idx 11/14): RSA-2048 e=`0x10001`
    mod sha256 `9a303370263459d7884924d38f9bad71bedac1360f66a23deb3b1ac5e6d67269`.
    CERT1 group `2.5`=6 both.
- Live LK: patched `unlock-serial` in `lk_a` (secret `REDACTED-LK-SECRET`, key
  `REDACTED-LK-KEY` per HANDOFF §4; stock kept as `lk.img.BAK`).
  Owner bootloader credentials (BOTH REDACTED above) — NEVER publish; they
  are device credentials, not silicon keys. Emulator consequence: none
  HwOracle crypto op).

## 2. Persist — `mot_key_cek` + `attest_keybox.so` + `wv.keys`

Live (read-only `ls -l` + `sha256sum` + `cat|od` of world-readable only):
`/mnt/vendor/persist/` (`persist` sdc24; PC backup `modem_bak/modem_bak/persist.img`
50,331,648 B sha256 `a3966cb4fb653fcbd6b490245e91afddad23e3dd43ca3faf830218841c38daf1`;
raw image contains ASCII names `mot_key_cek` @`0xa1b020`, `attest_keybox`
@`0x604148`, `wv.keys` @`0x604138`, `attestation_ids` @`0x604160` — proves
backup==live layout without decrypting anything).

- `security/mot_key_cek`: 168 B, `-rw-rw-rw- vendor_tcmd:vendor_tcmd`,
  sha256 `a9026d68cb2f2abec5b90adcab81b944828647ac0cc9cde7b5b698908f96d2a3`,
  magic `01 02 00 00 c5 2d 13 b2 …` (world-readable, `cat` allowed; only
  hash/size/magic recorded here, never full bytes). Motorola key-CEK blob,
  TEE/RPMB-bound. SILICON-BOUND.
- `wv.keys`: 176 B, `-rw-rw-r-- vendor_tcmd:system`,
  sha256 `addc44199f9dd7ba2481667207bbb0d3a53a38029a8761801a2864fbfedc22c8`,
  magic `46 05 03 12 d3 42 11 65 …` (world-readable). Widevine keybox,
  TEE-bound (`vendor.drm-widevine-hal` running, `ro.vendor.mtk_widevine_drm_l1_support 1`).
  SILICON-BOUND.
- `attest_keybox.so`: 8716 B, `-rw-r----- vendor_tcmd:system` (NOT
  world-readable; `cat` succeeded from this shell but treat as privileged —
  only hash/size recorded),
  sha256 `6735db2357d4ac6f75c4df048eb383f11a0694790cd6848e5a961c7c450c56db`,
  header `01 00 00 00 02 00 02 00 …`. Android attestation keybox for
  Trustonic Kinibi KeyMint (`ro.hardware.kmsetkey trustonic`,
  `ro.hardware.gatekeeper trustonic`). SILICON-BOUND (private attestation keys
  never leave TEE).
- `attestation_ids.so`: 892 B, same perms,
  sha256 `f0d13d42a7f662f505d8322e73bab3762527d658499674b8bfaa4789fde64ddd`.
  SILICON-BOUND (device identifiers for attestation).
- `rkp_complete`, `rkp_complete.tee_keymint`: 0 B each (`-rw-------`).
  Remote-key-provisioning completion flags (empty = not yet provisioned this
  boot). PUBLIC-offloadable (flags, no key material).
- `mcRegistry`/`mobicore` dirs, `security/` dir: Trustonic MobiCore registry
  paths (no key bytes listed here). SILICON-BOUND containers.

No `mot_key_cek` / `attest_keybox.so` / `wv.keys`FULL bytes are stored in this
file or the JSONL transcript — hashes/sizes/magic only.

## 3. `seccfg` contents

PC backup `modem_bak/modem_bak/seccfg.img` 524,288 B
sha256 `db0f8ae8f6ebe4cb1b4bc29c401463d79dc84d5a27988418b4455446e454ec5b` —
IDENTICAL to live `sha256sum /dev/block/by-name/seccfg` this session (proves
backup==live without exposing plaintext; block read was hash-only, no bytes
retained). `seccfg` → sdc34. Raw: magic `MMMM` (`4d4d4d4d`), ver `04 00 00 00`,
hdr `3c 00 00 00 01 00 00 00`, then `EEEE` marker + 32 B hash-like blob
(`83 ca ab 54 fe 74 e6 93 …`); only 2/1024 nonzero 512 B blocks; printable
strings exactly `MMMM`, `EEEE`. Captures carry identical 524,288 B copies
(3×). Bootloader lock-state container verified against the fused Motorola root
— header/magic/hashes PUBLIC-offloadable; fused root + any private state
SILICON-BOUND. Emulator: `efuse_read` for the root only; no `chl_*` (not a
modem CHL blob).

## 4. NVRAM key-ID references — `nv_mini_dump`, `sec_factor` IDs, `CK17` etc.

Backups `protect1.img`/`protect2.img` 8,388,608 B each; live
`/mnt/vendor/protect_f/md/` + `/mnt/vendor/nvdata/md/NVRAM/`. All SML LID
blobs are SW+HW ENCRYPTED (192 B LID header + checksum @`0x80` + ciphertext);
ciphertext stays opaque (HW-bound, `HwBoundOracle` truthful default). Recorded:
names, LID IDs, geometry, sizes, sha256 — never plaintext.

- SML lock blobs (the carrier-lock surface): `SL00_000` LID `0xEF28` (1 rec,
  rec 777 / sec 832 / file 1024, sha `5ab32a52…`), `SL01_000` LID `0xEF29`
  (259/304/496, sha `cc109765…`), `LD36_003` LID `0xEF2F` (690/736/928,
  sha `a7814619…`), `LD38_010` LID `0xEF31` (4516×4 / 4560 / 18432,
  sha `d223051c…`). Full protect geometry: 40 LID containers + `DEV_INFO`
  16 B (sha `e46c1668…`) + `nv_mini_dump` (below). `protect1` vs `protect2`
  payloads identical 41/41 per HANDOFF Phase-2 (41 files incl. extras).
- `nv_mini_dump` (modem FS log, NOT a key — key-ID index): backup
  `protect1.img:/md/nv_mini_dump` 1,197,850 B sha `8d89eee1…` (live
  `/mnt/vendor/protect_f/md/nv_mini_dump` 1,211,864 B — size differs by boot
  count, expected). 12,106 printable strings. Distinct
  `sec_factor[id:…]` IDs: `0xe42d`×3, `0xef2f`×4, `0xef31`×39, `0xf006`×1,
  `0xf008`×2 (5 distinct). Each creation logs `CREATE HW encrypted data` +
  `CREATE sw encrypted data` + `CREATE chksum data [size:32]` + `W sec_factory`
  triplets (e.g. `EF2F` rec 690/736, `EF31` rec 4516/4560). CK refs inside
  dump: `CK04_000`×4 only. Critical SML line present:
  `MOTO: startup_handler()critical SML data sign check error` (the modem-boot
  SML verification gate). All IDs/sizes PUBLIC-offloadable; backing ciphertext
  SILICON-BOUND.
- `CK*` NVRAM records (`nvram_live/`, 254 `NVD_DATA` + 5 `NVD_IMEI`; live
  `/mnt/vendor/nvdata/md/NVRAM/` mirrors): `CK0X_001` 272 B
  (`42e94355…`), `CK10_000` 240 B (`57d62858…`), `CK14_001` 672 B
  (`464b2a6c…`), `CK17_000` 256 B (`18f0ea87…`, `NVD_IMEI`, `root:system`
  perms vs `system:radio` for the rest), plus live-only `CK00_000` 816 B,
  `CK0B_000` 496 B, `CK0D_003` 368 B, `CK0G_000` 3184 B. `NVD_IMEI/FILELIST`
  45 B (`NV0S_000 LD0B_001 NV01_000 CK17_000 FILELIST`). These are NVRAM record
  IDs (CK = calibration/key-store records), names/sizes/sha PUBLIC-offloadable;
  any embedded key bytes stay opaque (recorded as LID headers `LID\0` + sha,
  never plaintext Blood).
- No file literally named `sec_factor` / `secfactor` exists in-repo (recursive
  filename grep: zero hits) — the IDs live ONLY as `sec_factor[id:…]` log lines
  in `nv_mini_dump` plus LID geometry above. No `CK17` private bytes reproduced.

## 5. GSMA CI / EUM / SM-DP+ cert mentions in eSIM logs

Which certs are NAMED/HASHED (never private). Full BPP parse in
`sim/esim_sim.py` (stdlib, offline); both sessions reproduced this session.

- Device: production eUICC, SGP.22 v2.3, ~1.16 MB free, ISD-R unreadable,
  carrier Tracfone per LPA UI; EID `89000000000000000000000000000000` (props
  only — absent from both BPPs in ascii/bcd/swapped, so no on-card EID-binding
  mismatch). `Euicc enabled=false` (`dump_isub`), slot1 `POWER_OFF/NOT_READY`.
- Session 1 `gsi/diag.txt` tx `47C80E586DD3B370115A18D37FA0720D` / Session 2
  `gsi/diag2.txt` tx `B46BBF761F2C51BC2A5138D78BC1DF8A`: ES9+
  `Executed-Success` both, then chip `6A80` on STORE DATA
  (`ES10B_ERROR_REASON_UNDEFINED`, no PIR). BPPs: 27,531 B raw each
  (sha1 `b0346995…` / `5717a746…`), outer `BF36[54]` len 27526,
  `initSecureChannel BF23` len 176 (ctrl 01, GSMA SM-XX OID, 5F49 65 B /
  5F37 64 B), `first87`×1 (24 B) + `seq88`×1 (156 B = BF25 148 B + MAC 8 B) +
  `second87`×1 (72 B) + `sequenceOf86`×27 (26×1016 B + 552 B). StoreMetadata
  BF25 len 144: ICCID `8914800000000004`, SP `GigSky`, profile
  `IPPv6.1c_Prod`, class `0x02 operational`, SM-DP+ id `0470`
  addr `smdpplus.ripsim.com`, PPR `80=130083 81=6FFFFF 82=FFFFFF`, pkg
  `com.gigsky.gigsky` seq 1. Trailing SCP03t C-MACs differ
  (`a9a1e46efb5103b9` vs `961522dd3b6c6afa` — fresh session keys each time);
  A3 profile bytes identical (sha1 `180e0c9f…`). Inference: `prod-inferred
  (heuristic; DPauth chain absent, NOT cryptographic proof)` — zero test
  markers (no `rsp.goog`/`sysmocom`/`test`). Definitive CI proof would need the
  ES9+ `AuthenticateServer` chain (absent — BPP only), so NO GSMA CI / EUM /
  SM-DP+ CERT bytes are present in `diag*.txt` to hash; only names/addrs above
  are PUBLIC-offloadable. Session MACs + SCP03t keys are SILICON/session-bound
  (per-session, never leave chip/SM-DP+).
- Named-but-absent test trust (never retried on this chip by policy):
  `prod.smdp-plus.rsp.goog` (+ `3TD6-8L82-HUE1-LVN6` etc.), sysmocom
  `smdpp.test.rsp.sysmocom.de` (`TS48V1-A-UNIQUE`), self-hosted `osmo-smdpp.py`
  SGP.26 TEST set (`smdpp-data/certs/`, UPP `.der` per matchingID). General rule
  (HIGH, not this pair): test-CI BPP on prod-CI chip ⇒ on-card ISD-R `6A80`;
  this production chip trusts ONLY prod GSMA CI → prod SM-DP+ → prod EUM.
- Captures `logcat_all.txt` (3 dirs, NO `esim_retry/` — never saved):
  `EuiccChannelManagerService` + ~82× `054d/054e` extended-access traces in
  baseline only; install-phase APDUs absent. Substring hits for `CI`/`MDP` are
  false positives (`DataSettingsManager`, `C2MtkConvert isMDPSupport10bits`);
  zero `EUM` / `GSMA` / `CERT` / `6A80` lines in any capture logcat. ATR
  (`gsi/atr.txt` 46 B) truncated — no cert data.
- Lab-owned test subscriber lives in `esim_lab/dummy_subscriber.json` (NOT
  published — this repo carries a TEMPLATE with placeholder values; generate
  your own Ki/OPc, e.g. `openssl rand -hex 16`, and keep the real file local).
  TEST-CI style PLMN, permissive PPR, no EID binding. MUST fail `6A80` on a
  prod chip by design; installs only on test-cert eUICC hardware.
- GigSky QR `1$smdpplus.ripsim.com$REDACTED-MATCHING-ID` (matchingID
  Old matchingIDs may be spent (single-use codes).

## 6. Live read-only (this session, REDACTED-SERIAL `device`)

- `dumpsys keystore` / `keystore2`: `Can't find service` (expected on this
  build — Keystore2 is reached via `android.system.keystore2.IKeystoreService/default`,
  which takes no `dumpsys` args from shell). Entry NAMES: none exposed.
  `dumpsys android.security.maintenance` (read-only, allowed): `keystore2
  running`, Kinibi KeyMint (Trustonic), HAL 200, DB 94208 B, tables
  (`KEY_ENTRY` 4096 unused 3278 …), exactly 1 `AES-256` keygen (NOAUTH, TEE),
  6 KEYOPs (`DECRYPT G---`×4, `SIGN --2-`×1, `VERIFY --2-`×1, all
  `SUCCESS/TEE`). `android.security.metrics|legacykeystore` empty;
  `compat` shows no cached KeyMint/SharedSecret. `/data/misc/keystore/`
  `persistent.sqlite` 94208 B + `vpnprofilestore.sqlite` 16384 B (`0600
  keystore:keystore`, metadata only — not catted). Conclusion: keystore
  exposes COUNTS/SIZES only; no alias/names to offload; all private key bytes
  SILICON-BOUND (TEE). Emulator: no `chl_*` (KeyMint≠modem CHL); `efuse_read`
  metadata only.
- `/dev` inventory (`ls -l`, no reads): NO `/dev/*key*`, NO `/dev/tee*`
  (only `/dev/teeperf` 505,1 system:system), NO `/dev/*rpmb*` besides
  `/dev/rpmb0` 506,0 root:root, `/dev/fuse` 10,229 root:root,
  `/dev/trusty-ipc-dev0` 503,0 system:system. `by-name`: `efuse` sdc28,
  `efuseBackup` sdc29, `otp` sdc36, `persist` sdc24, `prodpersist` sdc25,
  `proinfo` sdc20, `protect1/2` sdc31/32, `seccfg` sdc34, `tee_a/b`
  sdc55/79, `md1img_a/b` sdc39/61, `lk_a/b` sdc49/71, full map in transcript.
  `/dev/ccci_*` modem nodes present (AP↔modem transport, not key stores).
  All SILICON-BOUND nodes — only presence/major:minor/perms offloadable.
  Emulator: `efuse_read` (presence) only; no data reads performed.
- `getprop | grep -i -E 'key|fuse|otp|secure|attest|drm|fips'` (host-side
  filter, live): `drm.service.enabled true`, `keystore.*` (boot_level
  1000000000, crash 0), `persist.sys.fuse true` + `settings_fuse true`
  (Linux FUSE, NOT eFuse), `ro.fuse.bpf.* false`, `sys.fuse.transcode true`,
  `ro.secure 1`, `ro.hardware.kmsetkey/gatekeeper trustonic`,
  `ro.mtk_key_manager_support 1`, `ro.vendor.mtk_tee_gp_support 1`,
  `ro.vendor.mtk_trustonic_tee_support 1`, `ro.vendor.mtk_widevine_drm_l1_support 1`,
  `ro.keymaster.*` (AOSP/ARM64, xxx release 15, patch 2024-05-05,
  vbmeta `unlocked`, verifiedboot `orange`), `ro.vendor.sim_me_lock_mode 3`,
  `ro.vendor.esimid` + `ro.vendor.hw.esimid` (EID above),
  `vendor.gsm.sim.slot.lock.*` (state 0, policy 983040, remain 5,
  card.valid 2/2, svc.cap 4/4; SIM-insert transients 2→0/4→0 per HANDOFF),
  `persist.vendor.mot.model_for_attestation kansas`. NO `ro.vendor.*fuse*`,
  `*otp*`, `*tfn*` eFuse props exposed (TFN-OTP path dormant — matches
  hardcoded TFN stubs `custom_sml_tfn_get_tfn_otp_bit` 6 B /
  `custom_sml_set_device_unlock_tfn_otp_off` 4 B `01 d2 e0 db` /
  `custom_sml_cat_verify_pass_permanent_unlock` 4 B). Only IDs/policies
  PUBLIC-offloadable. Emulator: `efuse_read` (filtered props) + `sml_status`
  (lock bundle + remain pair 5==5, zero-state-change proof).
- `service list` key-related (read-only, 342 total, 15 hits):
  `drm.IDrmFactory/clearkey|widevine`, `keymint.IKeyMintDevice/default`,
  `keymint.IRemotelyProvisionedComponent/default`, `secureclock.ISecureClock`,
  `security.authorization|compat|legacykeystore|maintenance|metrics`,
  `gatekeeper.IGateKeeperService`, `keystore2.IKeystoreService/default`,
  `attestation_verification`, `drm.drmManager`, `keyAttestation
  AppIdProvider`, `secure_element (OMAPI)`. Service NAMES only — no key USE.
  Emulator: none directly (service presence for `apdu_xfer` routing note:
  `secure_element` + `054d/054e` path underlies the chunking hypothesis).
- World-readable cert/key files (`cat`/`sha256sum` only):
  `/system/etc/security/cacerts/` 143 files, `/vendor/etc/security/cacerts/`
  125 files + `cacerts_supl/` (~20, `111e6273.0`…), `/system/etc/security/
  otacerts.zip` sha `0475f5ba…ff79eb`, `/vendor/firmware/aw869x_rtp_Keys.bin`
  272,433 B (haptics keys, not silicon). System CA bundle names/hashes
  PUBLIC-offloadable; device-private blobs (§2) hash-only. Emulator: none
  (Android CA store ≠ modem CHL; listed for completeness, no `chl_*`).

## 7. Offload boundary table

`PUBLIC-offloadable` = pubkeys, certs (public halves), key-IDs, sizes, hashes,
policies, names/addrs — safe for PC emulator. `SILICON-BOUND` = private/HW
keys, RPMB/TEE/eFuse/OTP bytes, ciphertext, session keys — NEVER leave silicon;
PC gets only opaque sizes/hashes + oracle RECORDS. Right column is the exact
`HwOracle` op the emulator must call (recorded + raised; transport lives
outside `sim/` by design).

| # | Item | Location | Boundary | Emulator consequence (HwOracle op) |
|---|------|----------|----------|------------------------------------|
| 1 | CERT1 root pubkey (mod sha `c222c374…fd19`, RSA-2048/`0x10001`, OIDs `1.1/1.2/2.9/2.10/3.x`) | `stock_XT2513V/md1img.img:cert1md` ×3 @`0x2bc4a50…` + `lk.img:cert1` ×5 | PUBLIC-offloadable (pubkey + hashes + OIDs + types) | SOFTWARE `sw_cert2_rsa_sha256` (local RSA-PSS verify, NO oracle; eFuse compare skipped by design) |
| 2 | CERT1 image pubkeys / CERT2 pubkeys (modem `13a9c09a…03a`; LK-A `4f117a51…481e`; LK-B `9a303370…269`) + header/image hashes | `md1img.img:cert2` ×3 (1021 B) + `lk.img:cert2` ×5 (1021 B) | PUBLIC-offloadable | SOFTWARE `sw_cert2_rsa_sha256` (hash + sig + pubkey-match locally) |
| 3 | LK unlock secret `REDACTED-LK-SECRET` + key `REDACTED-LK-KEY` (live `lk_a`) | HANDOFF §4 / `stock_XT2513V/lk*.img` | NEVER publish owner bootloader credentials (redacted here) | NONE (boot bypass proven; no crypto op) |
| 4 | `mot_key_cek` 168 B (`a9026d68…`) | live `/mnt/vendor/persist/security/mot_key_cek` (644) = backup `persist.img`@`0xa1b020` | SILICON-BOUND (hash/size/magic only to PC) | NONE for modem emulator (TEE/Moto key; NOT `chl_*`; would be KeyMint/DRM scope) — `efuse_read` presence only |
| 5 | `wv.keys` 176 B (`addc4419…`) | `/mnt/vendor/persist/wv.keys` (644) = `persist.img`@`0x604138` | SILICON-BOUND | NONE (Widevine TEE; not modem CHL) |
| 6 | `attest_keybox.so` 8716 B (`6735db23…`) + `attestation_ids.so` 892 B (`f0d13d42…`) | `/mnt/vendor/persist/*.so` (640) = `persist.img`@`0x604148/60` | SILICON-BOUND | NONE (Kinibi KeyMint attestation; not modem CHL) |
| 7 | `rkp_complete[.tee_keymint]` 0 B flags | `/mnt/vendor/persist/rkp_complete*` | PUBLIC-offloadable (empty flags) | NONE |
| 8 | `seccfg` 524288 B (`db0f8ae8…`, `MMMM`/`EEEE`, 2 nonzero blocks) | `modem_bak/.../seccfg.img` = live sdc34 | PUBLIC header/hashes; fused root SILICON-BOUND | `efuse_read` (root presence only); no `chl_*` |
| 9 | SML blobs `SL00` (`0xEF28`) / `SL01` (`0xEF29`) / `LD36` (`0xEF2F`) / `LD38` (`0xEF31`) + 36 other LIDs (192 B hdr + chk @`0x80` + ct) | `protect1/2.img` = live `/mnt/vendor/protect_f/md/` | PUBLIC geometry/IDs/sizes/sha; ciphertext SILICON-BOUND (opaque) | `nv_read` (opaque `lid_name`+`rec_idx` → size/sha/geometry, never plaintext) |
| 10 | `nv_mini_dump` + `DEV_INFO` 16 B + `sec_factor[id:…]` IDs (`0xe42d/ef2f/ef31/f006/f008`) + `CK04_000` refs | `protect1.img:/md/nv_mini_dump` 1197850 B (`8d89eee1…`) / live 1211864 B | PUBLIC-offloadable (IDs, counts, sizes, log lines) | `nv_read` (extras inventory); HW/SW-enc triplets inform `chl_hash`/`chl_mac` routing (see §8) |
| 11 | `CK*` NVRAM records (`CK17_000` 256 B `18f0ea87…`, `CK14_001` 672 B, `CK10_000`, `CK0X_001`, live `CK00/0B/0D/0G`) | `nvram_live/` = live `/mnt/vendor/nvdata/md/NVRAM/NVD_{DATA,IMEI}/` | PUBLIC names/sizes/sha; embedded bytes opaque | `nv_read` (LID-indexed, same as §9) |
| 12 | `CustCHL_Calculate_Hash` [0x903fec66,0x903fecdc) 118 B | `md1work_romonly.bin` (VA-`0x90000000`=file off) | SILICON-BOUND key slot (`key_id`) | `chl_hash` (`data_hex`+`key_id`) |
| 13 | `CustCHL_Calculate_MAC` / `CustCHL_Verify_MAC` [0x903feba6,0x903fec66) | same image | SILICON-BOUND | `chl_mac` (`key_id`+`msg_hex`+`mac_hex`/`mac_len`) |
| 14 | `CustCHL_AES_{Encrypt,Decrypt}_data` | same (`0x903fe8ca…0x903feba6`) | SILICON-BOUND (no stdlib AES by policy) | ROUTER SAYS `nv_read` opaque-record — CORRECTION §8.1 (schema mismatch, live-uncallable; needs dedicated AES op) |
| 15 | `CustCHL_Verify_{RSA,PSS}_Signature` (fused root) | `0x903fefba…0x903ff46e` | SILICON-BOUND fused root (contrast image-key CERT2 which IS software) | ROUTER SAYS `chl_mac` — CORRECTION §8.2 (RSA≠HMAC, needs distinct op) |
| 16 | `CustCHL_Gen_Root_Key` / `Get_Sym_Key_Extend` + `cust_sec_get_device_secret_key` [0x90598e8a,0x90598ea8) + `mot_sec_calc_tfn_device_secret_key` [0x912db96e,0x912dba4e) (IMEI input `REDACTED-IMEI`) | same image | SILICON-BOUND (slots/secrets; IMEI public input only) | ROUTER SAYS `efuse_read` w/ `slot`/`imei` — CORRECTION §8.3 (live `efuse_read` takes no slot/imei; uncallable) |
| 17 | `cust_sec_calc_enc_auth` [0x90598c2e,0x90598d5e) 304 B + `cal_generate_hmac` [0x903e6690,0x903e66e6) + `smu_op08_verify_msg_hmac` [0x91990e08,0x91990e88) | same image | SILICON-BOUND device/CAL/op08 keys | `chl_mac` (explicit-key HMACs stay SOFTWARE `sw_hmac_sha256` — CORRECTION §8.4 dual-path) |
| 18 | `mot_sml_db_parameter_hash_verify` [0x912dc6c8,0x912dc93c) 628 B | same image | Silicon-anchored digest | `chl_hash` (`data_hex`+`digest_hex`) — CORRECTION §8.5 (param inconsistency vs §12) |
| 19 | `nvram_{HW,SW}_AES_encrypt_ext` ([0x919ad648,0x919ad698) 80 B / [0x919ad3de,0x919ad48e) 176 B) | same image | Record keys HW-bound (no SW AES in stdlib) | ROUTER SAYS `nv_read` w/ `lid`+`data_hex` — CORRECTION §8.1 (type mismatch vs `lid_name`) |
| 20 | Plain SHA256/HMAC-SHA256/MD5 (explicit key/data) + CERT2 image-key RSA-PSS | PC stdlib + repo tools | PUBLIC-offloadable (no HW key) | SOFTWARE `sw_sha256` / `sw_hmac_sha256` / `sw_md5` / `sw_cert2_rsa_sha256` (REAL local verifiers, NIST/RFC4231 + stock CERT2 `all_ok`) |
| 21 | Keystore2 / Kinibi KeyMint / Gatekeeper / `persistent.sqlite` 94208 B / RPMB (`/dev/rpmb0`) / `trusty-ipc-dev0` / `teeperf` / eFuse sdc28-29 / OTP sdc36 | live `/dev/*`, `/data/misc/keystore/`, TEE | SILICON-BOUND (counts/sizes/names only to PC) | `efuse_read` (filtered `getprop` only; no fuse/otp props exposed); NO `chl_*` (KeyMint≠modem CHL) |
| 22 | SML status (7-tuple `ESMLCK?`, test `ESMLCK=?`, lock props, remain 5, policy 983040, ME mode 3) | live AT `?` forms + `getprop` lock bundle | PUBLIC-offloadable (status snapshot) | `sml_status` (remain_before==remain_after 5==5, zero-state-change proof) |
| 23 | eUICC prod trust (GSMA prod CI → prod SM-DP+ `smdpplus.ripsim.com`/id `0470` → prod EUM/EID `REDACTED-EID`) + BPP outer (ICCID `REDACTED-ICCID`, `IPPv6.1c_Prod`, PPR, pkg) | `gsi/diag*.txt` (BPP outer) + props (EID) | PUBLIC-offloadable (names/addrs/hashes; DPauth chain absent so NO cert bytes to hash) | `apdu_xfer` METADATA only (forensics; UNIMPLEMENTED live) |
| 24 | BPP session keys / SCP03t C-MACs (`a9a1e46e…`/`961522dd…`, 5F49/5F37) + ISD-R private verification | chip + SM-DP+ session | SILICON-BOUND (per-session, never leave) | `apdu_xfer` (recorded + raised; chunking hypothesis: 27×86 ≤1016 B → MTK `054d/054e` ≤255 B STORE DATA) |
| 25 | Lab test keys (`dummy_subscriber.json` Ki/OPc, sysmo TEST SM-DP+, `osmo-smdpp` SGP.26 TEST set) + test QRs (`rsp.goog`, `smdpp.test…`) | `esim_lab/` + HANDOFF §4 (repo) | PUBLIC-offloadable (self-owned TEST only) | NONE on this chip (MUST `6A80` by design); `apdu_xfer` only against test eUICC (`sysmoEUICC1-C2T`) / `sysmoISIM-SJA5` |

## 8. Corrections to `sim/crypto_stubs.py` router assumptions (REPORT ONLY — no edit)

All findings verified against `sim/emu_engine.py HwOracle.OPS` +
`sim/oracle_transport.py` (dry-run default ON, denylist + allowlist) this
session. Router text (`--routes`) is quoted; live schemas are from
`OracleTransport.{nv_read,efuse_read,chl_hash,chl_mac,apdu_xfer,sml_status}`.

- 8.1 AES routes misuse `nv_read`. `CustCHL_AES_Encrypt_data`
  (`key_id`+`pt_hex`+`mode`) / `CustCHL_AES_Decrypt_data`
  (`key_id`+`ct_hex`+`mode`) route `via nv_read`, but live
  `nv_read(lid_name: str, rec_idx: int)` accepts ONLY allowlisted backup names
  (`SL00_000`, `SL01_000`, `LD36_003`, `LD38_010`, `NVD_DATA`, `NVD_IMEI`,
  `DEV_INFO`) — any `key_id`/`pt_hex` call raises `BannedOperation` before any
  I/O. Same for `nvram_HW/SW_AES_encrypt_ext` (`lid: int`+`rec_idx`+`data_hex`
  vs `lid_name: str`+`rec_idx` — `int` vs `str` type mismatch plus extra
  `data_hex`). Effect: all four AES routes are PC-record-only, NOT
  live-callable despite `kind=oracle`. Fix (not applied): dedicated oracle op
  (e.g. `aes_opaque` with `{key_id, in_hex, mode}` → `{note}`) or route HW-AES
  NVRAM via `nv_read` with `{lid_name, rec_idx}` ONLY and drop `data_hex` to a
  separate `chl_*` record. Policy `NO homebrew AES` stays.
- 8.2 RSA-veriy via `chl_mac` conflates primitives.
  `CustCHL_Verify_RSA_Signature` / `Verify_PSS_Signature`
  (`key_id`+`msg_hex`+`sig_hex`) route `via chl_mac`, whose live meaning is
  HMAC/MAC (`smu_op08`, `cal_generate_hmac`, `cust_sec_calc_enc_auth` share the
  same op with `mac_hex`). Replaying an RSA `sig_hex` where an HMAC `mac_hex`
  is expected (or vice versa) is a type confusion for any future transport that
  actually implements `chl_mac`. Fix: distinct op (e.g. `chl_rsa` with
  `{key_id, msg_hex, sig_hex, scheme: rsa-pkcs1|pss}`), keeping the correct
  boundary note (fused-root ⇒ oracle; image-key CERT2 ⇒ `sw_cert2_rsa_sha256`).
- 8.3 `efuse_read` slot/IMEI params have no live counterpart. `Gen_Root_Key`
  (`slot`), `Get_Sym_Key_Extend` (`slot`), `cust_sec_get_device_secret_key`
  (`slot`), `mot_sec_calc_tfn_device_secret_key` (`imei`) all route
  `via efuse_read`, but live `efuse_read()` takes NO arguments (fixed filter
  `getprop | grep fuse|otp|tfn|sim_me_lock`, host-side) and this build exposes
  zero fuse/otp/TFN props (dormant TFN stubs confirmed). Any slot/IMEI call
  cannot be issued live. IMEI-as-`imei` is additionally misleading: IMEI is a
  PUBLIC derivation input, not a secret slot — the fused secret never leaves
  silicon, but the router implies the IMEI itself needs the oracle. Fix: keep
  `efuse_read` for the filter-only probe; add slot-indexed op (e.g.
  `key_derive {fn, slot|imei}` → record-only) for the four derivation fns.
- 8.4 `cal_generate_hmac` needs a dual path. Router forces
  `via chl_mac` for every CAL HMAC, but the module docstring already admits
  `sw_hmac_sha256` is correct "when the key is EXPLICIT". There is no
  explicit-vs-provisioned discriminator in `ROUTES` — a caller with a test/LAB
  key in hand is still forced to the oracle (UNIMPLEMENTED) instead of the REAL
  local HMAC. Fix: `cal_generate_hmac_explicit {key_hex, msg_hex}` →
  `sw_hmac_sha256`; keep `cal_generate_hmac {key_id, msg_hex}` → `chl_mac`.
- 8.5 `chl_hash` has two incompatible schemas on one op. `CustCHL_Calculate_Hash`
  sends `{data_hex, key_id}` while `mot_sml_db_parameter_hash_verify` sends
  `{data_hex, digest_hex}` (no `key_id`). Both claim `via chl_hash`, and the
  fallback `HwOracle.query(op, params)` accepts anything, so selftest passes —
  but any real `chl_hash` transport must branch on shape. Fix: standardise
  `chl_hash {data_hex, key_id?, expected_digest_hex?}` and update both routes
  + selftest schema checks (currently only checks `via in OPS`, not params).
- 8.6 No eSIM session-key route. SCP03t / BPP `sequenceOf86` session
  encryption + C-MAC have NO `ROUTES` entry (only `apdu_xfer` UNIMPLEMENTED in
  the transport). Correct to leave them oracle-only, but the gap means a
  future STORE-DATA forensics harness has no router name to call — add
  `bpf_sc03t_wrap {bpp_sha1, seg_idx}` → `apdu_xfer` (record-only) instead of
  overloading `chl_mac`.
- 8.7 Convention arity is still UNRESOLVED (not a code bug, but a router
  soundness caveat). All four `CONVENTIONS` entries correctly mark
  `args a0-a? UNRESOLVED` / `ptr-vs-scalar UNRESOLVED` (no Ghidra pcode yet;
  `md1work_sml.asm` 0 hits by design). The router `params` dicts
  (`key_id`/`msg_hex`/…) are therefore GUESSED ABIs, not carved ABIs — they
  must not be cited as proven call shapes. Close-out per entry (fn-anchored
  `nanomips:LE:32:default` disasm + BALC/xref recovery) is still open; no
  &::emulator should hard-code arity until then.

No file was edited for this report. `sim/crypto_stubs.py --selftest` still
`PASS` (NIST/RFC4231 + CERT2 + carve + router-schema) — the corrections above
are live-transport/schema issues, not selftest failures.

## Appendix — methods, hashes, transcripts (no private bytes)

- PC hashes (sha256 unless noted): `md1img.img` CERT1-root `c222c374…`,
  modem-image `13a9c09a…`, LK-A `4f117a51…`, LK-B `9a303370…`; `persist.img`
  `a3966cb4…`; `seccfg.img` `db0f8ae8…` (== live sdc34); `mot_key_cek`
  `a9026d68…` (168 B); `wv.keys` `addc4419…` (176 B); `attest_keybox.so`
  `6735db23…` (8716 B); `attestation_ids.so` `f0d13d42…` (892 B);
  `otacerts.zip` `0475f5ba…`; BPP sha1 `b0346995…`/`5717a746…`, A3
  `180e0c9f…`; `nv_mini_dump` `8d89eee1…` (1197850 B backup / 1211864 B live).
- Live remain proof: `vendor.gsm.sim.slot.lock.device.lock.remain.count 5==5`
  before/after all reads (`zero_state_change true`); no AT `=` sent, no
  `setprop`, no writes, no reboot (audit: `at_log` empty; shell allowlist
  `getprop|dumpsys|service list|ls|cat|sha256sum|getenforce` only).
- Transcripts: prior `sim/oracle_logs/live_readonly_probe.jsonl`
  (`sml_status`+`efuse_read`, LIVE-READONLY) and `selftest_dryrun_probe.jsonl`
  (DRYRUN) untouched; this inventory appends
  `sim/oracle_logs/key_inventory_20260905.jsonl` (new file, JSONL, one
  `{op, params, result}` per §1–§6 row, hashes/sizes/policies only).
- Negative results (recorded, not omitted): NO `/dev/*key*`, NO `/dev/tee*`
  (exept `teeperf`), NO fuse/otp/TFN props, NO keystore entry names, NO
  `sec_factor` filenames, NO `esim_retry/` capture, NO GSMA CI/EUM cert bytes
  in `diag*.txt`/logcats, NO `mot_key_cek`/`wv.keys` plaintext in this file.
- Device-state bans observed: `setprop`/`dd`/flash/reboot/AT-set/NCK never
  issued; `attest_keybox.so` (640) hash-only despite readable shell;
  `/dev/block/*` hash-only for `seccfg` (no bulk reads); `dumpsys keystore*`
  correctly fails (`Can't find service`) — documented, not retried with key USE.
