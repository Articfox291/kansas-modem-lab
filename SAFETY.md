# SAFETY — read before running anything against hardware

## Non-negotiable lab rules
1. **Read-only default.** No flash/erase without a staged, verified revert
   image and a written reason. No `setprop`/`settings put`/reboot as part of
   analysis. No `Nvdata`/`nvram`/`protect` writes or erases, ever — corrupting
   modem NVRAM bricks the baseband into an exception loop.
2. **Attempt floor.** SIM-unlock attempts are capped in hardware (commonly 5,
   then sticky hard-lock). Never send set/unlock/commit forms, never trial
   NCK codes, never touch ESMLCK-set / CLCK-unlock / RSU-set / MOTSMLDB
   writes. Read-only query forms (`...=?` / `...?` / facility-status) only.
   Read the counter before AND after every session; any movement aborts
   the session.
3. **No identity writes.** IMEI, IMSI, GID, keys, certificates, QRs: display
   truth only. Changing device identity is illegal in multiple jurisdictions
   (e.g. UK re-programming law) and serves no research purpose here.
4. **No bricking paths.** Never flash or model writes to preloader, GPT,
   efuse, LK/bootloader regions, or partition tables. Keep one known-good
   slot/image aside; never test on your only copy of anything.
5. **RF honesty.** Receiving/listening is safe. Anything radiated must stay
   inside your national rules (power, bands, equipment authorization);
   modified firmware + antennas is not a license. Prefer conducted
   (cabled/attenuated) or shielded testing; log every TX run.

## Credentials in this repo: none, by construction
- `esim_lab/dummy_subscriber.json` is a TEMPLATE (placeholder values).
  Generate real test keys locally (`openssl rand -hex 16`) and never commit
  them. Fixture APDUs in `sim/` are expired single-use sessions plus
  published FIPS test vectors — cryptographically dead by design.
- Never paste unlock keys, bootloader secrets, QR codes, EIDs, ICCIDs,
  IMSIs, serials, or certificates into code, docs, logs, or issues in
  this repo. The pre-release audit that cleaned this tree is re-runnable:
  search for 15+-digit runs, `89…` ICCID shapes, 32-hex strings near
  key-like words, emails, MACs, absolute user paths, and PEM/token markers.

## If you find a real vulnerability
Do not drop a weaponized PoC here. Validate sim-first, keep the write-up to
findings + preconditions + fail-closed analysis, and disclose through the
vendor's security channel (SoC vendor, then OEM) with a reasonable embargo.
Unproven/conditional primitives stay labeled as such — severity without an
end-to-end chain is a hardening note, not a CVE. See `docs/MODEM_CODEMOD.md`
§10 for the audit/writeup pattern used here.
