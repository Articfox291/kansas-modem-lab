# MODEM CODE MODIFICATION — complete transfer dossier
Kansas lab (XT2513V, MT6835, build P247.01.339R) → any next agent/device.
READ THIS WHOLE FILE BEFORE TOUCHING A MODEM IMAGE. The failure catalog (§11)
is as valuable as the recipes: each entry cost real flash cycles to learn.

Rule zero: modem slot A is the lab bench, slot B is never stock here (OTA
image — see §3), preloader/LK/GPT/efuse are never named in any command.

---

## 1. Image anatomy (exact numbers)

- `md1img` container: **23 files** (`md1imgpy` must list all 23 or stop).
  Stock file: **75,697,504 B**, sha256 `371671d3…ab3272`.
- `md1rom` payload: **45,893,712 B @ file offset 0x200**. Loads at AP-phys
  `0xD0000000` (45.8 MB carveout), runs at modem VA **`0x90000000`**.
- GFH `FILE_INFO` at md1rom+0x400 gives `load_addr 0x400`. GFH header region
  `0x400–0x5ff` is bootloader-parsed: **NEVER patch there**.
- CATI debug table (`md1work_dbginfo.bin`): **125k–135k symbols**, format
  `(prev,start,name,start,next)` → exact function extents. Pre-parsed to
  `cati_syms.json` (`{name:[startHex,endHex]}`); resolve via
  `sim/emu_engine.py load_cati()`.
- CERT1 type `0x02000001` (LK uses `0x02000000`; only CERT2 matters here),
  CERT2 `0x02000002`, RSA-2048, sha256, sec_level 0. Per-triple model:
  (target + CERT1 + CERT2). OIDs: image hash `2.16.886.2454.2.1`, header hash
  `...2.4`. CERT2 dsize stock = 1021 per triple.
- Offset math: `romonly_off = VA - 0x90000000`; `img_off = romonly_off +
  0x200`. PROVEN for 0x905D/0x905E/0x9198 regions **per site** — one 0x9198
  sub-region once mismatched, so verify every site's bytes before patching,
  never trust arithmetic alone. CATI-anchored carve (`sim/decomp.py`) is
  authoritative; NEVER hand-compute a target VA without a carve check.
- Non-go zones (signature/separate-trust anchors outside the bypass):
  GFH header, SIGN5 manifest `@0x2af9607`, CERT blobs themselves, live
  marker bytes of other experiments.

## 2. CPU + encodings (nanoMIPS I7200, LE32 — all prior ARM analysis VOID)

- Proof: `nano_i7200.elf.gcc` string + CATI mips/VPE symbols + NCC loader
  (nanoMIPS-only) + GAS/GDBsim agreement. Ghidra language
  `nanomips:LE:32:default` + NCC MTK loader + nanomips plugin (built for
  Ghidra 12.1.3 with JDK 21; prebuilt zip is 11.4.2-only).
- Canonical stubs (triple-evidenced GAS+Ghidra+emu, byte order = FILE order):
  `LI a0,1` = `01 d2` (+`JRC ra` = `e0 db` → force-pair `01d2e0db`, 4B);
  `LI a0,0` = `00 d2`; `NOP(16)` = `08 90` (corpus precedent: 80 lines);
  4B no-op class = `SLL zero,zero,0` (`00 80 00 c0`, no literal NOP text).
  Pitfall: disassemblers print halfwords (`d201`) vs file bytes (`01 d2`).
- Branches: `BNEIC/BEQIC/BNZEC/BEQZC/BNEC/BEQC/BC/BGEIUC/BLTUC/BBNEZC`,
  `BALC`/`MOVE.BALC` (4B, `hilo_saddr26`: `tgt = next + sext26`,
  raw=`(tgt-(at+4))&0x3FFFFFF`, ±32MB — reaches anywhere in-image),
  `JALRC ra,rs`, `JRC ra` (`e0db`). `SAVE/RESTORE[.JRC]` = frame ops (NOT
  IRQ ops). `LSA/LWPC/ADDIUPC/ALUIPC` = pcrel math. `MFC0/RDHWR` = safe
  read-only coprocessor reads. No delay slots on nanoMIPS.
- IRON RULES: (1) same-footprint only — overwrite, never insert/shift;
  (2) never hand-assemble — every byte string must round-trip through
  `decode_tables.decode_bytes` + corpus/Ghidra text; (3) vendor GAS
  assembles almost nothing (`nop`/`break` only — objdump-direction evidence
  only); (4) `JRC`-via-arbitrary-reg encodings must be derived, not guessed.

## 3. Sign → flash → verify → revert (the proven pipeline)

1. Work on Temp copies, never repo originals (`git diff` stays empty).
2. Patch bytes (old-byte assert each site; sizes equal; diff audit lists
   every changed byte vs stock).
3. Re-sign: `python tools/sign_mtk_cert.py -w <img> -o <out>` (prepends 0xA0
   TLV hash-override, CERT2 dsize 1021→1111, file +96 B padded). Why it
   works: unlocked bootloader (`securestate: flashing_unlocked`), CERT2 is
   the enforced anchor and the override is accepted.
4. Verify: `sim/boot_sim.py verify_image` — ALL triples hash+RSA OK;
   `md1imgpy list` — 23/23 parse, growth isolated to md1rom CERT2.
5. Flash: `fastboot flash md1img_a` ONLY (2–3 s) → `fastboot reboot`.
   Fastboot via Vol-Down+Power (+cable-insert trick if looping).
6. Verify live: baseband alive, SIM/prop state as predicted, remain 5→5,
   `dmesg` modem-exception count 0, AT readback of markers.
7. Revert = reflash last-good (stock `371671d3…` or prior working build).
- Slot truth (measured, not assumed): A = our builds, **B = unknown OTA
  image** (not stock — the old "slot B stock" assumption is dead).
- Hash-size trap: signed files are +96 B; compare live partitions with
  `head -c 75697504 | sha256sum` math, never raw full-file hashes.
- Prop trap: `ro.boot.flash.locked=1`/green vbmeta are Frankenstein
  artifacts; fastboot `securestate` is authoritative truth.
- Reboot wipes logcat RAM buffers (capture before), NOT flash or props.

## 4. Patch technique catalog (all live-proven unless noted)

- **Entry-force** (4B `01d2e0db`): function returns pass/LEGAL unconditionally.
  Live at `legal_sim_rule` (cat0/Network door) + `sml_sl_Check` (SP-family
  door). Tail becomes unreachable — acceptable. Blast radius = all callers.
- **NOP-fill branch kill** (`0890 0890` over 4B conditional, `0890` over 2B):
  every arrival falls through to the fall-through arm. Live at 6 sites in
  `smu_check_sml` (E6E2/E6BA/E6E8/E6F0/E6F4/E6F8). Requires proving the
  fall-through arm is the allow arm **with the live register state**, not
  just structurally — branch-level proof is necessary, not sufficient (the
  E6E2 lesson: downstream gauntlet gates on verified-state contents).
- **Branch-flip** (BNEIC↔BEQIC, single-bit pool flip): NARROWER blast radius
  but INVERTED semantics (home cases regress) — document, prefer NOP-fill
  unless scope demands the flip + polarity proof both arms in harness.
- **Detour/trampoline** (BALC-to-cave + `JRC ra` return): for executing NEW
  logic. Cave rules: no calls (ra preservation), t-regs + replicated arg
  only, replicate the skipped insn verbatim, position-independent,
  return via known-good `JRC ra`. Detour AFTER send/format calls, never
  inside them (the 0x90F0E198 lesson: skipping a send-call kills the AT
  response — moved to 0x90F0E19C epilogue RESTORE instead).
- **Data-only string swaps** (same length, NUL + pad math): version/identity
  strings served by read-only AT paths (MTK2→MTKQ via ATI; P247→P248.TESTING
  via CGMR/prop/GUI). Readback-designed: every marker names its serving
  observable BEFORE flashing. NEVER identity digits (no IMEI/NCK/IMSI bytes
  exist in ROM — labels only; identity writes are permanently out of scope).
- **Cave hunting**: zero-run ≠ dead. Adjudicate: CATI emptiness + LE32-ref
  scan (false positives are instruction bits — decode the hit site!) + MPU
  RX region + neighbor analysis (tables alternate VA-words/holes; true pad
  is uniform). 1038 B pad used once; table holes (176–232 B) refused twice.

## 5. Live patch inventory (kansas P247 — 41 bytes total)

force-legal@0x5DF4FA + sl-force@0x5EFF10 (both `01d2e0db`) + 6×NOP gauntlet
(E6E2 `70ca5b0f`, E6BA `90c89c08`, E6E8 `f0c87009`, E6F0 `90c87008`,
E6F4 `a0ca6c38`, E6F8 `608ae000` → all `08900890`) + markers
(MTKQ@0x1E3DCE3, P248@0x2B7E777, TESTING suffix). Images: stock `371671d3`,
force1 `7ed17911`, marker `52b42f29`, msg `383bf508`, sp2/sp3 series —
each sha-pinned in capture manifests with before/after bundles
(remain/ESMLCK?/CGMR/ATI/dmesg).

## 6. Sim + verify harness (what's real, what's stubbed)

- `interp.py` strict Cpu (61 mnemonics, 4-backend agreement on core flows).
  REAL: carved-function execution, branch semantics, strict HW-boundary
  stops. STUBBED/GAPPED: SWM/LWM executors, XS-scale indexing, INS/EXT
  decode rows, one p32 decoder fault, ret1@0x0 auto-stubs for unmapped
  JALRC targets, zero-page RAM reads, CP0-always-0, no MMU/TLB/scheduler/
  DSP/RF/interrupts. Diffs proposed-not-applied live beside the code.
- `chain.py` presets (legal/link/esmlck/verify + `--fork-getitem` 3×3 over
  resolved getItem trio) + Temp harness patterns (StrictCpu subclass,
  single-gate stock-vs-patched asserts, breakpoint fork driver).
- `decode_tables.py` (1191/1191 corpus-identical text) is ground truth for
  bytes↔text; Ghidra Nmdis2 for full functions (fn-anchored carves ONLY —
  mid-function windows hang; full-image headless import spins forever).
- GDBsim bare-metal: ALL objects `-march=i7200` (32r6s trips the NMS gate),
  `--memory-region` map required (default 32 KB zero-reads), vector stubs
  from verified bytes only, iterative page mapping for `0x24xxxxxx`.
- `mem_model.py`: MPU table (md_rom RX — caves are executable),
  SMEM/CCIF/DPMAIF/WDT stubs. `sml_conform` gate: 1 known RED (home=1
  input-mismatch debt — input modeling, not engine).
- `boot_sim.py`: CERT triple verifier + stage/recovery model (also documents
  WRITE_BLOCKLIST: preloader/gpt/efuse never patchable by design).

## 7. Hard boundaries (physics, crypto, silicon — not skill gaps)

- **eUICC trust**: prod chip verifies server+profile signatures itself;
  modem transports opaque APDUs. No modem edit changes chip acceptance.
  Test path = test-cert chip + own SM-DP+, unmodified transport (proven).
- **Secrets**: SML plaintext/NCK/keys/eFuse/RPMB/TEE answer yes/no through
  oracles; bytes never surface. Hash-only handling, always.
- **DSP** (Coresonic, EL1D/TxDFE/DPD): no toolchain; numerology + closed-loop
  gain live here. Mailbox C2S/S2C glue is listed; cores are dark.
- **RF**: synth lock range, duplexer passbands (B8 UL covers 902–915;
  915–928 is roll-off), PA match, calibration tables. PCORE *requests* via
  tables + BSI words (band-idx a0 + freq-word a2 entry proven); hardware
  *disposes*. Conducted measurement decides; Part 97 ciphering conflicts
  with LTE OTA on amateur spectrum — conducted-first stands.
- **NVRAM**: HW-bound ciphertext + hash-verify + fail-closed asserts
  (`lid_error_handle.c:161` → exception loop; lived twice). Erase = brick
  loop (recovered). Checksum field ignored pre-read (use-before-verify
  window) but tampering fails closed downstream. Rec-size edges ACCEPT with
  stale-tail confusion only.
- **RF/TX map for tuners**: gain table `0x25c9348c`, comp-route `0x92479f54`,
  ramp `0x24a9cd90`, BSI hub `SetRxRFSetting`, AFC synth tune; GSM ARFCN
  converters listed, LTE EARFCN lives in RMM/MEME+EL1D (unmapped); TX power
  is table-capped (verifiable conducted); PUSCH gen is standard-LTE PHY.

## 8. SML verdict model (current truth)

- Polarity: 1=pass/LEGAL everywhere EXCEPT op-family inversion (0=pass) and
  inner-HCK inversion. 13 sites mapped, zero mixups.
- Doors: cat0/Network → `legal_sim_rule` (force-1); SP-family →
  `sml_sl_Check` + `smu_check_sml` gauntlet (force + 6 NOPs, live-cleared:
  NETWORK_LOCKED→LOADED, prompt gone, remain 5).
- Test-SIM conditions (sim-proven): allowlist-append `["311480","99970"]`
  is the minimal persistent form; NCK path RAM-only; test-gate RESTRICTS
  (no backdoor — test leg returns DENY).
- JALRC vtable: per-boot constructor from ROM templates
  (`[0,give,take,destory,getItem,putItem]`); slot+0x10 = getItem trio
  (sl/op07/sml) — fork-executed live, NULL-table assert on empty RAM.
- NCK: `[5,4,3,2,1,0]` → sticky hard-lock; stock oracle accepts nothing.

## 9. eSIM forensics (transport solved, chip gates)

- Live sessions: GigSky 27,531 B + Firsty 34,481 B, both prod-signed,
  both `authenticate_server=0` pre-pass, both dead on fragment #1
  (63 B, P1=0x11) with bare `6A80`, no PIR, ~28 ms, deterministic ×6.
- Models: M2 total-cap (>16 KB) FIRES on both; M4 no-slots tied; M1
  longform REFUTED (fires on proven-good opens); M3 hostid inert;
  chunking/transport/CI/memory all refuted with captures. LPA chains
  correctly (P1 intermediates all 9000).
- Open: D2 small-profile control (<16 KB total separates M2/M4), D3
  carrier QR, fresh-code discipline (one attempt per matchingID, verbose
  PIR, radio+main logcat, bundles shaped like `esim_retry_20260905_130857`).

## 10. Tooling built (reuse, don't rebuild)

- `.pi/extensions/modem-tools.ts` (chain/deep/disasm/guarded-atquery/
  bpp_replay/gates) + `modem-hunt` skill (lab rules: read-only default,
  remain floor, sim-first gates) + `deep-android.ts` (logparse, gates,
  DRY-RUN-ONLY flash planner that refuses without backups/slot-B-stock).
- `sim/` arsenal: sml/nv/rmmi/esim/boot/chain/deep/bpp_wire/at_fuzz(×2)/
  oob_proof/nv_fuzz(×2)/sml_logic_fuzz/verify_hardening/emu_rmmi/emu_nv/
  crypto_stubs/oracle_transport/mem_model/decomp/backend_ghidra/decode_tables.
- kansas-modem-unlock repo: fingerprint-gated unlocker + wizard
  (detect/flash/root/unlock) + device-profile schema + experimental red
  mode + custom-table flow + full-parse byte-exact audit + tkinter GUI +
  CachyOS installer. No personal data in either repo (audited per commit).

## 11. Failure catalog (read before repeating anything)

Magisk-anywhere (4 bootloops) → KSU-init_boot only. protect erase →
assert loop (restored). Thumb-2/RISC-V analysis → VOID (nanoMIPS proof).
Full-md1img headless import → infinite spin (carve-fn pipeline instead).
Mid-function Ghidra windows → hang (fn-anchored only). Unicorn MIPS32LE
approx → inexact (GDBsim exact-ISA instead). FirmWire/qemu-user → NO-GO
(classic-MIPS/Linux vs nanoMIPS/Nucleus). BROM/mtkclient → V6 patched.
NCK brute force → capped (floor 5, RAM-only models). Test profiles on prod
eUICC → auth-dead by design. MOLY→CGMR theory → refuted by live CGMR
(true source: third version copy). 0x90F0E198 detour → dropped the send
call (moved to epilogue). sl_Check force alone → insufficient (struct
returns; verdict lives at caller branch). E6E2-NOP alone → insufficient
(downstream gauntlet on verified-state contents). Stale VA E6C2 (−0x20
from true E6E2 — would have crashed; carve-verify rule). GAS assembly →
broken (objdump-direction only). Slot-B-stock myth → OTA-other (revert =
repo stock). ro.boot locked/green props → Frankenstein artifacts
(fastboot securestate is truth). /tmp mismatch (Win python vs MSYS)!
→ absolute C:/ Temp paths. Stock-hash size trap (+96 trailer math).
Screencap broken on GSI (photo fallback). adb PATH quirks (vendor/ +
ADB_PATH + bootstrap). `start` may not surface windows (PowerShell
Start-Process fallback + paste-in commands).

## 12. Open items (ranked for the next agent)

1. No-SIM boot under cascade (untested corner — revert ready).
2. OTA relock watch (re-verify baseband text after any modem update).
3. EARFCN/MEME + mcf-consumer + RPC-client listings (VAs banked).
4. H1/H2 closers (DeepRunner E1 + DST canary; JRC gadget survey needs writer).
5. Interp gaps (SWM/XS/INS diffs proposed, staged table word, decoder fault).
6. D2 small profile / D3 carrier QR / fresh-code discipline (eSIM tiebreak).
7. Test-eUICC + osmo-smdpp (full control down to KB profiles).
8. DHL unmute (muxreport/META — needs explicit approval; taps mapped).
9. eSIM slot power-up (LPA binding; read-only checklist banked).
10. Full-PCORE coverage is weeks (Ghidra-spin fix first); family-level
    ~90–95% on security-relevant code is the working ceiling — and it has
    been sufficient for every result banked here.
