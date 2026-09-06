# Kansas Modem Lab (MT6835 nanoMIPS) — replication package

Read-only baseband RE + emulation toolkit for the MediaTek MT6835 modem
(PCORE nanoMIPS I7200, Nucleus RTOS), as found in the Moto G 5G (2025).
Everything here runs against **your own dumps on your own hardware**.
Nothing here writes to a device, spends carrier unlock attempts, or touches
identity (IMEI/NCK/IMSI/keys) — see SAFETY.md first, it is short and load-bearing.

Origin: a private device lab, sanitized for publication. All device-unique
identifiers (IMEI/serial/EID/keys/QRs/MACs), owner bootloader credentials,
live captures, and all firmware binaries were removed. Fixture APDUs kept in
`sim/` are expired-session captures (single-use, cryptographically dead) and
AES vectors are published FIPS-197 test values.

## Layout

- `sim/` — stdlib-only Python arsenal (emulator core, SML/NVRAM/RMMI/eSIM
  models, fuzzers, decomp pipeline client, trace tools). Needs Python 3.10+
  plus `capstone`, `kaitaistruct`, `hexdump` (`pip install` all three).
- `docs/MODEM_CODEMOD.md` — the full methods dossier: image anatomy, ISA +
  encodings, sign/flash/verify pipeline, patch catalog, harness truth table,
  hard boundaries (eUICC trust, HW-bound secrets, DSP, RF physics),
  SML model, eSIM forensics, failure catalog, open items. **Read this first.**
- `docs/modem_map.html`, `docs/emu_window.html` — system map + trace bench
  (open in a browser; regenerate the bench with `tools/emu_window.py`
  after you run the sims).
- `pi-tools/` — pi agent extension (guarded read-only AT + sim runners) and
  the modem-hunt skill. Requires the `pi-subagents` package for subagent
  workflows; see `pi-tools/skills/modem-hunt/SKILL.md`.
- `tools/emu_window.py` — rebuilds the trace bench from `sim/chains/`.
- `esim_lab/dummy_subscriber.json` — TEMPLATE with placeholder values.
  Generate your own test keys (`openssl rand -hex 16`) and keep the real
  file out of git.
- `audits/` — not shipped; write your own findings there (see SAFETY.md on
  disclosure).

## Replicate in order

### 0. You need (not shipped — extract/build/provision yourself)
- A rooted device of your target build + `adb`/`fastboot` (platform-tools).
- Your modem image: pull your own `md1img` (`adb shell su -c "dd
  if=/dev/block/by-name/md1img_a ..."`, read-only), unpack with
  [R0rt1z2 md1img unpacker](https://github.com/R0rt1z2) or NCC `mtk_bp`
  (`md1rom` payload ≈ 45.9 MB here; yours will differ — re-derive sizes).
- CATI symbols: extract `md1_dbginfo` via NCC `mtk_bp`, parse to
  `{name:[startHex,endHex]}` JSON, point the sims at it with
  `MODEM_LAB_TMP` (they default to `sim/Temp/`).
- Ghidra + [ghidra-mtk-loader](https://github.com/nccgroup/ghidra-mtk-loader)
  + [ghidra-nanomips](https://github.com/nccgroup/ghidra-nanomips) (build the
  plugin from source for Ghidra 12.x with JDK 21; the prebuilt targets 11.x).
- Vendor MTK nanoMIPS toolchain (GAS `-march=i7200`, objdump `-m nanomips`,
  GDBsim) for triple-evidence on every patched byte. Never hand-assemble.

### 1. Gates first (all must pass before any device contact)
`python sim/emu_engine.py`, `python sim/hw_target.py`,
`python sim/sml_sim.py --selftest`, `python sim/rmmi_sim.py --selftest`,
`python sim/nv_model.py --selftest`, `python sim/interp.py --conform`.

### 2. Learn your image
Carve one function from your ROM by CATI extent, import raw-binary into
Ghidra (`nanomips:LE:32:default`, rebase to its VA), and reproduce the
stock-vs-patch execution differential in `sim/interp.py` before changing
anything. `docs/MODEM_CODEMOD.md` §2–§6 is the procedure; §11 lists every
dead end so you don't re-walk them (Thumb-2 decoding, full-image headless
import, Unicorn MIPS32 approximation, FirmWire full-system, BROM tools).

### 3. If you patch live firmware (your risk, your device)
Same-footprint overwrites only (never insert/shift); every byte string
verified by decode round-trip + simulator execution; Temp-only build;
CERT re-sign flow per your bootloader state; slot-disciplined flashing with
a tested revert image staged first; remain-counter and modem-exception
checks before AND after. Full recipe + abort criteria: `docs/MODEM_CODEMOD.md` §3.

## What this repo will never contain
Factory/vendor firmware binaries (extract your own; redistribution is both a
copyright and a supply-chain problem), APKs, live captures, NVRAM dumps,
private keys, certificates, QRs, identifiers, or credentials. Anything of
that shape is a bug — report it as one (see SAFETY.md disclosure note).
