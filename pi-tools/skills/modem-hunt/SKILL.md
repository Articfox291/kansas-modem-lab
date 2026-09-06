---
name: modem-hunt
description: Hunt modem baseband vulnerabilities on the Kansas lab (MT6835 nanoMIPS modem) using the repo's sim/* emulator arsenal. Use when tracing modem code, validating unlock hypotheses, replaying eSIM sessions, or checking verification gates before any device contact.
metadata:
  lab: kansas
  target: MT6835 PCORE nanoMIPS I7200
  model-note: built alongside opencode-go/muse-spark-1.3-contributor; run pi with `--provider <yours> --model <equivalent>` and your own credentials (`pi auth`); never commit keys.
---

# Modem Hunt (Kansas lab)

PC-side hunt rig for the Moto G 5G (2025) XT2513V modem. Everything runs
read-only against saved dumps. **Attempt floor: remain.count stays 5.**

## Lab rules (non-negotiable)

- No device writes: no flash/erase, no setprop, no settings-put, no reboot.
- No attempt consumption: no AT set/unlock/commit, no NCK trials, no
  ESMLCK-set / CLCK-unlock / ERSUKEY / ESMLRSU-set / MOTSMLDB writes.
- `modem_atquery` enforces this with a denylist; read-only forms only
  (`AT+CMD=?`, `AT+CMD?`, `AT+CLCK="PN",2`).
- HW-key oracle reads are allowed (recorded transcripts only, never keys).
- Verify in sim BEFORE any device contact: `modem_gates` must PASS.

## Native tools (this extension)

| Tool | Use |
|---|---|
| `modem_gates` | Fast gate bundle first, always. Green = proceed. |
| `modem_chain` | Whole-chain strict trace (legal/link/esmlck/verify) + verdict. |
| `modem_deep` | Deep run at any VA with real callees; honest HW-boundary stops. |
| `modem_disasm` | Ghidra batch disassembly by CATI name (cached after first run). |
| `modem_atquery` | Guarded read-only AT query via live channel. |
| `modem_bpp_replay` | 46-pair eSIM session vs card models (M2/M4 perfect baseline). |

Every tool returns PASS/FAIL with evidence and toasts on clean PASS.

## Gate table (all must hold before device contact)

1. `modem_gates` PASS (engine, spec, sml/nv/rmmi, interp conformance 25/1).
2. Target hypothesis has an emulation proof (trace + verdict in `sim/`).
3. Guard audit: no blocked form in the plan (`modem_atquery` dry-run first).
4. `remain.count` read before AND after (must stay 5).

## Active protocols

- **Foreign SIM (S2):** read-only observation only — props, ESMLCK?, CLCK-status, rejectCause, dmesg EE. Enter nothing. Abort on any prompt.
- **eSIM retry:** fresh matchingID only, verbose LPA + radio log, one attempt per code. Classify via PIR: no-PIR 6A80 on 86[0] = chunking; decoded PIR = policy/trust.
- **D1/D2:** spec-map euiccInfo caps vs IPPv6.1c; small-profile control separates M2-total-cap from M4-no-slots.
- **Escalation:** NO-GO until a primitive chains end-to-end in sim (HW_AES refuted-reachable, JRC bounded 0–442 — see HANDOFF §7).

## Key references (repo)

- `HANDOFF.md` §7 — full state, chains, debts. `PICKUP.md` — cold pickup.
- `sim/hw_target.py` — exact spec (I7200, LE32 ABI, memory map, stubs).
- `sim/chain.py`, `sim/deep_run.py`, `sim/bpp_wire_sim.py` — runners.
- `captures/esim_retry_20260905_130857/` — APDU forensics bundle + NOTES.
