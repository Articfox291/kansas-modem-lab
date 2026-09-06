# QEMU as exact-spec execution backend — MT6835 nanoMIPS-I7200 modem (Kansas lab)

Date: 2026-09-05. Target spec: `sim/hw_target.py` (I7200 LE, VA 0x90000000, Nucleus, no FPU).
Constraints honoured: nothing downloaded, device untouched, this file under `sim/` only.
C: free at check time: **6,484,520,960 B (~6.04 GiB)**. Single drive (C: only).
WSL 2.5.10 present, **zero distros installed**.

## 1. VERDICT (feasibility)

**CONDITIONAL GO — do not install to C: as-is.** Ranked backend order:

1. **(c) GDBsim (`nanomips-elf-run`) under WSL2 — FIRST.** Cheapest exact-ISA executor.
   Bare-metal ELF, entry from ELF header, no board/MMU to fight, UHI semihosting
   (`mti32.ld`/`uhi32.ld`). Ideal for the SML function harness (carve 0x5E B @
   0x905DF2FA + stub BALC targets, exactly as the Ghidra EmulatorHelper proof did).
2. **(b) MTK-fork QEMU under WSL2 — SECOND.** Only QEMU with the 2024/2025 DSP/emulation
   fixes our modem code can actually hit (MTHLIP ac1–3, BPOSGE32C ∓offsets, SCWP crash,
   ADDSC carry). Upstream lacks these (see §3).
3. **(a) Upstream QEMU Windows build — THIRD.** Zero-Linux smoke test only
   (`-cpu I7200` decode check). Board/VA mismatch makes it the *least* exact for
   modem bytes despite being cheapest to install.
4. **(d) Ghidra pcode + Python interp (`sim/emu_engine.py`) — KEEP AS BASELINE.**
   Already working, zero bytes, zero risk. QEMU/GDBsim results must conform to it,
   not replace it until they beat its stock-vs-patch differential (25-step stock
   HIT-RET a0=0 vs 1-step patch HIT-RET a0=1).

Why not (a) first: `-M malta` maps RAM at `0x0` (Linux `mem=256m@0x0`); our modem runs
at `0x90000000` (45.8 MB carveout, AP-phys 0xD0000000). The generic loader *can* place
bytes at 0x90000000, but whether Malta's memory map accepts that address vs needing
`-M none` (+ manual RAM) is a 1-command local check, not something to assume.
The MTK fork exists precisely because upstream's generic I7200 + Malta is not a modem.

## 2. UPSTREAM QEMU STATUS (verified today via web)

- nanoMIPS support is **in upstream master TODAY** (merged Aug 2018, i.e. every modern
  release since ~3.0). Sources checked: `qemu.org/docs/master/system/target-mips.html`,
  `github.com/qemu/qemu/blob/master/docs/system/target-mips.rst`, readthedocs v7.2/v8.1.
- **Binary:** `qemu-system-mipsel` (LE). There is no `qemu-system-nanomips`.
- **Only nanoMIPS `-cpu` value:** `I7200` ("MIPS I7200 (nanoMIPS, 2018)"). No R6/generic-
  nanoMIPS variant exists. Preferred-CPU table: `nanoMIPS → I7200`.
- **Only documented `-M`:** `malta`. Reference (Linux) recipe, verbatim from docs:
  `qemu-system-mipsel -cpu I7200 -kernel <kernel> -M malta -serial stdio -m <mem>
  -drive file=<disk>,format=raw -append "mem=256m@0x0 rw console=ttyS0 …"`.
  Kernel/disk URLs in docs are dead MIPS-distros links (2018) — irrelevant to us
  (bare-metal harness doesn't use them).
- **Windows builds:** qemu.org hosts **no binaries**; it links Stefan Weil
  (`qemu.weilnetz.de/w64/`, now `qemu.eu/w64/`) + MSYS2
  (`mingw-w64-ucrt-x86_64-qemu`). Weil builds track **master**, so `qemu-system-mipsel`
  with `-cpu I7200` is included in every 2025/2026 installer (verified build history;
  nanoMIPS predates all of them by 7 years). Confirm locally after install:
  `qemu-system-mipsel -cpu help | findstr I7200`.
- **qemu-user (linux-user): YES ISA support, NO-GO for modem bytes.** The 2018 series
  explicitly added it (`linux-user/nanomips/cpu_loop`, `EM_NANOMIPS` in elfload,
  `qemu-mipsel` user config). Current docs still list `qemu-mipsel` (LE O32 ABI).
  But linux-user does **Linux syscall translation** — our blob is a Nucleus RTOS
  bare-metal image at a fixed VA with no syscalls. Useful only for toolchain-built
  Linux test ELFs, never for `md1work_romonly.bin` slices.

## 3. MEDIATEK FORK (verified from release pages)

Release: `nanoMIPS-2025.09-02`, published 2025-11-18 (latest), repo
`github.com/MediaTek-Labs/nanomips-gnu-toolchain`.

- **Base versions (all releases):** binutils 2.28, GCC 6.3.0, newlib 2.5.0, **GDB 8.0
  (+GDBsim `nanomips-elf-run`)**, **QEMU 2.5.0-MTK**, gold 2.30, smallClib internal,
  Python 2.7.16. (Yes: a 2015 QEMU + 2016 GCC with MTK nanoMIPS backports.)
- **2024/2025 emulation fixes (the reason to prefer the fork):**
  - 2025.09-02: QEMU MTHLIP for accumulators $ac1–$ac3; QEMU BPOSGE32C with -ve offsets;
    gold crash on same-named section groups; DSP-prepend→EXTW mapping (TRM v0.04 typo).
  - 2025.04-01: linker BPOSGE32C relaxation crash; **GDBsim SCWP crash fix**.
  - 2024.11-02: gold BPOSGE32C >+16 kB trampoline; GDBsim ADDSC→ADDWC carry-bit fix;
    assembler DSP-prepend encoding fix. Known issue: assembler relocation-minimisation
    pass disabled by default (keep disabled).
  - 2025.01-03: default linker scripts `mti32.ld` + `uhi32.ld` work with LLD or GOLD.
- **CPU models the fork defines: PROVISIONAL.** Release notes never enumerate `-cpu`
  names. Expect `I7200` (same name as upstream) but verify after install:
  `qemu-system-mipsel -cpu help` (fork) and compare `target-mips/cpu.c` in
  `qemu-*-src.tgz` vs upstream. Recorded as open question Q4 in `hw_target.py`.
- **GDBsim as lighter alternative: GO for harness.** `nanomips-elf-run <elf>` runs a
  statically-linked bare-metal ELF directly (program headers define load addresses,
  entry point from ELF header — no `-M`, no BIOS, no MMU). Ship a harness ELF linked
  at the modem VA (linker script `ORIGIN 0x90000000` + `INCBIN` of the carved slice,
  or copy slice into `.text.modem`), with `_start` setting `sp`, calling the SML fn,
  then UHI `exit`/`write` for the verdict. GDB `sim` target (`nanomips-elf-gdb` +
  `target sim`) gives breakpoints/single-step without any QEMU board. Full CLI flags
  (`--help`, supported syscalls) are PROVISIONAL until the toolchain lands — check
  `nanomips-elf-run --help` on first run.
- **Windows build? NO — Linux-only, strictly.** Prebuilt variant is named
  `nanomips-elf_x86_64-pc-linux-gnu` ("Linux x64" only, no mingw/w64 asset in any
  release). Sources *could* be attempted under MSYS2/mingw64, but: QEMU 2.5.0-era code
  + Python 2.7.16 + GDB 8.0 sim against a modern mingw64 is untested, undocumented,
  and high-effort. **Plan: WSL2 only. Do not burn C: space on a mingw attempt.**
  (Closes hw_target.py Q5's platform half; the `-march`/ABI byte-exact half still
  needs the toolchain: `nanomips-elf-gcc -march=? -mabi=?` reproducing
  `01 d2 e0 db` for `LI a0,1; JRC ra`.)

## 4. WSL2 COST — GO/NO-GO WITH NUMBERS

Measured/ documented inputs (no downloads performed):

| Item | Size | Provenance |
|---|---|---|
| C: free **now** | **6.48 GB** (6,484,520,960 B) | `Get-PSDrive` this session |
| WSL feature + kernel | ~100–200 MB | SuperUser measured (kernel pkg 16 MB dl, ~73 MB installed) |
| Ubuntu `.wsl` installer (24.04) | **~400 MB** | releases.ubuntu.com 24.04 file (BestHub guide 2026) |
| Ubuntu vhdx fresh → after upgrade | **1.5–1.6 GB → ~2.7 GB** | measured 20.04/22.04 (NotTheDr01ds); 24.04 same class |
| MTK prebuilt toolchain `.tgz` | **183 MB** | release page (see §6 checksums) |
| Toolchain extracted + deps + build tree | **~2–4 GB est.** (tgz ×3–4 + gcc/make/ncurses/dev libs + qemu build artifacts) | estimate, mark PROVISIONAL until `du` after install |
| **Total new footprint (WSL2 path)** | **~4.5–7 GB** | sum above |
| Upstream Windows QEMU installer | **172–179 MB** (2025 builds, e.g. 20250826 = 172 MB) | `qemu.eu/w64/2025/` listing; `.sha512` alongside |

**NO-GO for default install to C:.** 6.48 GB free minus a 4.5–7 GB WSL2 path leaves
~0–2 GB — below any safe floor on a system drive, and vhdx is grow-only (never shrinks
without manual `compact`). **GO iff one of:**

- (i) free ≥4 GB on C: first (Disk Cleanup / move a big zip; ask user — Downloads zips
  are explicitly hands-off per HANDOFF §6), **or**
- (ii) install the distro with `--location` onto a non-C volume (none present — would
  need new storage), **or**
- (iii) minimal path: WSL2 + Ubuntu minimal + **prebuilt toolchain only + GDBsim only**
  (skip full QEMU build; skip `packages-*.src.tgz` 192 MB + `gcc-*.src.tgz` 119 MB),
  then `wsl --manage <distro> --compact` / `diskpart compact vdisk` after setup.

Nothing on the shopping list exceeds the **500 MB single-file cap** (largest single
file is the ~400 MB Ubuntu `.wsl`), so no single download needs pre-approval — but the
**aggregate** does not fit, hence this report-first NO-GO-by-default.

## 5. DECISION MATRIX (exactness-to-I7200 vs cost)

| Opt | Backend | Exactness | Cost (disk / effort) | Verdict |
|---|---|---|---|---|
| (c) | **GDBsim under WSL2** | HIGH — same ISA front-end as fork QEMU incl. SCWP/ADDSC fixes; no board to mismatch; VA comes from ELF | LOW — prebuilt 183 MB only, no QEMU build | **DO FIRST** |
| (b) | **MTK-fork QEMU under WSL2** | HIGHEST — MTHLIP/BPOSGE32C/DSP fixes upstream lacks; still needs custom-machine/loader work for 0x90000000 | MED — 90 MB src + build deps + build tree (~1–2 GB transient) | **DO SECOND** |
| (a) | **Upstream QEMU Windows build** | MED — real I7200 TCG decode, but generic CPU (no MTK DSP fixes), Malta board ≠ modem SoC, VA mapping TBD | LOWEST — ~174 MB installer, native, no WSL | **SMOKE TEST ONLY** |
| (d) | **Ghidra pcode + `sim/emu_engine.py`** | BASELINE (already-proven differentials) — not cycle-exact HW | ZERO | **KEEP; conformance oracle for (a–c)** |

Conformance gate (any backend passes iff it reproduces, at minimum):
`decode_conformance()` vectors (`01 d2`→`LI a0,0x1`, `e0 db`→`JRC r31`),
stock 25-step HIT-RET a0=0x0 vs patched 1-step HIT-RET a0=0x1 on
`custom_check_link_sml_legal_sim_rule` [0x905df2fa,0x905df358).

## 6. EXACT COMMAND RECIPE (bare-metal I7200 harness — modem bytes loading)

Conventions: `%QEMU%` = install dir (`C:\Program Files\qemu\` or MSYS2 mingw64);
`harness.elf` = toolchain-linked harness (see build step); `slice.bin` = raw carve
from `md1work_romonly.bin` (`off = VA − 0x90000000`); all addresses hex with `0x`.

### 6.0 One-time verify (after any QEMU lands; no modem bytes needed)

```powershell
& "$env:ProgramFiles\qemu\qemu-system-mipsel.exe" -cpu help | Select-String I7200
& "$env:ProgramFiles\qemu\qemu-system-mipsel.exe" -M help
# EXPECT: a line "I7200 … (nanoMIPS, 2018)"; machine list incl. "malta" and (modern QEMU) "none".
# WSL2/fork equivalents: qemu-system-mipsel -cpu help ; qemu-system-mipsel -M help
```

### 6.1 Recommended harness load (THREE ways, preferred first)

**Way 1 — ELF via generic loader (works upstream AND fork, no `-kernel` abuse):**

```powershell
& "$env:ProgramFiles\qemu\qemu-system-mipsel.exe" `
  -cpu I7200 -M none -m 256 -nographic -no-reboot `
  -device loader,file=harness.elf,cpu-num=0 `
  -s -S -d in_asm,cpu -D qemu_harness.log
# then in another shell: nanomips-elf-gdb harness.elf -ex "target remote :1234"
# (gdb) break *0x905DF2FA ; continue ; info registers a0 ; quit
# FALLBACK if "-M none" missing on this target: replace "-M none" with "-M malta".
#   Malta RAM lives at 0x0 — the loader still places ELF segments at their linked
#   addresses, but if 0x90000000 faults, that PROVES the need for -M none / fork
#   machine. Record result; do not force it.
```

**Way 2 — raw slice + explicit PC (no ELF tooling at all):**

```powershell
& "$env:ProgramFiles\qemu\qemu-system-mipsel.exe" `
  -cpu I7200 -M none -m 256 -nographic -no-reboot `
  -device loader,file=slice.bin,addr=0x905DF2FA,force-raw=on,cpu-num=0 `
  -device loader,addr=0x905DF2FA,cpu-num=0 `
  -s -S -d in_asm,cpu -D qemu_raw.log
# slice.bin for the proven fn: 0x5E bytes from md1work_romonly.bin @ off 0x5DF2FA.
# cpu-num=0 both loads into CPU 0's AS and sets PC — generic-loader documented
# behaviour (qemu.org/docs/master/system/generic-loader.html).
```

**Way 3 — gdb `load` (when the board refuses your address but gdbstub works):**

```text
(gdb) target remote :1234
(gdb) load harness.elf        # or: restore slice.bin binary 0x905DF2FA
(gdb) set $pc = 0x905DF2FA
(gdb) break *0x905DF358       # fn end / HIT-RET
(gdb) continue
```

`-kernel` is deliberately NOT the load path here: on Malta `-kernel` means "Linux
kernel in Malta RAM at 0x0" — wrong address, wrong format contract for a Nucleus
blob. `-kernel raw` would also fight the Malta bootloader. Use loader/gdb.

### 6.2 Building `harness.elf` (needs WSL2 + prebuilt toolchain; Way 2 needs none)

```bash
# in WSL2, after extracting the §6 tarball to /opt/nanomips:
/opt/nanomips/bin/nanomips-elf-gcc -c harness.c -o harness.o   # _start: set sp, call sml_fn, UHI exit
/opt/nanomips/bin/nanomips-elf-ld -T harness.ld harness.o slice.o -o harness.elf
# harness.ld: MEMORY { RAM (rwx) : ORIGIN = 0x90000000, LENGTH = 64M }
#   .text.modem 0x905DF2FA : { slice.o(.data) }  (or INCBIN slice.bin)
#   ENTRY(_start); confirm: nanomips-elf-readelf -h -l harness.elf
# GAS byte-exact check (closes hw_target.py Q5):
/opt/nanomips/bin/nanomips-elf-as -march=i7200 -o t.o t.s   # flags PROVISIONAL until --help
/opt/nanomips/bin/nanomips-elf-objdump -d t.o               # expect 01 d2 e0 db for LI a0,1;JRC ra
```

### 6.3 GDBsim fast path (no QEMU at all)

```bash
/opt/nanomips/bin/nanomips-elf-run ./harness.elf ; echo "exit=$? a0-verdict via UHI write"
/opt/nanomips/bin/nanomips-elf-gdb ./harness.elf -ex "target sim" -ex "load" \
  -ex "break *0x905DF2FA" -ex run -ex "info registers a0"
```

### 6.4 What modem bytes go where (load map)

| Region | VA | Content | How |
|---|---|---|---|
| ROM mirror | 0x90000000 + full 45,893,712 B (or per-fn slice) | `md1work_romonly.bin` | loader raw @0x90000000 or ELF segments |
| Fn under test | 0x905DF2FA, 0x5E B | `legal_sim_rule` stock vs `01 d2 e0 db` patch | slice.bin (Way 2) or `.text.modem` (Way 1) |
| Stack/ctx | 0xA0000000 / 0xB0000000, 64 KiB each (mirror `emu_engine.py`) | zeroed harness RAM | linker script / second loader raw |
| BALC stubs | auto per-target pages | `ret1`/`ret0` 4 B | harness code + `StubRegistry.materialize` equivalent |

## 7. WHAT TO DOWNLOAD (sizes + URLs + checksums — nothing fetched yet)

**MTK toolchain 2025.09-02** (base `…/releases/download/nanoMIPS-2025.09-02/`):

| File | Size | md5 | sha256 |
|---|---|---|---|
| `MediaTek.GNU.Tools.2025.09-02.nanomips-elf_x86_64-pc-linux-gnu.tgz` (prebuilt, Linux x64 — TAKE THIS) | 183 MB | `40c9b5b50b1037440c73857c8fa4b470` | `6664aa9812afe5872132844e2dae625a3c6a28d0dc37d184020a1e70cedb0d38` |
| `qemu-2025.09-02.src.tgz` (fork QEMU 2.5.0-MTK — step 2 only) | 90 MB | `328581484749c7dd2c70ad70bed0fd81` | `d82e891dd2237a44c0cc557bb5dcbcc49dcfe69039c072c6d7c8d9d6dab19a16` |
| `gdb-2025.09-02.src.tgz` (GDB 8.0+GDBsim src — only if prebuilt sim misbehaves) | 51 MB | `8f0539ff6af6443e4fd6810023081cac` | `72c0176464037c9ea07594e8f2f43a01084763b3d8ab586eb273e3e37815e742` |
| `binutils-2025.09-02.src.tgz` | 51 MB | `12cdb0b6dfc62ecd34193e8abff555f8` | `c550fd88e9cd7b44187e4cda0c599c83f7eeeeedf183ffada5d318f536bac8e1` |
| `gcc-2025.09-02.src.tgz` (SKIP unless rebuilding toolchain) | 119 MB | `c9486540af9fb692ef58d0c5d00da3e0` | `f125770a59da69f1f32849a6f5587293e3b364d3ba97a0daa123b09356b580d2` |
| `packages-2025.09-02.src.tgz` (SKIP) | 192 MB | `4975afdee39c3dbd5dfa77fe817a9398` | `625469d7a13434f99fed00024c3def7e1579cab57a2ed792812d74b11f3c53ff` |

Full URLs: `https://github.com/MediaTek-Labs/nanomips-gnu-toolchain/releases/download/nanoMIPS-2025.09-02/<filename>`
(minimal path = prebuilt 183 MB + optionally qemu-src 90 MB = **273 MB total**, all
<500 MB cap; GDBsim ships IN the prebuilt, no separate download).

**Upstream QEMU for Windows (smoke test only):**
`https://www.qemu.eu/w64/2025/qemu-w64-setup-20250826.exe` (172 MB, `.sha512`
alongside — verify at download time) or latest in `https://www.qemu.eu/w64/2025/`
(Dec-2025 builds ~174 MB). Alternate: MSYS2 `pacman -S mingw-w64-ucrt-x86_64-qemu`.
Latest upstream release context: 11.1.1 (2026-08-26) per qemu.org.

**WSL2 distro (if §4 gate passes):**
`https://releases.ubuntu.com/24.04/ubuntu-24.04-wsl-amd64.wsl` (~400 MB) +
`wsl --install --from-file <file> --location <non-C path>` (WSL ≥2.4; box has 2.5.10).
Online alternative: `wsl --install -d Ubuntu-24.04 --location <path>`.

## 8. OPEN QUESTIONS → hw_target.py MAPPING (close with evidence after install)

- Q4 (`-cpu` match): fork `-cpu help` output vs upstream `I7200`; any section/MT/DSP
  flags the modem needs. Closes via §6.0.
- `-M` match: does `-M none` exist on `qemu-system-mipsel` (both builds)? Does Malta
  accept a 0x90000000 loader mapping? Closes via §6.1 Way 1/2 fault-or-boot.
- Q1 (I7200 vs NCC sleigh gaps): any insn the modem uses that QEMU/GDBsim reject
  (log `unknownAddress`/RI faults; cross-check NCC listing). DSP ASE hits expected —
  that is exactly what the fork fixes cover.
- Q2 (CP0 touched): hook C0 range; TCG `XORI ra,a0,0x2d` RA-mangle note in
  `sml_crrst_Check` must survive emulation.
- Q3/Q5 (p32 ABI + GAS flags): `-march`/`-mabi` reproducing `ret1`/`ret0` byte-exact
  (§6.2); caller-saved set beyond cspec unaffected list.

## 9. NEXT ACTIONS (ordered, gated)

1. User decision on §4 gate (free space or external volume). **No download until then.**
2. (a)-smoke: install Windows QEMU (~174 MB), run §6.0, record `-cpu`/`-M` lists.
3. WSL2 + Ubuntu (§4 opts) → prebuilt toolchain → `nanomips-elf-run --help` +
   §6.3 on a 4-byte `ret1` ELF → then full-fn harness → conformance gate (§5).
4. Only then: build fork QEMU from `qemu-*-src.tgz`, rerun harness, diff vs GDBsim
   on DSP-heavy fns (`sml_op07_Check` 217 insn, `sml_crrst_Check` 94 insn).
5. Feed results back into `hw_target.py` open_questions + `emu_engine.py` CONFORMANCE.
