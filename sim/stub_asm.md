# nanoMIPS stub ASM — GAS-canonical source + byte-exact expectations

Scope: byte-exact machine-code stubs the PC emulator may inject
(`sim/emu_engine.py: StubRegistry.materialize`, `sim/hw_target.py: SPEC["stubs"]`).
No hand-encoding: every byte row below names its GAS source; only the
3 Ghidra-verified rows are TRUSTED, everything else is DERIVED and needs
triple-evidence before entering `emu_engine.py`.

Status of this file: research + tables only. No toolchain was downloaded
(C: has ~6.5 GB free; no fetch >500 MB was performed — nothing to report).

## 0. Normative sources (no vendored binutils)

`tools/ghidra-nanomips` vendors only the Ghidra SLEIGH side, not GAS/binutils.
All GAS/opcode facts below come from public docs + upstream patches, cross-checked
against the local SLEIGH (`data/languages/nanomips.sinc`) and the ISA TRM mirror:

- Local SLEIGH (ground truth for Ghidra decodes):
  `tools/ghidra-nanomips/data/languages/nanomips.sinc` (tokens/attach),
  `tools/ghidra-nanomips/data/languages/nanomips.slaspec` (mem map/regs),
  `tools/ghidra-nanomips/data/languages/nanomips.cspec` (a0–a7 args, a0–a1 ret),
  `tools/ghidra-nanomips/data/languages/nanomips.ldefs` (`nanomips:LE:32:default`).
- ISA TRM rev 1.01 mirror (formats/availability/NMS notes):
  `https://jnastarot.io/arch_index/nanomips/nanomips_index.html`
  + per-insn pages `.../main/LI.html`, `JRC.html`, `JALRC.html`, `BALC.html`,
  `MOVE.html`, `MOVEP.html`, `ADDIU.html`, `ADDIUPC.html`, `SBX.html`,
  `LBUX.html`, `SAVE.html`, `RESTORE_RESTORE.JRC.html`, `NOP.html`,
  `SIGRIE.html`, `BREAK.html`.
- GNU opcode definition (replaces `opcodes/nanomips-opc.c` knowledge):
  binutils patch `[PATCH 3/6] Opcodes changes for nanoMIPS support`
  `https://sourceware.org/pipermail/binutils/2026-July/150276.html`
  (excerpts: `{"li","[16]","md,mI",0xd000,0xfc00,...} /* LI[16] */`,
  `{"jalrc","","mp,-i",0xd810,0xfc1f,...} /* JALRC[16] */`,
  `{"jr","","mp",0xd800,0xfc1f,...} /* JRC */`, `restore`/`save` rows).
- GAS front end (replaces `gas/config/tc-nanomips.c` knowledge):
  `[PATCH 1/6] Gas changes for nanoMIPS support`
  `https://sourceware.org/pipermail/binutils/2026-July/150277.html`
  (`config/mt-nanomips`, `tc-nanomips.c/h`, `configure.tgt nanomips*-*-elf`,
  `OPTION_M32 -> P32_ABI`, `OPTION_M64 -> P64_ABI`).
- MediaTek doc index (ABI supplement / porting / programmer's guides live here):
  `https://github.com/MediaTek-Labs/nanomips-docs/blob/main/README.md`
  (`MIPS_nanoMIPS_ABI_supplement_01_03_DN00179.pdf`,
  `MIPS_nanoMIPS_p32_ABI_Porting_Guide_01_02_DN00184.pdf`,
  `MIPS_nanoMIPS_GNU_Toolchain_Programmers_Guide_01_04_DN00180.pdf`,
  `MIPS_nanoMIPS_GNU_Toolchain_Getting_Started_Guide_01_02_DN00183.pdf`).
- QEMU I7200 CPU name: `qemu-system-mipsel -cpu I7200`
  (`https://www.qemu.org/docs/master/system/target-mips.html`).
- Repo spec: `sim/hw_target.py` (I7200, Nucleus, `nanomips:LE:32:default`,
  binutils 2.28 / GCC 6.3.0 / GDB 8.0 / QEMU 2.5.0-MTK, Linux-x64 only),
  `sim/emu_engine.py` (`STUB_RET1/RET0`, `decode_one`, `decode_conformance`,
  `selftest`).

## 1. GAS flag set — I7200-class (p32, LE)

Target triple: `nanomips-mti-elf` (bare-metal) or `nanomips*-*-linux*`.
The modem PCORE is a 32-bit I7200, little-endian, p32 ABI
(`sim/hw_target.py`: `endian=little, bits=32, args a0–a7, ret a0–a1`).

Canonical flags (MediaTek 2025.09-02 toolchain = binutils 2.28 vintage;
same names in the 2026 upstream re-port):

```
nanomips-mti-elf-as -march=32r6 -mabi=p32 -EL stub.s -o stub.o
nanomips-mti-elf-objdump -d -M numeric stub.o      # byte check
nanomips-mti-elf-objcopy -O binary stub.o stub.bin # byte check
```

| Flag | Value for this lab | Why / provenance |
|---|---|---|
| `--target` / triple | `nanomips-mti-elf` (or `nanomipsel-*-elf`) | `gas/configure.tgt`: `nanomips*-*-elf -> fmt=elf`; `nanomips*` defaults LE, `nanomips*eb` BE |
| `-march=` | `32r6` | `gas/configure` + `nanomips-dis.c: nanomips_arch_choices[]`: `32r6` = nanoMIPS32R6 (I7200 is the 32-bit nanoMIPS R6 core, cf. QEMU `-cpu I7200`). `from-abi` resolves to the same once `-mabi=p32` is given. `64r6` is wrong for PCORE (64-bit pointers). `32r6s` is the NMS-subset variant — do NOT use (would reject LI48/MOVEP/SBX, see §3) |
| `-mabi=` | `p32` (aka `-m32`) | `tc-nanomips.c: OPTION_M32 -> P32_ABI`; disassembler `nanomips_abi_choices[] = numeric/p32/p64`. Modem is p32 (`hw_target.py` args/retval, ABI supplement v1.03). `-mabi=p64`/`-m64` is for 64-bit cores only |
| `-EL` | little-endian | Path of least surprise; `nanomips*` (no `eb`) already defaults LE, but pass `-EL` explicitly so a big-endian host default can never flip stub bytes. Ghidra language is `nanomips:LE:32:default`, `define endian=little` |
| `-mno-gpopt` (libs only) | size-optimised libs | `config/mt-nanomips`: `CFLAGS_FOR_TARGET += -Os -mno-gpopt`. Not needed for stub `.s` files |
| ISA extension flags | none (default) | I7200 PCORE run: full nanoMIPS R6 + MT ASE where present. Do not pass an NMS-restrict flag: NMS cores trap on LI48/ADDIU48/MOVEP/SBX (see §3). Our stubs avoid those forms anyway except the documented LI48 example |

Check the assembler understood you:

```
nanomips-mti-elf-as --help | grep -i -A2 'march\|mabi'
# expect: -march=32r6|32r6s|64r6|from-abi  -mabi=p32|p64 (-32/-m32 => p32)
```

Ghidra/QEMU partners for the same spec:

```
Ghidra language: nanomips:LE:32:default   (nanomips.ldefs)
QEMU:            qemu-system-mipsel -cpu I7200 -M malta
```

## 2. Canonical GAS syntax (what to write in `.s` files)

MIPS GAS is `$`-register, `dst last` for 3-operand ops, `offset(base)` for loads/stores.
All mnemonics below are lowercase in GAS source; Ghidra prints uppercase — same insn.
Each entry cites its SLEIGH constructor and ISA page.

```
# --- §2.1 LI: load immediate -------------------------------------------
li $a0,1            # LI[16] if rt in gpr3 and -1 <= imm <= 126 (macro otherwise)
li $a0,0            # same
li $a0,-1           # LI[16] eu=127 special case (NOT +127; +127 is unencodable)
li $a0,0x12345678   # LI[48]: 6-byte form (hi + s[15:0] + s[31:16]); RI on NMS
# SLEIGH nanonips.sinc:1920 `:LI rt3, eu_imm7` / :1911 `eu==127 -> -1` /
#   :1927 `:LI rt, full_simm32` (hi_pool10_6=011000, hi_pool0_5=00000).
# ISA: LI.html: LI[16]=110100|rt3|eu ; LI[48]=011000|rt|00000|s15:0|s31:16.
# OPC: {"li","[16]","md,mI",0xd000,0xfc00}  md=gpr3@bit7, mI=7b@bit0.

# --- §2.2 JRC / JALRC: compact indirect jump ---------------------------
jrc $ra              # return: JRC ra (16-bit). Alias: jr $ra
jrc $a0              # computed goto (no link)
jalrc $a0            # JALRC[16]: dst=ra implied, src=$a0. Aliases: jalr $a0, jalrc $ra,$a0
jalrc $a1,$a2        # JALRC[32]: dst=$a1, src=$a2
# SLEIGH :1655 (JRC ra, rt_raw==31) / :1662 (JRC rt) /
#   :1624 `:JALRC rt,rs` (32b 010010|rt|rs|0000|x) /
#   :1633 `:JALRC ra,rt` (16b 110110|rt|1|0000).
# ISA: JRC.html=110110|rt|0|0000 ; JALRC.html JALRC[32]=010010|rt|rs|0000|x,
#   JALRC[16]=110110|rt|1|0000 (dst=31).
# OPC: {"jr","","mp",0xd800,0xfc1f} = JRC ; {"jalrc","","mp,-i",0xd810,0xfc1f}.

# --- §2.3 BALC: compact branch-and-link ---------------------------------
balc target_label    # GAS picks BALC[16] (001110, ±1K) or BALC[32] (001010:1, ±16M)
                     # via relaxation; $ra = next_pc. Never hand-pick the width.
# SLEIGH :978 `:BALC hi_saddr11` (hi_pool10_6=001110) /
#   :970 `:BALC hilo_saddr26` (001010:1).
# ISA: BALC.html BALC[16]=001110|s9:1|s10 ; BALC[32]=001010|1|s24:1|s25.

# --- §2.4 MOVE / MOVEP --------------------------------------------------
move $a0,$a1         # MOVE (16-bit): 000100|rt|rs, rt!=0. Pseudo-ops welcome.
movep $a0,$a1,$a2,$a3
                     # MOVEP (16-bit, NOT on NMS): 101111|... packed gpr4.zero/
                     # gpr2.reg1/reg2. dst1,dst2,src1,src2 order. No overlap
                     # between {dst} and {src} (else UNPREDICTABLE).
# SLEIGH :2300 `:MOVE rt,rs` (000100, rt_raw!=0) / :2319
#   `:MOVEP rd2_reg1,rd2_reg2,rsz4,rtz4` (101111) + :2327 REV form (111111).
# ISA: MOVE.html=000100|rt|rs ; MOVEP.html full bit-split table.
# OPC gas tests: move.s/move.d cover `move` aliasing.

# --- §2.5 SAVE / RESTORE (reglists) -------------------------------------
save 16              # adjust sp only: SAVE[16] count=0  (== addiu sp,sp,-16)
save 32,$ra,$fp      # SAVE u,reg,...  u = total frame bytes (mult of 16 for [16])
restore 32,$ra,$fp   # RESTORE u,reg,... (jr=0)
restore.jrc 32,$ra,$fp  # RESTORE.JRC (jr=1): restore + return [ra]
jraddiusp 32         # alias for count=0 RESTORE.JRC[16]/[32]
# SLEIGH :2863 `:SAVE hi_uoffset8_sl4^reglist_sv16` (000111:...:0) /
#   :3044 `:SAVE lo_uimm12_sl3^reglist_sv32` (100000:...:0011:...:00) /
#   :2590 `:RESTORE.JRC hi_uoffset8_sl4^reglist_rs16` (000111:...:1) /
#   2773ff `:RESTORE[.JRC] lo_uimm12_sl3^reglist_rs32` (100000:...:0011:...:10/11).
#   reglist text order is fp,ra,s0.. (rt1/rt encodings in sleigh_scripts/).
# ISA: SAVE.html / RESTORE_RESTORE.JRC.html (u in 0..4092, up to 16 consecutive
#   regs, wrap 31->16 allowed, gp-bit form RI on NMS).
# OPC: {"restore","[32]","+N,n",0x80003002,...}, {"restore.jrc","[16]","mG",0x1d00,..}.
# NOTE: operand ORDER (u first vs regs first) differs between ISA text
#   (`SAVE u[, regs]`) and some GAS testsuite samples — always re-check the
#   disassembly; that is exactly what the triple-evidence rule (§5) is for.

# --- §2.6 ADDIU / ADDIUPC -----------------------------------------------
addiu $a0,$a1,100    # ADDIU[32]: 000000|rt|rs|u16. (32-bit, any GPR)
addiu $a0,$a1,-5     # same (u16 field carries two's complement)
addiu $a0,$a0,0x12345678  # ADDIU[48]: 011000|rt|00001|s... (rs==rt; RI on NMS)
addiupc $a0,label    # ADDIUPC[32]: 000001|rt|s20:1|s21 ; rt = next_pc + s + 4
                     # (48-bit form 011000|rt|00011|s... RI on NMS, P64: DADDIUPC)
nop                  # NOP[16] == addiu $0,$0,0 ; NOP[32] == sll $0,$0,0
# SLEIGH :771 ADDIU[32] / :779 ADDIU[48] / :797 ADDIU[GP.B] / :809 ADDIU[GP.W] /
#   :821 ADDIU[R1.SP] / :831 ADDIU[R2] / :842 ADDIU[RS5] (NOP16 when rt=0) /
#   :852 ADDIU[NEG] ; :870 ADDIUPC[32] (`"%pcrel"(addr)`) / :885 ADDIUPC[48].
# ISA: ADDIU.html / ADDIUPC.html (imm = s+4 for [32], s+6 for [48]).
# NOP.html: NOP[32]=100000|00000|x|1100|x|0000|00000, NOP[16]=100100|00000|x|1|x.

# --- §2.7 SBX / LBUX indexed forms ---------------------------------------
lbux $a0,$a1($a2)    # LBUX rd, rs(rt): rd=[rt+rs] zero-extended.  (001000/.../0010/0/000/111)
sbx $a0,$a1($a2)     # SBX  rd, rs(rt): [rt+rs]=rd[7:0].           (001000/.../0001/0/000/111)
lbx $a0,$a1($a2)     # LBX sign-extending twin (..../0000/0/000/111)
# SLEIGH :1760 `:LBUX rd, rt_offset_rs` / :3102 `:SBX rd, rt_offset_rs` /
#   :1769 `:LBX rd, rt_offset_rs`.
# ISA: LBUX.html / SBX.html: 001000|rt|rs|rd|0001|0|000|111 (SBX),
#   001000|rt|rs|rd|0010|0|000|111 (LBUX). SBX is NOT on NMS; LBUX is.
# NOTE the ISA operand names are confusing (`SBX rd, rs(rt)` stores RD, address
#   is RS+RT) — copy the `rd, rs(rt)` order verbatim; do not "fix" it by hand.
```

NMS/availability cheat-sheet (I7200 PCORE is full nanoMIPS, NMS=0, so all rows
assemble — but stubs still avoid the right column to stay portable):

| Form | Full nanoMIPS (I7200) | NMS subset | Stub guidance |
|---|---|---|---|
| LI[16], JRC/JALRC, BALC, MOVE, ADDIU[32]/[R2]/[RS5]/[NEG], ADDIUPC[32], LBUX/LBX, NOP, SIGRIE/BREAK, SAVE/RESTORE[16+32] | yes | yes | preferred |
| LI[48], ADDIU[48]/[GP48], ADDIUPC[48], MOVEP[REV], SBX/SHX/SWX, SAVE-gp | yes | RI (Reserved Instruction) | avoid in stubs; LI48 row kept as reference only |

## 3. Stub encoding table (GAS source -> bytes LE -> status)

`bytes` are little-endian file order (what `objcopy -O binary` must emit and
what `Memory.read` must return). `GAS` column is the exact source line.
`Ghidra` column is the expected disassembly in `nanomips:LE:32:default`.

Engine sizes: every `LI[16];JRC` stub is 4 bytes (2+2). The `LI[48];JRC` form
is 8 bytes (6+2) — `StubRegistry.materialize` today reserves 4 (`find(va,4)`,
`write(va,STUB_*)`); it must grow to 8 before any LI48 stub is admitted.

### 3a. Return-constant stubs (the only stubs the engine injects today)

| # | GAS source | bytes LE | len | Ghidra decode | Status |
|---|---|---|---|---|---|
| R-a0-0 | `li $a0,0` + `jrc $ra` | `00 d2 e0 db` | 4 | `LI a0,0x0` ; `JRC ra` | VERIFIED (hw_target SPEC["stubs"]["ret0"], emu_engine STUB_RET0 + selftest vector `00d2`) |
| R-a0-1 | `li $a0,1` + `jrc $ra` | `01 d2 e0 db` | 4 | `LI a0,0x1` ; `JRC r31`/`JRC ra` | VERIFIED (SPEC["stubs"]["ret1"], STUB_RET1 + selftest vector `01d2`, conformance expects `LI a0,0x1`) |
| R-a1-0 | `li $a1,0` + `jrc $ra` | `80 d2 e0 db` | 4 | `LI a1,0x0` ; `JRC ra` | DERIVED (formula §4, needs triple-evidence) |
| R-a1-1 | `li $a1,1` + `jrc $ra` | `81 d2 e0 db` | 4 | `LI a1,0x1` ; `JRC ra` | DERIVED |
| R-a2-0 | `li $a2,0` + `jrc $ra` | `00 d3 e0 db` | 4 | `LI a2,0x0` ; `JRC ra` | DERIVED |
| R-a2-1 | `li $a2,1` + `jrc $ra` | `01 d3 e0 db` | 4 | `LI a2,0x1` ; `JRC ra` | DERIVED |
| R-a3-0 | `li $a3,0` + `jrc $ra` | `80 d3 e0 db` | 4 | `LI a3,0x0` ; `JRC ra` | DERIVED |
| R-a3-1 | `li $a3,1` + `jrc $ra` | `81 d3 e0 db` | 4 | `LI a3,0x1` ; `JRC ra` | DERIVED |
| R-a0-N | `li $a0,N` + `jrc $ra`, -1 <= N <= 126, N != 0,1 | `NN' d2 e0 db` where `NN' = N & 0x7F` (`-1 -> 7f`) | 4 | `LI a0,N` ; `JRC ra` | DERIVED (examples: N=2 -> `02 d2 e0 db`; N=126 -> `7e d2 e0 db`; N=-1 -> `7f d2 e0 db`. N=+127 UNENCODABLE — assembler must emit LI48 or error) |
| R-a1-N | `li $a1,N` + `jrc $ra` | base `80 d2`, OR low byte with N (`-1 -> ff d2`) | 4 | `LI a1,N` ; `JRC ra` | DERIVED (ex: N=2 -> `82 d2 e0 db`; N=-1 -> `ff d2 e0 db`) |
| R-a2-N | `li $a2,N` + `jrc $ra` | base `00 d3` OR N (N=-1 -> `7f d3`) | 4 | `LI a2,N` ; `JRC ra` | DERIVED |
| R-a3-N | `li $a3,N` + `jrc $ra` | base `80 d3` OR N (N=-1 -> `ff d3`) | 4 | `LI a3,N` ; `JRC ra` | DERIVED |
| R-a0-big | `li $a0,0x12345678` + `jrc $ra` | `80 60 78 56 34 12 e0 db` | 8 | `LI a0,0x12345678` ; `JRC ra` | DERIVED reference only (LI48, RI on NMS, needs 8-byte slot; NOT for injection until materialize grows) |
| J-ra | `jrc $ra` (bare tail, no LI) | `e0 db` | 2 | `JRC ra` | VERIFIED (`jrc_ra` + selftest `e0db` vector) |

GPR3 attach (why the four bases differ) — `nanomips.sinc:261`:

```
attach variables [ rt3 rs3 rd3 rd3_from_rt3 ] [
    s0 s1 s2 s3 a0 a1 a2 a3 ];   # raw 0-7 -> [16,17,18,19,4,5,6,7]
```

Only raw==4 (`a0`) is Ghidra-verified today (`hw_target.SPEC["gpr3_verified"]`,
`emu_engine.RT3_PROVISIONAL`); raw 0–3/5–7 rows above inherit that mapping and
are DERIVED until the conformance corpus grows a second vector per register.

### 3b. Trap / control stubs (engine `trap` policy + alignment padding)

| # | GAS source | bytes LE | len | Ghidra decode | Semantics / status |
|---|---|---|---|---|---|
| T-loop | `1: bc 1b` (i.e. `bc .`) self-branch | `ff 1b` | 2 | `BC .` / `BC inst_start` | DERIVED infinite loop. `BC[16]=000110\|s9:1\|s10`, offset -2 (`s=0x7FE`, imm=0x1FF, sign=1). No link, no register write — safe parking stub for `trap`. Preferred over BALC-loop (which would clobber `$ra` each lap) |
| T-sigrie | `sigrie 0` | `00 00 00 00` | 4 | `SIGRIE 0x0` | DERIVED ebreak-equivalent. `SIGRIE=000000\|00000\|00\|code19` (BREAK-family pool `000000`, sub `00`); operation is unconditional `raise RI`. All-zero word traps instead of sliding — ideal `trap` body and zero-fill guard. Emulator behaviour: halt/fault, never fall through |
| T-break16 | `break 0` | `10 10` | 2 | `BREAK 0x0` | DERIVED alternative trap. `BREAK[16]=000100\|00000\|10\|code3`. Raises BP (breakpoint), not RI — use only when the harness explicitly wants a BP vs RI distinction. 16-bit, handy as 2-byte padding trap |
| T-break32 | `break 0` (forced 32-bit) | `00 00 10 00` — see note | 4 | `BREAK 0x0` | DERIVED. `BREAK[32]=000000\|00000\|10\|code19`: hi=`0000`, lo=`1000`? Exact half order is `hi_pool(000000:00000:10:u3) + u16`; canonical all-zero-code word is `00 00 10 00` LE. GAS picks [16] by default for code 0 — force with `.set micromips`... no: use explicit width only after triple-evidence; table keeps the [16] form as canonical |
| N-nop16 | `nop` (16-bit) | `08 90` | 2 | `NOP` | DERIVED padding. `NOP[16]=100100\|00000\|x\|1\|x`, canonical x=0 -> `0x9008` LE `08 90` (== `addiu $0,$0,0`). Emulator behaviour: no-op, advance PC by 2. Any x!=0 is also NOP in hardware but MUST NOT be generated (reserved for future use per ISA note) |
| N-nop32 | `nop` (32-bit) | `00 80 00 c0` | 4 | `NOP` | DERIVED reference. `NOP[32]=100000\|00000\|x\|1100\|x\|0000\|00000` (== `sll $0,$0,0`), canonical `hi=0x8000 lo=0xC000`. Only for 4-byte alignment fill; prefer NOP16 in stubs |

Do NOT invent: `jrc` with nonzero `hi_pool0_4`, `li` with rt outside gpr3
assembled as 16-bit, `movep` with overlapping dst/src, `save` with unaligned `u`,
`sbx` on an NMS-only build. All of those are RI/UNPREDICTABLE per the ISA pages.

## 4. Bit-layout proofs for the 3 immutable vectors

All multi-byte values are little-endian on the wire; the 16-bit word `w` is
assembled from fields MSB-first, then stored low byte first.

### 4.1 `LI a0,1 = 01 d2`

```
bytes LE 01 d2  ->  w = 0xd201 = 1101 0010 0000 0001
LI[16] = 110100 | rt3 | eu            (ISA LI.html, SLEIGH :1920)
         110100 | 100 | 0000001
         pool=0b110100 (bits15-10)     rt3=0b100=4 (bits9-7)  eu=1 (bits6-0)
gpr3[4] = a0  (attach list s0,s1,s2,s3,a0,a1,a2,a3; raw4->a0 VERIFIED)
s = eu (eu != 127) = 1                -> GPR[a0] = 1
OPC match: ("li","[16]","md,mI",0xd000,0xfc00): w & 0xfc00 == 0xd000 ✓
Ghidra: LI a0,0x1  (emu_engine.decode_conformance expects exactly this string)
```

### 4.2 `LI a0,0 = 00 d2`

```
bytes LE 00 d2  ->  w = 0xd200 = 1101 0010 0000 0000
         110100 | 100 | 0000000       (same pool/rt3, eu=0)
GPR[a0] = 0. Same OPC mask check ✓. Ghidra: LI a0,0x0 ✓
```

### 4.3 `JRC ra = e0 db`

```
bytes LE e0 db  ->  w = 0xdbe0 = 1101 1011 1110 0000
JRC = 110110 | rt | 0 | 0000          (ISA JRC.html, SLEIGH :1655/:1662)
      110110 | 11111 | 0 | 0000
      pool=0b110110 (bits15-10)  rt=31 (bits9-5, = ra)  bit4=0  bits3-0=0000
IGE: rt_raw==31 selects the `return [rt]` constructor (JRC ra); any other rt
uses the plain `goto [rt]` constructor (same bytes, different pcode).
OPC match: ("jr","","mp",0xd800,0xfc1f): w & 0xfc1f = 0xd800 ✓
  (0xdbe0 & 0xfc1f = 0xd800; the mask keeps pool+bit4+low4, varies rt@bit5)
Ghidra: JRC ra (emu_engine prints `JRC r31`; same insn, numeric vs symbolic ABI)
```

Cross-check arithmetic (recompute in Python, compare with `objdump -d`):

```python
def li16(rt3, eu): return (0b110100 << 10) | (rt3 << 7) | (eu & 0x7F)
assert li16(4, 1).to_bytes(2, 'little') == bytes.fromhex('01d2')
assert li16(4, 0).to_bytes(2, 'little') == bytes.fromhex('00d2')
def jrc(rt): return (0b110110 << 10) | (rt << 5)
assert jrc(31).to_bytes(2, 'little') == bytes.fromhex('e0db')
```

Family derivation (used for §3a): keep pool, vary `rt3`:

```
LI a1,1: rt3=5 -> (0x34<<10)|(5<<7)|1 = 0xd281 -> LE 81 d2
LI a2,1: rt3=6 -> 0xd301 -> LE 01 d3     LI a3,1: rt3=7 -> 0xd381 -> LE 81 d3
LI a1,0: 0xd280 -> 80 d2                 LI a2,0: 0xd300 -> 00 d3, etc.
LI a0,-1: eu=127 -> 0xd27f -> 7f d2 (the ONLY way to encode -1 in 16 bits)
```

## 5. Acceptance rule (the interp agent must enforce this)

> Any NEW stub byte-sequence enters `sim/emu_engine.py` (or `sim/hw_target.py`
> `SPEC["stubs"]`) ONLY with a triple-evidence bundle. No bundle, no merge —
> hand-computed bytes are rejected even if they "look right".

Each new stub needs, in the PR/commit message AND as comments above the constant:

1. **GAS source** — the exact `.s` line(s) + flags from §1 and the
   `objdump -d` / `objcopy -O binary | xxd` output proving the bytes.
   Example:
   ```
   $ cat ret_a2.s
       .text; .set noreorder
       li $a2,1
       jrc $ra
   $ nanomips-mti-elf-as -march=32r6 -mabi=p32 -EL ret_a2.s -o ret_a2.o
   $ nanomips-mti-elf-objdump -d ret_a2.o   # LI a2,0x1 ; JRC ra
   $ nanomips-mti-elf-objcopy -O binary ret_a2.o ret_a2.bin && xxd ret_a2.bin
   00000000: 01d3 e0db
   ```
2. **Ghidra decode screenshot-text** — headless or GUI disassembly of the same
   bytes pasted verbatim under `nanomips:LE:32:default`, e.g.
   ```
   90001000 01 d3        LI a2,0x1
   90001002 e0 db        JRC ra
   ```
   plus the listing address, plus cross-check that pool/rt/imm
   fields match §4's layout (quote pool bits, rt3 field, imm field).
3. **Emulator behaviour** — `decode_one` string + single-step effect:
   ```
   decode_one -> "LI a2,0x1" / "JRC r31"; step sets GPR[a2]=1, PC=ra; selftest extended.
   ```
   Conformance rule (already in `emu_engine.py` header): every new encoding needs
   >= 2 ground-truth vectors; `decode_conformance()` must grow, never shrink;
   `selftest` (`STUB_RET1/RET0` materialize + fault cases) must keep passing.

Minimal template for a new constant:

```python
# GAS:  li $a2,1 ; jrc $ra   (-march=32r6 -mabi=p32 -EL)
# OBJDUMP: 01d3 (LI a2,0x1) e0db (JRC ra)  | GHIDRA nanomips:LE:32:default: same
# BEHAVIOUR: decode_one "LI a2,0x1"; step a2<-1, pc<-ra
STUB_RET1_A2 = bytes.fromhex("01d3e0db")  # DERIVED — see sim/stub_asm.md §3a
```

Existing `STUB_RET1/RET0`/`ret1/ret0`/`jrc_ra` are grandfathered (VERIFIED above)
and their `check_spec`/`selftest` asserts MUST NOT be weakened to admit a new stub.

## 6. What was NOT done (explicit non-claims)

- No MediaTek PDFs were downloaded and no toolchain was built: flag/syntax facts
  are from the upstream patch texts + ISA HTML mirror + local SLEIGH, not from
  running `nanomips-mti-elf-as`. The DERIVED rows are arithmetic consequences of
  those published maps, not GAS-observed outputs — hence their status.
- `save`/`restore` operand ORDER, `movep` pair-order constraints, and the 48-bit
  half order (`lo_imm16` then `hi_simm16`) are quoted from ISA/SLEIGH but have not
  been observed through GAS or Ghidra in this session — they are the first
  candidates for triple-evidence.
- QEMU `-cpu I7200` behaviour of SIGRIE-vs-BREAK (RI vs BP) and of `BC .` as a
  parking loop is per ISA operation text; device-side confirmation is out of scope
  for this file (oracle transport lives outside `sim/`, per `emu_engine.HwOracle`).
