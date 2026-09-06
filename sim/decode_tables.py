#!/usr/bin/env python3
"""decode_tables.py — COMPLETE nanoMIPS decode tables harvested from the Ghidra
language definition (NCC ghidra-nanomips), plus a corpus verifier.

Sources (all local, read-only):
  SINC = tools/ghidra-nanomips/data/languages/nanomips.sinc (3945 lines)
  MT   = tools/ghidra-nanomips/data/languages/nanomips_mt.sinc (71 lines)
  SPEC = tools/ghidra-nanomips/data/languages/nanomips.slaspec (107 lines)
Corpus (ground truth, Nmdis2 disassembly of real modem functions):
  DIR  = <temp>\\fn_*.log (12 files)
       + fn_*.bin companions (raw bytes; log holds addr+text only)

Contents:
  GPRxx ......... register attach tables (raw->name) with provenance
  POOL16 ........ every 16-bit major pool (hi_pool10_6, SINC token instrhi
                  bits 15..10) with resident mnemonics + sinc line numbers
  POOL32 ........ 32-bit forms keyed by (hi_pool10_6, lo discriminator)
  POOL48 ........ 48-bit forms keyed by hi_pool0_5 (pool 0b011000 only)
  ASE_MT / ASE_VPE  DSP/MT/VPE scope flags + per-function verdict
  BRANCH_MATH ... branch/PC-relative formulas (bit positions + worked examples)
  decode_bytes .. machine decoder: (addr, raw bytes) -> Ghidra-identical text
  verify_corpus . cross-checks every corpus line (addr bytes -> text)

Rules: stdlib only. Read sim/hw_target.py + sim/emu_engine.py for consumers.
Provenance tags look like [sinc:261] = file:line (1-based).
"""
from __future__ import annotations

import re
from pathlib import Path
import os

# ---------------------------------------------------------------- provenance
REPO = Path(__file__).resolve().parents[1]
SINC = REPO / "tools" / "ghidra-nanomips" / "data" / "languages" / "nanomips.sinc"
MT_SINC = REPO / "tools" / "ghidra-nanomips" / "data" / "languages" / "nanomips_mt.sinc"
SLASPEC = REPO / "tools" / "ghidra-nanomips" / "data" / "languages" / "nanomips.slaspec"
CORPUS_DIR = Path(os.environ.get("MODEM_LAB_CORPUS",
                           str(Path(__file__).resolve().parent / "Temp")))

CORPUS_FILES = (
    "fn_custom_link_sml_with_rule",
    "fn_legal_sim_rule",
    "fn_mot_sml_catkey_verify",
    "fn_rmmi_esmlck_hdlr",
    "fn_rmmi_esmlgen_hdlr",
    "fn_rmmi_esmlrsu_hdlr",
    "fn_sml_catkey_verify",
    "fn_sml_crrst_Check",
    "fn_sml_is_tfn_otp_on",
    "fn_sml_op07_Check",
    "fn_sml_Unlock",
    "fn_sml_Verify",
)


class UnknownInsn(Exception):
    """Raised when bytes match no harvested table entry."""


# ---------------------------------------------------------------- registers
# Full 5-bit GPR file. Order/names from the register block [slaspec:12-25]:
#   [zero at t4 t5 a0-a7 t0-t3 s0-s7 t8 t9 k0 k1 gp sp fp ra pc]
GPR = [
    "zero", "at", "t4", "t5",             # 0-3
    "a0", "a1", "a2", "a3",               # 4-7
    "a4", "a5", "a6", "a7",               # 8-11
    "t0", "t1", "t2", "t3",               # 12-15
    "s0", "s1", "s2", "s3",               # 16-19
    "s4", "s5", "s6", "s7",               # 20-23
    "t8", "t9", "k0", "k1",               # 24-27
    "gp", "sp", "fp", "ra",               # 28-31
]
# Raw MIPS regnos behind the compressed tables (comments in sinc):
GPR3_RAW = [16, 17, 18, 19, 4, 5, 6, 7]            # [sinc:260]
GPR4_RAW_LO = [8, 9, 10, 11, 4, 5, 6, 7]           # [sinc:273]
GPR4_RAW_HI = [16, 17, 18, 19, 20, 21, 22, 23]     # [sinc:273]

# gpr1: single-bit SAVE/JRC selector [sinc:237-240]
GPR1 = ["a0", "a1"]                                # rd1 = (8,8)
# gpr2 destinatario halves. The 2-bit code is (rd2_msb << 1) | bit8 where
# rd2_msb = instrhi bit 3 [sinc:56] and the low bit is instrhi bit 8
# [sinc:52-55]; reg1 and reg2 share the physical bits but use different
# name tables [sinc:242-258].
GPR2_REG1 = [["a0", "a1"], ["a2", "a3"]]            # [sinc:243-249]
GPR2_REG2 = [["a1", "a2"], ["a3", "a4"]]            # [sinc:252-258]
# gpr3: 3-bit compressed regs, rt3/rs3/rd3 = bits (7,9)/(4,6)/(1,3)
# [sinc:59-68]. VERIFIED: raw4 -> a0 (MOVE s1,a0 bytes 24 12).
GPR3 = ["s0", "s1", "s2", "s3", "a0", "a1", "a2", "a3"]   # [sinc:261-264]
GPR3_VERIFIED = {0: "s0", 1: "s1", 2: "s2", 3: "s3",      # corpus: SAVE/
                 4: "a0", 5: "a1", 6: "a2", 7: "a3"}      # MOVEP/LI/BEQZC/...
# gpr3.src.store: raw0 names zero (SB-16 "SB zero,...") [sinc:266-270]
GPR3_ZERO = ["zero", "s1", "s2", "s3", "a0", "a1", "a2", "a3"]
# gpr4: 4-bit = msb select + 3-bit index. msb: rt4_msb=(9,9),
# rs4_msb=(4,4) [sinc:79-88]; index rt4_msb0=(5,7), rs4_msb0=(0,2).
GPR4_LO = ["a4", "a5", "a6", "a7", "a0", "a1", "a2", "a3"]  # [sinc:276-279]
GPR4_HI = ["s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7"]  # [sinc:281-284]
# gpr4.zero: raw index 3 of the LO half names zero (MOVEP "zero",
# rtz4_msb0_raw = 3) [sinc:286-296 + sub-constructors sinc:428/432]
GPR4Z_LO = ["a4", "a5", "a6", "zero", "a0", "a1", "a2", "a3"]  # [sinc:288-291]
GPR4Z_HI = ["s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7"]    # [sinc:293-296]
# count3/shift3 raw->value (SLL-16 "SLL a3,a3,0x8" raw==0 -> 8) [sinc:334]
SHIFT3 = [8, 1, 2, 3, 4, 5, 6, 7]
# eu_imm4 raw->value (ANDI-16 "ANDI s2,s0,0xff" raw==12 -> 0xff) [sinc:336]
EUIMM4 = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x00FF, 0xFFFF, 14, 15]

ATTACHES = {
    # name -> (raw->display, provenance, verified-against-corpus?)
    "FULL-5bit": (dict(enumerate(GPR)), "[slaspec:12-25]", True),
    "gpr1-rd1": ({0: "a0", 1: "a1"}, "[sinc:238-240]", True),
    "gpr2-reg1": ({0: "a0", 1: "a1", 2: "a2", 3: "a3"}, "[sinc:243-249]", True),
    "gpr2-reg2": ({0: "a1", 1: "a2", 2: "a3", 3: "a4"}, "[sinc:252-258]", True),
    "gpr3": (dict(enumerate(GPR3)), "[sinc:261-264] raw [16,17,18,19,4,5,6,7]", True),
    "gpr3-zero": (dict(enumerate(GPR3_ZERO)), "[sinc:267-270]", True),
    "gpr4-lo": (dict(enumerate(GPR4_LO)), "[sinc:276-279]", True),
    "gpr4-hi": (dict(enumerate(GPR4_HI)), "[sinc:281-284]", True),
    "gpr4z-lo": (dict(enumerate(GPR4Z_LO)), "[sinc:288-291]", True),
    "gpr4z-hi": (dict(enumerate(GPR4Z_HI)), "[sinc:293-296]", True),
    "shift3": (dict(enumerate(SHIFT3)), "[sinc:334]", True),
    "eu_imm4": (dict(enumerate(EUIMM4)), "[sinc:336]", True),
}


def gpr4(msb: int, idx: int, zero: bool = False) -> str:
    """4-bit compressed register (MOVEP/MOVE.BALC/ADDU-gpr4/...)."""
    if zero:
        return (GPR4Z_HI if msb else GPR4Z_LO)[idx]
    return (GPR4_HI if msb else GPR4_LO)[idx]


# ---------------------------------------------------------------- pool inventory
# 16-bit major pools: hi_pool10_6 = instrhi bits (10,15) [sinc:5].
# value -> [(mnemonic, sinc line, note)]. "UNASSIGNED" pools have no
# constructor at all in the NCC language definition. Harvested from a full
# parse of all 245 ':' constructors in nanomips.sinc.
POOL16: dict[int, list[tuple[str, int, str]]] = {
    0b000000: [("ADDIU(32)", 771, "rt,rs,uimm16"),
               ("BREAK(32)", 1256, "rt_raw==0"),
               ("SDBBP(32)", 3206, "rt_raw==0"),
               ("SIGRIE(32)", 3314, "rt_raw==0"),
               ("SYSCALL(32)", 3754, "rt_raw==0")],
    0b000001: [("ADDIUPC(32)", 870, "rt,%pcrel(addr)")],
    0b000010: [("MOVE.BALC(32)", 2308, "rd1,rtz4,hilo_saddr22")],
    0b000011: [],
    0b000100: [("BREAK(16)", 1269, "rt_raw==0"),
               ("MOVE", 2300, "rt_raw!=0"),
               ("SDBBP(16)", 3215, "rt_raw==0"),
               ("SYSCALL(16)", 3765, "rt_raw==0")],
    0b000101: [("LW(16)", 2042, "rt3,hi_rs3_uoffset6")],
    0b000110: [("BC(16)", 1032, "hi_saddr11")],
    0b000111: [("RESTORE.JRC(16)", 2590, "bit8==1"),
               ("SAVE(16)", 2863, "bit8==0")],
    0b001000: [("ADD", 760, "lo3_7=0100010"), ("ADDU", 900, "lo3_7=0101010"),
               ("AND", 936, "lo3_7=1001010"), ("CLO", 1331, "lo9_7=0100101"),
               ("CLZ", 1341, "lo9_7=0101101"), ("CRC32B", 1350, "lo10_3=000"),
               ("CRC32CB", 1359, "lo10_3=100"), ("CRC32CH", 1368, "lo10_3=101"),
               ("CRC32CW", 1377, "lo10_3=110"), ("CRC32H", 1386, "lo10_3=001"),
               ("CRC32W", 1395, "lo10_3=010"), ("DERET", 1404, "priv"),
               ("DI", 1424, "priv"), ("DIV", 1435, "lo3_7=0100011"),
               ("DIVU", 1445, "lo3_7=0110011"),
               ("DVP", 1454, "VPE"), ("EI", 1475, "priv"),
               ("ERET", 1485, "priv"), ("ERETNC", 1520, "priv"),
               ("EVP", 1554, "VPE"), ("EXTW", 1580, "lo3_3=011"),
               ("GINVI", 1590, "priv"), ("GINVT", 1599, "priv"),
               ("LBUX", 1760, "lo7_4=0010"), ("LBX", 1769, "lo7_4=0000"),
               ("LHUX", 1874, "lo7_4=0110,bit6=0"),
               ("LHUXS", 1883, "lo7_4=0110,bit6=1"),
               ("LHX", 1892, "lo7_4=0100,bit6=0"),
               ("LHXS", 1901, "lo7_4=0100,bit6=1"),
               ("LSA", 2012, "lo3_3=001"), ("LWX", 2235, "lo7_4=1000,bit6=0"),
               ("LWXS", 2245, "lo7_4=1000,bit6=1"),
               ("MFC0", 2261, "lo3_7=0000110"), ("MFHC0", 2271, "lo3_7=0000111"),
               ("MOD", 2282, "lo3_7=0101011"), ("MODU", 2291, "lo3_7=0111011"),
               ("MOVN", 2336, "lo3_7=1000010,bit10=1"),
               ("MOVZ", 2347, "lo3_7=1000010,bit10=0"),
               ("MTC0", 2358, "lo3_7=0001110"), ("MTHC0", 2368, "lo3_7=0001111"),
               ("MUH", 2378, "lo3_7=0001011"), ("MUHU", 2388, "lo3_7=0011011"),
               ("MUL", 2399, "lo3_7=0000011"), ("MULU", 2415, "lo3_7=0010011"),
               ("NOR", 2439, "lo3_7=1011010"), ("OR", 2458, "lo3_7=1010010"),
               ("RDHWR", 2526, "lo3_7=0111000"), ("RDPGPR", 2541, "VPE-ish"),
               ("ROTRV", 2809, "lo3_7=0011010"), ("SBX", 3102, "lo7_4=0001"),
               ("SEB", 3221, "lo3_7=0000001"), ("SEH", 3230, "lo3_7=0001001"),
               ("SHX", 3296, "lo7_4=0101,bit6=0"),
               ("SHXS", 3305, "lo7_4=0101,bit6=1"),
               ("SLLV", 3344, "lo3_7=0000010"), ("SLT", 3353, "lo3_7=1101010"),
               ("SLTU", 3380, "lo3_7=1110010"), ("SOV", 3389, "lo3_7=1111010"),
               ("SRAV", 3407, "lo3_7=0010010"), ("SRLV", 3435, "lo3_7=0001010"),
               ("SUB", 3444, "lo3_7=0110010"), ("SUBU", 3455, "lo3_7=0111010"),
               ("SWX", 3689, "lo7_4=1001,bit6=0"),
               ("SWXS", 3700, "lo7_4=1001,bit6=1"),
               ("TEQ", 3773, "trap"), ("TLBINV", 3782, "priv"),
               ("TLBINVF", 3789, "priv"), ("TLBP", 3796, "priv"),
               ("TLBR", 3803, "priv"), ("TLBWI", 3810, "priv"),
               ("TLBWR", 3817, "priv"), ("TNE", 3824, "trap"),
               ("WAIT", 3895, "priv"), ("WRPGPR", 3913, "VPE-ish"),
               ("XOR", 3924, "lo3_7=1100010"),
               ("+MT-ASE", 0, "see ASE_MT (mt.sinc), same pool")],
    0b001001: [],
    0b001010: [("BALC(32)", 970, "bit9==1,hilo_saddr26"),
               ("BC(32)", 1024, "bit9==0,hilo_saddr26")],
    0b001011: [],
    0b001100: [("SLL(16)", 3336, "bit3==0,shift3"),
               ("SRL(16)", 3426, "bit3==1,shift3")],
    0b001101: [("LW[SP](16)", 2081, "rt,hi_sp_uoffset7")],
    0b001110: [("BALC(16)", 978, "hi_saddr11")],
    0b001111: [("ADDU-gpr4(16)", 915, "bit8==0,bit3==0"),
               ("MUL-gpr4(16)", 2407, "bit8==0,bit3==1")],
    0b010000: [("ADDIU-gp-u21(32)", 809, "lo bits1-0==00"),
               ("LW[GP](32)", 2063, "lo bits1-0==10"),
               ("SW[GP](32)", 3496, "lo bits1-0==11")],
    0b010001: [("ADDIU-gp-u18(32)", 797, "gp,u18"),
               ("LB[GP](32)", 1687, "hi_pool2_3=?"),
               ("LBU[GP](32)", 1732, "hi_pool2_3=010"),
               ("LH[GP](32)", 1796, "lo0_1==0"),
               ("LHU[GP](32)", 1844, "lo0_1==1"),
               ("SB[GP](32)", 3073, "hi_pool2_3=001"),
               ("SH[GP](32)", 3266, "lo0_1==0")],
    0b010010: [("BALRSC(32)", 987, "rt!=0,lo12_4=1000"),
               ("BRSC(32)", 1279, "rt_raw==0,lo12_4=1000"),
               ("JALRC(32)", 1624, "lo12_4=0000"),
               ("JALRC.HB(32)", 1642, "lo12_4=0001")],
    0b010011: [],
    0b010100: [("AND(16)", 944, "f2=2,f1=0,f0=0"),
               ("LWXS(16)", 2253, "f0==1"),
               ("NOT(16)", 2449, "f2=0,f1=0,f0=0"),
               ("OR(16)", 2466, "f2=3,f1=0,f0=0"),
               ("XOR(16)", 3932, "f2=1,f1=0,f0=0")],
    0b010101: [("LW[GP16](16)", 2056, "rt3,hi_gp_uoffset9")],
    0b010110: [],
    0b010111: [("LB(16)", 1680, "f3-2=2? see note"),
               ("LBU(16)", 1724, "hi_pool2_2=0b10"),
               ("SB(16)", 3066, "hi_pool2_2=0b01")],
    0b011000: [("P48I", 0, "see POOL48 (6-byte forms only)")],
    0b011001: [],
    0b011010: [],
    0b011011: [],
    0b011100: [("ADDIU-sp(16)", 821, "rt3,sp,u8")],
    0b011101: [("LW[4x4](16)", 2049, "rt4,hi_rs4_uoffset4")],
    0b011110: [],
    0b011111: [("LH(16)", 1788, "bit3==0,bit0==0"),
               ("LHU(16)", 1836, "bit3==1,bit0==0"),
               ("SH(16)", 3259, "bit3==0,bit0==1")],
    0b100000: [("ADDIU-neg(32)", 852, "lo12_4=1000"),
               ("ANDI(32)", 953, "lo12_4=0010"),
               ("BITREV*", 1115, "lo12_4=1101,..."), ("BYTEREV*", 1288, "lo12_4=1101"),
               ("EHB", 1466, "lo12_4=1100,f5=0,lo0_5=00011"),
               ("EXT", 1566, "lo12_4=1111"), ("INS", 1608, "lo12_4=1110"),
               ("NOP(32)", 2426, "lo12_4=1100,f5=0000"),
               ("ORI(32)", 2474, "lo12_4=0000"),
               ("PAUSE", 2483, "lo12_4=1100,f5=0,lo0_5=00101"),
               ("RESTORE(32)", 2773, "lo12_4=0011,lo0_2=10"),
               ("RESTORE.JRC(32)", 2785, "lo12_4=0011,lo0_2=11"),
               ("ROTR", 2799, "lo12_4=1100,f5=0110"),
               ("ROTX", 2819, "lo12_4=1101"), ("SAVE(32)", 3044, "lo12_4=0011,lo0_2=00"),
               ("SEQI", 3239, "lo12_4=0110"), ("SLL(32)", 3328, "lo12_4=1100,f5=0000"),
               ("SLTI", 3362, "lo12_4=0100"), ("SLTIU", 3371, "lo12_4=0101"),
               ("SRA", 3398, "lo12_4=1100,f5=0100"),
               ("SRL", 3417, "lo12_4=1100,f5=0010"),
               ("SYNC", 3714, "lo12_4=1100,f5=0,lo0_5=00110"),
               ("XORI(32)", 3940, "lo12_4=0001")],
    0b100001: [("LB(32)", 1671, "lo12_4=0000"), ("LBU(32)", 1715, "lo12_4=0010"),
               ("LH(32)", 1779, "lo12_4=0100"), ("LHU(32)", 1827, "lo12_4=0110"),
               ("LW(32)", 2033, "lo12_4=1000"), ("PREF(32)", 2504, "lo12_4=0011"),
               ("SB(32)", 3057, "lo12_4=0001"), ("SH(32)", 3250, "lo12_4=0101"),
               ("SW(32)", 3473, "lo12_4=1001"), ("SYNCI(32)", 3733, "lo12_4=0011")],
    0b100010: [("BEQC(32)", 1042, "lo14_2=00"), ("BGEC(32)", 1077, "lo14_2=10"),
               ("BGEUC(32)", 1105, "lo14_2=11")],
    0b100011: [],
    0b100100: [("ADDIU-rt3rs3(16)", 831, "bit3==0,u5"),
               ("ADDIU-rs_from_rt(16)", 842, "bit3==1,s4"),
               ("NOP(16)", 2433, "rt_raw==0,bit3==1")],
    0b100101: [("SW(16)", 3482, "rtz3,hi_rs3_uoffset6")],
    0b100110: [("BEQZC(16)", 1069, "rt3,hi_saddr8")],
    0b100111: [],
    0b101000: [],
    0b101001: [("CACHE", 1309, "EVA/priv-ish"), ("CACHEE", 1319, "EVA"),
               ("LB[S9]", 1694, "lo11_4=0000"), ("LBE", 1704, "EVA"),
               ("LBU[S9]", 1739, "lo11_4=0010"), ("LBUE", 1749, "EVA"),
               ("LH[S9]", 1805, "lo11_4=0100"), ("LHE", 1815, "EVA"),
               ("LHU[S9]", 1853, "lo11_4=0110"), ("LHUE", 1863, "EVA"),
               ("LL", 1936, "ll/sc"), ("LLE", 1947, "EVA"),
               ("LLWP", 1959, "ll/sc"), ("LLWPE", 1985, "EVA"),
               ("LW[S9]", 2072, "lo11_4=1000"), ("LWE", 2089, "EVA"),
               ("LWM", 2213, "load-multiple"), ("PREF[S9]", 2495, "lo11_4=0011"),
               ("PREFE", 2514, "EVA"), ("SB[S9]", 3081, "lo11_4=0001"),
               ("SBE", 3091, "EVA"), ("SC", 3111, "ll/sc"),
               ("SCE", 3127, "EVA"), ("SCWP", 3144, "ll/sc"),
               ("SCWPE", 3174, "EVA"), ("SH[S9]", 3275, "lo11_4=0101"),
               ("SHE", 3285, "EVA"), ("SW[S9]", 3512, "lo11_4=1001"),
               ("SWE", 3529, "EVA"), ("SWM", 3669, "store-multiple"),
               ("SYNCI[S9]", 3724, "lo11_4=0011"), ("SYNCIE", 3742, "EVA"),
               ("UALH", 3833, "unaligned"), ("UALW", 3844, "unaligned"),
               ("UALWM", 3854, "unaligned"), ("UASH", 3864, "unaligned"),
               ("UASW", 3875, "unaligned"), ("UASWM", 3885, "unaligned")],
    0b101010: [("BLTC(32)", 1182, "lo14_2=10"), ("BLTUC(32)", 1210, "lo14_2=11"),
               ("BNEC(32)", 1221, "lo14_2=00")],
    0b101011: [],
    0b101100: [("ADDU(16)", 908, "bit0==0"), ("SUBU(16)", 3464, "bit0==1")],
    0b101101: [("SW[SP](16)", 3521, "rt,hi_sp_uoffset7")],
    0b101110: [("BNEZC(16)", 1247, "rt3,hi_saddr8")],
    0b101111: [("MOVEP", 2319, "rd2_reg1,rd2_reg2,rsz4,rtz4")],
    0b110000: [],
    0b110001: [],
    0b110010: [("BBEQZC", 997, "f2=001"), ("BBNEZC", 1010, "f2=101"),
               ("BEQIC", 1059, "f2=000"), ("BGEIC", 1086, "f2=010"),
               ("BGEIUC", 1095, "f2=011"), ("BLTIC", 1191, "f2=110"),
               ("BLTIUC", 1200, "f2=111"), ("BNEIC", 1237, "f2=100")],
    0b110011: [],
    0b110100: [("LI-1(16)", 1911, "eu_imm7==127 -> -1"),
               ("LI(16)", 1920, "rt3,eu_imm7")],
    0b110101: [("SW[GP16](16)", 3505, "rtz3,hi_gp_uoffset9")],
    0b110110: [("BEQC(16)", 1051, "rs3_raw<rt3_raw,uimm4!=0"),
               ("BNEC(16)", 1229, "rs3_raw>=rt3_raw,uimm4!=0"),
               ("JALRC-ra(16)", 1633, "bit4==1,lo4==0"),
               ("JRC-ra(16)", 1655, "rt==31,bit4==0,lo4==0"),
               ("JRC(16)", 1662, "bit4==0,lo4==0")],
    0b110111: [],
    0b111000: [("ALUIPC(32)", 923, "lo bit1==1"), ("LUI(32)", 2022, "lo bit1==0")],
    0b111001: [],
    0b111010: [],
    0b111011: [],
    0b111100: [("ANDI(16)", 961, "rt3,rs3,eu_imm4")],
    0b111101: [("SW[4x4](16)", 3489, "rtz4,hi_rs4_uoffset4")],
    0b111110: [],
    0b111111: [("MOVEP[REV](16)", 2327, "rs4,rt4,rd2_reg1,rd2_reg2")],
}
UNASSIGNED_POOLS = sorted(p for p, v in POOL16.items() if not v)
# all-empty entries above double as the unassigned list; assert the count:
# 21 pools: 3,9,11,19,22,25,26,27,30,35,39,40,43,48,49,51,55,57,58,59,62.

# 32-bit discriminators actually observed in the modem corpus.
# NOTE: for pool 0b001000 lo bits 15-11 hold rd (a register), so lo12_4 is
# NOT an opcode there — the op lives in lo10-0 (f7/f33/op3/f7_4/lo6_1).
# For pools 001010/000010/110010/111000 the lo half is address/imm data
# (marked -1); the op lives in hi (bit9 / f2 / bit1).
POOL32_CORPUS: dict[tuple[int, int], str] = {
    (0b000000, 0): "ADDIU(32)",
    (0b001000, -1): "ADDU/AND/MUL/MOVN/MOVZ/SLLV/SRLV/SLTU/LSA/LBUX/SBX/...",
    (0b001010, -1): "BALC/BC(bit9; lo is saddr, not opcode)",
    (0b000010, -1): "MOVE.BALC(lo is saddr)",
    (0b010010, 8): "BRSC(rt==0)",
    (0b100000, 0): "ORI", (0b100000, 1): "XORI", (0b100000, 2): "ANDI",
    (0b100000, 5): "SLTIU", (0b100000, 6): "SEQI", (0b100000, 8): "ADDIU-neg",
    (0b100000, 12): "SLL(f5=0000)",
    (0b100001, 1): "SB", (0b100001, 2): "LBU", (0b100001, 5): "SH",
    (0b100001, 8): "LW", (0b100001, 9): "SW",
    (0b100010, 0): "BEQC/BGEC/BGEUC(lo14_2)",
    (0b101001, 9): "LBU[S9](signed off)",
    (0b101010, 0): "BNEC/BLTC/BLTUC(lo14_2)",
    (0b110010, -1): "BxxIC/BBExZC(f2 in hi; lo is imm+saddr)",
    (0b111000, -1): "ALUIPC(bit1==1)",
}

# 48-bit forms: pool 0b011000 + hi_pool0_5 = instrhi bits (0,4) [sinc:18].
# All are hi + instrlo + data16 (6 bytes).
POOL48: dict[int, tuple[str, int, str]] = {
    0b00000: ("LI(48)", 1927, "rt,full_simm32"),
    0b00001: ("ADDIU(48)", 779, "rt,rs_from_rt,full_simm32"),
    0b00010: ("ADDIU-gp(48)", 788, "rt,gp,full_simm32"),
    0b00011: ("ADDIUPC(48)", 885, "rt,%pcrel(addr)"),
    0b01011: ("LWPC(48)", 2226, "rt,pc_rel_saddr32"),
    0b01111: ("SWPC(48)", 3680, "rt,pc_rel_saddr32"),
}

# ---------------------------------------------------------------- ASE scope
# MT ASE lives ONLY in nanomips_mt.sinc ("nanoMIPS32 Multithreading TRM
# Rev 1.17" [mt.sinc:1]); every op touches TC/VPE control state and the NCC
# file marks the定点 ones unimpl ("TODO: implement thread context (TC)
# space" [mt.sinc:47,54,61,70]).
ASE_MT: list[tuple[str, int, str]] = [
    ("DMT", 4, "hi0_5=00001,sc=0; C0.VPEControl.TE=0"),
    ("DVPE", 14, "hi0_5=00000,sc=0; C0.MVPControl.EVP=0"),
    ("EMT", 24, "hi0_5=00001,sc=1; C0.VPEControl.TE=1"),
    ("EVPE", 34, "hi0_5=00000,sc=1; C0.MVPControl.EVP=1"),
    ("FORK", 43, "lo3_7=1000101 unimpl-TC"),
    ("MFTR", 50, "lo4_6=100011 unimpl-TC"),
    ("MTTR", 58, "lo4_6=100111 unimpl-TC"),
    ("YIELD", 68, "lo3_7=1001101 unimpl-TC"),
]
# VPE-flavoured ops in the MAIN sinc (implemented semantics, privileged):
ASE_VPE: list[tuple[str, int, str]] = [
    ("DVP", 1454, "C0.VPEControl.TEboarding? clears TE via rt==0 path"),
    ("EVP", 1554, "sets C0.MVPControl.EVP via rt==0 path"),
    ("RDPGPR", 2541, "shadow-reg read (stub)"),
    ("WRPGPR", 3913, "shadow-reg write (stub)"),
    ("MFC0/MTC0/MFHC0/MTHC0", 2261, "C0.* block [slaspec:27-60]"),
    ("RDHWR", 2526, "HW register read"),
]
# DSP ASE: NO dsp-ASE constructor exists anywhere in the NCC language
# definition (no .QB/.PH/SHRA/PRECR*/MULEQ*/APPEND/BALIGN-class mnemonics;
# full constructor scan). Modem DSP is a separate Coresonic core anyway
# (hw_target SPEC["dsp"]), so DSP scope is N/A for the PCORE emulator.
ASE_DSP: list = []
# Verdict over the 12 corpus functions (1191 insns): zero MT/VPE/DSP-asE
# instructions observed (no DMT/DVPE/EMT/EVPE/FORK/MFTR/MTTR/YIELD/DVP/EVP/
# MFC0/MTC0/RDHWR/CACHE/TLB). PCORE modem code in scope = base nanoMIPS
# (incl. SAVE/RESTORE/MOVEP/MOVE.BALC) only. Emulator: implement base;
# MT-ASE must trap (unimpl TC space); DSP is out of scope (other core).
ASE_CORPUS_USES_MT = False
ASE_CORPUS_USES_VPE = False
ASE_CORPUS_USES_DSP = False

# ---------------------------------------------------------------- NMS subset
# nanoMIPS NMS (nanoMIPS Subset?) gating per NCC sinc comments ("not
# available in NMS"). Ghidra still decodes these when the bytes occur, and
# I7200 silicon executes at least MOVEP[REV] (PROVEN: 0xfe38 bytes decode
# as MOVEP[REV] [sinc:2327]; silicon executes; MTK sim faults w/o 32r6s).
# Rule: never silently misdecode an NMS-gated form as a base form. Each
# NMS-gated decode site below carries an explicit [NMS-gated sinc:...]
# marker plus PROVEN/UNOBSERVED status. Text output stays Ghidra-identical.
NMS_GATED = {
    # 16-bit pool -> (mnemonic, sinc def, sinc NMS note, status)
    0b001111: ("ADDU-gpr4 [sinc:915]", "not available in NMS [sinc:914]",
               "UNOBSERVED-in-corpus; decode kept, marked"),
    0b011101: ("LW[4x4] [sinc:2049]", "not available in NMS [sinc:2048]",
               "UNOBSERVED-in-corpus; decode kept, marked"),
    0b110110: ("BEQC/BNEC-16 [sinc:1051,1229]", "not available in NMS "
               "[sinc:1050,1228]", "OBSERVED-in-corpus; decode kept, marked"),
    0b111111: ("MOVEP[REV] [sinc:2327]", "no NMS ban in sinc; PROVEN real "
               "(silicon executes 0xfe38; MTK sim faults w/o 32r6s)",
               "PROVEN-REAL"),
}
# 48-bit NMS-gated: ADDIUPC(48) [sinc:885] "not available in NMS [sinc:884]".
NMS_GATED_48 = {
    0b00011: ("ADDIUPC(48) [sinc:885]", "not available in NMS [sinc:884]",
              "OBSERVED-in-corpus (ADDIUPC a1 @0x905df46c); decode kept, marked"),
}

# ---------------------------------------------------------------- branch math
# Bit positions use token fields: instrhi (first halfword, LE) /
# instrlo (second halfword) / data16 (third halfword, 48-bit forms).
# inst_start = insn address; inst_next = inst_start + insn size (2/4/6).
# All saddr offsets are sign-extended, then added mod 2**32.
BRANCH_MATH = {
    # -- 32-bit BALC/BC target -----------------------------------------
    # hilo_saddr26: hi_simm0_9=(0,8)[sinc:106]; lo_simm1_15=(1,15)[sinc:197];
    # lo_signbit0_1=(0,0)[sinc:200]; addr = inst_next +
    #   ((sign<<25)|(hi9<<16)|(lo15<<1)) [sinc:488-497].
    # BALC needs hi bit9==1, BC bit9==0 [sinc:971,1025].
    # ex: BALC @0x905df3aa bytes 8f 2a 74 3e -> hi=0x2a8f lo=0x3e74:
    #   off=(0<<25)|(0x8f<<16)|(0x1f3a<<1)=0x8f3e74; next=0x905df3ae;
    #   0x905df3ae+0x8f3e74 = 0x90ed3222 (matches Nmdis2).
    "hilo_saddr26": "target = inst_next + sext26((lo0<<25)|(hi8_0<<16)|(lo15_1<<1))",
    # -- 16-bit BALC/BC target ------------------------------------------
    # hi_saddr11: hi_simm1_9=(1,9)[sinc:106]; hi_signbit0_1=(0,0)[sinc:110];
    # addr = inst_next + ((sign<<10)|(simm9<<1)) [sinc:531-539].
    # ex: BC @0x905df452 bytes 3e 18 -> hi=0x183e: simm=(hi>>1)&0x1ff=31;
    #   next=0x905df454; 0x905df454+62 = 0x905df492 (matches).
    "hi_saddr11": "target = inst_next + sext11((hi0<<10)|(hi9_1<<1))",
    # -- MOVE.BALC target ------------------------------------------------
    # hilo_saddr22: hi_simm0_5=(0,4)[sinc:108]; lo_simm1_15=(1,15);
    # lo_signbit0_1=(0,0); addr = inst_next +
    #   ((sign<<21)|(hi5<<16)|(lo15<<1)) [sinc:499-508].
    # ex: MOVE.BALC @0x905df3dc bytes 1f 0a 1b ff -> hi=0x0a1f lo=0xff1b:
    #   raw=(1<<21)|(31<<16)|(0x7f8d<<1)=0x3fff1a -> signed -0xe6;
    #   next=0x905df3e0; 0x905df3e0-0xe6 = 0x905df2fa (matches).
    "hilo_saddr22": "target = inst_next + sext22((lo0<<21)|(hi4_0<<16)|(lo15_1<<1))",
    # -- 32-bit BEQC/BNEC/... target ------------------------------------
    # lo_saddr15: lo_simm1_13=(1,13)[sinc:198]; lo_signbit0_1=(0,0);
    # addr = inst_next + ((sign<<14)|(simm13<<1)) [sinc:551-559].
    # ex: BGEUC s2,a3 @0x905edfe6 bytes f2 88 9b ff -> lo=0xff9b:
    #   raw=(1<<14)|(0x1fcd<<1)=0x7f9a -> signed -102;
    #   next=0x905edfea; -102 -> 0x905edf84 (matches).
    "lo_saddr15": "target = inst_next + sext15((lo0<<14)|(lo13_1<<1))",
    # -- 32-bit BEQIC/BNEIC/... target + immediate -----------------------
    # buimm7 = (hi_uimm0_2<<5)|lo_uimm11_5 [sinc:467-475] with
    # hi_uimm0_2=(0,1)[sinc:98], lo_uimm11_5=(11,15)[sinc:185];
    # lo_saddr12: lo_simm1_10=(1,10)[sinc:199]; addr = inst_next +
    #   ((sign<<11)|(simm10<<1)) [sinc:541-549].
    # ex: BNEIC a0,0x1 @0x905df3e2 bytes 90 c8 f6 08 -> hi=0xc890 lo=0x08f6:
    #   imm=(0<<5)|((lo>>11)&31)=1; v=(0<<11)|(((lo>>1)&0x3ff)<<1)=0xf6;
    #   next=0x905df3e6; 0x905df3e6+0xf6 = 0x905df4dc (matches).
    "buimm7": "imm7 = (hi1_0<<5)|(lo15_11)",
    "lo_saddr12": "target = inst_next + sext12((lo0<<11)|(lo10_1<<1))",
    # -- 16-bit BEQZC/BNEZC target ---------------------------------------
    # hi_saddr8: hi_simm1_6=(1,6)[sinc:105]; hi_signbit0_1=(0,0);
    # addr = inst_next + ((sign<<7)|(simm6<<1)) [sinc:520-529].
    # ex: BEQZC a0 @0x905df4e0 bytes 32 9a -> hi=0x9a32: simm=0x19=25;
    #   next=0x905df4e2; +50 = 0x905df514 (matches).
    "hi_saddr8": "target = inst_next + sext8((hi0<<7)|(hi6_1<<1))",
    # -- 16-bit BEQC/BNEC target -----------------------------------------
    # hi_uaddr5: hi_uimm0_4=(0,3)[sinc:101]; addr = inst_next +
    #   (uimm4<<1) [sinc:510-518]; BEQC iff rs3_raw<rt3_raw [sinc:1052],
    # BNEC iff rs3_raw>=rt3_raw [sinc:1230], both need uimm4!=0.
    # ex: BEQC s3,a0 @0x905edff8 bytes 35 da -> hi=0xda35: rs3=3<rt3=4,
    #   uimm=5; next=0x905edffa; +10 = 0x905ee004 (matches).
    "hi_uaddr5": "target = inst_next + (hi3_0<<1)",
    # -- BBEQZC/BBNEZC bitpos --------------------------------------------
    # bitpos = (hi_uimm0_1<<5)|lo_uimm11_5, hi_uimm0_1=(0,0)[sinc:98]
    # [sinc:997-1006]; target uses lo_saddr12.
    # ex: BBEQZC a2,0x0 @0x905df3fe bytes c4 c8 2e 00 -> bitpos=(0<<5)|0=0;
    #   lo=0x002e -> off=(((0x2e>>1)&0x3ff)<<1)=46; next=0x905df402;
    #   +46 = 0x905df430 (matches).
    "bitpos": "bitpos = (hi0<<5)|(lo15_11)",
    # -- JRC/JALRC/BRSC ---------------------------------------------------
    # JRC rt: goto [rt] [sinc:1662]; JALRC ra,rt: ra=inst_next;call [rt]
    # [sinc:1633]; JALRC rt,rs(32): rt=inst_next;call [rs] [sinc:1624];
    # BRSC: goto [rs*2+inst_next]; prints bare register [sinc:1279-1284].
    # ex: JALRC ra,s4 bytes 90 da -> hi=0xda90: rt=(hi>>5)&31=20=s4.
    "jrc": "JRC ra == bytes e0 db (rt=31); JALRC ra,rs needs hi bit4==1",
    # -- PC-relative data --------------------------------------------------
    # ADDIUPC(32): addr=(inst_start+((sign<<21)|(hi5<<16)|(lo15<<1))+4)
    # [sinc:870-882]. ADDIUPC(48): addr=(inst_start+((hi_simm16<<16)|
    # lo_imm16)+6) [sinc:885-895]; lo_imm16=(0,15),hi_simm16=(0,15)signed
    # of data16 [sinc:210-211].
    # ex: ADDIUPC a1 @0x905df46c bytes a3 60 a6 46 85 01 -> full=
    #   (0x0185<<16)|0x46a6=0x018546a6; 0x905df46c+full+6=0x91e33b18 (%pcrel).
    "addiupc48": "addr = (inst_start + ((ex16<<16)|lo16) + 6) & 0xffffffff",
    # ALUIPC: addr=(((sign<<31)|(simm10<<21)|(hi5<<16)|(simm4<<12))+
    #   inst_next)&~0xfff [sinc:923-931]; lo_simm12_4=(12,15)[sinc:194],
    # lo_simm2_10=(2,11)[sinc:195], lo_simm1_1=(1,1)=1, sign=lo bit0.
    # ex: ALUIPC a3 @0x919857a2 bytes fb e0 87 02 -> full=0x943b0000;
    #   next=0x919857a6; (full+next)&~0xfff = 0x25d35000 (%pcrel_hi).
    "aluipc": "addr = ((full31 + inst_next) & 0xffffffff) & ~0xfff",
    # LWPC/SWPC/LI(48): pc_rel/full use unsigned add:
    # addr = inst_next + ((hi_simm16<<16)|lo_imm16) [sinc:477-486];
    # LI: rt=full_simm32 [sinc:1927-1932].
    # ex: LWPC s1 @0x905edf58 bytes 2b 62 9a 31 4b 94 -> full=0x944b319a;
    #   inst_next for the 6-byte form = 0x905edf5e;
    #   (next+full)&0xffffffff = 0x24aa10f8 (matches).
    "pcrel48": "addr = (inst_next48 + ((ex16<<16)|lo16)) & 0xffffffff",
}


# ---------------------------------------------------------------- decoder
def _u16(blob: bytes, off: int) -> int:
    return int.from_bytes(blob[off:off + 2], "little")


def _hx(v: int) -> str:
    return "0x%x" % (v & 0xFFFFFFFF)


def _shx(v: int) -> str:
    return ("-0x%x" % -v) if v < 0 else ("0x%x" % v)


def _sext(v: int, bits: int) -> int:
    if v & (1 << (bits - 1)):
        v -= 1 << bits
    return v


def _mem(off: int, base: str) -> str:
    return "%s(%s)" % (_shx(off), base)


def decode_bytes(addr: int, blob: bytes) -> tuple[str, int]:
    """Decode one instruction at addr from LE bytes blob.

    Returns (text, size) where text is byte-identical to Nmdis2/Ghidra
    disassembly. Raises UnknownInsn for bytes outside harvested tables
    (privileged/EVA/LL-SC/MT/DSP/unassigned-pool encodings).
    blob must hold the full instruction (2, 4 or 6 bytes).
    """
    if len(blob) < 2:
        raise UnknownInsn("short blob")
    hi = _u16(blob, 0)
    pool = hi >> 10
    if pool == 0b011000:  # P48I: 6-byte forms only
        if len(blob) < 6:
            raise UnknownInsn("short48")
        return _dec48(addr, hi, _u16(blob, 2), _u16(blob, 4))
    if pool in _LEN32:
        if len(blob) < 4:
            raise UnknownInsn("short32")
        return _dec32(addr, hi, _u16(blob, 2))
    return _dec16(addr, hi)


# pools whose constructors all take instrhi+instrlo (4 bytes)
_LEN32 = frozenset([
    0b000000, 0b000001, 0b000010, 0b001000, 0b001010, 0b010000, 0b010001,
    0b010010, 0b100000, 0b100001, 0b100010, 0b101001, 0b101010, 0b110010,
    0b111000,
])
# every other assigned pool is 16-bit-only (2 bytes)


def _dec16(addr: int, hi: int) -> tuple[str, int]:
    pool = hi >> 10
    nxt = (addr + 2) & 0xFFFFFFFF
    if pool == 0b000100:  # MOVE / BREAK-16 [sinc:2300,1269]
        rt, rs = (hi >> 5) & 31, hi & 31
        if rt == 0:
            raise UnknownInsn("BREAK/SYSCALL-16")
        return ("MOVE %s,%s" % (GPR[rt], GPR[rs]), 2)
    if pool == 0b000101:  # LW(16) [sinc:2042]: off = uimm4<<2 [sinc:630]
        return ("LW %s,%s" % (GPR3[(hi >> 7) & 7],
                              _mem((hi & 15) << 2, GPR3[(hi >> 4) & 7])), 2)
    if pool in (0b000110, 0b001110):  # BC(16)[1032] / BALC(16)[978]
        # hi_saddr11 [sinc:531]: raw=(sign<<10)|(simm9<<1), sext11.
        v = ((hi & 1) << 10) | ((((hi >> 1) & 0x1FF)) << 1)
        tgt = (nxt + _sext(v, 11)) & 0xFFFFFFFF
        return (("BALC " if pool == 0b001110 else "BC ") + _hx(tgt), 2)
    if pool == 0b000111:  # SAVE(16)[2863] / RESTORE.JRC(16)[2590]
        frame = ((hi >> 4) & 15) << 4
        n = hi & 15
        start = 1 if (hi >> 9) & 1 else 0  # rt1_raw: 0->fp.., 1->ra..
        order = ["fp", "ra", "s0", "s1", "s2", "s3", "s4", "s5",
                 "s6", "s7", "t8", "t9", "k0", "k1", "gp", "sp"]
        regs = order[start:start + n]
        if len(regs) != n:
            raise UnknownInsn("SAVE-reglist")
        head = "RESTORE.JRC" if (hi >> 8) & 1 else "SAVE"
        return ("%s 0x%x,%s" % (head, frame, ",".join(regs)), 2)
    if pool == 0b001100:  # SLL(16)[3336] / SRL(16)[3426]
        op = "SLL" if ((hi >> 3) & 1) == 0 else "SRL"
        return ("%s %s,%s,0x%x" % (op, GPR3[(hi >> 7) & 7],
                                  GPR3[(hi >> 4) & 7], SHIFT3[hi & 7]), 2)
    if pool == 0b001101:  # LW[SP](16) [sinc:2081]
        return ("LW %s,%s" % (GPR[(hi >> 5) & 31],
                              _mem((hi & 31) << 2, "sp")), 2)
    if pool == 0b001111:  # ADDU/MUL-gpr4(16) [sinc:915,2407]
        # [NMS-gated sinc:914] ADDU[4X4] not available in NMS; MUL[4X4]
        # has no NMS ban. Decode kept Ghidra-identical, marked (see NMS_GATED).
        if (hi >> 8) & 1:
            raise UnknownInsn("gpr4-bit8")
        msb, idx = (hi >> 9) & 1, (hi >> 5) & 7
        op = "ADDU" if ((hi >> 3) & 1) == 0 else "MUL"
        rd = gpr4(msb, idx)
        return ("%s %s,%s,%s" % (op, rd, rd,
                                 gpr4((hi >> 4) & 1, hi & 7)), 2)
    if pool == 0b010100:  # AND/OR/XOR/NOT/LWXS(16)
        f2, f1, f0 = (hi >> 2) & 3, (hi >> 1) & 1, hi & 1
        rt3, rs3 = GPR3[(hi >> 7) & 7], GPR3[(hi >> 4) & 7]
        if f0 == 1:  # LWXS(16) [sinc:2253] — display PROVISIONAL
            return ("LWXS %s,%s(%s)" % (GPR[(hi >> 1) & 7], rs3, rt3), 2)
        if f1 != 0:
            raise UnknownInsn("p20-f1")
        if f2 == 0b00:
            return ("NOT %s,%s" % (rt3, rs3), 2)       # [sinc:2449]
        if f2 == 0b01:
            return ("XOR %s,%s,%s" % (rt3, rs3, rt3), 2)  # [sinc:3932]
        if f2 == 0b10:
            return ("AND %s,%s" % (rt3, rs3), 2)       # [sinc:944]
        return ("OR %s,%s,%s" % (rt3, rs3, rt3), 2)    # [sinc:2466]
    if pool == 0b010101:  # LW[GP16](16) [sinc:2056] — PROVISIONAL display
        return ("LW %s,%s" % (GPR3[(hi >> 7) & 7],
                              _mem((hi & 0x7F) << 2, "gp")), 2)
    if pool == 0b010111:  # LBU(16)[1724,hi_pool2_2=10] / SB(16)[3066,=01]
        f = (hi >> 2) & 3
        rs3 = GPR3[(hi >> 4) & 7]
        off = hi & 3  # hi_rs3_uoffset2 [sinc:650]
        if f == 0b10:
            return ("LBU %s,%s" % (GPR3[(hi >> 7) & 7], _mem(off, rs3)), 2)
        if f == 0b01:
            return ("SB %s,%s" % (GPR3_ZERO[(hi >> 7) & 7], _mem(off, rs3)), 2)
        raise UnknownInsn("p23-f")
    if pool == 0b011100:  # ADDIU-sp(16) [sinc:821]: u8 = uimm6<<2
        return ("ADDIU %s,sp,%s" % (GPR3[(hi >> 7) & 7],
                                    _hx((hi & 63) << 2)), 2)
    if pool == 0b011101:  # LW[4x4](16) [sinc:2049] — PROVISIONAL
        # [NMS-gated sinc:2048] LW[4X4] not available in NMS. Decode kept
        # Ghidra-identical, marked (see NMS_GATED).
        return ("LW %s,%s" % (gpr4((hi >> 9) & 1, (hi >> 5) & 7),
                              _mem((((hi >> 3) & 1) << 3) |
                                   (((hi >> 8) & 1) << 2),
                                   gpr4((hi >> 4) & 1, hi & 7))), 2)
    if pool == 0b011111:  # LH/LHU/SH(16) [sinc:1788,1836,3259]
        b3, b0 = (hi >> 3) & 1, hi & 1
        rt = GPR3[(hi >> 7) & 7] if b0 == 0 else GPR3_ZERO[(hi >> 7) & 7]
        mem = _mem(((hi >> 1) & 3) << 1, GPR3[(hi >> 4) & 7])
        if (b3, b0) == (0, 0):
            return ("LH %s,%s" % (rt, mem), 2)
        if (b3, b0) == (1, 0):
            return ("LHU %s,%s" % (rt, mem), 2)
        if (b3, b0) == (0, 1):
            return ("SH %s,%s" % (rt, mem), 2)
        raise UnknownInsn("p31")
    if pool == 0b100100:  # ADDIU(16) two forms [sinc:831,842] + NOP [2433]
        if (hi >> 3) & 1:
            rt = (hi >> 5) & 31
            if rt == 0:
                return ("NOP", 2)
            v = (((hi >> 4) & 1) << 3) | (hi & 7)  # s4 [sinc:842-846]
            return ("ADDIU %s,%s,%s" % (GPR[rt], GPR[rt],
                                        _shx(_sext(v, 4))), 2)
        return ("ADDIU %s,%s,%s" % (GPR3[(hi >> 7) & 7],
                                    GPR3[(hi >> 4) & 7],
                                    _hx((hi & 7) << 2)), 2)
    if pool == 0b100101:  # SW(16) [sinc:3482]: off = uimm4<<2 [sinc:630]
        return ("SW %s,%s" % (GPR3_ZERO[(hi >> 7) & 7],
                              _mem((hi & 15) << 2, GPR3[(hi >> 4) & 7])), 2)
    if pool in (0b100110, 0b101110):  # BEQZC [1069] / BNEZC [1247]
        # hi_saddr8 [sinc:520]: raw=(sign<<7)|(simm6<<1), sext8.
        v = ((hi & 1) << 7) | ((((hi >> 1) & 0x3F)) << 1)
        tgt = (nxt + _sext(v, 8)) & 0xFFFFFFFF
        op = "BEQZC" if pool == 0b100110 else "BNEZC"
        return ("%s %s,%s" % (op, GPR3[(hi >> 7) & 7], _hx(tgt)), 2)
    if pool == 0b101100:  # ADDU(16)[908] / SUBU(16)[3464]
        op = "ADDU" if (hi & 1) == 0 else "SUBU"
        return ("%s %s,%s,%s" % (op, GPR3[(hi >> 1) & 7],
                                 GPR3[(hi >> 4) & 7],
                                 GPR3[(hi >> 7) & 7]), 2)
    if pool == 0b101101:  # SW[SP](16) [sinc:3521]
        return ("SW %s,%s" % (GPR[(hi >> 5) & 31],
                              _mem((hi & 31) << 2, "sp")), 2)
    if pool == 0b101111:  # MOVEP [sinc:2319]
        return _movep(hi, False)
    if pool == 0b110100:  # LI(16) [sinc:1911,1920]
        rt3 = GPR3[(hi >> 7) & 7]
        imm7 = hi & 0x7F  # eu_imm7 [sinc:91]
        if imm7 == 127:  # [sinc:1911]: s = -1
            return ("LI %s,-0x1" % rt3, 2)
        return ("LI %s,%s" % (rt3, _hx(imm7)), 2)
    if pool == 0b110101:  # SW[GP16](16) [sinc:3505] — PROVISIONAL
        return ("SW %s,%s" % (GPR3_ZERO[(hi >> 7) & 7],
                              _mem((hi & 0x7F) << 2, "gp")), 2)
    if pool == 0b110110:  # JRC/JALRC-ra/BEQC-16/BNEC-16
        # [NMS-gated sinc:1050,1228] BEQC[16]/BNEC[16] not available in
        # NMS. JRC/JALRC-ra are base. Decode kept Ghidra-identical, marked.
        return _dec_p54_16(addr, hi)
    if pool == 0b111100:  # ANDI(16) [sinc:961]
        return ("ANDI %s,%s,%s" % (GPR3[(hi >> 7) & 7],
                                   GPR3[(hi >> 4) & 7],
                                   _hx(EUIMM4[hi & 15])), 2)
    if pool == 0b111101:  # SW[4x4](16) [sinc:3489] — PROVISIONAL
        return ("SW %s,%s" % (gpr4((hi >> 9) & 1, (hi >> 5) & 7, True),
                              _mem((((hi >> 3) & 1) << 3) |
                                   (((hi >> 8) & 1) << 2),
                                   gpr4((hi >> 4) & 1, hi & 7))), 2)
    if pool == 0b111111:  # MOVEP[REV] [sinc:2327]
        # [NMS-subset PROVEN-REAL] 0xfe38=MOVEP[REV]: silicon executes;
        # MTK sim faults w/o 32r6s. NOT gated out — decode kept.
        return _movep(hi, True)
    raise UnknownInsn("pool16=%02d" % pool)


def _movep(hi: int, rev: bool) -> tuple[str, int]:
    # rd2 code = (bit3<<1)|bit8 shared by both dests via different
    # tables [sinc:412-416,243-258].
    code = (((hi >> 3) & 1) << 1) | ((hi >> 8) & 1)
    d1, d2 = GPR2_REG1[code >> 1][code & 1], GPR2_REG2[code >> 1][code & 1]
    if not rev:  # MOVEP rd2_reg1,rd2_reg2,rsz4,rtz4 [sinc:2319]
        s1 = gpr4((hi >> 4) & 1, hi & 7, True)
        s2 = gpr4((hi >> 9) & 1, (hi >> 5) & 7, True)
        return ("MOVEP %s,%s,%s,%s" % (d1, d2, s1, s2), 2)
    # MOVEP rs4,rt4,rd2_reg1,rd2_reg2 [sinc:2327]
    s1 = gpr4((hi >> 4) & 1, hi & 7)
    s2 = gpr4((hi >> 9) & 1, (hi >> 5) & 7)
    return ("MOVEP %s,%s,%s,%s" % (s1, s2, d1, d2), 2)


def _dec_p54_16(addr: int, hi: int) -> tuple[str, int]:
    nxt = (addr + 2) & 0xFFFFFFFF
    rt, bit4, lo4 = (hi >> 5) & 31, (hi >> 4) & 1, hi & 15
    if bit4 == 1 and lo4 == 0:  # JALRC ra,rt [sinc:1633]
        return ("JALRC ra,%s" % GPR[rt], 2)
    if bit4 == 0 and lo4 == 0:  # JRC rt [sinc:1655,1662]
        return ("JRC %s" % GPR[rt], 2)
    if lo4 == 0:
        raise UnknownInsn("p54-lo4")
    # BEQC iff rs3_raw < rt3_raw [sinc:1051], else BNEC [sinc:1229];
    # hi_uaddr5: target = next + (uimm4<<1) [sinc:510].
    rs3, rt3 = (hi >> 4) & 7, (hi >> 7) & 7
    tgt = (nxt + (lo4 << 1)) & 0xFFFFFFFF
    op = "BEQC" if rs3 < rt3 else "BNEC"
    return ("%s %s,%s,%s" % (op, GPR3[rs3], GPR3[rt3], _hx(tgt)), 2)


def _dec32(addr: int, hi: int, lo: int) -> tuple[str, int]:
    pool = hi >> 10
    nxt = (addr + 4) & 0xFFFFFFFF
    rt, rs = (hi >> 5) & 31, hi & 31
    if pool == 0b000000:  # ADDIU(32) [sinc:771]; rt==0 -> BREAK/etc
        if rt == 0:
            raise UnknownInsn("BREAK-32")
        return ("ADDIU %s,%s,%s" % (GPR[rt], GPR[rs], _hx(lo)), 4)
    if pool == 0b000001:  # ADDIUPC(32) [sinc:870] — PROVISIONAL (unobserved)
        v = ((lo & 1) << 21) | ((hi & 31) << 16) | (((lo >> 1) & 0x7FFF) << 1)
        return ("ADDIUPC %s,%%pcrel(%s)" % (GPR[rt], _hx((addr + _sext(v, 22) + 4) & 0xFFFFFFFF)), 4)
    if pool == 0b000010:  # MOVE.BALC [sinc:2308]
        # hilo_saddr22 [sinc:499]: sign=lo bit0, hi5=hi bits4-0.
        v = ((lo & 1) << 21) | ((hi & 31) << 16) | (((lo >> 1) & 0x7FFF) << 1)
        tgt = (nxt + _sext(v, 22)) & 0xFFFFFFFF
        return ("MOVE.BALC %s,%s,%s" % (GPR1[(hi >> 8) & 1],
                                        gpr4((hi >> 9) & 1, (hi >> 5) & 7, True),
                                        _hx(tgt)), 4)
    if pool == 0b001000:  # big ALU / indexed-mem pool
        return _dec_p08(addr, hi, lo, rt, rs)
    if pool == 0b001010:  # BALC/BC(32) [sinc:970,1024]
        # hilo_saddr26 [sinc:488]: sign=lo bit0, hi9=hi bits8-0.
        v = ((lo & 1) << 25) | ((hi & 0x1FF) << 16) | (((lo >> 1) & 0x7FFF) << 1)
        tgt = (nxt + _sext(v, 26)) & 0xFFFFFFFF
        op = "BALC" if (hi >> 9) & 1 else "BC"
        return ("%s %s" % (op, _hx(tgt)), 4)
    if pool == 0b010000:  # ADDIU-gp/LW[GP]/SW[GP] — PROVISIONAL (unobserved)
        sel = lo & 3
        if sel == 0b10:
            return ("LW %s,%s" % (GPR[rt], _mem_gp(hi, lo)), 4)
        if sel == 0b11:
            return ("SW %s,%s" % (GPR[rt], _mem_gp(hi, lo)), 4)
        return ("ADDIU %s,gp,%s" % (GPR[rt], _hx(((hi & 31) << 18) | ((lo >> 2) & 0x3FFF) << 2)), 4)
    if pool == 0b010001:  # GP-byte pool — unobserved in corpus
        raise UnknownInsn("gp-byte-pool")
    if pool == 0b010010:  # JALRC/BRSC/BALRSC [sinc:987,1279,1624,1642]
        f = (lo >> 12) & 15
        if f == 0b1000:
            if rt == 0:  # BRSC rs_scale2 [sinc:1279]
                return ("BRSC %s" % GPR[rs], 4)
            return ("BALRSC %s,%s" % (GPR[rt], GPR[rs]), 4)  # PROVISIONAL
        if f == 0b0000:
            return ("JALRC %s,%s" % (GPR[rt], GPR[rs]), 4)
        if f == 0b0001:
            return ("JALRC.HB %s,%s" % (GPR[rt], GPR[rs]), 4)  # PROVISIONAL
        raise UnknownInsn("p18-lo")
    if pool == 0b100000:
        return _dec_p32_100000(addr, hi, lo, rt, rs)
    if pool == 0b100001:  # U12 loads/stores [sinc:1671-3733]
        f = (lo >> 12) & 15
        ops = {0b0000: "LB", 0b0010: "LBU", 0b0100: "LH", 0b0110: "LHU",
               0b0001: "SB", 0b0101: "SH", 0b1000: "LW", 0b1001: "SW"}
        if f not in ops:
            raise UnknownInsn("p33-lo")
        return ("%s %s,%s" % (ops[f], GPR[rt], _mem(lo & 0xFFF, GPR[rs])), 4)
    if pool == 0b100010:  # BEQC/BGEC/BGEUC [sinc:1042,1077,1105]
        f = (lo >> 14) & 3
        ops = {0b00: "BEQC", 0b10: "BGEC", 0b11: "BGEUC"}
        if f not in ops:
            raise UnknownInsn("p34-lo")
        v = ((lo & 1) << 14) | (((lo >> 1) & 0x1FFF) << 1)  # lo_saddr15
        return ("%s %s,%s,%s" % (ops[f], GPR[rs], GPR[rt],
                                 _hx((nxt + _sext(v, 15)) & 0xFFFFFFFF)), 4)
    if pool == 0b101001:  # S9 loads/stores + LWM/SWM (all S9 forms)
        return _dec_p41_s9(addr, hi, lo, rt, rs)
    if pool == 0b101010:  # BNEC/BLTC/BLTUC [sinc:1182,1210,1221]
        f = (lo >> 14) & 3
        ops = {0b00: "BNEC", 0b10: "BLTC", 0b11: "BLTUC"}
        if f not in ops:
            raise UnknownInsn("p42-lo")
        v = ((lo & 1) << 14) | (((lo >> 1) & 0x1FFF) << 1)
        return ("%s %s,%s,%s" % (ops[f], GPR[rs], GPR[rt],
                                 _hx((nxt + _sext(v, 15)) & 0xFFFFFFFF)), 4)
    if pool == 0b110010:  # BxxIC/BBExZC [sinc:997-1237]
        return _dec_p50(addr, hi, lo, rt)
    if pool == 0b111000:  # ALUIPC [sinc:923] (bit1==1) / LUI (bit1==0)
        if ((lo >> 1) & 1) == 0:
            raise UnknownInsn("LUI")
        full = (((lo & 1) << 31) | (((lo >> 2) & 0x3FF) << 21) |
                ((hi & 31) << 16) | (((lo >> 12) & 15) << 12))
        return ("ALUIPC %s,%%pcrel_hi(%s)" %
                (GPR[rt], _hx(((full + nxt) & 0xFFFFFFFF) & ~0xFFF)), 4)
    raise UnknownInsn("pool32=%02d" % pool)


def _mem_gp(hi: int, lo: int) -> str:  # hilo_gp_uoffset21 [sinc:600]
    return _mem(((hi & 31) << 16) | (((lo >> 2) & 0x3FFF) << 2), "gp")


def _dec_p08(addr: int, hi: int, lo: int, rt: int, rs: int) -> tuple[str, int]:
    # pool 0b001000. rd=(11,15)[sinc:171]; f7=(3,9); op3=(0,2)[sinc:150-163].
    rd, f7, op3 = (lo >> 11) & 31, (lo >> 3) & 0x7F, lo & 7
    R, S, D = GPR[rt], GPR[rs], GPR[rd]
    alu3 = {0b0101010: "ADDU", 0b1001010: "AND", 0b0000011: "MUL",
            0b0000010: "SLLV", 0b0001010: "SRLV", 0b1110010: "SLTU",
            0b0100010: "ADD", 0b0110010: "SUB", 0b0111010: "SUBU",
            0b0010010: "SRAV", 0b0011010: "ROTRV", 0b1101010: "SLT",
            0b1010010: "OR", 0b1011010: "NOR", 0b1100010: "XOR",
            0b0001011: "MUH", 0b0011011: "MUHU", 0b0010011: "MULU",
            0b0100011: "DIV", 0b0110011: "DIVU", 0b0101011: "MOD",
            0b0111011: "MODU", 0b1111010: "SOV"}
    if op3 == 0b000 and f7 in alu3:
        if f7 == 0b1110010 and rd == 0:
            raise UnknownInsn("SLTU-r0")
        return ("%s %s,%s,%s" % (alu3[f7], D, S, R), 4)
    if op3 == 0b000 and f7 == 0b1000010:  # MOVN/MOVZ [sinc:2336,2347]
        op = "MOVN" if (lo >> 10) & 1 else "MOVZ"
        return ("%s %s,%s,%s" % (op, D, S, R), 4)
    if op3 == 0b000 and f7 == 0b0000110:  # MFC0 rt,c0s,sel [sinc:2261]
        # hi: pool10_6=(10,15)[sinc:5], rt_att=(5,9)[sinc:35], c0s=(0,4)
        #   [sinc:43]; lo: sel=(11,15)[sinc:177], lo_pool3_7=(3,9)[sinc:146],
        #   lo_pool0_3=(0,2)[sinc:161]; c0_reg=c0s,sel [sinc:440-448].
        # Ghidra prints numeric "MFC0 a3,0x4,0x2" (not symbolic C0 names).
        # Worked example @0x9002635c bytes e4 20 30 10 (file off 0x2635c):
        #   hi=0x20e4 pool=001000 rt=(hi>>5)&31=7=a3 c0s=hi&31=4;
        #   lo=0x1030 f7=(lo>>3)&0x7F=0b0000110 op3=0 sel=(lo>>11)&31=2;
        #   -> "MFC0 a3,0x4,0x2" (matches Nmdis2 fn_stack_get_active_module_id).
        # Vectors: (0x9002635c,"e4203010","MFC0 a3,0x4,0x2"),
        #   (0x90004710,"82223030","MFC0 s4,0x2,0x6"). Ghidra wins on conflict.
        return ("MFC0 %s,%s,%s" % (GPR[rt], _hx(hi & 31),
                                   _hx((lo >> 11) & 31)), 4)
    if op3 == 0b000 and f7 == 0b0001110:  # MTC0 rt,c0s,sel [sinc:2358]
        # Same bit positions as MFC0; direction reversed (rt -> C0).
        # Vectors: (0x90004546,"a2207030","MTC0 a1,0x2,0x6"),
        #   (0x90004a9c,"c2207030","MTC0 a2,0x2,0x6"). Ghidra wins on conflict.
        return ("MTC0 %s,%s,%s" % (GPR[rt], _hx(hi & 31),
                                   _hx((lo >> 11) & 31)), 4)
    if op3 == 0b111:  # indexed + LSA group (lo_pool0_3=111)
        f4, b6, f33 = (lo >> 7) & 15, (lo >> 6) & 1, (lo >> 3) & 7
        if f33 == 0b001:  # LSA rd,rs,rt,u2 [sinc:2012]
            return ("LSA %s,%s,%s,%s" % (D, S, R, _hx((lo >> 9) & 3)), 4)
        if f33 == 0b000 and b6 == 0:
            idx = {0b0001: "SBX", 0b0010: "LBUX", 0b0000: "LBX",
                   0b0100: "LHX", 0b0110: "LHUX", 0b1000: "LWX",
                   0b0101: "SHX", 0b1001: "SWX"}.get(f4)
            if idx is None:
                raise UnknownInsn("p08-idx")
            # rt_offset_rs: display index(base) = rs(rt) i.e. S(R)
            return ("%s %s,%s(%s)" % (idx, D, S, R), 4)
        if f33 == 0b000 and b6 == 1:  # scaled x2/x4 forms
            idx = {0b0001: "SBXS", 0b0010: "LBUXS", 0b0000: "LBXS",
                   0b0100: "LHXS", 0b0110: "LHUXS", 0b1000: "LWXS",
                   0b0101: "SHXS", 0b1001: "SWXS"}.get(f4)
            if idx is None:
                raise UnknownInsn("p08-scaled-unmapped")
            return ("%s %s,%s(%s)" % (idx, D, S, R), 4)
    raise UnknownInsn("p08 lo=%04x" % lo)


def _s9_off(lo: int) -> int:
    # lo_rs_soffset9 via lo_soffset9 [sinc:571-578]: offs=(sign<<8)|simm0_8,
    # sign=lo bit15 [sinc:203], simm0_8=lo bits7-0 [sinc:201]; sext9.
    return _sext(((lo >> 15) & 1) << 8 | (lo & 0xFF), 9)


def _dec_p41_s9(addr: int, hi: int, lo: int, rt: int, rs: int
                ) -> tuple[str, int]:
    # pool 0b101001 (41). S9 single loads/stores share:
    #   hi_pool10_6=(10,15)[sinc:5], rt=(5,9)[sinc:35], rs=c0s-alias (0,4);
    #   lo_pool11_4=(11,14)[sinc:128] opcode, lo_pool10_1=(10,10)[sinc:132],
    #   lo_pool8_2=(8,9)[sinc:137], offset lo_soffset9 [sinc:571].
    # Base singles need bit10==0 and bits9-8==00 (else EVA=10 / LL-SC=01 /
    #   LWM-SWM/UAL=1x). Each form below cites its sinc constructor.
    # Ghidra wins on any text conflict (recorded, none observed 2026-09-06).
    op4 = (lo >> 11) & 15
    b10 = (lo >> 10) & 1
    b98 = (lo >> 8) & 3
    R, S = GPR[rt], GPR[rs]
    if b10 == 0 and b98 == 0b00:
        off = _s9_off(lo)
        mem = _mem(off, S)
        if op4 == 0b0000:  # LB[S9] [sinc:1693]
            # vectors: (0x90046d3e,"e7a4ff80","LB a3,-0x1(a3)"),
            #   (0x900e6da4,"e6a4f480","LB a3,-0xc(a2)")
            return ("LB %s,%s" % (R, mem), 4)
        if op4 == 0b0001:  # SB[S9] [sinc:3081]
            # vectors: (0x9000f2b0,"f7a47a88","SB a3,-0x86(s7)"),
            #   (0x9000f2bc,"f7a47888","SB a3,-0x88(s7)")
            return ("SB %s,%s" % (R, mem), 4)
        if op4 == 0b0010:  # LBU[S9] [sinc:1739]
            # vectors: (0x9000787a,"fea49290","LBU a3,-0x6e(fp)"),
            #   (0x90007886,"fea49390","LBU a3,-0x6d(fp)") + corpus
            #   LBU a7,-0x9(a3) @0x905eebcc ("67a5f790").
            return ("LBU %s,%s" % (R, mem), 4)
        if op4 == 0b0100:  # LH[S9] [sinc:1805]
            # vectors: (0x90049f80,"b0a4e8a0","LH a1,-0x18(s0)"),
            #   (0x90049f9c,"b5a4e8a0","LH a1,-0x18(s5)")
            return ("LH %s,%s" % (R, mem), 4)
        if op4 == 0b0101:  # SH[S9] [sinc:3275]
            # vectors: (0x900248e4,"85a4c0a8","SH a0,-0x40(a1)"),
            #   (0x900248ec,"85a4c2a8","SH a0,-0x3e(a1)")
            return ("SH %s,%s" % (R, mem), 4)
        if op4 == 0b0110:  # LHU[S9] [sinc:1853]
            # vectors: (0x9000786e,"fea490b0","LHU a3,-0x70(fp)"),
            #   (0x90007bf8,"1ea5b4b0","LHU a4,-0x4c(fp)")
            return ("LHU %s,%s" % (R, mem), 4)
        if op4 == 0b1000:  # LW[S9] [sinc:2072]
            # vectors: (0x90007834,"fea4d8c0","LW a3,-0x28(fp)"),
            #   (0x90007a48,"bea4d8c0","LW a1,-0x28(fp)")
            return ("LW %s,%s" % (R, mem), 4)
        if op4 == 0b1001:  # SW[S9] [sinc:3512]
            # vectors: (0x900049d0,"c4a4fcc8","SW a2,-0x4(a0)"),
            #   (0x90004c12,"25a5fcc8","SW a5,-0x4(a1)")
            return ("SW %s,%s" % (R, mem), 4)
        if op4 == 0b0011:  # PREF[S9][sinc:2495]/SYNCI[S9][sinc:3724]
            # PREF needs hint!=31, SYNCI needs rt==31 (hi_pool5_5=11111).
            # UNOBSERVED at true boundaries in 40k-function sweep
            # (2026-09-06); explicit trap, no silent misdecode.
            raise UnknownInsn("p41-PREF-SYNCI-unobserved")
        raise UnknownInsn("p41-s9-op=%x" % op4)
    if b10 == 1 and b98 == 0b00:
        # LWM/SWM: count3=(12,14)[sinc:181], lo_pool11_1=(11,11)=b11
        # selects LWM(b11=0)[sinc:2213]/SWM(b11=1)[sinc:3669];
        # lo_pool10_1=1, lo_pool8_2=00; offset is S9; count=8 iff count3==0
        # (reglist_lwm_pre/swm_pre [sinc:2210-2211,3666-3667]).
        count3 = (lo >> 12) & 7
        b11 = (lo >> 11) & 1
        count = 8 if count3 == 0 else count3
        mem = _mem(_s9_off(lo), S)
        if b11 == 0:  # LWM [sinc:2213]
            # vectors: (0x9000f240,"dda43824","LWM a2,0x38(sp),0x2"),
            #   (0x9000f410,"dda42c24","LWM a2,0x2c(sp),0x2")
            return ("LWM %s,%s,%s" % (R, mem, _hx(count)), 4)
        # SWM [sinc:3669]
        # vectors: (0x900367b2,"1da5302c","SWM a4,0x30(sp),0x2"),
        #   (0x900367b6,"5da5382c","SWM a6,0x38(sp),0x2") + count-8
        #   (0x904f93bc,"c4a40c00","SWM a2,0x0(a0),0x8").
        return ("SWM %s,%s,%s" % (R, mem, _hx(count)), 4)
    # EVA (b98==10) [sinc:1704,1749,1815,...], LL/SC (b98==01)
    # [sinc:1936,3111,...], unaligned UALH/UASH (b98==01,op 0100/0101)
    # [sinc:3833,3864], UALWM/UASWM [sinc:3854,3885]: all require
    # privileged/EVA/LL state — explicit trap, never misdecoded as S9.
    raise UnknownInsn("p41-lo=%04x(evA/llsc/ual-trap)" % lo)


def _dec_p32_100000(addr: int, hi: int, lo: int, rt: int, rs: int
                    ) -> tuple[str, int]:
    # pool 0b100000 [sinc:852-3940]. R, S = full regs; imm12 = lo bits11-0.
    f, imm = (lo >> 12) & 15, lo & 0xFFF
    R, S = GPR[rt], GPR[rs]
    if f == 0b1000:  # ADDIU-neg [sinc:852]: u_neg = -imm
        return ("ADDIU %s,%s,%s" % (R, S, _shx(-imm) if imm else "0x0"), 4)
    if f == 0b0010:
        return ("ANDI %s,%s,%s" % (R, S, _hx(imm)), 4)   # [sinc:953]
    if f == 0b0000:
        return ("ORI %s,%s,%s" % (R, S, _hx(imm)), 4)    # [sinc:2474]
    if f == 0b0001:
        return ("XORI %s,%s,%s" % (R, S, _hx(imm)), 4)   # [sinc:3940]
    if f == 0b0100:
        return ("SLTI %s,%s,%s" % (R, S, _hx(imm)), 4)   # [sinc:3362]
    if f == 0b0101:
        return ("SLTIU %s,%s,%s" % (R, S, _hx(imm)), 4)  # [sinc:3371]
    if f == 0b0110:
        return ("SEQI %s,%s,%s" % (R, S, _hx(imm)), 4)   # [sinc:3239]
    if f == 0b1100:  # SLL/SRL/SRA/... [sinc:3328,3417,3398,...]
        f5 = (lo >> 5) & 0x7F
        if f5 == 0b0000:
            return ("SLL %s,%s,%s" % (R, S, _hx(lo & 31)), 4)
        if f5 == 0b0010:
            return ("SRL %s,%s,%s" % (R, S, _hx(lo & 31)), 4)
        if f5 == 0b0100:
            return ("SRA %s,%s,%s" % (R, S, _hx(lo & 31)), 4)
        raise UnknownInsn("p32-shift")
    raise UnknownInsn("p32-lo=%x" % f)


def _dec_p50(addr: int, hi: int, lo: int, rt: int) -> tuple[str, int]:
    # pool 0b110010. f2 = hi bits4-2 [sinc:14]; buimm7 [sinc:467];
    # lo_saddr12 [sinc:541].
    nxt = (addr + 4) & 0xFFFFFFFF
    f2 = (hi >> 2) & 7
    v = ((lo & 1) << 11) | (((lo >> 1) & 0x3FF) << 1)
    tgt = (nxt + _sext(v, 12)) & 0xFFFFFFFF
    R = GPR[rt]
    if f2 in (0b000, 0b010, 0b011, 0b100, 0b110, 0b111):
        ops = {0b000: "BEQIC", 0b010: "BGEIC", 0b011: "BGEIUC",
               0b100: "BNEIC", 0b110: "BLTIC", 0b111: "BLTIUC"}
        imm7 = (((hi & 3) << 5) | ((lo >> 11) & 31)) & 0x7F
        return ("%s %s,%s,%s" % (ops[f2], R, _hx(imm7), _hx(tgt)), 4)
    if f2 in (0b001, 0b101):  # BBEQZC [997] / BBNEZC [1010]
        bitpos = (((hi & 1) << 5) | ((lo >> 11) & 31)) & 0x3F
        op = "BBEQZC" if f2 == 0b001 else "BBNEZC"
        return ("%s %s,%s,%s" % (op, R, _hx(bitpos), _hx(tgt)), 4)
    raise UnknownInsn("p50-f2")


def _dec48(addr: int, hi: int, lo: int, ex: int) -> tuple[str, int]:
    # pool 0b011000 + hi_pool0_5 [sinc:779-3680]. full = (ex<<16)|lo,
    # added mod 2**32 (sign handling is irrelevant mod 2**32).
    f5 = hi & 31
    rt = GPR[(hi >> 5) & 31]
    full = ((ex << 16) | lo) & 0xFFFFFFFF
    if f5 == 0b00000:  # LI(48) [sinc:1927]
        return ("LI %s,%s" % (rt, _hx(full)), 6)
    if f5 == 0b00011:  # ADDIUPC(48) [sinc:885]
        # [NMS-gated sinc:884] not available in NMS. Decode kept
        # Ghidra-identical, marked (see NMS_GATED_48).
        return ("ADDIUPC %s,%%pcrel(%s)" %
                (rt, _hx((addr + full + 6) & 0xFFFFFFFF)), 6)
    if f5 == 0b01011:  # LWPC(48) [sinc:2226]: next = addr+6
        return ("LWPC %s,%s" % (rt, _hx((addr + 6 + full) & 0xFFFFFFFF)), 6)
    if f5 == 0b01111:  # SWPC(48) [sinc:3680]: next = addr+6
        return ("SWPC %s,%s" % (rt, _hx((addr + 6 + full) & 0xFFFFFFFF)), 6)
    if f5 in (0b00001, 0b00010):  # ADDIU(48) — PROVISIONAL (unobserved)
        rs = GPR[(hi >> 5) & 31] if f5 == 0b00001 else "gp"  # rs_from_rt [sinc:779]
        return ("ADDIU %s,%s,%s" % (rt, rs, _hx(full)), 6)
    raise UnknownInsn("pool48-f5=%02d" % f5)


# ---------------------------------------------------------------- corpus I/O
_LINE_RE = re.compile(r"Nmdis2\.java>\s+([0-9a-fA-F]+)\s+(.*?)\s*\(GhidraScript\)")
_REBASE_RE = re.compile(r"REBASED to ([0-9a-fA-F]+) size=(\d+)")


def iter_corpus():
    """Yield (func, addr, text, raw) for every corpus line (~1191)."""
    for func in CORPUS_FILES:
        log = CORPUS_DIR / (func + ".log")
        raw = (CORPUS_DIR / (func + ".bin")).read_bytes()
        txt = log.read_text(errors="replace")
        m = _REBASE_RE.search(txt)
        if not m:
            raise FileNotFoundError("no REBASED in %s" % log)
        base = int(m.group(1), 16)
        cur: list[tuple[int, str]] = []
        for line in txt.splitlines():
            if "Nmdis2.java>" not in line:
                continue
            mm = _LINE_RE.search(line)
            if mm is None:
                continue
            text = mm.group(2).strip()
            if text.startswith("REBASED") or text.startswith("DONE"):
                continue
            cur.append((int(mm.group(1), 16), text))
        for i, (a, text) in enumerate(cur):
            nxt = cur[i + 1][0] if i + 1 < len(cur) else base + len(raw)
            size = nxt - a
            yield func, a, text, bytes(raw[a - base:a - base + size])


def verify_corpus(show: int = 15) -> tuple[int, int, list[str]]:
    """Cross-check every corpus line. Returns (ok, total, mismatches)."""
    ok, total, bad = 0, 0, []
    for func, addr, want, raw in iter_corpus():
        total += 1
        try:
            got, size = decode_bytes(addr, raw)
        except UnknownInsn as e:
            bad.append("%08x %-42s raw=%-20s NO-DECODE(%s) [%s]" %
                       (addr, want, raw.hex(" "), e, func))
            continue
        if size != len(raw):
            bad.append("%08x %-42s raw=%-20s SIZE got=%d want=%d [%s]" %
                       (addr, want, raw.hex(" "), size, len(raw), func))
        elif got != want:
            bad.append("%08x want=%-42s got=%-42s raw=%s [%s]" %
                       (addr, want, got, raw.hex(" "), func))
        else:
            ok += 1
    return ok, total, bad


def pool_inventory_text() -> str:
    lines = ["16-bit major pools (hi_pool10_6 = instrhi bits 15..10):"]
    for p in range(64):
        ent = POOL16.get(p, [])
        tag = "UNASSIGNED" if not ent else \
            "; ".join("%s[sinc:%d]%s" % (m, ln, ("(%s)" % n) if n else "")
                      for m, ln, n in ent)
        lines.append("  %2d 0b%s : %s" % (p, format(p, "06b"), tag))
    lines.append("48-bit (pool 0b011000 + hi_pool0_5 = instrhi bits 4..0):")
    for k in sorted(POOL48):
        m, ln, n = POOL48[k]
        lines.append("  0b%s : %s[sinc:%d](%s)" % (format(k, "05b"), m, ln, n))
    return "\n".join(lines)


def main() -> int:
    import sys
    ok, total, bad = verify_corpus()
    print("decode_tables verifier: %d/%d match (%.2f%%)" %
          (ok, total, 100.0 * ok / total if total else 0))
    for b in bad[:15]:
        print("  MISMATCH:", b)
    if len(bad) > 15:
        print("  ... +%d more" % (len(bad) - 15))
    print("pools: 16-bit assigned=%d/64 unassigned=%d; 48-bit forms=%d" %
          (64 - len(UNASSIGNED_POOLS), len(UNASSIGNED_POOLS), len(POOL48)))
    print("MT ASE ops: %d (all unimpl-TC); corpus uses MT/VPE/DSP: %s/%s/%s" %
          (len(ASE_MT), ASE_CORPUS_USES_MT, ASE_CORPUS_USES_VPE,
           ASE_CORPUS_USES_DSP))
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
