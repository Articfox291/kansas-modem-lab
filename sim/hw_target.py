#!/usr/bin/env python3
"""hw_target.py — EXACT target-hardware spec record (Kansas lab, MT6835 PCORE).

Single source of truth every engine component builds to. Each fact carries
provenance. Anything marked PROVISIONAL needs a conformance check before use.
QEMU and Ghidra backends must both implement THIS spec; divergences are bugs.

Ghidra language: nanomips:LE:32:default (NCC ghidra-nanomips, built for 12.1.3)
  endian=little, size=32, alignment=2, pc/sp/ra, args a0-a7, ret a0-a1,
  callee-saved s0-s7 (cspec), CP0 block @register 0x200-0x2200 (cspec global).
CPU: MIPS nanoMIPS I7200 (proof: nano_i7200.elf.gcc string in image + CATI
  mips_*/VPE symbols). Nucleus RTOS. DSP: Coresonic (modem DSP, NOT PCORE path).
ABI docs: MIPS nanoMIPS ABI Supplement v1.03 / p32 Porting Guide (MIPS Tech,
  linked from MediaTek toolchain release notes) — PROVISIONAL until cross-checked.
MediaTek toolchain (2025.09-02): binutils 2.28, GCC 6.3.0, GDB 8.0 (+GDBsim
  nanomips-elf-run), QEMU 2.5.0-MTK (MTHLIP/BPOSGE32C fixes), Linux-x64 only.
"""
from __future__ import annotations

SPEC = {
    "language_id": "nanomips:LE:32:default",
    "endian": "little",
    "bits": 32,
    "align": 2,
    "cpu": "MIPS nanoMIPS I7200",
    "cpu_proof": ["nano_i7200.elf.gcc in md1rom", "CATI mips_*/VPE symbols",
                  "vectors @0x90004000/100/180"],
    "rtos": "Nucleus",
    "dsp": "Coresonic (separate core; PCORE ISA scope only)",
    "pc": "pc", "sp": "sp", "ra": "ra",
    "args": ["a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"],
    "retval": ["a0", "a1"],
    "saved": ["s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7"],
    "tmp": ["t0", "t1", "t2", "t3", "t4", "t5", "t8", "t9"],
    "special": ["zero", "at", "k0", "k1", "gp", "fp"],
    # gpr3 attach (nanomips.sinc: gpr3 [16,17,18,19,4,5,6,7]); raw4->a0 VERIFIED.
    "gpr3": ["s0", "s1", "s2", "s3", "a0", "a1", "a2", "a3"],
    "gpr3_verified": {4: "a0"},
    # Memory map (DTB + GFH + live corroboration; addrs are AP-phys unless noted)
    "mem": {
        "modem_va": 0x90000000,
        "modem_ap_phys": 0xD0000000,
        "modem_size": 45893712,
        "md1img_hdr": 0x200,
        "vectors": [0x90004000, 0x90004100, 0x90004180],
        "modem_temp_share": 0x10018000,
        "ccif_pairs": ["10209000/1020a000", "1020b000/1020c000",
                       "1023c000/1023d000", "1023e000/1023f000",
                       "1024c000/1024d000", "1025c000/1025d000"],
        "dpmaif_cache": (0x190000, "1.6M"),
        "dpmaif_nocache": (0x50000, "320K"),
    },
    # Ghidra-verified stub encodings (bytes LE): never hand-assemble otherwise.
    "stubs": {
        "ret1": bytes.fromhex("01d2e0db"),   # LI a0,1 ; JRC ra
        "ret0": bytes.fromhex("00d2e0db"),   # LI a0,0 ; JRC ra
        "jrc_ra": bytes.fromhex("e0db"),
    },
    # Open spec questions (agents: close these with evidence, update here).
    # CLOSED 2026-09-05: GAS flags = -march=i7200 -m32 -EL (vendor GAS;
    #   -mabi=p32 rejected; -march list includes i7200). Triple-evidence:
    #   GAS(li a0,1)=d201 + Ghidra(LI a0,0x1) + emu(materials 01d2) agree.
    # CLOSED 2026-09-05: vendor GDBsim executes modem code EXACT-spec:
    #   objcopy -I binary -O elf32-littlenanomips -B nanomips carve->.o,
    #   ld -T <ABS-VA script> (carve @VA, ret1 BYTE-stubs at helpers,
    #   NOLOAD bss/stack), gdb batch: target sim, load, break entry (reg
    #   context!), set sp/a0/ra, continue to RET breakpoint, read a0.
    #   stock legal_sim_rule -> a0=0x0 @0x905df330; patch -> a0=0x1.
    #   GDB needs entry-break before regs exist ("No registers" otherwise).
    #   Toolchain: /opt/mtk-toolchain (WSL2 Ubuntu 24.04), sha256-verified
    #   MediaTek.GNU.Tools.2025.09-02 (6664aa98...0d38). objdump -m nanomips
    #   matches Ghidra text byte-for-byte (incl. BALC absolute targets).
    "open_questions": [
        "I7200 vs generic-nanoMIPS gaps in NCC sleigh (DSP ASE? MT ASE? VPE?)",
        "CP0 register map actually touched by modem code (hook C0 range)",
        "nanoMIPS p32 ABI: caller-saved set beyond cspec unaffected list",
        "QEMU CPU flag matching I7200 (-cpu I7200? section registers?)",
    ],
}


def check_spec() -> list[str]:
    """Self-consistency checks (not HW proof). Returns failure list."""
    fails = []
    if len(SPEC["args"]) != 8:
        fails.append("args != a0-a7")
    if SPEC["gpr3"][4] != "a0":
        fails.append("gpr3 raw4 != a0")
    if SPEC["stubs"]["ret1"] != bytes.fromhex("01d2e0db"):
        fails.append("ret1 encoding drift")
    if SPEC["mem"]["modem_va"] != 0x90000000:
        fails.append("VA base drift")
    return fails


if __name__ == "__main__":
    import sys
    fails = check_spec()
    print("hw_target:", "PASS" if not fails else f"FAIL {fails}")
    print(f"language={SPEC['language_id']} cpu={SPEC['cpu']} "
          f"open_questions={len(SPEC['open_questions'])}")
    sys.exit(1 if fails else 0)
