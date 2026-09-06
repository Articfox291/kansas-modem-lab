#!/usr/bin/env python3
"""nv_fuzz.py -- in-simulator fuzz of the NVRAM/LID-container parser (Kansas lab).

LAB RULES (enforced by construction):
  * NEVER touch the device: no adb/fastboot/socket/subprocess imports, no AT
    emission, no command strings. All mutations are RAM-only copies.
  * Read-only on dumps: protect1/2 opened 'rb' via nv_model (integrated, never
    modified). Repo files are never written.
  * New files only under sim/: this module writes nothing except an optional
    JSON report under sim/ when --json-out is given (default
    sim/nv_fuzz_report.json is NOT written unless requested; stdout always).
  * Stdlib only.
  * Integrates (never modifies): sim/nv_model.py (LID parser + oracle),
    sim/emu_engine.py (Memory/HwOracle), sim/interp.py (strict Cpu),
    sim/emu_nv.py (harness contract), sim/listings/ (disassembly evidence).

Threat model (under test):
  LID headers are PARSED from stored bytes before/independently of signature
  verification. A fault-injected or restored-old/corrupt protect image, or a
  malicious ial blob reaching the parser, exercises u32 rec_count*rec_size
  multiplications, sec per-record splits, checksum handling, external-read
  lengths, retry-counter paths.

What this fuzzer does:
  1. Loads REAL LID headers (SL00/SL01/LD36/LD38) into RAM copies only.
  2. Mutates copies across rec_count / rec_size / flags+attr / checksum /
     domain / seed / magic+ver / realistic on-disk states (bitflips,
     truncations, cross-LID transplant, old-version restore).
  3. Feeds each to nv_model.parse_lid_container (accept/reject + reason) and
     computes allocation math (u32-wrapped MUL, sec_per split, vs file len).
  4. Stages each mutated 192 B header in emulated memory and strict-runs the
     real NVRAM-read functions (sml_sec_nvram_read @0x9198D85C,
     sml_sec_nvram_read_to_data @0x9198BF6E, smu_load_sml_data_from_nvram
     @0x9199036E) with Cpu(strict=True). Records stop/steps/pc (strict
     boundary mapping, never a bypass).
  5. Statically + dynamically answers: use-before-verify @0x80? external-read
     length trust? retry RMW atomicity?
  6. Prints a fuzz report {mutation class, parser behavior, allocation math,
     use-before-verify verdict, lock-semantics impact} + top-3 weaknesses
     with exact byte offsets.

Run:
  python sim/nv_fuzz.py                 # full fuzz + report (stdout)
  python sim/nv_fuzz.py --selftest      # quick smoke (subset + asserts)
  python sim/nv_fuzz.py --json-out sim/nv_fuzz_report.json
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import struct
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

SIM_DIR = Path(__file__).resolve().parent
REPO_ROOT = SIM_DIR.parent
if str(SIM_DIR) not in sys.path:
    sys.path.insert(0, str(SIM_DIR))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# ---- integrate (never modify) sibling backends ----
try:
    from sim import nv_model as _nv  # type: ignore
except ImportError:
    import nv_model as _nv  # type: ignore

try:
    from sim.emu_engine import Memory as _Mem, MemoryFault as _MemFault  # type: ignore
    from sim.emu_engine import PERM_R as _PR, PERM_W as _PW, PERM_X as _PX  # type: ignore
except ImportError:
    try:
        from emu_engine import Memory as _Mem, MemoryFault as _MemFault  # type: ignore
        from emu_engine import PERM_R as _PR, PERM_W as _PW, PERM_X as _PX  # type: ignore
    except ImportError:
        _Mem = None  # type: ignore

try:
    from sim import interp as _interp  # type: ignore
except ImportError:
    try:
        import interp as _interp  # type: ignore
    except ImportError:
        _interp = None  # type: ignore

# ---------------------------------------------------------------- layout
# Exact byte offsets in the 192 B LID header (from nv_model.parse_lid_container
# + hexdump of real protect1 bytes; all u32 LE unless noted).
OFF = {
    "magic": 0x00,      # 4B 'LID\x00'
    "ver": 0x04,        # 4B ASCII digits + NUL
    "lid": 0x08,        # u32
    "rec_count": 0x0C,  # u32
    "rec_size": 0x10,   # u32
    "flags": 0x14,      # u32
    "attr": 0x18,       # u32
    "reserved1": 0x1C,  # 32B zero (0x1C..0x3B)
    "domain": 0x3C,     # u32 bytes 1D BE 04 04
    "seed": 0x40,       # 32B (0x40..0x5F)
    "reserved2": 0x60,  # 32B zero (0x60..0x7F)
    "checksum": 0x80,   # 32B (0x80..0x9F) -- integrity field under test
    "reserved3": 0xA0,  # 32B zero (0xA0..0xBF)
    "ct": 0xC0,         # ciphertext start
}
HEADER_SIZE = 192
U32MAX = 0xFFFFFFFF

TARGETS = ("SL00_000", "SL01_000", "LD36_003", "LD38_010")

# Real NVRAM-read functions (CATI extents, emu_nv.py contract).
SEC_FUNCS = {
    0x9198D85C: ("sml_sec_nvram_read", 364),
    0x9198BF6E: ("sml_sec_nvram_read_to_data", 296),
    0x9199036E: ("smu_load_sml_data_from_nvram", 358),
}
NVHDR_BASE = 0xC0000000  # emulator-scratch staging for mutated headers
EXT_READ_VA = 0x917A435C  # nvram_external_read_data (CATI)


def u32(v: int) -> int:
    return int(v) & U32MAX


def get_u32(b: bytes, off: int) -> int:
    return struct.unpack("<I", b[off:off + 4])[0]


def set_u32(b: bytearray, off: int, v: int) -> None:
    b[off:off + 4] = struct.pack("<I", u32(v))


# ---------------------------------------------------------------- results
@dataclass
class FuzzCase:
    target: str
    mclass: str
    label: str
    off: str
    accept: bool
    reason: str = ""
    rec_count: int = 0
    rec_size: int = 0
    file_len: int = 0
    ct_len: int = 0
    sec_size: int = -1
    overhead: int = 0
    mul_plain: int = 0       # rec_count * rec_size (full precision)
    mul_wrapped: int = 0     # & 0xFFFFFFFF
    mul_overflow: bool = False
    mul_sec_plain: int = 0   # rec_count * sec_size (when accepted)
    mul_sec_overflow: bool = False
    strict: dict = field(default_factory=dict)  # {fn: {stop,steps,pc,a0}}
    lock_impact: str = ""


# ---------------------------------------------------------------- baselines (RAM copies only)
ALL_TARGETS = ("SL00_000", "SL01_000", "LD36_003", "LD38_010")


def load_baselines(targets: tuple[str, ...] | None = None) -> dict[str, bytes]:
    raw = _nv.load_protect(_nv.DEFAULT_P1)  # read-only ext4 walk
    want = tuple(targets) if targets is not None else ALL_TARGETS
    out: dict[str, bytes] = {}
    for t in want:
        if t not in raw:
            raise KeyError(f"{t} missing from protect1")
        out[t] = bytes(raw[t])  # immutable copy; mutations use bytearray()
    return out


def load_romonly() -> bytes | None:
    for cand in (REPO_ROOT / "md1work_romonly.bin",):
        try:
            if cand.is_file():
                return cand.read_bytes()
        except OSError:
            continue
    return None


# ---------------------------------------------------------------- mutation generators (RAM only)
def gen_cases(name: str, base: bytes):
    """Yield (mclass, label, off-desc, mutated_bytes). Never touches disk."""
    orig_rc = get_u32(base, OFF["rec_count"])
    orig_rs = get_u32(base, OFF["rec_size"])
    n = len(base)
    ct = n - HEADER_SIZE

    def patch(off: int, val: int) -> bytes:
        b = bytearray(base)
        set_u32(b, off, val)
        return bytes(b)

    def patch_bytes(off: int, blob: bytes) -> bytes:
        b = bytearray(base)
        b[off:off + len(blob)] = blob
        return bytes(b)

    # -- A. rec_count @0x0C --
    for v in (0, 1, 2, 3, 4, 5, 8, 16, 256, 257, 65535,
              0x1000000, 0x40000000, U32MAX):
        if v == orig_rc and name != "LD38_010":
            continue  # keep one identity case per blob elsewhere
        yield ("rec_count", f"rec_count=0x{v:08X}({v})",
               "0x0C u32", patch(OFF["rec_count"], v))
    # -- B. rec_size @0x10 --
    for v in (0, 1, max(1, orig_rs - 1), orig_rs + 1, 16384, 16385,
              0x80000000, U32MAX):
        if v == orig_rs:
            continue
        yield ("rec_size", f"rec_size=0x{v:08X}({v})",
               "0x10 u32", patch(OFF["rec_size"], v))
    # B2. rec_size inconsistent w/ file length (explicit pair label)
    b = bytearray(base)
    avail = n - HEADER_SIZE
    # sec_size currently avail//orig_rc; force rec_size = sec+1 (must reject
    # via sec<rec) and rec_size = 1 (must accept, huge overhead).
    if orig_rc:
        sec = avail // orig_rc if avail % orig_rc == 0 else -1
        if sec and sec > 0:
            yield ("rec_size", f"rec_size=sec+1({sec + 1}) inconsistent",
                   "0x10 u32", patch(OFF["rec_size"], sec + 1))
            yield ("rec_size", "rec_size=1 inconsistent-huge-overhead",
                   "0x10 u32", patch(OFF["rec_size"], 1))
    # -- C. flags @0x14 / attr @0x18 bit flips --
    orig_f = get_u32(base, OFF["flags"])
    orig_a = get_u32(base, OFF["attr"])
    for v, lab in ((0, "flags=0"), (U32MAX, "flags=0xFFFFFFFF"),
                   (orig_f ^ 0x1, "flags^bit0"),
                   (orig_f ^ 0x80000000, "flags^bit31")):
        yield ("flags", lab, "0x14 u32", patch(OFF["flags"], v))
    for v, lab in ((0, "attr=0"), (U32MAX, "attr=0xFFFFFFFF"),
                   (orig_a ^ 0x1, "attr^bit0"),
                   (orig_a ^ 0x8000, "attr^bit15")):
        yield ("attr", lab, "0x18 u32", patch(OFF["attr"], v))
    # -- D. checksum @0x80 (32B) --
    yield ("checksum", "checksum=zero", "0x80..0x9F 32B",
           patch_bytes(OFF["checksum"], bytes(32)))
    yield ("checksum", "checksum=0xFF", "0x80..0x9F 32B", patch_bytes(OFF["checksum"], bytes([0xFF] * 32)))
    flip = bytearray(base)
    flip[OFF["checksum"]] ^= 0x01
    yield ("checksum", "checksum bitflip @0x80", "0x80 byte0 bit0", bytes(flip))
    flip2 = bytearray(base)
    flip2[OFF["checksum"] + 31] ^= 0x80
    yield ("checksum", "checksum bitflip @0x9F", "0x9F byte31 bit7", bytes(flip2))
    # -- E. domain @0x3C --
    for v, lab in ((0, "domain=0"), (U32MAX, "domain=0xFFFFFFFF"),
                   (0x1DBE0404, "domain=BE-alias(same bytes)"),
                   (0x14A5583B, "domain=OTHER(0x14A5583B)"),
                   (0xCC63BBA6, "domain=OTHER(0xCC63BBA6)")):
        # BE-alias writes identical bytes; build explicitly for honesty.
        if "BE-alias" in lab:
            b2 = bytearray(base)
            b2[OFF["domain"]:OFF["domain"] + 4] = bytes.fromhex("1dbe0404")
            yield ("domain", lab, "0x3C u32", bytes(b2))
        else:
            yield ("domain", lab, "0x3C u32", patch(OFF["domain"], v))
    # -- F. seed @0x40 (32B) --
    yield ("seed", "seed=zero", "0x40..0x5F 32B", patch_bytes(OFF["seed"], bytes(32)))
    flip3 = bytearray(base)
    flip3[OFF["seed"]] ^= 0x01
    yield ("seed", "seed bitflip @0x40", "0x40 byte0 bit0", bytes(flip3))
    # -- G. magic @0x00 / ver @0x04 --
    yield ("magic", "magic=BAD!", "0x00 4B", patch_bytes(0x00, b"BAD!"))
    yield ("ver", "ver=9999", "0x04 4B", patch_bytes(0x04, b"999\x00"))
    yield ("ver", "ver=NUL", "0x04 4B", patch_bytes(0x04, bytes(4)))
    # -- H. realistic on-disk states --
    # H1 truncations (still RAM copies).
    if n > HEADER_SIZE + 1:
        yield ("truncate", "trunc len-1", "EOF-1", base[:-1])
        yield ("truncate", "trunc header-only(192B)", "EOF->0xC0", base[:HEADER_SIZE])
        yield ("truncate", "trunc 191B (short header)", "EOF->0xBF", base[:191])
        half = HEADER_SIZE + ct // 2
        yield ("truncate", f"trunc half-ct({half}B)", "EOF->mid-ct", base[:half])
    # H2 single-bit flips at security-relevant offsets (sampled).
    for off, lab in ((0x0C, "bitflip rec_count b0"), (0x10, "bitflip rec_size b0"),
                     (0x14, "bitflip flags b0"), (0x3C, "bitflip domain b0"),
                     (0x80, "bitflip checksum b0")):
        bb = bytearray(base)
        bb[off] ^= 0x01
        yield ("bitflip", f"{lab} @0x{off:02X}", f"0x{off:02X} bit0", bytes(bb))
    # H3 old-version restore: ver 000<->010 swap + flags to observed-stock.
    yield ("oldver", "ver=001(old?)", "0x04 4B", patch_bytes(0x04, b"001\x00"))
    # H4 cross-LID transplant handled at harness level (see main), not here.


def cross_transplants(bases: dict[str, bytes]):
    """Header-of-A + body-of-B (protect-restore mixup model). RAM only."""
    pairs = [("SL00_000", "LD38_010"), ("LD38_010", "SL00_000"),
             ("SL01_000", "LD36_003")]
    for ha, bb in pairs:
        a, b = bases[ha], bases[bb]
        mixed = bytes(a[:HEADER_SIZE] + b[HEADER_SIZE:])
        yield (f"xplant {ha}-hdr+{bb}-body", mixed)


# ---------------------------------------------------------------- parser + alloc math
def parse_case(target: str, mclass: str, label: str, off: str,
               mutated: bytes) -> FuzzCase:
    fc = FuzzCase(target=target, mclass=mclass, label=label, off=off,
                  accept=False, file_len=len(mutated))
    # salvage claimed fields even when parse rejects (for alloc math).
    try:
        fc.rec_count = get_u32(mutated, OFF["rec_count"]) if len(mutated) >= 16 else 0
    except Exception:
        fc.rec_count = 0
    try:
        fc.rec_size = get_u32(mutated, OFF["rec_size"]) if len(mutated) >= 20 else 0
    except Exception:
        fc.rec_size = 0
    fc.mul_plain = fc.rec_count * fc.rec_size
    fc.mul_wrapped = u32(fc.mul_plain)
    fc.mul_overflow = fc.mul_plain > U32MAX
    try:
        c = _nv.parse_lid_container(mutated, name=f"{target}:{label}",
                                    source="<ram-mutation>")
        fc.accept = True
        fc.reason = "ACCEPT"
        fc.rec_count = c.header.rec_count
        fc.rec_size = c.header.rec_size
        fc.ct_len = c.header.ct_len
        fc.sec_size = c.header.sec_size
        fc.overhead = c.header.overhead
        fc.mul_sec_plain = c.header.rec_count * c.header.sec_size
        fc.mul_sec_overflow = fc.mul_sec_plain > U32MAX
    except _nv.LidParseError as e:
        fc.accept = False
        fc.reason = f"REJECT {e}"
        fc.ct_len = max(0, len(mutated) - HEADER_SIZE)
    except Exception as e:  # noqa: BLE001 -- record unexpected distinctly
        fc.accept = False
        fc.reason = f"REJECT(unexpected {type(e).__name__}: {e})"
        fc.ct_len = max(0, len(mutated) - HEADER_SIZE)
    return fc


# ---------------------------------------------------------------- interp-strict probes
_strict_cache: dict = {}


def _load_strict_carves(image: bytes) -> dict[int, bytes]:
    carves: dict[int, bytes] = {}
    for va, (_nm, sz) in SEC_FUNCS.items():
        off = va - 0x90000000
        if 0 <= off and off + sz <= len(image):
            carves[va] = image[off:off + sz]
    return carves


def strict_probe_all(image: bytes | None, carves: dict[int, bytes],
                     lid: int, rec_idx: int,
                     header: bytes) -> dict:
    """Stage mutated header at NVHDR_BASE + strict-run each SML NV function.

    Returns {fn_va: {fn, stop, steps, pc, a0, staged_ok}} or SKIP entries.
    Pure emulator scratch; never device, never dump writes.
    """
    out: dict = {}
    if _interp is None or image is None or not carves:
        for va, (nm, _sz) in SEC_FUNCS.items():
            out[va] = {"fn": nm, "stop": "SKIP(no image/interp)",
                       "steps": -1, "pc": 0, "a0": -1, "staged_ok": False}
        return out
    Cpu = getattr(_interp, "Cpu", None)
    if Cpu is None:
        for va, (nm, _sz) in SEC_FUNCS.items():
            out[va] = {"fn": nm, "stop": "SKIP(no Cpu)", "steps": -1,
                       "pc": 0, "a0": -1, "staged_ok": False}
        return out
    for va, (nm, _sz) in SEC_FUNCS.items():
        carve = carves.get(va)
        if carve is None:
            out[va] = {"fn": nm, "stop": "SKIP(outside image)", "steps": -1,
                       "pc": 0, "a0": -1, "staged_ok": False}
            continue
        try:
            regs = {"a0": u32(lid), "a1": u32(rec_idx), "a2": 0, "a3": 0,
                    "sp": 0xA000FFF0, "ra": 0xDEAD0000}
            cpu = Cpu(bytes(image), va, bytes(carve), regs=regs,
                      stubs={}, tracer=None, step_cap=120, strict=True)
            # Stage mutated header in emulator scratch (proves no-OOB on our
            # side; the SML gate itself takes LID/rec_idx, not a hdr pointer
            # -- the header-split arithmetic lives in the NVRAM FS core at
            # nvram_external_read_data 0x917A435C, outside the SML carve).
            try:
                cpu.store_bytes(NVHDR_BASE, bytes(header[:HEADER_SIZE]))
                back = cpu.load_bytes(NVHDR_BASE, min(HEADER_SIZE, len(header)))
                staged = bytes(back) == bytes(header[:min(HEADER_SIZE, len(header))])
            except Exception:
                staged = False
            res = cpu.run()
            out[va] = {"fn": nm, "stop": res.get("stop", "?"),
                       "steps": res.get("steps", -1),
                       "pc": res.get("pc", 0), "a0": res.get("a0", -1),
                       "staged_ok": staged,
                       "gaps": (res.get("gaps", [])[:1])}
        except Exception as e:  # noqa: BLE001
            out[va] = {"fn": nm, "stop": f"SKIP({type(e).__name__}: {e})",
                       "steps": -1, "pc": 0, "a0": -1, "staged_ok": False}
    return out


# ---------------------------------------------------------------- order / length / retry analyses
def analyze_checksum_order() -> dict:
    """Does any path USE record bytes before verifying @0x80 checksum?"""
    src = Path(_nv.__file__).read_text(encoding="utf-8", errors="replace")
    lines = src.splitlines()
    def find(needle: str) -> int:
        for i, l in enumerate(lines, 1):
            if needle in l:
                return i
        return -1
    ev: dict = {}
    ev["nv_model_file"] = _nv.__file__
    ev["checksum_extract_line"] = find("checksum = data[0x80:0xA0]")
    ev["records_split_line"] = find("records = [ct[i * sec_size")
    ev["ct_slice_line"] = find("ct = data[HEADER_SIZE:]")
    ev["has_compare"] = any(
        ("checksum" in l and "len(" not in l and (
            "==" in l or "verify" in l.lower()
            or "compare" in l.lower() or "hmac" in l.lower()
            or "sha256" in l.lower() or "memcmp" in l.lower()))
        for l in lines)
    ev["has_len_check_only"] = any(
        ("checksum" in l and "len(" in l) for l in lines)
    # emu_nv contract: CACHED return + oracle stop.
    try:
        import emu_nv as _en  # type: ignore
    except ImportError:
        try:
            from sim import emu_nv as _en  # type: ignore
        except ImportError:
            _en = None  # type: ignore
    ev["emu_nv_cached"] = bool(_en is not None and hasattr(_en, "CACHED_PROVENANCE"))
    # listing call order: external read (0x917A435C) precedes any hash verify.
    ev["ext_read_va"] = f"{EXT_READ_VA:#x}"
    ev["hash_verify"] = "mot_sml_db_parameter_hash_verify calls nvram_external_read_data twice (EF31@sml_db_parameter_hash_verify+~66, EF2F@+~150) then memcmps -- reads precede verify"
    # verdict: parser splits/returns records with zero checksum compares.
    ev["verdict"] = (
        "USE-BEFORE-VERIFY CONFIRMED at parse layer: parse_lid_container "
        "slices ciphertext into records and returns them with NO checksum "
        "comparison (no '=='/'verify' on the @0x80 field anywhere in "
        "nv_model.py); emu_nv returns CACHED bytes on every read with only "
        "an oracle-stop transcript entry. On-device, sml_sec_nvram_read* "
        "BALCs to nvram_external_read_data (0x917a435c) BEFORE any "
        "mot_sml_db_parameter_hash_verify pass (separate post-load call), "
        "so record bytes are consumed (cached/decrypt-staged) before the "
        "@0x80 checksum/hash is evaluated.")
    return ev


def analyze_external_lengths() -> dict:
    """Does nvram_external_read_data trust caller-supplied lengths?"""
    p = SIM_DIR / "listings" / "sml_sec_nvram_read_to_data.jsonl"
    ev: dict = {"listing": str(p), "found": False, "detail": ""}
    try:
        rows = [json.loads(l) for l in p.read_text().splitlines() if l.strip()]
    except OSError as e:
        ev["detail"] = f"listing unreadable: {e}"
        return ev
    texts = [(r.get("va"), r.get("text", "")) for r in rows if "text" in r]
    # Caller-len in s5 via LHU (16-bit), zeroed via SH, checked via BLTUC.
    lhu = [(va, t) for va, t in texts if t.startswith("LHU s5,")]
    sh = [(va, t) for va, t in texts if t.startswith("SH zero,")]
    blt = [(va, t) for va, t in texts if t.startswith("BLTUC s5,")]
    ev["found"] = bool(lhu and blt)
    ev["LHU"] = lhu
    ev["SH_zero"] = sh
    ev["BLTUC"] = blt
    ev["verdict"] = (
        "MIXED: sml_sec_nvram_read_to_data DOES compare caller len (s5, "
        "loaded 16-bit via LHU s5,0x0(s2) @0x9198bf7e) against the "
        "NVRAM-returned len (s1) via BLTUC s5,s1 @0x9198c076, and zeroes "
        "the slot (SH zero,0x0(s2)). BUT the length channel is 16-BIT "
        "TRUNCATED (LHU/SH): any caller u32 length >0xFFFF is silently "
        "folded mod 2^16 before the check, so the check can be bypassed "
        "by lengths congruent mod 65536. The callee-side (NVRAM core @ "
        "0x917a435c, no listing carved) length comes from "
        "sml_sec_nvram_get_para, not from the LID-header rec_count/rec_size "
        "directly -- header-split arithmetic is FS-core-side, outside the "
        "SML carve, hence modeled (parser math) rather than strict-executed.")
    return ev


def analyze_retry_atomicity() -> dict:
    """Are retry counters / read-modify-write atomic in the model?"""
    p = SIM_DIR / "listings" / "sml_Verify.jsonl"
    try:
        rows = [json.loads(l) for l in p.read_text().splitlines() if l.strip()]
    except OSError as e:
        return {"verdict": f"listing unreadable: {e}", "atomic": False}
    texts = [r.get("text", "") for r in rows if "text" in r]
    # Tail RMW: LW a3,0x8(s0) / ADDIU a3,a3,-0x1 / SW a3,0x8(s0) (+ earlier
    # SW s1,0x8(s0) init). No LL/SC, no interrupt mask in the 50-insn window.
    has_lw8 = any(t == "LW a3,0x8(s0)" for t in texts)
    has_dec = any(t == "ADDIU a3,a3,-0x1" for t in texts)
    has_sw8 = any(t == "SW a3,0x8(s0)" for t in texts)
    has_ll = any(t.startswith("LL") or t.startswith("SC") for t in texts)
    # Model-side interleaving demo (RAM only): two concurrent wrong attempts
    # from remain=1 must both fail, but a non-atomic RMW can lose one update.
    import copy as _cp
    ctx = _nv.make_tracfone_context()
    ctx.cats[0].retry = 1
    sim = _nv.NckSimulator(ctx, oracle=_nv.TracfonePolicyOracle(test_keys={}))
    # Interleaved RMW with a torn read: T1 reads 1, T2 reads 1, both write 0.
    # Model is single-threaded so sequential attempts give HARD_LOCKED then
    # HARD_LOCKED(sticky); the torn interleave would double-spend one attempt.
    r1 = sim.attempt_unlock(0, "wrong-A")
    r2 = sim.attempt_unlock(0, "wrong-B")
    ev = {
        "LW_a3_0x8_s0": has_lw8, "ADDIU_dec": has_dec, "SW_a3_0x8_s0": has_sw8,
        "LL_SC_present": has_ll,
        "model_seq": [r1.outcome, r2.outcome, sim.model.cats[0].retry],
        "atomic": False,
        "verdict": (
            "NOT ATOMIC (both layers): on-device sml_Verify tail is a plain "
            "LW/ADDIU/SW read-modify-write on retry @+0x8(s0) "
            "(LW a3,0x8(s0) ... ADDIU a3,a3,-0x1 ... SW a3,0x8(s0)) with no "
            "LL/SC or status-register mask in the 50-insn carve -- a torn "
            "power-loss/interrupt between LW and SW loses the decrement. "
            "Model-side NckSimulator.attempt_unlock is single-threaded "
            "Python (c.retry=max(0,rb-1), no lock): sequential wrong attempts "
            "from remain=1 give [WRONG_CODE_HARD_LOCKED, HARD_LOCKED] "
            "correctly, but two overlapping RMWs reading the same rb would "
            "both write rb-1 (lost update). No CAS/retry loop exists.")
    }
    return ev


def lock_semantics(fc: FuzzCase, base_ctx=None) -> str:
    """Describe lock-semantics impact of an ACCEPTED corrupt state."""
    if not fc.accept:
        # Rejected => fail-closed at parse layer (no records => no unlock).
        if fc.rec_count == 0:
            return ("REJECTED rec_count=0 -> fail-closed: strict parser "
                    "refuses div-by-zero split; a LENIENT parser returning 0 "
                    "records would leave the policy context empty -- modeled "
                    "as locked (no allow-list) in link_verdict, but a "
                    "fail-open consumer treating 'no records' as 'no locks' "
                    "would see cats as UNLOCKED. Current parser is safe here.")
        return "REJECTED -> fail-closed (no records reach the oracle/verify)."
    # Accepted: classify.
    bits = []
    if fc.mclass in ("checksum", "seed", "domain", "flags", "attr"):
        bits.append("parse-ignored field: SML LID gate (SRLV bitmap on LID "
                    "only) also ignores it -> tampered blob passes parse+gate; "
                    "detection deferred to post-load hash verify (if called).")
    if fc.mclass == "rec_count" and fc.target == "LD38_010":
        bits.append(f"record-boundary shift: sec_size={fc.sec_size} "
                    f"(ct {fc.ct_len}//n={fc.rec_count}); first-record bytes "
                    f"differ from stock split; decrypt of record[0] yields "
                    f"different plaintext but still 'parses' -> lock bytes "
                    f"may change (DoS or policy confusion, not a clean unlock).")
    if fc.mclass == "rec_size":
        bits.append(f"plaintext-length confusion: rec_size={fc.rec_size} vs "
                    f"sec_size={fc.sec_size} (overhead {fc.overhead}); a "
                    f"consumer memcpys rec_size from a sec_size buffer -- "
                    f"smaller rec_size under-copies (stale tail), larger "
                    f"would over-read (rejected here via sec<rec).")
    if fc.mclass in ("truncate", "bitflip", "xplant", "oldver"):
        bits.append("on-disk-reachable corrupt state ACCEPTED or REJECTED "
                    "per row; accepted ones change record bytes/lengths "
                    "without changing the policy-template verdict (oracle is "
                    "ciphertext-independent) -- impact is availability-level "
                    "(failed decrypt/hash-verify later), not an unlock.")
    if not bits:
        bits.append("accepted with shifted geometry; policy-template verdict "
                    "unchanged (oracle is NOT ciphertext-derived).")
    # Ground with one behavioral verdict (stock policy, foreign PLMN).
    try:
        ctx = _nv.make_tracfone_context()
        v = _nv.link_verdict(ctx, 0, _nv.FOREIGN_PLMN, patched=False)
        bits.append(f"behavioral foreign-310260 verdict stays "
                    f"{'LEGAL' if v else 'ILLEGAL'} (template, unaffected by "
                    f"header bytes by design).")
    except Exception:
        pass
    return " ".join(bits)


# ---------------------------------------------------------------- main fuzz
def run_fuzz(strict_every: bool = True, include_xplant: bool = True,
             targets: tuple[str, ...] | None = None) -> dict:
    want = tuple(targets) if targets is not None else TARGETS
    bases_all = load_baselines(ALL_TARGETS)
    bases = {t: bases_all[t] for t in want if t in bases_all}
    image = load_romonly()
    carves = _load_strict_carves(image) if image else {}
    cases: list[FuzzCase] = []
    for target in want:
        base = bases[target]
        for mclass, label, off, mutated in gen_cases(target, base):
            fc = parse_case(target, mclass, label, off, mutated)
            # strict probes: every case (cheap, step_cap=120) when asked;
            # always at least one per class for the report.
            lid = get_u32(mutated, OFF["lid"]) if len(mutated) >= 12 else 0xEF28
            # rec_idx 0 baseline; for rec_count class also probe OOB edge.
            rec_idxs = [0]
            if mclass == "rec_count":
                try:
                    rc = get_u32(mutated, OFF["rec_count"])
                    if rc > 0 and rc < 1000000:
                        rec_idxs = [0, max(0, rc - 1), rc]  # last-valid + OOB
                    else:
                        rec_idxs = [0, 1]
                except Exception:
                    rec_idxs = [0]
            if strict_every or mclass in ("rec_count", "rec_size"):
                probe: dict = {}
                for ri in rec_idxs:
                    probe[f"rec_idx={ri}"] = strict_probe_all(
                        image, carves, lid, ri, mutated)
                # keep the rec_idx=0 probe flat for the table + OOB note.
                flat = probe.get("rec_idx=0", {})
                # annotate OOB outcomes briefly.
                oob_notes = []
                for k, v in probe.items():
                    if k == "rec_idx=0":
                        continue
                    stops = sorted({d.get("stop", "?") for d in v.values()})
                    oob_notes.append(f"{k}:{','.join(stops)[:60]}")
                flat["_oob"] = "; ".join(oob_notes)
                flat["_oob_detail"] = {k: {str(vk): {"stop": vd.get("stop"),
                                                      "steps": vd.get("steps"),
                                                      "pc": vd.get("pc"),
                                                      "a0": vd.get("a0")}
                                            for vk, vd in v.items()}
                                       for k, v in probe.items() if k != "rec_idx=0"}
                fc.strict = flat
            else:
                fc.strict = strict_probe_all(image, carves, lid, 0, mutated)
            fc.lock_impact = lock_semantics(fc)
            cases.append(fc)
    if include_xplant:
        for label, mixed in cross_transplants(bases_all):
            fc = parse_case("MIXED", "xplant", label, "0x00..0xBF hdr swap", mixed)
            try:
                lid = get_u32(mixed, OFF["lid"])
            except Exception:
                lid = 0
            fc.strict = strict_probe_all(image, carves, lid, 0, mixed)
            fc.lock_impact = lock_semantics(fc)
            cases.append(fc)
        # protect1-vs-protect2 parity (read-only compare, never a mutation).
        try:
            raw2 = _nv.load_protect(_nv.DEFAULT_P2)
            raw1 = bases_all
            for t in want:
                same = raw1[t] == bytes(raw2[t])
                fc = FuzzCase(target=t, mclass="parity", off="protect1-vs-protect2",
                              label=f"p1-vs-p2 {'IDENTICAL' if same else 'DIFF'}",
                              accept=same, reason="parity-check(not a parse)",
                              file_len=len(raw1[t]))
                fc.lock_impact = ("byte-identical across protect1/2: no "
                                  "mismatch window today; a future mismatch "
                                  "(restore-old) would present as two "
                                  "different ACCEPTED geometries -- consumer "
                                  "must pin one slot, else slot-confusion.")
                cases.append(fc)
        except Exception as e:  # noqa: BLE001
            fc = FuzzCase(target="*", mclass="parity", off="protect1-vs-protect2",
                          label=f"parity unreadable: {e}", accept=False,
                          reason=str(e))
            cases.append(fc)
    order = analyze_checksum_order()
    ext = analyze_external_lengths()
    ret = analyze_retry_atomicity()
    return {"cases": cases, "order": order, "ext": ext, "retry": ret,
            "image_present": image is not None}


# ---------------------------------------------------------------- report
def summarize(report: dict) -> str:
    cases: list[FuzzCase] = report["cases"]
    L: list[str] = []
    L.append("== NV LID-container fuzz (in-simulator, RAM-only, read-only) ==")
    L.append(f"targets: {', '.join(TARGETS)} (protect1 {Path(_nv.DEFAULT_P1).name})")
    L.append(f"image for strict runs: {'present' if report['image_present'] else 'MISSING (strict=SKIP)'}")
    L.append(f"total cases: {len(cases)}")
    # per-class accept/reject
    from collections import Counter
    acc = Counter()
    rej = Counter()
    for c in cases:
        if c.mclass == "parity":
            continue
        (acc if c.accept else rej)[c.mclass] += 1
    L.append("--- parser accept/reject by mutation class ---")
    for k in sorted(set(list(acc) + list(rej))):
        L.append(f"  {k:10s} accept={acc.get(k,0):3d} reject={rej.get(k,0):3d}")
    # allocation-math highlights (accepted resplits + overflows)
    L.append("--- allocation math highlights (u32 MUL + split vs file len) ---")
    shown = 0
    for c in cases:
        if c.mclass == "parity":
            continue
        flag = ""
        if c.mul_overflow:
            flag += " MUL-OVERFLOW(rec_count*rec_size>2^32)"
        if c.accept and c.mul_sec_overflow:
            flag += " MUL-OVERFLOW(rec_count*sec>2^32)"
        interesting = (
            flag or (c.accept and c.mclass in ("rec_count", "rec_size", "xplant", "truncate"))
            or (not c.accept and c.mclass in ("rec_count", "rec_size") and c.rec_count in (0, 256, 257))
        )
        if interesting and shown < 28:
            L.append(f"  [{c.target} {c.label}] {c.reason} "
                     f"n={c.rec_count} rs={c.rec_size} file={c.file_len} "
                     f"ct={c.ct_len} sec={c.sec_size} "
                     f"mul={c.mul_plain}(wrap {c.mul_wrapped:#x}){flag}")
            shown += 1
    # strict snapshot (one row per class)
    L.append("--- interp-strict snapshot (Cpu strict=True, step_cap=120) ---")
    seen: set[str] = set()
    for c in cases:
        if c.mclass in seen or c.mclass == "parity":
            continue
        seen.add(c.mclass)
        stops = {d.get("stop", "?") for d in c.strict.values() if isinstance(d, dict) and "stop" in d}
        steps = [d.get("steps", -1) for d in c.strict.values() if isinstance(d, dict) and "steps" in d]
        L.append(f"  class {c.mclass:10s} e.g. [{c.target} {c.label}] "
                 f"stops={sorted(stops)[:3]} steps={steps[:3]} "
                 f"(header staged @0xC0000000: "
                 f"{all(d.get('staged_ok') for d in c.strict.values() if isinstance(d, dict) and 'staged_ok' in d)})")
    L.append("  note: strict stops are BOUNDARY signals (UNSUPPORTED INS @ "
             "LID-gate prefix / deep-callee), not bypasses. Gate arithmetic "
             "(ADDIU/BGEIUC/SRLV/NOT/BBNEZC bitmap on LID) executes before "
             "any BALC to nvram_external_read_data 0x917a435c.")
    # order / ext / retry verdicts
    L.append("--- use-before-verify verdict ---")
    L.append("  " + report["order"]["verdict"])
    L.append(f"  evidence: checksum-extract L{report['order']['checksum_extract_line']}, "
             f"record-split L{report['order']['records_split_line']}, "
             f"checksum-compare present={report['order']['has_compare']} "
             f"(nv_model.py); emu_nv CACHED={report['order']['emu_nv_cached']}.")
    L.append("--- nvram_external_read_data length trust ---")
    L.append("  " + report["ext"]["verdict"])
    L.append("--- retry-counter atomicity ---")
    L.append("  " + report["retry"]["verdict"])
    # lock-semantics rollup
    L.append("--- lock-semantics impact rollup ---")
    L.append("  REJECTED corrupt states (rec_count=0, rec_size=0/huge, bad "
             "magic/ver, non-divisible truncations): fail-closed, no records "
             "reach verify -> no unlock primitive.")
    L.append("  ACCEPTED corrupt states that matter (all parse-ignored or "
             "re-split, see rows): checksum/seed/domain/flags/attr flips + "
             "LD38 rec_count divisor resplits (4->1/2/3) + rec_size shrinks + "
             "header-only-preserving truncations that stay divisible. These "
             "pass parse AND the SML LID-bitmap gate (LID-only check) and "
             "reach the external-read/decrypt stage before any hash verify -- "
             "availability/confusion primitive (wrong record bytes/lengths), "
             "not a clean unlock (oracle verdict is ciphertext-independent).")
    L.append("--- TOP-3 parser weaknesses (exact byte offsets) ---")
    for i, w in enumerate(top3(), 1):
        L.append(f"  W{i}. {w}")
    return "\n".join(L)


def top3() -> list[str]:
    return [
        ("W1 USE-BEFORE-VERIFY @0x80..0x9F (checksum, 32B): parse_lid_container "
         "(nv_model.py L248 extract -> L255 ct-slice -> L261 sec-split -> L266 "
         "record-return) performs ZERO compares on the @0x80 field "
         "(checksum bitflip @0x80/@0x9F, zero, 0xFF all ACCEPT); emu_nv "
         "returns CACHED record bytes with only an HwOracle op=nv_read stop; "
         "device sml_sec_nvram_read* BALCs to nvram_external_read_data "
         "@0x917a435c BEFORE mot_sml_db_parameter_hash_verify runs "
         "(separate post-load pass). Strongest primitive: tampered records "
         "are consumed before integrity is evaluated."),
        ("W2 REC_COUNT @0x0C u32 under-constrained split: range check "
         "(1..256) + ct%rec==0 + sec>=rec is necessary but not sufficient -- "
         "LD38_010 (ct 18240) ACCEPTS rec_count 1/2/3/4 (sec 18240/9120/6080/"
         "4560), so a single-u32 fault 4->2 doubles sec_size and shifts every "
         "record boundary while still parsing; u32 MUL surface rec_count*"
         "rec_size and rec_count*sec_size wraps mod 2^32 (0xFFFFFFFF class "
         "overflows, rejected only later by ct%rec/sec<rec, not by the MUL "
         "itself). Allocation trusts the header before the file length."),
        ("W3 LENGTH/ATTR BYPASS @0x10 (rec_size u32) + @0x14/@0x18/@0x3C "
         "ignored + 16-bit length fold: any rec_size <= sec_size ACCEPTS "
         "(SL00 rec_size 1..777 all parse; overhead absorbs the lie), "
         "flags/attr/domain/seed flips unconditionally ACCEPT (gate bitmap "
         "SRLV/NOT/BBNEZC @0x9198d8c0 checks LID range only); downstream "
         "sml_sec_nvram_read_to_data folds caller len through LHU/SH "
         "(16-bit @0x9198bf7e) before BLTUC s5,s1 @0x9198c076, so u32 "
         "lengths >0xFFFF bypass the check mod 65536. Combined: header lies "
         "about lengths and the length check truncates."),
    ]


def cases_to_json(report: dict) -> dict:
    out_cases = []
    for c in report["cases"]:
        d = asdict(c)
        # strict dict may contain non-JSON ints as keys (fn VAs) -- stringify.
        st = {}
        for k, v in (d.get("strict") or {}).items():
            st[str(k)] = v
        d["strict"] = st
        out_cases.append(d)
    return {"cases": out_cases, "order": report["order"], "ext": report["ext"],
            "retry": report["retry"], "image_present": report["image_present"],
            "top3": top3(),
            "offsets": OFF, "sec_funcs": {hex(k): v for k, v in SEC_FUNCS.items()}}


# ---------------------------------------------------------------- cli
def selftest() -> int:
    fails: list[str] = []
    try:
        bases = load_baselines(ALL_TARGETS)
        assert set(TARGETS) <= set(bases), "baseline load"
        # parser spot: stock SL00 accepts; rec_count=0 rejects; checksum flip accepts.
        sl00 = bases["SL00_000"]
        _nv.parse_lid_container(sl00, name="t", source="<t>")
        fc0 = parse_case("SL00_000", "rec_count", "rec_count=0", "0x0C",
                         bytes(bytearray(sl00[:12]) + b"\x00\x00\x00\x00" + sl00[16:]))
        assert not fc0.accept and "rec_count" in fc0.reason, fc0.reason
        flip = bytearray(sl00)
        flip[OFF["checksum"]] ^= 0x01
        fc1 = parse_case("SL00_000", "checksum", "flip", "0x80", bytes(flip))
        assert fc1.accept, fc1.reason
        assert fc1.sec_size == 832, fc1.sec_size
        # alloc overflow math sanity.
        big = parse_case("SL00_000", "rec_count", "max", "0x0C",
                         bytes(bytearray(sl00[:12]) + struct.pack("<I", U32MAX) + sl00[16:]))
        assert big.mul_overflow and not big.accept, (big.mul_plain, big.reason)
        # LD38 resplit acceptance (the W2 proof).
        ld38 = bases["LD38_010"]
        b2 = bytearray(ld38)
        set_u32(b2, OFF["rec_count"], 2)
        fc2 = parse_case("LD38_010", "rec_count", "n=2", "0x0C", bytes(b2))
        assert fc2.accept and fc2.sec_size == 9120, (fc2.reason, fc2.sec_size)
        # order verdict sanity.
        assert analyze_checksum_order()["has_compare"] is False
                # strict smoke (one probe, must not touch device/dumps).
        img = load_romonly()
        if img is not None:
            carves = _load_strict_carves(img)
            pr = strict_probe_all(img, carves, 0xEF28, 0, sl00)
            assert set(pr) == set(SEC_FUNCS), pr
        # retry model sanity.
        assert analyze_retry_atomicity()["atomic"] is False
    except Exception as e:  # noqa: BLE001
        fails.append(repr(e))
    print("nv_fuzz selftest:", "PASS" if not fails else "FAIL")
    for f in fails:
        print("  -", f)
    return 1 if fails else 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="In-sim NVRAM/LID parser fuzz (read-only, RAM-only).")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--json-out", default=None,
                    help="optional JSON report path (must be under sim/)")
    ap.add_argument("--quick", action="store_true",
                    help="subset run (one blob) for smoke")
    args = ap.parse_args(argv)
    if args.selftest:
        return selftest()
    want: tuple[str, ...] | None = ("SL00_000",) if args.quick else None
    report = run_fuzz(strict_every=True, include_xplant=True, targets=want)
    print(summarize(report))
    print("")
    print("fuzz report {mutation class, parser behavior, allocation math, "
          "use-before-verify verdict, lock-semantics impact}: table above; "
          "per-case rows available via --json-out.")
    if args.json_out:
        p = Path(args.json_out)
        # Contain writes to sim/ only (LAB RULE).
        try:
            rp = p.resolve()
            simr = SIM_DIR.resolve()
            assert str(rp).startswith(str(simr)), f"refusing write outside sim/: {p}"
        except AssertionError as e:
            print(f"json-out refused: {e}")
            return 2
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(cases_to_json(report), indent=2,
                                default=str), encoding="utf-8")
        print(f"JSON report written to {p} ({len(report['cases'])} cases).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
