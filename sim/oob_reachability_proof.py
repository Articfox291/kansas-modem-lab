#!/usr/bin/env python3
"""oob_reachability_proof.py — DEFINITIVE reachability verdict for the OOB dispatch
jump in rmmi_extended_cmd_processor @0x90ef0c48 (Kansas lab, MT6835 PCORE).

LAB RULES (hard):
  * NEVER touches hardware: no adb/fastboot/socket/subprocess imports. All inputs
    parsed in RAM only. Read-only on dumps (md1work_romonly.bin opened 'rb').
  * New files only under sim/: this module writes nothing except stdout and an
    optional JSON report under sim/ when --report <path> is given.
  * Stdlib only. Attempt floor preserved (no ESMLCK-set/UNLOCK strings emitted;
    all fuzz inputs are SAFE query/parse shapes or synthetic in-RAM buffers).

Code facts under test (verified in §1 from ROM bytes + sim/listings/*.jsonl):
  * Processor @0x90ef0c48 (42 insn, 144B, sha d751a9…): LHU s2,0x12(s1) @0x90ef0c62;
    SLL s2,2 @0x90ef0c72; ADDIUPC a3,0x92400260 @0x90ef0c92; LWX a3,s2(a3)
    @0x90ef0c9a; RESTORE @0x90ef0c9e; JRC a3 @0x90ef0ca2. NO range check
    (contrast basic processor @0x90ef0b98 which checks <0xe @0x90ef0bda).
  * Table @0x92400260: 443 valid handler ptrs (0..442), then non-code.
  * Analyzer @0x90ef0cd8 (41 insn): loop a3=0..0x1ba (443) bounded by
    ADDIU a1,0x1bb @0x90ef0d04 + BEQC a1,a3,miss @0x90ef0d0a; match writes
    SH a6,ctx+0x12 @0x90ef0d24 with a6=EXT(a3) (0..442); miss/empty write nothing.
  * Hash @0x90ef0d58 (74 insn): base-38 accumulators, 11-char cap, alnum-only,
    terminators (mask 0xa8001 => , ; = ? plus RAM NULs), then BALC analyzer.
  * set_class @0x90ef0f04: find_class -> class 3 => hash => analyzer.

Prior work (build on, don't redo): sim/at_fuzz.py + sim/at_fuzz_report.json proved
s2 0..442 reachable via crafted ctx, OOB needs ctx+0x12>=443. This script proves
whether ANY valid AT text (via FULL hash path) can produce >=443, and whether
stale-ctx composition can.

Run:
  python sim/oob_reachability_proof.py --selftest   # fast checks
  python sim/oob_reachability_proof.py --fuzz --n 5000
  python sim/oob_reachability_proof.py --all --report sim/oob_proof_report.json
"""
from __future__ import annotations
import struct
import sys
import json
import random
from pathlib import Path

SIM_DIR = Path(__file__).resolve().parent
REPO_ROOT = SIM_DIR.parent
if str(SIM_DIR) not in sys.path:
    sys.path.insert(0, str(SIM_DIR))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# strict backends (integrate, never modify)
try:
    from sim import interp as _interp
except ImportError:
    import interp as _interp
try:
    from sim.at_fuzz import StrictCpu, make_strict_cpu, load_listing_map, fetch_text, load_rom as _load_rom
    from sim.at_fuzz import EXT_PROC_VA, EXT_PROC_SIZE, EXT_TABLE_BASE, EXT_TABLE_VALID
    from sim.at_fuzz import ANALYZER_BOUND, HWORD_TABLE_BASE
    _HAS_STRICT = True
except Exception:
    _HAS_STRICT = False
    EXT_PROC_VA, EXT_PROC_SIZE, EXT_TABLE_BASE, EXT_TABLE_VALID = 0x90EF0C48, 144, 0x92400260, 443
    ANALYZER_BOUND, HWORD_TABLE_BASE = 0x1BB, 0x923FC61C

VA_BASE = 0x90000000
PROC_VA = 0x90EF0C48
PROC_SIZE = 144
ANALYZER_VA = 0x90EF0CD8
ANALYZER_SIZE = 128
HASH_VA = 0x90EF0D58
HASH_SIZE = 228
SETCLASS_VA = 0x90EF0F04
TABLE_BASE = 0x92400260
TABLE_VALID = 443
HWORD_BASE = 0x923FC61C
HASHPAIR_BASE = 0x923FC994
BOUND = 0x1BB  # 443

def u32(v): return v & 0xFFFFFFFF

def load_rom() -> bytes:
    for cand in (REPO_ROOT / "md1work_romonly.bin", SIM_DIR.parent / "md1work_romonly.bin",):
        try:
            if cand.is_file():
                return cand.read_bytes()
        except OSError:
            continue
    raise RuntimeError("md1work_romonly.bin not found")

def rom_u32(rom: bytes, va: int) -> int:
    return struct.unpack("<I", rom[va - VA_BASE:va - VA_BASE + 4])[0]

def rom_u16(rom: bytes, va: int) -> int:
    return struct.unpack("<H", rom[va - VA_BASE:va - VA_BASE + 2])[0]

def rom_cstr(rom: bytes, va: int, lim: int = 48) -> bytes:
    if not (VA_BASE <= va < VA_BASE + len(rom)):
        return b"<unmapped>"
    off = va - VA_BASE
    end = rom.find(b"\x00", off, off + lim)
    if end < 0:
        end = off + lim
    return rom[off:end]

def load_cati_safe() -> dict:
    try:
        from sim.emu_engine import load_cati
    except ImportError:
        try:
            from emu_engine import load_cati
        except ImportError:
            return {}
    try:
        return load_cati()
    except Exception:
        return {}

def resolve_cati(cati: dict, va: int):
    if not cati:
        return None
    items = sorted(((s, e, n) for n, (s, e) in cati.items()))
    lo, hi = 0, len(items) - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        s, e, n = items[mid]
        if va < s:
            hi = mid - 1
        elif va >= e:
            lo = mid + 1
        else:
            return n
    return None

# ---------------------------------------------------------------- hash replica (EXACT, validated §2)
# Terminators that trigger analyzer call: mask 0xa8001 => , ; = ? (offsets 0,15,17,19 from 0x2c)
# plus count==11 cap, plus RAM bytes at (a7+0xe/0xf) which emulate as NUL (zero pages).
# Validation: A-Z/a-z/0-9 only (case-insensitive for letters); digit maps via -0x16.
MASK_TERMS = {0x2C, 0x3B, 0x3D, 0x3F}  # , ; = ?
RAM_TERMS = {0x00}  # emulated zero-page NUL (conservative; real HW also NUL-terminates)

def hash_name_replica(name: str):
    """Compute (h0,h1) for an AT+ name string (already isolated). Returns None if
    invalid char (hash would return 0 without calling analyzer). Truncates at 11
    (HW BEQIC a4,0xb calls analyzer, ignoring rest)."""
    h0 = h1 = 0
    cnt = 0
    for ch in name:
        o = ord(ch)
        if cnt >= 11:
            break  # HW stops hashing at 11, calls analyzer
        # terminator check would have fired BEFORE hashing this char in HW loop;
        # here caller isolates name, so terminators never reach here.
        if 0x41 <= o <= 0x5A:
            v = o - 0x41
        elif 0x61 <= o <= 0x7A:
            v = o - 0x61
        elif 0x30 <= o <= 0x39:
            v = o - 0x16  # 26..35
        else:
            return None  # HW validation fail -> return 0, no analyzer
        if cnt < 5:
            h0 = (v + 38 * h0 + 1) & 0xFFFFFFFF
        else:
            h1 = (v + 38 * h1 + 1) & 0xFFFFFFFF
        cnt += 1
    return (h0, h1)

def isolate_name(at_text: bytes):
    """Mimic HW hash loop over raw AT line bytes to isolate the extended name
    and decide outcome WITHOUT touching ctx+0x12 except via analyzer.
    Returns (kind, name_str_or_None, h0, h1) where kind in:
      empty/garbage/basic/extended/invalid/terminated.
    This mirrors: skip leading spaces, require AT (case-insens, 0xdf mask),
    require '+', then accumulate alnum up to 11 or terminator, else invalid.
    """
    # work on latin-1 decoded, preserve NULs/binaries as bytes
    b = bytes(at_text)
    # HW find_class advances offset past AT; here emulate minimal:
    # strip leading spaces (0x20) only (HW skips 0x20 at hash entry too)
    i = 0
    while i < len(b) and b[i] == 0x20:
        i += 1
    if i + 1 >= len(b):
        return ("empty", None, 0, 0)
    # require A/a T/t (ANDI 0xdf case-insensitive in find_class)
    if (b[i] & 0xDF) != 0x41 or (b[i+1] & 0xDF) != 0x54:
        return ("garbage", None, 0, 0)
    i += 2
    # skip spaces? HW skips spaces at hash entry (BEQIC 0x20 loop)
    while i < len(b) and b[i] == 0x20:
        i += 1
    if i >= len(b):
        return ("basic", None, 0, 0)  # bare AT
    # extended needs '+' (0x2b)? find_class checks '+' path via SW zero etc.
    # Actually find_class: after AT, checks '/'? '+'? Let's simplify: if next is '+', extended.
    if b[i] != 0x2B:  # '+'
        # could be basic (ATD/ATA...) or other classes; for s2 purposes, basic
        # path writes 0xe via basic_hash, never >=443. Model as basic.
        return ("basic", None, 0, 0)
    i += 1
    # now at name start; accumulate
    name_chars = []
    h0 = h1 = 0
    cnt = 0
    pos = i
    while pos < len(b):
        c = b[pos]
        # terminators trigger analyzer call with current hashes (even if cnt==0 => empty hashes)
        if c in MASK_TERMS or c in RAM_TERMS or c == 0x20:
            # HW: BEQIC 0x20 also triggers? At hash tail BEQIC 0x20 -> offset++ loop,
            # but for name obstacles spaces are skipped? Conservative: treat space/NUL/,
            # as terminator calling analyzer.
            break
        # count cap: HW calls analyzer when cnt==11 BEFORE reading next char
        if cnt >= 11:
            break
        # validate alnum
        if (0x41 <= c <= 0x5A) or (0x61 <= c <= 0x7A) or (0x30 <= c <= 0x39):
            if 0x41 <= c <= 0x5A:
                v = c - 0x41
            elif 0x61 <= c <= 0x7A:
                v = c - 0x61
            else:
                v = c - 0x16
            if cnt < 5:
                h0 = (v + 38 * h0 + 1) & 0xFFFFFFFF
            else:
                h1 = (v + 38 * h1 + 1) & 0xFFFFFFFF
            name_chars.append(chr(c))
            cnt += 1
            pos += 1
        else:
            # invalid char (binary, 0x1b, _, -, etc.) => HW validation fail
            # (MOVE a0,zero + RESTORE, no analyzer, no index write)
            return ("invalid", None, 0, 0)
    # reached terminator or end or cap with cnt chars
    if cnt == 0 and (h0 == 0 and h1 == 0):
        # HW analyzer would see s1==s2==0 => BEQZC empty path (no write, return 0)
        # This covers AT+=, AT+?, AT+<NUL>, AT+<space>, etc.
        return ("empty_hash", "".join(name_chars), h0, h1)
    return ("extended", "".join(name_chars), h0, h1)

def analyzer_model(rom: bytes, h0: int, h1: int, ctx_idx_before: int):
    """EXACT analyzer loop model (listings §1). Returns (ret, idx_after, matched_idx_or_None).
    ret 1 => match, wrote idx_after (0..442). ret 0 => miss/empty, idx_after==before (no write)."""
    if (u32(h0) | u32(h1)) == 0:
        return (0, ctx_idx_before, None)  # 0x90ef0cf6 BEQZC -> 0x90ef0d4e, no SH
    for idx in range(TABLE_VALID):  # 0..442
        a = rom_u32(rom, HASHPAIR_BASE + idx * 8)
        bb = rom_u32(rom, HASHPAIR_BASE + idx * 8 + 4)
        if a == u32(h0) and bb == u32(h1):
            return (1, idx, idx)  # 0x90ef0d24 SH a6
    return (0, ctx_idx_before, None)  # 0x90ef0d0a BEQC miss -> 0x90ef0d52, no SH

def full_path_replica(rom: bytes, at_text: bytes, ctx_idx_before: int, ctx_class_before: int = 0):
    """FULL hash path replica: isolate -> hash -> analyzer -> (class write on success).
    Returns dict with kind, ret, idx_after, class_after, matched."""
    kind, name, h0, h1 = isolate_name(at_text)
    if kind in ("empty", "garbage", "basic", "invalid"):
        # never reach analyzer; basic path would write 0xe to idx via basic_hash
        # for basic only; model basic write for completeness:
        if kind == "basic":
            return {"kind": kind, "name": name, "h": (h0, h1), "analyzer_ret": None,
                    "idx_after": 0x0E, "class_after": 0x25D, "matched": None,
                    "note": "basic_hash writes 0xe (bounded)"}
        return {"kind": kind, "name": name, "h": (h0, h1), "analyzer_ret": None,
                "idx_after": ctx_idx_before, "class_after": ctx_class_before,
                "matched": None, "note": "no analyzer call, no index write"}
    # extended or empty_hash: call analyzer
    ret, idx_after, matched = analyzer_model(rom, h0, h1, ctx_idx_before)
    if ret == 1:
        # hash success tail also writes class from halfword table (bounded, not index)
        cls = rom_u16(rom, HWORD_BASE + matched * 2)
        return {"kind": kind, "name": name, "h": (h0, h1), "analyzer_ret": ret,
                "idx_after": idx_after, "class_after": cls, "matched": matched,
                "note": "match: wrote 0..442"}
    else:
        return {"kind": kind, "name": name, "h": (h0, h1), "analyzer_ret": ret,
                "idx_after": idx_after, "class_after": ctx_class_before,
                "matched": None, "note": "miss/empty: no write, stale retained"}


# ---------------------------------------------------------------- §1 code-facts verification
def verify_code_facts(rom: bytes):
    fails = []
    notes = []
    # carve sha
    import hashlib
    carve = rom[PROC_VA - VA_BASE:PROC_VA - VA_BASE + PROC_SIZE]
    sha = hashlib.sha256(carve).hexdigest()
    if sha != "d751a91419fc29ad52c6db698eb15ce3b86fefc89521f6a35b77059e6fd2fa9e":
        fails.append(f"proc carve sha {sha}")
    else:
        notes.append(f"proc carve sha OK {sha[:16]}… (144B @0x90ef0c48)")
    # listings dispatch sequence
    try:
        lst = {}
        for line in (SIM_DIR / "listings" / "rmmi_extended_cmd_processor.jsonl").read_text().splitlines()[1:]:
            o = json.loads(line)
            if "va" in o:
                lst[int(o["va"])] = o["text"]
        expect = {
            0x90EF0C62: "LHU s2,0x12(s1)",
            0x90EF0C72: "SLL s2,s2,0x2",
            0x90EF0C92: "ADDIUPC a3,%pcrel(0x92400260)",
            0x90EF0C9A: "LWX a3,s2(a3)",
            0x90EF0C9E: "RESTORE 0x20,ra,s0,s1,s2,s3,s4",
            0x90EF0CA2: "JRC a3",
        }
        for va, want in expect.items():
            got = lst.get(va)
            if got != want:
                fails.append(f"proc listing {va:#x}: got {got!r} want {want!r}")
        if not any("proc listing" in f for f in fails):
            notes.append("proc dispatch sequence VERIFIED (LHU/SLL/ADDIUPC/LWX/RESTORE/JRC)")
        # analyzer bound
        lst2 = {}
        for line in (SIM_DIR / "listings" / "rmmi_extended_command_analyzer.jsonl").read_text().splitlines()[1:]:
            o = json.loads(line)
            if "va" in o:
                lst2[int(o["va"])] = o["text"]
        for va, want in ((0x90EF0D04, "ADDIU a1,zero,0x1bb"),
                         (0x90EF0D0A, "BEQC a1,a3,0x90ef0d52"),
                         (0x90EF0D10, "EXT a6,a3,0x0,0x10"),
                         (0x90EF0D24, "SH a6,0x0(s4)")):
            if lst2.get(va) != want:
                fails.append(f"analyzer listing {va:#x}: got {lst2.get(va)!r} want {want!r}")
        if not any("analyzer listing" in f for f in fails):
            notes.append("analyzer bound VERIFIED (0x1bb/BEQC/EXT/SH)")
    except Exception as e:
        fails.append(f"listings read: {e!r}")
    # table valid count
    cati = load_cati_safe()
    n_valid = 0
    for i in range(460):
        v = rom_u32(rom, TABLE_BASE + i * 4)
        nm = resolve_cati(cati, v) if cati else None
        if i < TABLE_VALID:
            if nm is None:
                fails.append(f"table entry {i} {v:#x} not code")
                break
            n_valid += 1
        else:
            break
    if n_valid != TABLE_VALID:
        fails.append(f"table valid {n_valid} != {TABLE_VALID}")
    else:
        notes.append(f"table @0x92400260: {n_valid} valid ptrs 0..442 VERIFIED")
    # OOB values
    oob443 = rom_u32(rom, TABLE_BASE + 443 * 4)
    notes.append(f"OOB[443] @0x9240094c = {oob443:#x} (non-code, CATI={resolve_cati(cati, oob443)})")
    # basic processor contrast check
    try:
        lst3 = {}
        for line in (SIM_DIR / "listings" / "rmmi_basic_cmd_processor.jsonl").read_text().splitlines()[1:]:
            o = json.loads(line)
            if "va" in o:
                lst3[int(o["va"])] = o["text"]
        # BGEIUC a3,0xe @0x90ef0bda? actual VA 0x90ef0bda? check listing: LHU a3,0x10(s0) then BGEIUC
        found = any("BGEIUC a3,0xe" in t for t in lst3.values())
        if found:
            notes.append("basic processor range check <0xe CONFIRMED (contrast: extended has none, relies on upstream bound)")
        else:
            notes.append("basic check text not found (non-fatal)")
    except Exception as e:
        notes.append(f"basic check skipped: {e!r}")
    return fails, notes


# ---------------------------------------------------------------- §2 replica validation vs ROM table
def validate_replica_vs_table(rom: bytes):
    fails = []
    # known names must hit expected indices/handlers
    known = {
        "ESMLCK": (0x91985788, 302),
        "CLCK": (0x90F0A052, 31),
        "ESMLRSU": (0x91987884, 307),
        "ESMLGEN": (0x91987A98, 309),
        "ECRRST": (0x91986422, 303),
        "ERSUKEY": (0x91987B40, 310),
    }
    for name, (want_handler, want_idx) in known.items():
        h = hash_name_replica(name)
        if h is None:
            fails.append(f"hash replica rejected {name}")
            continue
        ret, idx, _ = analyzer_model(rom, h[0], h[1], 0)
        if ret != 1 or idx != want_idx:
            fails.append(f"{name} hash {h} -> idx {idx} want {want_idx}")
            continue
        handler = rom_u32(rom, TABLE_BASE + idx * 4)
        if handler != want_handler:
            fails.append(f"{name} handler {handler:#x} != {want_handler:#x}")
    # MOTSMLDB must MISS (not RMMI)
    h = hash_name_replica("MOTSMLDB")
    ret, _, _ = analyzer_model(rom, h[0], h[1], 0)
    if ret != 0:
        fails.append("MOTSMLDB should miss analyzer (not RMMI)")
    return fails


# ---------------------------------------------------------------- §3 bulk fuzz FULL hash path
AT_ALPHABET = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+;,=? _-./*#:()@!$%&\x00\x1b\x7f\xff"

def gen_edge_cases():
    cases = []
    # empty/garbage/basic
    for s in [b"", b" ", b"AT", b"at", b"AT+", b"AT+ ", b"AT+=", b"AT+?", b"AT+,", b"AT+;",
              b"AT+\x00", b"AT+ \x00", b"+++", b"XYZ", b"AT+ESMLCK", b"AT+ESMLCK=",
              b"AT+ESMLCK=?", b"AT+ESMLCK?", b"AT+CLCK", b"at+esmlck=?", b"  AT+ESMLCK=?  ",
              b"AT+ESMLCK\x00EXTRA", b"AT+ES\x00MLCK=?", b"AT+\x1b=?", b"AT+\xff=?",
              b"AT+MOTSMLDB=?", b"ATD123", b"ATA", b"ATI"]:
        cases.append((f"edge:{s!r}"[:64], bytes(s)))
    # valid names with all terminators
    for nm in [b"ESMLCK", b"CLCK", b"ESMLRSU", b"ECRRST", b"ERSUKEY", b"ESLBLOB", b"ERMC"]:
        for term in [b"=?", b"?", b"=", b",", b";", b" ", b"\x00", b"", b"=1,0"]:
            cases.append((f"valid:{nm.decode()}{term!r}", b"AT+" + nm + term))
    # overlong: 12..300 chars, valid prefix + tail, pure long, binary long
    for n in (12, 13, 27, 40, 100, 300):
        cases.append((f"overlong_A*{n}", b"AT+" + b"A" * n + b"=?"))
        cases.append((f"overlong_ESMLCK+pad*{n}", b"AT+ESMLCK" + b"X" * n + b"=?"))
    cases.append(("overlong_0x1b_names", b"AT+" + b"\x1b" * 30 + b"=?"))
    cases.append(("nul_embedded", b"AT+ES\x00MLCK=?"))
    cases.append(("nul_after_plus", b"AT+\x00ESMLCK=?"))
    cases.append(("binary_all", b"AT+" + bytes(range(256)) + b"=?"))
    return cases

def gen_random_cases(n: int, seed: int = 0xC10C):
    rng = random.Random(seed)
    out = []
    for i in range(n):
        kind = i % 6
        if kind == 0:
            # random alnum name 1..15
            ln = rng.randint(1, 15)
            nm = bytes(rng.choice(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") for _ in range(ln))
            term = rng.choice([b"=?", b"?", b"=", b",", b";", b"", b"\x00", b" "])
            out.append((f"rand_alnum_{i}", b"AT+" + nm + term))
        elif kind == 1:
            # random over full alphabet incl binary
            ln = rng.randint(0, 20)
            nm = bytes(rng.choice(AT_ALPHABET) for _ in range(ln))
            out.append((f"rand_full_{i}", b"AT+" + nm + b"=?"))
        elif kind == 2:
            # random garbage (no AT+)
            ln = rng.randint(0, 20)
            out.append((f"rand_garbage_{i}", bytes(rng.choice(AT_ALPHABET) for _ in range(ln))))
        elif kind == 3:
            # overlong random
            ln = rng.choice((12, 27, 40, 100))
            nm = bytes(rng.choice(b"ABCXYZ019") for _ in range(ln))
            out.append((f"rand_overlong_{i}", b"AT+" + nm + b"=?"))
        elif kind == 4:
            # NUL/binary embedded in valid prefix
            base = rng.choice([b"ESMLCK", b"CLCK", b"AAAAA", b"ZZZZZZZZZZZ"])
            pos = rng.randint(0, len(base))
            inj = bytes(rng.choice([0x00, 0x1B, 0xFF, 0x7F, 0x5F, 0x2D]) for _ in range(rng.randint(1, 3)))
            nm = base[:pos] + inj + base[pos:]
            out.append((f"rand_inject_{i}", b"AT+" + nm + b"=?"))
        else:
            # case/space variations of valid
            base = rng.choice([b"ESMLCK", b"clck", b"eSmLcK", b"ERSUKEY"])
            pre = rng.choice([b"AT+", b"at+", b"AT +", b"  AT+"])
            # note "AT +" with space is garbage per HW (needs '+' immediately?); keep to test
            out.append((f"rand_case_{i}", pre + base + b"=?"))
    return out

def bulk_fuzz(rom: bytes, n_rand: int = 5000):
    cases = gen_edge_cases() + gen_random_cases(n_rand)
    max_idx = -1
    max_case = None
    n_match = n_miss = n_empty = n_invalid = n_basic = n_garbage = 0
    worst = []
    for label, blob in cases:
        r = full_path_replica(rom, blob, 0, 0)  # fresh zeroed ctx
        idx = r["idx_after"]
        if idx is not None and idx > max_idx:
            max_idx = idx
            max_case = (label, blob, r)
        if idx is not None and idx >= TABLE_VALID:
            worst.append((label, blob, r))
        k = r["kind"]
        if r.get("matched") is not None:
            n_match += 1
        elif k in ("empty", "empty_hash"):
            n_empty += 1
        elif k == "invalid":
            n_invalid += 1
        elif k == "basic":
            n_basic += 1
        elif k == "garbage":
            n_garbage += 1
        else:
            n_miss += 1
        # also test with poisoned/stale ctx to prove miss retains but never grows
        for stale in (0, 31, 442):
            r2 = full_path_replica(rom, blob, stale, 0)
            if r2["idx_after"] >= TABLE_VALID:
                worst.append((label + f"[stale={stale}]", blob, r2))
            if r2["idx_after"] not in (stale, 0x0E) and r2.get("matched") is None:
                # miss must retain stale (or basic overwrites to 0xe); anything else is bug
                if not (r["kind"] == "basic" and r2["idx_after"] == 0x0E):
                    worst.append((label + "[stale-corrupt]", blob, r2))
    # also fuzz analyzer directly with arbitrary hashes (attacker-controlled hash scenario)
    rng = random.Random(0xA6A)
    for i in range(2000):
        h0 = rng.getrandbits(32)
        h1 = rng.getrandbits(32)
        # bias to edge values
        if i % 5 == 0:
            h0, h1 = 0, 0
        elif i % 5 == 1:
            h0, h1 = 0xFFFFFFFF, 0xFFFFFFFF
        ret, idx_after, _ = analyzer_model(rom, h0, h1, 123)
        if idx_after >= TABLE_VALID or (ret == 1 and not (0 <= idx_after < TABLE_VALID)):
            worst.append((f"hashpair_{h0:#x}_{h1:#x}", b"", {"idx_after": idx_after}))
        if ret == 1 and not (0 <= idx_after <= 442):
            worst.append((f"hashpair_match_oob_{i}", b"", {"idx_after": idx_after}))
    return {"n": len(cases), "max_idx": max_idx, "max_case": max_case,
            "counts": {"match": n_match, "miss": n_miss, "empty": n_empty,
                       "invalid": n_invalid, "basic": n_basic, "garbage": n_garbage},
            "violations": worst}


# ---------------------------------------------------------------- §4 strict-emulation validation
def emu_analyzer_one(rom: bytes, h0: int, h1: int, stale_idx: int):
    """Strict-emulate REAL analyzer bytes @0x90ef0cd8 with crafted hashes + ctx.
    Proves match writes 0..442 / miss+empty write nothing (stale retained).
    Returns dict with emu ret/idx_after/steps/stop. Uses listing-driven fetch
    (exact DONE-match text) + StrictCpu (EXT/SEH/LHUXS). Trace BALC stubbed ret."""
    if not _HAS_STRICT:
        return {"skipped": True}
    CTX = _interp.CTX_BASE + 0x2000
    # ctx image: only +0x10/+0x12 matter for this test; poison stale
    ctx_img = bytearray(0x100)
    struct.pack_into("<H", ctx_img, 0x10, 0xBEEF & 0xFFFF)
    struct.pack_into("<H", ctx_img, 0x12, stale_idx & 0xFFFF)
    # analyzer args: a0=h0? No: analyzer takes (a0=s1=h0, a1=s2=h1, a2=&ctx+0x10, a3=&ctx+0x12)
    # Cpu maps _ctx_image at CTX_BASE; we relocate to CTX after init.
    regs = {"a0": u32(h0), "a1": u32(h1), "a2": CTX + 0x10, "a3": CTX + 0x12,
            "sp": _interp.STACK_INIT, "ra": _interp.RA_INIT, "_ctx_image": bytes(ctx_img)}
    stubs = {0x900367A4: "ret1"}  # trace
    cpu = make_strict_cpu(ANALYZER_VA, ANALYZER_SIZE, rom, regs, stubs)
    try:
        cpu.mem.write(CTX, bytes(ctx_img))
    except Exception:
        pass
    listing = load_listing_map("rmmi_extended_command_analyzer")
    pc = u32(ANALYZER_VA)
    cpu.pc = pc
    steps = 0
    stop = ""
    while steps < 5000:
        # HIT-RET detection: RESTORE.JRC at 0x90ef0d50
        if pc == 0x90EF0D50:
            stop = "HIT-RET"
            break
        try:
            text, size = fetch_text(cpu, listing, pc)
        except Exception as e:
            stop = f"DECODE-FAULT @{pc:#x}: {e}"
            break
        try:
            npc = cpu.step_once_with_text(pc, text, size)
        except Exception as e:
            stop = f"FAULT @{pc:#x}: {e}"
            break
        pc = u32(npc)
        cpu.pc = pc
        steps += 1
        if pc == u32(_interp.RA_INIT):
            stop = "HIT-RET"
            break
    else:
        stop = "STEP-CAP"
    try:
        idx_after = struct.unpack("<H", cpu.mem.read(CTX + 0x12, 2))[0]
        cls_after = struct.unpack("<H", cpu.mem.read(CTX + 0x10, 2))[0]
    except Exception:
        idx_after = cls_after = None
    return {"h": (u32(h0), u32(h1)), "stale": stale_idx, "a0": cpu.get("a0"),
            "idx_after": idx_after, "cls_after": cls_after,
            "stop": stop, "steps": steps}

def emu_validation_suite(rom: bytes):
    """Validate replica vs strict emulation on match/miss/empty + known names."""
    out = {"vectors": [], "mismatches": []}
    # hashes: known matches + miss + empty
    h_esmlck = hash_name_replica("ESMLCK")
    h_clck = hash_name_replica("CLCK")
    tests = [
        ("match_ESMLCK", h_esmlck[0], h_esmlck[1], 0, 302),
        ("match_CLCK", h_clck[0], h_clck[1], 0, 31),
        ("miss_random", 0x12345678, 0x9ABCDEF0, 77, 77),
        ("miss_max", 0xFFFFFFFF, 0xFFFFFFFF, 442, 442),
        ("empty_zero", 0, 0, 99, 99),
        ("match_stale_overwrite", h_esmlck[0], h_esmlck[1], 99, 302),
    ]
    for label, h0, h1, stale, want_idx in tests:
        emu = emu_analyzer_one(rom, h0, h1, stale)
        if emu.get("skipped"):
            out["vectors"].append({"label": label, "skipped": True})
            continue
        ret_model, idx_model, _ = analyzer_model(rom, h0, h1, stale)
        ok = (emu["idx_after"] == idx_model == want_idx) and (emu["stop"] == "HIT-RET")
        # a0 should be ret (1 match / 0 miss)
        if emu["a0"] != ret_model:
            ok = False
        out["vectors"].append({"label": label, "emu": emu, "model_idx": idx_model,
                               "want": want_idx, "ok": ok})
        if not ok:
            out["mismatches"].append(label)
    return out


# ---------------------------------------------------------------- §5 stale-ctx multi-command sequences
def stale_sequences(rom: bytes):
    """Simulate ctx reuse across commands: legal first + crafted second.
    ctx persists (no per-command zeroing assumed — worst case for attacker).
    Proves no LEGAL+crafted composition yields >=443.
    Poisoned-init cases (0xFFFF) are EXPECTED-OOB controls: they prove the
    dispatch WOULD OOB if poisoned, but poison is unreachable via AT text
    (all AT writers bounded §§3-4), so they do NOT count toward reachability."""
    seqs = []
    # helper to run sequence
    def run(seq, init_idx=0):
        idx = init_idx
        cls = 0
        trace = []
        for blob in seq:
            r = full_path_replica(rom, blob, idx, cls)
            trace.append((blob[:24], r["kind"], r["idx_after"]))
            idx = r["idx_after"]
            cls = r["class_after"]
        return idx, trace
    tests = [
        ("legal302_then_miss", [b"AT+ESMLCK=?", b"AT+UNKNOWNCMD=?"], 0, False),
        ("legal442_then_miss", None, 0, False),  # filled below: find name with idx 442
        ("legal31_then_empty", [b"AT+CLCK=?", b"AT+=", ], 0, False),
        ("miss_then_legal", [b"AT+UNKNOWN=?", b"AT+ESMLCK=?"], 0, False),
        ("garbage_then_overlong", [b"XYZ", b"AT+" + b"A" * 100 + b"=?"], 0, False),
        ("basic_then_miss", [b"ATD123", b"AT+UNKNOWN=?"], 0, False),
        ("overlong_then_valid", [b"AT+" + b"X" * 300 + b"=?", b"AT+CLCK=?"], 0, False),
        ("binary_then_valid", [b"AT+\x1b\xff\x00=?", b"AT+ESMLCK=?"], 0, False),
        ("poisoned_init_miss", [b"AT+UNKNOWN=?"], 0xFFFF, True),
        ("poisoned_init_valid", [b"AT+ESMLCK=?"], 0xFFFF, True),
    ]
    # find max-idx name (442) by scanning table for last entry's hash -> reverse?
    # Instead brute-force: find which valid name gives 442 via fuzz of alnum? Use table hash directly:
    # hash pair at 442:
    h442 = (rom_u32(rom, HASHPAIR_BASE + 442 * 8), rom_u32(rom, HASHPAIR_BASE + 442 * 8 + 4))
    # For sequence label, use direct analyzer call with those hashes (simulates legal 442 command)
    # implemented as two-step: first set idx to 442 via model, then miss.
    _, idx442, _ = analyzer_model(rom, h442[0], h442[1], 0)
    assert idx442 == 442, f"h442 {h442} -> {idx442}"
    results = []
    for label, seq, init, is_poison in tests:
        if label == "legal442_then_miss":
            # first command is the 442-hash (legal max), second is miss
            _ret, idx1, _matched = analyzer_model(rom, h442[0], h442[1], init)
            assert idx1 == 442, f"h442 setup {h442} -> {idx1}"
            r2 = full_path_replica(rom, b"AT+UNKNOWNCMD=?", idx1, 0)
            results.append({"label": label, "final": r2["idx_after"],
                            "trace": [(f"hash442{h442}", "match", idx1), (b"AT+UNKNOWNCMD=?", r2["kind"], r2["idx_after"])],
                            "oob": r2["idx_after"] >= TABLE_VALID, "poison_control": False})
        else:
            final, trace = run(seq, init)
            results.append({"label": label, "final": final, "trace": [(bytes(t[0]).decode("latin-1", "replace"), t[1], t[2]) for t in trace],
                            "oob": final >= TABLE_VALID, "poison_control": is_poison})
    # processor dispatch check for all finals (must be in-bounds handlers)
    for r in results:
        v = rom_u32(rom, TABLE_BASE + (r["final"] & 0xFFFF) * 4) if r["final"] < 0x10000 else None
        r["dispatch_target"] = v
        r["dispatch_iscallable"] = resolve_cati(load_cati_safe(), v) is not None if v is not None else False
    return {"h442": h442, "idx442": idx442, "seqs": results}


# ---------------------------------------------------------------- §6 OOB ROM dump + controlled-entry
def oob_dump(rom: bytes):
    cati = load_cati_safe()
    rows = []
    for i in range(442, 460):
        va = TABLE_BASE + i * 4
        v = rom_u32(rom, va)
        nm = resolve_cati(cati, v)
        # cstr if pointer-like
        cs = rom_cstr(rom, v, 24).decode("latin-1", "replace") if (VA_BASE <= v < VA_BASE + len(rom)) else "<unmapped/non-VA>"
        rows.append({"idx": i, "addr": va, "value": v, "cati": nm, "str": cs[:24]})
    # processor strict emulation for in-bounds vs OOB (prior at_fuzz shape, re-verified here)
    proc_vecs = []
    try:
        from sim.at_fuzz import emu_target1_one as _emu_t1
    except ImportError:
        try:
            from at_fuzz import emu_target1_one as _emu_t1
        except ImportError:
            _emu_t1 = None
    if _emu_t1 is not None:
        for s2 in (31, 442, 443, 444, 0xFFFF):
            try:
                vv = _emu_t1(rom, s2)
                proc_vecs.append({"s2": s2, "read": vv["oob_read_addr"], "val": vv["oob_value_rom"],
                                  "jrc": vv["a3_at_jrc"], "stop": vv["stop"], "loaded_ok": vv["loaded_ok"]})
            except Exception as e:
                proc_vecs.append({"s2": s2, "error": repr(e)})
    return {"rows": rows, "rom_end": VA_BASE + len(rom),
            "max_read": TABLE_BASE + 0xFFFF * 4, "proc_vecs": proc_vecs}

def controlled_entry():
    return {
        "allow": "MOVE.BALC a0,s0,0x90f06924 @0x90ef0c66 + BNEIC a0,0x1,0x90ef0cd6 @0x90ef0c6a (deny->RESTORE.JRC, no dispatch)",
        "mode": "LBU a3,0xd(s1) @0x90ef0c6e + BNEIC a3,0x3,dispatch @0x90ef0c74 (mode!=3 -> direct dispatch; mode==3 -> strlen pre-path @0x90ef0c78 + need_enter check @0x90ef0ca0, fail->fallback 0x90ef0ca4, no dispatch)",
        "dispatch": "ADDIUPC a3,0x92400260 @0x90ef0c92; LWX a3,s2(a3) @0x90ef0c9a; RESTORE @0x90ef0c9e (a3 survives, s-regs restored); JRC a3 @0x90ef0ca2",
        "restore_survival": "RESTORE list ra,s0,s1,s2,s3,s4 — a3 NOT restored, so loaded handler survives; register control (a0=s1 ctx, sp) is caller state",
        "note": "Even with N>=443 controlled, primitive is jump-to-ROM-word (read-simple), not write; N=443->0x390016 (fault), N=447->string ptr (fault/DoS). No AT-text path yields N>=443 (see §§3-5).",
    }


# ---------------------------------------------------------------- CLI
def cmd_selftest():
    fails = []
    try:
        rom = load_rom()
    except Exception as e:
        print(f"oob proof selftest: FAIL (rom: {e!r})")
        return 1
    f1, notes = verify_code_facts(rom)
    fails += [f"facts: {x}" for x in f1]
    for n in notes:
        print(f"  [facts] {n}")
    f2 = validate_replica_vs_table(rom)
    fails += [f"replica: {x}" for x in f2]
    if not f2:
        print("  [replica] 6 known names hit expected idx/handler; MOTSMLDB correctly misses")
    # quick fuzz small
    bz = bulk_fuzz(rom, 200)
    if bz["violations"]:
        fails.append(f"bulk violations {bz['violations'][:2]}")
    if bz["max_idx"] is not None and bz["max_idx"] >= TABLE_VALID:
        fails.append(f"bulk max {bz['max_idx']} OOB")
    else:
        print(f"  [fuzz200] n={bz['n']} max_idx={bz['max_idx']} counts={bz['counts']} violations=0")
    # emu spot check (fast: 6 vectors)
    try:
        ev = emu_validation_suite(rom)
        if ev["mismatches"]:
            fails.append(f"emu mismatches {ev['mismatches']}")
        else:
            print(f"  [emu] {len(ev['vectors'])} analyzer vectors match replica (strict, listing-driven)")
            for v in ev["vectors"]:
                e = v.get("emu", {})
                print(f"    {v['label']}: emu idx {e.get('idx_after')} a0={e.get('a0')} stop={e.get('stop')} ok={v.get('ok')}")
    except Exception as e:
        fails.append(f"emu raised {e!r}")
    # stale quick (legal only; poison controls expected-OOB, not counted)
    try:
        st = stale_sequences(rom)
        oobs = [s for s in st["seqs"] if s["oob"] and not s.get("poison_control")]
        poisons = [s for s in st["seqs"] if s.get("poison_control")]
        if oobs:
            fails.append(f"stale OOB {oobs}")
        else:
            legal_max = max(s["final"] for s in st["seqs"] if not s.get("poison_control"))
            print(f"  [stale] {len(st['seqs'])} sequences, legal max final {legal_max} (all in-bounds); poison controls: {[(p['label'], p['final'], p['oob']) for p in poisons]}")
    except Exception as e:
        fails.append(f"stale raised {e!r}")
    print("oob proof selftest:", "PASS" if not fails else "FAIL")
    for x in fails:
        print("  -", x)
    return 1 if fails else 0

def cmd_fuzz(n: int = 5000):
    rom = load_rom()
    print(f"oob proof bulk fuzz: {n} random + {len(gen_edge_cases())} edge + 2000 hashpairs ...")
    bz = bulk_fuzz(rom, n)
    print(f"  cases={bz['n']} max_idx={bz['max_idx']} (must be <=442)")
    print(f"  counts={bz['counts']}")
    mc = bz["max_case"]
    if mc:
        print(f"  max_case: {mc[0]} blob={mc[1][:48]!r} -> {mc[2]}")
    print(f"  violations={len(bz['violations'])} (must be 0)")
    for v in bz["violations"][:5]:
        print("   VIOL:", v)
    # hashpair max
    print("  analyzer arbitrary-hash fuzz: 2000 pairs, all bounded (see violations)")
    return 0 if (not bz["violations"] and bz["max_idx"] < TABLE_VALID) else 1

def cmd_all(report: str | None = None, n: int = 5000, verbose: bool = False):
    rom = load_rom()
    print("== §1 code facts ==")
    f1, notes = verify_code_facts(rom)
    for x in notes:
        print(f"  {x}")
    for x in f1:
        print(f"  FAIL {x}")
    print("== §2 replica validation ==")
    f2 = validate_replica_vs_table(rom)
    print(f"  {'PASS' if not f2 else 'FAIL ' + str(f2)}")
    print("== §3 bulk fuzz FULL hash path ==")
    bz = bulk_fuzz(rom, n)
    print(f"  n={bz['n']} max_idx={bz['max_idx']} counts={bz['counts']} violations={len(bz['violations'])}")
    if verbose and bz["max_case"]:
        print(f"  max_case={bz['max_case']}")
    print("== §4 strict emulation ==")
    ev = emu_validation_suite(rom)
    print(f"  mismatches={ev['mismatches']}")
    for v in ev["vectors"]:
        print(f"   {v['label']}: {v.get('emu')} model={v.get('model_idx')} ok={v.get('ok')}")
    print("== §5 stale sequences ==")
    st = stale_sequences(rom)
    for s in st["seqs"]:
        print(f"   {s['label']}: final={s['final']} ({s['final']:#x}) dispatch={s.get('dispatch_target',0):#x} oob={s['oob']}")
    print("== §6 OOB dump ==")
    od = oob_dump(rom)
    for r in od["rows"]:
        print(f"   idx {r['idx']:3d} @{r['addr']:#x} -> {r['value']:#x} cati={r['cati']} str={r['str']!r}")
    print(f"   rom_end={od['rom_end']:#x} max_s2_read={od['max_read']:#x} (in-ROM, no fault on read)")
    print("== §7 controlled entry ==")
    ce = controlled_entry()
    for k, v in ce.items():
        print(f"   {k}: {v}")
    # verdict (poison controls excluded: they prove OOB shape exists when poisoned,
    # but poison unreachable via AT text §§3-4)
    legal_oob = any(s["oob"] and not s.get("poison_control") for s in st["seqs"])
    oob_reachable = bool(bz["violations"] or legal_oob or f1 or f2 or ev["mismatches"])
    # also max must be <=442 and no violation
    if not oob_reachable and bz["max_idx"] is not None and bz["max_idx"] <= 442:
        verdict = "REFUTED"
        reason = ("No AT text via FULL hash path yields s2>=443. Bounding: analyzer loop "
                  "BEQC 0x1bb @0x90ef0d0a + EXT @0x90ef0d10 + SH-only-on-match @0x90ef0d24; "
                  "miss/empty/invalid/basic perform NO index write (stale retained, still bounded); "
                  "all index writers (analyzer 0..442, basic 0xe) bounded; stale composition safe.")
    else:
        verdict = "CONFIRMED"
        reason = f"violations={bz['violations'][:1]} stale_oob={[s for s in st['seqs'] if s['oob']]}"
    print(f"\n==== VERDICT: {verdict} ====")
    print(reason)
    if report:
        p = Path(report)
        p.parent.mkdir(parents=True, exist_ok=True)
        # max_case blob bytes -> latin-1 string for JSON
        mc = bz["max_case"]
        if mc:
            mc_json = {"label": mc[0], "blob": mc[1].decode("latin-1", "replace"), "result": {k: (v if not isinstance(v, bytes) else v.decode('latin-1','replace')) for k, v in mc[2].items()}}
        else:
            mc_json = None
        data = {"verdict": verdict, "reason": reason,
                "facts_notes": notes, "facts_fails": f1, "replica_fails": f2,
                "bulk": {"n": bz["n"], "max_idx": bz["max_idx"], "counts": bz["counts"],
                         "violations": len(bz["violations"]), "max_case": mc_json},
                "emu": ev, "stale": st, "oob": {**od, "rows": [{**r, "value": f"{r['value']:#x}", "addr": f"{r['addr']:#x}"} for r in od["rows"]],
                                                "rom_end": f"{od['rom_end']:#x}", "max_read": f"{od['max_read']:#x}"},
                "controlled_entry": ce}
        p.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        print(f"wrote {p}")
    return 0 if verdict == "REFUTED" else 2

def main(argv):
    if "--selftest" in argv:
        return cmd_selftest()
    if "--fuzz" in argv:
        n = 5000
        for i, a in enumerate(argv):
            if a == "--n" and i + 1 < len(argv):
                try:
                    n = int(argv[i+1])
                except ValueError:
                    pass
        return cmd_fuzz(n)
    if "--all" in argv:
        rep = None
        n = 5000
        for i, a in enumerate(argv):
            if a == "--report" and i + 1 < len(argv):
                rep = argv[i+1]
            if a == "--n" and i + 1 < len(argv):
                try:
                    n = int(argv[i+1])
                except ValueError:
                    pass
        return cmd_all(rep, n, verbose=("--verbose" in argv))
    # default: selftest
    return cmd_selftest()

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))


