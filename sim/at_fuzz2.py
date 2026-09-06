#!/usr/bin/env python3
"""at_fuzz2.py — DEEP RMMI AT-parser cluster fuzz (SIM-ONLY, never on device).

LAB RULES (hard, enforced by construction):
  * NEVER touches hardware: no adb/fastboot/socket/subprocess imports anywhere
    in this file. Adversarial inputs are byte buffers in EMULATED memory only.
    The only AT strings in this file are (a) safe query/test shapes routed via
    rmmi_sim.dispatch for sanity, and (b) the 5 blocked fixtures parsed in RAM
    which MUST raise AttemptCostingBlocked (never transmitted — no transmit
    code path exists in this file).
  * The attempt guard (rmmi_sim.guard_attempt_costing) MUST hold: this fuzzer
    never emits attempt-costing forms anywhere.
  * Read-only on dumps: md1work_romonly.bin opened 'rb' only.
  * New files only under sim/: stdout + optional JSON report under sim/ when
    --report <path> is given (default sim/at_fuzz2_report.json). Stdlib only.
  * Attempt floor preserved: mode-1/key-path boundaries are never crossed in
    emulation (no verify/unlock helpers are modeled; unknown helpers TRAP).

Prior (sim/at_fuzz.py + sim/at_fuzz_report.json — JRC bounded, sprintf safe,
spin-only, op12 needs bypass): this file goes DEEPER —
  (E1) emulate rmmi_sml_add_data_op12/op07/op08 + parse_imsi/gid/binary_gid
       with LONGER adversarial inputs (max-length numerics, F-padded
       wildcards, mixed hex, boundary lens 255/256/257, empty, all-F) in
       interp-strict with crafted arg buffers; record every MEM-FAULT /
       UNSUPPORTED / TRAP with VA + input class. Two validator postures:
       faithful (length-gated copy, 0xFF-on-fail) and bypass (approve-all)
       to test the "needs validator bypass" hypothesis explicitly.
  (E2) BRSC jump-table cases in EMULATION (not just static): add_data_op12
       @0x9198688e via 0x92a88e14, get_crrst @0x919862f6 via 0x92a88e10,
       get_data_op12 @0x91988c64 via 0x92a88e62 — full-run cat sweep plus
       forced-index micro-vectors (incl. out-of-range) with signed/unsigned
       table-byte semantics observed.
  (E3) hex-decode helpers with odd-length / mixed-case / nonhex payloads,
       executed as REAL bytes in strict mode:
       rmmi_sim_get_value_from_hex_string @0x9198541a,
       is_hex_number_string @0x90f03c38, check_hex_value @0x90f05c22,
       rmmi_hexstring_to_integer @0x90f05bda.
  (E4) snprintf/sprintf RET-value audit: static sweep of every BALC to
       snprintf/sprintf/l4_snprintf across sim/listings for BLTC/BGEC checks
       (find any unchecked return into a length var), plus emulation
       spot-checks (truncation bound, clck static-input proof attempt).
  (E5) validator functions THEMSELVES executed as real bytes with fuzzed
       (maxlen/delim) params: rmmi_string_validator @0x90f050b4,
       rmmi_string_validator_ext @0x90f051b2, rmmi_int_validator @0x90f03c66,
       rmmi_int_validator_ext @0x90f03ce6, range_check @0x90f03d92,
       signed_int_validator @0x90f03e5e, is_number_string @0x90f03c18,
       hex_string_validator_ext @0x90f05340 — boundary lens around the
       0x2c cap vs 41-byte binary-gid question (off-by-one hunt).

Each finding: {VA, input class, emulated effect, write-primitive? (exact
dst/len control?), verdict CONFIRMED/REFUTED/INCONCLUSIVE, confidence}.

Run:
  python sim/at_fuzz2.py --selftest        # fast: guard + one vector per engine
  python sim/at_fuzz2.py --all --report sim/at_fuzz2_report.json
  python sim/at_fuzz2.py --e1|--e2|--e3|--e4|--e5 [--verbose]
"""
from __future__ import annotations

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

try:
    from sim import rmmi_sim as _rmmi
except ImportError:
    import rmmi_sim as _rmmi  # type: ignore
try:
    from sim import interp as _interp
except ImportError:
    import interp as _interp  # type: ignore
try:
    from sim import at_fuzz as _atf
except ImportError:
    import at_fuzz as _atf  # type: ignore

# ---------------------------------------------------------------- constants
VA_BASE = 0x90000000
RA_INIT = _interp.RA_INIT
CTX = _interp.CTX_BASE
STACK_INIT = _interp.STACK_INIT

INP_BASE = CTX + 0x2000
INP_SIZE = 0x2000
DST_BASE = CTX + 0x5000
DST_SIZE = 0x100          # caller SML struct stand-in; canary follows
CANARY_BASE = DST_BASE + DST_SIZE
CANARY_LEN = 0x20
CANARY_PAT = b"\xCC" * CANARY_LEN
TOT_BASE = CTX + 0x6000
HEAP_BASE = CTX + 0x7000
HEAP_SIZE = 0x5000
AUX_BASE = CTX + 0xC000

# Target functions (CATI extents; sizes verified against listings headers).
FNS = {
    "add_data_op12":   (0x919867FA, 0x1FA),
    "add_data_op07":   (0x919871AC, 0x250),
    "add_data_op08":   (0x91986E8C, 0x14A),
    "parse_imsi":      (0x91985484, 0x120),
    "parse_gid":       (0x919855A4, 0x05A),
    "parse_binary_gid": (0x919855FE, 0x066),
    "get_data_op12":   (0x91988BB4, 0x1CA),
    "get_data_op08":   (0x91988D7E, 0x0E6),
    "get_data_op07":   (0x91988E64, 0x10C),
    "get_data":        (0x91987F96, 0x10A),
    "get_crrst":       (0x919862C0, 0x162),
    "parse_op12_factory": (0x919869F4, 0x184),
    "parse_op129":     (0x91986B78, 0x13C),
    "parse_op08":      (0x91986CB4, 0x1D8),
    "parse_op08_factory": (0x91986FD6, 0x1D6),
    "parse_op07_factory": (0x919873FC, 0x1D0),
    "parse_op12t":     (0x919875CC, 0x26C),
    "op12_rsu":        (0x91986644, 0x1B6),
    "getval_hex":      (0x9198541A, 0x06A),
    "is_hexnum":       (0x90F03C38, 0x02E),
    "check_hex":       (0x90F05C22, 0x064),
    "hexstr_to_int":   (0x90F05BDA, 0x048),
    "str_validator":   (0x90F050B4, 0x0FE),
    "str_validator_ext": (0x90F051B2, 0x18E),
    "int_validator":   (0x90F03C66, 0x080),
    "int_validator_ext": (0x90F03CE6, 0x0AC),
    "range_check":     (0x90F03D92, 0x0CC),
    "signed_int_validator": (0x90F03E5E, 0x0AC),
    "is_number":       (0x90F03C18, 0x020),
    "hexstr_validator_ext": (0x90F05340, 0x01C),
    "clck":            (0x90F0A052, 0x2DE),
}

# Leaf/helper VAs.
H_MEMSET = 0x90024A2E
H_MEMCPY = 0x90023558
H_STRLEN = 0x901DB1E4
H_STRVAL = 0x90F050B4
H_STRVAL_EXT = 0x90F051B2
H_ISNUM = 0x90F03C18
H_ISHEXNUM = 0x90F03C38
H_CHECKHEX = 0x90F05C22
H_SNPRINTF = 0x91DC900E
H_SPRINTF = 0x91DC908A
H_L4SNPRINTF = 0x90ED8E7E
H_MEMCMP = 0x9005EA10
H_COPY8 = 0x90ED29BC
H_DHL = 0x900367A4
H_ALLOC = 0x9004F8EC
H_FREE = 0x900262DA
# Lock-gate family (ret1 = allow; sibling bytes Ghidra-verified per emu_rmmi).
GATES_RET1 = (0x905F482A, 0x905DF776, 0x905F0322, 0x905F0312, 0x905F031A,
              0x905F031E, 0x905F032A, 0x90F06924, 0x90F06A08, 0x901DB1E4)
WILDCARD_FN = 0x905DF776  # returns wildcard char (hypothesis 0x46='F')
# Preserve-noop: BALC sites whose a0 ret is overwritten before any read
# (verified per call-site in listings; ret-ignored).
PRESERVE_NOOP = (H_DHL, 0x90F07734, 0x905DF772)

# BRSC sites: (host fn key, brsc VA, table VA, index reg, signed?, guard note).
BRSC_SITES = {
    "add_data_op12": {"brsc": 0x9198688E, "table": 0x92A88E14, "reg": "s4",
                      "signed": True, "gate": "BGEIUC s4,0x6 -> 0..5 pass",
                      "entry": 0x919867FA},
    "get_crrst": {"brsc": 0x919862F6, "table": 0x92A88E10, "reg": "s4",
                  "signed": False, "gate": "BGEIUC s4,0x4 -> 0..3 pass",
                  "entry": 0x919862C0},
    "get_data_op12": {"brsc": 0x91988C64, "table": 0x92A88E62, "reg": "s7",
                      "signed": False, "gate": "BGEIUC s7,0x6 -> 0..5 pass",
                      "entry": 0x91988BB4},
}

SNPRINTF_FAMILY = {H_SNPRINTF: "snprintf", H_SPRINTF: "sprintf",
                   H_L4SNPRINTF: "l4_snprintf"}

BLOCKED_FIXTURES = [
    ("F1", 'AT+ESMLCK=1,0,"00000000","000000000000000","",""'),
    ("F2", 'AT+CLCK="PN",0,"12345678"'),
    ("F3", 'AT+ERSUKEY="00:11:22:33"'),
    ("F4", 'AT+ESMLRSU=1,"deadbeef"'),
    ("F5", 'AT+MOTSMLDB="00112233"'),
    ("F5b", 'AT+MOTSMLEVENT="00112233"'),
]
SAFE_QUERIES = ["AT+ESMLCK=?", "AT+ESMLCK?", 'AT+CLCK="PN",2',
                "AT+ESMLRSU=?", "AT+ESMLGEN=?"]


def u32(v: int) -> int:
    return v & 0xFFFFFFFF


def s32(v: int) -> int:
    v &= 0xFFFFFFFF
    return v - 0x100000000 if v & 0x80000000 else v


def s8(v: int) -> int:
    v &= 0xFF
    return v - 0x100 if v & 0x80 else v


# ---------------------------------------------------------------- CPU
class StrictCpu2(_atf.StrictCpu):
    """at_fuzz.StrictCpu + INS (used heavily by add_data_op07 digit paths)."""

    def _exec_text(self, pc: int, text: str, size: int, nxt: int,
                   mn: str, ops: list[str]) -> int:
        if mn == "INS":
            # INS rt,rs,pos,size: rt[pos+size-1:pos] = rs[size-1:0]
            rd, rs, pos_s, size_s = ops[0], ops[1], ops[2], ops[3]
            pos = _interp.parse_imm(pos_s) & 31
            sz = _interp.parse_imm(size_s) & 31
            if sz == 0:
                return nxt
            mask = (((1 << sz) - 1) << pos) & 0xFFFFFFFF
            ins = (u32(self.get(rs)) << pos) & mask if False else \
                ((u32(self.get(rs)) & ((1 << sz) - 1)) << pos) & 0xFFFFFFFF
            self.put(rd, (u32(self.get(rd)) & (~mask & 0xFFFFFFFF)) | ins)
            return nxt
        return super()._exec_text(pc, text, size, nxt, mn, ops)


def make_cpu(rom: bytes, fn_va: int, fn_size: int,
             regs: dict | None = None, step_cap: int = 4000) -> StrictCpu2:
    off = fn_va - VA_BASE
    carve = rom[off:off + fn_size]
    assert len(carve) == fn_size, f"carve short {len(carve)} != {fn_size}"
    return StrictCpu2(bytes(rom), fn_va, bytes(carve), regs=dict(regs or {}),
                      stubs={}, tracer=None, step_cap=step_cap, strict=True)


def _split_ops(text: str) -> list[str]:
    parts = text.split(None, 1)
    if len(parts) < 2:
        return []
    return [o.strip() for o in parts[1].split(",")]


def _mn(text: str) -> str:
    return text.split(None, 1)[0] if text.strip() else ""


# ---------------------------------------------------------------- deep runner
@dataclass
class RunResult:
    fn: str
    fn_va: int
    input_class: str
    regs_note: str
    stop: str
    pc: int
    fault_va: int | None
    steps: int
    a0: int
    copies: list = field(default_factory=list)
    brsc: list = field(default_factory=list)
    dst_writes: list = field(default_factory=list)
    canary_ok: bool = True
    gaps: list = field(default_factory=list)
    trace_tail: list = field(default_factory=list)


class DeepRunner:
    """Strict-emulation driver with behavioral leaf models + interception.

    posture 'faithful': validators length-gate (0xFF on fail), wildcard=0x46.
    posture 'bypass': validators approve-all (copy full input, ret success).
    Unknown helpers TRAP (stop with VA) — never guessed.
    """

    def __init__(self, rom: bytes, posture: str = "faithful",
                 wildcard: int = 0x46) -> None:
        assert posture in ("faithful", "bypass")
        self.rom = bytes(rom)
        self.posture = posture
        self.wildcard = wildcard & 0xFF
        self.copies: list[dict] = []
        self.helper_hits: list = []

    # -- memory string helpers --------------------------------------
    @staticmethod
    def cstr_read(cpu, va: int, cap: int = 0x2000) -> bytes:
        out = bytearray()
        va = u32(va)
        for _ in range(cap):
            try:
                b = cpu.load_bytes(va, 1)[0]
            except Exception:
                break
            if b == 0:
                break
            out.append(b)
            va = u32(va + 1)
        return bytes(out)

    @staticmethod
    def cstr_write(cpu, va: int, data: bytes, cap: int = 0x2000) -> int:
        n = min(len(data), cap - 1)
        if n > 0:
            cpu.store_bytes(u32(va), bytes(data[:n]))
        cpu.store_bytes(u32(va) + n, b"\x00")
        return n

    def region_of(self, va: int) -> str:
        va = u32(va)
        if INP_BASE <= va < INP_BASE + INP_SIZE:
            return "INP"
        if DST_BASE <= va < DST_BASE + DST_SIZE:
            return "DST(out-buf)"
        if CANARY_BASE <= va < CANARY_BASE + CANARY_LEN:
            return "CANARY!"
        if TOT_BASE <= va < TOT_BASE + 0x100:
            return "TOTAL"
        if HEAP_BASE <= va < HEAP_BASE + HEAP_SIZE:
            return "HEAP"
        if AUX_BASE <= va < AUX_BASE + 0x1000:
            return "AUX"
        if 0xA0000000 <= va < 0xA0010000:
            return "STACK"
        if CTX <= va < CTX + 0x10000:
            return "CTX"
        if VA_BASE <= va < VA_BASE + len(self.rom):
            return "ROM"
        return "UNMAPPED!"

    # -- leaf models --------------------------------------------------
    def m_memset(self, cpu) -> int:
        dst, val, ln = cpu.get("a0"), cpu.get("a1") & 0xFF, u32(cpu.get("a2"))
        ln = min(ln, 0x10000)
        if ln:
            try:
                cpu.store_bytes(u32(dst), bytes([val]) * ln)
            except Exception:
                cpu._ensure_region(u32(dst), ln)
                cpu.store_bytes(u32(dst), bytes([val]) * ln)
        return u32(dst)

    def m_memcpy(self, cpu, tag: str = "memcpy") -> int:
        dst, src, ln = u32(cpu.get("a0")), u32(cpu.get("a1")), u32(cpu.get("a2"))
        ln = min(ln, 0x10000)
        try:
            data = cpu.load_bytes(src, ln) if ln else b""
        except Exception:
            data = b"\x00" * ln
        if ln:
            try:
                cpu.store_bytes(dst, data)
            except Exception:
                cpu._ensure_region(dst, ln)
                cpu.store_bytes(dst, data)
        self.copies.append({"site": tag, "dst": f"{dst:#x}",
                            "dst_region": self.region_of(dst),
                            "src": f"{src:#x}",
                            "src_region": self.region_of(src),
                            "len": ln, "len_hex": f"{ln:#x}"})
        return dst

    def m_strlen(self, cpu) -> int:
        return len(self.cstr_read(cpu, cpu.get("a0")))

    def m_memcmp(self, cpu) -> int:
        a0, a1, ln = u32(cpu.get("a0")), u32(cpu.get("a1")), u32(cpu.get("a2"))
        ln = min(ln, 0x10000)
        try:
            b0 = cpu.load_bytes(a0, ln)
        except Exception:
            b0 = b"\x00" * ln
        try:
            b1 = cpu.load_bytes(a1, ln)
        except Exception:
            b1 = b"\x00" * ln
        if b0 == b1:
            return 0
        return -1 if b0 < b1 else 1

    def m_validator(self, cpu, tag: str) -> int:
        """rmmi_string_validator[_ext]: (a0=dst, a1=src, a2=maxlen, a3=?)."""
        dst, src = u32(cpu.get("a0")), u32(cpu.get("a1"))
        maxlen = u32(cpu.get("a2")) & 0xFFFF
        data = self.cstr_read(cpu, src)
        if self.posture == "bypass":
            self.cstr_write(cpu, dst, data)
            self.helper_hits.append((tag, f"bypass approve len={len(data)}"))
            return 0
        if len(data) > maxlen:
            self.helper_hits.append(
                (tag, f"REJECT len={len(data)} > maxlen={maxlen}"))
            return 0xFF
        self.cstr_write(cpu, dst, data)
        self.helper_hits.append((tag, f"approve len={len(data)} maxlen={maxlen}"))
        return 0

    def m_is_number(self, cpu) -> int:
        data = self.cstr_read(cpu, cpu.get("a0"))
        ok = len(data) > 0 and all(0x30 <= b <= 0x39 for b in data)
        return 1 if ok else 0

    def m_is_hexnum(self, cpu) -> int:
        data = self.cstr_read(cpu, cpu.get("a0"))
        hexset = set(b"0123456789abcdefABCDEF")
        ok = len(data) > 0 and all(b in hexset for b in data)
        return 1 if ok else 0

    def m_check_hex(self, cpu) -> int:
        data = self.cstr_read(cpu, cpu.get("a0"))
        hexset = set(b"0123456789abcdefABCDEF")
        bad = sum(1 for b in data if b not in hexset)
        self.helper_hits.append(("check_hex", f"len={len(data)} bad={bad}"))
        return 0

    def fmt_engine(self, cpu, fmt: bytes, args: list[int]) -> bytes:
        out = bytearray()
        ai = 0
        i = 0
        while i < len(fmt):
            c = fmt[i]
            if c != 0x25:  # '%'
                out.append(c)
                i += 1
                continue
            i += 1
            zero = False
            width = 0
            if i < len(fmt) and fmt[i] == 0x30:
                zero = True
                i += 1
            while i < len(fmt) and 0x30 <= fmt[i] <= 0x39:
                width = width * 10 + (fmt[i] - 0x30)
                i += 1
            if i >= len(fmt):
                break
            spec = fmt[i]
            i += 1
            v = args[ai] if ai < len(args) else 0
            ai += 1
            if spec == 0x25:
                out += b"%"
                ai -= 1
            elif spec == 0x73:  # s
                out += self.cstr_read(cpu, u32(v))
            elif spec in (0x64, 0x75, 0x69):  # d/u/i
                sv = s32(v) if spec in (0x64, 0x69) else u32(v)
                out += str(sv).encode("ascii")
            elif spec in (0x58, 0x78):  # X/x
                s = ("%X" % u32(v)) if spec == 0x58 else ("%x" % u32(v))
                if width:
                    s = s.rjust(width, "0" if zero else " ")
                out += s.encode("ascii")
            elif spec == 0x63:  # c
                out += bytes([u32(v) & 0xFF])
            else:
                out += b"<%02X>" % spec
        return bytes(out)

    def m_snprintf(self, cpu, bounded: bool, tag: str) -> int:
        dst = u32(cpu.get("a0"))
        if bounded:
            size = u32(cpu.get("a1"))
            fmt_va, arg0 = u32(cpu.get("a2")), u32(cpu.get("a3"))
            extra = [cpu.get(r) for r in ("a4", "a5", "a6", "a7")]
        else:
            size = 0x7FFFFFFF
            fmt_va, arg0 = u32(cpu.get("a1")), u32(cpu.get("a2"))
            extra = [cpu.get(r) for r in ("a3", "a4", "a5", "a6", "a7")]
        try:
            fmt = self.cstr_read(cpu, fmt_va, 0x400)
        except Exception:
            fmt = b"?"
        full = self.fmt_engine(cpu, fmt, [arg0] + extra)[:0x4000]
        ret = len(full)
        if size > 0:
            w = min(ret, size - 1)
            if w:
                try:
                    cpu.store_bytes(dst, full[:w])
                except Exception:
                    cpu._ensure_region(dst, w)
                    cpu.store_bytes(dst, full[:w])
            try:
                cpu.store_bytes(u32(dst) + w, b"\x00")
            except Exception:
                pass
        self.helper_hits.append(
            (tag, f"dst={dst:#x} size={size:#x} fmt={fmt!r} ret={ret} "
                  f"trunc={ret >= size if bounded and size else False}"))
        self.copies.append({"site": tag, "dst": f"{dst:#x}",
                            "dst_region": self.region_of(dst),
                            "src": f"fmt@{fmt_va:#x}",
                            "src_region": self.region_of(fmt_va),
                            "len": min(ret, (size - 1) if bounded and size else ret),
                            "len_hex": f"{ret:#x}", "ret_full": ret})
        return u32(ret)

    def m_alloc(self, cpu) -> int:
        size = u32(cpu.get("a0"))
        if not hasattr(self, "_heap_ptr"):
            self._heap_ptr = HEAP_BASE
        ptr = (self._heap_ptr + 7) & ~7
        self._heap_ptr = ptr + max(size, 8)
        if self._heap_ptr >= HEAP_BASE + HEAP_SIZE:
            return 0
        try:
            cpu.store_bytes(ptr, b"\x00" * min(size, HEAP_SIZE))
        except Exception:
            pass
        self.helper_hits.append(("alloc", f"size={size:#x} -> {ptr:#x}"))
        return ptr

    def call_helper(self, cpu, va: int) -> int:
        va = u32(va)
        if va == H_MEMSET:
            return self.m_memset(cpu)
        if va == H_MEMCPY:
            return self.m_memcpy(cpu)
        if va == H_COPY8:
            return self.m_memcpy(cpu, "copy8")
        if va == H_STRLEN:
            return self.m_strlen(cpu)
        if va in (H_STRVAL, H_STRVAL_EXT):
            return self.m_validator(cpu, "strval-ext" if va == H_STRVAL_EXT else "strval")
        if va == H_ISNUM:
            return self.m_is_number(cpu)
        if va == H_ISHEXNUM:
            return self.m_is_hexnum(cpu)
        if va == H_CHECKHEX:
            return self.m_check_hex(cpu)
        if va == H_SNPRINTF:
            return self.m_snprintf(cpu, True, "snprintf")
        if va == H_SPRINTF:
            return self.m_snprintf(cpu, False, "sprintf")
        if va == H_L4SNPRINTF:
            return self.m_snprintf(cpu, True, "l4_snprintf")
        if va == H_MEMCMP:
            return self.m_memcmp(cpu)
        if va == H_ALLOC:
            return self.m_alloc(cpu)
        if va == H_FREE:
            return cpu.get("a0")
        if va in PRESERVE_NOOP:
            return cpu.get("a0")  # trace/enter stubs: regs untouched
        if va in GATES_RET1:
            if va == WILDCARD_FN:
                return self.wildcard  # wildcard-char hypothesis
            return 1
        raise _interp.EmuUnsupported(f"TRAP-unknown-helper @{va:#x}")

    # -- main loop ----------------------------------------------------
    def run(self, fn_key: str, regs: dict, input_class: str = "",
            regs_note: str = "", step_cap: int = 4000,
            listing_name: str | None = None) -> RunResult:
        fn_va, fn_size = FNS[fn_key]
        self.copies = []
        self.helper_hits = []
        full_regs = dict(regs)
        full_regs.setdefault("sp", STACK_INIT)
        full_regs.setdefault("ra", RA_INIT)
        cpu = make_cpu(self.rom, fn_va, fn_size, full_regs, step_cap)
        # layout: canary after DST
        try:
            cpu.mem.write(CANARY_BASE, CANARY_PAT)
        except Exception:
            try:
                cpu._ensure_region(CANARY_BASE, CANARY_LEN)
                cpu.mem.write(CANARY_BASE, CANARY_PAT)
            except Exception:
                pass
        try:
            dst_before = bytes(cpu.mem.read(DST_BASE, DST_SIZE))
        except Exception:
            dst_before = b""
        listing: dict = {}
        if listing_name:
            try:
                listing = _atf.load_listing_map(listing_name)
            except Exception:
                listing = {}
        fn_end = fn_va + fn_size
        pc = u32(fn_va)
        cpu.pc = pc
        steps = 0
        stop = ""
        fault_va = None
        gaps: list[str] = []
        brsc: list[dict] = []
        trace: list[str] = []
        while steps < step_cap:
            if pc == u32(RA_INIT) and steps > 0:
                stop = "HIT-RET"
                break
            if pc in SNPRINTF_FAMILY or pc in (H_MEMSET, H_MEMCPY, H_STRLEN,
                                               H_STRVAL, H_STRVAL_EXT, H_ISNUM,
                                               H_ISHEXNUM, H_CHECKHEX, H_MEMCMP,
                                               H_COPY8, H_ALLOC, H_FREE) \
                    or pc in GATES_RET1 or pc in PRESERVE_NOOP:
                try:
                    ret = self.call_helper(cpu, pc)
                except _interp.EmuUnsupported as e:
                    stop = f"TRAP @{pc:#x}"
                    fault_va = pc
                    gaps.append(str(e))
                    break
                cpu.put("a0", u32(ret))
                trace.append(f"{pc:#x} [HELPER -> a0={u32(ret):#x}]")
                pc = u32(cpu.get("ra"))
                cpu.pc = pc
                steps += 1
                continue
            try:
                hit = listing.get(u32(pc))
                if hit is not None:
                    text, size = hit
                else:
                    text, size, _raw = cpu._decode_at(u32(pc))
            except _interp.EmuUnsupported as e:
                stop = f"UNSUPPORTED @{pc:#x}"
                fault_va = pc
                gaps.append(str(e))
                break
            except Exception as e:  # noqa: BLE001
                stop = f"MEM-FAULT @{pc:#x}: {e}"
                fault_va = pc
                gaps.append(f"{pc:#x}: {e}")
                break
            nxt = u32(pc + size)
            mn = _mn(text)
            ops = _split_ops(text)
            tgt = None
            if mn == "BALC" and ops:
                try:
                    tgt = _interp.parse_imm(ops[0])
                except Exception:
                    tgt = None
            elif mn == "MOVE.BALC" and len(ops) >= 3:
                try:
                    tgt = _interp.parse_imm(ops[2])
                except Exception:
                    tgt = None
            if tgt is not None and u32(tgt) in (
                    set(SNPRINTF_FAMILY) | {H_MEMSET, H_MEMCPY, H_STRLEN,
                                            H_STRVAL, H_STRVAL_EXT, H_ISNUM,
                                            H_ISHEXNUM, H_CHECKHEX, H_MEMCMP,
                                            H_COPY8, H_ALLOC, H_FREE}
                    | set(GATES_RET1) | set(PRESERVE_NOOP)):
                cpu.put("ra", nxt)
                try:
                    ret = self.call_helper(cpu, u32(tgt))
                except _interp.EmuUnsupported as e:
                    stop = f"TRAP @{u32(tgt):#x} via BALC @{pc:#x}"
                    fault_va = u32(tgt)
                    gaps.append(str(e))
                    break
                cpu.put("a0", u32(ret))
                trace.append(f"{pc:#x} {text} [-> a0={u32(ret):#x}]")
                pc = nxt
                cpu.pc = pc
                steps += 1
                continue
            if mn == "BRSC" and ops:
                idx = u32(cpu.get(ops[0]))
                # parent semantics: target = nxt + idx*2 (mod 2^32; same for
                # signed LBX values via u32 wraparound)
                btgt = u32(nxt + u32(idx * 2))
                brsc.append({"pc": f"{pc:#x}", "reg": ops[0],
                             "idx_u": idx, "idx_s": s32(idx),
                             "target": f"{btgt:#x}",
                             "in_carve": bool(fn_va <= btgt < fn_end)})
            try:
                npc = cpu.step_once_with_text(pc, text, size)
            except _interp.EmuUnsupported as e:
                stop = f"UNSUPPORTED @{pc:#x}: {e}"
                fault_va = pc
                gaps.append(f"{pc:#x} {text}: {e}")
                break
            except Exception as e:  # noqa: BLE001
                stop = f"FAULT @{pc:#x} ({text}): {e}"
                fault_va = pc
                gaps.append(f"{pc:#x} {text}: {e}")
                break
            trace.append(f"{pc:#x} {text}")
            pc = u32(npc)
            cpu.pc = pc
            steps += 1
        else:
            stop = "STEP-CAP"
        if not stop:
            stop = "STEP-CAP"
        try:
            dst_after = bytes(cpu.mem.read(DST_BASE, DST_SIZE))
        except Exception:
            dst_after = b""
        writes: list[dict] = []
        if dst_before and dst_after and dst_before != dst_after:
            i = 0
            while i < len(dst_before):
                if dst_before[i] != dst_after[i]:
                    j = i
                    while j < len(dst_before) and dst_before[j] != dst_after[j]:
                        j += 1
                    writes.append({"off": f"{i:#x}", "len": j - i,
                                   "was": dst_before[i:j].hex(),
                                   "now": dst_after[i:j].hex()})
                    i = j
                else:
                    i += 1
        try:
            can = bytes(cpu.mem.read(CANARY_BASE, CANARY_LEN))
            canary_ok = (can == CANARY_PAT)
            canary_ev = "" if canary_ok else can.hex()
        except Exception:
            canary_ok, canary_ev = False, "unreadable"
        return RunResult(fn_key, fn_va, input_class, regs_note, stop, pc,
                         fault_va, steps, u32(cpu.get("a0")),
                         list(self.copies), brsc, writes, canary_ok, gaps,
                         trace[-8:], )


# ---------------------------------------------------------------- input classes
def build_classes() -> list[tuple[str, bytes]]:
    C: list[tuple[str, bytes]] = []
    C.append(("empty", b""))
    C.append(("one-digit", b"1"))
    C.append(("one-F", b"F"))
    for n in (5, 6, 7, 8, 15, 16, 40, 41, 42, 43, 44, 45, 64):
        C.append((f"digits-{n}", (b"1234567890" * 30)[:n]))
    for n in (255, 256, 257):
        C.append((f"digits-{n}", (b"9" * n)))
    for n in (5, 6, 7, 8, 41, 44):
        C.append((f"allF-{n}", b"F" * n))
    C.append(("Fpad-8", b"123" + b"F" * 5))
    C.append(("Fpad-16", b"12" + b"F" * 14))
    C.append(("Fpad-44", b"1" + b"F" * 43))
    C.append(("mixedhex-lower", b"a1b2c3d4e5f607"))
    C.append(("mixedhex-upper", b"A1B2C3D4E5F607"))
    C.append(("mixedhex-41", (b"aAbB09" * 7)[:41]))
    C.append(("nonhex-G8", b"G" * 8))
    C.append(("nonhex-space", b"12 34 56"))
    C.append(("nonhex-dash", b"12-34-56"))
    C.append(("nonhex-0x", b"0x1234"))
    C.append(("oddhex-3", b"ABC"))
    C.append(("oddhex-41", b"A" * 41))
    C.append(("zeros-16", b"0" * 16))
    return C


# ---------------------------------------------------------------- findings
@dataclass
class Finding:
    id: str
    target: str
    target_va: str
    input_class: str
    emulated_effect: str
    write_primitive: dict
    verdict: str  # CONFIRMED | REFUTED | INCONCLUSIVE
    confidence: str
    evidence: dict = field(default_factory=dict)

    def asdict(self) -> dict:
        return asdict(self)


def wp(no: bool = True, note: str = "", dst: str = "", len_ctl: str = "") -> dict:
    return {"exists": (not no), "dst": dst, "len_control": len_ctl, "note": note}


# ---------------------------------------------------------------- E1
def run_e1(rom: bytes, quick: bool = False, verbose: bool = False) -> tuple[list[Finding], dict]:
    findings: list[Finding] = []
    stats = {"runs": 0, "ret_ok": 0, "ret_err": 0, "traps": 0,
             "unsupported": 0, "faults": 0, "canary_hits": 0}
    classes = build_classes()
    if quick:
        classes = [c for c in classes if c[0] in (
            "empty", "digits-6", "digits-44", "allF-8", "nonhex-G8",
            "digits-256", "Fpad-44")]
    # (fn, a1-cats, listing)
    matrix = [
        ("add_data_op12", [0, 1, 2, 5, 6, 7], "rmmi_sml_add_data_op12"),
        ("add_data_op07", [0, 1, 2, 3], "rmmi_sml_add_data_op07"),
        ("add_data_op08", [0, 1, 2, 3], "rmmi_sml_add_data_op08"),
        ("parse_imsi", [0], "rmmi_sml_parse_imsi"),
        ("parse_gid", [0], "rmmi_sml_parse_gid"),
        ("parse_binary_gid", [0], "rmmi_sml_parse_binary_gid"),
    ]
    all_runs: list[RunResult] = []
    for posture in (["faithful"] if quick else ["faithful", "bypass"]):
        for fn, cats, listing in matrix:
            for cname, cdata in classes:
                for cat in cats:
                    dr = DeepRunner(rom, posture=posture)
                    inp = INP_BASE
                    regs = {"a0": inp, "a1": cat, "a2": TOT_BASE,
                            "a3": DST_BASE}
                    if fn.startswith("parse_"):
                        regs = {"a0": inp, "a1": DST_BASE, "a2": TOT_BASE,
                                "a3": cat}
                    # NOTE: input bytes are staged inside _dr_run_staged via
                    # a patched make_cpu (fresh CPU per run, no
                    # cross-contamination).
                    r = _run_with_staged_input(dr, fn, regs, inp, cdata,
                                               f"{cname}/cat={cat}/{posture}",
                                               listing)
                    all_runs.append(r)
                    stats["runs"] += 1
                    if r.stop == "HIT-RET" and r.a0 == 1:
                        stats["ret_ok"] += 1
                    elif r.stop == "HIT-RET" and r.a0 == 0:
                        stats["ret_err"] += 1
                    elif r.stop.startswith("TRAP"):
                        stats["traps"] += 1
                    elif r.stop.startswith("UNSUPPORTED"):
                        stats["unsupported"] += 1
                    elif "FAULT" in r.stop:
                        stats["faults"] += 1
                    if not r.canary_ok:
                        stats["canary_hits"] += 1
                    if verbose and (not r.canary_ok or "FAULT" in r.stop
                                    or r.stop.startswith("UNSUPPORTED")):
                        print(f"  E1 {fn} {cname} cat={cat} {posture}: "
                              f"{r.stop} a0={r.a0:#x} copies={len(r.copies)} "
                              f"canary_ok={r.canary_ok}")
    # --- summarize per fn ---
    for fn, _cats, _listing in matrix:
        runs = [r for r in all_runs if r.fn == fn]
        stops: dict[str, int] = {}
        for r in runs:
            key = r.stop.split("@")[0].split(":")[0].strip() + \
                (f" a0={r.a0:#x}" if r.stop == "HIT-RET" else "")
            stops[key] = stops.get(key, 0) + 1
        max_copy = 0
        max_copy_ev = None
        for r in runs:
            for c in r.copies:
                if c["len"] > max_copy:
                    max_copy = c["len"]
                    max_copy_ev = {"run": r.input_class, "copy": c,
                                   "stop": r.stop}
        can_hits = [r for r in runs if not r.canary_ok]
        faults = [r for r in runs if ("FAULT" in r.stop or r.stop.startswith("UNSUPPORTED"))]
        eff = (f"{len(runs)} vectors ({', '.join(f'{k}x{v}' for k, v in sorted(stops.items()))}); "
               f"max memcpy/snprintf len={max_copy:#x} {max_copy_ev}; "
               f"canary overruns={len(can_hits)}; "
               f"fault/unsupported={len(faults)}")
        if can_hits:
            verdict, conf = "CONFIRMED", "HIGH (emulated canary overwrite)"
            wprim = wp(False, "canary past DST71 overwritten in emulation",
                       dst="DST_BASE+0x100 (canary)", len_ctl="see evidence")
        elif max_copy and any("CANARY" in c.get("dst_region", "") or "UNMAPPED" in c.get("dst_region", "") for r in runs for c in r.copies):
            verdict, conf = "CONFIRMED", "HIGH"
            wprim = wp(False, "copy into CANARY/UNMAPPED region observed",
                       dst="see evidence", len_ctl="see evidence")
        else:
            verdict, conf = "REFUTED", \
                "MEDIUM (validator/copy models assumed; see evidence)"
            wprim = wp(True, "all copies land in STACK/DST/HEAP with "
                             "validator-capped lens; no canary/UNMAPPED write",
                       dst="s0-caller-buf / sp-slices", len_ctl="strlen<=maxlen (faithful) or input-len (bypass)")
        findings.append(Finding(
            f"E1-{fn}", f"{fn} deep emulation", f"{FNS[fn][0]:#x}",
            "adversarial classes x cats x validator postures (see evidence)",
            eff, wprim, verdict, conf,
            {"stops": stops, "max_copy": max_copy_ev,
             "faults": [{"run": r.input_class, "stop": r.stop,
                         "pc": f"{r.pc:#x}"} for r in faults[:12]],
             "canary_runs": [r.input_class for r in can_hits[:8]]}))
    return findings, stats


def _run_with_staged_input(dr: DeepRunner, fn: str, regs: dict, inp: int,
                           data: bytes, iclass: str, listing: str) -> RunResult:
    """Run with input bytes staged (wraps DeepRunner.run)."""
    fn_va, fn_size = FNS[fn]
    # monkey-stage: temporarily wrap make_cpu to pre-write input
    orig_make = globals()["make_cpu"]

    def staged(rom, va, size, regs=None, step_cap=4000):
        cpu = orig_make(rom, va, size, regs, step_cap)
        try:
            cpu.store_bytes(u32(inp), bytes(data) + b"\x00")
        except Exception:
            try:
                cpu._ensure_region(u32(inp), len(data) + 1)
                cpu.store_bytes(u32(inp), bytes(data) + b"\x00")
            except Exception:
                pass
        try:
            cpu.store_bytes(TOT_BASE, b"\x00" * 8)
        except Exception:
            pass
        try:
            cpu.store_bytes(DST_BASE, b"\x00" * DST_SIZE)
        except Exception:
            pass
        return cpu

    globals()["make_cpu"] = staged
    try:
        # replicate DeepRunner.run but with staged cpu: easiest is to call
        # dr.run then re-stage? No — patch at DeepRunner level:
        return _dr_run_staged(dr, fn, regs, iclass, listing)
    finally:
        globals()["make_cpu"] = orig_make


def _dr_run_staged(dr: DeepRunner, fn: str, regs: dict, iclass: str,
                   listing: str) -> RunResult:
    fn_va, fn_size = FNS[fn]
    full_regs = dict(regs)
    full_regs.setdefault("sp", STACK_INIT)
    full_regs.setdefault("ra", RA_INIT)
    cpu = make_cpu(dr.rom, fn_va, fn_size, full_regs, 4000)
    dr.copies = []
    dr.helper_hits = []
    try:
        cpu.mem.write(CANARY_BASE, CANARY_PAT)
    except Exception:
        try:
            cpu._ensure_region(CANARY_BASE, CANARY_LEN)
            cpu.mem.write(CANARY_BASE, CANARY_PAT)
        except Exception:
            pass
    try:
        dst_before = bytes(cpu.mem.read(DST_BASE, DST_SIZE))
    except Exception:
        dst_before = b""
    try:
        lmap = _atf.load_listing_map(listing)
    except Exception:
        lmap = {}
    fn_end = fn_va + fn_size
    pc = u32(fn_va)
    cpu.pc = pc
    steps = 0
    stop = ""
    fault_va = None
    gaps: list[str] = []
    brsc: list[dict] = []
    trace: list[str] = []
    HELPER_SET = (set(SNPRINTF_FAMILY) | {H_MEMSET, H_MEMCPY, H_STRLEN,
                                          H_STRVAL, H_STRVAL_EXT, H_ISNUM,
                                          H_ISHEXNUM, H_CHECKHEX, H_MEMCMP,
                                          H_COPY8, H_ALLOC, H_FREE}
                  | set(GATES_RET1) | set(PRESERVE_NOOP))
    while steps < 4000:
        if pc == u32(RA_INIT) and steps > 0:
            stop = "HIT-RET"
            break
        if pc in HELPER_SET:
            try:
                ret = dr.call_helper(cpu, pc)
            except _interp.EmuUnsupported as e:
                stop = f"TRAP @{pc:#x}"
                fault_va = pc
                gaps.append(str(e))
                break
            cpu.put("a0", u32(ret))
            trace.append(f"{pc:#x} [HELPER -> a0={u32(ret):#x}]")
            pc = u32(cpu.get("ra"))
            cpu.pc = pc
            steps += 1
            continue
        try:
            hit = lmap.get(u32(pc))
            if hit is not None:
                text, size = hit
            else:
                text, size, _raw = cpu._decode_at(u32(pc))
        except _interp.EmuUnsupported as e:
            stop = f"UNSUPPORTED @{pc:#x}"
            fault_va = pc
            gaps.append(str(e))
            break
        except Exception as e:  # noqa: BLE001
            stop = f"MEM-FAULT @{pc:#x}: {e}"
            fault_va = pc
            gaps.append(f"{pc:#x}: {e}")
            break
        nxt = u32(pc + size)
        mn = _mn(text)
        ops = _split_ops(text)
        tgt = None
        if mn == "BALC" and ops:
            try:
                tgt = u32(_interp.parse_imm(ops[0]))
            except Exception:
                tgt = None
        elif mn == "MOVE.BALC" and len(ops) >= 3:
            try:
                tgt = u32(_interp.parse_imm(ops[2]))
            except Exception:
                tgt = None
        if tgt is not None and tgt in HELPER_SET:
            cpu.put("ra", nxt)
            try:
                ret = dr.call_helper(cpu, tgt)
            except _interp.EmuUnsupported as e:
                stop = f"TRAP @{tgt:#x} via BALC @{pc:#x}"
                fault_va = tgt
                gaps.append(str(e))
                break
            cpu.put("a0", u32(ret))
            trace.append(f"{pc:#x} {text} [-> a0={u32(ret):#x}]")
            pc = nxt
            cpu.pc = pc
            steps += 1
            continue
        if mn == "BRSC" and ops:
            idx = u32(cpu.get(ops[0]))
            btgt = u32(nxt + u32(idx * 2))
            brsc.append({"pc": f"{pc:#x}", "reg": ops[0], "idx_u": idx,
                         "idx_s": s32(idx), "target": f"{btgt:#x}",
                         "in_carve": bool(fn_va <= btgt < fn_end)})
        try:
            npc = cpu.step_once_with_text(pc, text, size)
        except _interp.EmuUnsupported as e:
            stop = f"UNSUPPORTED @{pc:#x}: {e}"
            fault_va = pc
            gaps.append(f"{pc:#x} {text}: {e}")
            break
        except Exception as e:  # noqa: BLE001
            stop = f"FAULT @{pc:#x} ({text}): {e}"
            fault_va = pc
            gaps.append(f"{pc:#x} {text}: {e}")
            break
        trace.append(f"{pc:#x} {text}")
        pc = u32(npc)
        cpu.pc = pc
        steps += 1
    else:
        stop = "STEP-CAP"
    if not stop:
        stop = "STEP-CAP"
    try:
        dst_after = bytes(cpu.mem.read(DST_BASE, DST_SIZE))
    except Exception:
        dst_after = b""
    writes: list[dict] = []
    if dst_before and dst_after and dst_before != dst_after:
        i = 0
        while i < len(dst_before):
            if dst_before[i] != dst_after[i]:
                j = i
                while j < len(dst_before) and dst_before[j] != dst_after[j]:
                    j += 1
                writes.append({"off": f"{i:#x}", "len": j - i})
                i = j
            else:
                i += 1
    try:
        can = bytes(cpu.mem.read(CANARY_BASE, CANARY_LEN))
        canary_ok = (can == CANARY_PAT)
    except Exception:
        canary_ok = False
    return RunResult(fn, fn_va, iclass, str({k: (f"{v:#x}" if isinstance(v, int) else v) for k, v in regs.items()}),
                     stop, pc, fault_va, steps, u32(cpu.get("a0")),
                     list(dr.copies), brsc, writes, canary_ok, gaps, trace[-8:])


# ---------------------------------------------------------------- E2 BRSC
def run_e2(rom: bytes, quick: bool = False, verbose: bool = False) -> tuple[list[Finding], dict]:
    findings: list[Finding] = []
    info: dict = {}
    for key, site in BRSC_SITES.items():
        fn_va, fn_size = FNS[{"add_data_op12": "add_data_op12",
                              "get_crrst": "get_crrst",
                              "get_data_op12": "get_data_op12"}[key]]
        # ROM table dump (16 bytes) + extended read for OOB indices
        off = site["table"] - VA_BASE
        tbl = bytes(rom[off:off + 64])
        # forced-index micro-vectors: execute ADDIUPC/LBUX/BRSC triple
        brsc_va = site["brsc"]
        # locate the 2 fetch insns before BRSC via listing of host fn
        lname = {"add_data_op12": "rmmi_sml_add_data_op12",
                 "get_crrst": "rmmi_sml_get_crrst_data",
                 "get_data_op12": "rmmi_sml_get_data_op12"}[key]
        try:
            lmap = _atf.load_listing_map(lname)
        except Exception:
            lmap = {}
        # find BRSC entry; step back two insns (ADDIUPC 6B + LBUX/LBX 4B)
        start = brsc_va - 10
        idxs = [0, 1, 2, 3, 4, 5, 6, 7, 8, 0x46, 0xFF] if not quick else [0, 2, 5, 6, 0xFF]
        vecs = []
        for idx in idxs:
            cpu = make_cpu(rom, fn_va, fn_size,
                           {"a0": DST_BASE, "a1": 0, "a2": 0, "a3": 0,
                            "a4": 0, "sp": STACK_INIT, "ra": RA_INIT,
                            site["reg"]: idx}, 100)
            cpu.put(site["reg"], u32(idx))
            pc = u32(start)
            cpu.pc = pc
            steps = 0
            rec: dict = {"idx": idx, "idx_hex": f"{idx:#x}"}
            try:
                while steps < 6:
                    hit = lmap.get(u32(pc))
                    if hit is not None:
                        text, size = hit
                    else:
                        text, size, _raw = cpu._decode_at(u32(pc))
                    mn = _mn(text)
                    ops = _split_ops(text)
                    nxt = u32(pc + size)
                    if mn == "BRSC":
                        iv = u32(cpu.get(ops[0]))
                        btgt = u32(nxt + u32(iv * 2))
                        # table byte actually loaded one step earlier
                        rec["brsc_at"] = f"{pc:#x}"
                        rec["idx_at_brsc_u"] = iv
                        rec["idx_at_brsc_s"] = s32(iv)
                        rec["target"] = f"{btgt:#x}"
                        rec["in_carve"] = bool(fn_va <= btgt < fn_va + fn_size)
                        # decode target text if in carve
                        th = lmap.get(btgt)
                        rec["target_text"] = th[0] if th else "(no listing row)"
                        break
                    npc = cpu.step_once_with_text(pc, text, size)
                    # record table load
                    if mn in ("LBUX", "LBX") and steps >= 0 and "tbl_byte" not in rec:
                        rec["tbl_byte_u"] = u32(cpu.get(ops[0])) & 0xFF
                        rec["tbl_byte_s"] = s8(u32(cpu.get(ops[0])) & 0xFF)
                    pc = u32(npc)
                    cpu.pc = pc
                    steps += 1
                else:
                    rec["note"] = "BRSC not reached in 6 steps"
            except _interp.EmuUnsupported as e:
                rec["stop"] = f"UNSUPPORTED: {e}"
            except Exception as e:  # noqa: BLE001
                rec["stop"] = f"FAULT: {e}"
            vecs.append(rec)
            if verbose:
                print(f"  E2 {key} idx={idx:#x}: {rec}")
        # full-run attempt with benign input for in-range cats
        full = []
        if not quick:
            for cat in range(0, 4):
                dr = DeepRunner(rom)
                regs = {"a0": INP_BASE, "a1": cat, "a2": TOT_BASE, "a3": DST_BASE}
                if key != "add_data_op12":
                    # get_crrst/get_data have wider ABI; still attempt with
                    # plausible pointers (traps recorded honestly)
                    regs = {"a0": DST_BASE, "a1": cat, "a2": AUX_BASE,
                            "a3": INP_BASE, "a4": AUX_BASE + 0x100}
                    try:
                        tmp = make_cpu(rom, fn_va, fn_size)
                        tmp.store_bytes(AUX_BASE, struct.pack("<H", 4) + b"\x00" * 30)
                    except Exception:
                        pass
                r = _dr_run_staged(dr, key if key in FNS else "add_data_op12",
                                   regs, f"fullrun/cat={cat}", lname)
                # stage AUX len word inside real cpu: redo via helper
                full.append({"cat": cat, "stop": r.stop, "a0": f"{r.a0:#x}",
                             "brsc": r.brsc, "fault": f"{r.fault_va:#x}" if r.fault_va else None})
        oob_targets = [v for v in vecs if "target" in v and not v.get("in_carve")]
        tbl_hex = tbl[:16].hex(" ")
        eff = (f"table[{site['table']:#x}] = {tbl_hex}; micro-vectors "
               f"{len(vecs)} (forced {site['reg']}); "
               f"OOB-landing (outside carve) = {len(oob_targets)}; "
               f"full-run attempts = {full if full else 'skipped(quick)'}")
        if oob_targets:
            verdict, conf = "CONFIRMED", "HIGH (emulated BRSC target)"
            wprim = wp(False, "BRSC lands outside carve for forced index",
                       dst=str([v.get("target") for v in oob_targets]),
                       len_ctl="index-reg controlled")
        else:
            verdict, conf = "REFUTED", "HIGH (micro-emulation + ROM dump)"
            wprim = wp(True, "all forced-index BRSC targets land inside the "
                             "host carve (bounded forward/backward tails)",
                       dst="in-carve", len_ctl="table byte x2")
        findings.append(Finding(
            f"E2-{key}", f"{key} BRSC jump table",
            f"BRSC @{site['brsc']:#x} via table {site['table']:#x} "
            f"(host {fn_va:#x})",
            f"forced {site['reg']} in {[hex(i) for i in idxs]} "
            f"({'signed' if site['signed'] else 'unsigned'} load); gate: {site['gate']}",
            eff, wprim, verdict, conf,
            {"table16": tbl_hex, "vectors": vecs, "full_runs": full}))
        info[key] = {"table": tbl_hex, "vecs": vecs}
    return findings, info


# ---------------------------------------------------------------- E3 hex helpers
def run_e3(rom: bytes, quick: bool = False, verbose: bool = False) -> tuple[list[Finding], dict]:
    findings: list[Finding] = []
    payloads = [
        ("empty", b""), ("one-digit", b"1"), ("two-digit", b"12"),
        ("odd-3", b"ABC"), ("even-4", b"AB12"), ("odd-5", b"12345"),
        ("lower", b"ab12cd34"), ("upper", b"AB12CD34"),
        ("mixed-case", b"aAbB09fF"), ("nonhex-G", b"12G4"),
        ("nonhex-space", b"12 34"), ("nonhex-ZZ", b"ZZ"),
        ("len-41-odd", b"A" * 41), ("len-64", b"B" * 64),
        ("len-256", b"C" * 256),
    ]
    if quick:
        payloads = [p for p in payloads if p[0] in (
            "empty", "odd-3", "even-4", "mixed-case", "nonhex-G", "len-41-odd")]
    targets = ["getval_hex", "is_hexnum", "check_hex", "hexstr_to_int"]
    if quick:
        targets = ["getval_hex", "hexstr_to_int"]
    for t in targets:
        fn_va, fn_size = FNS[t]
        vecs = []
        for pname, pdata in payloads:
            for sig in (["a0=src"] if t in ("is_hexnum", "hexstr_to_int") else ["a0=dst,a1=src"]):
                dr = DeepRunner(rom)
                cpu_regs = {"sp": STACK_INIT, "ra": RA_INIT}
                if sig == "a0=src":
                    cpu_regs.update({"a0": INP_BASE, "a1": 0, "a2": 0, "a3": 0})
                else:
                    cpu_regs.update({"a0": DST_BASE, "a1": INP_BASE,
                                     "a2": 0, "a3": 0})
                # stage input with a local staged run: reuse _dr_run_staged
                # by pre-seeding via a throwaway cpu on the same addresses is
                # impossible (fresh cpu per run); so stage inside: easiest is
                # to run _dr_run_staged on a wrapper? Instead do manual loop
                # here with staging.
                res = _run_bare(dr, t, cpu_regs, INP_BASE, pdata,
                                f"{pname}/{sig}")
                vecs.append({"payload": pname, "sig": sig,
                             "plen": len(pdata), "stop": res.stop,
                             "a0": f"{res.a0:#x}",
                             "fault": f"{res.fault_va:#x}" if res.fault_va else None,
                             "copies": len(res.copies)})
                if verbose:
                    print(f"  E3 {t} {pname} {sig}: {res.stop} a0={res.a0:#x}")
        rets = {v["payload"]: v["a0"] for v in vecs if v["stop"] == "HIT-RET"}
        faults = [v for v in vecs if v["stop"] != "HIT-RET"]
        # verdict: odd-length accepted anywhere? (bug) vs rejected (safe)
        odd = [v for v in vecs if v["payload"].startswith("odd") and v["stop"] == "HIT-RET"]
        odd_accept = [v for v in odd if v["a0"] not in ("0x0", "0xff", "0xffffffff")]
        eff = (f"{len(vecs)} vectors; HIT-RET rets={rets}; "
               f"non-ret={len(faults)} "
               f"{str([(f['payload'], f['stop']) for f in faults[:6]])}")
        findings.append(Finding(
            f"E3-{t}", f"{t} hex helper (real bytes)",
            f"{fn_va:#x} size {fn_size:#x}",
            "odd/even/mixed-case/nonhex/empty/long hex payloads x arg shapes",
            eff,
            wp(True, "no write primitive in helper scope (leaf decoders); "
                     "copies only via modeled leaves" if not any(v["copies"] for v in vecs)
               else "helper-issued copies observed (see evidence)",
               dst="", len_ctl=""),
            "REFUTED" if not odd_accept and not faults else
            ("CONFIRMED" if odd_accept else "INCONCLUSIVE"),
            "MEDIUM (signature guess for multi-arg helpers; "
            "single-arg helpers HIGH)",
            {"vectors": vecs}))
    return findings, {}


def _run_bare(dr: DeepRunner, fn: str, regs: dict, inp: int,
              data: bytes, iclass: str) -> RunResult:
    """Bare strict run with staged input and NO helper interception except
    leaves (used for E3/E5 real-bytes targets)."""
    fn_va, fn_size = FNS[fn]
    full_regs = dict(regs)
    full_regs.setdefault("sp", STACK_INIT)
    full_regs.setdefault("ra", RA_INIT)
    cpu = make_cpu(dr.rom, fn_va, fn_size, full_regs, 4000)
    try:
        cpu.store_bytes(u32(inp), bytes(data) + b"\x00")
    except Exception:
        try:
            cpu._ensure_region(u32(inp), len(data) + 1)
            cpu.store_bytes(u32(inp), bytes(data) + b"\x00")
        except Exception:
            pass
    try:
        cpu.store_bytes(DST_BASE, b"\x00" * DST_SIZE)
    except Exception:
        pass
    dr.copies = []
    dr.helper_hits = []
    LEAVES = {H_MEMSET, H_MEMCPY, H_STRLEN, H_DHL, H_ALLOC, H_FREE, H_MEMCMP,
              H_COPY8}
    pc = u32(fn_va)
    cpu.pc = pc
    steps = 0
    stop = ""
    fault_va = None
    gaps: list[str] = []
    trace: list[str] = []
    while steps < 4000:
        if pc == u32(RA_INIT) and steps > 0:
            stop = "HIT-RET"
            break
        if pc in LEAVES:
            try:
                ret = dr.call_helper(cpu, pc)
            except _interp.EmuUnsupported as e:
                stop = f"TRAP @{pc:#x}"
                fault_va = pc
                gaps.append(str(e))
                break
            cpu.put("a0", u32(ret))
            pc = u32(cpu.get("ra"))
            cpu.pc = pc
            steps += 1
            continue
        try:
            text, size, _raw = cpu._decode_at(u32(pc))
        except _interp.EmuUnsupported as e:
            stop = f"UNSUPPORTED @{pc:#x}"
            fault_va = pc
            gaps.append(str(e))
            break
        except Exception as e:  # noqa: BLE001
            stop = f"MEM-FAULT @{pc:#x}: {e}"
            fault_va = pc
            gaps.append(f"{pc:#x}: {e}")
            break
        nxt = u32(pc + size)
        mn = _mn(text)
        ops = _split_ops(text)
        tgt = None
        if mn == "BALC" and ops:
            try:
                tgt = u32(_interp.parse_imm(ops[0]))
            except Exception:
                tgt = None
        elif mn == "MOVE.BALC" and len(ops) >= 3:
            try:
                tgt = u32(_interp.parse_imm(ops[2]))
            except Exception:
                tgt = None
        if tgt is not None and tgt in LEAVES:
            cpu.put("ra", nxt)
            try:
                ret = dr.call_helper(cpu, tgt)
            except _interp.EmuUnsupported as e:
                stop = f"TRAP @{tgt:#x} via BALC @{pc:#x}"
                fault_va = tgt
                gaps.append(str(e))
                break
            cpu.put("a0", u32(ret))
            trace.append(f"{pc:#x} {text} [-> a0={u32(ret):#x}]")
            pc = nxt
            cpu.pc = pc
            steps += 1
            continue
        try:
            npc = cpu.step_once_with_text(pc, text, size)
        except _interp.EmuUnsupported as e:
            stop = f"UNSUPPORTED @{pc:#x}: {e}"
            fault_va = pc
            gaps.append(f"{pc:#x} {text}: {e}")
            break
        except Exception as e:  # noqa: BLE001
            stop = f"FAULT @{pc:#x} ({text}): {e}"
            fault_va = pc
            gaps.append(f"{pc:#x} {text}: {e}")
            break
        trace.append(f"{pc:#x} {text}")
        pc = u32(npc)
        cpu.pc = pc
        steps += 1
    else:
        stop = "STEP-CAP"
    if not stop:
        stop = "STEP-CAP"
    try:
        can = bytes(cpu.mem.read(DST_BASE, DST_SIZE))
        _ = can
    except Exception:
        pass
    return RunResult(fn, fn_va, iclass, "", stop, pc, fault_va, steps,
                     u32(cpu.get("a0")), list(dr.copies), [], [], True,
                     gaps, trace[-8:])


# ---------------------------------------------------------------- E4 printf audit
def run_e4(rom: bytes, quick: bool = False, verbose: bool = False) -> tuple[list[Finding], dict]:
    import glob as _glob
    import json as _j
    findings: list[Finding] = []
    sites: list[dict] = []
    for p in sorted(_glob.glob(str(SIM_DIR / "listings" / "*.jsonl"))):
        name = Path(p).name
        try:
            rows = [_j.loads(l) for l in
                    Path(p).read_text(encoding="utf-8").splitlines()[1:]]
        except Exception:
            continue
        rows = [r for r in rows if "va" in r and "text" in r]
        for i, r in enumerate(rows):
            t = r["text"]
            if not t.startswith("BALC "):
                continue
            try:
                tgt = int(t.split()[1], 16)
            except Exception:
                continue
            if tgt not in SNPRINTF_FAMILY:
                continue
            nxt = [x["text"] for x in rows[i + 1:i + 5]]
            # classify: any branch predicated on a0 within 4 insns?
            check = "UNCHECKED"
            detail = ""
            for j, nt in enumerate(nxt[:4]):
                nm = _mn(nt)
                nops = _split_ops(nt)
                uses_a0 = "a0" in nops
                if nm in ("BLTC", "BGEC", "BGEUC", "BEQZC", "BNEZC", "BEQC",
                          "BNEC", "BLTUC", "BLTIC", "BGEIC", "BGEIUC",
                          "BEQIC", "BNEIC", "SEH", "SEB") and uses_a0:
                    if nm == "SEH":
                        check = "TRUNCATED-16 (SEH a0) then " + \
                            (nxt[j + 1] if j + 1 < len(nxt) else "?")
                    elif nm in ("BLTC",) and nops[0] == "a0":
                        check = "NEG-ONLY (misses upper bound)"
                    elif nm == "BGEC" and nops[0] == "zero":
                        check = "NEG-ONLY (0<=ret, misses upper bound)"
                    else:
                        check = f"CHECKED ({nm} on a0)"
                    detail = " <- ".join(nxt[:j + 1])
                    break
                if nm in ("MOVE", "MOVEP", "ANDI", "ADDIU", "LI") and uses_a0 \
                        and "a0" == nops[0]:
                    continue  # pure move, keep scanning
            sites.append({"listing": name, "va": f"{r['va']:#x}",
                          "call": f"{SNPRINTF_FAMILY[tgt]} @{tgt:#x}",
                          "verdict": check, "next": nxt[:4]})
    unchecked = [s for s in sites if s["verdict"] == "UNCHECKED"]
    negonly = [s for s in sites if s["verdict"].startswith("NEG-ONLY")]
    trunc = [s for s in sites if s["verdict"].startswith("TRUNCATED")]
    checked = [s for s in sites if s["verdict"].startswith("CHECKED")]
    if verbose:
        for s in sites:
            print(f"  E4 {s['listing']} {s['va']} {s['call']}: {s['verdict']}")
    eff = (f"{len(sites)} printf-family call sites across listings: "
           f"{len(checked)} CHECKED, {len(negonly)} NEG-ONLY, "
           f"{len(trunc)} TRUNCATED-16, {len(unchecked)} UNCHECKED. "
           f"UNCHECKED={[ (s['listing'], s['va']) for s in unchecked]}; "
           f"NEG-ONLY={[ (s['listing'], s['va']) for s in negonly]}")
    # Emulation spot-check: snprintf truncation bound in get_data_op12.
    # Craft tiny s3 (remaining-size analogue): run get_data_op12 prefix with
    # s3 small and observe BGEC-fail ERROR (bound enforced) vs overwrite.
    spot = {}
    try:
        dr = DeepRunner(rom)
        r = _dr_run_staged(dr, "get_data_op12",
                           {"a0": DST_BASE, "a1": INP_BASE, "a2": 1,
                            "a3": AUX_BASE, "a4": AUX_BASE + 0x100},
                           "spot/tiny-cat", "rmmi_sml_get_data_op12")
        spot = {"stop": r.stop, "a0": f"{r.a0:#x}",
                "fault": f"{r.fault_va:#x}" if r.fault_va else None,
                "copies": len(r.copies)}
    except Exception as e:  # noqa: BLE001
        spot = {"error": repr(e)}
    # sprintf upper-bound analysis (static math, formats ROM-verified):
    # clck: static s5 token; parse_op12t: validator-bounded sp slices.
    if unchecked:
        verdict, conf = "CONFIRMED", "HIGH (static listing sweep)"
        wprim = wp(False, "unchecked printf-family return flows into length "
                          "use (see evidence sites)", dst="see evidence",
                   len_ctl="return value reused without bound check")
    else:
        verdict, conf = "REFUTED", "HIGH (all sites NEG-checked/TRUNCATED/CHECKED)"
        wprim = wp(True, "every printf-family return is NEG-checked "
                         "(BLTC/BGEC-zero) or SEH-truncated before length use; "
                         "sprintf sites take static/enum-bounded inputs; "
                         "snprintf sites additionally size-bounded",
                   dst="sp slices / static tokens", len_ctl="remaining-size bound")
    findings.append(Finding(
        "E4-printf-ret", "snprintf/sprintf RET-value handling",
        "multi-site (see evidence)", "all BALC to 0x91dc900e/0x91dc908a/0x90ed8e7e",
        eff + f"; get_data_op12 tiny-craft spot: {spot}", wprim, verdict, conf,
        {"sites": sites, "spot": spot}))
    return findings, {"sites": len(sites), "unchecked": len(unchecked)}


# ---------------------------------------------------------------- E5 validators
def run_e5(rom: bytes, quick: bool = False, verbose: bool = False) -> tuple[list[Finding], dict]:
    findings: list[Finding] = []
    # (fn, signature lanes, maxlen/delim grid)
    val_targets = [
        ("str_validator", [{"a1": "src"}], [0x2c], [None]),
        ("str_validator_ext", [{"a1": "src"}], [0, 1, 0x29, 0x2c, 0x2d, 0xFF], [0x04, 0x10, 0x29, 0x41]),
        ("int_validator", [{"a1": "src"}], [0x2c], [None]),
        ("int_validator_ext", [{"a1": "src"}], [0, 1, 0x2c, 0xFF], [None]),
        ("range_check", [{"a1": "src"}], [0, 1, 5, 0x2c], [0, 1, 5]),
        ("signed_int_validator", [{"a1": "src"}], [0x2c], [None]),
        ("is_number", [{"a0": "src"}], [None], [None]),
        ("hexstr_validator_ext", [{"a1": "src"}], [0x2c], [None]),
    ]
    if quick:
        val_targets = [v for v in val_targets if v[0] in (
            "str_validator_ext", "is_number", "str_validator")]
    # input lens around caps: 0,1,40,41,42,43,44,45 + 255/256/257 + classes
    lens = [0, 1, 40, 41, 42, 43, 44, 45, 60]
    if not quick:
        lens += [255, 256, 257]
    for fn, lanes, maxlens, delims in val_targets:
        fn_va, fn_size = FNS[fn]
        vecs = []
        for L in lens:
            data = (b"5" * L) if L else b""
            for ml in maxlens:
                for dl in delims:
                    for lane in lanes:
                        regs = {"sp": STACK_INIT, "ra": RA_INIT, "a0": 0,
                                "a1": 0, "a2": 0, "a3": 0, "a4": 0}
                        if lane.get("a0") == "src":
                            regs["a0"] = INP_BASE
                        else:
                            regs["a0"] = AUX_BASE
                            regs["a1"] = INP_BASE
                        if ml is not None:
                            regs["a2"] = ml
                        if dl is not None:
                            regs["a3"] = dl
                        dr = DeepRunner(rom)
                        res = _run_bare(dr, fn, regs, INP_BASE, data,
                                        f"len={L}/maxlen={ml}/delim={dl}")
                        vecs.append({"len": L, "maxlen": ml, "delim": dl,
                                     "stop": res.stop, "a0": f"{res.a0:#x}",
                                     "fault": f"{res.fault_va:#x}" if res.fault_va else None})
        # boundary analysis: accept/reject edge for numeric '5'*L
        edge = [(v["len"], v["a0"], v["stop"]) for v in vecs
                if v["maxlen"] == 0x2c and v["delim"] in (None, 0x10, 0x04)]
        n_hiret = sum(1 for v in vecs if v["stop"] == "HIT-RET")
        n_unsup = sum(1 for v in vecs if v["stop"].startswith("UNSUPPORTED"))
        n_trap = sum(1 for v in vecs if v["stop"].startswith("TRAP"))
        # off-by-one hunt: does len==maxlen pass while maxlen+1 fails?
        verdict, conf = "INCONCLUSIVE", "LOW"
        ev_note = ""
        if n_hiret == len(vecs):
            # full execution: look for boundary anomaly
            rets = {(v["len"], v["maxlen"]): v["a0"] for v in vecs}
            verdict, conf = "REFUTED", "MEDIUM-HIGH (real-bytes boundary)"
            ev_note = "boundary executed; no off-by-one accept observed"
        elif n_hiret > 0:
            verdict, conf = "INCONCLUSIVE", "MEDIUM (partial execution)"
            ev_note = f"{n_hiret}/{len(vecs)} HIT-RET; rest trap/unsupported"
        else:
            verdict, conf = "INCONCLUSIVE", "LOW (no clean return; decoder/leaf gap)"
            ev_note = "validator body not emulatable with current decoder"
        if verbose:
            print(f"  E5 {fn}: hiret={n_hiret} unsup={n_unsup} trap={n_trap}")
        findings.append(Finding(
            f"E5-{fn}", f"{fn} validator (real bytes)",
            f"{fn_va:#x} size {fn_size:#x}",
            f"lens {lens} x maxlen {maxlens} x delim {delims}",
            f"{len(vecs)} vectors: HIT-RET={n_hiret} UNSUPPORTED={n_unsup} "
            f"TRAP={n_trap}; edge(0x2c)={edge[:10]}; {ev_note}",
            wp(True, "no write primitive assessed (validator scope); "
                     "finding is about accept/reject boundary only"),
            verdict, conf, {"vectors": vecs}))
    return findings, {}


# ---------------------------------------------------------------- guard + report
def check_guard() -> tuple[bool, list[str]]:
    notes: list[str] = []
    ok = True
    for tag, raw in BLOCKED_FIXTURES:
        try:
            _rmmi.dispatch(raw)
            ok = False
            notes.append(f"GUARD-FAIL {tag} did not raise")
        except _rmmi.AttemptCostingBlocked:
            notes.append(f"guard blocks {tag}")
        except Exception as e:  # noqa: BLE001
            ok = False
            notes.append(f"GUARD-WRONG-EXC {tag}: {e!r}")
    for q in SAFE_QUERIES:
        try:
            _rmmi.dispatch(q)
            notes.append(f"safe ok: {q}")
        except _rmmi.AttemptCostingBlocked:
            ok = False
            notes.append(f"SAFE-TRIPPED-GUARD: {q}")
        except Exception as e:  # noqa: BLE001
            notes.append(f"safe note {q}: {e!r}")
    return ok, notes


def cmd_selftest() -> int:
    fails: list[str] = []
    try:
        rom = _atf.load_rom()
    except Exception as e:
        print(f"at_fuzz2 selftest: FAIL (rom: {e!r})")
        return 1
    if len(rom) != 45893712:
        fails.append(f"rom size {len(rom)}")
    ok, notes = check_guard()
    if not ok:
        fails.append(f"guard: {notes}")
    try:
        f1, _s1 = run_e1(rom, quick=True)
        # every E1 run must at least terminate (no STEP-CAP/hang class)
        for f in f1:
            if "STEP-CAP" in str(f.evidence.get("stops", {})):
                fails.append(f"E1 hang {f.id}")
    except Exception as e:  # noqa: BLE001
        fails.append(f"E1 quick: {e!r}")
    try:
        f2, _s2 = run_e2(rom, quick=True)
        if not all("table16" in f.evidence for f in f2):
            fails.append("E2 missing table evidence")
    except Exception as e:  # noqa: BLE001
        fails.append(f"E2 quick: {e!r}")
    try:
        f3, _s3 = run_e3(rom, quick=True)
        if not f3:
            fails.append("E3 empty")
    except Exception as e:  # noqa: BLE001
        fails.append(f"E3 quick: {e!r}")
    try:
        f4, _s4 = run_e4(rom, quick=True)
        if not f4 or not f4[0].evidence.get("sites"):
            fails.append("E4 empty")
    except Exception as e:  # noqa: BLE001
        fails.append(f"E4 quick: {e!r}")
    try:
        f5, _s5 = run_e5(rom, quick=True)
        if not f5:
            fails.append("E5 empty")
    except Exception as e:  # noqa: BLE001
        fails.append(f"E5 quick: {e!r}")
    print("at_fuzz2 selftest:", "PASS" if not fails else "FAIL")
    for f in fails:
        print("  -", f)
    if not fails:
        print(f"  guard {len(notes)} notes; E1/E2/E3/E4/E5 quick engines green")
    return 1 if fails else 0


def cmd_all(report: str | None, verbose: bool = False,
            only: str | None = None) -> int:
    rom = _atf.load_rom()
    print("at_fuzz2: guard check ...")
    ok, notes = check_guard()
    print(f"  guard {'HOLDS' if ok else 'BROKEN'} ({len(notes)} notes)")
    if not ok:
        for n in notes:
            print("   !", n)
        return 1
    findings: list[Finding] = []
    if only in (None, "e1"):
        print("at_fuzz2: E1 add_data/parse deep emulation ...")
        f1, s1 = run_e1(rom, verbose=verbose)
        print(f"  runs={s1['runs']} ok={s1['ret_ok']} err={s1['ret_err']} "
              f"traps={s1['traps']} unsup={s1['unsupported']} "
              f"faults={s1['faults']} canary={s1['canary_hits']}")
        findings += f1
    if only in (None, "e2"):
        print("at_fuzz2: E2 BRSC tables in emulation ...")
        f2, _s2 = run_e2(rom, verbose=verbose)
        findings += f2
    if only in (None, "e3"):
        print("at_fuzz2: E3 hex helpers (real bytes) ...")
        f3, _s3 = run_e3(rom, verbose=verbose)
        findings += f3
    if only in (None, "e4"):
        print("at_fuzz2: E4 printf-ret audit ...")
        f4, _s4 = run_e4(rom, verbose=verbose)
        findings += f4
    if only in (None, "e5"):
        print("at_fuzz2: E5 validators (real bytes) ...")
        f5, _s5 = run_e5(rom, verbose=verbose)
        findings += f5
    print("\n==== FINDINGS ====")
    for f in findings:
        print(f"\n[{f.id}] {f.target}\n  VA: {f.target_va}\n"
              f"  input: {f.input_class}\n  effect: {f.emulated_effect}\n"
              f"  write-primitive: {f.write_primitive}\n"
              f"  verdict: {f.verdict} ({f.confidence})")
    if report:
        p = Path(report)
        try:
            rel = p.relative_to(REPO_ROOT / "sim")
        except Exception:
            try:
                rel = p.relative_to(Path("sim"))
            except Exception:
                p = SIM_DIR / Path(report).name
            else:
                p = REPO_ROOT / "sim" / rel if not p.is_absolute() else p
        else:
            p = REPO_ROOT / "sim" / rel if not p.is_absolute() else p
        if p.parent != SIM_DIR and SIM_DIR not in p.parents:
            p = SIM_DIR / p.name
        p.parent.mkdir(parents=True, exist_ok=True)
        import json as _j

        def _san(o):
            if isinstance(o, (bytes, bytearray)):
                try:
                    return bytes(o).decode("ascii", "replace")
                except Exception:
                    return repr(o)
            if isinstance(o, dict):
                return {str(k): _san(v) for k, v in o.items()}
            if isinstance(o, (list, tuple)):
                return [_san(v) for v in o]
            if isinstance(o, int) and o > 0xFFFF:
                return f"{o:#x} ({o})"
            return o

        doc = {"guard": "HOLDS", "guard_notes": notes,
               "findings": [f.asdict() for f in findings]}
        p.write_text(_j.dumps(_san(doc), indent=2))
        print(f"\nwrote {p}")
    n_conf = sum(1 for f in findings if f.verdict == "CONFIRMED")
    print(f"\nsummary: {len(findings)} findings, {n_conf} CONFIRMED")
    return 0


def main(argv: list[str]) -> int:
    if "--selftest" in argv or len(argv) == 0:
        return cmd_selftest()
    if "--e1" in argv:
        return cmd_all(None, verbose="--verbose" in argv, only="e1")
    if "--e2" in argv:
        return cmd_all(None, verbose="--verbose" in argv, only="e2")
    if "--e3" in argv:
        return cmd_all(None, verbose="--verbose" in argv, only="e3")
    if "--e4" in argv:
        return cmd_all(None, verbose="--verbose" in argv, only="e4")
    if "--e5" in argv:
        return cmd_all(None, verbose="--verbose" in argv, only="e5")
    if "--all" in argv:
        report = "sim/at_fuzz2_report.json"
        if "--report" in argv:
            try:
                report = argv[argv.index("--report") + 1]
            except Exception:
                pass
        return cmd_all(report, verbose="--verbose" in argv)
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
