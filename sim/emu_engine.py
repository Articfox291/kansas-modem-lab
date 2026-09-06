#!/usr/bin/env python3
"""modem_emu — PC-side nanoMIPS modem emulation engine (Kansas lab).

Jump-off point for full-depth modem bytecode execution on PC. Design:

  image.py    load md1rom/md1img, GFH/CATI helpers, carve-by-VA
  memory.py   regions + perms + MPU model + hooks + SMEM
  decode.py   table-driven nanoMIPS decoder (grown by conformance vs Ghidra)
  backends/   execution backends (ghidra headless bridge now, python interp next)
  stubs.py    BALC-target stub registry (ret const / behavioral / oracle / trap)
  oracle.py   HW-bound bridge: device answers ONLY read-only queries; all recorded
  tracer.py   insn trace + coverage + stock-vs-patch diff
  decomp.py   batch carve->disasm->listing cache (JSONL), incremental
  engine.py   orchestrator (this file's Emulator) + CLI selftest

Rules: stdlib only. No device contact from this package (oracle transport lives
outside; default oracle raises + records). Everything improvable: each module
has a CONFORMANCE section listing ground-truth checks against Ghidra listings.
"""
from __future__ import annotations

import json
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path
import os

REPO = Path(__file__).resolve().parents[1]
SIM = REPO / "sim"
TEMP = Path(os.environ.get("MODEM_LAB_TMP",
                str(Path(__file__).resolve().parent / "Temp")))
TEMP.mkdir(parents=True, exist_ok=True)
CATI_JSON = TEMP / "cati_syms.json"

VA_BASE = 0x90000000          # modem PCORE VA base
FILE_HDR = 0x200              # md1img header before md1rom payload
ROM_SIZE = 45893712
STACK_BASE = 0xA0000000
CTX_BASE = 0xB0000000
PAGE = 0x1000

# Verified nanoMIPS vectors (Ghidra ground truth, do not change):
#   LI a0,0x1 = bytes 01 d2 | JRC ra = bytes e0 db | LI a0,0 = bytes 00 d2


# ---------------------------------------------------------------- image
@dataclass
class Image:
    data: bytes
    base: int = VA_BASE

    @classmethod
    def load_romonly(cls, path: Path | None = None) -> "Image":
        p = path or (REPO / "md1work_romonly.bin")
        return cls(p.read_bytes())

    @classmethod
    def load_md1img_rom(cls, path: Path | None = None) -> "Image":
        p = path or (REPO / "stock_XT2513V" / "md1img.img")
        return cls(p.read_bytes()[FILE_HDR:FILE_HDR + ROM_SIZE])

    def carve(self, va: int, size: int) -> bytes:
        off = va - self.base
        if not (0 <= off < len(self.data)):
            raise ValueError(f"VA {va:#x} outside image")
        return self.data[off:off + size]

    def u32(self, va: int) -> int:
        return struct.unpack("<I", self.carve(va, 4))[0]


def load_cati(path: Path | None = None) -> dict[str, tuple[int, int]]:
    p = path or CATI_JSON
    raw = json.loads(p.read_text())
    return {k: (int(v[0], 16), int(v[1], 16)) for k, v in raw.items()}


# ---------------------------------------------------------------- memory
PERM_R, PERM_W, PERM_X = 4, 2, 1


@dataclass
class Region:
    name: str
    base: int
    size: int
    perm: int
    data: bytearray = field(init=False)

    def __post_init__(self) -> None:
        self.data = bytearray(self.size)

    def contains(self, addr: int, ln: int = 1) -> bool:
        return self.base <= addr and addr + ln <= self.base + self.size


class MemoryFault(Exception):
    def __init__(self, addr: int, kind: str):
        super().__init__(f"{kind} fault @ {addr:#x}")
        self.addr, self.kind = addr, kind


class Memory:
    """Flat 32-bit memory with regions, perms, read/write hooks, MPU log."""

    def __init__(self) -> None:
        self.regions: list[Region] = []
        self.hooks: dict[int, list] = {}   # addr -> [callables(kind,addr,size)]
        self.fault_log: list[tuple[int, str]] = []

    def add(self, name: str, base: int, size: int, perm: int,
            init: bytes = b"") -> Region:
        if any(not (base + size <= r.base or r.base + r.size <= base)
               for r in self.regions):
            raise ValueError(f"region {name} overlaps")
        r = Region(name, base, size, perm)
        r.data[:len(init)] = init
        self.regions.append(r)
        return r

    def find(self, addr: int, ln: int = 1) -> Region | None:
        for r in self.regions:
            if r.contains(addr, ln):
                return r
        return None

    def _fire(self, kind: str, addr: int, size: int) -> None:
        for cb in self.hooks.get(addr, []):
            cb(kind, addr, size)

    def read(self, addr: int, ln: int) -> bytes:
        r = self.find(addr, ln)
        if r is None or not (r.perm & PERM_R):
            self.fault_log.append((addr, "read"))
            raise MemoryFault(addr, "read")
        self._fire("read", addr, ln)
        o = addr - r.base
        return bytes(r.data[o:o + ln])

    def write(self, addr: int, buf: bytes) -> None:
        r = self.find(addr, len(buf))
        if r is None or not (r.perm & PERM_W):
            self.fault_log.append((addr, "write"))
            raise MemoryFault(addr, "write")
        self._fire("write", addr, len(buf))
        o = addr - r.base
        r.data[o:o + len(buf)] = buf

    def hook(self, addr: int, cb) -> None:
        self.hooks.setdefault(addr, []).append(cb)

    @classmethod
    def with_image(cls, img: Image, va: int | None = None,
                   size: int | None = None) -> "Memory":
        """Map whole ROM R-X + stack + ctx (emulator default layout)."""
        m = cls()
        m.add("rom", img.base, len(img.data), PERM_R | PERM_X, img.data)
        m.add("stack", STACK_BASE, 0x10000, PERM_R | PERM_W)
        m.add("ctx", CTX_BASE, 0x10000, PERM_R | PERM_W)
        return m


# ---------------------------------------------------------------- decode
# Table-driven nanoMIPS decoder. Full tables live in sim/decode_tables.py
# (harvested from tools/ghidra-nanomips/data/languages/nanomips.sinc);
# decode_one below keeps its legacy LI/JRC fast paths (and their exact
# legacy text) and delegates everything else to decode_tables.decode_bytes.
# CONFORMANCE: run decode_conformance() against Ghidra listings; every new
# encoding needs ≥2 ground-truth vectors before it is trusted.
# gpr3 attach (nanomips.sinc:261-264): raw 0-7 -> MIPS regno
# [16,17,18,19,4,5,6,7]; all 8 verified against the fn_* corpus.
RT3_PROVISIONAL = {0: "s0", 1: "s1", 2: "s2", 3: "s3",
                   4: "a0", 5: "a1", 6: "a2", 7: "a3"}

try:  # preferred when sim/ is a package on sys.path
    from sim.decode_tables import (  # noqa: F401
        UnknownInsn as _DtUnknown, decode_bytes as _dt_decode_bytes)
except ImportError:
    try:  # running as script (python sim/emu_engine.py puts sim/ on path)
        from decode_tables import (  # noqa: F401
            UnknownInsn as _DtUnknown, decode_bytes as _dt_decode_bytes)
    except ImportError:
        _dt_decode_bytes = None  # type: ignore[assignment]
        _DtUnknown = Exception  # type: ignore[assignment,misc]


@dataclass
class Insn:
    addr: int
    size: int
    text: str
    raw: bytes


def decode_one(mem: Memory, addr: int) -> Insn:
    try:
        h = mem.read(addr, 2)
    except MemoryFault:
        raise MemoryFault(addr, "exec")
    w = struct.unpack("<H", h)[0]
    # LI[16]: pool10_6 == 0b110100 (bits15-10). rt3=bits9-7, imm7=bits6-0.
    # imm7==127 means -1 (sinc:1911); that case falls through to the full
    # decoder below so its text matches Ghidra ("LI a3,-0x1").
    if (w >> 10) == 0b110100 and (w & 0x7F) != 0x7F:
        rt = RT3_PROVISIONAL.get((w >> 7) & 7, f"r3_{(w >> 7) & 7}")
        return Insn(addr, 2, f"LI {rt},{w & 0x7F:#x}", h)
    # JRC: pool10_6 == 0b110110 (16-bit) with JRC sub-opcode (bit4==0,
    # bits3-0==0; sinc:1655-1666). Narrowed so the pool-mates BEQC-16,
    # BNEC-16 and JALRC-ra fall through to decode_tables below.
    # Legacy text ("JRC r31", raw number) is preserved for conformance.
    if (w >> 10) == 0b110110 and ((w >> 4) & 1) == 0 and (w & 15) == 0:
        return Insn(addr, 2, f"JRC r{(w >> 5) & 31}", h)
    # Full decode via harvested tables (16/32/48-bit). Falls back to the
    # legacy DB_ header when bytes match no table entry.
    if _dt_decode_bytes is not None:
        try:
            try:
                blob = mem.read(addr, 6)
            except MemoryFault:
                try:
                    blob = mem.read(addr, 4)
                except MemoryFault:
                    blob = h
            text, size = _dt_decode_bytes(addr, bytes(blob))
            return Insn(addr, size, text, bytes(blob[:size]))
        except _DtUnknown:
            pass
    # 32-bit forms: need lo half for full decode; report header for now.
    return Insn(addr, 2, f"DB_{w:04x}", h)


def decode_conformance() -> list[str]:
    """Vectors verified against Ghidra Nmdis2 output. Extend, never weaken."""
    m = Memory()
    m.add("t", 0x1000, 0x100, PERM_R, bytes.fromhex("01d2e0db00d2"))
    fails = []
    for addr, want in ((0x1000, "LI a0,0x1"), (0x1002, "JRC r31"),
                       (0x1004, "LI a0,0x0")):
        got = decode_one(m, addr).text
        if got != want:
            fails.append(f"{addr:#x}: got {got!r} want {want!r}")
    # Extended vectors: (addr, hexbytes, want) harvested from the fn_*
    # corpus (ground truth = Nmdis2 text). PC-relative targets use their
    # true corpus addresses. decode_tables.verify_corpus() checks all 1191.
    extra: list[tuple[int, str, str]] = [
        (0x905DF3A2, "5a1c", "SAVE 0x50,fp,ra,s0,s1,s2,s3,s4,s5,s6,s7"),
        (0x905DF3A4, "34ff", "MOVEP s4,s1,a1,a2"),
        (0x905DF416, "96bd", "MOVEP a1,a2,s6,a0"),
        (0x905DF3A8, "0412", "MOVE s0,a0"),
        (0x905DF3AA, "8f2a743e", "BALC 0x90ed3222"),
        (0x905DF414, "4c3b", "BALC 0x905df762"),
        (0x905DF452, "3e18", "BC 0x905df492"),
        (0x905DF756, "0128a813", "BC 0x905f0b02"),
        (0x905DF3E2, "90c8f608", "BNEIC a0,0x1,0x905df4dc"),
        (0x905DF462, "e0c830b0", "BEQIC a3,0x16,0x905df496"),
        (0x905DF4E0, "329a", "BEQZC a0,0x905df514"),
        (0x905DF71A, "20b8", "BNEZC s0,0x905df73c"),
        (0x905DF3C2, "8cca84b3", "BGEIUC s4,0x16,0x905df74a"),
        (0x905EDFE6, "f2889bff", "BGEUC s2,a3,0x905edf84"),
        (0x9198584C, "3cca0c18", "BLTIUC s1,0x3,0x9198585c"),
        (0x905EE044, "26aac7ff", "BLTUC a2,s1,0x905ee00e"),
        (0x905DF402, "d08b2a00", "BEQC s0,fp,0x905df430"),
        (0x905EDFF8, "35da", "BEQC s3,a0,0x905ee004"),
        (0x91985890, "77da", "BNEC a3,a0,0x919858a0"),
        (0x905DF3D4, "e0a89a01", "BNEC zero,a3,0x905df572"),
        (0x905DF3FE, "c4c82e00", "BBEQZC a2,0x0,0x905df430"),
        (0x905DF3DC, "1f0a1bff", "MOVE.BALC a0,s0,0x905df2fa"),
        (0x905DF494, "5a1d",
         "RESTORE.JRC 0x50,fp,ra,s0,s1,s2,s3,s4,s5,s6,s7"),
        (0x905EDFA0, "90da", "JALRC ra,s4"),
        (0x905DF548, "05480080", "BRSC a1"),
        (0x905DF46C, "a360a6468501", "ADDIUPC a1,%pcrel(0x91e33b18)"),
        (0x905EDF58, "2b629a314b94", "LWPC s1,0x24aa10f8"),
        (0x919857A2, "fbe08702", "ALUIPC a3,%pcrel_hi(0x25d35000)"),
        (0x905EEA8A, "ef606484cd94", "SWPC a3,0x252c6ef4"),
        (0x905DF3C8, "c06010552500", "LI a2,0x255510"),
        (0x905EEA50, "ffd3", "LI a3,-0x1"),
        (0x905DF310, "d0800680", "ADDIU a2,s0,-0x6"),
        (0x905DF430, "8992", "ADDIU s4,s4,0x1"),
        (0x905DF33E, "f1800160", "SEQI a3,s1,0x1"),
        (0x905EEBCC, "67a5f790", "LBU a7,-0x9(a3)"),
        (0x905EE9B0, "6b210f82", "LSA s0,a7,a7,0x1"),
        (0x905DF3E8, "34220729", "LBUX a1,s4(s1)"),
        (0x905DF424, "932287b0", "SBX s6,s3(s4)"),
        (0x905DF3EC, "d483ff20", "ANDI fp,s4,0xff"),
        (0x905DF652, "0cf1", "ANDI s2,s0,0xff"),
        (0x905EDF88, "e4832d10", "XORI ra,a0,0x2d"),
        (0x905F0E14, "24820150", "SLTIU s1,a0,0x1"),
        # JOB1 harvest 2026-09-06: pool-08 C0 moves (sinc:2261,2358).
        # Ghidra ground truth from sim/listings (stack_get_active_module_id,
        # kal_adm_get_alloc_size, __kal_adm_alloc_core). Ghidra wins on conflict.
        (0x9002635C, "e4203010", "MFC0 a3,0x4,0x2"),
        (0x90004710, "82223030", "MFC0 s4,0x2,0x6"),
        (0x90004546, "a2207030", "MTC0 a1,0x2,0x6"),
        (0x90004A9C, "c2207030", "MTC0 a2,0x2,0x6"),
        # JOB1 pool-29 S9 singles (sinc S9 constructors). Ground truth from
        # fresh decomp.py listings (see inventory in decode_tables._dec_p41_s9).
        (0x90046D3E, "e7a4ff80", "LB a3,-0x1(a3)"),
        (0x900E6DA4, "e6a4f480", "LB a3,-0xc(a2)"),
        (0x9000F2B0, "f7a47a88", "SB a3,-0x86(s7)"),
        (0x9000F2BC, "f7a47888", "SB a3,-0x88(s7)"),
        (0x9000787A, "fea49290", "LBU a3,-0x6e(fp)"),
        (0x90007886, "fea49390", "LBU a3,-0x6d(fp)"),
        (0x90049F80, "b0a4e8a0", "LH a1,-0x18(s0)"),
        (0x90049F9C, "b5a4e8a0", "LH a1,-0x18(s5)"),
        (0x9000786E, "fea490b0", "LHU a3,-0x70(fp)"),
        (0x90007BF8, "1ea5b4b0", "LHU a4,-0x4c(fp)"),
        (0x90007834, "fea4d8c0", "LW a3,-0x28(fp)"),
        (0x90007A48, "bea4d8c0", "LW a1,-0x28(fp)"),
        (0x900248E4, "85a4c0a8", "SH a0,-0x40(a1)"),
        (0x900248EC, "85a4c2a8", "SH a0,-0x3e(a1)"),
        (0x900049D0, "c4a4fcc8", "SW a2,-0x4(a0)"),
        (0x90004C12, "25a5fcc8", "SW a5,-0x4(a1)"),
        # JOB1 pool-29 LWM/SWM (sinc:2213,3669). Observed SWM at 0x900367b2.
        (0x900367B2, "1da5302c", "SWM a4,0x30(sp),0x2"),
        (0x900367B6, "5da5382c", "SWM a6,0x38(sp),0x2"),
        (0x9000F240, "dda43824", "LWM a2,0x38(sp),0x2"),
        (0x9000F410, "dda42c24", "LWM a2,0x2c(sp),0x2"),
    ]
    m2 = Memory()
    for i, (addr, hx, want) in enumerate(extra):
        page = addr & ~0xFFF
        if m2.find(page, 0x1000) is None:
            m2.add(f"v{i}", page, 0x1000, PERM_R | PERM_W)
        m2.write(addr, bytes.fromhex(hx))
    for addr, _hx, want in extra:
        got = decode_one(m2, addr).text
        if got != want:
            fails.append(f"{addr:#x}: got {got!r} want {want!r}")
    return fails


# ---------------------------------------------------------------- stubs
STUB_RET1 = bytes.fromhex("01d2e0db")  # LI a0,1 ; JRC ra (Ghidra-verified)
STUB_RET0 = bytes.fromhex("00d2e0db")  # LI a0,0 ; JRC ra


class StubRegistry:
    """BALC-target policies: ret1 | ret0 | behavioral(fn) | oracle(name) | trap."""

    def __init__(self) -> None:
        self.table: dict[int, tuple[str, object]] = {}
        self.hits: list[tuple[int, str]] = []

    def set(self, va: int, policy: str, arg: object = None) -> None:
        assert policy in ("ret1", "ret0", "behavioral", "oracle", "trap")
        self.table[va] = (policy, arg)

    def materialize(self, mem: Memory) -> int:
        """Create stub bytes at each registered target. Returns count."""
        n = 0
        for va, (policy, _) in self.table.items():
            if mem.find(va, 4) is not None:
                continue
            page = va & ~(PAGE - 1)
            if mem.find(page, PAGE) is None:
                # R/W/X: emulator scratch, not real MPU state
                mem.add(f"stub{n}", page, PAGE, PERM_R | PERM_W | PERM_X)
            if policy == "ret1":
                mem.write(va, STUB_RET1)
            elif policy == "ret0":
                mem.write(va, STUB_RET0)
            # behavioral/oracle/trap resolved at runtime by backends
            n += 1
        return n


# ---------------------------------------------------------------- oracle
class OracleUnimplemented(Exception):
    pass


@dataclass
class OracleRecord:
    op: str
    params: dict
    result: str = "UNIMPLEMENTED"


class HwOracle:
    """HW-bound bridge. Device answers ONLY read-only queries; ALL recorded.

    Transport is deliberately OUT of scope here (implemented by the
    device-side agent): this class defines the op schema + transcript log so
    PC emulation and device oracle stay in lockstep and every HW answer is
    replayable offline later.
    """

    OPS = ("nv_read",      # read NVRAM/LID record (needs LID, rec_idx)
           "chl_hash",     # CustCHL_Calculate_Hash passthrough
           "chl_mac",      # CustCHL MAC verify passthrough
           "efuse_read",   # eFuse/OTP bit read
           "sml_status",   # modem SML status snapshot (read-only AT ? form)
           "apdu_xfer")    # raw eUICC APDU round-trip (for STORE-DATA forensics)

    def __init__(self, logdir: Path | None = None):
        self.logdir = logdir or (SIM / "oracle_logs")
        self.transcript: list[OracleRecord] = []

    def query(self, op: str, params: dict) -> OracleRecord:
        assert op in self.OPS, f"unknown oracle op {op}"
        rec = OracleRecord(op, dict(params))
        self.transcript.append(rec)
        raise OracleUnimplemented(
            f"oracle op {op} needs device transport (read-only). "
            f"Recorded transcript entry #{len(self.transcript)}.")

    def save(self, name: str) -> Path:
        self.logdir.mkdir(parents=True, exist_ok=True)
        p = self.logdir / f"{name}.jsonl"
        with p.open("w") as f:
            for r in self.transcript:
                f.write(json.dumps({"op": r.op, "params": r.params,
                                    "result": r.result}) + "\n")
        return p


# ---------------------------------------------------------------- tracer
@dataclass
class TraceEvent:
    step: int
    pc: int
    text: str
    a0: int | None = None


class Tracer:
    """Insn trace sink + coverage + stock-vs-patch diff.

    Extension notes (trace_tools.py interop, additive only):
      * to_normalized() exports events in the shared JSONL schema
        {step, pc, bytes, text, regs?} (bytes="" when the event source
        carries no bytes; verifiers skip byte checks then).
      * coverage_delta() / diff_detail() expose first-divergence +
        coverage-delta as data; diff() keeps its legacy lines first so
        existing consumers stay green, then appends delta lines.
    """

    def __init__(self) -> None:
        self.events: list[TraceEvent] = []
        self.coverage: set[int] = set()

    def log(self, step: int, pc: int, text: str, a0: int | None = None) -> None:
        self.events.append(TraceEvent(step, pc, text, a0))
        self.coverage.add(pc)

    def save(self, path: Path) -> None:
        with path.open("w") as f:
            for e in self.events:
                f.write(json.dumps({"step": e.step, "pc": f"{e.pc:#x}",
                                    "text": e.text, "a0": e.a0}) + "\n")

    def to_normalized(self) -> list[dict]:
        """Export events in the sim/trace_tools.py JSONL schema."""
        out: list[dict] = []
        for e in self.events:
            d: dict = {"step": e.step, "pc": f"{e.pc:#x}",
                       "bytes": "", "text": e.text}
            if e.a0 is not None:
                d["regs"] = {"a0": f"{e.a0:#x}"}
            out.append(d)
        return out

    @staticmethod
    def coverage_delta(a: "Tracer", b: "Tracer") -> dict:
        """Coverage sets compared as data: sizes, delta, only-in sets."""
        ca, cb = set(a.coverage), set(b.coverage)
        return {"a": len(ca), "b": len(cb), "delta": len(ca) - len(cb),
                "only_in_a": sorted(ca - cb), "only_in_b": sorted(cb - ca),
                "common": sorted(ca & cb)}

    @staticmethod
    def diff_detail(a: "Tracer", b: "Tracer") -> dict:
        """First divergence + coverage delta as data (diff() renders it)."""
        div: dict | None = None
        for ea, eb in zip(a.events, b.events):
            if ea.pc != eb.pc or ea.text != eb.text:
                div = {"step": ea.step, "a_pc": ea.pc, "b_pc": eb.pc,
                       "a_text": ea.text, "b_text": eb.text}
                break
        if div is None and len(a.events) != len(b.events):
            div = {"step": min(len(a.events), len(b.events)),
                   "a_pc": None, "b_pc": None, "a_text": "<end>",
                   "b_text": "<end>",
                   "note": f"common prefix; lengths {len(a.events)} "
                           f"vs {len(b.events)}"}
        return {"divergence": div, "lengths": (len(a.events), len(b.events)),
                "coverage": Tracer.coverage_delta(a, b)}

    @staticmethod
    def diff(a: "Tracer", b: "Tracer") -> list[str]:
        """First divergence between two traces (e.g. stock vs patch).

        Legacy lines first (unchanged format), then coverage-delta
        extension lines (added for sim/trace_tools.py; harmless to old
        consumers which only read the head).
        """
        out = []
        for ea, eb in zip(a.events, b.events):
            if ea.pc != eb.pc or ea.text != eb.text:
                out.append(f"diverge step {ea.step}: "
                           f"{ea.pc:#x} {ea.text} vs {eb.pc:#x} {eb.text}")
                break
        out.append(f"coverage: {len(a.coverage)} vs {len(b.coverage)} pcs")
        # --- extension: coverage delta + only-in sets + length note ---
        det = Tracer.diff_detail(a, b)
        cov = det["coverage"]
        out.append(f"coverage-delta: {cov['delta']:+d} pcs "
                   f"(a={cov['a']} b={cov['b']})")
        if det["divergence"] is None and det["lengths"][0] == det["lengths"][1]:
            out.append("no divergence in common prefix "
                       f"({det['lengths'][0]} steps each)")
        if cov["only_in_a"]:
            show = " ".join(f"{v:#x}" for v in cov["only_in_a"][:8])
            more = "" if len(cov["only_in_a"]) <= 8 else " ..."
            out.append(f"only-in-a: {len(cov['only_in_a'])} pcs {show}{more}")
        if cov["only_in_b"]:
            show = " ".join(f"{v:#x}" for v in cov["only_in_b"][:8])
            more = "" if len(cov["only_in_b"]) <= 8 else " ..."
            out.append(f"only-in-b: {len(cov['only_in_b'])} pcs {show}{more}")
        la, lb = det["lengths"]
        if la != lb:
            out.append(f"length: {la} vs {lb} steps")
        return out


# ---------------------------------------------------------------- selftest
def selftest() -> int:
    fails: list[str] = []
    fails += [f"decode: {x}" for x in decode_conformance()]
    try:
        img = Image.load_romonly()
        assert len(img.data) == ROM_SIZE, f"rom size {len(img.data)}"
        assert img.carve(0x905DF2FA, 4).hex(" ") == "14 1e 24 12", "SML head"
        assert img.carve(0x91985788, 2).hex(" ") == "66 1e", "esmlck head"
    except Exception as e:  # noqa: BLE001
        fails.append(f"image: {e}")
    try:
        syms = load_cati()
        a, b = syms["custom_check_link_sml_legal_sim_rule"]
        assert (a, b) == (0x905DF2FA, 0x905DF358), "cati extent"
        assert len(syms) > 100000, "cati count"
    except Exception as e:  # noqa: BLE001
        fails.append(f"cati: {e}")
    try:
        m = Memory.with_image(Image(b"\x00" * 0x100, base=0x90000000))
        m.add("rwx", 0x20000000, PAGE, PERM_R | PERM_W)
        m.write(0x20000000, b"\x01\xd2")
        assert decode_one(m, 0x20000000).text == "LI a0,0x1"
        sr = StubRegistry()
        sr.set(0x9198A6F0, "ret1")
        assert sr.materialize(m) == 1
        assert m.read(0x9198A6F0, 4) == STUB_RET1
        try:
            m.read(0xDEAD0000, 4)
            fails.append("memory: fault not raised")
        except MemoryFault:
            pass
    except Exception as e:  # noqa: BLE001
        fails.append(f"memory/stub: {e}")
    print("emu_engine selftest:", "PASS" if not fails else "FAIL")
    for f in fails:
        print("  -", f)
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(selftest())
