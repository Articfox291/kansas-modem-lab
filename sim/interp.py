#!/usr/bin/env python3
"""interp.py — Python nanoMIPS CPU core for the modem emulator (Kansas lab).

PC-side only. Stdlib only. No device contact. New code under sim/ only;
sibling modules are reused/extended, never modified.

Spec (sim/hw_target.py, EXACT):
  I7200, LE32, args a0-a7, ret a0-a1, saved s0-s7,
  gpr3 raw 0-7 -> s0,s1,s2,s3,a0,a1,a2,a3.
Engine reuse (sim/emu_engine.py):
  Memory, decode_one, Tracer, StubRegistry — reused/extended, selftest kept green.
Sibling seams (defensive try/except):
  sim/decode_tables.py (decode_bytes/UnknownInsn — authoritative text+size),
  sim/mem_model.py (MpuMemory — optional, not required),
  sim/stub_lib.py (behavioral fns — optional at runtime).

Pipeline:
  fetch (16-bit parcels; 32/48-bit forms via decode_tables) ->
  decode via decode_tables (Ghidra-identical text) ->
  execute (full register file 32 GPR + pc/hi/lo + CP0 stub block) ->
  loop with step cap + tracer hooks + StubRegistry
  (BALC to stubbed VA executes stub bytes from emulated memory).

Mnemonic coverage (all in decoded listings; ground truth
<temp>\\fn_*.log +
sim/listings/corpus.jsonl):
  LI, JRC, JALRC, BALC, MOVE, MOVEP, ADDIU, ADDIUPC, ALUIPC, LWPC,
  LW/SW/LB/SB/LBU/SH/LBUX/SBX (+LH/LHU/MUL/BBEQZC for corpus completeness),
  BEQZC/BNEZC, BNEIC/BEQIC, BGEIUC/BLTUC/BGEUC/BNEC/BEQC/BC/BRSC,
  (+BGEIC/BLTIC/BLTIUC/BGEC/BLTC/BBNEZC signed/completeness forms),
  SLTU/SLTIU, ANDI/AND/ORI/OR/XORI, SLL/SRLV/SLLV/ADDU (+SRL/MUL/SUBU),
  LSA, MOVN/MOVZ, SEQI, SAVE/RESTORE (stack push/pop on mapped stack).

Conformance:
  legal_sim_rule stock carve (md1work_romonly.bin off 0x5df2fa, 94B @0x905df2fa,
  helpers=ret1, a0=ctx) -> HIT-RET a0==0x0 in 25 steps;
  patched (first 4B=01d2e0db) -> a0==0x1 in 1 step.
  Sweep mode reproduces sim/traces/ corpus byte-for-byte (via trace_tools).

Memory model (emulator scratch, NOT modem truth):
  fn carve R-X at its VA + full-ROM fallback for data reads (jump tables),
  stack 64K RW at 0xA0000000 (sp init 0xA000FFF0),
  ctx 64K RW at 0xB0000000 (a0 init 0xB0001000),
  stub pages (ret1/ret0 bytes) + on-demand zero pages for low data VAs
  (0x24xxxxxx/0x25xxxxxx LWPC/SWPC targets read 0, matching Ghidra
  unknownAddress zero blocks).

Step counting matches Ghidra EmuSml.java: steps = insns executed BEFORE
reaching the return address (return itself is free). Stock = 25, patch = 1.
"""
from __future__ import annotations

import re
import struct
import sys
from pathlib import Path

SIM_DIR = Path(__file__).resolve().parent
REPO_ROOT = SIM_DIR.parent
if str(SIM_DIR) not in sys.path:
    sys.path.insert(0, str(SIM_DIR))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# ---------------------------------------------------------------- defensive imports
try:
    from decode_tables import decode_bytes as _dt_decode_bytes, UnknownInsn as _DtUnknown  # type: ignore
except ImportError:
    try:
        from sim.decode_tables import decode_bytes as _dt_decode_bytes, UnknownInsn as _DtUnknown  # type: ignore
    except ImportError:
        _dt_decode_bytes = None  # type: ignore
        _DtUnknown = Exception  # type: ignore

try:
    from emu_engine import Memory as _BaseMemory, MemoryFault as _MemoryFault  # type: ignore
    from emu_engine import PERM_R as _PERM_R, PERM_W as _PERM_W, PERM_X as _PERM_X  # type: ignore
    from emu_engine import StubRegistry as _StubRegistry, Tracer as _Tracer  # type: ignore
    from emu_engine import VA_BASE as _VA_BASE  # type: ignore
except ImportError:
    try:
        from sim.emu_engine import Memory as _BaseMemory, MemoryFault as _MemoryFault  # type: ignore
        from sim.emu_engine import PERM_R as _PERM_R, PERM_W as _PERM_W, PERM_X as _PERM_X  # type: ignore
        from sim.emu_engine import StubRegistry as _StubRegistry, Tracer as _Tracer  # type: ignore
        from sim.emu_engine import VA_BASE as _VA_BASE  # type: ignore
    except ImportError:
        _BaseMemory = None  # type: ignore
        _MemoryFault = Exception  # type: ignore
        _PERM_R, _PERM_W, _PERM_X = 4, 2, 1
        _StubRegistry = None  # type: ignore
        _Tracer = None  # type: ignore
        _VA_BASE = 0x90000000

try:
    from hw_target import SPEC as _HW_SPEC  # type: ignore  # noqa: F401
except ImportError:
    try:
        from sim.hw_target import SPEC as _HW_SPEC  # type: ignore  # noqa: F401
    except ImportError:
        _HW_SPEC = {}  # type: ignore

# stub_lib / mem_model are optional seams (behavioral fns at runtime only)
try:
    import stub_lib as _stub_lib  # type: ignore
except ImportError:
    try:
        from sim import stub_lib as _stub_lib  # type: ignore
    except ImportError:
        _stub_lib = None  # type: ignore

# ---------------------------------------------------------------- constants
VA_BASE = 0x90000000
STACK_BASE = 0xA0000000
STACK_SIZE = 0x10000
STACK_INIT = 0xA000FFF0
CTX_BASE = 0xB0000000
CTX_SIZE = 0x10000
CTX_INIT = 0xB0001000
RA_INIT = 0xDEAD0000
STEP_CAP_DEFAULT = 3000
PAGE = 0x1000

STUB_RET1 = bytes.fromhex("01d2e0db")
STUB_RET0 = bytes.fromhex("00d2e0db")
PATCH_BYTES = STUB_RET1

GPR_NAMES = [
    "zero", "at", "t4", "t5",
    "a0", "a1", "a2", "a3",
    "a4", "a5", "a6", "a7",
    "t0", "t1", "t2", "t3",
    "s0", "s1", "s2", "s3",
    "s4", "s5", "s6", "s7",
    "t8", "t9", "k0", "k1",
    "gp", "sp", "fp", "ra",
]

SUPPORTED_MNEMONICS = sorted([
    "ADDIU", "ADDIUPC", "ADDU", "ALUIPC", "AND", "ANDI",
    "BALC", "BBEQZC", "BBNEZC", "BC", "BEQC", "BEQIC", "BEQZC",
    "BGEC", "BGEIC", "BGEIUC", "BGEUC", "BLTC", "BLTIC", "BLTIUC", "BLTUC",
    "BNEC", "BNEIC", "BNEZC", "BRSC",
    "JALRC", "JRC",
    "LB", "LBU", "LBUX", "LH", "LHU", "LI", "LSA", "LW", "LWPC",
    "MOVE", "MOVE.BALC", "MOVEP", "MOVN", "MOVZ", "MUL",
    "OR", "ORI",
    "RESTORE", "RESTORE.JRC", "SAVE", "SB", "SBX", "SEQI", "SH",
    "SLL", "SLLV", "SLTIU", "SLTU", "SRL", "SRLV", "SUBU",
    "SW", "SWPC", "XORI",
])


class EmuUnsupported(Exception):
    """Decoded form outside the executable subset (needs backend/gap)."""


class BackendSkip(Exception):
    """Cannot emulate (no image, no decoder, etc.)."""


# ---------------------------------------------------------------- helpers
def u32(v: int) -> int:
    return v & 0xFFFFFFFF


def s32(v: int) -> int:
    v &= 0xFFFFFFFF
    return v - 0x100000000 if v & 0x80000000 else v


def parse_imm(s: str) -> int:
    s = s.strip()
    try:
        return int(s, 0)
    except ValueError:
        return int(s, 16)


def parse_pcrel(s: str) -> int:
    m = re.search(r"0[xX][0-9a-fA-F]+", s)
    if not m:
        raise EmuUnsupported(f"bad %pcrel operand {s!r}")
    return int(m.group(0), 16)


_MEM_RE = re.compile(r"^\s*(-?0[xX][0-9a-fA-F]+|-?\d+)\s*\(\s*(\w+)\s*\)\s*$")
_REGMEM_RE = re.compile(r"^\s*(\w+)\s*\(\s*(\w+)\s*\)\s*$")


def parse_mem(s: str) -> tuple[int, str]:
    """Numeric-offset form '0xc(sp)'/'-0x9(a3)' -> (offset, base)."""
    m = _MEM_RE.match(s)
    if not m:
        raise EmuUnsupported(f"bad mem operand {s!r}")
    return parse_imm(m.group(1)), m.group(2)


def parse_indexed(s: str) -> tuple[str, str]:
    """Register-indexed form 's4(s1)' -> (idx_reg, base_reg)."""
    m = _REGMEM_RE.match(s)
    if not m:
        raise EmuUnsupported(f"bad indexed operand {s!r}")
    return m.group(1), m.group(2)


def is_indexed_mem(s: str) -> bool:
    m = _REGMEM_RE.match(s)
    if not m:
        return False
    # numeric offset => not indexed; register => indexed
    try:
        int(m.group(1), 0)
        return False
    except ValueError:
        return True


# ---------------------------------------------------------------- CP0 stub
class Cp0Block:
    """CP0 stub block: reads return 0 + log, writes are logged (forensic)."""

    def __init__(self) -> None:
        self.regs: dict[str, int] = {}
        self.log: list[dict] = []
        self._seq = 0

    def read(self, name: str) -> int:
        self._seq += 1
        self.log.append({"seq": self._seq, "op": "read", "reg": name, "value": "0x0"})
        return 0

    def write(self, name: str, val: int) -> None:
        self._seq += 1
        self.regs[name] = u32(val)
        self.log.append({"seq": self._seq, "op": "write", "reg": name,
                         "value": f"{u32(val):#x}"})


# ---------------------------------------------------------------- CPU
class Cpu:
    """nanoMIPS I7200 Python core (LE32, hw_target ABI)."""

    def __init__(self, image: bytes,
                 fn_va: int, carve: bytes,
                 regs: dict | None = None,
                 stubs=None,
                 tracer=None,
                 step_cap: int = STEP_CAP_DEFAULT,
                 strict: bool = False) -> None:
        # strict=True: outside-carve decode/exec faults STOP with reason
        # (hardware-boundary mapping). Default False preserves legacy
        # helpers=ret1 leniency (auto-stub + continue). New code: use strict.
        self.strict = bool(strict)
        if _BaseMemory is None:
            raise BackendSkip("emu_engine.Memory unavailable")
        if _dt_decode_bytes is None:
            raise BackendSkip("decode_tables.decode_bytes unavailable")
        self.image = bytes(image)
        self.fn_va = fn_va
        self.fn_size = len(carve)
        self.fn_end = fn_va + len(carve)
        self.step_cap = int(step_cap)
        self.tracer = tracer
        self.cp0 = Cp0Block()
        self.hi = 0
        self.lo = 0
        self.steps = 0
        self.stop = ""
        self.pc = fn_va
        self.gaps: list[str] = []
        self.auto_stubs: list[int] = []
        self.mem = _BaseMemory()
        # fn carve R-X (exact size: stub pages must not shadow it)
        self.mem.add("fn", fn_va, len(carve), _PERM_R | _PERM_X, bytes(carve))
        self.mem.add("stack", STACK_BASE, STACK_SIZE, _PERM_R | _PERM_W)
        self.mem.add("ctx", CTX_BASE, CTX_SIZE, _PERM_R | _PERM_W)
        # registers
        self.regs: dict[str, int] = {n: 0 for n in GPR_NAMES}
        regs = dict(regs or {})
        # _ctx_image / _overlay handled by caller (run_fn); here support _ctx_image
        ctx_img = regs.get("_ctx_image")
        if isinstance(ctx_img, (bytes, bytearray)) and len(ctx_img):
            try:
                self.mem.write(CTX_BASE, bytes(ctx_img)[:CTX_SIZE])
            except Exception:
                pass
        a0_init = regs.get("a0", CTX_INIT)
        self.regs["a0"] = u32(a0_init)
        for k in GPR_NAMES:
            if k in regs and k not in ("a0",):
                v = regs[k]
                if isinstance(v, int):
                    self.regs[k] = u32(v)
        if "s0" not in regs:
            self.regs["s0"] = u32(a0_init)
        self.regs["sp"] = u32(regs.get("sp", STACK_INIT))
        self.regs["ra"] = u32(regs.get("ra", RA_INIT))
        self.ra_init = u32(regs.get("ra", RA_INIT))
        # zero is always 0
        self.regs["zero"] = 0
        # stub registry (normalize without importing sibling logic)
        self.stub_table: dict[int, tuple[str, object]] = {}
        self._init_stubs(stubs)
        self._materialize_stubs()
        self._prescan_auto_stub()
        # return set from carve decode
        self.ret_set = self._find_returns()

    # -- regs ------------------------------------------------------
    def get(self, name: str) -> int:
        if name == "zero":
            return 0
        return u32(self.regs.get(name, 0))

    def put(self, name: str, val: int) -> None:
        if name == "zero":
            return
        self.regs[name] = u32(val)
        if name == "zero":
            self.regs["zero"] = 0

    # -- stubs -----------------------------------------------------
    def _init_stubs(self, stubs) -> None:
        table: dict[int, tuple[str, object]] = {}
        if stubs is None:
            stubs = {}
        # StubRegistry duck-type
        inner = getattr(stubs, "table", None)
        if isinstance(inner, dict):
            for va, pol in inner.items():
                if isinstance(pol, (tuple, list)):
                    table[int(va)] = (str(pol[0]), pol[1] if len(pol) > 1 else None)
                else:
                    table[int(va)] = (str(pol), None)
        elif isinstance(stubs, dict):
            for va, pol in stubs.items():
                if isinstance(pol, (tuple, list)):
                    table[int(va)] = (str(pol[0]), pol[1] if len(pol) > 1 else None)
                else:
                    table[int(va)] = (str(pol), None)
        self.stub_table = table

    def _ensure_region(self, addr: int, ln: int) -> None:
        """Ensure [addr,addr+ln) is mapped RWX (ROM-initialized when in image).

        Tries a full 4K page first (Ghidra-like); on overlap with the fn
        carve (same-page stub, e.g. 0x905f0df8 vs 0x905f0f04) falls back to
        a minimal region so neighbouring ROM bytes stay visible via fallback.
        """
        try:
            if self.mem.find(addr, ln) is not None:
                return
        except Exception:
            pass
        page = addr & ~(PAGE - 1)
        # try full page (initialized from image when overlapping ROM)
        try:
            if self.mem.find(page, PAGE) is None:
                init = bytearray(PAGE)
                for i in range(PAGE):
                    off = page + i - VA_BASE
                    if 0 <= off < len(self.image):
                        init[i] = self.image[off]
                self.mem.add(f"dyn{page:08x}", page, PAGE,
                             _PERM_R | _PERM_W | _PERM_X, bytes(init))
                return
        except ValueError:
            pass
        except Exception:
            pass
        # fallback: minimal region (avoids shadowing the fn carve)
        try:
            if self.mem.find(addr, ln) is None:
                init = bytearray(ln)
                for i in range(ln):
                    off = addr + i - VA_BASE
                    if 0 <= off < len(self.image):
                        init[i] = self.image[off]
                self.mem.add(f"dyns{addr:08x}_{ln:x}", addr, ln,
                             _PERM_R | _PERM_W | _PERM_X, bytes(init))
        except ValueError:
            pass  # already mapped (race with fn region edge)
        except Exception:
            pass

    def _ensure_page(self, addr: int) -> None:
        self._ensure_region(addr, 2)

    def _write_stub_bytes(self, va: int, data: bytes) -> None:
        self._ensure_region(va, len(data))
        # dyn regions are RWX so plain write works; fn region is R-X and
        # never overlaps a stub VA (stubs are outside the carve by prescan)
        try:
            self.mem.write(va, data)
        except Exception:
            # fallback: direct region patch (should not happen for dyn pages)
            r = self.mem.find(va, len(data))
            if r is not None:
                o = va - r.base
                r.data[o:o + len(data)] = data

    def _materialize_stubs(self) -> None:
        for va, (pol, _arg) in list(self.stub_table.items()):
            if pol == "ret1":
                self._write_stub_bytes(va, STUB_RET1)
            elif pol == "ret0":
                self._write_stub_bytes(va, STUB_RET0)
            elif pol == "trap":
                self._write_stub_bytes(va, b"\x00\x00")
            # behavioral/oracle: runtime, no bytes

    def _decode_at(self, addr: int) -> tuple[str, int, bytes]:
        # try emulated memory first (stub pages win), fallback to image
        for ln in (6, 4, 2):
            try:
                blob = self.mem.read(addr, ln)
                break
            except Exception:
                blob = None  # type: ignore
                continue
        else:
            blob = None
        if blob is None:
            # image fallback (ROM data, e.g. jump tables)
            off = addr - VA_BASE
            if 0 <= off < len(self.image):
                blob = self.image[off:off + 6]
            else:
                raise _MemoryFault(addr, "exec")
        try:
            text, size = _dt_decode_bytes(addr, bytes(blob))
        except _DtUnknown as e:
            raise EmuUnsupported(f"no-decode @ {addr:#x} ({e})")
        return text, size, bytes(blob[:size])

    def _prescan_auto_stub(self) -> None:
        # In strict mode prescan writes NOTHING (real ROM executes via
        # image fallback); runtime faults outside the carve stop instead.
        if self.strict:
            return
        # pre-scan carve BALC/MOVE.BALC targets outside carve -> auto ret1
        # (mirrors Ghidra EmuSml pre-scan; keeps helpers=ret1 faithful)
        try:
            pc = self.fn_va
            while pc < self.fn_end:
                text, size, _raw = self._decode_at(pc)
                ops = self._split_ops(text)
                tgt = None
                if text.startswith("BALC "):
                    tgt = parse_imm(ops[0])
                elif text.startswith("MOVE.BALC "):
                    tgt = parse_imm(ops[2])
                if tgt is not None and not (self.fn_va <= tgt < self.fn_end):
                    if tgt not in self.stub_table:
                        self.stub_table[tgt] = ("ret1", None)
                        self._write_stub_bytes(tgt, STUB_RET1)
                        self.auto_stubs.append(tgt)
                pc += size
        except (EmuUnsupported, Exception):
            pass  # prescan is best-effort; runtime handles the rest

    def _find_returns(self) -> set[int]:
        out: set[int] = set()
        try:
            pc = self.fn_va
            while pc < self.fn_end:
                text, size, _raw = self._decode_at(pc)
                if text == "JRC ra" or text.startswith("RESTORE"):
                    out.add(pc)
                pc += size
        except (EmuUnsupported, Exception):
            pass
        return out

    # -- memory data path ------------------------------------------
    def _read_fallback(self, addr: int, ln: int) -> bytes | None:
        off = addr - VA_BASE
        if 0 <= off and off + ln <= len(self.image):
            return self.image[off:off + ln]
        return None

    def load_bytes(self, addr: int, ln: int) -> bytes:
        try:
            return self.mem.read(addr, ln)
        except Exception:
            fb = self._read_fallback(addr, ln)
            if fb is not None:
                return fb
            # unmapped data reads return zeros (Ghidra zero blocks)
            return b"\x00" * ln

    def store_bytes(self, addr: int, data: bytes) -> None:
        try:
            self.mem.write(addr, data)
        except Exception:
            # create on-demand mapping (ROM-initialized, RWX) then retry
            self._ensure_region(addr, len(data))
            for off in range(0, len(data), PAGE):
                self._ensure_region(addr + off, min(PAGE, len(data) - off))
            try:
                self.mem.write(addr, data)
            except Exception as e:
                raise _MemoryFault(addr, "write") from e

    def load_u8(self, addr: int) -> int:
        return self.load_bytes(addr, 1)[0]

    def load_u16(self, addr: int) -> int:
        return struct.unpack("<H", self.load_bytes(addr, 2))[0]

    def load_u32(self, addr: int) -> int:
        return struct.unpack("<I", self.load_bytes(addr, 4))[0]

    def store_u8(self, addr: int, v: int) -> None:
        self.store_bytes(addr, bytes([v & 0xFF]))

    def store_u16(self, addr: int, v: int) -> None:
        self.store_bytes(addr, struct.pack("<H", v & 0xFFFF))

    def store_u32(self, addr: int, v: int) -> None:
        self.store_bytes(addr, struct.pack("<I", v & 0xFFFFFFFF))

    # -- decode helpers --------------------------------------------
    @staticmethod
    def _split_ops(text: str) -> list[str]:
        parts = text.split(None, 1)
        if len(parts) < 2:
            return []
        return [o.strip() for o in parts[1].split(",")]

    @staticmethod
    def _mn(text: str) -> str:
        return text.split(None, 1)[0] if text.strip() else ""

    def _log(self, step: int, pc: int, text: str) -> None:
        if self.tracer is not None and hasattr(self.tracer, "log"):
            try:
                self.tracer.log(step, pc, text, None)
            except Exception:
                pass

    def _stub_policy(self, va: int) -> tuple[str, object] | None:
        return self.stub_table.get(va)

    def _call_behavioral(self, va: int) -> int:
        pol, fn = self.stub_table[va]  # type: ignore
        if not callable(fn):
            # oracle/trap without fn defaults to ret1 bytes semantic
            return 1
        regs = {n: self.get(n) for n in ("a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7")}
        try:
            return u32(int(fn(a0=regs["a0"], a1=regs["a1"], a2=regs["a2"],
                               a3=regs["a3"], a4=regs["a4"], a5=regs["a5"],
                               a6=regs["a6"], a7=regs["a7"], ctx=None)))
        except TypeError:
            try:
                return u32(int(fn(regs)))
            except Exception:
                return 1

    # -- one step ---------------------------------------------------
    def step_once(self) -> int:
        """Fetch/decode/execute one insn at self.pc. Returns next pc."""
        pc = u32(self.pc)
        text, size, _raw = self._decode_at(pc)
        nxt = u32(pc + size)
        mn = self._mn(text)
        ops = self._split_ops(text)
        base_mn = mn.split(".")[0]

        # ---- control ------------------------------------------------
        if mn == "BALC":
            tgt = parse_imm(ops[0])
            self.put("ra", nxt)
            st = self._stub_policy(tgt)
            if st is not None and st[0] in ("behavioral", "oracle"):
                self.put("a0", self._call_behavioral(tgt))
                return nxt
            if st is not None and st[0] == "trap":
                raise EmuUnsupported(f"trap stub @{tgt:#x}")
            return u32(tgt)
        if mn == "MOVE.BALC":
            rd, rs, tgt_s = ops[0], ops[1], ops[2]
            self.put(rd, self.get(rs))
            tgt = parse_imm(tgt_s)
            self.put("ra", nxt)
            st = self._stub_policy(tgt)
            if st is not None and st[0] in ("behavioral", "oracle"):
                self.put("a0", self._call_behavioral(tgt))
                return nxt
            if st is not None and st[0] == "trap":
                raise EmuUnsupported(f"trap stub @{tgt:#x}")
            return u32(tgt)
        if mn == "BC":
            return u32(parse_imm(ops[0]))
        if mn == "JRC":
            return u32(self.get(ops[0]))
        if mn in ("JALRC", "JALRC.HB"):
            rd, rs = ops[0], ops[1]
            tgt = self.get(rs)
            st = self._stub_policy(u32(tgt))
            self.put(rd, nxt)
            if st is not None and st[0] in ("behavioral", "oracle"):
                self.put("a0", self._call_behavioral(u32(tgt)))
                return nxt
            if st is not None and st[0] == "trap":
                raise EmuUnsupported(f"trap stub @{u32(tgt):#x}")
            # unmapped zero-pointer call -> auto ret1 stub (Ghidra-like)
            if self.mem.find(u32(tgt), 2) is None and self._read_fallback(u32(tgt), 2) is None:
                self.stub_table[u32(tgt)] = ("ret1", None)
                self._write_stub_bytes(u32(tgt), STUB_RET1)
                self.auto_stubs.append(u32(tgt))
            return u32(tgt)
        if mn == "BRSC":
            return u32((u32(self.get(ops[0]) * 2) + nxt) & 0xFFFFFFFF)
        if mn in ("BEQZC", "BNEZC"):
            tgt = parse_imm(ops[1])
            c = (self.get(ops[0]) == 0)
            if mn == "BNEZC":
                c = not c
            return u32(tgt) if c else nxt
        if mn in ("BEQIC", "BNEIC", "BGEIUC", "BLTIUC", "BGEIC", "BLTIC"):
            rt, imm_s, tgt_s = ops[0], ops[1], ops[2]
            rv, iv, tgt = self.get(rt), parse_imm(imm_s) & 0xFFFFFFFF, parse_imm(tgt_s)
            if mn == "BEQIC":
                c = (rv == iv)
            elif mn == "BNEIC":
                c = (rv != iv)
            elif mn == "BGEIUC":
                c = (rv >= iv)
            elif mn == "BLTIUC":
                c = (rv < iv)
            elif mn == "BGEIC":
                c = (s32(rv) >= s32(iv))
            else:
                c = (s32(rv) < s32(iv))
            return u32(tgt) if c else nxt
        if mn in ("BBEQZC", "BBNEZC"):
            rt, bit_s, tgt_s = ops[0], ops[1], ops[2]
            bit = parse_imm(bit_s) & 0x3F
            b = (self.get(rt) >> bit) & 1
            c = (b == 0) if mn == "BBEQZC" else (b == 1)
            return u32(parse_imm(tgt_s)) if c else nxt
        if mn in ("BEQC", "BNEC", "BGEUC", "BLTUC", "BGEC", "BLTC"):
            rs, rt, tgt_s = ops[0], ops[1], ops[2]
            a, b, tgt = self.get(rs), self.get(rt), parse_imm(tgt_s)
            if mn == "BEQC":
                c = (a == b)
            elif mn == "BNEC":
                c = (a != b)
            elif mn == "BGEUC":
                c = (a >= b)
            elif mn == "BLTUC":
                c = (a < b)
            elif mn == "BGEC":
                c = (s32(a) >= s32(b))
            else:
                c = (s32(a) < s32(b))
            return u32(tgt) if c else nxt

        # ---- data movement ------------------------------------------
        if mn == "LI":
            self.put(ops[0], parse_imm(ops[1]))
            return nxt
        if mn == "MOVE":
            self.put(ops[0], self.get(ops[1]))
            return nxt
        if mn == "MOVEP":
            d1, d2, s1, s2 = ops[0], ops[1], ops[2], ops[3]
            v1, v2 = self.get(s1), self.get(s2)
            self.put(d1, v1)
            self.put(d2, v2)
            return nxt
        if mn == "ADDIU":
            self.put(ops[0], u32(self.get(ops[1]) + parse_imm(ops[2])))
            return nxt
        if mn == "ADDIUPC":
            self.put(ops[0], parse_pcrel(ops[1]))
            return nxt
        if mn == "ALUIPC":
            self.put(ops[0], parse_pcrel(ops[1]))
            return nxt
        if mn == "LWPC":
            self.put(ops[0], self.load_u32(parse_imm(ops[1])))
            return nxt
        if mn == "SWPC":
            self.store_u32(parse_imm(ops[1]), self.get(ops[0]))
            return nxt
        if mn in ("LW", "SW", "LB", "LBU", "SB", "SH", "LH", "LHU"):
            rt = ops[0]
            off, base = parse_mem(ops[1])
            addr = u32(self.get(base) + off)
            if mn == "LW":
                self.put(rt, self.load_u32(addr))
            elif mn == "SW":
                self.store_u32(addr, self.get(rt))
            elif mn == "LB":
                v = self.load_u8(addr)
                self.put(rt, u32(struct.unpack("b", bytes([v]))[0]))
            elif mn == "LBU":
                self.put(rt, self.load_u8(addr))
            elif mn == "SB":
                self.store_u8(addr, self.get(rt))
            elif mn == "SH":
                self.store_u16(addr, self.get(rt))
            elif mn == "LH":
                v = self.load_u16(addr)
                self.put(rt, u32(struct.unpack("h", struct.pack("<H", v))[0]))
            elif mn == "LHU":
                self.put(rt, self.load_u16(addr))
            return nxt
        if mn in ("LBUX", "LBX", "LHX", "LHUX", "LWX", "SBX", "SHX", "SWX"):
            rd = ops[0]
            if is_indexed_mem(ops[1]):
                ir, br = parse_indexed(ops[1])
                addr = u32(self.get(ir) + self.get(br))
            else:
                off, base = parse_mem(ops[1])
                addr = u32(self.get(base) + off)
            if mn == "LBUX":
                self.put(rd, self.load_u8(addr))
            elif mn == "LBX":
                v = self.load_u8(addr)
                self.put(rd, u32(struct.unpack("b", bytes([v]))[0]))
            elif mn in ("LHX",):
                v = self.load_u16(addr)
                self.put(rd, u32(struct.unpack("h", struct.pack("<H", v))[0]))
            elif mn in ("LHUX",):
                self.put(rd, self.load_u16(addr))
            elif mn in ("LWX",):
                self.put(rd, self.load_u32(addr))
            elif mn == "SBX":
                self.store_u8(addr, self.get(rd))
            elif mn == "SHX":
                self.store_u16(addr, self.get(rd))
            elif mn == "SWX":
                self.store_u32(addr, self.get(rd))
            else:
                raise EmuUnsupported(f"indexed {mn} @{pc:#x}")
            return nxt

        # ---- ALU ------------------------------------------------------
        if mn in ("ANDI", "ORI", "XORI", "SLTIU", "SLTI", "SEQI"):
            rt, rs, imm_s = ops[0], ops[1], ops[2]
            iv = parse_imm(imm_s) & 0xFFFFFFFF
            a = self.get(rs)
            if mn == "ANDI":
                self.put(rt, a & iv)
            elif mn == "ORI":
                self.put(rt, a | iv)
            elif mn == "XORI":
                self.put(rt, a ^ iv)
            elif mn == "SLTIU":
                self.put(rt, 1 if a < iv else 0)
            elif mn == "SLTI":
                self.put(rt, 1 if s32(a) < s32(iv) else 0)
            elif mn == "SEQI":
                self.put(rt, 1 if a == iv else 0)
            return nxt
        if mn == "AND":
            if len(ops) == 2:
                self.put(ops[0], self.get(ops[0]) & self.get(ops[1]))
            else:
                self.put(ops[0], self.get(ops[1]) & self.get(ops[2]))
            return nxt
        if mn in ("OR", "XOR", "NOR"):
            if len(ops) == 2:
                a = self.get(ops[0])
                b = self.get(ops[1])
                if mn == "OR":
                    self.put(ops[0], a | b)
                elif mn == "XOR":
                    self.put(ops[0], a ^ b)
                else:
                    self.put(ops[0], u32(~(a | b)))
            else:
                a, b = self.get(ops[1]), self.get(ops[2])
                if mn == "OR":
                    self.put(ops[0], a | b)
                elif mn == "XOR":
                    self.put(ops[0], a ^ b)
                else:
                    self.put(ops[0], u32(~(a | b)))
            return nxt
        if mn == "NOT":
            self.put(ops[0], u32(~self.get(ops[1])))
            return nxt
        if mn == "SLL":
            # SLL rt,rs,shamt (16-bit shift3 and 32-bit shift agree here)
            self.put(ops[0], u32(self.get(ops[1]) << (parse_imm(ops[2]) & 0x1F)))
            return nxt
        if mn == "SRL":
            self.put(ops[0], u32(self.get(ops[1]) >> (parse_imm(ops[2]) & 0x1F)))
            return nxt
        if mn == "SRA":
            a = s32(self.get(ops[1]))
            self.put(ops[0], u32(a >> (parse_imm(ops[2]) & 0x1F)))
            return nxt
        if mn in ("SLLV", "SRLV", "SRAV", "ROTRV"):
            rd, rs, rt = ops[0], ops[1], ops[2]
            sh = self.get(rt) & 0x1F
            a = self.get(rs)
            if mn == "SLLV":
                self.put(rd, u32(a << sh))
            elif mn == "SRLV":
                self.put(rd, u32(a >> sh))
            elif mn == "SRAV":
                self.put(rd, u32(s32(a) >> sh))
            else:
                self.put(rd, u32(((a >> sh) | (a << ((32 - sh) & 31))) & 0xFFFFFFFF))
            return nxt
        if mn in ("ADDU", "SUBU", "SUB", "ADD", "MUL", "MULU", "SLT", "SLTU",
                  "DIV", "DIVU", "MOD", "MODU", "MUH", "MUHU"):
            rd, rs, rt = ops[0], ops[1], ops[2]
            a, b = self.get(rs), self.get(rt)
            if mn in ("ADDU", "ADD"):
                self.put(rd, u32(a + b))
            elif mn in ("SUBU", "SUB"):
                self.put(rd, u32(a - b))
            elif mn in ("MUL", "MULU"):
                self.put(rd, u32(a * b))
            elif mn == "SLT":
                self.put(rd, 1 if s32(a) < s32(rt) else 0)
            elif mn == "SLTU":
                self.put(rd, 1 if a < b else 0)
            elif mn == "DIV":
                self.put(rd, u32(int(s32(a) / s32(b))) if b != 0 else 0)
            elif mn == "DIVU":
                self.put(rd, u32(a // b) if b != 0 else 0)
            elif mn == "MOD":
                self.put(rd, u32(s32(a) % s32(b)) if b != 0 else 0)
            elif mn == "MODU":
                self.put(rd, u32(a % b) if b != 0 else 0)
            elif mn in ("MUH", "MUHU"):
                # upper 32 of 64-bit product (signed/unsigned)
                if mn == "MUH":
                    prod = s32(a) * s32(b)
                else:
                    prod = a * b
                self.put(rd, u32((prod >> 32) & 0xFFFFFFFF))
            return nxt
        if mn == "LSA":
            rd, rs, rt, u2 = ops[0], ops[1], ops[2], ops[3]
            self.put(rd, u32((u32(self.get(rs) << (parse_imm(u2) & 3)) + self.get(rt)) & 0xFFFFFFFF))
            return nxt
        if mn in ("MOVN", "MOVZ"):
            rd, rs, rt = ops[0], ops[1], ops[2]
            c = self.get(rt)
            if (mn == "MOVN" and c != 0) or (mn == "MOVZ" and c == 0):
                self.put(rd, self.get(rs))
            return nxt
        if mn == "NOP":
            return nxt
        if mn == "SAVE":
            frame = parse_imm(ops[0])
            regs_list = ops[1:]
            sp = self.get("sp")
            newsp = u32(sp - frame)
            n = len(regs_list)
            for i, r in enumerate(regs_list):
                addr = u32(newsp + frame - 4 * (i + 1))
                self.store_u32(addr, self.get(r))
            self.put("sp", newsp)
            return nxt
        if mn == "RESTORE":
            frame = parse_imm(ops[0])
            regs_list = ops[1:]
            sp = self.get("sp")
            for i, r in enumerate(regs_list):
                addr = u32(sp + frame - 4 * (i + 1))
                self.put(r, self.load_u32(addr))
            self.put("sp", u32(sp + frame))
            return nxt
        if mn == "RESTORE.JRC":
            frame = parse_imm(ops[0])
            regs_list = ops[1:]
            sp = self.get("sp")
            for i, r in enumerate(regs_list):
                addr = u32(sp + frame - 4 * (i + 1))
                self.put(r, self.load_u32(addr))
            self.put("sp", u32(sp + frame))
            return u32(self.get("ra"))
        # CP0 stub (reads 0+log, writes log)
        if mn in ("MFC0", "MFHC0", "RDHWR"):
            # text forms vary; best-effort: first op is dest
            self.put(ops[0], self.cp0.read(ops[1] if len(ops) > 1 else mn))
            return nxt
        if mn in ("MTC0", "MTHC0"):
            self.cp0.write(ops[1] if len(ops) > 1 else mn, self.get(ops[0]))
            return nxt

        raise EmuUnsupported(f"exec: {text!r} @ {pc:#x} (mn={mn})")

    # -- run ---------------------------------------------------------
    def run(self) -> dict:
        pc = u32(self.fn_va)
        self.pc = pc
        steps = 0
        trace_texts: list[str] = []
        while steps < self.step_cap:
            if pc in self.ret_set:
                self.stop = "HIT-RET"
                break
            if pc == self.ra_init and steps > 0:
                self.stop = "HIT-RET"
                break
            try:
                text, size, _raw = self._decode_at(pc)
            except _MemoryFault as e:
                # unmapped exec outside carve -> on-demand ret1 (Ghidra-like)
                # ...unless strict: stop, it is a hardware-boundary signal.
                if self.strict or (self.fn_va <= pc < self.fn_end):
                    self.stop = f"MEM-FAULT @{pc:#x}"
                    self.gaps.append(str(e))
                    break
                if not (self.fn_va <= pc < self.fn_end):
                    self.stub_table[pc] = ("ret1", None)
                    self._write_stub_bytes(pc, STUB_RET1)
                    self.auto_stubs.append(pc)
                    self.gaps.append(f"auto-stub exec @{pc:#x} (was {e})")
                    continue
                self.stop = f"MEM-FAULT @{pc:#x}"
                self.gaps.append(str(e))
                break
            except EmuUnsupported as e:
                # Lenient (legacy): outside-carve decode gap -> ret1 helper.
                # Strict: stop with reason (boundary map). Inside-carve gaps
                # are real FAILs in both modes.
                if self.strict or (self.fn_va <= pc < self.fn_end):
                    self.stop = f"UNSUPPORTED @{pc:#x}"
                    self.gaps.append(str(e))
                    break
                self.stub_table[pc] = ("ret1", None)
                self._write_stub_bytes(pc, STUB_RET1)
                self.auto_stubs.append(pc)
                self.gaps.append(f"auto-stub gap @{pc:#x} ({e})")
                continue
            self._log(steps, pc, text)
            trace_texts.append(f"{pc:#x} {text}")
            try:
                npc = self.step_once_internal(pc, text, size)
            except EmuUnsupported as e:
                self.stop = f"UNSUPPORTED @{pc:#x}"
                self.gaps.append(str(e))
                break
            except Exception as e:  # noqa: BLE001 (memory faults etc.)
                self.stop = f"FAULT @{pc:#x}: {e}"
                self.gaps.append(f"{pc:#x} {text}: {e}")
                break
            pc = u32(npc)
            self.pc = pc
            steps += 1
            # zero guard (spec: never touch device; also never spin forever)
            if steps >= self.step_cap:
                self.stop = "STEP-CAP"
                break
        else:
            self.stop = "STEP-CAP"
        if not self.stop:
            self.stop = "STEP-CAP"
        self.steps = steps
        # final pc: if HIT-RET via ret_set, pc is the ret insn address
        ret_at = pc if self.stop == "HIT-RET" else pc
        return {"a0": u32(self.get("a0")), "a1": u32(self.get("a1")),
                "steps": steps, "stop": self.stop, "pc": u32(ret_at),
                "ret_at": u32(ret_at), "trace": trace_texts, "gaps": list(self.gaps),
                "auto_stubs": list(self.auto_stubs)}

    def step_once_internal(self, pc: int, text: str, size: int) -> int:
        self.pc = u32(pc)
        # temporarily ensure _decode_at inside step_once uses same text/size
        # (step_once re-decodes; to avoid double decode cost we inline via text)
        # Simplest: call step_once which re-decodes (same result).
        # To keep single source, just execute via text here:
        saved_pc = self.pc
        # reuse step_once logic without refetch: duplicate dispatch inline
        # (call self.step_once would refetch same pc; identical, so just call it)
        self.pc = saved_pc
        return self.step_once_with_text(pc, text, size)

    def step_once_with_text(self, pc: int, text: str, size: int) -> int:
        # execute using already-decoded text (avoids refetch mismatch)
        self.pc = u32(pc)
        nxt = u32(pc + size)
        mn = self._mn(text)
        ops = self._split_ops(text)
        # stash decode so step_once() would agree; implement dispatch directly
        # by temporarily monkey-patching _decode_at? Simpler: set pc and call
        # the shared dispatch below (duplicated from step_once for text reuse).
        # To avoid duplication bugs, step_once() itself decodes; since decode
        # is deterministic, calling step_once() is equivalent.
        # So: just call step_once().
        return self._exec_text(pc, text, size, nxt, mn, ops)

    def _exec_text(self, pc: int, text: str, size: int, nxt: int,
                   mn: str, ops: list[str]) -> int:
        # full dispatch (same as step_once body, factored for testability)
        self.pc = u32(pc)
        # control
        if mn == "BALC":
            tgt = parse_imm(ops[0])
            self.put("ra", nxt)
            st = self._stub_policy(tgt)
            if st is not None and st[0] in ("behavioral", "oracle"):
                self.put("a0", self._call_behavioral(tgt))
                return nxt
            if st is not None and st[0] == "trap":
                raise EmuUnsupported(f"trap stub @{tgt:#x}")
            return u32(tgt)
        if mn == "MOVE.BALC":
            rd, rs, tgt_s = ops[0], ops[1], ops[2]
            self.put(rd, self.get(rs))
            tgt = parse_imm(tgt_s)
            self.put("ra", nxt)
            st = self._stub_policy(tgt)
            if st is not None and st[0] in ("behavioral", "oracle"):
                self.put("a0", self._call_behavioral(tgt))
                return nxt
            if st is not None and st[0] == "trap":
                raise EmuUnsupported(f"trap stub @{tgt:#x}")
            return u32(tgt)
        if mn == "BC":
            return u32(parse_imm(ops[0]))
        if mn == "JRC":
            return u32(self.get(ops[0]))
        if mn in ("JALRC", "JALRC.HB"):
            rd, rs = ops[0], ops[1]
            tgt = self.get(rs)
            st = self._stub_policy(u32(tgt))
            self.put(rd, nxt)
            if st is not None and st[0] in ("behavioral", "oracle"):
                self.put("a0", self._call_behavioral(u32(tgt)))
                return nxt
            if st is not None and st[0] == "trap":
                raise EmuUnsupported(f"trap stub @{u32(tgt):#x}")
            if self.mem.find(u32(tgt), 2) is None and self._read_fallback(u32(tgt), 2) is None:
                self.stub_table[u32(tgt)] = ("ret1", None)
                self._write_stub_bytes(u32(tgt), STUB_RET1)
                self.auto_stubs.append(u32(tgt))
            return u32(tgt)
        if mn == "BRSC":
            return u32((u32(self.get(ops[0]) * 2) + nxt) & 0xFFFFFFFF)
        if mn in ("BEQZC", "BNEZC"):
            tgt = parse_imm(ops[1])
            c = (self.get(ops[0]) == 0)
            if mn == "BNEZC":
                c = not c
            return u32(tgt) if c else nxt
        if mn in ("BEQIC", "BNEIC", "BGEIUC", "BLTIUC", "BGEIC", "BLTIC"):
            rt, imm_s, tgt_s = ops[0], ops[1], ops[2]
            rv, iv, tgt = self.get(rt), parse_imm(imm_s) & 0xFFFFFFFF, parse_imm(tgt_s)
            if mn == "BEQIC":
                c = (rv == iv)
            elif mn == "BNEIC":
                c = (rv != iv)
            elif mn == "BGEIUC":
                c = (rv >= iv)
            elif mn == "BLTIUC":
                c = (rv < iv)
            elif mn == "BGEIC":
                c = (s32(rv) >= s32(iv))
            else:
                c = (s32(rv) < s32(iv))
            return u32(tgt) if c else nxt
        if mn in ("BBEQZC", "BBNEZC"):
            rt, bit_s, tgt_s = ops[0], ops[1], ops[2]
            bit = parse_imm(bit_s) & 0x3F
            b = (self.get(rt) >> bit) & 1
            c = (b == 0) if mn == "BBEQZC" else (b == 1)
            return u32(parse_imm(tgt_s)) if c else nxt
        if mn in ("BEQC", "BNEC", "BGEUC", "BLTUC", "BGEC", "BLTC"):
            rs, rt, tgt_s = ops[0], ops[1], ops[2]
            a, b, tgt = self.get(rs), self.get(rt), parse_imm(tgt_s)
            if mn == "BEQC":
                c = (a == b)
            elif mn == "BNEC":
                c = (a != b)
            elif mn == "BGEUC":
                c = (a >= b)
            elif mn == "BLTUC":
                c = (a < b)
            elif mn == "BGEC":
                c = (s32(a) >= s32(b))
            else:
                c = (s32(a) < s32(b))
            return u32(tgt) if c else nxt
        if mn == "LI":
            self.put(ops[0], parse_imm(ops[1]))
            return nxt
        if mn == "MOVE":
            self.put(ops[0], self.get(ops[1]))
            return nxt
        if mn == "MOVEP":
            d1, d2, s1, s2 = ops[0], ops[1], ops[2], ops[3]
            v1, v2 = self.get(s1), self.get(s2)
            self.put(d1, v1)
            self.put(d2, v2)
            return nxt
        if mn == "ADDIU":
            self.put(ops[0], u32(self.get(ops[1]) + parse_imm(ops[2])))
            return nxt
        if mn == "ADDIUPC":
            self.put(ops[0], parse_pcrel(ops[1]))
            return nxt
        if mn == "ALUIPC":
            self.put(ops[0], parse_pcrel(ops[1]))
            return nxt
        if mn == "LWPC":
            self.put(ops[0], self.load_u32(parse_imm(ops[1])))
            return nxt
        if mn == "SWPC":
            self.store_u32(parse_imm(ops[1]), self.get(ops[0]))
            return nxt
        if mn in ("LW", "SW", "LB", "LBU", "SB", "SH", "LH", "LHU"):
            rt = ops[0]
            off, base = parse_mem(ops[1])
            addr = u32(self.get(base) + off)
            if mn == "LW":
                self.put(rt, self.load_u32(addr))
            elif mn == "SW":
                self.store_u32(addr, self.get(rt))
            elif mn == "LB":
                v = self.load_u8(addr)
                self.put(rt, u32(struct.unpack("b", bytes([v]))[0]))
            elif mn == "LBU":
                self.put(rt, self.load_u8(addr))
            elif mn == "SB":
                self.store_u8(addr, self.get(rt))
            elif mn == "SH":
                self.store_u16(addr, self.get(rt))
            elif mn == "LH":
                v = self.load_u16(addr)
                self.put(rt, u32(struct.unpack("h", struct.pack("<H", v))[0]))
            elif mn == "LHU":
                self.put(rt, self.load_u16(addr))
            return nxt
        if mn in ("LBUX", "LBX", "LHX", "LHUX", "LWX", "SBX", "SHX", "SWX",
                  "LBUXS", "LBXS", "LHXS", "LHUXS", "LWXS", "SHXS", "SWXS"):
            rd = ops[0]
            if is_indexed_mem(ops[1]):
                ir, br = parse_indexed(ops[1])
                addr = u32(self.get(ir) + self.get(br))
            else:
                off, base = parse_mem(ops[1])
                addr = u32(self.get(base) + off)
            base_mn = mn.rstrip("S")
            if base_mn in ("LBUX", "LBU"):
                self.put(rd, self.load_u8(addr))
            elif base_mn in ("LBX", "LB"):
                v = self.load_u8(addr)
                self.put(rd, u32(struct.unpack("b", bytes([v]))[0]))
            elif base_mn in ("LHX", "LH"):
                v = self.load_u16(addr)
                self.put(rd, u32(struct.unpack("h", struct.pack("<H", v))[0]))
            elif base_mn in ("LHUX", "LHU"):
                self.put(rd, self.load_u16(addr))
            elif base_mn in ("LWX", "LW"):
                self.put(rd, self.load_u32(addr))
            elif base_mn in ("SBX", "SB"):
                self.store_u8(addr, self.get(rd))
            elif base_mn in ("SHX", "SH"):
                self.store_u16(addr, self.get(rd))
            elif base_mn in ("SWX", "SW"):
                self.store_u32(addr, self.get(rd))
            else:
                raise EmuUnsupported(f"indexed {mn} @{pc:#x}")
            return nxt
        if mn in ("ANDI", "ORI", "XORI", "SLTIU", "SLTI", "SEQI"):
            rt, rs, imm_s = ops[0], ops[1], ops[2]
            iv = parse_imm(imm_s) & 0xFFFFFFFF
            a = self.get(rs)
            if mn == "ANDI":
                self.put(rt, a & iv)
            elif mn == "ORI":
                self.put(rt, a | iv)
            elif mn == "XORI":
                self.put(rt, a ^ iv)
            elif mn == "SLTIU":
                self.put(rt, 1 if a < iv else 0)
            elif mn == "SLTI":
                self.put(rt, 1 if s32(a) < s32(iv) else 0)
            elif mn == "SEQI":
                self.put(rt, 1 if a == iv else 0)
            return nxt
        if mn == "AND":
            if len(ops) == 2:
                self.put(ops[0], self.get(ops[0]) & self.get(ops[1]))
            else:
                self.put(ops[0], self.get(ops[1]) & self.get(ops[2]))
            return nxt
        if mn in ("OR", "XOR", "NOR"):
            if len(ops) == 2:
                a, b = self.get(ops[0]), self.get(ops[1])
                if mn == "OR":
                    self.put(ops[0], a | b)
                elif mn == "XOR":
                    self.put(ops[0], a ^ b)
                else:
                    self.put(ops[0], u32(~(a | b)))
            else:
                a, b = self.get(ops[1]), self.get(ops[2])
                if mn == "OR":
                    self.put(ops[0], a | b)
                elif mn == "XOR":
                    self.put(ops[0], a ^ b)
                else:
                    self.put(ops[0], u32(~(a | b)))
            return nxt
        if mn == "NOT":
            self.put(ops[0], u32(~self.get(ops[1])))
            return nxt
        if mn == "SLL":
            self.put(ops[0], u32(self.get(ops[1]) << (parse_imm(ops[2]) & 0x1F)))
            return nxt
        if mn == "SRL":
            self.put(ops[0], u32(self.get(ops[1]) >> (parse_imm(ops[2]) & 0x1F)))
            return nxt
        if mn == "SRA":
            self.put(ops[0], u32(s32(self.get(ops[1])) >> (parse_imm(ops[2]) & 0x1F)))
            return nxt
        if mn in ("SLLV", "SRLV", "SRAV", "ROTRV"):
            rd, rs, rt = ops[0], ops[1], ops[2]
            sh = self.get(rt) & 0x1F
            a = self.get(rs)
            if mn == "SLLV":
                self.put(rd, u32(a << sh))
            elif mn == "SRLV":
                self.put(rd, u32(a >> sh))
            elif mn == "SRAV":
                self.put(rd, u32(s32(a) >> sh))
            else:
                self.put(rd, u32(((a >> sh) | (a << ((32 - sh) & 31))) & 0xFFFFFFFF))
            return nxt
        if mn in ("ADDU", "SUBU", "SUB", "ADD", "MUL", "MULU", "SLT", "SLTU",
                  "DIV", "DIVU", "MOD", "MODU", "MUH", "MUHU"):
            rd, rs, rt = ops[0], ops[1], ops[2]
            a, b = self.get(rs), self.get(rt)
            if mn in ("ADDU", "ADD"):
                self.put(rd, u32(a + b))
            elif mn in ("SUBU", "SUB"):
                self.put(rd, u32(a - b))
            elif mn in ("MUL", "MULU"):
                self.put(rd, u32(a * b))
            elif mn == "SLT":
                self.put(rd, 1 if s32(a) < s32(b) else 0)
            elif mn == "SLTU":
                self.put(rd, 1 if a < b else 0)
            elif mn == "DIV":
                self.put(rd, u32(int(s32(a) / s32(b))) if b != 0 else 0)
            elif mn == "DIVU":
                self.put(rd, u32(a // b) if b != 0 else 0)
            elif mn == "MOD":
                self.put(rd, u32(s32(a) % s32(b)) if b != 0 else 0)
            elif mn == "MODU":
                self.put(rd, u32(a % b) if b != 0 else 0)
            elif mn in ("MUH", "MUHU"):
                prod = (s32(a) * s32(b)) if mn == "MUH" else (a * b)
                self.put(rd, u32((prod >> 32) & 0xFFFFFFFF))
            return nxt
        if mn == "LSA":
            rd, rs, rt, u2 = ops[0], ops[1], ops[2], ops[3]
            self.put(rd, u32((u32(self.get(rs) << (parse_imm(u2) & 3)) + self.get(rt)) & 0xFFFFFFFF))
            return nxt
        if mn in ("MOVN", "MOVZ"):
            rd, rs, rt = ops[0], ops[1], ops[2]
            c = self.get(rt)
            if (mn == "MOVN" and c != 0) or (mn == "MOVZ" and c == 0):
                self.put(rd, self.get(rs))
            return nxt
        if mn == "NOP":
            return nxt
        if mn == "SAVE":
            frame = parse_imm(ops[0])
            regs_list = ops[1:]
            sp = self.get("sp")
            newsp = u32(sp - frame)
            for i, r in enumerate(regs_list):
                addr = u32(newsp + frame - 4 * (i + 1))
                self.store_u32(addr, self.get(r))
            self.put("sp", newsp)
            return nxt
        if mn == "RESTORE":
            frame = parse_imm(ops[0])
            regs_list = ops[1:]
            sp = self.get("sp")
            for i, r in enumerate(regs_list):
                addr = u32(sp + frame - 4 * (i + 1))
                self.put(r, self.load_u32(addr))
            self.put("sp", u32(sp + frame))
            return nxt
        if mn == "RESTORE.JRC":
            frame = parse_imm(ops[0])
            regs_list = ops[1:]
            sp = self.get("sp")
            for i, r in enumerate(regs_list):
                addr = u32(sp + frame - 4 * (i + 1))
                self.put(r, self.load_u32(addr))
            self.put("sp", u32(sp + frame))
            return u32(self.get("ra"))
        if mn in ("MFC0", "MFHC0", "RDHWR"):
            self.put(ops[0], self.cp0.read(ops[1] if len(ops) > 1 else mn))
            return nxt
        if mn in ("MTC0", "MTHC0"):
            self.cp0.write(ops[1] if len(ops) > 1 else mn, self.get(ops[0]))
            return nxt
        raise EmuUnsupported(f"exec: {text!r} @ {pc:#x} (mn={mn})")

    # step_once kept for compat (refetch path)
    def step_once(self) -> int:
        pc = u32(self.pc)
        text, size, _raw = self._decode_at(pc)
        nxt = u32(pc + size)
        mn = self._mn(text)
        ops = self._split_ops(text)
        return self._exec_text(pc, text, size, nxt, mn, ops)


# ---------------------------------------------------------------- image helpers
def _load_image_bytes() -> bytes:
    for cand in (REPO_ROOT / "md1work_romonly.bin",):
        try:
            if cand.is_file():
                return cand.read_bytes()
        except OSError:
            continue
    raise BackendSkip("md1work_romonly.bin not found")


def _normalize_stubs(stubs) -> dict:
    if stubs is None:
        return {}
    inner = getattr(stubs, "table", None)
    if isinstance(inner, dict):
        out: dict = {}
        for va, pol in inner.items():
            out[int(va)] = pol[0] if isinstance(pol, (tuple, list)) else pol
            # preserve behavioral fn via full table path (Cpu handles registry)
        return stubs  # type: ignore — Cpu understands registry directly
    if isinstance(stubs, dict):
        return dict(stubs)
    return {}


def _normalize_regs(regs) -> dict:
    if regs is None:
        return {}
    out: dict = {}
    for k, v in dict(regs).items():
        if k.startswith("_"):
            out[k] = v
        elif isinstance(v, int):
            out[k] = v & 0xFFFFFFFF
        else:
            out[k] = v
    return out


# ---------------------------------------------------------------- run_fn (sml_conform-compatible)
def run_fn(*args, **kwargs):
    """Backend-agnostic runner.

    Accepted shapes (sml_conform delegate probes both):
      run_fn(backend, va, size, regs=None, stubs=None, tracer=None, step_cap=...)
      run_fn(va, size, regs=None, stubs=None, tracer=None, step_cap=...)
    Returns (a0, steps, trace[str,...]).
    """
    backend = None
    va = size = None
    regs: dict | None = None
    stubs = None
    tracer = kwargs.get("tracer")
    step_cap = kwargs.get("step_cap", STEP_CAP_DEFAULT)
    # kwargs alt names
    if "regs" in kwargs:
        regs = kwargs["regs"]
    if "stubs" in kwargs:
        stubs = kwargs["stubs"]
    if len(args) == 0:
        raise TypeError("run_fn needs (va,size) or (backend,va,size)")
    # detect (backend,va,size,...) vs (va,size,...)
    if isinstance(args[0], str) and args[0] in ("interp", "ghidra"):
        backend = args[0]
        va = args[1] if len(args) > 1 else None
        size = args[2] if len(args) > 2 else None
        if len(args) > 3 and regs is None:
            regs = args[3]
        if len(args) > 4 and stubs is None:
            stubs = args[4]
        if len(args) > 5 and tracer is None:
            tracer = args[5]
    elif isinstance(args[0], int):
        va = args[0]
        size = args[1] if len(args) > 1 else None
        if len(args) > 2 and regs is None:
            regs = args[2]
        if len(args) > 3 and stubs is None:
            stubs = args[3]
        if len(args) > 4 and tracer is None:
            tracer = args[4]
    else:
        raise TypeError(f"run_fn: bad first arg {args[0]!r}")
    if va is None or size is None:
        raise TypeError("run_fn: va/size required")
    return _run_fn_impl(int(va), int(size), regs, stubs, tracer, step_cap)


def _run_fn_impl(va: int, size: int, regs, stubs, tracer, step_cap) -> tuple:
    regs = _normalize_regs(regs)
    # overlay support (sml_conform patched proof: regs["_overlay"]={va:bytes})
    image = _load_image_bytes()
    off = va - VA_BASE
    if not (0 <= off < len(image)) or off + size > len(image):
        raise BackendSkip(f"VA {va:#x}+{size} outside image")
    carve = image[off:off + size]
    overlay = regs.get("_overlay") if isinstance(regs, dict) else None
    if isinstance(overlay, dict):
        buf = bytearray(carve)
        for ova, obytes in overlay.items():
            ova = int(ova)
            ob = bytes(obytes)
            if va <= ova < va + size:
                buf[ova - va:ova - va + len(ob)] = ob
        carve = bytes(buf)
    # default stubs: if caller passed none/empty, Cpu auto-stubs via prescan
    cpu = Cpu(image, va, bytes(carve), regs=regs, stubs=stubs,
              tracer=tracer, step_cap=step_cap)
    res = cpu.run()
    if res["stop"] not in ("HIT-RET",):
        # surface gaps but still return verdict for SKIP-tolerant callers?
        # sml_conform treats non-OK as SKIP; raise BackendSkip with reason
        # UNLESS it is a clean verdict with different stop (e.g. STEP-CAP)?
        # For strict conformance we raise so callers see SKIP, but run()
        # result is preserved in the exception for diagnostics.
        if res["stop"].startswith("UNSUPPORTED"):
            raise EmuUnsupported(f"{res['stop']} gaps={res['gaps'][:2]}")
        raise BackendSkip(f"{res['stop']} @ {res['pc']:#x} gaps={res['gaps'][:2]}")
    trace = [f"{t}" for t in res["trace"]]
    # append HIT-RET marker like _local_interp for compat
    trace.append(f"{res['pc']:#x} HIT-RET a0={res['a0']:#x} steps={res['steps']}")
    return res["a0"], res["steps"], trace


# aliases probed by sml_conform._find_delegate
def run(*args, **kwargs):
    return run_fn(*args, **kwargs)


def execute(*args, **kwargs):
    return run_fn(*args, **kwargs)


def emulate(*args, **kwargs):
    return run_fn(*args, **kwargs)


def emu_run(*args, **kwargs):
    return run_fn(*args, **kwargs)


# ---------------------------------------------------------------- sweep (listing-linear, corpus byte-for-byte)
def sweep(va: int, size: int, image: bytes | None = None,
          overlay: dict | None = None) -> list[dict]:
    """Linear-sweep decode va..va+size -> [{pc,bytes,text,size}].

    Uses interp fetch (decode_tables) so text matches Nmdis2 byte-identical.
    Bytes come from the (overlaid) carve. Raises EmuUnsupported on gaps.
    """
    img = bytes(image) if image is not None else _load_image_bytes()
    off = va - VA_BASE
    carve = img[off:off + size]
    if overlay:
        buf = bytearray(carve)
        for ova, ob in overlay.items():
            ova = int(ova)
            ob = bytes(ob)
            if va <= ova < va + size:
                buf[ova - va:ova - va + len(ob)] = ob
        carve = bytes(buf)
    out: list[dict] = []
    pc = va
    end = va + size
    while pc < end:
        chunk = carve[pc - va:pc - va + 6]
        if len(chunk) < 2:
            raise EmuUnsupported(f"sweep short @{pc:#x}")
        text, sz = _dt_decode_bytes(pc, bytes(chunk))
        raw = bytes(chunk[:sz])
        out.append({"pc": pc, "bytes": raw.hex(), "text": text, "size": sz})
        pc += sz
    if pc != end:
        raise EmuUnsupported(f"sweep overrun @{pc:#x} != end {end:#x}")
    return out


def sweep_to_normalized(va: int, size: int, image: bytes | None = None,
                        overlay: dict | None = None) -> list[dict]:
    """Sweep -> trace_tools normalized events (step,pc,bytes,text)."""
    try:
        from trace_tools import normalize as _norm  # type: ignore
    except ImportError:
        try:
            from sim.trace_tools import normalize as _norm  # type: ignore
        except ImportError:
            _norm = None  # type: ignore
    rows = sweep(va, size, image, overlay)
    out: list[dict] = []
    for i, r in enumerate(rows):
        if _norm is not None:
            out.append(_norm(i, r["pc"], bytes.fromhex(r["bytes"]), r["text"]))
        else:
            out.append({"step": i, "pc": f"{r['pc']:#x}",
                        "bytes": r["bytes"].lower(), "text": r["text"]})
    return out


# ---------------------------------------------------------------- conformance helpers
LEGAL_VA = 0x905DF2FA
LEGAL_SIZE = 94  # 0x5E [0x905df2fa,0x905df358)


def conform_legal_sim_rule(verbose: bool = True) -> dict:
    """Mandatory conformance: stock 25-step a0=0, patch 1-step a0=1."""
    image = _load_image_bytes()
    out: dict = {}
    # stock: helpers=ret1 via prescan (explicit too), a0=ctx
    regs_stock = {"a0": CTX_INIT, "s0": CTX_INIT, "ra": RA_INIT, "sp": STACK_INIT,
                  "_ctx_image": b"\x00" * CTX_SIZE}
    stubs = {0x9198A6F0: "ret1", 0x9198A744: "ret1",
             0x90ED3222: "ret1", 0x90ED7CE2: "ret1"}
    try:
        a0, steps, trace = _run_fn_impl(LEGAL_VA, LEGAL_SIZE, regs_stock, stubs, None,
                                        STEP_CAP_DEFAULT)
        out["stock"] = {"a0": a0, "steps": steps, "trace": trace[-3:],
                        "pass": (a0 == 0 and steps == 25)}
    except Exception as e:  # noqa: BLE001
        out["stock"] = {"error": repr(e), "pass": False}
    # patch: first 4B = 01d2e0db
    regs_patch = dict(regs_stock)
    regs_patch["_overlay"] = {LEGAL_VA: PATCH_BYTES}
    try:
        a0, steps, trace = _run_fn_impl(LEGAL_VA, LEGAL_SIZE, regs_patch, stubs, None,
                                        STEP_CAP_DEFAULT)
        out["patch"] = {"a0": a0, "steps": steps, "trace": trace[-3:],
                        "pass": (a0 == 1 and steps == 1)}
    except Exception as e:  # noqa: BLE001
        out["patch"] = {"error": repr(e), "pass": False}
    if verbose:
        for k in ("stock", "patch"):
            r = out[k]
            print(f"legal_sim_rule[{k}]: " +
                  (f"a0={r.get('a0'):#x} steps={r.get('steps')} "
                   f"{'PASS' if r.get('pass') else 'FAIL'}" if "a0" in r
                   else f"ERROR {r.get('error')} FAIL"))
    return out


def corpus_check(verbose: bool = True) -> dict:
    """Sweep all 7 seed-trace functions; compare to sim/traces/ byte-for-byte."""
    try:
        from trace_tools import CORPUS, load_rom, load_cati, expected_corpus_bytes, dumps_event  # type: ignore
    except ImportError:
        try:
            from sim.trace_tools import CORPUS, load_rom, load_cati, expected_corpus_bytes, dumps_event  # type: ignore
        except ImportError as e:
            return {"overall": "SKIP", "error": repr(e)}
    rom = load_rom()
    results: dict = {}
    ok_all = True
    for name, va, logname in CORPUS:
        try:
            want_blob, info = expected_corpus_bytes(name, va, logname, rom, load_cati())
            got_events = sweep_to_normalized(va, info["steps"] and (int(info["end"], 16) - int(info["va"], 16)),
                                             image=rom)
            # rebuild blob with trace_tools serialization for byte-exact compare
            got_blob = "".join(dumps_event(e) + "\n" for e in got_events).encode()
            match = (got_blob == want_blob)
            ok_all &= match
            results[name] = {"result": "PASS" if match else "FAIL",
                             "steps": info["steps"], "sha256": info["sha256"],
                             "got_sha": __import__("hashlib").sha256(got_blob).hexdigest()}
            if verbose:
                print(f"  {name:28s} {'PASS' if match else 'FAIL'}  {info['steps']} steps")
        except Exception as e:  # noqa: BLE001
            ok_all = False
            results[name] = {"result": "FAIL", "note": repr(e)}
            if verbose:
                print(f"  {name:28s} FAIL  {e!r}")
    return {"overall": "PASS" if ok_all else "FAIL", "funcs": results}


def coverage_report() -> str:
    lines = ["interp mnemonic coverage (exec uses decode_tables 1191/1191):"]
    for m in SUPPORTED_MNEMONICS:
        lines.append(f"  {m}")
    lines.append(f"total exec mnemonics: {len(SUPPORTED_MNEMONICS)}")
    return "\n".join(lines)


# ---------------------------------------------------------------- selftest
def selftest() -> int:
    fails: list[str] = []
    # 1. sibling selftests stay green (import-level, no modification)
    try:
        import importlib
        try:
            ee = importlib.import_module("emu_engine")
        except ImportError:
            ee = importlib.import_module("sim.emu_engine")
    except Exception:
        ee = None
    try:
        if ee is not None and hasattr(ee, "selftest"):
            # emu_engine.selftest() prints + returns exit code; call decode part only
            # to avoid double ROM load cost twice (still cheap). Call full.
            rc = ee.selftest()
            if rc != 0:
                fails.append("emu_engine selftest red")
        else:
            fails.append("emu_engine import failed")
    except Exception as e:  # noqa: BLE001
        fails.append(f"emu_engine selftest raised {e!r}")
    try:
        try:
            hw = importlib.import_module("hw_target")
        except ImportError:
            hw = importlib.import_module("sim.hw_target")
        if hasattr(hw, "check_spec") and hw.check_spec():
            fails.append(f"hw_target drift {hw.check_spec()}")
    except Exception as e:  # noqa: BLE001
        fails.append(f"hw_target import failed {e!r}")
    # 2. decode sanity (LI/JRC fast path parity with emu_engine.decode_one)
    try:
        image = _load_image_bytes()
        assert image[0x5df2fa:0x5df2fa + 4] == bytes.fromhex("141e2412"), "SML head drift"
    except Exception as e:  # noqa: BLE001
        fails.append(f"image head: {e}")
    # 3. mandatory conformance
    try:
        res = conform_legal_sim_rule(verbose=False)
        if not res["stock"].get("pass"):
            fails.append(f"stock conformance {res['stock']}")
        if not res["patch"].get("pass"):
            fails.append(f"patch conformance {res['patch']}")
    except Exception as e:  # noqa: BLE001
        fails.append(f"conformance raised {e!r}")
    # 4. mnemonic spot checks (register/memory/branch units, no image needed)
    try:
        _unit_checks()
    except AssertionError as e:
        fails.append(f"unit: {e}")
    except Exception as e:  # noqa: BLE001
        fails.append(f"unit raised {e!r}")
    print("interp selftest:", "PASS" if not fails else "FAIL")
    for f in fails:
        print("  -", f)
    if not fails:
        print(coverage_report())
    return 1 if fails else 0


def _unit_checks() -> None:
    """Pure-exec unit checks on synthetic carves (no ROM dependency)."""
    import tempfile  # noqa: F401 (kept for stdlib-only proof)
    # craft: LI a0,5; ADDIU a0,a0,3; SW a0,0x0(sp); LW a1,0x0(sp); SEQI a2,a1,8
    #        BEQIC a2,0x1,+2; LI a3,0x1; LI a3,0x2; SAVE/RESTORE roundtrip
    # Instead of hand-assembling (forbidden), drive Cpu._exec_text directly
    # with canonical texts (decoder is the assembler here).
    img = b"\x00" * 0x1000
    cpu = Cpu(img, 0x90000000, b"\x00" * 0x20,
              regs={"a0": 0, "sp": STACK_BASE + 0x8000, "ra": RA_INIT})
    n = 0x90000000
    cpu._exec_text(n, "LI a0,0x5", 2, n + 2, "LI", ["a0", "0x5"])
    assert cpu.get("a0") == 5
    cpu._exec_text(n, "ADDIU a0,a0,0x3", 4, n + 4, "ADDIU", ["a0", "a0", "0x3"])
    assert cpu.get("a0") == 8
    cpu._exec_text(n, "SW a0,0x0(sp)", 4, n + 4, "SW", ["a0", "0x0(sp)"])
    cpu._exec_text(n, "LW a1,0x0(sp)", 4, n + 4, "LW", ["a1", "0x0(sp)"])
    assert cpu.get("a1") == 8
    cpu._exec_text(n, "SEQI a2,a1,0x8", 4, n + 4, "SEQI", ["a2", "a1", "0x8"])
    assert cpu.get("a2") == 1
    npc = cpu._exec_text(n, "BEQIC a2,0x1,0x90000010", 4, n + 4, "BEQIC",
                         ["a2", "0x1", "0x90000010"])
    assert npc == 0x90000010
    npc = cpu._exec_text(n, "BNEIC a2,0x1,0x90000010", 4, n + 4, "BNEIC",
                         ["a2", "0x1", "0x90000010"])
    assert npc == n + 4
    cpu._exec_text(n, "LSA s0,a0,a1,0x1", 4, n + 4, "LSA", ["s0", "a0", "a1", "0x1"])
    assert cpu.get("s0") == (8 * 2 + 8) & 0xFFFFFFFF
    cpu._exec_text(n, "MOVEP a1,a2,s0,s1", 2, n + 2, "MOVEP",
                   ["a1", "a2", "s0", "s1"])
    # SAVE/RESTORE roundtrip preserves callee-saved + returns
    cpu.put("s0", 0x11111111)
    cpu.put("s1", 0x22222222)
    cpu.put("ra", 0x12345678)
    sp0 = cpu.get("sp")
    cpu._exec_text(n, "SAVE 0x10,ra,s0,s1,s2", 2, n + 2, "SAVE",
                   ["0x10", "ra", "s0", "s1", "s2"])
    assert cpu.get("sp") == u32(sp0 - 0x10)
    cpu.put("s0", 0)
    cpu.put("s1", 0)
    npc = cpu._exec_text(n, "RESTORE.JRC 0x10,ra,s0,s1,s2", 2, n + 2,
                         "RESTORE.JRC", ["0x10", "ra", "s0", "s1", "s2"])
    assert cpu.get("s0") == 0x11111111 and cpu.get("s1") == 0x22222222
    assert cpu.get("sp") == sp0 and npc == 0x12345678
    # branch units
    cpu.put("a0", 0)
    assert cpu._exec_text(n, "BEQZC a0,0x90000020", 2, n + 2, "BEQZC",
                          ["a0", "0x90000020"]) == 0x90000020
    cpu.put("a0", 1)
    assert cpu._exec_text(n, "BNEZC a0,0x90000020", 2, n + 2, "BNEZC",
                          ["a0", "0x90000020"]) == 0x90000020
    cpu.put("s4", 0x16)
    assert cpu._exec_text(n, "BGEIUC s4,0x16,0x90000020", 4, n + 4, "BGEIUC",
                          ["s4", "0x16", "0x90000020"]) == 0x90000020
    cpu.put("a2", 5)
    cpu.put("s1", 10)
    assert cpu._exec_text(n, "BLTUC a2,s1,0x90000020", 4, n + 4, "BLTUC",
                          ["a2", "s1", "0x90000020"]) == 0x90000020
    cpu.put("a3", 0)
    cpu._exec_text(n, "SLTU a3,zero,a0", 4, n + 4, "SLTU", ["a3", "zero", "a0"])
    assert cpu.get("a3") == (1 if 0 < cpu.get("a0") else 0)
    cpu._exec_text(n, "XORI ra,a0,0x2d", 4, n + 4, "XORI", ["ra", "a0", "0x2d"])
    assert cpu.get("ra") == (cpu.get("a0") ^ 0x2D) & 0xFFFFFFFF
    cpu.put("a3", 3)
    cpu._exec_text(n, "SLL a3,a3,0x8", 2, n + 2, "SLL", ["a3", "a3", "0x8"])
    assert cpu.get("a3") == (3 << 8) & 0xFFFFFFFF
    # indexed + CP0 stub
    cpu.put("s1", STACK_BASE + 0x7000)
    cpu.put("s4", 4)
    cpu.store_u8(u32(cpu.get("s1") + 4), 0xAB)
    cpu._exec_text(n, "LBUX a1,s4(s1)", 4, n + 4, "LBUX", ["a1", "s4(s1)"])
    assert cpu.get("a1") == 0xAB
    cpu.put("s6", 0xCD)
    cpu.put("s3", 8)
    cpu.put("s4", u32(cpu.get("s1")))
    # SBX s6,s3(s4): [s4+s3] = s6
    cpu._exec_text(n, "SBX s6,s3(s4)", 4, n + 4, "SBX", ["s6", "s3(s4)"])
    assert cpu.load_u8(u32(cpu.get("s4") + 8)) == 0xCD
    cpu._exec_text(n, "MFC0 a0,C0.Status", 4, n + 4, "MFC0", ["a0", "C0.Status"])
    assert cpu.get("a0") == 0 and len(cpu.cp0.log) == 1


def main(argv: list[str] | None = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="nanoMIPS Python CPU core (offline)")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--conform", action="store_true",
                    help="legal_sim_rule stock/patch conformance")
    ap.add_argument("--corpus-check", action="store_true",
                    help="sweep 7 seed traces vs sim/traces/ byte-for-byte")
    ap.add_argument("--coverage", action="store_true")
    ap.add_argument("--va", default="0x905df2fa")
    ap.add_argument("--size", default="94")
    ap.add_argument("--steps", type=int, default=STEP_CAP_DEFAULT)
    args = ap.parse_args(argv)
    if args.coverage:
        print(coverage_report())
        return 0
    if args.selftest:
        return selftest()
    if args.conform:
        res = conform_legal_sim_rule(verbose=True)
        ok = bool(res["stock"].get("pass") and res["patch"].get("pass"))
        print("conform:", "PASS" if ok else "FAIL")
        return 0 if ok else 1
    if args.corpus_check:
        res = corpus_check(verbose=True)
        print("corpus:", res["overall"])
        return 0 if res["overall"] == "PASS" else 1
    # default: run one fn (stock carve, helpers=ret1, a0=ctx)
    va = int(args.va, 16)
    size = int(str(args.size), 0)
    regs = {"a0": CTX_INIT, "s0": CTX_INIT, "ra": RA_INIT, "sp": STACK_INIT,
            "_ctx_image": b"\x00" * CTX_SIZE}
    stubs = {0x9198A6F0: "ret1", 0x9198A744: "ret1",
             0x90ED3222: "ret1", 0x90ED7CE2: "ret1"}
    try:
        a0, steps, trace = _run_fn_impl(va, size, regs, stubs, None, args.steps)
        print(f"run va={va:#x} size={size}: HIT-RET a0={a0:#x} steps={steps}")
        for t in trace[:12]:
            print("  " + t)
        if len(trace) > 12:
            print(f"  ... +{len(trace) - 12} more")
        return 0
    except (BackendSkip, EmuUnsupported) as e:
        print(f"run SKIP: {e}")
        return 2


if __name__ == "__main__":
    sys.exit(main())

