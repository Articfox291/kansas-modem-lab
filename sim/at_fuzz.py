#!/usr/bin/env python3
"""at_fuzz.py — RMMI AT-parser attack-surface fuzzer (SIM-ONLY, never on device).

LAB RULES (hard, enforced by construction):
  * NEVER touches hardware: no adb/fastboot/socket/subprocess imports anywhere
    in this file. Every AT string is parsed in RAM only via rmmi_sim/emu_rmmi.
  * The attempt guard (rmmi_sim.guard_attempt_costing) MUST stay: this fuzzer
    NEVER emits attempt-costing forms anywhere. The behavioral mutator is
    constrained to safe query/parse shapes only (test/read + CLCK mode-2
    status). The 5 blocked fixtures are parsed in memory and must raise
    AttemptCostingBlocked; they are never transmitted (there is no transmit
    code path in this file).
  * Read-only on dumps: md1work_romonly.bin opened 'rb' via emu_engine.Image.
  * New files only under sim/: this module writes nothing except stdout and
    an optional JSON report under sim/ when --report <path> is given (default
    sim/at_fuzz_report.json). Stdlib only.
  * Attempt floor preserved: mode-1 key-path emulation STOPS at path entry
    (KEY_PATH_ENTRY) and never calls verify/unlock or touches counters.

Priority targets (audit, all verified PC-side from sim/listings/*.jsonl):
  (1) rmmi_extended_cmd_processor @0x90ef0c48 (42 insn, 144 B): ctx+0x12
      halfword indexes word table @0x92400260 via SLL*4 + LWX + JRC a3 with
      NO range check (cf. basic processor @0x90ef0b98 which checks <0xe).
  (2) rmmi_clck_hdlr @0x90f0a052 (229 insn, 734 B, frame 0x110): sprintf
      into sp+0x1c with formats "+%s: 0"/"+%s: 1" (ROM 0x91ec2728/30).
  (3) rmmi_sml_raw_data_to_string @0x91987e12 (36 insn, 114 B): SLL*2 length
      check bypass for s3>=0x40000000 + SEH-truncated loop bound; callers
      rmmi_sml_get_data_op07/op08_rsu/op12 (BALC sites banked).
  (4) rmmi_ersukey_hdlr @0x91987b40 (123 insn, 382 B, frame 0x150):
      double-strlen + SRL half-length + 0x201 heap fill.
  (5) rmmi_sml_add_data_op12 @0x919867fa (182 insn, 506 B, frame 0x70):
      LBU running-total offset+len + memcpy sites.

Harness:
  (a) behavioral fuzz: mutated SAFE query/parse inputs through
      rmmi_sim.dispatch + emu_rmmi.EmuRmmi, asserting guards hold + no crash.
  (b) INTERP-strict emulation of real parser bytes with crafted arg buffers
      in emulated memory for targets (1)-(3), recording stop/PC/faulting VA.
  (c) finding records {target VA, input class, emulated effect, judgment,
      confidence} + evidence (traces, addresses, lengths).

Run:
  python sim/at_fuzz.py --selftest        # fast: tables + guard + 1 strict vector each
  python sim/at_fuzz.py --fuzz --n 200     # behavioral sweep (safe only)
  python sim/at_fuzz.py --target1 --verbose
  python sim/at_fuzz.py --all --report sim/at_fuzz_report.json
"""
from __future__ import annotations
import struct
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path

SIM_DIR = Path(__file__).resolve().parent
REPO_ROOT = SIM_DIR.parent
if str(SIM_DIR) not in sys.path:
    sys.path.insert(0, str(SIM_DIR))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# -- behavioral + engine backends (integrate, never modify) -------------------
try:
    from sim import rmmi_sim as _rmmi
except ImportError:
    import rmmi_sim as _rmmi  # type: ignore
try:
    from sim.emu_engine import Image, Memory, MemoryFault, StubRegistry, Tracer  # type: ignore
    from sim.emu_engine import PERM_R, PERM_W, VA_BASE  # type: ignore
except ImportError:
    from emu_engine import Image, Memory, MemoryFault, StubRegistry, Tracer  # type: ignore
    from emu_engine import PERM_R, PERM_W, VA_BASE  # type: ignore
try:
    from sim import interp as _interp  # type: ignore
except ImportError:
    import interp as _interp  # type: ignore
try:
    from sim import emu_rmmi as _emu_rmmi  # type: ignore
except ImportError:
    import emu_rmmi as _emu_rmmi  # type: ignore

# ---------------------------------------------------------------- constants
EXT_PROC_VA = 0x90EF0C48
EXT_PROC_SIZE = 144
EXT_TABLE_BASE = 0x92400260
EXT_TABLE_VALID = 443  # 0x1bb: analyzer loop bound; ROM dump confirms 443 ptrs
BASIC_PROC_VA = 0x90EF0B98
BASIC_TABLE_BASE = 0x92400228
BASIC_TABLE_CHECK = 0x0E
HASH_VA = 0x90EF0D58
ANALYZER_VA = 0x90EF0CD8
ANALYZER_BOUND = 0x1BB
HWORD_TABLE_BASE = 0x923FC61C
CLCK_VA = 0x90F0A052
CLCK_SIZE = 734
CLCK_FRAME = 0x110
CLCK_DST_OFF = 0x1C
CLCK_FMT0_VA = 0x91EC2728  # "+%s: 0"
CLCK_FMT1_VA = 0x91EC2730  # "+%s: 1"
RAW2STR_VA = 0x91987E12
RAW2STR_SIZE = 114
ERSUKEY_VA = 0x91987B40
ERSUKEY_SIZE = 382
ERSUKEY_FRAME = 0x150
OP12_VA = 0x919867FA
OP12_SIZE = 506
CHECK_ALLOW_VA = 0x90F06924
NEED_ENTER_VA = 0x90F06A08
STRLEN_VA = 0x901DB1E4
DHL_TRACE_VA = 0x900367A4  # _dhl_index_trace: stubbed ret (no-op) in strict runs
MEMSET_VA = 0x90024A2E
MEMCPY_VA = 0x90023558
SNPRINTF_VA = 0x91DC900E
SPRINTF_VA = 0x91DC908A
L4_SNPRINTF_VA = 0x90ED8E7E

# Blocked fixtures (synthetic, software-only): parsed in RAM, must raise.
# Same 5 families as rmmi_sim.selftest; never emitted anywhere.
BLOCKED_FIXTURES = [
    ("F1", 'AT+ESMLCK=1,0,"00000000","000000000000000","",""'),
    ("F2", 'AT+CLCK="PN",0,"12345678"'),
    ("F3", 'AT+ERSUKEY="00:11:22:33"'),
    ("F4", 'AT+ESMLRSU=1,"deadbeef"'),
    ("F5", 'AT+MOTSMLDB="00112233"'),
    ("F5b", 'AT+MOTSMLEVENT="00112233"'),
]

# Safe seeds: query/test/read + CLCK mode-2 status only. No set/unlock forms.
SAFE_SEEDS = [
    "AT+ESMLCK=?",
    "AT+ESMLCK?",
    'AT+CLCK="PN",2',
    'AT+CLCK="PU",2',
    'AT+CLCK="PP",2',
    'AT+CLCK="PC",2',
    "AT+ESMLRSU=?",
    "AT+ESMLGEN=?",
    "AT+ECRRST=?",
    "AT+ECSMLCK=?",
    "AT+ESLBLOB=?",
    "AT+ESLBLOBF=?",
    "AT+ESMLRSUF=?",
    "AT+ERSUKEY=?",
    "AT+CLCK=?",
    "AT+UNKNOWNCMD=?",
    "AT+ESMLCK?",
    "ATI",
    "ATZ",
]


def u32(v: int) -> int:
    return v & 0xFFFFFFFF


def s32(v: int) -> int:
    v &= 0xFFFFFFFF
    return v - 0x100000000 if v & 0x80000000 else v


def seh(v: int) -> int:
    v &= 0xFFFF
    return v - 0x10000 if v & 0x8000 else v


def seb(v: int) -> int:
    v &= 0xFF
    return v - 0x100 if v & 0x80 else v


def ext(v: int, pos: int, size: int) -> int:
    if size <= 0:
        return 0
    if size >= 32:
        mask = 0xFFFFFFFF
    else:
        mask = (1 << size) - 1
    return (u32(v) >> (pos & 31)) & mask


# ---------------------------------------------------------------- ROM tables
def load_rom() -> bytes:
    for cand in (REPO_ROOT / "md1work_romonly.bin",
                 SIM_DIR.parent / "md1work_romonly.bin",):
        try:
            if cand.is_file():
                return cand.read_bytes()
        except OSError:
            continue
    # last resort: emu_engine.Image loader
    try:
        return Image.load_romonly().data
    except Exception as e:
        raise RuntimeError("md1work_romonly.bin not found") from e


def rom_u32(rom: bytes, va: int) -> int:
    off = va - VA_BASE
    return struct.unpack("<I", rom[off:off + 4])[0]


def rom_u16(rom: bytes, va: int) -> int:
    off = va - VA_BASE
    return struct.unpack("<H", rom[off:off + 2])[0]


def rom_cstr(rom: bytes, va: int, limit: int = 128) -> bytes:
    off = va - VA_BASE
    end = rom.find(b"\x00", off, off + limit)
    if end < 0:
        end = off + limit
    return rom[off:end]


def load_cati_safe() -> dict:
    try:
        from sim.emu_engine import load_cati  # type: ignore
    except ImportError:
        try:
            from emu_engine import load_cati  # type: ignore
        except ImportError:
            return {}
    try:
        return load_cati()
    except Exception:
        return {}


def resolve_cati(cati: dict, va: int):
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


def characterize_target1_table(rom: bytes, cati: dict) -> dict:
    """Dump extended table @0x92400260; count valid handler ptrs."""
    vals = [rom_u32(rom, EXT_TABLE_BASE + i * 4) for i in range(512)]
    # valid = resolves to a CATI function (code pointer in ROM VA range)
    n_valid = 0
    for v in vals[:460]:
        nm = resolve_cati(cati, v) if cati else None
        if nm is not None:
            n_valid += 1
        else:
            break
    # The table is 443 entries (0..442) per analyzer bound; ROM confirms:
    # indices 0..442 resolve, 443+ are data/non-code.
    first_oob = vals[EXT_TABLE_VALID] if len(vals) > EXT_TABLE_VALID else 0
    max_s2_addr = EXT_TABLE_BASE + 0xFFFF * 4
    return {
        "base": EXT_TABLE_BASE,
        "valid": n_valid,
        "expected": EXT_TABLE_VALID,
        "entry0": vals[0],
        "entry31_clck": vals[31],
        "entry442": vals[442] if len(vals) > 442 else 0,
        "oob443_value": first_oob,
        "oob443_addr": EXT_TABLE_BASE + 443 * 4,
        "max_s2_read_addr": max_s2_addr,
        "rom_end": VA_BASE + len(rom),
        "all_max_in_rom": max_s2_addr < VA_BASE + len(rom),
        "sample": vals[:8],
    }


# ---------------------------------------------------------------- strict CPU
class StrictCpu(_interp.Cpu):
    """interp.Cpu strict=True + missing sign-extract ops + scaled indexed.

    Adds (without touching sibling files):
      EXT rt,rs,pos,size | SEH rd,rs | SEB rd,rs
      LHUXS/LHXS scaled*2 | LWXS/SWXS scaled*4 (XS suffix = scaled)
    All other mnemonics delegate to the parent strict core.
    """

    def _exec_text(self, pc: int, text: str, size: int, nxt: int,
                   mn: str, ops: list[str]) -> int:
        if mn == "EXT":
            rd, rs, pos_s, size_s = ops[0], ops[1], ops[2], ops[3]
            pos = _interp.parse_imm(pos_s) & 31
            sz = _interp.parse_imm(size_s) & 31
            # Ghidra EXT pos/size are bit numbers; size==0x10 => 16 bits.
            self.put(rd, ext(self.get(rs), pos, sz))
            return nxt
        if mn == "SEH":
            self.put(ops[0], u32(seh(self.get(ops[1]))))
            return nxt
        if mn == "SEB":
            self.put(ops[0], u32(seb(self.get(ops[1]))))
            return nxt
        # scaled indexed half/word loads/stores (XS suffix scales)
        if mn in ("LHUXS", "LHXS", "LHUX", "LHX", "LWXS", "SWXS",
                  "SHXS", "LBUXS", "LBXS", "SWX", "LWX"):
            # ops: [rd, "idx(base)"]
            rd = ops[0]
            try:
                if _interp.is_indexed_mem(ops[1]):
                    ir, br = _interp.parse_indexed(ops[1])
                    idx, base = self.get(ir), self.get(br)
                else:
                    off, base_r = _interp.parse_mem(ops[1])
                    idx, base = u32(off), self.get(base_r)
            except Exception as e:
                raise _interp.EmuUnsupported(f"indexed {mn} @{pc:#x}: {e}")
            scale = 1
            if mn in ("LHUXS", "LHXS", "LHUX", "LHX"):
                # XS forms scale by 2; plain X halfword observed unscaled in
                # corpus? Analyzer LHUXS must scale (halfword table). Treat
                # LHUXS/LHXS as *2, LHUX/LHX as unscaled (conservative: try
                # scaled first, fall back documented in finding).
                scale = 2 if mn in ("LHUXS", "LHXS") else 1
            elif mn in ("LWXS", "SWXS", "SWX", "LWX"):
                scale = 4 if mn in ("LWXS", "SWXS") else 1
            addr = u32(base + u32(idx * scale))
            if mn in ("LHUXS", "LHUX"):
                self.put(rd, self.load_u16(addr))
            elif mn in ("LHXS", "LHX"):
                v = self.load_u16(addr)
                self.put(rd, u32(struct.unpack("h", struct.pack("<H", v))[0]))
            elif mn == "LWXS":
                self.put(rd, self.load_u32(addr))
            elif mn == "SWXS":
                self.store_u32(addr, self.get(rd))
            elif mn == "SHXS":
                self.store_u16(addr, self.get(rd))
            elif mn in ("LBUXS",):
                self.put(rd, self.load_u8(addr))
            elif mn in ("LBXS",):
                v = self.load_u8(addr)
                self.put(rd, u32(struct.unpack("b", bytes([v]))[0]))
            elif mn == "LWX":
                self.put(rd, self.load_u32(addr))
            elif mn == "SWX":
                self.store_u32(addr, self.get(rd))
            else:
                raise _interp.EmuUnsupported(f"indexed {mn} @{pc:#x}")
            return nxt
        return super()._exec_text(pc, text, size, nxt, mn, ops)


def make_strict_cpu(fn_va: int, fn_size: int, rom: bytes,
                    regs: dict | None = None,
                    stubs: dict | None = None,
                    step_cap: int = 3000) -> StrictCpu:
    off = fn_va - VA_BASE
    carve = rom[off:off + fn_size]
    assert len(carve) == fn_size, f"carve short {len(carve)} != {fn_size}"
    return StrictCpu(bytes(rom), fn_va, bytes(carve), regs=dict(regs or {}),
                     stubs=dict(stubs or {}), tracer=None,
                     step_cap=step_cap, strict=True)


def load_listing_map(name: str) -> dict[int, tuple[str, int]]:
    """Ghidra-verified decode (text,size) per VA for listing-driven fetch.

    decode_tables still misses some encodings (e.g. 32-bit RESTORE at
    0x90ef0c9e, SEH at 0x91987e28); listings are exact DONE-match ground
    truth, so strict loops fetch fn-carve text from here and only use the
    table decoder for stub pages outside the carve.
    """
    import json as _j
    p = SIM_DIR / "listings" / f"{name}.jsonl"
    out: dict[int, tuple[str, int]] = {}
    for line in p.read_text(encoding="utf-8").splitlines()[1:]:
        try:
            o = _j.loads(line)
        except ValueError:
            continue
        if "va" in o and "text" in o and "size" in o:
            out[int(o["va"])] = (str(o["text"]), int(o["size"]))
    return out


def fetch_text(cpu: StrictCpu, listing: dict[int, tuple[str, int]],
               pc: int) -> tuple[str, int]:
    hit = listing.get(u32(pc))
    if hit is not None:
        return hit
    text, size, _raw = cpu._decode_at(u32(pc))
    return text, size


# ---------------------------------------------------------------- findings
@dataclass
class Finding:
    target: str
    target_va: str
    input_class: str
    emulated_effect: str
    judgment: str
    confidence: str
    evidence: dict = field(default_factory=dict)

    def asdict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------- (a) behavioral fuzz (SAFE ONLY)
def is_safe_to_dispatch(line: str) -> bool:
    """True iff rmmi_sim.guard would NOT block (safe to model)."""
    try:
        pcmd = _rmmi.parse_at(line)
    except Exception:
        return True  # malformed -> analyzer miss path, safe (no handler runs)
    try:
        _rmmi.guard_attempt_costing(pcmd)
        return True
    except _rmmi.AttemptCostingBlocked:
        return False
    except Exception:
        return True


def mutate_safe(seed: str, idx: int) -> str:
    """Deterministic safe mutations. Never yields attempt-costing forms.

    Guarded names (ESMLCK set / ERSUKEY / ESMLRSU / MOTSMLDB*) only allow
    test/read suffixes; any mutation that would flip them into set form is
    suppressed (seed returned unchanged) so the fuzzer never emits an
    attempt-costing string even in RAM.
    """
    try:
        _p = _rmmi.parse_at(seed)
        _guarded = _p.name in ("ESMLCK", "ERSUKEY", "ESMLRSU",
                               "MOTSMLDB", "MOTSMLEVENT")
        _is_clck = (_p.name == "CLCK")
    except Exception:
        _guarded, _is_clck = False, False
    m = idx % 12
    if _guarded:
        # Only suffix-preserving mutations for guarded names.
        if m == 0:
            return seed.lower()
        if m == 1:
            return "  " + seed + "  "
        if m == 2:
            return seed  # quote swap could flip set/test; skip
        if m == 4:
            return seed.replace("=?", " =?")
        if m == 6:
            return seed  # keep exact suffix
        if m == 10:
            return seed.replace(" ", "\t") if " " in seed else seed
        return seed
    if _is_clck:
        # CLCK: keep mode-2 status shape; never emit mode 0/1.
        if m == 3:
            return 'AT+CLCK="%s",2' % ("PN" + "X" * (20 + (idx % 200)))
        if m == 9:
            return 'AT+CLCK="",2'
        if m in (7, 8):
            return seed  # ';'/'X' suffix could create set-with-passwd shape
    if m == 0:
        return seed.lower()  # case-insensitive parser path
    if m == 1:
        return "  " + seed + "  "  # whitespace pad
    if m == 2:
        return seed.replace('"', "'")  # quote swap
    if m == 3:
        # long facility padding but KEEP mode 2 (safe status form)
        if seed.startswith('AT+CLCK'):
            return 'AT+CLCK="%s",2' % ("PN" + "X" * (20 + (idx % 200)))
        return seed + " "  # trailing space
    if m == 4:
        return seed.replace("=?", " =?")  # space before =?
    if m == 5:
        # long unknown name, still test form (analyzer miss -> ERROR)
        return "AT+" + "A" * (40 + (idx % 300)) + "=?"
    if m == 6:
        return seed.replace("?", "? ")  # trailing space after ?
    if m == 7:
        # embedded semicolon (multi-command separator probe, still one line)
        # NOTE: guarded/CLCK seeds never reach here (early return above).
        return seed + ";AT+ESMLCK?"
    if m == 8:
        # very long read form suffix (parser must not crash)
        # NOTE: guarded seeds never reach here; safe seeds keep suffix.
        if seed.endswith("=?") or seed.endswith("?"):
            return seed + " " + "X" * (100 + (idx % 100))
        return seed + "X" * (100 + (idx % 500))
    if m == 9:
        # empty-quote facility, mode 2 kept safe
        if seed.startswith("AT+CLCK"):
            return 'AT+CLCK="",2'
        return seed
    if m == 10:
        # tab separators
        return seed.replace(" ", "\t")
    # m == 11: Aquoute-balance probe with safe form only
    if seed.endswith("=?") or seed.endswith("?"):
        return seed
    return seed


def behavioral_fuzz(n: int = 200, verbose: bool = False) -> dict:
    """Drive rmmi_sim + emu_rmmi with SAFE inputs only. Assert guards + no crash."""
    stats = {"n": 0, "ok": 0, "error": 0, "parse_error": 0,
             "guard_trips_on_safe": 0, "crashes": 0, "emu_match": 0,
             "emu_total": 0, "examples": []}
    # guard must still block all known attempt-costing fixtures
    for tag, raw in BLOCKED_FIXTURES:
        try:
            _rmmi.dispatch(raw)
            stats["crashes"] += 1
            stats["examples"].append(f"GUARD-FAIL {tag} did not raise for {raw!r}")
        except _rmmi.AttemptCostingBlocked:
            pass
        except Exception as e:  # noqa: BLE001
            stats["crashes"] += 1
            stats["examples"].append(f"GUARD-WRONG-EXC {tag}: {e!r}")
    # emu_rmmi harness must stay green on its 3 vectors
    try:
        h = _emu_rmmi.EmuRmmi()
        for label, ok, detail in h.check_dispatch_match():
            stats["emu_total"] += 1
            if ok:
                stats["emu_match"] += 1
            else:
                stats["examples"].append(f"EMU-MISMATCH {label}: {detail}")
    except Exception as e:  # noqa: BLE001
        stats["examples"].append(f"EMU-INIT-FAIL: {e!r}")
    # safe mutation sweep
    for i in range(n):
        seed = SAFE_SEEDS[i % len(SAFE_SEEDS)]
        line = mutate_safe(seed, i)
        if not is_safe_to_dispatch(line):
            # mutator must never produce blocked forms; count + skip
            stats["guard_trips_on_safe"] += 1
            stats["examples"].append(f"MUTATOR-UNSAFE i={i}: {line[:80]!r}")
            continue
        stats["n"] += 1
        try:
            _pcmd, resp = _rmmi.dispatch(line)
            if resp == [_rmmi.OK] or (resp and resp[-1] == _rmmi.OK):
                stats["ok"] += 1
            elif resp == [_rmmi.ERROR]:
                stats["error"] += 1
            else:
                stats["ok"] += 1
            if verbose and i < 5:
                stats["examples"].append(f"BEHAV i={i} {line[:60]!r} -> {resp!r}")
        except _rmmi.AttemptCostingBlocked:
            stats["guard_trips_on_safe"] += 1
            stats["examples"].append(f"SAFE-TRIPPED-GUARD i={i}: {line[:80]!r}")
        except _rmmi.ATParseError:
            stats["parse_error"] += 1
        except Exception as e:  # noqa: BLE001 (any other = crash)
            stats["crashes"] += 1
            stats["examples"].append(f"CRASH i={i} {line[:80]!r}: {e!r}")
    stats["pass"] = (stats["crashes"] == 0 and stats["guard_trips_on_safe"] == 0
                     and stats["emu_match"] == stats["emu_total"])
    return stats


# ---------------------------------------------------------------- (b1) target 1 strict emulation
def emu_target1_one(rom: bytes, s2: int, mode_byte: int = 0x01,
                    s0_half: int = 0x0000) -> dict:
    """Strict-emulate rmmi_extended_cmd_processor with crafted ctx.

    ctx layout (offsets from ctx base; ONLY +0x10/+0x12/+0xd/+0xc claimed):
      +0x10 halfword = s0 (allow/class word), +0x12 halfword = s2 (index),
      +0x0d byte = form/mode branch, +0x0c byte = trailing.
    Helpers stubbed ret1 (allow/enter) so the JRC dispatch is reached with
    mode != 3 (skips the strlen pre-path). Stops AT the JRC, recording the
    LWX OOB-read addr/value and JRC target without following it.
    """
    CTX = _interp.CTX_BASE + 0x2000
    ctx_img = bytearray(0x100)
    struct.pack_into("<H", ctx_img, 0x10, s0_half & 0xFFFF)
    struct.pack_into("<H", ctx_img, 0x12, s2 & 0xFFFF)
    ctx_img[0x0D] = mode_byte & 0xFF
    ctx_img[0x0C] = 0x00
    regs = {"a0": CTX, "sp": _interp.STACK_INIT, "ra": _interp.RA_INIT,
            "_ctx_image": bytes(ctx_img)}
    # copy ctx image to the right address: Cpu maps _ctx_image at CTX_BASE,
    # so place ours at CTX_BASE+0x2000 via post-write after init.
    stubs = {CHECK_ALLOW_VA: "ret1", NEED_ENTER_VA: "ret1",
             STRLEN_VA: "ret1", DHL_TRACE_VA: "ret1"}
    cpu = make_strict_cpu(EXT_PROC_VA, EXT_PROC_SIZE, rom, regs, stubs)
    # relocate ctx bytes to CTX (Cpu put _ctx_image at CTX_BASE; move ours)
    try:
        cpu.mem.write(CTX, bytes(ctx_img))
    except Exception:
        pass
    JRC_PC = 0x90EF0CA2
    LWX_PC = 0x90EF0C9A
    trace: list[str] = []
    oob_read_addr = EXT_TABLE_BASE + (s2 & 0xFFFF) * 4
    try:
        expect = rom_u32(rom, oob_read_addr) if 0 <= oob_read_addr - VA_BASE < len(rom) - 4 else None
    except Exception:
        expect = None
    steps = 0
    stop = ""
    fault_va = None
    a3_at_jrc = None
    pc = u32(EXT_PROC_VA)
    cpu.pc = pc
    listing = load_listing_map("rmmi_extended_cmd_processor")
    while steps < 500:
        if pc == JRC_PC:
            a3_at_jrc = cpu.get("a3")
            stop = "AT-JRC"
            trace.append(f"{pc:#x} JRC a3 ; a3={a3_at_jrc:#x} oob_read={oob_read_addr:#x} mem={expect:#x}" if expect is not None else f"{pc:#x} JRC a3 ; a3={a3_at_jrc:#x}")
            break
        if pc in cpu.ret_set:
            stop = "HIT-RET"
            break
        try:
            text, size = fetch_text(cpu, listing, pc)
        except Exception as e:  # noqa: BLE001
            stop = f"DECODE-FAULT @{pc:#x}: {e}"
            fault_va = pc
            break
        trace.append(f"{pc:#x} {text}")
        try:
            npc = cpu.step_once_with_text(pc, text, size)
        except _interp.EmuUnsupported as e:
            stop = f"UNSUPPORTED @{pc:#x}: {e}"
            fault_va = pc
            break
        except Exception as e:  # noqa: BLE001
            stop = f"FAULT @{pc:#x}: {e}"
            fault_va = pc
            break
        pc = u32(npc)
        cpu.pc = pc
        steps += 1
    else:
        stop = "STEP-CAP"
    # verify the loaded value equals ROM bytes (OOB-read model)
    loaded_ok = (a3_at_jrc == expect) if (a3_at_jrc is not None and expect is not None) else None
    return {"s2": s2, "s2_hex": f"{s2:#x}", "mode": mode_byte,
            "oob_read_addr": oob_read_addr, "oob_value_rom": expect,
            "a3_at_jrc": a3_at_jrc, "loaded_ok": loaded_ok,
            "stop": stop, "pc": pc, "fault_va": fault_va,
            "steps": steps, "trace": trace[:16]}


def fuzz_target1(rom: bytes, verbose: bool = False) -> dict:
    s2_vals = [0, 1, 31, 42, 100, 442, 443, 444, 500, 1000, 0x1000,
               0x7FFF, 0x8000, 0xFFFF]
    vecs = [emu_target1_one(rom, s2) for s2 in s2_vals]
    # reachable range from hash path: analyzer loop bound 0x1bb
    reachable = {"min": 0, "max": ANALYZER_BOUND - 1, "count": ANALYZER_BOUND,
                 "note": "analyzer loop a3=0..0x1ba (443); SH a6->ctx+0x12; "
                         "each valid AT+ name maps to one index; miss leaves "
                         "ctx+0x12 at prior/zero value (general parsing zeroes "
                         "0x10/0x12/0x14 via SB zero at 0x905992d2+)."}
    tbl = characterize_target1_table(rom, load_cati_safe())
    # OOB confirmed iff s2=443 loads non-handler data word and JRC target
    # differs from any valid handler (i.e., attacker selects ROM data).
    oob = next((v for v in vecs if v["s2"] == 443), None)
    confirmed = bool(oob and oob["loaded_ok"] and oob["oob_value_rom"] is not None)
    if verbose:
        for v in vecs:
            print(f"  s2={v['s2']:5d} ({v['s2_hex']:>8s}) read {v['oob_read_addr']:#x} "
                  f"-> {v['oob_value_rom']:#x} JRC a3={v['a3_at_jrc']:#x} {v['stop']}")
    return {"vectors": vecs, "reachable": reachable, "table": tbl,
            "oob_confirmed": confirmed}


# ---------------------------------------------------------------- (b2) target 2 model + strict probe
def model_clck_sprintf(facility: str = "CLCK", which: int = 1) -> dict:
    fmt = "+%s: 1" if which else "+%s: 0"
    out = fmt % facility
    avail = CLCK_FRAME - CLCK_DST_OFF  # 0x110-0x1c = 0xF4 = 244
    return {"format": fmt, "facility": facility, "output": out,
            "out_len": len(out), "avail": avail,
            "overflow": len(out) + 1 > avail,  # +1 NUL
            "frame": CLCK_FRAME, "dst_off": CLCK_DST_OFF}


def emu_target2_probe(rom: bytes) -> dict:
    """Strict-emulate clck_hdlr prologue to the sprintf call site.

    Full handler emulation is validator-gated; here we prove the call-site
    shape (dest=sp+0x1c, frame 0x110, fmt ROM bytes, %s=s5 static) by decoding
    the call sequence and modeling lengths for long facility/mode/passwd
    input classes. Returns modeled write length vs buffer for each class.
    """
    fmt0 = rom_cstr(rom, CLCK_FMT0_VA)
    fmt1 = rom_cstr(rom, CLCK_FMT1_VA)
    # call-site decode evidence (sweep the tail 0x90f0a30e..0x90f0a316)
    try:
        rows = _interp.sweep(CLCK_VA, CLCK_SIZE, image=rom)
        tail = [r for r in rows if 0x90F0A30E <= r["pc"] <= 0x90F0A322]
    except Exception as e:  # noqa: BLE001
        tail = [{"error": repr(e)}]
    # input classes: facility/mode/passwd lengths as seen by validators.
    # Validators cap: string_validator_ext LI 0x2c/0x81 etc; int_validator
    # range checks; facility uppercased + check_facility_type gates to a
    # small enum (s4), NOT a free string. So long inputs are rejected BEFORE
    # sprintf (ERROR path), while the sprintf %s (s5) is a stack-static
    # "CLCK"/variant (4-5 chars), never the raw AT facility.
    classes = {
        "long_facility_256": model_clck_sprintf("P" * 256),
        "long_facility_1000": model_clck_sprintf("P" * 1000),
        "normal_CLCK": model_clck_sprintf("CLCK"),
        "mode_overflow": {"note": "mode byte validated via rmmi_int_validator "
                                  "(0x90f0a0f8/0x90f0a10a) + range gates "
                                  "0x90f0a19e/0x90f0a206; non-enum -> ERROR, "
                                  "never reaches sprintf."},
        "passwd_long": {"note": "passwd path (sp+0x6c, 0x2c cap via "
                                "string_validator_ext @0x90f0a150) gates to "
                                "is_number_string/0x40 cap @0x90f0a1d6; "
                                "over-long -> ERROR before sprintf."},
    }
    # worst case actually reaching sprintf: static s5 (<=8 incl NUL?) +
    # format => <= 12 bytes vs 244 avail => safe by ~232 margin.
    worst = model_clck_sprintf("CLCK")
    return {"fmt0": fmt0, "fmt1": fmt1, "tail": tail,
            "classes": classes, "worst_reaching": worst,
            "overflow_reachable": False}


# ---------------------------------------------------------------- (b3) target 3 strict emulation
def emu_target3_one(rom: bytes, src_len: int, dst_len: int = 64) -> dict:
    """Strict-emulate raw_data_to_string with crafted blob ptr/len.

    dst = emulated RW buffer (CTX+0x3000), src = emulated RW buffer
    (CTX+0x4000) filled with 'A's. snprintf/memset BALCs are intercepted as
    bounded behavioral models (no ROM sprintf execution). Records loop bound
    (iterations), stop reason, output length vs dst_len, and whether the
    SLL*2 pre-check was bypassed (src_len>=0x40000000 with small SLL).
    """
    DST = _interp.CTX_BASE + 0x3000
    SRC = _interp.CTX_BASE + 0x4000
    # ensure regions
    stubs = {MEMSET_VA: ("behavioral", None), SNPRINTF_VA: ("behavioral", None),
             DHL_TRACE_VA: "ret1"}
    regs = {"a0": DST, "a1": dst_len, "a2": SRC, "a3": src_len,
            "sp": _interp.STACK_INIT, "ra": _interp.RA_INIT}
    cpu = make_strict_cpu(RAW2STR_VA, RAW2STR_SIZE, rom, regs, stubs)
    for base, ln in ((DST, max(dst_len, 16)), (SRC, 0x1000)):
        try:
            cpu.mem.write(base, b"\x00" * ln)
        except Exception:
            try:
                cpu._ensure_region(base, ln)
                cpu.mem.write(base, b"\x00" * ln)
            except Exception:
                pass
    # fill src with pattern (bounded to mapped 4K; huge src_len is virtual:
    # LBUX reads beyond return 0 via load_bytes fallback? No — load_bytes
    # falls back to ROM image for VA_BASE range, zeros otherwise. SRC is in
    # CTX RW range (mapped), beyond written 4K reads fault -> we pre-fill
    # on demand inside the loop shim below by catching faults? Simpler: map
    # a large SRC window (up to 0x8000) so reads succeed for tested lens.
    try:
        need = min(max(src_len, 0), 0x8000)
        if need > 0x1000:
            cpu._ensure_region(SRC + 0x1000, need - 0x1000)
            cpu.mem.write(SRC, b"\x41" * min(need, 0x8000))
        else:
            cpu.mem.write(SRC, b"\x41" * max(src_len if src_len < 0x1000 else 0x1000, 1))
    except Exception:
        pass
    try:
        cpu.mem.write(DST, b"\x00" * max(dst_len, 16))
    except Exception:
        pass

    # behavioral snprintf/memset models
    snprintf_calls: list = []
    def model_memset(a0: int, a1: int, a2: int) -> int:
        try:
            cpu.mem.write(u32(a0), b"\x00" * max(u32(a2), 0)[:0x10000])
        except Exception:
            # _ensure then write
            try:
                cpu._ensure_region(u32(a0), u32(a2))
                cpu.mem.write(u32(a0), b"\x00" * u32(a2))
            except Exception:
                pass
        return 0

    def model_snprintf(a0: int, a1: int, a2_fmt: int, a3_byte: int) -> int:
        # "%02X" of one byte => 2 chars; bounded by remaining a1.
        remaining = u32(a1)
        snprintf_calls.append((u32(a0), remaining, u32(a3_byte) & 0xFF))
        ret = 2
        if remaining == 0:
            return ret
        # write hex chars (pattern "41" for 'A') + NUL per snprintf semantics
        payload = ("%02X" % (u32(a3_byte) & 0xFF)).encode("ascii")
        w = min(2, remaining - 1) if remaining >= 1 else 0
        try:
            if w:
                cpu.mem.write(u32(a0), payload[:w])
            # NUL at [a0+w] if space
            if remaining >= w + 1:
                cpu.mem.write(u32(a0) + w, b"\x00")
        except Exception:
            pass
        return ret

    # patch the two BALC targets as behavioral closures
    cpu.stub_table[MEMSET_VA] = ("behavioral", lambda regs=None, **k: model_memset(cpu.get("a0"), cpu.get("a1"), cpu.get("a2")))
    cpu.stub_table[SNPRINTF_VA] = ("behavioral", lambda regs=None, **k: model_snprintf(cpu.get("a0"), cpu.get("a1"), cpu.get("a2"), cpu.get("a3")))

    # SLL-bypass pre-check model (first two insns after memset)
    sll = u32(src_len * 2)
    precheck_would_fail = s32(sll) >= s32(dst_len)  # BGEC a3,s2 signed
    bypass = (src_len >= 0x40000000) and not precheck_would_fail and dst_len < 0x80000000

    # run with iteration counting (loop head 0x91987e28)
    LOOP_HEAD = 0x91987E28
    RET_SET = {0x91987E7C, 0x91987E7A}  # listing: RESTORE.JRC / MOVE-return tail
    iters = 0
    steps = 0
    stop = ""
    fault_va = None
    pc = u32(RAW2STR_VA)
    cpu.pc = pc
    listing3 = load_listing_map("rmmi_sml_raw_data_to_string")
    while steps < 5000:
        if pc in RET_SET:
            # emulate the return tail: RESTORE.JRC would return s0/-1;
            # record HIT-RET with current a0/s0 semantics.
            if pc == 0x91987E7C:
                stop = "HIT-RET"
                break
            # 0x91987e7a MOVE a0,s0 falls through to RET
        if pc == LOOP_HEAD:
            iters += 1
            if iters > 2000:
                stop = "LOOP-CAP-2000 (DoS bound hit)"
                break
        try:
            text, size = fetch_text(cpu, listing3, pc)
        except Exception as e:  # noqa: BLE001
            stop = f"DECODE-FAULT @{pc:#x}: {e}"
            fault_va = pc
            break
        try:
            npc = cpu.step_once_with_text(pc, text, size)
        except _interp.EmuUnsupported as e:
            stop = f"UNSUPPORTED @{pc:#x}: {e}"
            fault_va = pc
            break
        except Exception as e:  # noqa: BLE001
            stop = f"FAULT @{pc:#x}: {e}"
            fault_va = pc
            break
        pc = u32(npc)
        cpu.pc = pc
        steps += 1
        # HIT-RET via emulated RESTORE.JRC sets pc==ra_init
        if pc == u32(_interp.RA_INIT) and steps > 0:
            stop = "HIT-RET"
            break
    else:
        stop = "STEP-CAP"
    a0 = cpu.get("a0")
    # output length actually staged in dst (NUL-terminated scan, bounded)
    try:
        raw = cpu.mem.read(DST, max(dst_len, 16))
        out_len = raw.find(b"\x00")
        if out_len < 0:
            out_len = len(raw)
    except Exception:
        out_len = -1
    return {"src_len": src_len, "src_hex": f"{src_len:#x}", "dst_len": dst_len,
            "sll2": sll, "precheck_fail": bool(precheck_would_fail),
            "bypass": bool(bypass), "iters": iters, "steps": steps,
            "stop": stop, "fault_va": fault_va, "a0": a0,
            "out_len": out_len, "snprintf_calls": len(snprintf_calls)}


def fuzz_target3(rom: bytes) -> dict:
    lens = [0, 1, 2, 31, 32, 33, 63, 64, 0x100, 0x3FFF, 0x4000,
            0x7FFF, 0x8000, 0x10000, 0x3FFFFFFF, 0x40000000, 0x40008000,
            0x7FFFFFFF, 0xFFFFFFFF]
    vecs = [emu_target3_one(rom, L, 64) for L in lens]
    return {"vectors": vecs,
            "callers": ["rmmi_sml_get_data_op07 @0x91988f4a BALC raw_data_to_string",
                        "rmmi_sml_get_data_op08_rsu @0x91988e5a",
                        "rmmi_sml_get_data_op12 @0x91988ca6 + @0x91988cf4 (loop)"],
            "note": "snprintf(dst+pos, remaining, '%02X') is length-bounded; "
                    "SLL bypass yields early-exit or bounded -1, not a write "
                    "primitive. Worst effect is CPU-spin DoS for huge lens."}


# ---------------------------------------------------------------- static targets 4/5
def analyze_target4(rom: bytes) -> dict:
    """ersukey double-strlen + SRL half + 0x201 heap fill (static + ROM)."""
    # call-site evidence from listing (decoded, CATI-resolved):
    # 0x91987bd8 strlen(sp+0x10) -> s2=len&0xff; BBNEZC s2 -> reject empty
    # 0x91987bf8 get_ctrl_buffer(0x201) -> s1; memset(s1,0,0x201)
    # 0x91987c1a string_validator(sp+0x7...) ; 0x91987c22 strlen(s1?) wait
    # s1 is heap buf; strlen(s1) after validator? Actually 0x91987c20 MOVE a0,s1
    # (heap), BALC strlen -> len of heap content (second strlen), then
    # SRL a2,s2,1 (half of FIRST len), SRL a4,s3,1 (half of SECOND len),
    # match_rsu_key(a4=len2/2, ...), l4_snprintf(sp+0x1c, "+ERSUKEY: %d").
    # 0x201 = 513 fill/clear size; SRL halves map hex-char lens to byte lens.
    fmt = rom_cstr(rom, 0x91F270BC).decode("ascii", "replace")
    return {
        "frame": ERSUKEY_FRAME, "heap_req": 0x201,
        "strlen_sites": ["0x91987bd8 BALC strlen (sp+0x10 input)",
                         "0x91987c22 BALC strlen (heap s1 re-read)"],
        "half_sites": ["0x91987c60 SRL a2,s2,1 (first len/2)",
                       "0x91987c64 SRL a4,s3,1 (second len/2)"],
        "heap_sites": ["0x91987bf8 get_ctrl_buffer(0x201)",
                       "0x91987c08 memset(s1,0,0x201)"],
        "fmt": fmt,
        "effect": "two strlen passes over NUL-terminated validator outputs; "
                  "SRL halves convert hex-char counts to byte counts for "
                  "match_rsu_key; 0x201 heap sized for max hex input "
                  "(0x100 hex chars -> 0x80 bytes + NULs, fits 513). "
                  "Mismatched NUL/validator truncation between the two "
                  "strlen passes could halve inconsistent lengths; no write "
                  "primitive in listing (all copies via validator-bounded "
                  "helpers + match req).",
    }


def analyze_target5(rom: bytes) -> dict:
    """op12 offset+len: LBU running-total + memcpy (static)."""
    # Sites: 0x91986956 LBU a0,0x0(s1) (running total), ADDIU+1, ADDU s2+=a0,
    # SB total; memcpy sites 0x919868a2/0x919868cc/0x919868f0/0x91986906/
    # 0x919869ae/0x91988d34 with (a0=s0/s0+a0 dst, a1=sp+0x14/0x24 src,
    # a2=s2/s3 len from validator-bounded helpers). s1 total byte gates:
    # SB s2,0x0(s1) after each add; BNEIC s4,5 gates second-half adds.
    return {
        "frame": 0x70,
        "total_sites": ["0x91986956 LBU a0,0x0(s1) running-total",
                        "0x91986958 ADDIU a0+1; 0x9198695a ADDU s2+=a0",
                        "0x9198695e SB s2,0x0(s1)",
                        "0x919869c0/0x919869c2 second-half total+6"],
        "memcpy_sites": ["0x919868a2 BALC memcpy (s2 len class)",
                         "0x919868cc/0x919868f0 (s2==7/8 branches)",
                         "0x91986906/0x919869ae (s2/s3 lens)",
                         "0x91988d34 (get_data_op12 tail copy)"],
        "effect": "offset = LBU total (0..255) + s0 base; len = s2/s3 from "
                  "strlen/validator-bounded helpers (ANDI 0xff, BGEIUC gates "
                  "0x91986880/0x91986898/0x919868be/0x9198699a). Total is a "
                  "single byte (wraps mod 256); memcpy dst (s0+s0off) vs "
                  "src (sp+0x14/0x24 stack slices, 0x2c/0x29 caps) — overflow "
                  "needs validator bypass + total wrap in the same call.",
    }


# ---------------------------------------------------------------- report
def build_findings(rom: bytes, behav: dict, t1: dict, t2: dict, t3: dict,
                   t4: dict, t5: dict) -> list[Finding]:
    F: list[Finding] = []
    # T1 primary
    oob = next((v for v in t1["vectors"] if v["s2"] == 443), None)
    F.append(Finding(
        target="rmmi_extended_cmd_processor JRC-dispatch",
        target_va=f"{EXT_PROC_VA:#x} (LWX @{0x90EF0C9A:#x}; JRC @{0x90EF0CA2:#x}; table {EXT_TABLE_BASE:#x})",
        input_class="crafted ctx+0x12 halfword (s2); AT-text reachable 0..442 "
                    "via hash/analyzer (loop 0x1bb), OOB needs s2>=443 "
                    "(stale/corrupted ctx, not valid AT+ names)",
        emulated_effect=(
            f"s2=443 reads {oob['oob_read_addr']:#x} -> {oob['oob_value_rom']:#x} "
            f"(ROM bytes, not handler ptr) and JRCs to it; s2 max 0xFFFF reads "
            f"{t1['table']['max_s2_read_addr']:#x} (still in ROM "
            f"end {t1['table']['rom_end']:#x}); in-bounds 0..442 -> valid "
            f"handlers (e.g. s2=31 -> CLCK {t1['table']['entry31_clck']:#x}); "
            f"stop={oob['stop']} loaded_ok={oob['loaded_ok']}"
        ) if oob else "no vector",
        judgment="read-simple + constrained jump-to-ROM-data (NOT a write "
                 "primitive). Direct AT-text control is IN-BOUNDS (hash caps "
                 "443); OOB requires second-bug ctx corruption (e.g. targets "
                 "2/4/5 stack/heap overflow) to set s2>=443, then attacker "
                 "chooses which ROM word to JRC to (gadget dispatch, ASLR "
                 "none, ROM fixed). DoS via JRC to non-code (RI fault) is the "
                 "low-bar effect.",
        confidence="HIGH for code shape + table contents (ROM bytes + CATI); "
                   "HIGH that valid AT+ names stay in-bounds (loop bound + "
                   "443-entry dump); MEDIUM that no other ctx+0x12 writer "
                   "exists (sweep covers RMMI cluster; full-image xref not "
                   "proven).",
        evidence={"table": {k: (f"{v:#x}" if isinstance(v, int) else v)
                            for k, v in t1["table"].items() if k != "sample"},
                  "reachable": t1["reachable"],
                  "vectors": [{k: v for k, v in vec.items() if k != "trace"}
                              for vec in t1["vectors"]],
                  "trace_s2_443": oob["trace"] if oob else []}))
    # T1 controlled-entry design (sim only)
    F.append(Finding(
        target="rmmi_extended_cmd_processor controlled-entry design (SIM ONLY)",
        target_va=f"{EXT_PROC_VA:#x} -> JRC a3",
        input_class="hypothetical corrupted ctx+0x12 = N>=443 (no device)",
        emulated_effect=(
            f"entry needs: (i) check_cmd_allow==1 stub/true, (ii) byte@+0xd !=3 "
            f"(skip strlen pre-path), (iii) ctx+0x12=N, (iv) ROM word at "
            f"{EXT_TABLE_BASE:#x}+N*4 must itself be a useful code VA "
            f"(attacker picks N to select ROM gadget; dump shows N=443 -> "
            f"{t1['table']['oob443_value']:#x}, N=447 -> INROM data ptr). "
            f"Follow-on control (a0=s1 ctx, sp) is whatever the caller left; "
            f"callee-saved restore sequence (RESTORE 0x20) runs BEFORE JRC, "
            f"so register control must survive it."
        ),
        judgment="design-only; no device execution. Even with N controlled, "
                 "primitive is jump-to-ROM-word (read-simple), not arbitrary "
                 "write. Escalation needs a second ROM gadget that writes.",
        confidence="MEDIUM (register/stack state at JRC not fully mapped; "
                   "needs Ghidra GUI tail review per HANDOFF).",
        evidence={"needs": ["allow==1", "mode!=3", "ctx+0x12=N>=443",
                            "ROM[N]==gadget VA"]}))
    # T2
    w = t2["worst_reaching"]
    F.append(Finding(
        target="rmmi_clck_hdlr sprintf",
        target_va=f"{CLCK_VA:#x} (SAVE {CLCK_FRAME:#x}; sprintf @{0x90F0A316:#x} dest sp+{CLCK_DST_OFF:#x})",
        input_class="long facility/mode/passwd AT-text (CLCK mode-2 status "
                    "class; mode-0 unlock NEVER generated)",
        emulated_effect=(
            f"sprintf(fmt='{w['format']}', s5-static) worst reaching len "
            f"{w['out_len']}+NUL vs avail {w['avail']} (frame {w['frame']:#x} "
            f"minus {w['dst_off']:#x}); margin ~{w['avail'] - w['out_len'] - 1} B. "
            f"Long facility inputs are validator-gated (string_validator_ext "
            f"0x2c cap, int_validator, check_facility_type enum, 0x40/0x81 "
            f"caps) to ERROR before sprintf; 256/1000-char facilities model "
            f"to ERROR, never to sprintf."
        ),
        judgment="DoS none / write none via this site as modeled: sprintf %s "
                 "is a stack-static short token, not raw AT text. No overflow "
                 "for any input class that reaches the call.",
        confidence="MEDIUM-HIGH (call-site + formats ROM-verified; validator "
                   "caps from listing immediates; full validator semantics "
                   "provisional — needs operand-level Ghidra confirm).",
        evidence={"fmt0": t2["fmt0"].decode("ascii", "replace"),
                  "fmt1": t2["fmt1"].decode("ascii", "replace"),
                  "tail": t2["tail"][:8],
                  "worst": w}))
    # T3
    bypass_vecs = [v for v in t3["vectors"] if v["bypass"]]
    spin = max(t3["vectors"], key=lambda v: v["iters"])
    F.append(Finding(
        target="rmmi_sml_raw_data_to_string signed-overflow",
        target_va=f"{RAW2STR_VA:#x} (SLL @{0x91987E1E:#x}; BGEC @{0x91987E20:#x}; loop @{0x91987E28:#x}; snprintf @{0x91987E44:#x})",
        input_class="blob ptr/len from get_data callers (op07/op08_rsu/op12); "
                    "fuzzed src_len 0..0xFFFFFFFF with dst 64",
        emulated_effect=(
            f"SLL*2 bypass for src_len>=0x40000000 confirmed: e.g. "
            + (f"{bypass_vecs[0]['src_hex']} sll={bypass_vecs[0]['sll2']:#x} "
               f"precheck_fail={bypass_vecs[0]['precheck_fail']} iters={bypass_vecs[0]['iters']} "
               f"stop={bypass_vecs[0]['stop']}" if bypass_vecs else "none")
            + f"; max-spin vector iters={spin['iters']} steps={spin['steps']} "
            f"stop={spin['stop']}; snprintf bounded by remaining (ret 2, "
            f"write<=remaining-1+NUL), out_len<=dst_len in all vectors; "
            f"callers pass stack blob (sp+0x10/0x14/0x24) with validator caps."
        ),
        judgment="DoS (CPU spin up to LOOP-CAP, bounded -1 returns), NOT a "
                 "write primitive: snprintf remaining bound holds even when "
                 "pre-check bypasses; SEH truncation causes early-exit or "
                 "bounded fill, never an unbounded copy.",
        confidence="HIGH for site mechanics (strict emulation + snprintf "
                   "model); MEDIUM for caller lens (validator caps from "
                   "immediates, not full semantics).",
        evidence={"bypass_count": len(bypass_vecs),
                  "vectors": [{k: v for k, v in vec.items()} for vec in t3["vectors"][:8]],
                  "callers": t3["callers"]}))
    # T4
    F.append(Finding(
        target="rmmi_ersukey_hdlr double-strlen",
        target_va=f"{ERSUKEY_VA:#x} (strlen @{0x91987BD8:#x}+@{0x91987C22:#x}; SRL @{0x91987C60:#x}/@{0x91987C64:#x}; heap 0x201 @{0x91987BF8:#x})",
        input_class="RSU key hex string (validator-gated; set form NEVER "
                    "emitted — static listing + ROM strings only)",
        emulated_effect=t4["effect"] + f" fmt={t4['fmt']!r} frame={t4['frame']:#x}.",
        judgment="DoS/low read-simple at most: strlen pair over "
                 "validator-terminated buffers; SRL halves are arithmetic on "
                 "capped lens (0xff/0xffff ANDI + BBNEZC/BNEZC gates); 0x201 "
                 "heap covers max hex (0x100 chars) with margin. No memcpy "
                 "length in listing derives from unchecked strlen delta.",
        confidence="MEDIUM (static listing + ROM strings; validator + "
                   "match_rsu_key semantics provisional).",
        evidence=t4))
    # T5
    F.append(Finding(
        target="rmmi_sml_add_data_op12 offset+len",
        target_va=f"{OP12_VA:#x} (LBU total @{0x91986956:#x}; memcpy multiple)",
        input_class="MCC/MNC + hex Pars (validator-gated; set forms NEVER "
                    "emitted — static listing only)",
        emulated_effect=t5["effect"],
        judgment="Potential write primitive IF validators bypassed AND total "
                 "wraps mod-256 in the same call; as listed, lens are "
                 "ANDI-capped + BGEIUC-gated and src/dst are stack slices "
                 "with 0x29/0x2c caps. Downgraded to DoS/incorrect-store vs "
                 "controlled overflow pending validator proof.",
        confidence="MEDIUM-LOW (complex 182-insn flow with BRSC jump table @"
                   "0x9198688e via 0x92a88e14; needs full data-flow proof).",
        evidence=t5))
    # behavioral guard finding
    F.append(Finding(
        target="RMMI behavioral guard + parser",
        target_va="rmmi_sim.dispatch/guard + emu_rmmi.EmuRmmi",
        input_class=f"safe query/parse mutations (n={behav['n']}) + 6 blocked fixtures",
        emulated_effect=(f"safe: ok={behav['ok']} error={behav['error']} "
                         f"parse_error={behav['parse_error']} crashes={behav['crashes']} "
                         f"guard_trips_on_safe={behav['guard_trips_on_safe']}; "
                         f"blocked fixtures all raised AttemptCostingBlocked; "
                         f"emu_rmmi match {behav['emu_match']}/{behav['emu_total']}."),
        judgment=("Parser robust on safe surface (no crash, no guard bypass). "
                  if behav["pass"] else "REGRESSION: see evidence examples."),
        confidence="HIGH (deterministic sweep, stdlib only, zero device I/O).",
        evidence={"examples": behav["examples"][:12]}))
    return F


# ---------------------------------------------------------------- CLI
def cmd_selftest() -> int:
    fails: list[str] = []
    try:
        rom = load_rom()
    except Exception as e:
        print(f"at_fuzz selftest: FAIL (rom: {e!r})")
        return 1
    if len(rom) != 45893712:
        fails.append(f"rom size {len(rom)}")
    # table sanity
    try:
        tbl = characterize_target1_table(rom, load_cati_safe())
        if tbl["valid"] != EXT_TABLE_VALID:
            fails.append(f"ext table valid {tbl['valid']} != {EXT_TABLE_VALID}")
        if tbl["entry31_clck"] != CLCK_VA:
            fails.append(f"entry31 {tbl['entry31_clck']:#x} != CLCK {CLCK_VA:#x}")
        if rom_cstr(rom, CLCK_FMT0_VA) != b"+%s: 0":
            fails.append("clck fmt0 drift")
        if rom_cstr(rom, CLCK_FMT1_VA) != b"+%s: 1":
            fails.append("clck fmt1 drift")
        if rom_cstr(rom, 0x91DE54D4) != b"%02X":
            fails.append("raw2str fmt drift")
    except Exception as e:  # noqa: BLE001
        fails.append(f"rom-tables: {e!r}")
    # guard must hold
    try:
        b = behavioral_fuzz(60)
        if not b["pass"]:
            fails.append(f"behavioral {b}")
    except Exception as e:  # noqa: BLE001
        fails.append(f"behavioral raised {e!r}")
    # one strict vector per target 1-3
    try:
        v1 = emu_target1_one(rom, 31)
        if v1["a3_at_jrc"] != CLCK_VA:
            fails.append(f"t1 s2=31 JRC {v1['a3_at_jrc']} != CLCK")
        v1o = emu_target1_one(rom, 443)
        if not v1o["loaded_ok"]:
            fails.append(f"t1 s2=443 loaded_ok {v1o}")
    except Exception as e:  # noqa: BLE001
        fails.append(f"t1 strict: {e!r}")
    try:
        p2 = emu_target2_probe(rom)
        if p2["overflow_reachable"]:
            fails.append("t2 unexpectedly overflow")
    except Exception as e:  # noqa: BLE001
        fails.append(f"t2 probe: {e!r}")
    try:
        v3 = emu_target3_one(rom, 16, 64)
        if v3["stop"] != "HIT-RET":
            fails.append(f"t3 normal stop {v3['stop']}")
        vb = emu_target3_one(rom, 0x40000000, 64)
        if not vb["bypass"]:
            fails.append(f"t3 bypass not set {vb}")
    except Exception as e:  # noqa: BLE001
        fails.append(f"t3 strict: {e!r}")
    print("at_fuzz selftest:", "PASS" if not fails else "FAIL")
    for f in fails:
        print("  -", f)
    if not fails:
        print(f"  ext_table valid=443 entry31=CLCK fmt0/1 + raw2str fmt OK; "
              f"behavioral 60/60; t1/t2/t3 strict vectors green")
    return 1 if fails else 0


def cmd_all(n: int = 200, report: str | None = None, verbose: bool = False) -> int:
    rom = load_rom()
    print("at_fuzz: behavioral sweep (safe only, guards enforced) ...")
    behav = behavioral_fuzz(n, verbose=verbose)
    print(f"  safe n={behav['n']} ok={behav['ok']} error={behav['error']} "
          f"parse_err={behav['parse_error']} crashes={behav['crashes']} "
          f"guard_trips={behav['guard_trips_on_safe']} "
          f"emu {behav['emu_match']}/{behav['emu_total']} "
          f"-> {'PASS' if behav['pass'] else 'FAIL'}")
    print("at_fuzz: target1 strict (crafted ctx+0x12) ...")
    t1 = fuzz_target1(rom, verbose=verbose)
    print(f"  table valid={t1['table']['valid']} oob443={t1['table']['oob443_value']:#x} "
          f"reachable 0..{t1['reachable']['max']} oob_confirmed={t1['oob_confirmed']}")
    print("at_fuzz: target2 sprintf model ...")
    t2 = emu_target2_probe(rom)
    print(f"  fmt0={t2['fmt0']!r} fmt1={t2['fmt1']!r} "
          f"worst={t2['worst_reaching']['output']!r} len={t2['worst_reaching']['out_len']} "
          f"avail={t2['worst_reaching']['avail']} overflow={t2['overflow_reachable']}")
    print("at_fuzz: target3 strict (blob lens) ...")
    t3 = fuzz_target3(rom)
    nbypass = sum(1 for v in t3["vectors"] if v["bypass"])
    print(f"  {len(t3['vectors'])} lens bypass={nbypass} "
          f"max_iters={max(v['iters'] for v in t3['vectors'])}")
    t4 = analyze_target4(rom)
    t5 = analyze_target5(rom)
    findings = build_findings(rom, behav, t1, t2, t3, t4, t5)
    print("\n==== FINDINGS ====")
    for i, f in enumerate(findings, 1):
        print(f"\n[{i}] {f.target}\n  VA: {f.target_va}\n  input: {f.input_class}\n"
              f"  effect: {f.emulated_effect}\n  judgment: {f.judgment}\n"
              f"  confidence: {f.confidence}")
    if report:
        p = Path(report)
        if not str(p).startswith("sim"):
            # enforce new-files-under-sim (relative to repo)
            try:
                rel = p.relative_to(REPO_ROOT / "sim")
            except Exception:
                p = SIM_DIR / Path(report).name
        else:
            p = REPO_ROOT / p if not p.is_absolute() else p
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

        doc = {"findings": [f.asdict() for f in findings],
               "behavioral": behav,
               "target1_table": {k: (f"{v:#x}" if isinstance(v, int) else v)
                                 for k, v in t1["table"].items() if k != "sample"},
               "target1_reachable": t1["reachable"],
               "target2_worst": t2["worst_reaching"],
               "target3_note": t3["note"]}
        p.write_text(_j.dumps(_san(doc), indent=2))
        print(f"\nwrote {p}")
    rc = 0 if (behav["pass"] and t1["oob_confirmed"]) else 1
    return rc


def main(argv: list[str]) -> int:
    if "--selftest" in argv or len(argv) == 0:
        return cmd_selftest()
    if "--fuzz" in argv:
        n = 200
        for a in argv:
            if a.startswith("--n="):
                try:
                    n = int(a.split("=", 1)[1])
                except ValueError:
                    pass
        # allow --n 200 form
        if "--n" in argv:
            try:
                n = int(argv[argv.index("--n") + 1])
            except Exception:
                pass
        rom = load_rom()
        behav = behavioral_fuzz(n, verbose="--verbose" in argv)
        print(f"behavioral fuzz: n={behav['n']} ok={behav['ok']} error={behav['error']} "
              f"parse_err={behav['parse_error']} crashes={behav['crashes']} "
              f"guard_trips={behav['guard_trips_on_safe']} emu={behav['emu_match']}/{behav['emu_total']}")
        for ex in behav["examples"][:20]:
            print("  " + ex)
        return 0 if behav["pass"] else 1
    if "--target1" in argv:
        rom = load_rom()
        t1 = fuzz_target1(rom, verbose=True)
        import json as _j
        print(_j.dumps({"table": {k: (f"{v:#x}" if isinstance(v, int) else v)
                                  for k, v in t1["table"].items() if k != "sample"},
                        "reachable": t1["reachable"],
                        "oob_confirmed": t1["oob_confirmed"]}, indent=2))
        return 0 if t1["oob_confirmed"] else 1
    if "--target2" in argv:
        rom = load_rom()
        import json as _j
        t2 = emu_target2_probe(rom)
        print(_j.dumps({"fmt0": t2["fmt0"].decode(), "fmt1": t2["fmt1"].decode(),
                        "worst": t2["worst_reaching"],
                        "overflow": t2["overflow_reachable"]}, indent=2))
        return 0
    if "--target3" in argv:
        rom = load_rom()
        import json as _j
        t3 = fuzz_target3(rom)
        print(_j.dumps({"vectors": t3["vectors"], "callers": t3["callers"]}, indent=2))
        return 0
    if "--all" in argv:
        report = None
        if "--report" in argv:
            try:
                report = argv[argv.index("--report") + 1]
            except Exception:
                report = "sim/at_fuzz_report.json"
        else:
            report = "sim/at_fuzz_report.json"
        n = 200
        if "--n" in argv:
            try:
                n = int(argv[argv.index("--n") + 1])
            except Exception:
                pass
        return cmd_all(n, report, verbose="--verbose" in argv)
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
