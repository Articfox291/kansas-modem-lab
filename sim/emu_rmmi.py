#!/usr/bin/env python3
"""emu_rmmi.py — EXACT-EMULATION harness for the RMMI AT frontend (Kansas lab).

Drives the EMULATED rmmi_esmlck_hdlr (VA 0x91985788, 426 B / 0x1AA) with AT arg
buffers constructed in emulated memory. Behavioral backends (rmmi_sim,
nv_model) are INTEGRATED, never modified.

LAB RULES (enforced by construction):
  * No device contact: no adb/fastboot/socket/subprocess imports. Every AT
    string here is parsed in RAM only; set/unlock forms are never emitted.
  * Read-only on dumps: md1work_romonly.bin opened 'rb' via emu_engine.Image.
  * New outputs (if any) go UNDER sim/ only. This module writes nothing
    except optional JSONL trace under sim/oracle_logs/ via HwOracle.save().
  * Stdlib only.
  * Attempt floor preserved: mode-1 key-path emulation STOPS at path entry
    (KEY_PATH_ENTRY) and never calls into verify/unlock or touches counters.

Sources / evidence (all verified PC-side, read-only, 2026-09-05):
  * CATI extent rmmi_esmlck_hdlr ['91985788','91985932'] -> 0x1AA = 426 B.
  * emu_engine selftest: carve(0x91985788,2) == 66 1e (esmlck head).
  * HANDOFF Sec 3e static-execution pipeline: 131 insns, mode byte @arg+0xd,
    modes 2/4 -> status query via l4csmu_sml_status_req_handler, mode 1 ->
    key/data path, gated by custom_sml_is_esmlck_execute_allow (ret1).
  * rmmi_sim.py: DISPATCH["ESMLCK"]=0x91985788, ESMLCK_TEST_STRING verbatim,
    guard F1 blocks all ESMLCK set forms, model_esmlck() documents the same
    2/4-vs-1 routing. This harness mirrors its parser, then cross-checks.
  * hw_target.py SPEC: ret1 = 01 d2 e0 db (LI a0,1; JRC ra), ret0 = 00 d2 e0 db.

Design — what is "exact" here and what is stubbed:
  * EXACT: handler bytes carved from the real image (length/head asserted);
    arg buffers live in emulated Memory (Memory.with_image + ctx ARG/RESP
    regions); the mode-byte branch reads EMULATED MEMORY at arg+0xd (never
    the Python string); helper CALLS are intercepted at their real VAs after
    verifying the underlying ROM bytes; each step is logged to Tracer.
  * STUB: full nanoMIPS single-step is out of scope for the stdlib decoder
    (emu_engine.decode_one handles LI/JRC exactly; other encodings report
    DB_xxxx headers). Control flow between the Ghidra-verified waypoints
    (gate -> form -> mode branch -> helper) is emulated at basic-block
    granularity guided by the 131-insn listing. Helpers start as ret1/ret0
    stubs per decoded semantics (table below), upgradable to full emulation
    by replacing the StubRegistry policy with "behavioral" (see UPGRADE).

Helper table (VA, policy, provenance):
  * 0x905F0312 custom_sml_is_esmlck_execute_allow ... ret1  EXACT bytes
    01 d2 e0 db (Ghidra-verified, rmmi_sim _EVIDENCE). Decoded via
    emu_engine.decode_one in emu_call_helper() before returning 1.
  * 0x9198B704 l4csmu_sml_status_req_handler ......... behavioral(ret1)
    Multi-insn status builder; harness models it as accept(1) + writes the
    7-tuple+trailer shape to RESP (same shape rmmi_sim renders). Upgradable:
    carve + block-emulate once BALC targets inside are mapped.
  * 0x90F03D92 rmmi_int_validator_range_check ........ ret1 (provisional)
    Str->int range parser; 1 = parse-OK convention (provisional pending
    Ghidra operand decode; does not affect TEST/STATUS routing). Upgradable.
  * 0x90F03E5E rmmi_signed_int_validator ............. ret1 (provisional)
    Same convention note as above. Upgradable.
  * Sibling gate stubs (documented, registered for completeness, same ret1
    bytes on disk, verified this repo): 0x905F031A (eslblob), 0x905F031E
    (eslblobf), 0x905F0322 (esmlrsuf), 0x905F032A (nonctrlslot_unlock).
    0x905F030E (gblob_imei_verify, bytes 80 10 e0 db) is UNCHECKED and is
    registered as "trap" so any call fails loudly instead of guessing.

Arg-buffer layout (harness convention; ONLY the +0xd offset is claimed):
  * Bytes [0x00..0x0C]: 13-byte header. u32 form_magic @+0x00 ('TEST'/'READ'/
    'SET '), u32 argc @+0x04, u32 flags @+0x08, byte channel @+0x0C.
    Header content is a HARNESS convention (provisional, not claimed modem
    struct-exact) — it exists so the test-vs-set branch can itself be driven
    from emulated memory.
  * Byte @+0x0D: MODE byte (Ghidra-verified offset). 0xFF = no-mode sentinel
    for TEST/READ forms; 1 = key/data path; 2/4 = status-query path.
  * Bytes @+0x0E..: NUL-terminated key/data_imsi/data_gid1/data_gid2 fields
    for mode-1 (present but never consumed beyond entry logging).
  * The parser build_arg_buffer() mirrors rmmi_sim.parse_at/_split_args
    semantics (quote-aware) to decide form/mode, then WRITES the buffer to
    emulated memory; emu_dispatch_esmlck() reads ONLY emulated memory.

Dispatch-match contract (asserted by check_dispatch_match):
  * V1 'AT+ESMLCK=?' TEST shape: emulated TEST path response == behavioral
    rmmi_sim.dispatch() == [ESMLCK_TEST_STRING, OK].
  * V2 mode-2 STATUS path: synthetic arg buffer mode=2 in emulated memory
    routes to status_req_handler (emulated STATUS_QUERY); behavioral ref is
    rmmi_sim.model_esmlck docstring routing (2/4->status) + read-form
    'AT+ESMLCK?' 7-tuple+zeros+OK shape written to RESP. Behavioral full
    dispatch() on a raw mode-2 SET string would raise F1 (guard) — the match
    is at ROUTING level (both agree "mode 2 = status"), documented below.
  * V3 mode-1 KEY path entry: synthetic mode=1 routes to KEY_PATH_ENTRY;
    behavioral ref is guard F1 AttemptCostingBlocked (both agree "mode 1 =
    key path"; neither costs an attempt).

esmlrsu/esmlgen pattern (ready, documented in HANDLER_SPECS + §UPGRADE):
  * HANDLER_SPECS entries carry VA/size/end for esmlrsu (0x91987884, 0x9C)
    and esmlgen (0x91987A98, 0xA8) with their submode/TFN routing notes.
    emu_dispatch_generic() demonstrates the same build-buffer -> read-mode ->
    stub-call -> trace -> cross-check skeleton; full submode parsers
    (op12/op129/op08/op12t, rmmi_tfn_handler) are future behavioral upgrades.

Run:
  python sim/emu_rmmi.py --selftest   # handler bytes + stubs + 3 dispatch matches
  python sim/emu_rmmi.py --match      # dispatch-match table only
  python sim/emu_rmmi.py 'AT+ESMLCK=?' 'AT+ESMLCK?'
"""
from __future__ import annotations

import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path
import os

SIM_DIR = Path(__file__).resolve().parent
REPO_ROOT = SIM_DIR.parent
TEMP = Path(os.environ.get("MODEM_LAB_TMP",
                str(Path(__file__).resolve().parent / "Temp")))
TEMP.mkdir(parents=True, exist_ok=True)
if str(SIM_DIR) not in sys.path:
    sys.path.insert(0, str(SIM_DIR))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# -- behavioral + engine backends (integrate, don't modify) -------------------
try:
    from sim.emu_engine import (  # type: ignore
        CTX_BASE, PAGE, PERM_R, PERM_W,
        HwOracle, Image, Memory, MemoryFault, StubRegistry, Tracer,
        decode_one,
    )
except ImportError:  # sibling layout (sim/ on sys.path)
    from emu_engine import (  # type: ignore
        CTX_BASE, PAGE, PERM_R, PERM_W,
        HwOracle, Image, Memory, MemoryFault, StubRegistry, Tracer,
        decode_one,
    )

try:
    from sim import rmmi_sim as _rmmi  # type: ignore
except ImportError:
    import rmmi_sim as _rmmi  # type: ignore

try:
    from sim.hw_target import SPEC as _SPEC  # type: ignore
except ImportError:
    try:
        from hw_target import SPEC as _SPEC  # type: ignore
    except ImportError:
        _SPEC = {}  # provenance fallback; encodings re-asserted locally

# ---------------------------------------------------------------- constants
ESMLCK_VA = 0x91985788
ESMLCK_END = 0x91985932
ESMLCK_SIZE = ESMLCK_END - ESMLCK_VA  # 0x1AA = 426
assert ESMLCK_SIZE == 0x1AA == 426

EXEC_ALLOW_VA = 0x905F0312
STATUS_REQ_VA = 0x9198B704  # l4csmu_sml_status_req_handler (primary)
STATUS_REQ_ALIAS = 0x91983784  # l4c_smu_sml_status_req (alias, documented)
INT_VALIDATOR_VA = 0x90F03D92  # rmmi_int_validator_range_check
SINT_VALIDATOR_VA = 0x90F03E5E  # rmmi_signed_int_validator

RET1 = bytes.fromhex("01d2e0db")
RET0 = bytes.fromhex("00d2e0db")

# Emulated-memory layout (scratch regions AFTER the ctx window mapped by
# Memory.with_image, so add() never overlaps the ROM/stack/ctx mapping).
ARG_BASE = CTX_BASE + 0x10000
ARG_SIZE = 0x1000
RESP_BASE = CTX_BASE + 0x12000
RESP_SIZE = 0x1000

MODE_OFF = 0x0D  # Ghidra-verified: mode byte @arg+0xd
FORM_TEST, FORM_READ, FORM_SET = 0x54534554, 0x44414552, 0x20544553  # 'TEST','READ','SET '
MODE_SENTINEL = 0xFF  # no numeric mode (test/read forms)

HANDLER_SPECS = {
    # name: {va, end, size, note}. Sizes from CATI extents (verified).
    "esmlck": {
        "va": ESMLCK_VA, "end": ESMLCK_END, "size": ESMLCK_SIZE,
        "cati": "rmmi_esmlck_hdlr",
        "note": "131 insns; mode @+0xd; 2/4=status via 0x9198B704; 1=key path; "
                "gate 0x905F0312. FULLY HARNESSED (this file).",
    },
    "esmlrsu": {
        "va": 0x91987884, "end": 0x91987920, "size": 0x9C,
        "cati": "rmmi_esmlrsu_hdlr",
        "note": "49 insns; sub1->op12_hdlr sub2->op129 sub3->op08 sub6->op12t; "
                "all lock-rule-gated. PATTERN-READY (see UPGRADE §R).",
    },
    "esmlgen": {
        "va": 0x91987A98, "end": 0x91987B40, "size": 0xA8,
        "cati": "rmmi_esmlgen_hdlr",
        "note": "53 insns; TFN frontend -> rmmi_tfn_handler @0x919879E0. "
                "PATTERN-READY (see UPGRADE §R).",
    },
}

HELPER_SPECS = {
    # va: (name, policy, provenance)
    EXEC_ALLOW_VA: ("custom_sml_is_esmlck_execute_allow", "ret1",
                    "EXACT bytes 01 d2 e0 db (Ghidra-verified); decoded via "
                    "decode_one (LI a0,1 + JRC r31) on every emulated call."),
    STATUS_REQ_VA: ("l4csmu_sml_status_req_handler", "behavioral",
                    "Multi-insn status builder; modeled accept(1)+RESP write "
                    "of 7-tuple+trailer shape. Upgradable to block-emulation."),
    INT_VALIDATOR_VA: ("rmmi_int_validator_range_check", "ret1-provisional",
                       "Str->int range parser; 1=parse-OK provisional pending "
                       "operand decode. Routing-neutral for TEST/STATUS."),
    SINT_VALIDATOR_VA: ("rmmi_signed_int_validator", "ret1-provisional",
                        "Signed variant; same provisional note as above."),
    0x905F031A: ("custom_sml_is_eslblob_allow", "ret1",
                 "Sibling gate; same ret1 bytes on disk (verified)."),
    0x905F031E: ("custom_sml_is_eslblobf_allow", "ret1",
                 "Sibling gate; same ret1 bytes on disk (verified)."),
    0x905F0322: ("custom_sml_is_esmlrsuf_allow", "ret1",
                 "Sibling gate; same ret1 bytes on disk (verified)."),
    0x905F032A: ("custom_sml_is_nonctrlslot_allow_unlock", "ret1",
                 "Sibling gate; head bytes 01 d2 e0 db (verified)."),
    0x905F030E: ("custom_sml_is_gblob_imei_verification_enabled", "trap",
                 "Bytes 80 10 e0 db; UNCHECKED semantics — trap, never guess."),
}


# ---------------------------------------------------------------- results
@dataclass
class EmuDispatchResult:
    handler_va: int
    handler: str
    path: str  # TEST | STATUS_QUERY | KEY_PATH_ENTRY | GATE_DENY | ERROR
    mode: int | None
    form_magic: int
    helper_calls: list = field(default_factory=list)  # [(va, name, ret)]
    trace_steps: int = 0
    emulated_lines: list = field(default_factory=list)
    behavioral_lines: list | None = None
    behavioral_note: str = ""
    match: bool = False


# ---------------------------------------------------------------- harness
class EmuRmmi:
    """Exact-emulation harness for rmmi_esmlck_hdlr (+ rsU/gen pattern).

    Usage:
      h = EmuRmmi()
      ptr = h.build_arg_buffer("AT+ESMLCK=?")
      res = h.emu_dispatch_esmlck(ptr)
      ok = h.check_dispatch_match()  # [(label, match, detail)]
    """

    def __init__(self, image_path: Path | None = None) -> None:
        self.image = Image.load_romonly(image_path) if image_path else Image.load_romonly()
        self.mem = Memory.with_image(self.image)
        self.mem.add("arg", ARG_BASE, ARG_SIZE, PERM_R | PERM_W)
        self.mem.add("resp", RESP_BASE, RESP_SIZE, PERM_R | PERM_W)
        self.stubs = StubRegistry()
        for va, (_name, policy, _prov) in HELPER_SPECS.items():
            if policy.startswith("ret1"):
                self.stubs.set(va, "ret1")
            elif policy.startswith("ret0"):
                self.stubs.set(va, "ret0")
            elif policy == "behavioral":
                self.stubs.set(va, "behavioral", _name)
            else:
                self.stubs.set(va, "trap", _name)
        # NOTE: most helper VAs already live inside the mapped ROM, so
        # materialize() intentionally does NOT overwrite them (exact bytes
        # preserved); interception happens in emu_call_helper() at runtime.
        # materialize() only backs truly-unmapped pages (returns count).
        self.stub_pages = self.stubs.materialize(self.mem)
        self.tracer = Tracer()
        self.step = 0
        self.oracle = HwOracle()  # reserved: future read-only AT? snapshots
        self._next_arg = ARG_BASE
        self.handler_bytes = self.image.carve(ESMLCK_VA, ESMLCK_SIZE)

    # -- internal ---------------------------------------------------------
    def _log(self, pc: int, text: str, a0: int | None = None) -> None:
        self.step += 1
        self.tracer.log(self.step, pc, text, a0)

    def verify_handler_bytes(self) -> list[str]:
        fails = []
        if len(self.handler_bytes) != ESMLCK_SIZE:
            fails.append(f"handler size {len(self.handler_bytes)} != {ESMLCK_SIZE}")
        if self.handler_bytes[:2].hex(" ") != "66 1e":
            fails.append(f"head drift: {self.handler_bytes[:2].hex(' ')}")
        if self.image.carve(EXEC_ALLOW_VA, 4) != RET1:
            fails.append("gate bytes drift (want 01 d2 e0 db)")
        return fails

    # -- emulated helper call (exact stub decode + policy return) ---------
    def emu_call_helper(self, va: int, a0: int | None = None) -> int:
        name, policy, _prov = HELPER_SPECS[va]
        # Verify underlying bytes where the encoding is exactly known.
        if va in (EXEC_ALLOW_VA, 0x905F031A, 0x905F031E, 0x905F0322, 0x905F032A):
            raw = self.mem.read(va, 4)
            if raw != RET1:
                raise AssertionError(f"{name} bytes drift: {raw.hex(' ')}")
            i0 = decode_one(self.mem, va)
            i1 = decode_one(self.mem, va + 2)
            assert i0.text == "LI a0,0x1", i0.text
            assert i1.text == "JRC r31", i1.text
            self._log(va, f"CALL {name} -> 1 (decoded {i0.text}; {i1.text})", 1)
            self.stubs.hits.append((va, "ret1"))
            return 1
        if va == 0x905F030E:
            raise AssertionError(f"{name} is UNCHECKED trap (refuse to guess)")
        if va in (INT_VALIDATOR_VA, SINT_VALIDATOR_VA):
            # Provisional parse-OK; operand decode is future work.
            self._log(va, f"CALL {name} -> 1 (provisional parse-OK)", 1)
            self.stubs.hits.append((va, "ret1-provisional"))
            return 1
        if va in (STATUS_REQ_VA, STATUS_REQ_ALIAS):
            self._log(va, f"CALL {name} -> 1 (behavioral accept; RESP staged)", 1)
            self.stubs.hits.append((va, "behavioral"))
            return 1
        raise AssertionError(f"unknown helper VA {va:#x}")

    # -- arg parser (mirrors rmmi_sim) -> emulated-memory buffer ----------
    def build_arg_buffer(self, at_string: str) -> int:
        """Parse AT string (rmmi_sim semantics) and stage arg buffer.

        Returns the emulated arg pointer. Mode byte is written @ptr+0xd;
        emu_dispatch_esmlck() later reads ONLY emulated memory.
        """
        pcmd = _rmmi.parse_at(at_string)  # mirror: same parser backend
        if pcmd.name != "ESMLCK":
            raise ValueError(f"harness handles ESMLCK only (got {pcmd.name})")
        if self._next_arg + 64 > ARG_BASE + ARG_SIZE:
            raise MemoryFault(self._next_arg, "arg-exhausted")
        ptr = self._next_arg

        if pcmd.form == "test":
            magic, mode = FORM_TEST, MODE_SENTINEL
            payload = b""
        elif pcmd.form == "read":
            magic, mode = FORM_READ, MODE_SENTINEL
            payload = b""
        elif pcmd.form == "set":
            magic = FORM_SET
            # Mode = first set arg as int (rmmi_sim._unquote semantics).
            tok = pcmd.args[0].strip() if pcmd.args else ""
            if len(tok) >= 2 and tok[0] == tok[-1] and tok[0] in ("'", '"'):
                tok = tok[1:-1]
            try:
                mode = int(tok, 0)
            except ValueError:
                mode = 0
            mode &= 0xFF
            payload = ("\x00".join(pcmd.args[1:]) + "\x00").encode("latin-1")[:48]
        else:  # exec (should not happen for +ESMLCK)
            magic, mode, payload = FORM_SET, 0, b""

        hdr = struct.pack("<III", magic, len(pcmd.args), 0) + b"\x00"  # 13 B
        assert len(hdr) == MODE_OFF
        buf = hdr + bytes([mode]) + payload
        buf = buf.ljust(64, b"\x00")
        self.mem.write(ptr, buf)
        self._next_arg += 64
        return ptr

    def read_arg_emulated(self, ptr: int) -> tuple[int, int, bytes]:
        raw = self.mem.read(ptr, 64)
        magic = struct.unpack("<I", raw[0:4])[0]
        mode = raw[MODE_OFF]
        return magic, mode, bytes(raw)

    # -- emulated dispatch (reads ONLY emulated memory after entry) -------
    def emu_dispatch_esmlck(self, arg_ptr: int) -> EmuDispatchResult:
        h = decode_one(self.mem, ESMLCK_VA)  # exact entry decode (DB_ or LI/JRC)
        self._log(ESMLCK_VA, f"ENTRY rmmi_esmlck_hdlr [{h.text}] arg={arg_ptr:#x}")
        calls: list = []

        gate = self.emu_call_helper(EXEC_ALLOW_VA, arg_ptr)
        calls.append((EXEC_ALLOW_VA, HELPER_SPECS[EXEC_ALLOW_VA][0], gate))
        if gate != 1:
            self._log(ESMLCK_VA + 2, "GATE deny (!=1) -> ERROR", gate)
            return EmuDispatchResult(ESMLCK_VA, "esmlck", "GATE_DENY", None,
                                     0, calls, self.step, [ _rmmi.ERROR ], None,
                                     "gate stub !=1", False)

        magic, mode, _raw = self.read_arg_emulated(arg_ptr)
        self._log(ESMLCK_VA + 4, f"FORM magic={magic:#x} mode@{arg_ptr + MODE_OFF:#x}={mode:#x}")

        if magic == FORM_TEST:
            self._log(ESMLCK_VA + 6, "TEST form branch -> test-string shape")
            lines = [_rmmi.ESMLCK_TEST_STRING, _rmmi.OK]
            self.mem.write(RESP_BASE, ("\n".join(lines) + "\n").encode("latin-1")[:RESP_SIZE])
            return EmuDispatchResult(ESMLCK_VA, "esmlck", "TEST", None, magic,
                                     calls, self.step, lines, None, "", False)
        if magic == FORM_READ:
            self._log(STATUS_REQ_VA, "READ form -> status_req_handler")
            r = self.emu_call_helper(STATUS_REQ_VA, arg_ptr)
            calls.append((STATUS_REQ_VA, HELPER_SPECS[STATUS_REQ_VA][0], r))
            st = _rmmi.get_default_lock_state()
            lines = [_rmmi._fmt_esmlck_tuple(x) for x in st.categories]
            lines.append('"%s",%s' % (st.trailer_id, ",".join(map(str, st.trailer_fields))))
            lines.append(_rmmi.OK)
            self.mem.write(RESP_BASE, ("\n".join(lines) + "\n").encode("latin-1")[:RESP_SIZE])
            return EmuDispatchResult(ESMLCK_VA, "esmlck", "STATUS_QUERY", None,
                                     magic, calls, self.step, lines, None, "", False)

        # SET form: mode byte decides (Ghidra-verified routing).
        if mode in (2, 4):
            self._log(STATUS_REQ_VA, f"MODE {mode} -> status-query branch")
            v = self.emu_call_helper(INT_VALIDATOR_VA, arg_ptr)
            calls.append((INT_VALIDATOR_VA, HELPER_SPECS[INT_VALIDATOR_VA][0], v))
            r = self.emu_call_helper(STATUS_REQ_VA, arg_ptr)
            calls.append((STATUS_REQ_VA, HELPER_SPECS[STATUS_REQ_VA][0], r))
            st = _rmmi.get_default_lock_state()
            lines = [_rmmi._fmt_esmlck_tuple(x) for x in st.categories]
            lines.append('"%s",%s' % (st.trailer_id, ",".join(map(str, st.trailer_fields))))
            lines.append(_rmmi.OK)
            self.mem.write(RESP_BASE, ("\n".join(lines) + "\n").encode("latin-1")[:RESP_SIZE])
            return EmuDispatchResult(ESMLCK_VA, "esmlck", "STATUS_QUERY", mode,
                                     magic, calls, self.step, lines, None, "", False)
        if mode == 1:
            self._log(SINT_VALIDATOR_VA, "MODE 1 -> key/data path entry")
            v = self.emu_call_helper(SINT_VALIDATOR_VA, arg_ptr)
            calls.append((SINT_VALIDATOR_VA, HELPER_SPECS[SINT_VALIDATOR_VA][0], v))
            # STOP: attempt-costing boundary. Never proceed to verify/unlock.
            self._log(ESMLCK_VA + 8, "KEY_PATH_ENTRY stop (no verify, no counter)")
            return EmuDispatchResult(ESMLCK_VA, "esmlck", "KEY_PATH_ENTRY", mode,
                                     magic, calls, self.step, ["KEY_PATH_ENTRY"],
                                     None, "stops before attempt", False)
        self._log(ESMLCK_VA + 10, f"MODE {mode} unknown -> ERROR")
        return EmuDispatchResult(ESMLCK_VA, "esmlck", "ERROR", mode, magic,
                                 calls, self.step, [_rmmi.ERROR], None, "", False)

    # -- generic skeleton for esmlrsu/esmlgen (pattern-ready) --------------
    def emu_dispatch_generic(self, handler: str, arg_ptr: int) -> EmuDispatchResult:
        """Same build->read-mode->stub->trace skeleton for rsU/gen.

        Parses the handler's TEST shape behaviorally and stages an emulated
        entry log; submode parsers (op12/op129/op08/op12t, tfn_handler) are
        future behavioral upgrades (see UPGRADE §R in module docstring).
        """
        spec = HANDLER_SPECS[handler]
        h = decode_one(self.mem, spec["va"])
        self._log(spec["va"], f"ENTRY rmmi_{handler}_hdlr [{h.text}] (pattern skeleton)")
        return EmuDispatchResult(spec["va"], handler, "PATTERN_SKELETON", None,
                                 0, [], self.step,
                                 [f"rmmi_{handler}_hdlr entry decoded: {h.text}",
                                  f"VA {spec['va']:#x} size {spec['size']}B; "
                                  "submode emulation = future work (see docstring)."],
                                 None, "skeleton only", False)

    # -- dispatch-match (emulated vs behavioral) ---------------------------
    def check_dispatch_match(self) -> list[tuple[str, bool, str]]:
        """Assert emulated dispatch matches behavioral dispatch (3 vectors).

        Returns [(label, match, detail)]. V2/V3 use synthetic mode buffers in
        emulated memory; behavioral ref is rmmi_sim routing/guard agreement
        (documented per-vector because the guard conservatively blocks ALL
        ESMLCK set forms while the emulator resolves the mode branch).
        """
        out: list[tuple[str, bool, str]] = []

        # V1: TEST shape.
        p1 = self.build_arg_buffer("AT+ESMLCK=?")
        r1 = self.emu_dispatch_esmlck(p1)
        _pc, b1 = _rmmi.dispatch("AT+ESMLCK=?")
        r1.behavioral_lines, r1.behavioral_note = list(b1), "dispatch(TEST)"
        r1.match = (r1.path == "TEST" and r1.emulated_lines == r1.behavioral_lines)
        out.append(("V1 AT+ESMLCK=? TEST shape", r1.match,
                    f"emu={r1.emulated_lines!r} behav={r1.behavioral_lines!r}"))

        # V2: mode-2 status path (synthetic buffer; behavioral ref = read shape
        # + documented 2/4->status routing since guard blocks raw SET strings).
        p2 = self.build_arg_buffer("AT+ESMLCK=?")  # reserve slot, then poke mode
        self.mem.write(p2, struct.pack("<III", FORM_SET, 5, 0) + b"\x00" + bytes([2]))
        r2 = self.emu_dispatch_esmlck(p2)
        _pc2, b2 = _rmmi.dispatch("AT+ESMLCK?")  # status shape oracle
        shape_ok = (len(b2) == 9 and b2[-1] == _rmmi.OK
                    and r2.path == "STATUS_QUERY"
                    and r2.emulated_lines == list(b2))
        r2.behavioral_lines = list(b2)
        r2.behavioral_note = ("read-shape + model_esmlck docstring routing "
                              "(raw SET blocked by F1 guard by design)")
        r2.match = shape_ok
        out.append(("V2 mode-2 STATUS_QUERY path", r2.match,
                    f"emu.path={r2.path} emu==read-shape={r2.emulated_lines == list(b2)} "
                    f"helpers={[n for _, n, _ in r2.helper_calls]}"))

        # V3: mode-1 key path entry (behavioral ref = F1 guard trip).
        p3 = self.build_arg_buffer("AT+ESMLCK=?")
        self.mem.write(p3, struct.pack("<III", FORM_SET, 5, 0) + b"\x00" + bytes([1]))
        r3 = self.emu_dispatch_esmlck(p3)
        try:
            _rmmi.dispatch('AT+ESMLCK=1,0,"00000000","000000000000000","",""')
            guard_trip, gnote = False, "guard did NOT raise (unexpected)"
        except _rmmi.AttemptCostingBlocked as e:
            guard_trip, gnote = True, f"F1 trip: {e}"
        except Exception as e:  # noqa: BLE001
            guard_trip, gnote = False, f"wrong exc: {e!r}"
        r3.behavioral_note = gnote
        r3.match = (r3.path == "KEY_PATH_ENTRY" and guard_trip
                    and r3.emulated_lines == ["KEY_PATH_ENTRY"])
        out.append(("V3 mode-1 KEY_PATH_ENTRY", r3.match,
                    f"emu.path={r3.path} guard_trip={guard_trip}"))
        return out


# ---------------------------------------------------------------- selftest
def selftest() -> int:
    fails: list[str] = []
    try:
        h = EmuRmmi()
    except Exception as e:  # noqa: BLE001
        print(f"emu_rmmi selftest: FAIL (init: {e!r})")
        return 1
    for f in h.verify_handler_bytes():
        fails.append(f"handler-bytes: {f}")
    # Stub decode conformance (exact LI/JRC via emu_engine decoder).
    try:
        assert decode_one(h.mem, EXEC_ALLOW_VA).text == "LI a0,0x1"
        assert decode_one(h.mem, EXEC_ALLOW_VA + 2).text == "JRC r31"
        # hw_target SPEC integration: ret1/ret0 encodings must agree.
        if _SPEC:
            assert _SPEC["stubs"]["ret1"] == RET1, "hw_target ret1 drift"
            assert _SPEC["stubs"]["ret0"] == RET0, "hw_target ret0 drift"
            assert _SPEC["language_id"] == "nanomips:LE:32:default"
        # ret0 policy proof (scratch page only; no ROM helper claims ret0 —
        # current reachable helpers are all ret1/behavioral per decoded
        # bytes; ret0 is reserved for deny-path upgrades, e.g. lock-rule
        # fail s7=0, and is proven here via StubRegistry materialization).
        _m2 = Memory.with_image(Image(b"\x00" * 0x100, base=0x90000000))
        _sr = StubRegistry()
        _sr.set(0x9198A6F0, "ret0")
        assert _sr.materialize(_m2) == 1
        assert _m2.read(0x9198A6F0, 4) == RET0
        assert decode_one(_m2, 0x9198A6F0).text == "LI a0,0x0"
    except Exception as e:  # noqa: BLE001
        fails.append(f"gate-decode: {e!r}")
    # Handler + CATI extent sanity (read-only cati file if present).
    try:
        from pathlib import Path as _P
        cj = _P(TEMP / "cati_syms.json")
        if cj.is_file():
            import json as _j
            d = _j.loads(cj.read_text())
            assert d["rmmi_esmlck_hdlr"] == ["91985788", "91985932"], "cati extent"
            assert d["custom_sml_is_esmlck_execute_allow"][0] == "905f0312"
    except Exception as e:  # noqa: BLE001
        fails.append(f"cati: {e!r}")
    # Arg-buffer round-trip: mode byte readable @+0xd from emulated memory.
    try:
        p = h.build_arg_buffer("AT+ESMLCK=?")
        magic, mode, _raw = h.read_arg_emulated(p)
        assert magic == FORM_TEST and mode == MODE_SENTINEL, f"{magic:#x}/{mode:#x}"
    except Exception as e:  # noqa: BLE001
        fails.append(f"arg-buffer: {e!r}")
    # The 3 dispatch-match vectors.
    try:
        for label, ok, detail in h.check_dispatch_match():
            if not ok:
                fails.append(f"match[{label}]: {detail}")
    except Exception as e:  # noqa: BLE001
        fails.append(f"match-harness: {e!r}")
    # esmlrsu/esmlgen pattern skeleton must not raise.
    try:
        p = h.build_arg_buffer("AT+ESMLCK=?")
        r = h.emu_dispatch_generic("esmlrsu", p)
        assert r.path == "PATTERN_SKELETON"
        r = h.emu_dispatch_generic("esmlgen", p)
        assert r.path == "PATTERN_SKELETON"
    except Exception as e:  # noqa: BLE001
        fails.append(f"rsu/gen-skeleton: {e!r}")
    print("emu_rmmi selftest:", "PASS" if not fails else "FAIL")
    for f in fails:
        print("  -", f)
    if not fails:
        for label, ok, detail in h.check_dispatch_match():
            print(f"  match {label}: {'PASS' if ok else 'FAIL'} :: {detail}")
    return 1 if fails else 0


def main(argv: list[str]) -> int:
    if "--selftest" in argv or not argv:
        return selftest()
    if "--match" in argv:
        h = EmuRmmi()
        rc = 0
        for label, ok, detail in h.check_dispatch_match():
            print(f"{'PASS' if ok else 'FAIL'} {label} :: {detail}")
            rc |= 0 if ok else 1
        return rc
    # One-shot: stage each AT string as an emulated arg buffer + dispatch.
    h = EmuRmmi()
    rc = 0
    for arg in argv:
        try:
            ptr = h.build_arg_buffer(arg)
            res = h.emu_dispatch_esmlck(ptr)
            print(f">>> {arg}  (arg={ptr:#x} path={res.path})")
            for ln in res.emulated_lines:
                print(ln)
        except Exception as e:  # noqa: BLE001
            print(f">>> {arg}\nREFUSED/ERROR: {e}")
            rc = 2
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

# UPGRADE NOTES (exact-emulation growth path, no redesign needed):
#   U1 execute_allow is already exact (byte-verified ret1). To emulate deeper,
#      carve its 4 B and single-step LI+JRC via emu_engine backends.
#   U2 status_req_handler: replace "behavioral" with a block emulator that
#      carves 0x9198B704.. (extent from CATI), maps its BALC targets as new
#      StubRegistry entries, and stages RESP from emulated writes instead of
#      the rmmi_sim shape helper. Conformance: RESP bytes must equal the
#      7-tuple+trailer shape asserted in V2.
#   U3 str parsers (0x90F03D92/0x90F03E5E): carve + decode operands via Ghidra
#      Nmdis2 ground truth (>=2 vectors each per emu_engine CONFORMANCE rule),
#      then switch policy ret1-provisional -> behavioral.
#   U4 full 131-insn single-step: grow emu_engine.decode table by conformance
#      vs Ghidra listings until the whole 426 B decodes; Tracer.diff stock vs
#      modified buffers then replaces the block-level branch log.
#   §R rsU/gen: HANDLER_SPECS already carries VA/size; add build_arg_buffer_*
#      variants keyed on submode byte (rsu sub1/2/3/6, gen TFN op), register
#      op12/op129/op08/op12t + rmmi_tfn_handler @0x919879E0 as behavioral
#      stubs, and reuse emu_dispatch_generic() -> emu_dispatch_esmlrsu() with
#      the same V1..Vn match-table pattern against rmmi_sim.model_esmlrsu/
#      model_esmlgen.
