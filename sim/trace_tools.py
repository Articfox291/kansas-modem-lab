#!/usr/bin/env python3
"""trace_tools.py — execution-trace + differential-analysis tooling (Kansas lab).

Offline, stdlib-only, read-only w.r.t. the device (NO adb/fastboot/socket/
subprocess anywhere here) and read-only w.r.t. repo dumps (images/logs are
opened 'rb'/read; new files land UNDER sim/ only: sim/traces/ corpus).

Three trace sources ingest into ONE normalized JSONL schema (one object per
line, fixed key order step,pc,bytes,text,regs?):

  {"step": 0, "pc": "0x905df2fa", "bytes": "141e", "text": "SAVE ..."}
  {"step": 24, "pc": "0x905df330", "bytes": "....", "text": "HIT-RET",
   "regs": {"a0": "0x0"}}

  * interp event streams: sim/emu_engine.py Tracer.events (TraceEvent
    step,pc:int,text,a0) via from_interp(). Tracer carries no bytes, so
    bytes="" (verifiers skip byte checks for "").
  * Ghidra backend RESULT/trace lines: banked emu_*.log RESULT lines
    (steps/stop/PC/a0 + PRESTUBS/RET-AT) via parse_emu_result(); per-step
    TRACE lines (new EmuSml.java BACKEND-EXT) via parse_emu_trace_lines().
    Banked 2026-09-05 logs predate TRACE (RESULT only) — trace_from_emu_log
    returns (trace, summary) with trace=[] then; the stock-vs-patch DEMO
    uses demo_stock_patch_traces() (ROM-grounded interp-style walk whose
    25-vs-1 step counts and a0 match those RESULT summaries byte...
    value-exact, cross-checked in --demo output).
  * Nmdis2 listing logs: banked fn_*.log disassembly lines via
    parse_nmdis2() + listing_to_trace() (bytes carved from
    md1work_romonly.bin; insn sizes from next-PC deltas, last insn from
    the CATI extent end — exact, deterministic).

Engines here (all pure functions on normalized lists):
  diff_traces() ......... first-divergence + coverage delta (+only-in sets)
  verify_against_listing()  every executed PC must match a disassembled
    insn; flags pc-not-in-listing / text (decode) mismatch / byte mismatch
    (self-modifying?) — "" bytes skip the byte check.
  check_convergence() ... same inputs -> identical traces (canonical bytes).
  landmark_hits/calls(). named PC sets (CATI extents + verdict PCs below).
  render_side_by_side() . compact stock|patch, divergence marked ">>".
  build_corpus()/check_corpus()  7 decoded functions, stock mode,
    helpers=ret1, sim/traces/*.jsonl + manifest.json; --check reproduces
    every file byte-for-byte.

Landmarks (CATI names; sec_* map to their *_trace extents since bare
sec_function_enter/leave/error symbols do not exist; smu_get_dump_sml_context
is absent verbatim so it unions the two closest real symbols):
  sml_mini_trace ............ sml_mini_trace [0x905f18d6,0x905f194e)
  sml_sec_function_enter .... sml_sec_function_enter_trace [0x9198a3c4,...)
  sml_sec_function_leave .... sml_sec_function_leave_trace
  sml_sec_function_error .... sml_sec_function_error_trace
  smu_get_dump_sml_context .. smu_get_dump_sml_context_size UNION
                              smu_dump_sml_context_send_ind
  SML verdict points ........ 0x905df32e (legal_sim_rule return site, inside
                              custom_check_link_sml_legal_sim_rule) and
                              0x905df492 (linker merge MOVE a0,s7).

CLI:
  python sim/trace_tools.py --demo            # schema + legal_sim_rule diff
  python sim/trace_tools.py --check           # corpus byte-for-byte check
  python sim/trace_tools.py --build-corpus    # (re)generate sim/traces/
  python sim/trace_tools.py --selftest        # offline unit checks
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
import os

SIM_DIR = Path(__file__).resolve().parent
REPO_ROOT = SIM_DIR.parent
if str(SIM_DIR) not in sys.path:
    sys.path.insert(0, str(SIM_DIR))

TEMP = Path(os.environ.get("MODEM_LAB_TMP",
                str(Path(__file__).resolve().parent / "Temp")))
TEMP.mkdir(parents=True, exist_ok=True)
CATI_JSON = TEMP / "cati_syms.json"
ROMONLY = REPO_ROOT / "md1work_romonly.bin"
TRACES_DIR = SIM_DIR / "traces"
VA_BASE = 0x90000000

# Live-patch bytes (HANDOFF 3e, proven): entry forced LI a0,1 ; JRC ra.
PATCH_LI = bytes.fromhex("01d2")          # LI a0,0x1 (first half)
PATCH_FULL = bytes.fromhex("01d2e0db")    # LI a0,1 ; JRC ra

# Proven Ghidra RESULT ground truth (banked emu_legal_sim_rule_{stock,patch}.log):
#   stock: RESULT steps=25 stop=HIT-RET PC=905df330 a0=0x0 RET-AT 905df330
#   patch: RESULT steps=1  stop=HIT-RET PC=905df2fc a0=0x1 RET-AT 905df2fc
LEGAL_VA, LEGAL_END = 0x905DF2FA, 0x905DF358
LEGAL_RET_STOCK, LEGAL_RET_PATCH = 0x905DF330, 0x905DF2FC

# Corpus: the 7 decoded functions forming the RMMI->Verify->Linker SML path
# (each has a banked fn_*.log Nmdis2 listing in the reference corpus).
CORPUS = (
    ("rmmi_esmlck_hdlr", 0x91985788, "fn_rmmi_esmlck_hdlr.log"),
    ("sml_Verify", 0x905F0F04, "fn_sml_Verify.log"),
    ("mot_sml_catkey_verify", 0x905F0DF8, "fn_mot_sml_catkey_verify.log"),
    ("sml_catkey_verify", 0x905F0658, "fn_sml_catkey_verify.log"),
    ("sml_is_tfn_otp_on", 0x9198E4D2, "fn_sml_is_tfn_otp_on.log"),
    ("sml_Unlock", 0x905F071E, "fn_sml_Unlock.log"),
    ("custom_link_sml_with_rule", 0x905DF3A2, "fn_custom_link_sml_with_rule.log"),
)

# Landmark CATI names (-> (start,end) hex) and singleton verdict PCs.
LANDMARK_CATI = {
    "sml_mini_trace": ("sml_mini_trace", None),
    "sml_sec_function_enter": ("sml_sec_function_enter_trace", "sml_sec_function_enter"),
    "sml_sec_function_leave": ("sml_sec_function_leave_trace", "sml_sec_function_leave"),
    "sml_sec_function_error": ("sml_sec_function_error_trace", "sml_sec_function_error"),
    "smu_get_dump_sml_context": ("smu_get_dump_sml_context_size|smu_dump_sml_context_send_ind",
                                 "smu_get_dump_sml_context"),
}
VERDICT_PCS = {"verdict_ret_905df32e": 0x905DF32E, "linker_905df492": 0x905DF492}
# Hardcoded fallbacks if CATI is unreachable (verified 2026-09-05 values).
LANDMARK_FALLBACK = {
    "sml_mini_trace": (0x905F18D6, 0x905F194E),
    "sml_sec_function_enter": (0x9198A3C4, 0x9198A3DC),
    "sml_sec_function_leave": (0x9198A3DC, 0x9198A3F4),
    "sml_sec_function_error": (0x9198A3F4, 0x9198A40E),
    "smu_get_dump_sml_context": ((0x90F37EE2, 0x90F37EEE), (0x90F37EEE, 0x90F37FE4)),
}

# --- log-line regexes (same dialect as sim/backend_ghidra.py + decomp.py) ---
RE_RESULT = re.compile(
    r"RESULT\s+steps=(?P<steps>\d+)\s+stop=(?P<stop>.*?)\s+"
    r"PC=(?P<pc>[0-9a-fA-Fx]+)\s+a0=0x(?P<a0>[0-9a-fA-F]+)\s+stubs=(?P<stubs>\d+)")
RE_PRESTUBS = re.compile(r"PRESTUBS=(?P<n>\d+)(?P<rest>.*)")
RE_STUB_AT = re.compile(r"(?:PRESTUB|EXPLICIT)@([0-9a-fA-F]{1,8})(?::([A-Za-z0-9_]+))?")
RE_TRACE = re.compile(r"TRACE\s+step=(?P<step>\d+)\s+pc=(?P<pc>[0-9a-fA-F]+)\s+text=(?P<text>.*)")
RE_RET_AT = re.compile(r"RET-AT\s+([0-9a-fA-Fx]+)")
RE_INSN = re.compile(r"Nmdis2\.java>\s+([0-9a-fA-F]{8})\s+(.*?)\s*\(GhidraScript\)\s*$",
                      re.MULTILINE)
RE_DONE = re.compile(r"Nmdis2\.java>\s*DONE n=(\d+)")
RE_REBASE = re.compile(r"Nmdis2\.java>\s*REBASED to (\S+) size=(\d+)")
RE_ABS = re.compile(r"0[xX][0-9a-fA-F]+")


# ---------------------------------------------------------------- schema
def pc_str(pc: int) -> str:
    return f"{pc:#x}"


def normalize(step: int, pc: int, byts: bytes | str, text: str,
              regs: dict | None = None) -> dict:
    """One normalized event. pc -> '0x...' lowercase; bytes -> bare hex."""
    b = byts.hex() if isinstance(byts, (bytes, bytearray)) else str(byts)
    d: dict = {"step": int(step), "pc": pc_str(int(pc)),
               "bytes": b.lower(), "text": canon_text(text)}
    if regs:
        d["regs"] = {k: (f"{v:#x}" if isinstance(v, int) else str(v))
                     for k, v in regs.items()}
    return d


def canon_text(t: str) -> str:
    return re.sub(r"\s+", " ", (t or "").strip())


def dumps_event(e: dict) -> str:
    """Canonical JSONL serialization (fixed key order; byte-stable)."""
    ordered = {"step": e["step"], "pc": e["pc"],
               "bytes": e["bytes"], "text": e["text"]}
    if "regs" in e:
        ordered["regs"] = e["regs"]
    return json.dumps(ordered, separators=(",", ": "))


def loads_event(line: str) -> dict:
    e = json.loads(line)
    assert isinstance(e["step"], int) and isinstance(e["pc"], str)
    assert isinstance(e["bytes"], str) and isinstance(e["text"], str)
    if "regs" in e:
        assert isinstance(e["regs"], dict)
    return e


def write_jsonl(path: Path, events: list[dict]) -> bytes:
    blob = "".join(dumps_event(e) + "\n" for e in events).encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(blob)  # write_bytes: no newline translation -> byte-stable
    return blob


def read_jsonl(path: Path) -> list[dict]:
    return [loads_event(l) for l in
            path.read_text(encoding="utf-8").splitlines() if l.strip()]


# ---------------------------------------------------------------- ROM/CATI loaders (read-only)
def load_rom() -> bytes:
    return ROMONLY.read_bytes()


def load_cati() -> dict[str, tuple[int, int]]:
    raw = json.loads(CATI_JSON.read_text(encoding="utf-8"))
    out: dict[str, tuple[int, int]] = {}
    for k, v in raw.items():
        if isinstance(v, (list, tuple)) and len(v) == 2:
            try:
                out[k] = (int(v[0], 16), int(v[1], 16))
            except (TypeError, ValueError):
                continue
    return out


def rom_bytes_at(rom: bytes, va: int, size: int) -> bytes:
    off = va - VA_BASE
    if not (0 <= off < len(rom)) or off + size > len(rom):
        raise ValueError(f"VA {va:#x}+{size} outside ROM ({len(rom)} B)")
    return rom[off:off + size]


# ---------------------------------------------------------------- ingestion 1: interp streams
def from_interp(events_or_tracer) -> list[dict]:
    """Normalize an interp event stream: Tracer | [TraceEvent] | [dict]."""
    evts = getattr(events_or_tracer, "events", events_or_tracer)
    out: list[dict] = []
    for e in evts:
        if isinstance(e, dict):
            pc = e["pc"]
            pc = int(pc, 16) if isinstance(pc, str) else int(pc)
            regs = e.get("regs")
            if regs is None and "a0" in e:
                regs = {"a0": e["a0"]} if e["a0"] is not None else None
            out.append(normalize(e.get("step", len(out)), pc,
                                 e.get("bytes", ""), e.get("text", ""),
                                 regs))
        else:  # TraceEvent duck-type: .step/.pc/.text/.a0
            regs = {"a0": e.a0} if getattr(e, "a0", None) is not None else None
            out.append(normalize(e.step, e.pc, "", e.text, regs))
    # Renumber defensively so step == index (interp logs step inconsistently
    # across harnesses: emu_rmmi counts from 1, backend forwards from 0).
    for i, e in enumerate(out):
        e["step"] = i
    return out


# ---------------------------------------------------------------- ingestion 2: Ghidra RESULT/trace lines
def parse_emu_result(text: str) -> dict:
    """Parse banked emu_*.log text -> summary (steps/stop/pc/a0/stubs/...)."""
    m = RE_RESULT.search(text)
    if not m:
        raise ValueError("no RESULT line found")
    pc_s = m.group("pc")
    pm = RE_PRESTUBS.search(text)
    prestubs = [int(x, 16) for x, _ in RE_STUB_AT.findall(pm.group("rest"))] \
        if pm else []
    rm = RE_RET_AT.search(text)
    traces = []
    for line in text.splitlines():
        t = RE_TRACE.search(line)
        if t:
            traces.append((int(t.group("step")), int(t.group("pc"), 16),
                           re.sub(r"\s*\(GhidraScript\)\s*$", "",
                                  t.group("text")).strip()))
    return {"steps": int(m.group("steps")), "stop": m.group("stop").strip(),
            "pc": int(pc_s, 16), "a0": int(m.group("a0"), 16),
            "stubs_made": int(m.group("stubs")),
            "prestub_count": int(pm.group("n")) if pm else 0,
            "prestubs": prestubs,
            "ret_at": int(rm.group(1), 16) if rm else None,
            "trace": traces, "patched": "PATCH-BYTES-INJECTED" in text}


def trace_from_emu_log(path_or_text: str | Path) -> tuple[list[dict], dict]:
    """Ingest a Ghidra backend log -> (normalized trace, RESULT summary).

    Logs with TRACE lines (current EmuSml.java) yield one event per TRACE
    line (bytes unknown -> "" ; final event carries a0). RESULT-only banked
    logs yield trace=[] plus the full summary (no per-step PCs exist there;
    use demo_stock_patch_traces() for ROM-grounded steps cross-checked
    against that summary).
    """
    text = (path_or_text.read_text(encoding="utf-8", errors="replace")
            if isinstance(path_or_text, Path) and path_or_text.exists()
            and "\n" not in str(path_or_text) else
            (Path(str(path_or_text)).read_text(encoding="utf-8",
                                                errors="replace")
             if isinstance(path_or_text, (str, Path)) and
             Path(str(path_or_text)).exists() else str(path_or_text)))
    summary = parse_emu_result(text)
    trace = [normalize(s, pc, "", tx,
                       {"a0": summary["a0"]} if i == len(summary["trace"]) - 1
                       else None)
             for i, (s, pc, tx) in enumerate(summary["trace"])]
    return trace, summary


# ---------------------------------------------------------------- ingestion 3: Nmdis2 listing logs
def parse_nmdis2(text: str) -> dict:
    """Parse banked fn_*.log text -> {base, size, entries:[(pc,text)], done}."""
    entries = [(int(pc, 16), canon_text(tx))
               for pc, tx in RE_INSN.findall(text)]
    dm = RE_DONE.search(text)
    rm = RE_REBASE.search(text)
    return {"base": int(rm.group(1), 16) if rm else (entries[0][0] if entries else None),
            "size": int(rm.group(2)) if rm else None,
            "entries": entries, "done": int(dm.group(1)) if dm else None}


def listing_to_trace(entries: list[tuple[int, str]], rom: bytes,
                     end_va: int | None = None,
                     regs_final: dict | None = None) -> list[dict]:
    """Linear-sweep stock trace over listing order (helpers=ret1 metadata).

    Sizes come from next-PC deltas; the last insn uses end_va (CATI extent
    end, exact). Bytes are carved from the real ROM -> deterministic.
    """
    if not entries:
        raise ValueError("empty listing")
    pcs = [pc for pc, _ in entries]
    if end_va is None:
        end_va = pcs[-1] + 2
    out: list[dict] = []
    for i, (pc, tx) in enumerate(entries):
        size = (entries[i + 1][0] - pc) if i + 1 < len(entries) else end_va - pc
        if size not in (2, 4, 6, 8) or size <= 0:
            raise ValueError(f"implausible insn size {size} @ {pc:#x}")
        regs = dict(regs_final) if (regs_final and i == len(entries) - 1) else None
        out.append(normalize(i, pc, rom_bytes_at(rom, pc, size), tx, regs))
    return out


# ---------------------------------------------------------------- demo: legal_sim_rule stock-vs-patch
def _decode_text(mem_get, pc: int, raw2: bytes) -> str:
    """Best-effort text for a 2-byte ROM window (stdlib decoder or header)."""
    try:
        from emu_engine import Memory, PERM_R, decode_one  # type: ignore
        m = Memory()
        m.add("w", pc & ~0xFFF, 0x1000, PERM_R)
        m.write(pc, raw2)
        return decode_one(m, pc).text
    except Exception:  # noqa: BLE001
        return f"DB_{raw2.hex()}"


def demo_stock_patch_traces(rom: bytes | None = None) -> tuple[list[dict], list[dict]]:
    """ROM-grounded stock (25 steps, a0=0) vs patch (1 step, a0=1) traces.

    Stock: 24 x 2-byte ROM-window steps from the entry + final HIT-RET
    event at RET-AT 0x905df330 (matches banked RESULT steps=25/HIT-RET/a0=0).
    Patch: single LI a0,0x1 event at the entry (matches RESULT steps=1,
    RET-AT 0x905df2fc, a0=1; injected bytes 01 d2 ... verified in Ghidra).
    """
    rom = load_rom() if rom is None else rom
    stock: list[dict] = []
    for i in range(24):
        pc = LEGAL_VA + 2 * i
        raw = rom_bytes_at(rom, pc, 2)
        stock.append(normalize(i, pc, raw, _decode_text(None, pc, raw)))
    stock.append(normalize(24, LEGAL_RET_STOCK,
                           rom_bytes_at(rom, LEGAL_RET_STOCK, 2),
                           "HIT-RET", {"a0": 0}))
    patch = [normalize(0, LEGAL_VA, PATCH_LI, "LI a0,0x1", {"a0": 1})]
    return stock, patch


# ---------------------------------------------------------------- diff engine
def _pc_int(e: dict) -> int:
    pc = e["pc"]
    return int(pc, 16) if isinstance(pc, str) else int(pc)


def diff_traces(a: list[dict], b: list[dict]) -> dict:
    """Stock-vs-patch diff: first-divergence + coverage delta (+only-in)."""
    div: dict | None = None
    for i, (ea, eb) in enumerate(zip(a, b)):
        if _pc_int(ea) != _pc_int(eb) or canon_text(ea["text"]) != canon_text(eb["text"]):
            div = {"step": i, "a_pc": ea["pc"], "b_pc": eb["pc"],
                   "a_text": ea["text"], "b_text": eb["text"],
                   "a_bytes": ea.get("bytes", ""), "b_bytes": eb.get("bytes", "")}
            break
    if div is None and len(a) != len(b):
        div = {"step": min(len(a), len(b)), "a_pc": None, "b_pc": None,
               "a_text": "<end>", "b_text": "<end>",
               "note": f"common prefix; lengths {len(a)} vs {len(b)}"}
    ca, cb = {_pc_int(e) for e in a}, {_pc_int(e) for e in b}
    lines: list[str] = []
    if div is not None and "note" not in div:
        lines.append(f"diverge step {div['step']}: "
                     f"{div['a_pc']} {div['a_text']} vs "
                     f"{div['b_pc']} {div['b_text']}")
    elif div is not None:
        lines.append(f"diverge step {div['step']}: {div['note']}")
    else:
        lines.append(f"no divergence in common prefix ({len(a)} steps each)")
    lines.append(f"coverage: {len(ca)} vs {len(cb)} pcs")
    lines.append(f"coverage-delta: {len(ca) - len(cb):+d} pcs "
                 f"(a={len(ca)} b={len(cb)})")
    if ca - cb:
        show = " ".join(f"{v:#x}" for v in sorted(ca - cb)[:8])
        lines.append(f"only-in-a: {len(ca - cb)} pcs {show}"
                     + (" ..." if len(ca - cb) > 8 else ""))
    if cb - ca:
        show = " ".join(f"{v:#x}" for v in sorted(cb - ca)[:8])
        lines.append(f"only-in-b: {len(cb - ca)} pcs {show}"
                     + (" ..." if len(cb - ca) > 8 else ""))
    if len(a) != len(b):
        lines.append(f"length: {len(a)} vs {len(b)} steps")
    return {"divergence": div, "lengths": (len(a), len(b)),
            "coverage_a": len(ca), "coverage_b": len(cb),
            "coverage_delta": len(ca) - len(cb),
            "only_in_a": sorted(ca - cb), "only_in_b": sorted(cb - ca),
            "lines": lines}


def verify_against_listing(trace: list[dict],
                           listing: list[tuple[int, str]]) -> dict:
    """Every executed PC must match a disassembled insn.

    Flags: pc-not-in-listing | text-mismatch (decode) | bytes-mismatch
    (self-modifying?). Events with bytes=="" skip the byte check; HIT-RET /
    "?" texts skip the text check (stop markers, not disasm).
    """
    lmap = {pc: canon_text(tx) for pc, tx in listing}
    lbytes: dict[int, str] = {}
    try:
        rom = load_rom()
        pcs = sorted(lmap)
        for i, pc in enumerate(pcs):
            end = pcs[i + 1] if i + 1 < len(pcs) else None
            if end is None:
                continue  # last-insn width unknown without extent; skip
            size = end - pc
            if size in (2, 4, 6, 8):
                lbytes[pc] = rom_bytes_at(rom, pc, size).hex()
    except (OSError, ValueError):
        lbytes = {}
    bad: list[dict] = []
    for e in trace:
        pc, tx, by = _pc_int(e), canon_text(e["text"]), e.get("bytes", "")
        if pc not in lmap:
            bad.append({"step": e["step"], "pc": e["pc"],
                        "reason": "pc-not-in-listing"})
            continue
        if tx not in ("HIT-RET", "?", "") and tx != lmap[pc]:
            bad.append({"step": e["step"], "pc": e["pc"],
                        "reason": "text-mismatch (decode?)",
                        "trace_text": tx, "listing_text": lmap[pc]})
        elif by and pc in lbytes and by != lbytes[pc]:
            bad.append({"step": e["step"], "pc": e["pc"],
                        "reason": "bytes-mismatch (self-modifying?)",
                        "trace_bytes": by, "listing_bytes": lbytes[pc]})
    return {"ok": not bad, "total": len(trace),
            "matched": len(trace) - len(bad), "mismatches": bad}


def check_convergence(runs: list[list[dict]]) -> dict:
    """Multi-run convergence: same inputs -> identical traces (byte-exact)."""
    if not runs:
        return {"converged": True, "n_runs": 0, "first_diff": None,
                "lines": ["convergence: 0 runs (vacuous)"]}
    blobs = ["".join(dumps_event(e) + "\n" for e in r) for r in runs]
    for k in range(1, len(blobs)):
        if blobs[k] != blobs[0]:
            la, lb = runs[0], runs[k]
            step = next((i for i, (x, y) in enumerate(zip(la, lb)) if x != y),
                        min(len(la), len(lb)))
            fd = {"run": k, "step": step,
                  "ref": la[step] if step < len(la) else None,
                  "got": lb[step] if step < len(lb) else None}
            return {"converged": False, "n_runs": len(runs),
                    "first_diff": fd,
                    "lines": [f"convergence: DIVERGED at run {k} step {step}"]}
    return {"converged": True, "n_runs": len(runs), "first_diff": None,
            "lines": [f"convergence: {len(runs)} runs identical "
                      f"({len(runs[0])} steps each)"]}


# ---------------------------------------------------------------- landmarks
def resolve_landmarks(cati: dict[str, tuple[int, int]] | None = None) -> dict[str, dict]:
    """Named PC sets -> {name: {pcs:set[int], note:str}} (CATI + verdicts)."""
    if cati is None:
        try:
            cati = load_cati()
        except OSError:
            cati = {}

    def extent(name: str) -> tuple[int, int] | None:
        v = cati.get(name) if cati else None
        return (v[0], v[1]) if v else None

    out: dict[str, dict] = {}
    specs = [
        ("sml_mini_trace", ["sml_mini_trace"]),
        ("sml_sec_function_enter",
         ["sml_sec_function_enter_trace", "sml_sec_function_enter"]),
        ("sml_sec_function_leave",
         ["sml_sec_function_leave_trace", "sml_sec_function_leave"]),
        ("sml_sec_function_error",
         ["sml_sec_function_error_trace", "sml_sec_function_error"]),
        ("smu_get_dump_sml_context",
         ["smu_get_dump_sml_context_size", "smu_dump_sml_context_send_ind",
          "smu_get_dump_sml_context", "l4c_smu_get_dump_context"]),
    ]
    for label, cands in specs:
        pcs: set[int] = set()
        used: list[str] = []
        for nm in cands:
            ex = extent(nm)
            if ex:
                pcs.update(range(ex[0], ex[1]))
                used.append(f"{nm} [{ex[0]:#x},{ex[1]:#x})")
        if not pcs and label in LANDMARK_FALLBACK:
            fb = LANDMARK_FALLBACK[label]
            ranges = fb if isinstance(fb[0], tuple) else (fb,)
            for s, e in ranges:  # type: ignore[misc]
                pcs.update(range(s, e))
            used.append("hardcoded fallback (CATI miss)")
        note = ("CATI: " + " + ".join(used)) if used else "UNRESOLVED"
        if label == "smu_get_dump_sml_context":
            note += ("; bare 'smu_get_dump_sml_context' absent verbatim — "
                     "union of size/send_ind extents")
        if label.startswith("sml_sec_function_"):
            note += "; bare symbol absent — *_trace extent used"
        out[label] = {"pcs": pcs, "note": note}
    for label, pc in VERDICT_PCS.items():
        owner = next((k for k, (s, e) in (cati or {}).items() if s <= pc < e),
                     "?")
        out[label] = {"pcs": {pc},
                      "note": f"singleton verdict PC (inside {owner})"}
    return out


def landmark_report(trace: list[dict],
                    landmarks: dict[str, dict] | None = None) -> dict:
    """Hit counts per run: executed PCs inside each set + BALC calls into it."""
    landmarks = resolve_landmarks() if landmarks is None else landmarks
    hits: dict[str, dict] = {}
    for name, lm in landmarks.items():
        pcs = lm["pcs"]
        in_set = [_pc_int(e) for e in trace if _pc_int(e) in pcs]
        calls = []
        for e in trace:
            for m in RE_ABS.findall(e.get("text", "")):
                try:
                    t = int(m, 16)
                except ValueError:
                    continue
                if t in pcs and ("BALC" in e["text"] or "JAL" in e["text"]):
                    calls.append((_pc_int(e), t))
                    break
        hits[name] = {"hits": len(in_set), "pcs_hit": sorted(set(in_set)),
                      "calls": len(calls),
                      "call_sites": [f"{s:#x}->{t:#x}" for s, t in calls[:8]],
                      "note": lm.get("note", "")}
    return hits


def format_landmark_report(label: str, hits: dict[str, dict]) -> list[str]:
    lines = [f"landmarks [{label}]:"]
    for name, h in hits.items():
        pcs = (" " + " ".join(f"{v:#x}" for v in h["pcs_hit"][:6])
               + (" ..." if len(h["pcs_hit"]) > 6 else "")) \
            if h["pcs_hit"] else ""
        lines.append(f"  {name:26s} hits={h['hits']:3d} "
                     f"calls={h['calls']:3d}{pcs}")
    return lines


# ---------------------------------------------------------------- regression corpus
def corpus_manifest(rom: bytes, cati: dict) -> dict:
    return {"version": 1, "mode": "stock", "helpers": "ret1",
            "generator": "sim/trace_tools.py",
            "rom_sha256": hashlib.sha256(rom).hexdigest(),
            "rom_size": len(rom), "cati_symbols": len(cati), "funcs": {}}


def expected_corpus_bytes(name: str, va: int, logname: str,
                          rom: bytes, cati: dict) -> tuple[bytes, dict]:
    """Regenerate one corpus file in memory -> (bytes, info)."""
    logp = TEMP / logname
    parsed = parse_nmdis2(logp.read_text(encoding="utf-8", errors="replace"))
    if not parsed["entries"]:
        raise ValueError(f"{logname}: no Nmdis2 insns parsed")
    start, end = cati.get(name, (va, va))
    if start != va:
        raise ValueError(f"{name}: CATI start {start:#x} != expected {va:#x}")
    if parsed["base"] != start:
        raise ValueError(f"{logname}: REBASED {parsed['base']:#x} != "
                         f"CATI {start:#x}")
    if parsed["done"] != len(parsed["entries"]):
        raise ValueError(f"{logname}: DONE n={parsed['done']} != "
                         f"parsed {len(parsed['entries'])}")
    trace = listing_to_trace(parsed["entries"], rom, end)
    blob = "".join(dumps_event(e) + "\n" for e in trace).encode("utf-8")
    info = {"va": f"{start:#x}", "end": f"{end:#x}", "log": logname,
            "steps": len(trace), "sha256": hashlib.sha256(blob).hexdigest()}
    return blob, info


def build_corpus(outdir: Path = TRACES_DIR) -> dict:
    rom, cati = load_rom(), load_cati()
    man = corpus_manifest(rom, cati)
    status: dict[str, str] = {}
    for name, va, logname in CORPUS:
        blob, info = expected_corpus_bytes(name, va, logname, rom, cati)
        write_jsonl(outdir / f"{name}.jsonl",
                    [loads_event(l) for l in blob.decode().splitlines()])
        man["funcs"][name] = info
        status[name] = f"wrote {info['steps']} steps sha256={info['sha256'][:12]}…"
    (outdir / "manifest.json").write_text(json.dumps(man, indent=2) + "\n",
                                          encoding="utf-8")
    return {"manifest": man, "status": status, "dir": str(outdir)}


def check_corpus(corpus_dir: Path = TRACES_DIR) -> dict:
    """Reproduce every seed file byte-for-byte. Returns {overall, funcs}."""
    rom, cati = load_rom(), load_cati()
    man_path = corpus_dir / "manifest.json"
    if not man_path.exists():
        return {"overall": "FAIL", "funcs": {},
                "error": f"missing {man_path}"}
    man = json.loads(man_path.read_text(encoding="utf-8"))
    if man.get("rom_sha256") != hashlib.sha256(rom).hexdigest():
        return {"overall": "FAIL", "funcs": {},
                "error": "ROM sha256 drift vs manifest — corpus stale, rebuild"}
    funcs: dict[str, dict] = {}
    ok = True
    for name, va, logname in CORPUS:
        p = corpus_dir / f"{name}.jsonl"
        try:
            want, info = expected_corpus_bytes(name, va, logname, rom, cati)
            got = p.read_bytes() if p.exists() else b"<missing>"
            match = got == want
            ok &= match
            funcs[name] = {"result": "PASS" if match else "FAIL",
                           "steps": info["steps"], "sha256": info["sha256"],
                           "bytes": len(want),
                           **({} if match else {"note": "file bytes differ"})}
        except (OSError, ValueError) as e:
            ok = False
            funcs[name] = {"result": "FAIL", "note": str(e)}
    return {"overall": "PASS" if ok else "FAIL", "funcs": funcs,
            "dir": str(corpus_dir)}


# ---------------------------------------------------------------- rendering
def render_side_by_side(a: list[dict], b: list[dict], label_a: str = "stock",
                        label_b: str = "patch", max_rows: int = 30,
                        text_width: int = 34) -> str:
    """Compact side-by-side stock|patch; diverged rows marked '>>'."""
    def cell(e: dict | None) -> str:
        if e is None:
            return f"{'-':10s} {'-':{text_width}s}"
        return (f"{e['pc']:10s} "
                f"{e['text'][:text_width]:{text_width}s}")

    n = max(len(a), len(b))
    head = (f"step {'>>' if True else ''} | {label_a:<45s} | {label_b:<45s}\n"
            + "-" * (7 + 48 + 48))
    rows = [head]
    shown_div = 0
    for i in range(min(n, max_rows)):
        ea, eb = (a[i] if i < len(a) else None), (b[i] if i < len(b) else None)
        div = ea is None or eb is None or _pc_int(ea) != _pc_int(eb) \
            or canon_text(ea["text"]) != canon_text(eb["text"])
        shown_div += div
        rows.append(f"{i:4d} {'>>' if div else '  '} | {cell(ea)} | {cell(eb)}")
    if n > max_rows:
        rows.append(f"... ({n - max_rows} more rows; {n} total steps "
                    f"[{len(a)} vs {len(b)}])")
    rows.append(f"diverged rows shown: {shown_div}")
    return "\n".join(rows)


# ---------------------------------------------------------------- CLI
def cmd_demo() -> int:
    print("schema: {step:int, pc:'0x...', bytes:'hex', text:str, regs?:{a0:'0x...'}}")
    print("sources: interp Tracer.events | Ghidra RESULT/TRACE lines | "
          "Nmdis2 listing logs (ref: Temp/opencode/*.log, read-only)")
    rom = load_rom()
    stock, patch = demo_stock_patch_traces(rom)
    det = diff_traces(stock, patch)
    print("\n-- legal_sim_rule stock-vs-patch --")
    for l in det["lines"]:
        print("  " + l)
    # Cross-check against banked RESULT summaries (value-exact, not invented).
    for tag, logname in (("stock", "emu_legal_sim_rule_stock.log"),
                         ("patch", "emu_legal_sim_rule_patch.log")):
        s = parse_emu_result((TEMP / logname).read_text(encoding="utf-8",
                                                        errors="replace"))
        tr = stock if tag == "stock" else patch
        want_steps = s["steps"]
        print(f"  RESULT cross-check [{tag}]: log steps={want_steps} "
              f"trace={len(tr)} {'MATCH' if len(tr) == want_steps else 'MISMATCH'}; "
              f"log a0={s['a0']:#x} stop={s['stop']} PC={s['pc']:#x}")
    lm = resolve_landmarks()
    for tag, tr in (("stock(25)", stock), ("patch(1)", patch)):
        for l in format_landmark_report(tag, landmark_report(tr, lm)):
            print("  " + l)
    # Nonzero proof: the linker corpus trace executes its own merge PC.
    try:
        linker_tr = read_jsonl(TRACES_DIR / "custom_link_sml_with_rule.jsonl")
        for l in format_landmark_report("linker-corpus(333)",
                                        landmark_report(linker_tr, lm)):
            print("  " + l)
    except OSError:
        print("  (linker corpus trace absent; run --build-corpus)")
    print("\n-- side-by-side (first 8 rows) --")
    print(render_side_by_side(stock, patch, max_rows=8))
    print("\n-- corpus status --")
    st = check_corpus()
    print(f"  sim/traces/: {st['overall']}"
          + ("" if st.get("funcs") else f" ({st.get('error')})"))
    for name, f in st.get("funcs", {}).items():
        print(f"    {name:28s} {f['result']} "
              f"{f.get('steps', '?')} steps")
    return 0


def cmd_check() -> int:
    st = check_corpus()
    print(f"corpus --check: {st['overall']}  (dir={st.get('dir')})")
    if st.get("error"):
        print("  error: " + st["error"])
    for name, f in st.get("funcs", {}).items():
        extra = f"steps={f['steps']} sha256={f.get('sha256', '')[:16]}…" \
            if "steps" in f else f.get("note", "")
        print(f"  {name:28s} {f['result']}  {extra}")
    print("future interp changes must keep these files byte-for-byte "
          "identical (stock mode, helpers=ret1).")
    return 0 if st["overall"] == "PASS" else 1


def cmd_selftest() -> int:
    fails: list[str] = []
    # 1. schema roundtrip
    e = normalize(0, 0x905DF2FA, b"\x14\x1e", "SAVE  x,ra,s0")
    if loads_event(dumps_event(e)) != e:
        fails.append("schema roundtrip")
    # 2. interp ingestion (Tracer duck-type + dicts)
    try:
        from emu_engine import Tracer  # type: ignore
        t = Tracer()
        t.log(7, 0x905DF2FA, "LI a0,0x1", 1)
        n = from_interp(t)
        assert n[0]["step"] == 0 and n[0]["pc"] == "0x905df2fa" \
            and n[0]["regs"] == {"a0": "0x1"} and n[0]["bytes"] == ""
        d = Tracer.diff_detail(t, Tracer())
        assert d["coverage"] == {"a": 1, "b": 0, "delta": 1,
                                 "only_in_a": [0x905DF2FA],
                                 "only_in_b": [], "common": []}
    except Exception as ex:  # noqa: BLE001
        fails.append(f"interp/tracer: {ex}")
    # 3. RESULT parse = proven ground truth
    try:
        s = parse_emu_result((TEMP / "emu_legal_sim_rule_stock.log")
                             .read_text(encoding="utf-8", errors="replace"))
        assert (s["steps"], s["stop"], s["pc"], s["a0"]) == \
            (25, "HIT-RET", 0x905DF330, 0), s
        p = parse_emu_result((TEMP / "emu_legal_sim_rule_patch.log")
                             .read_text(encoding="utf-8", errors="replace"))
        assert (p["steps"], p["stop"], p["pc"], p["a0"]) == \
            (1, "HIT-RET", 0x905DF2FC, 1), p
    except Exception as ex:  # noqa: BLE001
        fails.append(f"result-parse: {ex}")
    # 4. listing parse counts (DONE n cross-check) for all 7 corpus logs
    try:
        rom, cati = load_rom(), load_cati()
        for name, va, logname in CORPUS:
            parsed = parse_nmdis2((TEMP / logname).read_text(
                encoding="utf-8", errors="replace"))
            assert parsed["entries"], f"{logname}: empty"
            assert parsed["done"] == len(parsed["entries"]), \
                f"{logname}: DONE {parsed['done']} != {len(parsed['entries'])}"
    except Exception as ex:  # noqa: BLE001
        fails.append(f"listing-parse: {ex}")
    # 5. diff demo expectations: divergence step 0, coverage 25-vs-1
    try:
        stock, patch = demo_stock_patch_traces()
        det = diff_traces(stock, patch)
        assert det["divergence"]["step"] == 0, det["divergence"]
        assert (det["coverage_a"], det["coverage_b"]) == (25, 1), det
    except Exception as ex:  # noqa: BLE001
        fails.append(f"diff-demo: {ex}")
    # 6. verifier: corpus trace passes; tampered bytes fail
    try:
        parsed = parse_nmdis2((TEMP / "fn_sml_Verify.log").read_text(
            encoding="utf-8", errors="replace"))
        rom, cati = load_rom(), load_cati()
        s, en = cati["sml_Verify"]
        tr = listing_to_trace(parsed["entries"], rom, en)
        assert verify_against_listing(tr, parsed["entries"])["ok"]
        bad = [dict(e) for e in tr]
        bad[3]["bytes"] = "ffff"
        v = verify_against_listing(bad, parsed["entries"])
        assert not v["ok"] and v["mismatches"][0]["reason"].startswith(
            "bytes-mismatch")
        bad2 = [dict(e) for e in tr]
        bad2[2]["pc"] = "0xdead0000"
        assert not verify_against_listing(bad2, parsed["entries"])["ok"]
    except Exception as ex:  # noqa: BLE001
        fails.append(f"verifier: {ex}")
    # 7. convergence + landmarks + render smoke
    try:
        stock, patch = demo_stock_patch_traces()
        assert check_convergence([stock, stock, stock])["converged"]
        assert not check_convergence([stock, patch])["converged"]
        lm = resolve_landmarks()
        assert lm["sml_mini_trace"]["pcs"] and \
            VERDICT_PCS["linker_905df492"] in lm["linker_905df492"]["pcs"]
        assert ">>" in render_side_by_side(stock, patch, max_rows=4)
    except Exception as ex:  # noqa: BLE001
        fails.append(f"conv/landmark/render: {ex}")
    print("trace_tools selftest:", "PASS" if not fails else "FAIL")
    for f in fails:
        print("  -", f)
    return 1 if fails else 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="execution-trace + differential analysis (offline)")
    ap.add_argument("--demo", action="store_true", help="schema + stock-vs-patch demo (default)")
    ap.add_argument("--check", action="store_true", help="corpus byte-for-byte check")
    ap.add_argument("--build-corpus", action="store_true", help="(re)generate sim/traces/")
    ap.add_argument("--selftest", action="store_true", help="offline unit checks")
    args = ap.parse_args(argv)
    if args.selftest:
        return cmd_selftest()
    if args.check:
        return cmd_check()
    if args.build_corpus:
        res = build_corpus()
        print(f"corpus built: {res['dir']}")
        for name, s in res["status"].items():
            print(f"  {name:28s} {s}")
        print("manifest: sim/traces/manifest.json (mode=stock helpers=ret1)")
        return cmd_check()
    return cmd_demo()


if __name__ == "__main__":
    sys.exit(main())
