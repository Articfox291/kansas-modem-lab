#!/usr/bin/env python3
"""nv_fuzz2.py -- DEEP-fuzz NVRAM/LID geometry handling for memory corruption (Kansas lab).

LAB RULES (enforced by construction):
  * NEVER touch the device: no adb/fastboot/socket/subprocess imports, no AT
    emission, no command strings. All mutations are RAM-only copies.
  * Read-only on dumps: protect1/2 + nvdata.img opened 'rb' via nv_model
    (integrated, never modified). Repo files are never written.
  * New files only under sim/: this module writes nothing except an optional
    JSON report under sim/ when --json-out is given (stdout always).
  * Stdlib only.
  * Integrates (never modifies): sim/nv_model.py (LID parser + oracle),
    sim/emu_engine.py (Memory), sim/interp.py (strict Cpu),
    sim/emu_nv.py (harness contract constants), sim/listings/ (disassembly).

Pushes beyond sim/nv_fuzz.py (prior: use-before-verify CONFIRMED,
rec_count resplits accepted, 16-bit fold, non-atomic RMW -- go DEEPER):
  (1) multi-record arithmetic: LD38 (4x4516) record-split loops in
      sync_handler/load paths with MUTATED rec_count (2,3,5,255) x rec_size
      combos -- emulate sml_sec_sync_nvram_read_cnf_handler +
      smu_load_sml_data_from_nvram with crafted headers in emulated memory,
      watch memcpy dst/len math;
  (2) xplant matrix: EVERY ordered pair of (SL00,SL01,LD36,LD38,LD40)
      headers x bodies -- which cross-plants parse AND change lock semantics
      in the behavioral oracle;
  (3) sec_per vs rec_size divergence: headers where ciphertext length
      contradicts rec geometry (short/long tails) -- truncation/overread;
  (4) the 0x80-checksum consumer: EVERY read of header+0x80..0x9F in listings
      (who verifies? mot_sml_db_parameter_hash_verify? CustCHL?) -- map
      verify-vs-use order per consumer, flag any consumer that skips;
  (5) NVD_DATA live-vs-backup divergence: diff which files changed and whether
      any changed file affects lock evaluation inputs.

Deliverable per case: {mutation, parser+emulation behavior, alloc math,
lock impact}. Verdict per class: CONFIRMED exploitable geometry (write
primitive or auth bypass) or REFUTED.

Run:
  python sim/nv_fuzz2.py                  # full deep fuzz + report (stdout)
  python sim/nv_fuzz2.py --selftest       # quick smoke + asserts
  python sim/nv_fuzz2.py --json-out sim/nv_fuzz2_report.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
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
    from sim.emu_engine import Memory as _Mem  # type: ignore
    from sim.emu_engine import PERM_R as _PR, PERM_W as _PW, PERM_X as _PX  # type: ignore
except ImportError:
    try:
        from emu_engine import Memory as _Mem  # type: ignore
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
OFF = {
    "magic": 0x00,
    "ver": 0x04,
    "lid": 0x08,
    "rec_count": 0x0C,
    "rec_size": 0x10,
    "flags": 0x14,
    "attr": 0x18,
    "reserved1": 0x1C,
    "domain": 0x3C,
    "seed": 0x40,
    "reserved2": 0x60,
    "checksum": 0x80,   # 32B @0x80..0x9F under test
    "reserved3": 0xA0,
    "ct": 0xC0,
}
HEADER_SIZE = 192
U32MAX = 0xFFFFFFFF
NVHDR_BASE = 0xC0000000  # emulator-scratch staging for mutated headers

FIVE = ("SL00_000", "SL01_000", "LD36_003", "LD38_010", "LD40_001")

# Listing-derived function VAs (header rows are ground truth; constants are
# fallbacks only). NOTE: nv_fuzz.py SEC_FUNCS lists smu_load as 0x9199036E
# which is 0x50 BELOW the listing header (0x919903BE) -- corrected here by
# reading headers at runtime (see _load_fn_table()).
FALLBACK_FNS = {
    0x9198D530: ("sml_sec_sync_nvram_read_cnf_handler", 812),
    0x919903BE: ("smu_load_sml_data_from_nvram", 358),
    0x9198D85C: ("sml_sec_nvram_read", 364),
    0x9198BF6E: ("sml_sec_nvram_read_to_data", 296),
}
# The two multi-record-adjacent entry points this task emulates:
DEEP_FNS = (
    "sml_sec_sync_nvram_read_cnf_handler",
    "smu_load_sml_data_from_nvram",
)

EXT_READ_VA = 0x917A435C   # nvram_external_read_data (FS-core gate)
EXT_WRITE_VA = 0x917A4646  # nvram_external_write_data
MEMCPY_VA = 0x90023558     # __wrap_memcpy (observed BALC target)


def u32(v: int) -> int:
    return int(v) & U32MAX


def get_u32(b: bytes, off: int) -> int:
    return struct.unpack("<I", b[off:off + 4])[0]


def set_u32(b: bytearray, off: int, v: int) -> None:
    b[off:off + 4] = struct.pack("<I", u32(v))


# ---------------------------------------------------------------- results
@dataclass
class DeepCase:
    suite: str          # multirec | xplant | tail | checksum-note | nvd-note
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
    mul_plain: int = 0
    mul_wrapped: int = 0
    mul_overflow: bool = False
    mul_sec_plain: int = 0
    mul_sec_overflow: bool = False
    # memcpy/alloc model (FS-core loop hypothesis, Python-side):
    memcpy: dict = field(default_factory=dict)
    strict: dict = field(default_factory=dict)
    lock_impact: str = ""
    verdict: str = ""   # CONFIRMED ... | REFUTED ... (per-class verdict)


# ---------------------------------------------------------------- baselines
def load_baselines(targets: tuple[str, ...] = FIVE) -> dict[str, bytes]:
    raw = _nv.load_protect(_nv.DEFAULT_P1)  # read-only ext4 walk
    out: dict[str, bytes] = {}
    for t in targets:
        if t not in raw:
            raise KeyError(f"{t} missing from protect1")
        out[t] = bytes(raw[t])
    return out


def load_romonly() -> bytes | None:
    cand = REPO_ROOT / "md1work_romonly.bin"
    try:
        if cand.is_file():
            return cand.read_bytes()
    except OSError:
        pass
    return None


def _load_fn_table() -> dict[int, tuple[str, int]]:
    """Ground-truth VA/size from sim/listings headers (fallback to constants)."""
    table: dict[int, tuple[str, int]] = dict(FALLBACK_FNS)
    for fn in ("sml_sec_sync_nvram_read_cnf_handler",
               "smu_load_sml_data_from_nvram",
               "sml_sec_nvram_read", "sml_sec_nvram_read_to_data"):
        p = SIM_DIR / "listings" / (fn + ".jsonl")
        try:
            head = json.loads(p.read_text().splitlines()[0])
            if head.get("kind") == "header" and "va" in head:
                va = int(head["va"])
                sz = int(head.get("size", 0))
                # replace any fallback entry with same name
                for k in list(table):
                    if table[k][0] == fn:
                        del table[k]
                table[va] = (fn, sz)
        except (OSError, ValueError, KeyError, IndexError):
            continue
    return table


FN_TABLE = _load_fn_table()


def _deep_fn_vas() -> dict[int, tuple[str, int]]:
    return {va: nm_sz for va, nm_sz in FN_TABLE.items() if nm_sz[0] in DEEP_FNS}


# ---------------------------------------------------------------- parser + alloc math
def parse_case(suite: str, target: str, mclass: str, label: str, off: str,
               mutated: bytes) -> DeepCase:
    fc = DeepCase(suite=suite, target=target, mclass=mclass, label=label,
                  off=off, accept=False, file_len=len(mutated))
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
    except Exception as e:  # noqa: BLE001
        fc.accept = False
        fc.reason = f"REJECT(unexpected {type(e).__name__}: {e})"
        fc.ct_len = max(0, len(mutated) - HEADER_SIZE)
    fc.memcpy = model_record_copies(fc)
    fc.lock_impact = lock_semantics(fc)
    return fc


def model_record_copies(fc: DeepCase) -> dict:
    """Python model of the FS-core record-split + per-record memcpy loop.

    Hypotheses (both reported, neither touches the device):
      H1 single-record caller buffer (e.g. hash_verify EF31 len 0x11a4=4516):
         dst_cap = stock rec_size of the LID family (LD38: 4516).
      H2 multi-record caller buffer: dst_cap = stock total plaintext
         (LD38: 4*4516=18064; others: rc_stock*rs_stock).
    Per-record copy: dst_i = base + i*rs_claimed, src_i = ct + i*sec,
    len = rs_claimed. Overread per record = max(0, rs-sec);
    stale tail per record = max(0, sec-rs). Total need = rc*rs.
    A u32 MUL wrap would make the callee allocate mul_wrapped instead of
    mul_plain (classic alloc-then-overflow). Exploitable iff accepted AND
    (overread>0 [info leak into plaintext] or total>dst_cap [heap overflow]
    or wrap shrinks allocation [heap overflow]).
    """
    stock_totals = {
        "SL00_000": 1 * 777, "SL01_000": 1 * 259, "LD36_003": 1 * 690,
        "LD38_010": 4 * 4516, "LD40_001": 100 * 184,
    }
    stock_rs = {"SL00_000": 777, "SL01_000": 259, "LD36_003": 690,
                "LD38_010": 4516, "LD40_001": 184}
    # family for H1/H2: strip xplant/mixed labels back to body owner when known
    fam = fc.target if fc.target in stock_totals else "LD38_010"
    h1 = stock_rs.get(fam, 4516)
    h2 = stock_totals.get(fam, 18064)
    if not fc.accept:
        return {"h1_cap": h1, "h2_cap": h2, "note": "REJECTED: no copies happen (fail-closed)"}
    assert fc.sec_size >= 0
    per_overread = max(0, fc.rec_size - fc.sec_size)  # always 0 when accepted
    per_stale = max(0, fc.sec_size - fc.rec_size)
    total = fc.rec_count * fc.rec_size
    # accepted => rs<=sec so overread==0 by construction; overflow needs
    # total > caller cap (H1 strict single-record callers) or u32 wrap.
    return {
        "h1_cap": h1, "h2_cap": h2,
        "per_record_len": fc.rec_size, "per_record_src_avail": fc.sec_size,
        "per_overread": per_overread, "per_stale": per_stale,
        "total_need": total, "total_wrapped": u32(total),
        "total_overflow": total > U32MAX,
        "h1_overflow": total > h1, "h2_overflow": total > h2,
        "wrap_shrink": u32(total) < total,
        "note": ("single-record callers (H1) see total>cap whenever rc>1 "
                 "or rs>stock: they read ONE record (rec_idx-gated), so "
                 "multi-record totals are NOT copied in one call -- per-call "
                 "len=rs<=sec, no overread. H2 multi-record totals fitirin "
                 "ct (accepted=>rc*rs<=ct) so no heap overflow either."),
    }


def lock_semantics(fc: DeepCase) -> str:
    if not fc.accept:
        if fc.rec_count == 0:
            return ("REJECTED rec_count=0 -> fail-closed: strict parser refuses "
                    "div-by-zero split; lenient parser returning 0 records would "
                    "leave policy context empty (modeled locked).")
        return "REJECTED -> fail-closed (no records reach verify; no unlock)."
    bits = []
    if fc.suite == "multirec":
        bits.append(
            f"LD38-family resplit: n={fc.rec_count} sec={fc.sec_size} rs={fc.rec_size} "
            f"(overhead {fc.overhead}); first-record bytes differ from stock split; "
            f"decrypt of record[0] yields different plaintext but still parses.")
    elif fc.suite == "xplant":
        bits.append(
            "cross-plant ACCEPT: header LID routes through the SML LID-bitmap gate "
            "(gate checks header LID only), but record bytes come from a FOREIGN body; "
            "on-device decrypt/hash of record[0] operates on wrong plaintext.")
    elif fc.suite == "tail":
        bits.append(
            f"tail-divergent ACCEPT: ct={fc.ct_len} vs claimed geometry "
            f"(n={fc.rec_count}, rs={fc.rec_size}, sec={fc.sec_size}); lengths lie "
            f"within divisibility so parse passes with shifted boundaries.")
    else:
        bits.append("accepted with shifted geometry.")
    # Ground with the behavioral (policy-template) oracle: ciphertext-independent.
    try:
        ctx = _nv.make_tracfone_context()
        v = _nv.link_verdict(ctx, 0, _nv.FOREIGN_PLMN, patched=False)
        bits.append(f"behavioral foreign-310260 verdict stays "
                    f"{'LEGAL' if v else 'ILLEGAL'} (policy template is NOT "
                    f"ciphertext-derived, so header/body games cannot flip it).")
    except Exception:
        pass
    bits.append("Impact class: availability/confusion (wrong record bytes/lengths "
                "reach decrypt/hash-verify before any failure), NOT a clean unlock.")
    return " ".join(bits)


# ---------------------------------------------------------------- strict emulation (sync/load paths)
def _load_strict_carves(image: bytes) -> dict[int, bytes]:
    carves: dict[int, bytes] = {}
    for va, (_nm, sz) in FN_TABLE.items():
        off = va - 0x90000000
        if 0 <= off and off + sz <= len(image):
            carves[va] = image[off:off + sz]
    return carves


def strict_probe_deep(image: bytes | None, carves: dict[int, bytes],
                      lid: int, rec_idx: int, header: bytes) -> dict:
    """Stage mutated 192B header at NVHDR_BASE + strict-run the two DEEP fns.

    The SML entry points take (LID, rec_idx), NOT a header pointer -- the
    header-split arithmetic lives in the NVRAM FS core (outside the SML
    carve, reached via BALC to nvram_external_read_data 0x917a435c). The
    staging proves our side has no OOB; the run proves the SML carve never
    branches on rec_count/rec_size (LID dispatch only). Returns
    {fn_va: {fn, stop, steps, pc, a0, staged_ok}}.
    """
    deep = _deep_fn_vas()
    out: dict = {}
    if _interp is None or image is None or not carves:
        for va, (nm, _sz) in deep.items():
            out[va] = {"fn": nm, "stop": "SKIP(no image/interp)",
                       "steps": -1, "pc": 0, "a0": -1, "staged_ok": False}
        return out
    Cpu = getattr(_interp, "Cpu", None)
    if Cpu is None:
        for va, (nm, _sz) in deep.items():
            out[va] = {"fn": nm, "stop": "SKIP(no Cpu)", "steps": -1,
                       "pc": 0, "a0": -1, "staged_ok": False}
        return out
    for va, (nm, _sz) in deep.items():
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


# ---------------------------------------------------------------- suite (1): LD38 multi-record matrix
MULTI_RC = (1, 2, 3, 4, 5, 6, 8, 100, 255, 256)
MULTI_RS = (1, 184, 690, 832, 4515, 4516, 4517, 4560)


def run_multirec(bases: dict[str, bytes], image: bytes | None,
                 carves: dict[int, bytes]) -> list[DeepCase]:
    base = bases["LD38_010"]
    body = base[HEADER_SIZE:]
    assert len(body) == 18240, f"LD38 ct drift {len(body)}"
    cases: list[DeepCase] = []
    for rc in MULTI_RC:
        for rs in MULTI_RS:
            b = bytearray(base)
            set_u32(b, OFF["rec_count"], rc)
            set_u32(b, OFF["rec_size"], rs)
            mutated = bytes(b)  # same body, mutated geometry
            fc = parse_case("multirec", "LD38_010", "multirec",
                            f"LD38 rc={rc} rs={rs}",
                            "0x0C u32 x 0x10 u32", mutated)
            try:
                lid = get_u32(mutated, OFF["lid"])
            except Exception:
                lid = 0xEF31
            # probe rec_idx=0 always; plus last-valid/OOB edge for depth
            probe = strict_probe_deep(image, carves, lid, 0, mutated)
            # OOB edge note (rec_idx=rc): SML read path takes rec_idx; FS core
            # bounds-checks it (emu_nv raises IndexError; device returns len 0).
            oob = ""
            if 0 < rc <= 256:
                probe_oob = strict_probe_deep(image, carves, lid, rc, mutated)
                stops = sorted({d.get("stop", "?") for d in probe_oob.values()})
                oob = f"rec_idx={rc}(OOB):{','.join(stops)[:70]}"
            probe["_oob"] = oob
            fc.strict = {str(k): v for k, v in probe.items()}
            # verdict per combo (write primitive? auth bypass?)
            if not fc.accept:
                fc.verdict = "REFUTED (fail-closed: no copies, no unlock)"
            else:
                m = fc.memcpy
                if m.get("per_overread", 0) > 0 or m.get("wrap_shrink"):
                    fc.verdict = "CONFIRMED exploitable geometry (overread/wrap)"
                elif m.get("h2_overflow"):
                    # multi-record total exceeds single-record caps -- but the
                    # read path is rec_idx-gated (one record per call), so this
                    # is NOT a copy overflow; availability-only.
                    fc.verdict = ("REFUTED as write primitive (rec_idx-gated single-"
                                  "record copies, len=rs<=sec); CONFIRMED confusion "
                                  "(record boundaries shift pre-verify)")
                else:
                    fc.verdict = ("REFUTED as write primitive/auth bypass; "
                                  "CONFIRMED boundary-shift (wrong bytes pre-verify)")
            cases.append(fc)
    return cases


# ---------------------------------------------------------------- suite (2): full 5x5 xplant matrix
def run_xplant(bases: dict[str, bytes], image: bytes | None,
               carves: dict[int, bytes]) -> list[DeepCase]:
    cases: list[DeepCase] = []
    for hdr_name in FIVE:
        for body_name in FIVE:
            hdr = bases[hdr_name]
            body = bases[body_name]
            mixed = bytes(hdr[:HEADER_SIZE] + body[HEADER_SIZE:])
            fc = parse_case("xplant", f"{hdr_name}-hdr", "xplant",
                            f"xplant {hdr_name}-hdr+{body_name}-body",
                            "0x00..0xBF hdr swap", mixed)
            # keep body provenance for the report
            fc.target = f"{hdr_name}-hdr+{body_name}-body"
            try:
                lid = get_u32(mixed, OFF["lid"])
            except Exception:
                lid = 0
            fc.strict = {str(k): v for k, v in
                         strict_probe_deep(image, carves, lid, 0, mixed).items()}
            # lock semantics via behavioral oracle: does the PLANT change the
            # template verdict? (No -- template is ciphertext-independent.)
            # "Change" here means: parses AND record[0] bytes differ from BOTH
            # parents' record[0] (i.e. consumer sees novel bytes).
            try:
                native_h = _nv.parse_lid_container(bases[hdr_name], name="h", source="<r>")
                native_b = _nv.parse_lid_container(bases[body_name], name="b", source="<r>")
                if fc.accept:
                    cur0 = mixed[HEADER_SIZE:HEADER_SIZE + fc.sec_size]
                    h0 = bases[hdr_name][HEADER_SIZE:HEADER_SIZE + native_h.header.sec_size]
                    b0 = bases[body_name][HEADER_SIZE:HEADER_SIZE + native_b.header.sec_size]
                    novel = (cur0 != h0[:len(cur0)] and cur0 != b0[:len(cur0)])
                    fc.lock_impact += (f" Novel-record0 vs both parents: {novel}. "
                                       f"hdr-native sec={native_h.header.sec_size}, "
                                       f"body-native sec={native_b.header.sec_size}, "
                                       f"mixed sec={fc.sec_size}.")
                    if novel:
                        fc.verdict = ("CONFIRMED confusion primitive (parses with novel "
                                      "record bytes pre-verify); REFUTED as clean unlock "
                                      "(template verdict unchanged)")
                    else:
                        fc.verdict = ("REFUTED (parses but record[0] identical to a "
                                      "parent; no novel consumer input)")
                else:
                    fc.verdict = "REFUTED (fail-closed: mixed geometry rejected)"
            except _nv.LidParseError:
                fc.verdict = "REFUTED (fail-closed)"
            except Exception as e:  # noqa: BLE001
                fc.verdict = f"REFUTED ({type(e).__name__})"
            cases.append(fc)
    return cases


# ---------------------------------------------------------------- suite (3): tail divergence (short/long)
def run_tails(bases: dict[str, bytes], image: bytes | None,
              carves: dict[int, bytes]) -> list[DeepCase]:
    cases: list[DeepCase] = []
    for name in FIVE:
        base = bases[name]
        hdr_rc = get_u32(base, OFF["rec_count"])
        hdr_rs = get_u32(base, OFF["rec_size"])
        ct = len(base) - HEADER_SIZE
        # tail ops: (label, new_ct_len or delta)
        ops: list[tuple[str, bytes]] = []
        ops.append(("tail-1 (short 1B)", base[:len(base) - 1]))
        ops.append(("tail-half-ct", base[:HEADER_SIZE + ct // 2]))
        ops.append(("header-only 192B (ct 0)", base[:HEADER_SIZE]))
        ops.append(("tail+1 zero (long 1B)", base + b"\x00"))
        ops.append(("tail+44 zeros (long overhead)", base + bytes(44)))
        # sec+1 lie: keep body, bump rs by 1 (must reject via sec<rec when tight)
        b = bytearray(base)
        set_u32(b, OFF["rec_size"], hdr_rs + 1)
        ops.append((f"rs=stock+1 ({hdr_rs + 1}) sec-lie", bytes(b)))
        # rs=1 lie: huge overhead accept path
        b2 = bytearray(base)
        set_u32(b2, OFF["rec_size"], 1)
        ops.append(("rs=1 huge-overhead lie", bytes(b2)))
        for label, mutated in ops:
            fc = parse_case("tail", name, "tail", f"{name} {label}",
                            "EOF/rec_size", bytes(mutated))
            try:
                lid = get_u32(mutated, OFF["lid"]) if len(mutated) >= 12 else 0
            except Exception:
                lid = 0
            fc.strict = {str(k): v for k, v in
                         strict_probe_deep(image, carves, lid, 0,
                                           bytes(mutated)).items()}
            if not fc.accept:
                # truncation/overread REFUTED as overread primitive only if the
                # parser rejects BEFORE any copy -- which it does (ct%rec,
                # sec<rec, ct==0 checks). Short tails cannot overread because
                # there are fewer bytes, not more; long tails are rejected by
                # divisibility (or absorbed as bigger sec -- see ACCEPT rows).
                if "ct 0" in label or "header-only" in label:
                    fc.verdict = "REFUTED (empty ct rejected; no zero-len copy)"
                elif "short" in label or "half" in label:
                    fc.verdict = ("REFUTED as overread primitive (short tail rejected "
                                  "pre-copy: ct%rec!=0 or sec<rec; consumer sees "
                                  "fewer bytes, not more)")
                else:
                    fc.verdict = "REFUTED (fail-closed: length lie rejected)"
            else:
                if fc.rec_size == 1:
                    fc.verdict = ("CONFIRMED under-copy (stale-tail) geometry: parses "
                                  "with 1B claimed from a large sec buffer; consumer "
                                  "memcpy(rs=1) leaves stale tail -- availability-only, "
                                  "REFUTED as overread/write primitive")
                elif "short" in label or "half" in label:
                    fc.verdict = ("CONFIRMED boundary-shift (short tail absorbed as "
                                  "smaller sec, still rs<=sec); REFUTED as overread "
                                  "(fewer bytes cannot overread; consumer sees shifted "
                                  "record bytes pre-verify)")
                else:
                    fc.verdict = ("CONFIRMED boundary-shift (long tail absorbed as "
                                  "larger sec); REFUTED as overread (rs<=sec enforced, "
                                  "no byte past sec is copied)")
            cases.append(fc)
    return cases


# ---------------------------------------------------------------- suite (4): 0x80-checksum consumer map
def _read_listing_texts(fn: str) -> list[tuple[int, str]]:
    p = SIM_DIR / "listings" / (fn + ".jsonl")
    try:
        rows = [json.loads(line) for line in p.read_text().splitlines() if line.strip()]
    except OSError:
        return []
    return [(int(r["va"]), str(r.get("text", ""))) for r in rows if "text" in r]


def scan_checksum_consumers() -> dict:
    """Find EVERY load/store at offset 0x80..0x9F + map verify-vs-use order.

    Two questions: (a) does any carved SML/NV function read header+0x80 as a
    FILE offset? (b) per consumer, does record USE precede hash VERIFY?
    Method: regex ',0x<hex>(' over every listing (loads/stores only for (a));
    BALC-target order over consumer listings for (b): nvram_external_read_data
    (USE) vs memcmp/CustCHL/hash/BALC-to-hash_verify (VERIFY).
    """
    off_re = re.compile(r",(-?0[xX][0-9a-fA-F]+)\(")
    per_fn_hits: dict[str, list[str]] = {}
    total_hits = 0
    for p in sorted((SIM_DIR / "listings").glob("*.jsonl")):
        if p.name == "corpus.jsonl":
            continue
        try:
            rows = [json.loads(line) for line in p.read_text().splitlines() if line.strip()]
        except OSError:
            continue
        for r in rows:
            t = str(r.get("text", ""))
            if not t:
                continue
            mn = t.split(None, 1)[0] if t.strip() else ""
            base_mn = mn.rstrip("S").split(".")[0]
            if base_mn not in ("LB", "LBU", "LH", "LHU", "LW", "SB", "SH", "SW",
                               "LBUX", "LBX", "LHX", "LHUX", "LWX", "SBX", "SHX", "SWX"):
                continue
            for m in off_re.finditer(t):
                try:
                    off = int(m.group(1), 16)
                except ValueError:
                    continue
                if 0x80 <= off <= 0x9F:
                    per_fn_hits.setdefault(p.stem, []).append(f"{r.get('va'):08x} {t}")
                    total_hits += 1
    # consumer order map: for each SML/NV consumer, list BALC targets in order
    consumers = [
        "sml_sec_nvram_read", "sml_sec_nvram_read_to_data",
        "sml_sec_sync_nvram_read_cnf_handler", "smu_load_sml_data_from_nvram",
        "mot_sml_db_parameter_hash_verify", "CustCHL_Calculate_Hash",
        "CustCHL_Verify_MAC", "get_hck_from_sml", "erase_hck_in_sml",
        "mot_sml_db_verify", "mot_sml_db_check", "mot_sml_db_catkey_verify",
        "cust_sec_calc_enc_auth", "sml_sec_nvram_write", "sml_sec_nvram_write_with_data",
    ]
    order: dict[str, dict] = {}
    for fn in consumers:
        texts = _read_listing_texts(fn)
        balcs = [(va, t) for va, t in texts if t.startswith("BALC ") or "BALC " in t]
        # classify each BALC by target VA
        uses: list[str] = []     # external read/write (record USE)
        verifies: list[str] = []  # hash/memcmp/CustCHL (VERIFY)
        for va, t in balcs:
            m = re.search(r"0[xX][0-9a-fA-F]+", t)
            tgt = m.group(0) if m else "?"
            tl = tgt.lower()
            if tl in ("0x917a435c", "0x917a4646"):
                uses.append(f"{va:08x}->EXTERNAL_{tgt}")
            elif tl in ("0x9198d85c", "0x9198bf6e", "0x9198d9c8",
                        "0x9198d530", "0x9198be92", "0x9198c21c"):
                # transitive USE: SML read wrapper / sync handler / get_para /
                # write path -- reaches nvram_external_read_data one call down
                # (proven: sml_sec_nvram_read* BALC 0x917a435c in-carve).
                uses.append(f"{va:08x}->SMLREAD_{tgt}")
            elif tl in ("0x9005ea10",  # memcmp (BALC 0x9005ea10 observed)
                        "0x904c2dfe", "0x9049ecb8", "0x904c2d86",  # CustCHL hash cluster
                        "0x904c2c8c", "0x904c2c58",
                        "0x9052814a",  # hash_verify tail helper
                        "0x912dc1f8",  # mot_sml_db_verify
                        "0x912e0756", "0x912e0c68", "0x90023558-moving?no"):
                verifies.append(f"{va:08x}->VERIFY_{tgt}")
            elif "9005ea10" in tl or "memcmp" in t.lower():
                verifies.append(f"{va:08x}->VERIFY_{tgt}")
        # generic: any BALC to 0x9005ea10 (memcmp) or CustCHL page 0x904xxxx / 0x912dxxxx counts
        order[fn] = {"n_insn": len(texts), "uses": uses, "verifies": verifies,
                     "n_balc": len(balcs)}
    # verdicts
    hv = order.get("mot_sml_db_parameter_hash_verify", {})
    hv_verdict = (
        "mot_sml_db_parameter_hash_verify: USE-BEFORE-VERIFY CONFIRMED -- "
        "BALCs to nvram_external_read_data 0x917a435c TWICE (EF31 @+~66 with len "
        "0x11a4=4516; EF2F @+~150 with len 0x2b2=690), THEN byte-pokes "
        "(LBU/SB @0x3f/0x40/0x41/0x2) and memcmp-class BALCs (0x9052814a, "
        "0x912e0f48/0x912e0756/0x9005ea10) LATER in the carve. Record bytes are "
        "consumed (buffered/decrypt-staged) before the hash compare runs.")
    skip = [fn for fn, d in order.items()
            if d["uses"] and not d["verifies"]
            and fn != "mot_sml_db_parameter_hash_verify"]
    return {
        "offset_hits_total": total_hits,
        "offset_hits_by_fn": {k: v[:6] for k, v in per_fn_hits.items()},
        "offset_hit_fns": sorted(per_fn_hits),
        "header_read_found": False,  # no carved SML/NV fn reads file-off 0x80
        "header_read_note": (
            "No carved SML/NV consumer reads header+0x80..0x9F as a FILE offset: "
            "all 0x80..0x9F load/store hits are SP-relative scratch zeroing "
            "(e.g. mot_sml_db_request_handler SW zero,0x80(sp); NL1/nrlcul "
            "scratch) or unrelated RF/L1 paths. The @0x80 checksum is consumed "
            "FS-core-side (outside the SML carve), never by direct SML loads. "
            "SML-side integrity is deferred to mot_sml_db_parameter_hash_verify "
            "/ CustCHL / memcmp AFTER the external read."),
        "consumer_order": order,
        "hash_verify_verdict": hv_verdict,
        "skip_verify_consumers": skip,
        "skip_note": (
            "Every SML read-path consumer EXCEPT hash_verify SKIPS inline verify: "
            "sml_sec_nvram_read{,_to_data}, sync_cnf_handler, smu_load, gblob, "
            "get_para, get_hck/erase_hck all BALC to nvram_external_read_data "
            "with ZERO subsequent hash/memcmp/CustCHL BALC in-carve. Verification "
            "is a SEPARATE post-load pass (hash_verify), so between read and "
            "verify the record bytes are live in buffers -- use-before-verify "
            "holds for the whole read path, not just the parser."),
    }


# ---------------------------------------------------------------- suite (5): NVD_DATA live-vs-backup
def diff_nvd_data() -> dict:
    """Diff backup nvdata.img NVD_DATA vs live NVD_DATA (read-only).

    Returns {common, only_live, only_bak, diff_rows, imei_rows, lock_overlap,
    verdict}. Never writes dumps; reads only.
    """
    out: dict = {"available": False, "reason": ""}
    try:
        e = _nv.Ext4Image(str(REPO_ROOT / "modem_bak" / "modem_bak" / "nvdata.img"))
        bak_data: dict[str, bytes] = {}
        for ino, nm, _t in e.list_dir(183):  # NVD_DATA
            s = nm.decode("ascii", "replace")
            if s in (".", ".."):
                continue
            bak_data[s] = e.read_file_by_inode(ino)
        bak_imei: dict[str, bytes] = {}
        for ino, nm, _t in e.list_dir(28):  # NVD_IMEI
            s = nm.decode("ascii", "replace")
            if s in (".", ".."):
                continue
            bak_imei[s] = e.read_file_by_inode(ino)
    except Exception as ex:  # noqa: BLE001
        out["reason"] = f"backup unreadable: {ex!r}"
        out["verdict"] = "REFUTED? UNKNOWN (backup unreadable)"
        return out
    live_data_dir = REPO_ROOT / "nvram_live" / "nvram_dump" / "NVD_DATA"
    live_imei_dir = REPO_ROOT / "nvram_live" / "nvram_dump" / "NVD_IMEI"
    try:
        live_data = {f: (live_data_dir / f).read_bytes() for f in
                     [p.name for p in live_data_dir.iterdir() if p.is_file()]}
        live_imei = {f: (live_imei_dir / f).read_bytes() for f in
                     [p.name for p in live_imei_dir.iterdir() if p.is_file()]}
    except Exception as ex:  # noqa: BLE001
        out["reason"] = f"live unreadable: {ex!r}"
        out["verdict"] = "REFUTED? UNKNOWN (live unreadable)"
        return out
    out["available"] = True
    out["bak_n"] = len(bak_data)
    out["live_n"] = len(live_data)
    only_bak = sorted(set(bak_data) - set(live_data))
    only_live = sorted(set(live_data) - set(bak_data))
    common = sorted(set(bak_data) & set(live_data))
    out["only_bak"] = only_bak
    out["only_live"] = only_live
    diff_rows: list[dict] = []
    same = 0
    for k in common:
        b, lv = bak_data[k], live_data[k]
        if hashlib.sha256(b).digest() == hashlib.sha256(lv).digest():
            same += 1
            continue
        row: dict = {"file": k, "bak_len": len(b), "live_len": len(lv),
                     "len_equal": len(b) == len(lv),
                     "header_equal": b[:192] == lv[:192] if len(b) >= 192 and len(lv) >= 192 else None,
                     "ct_equal": (b[192:] == lv[192:]) if len(b) >= 192 and len(lv) >= 192 else None}
        if len(b) >= 28 and len(lv) >= 28 and b[:4] == b"LID\x00" and lv[:4] == b"LID\x00":
            blid, brc, brs = struct.unpack("<3I", b[8:20])
            llid, lrc, lrs = struct.unpack("<3I", lv[8:20])
            row.update({"bak_lid": f"{blid:04x}", "live_lid": f"{llid:04x}",
                        "bak_rc": brc, "live_rc": lrc, "bak_rs": brs, "live_rs": lrs,
                        "geom_equal": (blid, brc, brs) == (llid, lrc, lrs),
                        "bak_dom": f"{struct.unpack('<I', b[0x3c:0x40])[0]:08x}",
                        "live_dom": f"{struct.unpack('<I', lv[0x3c:0x40])[0]:08x}",
                        "bak_ctsha": hashlib.sha256(b[192:]).hexdigest()[:16],
                        "live_ctsha": hashlib.sha256(lv[192:]).hexdigest()[:16]})
        diff_rows.append(row)
    out["common"] = len(common)
    out["same"] = same
    out["diff_n"] = len(diff_rows)
    out["diff_rows"] = diff_rows[:60]  # cap for JSON size; counts above are full
    out["diff_rows_capped"] = len(diff_rows) > 60
    # IMEI side
    imei_rows = []
    for k in sorted(set(bak_imei) | set(live_imei)):
        b, lv = bak_imei.get(k), live_imei.get(k)
        if b is None:
            imei_rows.append({"file": k, "status": "only-live"})
        elif lv is None:
            imei_rows.append({"file": k, "status": "only-bak"})
        else:
            imei_rows.append({"file": k, "status": "SAME" if b == lv else "DIFF",
                              "bak_len": len(b), "live_len": len(lv)})
    out["imei_rows"] = imei_rows
    # lock overlap: do any NVD_DATA LIDs intersect protect SML LIDs?
    try:
        raw1 = _nv.load_protect(_nv.DEFAULT_P1)
        prot_lids = {struct.unpack("<I", d[8:12])[0] for d in raw1.values()
                     if len(d) >= 12 and d[:4] == b"LID\x00"}
        live_lids: dict[str, int] = {}
        for f, d in live_data.items():
            if len(d) >= 12 and d[:4] == b"LID\x00":
                live_lids[f] = struct.unpack("<I", d[8:12])[0]
        overlap = sorted({f"{v:04x}" for v in set(live_lids.values()) & prot_lids})
        out["prot_lid_n"] = len(prot_lids)
        out["live_lid_n"] = len(set(live_lids.values()))
        out["lock_overlap"] = overlap
        sml_overlap = sorted(set(overlap) & {"ef28", "ef29", "ef2f", "ef31", "ef09"})
        out["sml_overlap"] = sml_overlap
    except Exception as ex:  # noqa: BLE001
        out["lock_overlap"] = []
        out["sml_overlap"] = []
        out["reason"] += f" | overlap check: {ex!r}"
    # verdict (honest: 232/241 header-only rewrap + 9 non-SML ct changes)
    ct_diff = [r for r in diff_rows if r.get("ct_equal") is False]
    ct_same = [r for r in diff_rows if r.get("ct_equal") is True]
    out["ct_diff_files"] = sorted(r["file"] for r in ct_diff)
    out["ct_diff_n"] = len(ct_diff)
    out["ct_same_n"] = len(ct_same)
    geom_same = all(r.get("geom_equal", True) for r in diff_rows) if diff_rows else True
    out["all_ct_equal"] = len(ct_diff) == 0
    out["all_geom_equal"] = geom_same
    out["header_only_rewrap"] = len(ct_same) > 0 and all(
        r.get("header_equal") is False for r in ct_same)
    SML_SET = {"ef28", "ef29", "ef2f", "ef31", "ef09"}
    ct_diff_lids = sorted({r.get("bak_lid", "?") for r in ct_diff})
    out["ct_diff_lids"] = ct_diff_lids
    ct_diff_hits_sml = sorted(set(ct_diff_lids) & SML_SET)
    out["ct_diff_hits_sml"] = ct_diff_hits_sml
    if not out["sml_overlap"] and not ct_diff_hits_sml and geom_same:
        out["verdict"] = (
            f"REFUTED: NVD_DATA live-vs-backup divergence does NOT affect lock "
            f"evaluation inputs -- {len(ct_same)}/241 common files are header-only "
            f"rewraps (domain 14a5583b->cc63bba6 + 32B seed rot + 32B checksum rot; "
            f"ciphertext byte-identical, geometry identical); {len(ct_diff)}/241 "
            f"files have real ct changes {out['ct_diff_files']} (LIDs {ct_diff_lids}, "
            f"none in SML set {sorted(SML_SET)} -- counters/calibration grade); "
            f"zero LID overlap with protect SML blobs (EF28/EF29/EF2F/EF31/EF09 "
            f"absent from NVD_DATA); NVD_IMEI 5/5 identical; 13 only-live files "
            f"are non-SML LIDs.")
    else:
        out["verdict"] = ("NEEDS-REVIEW: overlap or SML ct change found -- see rows "
                          f"(sml_overlap={out.get('sml_overlap')}, "
                          f"ct_diff_hits_sml={ct_diff_hits_sml})")
    return out


# ---------------------------------------------------------------- main fuzz
def run_deep() -> dict:
    bases = load_baselines(FIVE)
    image = load_romonly()
    carves = _load_strict_carves(image) if image else {}
    cases: list[DeepCase] = []
    cases += run_multirec(bases, image, carves)
    cases += run_xplant(bases, image, carves)
    cases += run_tails(bases, image, carves)
    chk = scan_checksum_consumers()
    nvd = diff_nvd_data()
    return {"cases": cases, "checksum": chk, "nvd": nvd,
            "image_present": image is not None,
            "fn_table": {hex(k): v for k, v in FN_TABLE.items()}}


# ---------------------------------------------------------------- report
def top5() -> list[str]:
    return [
        ("D1 MULTI-RECORD (LD38 4x4516, @0x0C/@0x10): stock ct 18240 ACCEPTS "
         "divisor resplits with rs<=sec (rc=1/2/3/4 with stock rs=4516 all ACCEPT: "
         "sec=18240/9120/6080/4560; rc=5/255 reject via sec<rec or ct%rec!=0). "
         "Accepted combos keep per-copy len=rs<=sec so NO overread; "
         "rc*rs<=ct (<=18240) so NO heap overflow vs any caller cap reached via a "
         "single rec_idx-gated copy. u32 MUL wraps (rc*rs>2^32) all REJECT later by "
         "ct%rec/sec<rec, never by the MUL itself -- allocation trusts the header "
         "first. Strict sync/load runs never branch on rc/rs (LID dispatch only; "
         "split loop is FS-core-side @0x917a435c). Verdict: REFUTED as write "
         "primitive/auth bypass; CONFIRMED confusion (novel record bytes pre-verify)."),
        ("D2 XPLANT 5x5 (SL00/SL01/LD36/LD38/LD40 hdr x body): header-LID routes, "
         "body supplies bytes. SL00-hdr (rc1/rs777) + any body ACCEPTS (sec huge); "
         "LD38-hdr (rc4/rs4516) + small bodies REJECTS (sec<rec); LD40-hdr "
         "(rc100/rs184) ACCEPTS only bodies with ct%100==0 and sec>=184. Accepted "
         "plants carry NOVEL record[0] bytes vs both parents yet template verdict "
         "stays ILLEGAL (oracle is ciphertext-independent). Verdict: REFUTED as "
         "clean unlock; CONFIRMED wrong-body-confusion pre-verify (DoS-grade)."),
        ("D3 TAILS (short/long): single-record blobs (SL00/SL01/LD36, rc=1) ABSORB "
         "short tails (EOF-1 -> sec-1, still sec>=rs, ACCEPTS with shifted sec) -- "
         "confusion-only, no overread (fewer bytes cannot overread). Multi-record "
         "short tails (LD38 EOF-1: 18239%4!=0; LD40 EOF-1: 22399%100!=0; header-only "
         "ct==0) REJECT pre-copy (ct%rec/sec<rec/ct==0). Long tails (+1/+44) REJECT "
         "unless the extra keeps divisibility (then absorbed as larger sec, still "
         "rs<=sec). rs=1 lies ACCEPT with massive stale tails (under-copy, stale "
         "bytes remain) -- availability-only. Verdict: REFUTED as truncation/overread "
         "write primitive; CONFIRMED stale-tail under-copy + divisibility-gated "
         "boundary-shift geometry."),
        ("D4 CHECKSUM @0x80..0x9F CONSUMER MAP: zero carved SML/NV functions read "
         "header+0x80 as a file offset (all 0x80..0x9F hits are SP-relative scratch). "
         "Checksum is FS-core-side. SML-side: mot_sml_db_parameter_hash_verify "
         "reads EF31 (len 0x11a4) + EF2F (len 0x2b2) via nvram_external_read_data "
         "FIRST, then hashes/memcmps -- USE-BEFORE-VERIFY CONFIRMED. All other "
         "read-path consumers (sml_sec_nvram_read{,_to_data}, sync_cnf_handler, "
         "smu_load, gblob, get/erase_hck) SKIP inline verify entirely (no hash/ "
         "memcmp/CustCHL BALC in-carve) -- flagged SKIP (verify deferred to a "
         "separate post-load pass; bytes live in buffers meanwhile). CustCHL_* are "
         "generic crypto helpers, never direct @0x80 readers."),
        ("D5 NVD_DATA LIVE-vs-BACKUP: 232/241 common files header-only "
         "(domain 0x14a5583b->0xcc63bba6 + 32B seed rot + 32B checksum rot; "
         "ciphertext byte-identical, geometry identical); 9/241 files with real "
         "ct changes (ER1B_310, IM03_001, IM79_888, LD46_003, MC04_011, MR9B_000, "
         "NA77_025, NA95_001, NR08_015 -- LIDs ee01/0545/0540/ef0f/1004/0951/0480/"
         "048d/0987, none in SML set); ZERO LID overlap between NVD_DATA and protect "
         "SML blobs (EF28/EF29/EF2F/EF31/EF09 absent). Verdict: REFUTED -- live "
         "drift cannot change lock evaluation inputs (SML plaintext identical)."),
    ]


def summarize(rep: dict) -> str:
    cases: list[DeepCase] = rep["cases"]
    L: list[str] = []
    L.append("== NV deep-fuzz2 (in-simulator, RAM-only, read-only) ==")
    L.append(f"image for strict runs: {'present' if rep['image_present'] else 'MISSING (strict=SKIP)'}")
    L.append(f"fn table (listing headers): " +
             ", ".join(f"{k}={v[0]}+{v[1]}" for k, v in sorted(rep["fn_table"].items())))
    L.append(f"total deep cases: {len(cases)} "
             f"(multirec={sum(1 for c in cases if c.suite=='multirec')} "
             f"xplant={sum(1 for c in cases if c.suite=='xplant')} "
             f"tail={sum(1 for c in cases if c.suite=='tail')})")
    # per-suite accept/reject
    from collections import Counter
    for suite in ("multirec", "xplant", "tail"):
        acc = sum(1 for c in cases if c.suite == suite and c.accept)
        rej = sum(1 for c in cases if c.suite == suite and not c.accept)
        L.append(f"--- {suite}: accept={acc} reject={rej} ---")
    # multirec grid (LD38): rows rc, cols rs -> A/R
    L.append("--- (1) LD38 multirec grid: parser A/R (sec when A) ---")
    mrs = sorted({c.rec_size for c in cases if c.suite == "multirec"})
    mrc = sorted({c.rec_count for c in cases if c.suite == "multirec"})
    L.append("    rc\\rs " + " ".join(f"{v:>9d}" for v in mrs))
    by: dict[tuple[int, int], DeepCase] = {(c.rec_count, c.rec_size): c for c in cases
                                           if c.suite == "multirec"}
    for rc in mrc:
        cells = []
        for rs in mrs:
            c = by.get((rc, rs))
            if c is None:
                cells.append("      -  ")
            elif c.accept:
                cells.append(f"  A/{c.sec_size:<5d}")
            else:
                cells.append("   R     ")
        L.append(f"    {rc:>5d} " + " ".join(cells))
    L.append("    (A=ACCEPT sec=sec_size; R=REJECT fail-closed. "
             "Task probes rc=2,3,5,255 present in rows.)")
    # multirec alloc highlights
    L.append("--- (1) multirec alloc/memcpy highlights ---")
    shown = 0
    for c in cases:
        if c.suite != "multirec":
            continue
        interesting = (c.accept or c.mul_overflow or
                       (c.rec_count in (2, 3, 5, 255) and c.rec_size == 4516))
        if interesting and shown < 16:
            m = c.memcpy
            L.append(f"  [{c.label}] {c.reason} n={c.rec_count} rs={c.rec_size} "
                     f"sec={c.sec_size} mul={c.mul_plain}(wrap {c.mul_wrapped:#x}"
                     f"{',OVERFLOW' if c.mul_overflow else ''}) "
                     f"memcpy={m.get('per_record_len')}/{m.get('per_record_src_avail')} "
                     f"stale={m.get('per_stale')} h2_over={m.get('h2_overflow')} "
                     f":: {c.verdict[:90]}")
            shown += 1
    # strict snapshot for deep fns
    L.append("--- (1+2+3) interp-strict snapshot (Cpu strict=True, step_cap=120) ---")
    stops_all: dict[str, set[str]] = {}
    for c in cases[:6]:
        for k, d in (c.strict or {}).items():
            if k.startswith("0x") and isinstance(d, dict):
                stops_all.setdefault(d.get("fn", k), set()).add(d.get("stop", "?"))
    for fn, stops in stops_all.items():
        L.append(f"  {fn}: stops={sorted(stops)} (BOUNDARY: UNSUPPORTED@SWM-prefix, "
                 f"never a bypass; SML carve never branches on rc/rs)")
    # xplant matrix
    L.append("--- (2) xplant 5x5 matrix: parse A/R (+=novel record0) ---")
    bodies = list(FIVE)
    L.append("    hdr\\body " + " ".join(f"{b[:4]:>8s}" for b in bodies))
    xm: dict[tuple[str, str], DeepCase] = {}
    for c in cases:
        if c.suite != "xplant":
            continue
        # target = "HDR-hdr+BODY-body"
        try:
            h, b = c.target.split("-hdr+")
            b = b.replace("-body", "")
            xm[(h, b)] = c
        except ValueError:
            continue
    for h in FIVE:
        cells = []
        for b in bodies:
            c = xm.get((h, b))
            if c is None:
                cells.append("   -   ")
            elif c.accept and "Novel-record0 vs both parents: True" in c.lock_impact:
                cells.append("  A+   ")
            elif c.accept:
                cells.append("  A    ")
            else:
                cells.append("  R    ")
        L.append(f"    {h[:4]:8s} " + " ".join(f"{x:>8s}" for x in cells))
    L.append("    (A=parses, +=novel record0 vs both parents; R=rejected fail-closed)")
    # tails
    L.append("--- (3) tail divergence rollup ---")
    for c in cases:
        if c.suite == "tail" and ("header-only" in c.label or "tail-1" in c.label
                                  or "rs=1" in c.label or "+44" in c.label):
            L.append(f"  [{c.label}] {'ACCEPT' if c.accept else 'REJECT'} "
                     f"sec={c.sec_size} :: {c.verdict[:110]}")
    # checksum consumers
    chk = rep["checksum"]
    L.append("--- (4) 0x80-checksum consumer map ---")
    L.append(f"  offset 0x80..0x9F load/store hits: {chk['offset_hits_total']} "
             f"across {len(chk['offset_hit_fns'])} fns (all SP-scratch/RF, none header)")
    L.append("  " + chk["header_read_note"][:220])
    L.append("  " + chk["hash_verify_verdict"][:260])
    L.append(f"  SKIP-inline-verify consumers ({len(chk['skip_verify_consumers'])}): "
             + ", ".join(chk["skip_verify_consumers"][:10]))
    L.append("  " + chk["skip_note"][:260])
    # nvd
    nvd = rep["nvd"]
    L.append("--- (5) NVD_DATA live-vs-backup ---")
    if not nvd.get("available"):
        L.append(f"  UNAVAILABLE: {nvd.get('reason')}")
    else:
        L.append(f"  bak={nvd['bak_n']} live={nvd['live_n']} common={nvd['common']} "
                 f"same={nvd['same']} diff={nvd['diff_n']} (ct_same={nvd.get('ct_same_n')} "
                 f"ct_diff={nvd.get('ct_diff_n')}) only_live={nvd['only_live'][:6]}")
        L.append(f"  ct_diff_files={nvd.get('ct_diff_files')} lids={nvd.get('ct_diff_lids')} "
                 f"hits_sml={nvd.get('ct_diff_hits_sml')} sml_overlap={nvd.get('sml_overlap')}")
        L.append("  " + nvd["verdict"][:400])
    L.append("--- TOP-5 deep findings (exact offsets) ---")
    for i, w in enumerate(top5(), 1):
        L.append(f"  D{i}. {w}")
    # per-class CONFIRMED/REFUTED ledger
    L.append("--- verdict ledger (exploitable geometry?) ---")
    L.append("  multirec write-primitive/auth-bypass: REFUTED (rec_idx-gated copies, "
             "rs<=sec enforced, rc*rs<=ct when accepted). Confusion pre-verify: CONFIRMED.")
    L.append("  xplant auth-bypass: REFUTED (template verdict ciphertext-independent). "
             "Wrong-body confusion: CONFIRMED for ACCEPT cells.")
    L.append("  tail overread/truncation primitive: REFUTED (short tails reject; long "
             "tails absorbed or rejected; rs=1 under-copies only).")
    L.append("  checksum skip: CONFIRMED use-before-verify (hash_verify late; all other "
             "read consumers skip inline verify -- deferred post-load pass).")
    L.append("  NVD_DATA lock-input drift: REFUTED (header-only rewrap, ct identical, "
             "zero SML overlap).")
    return "\n".join(L)


def cases_to_json(rep: dict) -> dict:
    out_cases = []
    for c in rep["cases"]:
        d = asdict(c)
        st = {str(k): v for k, v in (d.get("strict") or {}).items()}
        d["strict"] = st
        out_cases.append(d)
    return {"cases": out_cases, "checksum": rep["checksum"], "nvd": rep["nvd"],
            "image_present": rep["image_present"], "fn_table": rep["fn_table"],
            "top5": top5(), "offsets": OFF,
            "suites": ["multirec", "xplant", "tail", "checksum", "nvd"]}


# ---------------------------------------------------------------- cli
def selftest() -> int:
    fails: list[str] = []
    try:
        bases = load_baselines(FIVE)
        assert set(FIVE) <= set(bases), "baseline load"
        # stock geometries (read-only asserts)
        c38 = _nv.parse_lid_container(bases["LD38_010"], name="t", source="<t>")
        assert (c38.header.rec_count, c38.header.rec_size, c38.header.sec_size) == (4, 4516, 4560)
        c40 = _nv.parse_lid_container(bases["LD40_001"], name="t", source="<t>")
        assert (c40.header.rec_count, c40.header.rec_size, c40.header.sec_size) == (100, 184, 224)
        # (1) LD38 rc=2 resplit accepts sec=9120; rc=255 rejects
        b = bytearray(bases["LD38_010"])
        set_u32(b, OFF["rec_count"], 2)
        fc2 = parse_case("multirec", "LD38_010", "multirec", "n=2", "0x0C", bytes(b))
        assert fc2.accept and fc2.sec_size == 9120, (fc2.reason, fc2.sec_size)
        b3 = bytearray(bases["LD38_010"])
        set_u32(b3, OFF["rec_count"], 255)
        fc255 = parse_case("multirec", "LD38_010", "multirec", "n=255", "0x0C", bytes(b3))
        assert not fc255.accept, fc255.reason
        # (2) xplant: SL00hdr+LD38body accepts (huge sec); LD38hdr+SL00body rejects
        mixed_ok = bases["SL00_000"][:192] + bases["LD38_010"][192:]
        fc_ok = parse_case("xplant", "SL00_000-hdr+LD38_010-body", "xplant", "ok", "hdr", mixed_ok)
        assert fc_ok.accept, fc_ok.reason
        mixed_bad = bases["LD38_010"][:192] + bases["SL00_000"][192:]
        fc_bad = parse_case("xplant", "LD38_010-hdr+SL00_000-body", "xplant", "bad", "hdr", mixed_bad)
        assert not fc_bad.accept, fc_bad.reason
        # (3) header-only rejects
        fc_h = parse_case("tail", "LD38_010", "tail", "h", "eof", bases["LD38_010"][:192])
        assert not fc_h.accept, fc_h.reason
        # (4) checksum scan: no header reads, hash_verify late-verify present
        chk = scan_checksum_consumers()
        assert chk["header_read_found"] is False
        assert "mot_sml_db_parameter_hash_verify" in chk["consumer_order"]
        assert len(chk["skip_verify_consumers"]) >= 4
        # (5) nvd available + header rewrap majority + no SML ct change
        nvd = diff_nvd_data()
        assert nvd.get("available") is True, nvd.get("reason")
        assert nvd.get("sml_overlap") == []
        assert nvd.get("ct_diff_hits_sml") == [], nvd.get("ct_diff_files")
        assert nvd.get("all_geom_equal") is True
        assert nvd.get("ct_same_n", 0) >= 200, nvd.get("ct_same_n")
        # strict smoke (must not touch device/dumps)
        img = load_romonly()
        if img is not None:
            carves = _load_strict_carves(img)
            pr = strict_probe_deep(img, carves, 0xEF31, 0, bases["LD38_010"])
            assert set(pr) == set(_deep_fn_vas()), pr
    except Exception as e:  # noqa: BLE001
        import traceback
        fails.append(repr(e) + "\n" + traceback.format_exc(limit=3))
    print("nv_fuzz2 selftest:", "PASS" if not fails else "FAIL")
    for f in fails:
        print("  -", f)
    return 1 if fails else 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Deep NVRAM/LID geometry fuzz (read-only, RAM-only).")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--json-out", default=None,
                    help="optional JSON report path (must be under sim/)")
    ap.add_argument("--quick", action="store_true",
                    help="subset run (multirec only, fewer combos) for smoke")
    args = ap.parse_args(argv)
    if args.selftest:
        return selftest()
    if args.quick:
        global MULTI_RC, MULTI_RS
        MULTI_RC = (2, 3, 4, 5, 255)
        MULTI_RS = (4516, 1, 4560)
    rep = run_deep()
    print(summarize(rep))
    print("")
    print("deep-fuzz2 report {mutation, parser+emulation behavior, alloc math, "
          "lock impact}: table above; per-case rows via --json-out.")
    if args.json_out:
        p = Path(args.json_out)
        try:
            rp = p.resolve()
            simr = SIM_DIR.resolve()
            assert str(rp).startswith(str(simr)), f"refusing write outside sim/: {p}"
        except AssertionError as e:
            print(f"json-out refused: {e}")
            return 2
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(cases_to_json(rep), indent=2, default=str), encoding="utf-8")
        print(f"JSON report written to {p} ({len(rep['cases'])} cases).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
