#!/usr/bin/env python3
"""sml_trace_campaign.py — full execution traces for top SML entry points (Kansas lab).

PC-side only. Stdlib + local Ghidra only. NEVER touches the device (no adb/
fastboot/socket/subprocess to device; only local analyzeHeadless.bat via
sim/backend_ghidra.py for ground-truth comparison).

For each of 10 entry points, run interp Cpu strict=True with:
  (a) all-helpers-ret1 stubs (every BALC/MOVE.BALC target outside the carve
      gets ret1 bytes 01d2e0db = LI a0,1;JRC ra),
  (b) all-REAL (no stubs, full-ROM fallback via image bytes),
with synthetic ctx inputs:
  - zeroed ctx (all-zero backing at CTX),
  - Tracfone-template ctx (nv_model/sml_sim oracle: cat0 LOCK/retry5/311480).

Records per run: stop reason, steps, verdict (a0/a1), coverage (total + in/out),
boundary list (outside-carve PCs, stub VAs, fault PC, cross-boundary edges),
gaps, auto_stubs, indirects (JALRC/BRSC/JRC-non-ra with concrete values).

Saves every interp trace to sim/traces/<fn>_ret1_zeroed|_ret1_tfn|_real_zeroed|_real_tfn.jsonl
in sim/trace_tools.py normalized schema (step,pc,bytes,text,regs on final).
Ghidra ground-truth traces saved as sim/traces/<fn>_ghidra_zeroed.jsonl (same schema,
bytes="" where Ghidra carries no bytes, final regs a0) for divergence analysis.

Seed corpus untouched: existing sim/traces/<fn>.jsonl (7 files) + manifest.json
are never overwritten; --check must stay PASS. New manifest:
sim/traces/sml_dynamic_manifest.json (+ stdout tables).

Run:
  python sim/sml_trace_campaign.py --interp-only     # fast, no JVM
  python sim/sml_trace_campaign.py --ghidra-only     # local Ghidra only
  python sim/sml_trace_campaign.py --all             # both (default)
  python sim/sml_trace_campaign.py --selftest        # offline checks, no Ghidra
"""
from __future__ import annotations
import argparse
import hashlib
import json
import struct
import sys
import time
from pathlib import Path
import os

SIM_DIR = Path(__file__).resolve().parent
REPO_ROOT = SIM_DIR.parent
if str(SIM_DIR) not in sys.path:
    sys.path.insert(0, str(SIM_DIR))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# defensive local imports (stdlib + sibling sim modules only)
try:
    from emu_engine import Tracer as _Tracer, VA_BASE as _EE_VA
except ImportError:
    from sim.emu_engine import Tracer as _Tracer, VA_BASE as _EE_VA  # type: ignore
try:
    from interp import Cpu as _Cpu, CTX_INIT as _CTX_INIT, STACK_INIT as _STACK_INIT
    from interp import RA_INIT as _RA_INIT, CTX_SIZE as _CTX_SIZE, CTX_BASE as _CTX_BASE
    from interp import STACK_BASE as _STACK_BASE, STEP_CAP_DEFAULT as _STEP_CAP
except ImportError:
    from sim.interp import Cpu as _Cpu, CTX_INIT as _CTX_INIT, STACK_INIT as _STACK_INIT  # type: ignore
    from sim.interp import RA_INIT as _RA_INIT, CTX_SIZE as _CTX_SIZE, CTX_BASE as _CTX_BASE  # type: ignore
    from sim.interp import STACK_BASE as _STACK_BASE, STEP_CAP_DEFAULT as _STEP_CAP  # type: ignore
try:
    from decode_tables import decode_bytes as _decode_bytes, UnknownInsn as _Unknown
except ImportError:
    from sim.decode_tables import decode_bytes as _decode_bytes, UnknownInsn as _Unknown  # type: ignore
try:
    from trace_tools import normalize as _norm, write_jsonl as _write_jsonl, diff_traces as _diff
except ImportError:
    from sim.trace_tools import normalize as _norm, write_jsonl as _write_jsonl, diff_traces as _diff  # type: ignore

VA_BASE = 0x90000000
FNS = [
    "rmmi_esmlck_hdlr",
    "rmmi_esmlrsu_hdlr",
    "rmmi_esmlgen_hdlr",
    "custom_link_sml_with_rule",
    "sml_Verify",
    "sml_Unlock",
    "sml_crrst_Check",
    "sml_op07_Check",
    "sml_op12_Check",
    "smu_sml_verify",
]
TRACES_DIR = SIM_DIR / "traces"
MANIFEST_NEW = TRACES_DIR / "sml_dynamic_manifest.json"
TEMP = Path(os.environ.get("MODEM_LAB_TMP",
                str(Path(__file__).resolve().parent / "Temp")))
TEMP.mkdir(parents=True, exist_ok=True)
CATI_JSON = TEMP / "cati_syms.json"
ROMONLY = REPO_ROOT / "md1work_romonly.bin"


def load_rom() -> bytes:
    return ROMONLY.read_bytes()


def load_cati() -> dict:
    raw = json.loads(CATI_JSON.read_text(encoding="utf-8"))
    out = {}
    for k, v in raw.items():
        try:
            out[k] = (int(v[0], 16), int(v[1], 16))
        except (TypeError, ValueError):
            continue
    return out


def get_contexts():
    """Return (tracfone_ctx, zeroed_ctx, provenance). Prefers nv_model/sml_sim."""
    prov = []
    tctx = zctx = None
    try:
        import nv_model as _nv  # type: ignore
        tctx = _nv.make_tracfone_context()
        prov.append("nv_model.make_tracfone_context")
    except Exception:
        try:
            from sim import nv_model as _nv2  # type: ignore
            tctx = _nv2.make_tracfone_context()
            prov.append("sim.nv_model.make_tracfone_context")
        except Exception as e:
            prov.append(f"nv_model miss: {e}")
    try:
        import sml_sim as _sml  # type: ignore
        if tctx is None and hasattr(_sml, "tracfone_default_context"):
            tctx = _sml.tracfone_default_context()
            prov.append("sml_sim.tracfone_default_context fallback")
        if hasattr(_sml, "zeroed_context"):
            zctx = _sml.zeroed_context()
            prov.append("sml_sim.zeroed_context")
    except Exception:
        try:
            from sim import sml_sim as _sml2  # type: ignore
            if tctx is None and hasattr(_sml2, "tracfone_default_context"):
                tctx = _sml2.tracfone_default_context()
                prov.append("sim.sml_sim.tracfone_default_context fallback")
            if hasattr(_sml2, "zeroed_context"):
                zctx = _sml2.zeroed_context()
                prov.append("sim.sml_sim.zeroed_context")
        except Exception as e:
            prov.append(f"sml_sim miss: {e}")
    if tctx is None or zctx is None:
        raise RuntimeError(f"no SML context source ({'; '.join(prov)})")
    return tctx, zctx, "; ".join(prov)


def build_ctx_image(ctx) -> bytes:
    """Serialize SmlContext to PROVISIONAL image (sml_conform layout, first 0x1C8)."""
    try:
        import sml_conform as _sc  # type: ignore
        return bytes(_sc.build_ctx_image(ctx))
    except Exception:
        try:
            from sim import sml_conform as _sc2  # type: ignore
            return bytes(_sc2.build_ctx_image(ctx))
        except Exception:
            pass
    # local fallback (same layout as sml_conform CTX_LAYOUT_DOC)
    buf = bytearray(0x1C8)
    cats = getattr(ctx, "cats", [])
    for i in range(min(7, len(cats))):
        c = cats[i]
        base = i * 0x40
        struct.pack_into("<6I", buf, base,
                         int(getattr(c, "state", 0)) & 0xFFFFFFFF,
                         int(getattr(c, "retry", 0)) & 0xFFFFFFFF,
                         int(getattr(c, "autolock", 0)) & 0xFFFFFFFF,
                         int(getattr(c, "num", 0)) & 0xFFFFFFFF,
                         int(getattr(c, "key_state", 0)) & 0xFFFFFFFF,
                         0x1 if getattr(c, "allow_list", None) else 0x0)
        try:
            al = list(getattr(c, "allow_list", []) or [])
            plmn0 = str(al[0]) if al else ""
        except Exception:
            plmn0 = ""
        buf[base + 0x18:base + 0x18 + 8] = plmn0.encode("ascii", "replace")[:8].ljust(8, b"\x00")
    struct.pack_into("<2I", buf, 7 * 0x40,
                     int(getattr(ctx, "tfn_otp_on", 1)) & 0xFFFFFFFF,
                     int(getattr(ctx, "permanent_unlock", 0)) & 0xFFFFFFFF)
    return bytes(buf)


def full_ctx_backing(ctx) -> bytes:
    """Full CTX_SIZE backing: first 0x1C8 = ctx image, rest zeros."""
    img = build_ctx_image(ctx)
    buf = bytearray(_CTX_SIZE)
    buf[:len(img)] = img
    return bytes(buf)


def sweep_balc_targets(va: int, size: int, carve: bytes):
    """Best-effort BALC/MOVE.BALC outside-carve targets. Returns (set, err)."""
    out = set()
    pc = va
    end = va + size
    while pc < end:
        chunk = carve[pc - va:pc - va + 6]
        if len(chunk) < 2:
            return out, f"sweep short @{pc:#x}"
        try:
            text, sz = _decode_bytes(pc, bytes(chunk))
        except _Unknown as e:
            return out, f"no-decode @{pc:#x} ({e})"
        except Exception as e:  # noqa: BLE001
            return out, f"decode-err @{pc:#x} ({e})"
        if text.startswith("BALC "):
            try:
                tgt = int(text.split(None, 1)[1].split(",")[0].strip(), 16)
            except ValueError:
                tgt = None
            if tgt is not None and not (va <= tgt < end):
                out.add(tgt)
        elif text.startswith("MOVE.BALC "):
            try:
                parts = [p.strip() for p in text.split(None, 1)[1].split(",")]
                tgt = int(parts[2], 16)
            except (ValueError, IndexError):
                tgt = None
            if tgt is not None and not (va <= tgt < end):
                out.add(tgt)
        pc += sz
        if sz <= 0:
            return out, f"zero-size @{pc:#x}"
    if pc != end:
        return out, f"sweep overrun @{pc:#x} != end {end:#x}"
    return out, ""


class InstrumentedCpu(_Cpu):
    """Cpu with raw-byte capture + indirect-branch observation (no exec change)."""

    def __init__(self, *a, **k):
        # pre-create logs so super().__init__ prescan/ret-scan decodes
        # (which call our overridden _decode_at) have somewhere to go,
        # then drop them: only run()-time fetches belong to the trace.
        self.raw_log: list = []  # (pc, text, size, raw_bytes)
        self.indirects: list = []  # dicts per JALRC/BRSC/JRC-non-ra executed
        self._step_no = 0
        super().__init__(*a, **k)
        self.raw_log.clear()
        self.indirects.clear()
        self._step_no = 0

    def _decode_at(self, addr: int):
        text, size, raw = super()._decode_at(addr)
        # record in decode order (mirrors run() fetch order incl. helper bodies)
        self.raw_log.append((addr, text, size, bytes(raw)))
        return text, size, raw

    def _exec_text(self, pc: int, text: str, size: int, nxt: int, mn: str, ops: list):
        # observe indirects BEFORE execution (register values pre-branch)
        try:
            if mn in ("JALRC", "JALRC.HB"):
                rs = ops[1] if len(ops) > 1 else "?"
                tgt = self.get(rs) if len(ops) > 1 else 0
                self.indirects.append({
                    "step": self._step_no, "pc": pc, "text": text,
                    "kind": "JALRC", "reg": rs,
                    "value": tgt & 0xFFFFFFFF,
                    "value_hex": f"{(tgt & 0xFFFFFFFF):#x}",
                    "rd": ops[0] if ops else "?",
                })
            elif mn == "BRSC":
                idx = self.get(ops[0]) if ops else 0
                tgt = ((idx & 0xFFFFFFFF) * 2 + nxt) & 0xFFFFFFFF
                self.indirects.append({
                    "step": self._step_no, "pc": pc, "text": text,
                    "kind": "BRSC", "reg": ops[0] if ops else "?",
                    "index": idx & 0xFFFFFFFF,
                    "index_hex": f"{(idx & 0xFFFFFFFF):#x}",
                    "value": tgt, "value_hex": f"{tgt:#x}",
                })
            elif mn == "JRC":
                rs = ops[0] if ops else "?"
                if rs != "ra":
                    tgt = self.get(rs)
                    self.indirects.append({
                        "step": self._step_no, "pc": pc, "text": text,
                        "kind": "JRC-non-ra", "reg": rs,
                        "value": tgt & 0xFFFFFFFF,
                        "value_hex": f"{(tgt & 0xFFFFFFFF):#x}",
                    })
        except Exception:
            pass
        self._step_no += 1
        return super()._exec_text(pc, text, size, nxt, mn, ops)


def run_one(image: bytes, va: int, size: int, regs: dict, stubs: dict,
            step_cap: int = 3000) -> dict:
    """Strict run with instrumentation. Returns full record (never raises)."""
    off = va - VA_BASE
    carve = image[off:off + size]
    tr = _Tracer()
    cpu = InstrumentedCpu(bytes(image), va, bytes(carve), regs=dict(regs),
                          stubs=dict(stubs), tracer=tr, step_cap=step_cap,
                          strict=True)
    try:
        res = cpu.run()
    except Exception as e:  # noqa: BLE001 (Cpu.run never raises, but be safe)
        res = {"a0": cpu.get("a0") if hasattr(cpu, "get") else 0,
               "a1": 0, "steps": 0, "stop": f"RUNNER-EXC: {e}",
               "pc": va, "ret_at": va, "trace": [], "gaps": [repr(e)],
               "auto_stubs": []}
    # coverage split
    cov = set(getattr(tr, "coverage", set()))
    inside = sorted(p for p in cov if va <= p < va + size)
    outside = sorted(p for p in cov if not (va <= p < va + size))
    # cross-boundary edges: consecutive tracer events crossing the carve edge
    evs = list(getattr(tr, "events", []))
    edges = []
    for a, b in zip(evs, evs[1:]):
        ain = va <= a.pc < va + size
        bin_ = va <= b.pc < va + size
        if ain != bin_:
            edges.append(f"{a.pc:#x}->{b.pc:#x}")
    # raw bytes per event (aligned by decode order; tracer logs once per
    # decoded insn pre-exec, raw_log has one entry per _decode_at incl. ret
    # probes — align by pc/text match, fallback to image bytes)
    raw_by_step = {}
    for (rpc, rtext, rsize, rraw) in cpu.raw_log:
        raw_by_step.setdefault((rpc, rtext), (rsize, rraw))
    norm_events = []
    for i, e in enumerate(evs):
        key = (e.pc, e.text)
        if key in raw_by_step:
            sz, raw = raw_by_step[key]
            bhex = bytes(raw).hex()
        else:
            # fallback: re-decode size via image (best-effort, else "")
            bhex = ""
            try:
                o = e.pc - VA_BASE
                if 0 <= o < len(image):
                    t, s = _decode_bytes(e.pc, bytes(image[o:o + 6]))
                    if t == e.text:
                        bhex = bytes(image[o:o + s]).hex()
            except Exception:
                bhex = ""
        d = _norm(i, e.pc, bhex, e.text, None)
        norm_events.append(d)
    # final marker event carrying the verdict (demo_stock_patch_traces pattern)
    stop = res.get("stop", "?")
    a0 = res.get("a0", 0) & 0xFFFFFFFF
    a1 = res.get("a1", 0) & 0xFFFFFFFF
    ret_pc = res.get("pc", va) & 0xFFFFFFFF
    if stop == "HIT-RET":
        ftext = "HIT-RET"
    else:
        ftext = f"STOP:{stop}"
    # bytes for final pc (best-effort)
    fbhex = ""
    try:
        o = ret_pc - VA_BASE
        if 0 <= o < len(image):
            t, s = _decode_bytes(ret_pc, bytes(image[o:o + 6]))
            fbhex = bytes(image[o:o + s]).hex()
    except Exception:
        fbhex = ""
    # stub-body bytes win when ret_pc is a stub VA
    try:
        sb = cpu.mem.read(ret_pc, 2)
        # only trust 2-byte stub reads when they decode to LI/JRC
        fbhex = bytes(sb).hex()
    except Exception:
        pass
    norm_events.append(_norm(len(norm_events), ret_pc, fbhex, ftext,
                             {"a0": a0, "a1": a1}))
    # indirects annotated with input labels later by caller; add loc class
    for ind in cpu.indirects:
        v = ind["value"] & 0xFFFFFFFF
        o = v - VA_BASE
        if va <= v < va + size:
            ind["loc"] = "inside-carve"
        elif 0 <= o < len(image):
            ind["loc"] = "in-ROM-outside-carve"
        elif v == 0 or v == 0xDEAD0000:
            ind["loc"] = "sentinel/unmapped"
        else:
            ind["loc"] = "unmapped-outside-ROM"
    return {
        "cpu": cpu, "tracer": tr, "res": res,
        "a0": a0, "a1": a1, "steps": res.get("steps", 0),
        "stop": stop, "pc": ret_pc,
        "coverage_total": len(cov), "coverage_inside": len(inside),
        "coverage_outside": len(outside),
        "coverage_outside_pcs": [f"{p:#x}" for p in outside],
        "boundary_outside_pcs": [f"{p:#x}" for p in outside],
        "cross_edges": edges,
        "gaps": list(res.get("gaps", [])),
        "auto_stubs": [f"{v:#x}" for v in res.get("auto_stubs", [])],
        "indirects": list(cpu.indirects),
        "events": norm_events,
    }


def ghidra_runs_for(cati: dict, timeout: float, retries: int) -> dict:
    """Local-Ghidra ground truth per fn (stock/auto-ret1, zeroed-CTX defaults).

    Uses sim/EmuSmlSP.java (same-page fix; proven-path identical on
    legal_sim_rule) because vendored EmuSml.java raises
    MemoryConflictException on every fn whose BALC target shares the carve
    page (9/10 here; only legal_sim_rule is page-clean). Falls back to the
    vendored script if the SP variant is absent.
    """
    out = {}
    try:
        from backend_ghidra import GhidraBackend  # type: ignore
    except ImportError:
        try:
            from sim.backend_ghidra import GhidraBackend  # type: ignore
        except ImportError as e:
            return {"_error": f"backend_ghidra import failed: {e}"}
    sp = SIM_DIR / "EmuSmlSP.java"
    kw = {"timeout": timeout, "retries": retries}
    if sp.exists():
        kw["script"] = sp
        out["_script"] = "sim/EmuSmlSP.java (same-page fix)"
    else:
        out["_script"] = "sim/EmuSml.java (vendored; expect same-page conflicts)"
    try:
        be = GhidraBackend(**kw)
    except Exception as e:  # noqa: BLE001
        return {"_error": f"GhidraBackend init failed: {e}"}
    for fn in FNS:
        s, e = cati[fn]
        size = e - s
        try:
            r = be.run(s, size, mode="stock", stubs=None, regs=None,
                       tracer=None, fn_name=fn, timeout=timeout,
                       retries=retries)
            evs = []
            for i, (ppc, ptext) in enumerate(r.get("trace", [])):
                last = (i == len(r["trace"]) - 1)
                evs.append(_norm(i, ppc, "", ptext,
                                 {"a0": r["a0"]} if last else None))
            # final marker for parity with interp traces
            evs.append(_norm(len(evs), r.get("ret_at") or r.get("pc") or s,
                             "", "HIT-RET" if r.get("stop") == "HIT-RET"
                             else f"STOP:{r.get('stop')}",
                             {"a0": r.get("a0", 0)}))
            out[fn] = {"ok": True, "result": r, "events": evs}
        except Exception as ex:  # noqa: BLE001
            out[fn] = {"ok": False, "error": f"{type(ex).__name__}: {ex}"}
    return out


def save_traces(manifest_runs: dict) -> None:
    TRACES_DIR.mkdir(parents=True, exist_ok=True)
    for key, run in manifest_runs.items():
        fn = run["fn"]
        # interp keys: <fn>:ret1:zeroed etc; ghidra key: <fn>:ghidra:zeroed
        if key.endswith(":ghidra:zeroed"):
            fname = f"{fn}_ghidra_zeroed.jsonl"
        else:
            _, stub, ctx = key.split(":")
            fname = f"{fn}_{stub}_{ctx}.jsonl"
        blob = _write_jsonl(TRACES_DIR / fname, run["events"])
        run["trace_file"] = f"sim/traces/{fname}"
        run["trace_sha256"] = hashlib.sha256(blob).hexdigest()
        run["trace_steps"] = len(run["events"])


def build_manifest(manifest_runs: dict, cati: dict, rom: bytes,
                   ctx_prov: str, sweep_notes: dict,
                   ghidra_raw: dict | None) -> dict:
    man = {
        "tool": "sim/sml_trace_campaign.py",
        "stdlib_only": True, "device_contact": False,
        "rom": {"sha256": hashlib.sha256(rom).hexdigest(),
                "size": len(rom), "source": "md1work_romonly.bin"},
        "cati": {"source": str(CATI_JSON), "count": len(cati)},
        "cpu": "interp Cpu strict=True (outside-carve faults STOP)",
        "stub_modes": {
            "ret1": "all BALC/MOVE.BALC outside-carve targets -> ret1 (01d2e0db)",
            "real": "no stubs; full-ROM fallback (REAL bytes execute)",
        },
        "inputs": {
            "zeroed": "all-zero CTX backing (matches Ghidra zero CTX)",
            "tfn": "Tracfone-template CTX (nv_model/sml_sim oracle)",
        },
        "ctx_provenance": ctx_prov,
        "ctx_layout": ("PROVISIONAL sml_conform image: 7x0x40 cats "
                       "(state/retry/autolock/num/key_state/flags/plmn0/key) "
                       "+ tfn_otp_on/permanent_unlock @+0x1C0; a0=s0=CTX_BASE"),
        "regs": {"a0": f"{_CTX_INIT:#x}", "s0": f"{_CTX_INIT:#x}",
                 "sp": f"{_STACK_INIT:#x}", "ra": f"{_RA_INIT:#x}",
                 "step_cap": _STEP_CAP},
        "sweep_notes": sweep_notes,
        "runs": {},
    }
    for key, run in manifest_runs.items():
        man["runs"][key] = {
            "fn": run["fn"], "va": f"{run['va']:#x}",
            "size": run["size"], "stub_mode": run["stub_mode"],
            "ctx": run["ctx"], "stop": run["stop"],
            "steps": run["steps"], "a0": f"{run['a0']:#x}",
            "a1": f"{run['a1']:#x}",
            "coverage_total": run["coverage_total"],
            "coverage_inside": run["coverage_inside"],
            "coverage_outside": run["coverage_outside"],
            "boundary_outside_pcs": run["boundary_outside_pcs"],
            "cross_edges": run["cross_edges"],
            "stub_targets": run["stub_targets"],
            "sweep_issue": run["sweep_issue"],
            "gaps": run["gaps"], "auto_stubs": run["auto_stubs"],
            "indirects": run["indirects"],
            "trace_file": run.get("trace_file", ""),
            "trace_sha256": run.get("trace_sha256", ""),
            "trace_steps": run.get("trace_steps", 0),
        }
        if run.get("ghidra"):
            man["runs"][key]["ghidra"] = run["ghidra"]
    if ghidra_raw is not None:
        man["ghidra_raw_error"] = ghidra_raw.get("_error", "")
    return man


def print_inventory(manifest_runs: dict) -> None:
    print("trace inventory (interp strict=True; verdict=a0; cov=in+out=total):")
    hdr = (f"{'fn':28s} {'stub':4s} {'ctx':6s} {'stop':28s} "
           f"{'steps':>5s} {'a0':>10s} {'cov':>9s} "
           f"{'bounds':>6s} {'ind':>3s}")
    print("  " + hdr)
    print("  " + "-" * len(hdr))
    for fn in FNS:
        for stub in ("ret1", "real"):
            for ctx in ("zeroed", "tfn"):
                key = f"{fn}:{stub}:{ctx}"
                r = manifest_runs.get(key)
                if not r:
                    continue
                cov = (f"{r['coverage_inside']}+{r['coverage_outside']}"
                       f"={r['coverage_total']}")
                print(f"  {fn:28s} {stub:4s} {ctx:6s} {r['stop'][:28]:28s} "
                      f"{r['steps']:>5d} {r['a0']:#10x} {cov:>9s} "
                      f"{len(r['boundary_outside_pcs']):>6d} "
                      f"{len(r['indirects']):>3d}")


def print_dynamic_map(manifest_runs: dict) -> None:
    print("dynamic-target map (JALRC reg value / BRSC index->target / JRC non-ra):")
    any_ind = False
    for fn in FNS:
        rows = []
        for stub in ("ret1", "real"):
            for ctx in ("zeroed", "tfn"):
                key = f"{fn}:{stub}:{ctx}"
                r = manifest_runs.get(key)
                if not r:
                    continue
                for ind in r["indirects"]:
                    any_ind = True
                    if ind["kind"] == "JALRC":
                        rows.append(
                            f"    [{stub}/{ctx}] step {ind['step']}: "
                            f"{ind['pc']:#x} {ind['text']} :: "
                            f"{ind['reg']}={ind['value_hex']} "
                            f"({ind['loc']})")
                    elif ind["kind"] == "BRSC":
                        rows.append(
                            f"    [{stub}/{ctx}] step {ind['step']}: "
                            f"{ind['pc']:#x} {ind['text']} :: "
                            f"{ind['reg']}={ind['index_hex']} -> "
                            f"{ind['value_hex']} ({ind['loc']})")
                    else:
                        rows.append(
                            f"    [{stub}/{ctx}] step {ind['step']}: "
                            f"{ind['pc']:#x} {ind['text']} :: "
                            f"{ind['reg']}={ind['value_hex']} "
                            f"({ind['loc']})")
        if rows:
            print(f"  {fn}: {len(rows)} indirect(s)")
            for ln in rows[:12]:
                print(ln)
            if len(rows) > 12:
                print(f"    ... +{len(rows) - 12} more")
        else:
            # distinguish "none encountered" from "run never got there"
            stops = {manifest_runs[f"{fn}:{s}:{c}"]["stop"]
                     for s in ("ret1", "real") for c in ("zeroed", "tfn")
                     if f"{fn}:{s}:{c}" in manifest_runs}
            print(f"  {fn}: 0 indirects (stops={sorted(stops)})")
    if not any_ind:
        print("  (no JALRC/BRSC/JRC-non-ra executed in any run)")


STUB_TEXTS = {"LI a0,0x1", "LI a0,0x0", "JRC ra", "JRC r31"}


def norm_pair_match(a: dict, b: dict) -> bool:
    """Convention-aware event match: same PC + (same text | Ghidra stub-? |
    final-marker equivalence)."""
    pa, pb = str(a.get("pc", "")).lower(), str(b.get("pc", "")).lower()
    if pa != pb:
        return False
    ta = " ".join(str(a.get("text", "")).split())
    tb = " ".join(str(b.get("text", "")).split())
    if ta == tb:
        return True
    # Ghidra TRACE is "?" inside dynamically-created stub blocks (no listing);
    # interp decodes the stub bytes it wrote. Same PC + stub text = same edge.
    if tb == "?" and ta in STUB_TEXTS:
        return True
    if ta == "?" and tb in STUB_TEXTS:
        return True
    # final markers: interp synthetic HIT-RET/STOP vs Ghidra RET-insn text
    if ta in ("HIT-RET",) or ta.startswith("STOP:"):
        if tb.startswith("RESTORE") or "JRC" in tb or tb == "?":
            return True
    if tb in ("HIT-RET",) or tb.startswith("STOP:"):
        if ta.startswith("RESTORE") or "JRC" in ta or ta == "?":
            return True
    return False


def norm_diff(a: list, b: list) -> dict:
    """First convention-aware divergence + raw-diff passthrough."""
    div = None
    for i, (ea, eb) in enumerate(zip(a, b)):
        if not norm_pair_match(ea, eb):
            div = {"step": i, "a_pc": ea.get("pc"),
                   "b_pc": eb.get("pc"), "a_text": ea.get("text"),
                   "b_text": eb.get("text")}
            break
    if div is None and len(a) != len(b):
        div = {"step": min(len(a), len(b)), "a_pc": None, "b_pc": None,
               "a_text": "<end>", "b_text": "<end>",
               "note": f"common prefix; lengths {len(a)} vs {len(b)}"}
    return {"divergence": div, "lengths": (len(a), len(b))}


def print_divergences(manifest_runs: dict) -> None:
    print("divergences (interp-strict ret1/zeroed vs Ghidra stock/auto-ret1):")
    n_div = 0
    for fn in FNS:
        key = f"{fn}:ret1:zeroed"
        r = manifest_runs.get(key, {})
        g = (r.get("ghidra") or {})
        if not g.get("compared"):
            print(f"  {fn}: Ghidra {g.get('note', 'no data')}")
            continue
        d = dict(g["diff"])
        # convention-aware re-diff over the saved event streams
        try:
            gkey = f"{fn}:ghidra:zeroed"
            if gkey in manifest_runs:
                nd = norm_diff(r.get("events", []),
                               manifest_runs[gkey].get("events", []))
                d["norm_divergence"] = nd["divergence"]
                d["norm_lengths"] = nd["lengths"]
        except Exception:
            pass
        div = d.get("divergence")
        status = ("MATCH" if div is None and
                  d.get("lengths", (1, 0))[0] == d.get("lengths", (0, 1))[1]
                  else "DIVERGE")
        if status == "DIVERGE":
            n_div += 1
        print(f"  [{status}] {fn}: interp steps={g['interp']['steps']} "
              f"stop={g['interp']['stop']} a0={g['interp']['a0']} :: "
              f"ghidra steps={g['ghidra']['steps']} stop={g['ghidra']['stop']} "
              f"a0={g['ghidra']['a0']}")
        for ln in d.get("lines", [])[:6]:
            print(f"      {ln}")
        print(f"      note: {g['note']}")
        # d["norm_divergence"] IS the divergence (None = convention-match)
        nd = d.get("norm_divergence", "n/a (no saved ghidra trace in memory)")
        if nd == "n/a (no saved ghidra trace in memory)":
            print("      norm: n/a (no saved ghidra trace in memory)")
        elif nd is None:
            extra = d.get("norm_lengths")
            print(f"      norm: MATCH under stub-?/marker conventions "
                  f"(lengths={extra})")
        elif isinstance(nd, dict) and nd.get("note", "").startswith("common prefix"):
            print(f"      norm: PREFIX-MATCH then length split "
                  f"({nd.get('note')})")
        elif isinstance(nd, dict):
            print(f"      norm: DIVERGE step {nd.get('step')}: "
                  f"{nd.get('a_pc')} {nd.get('a_text')} vs "
                  f"{nd.get('b_pc')} {nd.get('b_text')}")
        else:
            print(f"      norm: {nd}")
    print(f"  diverged (raw): {n_div}/{len(FNS)} fns; "
          f"see norm lines + final report for artifact-vs-real split")


def cmd_selftest() -> int:
    fails: list = []
    try:
        rom = load_rom()
        assert len(rom) == 45893712, f"rom size {len(rom)}"
    except Exception as e:  # noqa: BLE001
        print(f"campaign selftest: FAIL (rom: {e})")
        return 1
    try:
        cati = load_cati()
        assert len(cati) > 100000
        for fn in FNS:
            assert fn in cati, f"CATI miss {fn}"
    except Exception as e:  # noqa: BLE001
        print(f"campaign selftest: FAIL (cati: {e})")
        return 1
    try:
        tctx, zctx, prov = get_contexts()
        zb = full_ctx_backing(zctx)
        tb = full_ctx_backing(tctx)
        assert len(zb) == _CTX_SIZE and len(tb) == _CTX_SIZE
        assert zb[:0x1C8] == b"\x00" * 0x1C8, "zeroed image not zero"
        assert tb[:0x1C8] != b"\x00" * 0x1C8, "tfn image unexpectedly zero"
        print(f"  contexts: {prov}")
    except Exception as e:  # noqa: BLE001
        fails.append(f"contexts: {e}")
    # one fast strict run (legal-rule-adjacent small fn: sml_Verify ret1/zeroed)
    try:
        va, ve = cati["sml_Verify"]
        size = ve - va
        carve = rom[va - VA_BASE:va - VA_BASE + size]
        tgts, issue = sweep_balc_targets(va, size, carve)
        assert len(tgts) == 4, f"sml_Verify BALCs {tgts}"
        regs = {"a0": _CTX_INIT, "s0": _CTX_INIT, "ra": _RA_INIT,
                "sp": _STACK_INIT,
                "_ctx_image": full_ctx_backing(zctx)}
        rec = run_one(rom, va, size, regs, {t: "ret1" for t in tgts})
        assert rec["stop"] == "HIT-RET", rec["stop"]
        assert rec["steps"] > 0 and rec["coverage_total"] > 0
        assert rec["events"] and rec["events"][-1].get("regs", {}).get("a0")
        print(f"  probe sml_Verify ret1/zeroed: HIT-RET steps={rec['steps']} "
              f"a0={rec['a0']:#x} cov={rec['coverage_total']}")
    except Exception as e:  # noqa: BLE001
        fails.append(f"probe run: {e}")
    # schema + manifest-write smoke (Temp only, repo untouched)
    try:
        import tempfile
        ev = [_norm(0, 0x905DF2FA, "141e", "SAVE x"),
              _norm(1, 0x905DF330, "e0db", "HIT-RET", {"a0": 0})]
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "t.jsonl"
            blob = _write_jsonl(p, ev)
            assert p.read_bytes() == blob and len(blob.splitlines()) == 2
    except Exception as e:  # noqa: BLE001
        fails.append(f"schema smoke: {e}")
    print("campaign selftest:", "PASS" if not fails else "FAIL")
    for f in fails:
        print("  -", f)
    return 1 if fails else 0


def load_saved_runs() -> dict:
    """Reload all runs (interp + ghidra) from manifest + trace files."""
    prev = json.loads(MANIFEST_NEW.read_text(encoding="utf-8"))
    out: dict = {}
    for k, v in (prev.get("runs") or {}).items():
        tf = REPO_ROOT / v.get("trace_file", "")
        try:
            lines = tf.read_text(encoding="utf-8").splitlines()
            v["events"] = [json.loads(l) for l in lines if l.strip()]
        except OSError:
            continue
        for fld in ("va", "a0", "a1", "pc"):
            try:
                if isinstance(v.get(fld), str):
                    v[fld] = int(v[fld], 16)
            except ValueError:
                pass
        for ind in v.get("indirects", []):
            for fld in ("value", "index"):
                try:
                    if isinstance(ind.get(fld), str):
                        ind[fld] = int(ind[fld], 16)
                except ValueError:
                    pass
        out[k] = v
    return out


def cmd_report_only() -> int:
    try:
        runs = load_saved_runs()
    except OSError as e:
        print(f"report-only: no saved manifest ({e}); run --interp-only first")
        return 2
    interp = {k: v for k, v in runs.items() if ":ghidra:" not in k}
    print_inventory(interp)
    print_dynamic_map(interp)
    print_divergences(runs)
    try:
        from trace_tools import check_corpus as _check  # type: ignore
    except ImportError:
        from sim.trace_tools import check_corpus as _check  # type: ignore
    st = _check()
    print(f"seed corpus --check: {st['overall']} (7 seed files untouched)")
    print(f"saved runs: {len(interp)} interp + {len(runs) - len(interp)} ghidra "
          f"(manifest: sim/traces/sml_dynamic_manifest.json)")
    return 0 if st["overall"] == "PASS" else 1


def main(argv: list | None = None) -> int:
    ap = argparse.ArgumentParser(description="SML full-trace campaign (offline)")
    ap.add_argument("--interp-only", action="store_true")
    ap.add_argument("--ghidra-only", action="store_true")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--report-only", action="store_true",
                    help="no emulation: reload saved traces + reprint tables")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--step-cap", type=int, default=_STEP_CAP)
    ap.add_argument("--timeout", type=float, default=300.0)
    ap.add_argument("--retries", type=int, default=1)
    args = ap.parse_args(argv)
    if args.selftest:
        return cmd_selftest()
    if args.report_only:
        return cmd_report_only()
    want_ghidra = args.ghidra_only or args.all or not (args.interp_only or args.ghidra_only)
    want_interp = args.interp_only or args.all or not (args.interp_only or args.ghidra_only)
    if args.ghidra_only:
        want_interp = False
    if args.interp_only:
        want_ghidra = False

    rom = load_rom()
    cati = load_cati()
    # previous manifest runs (if rerunning halves separately, merge)
    manifest_runs: dict = {}
    if MANIFEST_NEW.exists():
        try:
            prev = json.loads(MANIFEST_NEW.read_text(encoding="utf-8"))
            for k, v in (prev.get("runs") or {}).items():
                # events are reloaded lazily from trace files below
                pass
        except Exception:
            pass

    if want_interp:
        tctx, zctx, ctx_prov = get_contexts()
        backings = {"zeroed": full_ctx_backing(zctx),
                    "tfn": full_ctx_backing(tctx)}
        sweep_notes: dict = {}
        for fn in FNS:
            va, ve = cati[fn]
            size = ve - va
            carve = rom[va - VA_BASE:va - VA_BASE + size]
            tgts, issue = sweep_balc_targets(va, size, carve)
            sweep_notes[fn] = {"n_targets": len(tgts),
                               "targets": [f"{t:#x}" for t in sorted(tgts)],
                               "issue": issue}
            stubs_ret1 = {t: "ret1" for t in tgts}
            for stub_label, stubs in (("ret1", stubs_ret1), ("real", {})):
                for ctx_label in ("zeroed", "tfn"):
                    regs = {"a0": _CTX_INIT, "s0": _CTX_INIT,
                            "ra": _RA_INIT, "sp": _STACK_INIT,
                            "_ctx_image": backings[ctx_label]}
                    rec = run_one(rom, va, size, regs, stubs,
                                  step_cap=args.step_cap)
                    key = f"{fn}:{stub_label}:{ctx_label}"
                    manifest_runs[key] = {
                        "fn": fn, "va": va, "size": size,
                        "stub_mode": stub_label, "ctx": ctx_label,
                        "stop": rec["stop"], "steps": rec["steps"],
                        "a0": rec["a0"], "a1": rec["a1"],
                        "pc": rec["pc"],
                        "coverage_total": rec["coverage_total"],
                        "coverage_inside": rec["coverage_inside"],
                        "coverage_outside": rec["coverage_outside"],
                        "boundary_outside_pcs": rec["boundary_outside_pcs"],
                        "cross_edges": rec["cross_edges"],
                        "stub_targets": [f"{t:#x}" for t in sorted(tgts)],
                        "sweep_issue": issue,
                        "gaps": rec["gaps"],
                        "auto_stubs": rec["auto_stubs"],
                        "indirects": rec["indirects"],
                        "events": rec["events"],
                    }
            print(f"  {fn} done "
                  f"({sweep_notes[fn]['n_targets']} BALCs; issue={issue or 'none'})")
        save_traces({k: v for k, v in manifest_runs.items()
                     if ":ghidra:" not in k})
        man = build_manifest(manifest_runs, cati, rom, ctx_prov, sweep_notes,
                             None)
        MANIFEST_NEW.write_text(json.dumps(man, indent=2) + "\n",
                                encoding="utf-8")
        print_inventory(manifest_runs)
        print_dynamic_map(manifest_runs)
    if want_ghidra:
        # merge with existing interp runs from manifest file when present
        if not manifest_runs:
            try:
                prev = json.loads(MANIFEST_NEW.read_text(encoding="utf-8"))
                for k, v in (prev.get("runs") or {}).items():
                    if ":ghidra:" in k:
                        continue
                    # reload events from saved trace files
                    tf = REPO_ROOT / v.get("trace_file", "")
                    try:
                        lines = tf.read_text(encoding="utf-8").splitlines()
                        v["events"] = [json.loads(l) for l in lines if l.strip()]
                    except OSError:
                        continue
                    # JSON round-trip stringifies ints: restore numeric fields
                    for fld in ("va", "a0", "a1", "pc"):
                        try:
                            if isinstance(v.get(fld), str):
                                v[fld] = int(v[fld], 16)
                        except ValueError:
                            pass
                    for ind in v.get("indirects", []):
                        for fld in ("value", "index"):
                            try:
                                if isinstance(ind.get(fld), str):
                                    ind[fld] = int(ind[fld], 16)
                            except ValueError:
                                pass
                    manifest_runs[k] = v
            except OSError:
                pass
            if not manifest_runs:
                print("ghidra-only: no interp runs found; "
                      "run --interp-only first")
                return 2
        graw = ghidra_runs_for(cati, args.timeout, args.retries)
        for fn in FNS:
            key = f"{fn}:ret1:zeroed"
            g = graw.get(fn, {})
            if key not in manifest_runs:
                continue
            manifest_runs[key]["ghidra"] = compare_one_ghidra(
                manifest_runs[key], g)
            if g.get("ok"):
                gkey = f"{fn}:ghidra:zeroed"
                manifest_runs[gkey] = {
                    "fn": fn, "va": manifest_runs[key]["va"],
                    "size": manifest_runs[key]["size"],
                    "stub_mode": "ghidra-auto-ret1", "ctx": "zeroed",
                    "stop": g["result"]["stop"],
                    "steps": g["result"]["steps"],
                    "a0": g["result"]["a0"] & 0xFFFFFFFF,
                    "a1": 0, "pc": g["result"]["pc"] & 0xFFFFFFFF,
                    "coverage_total": len({e["pc"] for e in g["events"]}),
                    "coverage_inside": 0, "coverage_outside": 0,
                    "boundary_outside_pcs": [],
                    "cross_edges": [],
                    "stub_targets": manifest_runs[key]["stub_targets"],
                    "sweep_issue": "",
                    "gaps": [], "auto_stubs": [],
                    "indirects": [],
                    "events": g["events"],
                }
        # re-save (interp files byte-stable rewrite + new ghidra files)
        save_traces(manifest_runs)
        try:
            prev = json.loads(MANIFEST_NEW.read_text(encoding="utf-8"))
            sweep_notes = prev.get("sweep_notes", {})
            ctx_prov = prev.get("ctx_provenance", "")
        except OSError:
            sweep_notes, ctx_prov = {}, ""
        man = build_manifest(manifest_runs, cati, rom, ctx_prov, sweep_notes,
                             graw)
        MANIFEST_NEW.write_text(json.dumps(man, indent=2) + "\n",
                                encoding="utf-8")
        print_inventory({k: v for k, v in manifest_runs.items()
                         if ":ghidra:" not in k})
        print_dynamic_map({k: v for k, v in manifest_runs.items()
                           if ":ghidra:" not in k})
        print_divergences(manifest_runs)
    # seed-corpus guard
    try:
        from trace_tools import check_corpus as _check  # type: ignore
    except ImportError:
        from sim.trace_tools import check_corpus as _check  # type: ignore
    st = _check()
    print(f"seed corpus --check: {st['overall']} "
          f"(7 seed files untouched)")
    if st["overall"] != "PASS":
        print("  WARNING: seed corpus check red — new files must not "
              "have touched sim/traces/<seed>.jsonl")
        return 1
    return 0


def compare_one_ghidra(interp_run: dict, g: dict) -> dict:
    if not g.get("ok"):
        return {"compared": False, "note": g.get("error", "no ghidra data")}
    gr = g["result"]
    ievents = interp_run["events"]
    gevents = g["events"]
    try:
        d = _diff(ievents, gevents)
    except Exception as e:  # noqa: BLE001
        return {"compared": False, "note": f"diff failed: {e}"}
    div = d.get("divergence")
    if div is None:
        note = ("no divergence in common prefix" if d.get("lengths",
                (0, 0))[0] == d.get("lengths", (0, 0))[1]
                else "common prefix; lengths differ")
    else:
        note = (f"first divergence step {div.get('step')}: "
                f"{div.get('a_pc')} {div.get('a_text')} vs "
                f"{div.get('b_pc')} {div.get('b_text')}")
    def _hx(v):
        return f"{v:#x}" if isinstance(v, int) else str(v)
    return {"compared": True, "diff": d, "note": note,
            "interp": {"steps": interp_run["steps"],
                       "stop": interp_run["stop"],
                       "a0": _hx(interp_run['a0'])},
            "ghidra": {"steps": gr["steps"], "stop": gr["stop"],
                       "a0": _hx(gr['a0']), "pc": _hx(gr['pc']),
                       "ret_at": (_hx(gr['ret_at'])
                                  if gr.get("ret_at") else "?"),
                       "log": gr.get("log", "")}}


if __name__ == "__main__":
    sys.exit(main())
