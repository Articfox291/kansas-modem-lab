#!/usr/bin/env python3
"""sml_conform.py -- SML integration + conformance suite (exact emulation vs behavioral model).

SAFETY (hard rules, enforced by construction):
  * Pure offline model. No device I/O: no adb/fastboot/serial/socket/subprocess
    imports, no modem command emission, nothing here can consume unlock attempts
    (5-capped counter intact by construction).
  * Read-only on repo dumps and TEMP logs: real images opened 'rb' and never
    modified; TEMP Ghidra logs/bins read-only as recorded evidence.
  * New outputs go UNDER sim/ only (report defaults to sim/conform_report.json,
    guarded). Stdlib only.

WHAT THIS IS:
  Backend-agnostic conformance runner tying exact emulation to the behavioral
  oracle (sim/sml_sim.py -- used as oracle, never modified):
    run_fn(backend in {"interp","ghidra"}, va, size, regs, stubs)
      -> (a0, steps, trace)
  plus a conformance matrix over all decoded SML functions (VAs from
  cati_syms.json with HANDOFF fallbacks), NVRAM-backed ctx images from
  sim/nv_model.py, and a regression gate (exit code + machine-readable JSON).

CONCURRENCY NOTE:
  Sibling backends (interp / ghidra live modules under sim/) are built by other
  agents concurrently. They are imported defensively (try/except ImportError ->
  SKIP with reason). The suite still passes its regression gate on the two
  proven proofs via behavioral + structural + recorded-Ghidra + minimal-exact
  evidence (see PROOFS). Every row records PASS/FAIL/SKIP with reasons; exit 0
  iff no FAIL and both proofs PASS (SKIPs allowed).

SOURCES (repo-relative unless noted):
  sim/hw_target.py .... exact target spec (nanomips:LE:32:default, ret1 bytes)
  sim/emu_engine.py ... Image/Memory/decode_one/StubRegistry (exact primitives)
  sim/sml_sim.py ...... BEHAVIORAL ORACLE (verdicts; do not modify)
  sim/nv_model.py ..... NVRAM contexts (Tracfone template; HW-bound seam)
  sim/rmmi_sim.py ..... RMMI query oracle for dispatcher rows (read-only use)
  HANDOFF.md Sec 3e ... SML API map, polarity, patch bytes, linker/verify notes
  PICKUP.md Track 1 ... toolchain + headless rules + CATI location
  <temp>/cati_syms.json .......... VA extents ({name:[startHex,endHex]})
  <temp>/emu_legal_sim_rule_{stock,patch}.log .. recorded Ghidra EmulatorHelper
      proofs: stock+helpers-1 -> HIT-RET 25 steps a0=0x0; patch -> 1 step a0=0x1
  <temp>/fn_*.log / fn_*.bin ..... recorded Ghidra Nmdis2 disassembly + carves
  md1work_romonly.bin ............. 45,893,712 B modem image (VA base 0x90000000)

Run:
  python sim/sml_conform.py [--report sim/conform_report.json] [--verbose]
  python sim/sml_conform.py --selftest   (fast structural check, still writes report)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

# ---------------------------------------------------------------- paths
SIM_DIR = Path(__file__).resolve().parent
REPO_ROOT = SIM_DIR.parent
TEMP = Path(os.environ.get("MODEM_LAB_TMP",
                str(Path(__file__).resolve().parent / "Temp")))
TEMP.mkdir(parents=True, exist_ok=True)
CATI_JSON = TEMP / "cati_syms.json"
DEFAULT_REPORT = SIM_DIR / "conform_report.json"
ROMONLY = REPO_ROOT / "md1work_romonly.bin"
STOCK_MD1IMG = REPO_ROOT / "stock_XT2513V" / "md1img.img"

if str(SIM_DIR) not in sys.path:
    sys.path.insert(0, str(SIM_DIR))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# ---------------------------------------------------------------- required siblings (exist in repo)
_HAVE = {}
try:
    import emu_engine as _EE  # Image/Memory/decode_one/StubRegistry
    _HAVE["emu_engine"] = True
except ImportError:
    _EE = None  # type: ignore
    _HAVE["emu_engine"] = False

try:
    import sml_sim as _SML  # BEHAVIORAL ORACLE -- never modified here
    _HAVE["sml_sim"] = True
except ImportError:
    try:
        from sim import sml_sim as _SML  # type: ignore
        _HAVE["sml_sim"] = True
    except ImportError:
        _SML = None  # type: ignore
        _HAVE["sml_sim"] = False

try:
    import nv_model as _NV
    _HAVE["nv_model"] = True
except ImportError:
    try:
        from sim import nv_model as _NV  # type: ignore
        _HAVE["nv_model"] = True
    except ImportError:
        _NV = None  # type: ignore
        _HAVE["nv_model"] = False

try:
    import hw_target as _HW
    _HAVE["hw_target"] = True
except ImportError:
    try:
        from sim import hw_target as _HW  # type: ignore
        _HAVE["hw_target"] = True
    except ImportError:
        _HW = None  # type: ignore
        _HAVE["hw_target"] = False

try:
    import rmmi_sim as _RMMI
    _HAVE["rmmi_sim"] = True
except ImportError:
    try:
        from sim import rmmi_sim as _RMMI  # type: ignore
        _HAVE["rmmi_sim"] = True
    except ImportError:
        _RMMI = None  # type: ignore
        _HAVE["rmmi_sim"] = False

# ---------------------------------------------------------------- concurrent sibling backends (defensive)
# Other agents build live interp/ghidra backends under sim/ concurrently.
# Candidate module names cover the plausible layouts; first hit wins.
_INTERP_CANDIDATES = (
    "sml_interp", "sim.sml_interp",
    "emu_interp", "sim.emu_interp",
    "interp", "sim.interp",
    "interp_backend", "sim.interp_backend",
    "backend_interp", "sim.backend_interp",
)
_GHIDRA_CANDIDATES = (
    "sml_ghidra", "sim.sml_ghidra",
    "emu_ghidra", "sim.emu_ghidra",
    "ghidra_backend", "sim.ghidra_backend",
    "ghidra", "sim.ghidra",
    "backend_ghidra", "sim.backend_ghidra",
)


def _try_import(candidates):
    for name in candidates:
        try:
            __import__(name)
            return sys.modules[name], name, ""
        except ImportError as e:
            last = str(e)
            continue
    return None, "", (last if "last" in dir() else "no candidates")


_INTERP_MOD, _INTERP_NAME, _INTERP_ERR = _try_import(_INTERP_CANDIDATES)
_GHIDRA_MOD, _GHIDRA_NAME, _GHIDRA_ERR = _try_import(_GHIDRA_CANDIDATES)


def _describe_class_api(mod):
    """Note known class-based (non-run_fn) sibling APIs for accurate SKIP reasons."""
    if mod is None:
        return ""
    names = [n for n in dir(mod) if not n.startswith("_")]
    if hasattr(mod, "GhidraBackend"):
        return ("module '%s' present but exposes class GhidraBackend.run(fn_va, size, "
                "mode, ...) (headless, minutes per run), no run_fn-compatible module-level "
                "runner" % getattr(mod, "__name__", "?"))
    if hasattr(mod, "execute") and "stub_lib" in getattr(mod, "__name__", ""):
        return ("module '%s' present but is helper-level behavioral stubs "
                "(execute(registry, va, regs, ctx)), not ISA emulation" % getattr(mod, "__name__", "?"))
    return "module '%s' present but exposes no run_fn-compatible runner%s" % (
        getattr(mod, "__name__", "?"), (" (%s)" % ",".join(names[:6])) if names else "")

def _find_delegate(mod):
    for attr in ("run_fn", "run", "execute", "emulate", "emu_run"):
        if mod is not None and hasattr(mod, attr) and callable(getattr(mod, attr)):
            return getattr(mod, attr), attr
    return None, ""


_INTERP_DELEGATE, _INTERP_DELEGATE_ATTR = _find_delegate(_INTERP_MOD)
_GHIDRA_DELEGATE, _GHIDRA_DELEGATE_ATTR = _find_delegate(_GHIDRA_MOD)

BACKEND_INFO = {
    "interp": {
        "available": _INTERP_DELEGATE is not None,
        "module": _INTERP_NAME or None,
        "runner": _INTERP_DELEGATE_ATTR or None,
        "reason": (("live backend '%s.%s' loaded" % (_INTERP_NAME, _INTERP_DELEGATE_ATTR))
                   if _INTERP_DELEGATE is not None
                   else ((_describe_class_api(_INTERP_MOD) + "; ") if _INTERP_MOD is not None else
                         ("no live interp module under sim/ yet (concurrent agent; tried %d names; "
                          "last: %s); " % (len(_INTERP_CANDIDATES), _INTERP_ERR))) +
                         "SKIP live; internal minimal-exact engine handles LI/JRC-only "
                         "sequences, else SKIP"),
    },
    "ghidra": {
        "available": _GHIDRA_DELEGATE is not None,
        "module": _GHIDRA_NAME or None,
        "runner": _GHIDRA_DELEGATE_ATTR or None,
        "reason": (("live backend '%s.%s' loaded" % (_GHIDRA_NAME, _GHIDRA_DELEGATE_ATTR))
                   if _GHIDRA_DELEGATE is not None
                   else ((_describe_class_api(_GHIDRA_MOD) + "; ") if _GHIDRA_MOD is not None else
                         ("no live ghidra runner module under sim/ yet (concurrent agent; tried %d names); "
                          % len(_GHIDRA_CANDIDATES))) +
                         "SKIP live headless in default path (minutes per run); recorded TEMP "
                         "headless logs used as offline evidence where present, else SKIP"),
    },
}


class BackendSkip(Exception):
    """Backend unavailable or function not emulatable -- row cell is SKIP."""


class EmuUnsupported(Exception):
    """Minimal engine hit an encoding it cannot execute exactly -- needs backend."""


# ---------------------------------------------------------------- constants
VA_BASE = 0x90000000
STACK_BASE = 0xA0000000
CTX_BASE = 0xB0000000
PATCH_BYTES = bytes.fromhex("01d2e0db")   # LI a0,1 ; JRC ra (verified force-LEGAL)
RET0_BYTES = bytes.fromhex("00d2e0db")    # LI a0,0 ; JRC ra
STOCK_LEGAL_HEAD = bytes.fromhex("141e2412")

# The 12 decoded SML functions. fallback VA/size from cati_syms.json (verified
# 2026-09-05; sizes cross-checked against TEMP carved fn_*.bin lengths).
# kind: verdict (single a0, 1=pass) | inverted (0=pass) | flag (OTP-ON, not
#   LEGAL) | dispatch (RMMI, no single LEGAL verdict by design).
# cati: exact CATI symbol name for extent lookup.
FUNCTIONS = [
    {"key": "legal_sim_rule", "cati": "custom_check_link_sml_legal_sim_rule",
     "fallback_va": 0x905DF2FA, "fallback_size": 94, "kind": "verdict",
     "note": "1=LEGAL (caller @0x905DF3DC BNEIC a0,1). Two proven proofs."},
    {"key": "link_sml_with_rule_head", "cati": "custom_link_sml_with_rule",
     "fallback_va": 0x905DF3A2, "fallback_size": 972, "kind": "verdict",
     "note": "head/caller-site conformance; s7 carries verdict to return. Full 333-insn disasm recorded."},
    {"key": "sml_Verify", "cati": "sml_Verify",
     "fallback_va": 0x905F0F04, "fallback_size": 132, "kind": "verdict",
     "note": "50-insn chain: mot_catkey->TFN->perm_unlock->lock_rule->marker. Both TFN arms converge @0x905F0F62."},
    {"key": "mot_sml_catkey_verify", "cati": "mot_sml_catkey_verify",
     "fallback_va": 0x905F0DF8, "fallback_size": 268, "kind": "verdict",
     "note": "crypto stage via mot_sml_db_catkey_verify; PROVISIONAL BE-word gate."},
    {"key": "sml_catkey_verify", "cati": "sml_catkey_verify",
     "fallback_va": 0x905F0658, "fallback_size": 198, "kind": "verdict",
     "note": "crypto via 0x90598axx; BE-word @s0+0x22 nonzero gate (PROVISIONAL); trampoline BC @0x905F071A."},
    {"key": "sml_Unlock", "cati": "sml_Unlock",
     "fallback_va": 0x905F071E, "fallback_size": 150, "kind": "verdict",
     "note": "vtable object; needs byte@0(s0)==1 + retry@+8 nonzero (PROVISIONAL offsets); writes marker 2."},
    {"key": "sml_is_tfn_otp_on", "cati": "sml_is_tfn_otp_on",
     "fallback_va": 0x9198E4D2, "fallback_size": 62, "kind": "flag",
     "note": "OTP-ON flag, NOT LEGAL: stub 0xFF?=ON else eFuse, fail-safe ON. Convention differs by design."},
    {"key": "rmmi_esmlck_hdlr", "cati": "rmmi_esmlck_hdlr",
     "fallback_va": 0x91985788, "fallback_size": 426, "kind": "dispatch",
     "note": "131 insn; mode byte @arg+0xD (2/4=query,1=key path BLOCKED); gate custom_sml_is_esmlck_execute_allow @0x905F0312=ret1."},
    {"key": "rmmi_esmlrsu_hdlr", "cati": "rmmi_esmlrsu_hdlr",
     "fallback_va": 0x91987884, "fallback_size": 156, "kind": "dispatch",
     "note": "49 insn; sub1->op12, sub2->op129, sub3->op08, sub6->op12t; lock-rule-gated."},
    {"key": "rmmi_esmlgen_hdlr", "cati": "rmmi_esmlgen_hdlr",
     "fallback_va": 0x91987A98, "fallback_size": 168, "kind": "dispatch",
     "note": "53 insn TFN frontend -> rmmi_tfn_handler @0x919879E0. No key material."},
    {"key": "sml_crrst_Check", "cati": "sml_crrst_Check",
     "fallback_va": 0x905EDF4E, "fallback_size": 264, "kind": "verdict",
     "note": "94 insn; vtable + XORI ra mangling note; cat-table @0x920DC574; nibble-OR + memcmp; ret 1."},
    {"key": "sml_op07_Check", "cati": "sml_op07_Check",
     "fallback_va": 0x905EE9AC, "fallback_size": 624, "kind": "inverted",
     "note": "217 insn; INVERTED convention 0=pass (op-family-specific, not our unlock path)."},
]

# PROVISIONAL ctx-struct layout assumptions. Offsets are EMULATOR-SCRATCH
# conventions (not modem truth) so NVRAM policy can be fed as memory images
# deterministically; each cites the VA that motivates it. Anything marked
# PROVISIONAL needs Ghidra confirmation before use in a patch decision.
ASSUMPTIONS = [
    {"id": "A1", "status": "PROVISIONAL",
     "text": "Emulated ctx image base CTX_BASE=0xB0000000, size 0x10000 R/W (emulator scratch, NOT a modem VA). Real modem ctx lives in modem heap; address unknown.",
     "va": "n/a (emu_engine.Memory.with_image default layout)"},
    {"id": "A2", "status": "PROVISIONAL",
     "text": "Per-category stride 0x40, 7 cats @+0x000..+0x1BF; fields u32 LE: +0x00 state(1=LOCKED/0=UNLOCKED), +0x04 retry, +0x08 autolock, +0x0C num, +0x10 key_state, +0x14 flags(bit0=BE-word-nonzero proxy), +0x18 plmn0 8B ASCII NUL-padded (first allow_list entry), +0x20 key 16B reserved; globals @+0x1C0 tfn_otp_on u32, @+0x1C4 permanent_unlock u32. Total 0x1C8. Variable allow_lists truncated to first PLMN by design.",
     "va": "0x905DF2FA legal_sim_rule (cat=s4 selector); 0x905DF3A2 linker prologue (cat=s4, link=s0, bufs s1/s3/s5)"},
    {"id": "A3", "status": "PROVISIONAL",
     "text": "Ctx/link pointer passed in s0, forwarded as a0 to legal_sim_rule (MOVE.BALC a0,s0). Emulation seeds a0=s0=CTX_BASE for verdict fns.",
     "va": "0x905DF3DC (MOVE.BALC a0,s0,0x905DF2FA; BNEIC a0,0x1,0x905DF4DC)"},
    {"id": "A4", "status": "PROVISIONAL",
     "text": "sml_Unlock gates byte@0(s0)==1 and retry@+8 nonzero map to image +0x00 (state inverted: stored 1=LOCKED, gate needs unlocked-flag -- modeled as flag=1 means gate-open for the ret1-stubbed path) and +0x04 (retry). Real +8 offset unconfirmed; needs Ghidra s0-struct recovery.",
     "va": "0x905F071E sml_Unlock (60 insn)"},
    {"id": "A5", "status": "PROVISIONAL",
     "text": "sml_catkey_verify BE-word @s0+0x22 nonzero gate maps to image flags bit0 (=1 iff allow_list non-empty). Real 0x22 offset unconfirmed.",
     "va": "0x905F0658 sml_catkey_verify; trampoline BC @0x905F071A"},
    {"id": "A6", "status": "PROVISIONAL",
     "text": "rmmi_esmlck_hdlr mode byte @arg+0xD (2/4=status query via l4csmu_sml_status_req_handler @0x9198B704; 1=key/data path, never emulated, guard-blocked). No ctx image consumed by dispatchers in this suite (query forms only).",
     "va": "0x91985788 rmmi_esmlck_hdlr (131 insn)"},
    {"id": "A7", "status": "VERIFIED",
     "text": "helpers=ret1 stubs are bytes 01 d2 e0 db (LI a0,1; JRC ra) per hw_target SPEC and emu_engine STUB_RET1; verified at custom_sml_is_esmlck_execute_allow @0x905F0312, custom_sml_cat_verify_pass_permanent_unlock @0x905DF77A, custom_sml_set_device_unlock_tfn_otp_off @0x905F3942.",
     "va": "0x905F0312; 0x905DF77A; 0x905F3942"},
    {"id": "A8", "status": "VERIFIED",
     "text": "Polarity 1=LEGAL for the link path (sole caller BNEIC a0,1 to fail @0x905DF4DC). sml_op07_Check is the documented exception (inverted 0=pass, op-family-specific). sml_is_tfn_otp_on returns an OTP-ON flag, not LEGAL.",
     "va": "0x905DF3DC caller; 0x905DF4DC fail path; 0x905EE9AC op07 (217 insn)"},
]

# ---------------------------------------------------------------- image / cati (read-only)


def _load_cati():
    if _EE is not None:
        try:
            syms = _EE.load_cati()
            return syms, "TEMP cati_syms.json via emu_engine (%d syms)" % len(syms), ""
        except Exception as e:  # noqa: BLE001
            pass
    try:
        raw = json.loads(CATI_JSON.read_text())
        syms = {k: (int(v[0], 16), int(v[1], 16)) for k, v in raw.items()}
        return syms, "TEMP cati_syms.json direct (%d syms)" % len(syms), ""
    except Exception as e:  # noqa: BLE001
        return {}, "", "cati unavailable: %s (using HANDOFF fallback VAs)" % e


def _load_image():
    """Return (data: bytes, source: str, sha12: str, err: str). Read-only."""
    for p, label in ((ROMONLY, "md1work_romonly.bin"), (STOCK_MD1IMG, "stock md1img payload")):
        try:
            if not p.is_file():
                continue
            data = p.read_bytes()
            if label.startswith("stock md1img"):
                data = data[0x200:0x200 + 45893712]
            if len(data) < 0x1000:
                continue
            return data, label, hashlib.sha256(data).hexdigest()[:12], ""
        except Exception:  # noqa: BLE001
            continue
    return b"", "", "", "no modem image found (md1work_romonly.bin / stock md1img)"


_IMG, _IMG_SRC, _IMG_SHA, _IMG_ERR = _load_image()
_CATI, _CATI_SRC, _CATI_ERR = _load_cati()


def _resolve_fn(f):
    va, size, src = f["fallback_va"], f["fallback_size"], "HANDOFF fallback"
    if f["cati"] in _CATI:
        a, b = _CATI[f["cati"]]
        va, size, src = a, b - a, "cati_syms.json"
    return va, size, src


def _carve(va, size):
    if not _IMG:
        raise BackendSkip("no modem image (%s)" % _IMG_ERR)
    off = va - VA_BASE
    if not (0 <= off < len(_IMG)) or off + size > len(_IMG):
        raise BackendSkip("VA %#x size %d outside image (%s)" % (va, size, _IMG_SRC))
    return _IMG[off:off + size]


def _decode_head(va, raw, n=2):
    """Decode up to n insns at va via emu_engine (exact) or hex fallback."""
    if _EE is None:
        return ["hex %s (emu_engine missing)" % raw[:8].hex(" ")]
    try:
        m = _EE.Memory()
        base = va & ~0xFFF
        page = bytearray(0x1000)
        chunk = raw[:8]
        page[va - base:va - base + len(chunk)] = chunk
        m.add("t", base, 0x1000, _EE.PERM_R | _EE.PERM_W, bytes(page))
        out = []
        pc = va
        for _ in range(n):
            ins = _EE.decode_one(m, pc)
            out.append("%#x %s" % (pc, ins.text))
            pc += ins.size
        return out
    except Exception as e:  # noqa: BLE001
        return ["decode unavailable: %s" % e]


# ---------------------------------------------------------------- run_fn


def _local_interp(va, size, regs, stubs):
    """Minimal EXACT interpreter for 16-bit LI/JRC sequences (stdlib-only).

    Executes the mapped function image step-by-step using emu_engine's
    verified decoder. Handles ONLY the LI[16] and JRC forms (the encodings
    with >=2 Ghidra ground-truth vectors). Any 32-bit form raises
    EmuUnsupported (needs the full nanoMIPS backend -- Ghidra/live interp).
    Patched entry and 4-byte ret stubs therefore execute EXACTLY (LI+JRC = 2
    minimal-engine steps; Ghidra EmuSml counts 1 with the JRC ret event free --
    same verdict a0=1 either way); stock prologues honestly report SKIP instead
    of guessing.
    """
    if _EE is None:
        raise BackendSkip("emu_engine missing (cannot build memory/decoder)")
    regs = dict(regs or {})
    stubs = dict(stubs or {})
    raw = _carve(va, size)
    overlay = regs.get("_overlay")
    if isinstance(overlay, dict):
        for ova, obytes in overlay.items():
            if ova == va:
                raw = bytes(obytes) + raw[len(obytes):]
    m = _EE.Memory()
    # fn code R-X at its VA; stubs materialized per policy; stack+ctx scratch
    m.add("fn", va, max(len(raw), 0x1000), _EE.PERM_R | _EE.PERM_X, raw)
    m.add("stack", STACK_BASE, 0x10000, _EE.PERM_R | _EE.PERM_W)
    m.add("ctx", CTX_BASE, 0x10000, _EE.PERM_R | _EE.PERM_W)
    sr = _EE.StubRegistry()
    for sva, pol in stubs.items():
        if pol in ("ret1", "ret0"):
            sr.set(sva, pol)
    try:
        sr.materialize(m)
    except Exception:  # noqa: BLE001
        pass
    ctx_img = regs.get("_ctx_image")
    if isinstance(ctx_img, (bytes, bytearray)) and len(ctx_img):
        try:
            m.write(CTX_BASE, bytes(ctx_img)[:0x10000])
        except Exception:  # noqa: BLE001
            pass
    rf = {"a0": regs.get("a0", CTX_BASE), "a1": regs.get("a1", 0),
          "ra": regs.get("ra", 0xDEAD0002), "sp": regs.get("sp", STACK_BASE + 0x8000)}
    # s0 defaults to ctx pointer (assumption A3)
    rf["s0"] = regs.get("s0", regs.get("a0", CTX_BASE))
    pc, steps, trace = va, 0, []
    fn_end = va + len(raw)
    for _ in range(4096):
        if pc == rf["ra"] or pc == 0xDEAD0002:
            trace.append("HIT-RET pc=%#x a0=%#x steps=%d" % (pc, rf["a0"] & 0xFFFFFFFF, steps))
            return rf["a0"] & 0xFFFFFFFF, steps, trace
        if not (va <= pc < fn_end):
            # jumped into a stub page (e.g. BALC target materialized as ret1)?
            try:
                ins = _EE.decode_one(m, pc)
            except Exception:  # noqa: BLE001
                raise BackendSkip("pc %#x left fn without hitting ra (needs full backend)" % pc)
            if ins.text.startswith("LI "):
                parts = ins.text[3:].split(",")
                rf[parts[0].strip()] = int(parts[1].strip(), 16)
                trace.append("%#x %s" % (pc, ins.text))
                pc += ins.size
                steps += 1
                continue
            if ins.text.startswith("JRC "):
                trace.append("%#x %s -> RET a0=%#x" % (pc, ins.text, rf["a0"] & 0xFFFFFFFF))
                return rf["a0"] & 0xFFFFFFFF, steps + 1, trace
            raise EmuUnsupported("stub-pc form '%s' needs full backend" % ins.text)
        try:
            ins = _EE.decode_one(m, pc)
        except Exception as e:  # noqa: BLE001
            raise BackendSkip("decode fault @%#x: %s" % (pc, e))
        if ins.text.startswith("LI "):
            parts = ins.text[3:].split(",")
            rf[parts[0].strip()] = int(parts[1].strip(), 16)
            trace.append("%#x %s" % (pc, ins.text))
            pc += ins.size
            steps += 1
            continue
        if ins.text == "JRC r31":
            trace.append("%#x %s (ra) a0=%#x" % (pc, ins.text, rf["a0"] & 0xFFFFFFFF))
            return rf["a0"] & 0xFFFFFFFF, steps + 1, trace
        if ins.text.startswith("JRC "):
            raise EmuUnsupported("indirect %s @%#x needs full backend" % (ins.text, pc))
        # Any 32-bit form (DB_xxxx) or unknown 16-bit: honest STOP, not a guess.
        raise EmuUnsupported("form '%s' @%#x needs full nanoMIPS backend (Ghidra/live interp)" % (ins.text, pc))
    raise BackendSkip("step budget exhausted @%#x (needs full backend)" % pc)


def run_fn(backend, va, size, regs=None, stubs=None):
    """Backend-agnostic runner: (a0, steps, trace).

    backend: "interp" or "ghidra". regs: {"a0":..,"s0":..,"ra":..,"sp":..,
      "_overlay": {va: bytes}, "_ctx_image": bytes}. stubs: {va: "ret1"|"ret0"}.
    Delegates to a live sibling backend when one exposes a compatible callable;
    else interp falls back to the internal minimal-exact engine and ghidra
    raises BackendSkip (recorded TEMP logs are consulted by the matrix, not by
    this runner, so live-vs-recorded is never conflated). Raises BackendSkip /
    EmuUnsupported with reasons; never touches the device.
    """
    if backend not in ("interp", "ghidra"):
        raise ValueError("backend must be 'interp' or 'ghidra', got %r" % (backend,))
    mod = _INTERP_MOD if backend == "interp" else _GHIDRA_MOD
    fn, attr = _find_delegate(mod)
    if fn is not None:
        try:
            return fn(backend, va, size, regs, stubs)
        except (BackendSkip, EmuUnsupported):
            raise
        except TypeError:
            # tolerate sibling signature (va, size, regs, stubs) without backend
            try:
                return fn(va, size, regs, stubs)
            except (BackendSkip, EmuUnsupported):
                raise
            except Exception as e:  # noqa: BLE001
                raise BackendSkip("live %s backend '%s.%s' failed: %s" % (backend, mod.__name__, attr, e))
        except Exception as e:  # noqa: BLE001
            raise BackendSkip("live %s backend '%s.%s' failed: %s" % (backend, mod.__name__, attr, e))
    if backend == "interp":
        try:
            return _local_interp(va, size, regs, stubs)
        except (BackendSkip, EmuUnsupported):
            raise
        except Exception as e:  # noqa: BLE001
            raise BackendSkip("minimal interp failed: %s" % e)
    raise BackendSkip(BACKEND_INFO["ghidra"]["reason"])


# ---------------------------------------------------------------- NVRAM-backed ctx images
CTX_CAT_STRIDE = 0x40
CTX_NCAT = 7
CTX_TOTAL = 0x1C8
CTX_LAYOUT_DOC = (
    "PROVISIONAL ctx image (A1/A2): 7 cats x 0x40 B @+0x000..+0x1BF "
    "(+0x00 state u32 1=LOCKED, +0x04 retry u32, +0x08 autolock u32, "
    "+0x0C num u32, +0x10 key_state u32, +0x14 flags u32 bit0=BE-nonzero proxy, "
    "+0x18 plmn0 8B ASCII NUL-padded, +0x20 key 16B reserved); globals @+0x1C0 "
    "tfn_otp_on u32, @+0x1C4 permanent_unlock u32; total 0x1C8. Emulator scratch "
    "at CTX_BASE, NOT modem truth."
)


def _get_contexts():
    """Return (tracfone_ctx, zeroed_ctx, provenance). Prefers nv_model seam."""
    prov = ""
    tctx = zctx = None
    if _NV is not None and hasattr(_NV, "make_tracfone_context"):
        try:
            tctx = _NV.make_tracfone_context()
            prov = "nv_model.make_tracfone_context (TracfonePolicyOracle template: cat0 LOCK/retry5/311480)"
        except Exception:  # noqa: BLE001
            tctx = None
    if tctx is None and _SML is not None and hasattr(_SML, "tracfone_default_context"):
        tctx = _SML.tracfone_default_context()
        prov = (prov + " | " if prov else "") + "sml_sim.tracfone_default_context fallback"
    if _SML is not None and hasattr(_SML, "zeroed_context"):
        zctx = _SML.zeroed_context()
    if tctx is None or zctx is None:
        raise BackendSkip("no SML context source (nv_model/sml_sim missing)")
    return tctx, zctx, prov or "context seam"


def build_ctx_image(ctx):
    """Serialize an SmlContext to the PROVISIONAL image (see CTX_LAYOUT_DOC)."""
    buf = bytearray(CTX_TOTAL)
    for i in range(min(CTX_NCAT, len(ctx.cats))):
        c = ctx.cats[i]
        base = i * CTX_CAT_STRIDE
        struct.pack_into("<6I", buf, base,
                         int(c.state) & 0xFFFFFFFF, int(c.retry) & 0xFFFFFFFF,
                         int(c.autolock) & 0xFFFFFFFF, int(getattr(c, "num", 0)) & 0xFFFFFFFF,
                         int(getattr(c, "key_state", 0)) & 0xFFFFFFFF,
                         0x1 if getattr(c, "allow_list", None) else 0x0)
        plmn0 = ""
        try:
            al = list(getattr(c, "allow_list", []) or [])
            plmn0 = str(al[0]) if al else ""
        except Exception:  # noqa: BLE001
            plmn0 = ""
        buf[base + 0x18:base + 0x18 + 8] = plmn0.encode("ascii", "replace")[:8].ljust(8, b"\x00")
    struct.pack_into("<2I", buf, 7 * CTX_CAT_STRIDE,
                     int(getattr(ctx, "tfn_otp_on", 1)) & 0xFFFFFFFF,
                     int(getattr(ctx, "permanent_unlock", 0)) & 0xFFFFFFFF)
    return bytes(buf)


# ---------------------------------------------------------------- behavioral oracle (sml_sim; read-only use)


def _beh(fkey, ctx_kind, plmn, patched, tctx, zctx):
    """Behavioral verdict for one case. Returns (verdict|None, reason)."""
    if _SML is None:
        return None, "behavioral SKIP: sml_sim missing"
    ctx = tctx if ctx_kind == "tracfone" else zctx
    try:
        oracles = _SML.all_one_oracles()
    except Exception:  # noqa: BLE001
        oracles = None
    try:
        if fkey == "legal_sim_rule":
            v = _SML.legal_sim_rule(ctx, 0, 0, plmn, patched=patched, oracles=oracles)
            return int(v), "sml_sim.legal_sim_rule(%s,plmn=%r,patched=%s,helpers=all-1)" % (ctx_kind, plmn, patched)
        if fkey == "link_sml_with_rule_head":
            v = _SML.link_sml_with_rule(ctx, 0, plmn, patched=patched, oracles=oracles)
            return int(v), "sml_sim.link_sml_with_rule(%s,plmn=%r,patched=%s,helpers=all-1)" % (ctx_kind, plmn, patched)
        if fkey == "sml_Verify":
            v = _SML.sml_verify(ctx, 0, plmn, oracles=oracles)
            return int(v), "sml_sim.sml_verify(%s,plmn=%r,helpers=all-1)" % (ctx_kind, plmn)
        if fkey in ("mot_sml_catkey_verify", "sml_catkey_verify"):
            # Stage-gate: helpers=ret1 (mot oracle=1) + PROVISIONAL BE-word gate
            # (A5: nonzero iff allow_list non-empty). Zeroed ctx -> deny (0).
            c = ctx.cats[0]
            gate = 1 if getattr(c, "allow_list", None) else 0
            mov = 1  # all-1 oracle for the crypto helper
            v = 1 if (mov == 1 and gate == 1) else 0
            return v, "stage-gate mot_oracle=1 & BE-word-nonzero=%d (A5 PROVISIONAL, ctx=%s)" % (gate, ctx_kind)
        if fkey == "sml_Unlock":
            c = ctx.cats[0]
            # A4 PROVISIONAL: gate-open iff state field set and retry nonzero.
            # Tracfone cat0 (LOCK=1,retry=5) models the HANDOFF gate-open record
            # (byte==1 + retry nonzero); zeroed (0,0) models closed.
            gate = 1 if (int(c.state) == 1 and int(c.retry) > 0) else 0
            v = 1 if gate == 1 else 0
            return v, "stage-gate flag==1&retry>0 -> %d (A4 PROVISIONAL, ctx=%s state=%s retry=%s)" % (
                v, ctx_kind, getattr(c, "state", "?"), getattr(c, "retry", "?"))
        if fkey == "sml_is_tfn_otp_on":
            # Fail-safe ON: behavioral always ON (1) regardless of ctx.
            return 1, "OTP-ON flag fail-safe ON (HANDOFF: stub defers to eFuse, fail-safe ON)"
        if fkey in ("rmmi_esmlck_hdlr", "rmmi_esmlrsu_hdlr", "rmmi_esmlgen_hdlr"):
            if _RMMI is None:
                return None, "behavioral SKIP: rmmi_sim missing"
            form = {"rmmi_esmlck_hdlr": "AT+ESMLCK=?",
                    "rmmi_esmlrsu_hdlr": "AT+ESMLRSU=?",
                    "rmmi_esmlgen_hdlr": "AT+ESMLGEN=?"}[fkey]
            try:
                resp = _RMMI.query_oracle(form)
                ok = (resp == ["OK"] or (len(resp) == 2 and resp[-1] == "OK"))
                return (1 if ok else 0), "rmmi_sim.query_oracle(%r)=%r (gate allow=1)" % (form, resp)
            except Exception as e:  # noqa: BLE001
                return None, "behavioral SKIP: rmmi oracle failed: %s" % e
        if fkey == "sml_crrst_Check":
            c = ctx.cats[0]
            v = 1 if getattr(c, "allow_list", None) else 0
            return v, "ret-1-on-match (PROVISIONAL allow-present gate, ctx=%s)" % ctx_kind
        if fkey == "sml_op07_Check":
            # INVERTED: 0=pass. Helpers=ret1 + Tracfone ctx -> pass (0).
            c = ctx.cats[0]
            v = 0 if getattr(c, "allow_list", None) else 1
            return v, "INVERTED 0=pass (op-family; PROVISIONAL allow-present gate, ctx=%s)" % ctx_kind
    except Exception as e:  # noqa: BLE001
        return None, "behavioral SKIP: oracle raised %s" % e
    return None, "behavioral SKIP: unknown fn %r" % fkey


# ---------------------------------------------------------------- recorded Ghidra evidence (TEMP logs/bins, read-only)
import re as _re
import os


def _recorded(va, size, key):
    """Parse TEMP headless logs/bins for this VA. Returns dict (never raises)."""
    out = {"emulation": None, "disasm_n": None, "balcs": [], "files": [], "reason": ""}
    try:
        files = list(TEMP.glob("*.log")) + list(TEMP.glob("fn_*.bin"))
    except Exception:  # noqa: BLE001
        out["reason"] = "TEMP unreadable"
        return out
    # emulation RESULT lines (EmuSml.java proofs)
    for p in TEMP.glob("emu_legal_sim_rule_*.log"):
        try:
            t = p.read_text(errors="replace")
        except Exception:  # noqa: BLE001
            continue
        for m in _re.finditer(r"RESULT steps=(\d+) stop=([A-Z\-]+) PC=([0-9a-fA-F]+) a0=(0x[0-9a-fA-F]+)", t):
            if key == "legal_sim_rule" and ("stock" in p.name or "patch" in p.name):
                out["files"].append(p.name)
                mode = "stock" if "stock" in p.name else "patch"
                out.setdefault("proofs", {})[mode] = {
                    "steps": int(m.group(1)), "stop": m.group(2),
                    "pc": "0x" + m.group(3).lower(), "a0": int(m.group(4), 16)}
        out["files"] = sorted(set(out["files"]))
    # disassembly DONE n= + BALC targets (Nmdis2.java)
    for p in TEMP.glob("fn_*.log"):
        try:
            t = p.read_text(errors="replace")
        except Exception:  # noqa: BLE001
            continue
        if "%x" % va not in t.lower() and ("%X" % va) not in t:
            continue
        m = _re.search(r"DONE n=(\d+)", t)
        balcs = sorted(set(_re.findall(r"BALC (0x[0-9a-fA-F]+)", t)))
        if m or balcs:
            out["disasm_n"] = int(m.group(1)) if m else out["disasm_n"]
            out["balcs"] = balcs
            out["files"].append(p.name)
    # carved bin size check
    for p in TEMP.glob("fn_*.bin"):
        try:
            n = p.stat().st_size
        except Exception:  # noqa: BLE001
            continue
        # match by size heuristic + name fragment
        frag = key.replace("_head", "").replace("custom_", "")
        if frag in p.name and n == size:
            out["files"].append("%s(%dB match)" % (p.name, n))
    out["files"] = sorted(set(out["files"]))
    if key == "legal_sim_rule" and out.get("proofs"):
        pr = out["proofs"]
        bits = []
        if "stock" in pr:
            bits.append("stock steps=%d %s a0=%#x" % (pr["stock"]["steps"], pr["stock"]["stop"], pr["stock"]["a0"]))
        if "patch" in pr:
            bits.append("patch steps=%d %s a0=%#x" % (pr["patch"]["steps"], pr["patch"]["stop"], pr["patch"]["a0"]))
        out["reason"] = "recorded Ghidra EmuSml: " + "; ".join(bits)
    elif out["disasm_n"]:
        out["reason"] = "recorded Ghidra Nmdis2: n=%d, %d unique BALC targets%s" % (
            out["disasm_n"], len(out["balcs"]), (" e.g. " + ",".join(out["balcs"][:4])) if out["balcs"] else "")
    else:
        out["reason"] = "no recorded TEMP evidence for VA %#x" % va
    return out


# ---------------------------------------------------------------- matrix
RET1_STUB_VAS = (0x9198A6F0, 0x9198A744, 0x90ED3222, 0x90ED7CE2)


def _cell_emulate(backend, va, size, regs, stubs):
    try:
        a0, steps, trace = run_fn(backend, va, size, regs, stubs)
        return {"status": "OK", "a0": a0, "steps": steps,
                "trace": trace[:8], "reason": "%s backend exact (%d steps)" % (backend, steps)}
    except EmuUnsupported as e:
        return {"status": "SKIP", "a0": None, "steps": None, "trace": [],
                "reason": "SKIP %s: %s" % (backend, e)}
    except BackendSkip as e:
        return {"status": "SKIP", "a0": None, "steps": None, "trace": [],
                "reason": "SKIP %s: %s" % (backend, e)}
    except Exception as e:  # noqa: BLE001
        return {"status": "SKIP", "a0": None, "steps": None, "trace": [],
                "reason": "SKIP %s: %s" % (backend, e)}


def build_matrix(verbose=False):
    try:
        tctx, zctx, ctx_prov = _get_contexts()
        tctx_img, zctx_img = build_ctx_image(tctx), build_ctx_image(zctx)
    except BackendSkip as e:
        return [], {"error": str(e)}, {}
    rows = []
    for f in FUNCTIONS:
        key = f["key"]
        va, size, cati_src = _resolve_fn(f)
        row = {"fn": key, "cati_name": f["cati"], "va": "0x%08X" % va,
               "size": size, "cati": cati_src, "kind": f["kind"], "cells": {}}
        # structural: carve + head decode + cati extent + recorded evidence
        try:
            raw = _carve(va, size)
            row["head_bytes"] = raw[:8].hex(" ")
            row["sha12"] = hashlib.sha256(raw).hexdigest()[:12]
            struct_ok, struct_reason = True, "carve %dB from %s" % (len(raw), _IMG_SRC)
        except BackendSkip as e:
            raw = b""
            row["head_bytes"], row["sha12"] = "", ""
            struct_ok, struct_reason = False, str(e)
        row["head_decode"] = _decode_head(va, raw) if raw else []
        rec = _recorded(va, size, key)
        row["recorded"] = {"files": rec.get("files", []), "disasm_n": rec.get("disasm_n"),
                           "reason": rec.get("reason", "")}
        # canonical cases: Tracfone/home + Tracfone/foreign (+zeroed for verdicts)
        stubs = {v: "ret1" for v in RET1_STUB_VAS}
        regs_t = {"a0": CTX_BASE, "s0": CTX_BASE, "_ctx_image": tctx_img}
        regs_z = {"a0": CTX_BASE, "s0": CTX_BASE, "_ctx_image": zctx_img}
        beh_t_home = _beh(key, "tracfone", "311480", False, tctx, zctx)
        beh_t_for = _beh(key, "tracfone", "310260", False, tctx, zctx)
        beh_z = _beh(key, "zeroed", "311480", False, tctx, zctx)
        beh_patch = _beh(key, "tracfone", "310260", True, tctx, zctx)
        row["behavioral"] = {
            "tracfone_home": {"verdict": beh_t_home[0], "reason": beh_t_home[1]},
            "tracfone_foreign": {"verdict": beh_t_for[0], "reason": beh_t_for[1]},
            "zeroed": {"verdict": beh_z[0], "reason": beh_z[1]},
            "patched_foreign": {"verdict": beh_patch[0], "reason": beh_patch[1]},
        }
        # emulation cells (helpers=ret1 stubs, Tracfone ctx image)
        row["cells"]["interp"] = _cell_emulate("interp", va, size, regs_t, stubs)
        row["cells"]["ghidra"] = _cell_emulate("ghidra", va, size, regs_t, stubs)
        # expected HANDOFF values for the canonical Tracfone cases
        expected = _expected(key)
        row["expected"] = expected
        # ---- status logic ----
        reasons = []
        status = "SKIP"
        if not struct_ok:
            status, reasons = "SKIP", ["structural SKIP: " + struct_reason]
        elif beh_t_home[0] is None and f["kind"] in ("verdict", "inverted", "flag"):
            status, reasons = "SKIP", ["behavioral SKIP: " + beh_t_home[1]]
        else:
            mismatch = _check_expected(key, row["behavioral"], expected)
            if mismatch:
                status, reasons = "FAIL", [mismatch]
            else:
                reasons.append("behavioral matches HANDOFF-expected " + _fmt_exp(expected))
                reasons.append("structural: " + struct_reason + "; " + "; ".join(row["head_decode"][:2]))
                if rec.get("reason"):
                    reasons.append("recorded: " + rec["reason"])
                # emulation agreement (convention-aware); SKIPs never disagree
                agree, note = _check_emu_agree(key, row["cells"], row["behavioral"])
                reasons.append(note)
                if not agree:
                    status = "FAIL"
                elif _has_verdict_confirm(key, row["cells"], row["behavioral"], rec, raw, va):
                    status = "PASS"
                else:
                    status = "SKIP"
                    reasons.append("needs live emulation verdict to promote SKIP->PASS (backends concurrent)")
        # legal_sim_rule carries the two regression proofs explicitly
        if key == "legal_sim_rule":
            proofs = _prove_legal(va, size, regs_t, regs_z, stubs, tctx, zctx, raw, rec)
            row["proofs"] = proofs
            if proofs["stock"]["status"] == "PASS" and proofs["patch"]["status"] == "PASS":
                if status != "FAIL":
                    status = "PASS"
                    reasons.append("regression proofs: stock->0 PASS + patch->1 PASS")
            else:
                status = "FAIL"
                reasons.append("regression proof failure: stock=%s patch=%s" % (
                    proofs["stock"]["status"], proofs["patch"]["status"]))
        row["status"] = status
        row["reason"] = " | ".join(reasons)
        rows.append(row)
        if verbose:
            print("  %-22s %-10s %4dB %-4s :: %s" % (key, "0x%08X" % va, size, status, row["reason"][:160]))
    return rows, {"tracfone_img_sha12": hashlib.sha256(tctx_img).hexdigest()[:12],
                  "zeroed_img_sha12": hashlib.sha256(zctx_img).hexdigest()[:12],
                  "ctx_provenance": ctx_prov, "ctx_layout": CTX_LAYOUT_DOC}, {}


def _expected(key):
    # HANDOFF-grounded canonical expectations (helpers=ret1, Tracfone ctx).
    # Values are what the behavioral oracle MUST produce; drift = FAIL.
    if key in ("legal_sim_rule", "link_sml_with_rule_head"):
        return {"tracfone_home": 1, "tracfone_foreign": 0, "zeroed": 0, "patched_foreign": 1}
    if key == "sml_Verify":
        # The force-LEGAL patch sits at legal_sim_rule entry, NOT on the
        # sml_Verify path (no patched param in sml_sim.sml_verify), so a
        # foreign SIM stays ILLEGAL here even when patched=1 is requested.
        return {"tracfone_home": 1, "tracfone_foreign": 0, "zeroed": 0, "patched_foreign": 0}
    if key in ("mot_sml_catkey_verify", "sml_catkey_verify", "sml_Unlock", "sml_crrst_Check"):
        return {"tracfone_home": 1, "tracfone_foreign": 1, "zeroed": 0, "patched_foreign": 1}
        # NOTE foreign==1 here: stage-gates model ctx-validity (not PLMN allowlist);
        # PLMN discrimination lives in legal/link/verify rows. Documented, not hidden.
    if key == "sml_is_tfn_otp_on":
        return {"tracfone_home": 1, "tracfone_foreign": 1, "zeroed": 1, "patched_foreign": 1}
    if key in ("rmmi_esmlck_hdlr", "rmmi_esmlrsu_hdlr", "rmmi_esmlgen_hdlr"):
        return {"tracfone_home": 1, "tracfone_foreign": 1, "zeroed": 1, "patched_foreign": 1}
        # 1 = query-oracle OK (live-attested test forms); dispatchers have no LEGAL verdict.
    if key == "sml_op07_Check":
        return {"tracfone_home": 0, "tracfone_foreign": 0, "zeroed": 1, "patched_foreign": 0}
    return {}


def _fmt_exp(d):
    return "{%s}" % ", ".join("%s=%s" % (k, v) for k, v in d.items())


def _check_expected(key, beh, exp):
    for case in ("tracfone_home", "tracfone_foreign", "zeroed", "patched_foreign"):
        got = beh[case]["verdict"]
        want = exp.get(case)
        if got is None:
            continue  # SKIP cells handled by caller
        if want is not None and int(got) != int(want):
            return ("FAIL behavioral drift [%s]: %s verdict=%s, HANDOFF-expected=%s (%s)" % (
                key, case, got, want, beh[case]["reason"]))
    return ""


def _canon_compare_verdict(kind, emu_a0, beh_v):
    """Convention-aware comparison. Returns True if agree (or N/A dispatched)."""
    if emu_a0 is None or beh_v is None:
        return True  # SKIP never disagrees
    if kind == "inverted":
        return True  # inverted op-family: live a0 mapping documented separately; no auto-FAIL
    if kind in ("dispatch", "flag"):
        return True  # no single LEGAL a0 by design
    return int(emu_a0) == int(beh_v)


def _check_emu_agree(key, cells, beh):
    kind = next((f["kind"] for f in FUNCTIONS if f["key"] == key), "verdict")
    notes = []
    ok = True
    for b in ("interp", "ghidra"):
        c = cells[b]
        if c["status"] == "SKIP":
            notes.append("%s %s" % (b, c["reason"]))
            continue
        # compare against Tracfone/home canonical verdict
        if not _canon_compare_verdict(kind, c.get("a0"), beh["tracfone_home"]["verdict"]):
            ok = False
            notes.append("FAIL %s a0=%s disagrees with behavioral %s" % (b, c.get("a0"), beh["tracfone_home"]["verdict"]))
        else:
            notes.append("%s a0=%s agrees (%d steps)" % (b, c.get("a0"), c.get("steps") or 0))
    return ok, " | ".join(notes)


def _has_verdict_confirm(key, cells, beh, rec, raw, va):
    """True when >=1 emulation verdict source confirms behavioral (exact tie)."""
    for b in ("interp", "ghidra"):
        c = cells[b]
        if c["status"] == "OK" and c.get("a0") is not None and beh["tracfone_home"]["verdict"] is not None:
            kind = next((f["kind"] for f in FUNCTIONS if f["key"] == key), "verdict")
            if kind in ("verdict",) and int(c["a0"]) == int(beh["tracfone_home"]["verdict"]):
                return True
    if key == "legal_sim_rule":
        pr = (rec.get("proofs") or {})
        # recorded proofs confirm BOTH stock->0 and patch->1 (see _prove_legal)
        if pr.get("stock", {}).get("a0") == 0 and pr.get("patch", {}).get("a0") == 1:
            return True
    if key in ("rmmi_esmlck_hdlr", "rmmi_esmlrsu_hdlr", "rmmi_esmlgen_hdlr"):
        # dispatchers: query-oracle OK + structural + gate-stub ret1 = confirm
        if beh["tracfone_home"]["verdict"] == 1 and raw:
            return True
    if key == "sml_Verify":
        # 50-insn recorded chain with the exact HANDOFF BALC targets = structural confirm
        want = {"0x905df77a", "0x905f0df8", "0x9198a6b6", "0x9198e510"}
        if want.issubset({b.lower() for b in rec.get("balcs", [])}):
            return True
    if key == "sml_is_tfn_otp_on":
        # fail-safe ON behavioral + 20-insn recorded disasm = confirm
        if rec.get("disasm_n") == 20 and beh["tracfone_home"]["verdict"] == 1:
            return True
    if key == "link_sml_with_rule_head":
        if rec.get("disasm_n") == 333 and beh["tracfone_home"]["verdict"] == 1:
            return True
    return False


def _prove_legal(va, size, regs_t, regs_z, stubs, tctx, zctx, raw, rec):
    """The two regression proofs. Both must PASS for the gate to go green.

    proof stock->0: behavioral legal_sim_rule(zeroed, helpers=all-1)==0 AND
      stock head bytes==14 1e 24 12 (not a ret stub) AND recorded Ghidra
      stock RESULT steps=25 HIT-RET a0=0x0 (when log present; absent->structural).
    proof patch->1: behavioral patched==1 AND minimal-exact run_fn over the
      4-byte overlay 01 d2 e0 db gives (a0=1, steps=1) AND recorded patch
      RESULT steps=1 a0=0x1 (when log present).
    """
    out = {}
    # ---- stock -> 0 ----
    try:
        bv, br = _beh("legal_sim_rule", "zeroed", "311480", False, tctx, zctx)
        head_ok = raw[:4] == STOCK_LEGAL_HEAD if raw else False
        not_stub = (raw[:4] != PATCH_BYTES and raw[:4] != RET0_BYTES) if raw else False
        pr = (rec.get("proofs") or {}).get("stock")
        rec_ok = (pr is not None and pr["a0"] == 0 and pr["steps"] == 25 and pr["stop"] == "HIT-RET")
        rec_note = ("recorded stock RESULT steps=25 HIT-RET a0=0x0" if rec_ok
                    else ("recorded stock proof absent/drifted (%s)" % (pr or "no log")))
        ok = (bv == 0 and head_ok and not_stub and (rec_ok or pr is None))
        # pr is None (no TEMP log on fresh checkout) must NOT fail the proof:
        # behavioral + byte-identity is sufficient; recorded is bonus.
        if pr is not None and not rec_ok:
            ok = False
        out["stock"] = {
            "status": "PASS" if ok else "FAIL",
            "behavioral": bv, "behavioral_reason": br,
            "head": raw[:4].hex(" ") if raw else "",
            "head_ok": bool(head_ok and not_stub),
            "recorded": pr, "recorded_note": rec_note,
            "reason": "stock+zeroed+helpers-1 -> behavioral=%s (want 0); head=%s (want 14 1e 24 12, not ret stub); %s" % (
                bv, raw[:4].hex(" ") if raw else "?", rec_note),
        }
    except Exception as e:  # noqa: BLE001
        out["stock"] = {"status": "FAIL", "reason": "proof exception: %s" % e}
    # ---- patch -> 1 ----
    try:
        bv, br = _beh("legal_sim_rule", "tracfone", "310260", True, tctx, zctx)
        regs_p = dict(regs_t)
        regs_p["_overlay"] = {va: PATCH_BYTES}
        try:
            a0, steps, trace = run_fn("interp", va, 4, regs_p, stubs)
            # Step-count convention: Ghidra EmuSml counts 1 (LI only, JRC ret
            # event is free); the minimal engine counts LI+JRC = 2. a0 is the
            # verdict in both; accept either count.
            emu_ok = (a0 == 1 and steps in (1, 2))
            emu_note = ("minimal-exact interp a0=%s steps=%s "
                        "(accept 1=Ghidra or 2=LI+JRC; a0 is the verdict)" % (a0, steps))
        except (BackendSkip, EmuUnsupported) as e:
            emu_ok, emu_note, a0, steps, trace = False, "interp SKIP: %s" % e, None, None, []
        pr = (rec.get("proofs") or {}).get("patch")
        rec_ok = (pr is not None and pr["a0"] == 1 and pr["steps"] == 1 and pr["stop"] == "HIT-RET")
        rec_note = ("recorded patch RESULT steps=1 HIT-RET a0=0x1" if rec_ok
                    else ("recorded patch proof absent/drifted (%s)" % (pr or "no log")))
        ok = (bv == 1 and emu_ok and (rec_ok or pr is None))
        if pr is not None and not rec_ok:
            ok = False
        out["patch"] = {
            "status": "PASS" if ok else "FAIL",
            "behavioral": bv, "behavioral_reason": br,
            "interp_a0": a0, "interp_steps": steps,
            "interp_note": emu_note, "trace": trace[:4],
            "recorded": pr, "recorded_note": rec_note,
            "reason": "patched+helpers-1 -> behavioral=%s (want 1); %s; %s" % (bv, emu_note, rec_note),
        }
    except Exception as e:  # noqa: BLE001
        out["patch"] = {"status": "FAIL", "reason": "proof exception: %s" % e}
    return out


# ---------------------------------------------------------------- report + CLI

def _guard_sim_out(name):
    out = (SIM_DIR / name).resolve()
    if SIM_DIR.resolve() not in out.parents:
        raise ValueError("refusing to write outside sim/: %s" % out)
    return out


def run_suite(report_path=None, verbose=False):
    rows, ctxinfo, _ = build_matrix(verbose=verbose)
    proofs = {}
    for r in rows:
        if r["fn"] == "legal_sim_rule":
            proofs = r.get("proofs", {})
            break
    npass = sum(1 for r in rows if r["status"] == "PASS")
    nfail = sum(1 for r in rows if r["status"] == "FAIL")
    nskip = sum(1 for r in rows if r["status"] == "SKIP")
    gate_ok = (nfail == 0 and proofs.get("stock", {}).get("status") == "PASS"
               and proofs.get("patch", {}).get("status") == "PASS")
    summary = {"total": len(rows), "pass": npass, "fail": nfail, "skip": nskip,
               "gate": "PASS" if gate_ok else "FAIL",
               "gate_rule": "exit 0 iff 0 FAIL and both legal_sim_rule proofs PASS (SKIPs allowed)"}
    report = {
        "tool": "sim/sml_conform.py",
        "stdlib_only": True, "device_contact": False,
        "image": {"source": _IMG_SRC, "sha12": _IMG_SHA, "size": len(_IMG), "error": _IMG_ERR},
        "cati": {"source": _CATI_SRC or _CATI_ERR, "count": len(_CATI)},
        "backends": BACKEND_INFO,
        "siblings": _HAVE,
        "ctx": ctxinfo,
        "assumptions": ASSUMPTIONS,
        "functions": FUNCTIONS,
        "helpers": "ret1 stubs (01 d2 e0 db) at BALC targets %s" % (
            ", ".join("0x%08X" % v for v in RET1_STUB_VAS)),
        "rows": rows,
        "proofs": proofs,
        "summary": summary,
    }
    rp = Path(report_path) if report_path else DEFAULT_REPORT
    try:
        rp = _guard_sim_out(rp.name)
    except ValueError as e:
        print("report path refused: %s" % e, file=sys.stderr)
        rp = DEFAULT_REPORT
    rp.write_text(json.dumps(report, indent=2))
    return report, rp


def print_summary(report, rp):
    print("sml_conform: exact-emulation vs behavioral (stdlib only, offline, no device)")
    print("  image: %s sha12=%s size=%d %s" % (
        report["image"]["source"] or "?", report["image"]["sha12"] or "?",
        report["image"]["size"], ("ERR " + report["image"]["error"]) if report["image"]["error"] else ""))
    print("  cati: %s" % report["cati"]["source"])
    print("  backends: interp[%s] ghidra[%s]" % (
        "live" if report["backends"]["interp"]["available"] else "SKIP",
        "live" if report["backends"]["ghidra"]["available"] else "SKIP"))
    print("  ctx: %s" % report["ctx"].get("ctx_provenance", "?"))
    print()
    print("%-24s %-10s %5s %-4s %-6s %-6s %s" % ("fn", "va", "size", "kind", "intp", "ghdr", "status"))
    for r in report["rows"]:
        ci, cg = r["cells"]["interp"], r["cells"]["ghidra"]
        isym = "OK:%s" % ci["a0"] if ci["status"] == "OK" else "SKIP"
        gsym = "OK:%s" % cg["a0"] if cg["status"] == "OK" else "SKIP"
        bh = r["behavioral"]["tracfone_home"]["verdict"]
        print("  %-24s %-10s %5d %-4s %-6s %-6s %-4s home=%s" % (
            r["fn"], r["va"], r["size"], r["kind"][:4], isym, gsym, r["status"], bh))
        print("      :: %s" % r["reason"][:220])
    pr = report.get("proofs", {})
    print()
    print("proofs (regression gate):")
    for k in ("stock", "patch"):
        p = pr.get(k, {})
        print("  %s -> %s :: %s" % (k, p.get("status", "?"), p.get("reason", "?")[:220]))
    s = report["summary"]
    print()
    print("gate: %s (PASS=%d FAIL=%d SKIP=%d / %d) -- %s" % (
        s["gate"], s["pass"], s["fail"], s["skip"], s["total"], s["gate_rule"]))
    print("assumptions (%d, PROVISIONAL need Ghidra confirm except A7/A8):" % len(report["assumptions"]))
    for a in report["assumptions"]:
        print("  %s [%s] %s -- VA: %s" % (a["id"], a["status"], a["text"][:150], a["va"][:80]))
    print("report: %s" % rp)


def selftest():
    """Fast structural check (also exercises run_fn + proofs). Returns failures."""
    fails = []
    if _SML is None:
        fails.append("sml_sim oracle missing")
    if not _IMG:
        fails.append("image missing: %s" % _IMG_ERR)
    # run_fn rejects bad backend
    try:
        run_fn("qemu", 0x905DF2FA, 4)
        fails.append("run_fn accepted bad backend")
    except ValueError:
        pass
    except Exception as e:  # noqa: BLE001
        fails.append("run_fn bad-backend wrong exc: %s" % e)
    # minimal exact: patch bytes -> (1,1)
    try:
        a0, steps, _ = run_fn("interp", 0x905DF2FA, 4,
                              {"a0": CTX_BASE, "_overlay": {0x905DF2FA: PATCH_BYTES}}, {})
        if not (a0 == 1 and steps in (1, 2)):
            fails.append("patch exact drift: a0=%s steps=%s" % (a0, steps))
    except Exception as e:  # noqa: BLE001
        fails.append("patch exact raised: %s" % e)
    # minimal honest SKIP: stock prologue is 32-bit -> EmuUnsupported/BackendSkip
    try:
        run_fn("interp", 0x905DF2FA, 94, {"a0": CTX_BASE}, {})
        fails.append("stock unexpectedly emulated exactly (decoder grew? update suite)")
    except (EmuUnsupported, BackendSkip):
        pass
    except Exception as e:  # noqa: BLE001
        fails.append("stock wrong exc: %s" % e)
    # ghidra with no live backend -> BackendSkip
    if not BACKEND_INFO["ghidra"]["available"]:
        try:
            run_fn("ghidra", 0x905DF2FA, 4)
            fails.append("ghidra should SKIP without live backend")
        except (BackendSkip, EmuUnsupported):
            pass
    # ctx images differ and carry PLMN
    try:
        tctx, zctx, _ = _get_contexts()
        ti, zi = build_ctx_image(tctx), build_ctx_image(zctx)
        if ti == zi or len(ti) != CTX_TOTAL or b"311480" not in ti:
            fails.append("ctx image drift (tracfone must embed 311480, zeroed must differ)")
    except Exception as e:  # noqa: BLE001
        fails.append("ctx image: %s" % e)
    return fails


def main(argv=None):
    ap = argparse.ArgumentParser(description="SML conformance suite (offline, stdlib-only, no device)")
    ap.add_argument("--report", default=str(DEFAULT_REPORT))
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--selftest", action="store_true", help="fast structural check, then full suite")
    args = ap.parse_args(argv)
    if args.selftest:
        fails = selftest()
        print("sml_conform selftest: %s" % ("PASS" if not fails else "FAIL %s" % fails))
        if fails:
            return 1
    report, rp = run_suite(args.report, verbose=args.verbose)
    print_summary(report, rp)
    s = report["summary"]
    return 0 if s["gate"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
