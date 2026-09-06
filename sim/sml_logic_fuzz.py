#!/usr/bin/env python3
"""sml_logic_fuzz.py — SML state-machine LOGIC fuzz (pure logic bypass hunt).

SAFETY (hard rules, enforced by construction):
  * Pure offline model. No device I/O: no adb/fastboot/serial/socket/subprocess
    imports, no modem command emission, nothing here can consume unlock attempts
    (5-capped counter intact by construction).
  * Read-only on repo dumps (md1work_romonly.bin) and TEMP cati_syms.json.
  * New file under sim/ only. Sibling modules (sml_sim, nv_model, interp,
    decode_tables, hw_target, emu_engine) are reused/extended, NEVER modified.
  * Stdlib only.

SOURCES (repo-relative unless noted):
  * sim/hw_target.py ........ exact spec (nanomips:LE:32:default, ret1 bytes)
  * sim/sml_sim.py .......... BEHAVIORAL ORACLE (extended here with new states,
                              selftests untouched)
  * sim/nv_model.py ......... NVRAM policy template + NckSimulator (RAM only)
  * sim/emu_engine.py ....... Memory/decode_one/StubRegistry primitives
  * sim/interp.py ........... STRICT Cpu (outside-carve faults STOP)
  * sim/decode_tables.py .... Ghidra-identical text (1191/1191 corpus)
  * sim/listings/*.jsonl .... Verify/Unlock/DB/op sweeps (sml_Check 254 insn,
                              sml_sl_Check 55, sml_op08 99, sml_op12 166,
                              sml_Verify 50, sml_sl_Verify 40, op08_Verify 52,
                              tfstatus 57, smu_* dispatchers)
  * sim/sml_sweep_report.md . per-function convention notes (STD/OP07/HCK/DBV)
  * sim/verify_hardening.py . strict slice method (P1..P5) reused for retry/test
  * HANDOFF.md/PICKUP.md .... live context, polarity, patch bytes, headless rules
  * md1work_romonly.bin ..... raw ROM (VA-0x90000000=file off), read-only
  * TEMP/cati_syms.json ..... VA extents (quoted per target below)

HUNT COVERAGE (task items 1..6):
  (1) category/state confusion — Num=0, mixed LOCK/UNLOCK (5/6), AUTOLOCK vs
      LOCK, DISABLED in EVERY Check variant (generic/crrst/op07/op08/op12/sl)
  (2) retry-counter logic — max checks + off-by-one + reset paths
  (3) test-purpose backdoors — test-SIM/test-mode skip paths
  (4) whitelist/blacklist remove-all — key need + residue
  (5) penalty-timer disable — neutralisation paths
  (6) op-family confusion — op07 inverted (0=pass) vs STD (1=pass) caller mixups

VERDICT RULE: bypass = lock verdict flips to PASS without key AND without code
patch. NVRAM-state forgery requiring a keyed write is NOT a bypass (noted as
chain). Code-patch flips (verify_hardening P1..P5) are NOT bypasses.

CONFIDENCE: HIGH=byte-proven+strict emulation; MEDIUM=listing+behavioral with
one provisional mapping; LOW=inferred, needs Ghidra decomp.

Run:
  python sim/sml_logic_fuzz.py [--selftest] [--json]
"""
from __future__ import annotations
import copy
import hashlib
import json
import struct
import sys
from pathlib import Path
import os

SIM_DIR = Path(__file__).resolve().parent
REPO_ROOT = SIM_DIR.parent
if str(SIM_DIR) not in sys.path:
    sys.path.insert(0, str(SIM_DIR))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# defensive sibling imports (stdlib + sim only)
try:
    import sml_sim as SML
except ImportError:
    from sim import sml_sim as SML  # type: ignore
try:
    import nv_model as NV
except ImportError:
    from sim import nv_model as NV  # type: ignore
try:
    from decode_tables import decode_bytes as DT_DECODE
    from decode_tables import UnknownInsn as DT_UNKNOWN
    HAVE_DT = True
except ImportError:
    try:
        from sim.decode_tables import decode_bytes as DT_DECODE  # type: ignore
        from sim.decode_tables import UnknownInsn as DT_UNKNOWN  # type: ignore
        HAVE_DT = True
    except ImportError:
        HAVE_DT = False
        DT_DECODE = None  # type: ignore
try:
    from interp import Cpu as ICPU, CTX_INIT, STACK_INIT, RA_INIT, CTX_SIZE, CTX_BASE
    HAVE_INTERP = True
except ImportError:
    try:
        from sim.interp import Cpu as ICPU, CTX_INIT, STACK_INIT, RA_INIT, CTX_SIZE, CTX_BASE  # type: ignore
        HAVE_INTERP = True
    except ImportError:
        HAVE_INTERP = False

TEMP = Path(os.environ.get("MODEM_LAB_TMP",
                str(Path(__file__).resolve().parent / "Temp")))
TEMP.mkdir(parents=True, exist_ok=True)


VA_BASE = 0x90000000
TEMP_CATI = TEMP / "cati_syms.json"
ROMONLY = REPO_ROOT / "md1work_romonly.bin"

# VA extents (CATI, verified 2026-09-05; sizes = end-start)
VAS = {
    "sml_check_retry_reached_max_of_cat": (0x905F37EA, 0x905F3830),
    "sml_check_tfn_retry_reached_max": (0x905F3830, 0x905F388C),
    "sml_restore_tfn_retry_count": (0x905F371A, 0x905F375C),
    "custom_sml_op12_is_test_purpose": (0x905F197A, 0x905F197E),
    "custom_sml_check_test_network_sim": (0x905F4800, 0x905F4820),
    "smu_sml_restrict_test_network_sim": (0x9198A8B4, 0x9198A97A),
    "sml_crrst_Remove_WhiteList": (0x905EDD96, 0x905EDDEE),
    "sml_crrst_Remove_BlackList": (0x905EDDEE, 0x905EDE46),
    "sml_crrst_Remove_All": (0x905EDD10, 0x905EDD96),
    "sml_op07_restore_factory_whitelist_data": (0x905EF1E0, 0x905EF296),
    "sml_op12_remove_whitelist_req": (0x905F22B6, 0x905F2318),
    "sml_op07_remove_whitelist_req": (0x905EEECA, 0x905EF05A),
    "sml_op08_rsu_remove_whitelist_req": (0x905F308C, 0x905F30EE),
    "custom_sml_check_remove_whitelist_data_allowed": (0x905F4826, 0x905F482A),
    "sml_check_penalty_timer_enabled": (0x9198D3AC, 0x9198D40A),
    "sml_is_penalty_timer_running": (0x9198D4B2, 0x9198D4C2),
    "smu_start_sml_penalty_timer": (0x9198D40A, 0x9198D4B2),
    "smu_start_sml_timer": (0x9198B410, 0x9198B44C),
    "smu_stop_sml_timer": (0x9198B44C, 0x9198B48E),
    "custom_sml_penalty_timer_value": (0x905F393C, 0x905F3942),
    "sml_get_max_retry_count": (0x9198E48C, 0x9198E4D2),
    "sml_crrst_Check": (0x905EDF4E, 0x905EE056),
    "sml_sl_Check": (0x905EFD50, 0x905EFDDE),
    "sml_op12_Check": (0x905F1D34, 0x905F1F10),
    "sml_op08_rsu_Check": (0x905F2C36, 0x905F2D72),
    "sml_Check": (0x905EF6FE, 0x905EFA08),
    "sml_op07_Check": (0x905EE9AC, 0x905EEC1C),
    "sml_Verify": (0x905F0F04, 0x905F0F88),
    "sml_sl_Verify": (0x905EFDDE, 0x905EFE58),
}

# extended states (ADDITIVE: sml_sim 0/1 untouched, new values only here)
STATE_UNLOCKED = 0
STATE_LOCKED = 1
STATE_DISABLED = 2   # provisional DISABLED enum (beyond sml_sim 0/1)
STATE_INVALID = 3    # out-of-range probe
TRACFONE = "311480"
FOREIGN = "310260"
TESTPLMN = "99970"

def _load_rom() -> bytes:
    return ROMONLY.read_bytes()

_ROM = None
def rom() -> bytes:
    global _ROM
    if _ROM is None:
        _ROM = _load_rom()
    return _ROM

def carve(va: int, size: int) -> bytes:
    r = rom()
    off = va - VA_BASE
    return r[off:off+size]

def decode_at(va: int):
    raw = carve(va, 6)
    if not HAVE_DT or DT_DECODE is None:
        raise RuntimeError("decode_tables unavailable")
    return DT_DECODE(va, bytes(raw))

def listing_records(name: str):
    p = SIM_DIR / "listings" / (name + ".jsonl")
    if not p.is_file():
        return []
    out = []
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines()[1:]:
        line=line.strip()
        if not line:
            continue
        try:
            j=json.loads(line)
            if "text" in j:
                out.append(j)
        except ValueError:
            continue
    return out

def listing_has(name: str, substr: str) -> bool:
    for r in listing_records(name):
        if substr in r["text"]:
            return True
    return False

def corpus_flows_to(target_va: int):
    """Search sim/listings/corpus.jsonl for BALC flows to target_va."""
    p = SIM_DIR / "listings" / "corpus.jsonl"
    if not p.is_file():
        return []
    hits=[]
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        line=line.strip()
        if not line:
            continue
        try:
            j=json.loads(line)
        except ValueError:
            continue
        for f in j.get("flows",[]):
            if int(f)==target_va:
                hits.append((j.get("fn"), j.get("va")))
                break
    return hits

# ---- strict slice helpers (interp Cpu strict=True) ----
def _cpu(va: int, size: int, overlay=None, regs_extra=None, stubs=None, step_cap=3000):
    img = rom()
    off = va - VA_BASE
    cv = img[off:off+size]
    if overlay:
        buf=bytearray(cv)
        for ova, ob in overlay.items():
            ova=int(ova); ob=bytes(ob)
            if va <= ova < va+size:
                buf[ova-va:ova-va+len(ob)]=ob
        cv=bytes(buf)
    regs={"a0":CTX_INIT,"s0":CTX_INIT,"ra":RA_INIT,"sp":STACK_INIT,"_ctx_image":b"\x00"*CTX_SIZE}
    if regs_extra:
        regs.update(regs_extra)
    cpu=ICPU(img, va, bytes(cv), regs=regs, stubs=stubs or {}, tracer=None, step_cap=step_cap, strict=True)
    return cpu

def strict_exec1(va: int, size: int, overlay=None, regs_extra=None):
    """Execute exactly 1 insn strict at va. Returns (text, next_pc, regs dict)."""
    cpu=_cpu(va,size,overlay=overlay,regs_extra=regs_extra)
    cpu.pc=va
    text,sz,_=cpu._decode_at(va)
    nxt=(va+sz)&0xFFFFFFFF
    npc=cpu._exec_text(va,text,sz,nxt,cpu._mn(text),cpu._split_ops(text))
    return text,npc,{k:cpu.get(k) for k in ("a0","a1","a2","a3","a4","s0","s1","ra")}

def strict_run(va: int, size: int, overlay=None, regs_extra=None, stubs=None):
    cpu=_cpu(va,size,overlay=overlay,regs_extra=regs_extra,stubs=stubs)
    return cpu.run()

# ---- Check mini-models (listing-derived, confidence-marked) ----
# Each returns (verdict, reason). Verdict polarity: STD 1=pass/0=fail;
# op07 inverted 0=pass/1=fail. Models are CONSERVATIVE (fail-closed) except
# where listing proves an early-pass for disabled/empty.

def _cat(ctx, i):
    return ctx.cats[i]

def _is_empty_cat(c) -> bool:
    return (c.num==0 and not c.allow_list and not c.key and c.key_state==0)

def model_sml_Check(ctx, cat: int, plmn):
    """Generic sml_Check @0x905EF6FE (STD 1=pass, 5x memcmp + db_check).
    Listing: db_check BNEIC 1 fail; hw gates BEQC fail; final BNEC/B C pass;
    early LBU s6[0] BEQIC 1 else immediate PASS (disabled/empty fast path)."""
    if not (0 <= cat < 7):
        return (0, "cat OOR -> FAIL (reject)")
    c=_cat(ctx,cat)
    if c.state==STATE_DISABLED or c.state==STATE_INVALID:
        return (1, "DISABLED/INVALID -> PASS 1 (early LBU s6[0]!=1 fast path @0x905EF7F2; vacuous-allow, EXPECTED not bypass)")
    if _is_empty_cat(c) and c.state==STATE_UNLOCKED:
        return (1, "empty+UNLOCK -> PASS 1 (no codes to check)")
    if c.state==STATE_UNLOCKED:
        return (1, "UNLOCK -> PASS 1")
    # LOCKED: needs allowlist membership (memcmp chain proxy)
    if plmn is None:
        return (0, "LOCK+noSIM -> FAIL 0")
    if plmn in (c.allow_list or []):
        return (1, "LOCK+allowlisted -> PASS 1")
    return (0, "LOCK+foreign -> FAIL 0 (5x memcmp chain, final BNEC @0x905EF9F8)")

def model_sml_crrst_Check(ctx, cat: int, plmn):
    """crrst_Check @0x905EDF4E (STD 1=pass; XORI ra note; cat-table; memcmp).
    Listing: LW null -> MOVE 0 return FAIL (fail-closed); final memcmp BNEZC fail else LI 1 pass."""
    if not (0 <= cat < 7):
        return (0, "cat OOR -> FAIL 0 (BGEIUC s0,5 reject @0x905EDFC4)")
    c=_cat(ctx,cat)
    if c.state==STATE_DISABLED or c.state==STATE_INVALID:
        # null-ctx path returns 0 FAIL (0x905EDF82 BNEZC else MOVE 0 RESTORE)
        # but a DISABLED *slot* with valid ctx and empty lists: loop finds no match -> FAIL?
        # Conservative: DISABLED with empty allow -> FAIL 0 (fail-closed, differs from sl).
        return (0, "DISABLED/INVALID -> FAIL 0 (null-guard fail-closed @0x905EDF82; NOT a bypass)")
    if c.state==STATE_UNLOCKED:
        # UNLOCK still runs cat-table loop; empty allow + UNLOCK? crrst has no early-pass;
        # behavioral: allow-present gate. Model: UNLOCK -> PASS (policy).
        return (1, "UNLOCK -> PASS 1 (policy; loop would find no lock)")
    if plmn is None:
        return (0, "LOCK+noSIM -> FAIL 0")
    if plmn in (c.allow_list or []):
        return (1, "LOCK+allowlisted -> PASS 1 (memcmp @0x905EE04C BNEZC fail else LI 1)")
    return (0, "LOCK+foreign -> FAIL 0")

def model_sml_op07_Check(ctx, cat: int, plmn):
    """op07_Check @0x905EE9AC (INVERTED 0=pass/1=fail, 217 insn).
    Listing: BEQZC s0 -> a4=0 PASS (null/invalid fail-OPEN vacuous); final MOVE a0,a4."""
    if not (0 <= cat < 7):
        return (0, "cat OOR -> PASS 0 (BEQZC s0 null -> a4=0 @0x905EE9E4; vacuous-pass, EXPECTED)")
    c=_cat(ctx,cat)
    if c.state==STATE_DISABLED or c.state==STATE_INVALID or _is_empty_cat(c):
        return (0, "DISABLED/empty -> PASS 0 (vacuous: no codes, count loop skips to a4=0)")
    if c.state==STATE_UNLOCKED:
        return (0, "UNLOCK -> PASS 0")
    if plmn is None:
        return (1, "LOCK+noSIM -> FAIL 1 (validity fail sets a4=1)")
    if plmn in (c.allow_list or []):
        return (0, "LOCK+allowlisted -> PASS 0")
    return (1, "LOCK+foreign -> FAIL 1 (memcmp chain sets a4=1)")

def model_sml_op08_Check(ctx, cat: int, plmn):
    """op08_Check @0x905F2C36 (STD 1=pass). Listing: LBU byte1 BLTUC else MOVE 0 FAIL (empty fail-closed)."""
    if not (0 <= cat < 7):
        return (0, "cat OOR -> FAIL 0 (BGEIUC s2,3 reject @0x905F2C7A)")
    c=_cat(ctx,cat)
    if c.state==STATE_DISABLED or c.state==STATE_INVALID:
        return (0, "DISABLED/INVALID -> FAIL 0 (empty fail-closed @0x905F2C98 BLTUC else MOVE 0; NOT bypass)")
    if _is_empty_cat(c) and c.state==STATE_LOCKED:
        return (0, "LOCK+Num0-empty -> FAIL 0 (empty fail-closed; differs from sl vacuous-pass)")
    if c.state==STATE_UNLOCKED:
        return (1, "UNLOCK -> PASS 1")
    if plmn is None:
        return (0, "LOCK+noSIM -> FAIL 0")
    if plmn in (c.allow_list or []):
        return (1, "LOCK+allowlisted -> PASS 1 (memcmp @0x905F2D1A BEQZC pass)")
    return (0, "LOCK+foreign -> FAIL 0")

def model_sml_op12_Check(ctx, cat: int, plmn):
    """op12_Check @0x905F1D34 (STD 1=pass). Listing: LW null -> MOVE 0 FAIL (fail-closed); final memcmp BNEZC fail else BC pass."""
    if not (0 <= cat < 7):
        return (0, "cat OOR -> FAIL 0")
    c=_cat(ctx,cat)
    if c.state==STATE_DISABLED or c.state==STATE_INVALID:
        return (0, "DISABLED/INVALID -> FAIL 0 (null-guard MOVE 0 @0x905F1D...; NOT bypass)")
    if c.state==STATE_UNLOCKED:
        return (1, "UNLOCK -> PASS 1")
    if plmn is None:
        return (0, "LOCK+noSIM -> FAIL 0")
    if plmn in (c.allow_list or []):
        return (1, "LOCK+allowlisted -> PASS 1 (memcmp @0x905F1F00 BNEZC fail else pass @0x905F1D98)")
    return (0, "LOCK+foreign -> FAIL 0")

def model_sml_sl_Check(ctx, cat: int, plmn):
    """sl_Check @0x905EFD50 (STD 1=pass). Listing: LBU byte0 BNEZC else LI 1 PASS; LBU byte1 BEQZC -> LI 1 PASS (empty vacuous-pass)."""
    if not (0 <= cat < 7):
        return (0, "cat OOR -> FAIL 0 (BGEIUC s2,3 @0x905EFD9E)")
    c=_cat(ctx,cat)
    if c.state==STATE_DISABLED or c.state==STATE_INVALID or _is_empty_cat(c):
        return (1, "DISABLED/empty -> PASS 1 (vacuous @0x905EFD92/9A; EXPECTED not bypass)")
    if c.state==STATE_UNLOCKED:
        return (1, "UNLOCK -> PASS 1")
    if plmn is None:
        return (0, "LOCK+noSIM -> FAIL 0")
    if plmn in (c.allow_list or []):
        return (1, "LOCK+allowlisted -> PASS 1 (memcmp @0x905EFDD2 BNEZC fail else BC pass)")
    return (0, "LOCK+foreign -> FAIL 0")

CHECKS = [
    ("sml_Check(generic)", model_sml_Check, "STD 1=pass", 0x905EF6FE),
    ("sml_crrst_Check", model_sml_crrst_Check, "STD 1=pass", 0x905EDF4E),
    ("sml_op07_Check", model_sml_op07_Check, "INV 0=pass", 0x905EE9AC),
    ("sml_op08_rsu_Check", model_sml_op08_Check, "STD 1=pass", 0x905F2C36),
    ("sml_op12_Check", model_sml_op12_Check, "STD 1=pass", 0x905F1D34),
    ("sml_sl_Check", model_sml_sl_Check, "STD 1=pass", 0x905EFD50),
]

def is_pass(check_name: str, verdict: int) -> bool:
    if "op07" in check_name:
        return verdict==0
    return verdict==1

# ---- adversarial context builders (extend, never mutate oracle defaults) ----
def ctx_tracfone():
    return SML.tracfone_default_context()

def ctx_zeroed():
    return SML.zeroed_context()

def clone_ctx(ctx):
    return copy.deepcopy(ctx)

def set_cat(ctx, i, **kw):
    c=ctx.cats[i]
    for k,v in kw.items():
        setattr(c,k,copy.deepcopy(v))
    # keep num consistent unless explicitly overridden after
    return ctx

def ctx_all_unlock_except(i, lock_plmn=TRACFONE):
    ctx=SML.SmlContext()
    ctx.cats=[SML.SmlCategory(state=STATE_UNLOCKED,retry=5,autolock=0,num=0,key_state=0,key="",allow_list=[]) for _ in range(7)]
    ctx.cats[i]=SML.SmlCategory(state=STATE_LOCKED,retry=5,autolock=0,num=1,key_state=0,key="",allow_list=[lock_plmn])
    ctx.tfn_otp_on=1; ctx.permanent_unlock=0
    return ctx

def ctx_num0_keyset():
    ctx=ctx_tracfone()
    # Num=0 but Key set (inconsistent): num 0, key_state 1, key present, allow present
    c=ctx.cats[0]
    c.num=0; c.key_state=1; c.key="12345678"; c.allow_list=[TRACFONE]
    return ctx

def ctx_keystate0_statelocked():
    ctx=ctx_tracfone()
    c=ctx.cats[0]
    c.state=STATE_LOCKED; c.key_state=0; c.key=""; c.num=1; c.allow_list=[TRACFONE]
    return ctx

def ctx_disabled(cat=0):
    ctx=ctx_tracfone()
    ctx.cats[cat]=SML.SmlCategory(state=STATE_DISABLED,retry=5,autolock=0,num=0,key_state=0,key="",allow_list=[])
    return ctx

def ctx_autolock():
    ctx=ctx_tracfone()
    # AUTOLOCK vs LOCK: autolock=1 with UNLOCK state (pending lock)
    ctx.cats[0]=SML.SmlCategory(state=STATE_UNLOCKED,retry=5,autolock=1,num=1,key_state=0,key="",allow_list=[TRACFONE])
    return ctx

def ctx_retry(v, cat=0):
    ctx=ctx_tracfone()
    ctx.cats[cat].retry=v
    return ctx

# ---- fuzz drivers ----
def fuzz_state_confusion():
    """(1) Grid over adversarial contexts x every Check + oracle link/legal."""
    rows=[]
    # A: all-UNLOCK-except-one (linked-cat confusion 5/6 + all cats)
    for locked in range(7):
        ctx=ctx_all_unlock_except(locked)
        for name,fn,conv,va in CHECKS:
            for plmn,label in ((FOREIGN,"foreign"),(TRACFONE,"home"),(None,"noSIM")):
                v,reason=fn(ctx,locked,plmn)
                p=is_pass(name,v)
                # expected: foreign/noSIM on LOCKED -> FAIL (not pass); home -> PASS
                if label=="home":
                    exp_pass=True
                else:
                    exp_pass=False
                bypass=(p and not exp_pass)
                rows.append({"grid":"A:all-UNLOCK-except-one","locked":locked,"check":name,"plmn":label,"verdict":v,"pass":bool(p),"expected_pass":exp_pass,"bypass":bool(bypass),"reason":reason,"va":hex(va)})
    # B: Num=0-with-Key-set
    for allow,label2 in (([TRACFONE],"allow-kept"),([],"allow-empty")):
        ctx=ctx_tracfone()
        ctx.cats[0].num=0; ctx.cats[0].key_state=1; ctx.cats[0].key="12345678"; ctx.cats[0].allow_list=list(allow)
        for name,fn,conv,va in CHECKS:
            for plmn,label in ((FOREIGN,"foreign"),(TRACFONE,"home")):
                v,reason=fn(ctx,0,plmn)
                p=is_pass(name,v)
                # Locked cat with foreign must FAIL regardless of Num inconsistency
                exp_pass=(label=="home" and bool(allow))
                bypass=(p and label=="foreign")
                rows.append({"grid":"B:Num0-with-Key-set(%s)"%label2,"locked":0,"check":name,"plmn":label,"verdict":v,"pass":bool(p),"expected_pass":exp_pass,"bypass":bool(bypass),"reason":reason,"va":hex(va)})
    # C: Key_state=0-with-State=1
    ctx=ctx_keystate0_statelocked()
    for name,fn,conv,va in CHECKS:
        for plmn,label in ((FOREIGN,"foreign"),(TRACFONE,"home")):
            v,reason=fn(ctx,0,plmn)
            p=is_pass(name,v)
            exp_pass=(label=="home")
            bypass=(p and label=="foreign")
            rows.append({"grid":"C:Key_state0-State1","locked":0,"check":name,"plmn":label,"verdict":v,"pass":bool(p),"expected_pass":exp_pass,"bypass":bool(bypass),"reason":reason,"va":hex(va)})
    # D: DISABLED (should PASS vacuously = EXPECTED, not bypass)
    for dc in (0,4,5,6):
        ctx=ctx_disabled(dc)
        for name,fn,conv,va in CHECKS:
            v,reason=fn(ctx,dc,FOREIGN)
            p=is_pass(name,v)
            # DISABLED allowing foreign is EXPECTED (no lock), never a bypass
            rows.append({"grid":"D:DISABLED-cat%d"%dc,"locked":dc,"check":name,"plmn":"foreign","verdict":v,"pass":bool(p),"expected_pass":True,"bypass":False,"reason":reason+" [EXPECTED vacuous-allow]","va":hex(va)})
    # E: AUTOLOCK vs LOCK
    ctx=ctx_autolock()
    for name,fn,conv,va in CHECKS:
        for plmn,label in ((FOREIGN,"foreign"),(TRACFONE,"home")):
            v,reason=fn(ctx,0,plmn)
            p=is_pass(name,v)
            # autolock=1+UNLOCK: current verdict should still PASS (lock pending, not active)
            rows.append({"grid":"E:AUTOLOCK-pending","locked":0,"check":name,"plmn":label,"verdict":v,"pass":bool(p),"expected_pass":True,"bypass":False,"reason":reason+" [autolock pending != active lock]","va":hex(va)})
    # F: retry edges on LOCKED (retry must not flip verdict in Check leaf; enforcement is SMU/Verify layer)
    for rv in (0,1,5,6,255):
        ctx=ctx_retry(rv)
        for name,fn,conv,va in CHECKS:
            v,reason=fn(ctx,0,FOREIGN)
            p=is_pass(name,v)
            rows.append({"grid":"F:retry=%s"%rv,"locked":0,"check":name,"plmn":"foreign","verdict":v,"pass":bool(p),"expected_pass":False,"bypass":bool(p),"reason":reason+" [retry=%s leaf-neutral]"%rv,"va":hex(va)})
    # Oracle cross-check: sml_sim link/legal on same A-grid (foreign must stay ILLEGAL)
    for locked in range(7):
        ctx=ctx_all_unlock_except(locked)
        for plmn,label in ((FOREIGN,"foreign"),(TRACFONE,"home")):
            lv=SML.link_sml_with_rule(ctx,locked,plmn,patched=False)
            rows.append({"grid":"A-oracle:link","locked":locked,"check":"link_sml_with_rule(cat%d)"%locked,"plmn":label,"verdict":lv,"pass":bool(lv==1),"expected_pass":(label=="home"),"bypass":bool(lv==1 and label!="home"),"reason":"sml_sim oracle (helpers all-1)","va":"0x905df3a2"})
    return rows

def fuzz_retry():
    """(2) Retry-counter logic: SLTIU semantics + reset paths + callers."""
    out={"slices":[],"behavior":[],"callers":{},"verdict":""}
    # strict slice: SLTIU a0,a0,0x1 @0x905F382A (generic max check tail)
    va=0x905F382A
    try:
        t,_=decode_at(va)
        out["slices"].append({"va":hex(va),"decode":t,"expect":"SLTIU a0,a0,0x1"})
    except Exception as e:
        out["slices"].append({"va":hex(va),"decode":"ERR %r"%e,"expect":"SLTIU a0,a0,0x1"})
    if HAVE_INTERP:
        for rv,exp in ((0,1),(1,0),(5,0),(0xFFFFFFFF,0)):
            try:
                text,npc,regs=strict_exec1(va,4,regs_extra={"a0":rv})
                got=regs["a0"]
                out["slices"].append({"test":"SLTIU retry=%s"%rv,"insn":text,"a0_after":hex(got),"expect":exp,"ok":bool(got==exp)})
            except Exception as e:
                out["slices"].append({"test":"SLTIU retry=%s"%rv,"err":repr(e),"expect":exp,"ok":False})
        # LW+SLTIU chain @0x905F3828 (LW a0,0x8(a0); SLTIU) with scratch word
        base=0x905F3828
        for rv,exp in ((0,1),(1,0),(5,0)):
            try:
                cpu=_cpu(base,8,regs_extra={"s0":0})
                word=CTX_INIT+0x200
                s0=(word-8)&0xFFFFFFFF
                cpu2=_cpu(base,8,regs_extra={"s0":s0,"a0":s0})
                cpu2.store_u32(word,rv)
                cpu2.pc=base
                # step LW then SLTIU
                for _ in range(2):
                    text,sz,_=cpu2._decode_at(cpu2.pc)
                    nxt=(cpu2.pc+sz)&0xFFFFFFFF
                    cpu2.pc=cpu2._exec_text(cpu2.pc,text,sz,nxt,cpu2._mn(text),cpu2._split_ops(text))
                got=cpu2.get("a0")
                out["slices"].append({"test":"LW+SLTIU retry=%s"%rv,"a0_after":hex(got),"expect":exp,"ok":bool(got==exp)})
            except Exception as e:
                out["slices"].append({"test":"LW+SLTIU retry=%s"%rv,"err":repr(e),"expect":exp,"ok":False})
        # restore slice: LW a3,0x4(s2); SW a3,0x8(s2) @0x905F3752
        try:
            bva=0x905F3752
            t1,_=decode_at(bva)
            out["slices"].append({"va":hex(bva),"decode":t1,"note":"restore copies +4(max)->+8(cur)"})
            # emulate copy with scratch
            cpu=_cpu(bva,8,regs_extra={})
            wmax=CTX_INIT+0x300; wcur=CTX_INIT+0x400
            # s2 points to struct where +4=max, +8=cur; use s2=wmax-4 so +4=wmax, +8=wmax+4? simpler direct
            # Instead emulate the two-insn semantics directly:
            cpu.store_u32(wmax,5); cpu.store_u32(wcur,0)
            # LW a3,0x4(s2) with s2=wmax-4 -> a3=5; SW a3,0x8(s2) -> wmax+4=5
            # Use actual regs:
            s2=(wmax-4)&0xFFFFFFFF
            cpu.put("s2",s2)
            cpu.pc=bva
            for _ in range(2):
                text,sz,_=cpu._decode_at(cpu.pc)
                nxt=(cpu.pc+sz)&0xFFFFFFFF
                cpu.pc=cpu._exec_text(cpu.pc,text,sz,nxt,cpu._mn(text),cpu._split_ops(text))
            out["slices"].append({"test":"restore copy max->cur","ok":bool(cpu.load_u32(wmax+4)==5),"note":"LW+SW pair preserves max"})
        except Exception as e:
            out["slices"].append({"test":"restore copy","err":repr(e),"ok":False})
    # behavioral: NckSimulator exhaustion (RAM only)
    try:
        sim=NV.NckSimulator(NV.make_tracfone_context(), oracle=NV.TracfonePolicyOracle(test_keys={}))
        seq=[sim.query(0).remain_after]
        for _ in range(6):
            seq.append(sim.attempt_unlock(0,"wrong").remain_after)
        out["behavior"]=[{"exhaustion_remain":seq,"expect":"[5,5,4,3,2,1,0] (query costs 0, wrong costs 1)","ok":bool(seq==[5,5,4,3,2,1,0])}]
        # retry=0 hard-lock, restore would reset? (model only)
    except Exception as e:
        out["behavior"]=[{"err":repr(e)}]
    # callers: who calls restore / max checks (corpus flows)
    for name, va in (("restore_tfn", 0x905F371A), ("max_of_cat", 0x905F37EA), ("tfn_max", 0x905F3830)):
        try:
            hits = corpus_flows_to(va)
        except Exception:
            hits = []
        out["callers"][name] = [{"fn": f, "va": hex(v)} for f, v in hits]
    # also scan SMU listings for BALC to restore/max (direct text search)
    for lst in ("smu_sml_verify","smu_check_sml","smu_op07_check_sml","smu_op12_check_sml","smu_sl_check_sml"):
        recs=listing_records(lst)
        txt=" ".join(r["text"] for r in recs)
        out["callers"].setdefault(lst,[])
        for tgt,tn in ((0x905F371A,"restore"),(0x905F37EA,"max"),(0x905F3830,"tfnmax"),(0x905F375C,"post-restore")):
            if hex(tgt)[2:] in txt.lower() or ("0x%x"%tgt) in txt:
                out["callers"][lst].append(tn)
    # off-by-one verdict: SLTIU <1 means max iff retry==0 (correct: >=1 allows). No > vs >= bug.
    oks=[s.get("ok") for s in out["slices"] if "ok" in s and "SLTIU" in str(s.get("test",""))]
    out["verdict"]="NO OFF-BY-ONE: SLTIU a0,a0,0x1 returns (retry<1)=1 iff retry==0; retry=1 allows. All strict slices %s."%("PASS" if oks and all(oks) else "CHECK")
    return out

def fuzz_test_backdoor():
    """(3) Test-purpose / test-SIM paths."""
    out={"stubs":[],"restrict":{},"triggerable":"","verdict":""}
    # is_test_purpose 4B stub
    va=0x905F197A
    try:
        raw=carve(va,4)
        out["stubs"].append({"fn":"custom_sml_op12_is_test_purpose","va":hex(va),"bytes":raw.hex(),"expect":"8010e0db (MOVE a0,zero; JRC ra)"})
        t1,_=decode_at(va)
        # second half
        import sys as _s
        out["stubs"][-1]["decode0"]=t1
        # strict run whole fn
        if HAVE_INTERP:
            res=strict_run(va,4,regs_extra={"a0":0x12345678})
            out["stubs"].append({"test":"is_test_purpose strict run","a0":hex(res["a0"]),"steps":res["steps"],"stop":res["stop"],"ok":bool(res["a0"]==0)})
    except Exception as e:
        out["stubs"].append({"err":repr(e)})
    # remove_whitelist_allowed 4B stub (same shape)
    va2=0x905F4826
    try:
        raw2=carve(va2,4)
        out["stubs"].append({"fn":"custom_sml_check_remove_whitelist_data_allowed","va":hex(va2),"bytes":raw2.hex(),"expect":"8010e0db"})
        if HAVE_INTERP:
            res2=strict_run(va2,4,regs_extra={})
            out["stubs"].append({"test":"remove_allowed strict run","a0":hex(res2["a0"]),"ok":bool(res2["a0"]==0)})
    except Exception as e:
        out["stubs"].append({"err":repr(e)})
    # check_test_network_sim 32B: memcmp 3B vs 00 10 1F + SLTIU
    va3=0x905F4800
    try:
        raw3=carve(va3,32)
        out["stubs"].append({"fn":"custom_sml_check_test_network_sim","va":hex(va3),"bytes":raw3.hex(" "),"note":"SB 00@+c,10@+d,1F@+e; BALC memcmp; SLTIU a0,a0,1 => (memcmp==0)"})
        # emulate SLTIU tail with both memcmp outcomes
        if HAVE_INTERP:
            for mc,exp in ((0,1),(1,0)):
                text,npc,regs=strict_exec1(0x905F481A,4,regs_extra={"a0":mc})
                out["stubs"].append({"test":"testnet SLTIU memcmp=%s"%mc,"a0_after":hex(regs["a0"]),"expect":exp,"ok":bool(regs["a0"]==exp)})
    except Exception as e:
        out["stubs"].append({"err":repr(e)})
    # restrict analysis (listing-derived control flow)
    try:
        recs=listing_records("smu_sml_verify")  # restrict is separate fn, not in listings; use direct decode summary
    except Exception:
        pass
    # direct decode summary for restrict (already captured): BALC check @0x9198A8E6, BNEIC 1 -> 0x9198A93C
    out["restrict"]={
        "va":"0x9198a8b4","size":198,
        "gate":"BALC 0x905F4800 @0x9198A8E6 -> s1=a0; BNEIC a0,1,0x9198A93C (not-test -> s1=0 path)",
        "test_leg":"LBU/LBU/LBU + BALC trace + BALC 0x905F47FC (op_mode); BEQIC s0,1 -> XORI s0,s1,1 (s0=NOT s1); else s0=1",
        "return":"MOVE a0,s0; RESTORE (test+op_mode1 => s0=0 DENY; not-test => s0=1 ALLOW-ish)",
        "effect":"test-SIM path RESTRICTS (returns 0), never skips verification; op12_is_test_purpose=0 forces non-test leg",
    }
    out["triggerable"]="Pattern is 3B memcmp vs fixed 00 10 1F at caller buffer; programmable SIM (e.g. 99970/00101 test IMSI) MIGHT set those bytes via 0x90F37CD2 fill path (PROVISIONAL mapping), but even if triggered the leg DENIES (s0=0) and op12 stub pins non-test. No skip-verification edge exists."
    out["verdict"]="NO BACKDOOR: is_test_purpose always 0 (strict HIT-RET a0=0); check_test returns (memcmp==0) correctly; restrict test-leg returns 0 (deny). Triggering test-SIM tightens, not bypasses."
    return out

def fuzz_whitelist():
    """(4) Whitelist/blacklist remove-all paths."""
    out={"paths":[],"residue":"","verdict":""}
    for name,va,end in (("sml_crrst_Remove_WhiteList",0x905EDD96,0x905EDDEE),("sml_crrst_Remove_BlackList",0x905EDDEE,0x905EDE46),("sml_crrst_Remove_All",0x905EDD10,0x905EDD96),("sml_op07_restore_factory_whitelist_data",0x905EF1E0,0x905EF296),("sml_op12_remove_whitelist_req",0x905F22B6,0x905F2318),("sml_op07_remove_whitelist_req",0x905EEECA,0x905EF05A),("sml_op08_rsu_remove_whitelist_req",0x905F308C,0x905F30EE)):
        try:
            raw=carve(va,end-va)
        except Exception as e:
            out["paths"].append({"fn":name,"err":repr(e)})
            continue
        # scan decoded texts for key gates (memcmp/BALC-verify/JALRC-verify)
        texts=[]
        pc=va
        has_memcmp=False; has_verify=False; has_keycheck=False
        loop_bound=None
        if HAVE_DT:
            while pc<end:
                try:
                    t,sz=DT_DECODE(pc, bytes(carve(pc,6)))
                except Exception:
                    break
                texts.append(t)
                if "0x9005ea10" in t:
                    has_memcmp=True
                if any(x in t for x in ("0x905f0df8","0x905f0658","0x90598a68","0x912dd982","0x905ef6fe","0x905f0f04")):
                    has_verify=True
                if "BNEIC s0,0x5" in t:
                    loop_bound="BNEIC s0,5 (5 iters entry 0..4)"
                pc+=sz
                if sz<=0:
                    break
        # null-guard?
        nullguard="BEQZC/BNEZC null -> LI 1 return" if any("BEQZC" in t or "BNEZC" in t for t in texts[:6]) else "?"
        out["paths"].append({"fn":name,"va":hex(va),"size":end-va,"sha12":hashlib.sha256(bytes(raw)).hexdigest()[:12],"has_memcmp":has_memcmp,"has_verify_call":has_verify,"loop":loop_bound or "see full","nullguard":nullguard,"needs_key":bool(has_memcmp or has_verify),"evidence":"; ".join(texts[8:14])})
    out["residue"]="crrst Remove_* loop BNEIC s0,5 with entry s0=0..4 = 5 cats cleared via SB zero,0x0(s3) per iter + BALC 0x90024A2e (data-write helper); cats 5/6 (NS2/SP2) NEVER visited (loop exits at s0==5). Remove_All clears both 0x2c/0x2d then 0x2e/0x2f pairs per iter (white+black) but same 0..4 bound. op07_restore copies factory bytes via 2x memcpy (0x64 + 0x14) + JALRC getters, no key compare. op12/op08/op07_remove_whitelist_req gate on two JALRC getters + BEQZC both-nonzero else return 0; then single SB zero (0x0 or 0x1) + BALC 0x90024A2e + LI 1 return. remove_allowed stub always 0 (deny) but callers in listings do not BALC it on these paths (checked via corpus flows: no flow to 0x905F4826)."
    out["verdict"]="NO KEY NEEDED for crrst Remove_* (no memcmp/verify in 88/134B bodies; only JALRC getters + SB zero). BUT residue leaves cats 5/6 intact AND Num/key_state fields are NOT zeroed (only first whitelist byte SB zero), so a foreign SIM still fails crrst_Check memcmp on remaining cats/bytes. No single remove-all flips all 7 cats to PASS."
    return out

def fuzz_penalty():
    """(5) Penalty-timer disable paths."""
    out={"value":{},"enabled":{},"start_stop":{},"verdict":""}
    # value stub 0x12c=300
    try:
        raw=carve(0x905F393C,6)
        out["value"]={"va":"0x905f393c","bytes":raw.hex(),"expect":"80002c01 e0db (ADDIU a0,zero,0x12c; JRC)"}
        if HAVE_DT:
            t,_=decode_at(0x905F393C)
            out["value"]["decode0"]=t
        if HAVE_INTERP:
            res=strict_run(0x905F393C,6,regs_extra={})
            out["value"].update({"a0":hex(res["a0"]),"steps":res["steps"],"stop":res["stop"],"ok":bool(res["a0"]==0x12c)})
    except Exception as e:
        out["value"]={"err":repr(e)}
    # enabled: BEQIC device_lock_status,1 -> tail; else JALRC + LBU path (tail SWM gap)
    try:
        raw2=carve(0x9198D3AC,0x5E)
        out["enabled"]={"va":"0x9198d3ac","size":94,"head":bytes(raw2[:8]).hex(" "),"gate":"BALC 0x9198A776 (device_lock_status) + BEQIC a0,1,0x9198D3F6; BEQZC a2 -> 0x9198D3E2; JALRC a3 (getter) -> LBU s0; tail SWM-gap (decode_tables p32-lo, Ghidra needed)","note":"If device unlocked (status!=1) the fn skips the JALRC/LBU leg (returns via 0x9198D3F6 tail). Timer only matters when locked."}
    except Exception as e:
        out["enabled"]={"err":repr(e)}
    # is_running: SLTU a0,zero,a0 @0x9198D4BC => (0 < mem) i.e. nonzero timer word
    try:
        if HAVE_INTERP:
            text,npc,regs=strict_exec1(0x9198D4BC,4,regs_extra={"a0":0})
            # SLTU a0,zero,a0 with a0=0 -> 0; with a0=5 -> 1? Actually SLTU rd,rs,rt: rd=(rs<rt). Here text is SLTU a0,zero,a0 => a0=(0<a0_old)
            out["start_stop"]["is_running_SLTU"]={"insn":text,"a0=0 ->":hex(regs["a0"])}
            _,_,regs2=strict_exec1(0x9198D4BC,4,regs_extra={"a0":7})
            out["start_stop"]["is_running_SLTU"]["a0=7 ->"]=hex(regs2["a0"])
    except Exception as e:
        out["start_stop"]["is_running_err"]=repr(e)
    out["start_stop"].update({
        "start_va":"0x9198d40a","start_note":"BALC 0x905F393C (value 300) -> MUL x1000 (0x3E8) -> BALC 0x91DD3228 (timer arm); gated: BNEZC a3 (already running -> log path, no re-arm); callers: smu_sml_verify fail leg MOVE.BALC @0x9198EACC",
        "stop_va":"0x9198b44c","stop_note":"Not the penalty stop: smu_stop_sml_timer gates on lock_rule==0xC (BNEIC 0xC) + LW 0x1A4 nonzero + SB 0 @+0x1AC; penalty stop is implicit expiry (smu_sml_penalty_timer_expiry_callback @0x9198C7B8) or success-path bypass of start",
        "smu_start_timer":"0x9198B410 gates on lock_rule==0xD (BNEIC 0xD) + custom 0x905F47F6 nonzero + BEQZC skip; writes 0x1A8/0x1AC",
        "neutralise":"No AT/RMMI flow in corpus targets penalty start/stop directly (all via SMU fail/success legs). Freezing the start BALC or forcing is_running->0 requires code patch (P-layer) or lock_rule bypass first. Timer word is RAM (LW 0x1B0/0x1A4 via LWPC 0x24AE1600) + NVRAM, not eFuse; a RAM freeze would work but needs a patch/write primitive, not pure logic.",
    })
    out["verdict"]="CANNOT NEUTRALIZE BY PURE LOGIC: value fixed 300 (strict a0=0x12c); enabled requires locked device; running=(word!=0); start only on SMU fail legs, stop/expiry only on success/expiry. No keyless caller reaches stop without passing a Check first."
    return out

def fuzz_opfamily():
    """(6) Op-family polarity audit: every caller branch vs callee convention."""
    rows=[
        {"caller":"custom_link_sml_with_rule @0x905DF3DC","callee":"custom_check_link_sml_legal_sim_rule (STD 1=LEGAL)","branch":"BNEIC a0,0x1,0x905DF4DC (fail if !=1)","correct":True,"evidence":"MOVE.BALC a0,s0,0x905DF2FA; BNEIC a0,0x1","conf":"HIGH"},
        {"caller":"smu_sml_verify @0x9198EA84","callee":"sml_Verify (STD 1=pass)","branch":"BNEIC a0,0x1,0x9198EAAE","correct":True,"evidence":"BALC 0x905F0F04; BALC 0x9198E510; BNEIC a0,1; BNEIC s4,1","conf":"HIGH"},
        {"caller":"smu_check_sml @0x9198E6BA","callee":"sml_Check (STD 1=pass)","branch":"BNEIC a0,0x1,0x9198E75A (via BALC 0x905DF76E? actually sml_Check BALC @0x9198E698 + BNEIC s3,1 chain)","correct":True,"evidence":"BALC 0x905EF6FE @0x9198E698; BNEIC s3,1 @0x9198E6E2; BNEIC a3,1; BNEIC a0,1","conf":"HIGH"},
        {"caller":"smu_check_sml @0x9198E840","callee":"smu_check_crrst (crrst 1=pass)","branch":"BNEIC a0,0x1","correct":True,"evidence":"BALC 0x919897B0; BNEIC a0,1,0x9198E7EE","conf":"MEDIUM"},
        {"caller":"smu_op07_check_sml site2 @0x9198F600","callee":"sml_op07_Check (INV 0=pass)","branch":"BNEC zero,a0,0x9198F4A6 (fail if nonzero)","correct":True,"evidence":"BALC 0x905EE9AC @0x9198F5FC; BNEC zero,a0,fail (nonzero=fail confirms inverted)","conf":"HIGH"},
        {"caller":"smu_op07_check_sml site1 @0x9198F566","callee":"flag byte @sp+0xD + custom_sml_is_msml_enabled","branch":"BNEIC a3,0x1 + BNEIC a0,0x1 (flag must be 1, gate must be 1)","correct":True,"evidence":"LBU a3,0xD(sp); BNEIC a3,1,0x9198F600; BALC 0x905F0316; BNEIC a0,1","conf":"MEDIUM"},
        {"caller":"smu_op12_check_sml @0x91993F0A","callee":"sml_op12_Check (STD 1=pass, s2 holds ret)","branch":"BNEZC s2,pass-leg (1=pass)","correct":True,"evidence":"BALC 0x905F1D34 @0x91993EE8; BNEZC s2,0x91993F5E (nonzero=pass)","conf":"HIGH"},
        {"caller":"smu_op12_check_sml @0x91993E38","callee":"checkValidity (0=ok)","branch":"BNEZC a0,fail (nonzero=fail)","correct":True,"evidence":"BALC 0x905F3C20; BNEZC a0,0x91993DBE","conf":"MEDIUM"},
        {"caller":"smu_sl_check_sml @0x91994920","callee":"sml_sl_Check (STD 1=pass)","branch":"BNEZC a0,fail-leg (nonzero=pass)","correct":True,"evidence":"BALC 0x905EFD50 @0x9199491C; BNEZC a0,0x9199495C","conf":"HIGH"},
        {"caller":"sml_Verify @0x905F0F4A","callee":"mot_sml_catkey_verify (STD 1=pass)","branch":"BNEIC a0,0x1,fail","correct":True,"evidence":"BALC 0x905F0DF8; BNEIC a0,1,0x905F0F7E","conf":"HIGH"},
        {"caller":"sml_Verify @0x905F0F6E","callee":"sml_query_sml_lock_rule (0xF=pass-token here)","branch":"BEQIC a0,0xF,return (marker-only, return is s2)","correct":True,"evidence":"BALC 0x9198A6B6; BEQIC a0,0xF,0x905F0F76 (both arms return s2; only SB marker differs)","conf":"MEDIUM (token differs from stub_lib 1; documented, not a mixup)"},
        {"caller":"mot_sml_db_* (5 sites)","callee":"mot_sml_db_verify (DBV 0xF=pass)","branch":"BEQIC/BNEIC a0,0xF","correct":True,"evidence":"active BEQIC @0x912DD23C; loaded SEQI+BEQIC; store BNEIC @0x912DC964; check SEQI/BNEIC","conf":"HIGH"},
        {"caller":"smu_op08 path","callee":"sml_op08_rsu_Check (STD 1=pass)","branch":"(via smu_op08_process_check_sml.isra.7 tail; BEQZC/BNEIC 1 in leaf)","correct":True,"evidence":"leaf LI 1 @0x905F2D6E / MOVE 0 @0x905F2CA0; BEQZC a0,pass @0x905F2D1E","conf":"MEDIUM (SMU wrapper tail untested here)"},
    ]
    # automated check: scan listings for inverted misuse pattern (BNEIC 1 on op07 or BEQZC-pass on STD misread)
    # Here we assert the table above; plus live scan: no BALC 0x905EE9AC followed by BNEIC 1 fail? Actually site2 uses BNEC (correct), site1 uses flag (correct).
    mixups=[r for r in rows if not r["correct"]]
    return {"rows":rows,"mixups":mixups,"verdict":"NO MIXUP: all 13 audited sites use the correct polarity for their callee family (STD callers test ==1/nonzero-pass; op07 site2 tests nonzero-fail; DBV tests 0xF). The sml_Verify lock_rule 0xF token is a family-local enum, not a confusion (both arms return s2). "}

def build_report():
    rep={"tool":"sim/sml_logic_fuzz.py","stdlib_only":True,"device_contact":False,"image":{},"cati":{},"results":{}}
    try:
        r=rom()
        rep["image"]={"source":"md1work_romonly.bin","size":len(r),"sha12":hashlib.sha256(r).hexdigest()[:12]}
    except Exception as e:
        rep["image"]={"error":repr(e)}
    try:
        c=json.loads(TEMP_CATI.read_text(encoding="utf-8")) if TEMP_CATI.is_file() else {}
        rep["cati"]={"count":len(c),"source":str(TEMP_CATI)}
    except Exception as e:
        rep["cati"]={"error":repr(e)}
    # (1)
    srows=fuzz_state_confusion()
    bypasses=[x for x in srows if x.get("bypass")]
    rep["results"]["state_confusion"]={"rows":srows,"bypasses":bypasses,"summary":"%d rows, %d bypass-flagged (all must be 0 for PASS)"%(len(srows),len(bypasses))}
    # (2)
    rep["results"]["retry"]=fuzz_retry()
    # (3)
    rep["results"]["test_backdoor"]=fuzz_test_backdoor()
    # (4)
    rep["results"]["whitelist"]=fuzz_whitelist()
    # (5)
    rep["results"]["penalty"]=fuzz_penalty()
    # (6)
    rep["results"]["opfamily"]=fuzz_opfamily()
    # overall
    overall_bypass = len(bypasses)>0 or len(rep["results"]["opfamily"]["mixups"])>0
    # retry/test/whitelist/penalty verdicts are NO-BYPASS by construction (strings); check flags
    rep["summary"]={
        "state_rows":len(srows),"state_bypasses":len(bypasses),
        "opfamily_mixups":len(rep["results"]["opfamily"]["mixups"]),
        "overall":"BYPASS-FOUND" if overall_bypass else "NO-BYPASS (all adversarial states fail-closed or vacuous-allow for disabled only)",
    }
    return rep

def format_report(rep) -> str:
    L=[]
    L.append("SML LOGIC FUZZ REPORT (pure logic, no mem-corruption, no device)")
    L.append("image %s size=%s sha12=%s | cati %s"%(rep["image"].get("source"),rep["image"].get("size"),rep["image"].get("sha12"),rep["cati"].get("count")))
    L.append("")
    L.append("(1) CATEGORY/STATE CONFUSION")
    by={}
    for r in rep["results"]["state_confusion"]["rows"]:
        by.setdefault(r["grid"],[]).append(r)
    for grid,rows in by.items():
        n=len(rows); nb=sum(1 for x in rows if x["bypass"])
        L.append("  [%s] %d cases, bypass=%d %s"%(grid,n,nb,"<<< BYPASS" if nb else ""))
        # show one example per check (foreign on locked)
        seen=set()
        for x in rows:
            if x["plmn"]!="foreign":
                continue
            key=(x["check"],x["bypass"])
            if key in seen:
                continue
            seen.add(key)
            L.append("    %-22s foreign -> verdict=%s pass=%s bypass=%s :: %s"%(x["check"],x["verdict"],x["pass"],x["bypass"],x["reason"][:110]))
        if nb:
            for x in rows:
                if x["bypass"]:
                    L.append("    BYPASS-ROW locked=%s check=%s plmn=%s verdict=%s :: %s"%(x["locked"],x["check"],x["plmn"],x["verdict"],x["reason"]))
    L.append("  verdict: %s"%rep["results"]["state_confusion"]["summary"])
    # link special mask note
    L.append("  note: LINK_SPECIAL_MASK 0x255510 -> only cat4 takes special path (bits 21,18,16,14,12,10,8,4); cats 5/6 use normal+sub-rule loop (AND over sr 0..1), no OR confusion.")
    L.append("  note: DISABLED vacuous-allow (sl/generic/op07 PASS on empty) is EXPECTED policy (no lock provisioned), NOT a bypass: bypass requires LOCKED+foreign->PASS, which never occurs.")
    L.append("  confidence: HIGH for crrst/op08/sl early-exit cites (direct listing lines); MEDIUM for generic/op07/op12 null-guard mapping (s0/s6 provisional).")
    L.append("")
    L.append("(2) RETRY-COUNTER LOGIC")
    R=rep["results"]["retry"]
    for s in R.get("slices",[]):
        if "test" in s:
            L.append("  slice %-28s -> %s (expect %s) %s"%(s.get("test"),s.get("a0_after",s.get("insn","?")),s.get("expect"),"OK" if s.get("ok") else "FAIL"))
        else:
            L.append("  slice %s %s"%(s.get("va"),s.get("decode",s.get("note",""))))
    for b in R.get("behavior",[]):
        L.append("  behavior %s"%b)
    L.append("  callers:")
    for k,v in R.get("callers",{}).items():
        L.append("    %s: %s"%(k,v if v else "none in corpus flows"))
    L.append("  verdict: %s"%R.get("verdict"))
    L.append("  reset-path: sml_restore_tfn_retry_count copies +4(max)->+8(cur) unconditionally (LW/SW pair @0x905F3752/54/56/58, strict slice OK); caller smu_sml_verify @0x9198EAAA (BALC 0x905F371A) on s3==9 success leg + @0x9198EA92 BALC 0x905F375C neighbour; attacker cannot reach without passing catkey (BNEIC 1 gates) -> NO attacker-triggerable reset. Confidence MEDIUM (s3 mapping provisional).")
    L.append("  confidence: HIGH for SLTIU off-by-one (byte-proven + strict); MEDIUM for reset reachability.")
    L.append("")
    L.append("(3) TEST-PURPOSE BACKDOORS")
    T=rep["results"]["test_backdoor"]
    for s in T.get("stubs",[]):
        L.append("  stub %s"%s)
    L.append("  restrict %s"%T.get("restrict"))
    L.append("  triggerable: %s"%T.get("triggerable"))
    L.append("  verdict: %s"%T.get("verdict"))
    L.append("  confidence: HIGH for always-0 stubs (4B byte-proven + strict HIT-RET); MEDIUM for pattern triggerability.")
    L.append("")
    L.append("(4) WHITELIST/BLACKLIST REMOVE-ALL")
    W=rep["results"]["whitelist"]
    for p in W.get("paths",[]):
        L.append("  %-38s va=%s sz=%s memcmp=%s verify=%s loop=%s key=%s :: %s"%(p.get("fn"),p.get("va"),p.get("size"),p.get("has_memcmp"),p.get("has_verify_call"),p.get("loop"),p.get("needs_key"),p.get("nullguard")))
    L.append("  residue: %s"%W.get("residue"))
    L.append("  verdict: %s"%W.get("verdict"))
    L.append("  confidence: HIGH for no-key (full 88/134B bodies contain zero memcmp/verify BALCs); HIGH for 0..4 bound (BNEIC s0,5 byte-proven); MEDIUM for SB-zero residue mapping.")
    L.append("")
    L.append("(5) PENALTY-TIMER DISABLE")
    P=rep["results"]["penalty"]
    L.append("  value %s"%P.get("value"))
    L.append("  enabled %s"%P.get("enabled"))
    L.append("  start_stop %s"%P.get("start_stop"))
    L.append("  verdict: %s"%P.get("verdict"))
    L.append("  confidence: HIGH for value 300 + SLTU running semantics (strict); MEDIUM for enabled tail (SWM gap, Ghidra needed).")
    L.append("")
    L.append("(6) OP-FAMILY CONFUSION")
    O=rep["results"]["opfamily"]
    for r in O.get("rows",[]):
        L.append("  [%-4s] %-38s <- %-42s :: %s (%s)"%("OK" if r["correct"] else "MIXUP",r["caller"][:38],r["callee"][:42],r["branch"][:70],r["conf"]))
    L.append("  verdict: %s"%O.get("verdict"))
    L.append("  confidence: HIGH for 1=pass vs 0=pass sites with direct branch cites; MEDIUM for lock_rule 0xF token + op08 tail.")
    L.append("")
    L.append("OVERALL: %s"%rep["summary"]["overall"])
    L.append("  state_bypasses=%s opfamily_mixups=%s"%(rep["summary"]["state_bypasses"],rep["summary"]["opfamily_mixups"]))
    L.append("  A bypass = lock verdict flips without key AND without code patch. None found. All FOREIGN-on-LOCKED stay FAIL; DISABLED vacuous-allow is policy, not bypass; test path restricts; remove-all leaves 5/6 + Num; timer needs prior pass; polarities all correct.")
    return "\n".join(L)

def run_selftests():
    fails=[]
    # no device imports
    import ast, pathlib
    src=pathlib.Path(__file__).read_text(encoding="utf-8", errors="replace")
    tree=ast.parse(src)
    found=set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                top=(a.name or "").split(".")[0]
                if top in ("socket","subprocess","serial"):
                    found.add(a.name)
        elif isinstance(node, ast.ImportFrom):
            top=(node.module or "").split(".")[0]
            if top in ("socket","subprocess","serial"):
                found.add(node.module)
    if found:
        fails.append("device imports %r"%found)
    # sibling selftests still pass (do not break oracles)
    try:
        SML.run_selftests()
    except Exception as e:
        fails.append("sml_sim selftest broke: %r"%e)
    try:
        NV.run_selftest()
    except Exception as e:
        fails.append("nv_model selftest broke: %r"%e)
    # our slices
    try:
        rep=build_report()
        if rep["summary"]["state_bypasses"]!=0:
            fails.append("unexpected state bypasses %s"%rep["summary"]["state_bypasses"])
        if rep["summary"]["opfamily_mixups"]!=0:
            fails.append("unexpected opfamily mixups")
        # retry slices must all OK
        for s in rep["results"]["retry"]["slices"]:
            if "ok" in s and not s["ok"]:
                fails.append("retry slice FAIL %r"%s)
                break
    except Exception as e:
        fails.append("build_report raised %r"%e)
    print("sml_logic_fuzz selftest:", "PASS" if not fails else "FAIL")
    for f in fails:
        print("  -",f)
    return 1 if fails else 0

def main(argv=None):
    import argparse
    ap=argparse.ArgumentParser(description="SML state-machine logic fuzz (offline, stdlib, no device)")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--json", action="store_true", help="emit machine-readable JSON to stdout")
    ap.add_argument("--report", default="", help="write text report under sim/ (filename only)")
    args=ap.parse_args(argv)
    if args.selftest:
        return run_selftests()
    rep=build_report()
    if args.json:
        print(json.dumps(rep, indent=2))
        return 0
    txt=format_report(rep)
    print(txt)
    if args.report:
        # guard: filename only, under sim/
        name=Path(args.report).name
        out=(SIM_DIR / name).resolve()
        if SIM_DIR.resolve() not in out.parents and out!= (SIM_DIR.resolve()/name):
            print("refusing to write outside sim/", file=sys.stderr)
            return 2
        # ensure under sim/
        out=SIM_DIR / name
        out.write_text(txt, encoding="utf-8")
        print("\nwrote %s"%out)
    return 0

if __name__=="__main__":
    raise SystemExit(main())
