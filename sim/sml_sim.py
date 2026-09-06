#!/usr/bin/env python3
"""PC-side behavioral simulator of the MediaTek MT6835 modem SML lock decision path.

SAFETY: pure offline model. No device I/O (no adb/fastboot/serial/socket),
no modem command emission of any kind, nothing here can consume unlock
attempts (5-capped counter stays intact). Read-only use of repo files only.

Sources modeled (repo-relative unless noted):
  - HANDOFF.md  (SML API map, polarity, patch bytes, linker/verify summaries)
  - PICKUP.md   (toolchain, verified results, headless rules)
  - esim_lab/dummy_subscriber.json (test PLMN case)
  - <temp>/cati_syms.json (VA extents; queried read-only for VA confirmation)

Virtual addresses modeled (confirmed via cati_syms.json):
  VA_LEGAL_RULE   = 0x905DF2FA  (ends 0x905DF358, 0x5E bytes)
  VA_LINK_RULE    = 0x905DF3A2  (ends 0x905DF76E, 333 insns per HANDOFF)
  VA_LINK_CALL    = 0x905DF3DC  (sole caller: MOVE.BALC to legal rule, then
                                 BNEIC a0,1 -> fail; hence 1 == LEGAL)
  VA_FAIL         = 0x905DF4DC  (linker fail path entry)
  VA_SPECIAL      = 0x905DF572  (bitmask-selected special path; see MASK)
  VA_REJECT       = 0x905DF74A  (cat >= 22 reject)
  VA_TAIL_BASE    = 0x905DF756  (tail trampolines 0x756..0x76A)
  VA_VERIFY       = 0x905F0F04  (ends 0x905F0F88, 50 insns per HANDOFF)
  VA_CONVERGE     = 0x905F0F62  (both sml_Verify branches converge here)
  VA_PERM_UNLOCK  = 0x905DF77A  (4-byte always-1 stub, stock)
  VA_TFN_GET_BIT  = 0x905F37E4  (6-byte stub, returns != 0xFF, stock)
  VA_TFN_SET_OFF  = 0x905F3942  (4-byte return-1 no-op, stock)

Live-modem patch modeled by `patched=True`:
  entry bytes `01 d2 e0 db` == `LI a0,1; JRC ra` -> immediate return 1
  (dynamic proof: stock + all-helpers-1 -> verdict 0 in 25 steps;
   patched -> verdict 1 in 1 step).

Conventions:
  LEGAL   = 1
  ILLEGAL = 0
  STATE_LOCKED   = 1
  STATE_UNLOCKED = 0
  LINK_SPECIAL_MASK = 0x255510 (from HANDOFF full-linker decomp)

Stdlib only.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

# ---------------------------------------------------------------- constants

LEGAL = 1
ILLEGAL = 0

STATE_LOCKED = 1
STATE_UNLOCKED = 0

CAT_COUNT = 7
CAT_NAMES = ("N", "NS", "SP", "C", "SIM", "NS2", "SP2")
# NOTE: short labels only; exact per-category NVRAM semantics were not in the
# decoded summaries, so names are positional conveniences (see gaps §G6).

VA_LEGAL_RULE = 0x905DF2FA
VA_LEGAL_END = 0x905DF358
VA_LINK_RULE = 0x905DF3A2
VA_LINK_END = 0x905DF76E
VA_LINK_CALL = 0x905DF3DC
VA_FAIL = 0x905DF4DC
VA_SPECIAL = 0x905DF572
VA_REJECT = 0x905DF74A
VA_TAIL_BASE = 0x905DF756
VA_VERIFY = 0x905F0F04
VA_CONVERGE = 0x905F0F62

LINK_SPECIAL_MASK = 0x255510
LINK_CAT_REJECT_AT = 22  # `cat >= 22 -> reject @0x74A` per HANDOFF

TRACFONE_PLMN = "311480"
FOREIGN_PLMN = "310260"  # generic non-allowlisted PLMN used as foreign-SIM case
TEST_PLMN_FALLBACK = "99970"  # matches esim_lab/dummy_subscriber.json ("plmn")

PATCH_BYTES = bytes((0x01, 0xD2, 0xE0, 0xDB))  # LI a0,1; JRC ra (informational)

# ---------------------------------------------------------------- data model


@dataclass
class SmlCategory:
    """One SML category slot.

    Fields per task spec: state / retry / autolock / num / key_state /
    key / allow_list. `num` is kept consistent with len(allow_list) by
    `tracfone_default_context` but left free-form so tests can build a
    zeroed ctx (all fields zero/empty) for the dynamic-proof case.
    """

    state: int = STATE_UNLOCKED
    retry: int = 5
    autolock: int = 0
    num: int = 0
    key_state: int = 0
    key: str = ""
    allow_list: List[str] = field(default_factory=list)


@dataclass
class SmlContext:
    """SML context: 7 categories + minimal global harness flags.

    Global flags are test-harness state (not claimed NVRAM layout):
      tfn_otp_on: modeled TFN-OTP latch (dormant path per HANDOFF).
      permanent_unlock: latch for the always-1 stub (stock).
    """

    cats: List[SmlCategory] = field(default_factory=lambda: [SmlCategory() for _ in range(CAT_COUNT)])
    tfn_otp_on: int = 1
    permanent_unlock: int = 0

    def __post_init__(self) -> None:
        if len(self.cats) != CAT_COUNT:
            raise ValueError("SmlContext requires exactly %d categories" % CAT_COUNT)


def tracfone_default_context() -> SmlContext:
    """Tracfone default: cat0 LOCK / retry 5 / MCC-MNC 311480, rest UNLOCK."""
    ctx = SmlContext()
    ctx.cats[0] = SmlCategory(
        state=STATE_LOCKED,
        retry=5,
        autolock=0,
        num=1,
        key_state=0,
        key="",
        allow_list=[TRACFONE_PLMN],
    )
    for i in range(1, CAT_COUNT):
        ctx.cats[i] = SmlCategory(
            state=STATE_UNLOCKED,
            retry=5,
            autolock=0,
            num=0,
            key_state=0,
            key="",
            allow_list=[],
        )
    return ctx


def zeroed_context() -> SmlContext:
    """All-zero context: every field 0/empty (dynamic-proof stock case)."""
    ctx = SmlContext()
    ctx.cats = [
        SmlCategory(state=0, retry=0, autolock=0, num=0, key_state=0, key="", allow_list=[])
        for _ in range(CAT_COUNT)
    ]
    ctx.tfn_otp_on = 0
    ctx.permanent_unlock = 0
    return ctx


# ---------------------------------------------------------------- oracles

# A helper oracle models one BALC/call target the carved function would jump
# to on hardware. Default return is 1 (the dynamic-proof "all-helpers-1"
# condition). Inject 0-returning callables to explore gate behavior.


@dataclass
class Oracles:
    """Injectable helper-call oracles. Each takes (*args) and returns int."""

    helper_a: Callable[..., int] = field(default=lambda *a, **k: 1)
    helper_b: Callable[..., int] = field(default=lambda *a, **k: 1)
    mot_sml_catkey_verify: Callable[..., int] = field(default=lambda *a, **k: 1)
    tfn_otp_bit: Callable[..., int] = field(default=lambda *a, **k: 0x00)
    # NOTE default 0x00: stock stub returns "!= 0xFF" (defers to eFuse).
    # Any non-0xFF value behaves identically in this model.
    set_device_unlock_tfn_otp_off: Callable[..., int] = field(default=lambda *a, **k: 1)
    permanent_unlock: Callable[..., int] = field(default=lambda *a, **k: 1)
    lock_rule: Callable[..., int] = field(default=lambda *a, **k: 1)
    not_legal_rule: Callable[..., int] = field(default=lambda *a, **k: 1)
    nonctrlslot_check: Callable[..., int] = field(default=lambda *a, **k: 1)
    verify_action: Callable[..., int] = field(default=lambda *a, **k: 1)
    special_path: Callable[..., int] = field(default=lambda *a, **k: 1)
    sim_active_status: Callable[..., int] = field(default=lambda *a, **k: 1)
    gemini_sim_id: Callable[..., int] = field(default=lambda *a, **k: 0)
    trace_hook: Callable[..., int] = field(default=lambda *a, **k: 1)
    update_service_state: Callable[..., int] = field(default=lambda *a, **k: 1)


def all_one_oracles() -> Oracles:
    """Explicit all-helpers-return-1 set (dynamic-proof stock condition)."""
    one: Callable[..., int] = lambda *a, **k: 1  # noqa: E731
    return Oracles(
        helper_a=one,
        helper_b=one,
        mot_sml_catkey_verify=one,
        tfn_otp_bit=lambda *a, **k: 0x00,  # != 0xFF, i.e. stock stub behavior
        set_device_unlock_tfn_otp_off=one,
        permanent_unlock=one,
        lock_rule=one,
        not_legal_rule=one,
        nonctrlslot_check=one,
        verify_action=one,
        special_path=one,
        sim_active_status=one,
        gemini_sim_id=lambda *a, **k: 0,
        trace_hook=one,
        update_service_state=one,
    )


# ---------------------------------------------------------------- core fns


def _is_zeroed_category(c: SmlCategory) -> bool:
    return (
        c.state == 0
        and c.retry == 0
        and c.autolock == 0
        and c.num == 0
        and c.key_state == 0
        and c.key == ""
        and not c.allow_list
    )


def legal_sim_rule(
    ctx: SmlContext,
    cat: int,
    sub_rule: int,
    sim_plmn: Optional[str] = None,
    *,
    patched: bool = False,
    oracles: Optional[Oracles] = None,
    link_type: Optional[int] = None,
    trace: Optional[List[str]] = None,
) -> int:
    """Model custom_check_link_sml_legal_sim_rule @VA_LEGAL_RULE.

    Verdict in a0, 1 == LEGAL (caller @VA_LINK_CALL branches BNEIC a0,1).
    `link_type` models the s0 selector whose 9/4/5/7 values take distinct
    internal paths (see gap §G1); it only affects trace labels, all such
    paths converge on the same allowlist gate.
    """
    if trace is None:
        trace = []
    if oracles is None:
        oracles = all_one_oracles()

    if patched:
        # Live modem: entry forced `LI a0,1; JRC ra` -> HIT-RET in 1 step.
        trace.append("0x905DF2FA entry: LI a0,1; JRC ra -> return 1 (patched, 1 step)")
        return LEGAL

    # Stock path: SAVE/MOVE/BALC prologue (verdict computed below).
    trace.append("0x905DF2FA SAVE/MOVE prologue (stock)")
    ha = oracles.helper_a(ctx, cat, sub_rule)
    hb = oracles.helper_b(ctx, cat, sub_rule)
    trace.append("BALC helper_a -> %r; BALC helper_b -> %r" % (ha, hb))

    if not (0 <= cat < CAT_COUNT):
        trace.append("cat %r out of 0..6 -> ILLEGAL" % (cat,))
        return ILLEGAL
    if sub_rule not in (0, 1):
        trace.append("sub_rule %r outside loop range 0..1 -> ILLEGAL" % (sub_rule,))
        return ILLEGAL

    c = ctx.cats[cat]

    # Validity gate: all-zero slot can never be LEGAL. This is what makes the
    # dynamic-proof condition (stock + all-helpers-1 on zeroed/carved memory)
    # yield verdict 0 after ~25 steps instead of 1. See gap §G5.
    if _is_zeroed_category(c):
        trace.append("zeroed slot (num=0, empty allow/key) -> ILLEGAL (dynamic-proof match)")
        return ILLEGAL

    # s0 selector dispatch (trace-level; all arms converge below).
    sel = link_type if link_type is not None else cat
    if sel == 9:
        trace.append("s0==9 path")
    elif sel == 4:
        trace.append("s0==4 path")
    elif sel == 5:
        trace.append("s0==5 path")
    elif sel == 7:
        trace.append("s0==7 path")
    else:
        trace.append("s0==%r default path" % (sel,))

    if sim_plmn is None:
        trace.append("no SIM (PLMN absent) -> ILLEGAL")
        return ILLEGAL

    if c.state == STATE_UNLOCKED:
        trace.append("cat %d UNLOCKED (validity passed) -> LEGAL" % cat)
        return LEGAL

    # Locked category: lock-rule oracle gates, then allowlist decides.
    lr = oracles.lock_rule(ctx, cat, sub_rule, sim_plmn)
    trace.append("lock_rule -> %r" % (lr,))
    if lr != 1:
        trace.append("lock_rule != 1 -> ILLEGAL")
        return ILLEGAL
    if sim_plmn in c.allow_list:
        trace.append("PLMN %s in allow_list -> LEGAL" % sim_plmn)
        return LEGAL
    trace.append("PLMN %s not in allow_list %r -> ILLEGAL" % (sim_plmn, c.allow_list))
    return ILLEGAL


def sml_verify(
    ctx: SmlContext,
    cat: int,
    sim_plmn: Optional[str] = None,
    *,
    oracles: Optional[Oracles] = None,
    trace: Optional[List[str]] = None,
) -> int:
    """Model sml_Verify @VA_VERIFY (50 insns per HANDOFF).

    Chain: mot_sml_catkey_verify -> TFN check -> permanent-unlock stub
    (always 1, stock) -> lock-rule -> marker byte. Both TFN arms converge
    at @VA_CONVERGE, so TFN state is trace-only here (gap §G3).
    """
    if trace is None:
        trace = []
    if oracles is None:
        oracles = all_one_oracles()

    trace.append("0x905F0F04 sml_Verify prologue cat=%r plmn=%r" % (cat, sim_plmn))

    cv = oracles.mot_sml_catkey_verify(ctx, cat, sim_plmn)
    trace.append("mot_sml_catkey_verify -> %r" % (cv,))
    if cv != 1:
        trace.append("catkey verify != 1 -> ILLEGAL")
        return ILLEGAL

    bit = oracles.tfn_otp_bit(ctx, cat)
    trace.append("tfn_otp_bit -> 0x%02X (0xFF would mean OTP-ON latch)" % (bit & 0xFF,))
    trace.append("0x905F0F62 converge (both TFN arms join; dormant path)")

    pu = oracles.permanent_unlock(ctx, cat)
    trace.append("permanent_unlock stub -> %r (stock always 1)" % (pu,))
    if pu != 1:
        trace.append("permanent_unlock != 1 -> ILLEGAL (stage gate)")
        return ILLEGAL

    lr = oracles.lock_rule(ctx, cat, 0, sim_plmn)
    trace.append("lock_rule -> %r" % (lr,))
    if lr != 1:
        return ILLEGAL

    if not (0 <= cat < CAT_COUNT):
        return ILLEGAL
    c = ctx.cats[cat]
    if _is_zeroed_category(c):
        trace.append("zeroed slot -> ILLEGAL")
        return ILLEGAL
    if sim_plmn is None:
        trace.append("no SIM -> ILLEGAL")
        return ILLEGAL
    if c.state == STATE_UNLOCKED:
        trace.append("marker <- 1 (pass); UNLOCKED -> LEGAL")
        return LEGAL
    if sim_plmn in c.allow_list:
        trace.append("marker <- 1 (pass); allowlisted -> LEGAL")
        return LEGAL
    trace.append("marker <- 0 (deny); not allowlisted -> ILLEGAL")
    return ILLEGAL


def link_sml_with_rule(
    ctx: SmlContext,
    cat: int,
    sim_plmn: Optional[str] = None,
    *,
    patched: bool = False,
    oracles: Optional[Oracles] = None,
    verify_action: Optional[int] = None,
    link_type: Optional[int] = None,
    trace: Optional[List[str]] = None,
) -> int:
    """Model custom_link_sml_with_rule @VA_LINK_RULE.

    s7 carries the verdict to the `MOVE a0,s7; RESTORE.JRC` return.
    Flow: cat>=22 reject @VA_REJECT; bitmask 1<<cat & MASK -> special
    @VA_SPECIAL; cat==0 -> legal check @VA_LINK_CALL, verdict to s7,
    !=1 -> fail @VA_FAIL; sub-rule loop 0..1; verify-action gates;
    tail trampolines @VA_TAIL_BASE..+0x14 are post-decision side effects.
    """
    if trace is None:
        trace = []
    if oracles is None:
        oracles = all_one_oracles()

    trace.append("0x905DF3A2 link prologue cat=s4=%r link=s0 bufs=s1/s3/s5" % (cat,))

    # Reject gate @0x74A.
    if cat >= LINK_CAT_REJECT_AT:
        trace.append("0x905DF74A cat>=22 reject -> ILLEGAL")
        return ILLEGAL
    if cat < 0:
        trace.append("cat<0 reject -> ILLEGAL")
        return ILLEGAL

    # Bitmask-selected special path @0x572.
    if cat < 32 and ((1 << cat) & LINK_SPECIAL_MASK) != 0:
        trace.append("0x905DF572 special path (1<<%d & 0x255510 != 0)" % cat)
        sp = oracles.special_path(ctx, cat, sim_plmn)
        trace.append("special oracle -> %r" % (sp,))
        if sp != 1:
            return _link_fail(ctx, cat, sim_plmn, oracles, trace, reason="special-gate")
        if sim_plmn is None:
            return _link_fail(ctx, cat, sim_plmn, oracles, trace, reason="special-no-sim")
        if 0 <= cat < CAT_COUNT:
            c = ctx.cats[cat]
            if _is_zeroed_category(c):
                return _link_fail(ctx, cat, sim_plmn, oracles, trace, reason="special-zeroed")
            if c.state == STATE_UNLOCKED or sim_plmn in c.allow_list:
                return _link_return(LEGAL, oracles, trace)
        return _link_fail(ctx, cat, sim_plmn, oracles, trace, reason="special-deny")

    # Only cat0 reaches the patched check through the documented call site;
    # other small cats fall through to the sub-rule loop directly (gap §G2).
    s7 = LEGAL
    if cat == 0:
        v = legal_sim_rule(
            ctx, cat, 0, sim_plmn,
            patched=patched, oracles=oracles, link_type=link_type, trace=trace,
        )
        trace.append("0x905DF3DC MOVE.BALC verdict=%r -> s7; BNEIC a0,1 -> fail if !=1" % (v,))
        s7 = v
        if s7 != 1:
            return _link_fail(ctx, cat, sim_plmn, oracles, trace, reason="not-legal")
    else:
        trace.append("cat!=0: no direct legal-check call site; enter sub-rule loop")

    # Sub-rule loop s4 = 0..1 (AND-combination; gap §G2).
    for sr in (0, 1):
        v = legal_sim_rule(
            ctx, cat, sr, sim_plmn,
            patched=patched, oracles=oracles, link_type=link_type, trace=trace,
        )
        trace.append("sub-rule loop sr=%d verdict=%r (s7 was %r)" % (sr, v, s7))
        if v != 1:
            s7 = ILLEGAL
            return _link_fail(ctx, cat, sim_plmn, oracles, trace, reason="sub-rule-%d" % sr)
    s7 = LEGAL

    # Verify-action gates.
    if verify_action is not None:
        va = oracles.verify_action(ctx, cat, verify_action, sim_plmn)
        trace.append("verify-action gate(%r) -> %r" % (verify_action, va))
        if va != 1:
            return _link_fail(ctx, cat, sim_plmn, oracles, trace, reason="verify-action")

    return _link_return(s7, oracles, trace)


def _link_fail(
    ctx: SmlContext,
    cat: int,
    sim_plmn: Optional[str],
    oracles: Oracles,
    trace: List[str],
    reason: str,
) -> int:
    """Fail path @VA_FAIL: nonctrlslot/TFN/not_legal gates, markers, s7=0."""
    trace.append("0x905DF4DC fail path (%s)" % reason)
    nc = oracles.nonctrlslot_check(ctx, cat, sim_plmn)
    trace.append("nonctrlslot_check -> %r" % (nc,))
    oracles.tfn_otp_bit(ctx, cat)
    trace.append("tfn gate (trace-only; dormant)")
    nl = oracles.not_legal_rule(ctx, cat, sim_plmn)
    trace.append("not_legal_rule -> %r" % (nl,))
    trace.append("locked markers <- 3/0/1 (targets unmapped; trace-only); s7 <- 0")
    return _link_return(ILLEGAL, oracles, trace)


def _link_return(verdict: int, oracles: Oracles, trace: List[str]) -> int:
    """`MOVE a0,s7; RESTORE.JRC` return + tail trampolines (side effects)."""
    trace.append("MOVE a0,s7(%r); RESTORE.JRC return" % (verdict,))
    # Tail trampolines @0x756..0x76A: post-decision, verdict-neutral.
    oracles.nonctrlslot_check()
    trace.append("0x905DF756 -> nonctrlslot_check (tail)")
    trace.append("0x905DF75A -> 0x90F3AAEA trampoline (target unmapped; trace-only)")
    oracles.sim_active_status()
    trace.append("0x905DF75E -> sim_active_status (tail)")
    oracles.gemini_sim_id()
    trace.append("0x905DF762 -> gemini_sim_id (tail)")
    oracles.trace_hook()
    trace.append("0x905DF766 -> trace hook (tail)")
    oracles.update_service_state()
    trace.append("0x905DF76A -> update_service_state (tail)")
    return verdict


# ---------------------------------------------------------------- test cases


def load_dummy_subscriber_plmn() -> Tuple[str, Dict[str, str]]:
    """Load test PLMN from esim_lab/dummy_subscriber.json (fallback 99970).

    Returns (plmn, info). Never touches the device.
    """
    here = os.path.dirname(os.path.abspath(__file__))
    cand = os.path.normpath(os.path.join(here, "..", "esim_lab", "dummy_subscriber.json"))
    info: Dict[str, str] = {}
    try:
        with open(cand, "r", encoding="utf-8") as f:
            data = json.load(f)
        plmn = str(data.get("plmn", TEST_PLMN_FALLBACK))
        info = {"file": cand, "imsi": str(data.get("imsi", "")), "plmn": plmn}
    except (OSError, ValueError):
        plmn = TEST_PLMN_FALLBACK
        info = {"file": cand + " (missing/unreadable; fallback)", "imsi": "", "plmn": plmn}
    return plmn, info


def sim_cases() -> List[Tuple[str, Optional[str]]]:
    """The four matrix SIM cases: (label, plmn-or-None-for-no-SIM)."""
    test_plmn, _ = load_dummy_subscriber_plmn()
    return [
        ("tracfone-311480", TRACFONE_PLMN),
        ("foreign", FOREIGN_PLMN),
        ("no-sim", None),
        ("test-plmn-%s" % test_plmn, test_plmn),
    ]


def verdict_table() -> List[Tuple[str, Optional[str], int, int]]:
    """Build (label, plmn, stock_verdict, patched_verdict) rows on cat0."""
    ctx = tracfone_default_context()
    rows: List[Tuple[str, Optional[str], int, int]] = []
    for label, plmn in sim_cases():
        stock = link_sml_with_rule(ctx, 0, plmn, patched=False)
        patched_v = link_sml_with_rule(ctx, 0, plmn, patched=True)
        rows.append((label, plmn, stock, patched_v))
    return rows


def format_verdict_table(rows: List[Tuple[str, Optional[str], int, int]]) -> str:
    def tag(v: int) -> str:
        return "LEGAL(1)" if v == 1 else "ILLEGAL(0)"

    lines = ["mode     | " + " | ".join("%-18s" % label for label, _, _, _ in rows) + " |"]
    lines.append(
        "stock    | " + " | ".join("%-18s" % tag(s) for _, _, s, _ in rows) + " |"
    )
    lines.append(
        "patched  | " + " | ".join("%-18s" % tag(p) for _, _, _, p in rows) + " |"
    )
    plmns = ["(plmn %s)" % (plmn if plmn is not None else "absent") for _, plmn, _, _ in rows]
    lines.append("plmn     | " + " | ".join("%-18s" % p for p in plmns) + " |")
    return "\n".join(lines)


def run_selftests() -> None:
    """Self-test: patched==1 for all SIM cases; stock==0 for zeroed ctx."""
    # 1) patched verdict == 1 for every SIM case (Tracfone ctx, cat0).
    ctx = tracfone_default_context()
    for label, plmn in sim_cases():
        v = link_sml_with_rule(ctx, 0, plmn, patched=True)
        assert v == 1, "patched verdict must be 1, got %r for case %s" % (v, label)
        v2 = legal_sim_rule(ctx, 0, 0, plmn, patched=True)
        assert v2 == 1, "patched legal_sim_rule must be 1 for case %s" % label

    # 2) stock verdict == 0 for the zeroed-ctx case with all-helpers-1.
    #    Mirrors the dynamic proof: stock bytes + return-1 stubs -> a0=0.
    z = zeroed_context()
    oracles = all_one_oracles()
    test_plmn, _ = load_dummy_subscriber_plmn()
    for plmn in (TRACFONE_PLMN, FOREIGN_PLMN, None, test_plmn):
        v = legal_sim_rule(z, 0, 0, plmn, patched=False, oracles=oracles)
        assert v == 0, "stock zeroed-ctx legal verdict must be 0, got %r (plmn=%r)" % (v, plmn)
        w = link_sml_with_rule(z, 0, plmn, patched=False, oracles=oracles)
        assert w == 0, "stock zeroed-ctx link verdict must be 0, got %r (plmn=%r)" % (w, plmn)
        u = sml_verify(z, 0, plmn, oracles=oracles)
        assert u == 0, "stock zeroed-ctx sml_verify must be 0, got %r (plmn=%r)" % (u, plmn)

    # 3) stock sanity on Tracfone ctx: allowlisted PLMN passes, others fail.
    assert link_sml_with_rule(ctx, 0, TRACFONE_PLMN, patched=False) == 1
    assert link_sml_with_rule(ctx, 0, FOREIGN_PLMN, patched=False) == 0
    assert link_sml_with_rule(ctx, 0, None, patched=False) == 0
    assert link_sml_with_rule(ctx, 0, test_plmn, patched=False) == 0


def main(argv: List[str]) -> int:
    _ = argv
    run_selftests()
    print("self-tests: PASS")
    print("  - patched verdict == 1 for all SIM cases")
    print("  - stock verdict == 0 for zeroed-ctx case (dynamic-proof match)")
    print()
    test_plmn, info = load_dummy_subscriber_plmn()
    print("dummy subscriber: plmn=%s imsi=%s src=%s" % (info.get("plmn"), info.get("imsi"), info.get("file")))
    print()
    rows = verdict_table()
    print("verdict table (SML ctx=Tracfone default, cat0, link_sml_with_rule):")
    print(format_verdict_table(rows))
    print()
    print("1 == LEGAL (link path), 0 == ILLEGAL (fail path @0x905DF4DC).")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
