#!/usr/bin/env python3
"""stub_lib.py — behavioral stub library for the top SML/L4C helpers (pure PC).

SAFETY: pure offline model. No device I/O of any kind: no adb/fastboot/AT/
socket/subprocess/serial imports, no modem command emission, nothing here can
consume unlock attempts. Stdlib only. New code lives UNDER sim/ only.

Sources (repo-relative unless noted):
  - sim/hw_target.py ............ cspec: args a0-a7, ret a0-a1, LE32 nanoMIPS.
  - sim/emu_engine.py ........... StubRegistry ('behavioral' policy) + HwOracle
                                  OPS + transcript schema (implemented against).
  - HANDOFF.md Sec 3e ........... decoded-listing semantics: linker flow (333
                                  insn, s7 verdict, BNEIC a0,1 @0x905df3dc),
                                  sml_Verify chain (mot verify -> TFN -> perm-
                                  unlock stub -> lock-rule -> marker, converge
                                  @0x905f0f62), TFN stubs hardcoded stock,
                                  AT-gate stubs return-1, tail trampolines
                                  0x756..0x76a, RSU/GEN dispatch, polarity 1=LEGAL.
  - PICKUP.md ................... toolchain + verified patch bytes 01 d2 e0 db.
  - tools/atci.py ............... read-only AT reference (NOT imported here).
  - cati_syms.json (Temp/opencode). CATI {name:[startHex,endHex]} extents used
                                  as VA provenance (queried read-only 2026-09-05).
  - md1work_romonly.bin ......... raw bytes per extent (VA-0x90000000=file off),
                                  read-only, quoted below as provenance.

VA provenance table (CATI start/end, raw LE bytes from md1work_romonly.bin):
  custom_sml_is_esmlck_execute_allow @0x905f0312-16 4B  01d2e0db (LI a0,1;JRC ra)
  custom_sml_cat_verify_pass_permanent_unlock @0x905df77a-7e 4B 01d2e0db (=1)
  custom_sml_set_device_unlock_tfn_otp_off @0x905f3942-46 4B  01d2e0db (no-op 1)
  custom_sml_tfn_get_tfn_otp_bit @0x905f37e4-ea 6B 8000ff00e0db (!=0xff)
  custom_sml_is_nonctrlslot_allow_unlock @0x905f032a-2e 4B 01d2e0db (=1)
  custom_sml_is_nonctrlslot_allow_sml_check @0x905f0b02-06 (CATI; bytes unquoted)
  custom_sml_allow_both_sim_unlock @0x905df77e-8a (CATI; neighbor of perm-unlock)
  sml_query_sml_lock_rule @0x9198a6b6-f0 58B 121eeb60... (query dispatcher)
  sml_query_sml_lock_sub_rule @0x9198a6f2-44 82B 221eeb60... (sub-rule loop 0..1)
  sml_query_custom_convert_sml_lock_rule @0x9198a6f0-f2 2B c51b (thunk/alias slot
      sandwiched between lock_rule end and sub_rule start; body undecoded)
  sml_query_rsu_sub_rule_key_set_idx @0x9198a744-4e 10B 111eab3b8480c8f0111f
  sml_query_legal_service @0x9198a74e-62 20B e000e8018f3ce3606e117b95...
  sml_query_sml_sim_state @0x9198a762-76 20B e000e8018f3ce3605a117b95...
  sml_query_sml_device_lock_status @0x9198a776-ae 56B 121eeb607670...
  sml_query_linksml_invalid_sim_rule @0x9198a7ae-ec (CATI; invalid-SIM gate)
  sml_get_sim_card_active_status @0x9198aab4-c8 20B e000e8018f3ce360080e7b95...
  sml_lock_rule_and_status_update_ind @0x9198aac8-ab84 188B 141e24128360...
  sml_update_legal_service @0x9198bcdc-dc 96B 131ee003e801e360e0fb7a95...
  sml_is_tfn_otp_on @0x9198e4d2-510 62B 221e03b4c62a... (stub->0xff?=ON else
      eFuse read, fail-safe ON per HANDOFF)
  sml_query_is_tfn_lock_enabled @0x9198e510-28 24B 111eff2ba1c1e01090c80818...
  l4c_gemini_get_switched_sim_id @0x90ed3222-64 66B 121e04128010...
  l4c_check_is_sml_verify_action @0x90ed7ce2-d02 32B e0108cc81610e000e02b8f3c...
  l4c_check_cur_protocol_cap_with_gmss_mode @0x90ed365e-72 20B e5e09fb2a410e784...

Decoded-listing semantics (what each stub MEANS in the link/verify flow):
  esmlck_allow: RMMI gate in front of rmmi_esmlck_hdlr (131 insn @0x91985788).
      1=allow (stock stub), 0=deny->ERROR. Default 1.
  perm_unlock: sml_Verify stage gate after TFN converge @0x905f0f62; stock
      always-1. !=1 -> ILLEGAL. Default 1.
  tfn_bit: stock returns !=0xff (defers to eFuse); 0xff means OTP-ON latch.
      Both sml_Verify arms converge, so TFN is trace-only here. Default 0x00.
  tfn_off: return-1 no-op (dormant path). Default 1.
  tfn_on: fail-safe returns ON (1). Default 1.
  tfn_lock_enabled: dormant feature flag. Default 0 (disabled).
  lock_rule/sub_rule: allowlist gates in legal_sim_rule/link sub-rule loop
      (s4=0..1) and sml_Verify marker stage. 1=pass. Default 1.
  convert: rule-enum mapper feeding lock_rule (identity in stock single-rule
      build). Default identity(a0); alternates force 0/1.
  rsu_idx: RSU submode (1/2/3/6 -> op12/op129/op08/op12t) key-set selector.
      Default 0.
  gemini: tail trampoline @0x905df762; switched SIM id 0/1. Default 0.
  verify_action: sub-rule-loop gate after verify (l4c check). 1=proceed. Dflt 1.
  proto_cap: camp/gmss capability gate. 1=capable. Default 1.
  legal_service: per-cat service/limited-service query. 1=legal. Default 1.
  sim_state: per-slot SIM presence/state. 1=present-ready. Default 1.
  sim_active: per-slot active status (tail @0x905df75e). 1=active. Default 1.
  dev_lock_status: device-level lock rows for ESMLCK? 7-tuple. 1=locked-row
      present-actually-reporting (query ack). Default 1.
  invalid_sim_rule: 1=SIM ruled invalid (fail path), 0=not-invalid. Default 0.
  update_legal_service / lock_ind: void-ish indicators/acks (post-decision side
      effects, verdict-neutral per linker tail analysis). Default ack 1.
  nonctrlslot allow_unlock/allow_sml_check, both_sim_unlock: slot-policy gates
      on fail path (@0x905df4dc) and tail @0x905df756. Default 1.

Signatures: per hw_target.py cspec, args arrive in a0-a7, return in a0
(single-word helpers; a1 unused). Arity below is the MODELED contract inferred
from the helper name + extent + caller context (linker tail / verify chain /
RMMI dispatch). Confidence is marked per stub: VERIFIED (byte-proven ret stub)
vs INFERRED (name+context; full Ghidra decomp pending). Behavioral fns take
(a0..a7 as ints, ctx=None) and return int placed in a0.

Policy sets:
  default ... stock-faithful (gates 1 except gemini 0 / tfn_bit 0x00 /
              tfn_lock_enabled 0 / invalid_sim 0 / converter identity).
  all_allow . every boolean gate forced 1 (tfn_bit 0x00, gemini 0, converter 1;
              reproduces the dynamic-proof all-helpers-1 condition).
  all_deny .. every boolean gate forced 0 (tfn_bit 0xff, gemini 1, converter 0).

Wiring: install(registry, selection='default'|'all_allow'|'all_deny'|{name:pol})
sets StubRegistry policy 'behavioral' with the python fn as arg. Backends
execute via call(registry, va, a0..a7, ctx=None) -> int (a0).
"""

from __future__ import annotations

from dataclasses import dataclass, field

try:  # package-relative: sim/stub_lib.py when imported as sim.stub_lib
    from sim.emu_engine import StubRegistry  # type: ignore
except ImportError:
    try:  # sibling: stub_lib.py on sys.path (sim/ dir)
        from emu_engine import StubRegistry  # type: ignore
    except ImportError:
        StubRegistry = None  # type: ignore  # selftest skips registry roundtrip

try:
    from sim.sml_sim import Oracles as _SmlOracles  # type: ignore
except ImportError:
    try:
        from sml_sim import Oracles as _SmlOracles  # type: ignore
    except ImportError:
        _SmlOracles = None  # type: ignore

# ---------------------------------------------------------------- constants

RET_ALLOW = 1
RET_DENY = 0

# ---------------------------------------------------------------- spec


@dataclass
class StubSpec:
    name: str
    va: int
    end: int
    raw_hex: str          # raw LE bytes from md1work_romonly.bin (provenance)
    args: str             # modeled cspec signature, e.g. "a0=cat, a1=ctx_ptr -> a0"
    confidence: str       # "VERIFIED-ret-stub" | "INFERRED-name+context"
    semantics: str        # one-line decoded-listing meaning
    default_policy: str   # key into POLICIES[name]
    policies: list = field(default_factory=list)  # alternate policy names


def _u32(x: int) -> int:
    return x & 0xFFFFFFFF


def _bool(x: int) -> int:
    return 1 if x else 0


# ---------------------------------------------------------------- policies
# Each policy fn: (a0,a1,a2,a3,a4,a5,a6,a7, ctx=None) -> int (goes to a0).
# `ctx` is an optional sml_sim.SmlContext for ctx-sensitive alternates; the
# DEFAULT policy of every stub is ctx-free (canned constant/identity) so the
# library stays usable without any model import.

def _mk_const(v):
    def fn(a0=0, a1=0, a2=0, a3=0, a4=0, a5=0, a6=0, a7=0, ctx=None):
        return v
    fn.__name__ = "const_%s" % (v,)
    return fn


def _convert_identity(a0=0, a1=0, a2=0, a3=0, a4=0, a5=0, a6=0, a7=0, ctx=None):
    return _u32(a0)


def _lock_rule_ctx(a0=0, a1=0, a2=0, a3=0, a4=0, a5=0, a6=0, a7=0, ctx=None):
    """Ctx-sensitive alternate: consult sml_sim context allowlist (cat0)."""
    try:
        cat = int(a0)
        c = ctx.cats[cat]
        plmn = getattr(ctx, "_probe_plmn", None)
        if plmn is None:
            return 1 if c.state == 0 else 0
        if c.state == 0:
            return 1
        return 1 if plmn in (c.allow_list or []) else 0
    except Exception:
        return 0


def _gemini_ctx(a0=0, a1=0, a2=0, a3=0, a4=0, a5=0, a6=0, a7=0, ctx=None):
    try:
        return int(getattr(ctx, "_gemini_sim_id", 0)) & 0xFFFFFFFF
    except Exception:
        return 0


# name -> {policy_name: fn}
POLICIES: dict = {
    "sml_query_custom_convert_sml_lock_rule": {
        "default": _convert_identity, "identity": _convert_identity,
        "force_legal": _mk_const(1), "force_illegal": _mk_const(0),
    },
    "sml_query_rsu_sub_rule_key_set_idx": {
        "default": _mk_const(0), "zero": _mk_const(0), "one": _mk_const(1),
    },
    "l4c_gemini_get_switched_sim_id": {
        "default": _mk_const(0), "sim0": _mk_const(0), "sim1": _mk_const(1),
        "from_ctx": _gemini_ctx,
    },
    "l4c_check_is_sml_verify_action": {
        "default": _mk_const(1), "allow": _mk_const(1), "deny": _mk_const(0),
    },
    "l4c_check_cur_protocol_cap_with_gmss_mode": {
        "default": _mk_const(1), "allow": _mk_const(1), "deny": _mk_const(0),
    },
    "sml_query_sml_lock_rule": {
        "default": _mk_const(1), "allow": _mk_const(1), "deny": _mk_const(0),
        "from_ctx": _lock_rule_ctx,
    },
    "sml_query_sml_lock_sub_rule": {
        "default": _mk_const(1), "allow": _mk_const(1), "deny": _mk_const(0),
        "from_ctx": _lock_rule_ctx,
    },
    "sml_query_legal_service": {
        "default": _mk_const(1), "allow": _mk_const(1), "deny": _mk_const(0),
    },
    "sml_query_sml_sim_state": {
        "default": _mk_const(1), "allow": _mk_const(1), "deny": _mk_const(0),
    },
    "sml_update_legal_service": {
        "default": _mk_const(1), "ack": _mk_const(1), "nack": _mk_const(0),
    },
    "sml_get_sim_card_active_status": {
        "default": _mk_const(1), "allow": _mk_const(1), "deny": _mk_const(0),
    },
    "sml_lock_rule_and_status_update_ind": {
        "default": _mk_const(1), "ack": _mk_const(1), "nack": _mk_const(0),
    },
    "custom_sml_is_esmlck_execute_allow": {
        "default": _mk_const(1), "allow": _mk_const(1), "deny": _mk_const(0),
    },
    "custom_sml_tfn_get_tfn_otp_bit": {
        # Stock returns "!= 0xff" (defers to eFuse). 0x00 is the sml_sim default.
        "default": _mk_const(0x00), "defer_efuse": _mk_const(0x00),
        "otp_on": _mk_const(0xFF), "one": _mk_const(0x01),
    },
    "custom_sml_set_device_unlock_tfn_otp_off": {
        "default": _mk_const(1), "allow": _mk_const(1), "deny": _mk_const(0),
    },
    "sml_is_tfn_otp_on": {
        # Fail-safe returns ON (1) per decoded summary.
        "default": _mk_const(1), "on": _mk_const(1), "off": _mk_const(0),
    },
    "sml_query_is_tfn_lock_enabled": {
        # Dormant feature flag: disabled in stock.
        "default": _mk_const(0), "disabled": _mk_const(0), "enabled": _mk_const(1),
    },
    "custom_sml_cat_verify_pass_permanent_unlock": {
        "default": _mk_const(1), "allow": _mk_const(1), "deny": _mk_const(0),
    },
    "custom_sml_is_nonctrlslot_allow_unlock": {
        "default": _mk_const(1), "allow": _mk_const(1), "deny": _mk_const(0),
    },
    "custom_sml_is_nonctrlslot_allow_sml_check": {
        "default": _mk_const(1), "allow": _mk_const(1), "deny": _mk_const(0),
    },
    "custom_sml_allow_both_sim_unlock": {
        "default": _mk_const(1), "allow": _mk_const(1), "deny": _mk_const(0),
    },
    "sml_query_sml_device_lock_status": {
        "default": _mk_const(1), "allow": _mk_const(1), "deny": _mk_const(0),
    },
    "sml_query_linksml_invalid_sim_rule": {
        # 1 = SIM ruled invalid (fail path). Stock default: not-invalid.
        "default": _mk_const(0), "valid": _mk_const(0), "invalid": _mk_const(1),
    },
}

SPECS: dict = {}


def _spec(name, va, end, raw_hex, args, confidence, semantics):
    pols = sorted(POLICIES[name].keys())
    SPECS[name] = StubSpec(name, va, end, raw_hex, args, confidence, semantics,
                           "default", pols)


_spec("sml_query_custom_convert_sml_lock_rule", 0x9198A6F0, 0x9198A6F2, "c51b",
      "a0=rule_in -> a0=rule_out (a1-a7 unused)",
      "INFERRED-name+context",
      "Rule-enum mapper feeding lock_rule; 2B thunk/alias slot, body undecoded.")
_spec("sml_query_rsu_sub_rule_key_set_idx", 0x9198A744, 0x9198A74E,
      "111eab3b8480c8f0111f", "a0=rsu_submode, a1=key_set_ptr? -> a0=idx",
      "INFERRED-name+context",
      "RSU submode (1/2/3/6) key-set selector for op12/op129/op08/op12t.")
_spec("l4c_gemini_get_switched_sim_id", 0x90ED3222, 0x90ED3264,
      "121e041280102f2b7d7a07da01d22f2b757a45d801d09010121f0012f91b162b23362001020044111011e36052a9f100c0602102a00ea000ea008910162b4335d51b",
      "a0=slot_hint? -> a0=sim_id (0/1)",
      "INFERRED-name+context",
      "Tail trampoline @link+0x762 (0x905df762); switched SIM id.")
_spec("l4c_check_is_sml_verify_action", 0x90ED7CE2, 0x90ED7D02,
      "e0108cc81610e000e02b8f3ce3606469e59478b2e4841260e780c3608710e0db",
      "a0=action_id -> a0=bool (1=verify-action)",
      "INFERRED-name+context",
      "Sub-rule-loop verify-action gate after link check.")
_spec("l4c_check_cur_protocol_cap_with_gmss_mode", 0x90ED365E, 0x90ED3672,
      "e5e09fb2a410e7848425e70016007cf22f296b00",
      "a0=cap?, a1=gmss_mode -> a0=bool (1=capable)",
      "INFERRED-name+context", "Camp/GMSS capability gate.")
_spec("sml_query_sml_lock_rule", 0x9198A6B6, 0x9198A6F0,
      "121eeb60367111930002ff007017089bf31707d2f0d804126a2a95c130110411e36048f84500c0601c001024a000410207d26a2ab9c09010121f",
      "a0=cat, a1=rule_ctx_ptr? -> a0=bool (1=pass)",
      "INFERRED-name+context",
      "Allowlist gate in legal_sim_rule + sml_Verify marker stage.")
_spec("sml_query_sml_lock_sub_rule", 0x9198A6F2, 0x9198A744,
      "221eeb60fa7011931d840c5070170012189bf41702d3c37208d2f0d81d860d20fd840c20003080b30df06a2a47c15d850d203d850c200411e3604cf84500c0601d001024a000410207d26a2a65c09010221f",
      "a0=cat, a1=sub_rule(0/1), a2=rule_ctx_ptr? -> a0=bool",
      "INFERRED-name+context", "Sub-rule loop (s4=0..1) gate in link path.")
_spec("sml_query_legal_service", 0x9198A74E, 0x9198A762,
      "e000e8018f3ce3606e117b9578b284840420e0db",
      "a0=cat?, a1=service? -> a0=bool (1=legal)",
      "INFERRED-name+context", "Per-cat service/limited-service query.")
_spec("sml_query_sml_sim_state", 0x9198A762, 0x9198A776,
      "e000e8018f3ce3605a117b9578b284840520e0db",
      "a0=slot? -> a0=state (1=ready)",
      "INFERRED-name+context", "Per-slot SIM presence/state query.")
_spec("sml_update_legal_service", 0x9198BCDC, 0x9198BD3C,
      "131ee003e801e360e0fb7a95e62318f819fee72350f99f840410bf840510b0c8081881d286105a2b35c06a2a5dabe000e801f93c24111111c06022001024a000410207d28eb36785052047850420e360c0bc56006a2a71aae383123000286a4a",
      "a0=cat, a1=service, a2=val -> a0=ack (1; verdict-neutral)",
      "INFERRED-name+context",
      "Post-decision service-state update; side-effect-free no-op in model.")
_spec("sml_get_sim_card_active_status", 0x9198AAB4, 0x9198AAC8,
      "e000e8018f3ce360080e7b9578b28484e521e0db",
      "a0=slot -> a0=bool (1=active)",
      "INFERRED-name+context",
      "Per-slot active status; tail trampoline @link+0x75e.")
_spec("sml_lock_rule_and_status_update_ind", 0x9198AAC8, 0x9198AB84,
      "141e241283609aef0f01ff2beff8e000f003c360c8c8590081d20cd2442ac67404128b3844129084081030baff2bbffb90840410ff2bf3fbe000e801f1201830e360ba0d7b957eb3c7840420077ed0840910e7840520f0840a101c1890c8180891105a2b73e210840410077c90c836105086091050860a10002a625c1df2a400ea001011e0005a08c00005018400f500442aae7aa0001d04836006ef0f01e4831230ff296ff80aba1084091010840a10c71b85d3f084091083d39b1b",
      "a0=cat, a1=rule, a2=status -> a0=ack (1; verdict-neutral)",
      "INFERRED-name+context",
      "Lock-rule/status indication; post-decision, verdict-neutral.")
_spec("custom_sml_is_esmlck_execute_allow", 0x905F0312, 0x905F0316, "01d2e0db",
      "() -> a0=bool (1=allow; no inputs)",
      "VERIFIED-ret-stub",
      "RMMI gate before rmmi_esmlck_hdlr; stock LI a0,1;JRC ra.")
_spec("custom_sml_tfn_get_tfn_otp_bit", 0x905F37E4, 0x905F37EA, "8000ff00e0db",
      "() -> a0=otp_bit (stock !=0xff, defers to eFuse)",
      "VERIFIED-ret-stub",
      "TFN OTP bit stub (6B); 0xff would mean OTP-ON latch.")
_spec("custom_sml_set_device_unlock_tfn_otp_off", 0x905F3942, 0x905F3946,
      "01d2e0db", "() -> a0=1 (no-op ack)",
      "VERIFIED-ret-stub", "Dormant TFN-OTP-off no-op, always 1.")
_spec("sml_is_tfn_otp_on", 0x9198E4D2, 0x9198E510,
      "221e03b4c62a0b53e000ff0072da01d2221f04d3c372012abeede360fa3445000412c06099001024a000410280106a2aa18210cad90f833480209023221f",
      "a0=tfn_ctx? -> a0=bool (1=ON; fail-safe ON)",
      "INFERRED-name+context",
      "TFN OTP latch: stub 0xff?=ON else eFuse read, fail-safe ON.")
_spec("sml_query_is_tfn_lock_enabled", 0x9198E510, 0x9198E528,
      "111eff2ba1c1e01090c80818ff2b25c2e48001608710111f",
      "a0=lock_id? -> a0=bool (1=enabled; stock dormant 0)",
      "INFERRED-name+context", "Dormant TFN-lock feature flag.")
_spec("custom_sml_cat_verify_pass_permanent_unlock", 0x905DF77A, 0x905DF77E,
      "01d2e0db", "a0=cat? -> a0=1 (always-pass)",
      "VERIFIED-ret-stub",
      "sml_Verify stage gate after TFN converge @0x905f0f62; stock always 1.")
_spec("custom_sml_is_nonctrlslot_allow_unlock", 0x905F032A, 0x905F032E,
      "01d2e0db", "a0=slot? -> a0=bool (1=allow)",
      "VERIFIED-ret-stub", "Fail-path (@0x905df4dc) slot-policy gate.")
_spec("custom_sml_is_nonctrlslot_allow_sml_check", 0x905F0B02, 0x905F0B06,
      "unquoted-CATI", "a0=slot? -> a0=bool (1=allow)",
      "INFERRED-name+context",
      "Fail-path + tail @0x905df756 slot check gate.")
_spec("custom_sml_allow_both_sim_unlock", 0x905DF77E, 0x905DF78A,
      "unquoted-CATI", "a0=slot? -> a0=bool (1=allow)",
      "INFERRED-name+context",
      "Dual-SIM unlock policy gate (neighbor of perm-unlock).")
_spec("sml_query_sml_device_lock_status", 0x9198A776, 0x9198A7AE,
      "121eeb607670119300127017089bf31702d2f0d804126a2ad7c030110411e36046454e00c06021001024a000410207d26a2afbbf9010121f",
      "a0=cat? -> a0=bool (1=reporting)",
      "INFERRED-name+context",
      "Device-level lock rows backing the ESMLCK? 7-tuple.")
_spec("sml_query_linksml_invalid_sim_rule", 0x9198A7AE, 0x9198A7EC,
      "unquoted-CATI", "a0=cat?, a1=plmn_ptr? -> a0=bool (1=invalid)",
      "INFERRED-name+context",
      "Invalid-SIM gate; 1 routes to fail path (default 0=not-invalid).")

VA_BY_ADDR = {s.va: s.name for s in SPECS.values()}
assert len(VA_BY_ADDR) == len(SPECS), "VA collision in stub table"

# Policy-set expansion: name -> policy key for 'all_allow' / 'all_deny'.
SET_ALL_ALLOW = {
    "sml_query_custom_convert_sml_lock_rule": "force_legal",
    "sml_query_rsu_sub_rule_key_set_idx": "zero",
    "l4c_gemini_get_switched_sim_id": "sim0",
    "custom_sml_tfn_get_tfn_otp_bit": "defer_efuse",
    "sml_is_tfn_otp_on": "on",
    "sml_query_is_tfn_lock_enabled": "disabled",
    "sml_query_linksml_invalid_sim_rule": "valid",
}
SET_ALL_DENY = {
    "sml_query_custom_convert_sml_lock_rule": "force_illegal",
    "sml_query_rsu_sub_rule_key_set_idx": "one",
    "l4c_gemini_get_switched_sim_id": "sim1",
    "custom_sml_tfn_get_tfn_otp_bit": "otp_on",
    "sml_is_tfn_otp_on": "off",
    "sml_query_is_tfn_lock_enabled": "enabled",
    "sml_query_linksml_invalid_sim_rule": "invalid",
}


def _default_for(name: str):
    return POLICIES[name]["default"]


def _policy_fn(name: str, policy: str):
    try:
        return POLICIES[name][policy]
    except KeyError:
        raise ValueError("unknown policy %r for stub %r (have %s)"
                         % (policy, name, sorted(POLICIES[name].keys())))


def resolve_selection(selection=None) -> dict:
    """Normalize selection to {stub_name: policy_name}."""
    if selection is None or selection == "default":
        return {n: "default" for n in SPECS}
    if selection == "all_allow":
        return {n: SET_ALL_ALLOW.get(n, "allow" if "allow" in POLICIES[n] else "default")
                for n in SPECS}
    if selection == "all_deny":
        d = {}
        for n in SPECS:
            if n in SET_ALL_DENY:
                d[n] = SET_ALL_DENY[n]
            elif "deny" in POLICIES[n]:
                d[n] = "deny"
            elif "nack" in POLICIES[n]:
                d[n] = "nack"
            else:
                d[n] = "default"
        return d
    if isinstance(selection, dict):
        out = {n: "default" for n in SPECS}
        for n, p in selection.items():
            if n not in SPECS:
                raise ValueError("unknown stub %r" % (n,))
            _policy_fn(n, p)  # validates
            out[n] = p
        return out
    raise ValueError("bad selection %r" % (selection,))


# ---------------------------------------------------------------- wiring


def install(registry, selection=None) -> int:
    """Register every stub as StubRegistry policy 'behavioral' (python fn).

    Returns the number of stubs installed. `selection` is
    'default' | 'all_allow' | 'all_deny' | {stub_name: policy_name}.
    The python fn is stored as the registry arg so backends execute it via
    call()/execute() below (emu_engine materialize() leaves behavioral addrs
    to runtime resolution, which is exactly this hook).
    """
    if StubRegistry is None:
        raise RuntimeError("StubRegistry unavailable (emu_engine import failed)")
    mapping = resolve_selection(selection)
    for name, policy in mapping.items():
        spec = SPECS[name]
        fn = _policy_fn(name, policy)
        fn._stub_lib = (name, policy, spec.va)  # type: ignore[attr-defined]
        registry.set(spec.va, "behavioral", fn)
    return len(mapping)


def lookup(registry, va: int):
    """Return (policy, arg) for va, or None."""
    return registry.table.get(va)


def call(registry, va: int, a0=0, a1=0, a2=0, a3=0, a4=0, a5=0, a6=0, a7=0,
         ctx=None) -> int:
    """Execute the behavioral fn registered at va; return int for a0."""
    entry = registry.table.get(va)
    if entry is None:
        raise KeyError("no stub registered at %#x" % va)
    policy, fn = entry
    if policy != "behavioral":
        raise TypeError("stub at %#x is policy %r, not behavioral" % (va, policy))
    if not callable(fn):
        raise TypeError("behavioral stub at %#x has non-callable arg" % va)
    return int(_u32(fn(a0=a0, a1=a1, a2=a2, a3=a3, a4=a4, a5=a5, a6=a6, a7=a7,
                       ctx=ctx)))


# Backends written against an `execute(va, regs)` shape can use this alias.
def execute(registry, va: int, regs: dict | None = None, ctx=None) -> int:
    regs = regs or {}
    return call(registry, va,
                a0=regs.get("a0", 0), a1=regs.get("a1", 0),
                a2=regs.get("a2", 0), a3=regs.get("a3", 0),
                a4=regs.get("a4", 0), a5=regs.get("a5", 0),
                a6=regs.get("a6", 0), a7=regs.get("a7", 0), ctx=ctx)


def to_sml_sim_oracles(selection=None):
    """Build an sml_sim.Oracles wired to the selected stub policies.

    Mapping (sml_sim field <- stub): lock_rule <- sml_query_sml_lock_rule,
    verify_action <- l4c_check_is_sml_verify_action, gemini_sim_id <-
    l4c_gemini_get_switched_sim_id, sim_active_status <-
    sml_get_sim_card_active_status, permanent_unlock <-
    custom_sml_cat_verify_pass_permanent_unlock, tfn_otp_bit <-
    custom_sml_tfn_get_tfn_otp_bit, set_device_unlock_tfn_otp_off <-
    custom_sml_set_device_unlock_tfn_otp_off, nonctrlslot_check <-
    custom_sml_is_nonctrlslot_allow_sml_check. Unmapped oracle fields keep
    their sml_sim defaults (all-helpers-1).
    """
    if _SmlOracles is None:
        raise RuntimeError("sml_sim.Oracles unavailable")
    from functools import partial
    mapping = resolve_selection(selection)

    def _wrap(name):
        fn = _policy_fn(name, mapping[name])
        return lambda *a, **k: fn(ctx=k.get("ctx"))

    kw = {}
    pairs = {
        "lock_rule": "sml_query_sml_lock_rule",
        "verify_action": "l4c_check_is_sml_verify_action",
        "gemini_sim_id": "l4c_gemini_get_switched_sim_id",
        "sim_active_status": "sml_get_sim_card_active_status",
        "permanent_unlock": "custom_sml_cat_verify_pass_permanent_unlock",
        "tfn_otp_bit": "custom_sml_tfn_get_tfn_otp_bit",
        "set_device_unlock_tfn_otp_off":
            "custom_sml_set_device_unlock_tfn_otp_off",
        "nonctrlslot_check": "custom_sml_is_nonctrlslot_allow_sml_check",
    }
    base = _SmlOracles()
    for oracle_field, stub_name in pairs.items():
        fn = _policy_fn(stub_name, mapping[stub_name])
        setattr(base, oracle_field, lambda *a, _fn=fn, **k: _fn(ctx=k.get("ctx")))
    void = _policy_fn("sml_update_legal_service", mapping["sml_update_legal_service"])
    base.update_service_state = lambda *a, **k: void(ctx=k.get("ctx"))
    trace = _policy_fn("sml_lock_rule_and_status_update_ind",
                       mapping["sml_lock_rule_and_status_update_ind"])
    base.trace_hook = lambda *a, **k: trace(ctx=k.get("ctx"))
    return base


# ---------------------------------------------------------------- reporting


def coverage_table() -> str:
    lines = []
    hdr = "%-46s %-12s %-6s %-34s %-8s %s" % (
        "stub", "VA", "size", "signature", "default", "confidence")
    lines.append(hdr)
    lines.append("-" * len(hdr))
    for name in sorted(SPECS, key=lambda n: SPECS[n].va):
        s = SPECS[name]
        try:
            dflt = _policy_fn(name, "default")()
        except Exception:
            dflt = "?"
        lines.append("%-46s %#12x %-6d %-34s %-8s %s" % (
            name, s.va, s.end - s.va, s.args.split("->")[0].strip()[:34],
            dflt, s.confidence))
    return "\n".join(lines)


# ---------------------------------------------------------------- selftest


def selftest() -> tuple:
    passed, failed, details = 0, 0, []

    def check(label, cond, extra=""):
        nonlocal passed, failed
        if cond:
            passed += 1
            details.append("PASS %s" % label)
        else:
            failed += 1
            details.append("FAIL %s %s" % (label, extra))

    # 1. No device-I/O imports in this file (pure PC by construction).
    # AST-based so the check cannot match its own string literals.
    import ast as _ast
    import pathlib as _pl
    _src = _pl.Path(__file__).read_text(encoding="utf-8", errors="replace")
    _tree = _ast.parse(_src)
    _found = set()
    for _node in _ast.walk(_tree):
        if isinstance(_node, _ast.Import):
            for _a in _node.names:
                _top = (_a.name or "").split(".")[0]
                if _top in ("socket", "subprocess", "serial"):
                    _found.add(_a.name)
        elif isinstance(_node, _ast.ImportFrom):
            _top = (_node.module or "").split(".")[0]
            if _top in ("socket", "subprocess", "serial"):
                _found.add(_node.module)
    for _mod in ("socket", "subprocess", "serial"):
        check("no-import-%s" % _mod,
              not any(f == _mod or f.startswith(_mod + ".") for f in _found),
              "%r" % sorted(_found))
    _cc = "create" + "_" + "connection("
    _pp = "Pop" + "en("
    check("no-adb-code", _pp not in _src and _cc not in _src,
          "device-I/O call present")

    # 2. Table shape: 23 stubs, distinct VAs, required names present.
    required = ["sml_query_custom_convert_sml_lock_rule",
                "sml_query_rsu_sub_rule_key_set_idx",
                "l4c_gemini_get_switched_sim_id",
                "l4c_check_is_sml_verify_action",
                "l4c_check_cur_protocol_cap_with_gmss_mode",
                "sml_query_sml_lock_rule", "sml_query_sml_lock_sub_rule",
                "sml_query_legal_service", "sml_query_sml_sim_state",
                "sml_update_legal_service", "sml_get_sim_card_active_status",
                "sml_lock_rule_and_status_update_ind",
                "custom_sml_is_esmlck_execute_allow",
                "custom_sml_tfn_get_tfn_otp_bit",
                "custom_sml_set_device_unlock_tfn_otp_off",
                "custom_sml_cat_verify_pass_permanent_unlock"]
    for n in required:
        check("present[%s]" % n, n in SPECS)
    check("va-distinct", len({s.va for s in SPECS.values()}) == len(SPECS))
    check("provenance-va[esmlck_allow]",
          SPECS["custom_sml_is_esmlck_execute_allow"].va == 0x905F0312)
    check("provenance-va[perm_unlock]",
          SPECS["custom_sml_cat_verify_pass_permanent_unlock"].va == 0x905DF77A)

    # 3. Defaults: gates 1, value getters canned, ret-stubs exact.
    try:
        check("dflt[esmlck_allow==1]",
              _policy_fn("custom_sml_is_esmlck_execute_allow", "default")() == 1)
        check("dflt[perm_unlock==1]",
              _policy_fn("custom_sml_cat_verify_pass_permanent_unlock", "default")() == 1)
        check("dflt[tfn_bit==0x00]",
              _policy_fn("custom_sml_tfn_get_tfn_otp_bit", "default")() == 0x00)
        check("dflt[tfn_off==1]",
              _policy_fn("custom_sml_set_device_unlock_tfn_otp_off", "default")() == 1)
        check("dflt[tfn_on==1]",
              _policy_fn("sml_is_tfn_otp_on", "default")() == 1)
        check("dflt[tfn_lock==0]",
              _policy_fn("sml_query_is_tfn_lock_enabled", "default")() == 0)
        check("dflt[gemini==0]",
              _policy_fn("l4c_gemini_get_switched_sim_id", "default")() == 0)
        check("dflt[rsu_idx==0]",
              _policy_fn("sml_query_rsu_sub_rule_key_set_idx", "default")() == 0)
        check("dflt[convert-identity]",
              _policy_fn("sml_query_custom_convert_sml_lock_rule", "default")(a0=7) == 7)
        check("dflt[invalid_sim==0]",
              _policy_fn("sml_query_linksml_invalid_sim_rule", "default")() == 0)
        for n in ("sml_query_sml_lock_rule", "sml_query_sml_lock_sub_rule",
                  "sml_query_legal_service", "sml_query_sml_sim_state",
                  "sml_update_legal_service", "sml_get_sim_card_active_status",
                  "sml_lock_rule_and_status_update_ind",
                  "l4c_check_is_sml_verify_action",
                  "l4c_check_cur_protocol_cap_with_gmss_mode",
                  "sml_query_sml_device_lock_status",
                  "custom_sml_is_nonctrlslot_allow_unlock",
                  "custom_sml_is_nonctrlslot_allow_sml_check",
                  "custom_sml_allow_both_sim_unlock"):
            check("dflt[%s==1]" % n,
                  _policy_fn(n, "default")() == 1)
    except Exception as e:  # noqa: BLE001
        check("defaults-run", False, repr(e))

    # 4. Alternates exist and differ where applicable.
    try:
        check("alt[esmlck_allow/deny==0]",
              _policy_fn("custom_sml_is_esmlck_execute_allow", "deny")() == 0)
        check("alt[perm_unlock/deny==0]",
              _policy_fn("custom_sml_cat_verify_pass_permanent_unlock", "deny")() == 0)
        check("alt[tfn_bit/otp_on==0xff]",
              _policy_fn("custom_sml_tfn_get_tfn_otp_bit", "otp_on")() == 0xFF)
        check("alt[gemini/sim1==1]",
              _policy_fn("l4c_gemini_get_switched_sim_id", "sim1")() == 1)
        check("alt[convert/force_legal==1]",
              _policy_fn("sml_query_custom_convert_sml_lock_rule", "force_legal")(a0=9) == 1)
        for bad in (("sml_query_sml_lock_rule", "nope"), ("no_stub", "default")):
            try:
                _policy_fn(*bad)
                check("reject[%s/%s]" % bad, False, "no raise")
            except (ValueError, KeyError):
                check("reject[%s/%s]" % bad, True)
    except Exception as e:  # noqa: BLE001
        check("alternates-run", False, repr(e))

    # 5. StubRegistry wiring: behavioral policy executes the python fn.
    if StubRegistry is None:
        check("registry-roundtrip", False, "StubRegistry import failed")
    else:
        try:
            from emu_engine import Memory, Image  # type: ignore
        except ImportError:
            try:
                from sim.emu_engine import Memory, Image  # type: ignore
            except ImportError:
                Memory, Image = None, None  # type: ignore
        try:
            reg = StubRegistry()
            n = install(reg, "default")
            check("install-count", n == len(SPECS), "got %r" % n)
            check("install-policy",
                  reg.table[SPECS["custom_sml_is_esmlck_execute_allow"].va][0]
                  == "behavioral")
            check("call[esmlck_allow]",
                  call(reg, 0x905F0312) == 1)
            check("call[perm_unlock]",
                  call(reg, 0x905DF77A, a0=3) == 1)
            check("call[tfn_bit]",
                  call(reg, 0x905F37E4) == 0x00)
            check("call[convert-identity]",
                  call(reg, 0x9198A6F0, a0=5) == 5)
            check("call[gemini]",
                  call(reg, 0x90ED3222) == 0)
            check("execute[regs-dict]",
                  execute(reg, 0x9198A6B6, {"a0": 0, "a1": 0}) == 1)
            reg2 = StubRegistry()
            install(reg2, "all_deny")
            check("all_deny[esmlck==0]", call(reg2, 0x905F0312) == 0)
            check("all_deny[tfn_bit==0xff]", call(reg2, 0x905F37E4) == 0xFF)
            check("all_deny[gemini==1]", call(reg2, 0x90ED3222) == 1)
            reg3 = StubRegistry()
            install(reg3, "all_allow")
            check("all_allow[esmlck==1]", call(reg3, 0x905F0312) == 1)
            check("all_allow[invalid_sim==0]",
                  call(reg3, 0x9198A7AE) == 0)
            try:
                call(reg, 0xDEAD0000)
                check("call[unknown-raises]", False, "no raise")
            except KeyError:
                check("call[unknown-raises]", True)
        except Exception as e:  # noqa: BLE001
            check("registry-roundtrip", False, repr(e))

    # 6. sml_sim oracle bridge (if sml_sim present).
    if _SmlOracles is None:
        details.append("SKIP oracle-bridge (sml_sim unavailable)")
    else:
        try:
            o = to_sml_sim_oracles("default")
            check("oracle[lock_rule==1]", o.lock_rule() == 1)
            check("oracle[gemini==0]", o.gemini_sim_id() == 0)
            check("oracle[tfn==0x00]", o.tfn_otp_bit() == 0x00)
            check("oracle[perm==1]", o.permanent_unlock() == 1)
        except Exception as e:  # noqa: BLE001
            check("oracle-bridge", False, repr(e))

    return passed, failed, details


def main(argv=None) -> int:
    import sys as _sys
    argv = list(argv or [])
    if "--coverage" in argv or not argv or "--selftest" in argv:
        passed, failed, details = selftest()
        print("stub_lib selftest: %d passed, %d failed" % (passed, failed))
        for d in details:
            print("  " + d)
        print()
        print("coverage (%d stubs; default policy return shown):" % len(SPECS))
        print(coverage_table())
        print()
        print("alternate policies per stub:")
        for n in sorted(SPECS):
            print("  %-46s %s" % (n, ", ".join(SPECS[n].policies)))
        print()
        print("wiring: install(registry, selection) sets StubRegistry policy "
              "'behavioral' with the python fn as arg; backends run it via "
              "call(registry, va, a0..a7, ctx) / execute(registry, va, regs).")
        return 1 if failed else 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    import sys
    sys.exit(main(sys.argv[1:]))
