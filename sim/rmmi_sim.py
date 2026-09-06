#!/usr/bin/env python3
"""PC-side simulator of the MediaTek RMMI AT-command dispatch layer (SML focus).

LAB RULES (enforced by this file, see `guard_attempt_costing`):
  * Software model ONLY. This module performs no I/O: it never opens a
    socket, never talks to adb/atcid/rild, never touches a live device.
  * Query/test forms (`AT+CMD=?`, `AT+CMD?`) are modeled in software.
  * Attempt-costing set/unlock/commit forms (ESMLCK=m,n,... / CLCK unlock /
    RSU key / MOTSMLDB writes) are REJECTED: parsing them raises
    `AttemptCostingBlocked` before any handler model runs. The 5 capped
    modem attempts (`vendor.gsm.sim.slot.lock.device.lock.remain.count`)
    stay intact by construction -- there is no code path that emits them.

Sources (all under <repo> unless noted):
  * HANDOFF.md Sec 3e ......... RMMI dispatch facts, handler behaviors,
    live read-only AT results, gate-stub conventions.
  * PICKUP.md ................. toolchain notes, CATI symbol file location.
  * tools/atci.py ............. read-only client reference (single AT cmd
    per line discipline; this parser mirrors that).
  * md1work_romonly.bin ....... ROM image; dispatch-table region and symbol
    addresses verified against it (see `_EVIDENCE` below).
  * cati_syms.json (Temp/opencode) .. CATI symbol {name: [startHex,endHex]}.

_EVIDENCE (verified PC-side, read-only, 2026-09-05):
  * CATI starts match every handler VA in DISPATCH (e.g. rmmi_esmlck_hdlr
    -> ['91985788','91985932']).
  * File region 0x24002d0-0x2400750 (288 words, VA base 0x924002d0, since
    VA - 0x90000000 = file offset): all 288 words are modem-VA pointers
    and each of the 10 RMMI handler VAs below occurs exactly once.
  * `custom_sml_is_esmlck_execute_allow` @0x905f0312 = bytes
    `01 d2 e0 db` (`LI a0,1; JRC ra`) -> gate returns 1 (allow).
  * `re.findall(rb'AT\\+([A-Z0-9]{2,14})', rom)` -> 351 distinct names;
    SML-family literals present: ECRRST, ESLBLOB, ESMLCK, ESMLGEN,
    ESMLRSU, EUULK, MOTSMLDB, MOTSMLEVENT.
  * Live read-only results (HANDOFF.md Sec 3e, from tools/atci.py):
      AT+ESMLCK=?             -> +ESMLCK:(0-4),(0-4),<key>,<data_imsi>,
                                 <data_gid1>,<data_gid2>  then OK
      AT+ESMLCK?              -> 7 lock-category tuples, then a trailing
                                 "000000000000000",0,0,0,0,0 line, then OK
      AT+CLCK="PN|PU|PP|PC",2 -> ERROR (no SIM context)
      AT+ESMLRSU=? / AT+ESMLGEN=? -> bare OK

Stdlib only.
"""

# --------------------------------------------------------------------------
# 0. State seam: sim/sml_sim.py if present, else local stub.
# --------------------------------------------------------------------------
# NOTE (seam): if a richer SML state backend ever lands at sim/sml_sim.py
# exposing `LockState` / `get_default_lock_state`, it is picked up
# automatically. Today no sim/sml_sim.py exists, so the local stub below
# is used. The stub defaults are lab-observed values, all file-backed:
#   * remain.count = 5 ... captures/*/props.txt
#     ([vendor.gsm.sim.slot.lock.device.lock.remain.count]: [5])
#   * slot lock state 0 ..... HANDOFF.md Sec 1 (lock.state=0)
#   * 7 tuples + zeros line  HANDOFF.md Sec 3e (live AT+ESMLCK? shape)
try:  # package-relative: sim/sml_sim.py when imported as sim.rmmi_sim
    from sim.sml_sim import LockState, get_default_lock_state  # type: ignore
    _SML_SIM_BACKEND = "sim.sml_sim"
except ImportError:
    try:  # sibling: sml_sim.py on sys.path (sim/ dir)
        from sml_sim import LockState, get_default_lock_state  # type: ignore
        _SML_SIM_BACKEND = "sml_sim"
    except ImportError:
        _SML_SIM_BACKEND = "stub(local)"

        from dataclasses import dataclass, field

        @dataclass
        class LockState:
            """Configurable modem SML lock state driving the query oracle.

            `categories`: 7 lock-category rows (cat 0..6). Each row is a
            dict of ints rendered into one +ESMLCK: tuple line.
            Field layout of the tuple line is a MODELING SEAM: only the
            tuple *count* (7) and the trailing zeros line are live-attested
            (HANDOFF.md Sec 3e); verbatim per-line bytes were never
            captured. Paste verbatim rows here when available -- the
            oracle renders whatever this object holds.
            """

            categories: list = field(default_factory=lambda: [
                {"cat": c, "state": 0, "max_retry": 5, "remain": 5,
                 "autolock": 0, "wcard": 0}
                for c in range(7)
            ])
            # Trailing line, verbatim from live AT+ESMLCK? (HANDOFF.md).
            trailer_id: str = "000000000000000"
            trailer_fields: tuple = (0, 0, 0, 0, 0)
            remain_count: int = 5  # lab-observed (props.txt)
            esmlck_execute_allow: bool = True  # gate stub returns 1
            lock_rule_legal: bool = True  # custom_link_sml_with_rule path
            sim_present: bool = False  # lab has no SIM ctx -> CLCK q=ERROR

        def get_default_lock_state():
            return LockState()


# --------------------------------------------------------------------------
# 1. Dispatch table: AT name -> modem handler VA (+ backend marker).
# --------------------------------------------------------------------------
# RMMI extended-command dispatch: rmmi_extended_command_analyzer @0x90EF0CD8
# + rmmi_comptue_extended_cmd_hash_value @0x90EF0D58 (sic: "comptue" is the
# verbatim CATI spelling) map the AT+ name to a handler-pointer array at
# file 0x24002d0-0x2400750 (VA 0x924002d0 + i*4). Every VA below was found
# exactly once in that region and matches its CATI start address.
ANALYZER_VA = 0x90EF0CD8
HASH_FN_VA = 0x90EF0D58  # rmmi_comptue_extended_cmd_hash_value (sic)
DISPATCH_TABLE_FILE_RANGE = (0x24002D0, 0x2400750)
DISPATCH_TABLE_VA_BASE = 0x924002D0

NOT_RMMI = "mot_sml_db"  # backend marker (not dispatched via RMMI table)
MOT_SML_DB_HANDLER_VA = 0x912DE034  # mot_sml_db_handler (CATI-verified)

DISPATCH = {
    # --- SML-relevant RMMI commands (handler VA = CATI start) ---
    "ESMLCK":   0x91985788,  # rmmi_esmlck_hdlr   (131 insns)
    "ECRRST":   0x91986422,  # rmmi_ecrrst_hdlr
    "ECSMLCK":  0x91985F5A,  # rmmi_ecsmlck_hdlr
    "ESLBLOB":  0x90F1BF52,  # rmmi_eslblob_hdlr
    "ESLBLOBF": 0x91985A30,  # rmmi_eslblobf_hdlr
    "ESMLRSU":  0x91987884,  # rmmi_esmlrsu_hdlr  (49 insns)
    "ESMLRSUF": 0x91987920,  # rmmi_esmlrsuf_hdlr
    "ESMLGEN":  0x91987A98,  # rmmi_esmlgen_hdlr  (53 insns, TFN frontend)
    "ERSUKEY":  0x91987B40,  # rmmi_ersukey_hdlr
    "CLCK":     0x90F0A052,  # rmmi_clck_hdlr
    # --- NOT RMMI: routed to the mot_sml_db_handler backend ---
    "MOTSMLDB":    MOT_SML_DB_HANDLER_VA,
    "MOTSMLEVENT": MOT_SML_DB_HANDLER_VA,
}
DISPATCH_BACKEND = {n: ("RMMI" if n not in ("MOTSMLDB", "MOTSMLEVENT")
                        else NOT_RMMI) for n in DISPATCH}

# ROM AT-literal coverage note (verified by regex over md1work_romonly.bin):
# AT+ literals present: ECRRST, ESLBLOB, ESMLCK, ESMLGEN, ESMLRSU (+ EUULK,
# whose handler rmmi_euulk_hdlr @0x91985D88 sits between ESLBLOBF/ECSLCK).
# NO AT+ literal found for ECSMLCK / ESLBLOBF / ESMLRSUF / ERSUKEY, yet all
# four handler VAs sit in the dispatch-pointer region -- they are reachable
# via the hash dispatch (sub-command spelling or non-literal compare), so
# they stay in DISPATCH. CLCK is a generic 3GPP command (shared handler).
ROM_AT_LITERAL_PRESENT = frozenset(
    ["ECRRST", "ESLBLOB", "ESMLCK", "ESMLGEN", "ESMLRSU",
     "MOTSMLDB", "MOTSMLEVENT", "CLCK"])
ROM_AT_LITERAL_ABSENT = frozenset(
    ["ECSMLCK", "ESLBLOBF", "ESMLRSUF", "ERSUKEY"])


# --------------------------------------------------------------------------
# 2. AT parser: test / read / set / execute syntax -> ParsedCommand.
# --------------------------------------------------------------------------
from dataclasses import dataclass


class ATParseError(ValueError):
    """Input is not well-formed Hayes AT extended syntax."""


@dataclass
class ParsedCommand:
    raw: str          # original input line (stripped)
    name: str         # upper-cased command name, no "AT+" prefix
    form: str         # one of: "test" (=?), "read" (?), "set" (=...), "exec"
    args: list        # set-form args (quote-aware split); [] otherwise
    handler_va: object  # int VA, or None if name not in DISPATCH


def _split_args(body):
    """Quote-aware comma split for AT set-form arguments.

    Handles: "quoted,str", 'single', bare tokens, empty fields, nested
    parens in test ranges like (0-4). Raises ATParseError on unbalanced
    quotes.
    """
    args, cur, quote, depth = [], [], None, 0
    for ch in body:
        if quote:
            cur.append(ch)
            if ch == quote:
                quote = None
        elif ch in ('"', "'"):
            quote = ch
            cur.append(ch)
        elif ch == "(":
            depth += 1
            cur.append(ch)
        elif ch == ")":
            depth -= 1
            cur.append(ch)
        elif ch == "," and depth == 0:
            args.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    if quote:
        raise ATParseError("unbalanced quote in: %r" % body)
    args.append("".join(cur).strip())
    return args


def parse_at(line):
    """Parse one AT line (mirror tools/atci.py: one command per line).

    Returns ParsedCommand. Unknown names parse fine with handler_va=None
    (dispatch later yields ERROR, like the modem's analyzer miss path).
    """
    raw = line.strip()
    if not raw or not raw.upper().startswith("AT"):
        raise ATParseError("not an AT line: %r" % line)
    body = raw[2:].strip()  # drop AT prefix
    if not body.startswith("+"):
        # Basic form (ATI, ATZ...): out of scope for RMMI extended sim.
        return ParsedCommand(raw, body.upper(), "exec", [], None)
    body = body[1:]
    up = body.upper()
    if up.endswith("=?") :
        name = up[:-2].strip()
        form, args = "test", []
    elif up.endswith("?") and "=" not in up:
        name = up[:-1].strip()
        form, args = "read", []
    elif "=" in body:
        name, _, argbody = body.partition("=")
        name = name.strip().upper()
        form, args = "set", _split_args(argbody)
    else:
        name, form, args = up.strip(), "exec", []
    if not name.replace("_", "").replace("-", "").isalnum() or not name:
        raise ATParseError("bad command name in: %r" % line)
    return ParsedCommand(raw, name, form, args, DISPATCH.get(name))


# --------------------------------------------------------------------------
# 3. Guard: attempt-costing forms are rejected BEFORE handler models run.
# --------------------------------------------------------------------------
class AttemptCostingBlocked(RuntimeError):
    """Raised when input models an attempt-costing modem form.

    The 5 capped unlock attempts must stay intact: these strings are only
    ever *parsed* in software and then refused. They must never be emitted
    toward a device.
    """


# The 5 guarded forms (each maps to a forbidden live operation):
#   F1 ESMLCK_SET .... AT+ESMLCK=<mode>,... (mode 1 = key/data unlock path;
#                      all set modes blocked conservatively -- any of them
#                      reaches rmmi_esmlck_hdlr key/data handling)
#   F2 CLCK_UNLOCK ... AT+CLCK="<fac>",0[,...] (mode 0 = unlock; the live
#                      read-only form is mode 2 / test only)
#   F3 ERSUKEY_SET ... AT+ERSUKEY=<...> (RSU key provision)
#   F4 ESMLRSU_SET ... AT+ESMLRSU=<...> (RSU submode parsers take key/data)
#   F5 MOTSMLDB_WRITE  AT+MOTSMLDB=<...> / AT+MOTSMLEVENT=<...> (backend
#                      mot_sml_db_handler writes)
GUARDED_FORMS = ("ESMLCK_SET", "CLCK_UNLOCK", "ERSUKEY_SET",
                 "ESMLRSU_SET", "MOTSMLDB_WRITE")

_SML_FACS = frozenset(["PN", "PU", "PP", "PC", "PF", "PS", "SC"])


def _unquote(tok):
    tok = tok.strip()
    if len(tok) >= 2 and tok[0] == tok[-1] and tok[0] in ('"', "'"):
        return tok[1:-1]
    return tok


def guard_attempt_costing(pcmd):
    """Inspect a ParsedCommand; raise AttemptCostingBlocked if attempt-costing.

    Must be called after parse_at() and BEFORE any handler model. Returns
    the guard-form id (one of GUARDED_FORMS) when the command is safe... no:
    returns None when safe (execution may proceed). Raises otherwise.
    """
    name, form, args = pcmd.name, pcmd.form, pcmd.args
    if form != "set" or not args:
        return None  # test/read/exec forms never cost attempts
    if name == "ESMLCK":
        raise AttemptCostingBlocked(
            "F1 ESMLCK_SET: %r would enter rmmi_esmlck_hdlr key/data path "
            "(mode byte @arg+0xd, mode 1) and burn a capped attempt." % pcmd.raw)
    if name == "CLCK" and len(args) >= 2:
        try:
            mode = int(_unquote(args[1]))
        except ValueError:
            mode = None
        if mode == 0:
            raise AttemptCostingBlocked(
                "F2 CLCK_UNLOCK: %r is a facility-unlock (mode 0) for %r." %
                (pcmd.raw, _unquote(args[0])))
        return None  # mode 2 (status) etc. are safe to MODEL (no SIM ctx)
    if name == "ERSUKEY":
        raise AttemptCostingBlocked(
            "F3 ERSUKEY_SET: %r provisions RSU key material." % pcmd.raw)
    if name == "ESMLRSU":
        raise AttemptCostingBlocked(
            "F4 ESMLRSU_SET: %r would enter rmmi_esmlrsu_hdlr submode "
            "parsers (op12/op129/op08/op12t) with key/data." % pcmd.raw)
    if name in ("MOTSMLDB", "MOTSMLEVENT"):
        raise AttemptCostingBlocked(
            "F5 MOTSMLDB_WRITE: %r is a mot_sml_db_handler backend write." %
            pcmd.raw)
    return None


# --------------------------------------------------------------------------
# 4. Behavioral handler models (software only; honor the guard).
# --------------------------------------------------------------------------
OK = "OK"
ERROR = "ERROR"

# Verbatim live test string for AT+ESMLCK=? (HANDOFF.md Sec 3e).
ESMLCK_TEST_STRING = "+ESMLCK:(0-4),(0-4),<key>,<data_imsi>,<data_gid1>,<data_gid2>"

# rmmi_esmlrsu_hdlr submode routing (HANDOFF.md Sec 3e: 49 insns).
RSU_SUBMODES = {1: "rmmi_op12_rsu_hdlr",
                2: "op129_parse(rmmi_parse_op129_rsu_cmd)",
                3: "op08_parse(rmmi_parse_op08_rsu_cmd)",
                6: "op12t_parse(rmmi_parse_op12t_rsu_cmd)"}


def _fmt_esmlck_tuple(row):
    # Modeling seam: field layout per §0 LockState docstring (count=7 and
    # the trailer line are live-attested; per-line layout is configurable).
    return "+ESMLCK: %d,%d,%d,%d,%d,%d" % (
        row["cat"], row["state"], row["max_retry"],
        row["remain"], row["autolock"], row["wcard"])


def model_esmlck(pcmd, state=None):
    """rmmi_esmlck_hdlr @0x91985788 (131 insns).

    Gate: custom_sml_is_esmlck_execute_allow (stub returns 1 -> allow).
    Mode byte @arg+0xd: 2/4 -> status query via
    l4csmu_sml_status_req_handler; 1 -> key/data path (BLOCKED by guard
    before reaching here); set forms never arrive (guard raises first).
    """
    state = state or get_default_lock_state()
    if not state.esmlck_execute_allow:
        return [ERROR]  # gate stub would return !=1
    if pcmd.form == "test":
        return [ESMLCK_TEST_STRING, OK]
    if pcmd.form == "read":
        lines = [_fmt_esmlck_tuple(r) for r in state.categories]
        lines.append('"%s",%s' % (state.trailer_id,
                                  ",".join(map(str, state.trailer_fields))))
        lines.append(OK)
        return lines
    if pcmd.form == "set":
        # Unreachable via dispatch() (guard raises first); kept as
        # defense-in-depth so direct model calls stay safe too.
        raise AttemptCostingBlocked(
            "F1 ESMLCK_SET (defense-in-depth): set forms never execute.")
    return [ERROR]


def model_esmlrsu(pcmd, state=None):
    """rmmi_esmlrsu_hdlr @0x91987884 (49 insns): submode dispatch.

    sub1 -> rmmi_op12_rsu_hdlr; sub2 -> op129 parse; sub3 -> op08 parse;
    sub6 -> op12t parse; all lock-rule-gated. Set forms (key material)
    are BLOCKED by the guard; test -> bare OK (live-attested).
    """
    state = state or get_default_lock_state()
    if pcmd.form == "test":
        return [OK]  # live: AT+ESMLRSU=? -> bare OK
    if pcmd.form == "read":
        return [OK]  # unobserved live; modeled symmetric to test form
    if pcmd.form == "set":
        raise AttemptCostingBlocked(
            "F4 ESMLRSU_SET (defense-in-depth): set forms never execute.")
    return [ERROR]


def model_esmlgen(pcmd, state=None):
    """rmmi_esmlgen_hdlr @0x91987A98 (53 insns): TFN frontend.

    Forwards to rmmi_tfn_handler @0x919879E0. Live: =? -> bare OK.
    GEN takes no key material, so modeled set forms are answered by the
    TFN-frontend stub (no guard trip, no attempt cost by construction).
    """
    if pcmd.form in ("test", "read"):
        return [OK]  # live: AT+ESMLGEN=? -> bare OK
    if pcmd.form == "set":
        return ["+ESMLGEN: 0", OK]  # TFN-frontend stub (modeled, no keys)
    return [ERROR]


def model_clck(pcmd, state=None):
    """rmmi_clck_hdlr @0x90F0A052. Live: CLCK="PN/PU/PP/PC",2 -> ERROR
    (needs SIM context). Unlock (mode 0) is BLOCKED by the guard."""
    state = state or get_default_lock_state()
    if pcmd.form == "test":
        # Not captured live; modeled range of the generic facility handler.
        return ['+CLCK: ("PN","PU","PP","PC","PS","SC")', OK]
    if pcmd.form == "set" and len(pcmd.args) >= 2:
        fac = _unquote(pcmd.args[0]).upper()
        try:
            mode = int(_unquote(pcmd.args[1]))
        except ValueError:
            return [ERROR]
        if mode == 0:
            raise AttemptCostingBlocked(
                "F2 CLCK_UNLOCK (defense-in-depth): unlock never executes.")
        if mode == 2 and (fac in _SML_FACS or fac):
            if not state.sim_present:
                return [ERROR]  # live: ERROR without SIM context
            return ["+CLCK: 0", OK]  # modeled SIM-present answer
        return [ERROR]
    return [ERROR]


def _model_bare_ok(pcmd, _state=None):  # ECRRST/ECSMLCK/ESLBLOB/...
    if pcmd.form in ("test", "read"):
        return [OK]  # unobserved live; conservative bare-OK stub
    return [ERROR]


def model_motsmldb(pcmd, state=None):
    """MOTSMLDB/MOTSMLEVENT are NOT RMMI: mot_sml_db_handler @0x912DE034
    backend. Query forms modeled; writes BLOCKED by the guard."""
    if pcmd.form in ("test", "read"):
        return [OK]  # modeled stub; no live capture exists
    raise AttemptCostingBlocked(
        "F5 MOTSMLDB_WRITE (defense-in-depth): writes never execute.")


# Name -> model function. Commands without a dedicated model share the
# conservative bare-OK stub (their set forms carry no key material per
# the RE analysis; the 5 attempt-costing families all have explicit
# models + guard trips above).
MODELS = {
    "ESMLCK": model_esmlck,
    "ESMLRSU": model_esmlrsu,
    "ESMLGEN": model_esmlgen,
    "CLCK": model_clck,
    "MOTSMLDB": model_motsmldb,
    "MOTSMLEVENT": model_motsmldb,
    "ECRRST": _model_bare_ok,
    "ECSMLCK": _model_bare_ok,
    "ESLBLOB": _model_bare_ok,
    "ESLBLOBF": _model_bare_ok,
    "ESMLRSUF": _model_bare_ok,
    "ERSUKEY": _model_bare_ok,  # set forms blocked by guard before here
}


def dispatch(line, state=None):
    """Full software pipeline: parse -> guard -> route -> model.

    Returns (ParsedCommand, [response lines]). Raises AttemptCostingBlocked
    for the 5 guarded forms, ATParseError for malformed input. Unknown
    names -> [ERROR] (analyzer miss path). Nothing is ever transmitted.
    """
    state = state or get_default_lock_state()
    pcmd = parse_at(line)
    guard_attempt_costing(pcmd)  # <-- must precede any model execution
    fn = MODELS.get(pcmd.name)
    if fn is None:
        return pcmd, [ERROR]
    return pcmd, fn(pcmd, state)


# --------------------------------------------------------------------------
# 5. Query oracle: exact live responses for =? and ? forms.
# --------------------------------------------------------------------------
# Every entry below is live-attested (HANDOFF.md Sec 3e). The ESMLCK? rows
# render from the configurable LockState so updated verbatim captures can
# replace the stub layout without touching the oracle.
def query_oracle(line, state=None):
    """Return the exact live response lines for a read-only string.

    Accepts =? / ? forms plus the live-attested read-only status form
    AT+CLCK="<fac>",2 (syntactically a set form, costs no attempt and is
    safe to model). Anything else raises ATParseError (the oracle has no
    opinion on -- and never executes -- other forms).
    """
    state = state or get_default_lock_state()
    pcmd = parse_at(line)
    if pcmd.form in ("test", "read"):
        pass
    elif (pcmd.name == "CLCK" and pcmd.form == "set" and len(pcmd.args) >= 2
            and _unquote(pcmd.args[1]) == "2"):
        pass  # live read-only form: CLCK="PN/PU/PP/PC",2 -> ERROR
    else:
        raise ATParseError("oracle is read-only-query-only: %r" % line)
    _pcmd, resp = dispatch(line, state)
    return resp


# --------------------------------------------------------------------------
# 6. Self-test (software only: parses strings, asserts routes + guard).
# --------------------------------------------------------------------------
def selftest():
    """Parse known-good queries, verify dispatch targets + guard + oracle.

    Uses ONLY query/test strings from live captures plus synthetic set-form
    strings that are parsed in memory and refused -- nothing is emitted.
    Returns (passed, failed, details). Exit code derives from it in main.
    """
    passed, failed, details = 0, 0, []

    def check(label, cond, extra=""):
        nonlocal passed, failed
        if cond:
            passed += 1
            details.append("PASS %s" % label)
        else:
            failed += 1
            details.append("FAIL %s %s" % (label, extra))

    st = get_default_lock_state()

    # -- 6a. known-good query strings parse + hit the right handler VA ----
    known_good = [
        ("AT+ESMLCK=?", "ESMLCK", "test", 0x91985788),
        ("AT+ESMLCK?", "ESMLCK", "read", 0x91985788),
        ('AT+CLCK="PN",2', "CLCK", "set", 0x90F0A052),
        ('AT+CLCK="PU",2', "CLCK", "set", 0x90F0A052),
        ('AT+CLCK="PP",2', "CLCK", "set", 0x90F0A052),
        ('AT+CLCK="PC",2', "CLCK", "set", 0x90F0A052),
        ("AT+ESMLRSU=?", "ESMLRSU", "test", 0x91987884),
        ("AT+ESMLGEN=?", "ESMLGEN", "test", 0x91987A98),
        ("AT+ECRRST=?", "ECRRST", "test", 0x91986422),
        ("AT+ECSMLCK=?", "ECSMLCK", "test", 0x91985F5A),
        ("AT+ESLBLOB=?", "ESLBLOB", "test", 0x90F1BF52),
        ("AT+ESLBLOBF=?", "ESLBLOBF", "test", 0x91985A30),
        ("AT+ESMLRSUF=?", "ESMLRSUF", "test", 0x91987920),
        ("AT+ERSUKEY=?", "ERSUKEY", "test", 0x91987B40),
    ]
    for raw, name, form, va in known_good:
        try:
            p = parse_at(raw)
            check("parse[%s]" % raw,
                  p.name == name and p.form == form and p.handler_va == va,
                  "got %r" % (p,))
        except Exception as e:  # noqa: BLE001
            check("parse[%s]" % raw, False, "raised %r" % (e,))

    # -- 6b. oracle reproduces the exact live responses --------------------
    try:
        check("oracle[ESMLCK=?]",
              query_oracle("AT+ESMLCK=?", st) == [ESMLCK_TEST_STRING, OK],
              "got %r" % (query_oracle("AT+ESMLCK=?", st),))
    except Exception as e:  # noqa: BLE001
        check("oracle[ESMLCK=?]", False, "raised %r" % (e,))
    try:
        r = query_oracle("AT+ESMLCK?", st)
        shape_ok = (len(r) == 9 and r[-1] == OK
                    and r[-2] == '"000000000000000",0,0,0,0,0'
                    and all(x.startswith("+ESMLCK: ") for x in r[:-2]))
        check("oracle[ESMLCK? 7-tuple+zeros+OK]", shape_ok, "got %r" % (r,))
    except Exception as e:  # noqa: BLE001
        check("oracle[ESMLCK? 7-tuple+zeros+OK]", False, "raised %r" % (e,))
    for fac in ("PN", "PU", "PP", "PC"):
        try:
            r = query_oracle('AT+CLCK="%s",2' % fac, st)
            check("oracle[CLCK %s,2 -> ERROR]" % fac, r == [ERROR],
                  "got %r" % (r,))
        except Exception as e:  # noqa: BLE001
            check("oracle[CLCK %s,2 -> ERROR]" % fac, False,
                  "raised %r" % (e,))
    for raw in ("AT+ESMLRSU=?", "AT+ESMLGEN=?"):
        try:
            check("oracle[%s -> bare OK]" % raw,
                  query_oracle(raw, st) == [OK])
        except Exception as e:  # noqa: BLE001
            check("oracle[%s -> bare OK]" % raw, False, "raised %r" % (e,))

    # -- 6c. guard blocks all 5 attempt-costing forms (parsed, refused) ----
    # NOTE: these literals are synthetic software-only fixtures. They are
    # parsed in memory and must raise; they are never emitted anywhere.
    blocked = [
        ("F1", 'AT+ESMLCK=1,0,"00000000","000000000000000","",""'),
        ("F2", 'AT+CLCK="PN",0,"12345678"'),
        ("F3", 'AT+ERSUKEY="00:11:22:33"'),
        ("F4", 'AT+ESMLRSU=1,"deadbeef"'),
        ("F5", 'AT+MOTSMLDB="00112233"'),
        ("F5b", 'AT+MOTSMLEVENT="00112233"'),
    ]
    for tag, raw in blocked:
        try:
            dispatch(raw, st)
            check("guard[%s blocks]" % tag, False, "no raise for %r" % raw)
        except AttemptCostingBlocked:
            check("guard[%s blocks]" % tag, True)
        except Exception as e:  # noqa: BLE001
            check("guard[%s blocks]" % tag, False, "wrong exc %r" % (e,))
    # Safe forms must NOT trip the guard:
    for raw in ("AT+ESMLCK=?", "AT+ESMLCK?", 'AT+CLCK="PN",2',
                "AT+ESMLRSU=?", "AT+ESMLGEN=?"):
        try:
            dispatch(raw, st)
            check("noguard[%s]" % raw, True)
        except AttemptCostingBlocked as e:
            check("noguard[%s]" % raw, False, "tripped: %s" % (e,))
        except Exception as e:  # noqa: BLE001
            check("noguard[%s]" % raw, False, "raised %r" % (e,))

    # -- 6d. submode / gate / backend routing sanity -----------------------
    check("rsu-submodes", RSU_SUBMODES == {
        1: "rmmi_op12_rsu_hdlr",
        2: "op129_parse(rmmi_parse_op129_rsu_cmd)",
        3: "op08_parse(rmmi_parse_op08_rsu_cmd)",
        6: "op12t_parse(rmmi_parse_op12t_rsu_cmd)"})
    check("backend[MOTSMLDB]",
          DISPATCH.get("MOTSMLDB") == MOT_SML_DB_HANDLER_VA
          and DISPATCH_BACKEND.get("MOTSMLDB") == NOT_RMMI)
    check("backend[MOTSMLEVENT]",
          DISPATCH.get("MOTSMLEVENT") == MOT_SML_DB_HANDLER_VA
          and DISPATCH_BACKEND.get("MOTSMLEVENT") == NOT_RMMI)
    check("gate-default-allow", bool(st.esmlck_execute_allow))
    check("sml-sim-backend", _SML_SIM_BACKEND in (
        "stub(local)", "sim.sml_sim", "sml_sim"),
        "got %r" % (_SML_SIM_BACKEND,))
    return passed, failed, details


def main(argv):
    if "--selftest" in argv or len(argv) == 1:
        passed, failed, details = selftest()
        print("rmmi_sim selftest: %d passed, %d failed "
              "[sml_sim backend: %s]" % (passed, failed, _SML_SIM_BACKEND))
        for d in details:
            print("  " + d)
        return 1 if failed else 0
    # One-shot software query: python sim/rmmi_sim.py 'AT+ESMLCK=?'
    state = get_default_lock_state()
    rc = 0
    for arg in argv:
        try:
            _pcmd, resp = dispatch(arg, state)
            print(">>>", arg)
            for line in resp:
                print(line)
        except (AttemptCostingBlocked, ATParseError) as e:
            print(">>>", arg)
            print("REFUSED: %s" % (e,))
            rc = 2
    return rc


if __name__ == "__main__":
    import sys
    sys.exit(main(sys.argv[1:]))
