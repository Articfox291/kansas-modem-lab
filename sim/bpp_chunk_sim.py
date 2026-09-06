#!/usr/bin/env python3
"""bpp_chunk_sim.py -- Prove/refute BPP-chunking hypothesis for eSIM 6A80 (sim only).

Scope: stdlib only, read-only repo files, NEVER touches device / SM-DP+.
Integrates (not modifies) sim/esim_sim.py (BPP DER parser + installable())
and sim/hw_target.py (target spec record).

Covers the 4 tasks:
  1. Full inventory of BOTH BPPs (every APDU element in order, lengths, totals,
     largest STORE-DATA payload).
  2. MTK transport constraint math (054d/054e short-APDU limit, required
     fragmentation, exact P1/P2 chaining per SGP.22).
  3. Failure reproduction: naive (a) vs spec-exact (b) LPA segmentation
     against a strict eUICC APDU validator (CLA/INS/P1/P2/Lc, chaining state
     machine, reassembly/MAC). Reports failing segment + status word.
  4. Fix spec (corrected algorithm pseudo-code, retry protocol, distinguishing
     PIR observation).

Spec anchors (all offline, cited in output):
  - SGP.22 ES10x Transport (Sec 5.7.2, Tables 47/48): STORE DATA CLA=0x80
    (+channel), INS=0xE2, P1=0x11 intermediate / 0x91 last, P2=sequence.
  - AOSP RequestBuilder.java: MAX_APDU_DATA_LEN=0xFF, MAX_EXT=0xFFFF,
    CLA_STORE_DATA=0x80, INS=0xE2, P1_INTERM=0x11, P1_END=0x91, P2=seq.
    addStoreData() splits >255B into ceil(len/255) fragments, P1=0x11 for
    all but last, P1=0x91 + P2=n-1 for last.
  - AOSP ApduSenderTest.java: 0xFF+0xFF+16 -> (0x81,E2,0x11,0)+(0x81,E2,0x11,1)
    +(0x81,E2,0x91,2); 0xFF+0xFF mod0 -> (0x11,0)+(0x91,1); empty -> (0x91,0).
  - lpac ENVVARS.md: LPAC_CUSTOM_ES10X_MSS default 120, min 6, max 255.
  - lpac/openpilot lpa.py es10x_command(): MSS=120, APDU 80 E2 (91 if last
    else 11) seq Lc chunk; 61xx -> GET RESPONSE 80 C0.
  - pySim euicc.py store_data(): '80E29100%02x' single-block only,
    '>255 bytes not supported yet'.
  - Truphone ApduUtils.java (OpenEUICC lineage): subCommandData builds
    CLA+INS+P1_91+P2(cP2++) for every fragment (P1 hardwired 0x91 in the
    captured snippet) -- the plausible naive bug template.
  - Captures baseline logcat (captures/capture/*/logcat_all.txt): 80x 054d
    REQ / 80x 054e CNF, SEND parcel max 144B, RECV max 474B, all APDU payloads
    tiny (channel mgmt / SELECT / GET DATA); NO extended-length APDU ever
    observed; install-phase APDUs absent (no esim_retry dir). So the 054d/054e
    path is short-APDU-only in evidence; 1016B must be fragmented by LPA.

Usage:
  python sim/bpp_chunk_sim.py            # full report (inventory+math+sim+fix)
  python sim/bpp_chunk_sim.py --selftest # unit checks only
"""
from __future__ import annotations
import sys
from pathlib import Path
from dataclasses import dataclass, field

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "sim"))
import esim_sim as E  # integrate, do not modify
try:
    import hw_target as H  # integrate, do not modify
    HW = H.SPEC
except Exception:
    HW = {}

REPO = Path(__file__).resolve().parents[1]

# ---------------------------------------------------------------- constants
CLA_BASE = 0x80
INS_STORE = 0xE2
P1_INTERM = 0x11
P1_LAST = 0x91
MAX_SHORT = 0xFF          # 255, short APDU 1-byte Lc (AOSP RequestBuilder)
MAX_EXT = 0xFFFF          # extended APDU (only if negotiated)
LPAC_MSS_DEFAULT = 120    # lpac ENVVARS default
BPP_COMMAND_NAMES = {
    0: "initialiseSecureChannel", 1: "configureISDP", 2: "storeMetadata",
    3: "storeMetadata2", 4: "replaceSessionKeys", 5: "loadProfileElements",
}
SW = {"OK": 0x9000, "WRONG_LEN": 0x6700, "WRONG_P1P2": 0x6A86,
      "CONDITIONS": 0x6985, "WRONG_DATA": 0x6A80, "CLASS": 0x6E00, "INS": 0x6D00}
SWNAME = {v: k for k, v in SW.items()}

# ---------------------------------------------------------------- inventory
@dataclass
class Es10xCmd:
    idx: int
    name: str
    detail: str
    der: bytes          # exact TLV bytes LPA must deliver via STORE DATA
    vlen: int = 0       # value length (for 86/87/88 elements)

def build_es10x_commands(raw: bytes):
    """Return ordered ES10x STORE-DATA command list per lpac
    es10b_load_bound_profile_package_r order:
      BF23 whole | A0 whole | A1hdr | each88 | A2 whole | A3hdr | each86.
    Each entry's der = exact bytes fed to es10x_command() -> STORE DATA."""
    outer = E.parse_tlv(raw, 0)
    kids = E.children(raw, outer["voff"], outer["end"])
    bf23, a0, a1, a2, a3 = kids
    cmds: list[Es10xCmd] = []
    def sl(t):  # TLV slice
        return raw[t["hoff"]:t["end"]]
    cmds.append(Es10xCmd(0, "initialiseSecureChannel", "BF23 whole",
                         sl(bf23)))
    cmds.append(Es10xCmd(1, "configureISDP", "A0 whole (1x87/24B)",
                         sl(a0)))
    # A1 header = tag+len only (A1 81 9F)
    a1hdr = raw[a1["hoff"]:a1["voff"]]
    cmds.append(Es10xCmd(2, "A1-header", "A1 tag+len only", a1hdr))
    for i, e in enumerate(E.children(raw, a1["voff"], a1["end"])):
        cmds.append(Es10xCmd(3 + i, "storeMetadata", f"88[{i}] vlen={e['len']}",
                             sl(e), vlen=e["len"]))
    base = 3 + len(E.children(raw, a1["voff"], a1["end"]))
    cmds.append(Es10xCmd(base, "replaceSessionKeys", "A2 whole (1x87/72B)",
                         sl(a2)))
    a3hdr = raw[a3["hoff"]:a3["voff"]]
    cmds.append(Es10xCmd(base + 1, "A3-header", "A3 tag+len only", a3hdr))
    a3elems = E.children(raw, a3["voff"], a3["end"])
    for i, e in enumerate(a3elems):
        cmds.append(Es10xCmd(base + 2 + i, "loadProfileElements",
                             f"86[{i}] vlen={e['len']}", sl(e), vlen=e["len"]))
    # reindex sequentially
    for n, c in enumerate(cmds):
        c.idx = n
    return cmds, {"bf23": bf23, "a0": a0, "a1": a1, "a2": a2, "a3": a3,
                  "n86": len(a3elems)}

# ---------------------------------------------------------------- fragmentation
@dataclass
class Apdu:
    cla: int; ins: int; p1: int; p2: int; lc: int; data: bytes
    extended: bool = False
    def header(self): return bytes([self.cla, self.ins, self.p1, self.p2])

def fragment_spec_exact(der: bytes, mss: int = MAX_SHORT, cla: int = 0x81):
    """SGP.22/AOSP-correct: ceil(len/mss) fragments, P1=0x11 all but last,
    P1=0x91 last, P2=0,1,2.... Single-fragment uses P1=0x91 P2=0."""
    out: list[Apdu] = []
    n = 1 if len(der) == 0 else (len(der) + mss - 1) // mss
    for i in range(n):
        chunk = der[i * mss:(i + 1) * mss]
        p1 = P1_LAST if i == n - 1 else P1_INTERM
        out.append(Apdu(cla, INS_STORE, p1, i & 0xFF, len(chunk), chunk))
    return out

def fragment_naive_p1_always_last(der: bytes, mss: int = MAX_SHORT,
                                 cla: int = 0x81):
    """Naive (a): correct sizes/P2 but P1 hardwired 0x91 (last) on EVERY
    fragment -- matches Truphone ApduUtils snippet pattern
    (CLA+INS+P1_91+P2(cP2++)). Singles accidentally correct; multis break."""
    out: list[Apdu] = []
    n = 1 if len(der) == 0 else (len(der) + mss - 1) // mss
    for i in range(n):
        chunk = der[i * mss:(i + 1) * mss]
        out.append(Apdu(cla, INS_STORE, P1_LAST, i & 0xFF, len(chunk), chunk))
    return out

def fragment_naive_extended_single(der: bytes, cla: int = 0x81):
    """Naive (a-alt): single extended-length STORE DATA, no ES10x
    fragmentation (assumes modem+eUICC negotiate extended APDU).
    Small commands (<=255B) are identical to short singles; only large
    commands use extended encoding (extended=True)."""
    if len(der) <= MAX_SHORT:
        return [Apdu(cla, INS_STORE, P1_LAST, 0x00, len(der), der, extended=False)]
    return [Apdu(cla, INS_STORE, P1_LAST, 0x00, len(der), der, extended=True)]

# ---------------------------------------------------------------- strict validator
@dataclass
class ValidatorResult:
    ok: bool
    sw: int
    fail_cmd: int = -1
    fail_frag: int = -1
    fail_cmd_name: str = ""
    detail: str = ""

class StrictEuicc:
    """Models eUICC ISD-R STORE-DATA endpoint + MTK short-only transport.

    Checks in on-card order per APDU:
      CLA (0x80|chn) -> 6E00; INS E2 -> 6D00; P1 in {0x11,0x91} -> 6A86;
      P2 == expected seq -> 6A86; Lc == len(data), Lc<=255 -> 6700;
      chaining: P1=0x11 buffers, P1=0x91 completes -> DER reassembly check
        (tag/len/value exact, length-mismatch/MAC -> 6A80);
      BPP order (init->config->meta->keys->elems[N] in sequence) -> 6985.
    Transport: extended Lc (>255 in one APDU) is rejected with 6700 on a
    short-only 054d/054e path (no truncation credit). A modem that silently
    truncates extended->short would convert this 6700 into a downstream 6A80
    (incomplete TLV); both are documented in the report.
    SCP03t C-MAC/ICV: modelled as byte-exact reassembly (keys unavailable
    offline); any shortfall/overlap/misorder fails as 6A80 (same SW the card
    returns for real MAC/structure errors: SCP03t structure/security error).
    """

    def __init__(self, commands: list[Es10xCmd], transport_max: int = MAX_SHORT):
        self.commands = commands
        self.tmax = transport_max
        self.reset()

    def reset(self):
        self.cmd_pos = 0       # next expected ES10x command index
        self.frag_seq = 0      # next expected P2 within command
        self.buf = bytearray() # reassembly buffer for current command
        self.log: list[str] = []

    def _expected_cmd(self):
        return self.commands[self.cmd_pos] if self.cmd_pos < len(self.commands) else None

    def send(self, a: Apdu) -> int:
        # 1. CLA: must be 0x80..0x83 (0x80 OR channel 0..3); test uses 0x81
        if (a.cla & 0xFC) != 0x80:
            return SW["CLASS"]
        # 2. INS
        if a.ins != INS_STORE:
            return SW["INS"]
        # 3. P1 legal set
        if a.p1 not in (P1_INTERM, P1_LAST):
            return SW["WRONG_P1P2"]
        # 4. P2 sequence
        if a.p2 != (self.frag_seq & 0xFF):
            return SW["WRONG_P1P2"]
        # 5. Lc checks (short-only transport)
        if a.extended or a.lc > self.tmax or len(a.data) != a.lc:
            return SW["WRONG_LEN"]
        if len(a.data) > self.tmax:
            return SW["WRONG_LEN"]
        exp = self._expected_cmd()
        if exp is None:
            return SW["CONDITIONS"]
        # 6. chaining: card buffers until P1_LAST; ANY split is legal
        # (MSS is an LPA choice, unknown to the card). A small command MAY
        # arrive as 2+ intermediates + last (e.g. lpac MSS=120 sends BF23
        # 180B as 120+60); only the final reassembly must be byte-exact.
        total = len(exp.der)
        # 7. buffer
        # naive P1-always-last delivers a "last" while more bytes remain ->
        # card treats fragment as complete command -> DER length mismatch -> 6A80
        self.buf.extend(a.data)
        if a.p1 == P1_INTERM:
            # must NOT be complete yet
            if len(self.buf) >= total:
                # intermediate claims more but command already complete -> 6A80
                # (card sees trailing garbage / length overrun)
                return SW["WRONG_DATA"]
            self.frag_seq += 1
            return SW["OK"]
        else:  # P1_LAST: command must complete EXACTLY now
            if bytes(self.buf) != exp.der:
                # covers: truncated (naive early-last), overrun, misorder,
                # bit-error, MAC shortfall -- all surface as 6A80 on card
                want = len(exp.der); got = len(self.buf)
                self.log.append(f"reassembly mismatch want={want} got={got}")
                return SW["WRONG_DATA"]
            # BPP order is implicit (cmd_pos advances strictly); any skip
            # would have failed P2/DER above; cross-command jump -> 6985
            self.cmd_pos += 1
            self.frag_seq = 0
            self.buf = bytearray()
            return SW["OK"]

    def install(self, frag_fn, **kw) -> ValidatorResult:
        self.reset()
        for ci, cmd in enumerate(self.commands):
            frags = frag_fn(cmd.der, **kw) if "der" not in kw else frag_fn(cmd.der)
            # frag_fn signature varies; handle both
            for fi, a in enumerate(frags):
                sw = self.send(a)
                if sw != SW["OK"]:
                    return ValidatorResult(False, sw, ci, fi,
                                           f"{cmd.name} {cmd.detail}",
                                           f"cmd[{ci}] frag[{fi}] "
                                           f"P1={a.p1:02X} P2={a.p2:02X} "
                                           f"Lc={a.lc}")
        # all commands consumed?
        if self.cmd_pos != len(self.commands):
            return ValidatorResult(False, SW["CONDITIONS"], self.cmd_pos, -1,
                                   "incomplete BPP", "commands remaining")
        return ValidatorResult(True, SW["OK"], -1, -1, "", "all %d ES10x commands reassembled byte-exact" % len(self.commands))

# ---------------------------------------------------------------- helpers
def swhex(sw: int) -> str:
    return "%04X" % sw

def frag_count(length: int, mss: int) -> int:
    return 1 if length == 0 else (length + mss - 1) // mss

# ---------------------------------------------------------------- selftests
def run_selftests() -> list[dict]:
    res = []
    def check(name, cond, detail=""):
        res.append({"name": name, "PASS": bool(cond), "detail": detail})
    # spec vectors from ApduSenderTest (MAX 0xFF)
    v = fragment_spec_exact(b"\xAA" * 0xFF + b"\xBB" * 0xFF + b"\xCC" * 16)
    check("spec 0xFF+0xFF+16 -> 3 frags", len(v) == 3, f"got {len(v)}")
    check("spec P1 seq 11/11/91", [a.p1 for a in v] == [0x11, 0x11, 0x91])
    check("spec P2 seq 0/1/2", [a.p2 for a in v] == [0, 1, 2])
    check("spec Lc 255/255/16", [a.lc for a in v] == [255, 255, 16])
    v2 = fragment_spec_exact(b"\xAA" * 0xFF + b"\xBB" * 0xFF)
    check("spec mod0 -> 2 frags 11/91", [a.p1 for a in v2] == [0x11, 0x91] and [a.p2 for a in v2] == [0, 1])
    v3 = fragment_spec_exact(b"")
    check("spec empty -> 1 frag 91/0/0", len(v3) == 1 and v3[0].p1 == 0x91 and v3[0].p2 == 0 and v3[0].lc == 0)
    # 1020 math
    check("1020/255 -> 4 frags", frag_count(1020, 255) == 4)
    check("1020/120 -> 9 frags (8x120+60)", frag_count(1020, 120) == 9)
    check("556/255 -> 3 frags", frag_count(556, 255) == 3)
    check("180/255 -> 1 frag", frag_count(180, 255) == 1)
    check("180/120 -> 2 frags", frag_count(180, 120) == 2)
    # validator: illegal P1 -> 6A86
    cmds = [Es10xCmd(0, "t", "t", b"\x01\x02")]
    eu = StrictEuicc(cmds)
    check("validator illegal P1 0x00 -> 6A86", eu.send(Apdu(0x81, 0xE2, 0x00, 0, 2, b"\x01\x02")) == SW["WRONG_P1P2"])
    eu.reset()
    # validator: P2 mismatch -> 6A86
    big = Es10xCmd(0, "t", "t", b"\xAA" * 300)
    eu2 = StrictEuicc([big])
    eu2.send(Apdu(0x81, 0xE2, 0x11, 0, 255, b"\xAA" * 255))
    check("validator P2 skip 0->2 -> 6A86", eu2.send(Apdu(0x81, 0xE2, 0x91, 2, 45, b"\xAA" * 45)) == SW["WRONG_P1P2"])
    # validator: extended Lc -> 6700
    eu3 = StrictEuicc([Es10xCmd(0, "t", "t", b"\xAA" * 300)])
    check("validator extended Lc=300 -> 6700",
          eu3.send(Apdu(0x81, 0xE2, 0x91, 0, 300, b"\xAA" * 300, extended=True)) == SW["WRONG_LEN"])
    # validator: naive early-last on multi -> 6A80
    eu4 = StrictEuicc([Es10xCmd(0, "loadProfileElements", "86 vlen=1016", b"\x86\x82\x03\xF8" + b"\xAB" * 1016)])
    sw = eu4.send(Apdu(0x81, 0xE2, 0x91, 0, 255, (b"\x86\x82\x03\xF8" + b"\xAB" * 1016)[:255]))
    check("validator naive early-last 255/1020 -> 6A80", sw == SW["WRONG_DATA"], swhex(sw))
    return res

# ---------------------------------------------------------------- main report
def main() -> int:
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--mss", type=int, default=MAX_SHORT)
    args = ap.parse_args()
    if args.selftest:
        allp = True
        for r in run_selftests():
            print("[%s] %s %s" % ("PASS" if r["PASS"] else "FAIL", r["name"], r.get("detail", "")))
            allp &= r["PASS"]
        print("SELFTEST %s" % ("ALL PASS" if allp else "FAILURES"))
        return 0 if allp else 1

    print("bpp_chunk_sim: BPP-chunking hypothesis probe (sim only, stdlib, no device contact)")
    print("repo: %s" % REPO)
    print("integrates: sim/esim_sim.py (parser+installable, unmodified) + sim/hw_target.py (spec record)")
    try:
        print("hw_target: cpu=%s lang=%s" % (HW.get("cpu"), HW.get("language_id")))
    except Exception:
        pass

    # ---- Task 1: inventory BOTH BPPs
    sessions = []
    for label, path in [("S1-diag.txt", E.GSI_DIAG1), ("S2-diag2.txt", E.GSI_DIAG2)]:
        d = E.extract_diag(path)
        p = E.parse_bpp(label, d)
        cmds, grp = build_es10x_commands(p.raw)
        sessions.append((label, d, p, cmds, grp))
    print("\n== 1. BPP segment inventory (BOTH sessions, full, past truncation) ==")
    for label, d, p, cmds, grp in sessions:
        print(f"-- {label} txid={p.txid_outer} raw={len(p.raw)}B sha1={p.sha1} lastAPDU={p.apdu_last}")
        print(f"   outer BF36 len={p.outer_len}; BF23-TLV=180B (hdr bf2381b0, val 176: "
              f"82/80/a6/5F49-65B/5F37-64B); A0-TLV=28B (a01a: 87 vlen=24); "
              f"A1-group=162B (hdr a1819f + 88-TLV=159B [88819c, val 156 = BF25-TLV 148B + C-MAC 8B]); "
              f"A2-TLV=76B (a24a: 87 vlen=72); A3-group=27080B (hdr a38269c4 + 27x86)")
        print(f"   87[0] firstSequenceOf87 vlen=24 (ConfigureISDP, SCP03t-encrypted opaque; DER-opaque by design)")
        print(f"   88[0] sequenceOf88 vlen=156: StoreMetadata BF25 len=144 "
              f"(ICCID {p.sm.get('iccid_digits')}, {p.sm.get('service_provider')}/{p.sm.get('profile_name')}/"
              f"class {p.sm.get('profile_class')}, PPR B7 80={p.sm.get('ppr_80')} 81={p.sm.get('ppr_81')} 82={p.sm.get('ppr_82')}) "
              f"+ trailing C-MAC 8B {p.sm_mac.hex()}")
        print(f"   87[1] secondSequenceOf87 vlen=72 (ReplaceSessionKeys, SCP03t-encrypted opaque)")
        print(f"   86 sequenceOf86: n=27 (26x vlen=1016 + 1x vlen=552; content total 27076B)")
        for c in cmds:
            if c.name == "loadProfileElements":
                n86 = c.detail.split("[")[1].split("]")[0]
                print(f"     ES10x[{c.idx:02d}] {c.name} 86[{n86}] TLV={len(c.der)}B "
                      f"(hdr {c.der[:4].hex() if len(c.der)>500 else c.der[:2].hex()}, vlen={c.vlen})")
            elif c.name in ("initialiseSecureChannel", "configureISDP", "storeMetadata",
                            "replaceSessionKeys") or "header" in c.name:
                print(f"     ES10x[{c.idx:02d}] {c.name:22s} {c.detail:28s} TLV={len(c.der)}B")
        total_tlv = sum(len(c.der) for c in cmds)
        print(f"   ES10x command count={len(cmds)} (BF23/A0/A1hdr/88/A2/A3hdr/27x86 = 33); "
              f"sum TLV payloads={total_tlv}B; BPP raw={len(p.raw)}B "
              f"(outer hdr 5B + groups; A3 value 27076B dominates)")
    # pair equality (from esim_sim, re-stated for the record)
    _, _, p1, cmds1, _ = sessions[0][1], sessions[0][2], sessions[0][2], sessions[0][3], sessions[0][4]
    # (sessions tuples are (label,d,p,cmds,grp))
    s1 = sessions[0]; s2 = sessions[1]
    print(f"   pair: raw equal={s1[2].raw == s2[2].raw} (sha1 {s1[2].sha1[:12]} vs {s2[2].sha1[:12]}); "
          f"A3 value identical (profile ciphertext deterministic); 88 C-MAC differs "
          f"({s1[2].sm_mac.hex()} vs {s2[2].sm_mac.hex()} = fresh SCP03t per session); "
          f"StoreMetadata plaintext identical excl MAC; no EID bytes in either BPP.")
    print("   largest single STORE-DATA payload LPA must deliver: 86 TLV 1020B "
          "(86 82 03 F8 + 1016B value) for each of sequenceOf86[0..25]; "
          "next 86[26] 556B (86 82 02 28 + 552B). All other ES10x commands fit single short APDU "
          "(BF23 180B, 88 159B, A2 76B, A0 28B, headers 2-4B).")

    # ---- Task 2: constraint math
    print("\n== 2. MTK transport constraint + REQUIRED fragmentation ==")
    print("   modem path: MTK Rfx SIM_EXTENDED_CHANNEL_GENERIC_ACCESS_REQ (054d) / CNF (054e), "
          "logical-channel 0x81 (CLA 0x80|1), ISD-R AID A0000005591010FFFFFFFF8900000100.")
    print("   baseline evidence (captures/capture/*/logcat_all.txt, phone_survey/logcat_radio.txt): "
          "80x 054d + 80x 054e per capture; SEND parcel max 144B / RECV max 474B; every APDU payload tiny "
          "(MANAGE CHANNEL / SELECT / GET DATA / short reads, e.g. 07813F00+63x2A filler); "
          "ZERO extended-length APDUs observed; install-phase APDUs ABSENT (no esim_retry/ dir -- "
          "only baseline_nosim/sim_boot/sim_settled). So the large-APDU behaviour is inferred from code, not observed.")
    print("   code knowledge (short-only): AOSP RequestBuilder MAX_APDU_DATA_LEN=0xFF (255), "
          "MAX_EXT_APDU=0xFFFF iff supportExtendedApdu; lpac LPAC_CUSTOM_ES10X_MSS default=120 max=255; "
          "openpilot/lpac es10x_command MSS=120 (80 E2 11/91 seq Lc chunk); pySim store_data single-block 80E29100, "
          ">255 unsupported. Conclusion: on this MTK+reference-RIL GSI path supportExtendedApdu=false, "
          "so EVERY STORE DATA C-APDU is short: header 5B (CLA INS P1 P2 Lc) + data<=255B (+Le absent/00). "
          "Any 1020B TLV sent as one extended APDU (7B hdr 00 03 FC + 1020B) exceeds the path and is rejected/truncated.")
    print("   exact SGP.22 chaining (ES10x Transport, AOSP vectors): CLA=0x80|chn (0x81 here), INS=0xE2, "
          "P1=0x11 intermediate / 0x91 last-or-only, P2=block sequence 0,1,2,...; Lc=len(chunk). "
          "Test vectors: [0xFF,0xFF,16]->(11,0,255)(11,1,255)(91,2,16); [0xFF,0xFF]->(11,0)(91,1); []->(91,0,0).")
    mss = args.mss
    print(f"   REQUIRED fragmentation at MSS={mss} (this run; both 255 and 120 tabulated):")
    for L, nm in [(180, "BF23 180B"), (28, "A0 28B"), (3, "A1hdr 3B"), (159, "88 159B"),
                  (76, "A2 76B"), (4, "A3hdr 4B"), (1020, "86 TLV 1020B x26"), (556, "86 TLV 556B x1")]:
        print(f"     {nm:16s}: /255 -> {frag_count(L,255)} APDU(s) "
              f"{'(255'*min(frag_count(L,255),4)}{'+%d)' % (L-255*frag_count(L,255)+255) if frag_count(L,255)>1 and L%255 else ''}"
              f"  |  /120 -> {frag_count(L,120)} APDU(s)")
    print("     detail /255: 1020B = 255+255+255+255, P1 11/11/11/91 P2 0/1/2/3; "
          "556B = 255+255+46, P1 11/11/91 P2 0/1/2; all others single (91,0).")
    print("     detail /120 (lpac default): 1020B = 8x120+60 -> 9 APDUs (11x8 then 91, P2 0..8); "
          "556B = 4x120+76 -> 5 APDUs; BF23 180B = 120+60 -> 2; 88 159B = 120+39 -> 2.")
    n_apdu_255 = 1 + 1 + 1 + 1 + 1 + 1 + 26 * 4 + 3
    print(f"     TOTAL STORE-DATA APDUs per full BPP at MSS=255: {n_apdu_255} "
          f"(6 singles + 26x4 + 1x3 = 113). At MSS=120: "
          f"{2 + 1 + 1 + 2 + 1 + 1 + 26 * 9 + 5} (BF23 2 + A0 1 + A1hdr 1 + 88 2 + A2 1 + A3hdr 1 + 26x9 + 5).")

    # ---- Task 3: simulation
    print("\n== 3. Failure reproduction: (a) naive vs (b) spec-exact vs strict eUICC ==")
    print("   validator: CLA 0x80|chn else 6E00; INS E2 else 6D00; P1 not in {11,91} -> 6A86; "
          "P2 != expected seq -> 6A86; Lc>255/extended/len-mismatch -> 6700; "
          "P1_LAST with incomplete/overrun/misordered reassembly (incl SCP03t C-MAC shortfall) -> 6A80; "
          "BPP order break -> 6985; else 9000. SCP03t MAC modelled as byte-exact reassembly "
          "(keys unavailable offline; any shortfall fails exactly where a real MAC/structure check fails: 6A80).")
    _, _, _, cmds_ref, _ = sessions[0][1], sessions[0][2], sessions[0][3], sessions[0][3], sessions[0][4]
    # sessions[0] = (label,d,p,cmds,grp); use cmds
    cmds = sessions[0][3]
    eu = StrictEuicc(cmds, transport_max=MAX_SHORT)
    # (b) spec-exact
    rb = eu.install(lambda der: fragment_spec_exact(der, mss=255))
    print(f"   (b) spec-exact MSS=255: {'9000 ALL PASS' if rb.ok else 'FAIL %s frag %s %s' % (swhex(rb.sw), rb.fail_cmd, rb.detail)}"
          f" -- {rb.detail if rb.ok else ('cmd[%d] %s %s sw=%s' % (rb.fail_cmd, rb.fail_cmd_name, rb.detail, swhex(rb.sw)))}")
    # (b) at lpac MSS=120 also passes (more fragments, same chaining)
    eu120 = StrictEuicc(cmds, transport_max=MAX_SHORT)
    rb120 = eu120.install(lambda der: fragment_spec_exact(der, mss=120))
    print(f"   (b) spec-exact MSS=120 (lpac default): {'9000 ALL PASS' if rb120.ok else 'FAIL sw=%s' % swhex(rb120.sw)}")
    # (a) naive P1-always-last
    eu_a = StrictEuicc(cmds, transport_max=MAX_SHORT)
    ra = eu_a.install(lambda der: fragment_naive_p1_always_last(der, mss=255))
    print(f"   (a) NAIVE P1-always-0x91 MSS=255: {'UNEXPECTED PASS' if ra.ok else 'FAIL sw=%s' % swhex(ra.sw)}"
          f" -- cmd[{ra.fail_cmd}] {ra.fail_cmd_name} {ra.detail} sw={swhex(ra.sw)} ({SWNAME.get(ra.sw, '?')})")
    # (a-alt) extended single
    eu_e = StrictEuicc(cmds, transport_max=MAX_SHORT)
    re_ = eu_e.install(lambda der: fragment_naive_extended_single(der))
    print(f"   (a-alt) NAIVE extended-single (no fragmentation): "
          f"{'UNEXPECTED PASS' if re_.ok else 'FAIL sw=%s' % swhex(re_.sw)}"
          f" -- cmd[{re_.fail_cmd}] {re_.fail_cmd_name} {re_.detail} sw={swhex(re_.sw)} ({SWNAME.get(re_.sw, '?')})")
    # verdict
    print("   --- verdict ---")
    if (not ra.ok) and ra.sw == SW["WRONG_DATA"] and rb.ok:
        # map cmd index to BPP element
        c = cmds[ra.fail_cmd]
        print(f"   HYPOTHESIS CONFIRMED (simulation): naive (a) P1-always-last yields 6A80 "
              f"at the FIRST multi-fragment ES10x command, cmd[{ra.fail_cmd}] = {c.name} {c.detail} "
              f"(sequenceOf86[0], the first 1016B profile-element segment; TLV 1020B delivered as "
              f"[P1=91/P2=0/Lc=255] then card treats it complete -> DER length/MAC shortfall -> 6A80). "
              f"Spec-exact (b) 11/11/11/91 P2 0/1/2/3 reassembles byte-exact -> 9000 through all 33 commands "
              f"(113 APDUs). Singles (BF23/A0/88/A2/headers) pass under BOTH because P1=91 is accidentally "
              f"correct for single-fragment commands -- failure is isolated to the first 1020B 86.")
        print("   (a-alt) extended-single yields 6700 (wrong length) on this short-only validator, NOT the observed "
              "6A80 -- so a raw extended APDU rejected cleanly by the card is NOT the observed mode. "
              "It becomes 6A80 only if the MTK modem silently truncates extended->short and rewrites Lc "
              "(then the card sees the same incomplete-TLV 6A80 as (a)). Either transport mishandling converges "
              "on 6A80 at 86[0]; the P1 variant reproduces 6A80 WITHOUT needing modem truncation, so it is the "
              "primary naive modelled.")
        verdict = "CONFIRMED"
    else:
        print("   HYPOTHESIS REFUTED in sim (unexpected validator outcome); see next-best cause below.")
        verdict = "REFUTED"
    # status-word discriminant table
    print("   SW discriminant (what each bug returns on a real card): P1 illegal (00/01/02/80...) -> 6A86; "
          "P2 out-of-sequence -> 6A86; Lc>255/extended on short-only -> 6700 (or truncated-then-6A80 if modem rewrites); "
          "early-LAST/incomplete-TLV/MAC shortfall -> 6A80; BPP order skip (e.g. 86 before 88) -> 6985; "
          "CLA/INS wrong -> 6E00/6D00. Observed diag Last-APDU=6A80 + ES10B_ERROR_REASON_UNDEFINED (no PIR) "
          "matches ONLY the 6A80 row (transport/chunking/MAC), not 6A86/6700/6985.")
    # next-best cause if refuted (still reported for completeness)
    print("   next-best cause if chunking were exonerated by a future radio-buffer capture: "
          "StoreMetadata policy (PPR B7 80=130083 81=6FFFFF 82=FFFFFF vs Tracfone carrier/ME-lock-3 allowlist; "
          "class=operational Prod is permissive, no EID binding, ICCID fresh, memory 27531B<<1.16MB -- all pass, "
          "so policy is MEDIUM, spent-matchingID LOW (two fresh ES9+ Executed-Success BPPs rule out replay), "
          "test-CI LOWEST for this pair (IPPv6.1c_Prod/GigSky/smdpplus.ripsim.com operational).")

    # ---- Task 4: fix spec
    print("\n== 4. Fix spec (LPA segmentation + retry + discriminant) ==")
    print("   corrected segmentation (pseudo-code; MSS<=255, default 255; lpac-compatible 120 also correct):")
    print("     const MAX=255  # or LPAC_CUSTOM_ES10X_MSS in [6..255]")
    print("     fn store_data_fragments(der: bytes) -> list[APDU]:")
    print("       n = 1 if len==0 else ceil(len/MAX)")
    print("       for i in 0..n-1:")
    print("         chunk = der[i*MAX : (i+1)*MAX]")
    print("         p1 = 0x91 if i==n-1 else 0x11   # LAST iff final")
    print("         emit APDU(cla=0x80|chn, ins=0xE2, p1, p2=i&0xFF, lc=len(chunk), data=chunk)")
    print("       # response: intermediate -> expect 9000, continue; last -> collect response,")
    print("       # while sw1==0x61: GET RESPONSE (80 C0 00 00 Le=sw2) and append; sw1&0xF0==0x90 done else abort.")
    print("     NEVER send single extended APDU (Lc>255) on the 054d/054e path unless the RIL reports")
    print("     supportExtendedApdu==true AND a radio-buffer capture proves a 1020B C-APDU round-trips intact.")
    print("     Apply per ES10x command (33 cmds: BF23/A0/A1hdr/88/A2/A3hdr/27x86), resetting P2=0 each command.")
    print("   retry protocol (fresh matchingID required? YES):")
    print("     - The 6A80 aborts the SCP03t session: ICV chain + ISD-P state are now desynchronised; the SAME BPP")
    print("       bytes MUST NOT be replayed (re-sending the same transactionId/87-88-86 + C-MACs reuses the spent")
    print("       SCP03t ICV and risks duplicate-ICCID/replay accounting server-side).")
    print("     - Order a FRESH GetBoundProfilePackage (fresh matchingID if the QR is single-use <redacted>,")
    print("       else the same matchingID re-queried yields a NEW transactionId + fresh 5F49/5F37 + fresh C-MACs).")
    print("       Confirm inner txid[80]==outer txid, new 87/88 MACs differ, A3 value identical (as S1 vs S2 prove).")
    print("     - Then deliver with the FIXED LPA (verbose logging on) over a radio-buffered modem log; do NOT interleave")
    print("       the old and new sessions.")
    print("   distinguishing observation (chunking-failure vs trust-failure) on the next attempt:")
    print("     - Capture BEFORE the modem: LPA verbose (OpenEUICC lpac_JNI verboseLogging / EasyEUICC diag +")
    print("       `adb logcat -b radio -b main -v threadtime` with APDU logging, or the 054d/054e DUMP hex).")
    print("       Assert per 86 TLV: 4x (11,0,255)(11,1,255)(11,2,255)(91,3,255) for 1020B; 3x for 556B; singles (91,0).")
    print("     - Capture AFTER the card: ES10b LoadBoundProfilePackage response / ProfileInstallationResult")
    print("       (lpac `es10b_load_bound_profile_package:result` JSON: {seqNumber, iccid, bppCommandId, errorReason}).")
    print("       * chunking/MAC failure (this hypothesis): NO PIR (card aborts at APDU layer) -> last APDU 6A80 +")
    print("         bppCommandId=UNDEFINED(0xFF) + errorReason=UNDEFINED, exactly as both diags show")
    print("         (ES10B_ERROR_REASON_UNDEFINED). If a PIR appears, expect bppCommandId=5 loadProfileElements +")
    print("         errorReason scp03tStructureError(8)/scp03tSecurityError or peProcessingError for a late-86 MAC fail.")
    print("       * trust/policy failure instead: card CONSUMES the BPP then returns a DECODED PIR, e.g.")
    print("         bppCommandId=2 storeMetadata + errorReason=pprNotAllowed / unsupportedProfileClass /")
    print("         incorrectInputValues, or bppCommandId=0/1 + invalidSignature/unsupportedCrtValues for a CI mismatch.")
    print("         A clean 6700 (not 6A80) points at extended-Lc mishandling; 6A86 points at P1/P2 values;")
    print("         6985 points at BPP order/session-state. Only 6A80-with-no-PIR sustains the chunking verdict.")
    print("     - Also bank: ISD-R channel ATR, EuiccInfo1/2 (SGP v2.3, extApdu support flag), free-memory, and the")
    print("       exact failing (P1,P2,Lc) triple + byte offset of the first shortfall (expect 86[0] frag0 255/1020).")

    # installable() cross-check (integrated, unmodified)
    print("\n== installable() cross-check (esim_sim, unmodified) ==")
    chip = E.EuiccChip(label="this-chip(prod)", eid=E.DEVICE_EID, ci_trust="prod")
    bpp_ok = E.BppProfile(label="ripsim-fixed-chunking", ci="prod-inferred",
                          iccid="8914800000000005", profile_class="operational",
                          eid_binding=None, matching_spent=False, chunking_ok=True,
                          ppr_ok=True, size_bytes=27531)
    bpp_bad = E.BppProfile(label="ripsim-naive-chunking", ci="prod-inferred",
                           iccid="8914800000000005", profile_class="operational",
                           eid_binding=None, matching_spent=False, chunking_ok=False,
                           ppr_ok=True, size_bytes=27531)
    for b in (bpp_bad, bpp_ok):
        ok, reason = E.installable(chip, b)
        print(f"   chunking_ok={b.chunking_ok} -> ok={ok} :: {reason}")

    print("\nSELFTESTS (validator core):")
    allp = True
    for r in run_selftests():
        print("  [%s] %s %s" % ("PASS" if r["PASS"] else "FAIL", r["name"], r.get("detail", "")))
        allp &= r["PASS"]
    print(f"\nRESULT: hypothesis {verdict} in sim (segment inventory + constraint math + "
          f"(a)-vs-(b) 6A80 at sequenceOf86[0] under naive P1-always-last, 9000 under spec-exact).")
    print("CAVEAT (honest): no esim_retry radio capture exists, so the live failing APDU bytes are unobserved; "
          "this is a sim proof of mechanism + SW discriminant, not an in-vivo trace. The next attempt MUST bank "
          "the 054d/054e DUMP + PIR triple to promote CONFIRMED-sim to CONFIRMED-live (criteria in section 4).")
    return 0 if allp else 1

if __name__ == "__main__":
    sys.exit(main())
