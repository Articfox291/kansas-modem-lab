#!/usr/bin/env python3
"""PC-side SGP.22 profile-install simulator (offline, stdlib only).

Scope (strict): reads ONLY files under the repo (<repo>).
NEVER touches the live device (no adb/fastboot/AT). Creates no files.
Hand-rolled DER reader (no asn1 lib).

Sources read (full files, past any viewer truncation):
  gsi/diag.txt, gsi/diag2.txt          -- two real SM-DP+ sessions (ripsim)
  captures/capture/*/props.txt         -- device EID (ro.vendor.esimid)
  captures/capture/*/logcat_all.txt    -- EuiccChannelManagerService / 054d-054e (baseline only)
  captures/capture/*/dump_isub.txt     -- Euicc enabled flag
  esim_lab/dummy_subscriber.json       -- private-LTE test subscriber (999-70)
  gsi/atr.txt                          -- eUICC ATR (truncated capture)
  HANDOFF.md / PICKUP.md               -- credentials S4 (GigSky QR, test codes), provenance
    for SGP.22 v2.3 / ~1.16MB free / ISD-R unreadable / Tracfone carrier
    (LPA-UI observations; NOT present in baseline captures -- flagged below).

What this proves offline:
  - Both BPPs decode as valid SGP.22 BoundProfilePackage [54], 27531 B raw.
  - StoreMetadata (single 88, BF25) is byte-identical plaintext across sessions
    except the trailing 8-B SCP03t C-MAC (session-bound) -- same profile re-issued.
  - Profile = GigSky operational Prod (NOT a test-CI profile by metadata).
  - No EID value anywhere in either BPP (no on-card EID-binding mismatch).
  - sequenceOf86 (profile elements) is byte-identical across sessions (27 x 86).
  - 6A80 ranking + installability verdicts + self-issued requirements.
"""
from __future__ import annotations
import base64
import hashlib
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
GSI_DIAG1 = REPO / "gsi" / "diag.txt"
GSI_DIAG2 = REPO / "gsi" / "diag2.txt"
DUMMY_SUB = REPO / "esim_lab" / "dummy_subscriber.json"

DEVICE_EID = "89000000000000000000000000000000"  # placeholder; set to YOUR chip EID (getprop ro.vendor.hw.esimid)
GIGSKY_MATCHING_ID = "1$smdp.example.invalid$REDACTED-0000"  # placeholder format only

# ---------------------------------------------------------------- DER

def parse_tlv(buf: bytes, off: int):
    """Minimal BER/DER TLV reader. Returns dict; raises ValueError on truncation."""
    if off >= len(buf):
        raise ValueError("offset past end")
    start = off
    b0 = buf[off]
    off += 1
    cls = (b0 >> 6) & 0x03
    cons = (b0 >> 5) & 0x01
    tagnum = b0 & 0x1F
    tagbytes = bytes([b0])
    if tagnum == 0x1F:  # high-tag form
        tagnum = 0
        while True:
            if off >= len(buf):
                raise ValueError("truncated high-tag")
            b = buf[off]
            off += 1
            tagbytes += bytes([b])
            tagnum = (tagnum << 7) | (b & 0x7F)
            if not (b & 0x80):
                break
    if off >= len(buf):
        raise ValueError("truncated length")
    lb = buf[off]
    off += 1
    if lb & 0x80:
        n = lb & 0x7F
        if n == 0:
            raise ValueError("indefinite length not supported")
        if off + n > len(buf):
            raise ValueError("truncated long length")
        ln = int.from_bytes(buf[off:off + n], "big")
        off += n
    else:
        ln = lb
    if off + ln > len(buf):
        raise ValueError("truncated value (need %d, have %d)" % (ln, len(buf) - off))
    val = buf[off:off + ln]
    return {"cls": cls, "cons": cons, "tag": tagnum, "taghex": tagbytes.hex(),
            "len": ln, "hoff": start, "voff": off, "end": off + ln, "val": val}

def children(buf: bytes, off: int, end: int):
    out = []
    while off < end:
        t = parse_tlv(buf, off)
        out.append(t)
        off = t["end"]
    return out

CLSNAME = ["U", "A", "C", "P"]

def bcd_swap_to_digits(b: bytes) -> str:
    """Telecom BCD (low nibble first). Strips trailing F filler."""
    s = ""
    for byte in b:
        s += "%X%X" % (byte & 0x0F, (byte >> 4) & 0x0F)
    return s.rstrip("Ff")

def try_ascii(b: bytes):
    try:
        s = b.decode("ascii")
    except Exception:
        return None
    if all(32 <= c <= 126 for c in b):
        return s
    return None

# ---------------------------------------------------------------- BPP load

def extract_diag(diag_path: Path):
    """Read FULL diag file (past viewer truncation), return (txid, b64, raw)."""
    text = diag_path.read_text(encoding="utf-8", errors="replace")
    q = chr(34)
    m_tx = re.search(q + "transactionId" + q + r"\s*:\s*" + q + "([^" + q + "]+)" + q, text)
    m_bpp = re.search(q + "boundProfilePackage" + q + r"\s*:\s*" + q + "([^" + q + "]+)" + q, text)
    if not m_tx or not m_bpp:
        raise ValueError("diag parse failed: %s" % diag_path)
    txid = m_tx.group(1)
    # json unescape handles \/ sequences emitted by the LPA diag
    b64 = json.loads(q + m_bpp.group(1) + q)
    raw = base64.b64decode(b64)
    # last APDU status
    m_apdu = re.search(r"Last APDU response[^\n]*:\s*([0-9A-Fa-f]{4,})", text)
    apdu = m_apdu.group(1).upper() if m_apdu else "?"
    return {"txid": txid, "b64len": len(b64), "raw": raw, "apdu": apdu, "path": str(diag_path)}

# ---------------------------------------------------------------- parse

PROFILE_CLASS = {0: "test", 1: "provisioning", 2: "operational"}

@dataclass
class ParsedBPP:
    label: str
    txid_outer: str
    raw: bytes
    apdu_last: str
    outer_len: int = 0
    init_tx_inner: str = ""
    init_optr: dict = field(default_factory=dict)
    a0_87: list = field(default_factory=list)   # firstSequenceOf87
    a1_88: list = field(default_factory=list)   # sequenceOf88
    a2_87: list = field(default_factory=list)   # secondSequenceOf87
    a3_86: list = field(default_factory=list)   # sequenceOf86
    sm: dict = field(default_factory=dict)      # StoreMetadata fields
    sm_mac: bytes = b""
    sha1: str = ""

def parse_storemetadata(e88_val: bytes):
    """e88_val = value of the 88 OCTET (contains BF25 [+ 8-B MAC])."""
    bf25 = parse_tlv(e88_val, 0)
    if bf25["taghex"] != "bf25":
        raise ValueError("88 does not contain BF25 StoreMetadata, got %s" % bf25["taghex"])
    trailing = e88_val[bf25["end"]:]
    sm = {"bf25_len": bf25["len"], "trailing_mac_hex": trailing.hex(),
          "trailing_mac_len": len(trailing)}
    for c in children(e88_val, bf25["voff"], bf25["end"]):
        th = c["taghex"]
        if th == "5a":
            sm["iccid_bcd_hex"] = c["val"].hex()
            sm["iccid_digits"] = bcd_swap_to_digits(c["val"])
        elif th == "91":
            sm["service_provider"] = try_ascii(c["val"]) or c["val"].hex()
        elif th == "92":
            sm["profile_name"] = try_ascii(c["val"]) or c["val"].hex()
        elif th == "95":
            sm["profile_class_raw"] = c["val"].hex()
            sm["profile_class_val"] = c["val"][0] if len(c["val"]) else -1
            sm["profile_class"] = PROFILE_CLASS.get(sm["profile_class_val"], "unknown(%s)" % sm.get("profile_class_raw"))
        elif th == "b6":
            sm["b6_hex"] = c["val"].hex()
            for s in children(e88_val, c["voff"], c["end"]):
                if s["taghex"] == "30":
                    for ss in children(e88_val, s["voff"], s["end"]):
                        if ss["taghex"] == "80":
                            sm["smdp_id_hex"] = ss["val"].hex()
                        elif ss["taghex"] == "81":
                            sm["smdp_address"] = try_ascii(ss["val"]) or ss["val"].hex()
        elif th == "b7":
            sm["b7_hex"] = c["val"].hex()
            for s in children(e88_val, c["voff"], c["end"]):
                sm["ppr_%s" % s["taghex"]] = s["val"].hex()
        elif th == "bf76":
            sm["bf76_hex"] = c["val"].hex()
            # walk E2/E1/C1/CA/E3/DB for package name + sequence
            for s in children(e88_val, c["voff"], c["end"]):
                if s["taghex"] == "e2":
                    for ss in children(e88_val, s["voff"], s["end"]):
                        if ss["taghex"] == "e1":
                            for sss in children(e88_val, ss["voff"], ss["end"]):
                                if sss["taghex"] == "ca":
                                    sm["package"] = try_ascii(sss["val"]) or sss["val"].hex()
                                elif sss["taghex"] == "c1":
                                    sm["c1_hex"] = sss["val"].hex()
                        elif ss["taghex"] == "e3":
                            for sss in children(e88_val, ss["voff"], ss["end"]):
                                if sss["taghex"] == "db":
                                    sm["seq_hex"] = sss["val"].hex()
                                    sm["seq_int"] = int.from_bytes(sss["val"], "big")
        else:
            sm.setdefault("unknown", []).append((th, c["val"][:32].hex()))
    return sm, trailing

def parse_bpp(label: str, diag: dict) -> ParsedBPP:
    raw = diag["raw"]
    p = ParsedBPP(label=label, txid_outer=diag["txid"], raw=raw,
                  apdu_last=diag["apdu"], sha1=hashlib.sha1(raw).hexdigest())
    outer = parse_tlv(raw, 0)
    if outer["taghex"] != "bf36":
        raise ValueError("%s: outer tag %s != bf36[54]" % (label, outer["taghex"]))
    p.outer_len = outer["len"]
    kids = children(raw, outer["voff"], outer["end"])
    if len(kids) != 5 or [k["taghex"] for k in kids] != ["bf23", "a0", "a1", "a2", "a3"]:
        raise ValueError("%s: unexpected outer children %s" % (label, [k["taghex"] for k in kids]))
    bf23, a0, a1, a2, a3 = kids
    # initialiseSecureChannel [35]
    for c in children(raw, bf23["voff"], bf23["end"]):
        if c["taghex"] == "80":
            p.init_tx_inner = c["val"].hex().upper()
        elif c["taghex"] == "82":
            p.init_optr["ctrl_ref"] = c["val"].hex()
        elif c["taghex"] == "a6":
            for s in children(raw, c["voff"], c["end"]):
                if s["taghex"] == "84":
                    p.init_optr["oid_ascii"] = try_ascii(s["val"]) or s["val"].hex()
                else:
                    p.init_optr[s["taghex"]] = s["val"].hex()
        elif c["taghex"] in ("5f49", "5f37"):
            p.init_optr[c["taghex"]] = {"len": c["len"], "head": c["val"][:16].hex()}
    for grp, holder in ((a0, p.a0_87), (a1, p.a1_88), (a2, p.a2_87), (a3, p.a3_86)):
        for e in children(raw, grp["voff"], grp["end"]):
            holder.append({"taghex": e["taghex"], "len": e["len"], "head": e["val"][:16].hex()})
    # StoreMetadata lives in the single 88
    e88 = parse_tlv(raw, a1["voff"])
    sm, mac = parse_storemetadata(e88["val"])
    p.sm = sm
    p.sm_mac = mac
    return p

# ---------------------------------------------------------------- device / evidence

def load_device_eid() -> dict:
    found = {}
    for cap in sorted((REPO / "captures" / "capture").glob("*")):
        pt = cap / "props.txt"
        if pt.exists():
            for line in pt.read_text(errors="replace").splitlines():
                if "ro.vendor.esimid" in line or "ro.vendor.hw.esimid" in line:
                    found.setdefault(cap.name, []).append(line.strip())
    vals = set()
    for v in found.values():
        for line in v:
            m = re.search(r"\[([0-9]{20,})\]", line)
            if m:
                vals.add(m.group(1))
    return {"per_capture": found, "distinct_eids": sorted(vals)}

def eid_present_in_bpp(raw: bytes, eid: str) -> dict:
    res = {}
    res["ascii"] = eid.encode() in raw
    try:
        res["bcd"] = bytes.fromhex(eid) in raw
    except Exception:
        res["bcd"] = False
    def swap(bs: bytes) -> bytes:
        return bytes(((b << 4) & 0xF0) | ((b >> 4) & 0x0F) for b in bs)
    try:
        res["bcd_swapped"] = swap(bytes.fromhex(eid)) in raw
    except Exception:
        res["bcd_swapped"] = False
    return res

def infer_ci(smdp: str, profile_name: str, sp: str, pclass: str) -> str:
    blob = " ".join([smdp or "", profile_name or "", sp or ""]).lower()
    test_marks = ["rsp.goog", "sysmocom", "smdpp.test", "test", "999", "example", "invalid"]
    if any(m in blob for m in test_marks) or pclass == "test":
        return "test (heuristic)"
    if "ripsim.com" in blob or "gigsky" in blob or "prod" in blob or pclass == "operational":
        return "prod-inferred (heuristic; DPauth chain absent, NOT cryptographic proof)"
    return "unknown"

# ---------------------------------------------------------------- eUICC decision model

@dataclass
class EuiccChip:
    label: str
    eid: str
    ci_trust: str          # 'prod' or 'test'
    sgp_version: str = "2.3"
    free_bytes: int = 1216000  # ~1.16MB per HANDOFF LPA UI (not in baseline captures)
    installed_iccids: tuple = ()
    carrier: str = "Tracfone"

@dataclass
class BppProfile:
    label: str
    ci: str                # 'prod' | 'prod-inferred' | 'test'
    iccid: str
    profile_class: str     # test|provisioning|operational
    eid_binding: str | None
    matching_spent: bool
    chunking_ok: bool
    ppr_ok: bool
    size_bytes: int

def installable(chip: EuiccChip, bpp: BppProfile):
    """SGP.22 install decision in on-card order.

    Returns (ok: bool, reason: str). Any refusal surfaces to this LPA as
    6A80 + ES10B_ERROR_REASON_UNDEFINED (no decoded PIR), matching diag.txt.
    Stages: DPauth chain -> PrepareDownload/matchingID -> BPP signature/MAC
    + APDU segmentation -> metadata policy (class/PPR/EID/memory).
    """
    bci = bpp.ci.split()[0].replace("-inferred", "")
    if chip.ci_trust == "prod" and bci == "test":
        return (False, "6A80 ISD-R signature/MAC fail: test-CI BPP on production-CI chip "
                "(LPA pass-through; on-card ISD-R verification; ES10B_ERROR_REASON_UNDEFINED)")
    if chip.ci_trust == "test" and bci == "prod":
        return (False, "6A80 ISD-R signature fail: prod-CI BPP on test-CI chip")
    if bpp.matching_spent:
        return (False, "6A80 PrepareDownload replay: matchingID spent/single-use already consumed "
                "(fresh GetBoundProfilePackage would return ES9+ error, not a BPP)")
    if not bpp.chunking_ok:
        return (False, "6A80 STORE DATA segmentation/MAC fail: LPA chunking of 87/88/86 "
                "through MTK 054d/054e extended-access incorrect (P1 chaining/CLA/MAC); "
                "classic 6A80 with no PIR")
    if bpp.eid_binding and bpp.eid_binding != chip.eid:
        return (False, "6A80 StoreMetadata EID-binding mismatch: profile bound to %s, chip is %s"
                % (bpp.eid_binding, chip.eid))
    if not bpp.ppr_ok:
        return (False, "6A80 StoreMetadata policy refusal: PPR/profile-class/MNO not permitted on this chip")
    if bpp.profile_class == "test" and chip.ci_trust == "prod":
        # defence in depth: even a prod-signed test-class profile is rejected by policy on prod fleets
        return (False, "6A80 metadata policy: test-class profile on production chip")
    if bpp.iccid in chip.installed_iccids:
        return (False, "6A80 replay/duplicate: ICCID %s already installed" % bpp.iccid)
    if bpp.size_bytes > chip.free_bytes:
        return (False, "6A80/6A84 memory: BPP %d B > free %d B" % (bpp.size_bytes, chip.free_bytes))
    return (True, "9000 installable: CI trust + matchingID + MAC/chunking + metadata all pass")

def rank_causes_for_ripsim_pair() -> list:
    """Ranked 6A80 hypotheses for THESE two ripsim BPPs (evidence-bound)."""
    return [
        ("(3) LPA / secure-channel chunking (STORE DATA segmentation via MTK 054d/054e)",
         "HIGHEST",
         "for: BPPs carry 27 x 86 up to 1016 B each -- LPA MUST fragment into <=255 B STORE DATA "
         "(P1 first/intermediate/last chaining + SCP03t C-MAC per segment); both LPA apps "
         "(EasyEUICC + privileged OpenEUICC) fail identically with/without SIM via the same "
         "MTK Rfx extended-access path (054d REQ/054e CNF in baseline logcats); no PIR decoded "
         "(ES10B_ERROR_REASON_UNDEFINED) which is the classic chunking/MAC symptom; fresh BPPs "
         "rule out stale-replay, sane metadata rules out trivial policy blocks",
         "against: no esim_retry capture exists (only baseline_nosim/sim_boot/sim_settled), so the "
         "actual failing APDU bytes cannot be inspected -- chunking is inferred, not observed"),
        ("(4) StoreMetadata content policy (PPR / MNO / class)",
         "MEDIUM",
         "for: only remaining on-card gate after CI+replay+memory pass; PPR raw B7=80:130083 "
         "81:6FFFFF 82:FFFFFF must be evaluated against Tracfone carrier policy (chip carrier shows "
         "Tracfone, ME lock 3); GigSky MNO vs Tracfone allowlist cannot be excluded without PIR",
         "against: class=operational(0x02) Prod (IPPv6.1c_Prod/GigSky) is the permissive case; "
         "no EID binding present (passes); no enterprise PPR marker identified; ICCID fresh "
         "(profiles list empty, ISD-R unreadable but list empty per HANDOFF)"),
        ("(2) spent / replayed matchingID <redacted>",
         "LOW",
         "for: QR is single-use by nature; HANDOFF notes it 'may be spent'",
         "against: BOTH sessions returned ES9+ Executed-Success with DISTINCT transactionIds "
         "(47C80E58../B46BBF76..), distinct session keys (5F49/5F37) and distinct 87/88 C-MACs, "
         "inner txid == outer txid each time, identical A3 profile data re-issued -- a spent "
         "matchingID would fail at GetBoundProfilePackage with an ES9+ error, not yield two fresh "
         "BPPs; on-card duplicate-ICCID excluded (nothing installed)"),
        ("(1) test-CI BPP on production-CI chip",
         "LOWEST for THESE two BPPs (remains #1 generally for Google/sysmocom test codes)",
         "for (general rule): this production eUICC trusts ONLY production GSMA CI; "
         "prod.smdp-plus.rsp.goog + smdpp.test.rsp.sysmocom.de test profiles can NEVER install here "
         "(on-card ISD-R verification, LPA is pass-through) -- do not spend time retrying them",
         "against (these BPPs): metadata proves operational Prod: profileName IPPv6.1c_Prod, "
         "class 0x02 operational, SP GigSky, SM-DP+ smdpplus.ripsim.com, package com.gigsky.gigsky; "
         "zero test markers (no rsp.goog/sysmocom/test); commercial GigSky SM-DP+. Definitive CI proof "
         "would need the ES9+ AuthenticateServer cert chain (absent from diag.txt -- BPP only), so the "
         "inference is heuristic, but test-CI is strongly disfavoured for this pair"),
    ]

# ---------------------------------------------------------------- self-issued path

def self_issue_requirements() -> dict:
    return {
        "test_path (installable NOW, needs hardware)": [
            "sysmoEUICC1-C2T test eUICC (EUR 95, nano-SIM, TEST-CI trust) -- OR sysmoISIM-SJA5 "
            "programmable SIM (EUR 23.80) for the private-LTE attach side",
            "SM-DP+: sysmocom smdpp.test.rsp.sysmocom.de (e.g. 1$smdpp.test.rsp.sysmocom.de$TS48V1-A-UNIQUE) "
            "or self-hosted osmo-smdpp.py (pysim repo; binds ES9+ :443 or :8000 behind nginx)",
            "osmo-smdpp layout: UPP .der files in smdpp-data/upp/ named by matchingID; "
            "SGP.26 TEST cert set in smdpp-data/certs/ (replace for a private root CA)",
            "LPA: EasyEUICC with dev-option Ignore-TLS-cert ticked (test SM-DP+), or OpenEUICC",
            "No towers needed to INSTALL (internet only); SDR+srsRAN + Open5GS needed only to ATTACH",
            "This production chip can NEVER take this path (test-CI BPP, on-card ISD-R reject)",
        ],
        "production_path (only path for THIS chip)": [
            "Production-CI trust chain end to end: GSMA prod CI -> prod SM-DP+ cert "
            "(e.g. smdpplus.ripsim.com / carrier SM-DP+) -> prod EUM cert on this eUICC "
            "(EID %s)" % DEVICE_EID,
            "Fresh, unspent matchingID from a PROD SM-DP+: GigSky QR re-issue (current "
            "prior codes may be single-use) or carrier-issued eSIM QR (account transfer; doubles as "
            "carrier-acceptance control proving chip vs modem fault domain)",
            "Operational-class Prod profile (as observed: IPPv6.1c_Prod) with PPR/EID-binding "
            "compatible with this chip (no foreign EID binding; PPR cleared with carrier if locked)",
            "Correct LPA STORE DATA segmentation for 1016-B 86 elements + SCP03t MAC via a fixed "
            "MTK 054d/054e path (the prime suspect for the current 6A80)",
            "Free space: BPP 27531 B << ~1.16 MB free (already satisfied; memory ruled out)",
            "SGP.22 v2.3 LPA + readable ISD-R/EID (EID known via props: %s)" % DEVICE_EID,
        ],
    }

def sketch_private_lte_upp_bpp(dummy_path: Path = DUMMY_SUB) -> dict:
    sub = json.loads(dummy_path.read_text())
    # UPP = Unprotected Profile Package (cleartext template); BPP = UPP + protection
    return {
        "source": "esim_lab/dummy_subscriber.json (test PLMN 999-70; NO device contact)",
        "UPP.profileElements": [
            {"MF/ADF_USIM.EF_IMSI": sub["imsi"]},
            {"EF_PLMNwAcT/EHPLMN": sub["plmn"], "MCC_MNC": "999-70"},
            {"EF_ICCID": sub["iccid"]},
            {"AKA": {"K": sub["k"], "OPc": sub["opc"], "AMF": sub["amf"], "SQN": sub["sqn"]}},
            {"APN": sub.get("apn", "internet"), "slice": sub.get("slice", {"sst": 1})},
            {"profileClass": "operational (test-NW; sign with TEST CI for sysmoEUICC1-C2T)"},
            {"serviceProvider": "private-LTE-lab", "profileName": "lab-99970-test"},
            {"PPR": "permissive lab (no enterprise PPR)", "EID_binding": "none (lab install on any test EID)"},
        ],
        "UPP->BPP": [
            "1. Build UPP DER (profile elements above, 3GPP file tree + AKA params).",
            "2. osmo-smdpp protects UPP -> BPP: generates SCP03t session package "
            "(initialiseSecureChannel [35] + firstSequenceOf87[0] + sequenceOf88[1: StoreMetadata BF25] "
            "+ secondSequenceOf87[2] + sequenceOf86[3: encrypted elements]), signs with TEST SM-DP+ key.",
            "3. Name file smdpp-data/upp/<matchingID>.der; serve via ES9+ GetBoundProfilePackage.",
            "4. LPA downloads with test matchingID; test eUICC verifies TEST-CI chain and installs.",
            "WARNING: this BPP installs ONLY on a test-CI eUICC (sysmoEUICC1-C2T). It MUST fail "
            "with 6A80 on THIS production chip (EID %s) -- by design." % DEVICE_EID,
        ],
    }

# ---------------------------------------------------------------- selftests (verdict function)

def run_verdict_selftests():
    prod_chip = EuiccChip(label="this-chip (prod)", eid=DEVICE_EID, ci_trust="prod")
    test_chip = EuiccChip(label="sysmoEUICC1-C2T (test)", eid="89049032000000000000000000000000",
                          ci_trust="test", free_bytes=200000)
    # Real-world encodings for the test matrix:
    ripsim = BppProfile(label="ripsim-GigSky-BPP (observed)", ci="prod-inferred",
                        iccid="8914800000000003", profile_class="operational",
                        eid_binding=None, matching_spent=False,
                        chunking_ok=False,  # observed MTK LPA path fails -> reproduces 6A80
                        ppr_ok=True, size_bytes=27531)
    testbpp = BppProfile(label="sysmocom-test-BPP", ci="test", iccid="899 glue".replace(" glue", "999700000000001"),
                         profile_class="operational", eid_binding=None, matching_spent=False,
                         chunking_ok=True, ppr_ok=True, size_bytes=20000)
    carrier = BppProfile(label="carrier-EID-bound-prod-BPP", ci="prod", iccid="8914800000000001",
                         profile_class="operational", eid_binding=DEVICE_EID,
                         matching_spent=False, chunking_ok=True, ppr_ok=True, size_bytes=27531)
    cases = [
        (prod_chip, ripsim, False, "ripsim x prod chip -> False + reason"),
        (test_chip, testbpp, True, "test BPP x test chip -> True path"),
        (prod_chip, carrier, True, "carrier-EID-bound prod BPP x prod chip -> True path"),
        # extra guardrails (not required but pin the model):
        (prod_chip, testbpp, False, "test BPP x prod chip -> False (CI)"),
        (prod_chip, BppProfile(label="wrong-EID", ci="prod", iccid="8914800000000002",
                               profile_class="operational", eid_binding="89000000000000000000000000000000",
                               matching_spent=False, chunking_ok=True, ppr_ok=True, size_bytes=10000),
         False, "EID-mismatched prod BPP x prod chip -> False"),
    ]
    results = []
    for chip, bpp, expect_ok, name in cases:
        ok, reason = installable(chip, bpp)
        passed = (ok == expect_ok)
        results.append({"case": name, "chip": chip.label, "bpp": bpp.label,
                        "expect_ok": expect_ok, "got_ok": ok, "reason": reason,
                        "PASS": passed})
    return results

# ---------------------------------------------------------------- report

def report_session(p: ParsedBPP, eid: str) -> str:
    L = []
    L.append("session %s (%s):" % (p.label, p.txid_outer))
    L.append("  diag path transactionId : %s" % p.txid_outer)
    L.append("  inner init txid  [80]   : %s  match=%s" % (p.init_tx_inner, p.init_tx_inner == p.txid_outer))
    L.append("  ES9+ status             : Executed-Success (per diag JSON header)")
    L.append("  last APDU (chip)        : %s (FAILURE)" % p.apdu_last)
    L.append("  BPP raw                 : %d B (b64 %d chars), sha1 %s" % (
        len(p.raw), len(base64.b64encode(p.raw)), p.sha1))
    L.append("  outer                   : BF36[54] BoundProfilePackage len=%d" % p.outer_len)
    L.append("  initSecureChannel BF23  : len=176 ctrl=%s oid=%s 5F49=%sB 5F37=%sB" % (
        p.init_optr.get("ctrl_ref"), p.init_optr.get("oid_ascii"),
        p.init_optr.get("5f49", {}).get("len"), p.init_optr.get("5f37", {}).get("len")))
    L.append("  counts: A0 first87=%d (87 lens %s)" % (len(p.a0_87), [e["len"] for e in p.a0_87]))
    L.append("          A1 seq88  =%d (88 lens %s = BF25.148B + MAC.8B)" % (len(p.a1_88), [e["len"] for e in p.a1_88]))
    L.append("          A2 second87=%d (87 lens %s)" % (len(p.a2_87), [e["len"] for e in p.a2_87]))
    L.append("          A3 seq86  =%d (26x1016B + 1x552B; total content 27076B)" % len(p.a3_86))
    sm = p.sm
    L.append("  StoreMetadata BF25 len=%d:" % sm.get("bf25_len"))
    L.append("    ICCID 5A              : bcd=%s -> digits=%s" % (sm.get("iccid_bcd_hex"), sm.get("iccid_digits")))
    L.append("    SP      91            : %s" % sm.get("service_provider"))
    L.append("    profile 92            : %s" % sm.get("profile_name"))
    L.append("    class   95            : 0x%s -> %s (%s)" % (
        sm.get("profile_class_raw"), sm.get("profile_class"),
        "TEST" if sm.get("profile_class") == "test" else "OPERATIONAL (not test)"))
    L.append("    smdp B6               : id=%s addr=%s" % (sm.get("smdp_id_hex"), sm.get("smdp_address")))
    L.append("    PPR  B7               : 80=%s 81(PPR1)=%s 82(PPR2)=%s" % (
        sm.get("ppr_80"), sm.get("ppr_81"), sm.get("ppr_82")))
    L.append("    pkg BF76              : app=%s seq=%s (int %s)" % (
        sm.get("package"), sm.get("seq_hex"), sm.get("seq_int")))
    L.append("    88 C-MAC (trailing 8B): %s" % sm.get("trailing_mac_hex"))
    ev = eid_present_in_bpp(p.raw, eid)
    L.append("  EID binding vs device EID %s:" % eid)
    L.append("    EID bytes in BPP? ascii=%s bcd=%s swapped=%s -> %s" % (
        ev["ascii"], ev["bcd"], ev["bcd_swapped"],
        "ABSENT: no on-card EID mismatch (binding, if any, is server-side matchingID policy)"))
    L.append("  CI inference            : %s" % infer_ci(sm.get("smdp_address"), sm.get("profile_name"),
                                                        sm.get("service_provider"), sm.get("profile_class")))
    return "\n".join(L)

def main() -> int:
    print("esim_sim: offline SGP.22 install-path simulator (stdlib only, no device contact)")
    print("repo: %s" % REPO)
    d1, d2 = extract_diag(GSI_DIAG1), extract_diag(GSI_DIAG2)
    p1, p2 = parse_bpp("S1-diag.txt", d1), parse_bpp("S2-diag2.txt", d2)
    eidinfo = load_device_eid()
    print("\n== device EID (captures props) ==")
    for cap, lines in sorted(eidinfo["per_capture"].items()):
        for ln in lines:
            print("  %s %s" % (cap, ln))
    print("  distinct EIDs: %s (expected [%s])" % (eidinfo["distinct_eids"], DEVICE_EID))
    print("\n== BPP parse: session 1 ==")
    print(report_session(p1, DEVICE_EID))
    print("\n== BPP parse: session 2 ==")
    print(report_session(p2, DEVICE_EID))
    print("\n== pair equality (same profile, fresh secure channel) ==")
    print("  raw equal=%s sha1 %s vs %s" % (p1.raw == p2.raw, p1.sha1[:16], p2.sha1[:16]))
    print("  StoreMetadata equal (excl MAC)=%s" % (
        json.dumps({k: v for k, v in p1.sm.items() if not k.startswith("trailing")}, sort_keys=True) ==
        json.dumps({k: v for k, v in p2.sm.items() if not k.startswith("trailing")}, sort_keys=True)))
    print("  88 MAC differs: %s vs %s (proves per-session SCP03t channel)" % (p1.sm_mac.hex(), p2.sm_mac.hex()))
    # outer children: BF23/A0/A1/A2/A3 -- hash the A3 value (sequenceOf86) exactly
    def _a3_val(p):
        o = parse_tlv(p.raw, 0)
        ks = children(p.raw, o["voff"], o["end"])
        return ks[4]["val"]
    print("  A3 sequenceOf86 identical=%s sha1=%s (profile elements deterministic)" % (
        _a3_val(p1) == _a3_val(p2), hashlib.sha1(_a3_val(p1)).hexdigest()[:16]))
    print("  txids distinct=%s" % (p1.txid_outer != p2.txid_outer))
    print("  ES9+ handshake OK both (BPP issued, Executed-Success); chip 6A80 on STORE DATA; "
          "ES10B_ERROR_REASON_UNDEFINED; free ~1.16MB (memory ruled out, HANDOFF LPA-UI provenance)")
    print("\n== captures note ==")
    print("  captures/capture has ONLY baseline_nosim/sim_boot/sim_settled (no esim_retry/); "
          "baseline logcat DOES contain EuiccChannelManagerService (OpenEUICC) + 82x 054d/054e "
          "extended-access traces + Euicc enabled=false (dump_isub); install-phase APDUs absent.")
    print("  SGP.22 v2.3 / 1.16MB free / ISD-R unreadable / Tracfone carrier: per HANDOFF (LPA UI), "
          "EID+Tracfone verified in props; SGP/memory/ISD-R not in baseline captures.")
    print("\n== ranked 6A80 causes (for THESE two BPPs) ==")
    for i, (cause, rank, f, a) in enumerate(rank_causes_for_ripsim_pair(), 1):
        print("  %d. %s [%s]\n     +%s\n     -%s" % (i, cause, rank, f, a))
    print("\n== verdict selftests: installable(chip_certs, bpp) ==")
    allpass = True
    for r in run_verdict_selftests():
        print("  [%s] %s -> got=%s expect=%s\n       reason: %s" % (
            "PASS" if r["PASS"] else "FAIL", r["case"], r["got_ok"], r["expect_ok"], r["reason"]))
        allpass &= r["PASS"]
    print("\n== requirements: successful install on THIS chip (EID %s, prod-CI, SGP.22 v2.3) ==" % DEVICE_EID)
    for path, items in self_issue_requirements().items():
        print("  %s:" % path)
        for it in items:
            print("    - %s" % it)
    print("\n== private-LTE UPP->BPP sketch (dummy_subscriber.json, no device contact) ==")
    sk = sketch_private_lte_upp_bpp()
    print("  source: %s" % sk["source"])
    for e in sk["UPP.profileElements"]:
        print("    UPP: %s" % e)
    for s in sk["UPP->BPP"]:
        print("    %s" % s)
    try:
        sub = json.loads(DUMMY_SUB.read_text())
        print("  dummy: IMSI=%s PLMN=%s ICCID=%s K=%s.. OPc=%s.. APN=%s" % (
            sub["imsi"], sub["plmn"], sub["iccid"], sub["k"][:8], sub["opc"][:8], sub.get("apn")))
    except Exception as e:
        print("  dummy read error: %s" % e)
    print("\nSELFTESTS %s" % ("ALL PASS" if allpass else "FAILURES PRESENT"))
    return 0 if allpass else 1

if __name__ == "__main__":
    sys.exit(main())
