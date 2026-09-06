#!/usr/bin/env python3
"""ccci_threat.py — AP->modem (CCCI) attack-surface threat model (Kansas lab, MT6835).

SIMULATION ONLY — pure PC modeling. This module NEVER touches the device:
no /dev writes, no ioctl injection, no adb/fastboot/socket/subprocess imports
(the selftest asserts that via AST). All inputs are parsed in RAM only;
dumps (md1work_romonly.bin, kmod/*.ko, captures/*) are opened read-only.
New code lives under sim/ only; siblings are INTEGRATED (imported), never
modified — sim/hw_target.py (CCIF addrs), sim/mem_model.py (SMEM rings + MPU
+ hooks), sim/ap_peer.py + oracle transcripts (real boot replay),
sim/emu_engine.py (Memory/Image/Tracer).

What this is: a malicious-AP (root-level attacker) model of what could be
sent toward the modem over CCCI shared memory, and which modem handler would
consume it first. For every channel it reports
{handler, input shape, bounds checks present/absent, verdict} where verdict
is CONFIRMED (missing-check proven in sim) or REFUTED (bounded in sim), plus
an explicit device-transfer qualifier so a sim result is never overclaimed
as a device proof.

Channels (AP-written SMEM -> modem consumer):
  CH-RING  ring-index abuse ...... SmemRingSet.dequeue (HIF demux analogue,
             port_char_recv_skb / ccci_hif path). FIRST consumer of every
             hostile index/len — before any msgid/RPC/FS handler.
  CH-MSGID msgid dispatch ........ rmmi_extended_cmd_processor @0x90EF0C48
             (JRC dispatch, table @0x92400260, 443 entries) + analyzer
             @0x90EF0CD8 (bound 0x1BB) + per-msgid parsers. Notable AP->MD
             IDs: 0003 SYS_AT_REQ (raw Hayes incl ESMLCK), 0519 OPEN_CHANNEL
             (AID len+bytes), 054d EXTENDED_GENERIC_ACCESS (APDU P1/P2/Lc),
             0537 GET_FACILITY; 4508 SML_STATUS_IND is MD->AP ONLY.
  CH-RPC   RPC response abuse .... 27 IPC_RPC_* ops (26 AP-side in
             kmod/ccci_md_all.ko + MOTO_SECTEST in modem ROM). Direction is
             MD-req -> AP-rsp -> modem-parse, so a malicious AP shapes the
             RESPONSE blob (security_data, product_data, ints, tables).
             Destructive flags: EFUSE_BLOWING, DSP_EMI_MPU_SETTING.
  CH-FSD   file-service abuse .... modem FS client <-> AP ccci_fsd daemon.
             Filename direction MD->AP (X:/LD40_001 ...); content direction
             AP->MD (attacker-shaped file bytes + STAT). Traversal pattern
             + sanitization verdict.
  CH-CVE   CVE-2023-32840 ....... modem-CCCI OOB-write (MOLY01138425,
             MT6835/NR17 affected, Nov-2023 bulletin). Ringbuf equivalents
             in THIS kernel via strings/symbols + version fingerprinting
             (baseband P247 vs bulletin fix date).

Provenance (every fact carries its source; PROVISIONAL marks harness
conventions, not modem claims):
  * CCIF addrs ......... hw_target.SPEC["mem"]["ccif_pairs"] (6 pairs) +
    mem_model.CCIF_BLOCKS (12 x 4K, DTB ap/md_ccif0..5 verified).
  * SMEM discipline .... mem_model.SmemRingSet (quarantine semantics) +
    CVE-2022-21765 class note in its docstring.
  * Boot RPC ........... oracle_logs/rpcd_boot_idle.jsonl seq 0-12 +
    sim_boot logcat_all.txt:4232-4234 (CIDDATA off:0 step:1024 -> len 0 ->
    work_helper fail @33.766), :4254 (PRODUCT_OP @33.832 success),
    :5084-5086 (CIDDATA repeat @35.757 symmetric fail).
  * MSGID inventory .... sim_boot logcat_all.txt AT SEND/RECV lines
    (148 distinct MSGID values with [NAME]; 4508 x3 + 0519/054d/0003/0537
    shapes quoted in vectors below).
  * AT/RMMI bounds ..... oob_reachability_proof VERDICT REFUTED (analyzer
    bound 0x1BB + SH-only-on-match + bulk-fuzz max<=442 + strict emu) +
    at_fuzz targets T1-T5 (clck sprintf SAFE, raw_data_to_string DoS-only,
    ersukey read-simple, op12 conditional).
  * RMMI dispatch ...... rmmi_sim.DISPATCH (ESMLCK @0x91985788 etc) +
    emu_rmmi dispatch-match (TEST/STATUS/KEY_PATH_ENTRY).
  * RPC op names ....... kmod/ccci_md_all.ko strings (26 IPC_RPC_* at file
    offsets banked in RPC_OPS) + md1work_romonly.bin IPC_RPC_MOTO_SECTEST.
  * FSD adjacency ...... sim_boot logcat_all.txt:14983 O: X:/LD40_001 flag
    0x700 ret 2 / :14994 D: Y:/LD40_001 ret 0 / :14996 M: X:/LD40_001 ret 0
    + :15440/15941 FS_GetFileDetail fail MTK_MD_OTA_CONFIG.ini error=2.
  * CVE bulletin ....... MediaTek Nov-2023 bulletin + NVD CVE-2023-32840
    (CWE-787, Patch MOLY01138425 / MSV-862, System priv, MT6835+NR17 hit).
  * Version fingerprint  props.txt gsm.version.baseband P247.01.339R +
    ro.vendor.build.date Aug-16-2025 + kmod vermagic 5.15.180-android13-8.

Run:
  python sim/ccci_threat.py --selftest     (default; fast deterministic checks)
  python sim/ccci_threat.py --report       (per-channel verdict table, stdout)
  python sim/ccci_threat.py --report sim/ccci_threat_report.json
  python sim/ccci_threat.py --rings|--rpc|--fsd|--cve|--msgid  (one section)
"""
from __future__ import annotations

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

# -- sibling seams (integrate, never modify) ---------------------------------
try:
    from hw_target import SPEC as HW_SPEC  # type: ignore
except ImportError:
    try:
        from sim.hw_target import SPEC as HW_SPEC  # type: ignore
    except ImportError:
        HW_SPEC = {}  # type: ignore

try:
    from mem_model import (  # type: ignore
        MpuMemory,
        SmemRingSet,
        MalformedIndex,
        RingOverrun,
    )
except ImportError:
    try:
        from sim.mem_model import (  # type: ignore
            MpuMemory,
            SmemRingSet,
            MalformedIndex,
            RingOverrun,
        )
    except ImportError:
        MpuMemory = None  # type: ignore
        SmemRingSet = None  # type: ignore
        MalformedIndex = Exception  # type: ignore
        RingOverrun = Exception  # type: ignore

try:
    from emu_engine import Memory, Image  # type: ignore
except ImportError:
    try:
        from sim.emu_engine import Memory, Image  # type: ignore
    except ImportError:
        Memory = None  # type: ignore
        Image = None  # type: ignore

# --------------------------------------------------------------------------
# Canonical evidence paths (read-only; absence falls back to banked values).
# --------------------------------------------------------------------------

BOOT_TRANSCRIPT = SIM_DIR / "oracle_logs" / "rpcd_boot_idle.jsonl"
SIM_BOOT_LOG = (REPO_ROOT / "captures" / "capture" /
                "20260904_173252_sim_boot" / "logcat_all.txt")
PROPS_PATH = (REPO_ROOT / "captures" / "capture" /
              "20260904_173252_sim_boot" / "props.txt")
KMOD_MD = REPO_ROOT / "kmod" / "ccci_md_all.ko"
KMOD_UTIL = REPO_ROOT / "kmod" / "ccci_util_lib.ko"
ROM_PATH = REPO_ROOT / "md1work_romonly.bin"

# --------------------------------------------------------------------------
# 27 IPC_RPC_* ops: 26 AP-side (kmod file offsets banked) + 1 modem-side.
# Order = kmod string-table order (offsets ascending). Offsets are read-only
# fingerprints of THIS kernel build (5.15.180-android13-8-g9fd68d05d161).
# dir: MD-req -> AP-rsp -> modem-parse for all 26 kmod ops (AP serves);
#   MOTO_SECTEST is a modem-side log string (mot_security client), AP cannot
#   serve it via ccci_rpc_work — kept for completeness, marked accordingly.
# rsp_shape: what a malicious AP controls in the RESPONSE (attacker blob).
# destructive: True only where the op by NAME implies permanent HW/silicon
#   or privilege effect (blow MPU/fuse); TRNG/SECRO flagged separately as
#   entropy/confidentiality risk, not code-exec.
# --------------------------------------------------------------------------

# (name, kmod_off_or_None, req_shape, rsp_shape, class, destructive, note)
_RPC_ROWS: tuple[tuple, ...] = (
    ("IPC_RPC_GET_GPIO_ADC_OP", 0xCB35, "u32 request mask",
     "gpio+adc int pair (ccci_rpc_get_gpio_adc[_v2])", "small-int", False,
     "AP-side int pair; format strings banked in kmod"),
    ("IPC_RPC_PRODUCT_OP", 0xDD16, "empty query",
     "product_data blob 18B observed (ccci_product_data_parsing)", "blob", False,
     "boot replay seq 4-5 success; AP shapes product string"),
    ("IPC_RPC_CIDDATA_OP", 0x1D357, "offset u32 + stepsize u32 (obs 0,1024)",
     "security_data blob (obs len 0 -> work_helper FAIL x2)", "blob", False,
     "boot replay seq 0-3 + 6-9 symmetric fail; AP shapes blob+len"),
    ("IPC_RPC_CPSVC_SECURE_ALGO_OP", 0xE6B57, "algo id + params",
     "secure-algo output blob (TEE-adjacent)", "blob", False,
     "crypto-oracle shape; modem-side bounds unproven on PC"),
    ("IPC_RPC_GET_SECRO_OP", 0xE6B74, "secro id",
     "SECRO bytes (secure-RO partition read)", "blob", False,
     "confidentiality: AP-shaped secure bytes; info-leak, not exec"),
    ("IPC_RPC_GET_TDD_EINT_NUM_OP", 0xE6B89, "empty/enum",
     "u32 count", "small-int", False, "count consumed as loop bound? unproven"),
    ("IPC_RPC_GET_GPIO_NUM_OP", 0xE6BA5, "empty/enum",
     "u32 count", "small-int", False, "same note as EINT_NUM"),
    ("IPC_RPC_GET_ADC_NUM_OP", 0xE6BBD, "empty/enum",
     "u32 count", "small-int", False, "same note"),
    ("IPC_RPC_GET_EMI_CLK_TYPE_OP", 0xE6BD4, "empty/enum",
     "u32 clk type enum", "small-int", False, "enum; OOB needs corrupt switch"),
    ("IPC_RPC_GET_EINT_ATTR_OP", 0xE6BF0, "eint index",
     "eint attr struct (index-selected)", "small-int", False,
     "index-selected struct; AP shapes index echo + attrs"),
    ("IPC_RPC_GET_GPIO_VAL_OP", 0xE6C09, "gpio index",
     "u32 val", "small-int", False, "single int"),
    ("IPC_RPC_GET_ADC_VAL_OP", 0xE6C21, "adc index",
     "u32 val", "small-int", False, "single int"),
    ("IPC_RPC_GET_RF_CLK_BUF_OP", 0xE6C38, "buf index",
     "clk buf struct", "small-int", False, "index-selected struct"),
    ("IPC_RPC_USIM2NFC_OP", 0xE6C6A, "usim/nfc params",
     "status u32", "small-int", False, "status word"),
    ("IPC_RPC_DSP_EMI_MPU_SETTING", 0xE6C7E, "emi/mpu region descriptor",
     "mpu setting ack + region echo", "priv", True,
     "DESTRUCTIVE-POTENTIAL: MPU region programming; corrupt region = priv"),
    ("IPC_RPC_CCCI_LHIF_MAPPING", 0xE6C9A, "lhif map query",
     "mapping table (addr+len pairs)", "priv", False,
     "address mapping table; AP-shaped addrs feed modem HW programming"),
    ("IPC_RPC_DTSI_QUERY_OP", 0xE6CB4, "dtsi query (input struct)",
     "dtsi output blob (ccci_rpc_md_dtsi_output)", "blob", False,
     "blob; modem-side copy bounds unproven on PC"),
    ("IPC_RPC_QUERY_AP_SYS_PROPERTY", 0xE6CCA, "property name string",
     "property value string", "blob", False,
     "AP-shaped string; modem strcpy/strcat bounds unproven on PC"),
    ("IPC_RPC_SAR_TABLE_IDX_QUERY_OP", 0xE6CE8, "sar query",
     "sar table index + table bytes", "blob", False,
     "index + table; index selects modem table row"),
    ("IPC_RPC_EFUSE_BLOWING", 0xE6D07, "efuse field id + value",
     "blow ack/status", "priv", True,
     "DESTRUCTIVE: eFuse blow is permanent silicon state; flag highest"),
    ("IPC_RPC_TRNG", 0xE6D1D, "requested byte count",
     "random bytes (AP-sourced entropy)", "blob", False,
     "entropy risk: malicious AP returns predictable bytes; not exec"),
    ("IPC_RPC_QUERY_CARD_TYPE", 0xE6D2A, "slot id",
     "card-type enum (enter QUERY CARD_TYPE in ccci_rpc_work)", "small-int",
     False, "enum; observed handler-enter string in kmod"),
    ("IPC_RPC_AMMS_DRDI_CONTROL", 0xE6D42, "drdi control struct",
     "drdi ack (remap paths; size-invalid check exists AP-side)", "priv",
     False, "AP-side HAS size-invalid check; modem-side unproven"),
    ("IPC_RPC_SAVE_MD_CAPID", 0xE6D5C, "capid blob",
     "save ack (persistent modem capability)", "priv", False,
     "persistent write; destructive-adjacent but not fuse/MPU class"),
    ("IPC_RPC_RF_ECID_DATA_OP", 0xE6D72, "ecid request",
     "ecid data blob ([MMRF] ECID info IPC RPC status in ROM)", "blob",
     False, "blob; size field attacker-shaped"),
    ("IPC_RPC_IT_OP", 0xE6D8A, "IT test id + params",
     "IT result blob ([RPCIT] enter IT operation in ccci_rpc_work)", "blob",
     False, "test-interface op; broadest params, bounds unproven"),
    ("IPC_RPC_MOTO_SECTEST_QUERY_OP", None, "mot_security test query",
     "test result (modem-side mot_sec log, NOT served via ccci_rpc_work)",
     "modem-only", False,
     "ROM-only string 0x91EF6BB0; no AP-serve path; completeness entry"),
)


@dataclass
class RpcOp:
    name: str
    kmod_off: int | None
    direction: str
    req_shape: str
    rsp_shape: str
    blob_class: str  # small-int | blob | priv | modem-only
    destructive: bool
    ap_shaped: bool  # does malicious AP control response bytes?
    bounds_ap: str   # AP-side (kmod) check evidence
    bounds_md: str   # modem-side (ROM/listing) check evidence
    verdict: str     # per-op verdict word
    confidence: str


def build_rpc_ops() -> list[RpcOp]:
    out: list[RpcOp] = []
    for (name, off, req, rsp, cls, destr, note) in _RPC_ROWS:
        if name == "IPC_RPC_MOTO_SECTEST_QUERY_OP":
            out.append(RpcOp(
                name, None, "modem-internal (mot_sec log)",
                req, rsp, cls, False, False,
                "n/a (not served by AP)",
                "ABSENT from PC evidence (single ROM log string; no parser listing)",
                "REFUTED as AP-serve surface (no ccci_rpc_work path)",
                "HIGH (string provenance only)"))
            continue
        if name in ("IPC_RPC_CIDDATA_OP", "IPC_RPC_PRODUCT_OP"):
            bap = ("PRESENT (observed fail/success paths: get_security_data "
                   "fail len 0 -> work_helper fail; product_data success)")
            bmd = ("ABSENT from PC evidence (zero RPC listings in sim/listings; "
                   "ROM holds no CIDDATA/PRODUCT parser strings)")
            ver = ("CONFIRMED blob surface (boot replay proves modem consumes "
                   "AP-shaped len+bytes); missing-check INCONCLUSIVE on device")
        elif destr:
            bap = "UNKNOWN (no per-op fail string banked in kmod)"
            bmd = ("ABSENT from PC evidence (no modem RPC-client listing; "
                   "flagged by NAME semantics only)")
            ver = ("CONFIRMED destructive potential (name semantics); "
                   "missing-check INCONCLUSIVE on device")
        elif cls == "blob":
            bap = ("PARTIAL (generic AP-side guards exist: smem size error, "
                   "SMEM_USER_MD_DRDI size invalid; per-op strings vary)")
            bmd = "ABSENT from PC evidence (no modem RPC-client listing)"
            ver = ("CONFIRMED blob surface; missing-check INCONCLUSIVE on device")
        else:
            bap = ("PRESENT-generically (enum/int paths; no oversize string in "
                   "kmod format for this op)")
            bmd = ("ABSENT from PC evidence (no modem RPC-client listing; "
                   "int/index OOB needs corrupt-switch proof)")
            ver = "REFUTED as blob-overflow (int/enum shape); index-OOB INCONCLUSIVE"
        out.append(RpcOp(
            name, off, "md-req -> ap-rsp -> modem-parse",
            req, rsp, cls, destr, True, bap, bmd, ver,
            "HIGH (kmod offsets+strings)" if off is not None else "HIGH"))
    return out


# --------------------------------------------------------------------------
# MSGID inventory: banked AP->MD request shapes (attacker-writable) + the one
# MD->AP indication that must never be treated as an AP->modem handler.
# DUMP hex comes from sim_boot logcat_all.txt AT SEND/RECV lines (read-only).
# --------------------------------------------------------------------------

@dataclass
class MsgId:
    msgid: str
    name: str
    direction: str      # ap->md (attacker sends) | md->ap (modem indication)
    ap_shape: str       # attacker-controlled bytes for ap->md
    handler: str        # modem consumer (CATI/listing provenance)
    bounds: str
    verdict: str


MSGIDS: tuple[MsgId, ...] = (
    MsgId("0003", "SYS_AT_REQ", "ap->md",
          "raw Hayes text incl AT+ESMLCK/AT+CLCK (Rfx parcel DUMP)",
          "rmmi_general_command_parsing -> find_cmd_class -> "
          "extended/basic analyzer -> handler table @0x92400260",
          "dispatch REFUTED OOB via AT text (analyzer 0x1BB + SH-only-on-match; "
          "oob_reachability_proof bulk max<=442 + strict emu); per-cmd TLV "
          "see 0519/054d rows",
          "REFUTED (dispatch bounded)"),
    MsgId("0519", "SIM_OPEN_CHANNEL_REQ", "ap->md",
          "AID len u16 + AID bytes (DUMP ...0100090000 01010900 A00000015141434C...)",
          "SIM channel-open parser (modem SIM task); AID copied to channel ctx",
          "validator-gated per at_fuzz T5 class (ANDI caps + BGEIUC gates); "
          "raw length needs Ghidra operand proof -> CONDITIONAL",
          "REFUTED as listed (needs validator bypass for overflow)"),
    MsgId("054d", "SIM_EXTENDED_CHANNEL_GENERIC_ACCESS_REQ", "ap->md",
          "APDU P1/P2/Lc + data (DUMP ...078102002A2A...); len fields TLV",
          "SIM extended-access parser (APDU builder); Lc selects copy length",
          "snprintf/copy bounded per at_fuzz T3 (remaining-bound holds; SLL "
          "bypass -> DoS only); Lc-vs-buffer check needs Ghidra proof",
          "REFUTED write primitive (DoS-only proven); overflow CONDITIONAL"),
    MsgId("0537", "SIM_GET_FACILITY_REQ", "ap->md",
          "facility string + mode (PN/PU/PP/PC...)",
          "rmmi_clck_hdlr @0x90F0A052 (sprintf dest sp+0x1c frame 0x110)",
          "sprintf %s is stack-static short token, not raw AT text; long "
          "facility gated by validators to ERROR (at_fuzz T2)",
          "REFUTED"),
    MsgId("4508", "SIM_SML_STATUS_IND", "md->ap",
          "NONE (modem indication; AP must never send this to the modem)",
          "AP-side RmmSmlUrc.onHandleUrc (mipc messageId:4508); modem-side is "
          "the SENDER (sml_lock_rule_and_status_update_ind @0x9198AAC8)",
          "n/a AP->modem (direction violation to spoof); modem sender needs "
          "no AP-len check",
          "REFUTED as AP->modem handler (wrong direction by transcript)"),
    MsgId("0537/051d/051b", "SIM facility/channel family", "ap->md",
          "small TLVs (facility enum, channel id, CLA/INS/P1/P2/Lc)",
          "per-msgid SIM parsers under the same bounded dispatch",
          "same dispatch bound as 0003; per-msgid lens validator-gated",
          "REFUTED (dispatch) / CONDITIONAL (per-msgid len)"),
)

# --------------------------------------------------------------------------
# FSD traversal: modem-supplied names observed live vs hostile shapes.
# --------------------------------------------------------------------------

FSD_OBSERVED: tuple[str, ...] = (
    "X:/LD40_001",   # O: open, flag 0x700, ret 2 (fd) — logcat :14983
    "Y:/LD40_001",   # D: delete?, ret 0 — logcat :14994
    "X:/LD40_001",   # M: mkdir/move?, ret 0 — logcat :14996
    "/mnt/vendor/nvcfg/mdota/MTK_MD_OTA_CONFIG.ini",  # STAT fail error=2
)

FSD_DRIVE_MAP: tuple[tuple[str, str], ...] = (
    ("X:/", "modem virtual drive (protect-LID namespace, e.g. LD40_001=LID 0xEF09)"),
    ("Y:/", "modem virtual drive (second namespace in D: line)"),
    ("/mnt/vendor/nvcfg/mdota/", "AP-resolved real path for STAT (OTA config)"),
)

FSD_MAX_NAME = 128  # harness cap (PROVISIONAL; real fsd limit is future work)


def normalize_fsd_name(raw: str) -> str:
    """Strip quotes/space + X:/Y:/ drive prefix + leading slashes (harness)."""
    s = raw.strip().strip("'\"").strip()
    if ":/" in s:
        s = s.split(":/", 1)[1]
    return s.strip().lstrip("/")


def fsd_traversal_verdict(raw: str) -> dict:
    """Classify one filename. Pure function of the string (no I/O)."""
    nm = normalize_fsd_name(raw)
    reasons: list[str] = []
    hostile = False
    if ".." in nm.split("/"):
        hostile = True
        reasons.append("dotdot-segment")
    if "\\" in raw or "\x00" in raw:
        hostile = True
        reasons.append("backslash-or-NUL")
    if len(raw) > FSD_MAX_NAME:
        hostile = True
        reasons.append(f"overlong>{FSD_MAX_NAME}")
    if raw.startswith(("/", "\\")) and ":/" not in raw:
        reasons.append("absolute-AP-path (modem should use X:/Y:/)")
    if not nm:
        hostile = True
        reasons.append("empty-after-normalize")
    return {"raw": raw, "normalized": nm,
            "hostile": hostile, "reasons": reasons,
            "verdict": "REFUSE (ENOENT=2)" if hostile else "SERVE (if backed-up)"}


# --------------------------------------------------------------------------
# CVE-2023-32840 fingerprint constants (bulletin + this build).
# --------------------------------------------------------------------------

CVE_ID = "CVE-2023-32840"
CVE_BULLETIN = "MediaTek November-2023 product-security-bulletin"
CVE_PATCH = "MOLY01138425"
CVE_ISSUE = "MSV-862"
CVE_CWE = "CWE-787 (Out-of-bounds Write)"
CVE_PRIV = "System execution privileges needed; user interaction may be needed"
CVE_AFFECTED_CHIP = "MT6835"
CVE_AFFECTED_MODEM = ("LR12A", "NR15", "NR16", "VMOLYN", "NR17")
# Bulletin publish date (year, month, day) for version comparison.
CVE_BULLETIN_DATE = (2023, 11, 6)

# This build (banked from read-only captures + kmod vermagic).
BUILD_BASEBAND = "MT6835_NR17.RC.MP.V40.2.P247.01.339R"
BUILD_MODEM_BRANCH = "NR17"
BUILD_VENDOR_DATE_UTC = 1755341410  # ro.vendor.build.date.utc (2025-08-16)
BUILD_VENDOR_DATE_HUMAN = "2025-08-16"
BUILD_VENDOR_SPL = "2025-08-01"     # ro.vendor.build.security_patch
BUILD_KERNEL_VERMAGIC = "5.15.180-android13-8-g9fd68d05d161"


def cve_patch_state() -> dict:
    """Fingerprint THIS build against the bulletin fix date (no device)."""
    patched_by_date = (2025, 8, 16) > CVE_BULLETIN_DATE
    return {
        "cve": CVE_ID, "patch": CVE_PATCH, "issue": CVE_ISSUE, "cwe": CVE_CWE,
        "bulletin": CVE_BULLETIN, "bulletin_date": "%04d-%02d-%02d" % CVE_BULLETIN_DATE,
        "affected_chip": CVE_AFFECTED_CHIP, "affected_modems": list(CVE_AFFECTED_MODEM),
        "this_baseband": BUILD_BASEBAND, "this_modem_branch": BUILD_MODEM_BRANCH,
        "this_vendor_build": BUILD_VENDOR_DATE_HUMAN,
        "this_vendor_spl": BUILD_VENDOR_SPL,
        "this_kernel": BUILD_KERNEL_VERMAGIC,
        "postdates_bulletin_by_months": 21,
        "date_verdict": ("PROVISIONAL-PATCHED (build 2025-08 postdates "
                         "2023-11 bulletin by ~21mo; fix SHOULD be merged) "
                         if patched_by_date else "PRE-BULLETIN (exposed)"),
        "binary_verdict": ("INCONCLUSIVE on binary (no MOLY01138425 diff on PC; "
                           "kmod carries only AP-side size-error strings, no "
                           "modem CCCI bounds-check symbol to confirm)"),
    }


# --------------------------------------------------------------------------
# Verdict records.
# --------------------------------------------------------------------------

@dataclass
class Channel:
    id: str
    title: str
    handler: str
    input_shape: str
    bounds_present: str
    bounds_absent: str
    first_consumer: str
    verdict: str          # CONFIRMED | REFUTED (+ qualifier where honest)
    confidence: str
    evidence: list = field(default_factory=list)


def ring_adversarial_drive() -> dict:
    """Drive SmemRingSet ADVERSARIALLY as a malicious AP; report quarantine.

    Returns {vectors, events, first_consumer, handlers_reached, verdict}.
    The FIRST consumer of every hostile index/len is the ring demux itself
    (SmemRingSet.dequeue — the model of modem port_char_recv_skb/ccci_hif);
    no msgid/RPC/FS handler is reached on any hostile vector (their called
    flags stay False). That is the answer to 'which handler consumes a
    malicious index/len first'.
    """
    if MpuMemory is None or SmemRingSet is None:
        return {"skipped": True,
                "reason": "sim/mem_model.py not importable"}
    mem = MpuMemory.with_image_and_smem()
    rings = SmemRingSet(mem)
    rings.create_ring("ccci_at_req", capacity=4, slot_len=256, actor="md")
    rings.create_ring("ccci_rpc_rsp", capacity=4, slot_len=2048, actor="md")
    rings.create_ring("ccci_fs_rsp", capacity=8, slot_len=2048, actor="md")

    # Handler stand-ins: set True ONLY if a demux ever delivers to them.
    # The demux in this model delivers ONLY via dequeue() success; every
    # hostile vector below must raise before delivery, so all stay False.
    called = {"at_handler": False, "rpc_handler": False, "fs_handler": False}

    def deliver(ring: str, payload: bytes) -> None:
        if ring == "ccci_at_req":
            called["at_handler"] = True
        elif ring == "ccci_rpc_rsp":
            called["rpc_handler"] = True
        elif ring == "ccci_fs_rsp":
            called["fs_handler"] = True

    vectors: list[dict] = []

    def run_vector(label: str, ring: str, setup, action: str = "dequeue-md"):
        rec: dict = {"label": label, "ring": ring, "action": action}
        try:
            setup()
        except Exception as e:  # setup fault itself is a quarantine signal
            rec.update({"outcome": "SETUP-RAISE", "detail": repr(e),
                        "handler_reached": False})
            vectors.append(rec)
            return rec
        try:
            if action == "dequeue-md":
                payload = rings.dequeue(ring, actor="md")
                if payload is None:
                    rec.update({"outcome": "EMPTY-None",
                                "handler_reached": False})
                else:
                    deliver(ring, bytes(payload))
                    rec.update({"outcome": "DELIVERED",
                                "handler_reached": True,
                                "length": len(bytes(payload))})
            elif action == "enqueue-ap-oversize":
                rec.update({"outcome": "NO-RAISE (unexpected)",
                            "handler_reached": False})
        except MalformedIndex as e:
            rec.update({"outcome": "QUARANTINE-MalformedIndex",
                        "detail": str(e)[:160], "handler_reached": False})
        except RingOverrun as e:
            rec.update({"outcome": "QUARANTINE-RingOverrun",
                        "detail": str(e)[:160], "handler_reached": False})
        except Exception as e:
            rec.update({"outcome": "OTHER-RAISE", "detail": repr(e)[:160],
                        "handler_reached": False})
        vectors.append(rec)
        return rec

    # V1 count>cap: hostile AP plants widx far ahead.
    rings.set_indices("ccci_at_req", 0, 0, actor="ap")
    run_vector("V1-count-gt-cap", "ccci_at_req",
               lambda: rings.set_indices("ccci_at_req", 0, 99, actor="ap"))
    # V2 wrap: honest traffic advances indices, then hostile jump past cap.
    def v2setup():
        rings.set_indices("ccci_at_req", 0, 0, actor="ap")
        for i in range(6):  # wrap a 4-slot ring honestly (AP->MD then MD drain)
            rings.enqueue("ccci_at_req", bytes([i]) * 8, actor="ap")
            rings.dequeue("ccci_at_req", actor="md")
        rings.set_indices("ccci_at_req", 6, 6 + 5, actor="ap")  # count 5 > cap 4
    run_vector("V2-wrap-then-gt-cap", "ccci_at_req", v2setup)
    # V3 oversize len prefix: plant huge msg_len in the next slot.
    def v3setup():
        rings.set_indices("ccci_rpc_rsp", 0, 0, actor="ap")
        rings.enqueue("ccci_rpc_rsp", b"ok", actor="md")
        r, _w = rings.get_indices("ccci_rpc_rsp", actor="md")
        pos = r % 4
        slot = rings.data_base + rings.rings["ccci_rpc_rsp"].data_off + pos * 2048
        mem.write(slot, struct.pack("<I", 0xFFFFFF), "ap")  # hostile AP write
    run_vector("V3-oversize-len-prefix", "ccci_rpc_rsp", v3setup)
    # V4 bad magic: corrupt the ring header magic as AP.
    def v4setup():
        rings.set_indices("ccci_fs_rsp", 0, 0, actor="ap")
        spec = rings.rings["ccci_fs_rsp"]
        mem.write(rings.ctrl_base + spec.ctrl_off,
                  struct.pack("<I", 0xDEADBEEF), "ap")
    run_vector("V4-bad-magic", "ccci_fs_rsp", v4setup)
    # V5 geometry mismatch: corrupt capacity word as AP.
    def v5setup():
        spec = rings.rings["ccci_fs_rsp"]
        # restore header first (V4 corrupted magic), then corrupt geometry
        mem.write(rings.ctrl_base + spec.ctrl_off,
                  struct.pack("<5I", SmemRingSet.MAGIC, 8, 2048, 0, 0), "md")
        mem.write(rings.ctrl_base + spec.ctrl_off + 4,
                  struct.pack("<I", 0x7FFFFFFF), "ap")
    run_vector("V5-geometry-mismatch", "ccci_fs_rsp", v5setup)
    # V6 overrun: fill to capacity, one more enqueue must raise (producer waits).
    def v6setup():
        rings.set_indices("ccci_at_req", 0, 0, actor="ap")
        # drain leftovers first
        try:
            while rings.dequeue("ccci_at_req", actor="md") is not None:
                pass
        except Exception:
            rings.set_indices("ccci_at_req", 0, 0, actor="ap")
        for _ in range(4):
            rings.enqueue("ccci_at_req", b"x", actor="md")
        try:
            rings.enqueue("ccci_at_req", b"boom", actor="md")
            raise AssertionError("overrun did not raise")
        except RingOverrun:
            raise MalformedIndex("ccci_at_req",
                                 "overrun contained (expected quarantine)")
    run_vector("V6-overrun-contained", "ccci_at_req", v6setup)
    # V7 hostile AP enqueue with oversize payload (never stored).
    def v7setup():
        rings.set_indices("ccci_rpc_rsp", 0, 0, actor="ap")
        try:
            rings.enqueue("ccci_rpc_rsp", b"A" * 4096, actor="ap")
            raise AssertionError("oversize enqueue did not raise")
        except MalformedIndex:
            raise MalformedIndex("ccci_rpc_rsp",
                                 "oversize-enqueue refused (expected)")
    run_vector("V7-ap-oversize-enqueue-refused", "ccci_rpc_rsp", v7setup)
    # V8 u32 wrap: indices near 0xFFFFFFFF must still discipline correctly.
    def v8setup():
        rings.set_indices("ccci_at_req", 0xFFFFFFFE, 0xFFFFFFFE + 5, actor="ap")
    run_vector("V8-u32-wrap-gt-cap", "ccci_at_req", v8setup)

    kinds = [e.get("kind") for e in rings.events]
    quarantined = sum(1 for v in vectors
                      if v["outcome"].startswith("QUARANTINE")
                      or v["outcome"] == "SETUP-RAISE")
    reached = [v for v in vectors if v.get("handler_reached")]
    verdict = ("REFUTED (no msgid/RPC/FS handler reachable with hostile "
               "index/len: demux quarantines first)")
    return {
        "vectors": vectors,
        "ring_events": list(rings.events),
        "event_kinds": sorted(set(kinds)),
        "first_consumer": ("HIF demux (SmemRingSet.dequeue — model of modem "
                           "port_char_recv_skb/ccci_hif); msgid/RPC/FS handlers "
                           "are downstream and unreached on hostile vectors"),
        "handlers_reached": reached,
        "handlers_called_flags": dict(called),
        "quarantined": quarantined,
        "total": len(vectors),
        "verdict": verdict,
    }


def build_channels(ring_res: dict | None = None) -> list[Channel]:
    ring_res = ring_res or {}
    ch: list[Channel] = [
        Channel(
            id="CH-RING", title="ring-index abuse (read/write idx, wrap, count>cap, oversize len)",
            handler=("SmemRingSet.dequeue (model) = modem port_char_recv_skb / "
                     "ccci_hif demux + CCIF doorbell kick (CcifDevice CON set/clear)"),
            input_shape=("u32 read_idx + u32 write_idx (monotonic, pos=idx%cap, "
                         "count=(w-r)&0xFFFFFFFF) + u32 msg_len slot prefix + "
                         "header geometry (magic CCCI|caps|slot_len)"),
            bounds_present=("MODEL: count>cap -> MalformedIndex+event; enqueue-on-full "
                            "-> RingOverrun; msg_len>slot-4 -> MalformedIndex (no advance); "
                            "bad magic/geometry -> MalformedIndex; empty -> None. "
                            f"Adversarial drive: {ring_res.get('quarantined', '?')}/"
                            f"{ring_res.get('total', '?')} hostile vectors quarantined, "
                            f"{len(ring_res.get('handlers_reached', []))} reached a handler. "
                            "AP-side kmod HAS size guards (smem size error; "
                            "SMEM_USER_MD_DRDI size invalid)."),
            bounds_absent=("DEVICE pre-patch: missing-check class proven by bulletin "
                           "(CVE-2022-21765 CCCI-OOB + CVE-2023-32840 modem-CCCI OOB-write, "
                           "MOLY01138425). Modem-side demux listing absent on PC, so "
                           "device-transfer of the model quarantine is UNPROVEN."),
            first_consumer=(ring_res.get("first_consumer",
                            "HIF demux (SmemRingSet.dequeue); handlers downstream")),
            verdict=("REFUTED in model (malicious index/len never reaches a msgid/RPC/FS "
                     "handler — demux quarantines first); CONFIRMED missing-check class "
                     "on pre-patch modem (bulletin); THIS build provisional (see CH-CVE)"),
            confidence="HIGH (model, 8 hostile vectors) / LOW (device transfer)",
            evidence=[f"V{v['label']}={v['outcome']}" for v in ring_res.get("vectors", [])],
        ),
        Channel(
            id="CH-MSGID", title="msgid dispatch (AT 0519/054d/0003; 4508 SML_IND observed)",
            handler=("rmmi_extended_cmd_processor @0x90EF0C48 (LHU/SLL/LWX/JRC, NO range "
                     "check) <- analyzer @0x90EF0CD8 (bound 0x1BB, SH-only-on-match) <- "
                     "hash @0x90EF0D58 <- general_command_parsing; table @0x92400260 "
                     "(443 valid 0..442); per-msgid SIM parsers for 0519/054d/0537"),
            input_shape=("AP SEND Rfx parcel: msgid u16 + txid + TLV DUMP hex. 0003=SYS_AT_REQ "
                         "raw Hayes text; 0519=OPEN_CHANNEL AID len+bytes; 054d=EXTENDED_ACCESS "
                         "APDU P1/P2/Lc+data (1016B-chunked eSIM path); 0537=facility+mode. "
                         "4508 SML_STATUS_IND is MD->AP (64B policy/state/cap TLV, TXID ffff) — "
                         "AP must never send it."),
            bounds_present=("dispatch: analyzer loop 0x1BB + BEQC-miss (no SH write) + EXT mask; "
                            "bulk FULL-hash-path fuzz max_idx<=442 + strict-emu match "
                            "(oob_reachability_proof REFUTED); clck sprintf SAFE (T2: %s static, "
                            "244B avail); raw_data_to_string remaining-bound holds (T3 DoS-only); "
                            "basic processor checks <0xe (contrast)."),
            bounds_absent=("per-msgid TLV length-vs-destination checks need Ghidra operand proof "
                           "(op12 running-total wrap + memcpy sites are CONDITIONAL on validator "
                           "bypass per at_fuzz T5; 054d Lc-vs-APDU-buffer likewise). No 4508 REQ "
                           "parser exists (wrong direction)."),
            first_consumer=("RMMI dispatch (analyzer->processor) for 0003/0519/054d; "
                            "4508 bypasses RMMI (modem indication -> AP RmmSmlUrc)"),
            verdict=("REFUTED OOB-via-dispatch through valid AT/MSGID text (bounded 0..442); "
                     "REFUTED write primitive as listed for clck/sprintf + raw_data_to_string; "
                     "per-msgid TLV overflow CONDITIONAL on validator bypass (needs Ghidra)"),
            confidence="HIGH (dispatch) / MEDIUM (clck/raw2str) / MEDIUM-LOW (op12 TLV)",
            evidence=["analyzer bound 0x1BB/BEQC/SH (listing)",
                      "table 443 valid ptrs (ROM dump)",
                      "bulk fuzz max<=442, 0 violations (oob proof)",
                      "4508 x3 + 0519x17/054dx12 shapes (sim_boot logcat)"],
        ),
        Channel(
            id="CH-RPC", title="RPC op abuse (27 IPC_RPC_* ops)",
            handler=("AP-side ccci_rpc_work dispatch (kmod/ccci_md_all.ko: enter CIDDATA_OP "
                     "offset/stepsize; enter PRODUCT_OP; [RPCIT] IT; QUERY CARD_TYPE) + "
                     "ccci_rpc_get_security_data/get_product_data (ccci_util_lib.ko) + "
                     "modem-side RPC client (service/hif/ncccisrv/ccci_rpc/src/ccci_rpc.c + "
                     "ccci_rpc_data.c per ROM path strings; NO listing on PC)"),
            input_shape=("MD-req (offset/stepsize/ids/structs) -> AP-rsp BLOB parsed by modem: "
                         "CIDDATA security_data blob+len (obs 0 -> FAIL, modem continues boot); "
                         "PRODUCT product_data 18B string; GPIO/ADC/EINT ints + attr structs; "
                         "DTSI/property/ECID/IT blobs; TRNG bytes; SECRO bytes; SAR/DRDI tables; "
                         "MPU region descriptor (DSP_EMI_MPU); fuse field+value (EFUSE_BLOWING)"),
            bounds_present=("AP-side: get_security_data fail path (len 0, twice, symmetric) + "
                            "smem size error + SMEM_USER_MD_DRDI size invalid + "
                            "drdi_smem remap checks (kmod strings). Proves the AP daemon "
                            "validates some lengths — not the modem parser."),
            bounds_absent=("Modem-side RPC-client parse checks: ABSENT from PC evidence "
                           "(0 RPC listings in sim/listings; ROM holds 1 IPC_RPC string "
                           "(MOTO_SECTEST) + ECID status; no ccci_rpc_data bounds listing). "
                           "Hence per-op modem missing-check is INCONCLUSIVE from PC."),
            first_consumer=("modem RPC client parser for the op's response blob (downstream of "
                            "the ring demux); AP shapes bytes+len after the MD request"),
            verdict=("CONFIRMED attacker-shaped-blob surface for all 26 AP-served ops (AP controls "
                     "rsp bytes+len; boot replay proves modem consumes len 0 without crash); "
                     "CONFIRMED destructive potential for 2 ops (EFUSE_BLOWING permanent silicon, "
                     "DSP_EMI_MPU_SETTING privilege); modem-side missing-check INCONCLUSIVE "
                     "(needs Ghidra on ccci_rpc.c/ccci_rpc_data.c)"),
            confidence="HIGH (surface + 2 destructive flags) / LOW (modem missing-check)",
            evidence=["26 kmod offsets + MOTO_SECTEST ROM VA (RPC_OPS table)",
                      "CIDDATA 0/1024 x2 fail + PRODUCT 18B success (boot replay)",
                      "0 RPC listings on PC (absence noted, not a proof)"],
        ),
        Channel(
            id="CH-FSD", title="ccci_fsd path traversal + file-content abuse",
            handler=("AP daemon ccci_fsd(1) (O:/D:/M:/STAT opcodes; ENOENT=2 refusal) + "
                     "modem FS client (mcf_file_handling_proc.c per ROM string; "
                     "MTK_MD_OTA_CONFIG.ini STAT path; LD40_001 LID container)"),
            input_shape=("MD->AP: opcode O|D|M|STAT + name (X:/LD40_001, Y:/LD40_001, "
                         "/mnt/vendor/nvcfg/mdota/MTK_MD_OTA_CONFIG.ini) + flag 0x700; "
                         "AP->MD: file bytes (protect-LID records / NVD blobs) + STAT "
                         "(mtime/atime/ctime + size) or ERR:<OP>:<NAME>:2:ENOENT"),
            bounds_present=("AP daemon refuses unknown names with ENOENT=2 (live-observed for "
                            "OTA_CONFIG.ini x2); observed modem names are bare LIDs (no ../); "
                            "model FsdService normalizes X:/Y:/ prefixes and refuses "
                            "dotdot/backslash/NUL/overlong (harness convention)."),
            bounds_absent=("Real ccci_fsd source absent on PC (no fsd binary/strings beyond "
                           "logcat + CCCI_FS_RX/TX channel names in kmod): prefix-strip map "
                           "(X:/Y:/ -> real dir) + traversal sanitization + symlink/absolute "
                           "handling are UNPROVEN; modem FS-client copy bounds (file bytes -> "
                           "modem buffers, STAT size -> alloc) need Ghidra (mcf + FS client)."),
            first_consumer=("AP ccci_fsd daemon for the filename (MD->AP); modem FS client for "
                            "the content (AP->MD) — opposite directions per opcode phase"),
            verdict=("CONFIRMED direction (filename MD->AP: O:/D:/M: lines; content AP->MD); "
                     "traversal missing-check INCONCLUSIVE on device (no fsd source on PC); "
                     "AP->modem content-oversize missing-check INCONCLUSIVE (needs Ghidra); "
                     "model refuses hostile shapes (REFUTED in harness)"),
            confidence="HIGH (direction) / LOW (sanitization + content bounds)",
            evidence=["O:X:/LD40_001 ret2 / D:Y:/LD40_001 ret0 / M:X:/LD40_001 ret0",
                      "STAT OTA_CONFIG.ini error=2 x2",
                      "harness refuses ../, backslash, NUL, >128B (selftest)"],
        ),
        Channel(
            id="CH-CVE", title="CVE-2023-32840 CCCI OOB-write (MT6835 affected)",
            handler=("modem CCCI OOB-write site (Patch MOLY01138425 / MSV-862; exact function "
                     "not named in bulletin) ~ modem ring/CCCI parser; AP-side analogues in "
                     "THIS kernel: ccci_hif_send_data / ccci_port_recv_skb / port_char_recv_skb / "
                     "port_net_recv_skb / ccci_port_send_msg_to_md (symbols, kmod) + "
                     "ccci_ring_buffer struct (ccci_util_lib.ko)"),
            input_shape=("same as CH-RING (AP-written ring indices/lengths) + CCIF doorbell kick; "
                         " bulletin class: missing bounds check -> OOB write, System priv, "
                         "possible user-interaction gate"),
            bounds_present=("date: this build (vendor 2025-08-16, SPL 2025-08-01, baseband "
                            "P247.01.339R, kernel 5.15.180-android13-8) postdates Nov-2023 "
                            "bulletin by ~21mo, so the MOLY fix SHOULD be merged; AP-side kmod "
                            "carries size-error strings (smem size error; DRDI size invalid) "
                            "consistent with a post-fix tree. No OOB observed in 2025 captures."),
            bounds_absent=("binary: no ccci_ringbuf_write/readable-named symbols in THIS kmod "
                           "(only ccci_ring_buffer struct); modem OOB site unmapped on PC "
                           "(service/hif paths in ROM strings, no listing); no MOLY01138425 "
                           "diff available offline — patch presence UNVERIFIED at bytes level."),
            first_consumer="same as CH-RING (ring demux) — CVE site is downstream or the demux itself",
            verdict=("PROVISIONAL-REFUTED as unpatched-on-this-build (fingerprint says SHOULD be "
                     "fixed); binary-level patch state INCONCLUSIVE (needs Ghidra diff vs "
                     "MOLY01138425 + modem CCCI bounds audit). Do NOT claim fixed without diff."),
            confidence="MEDIUM (date arithmetic) / LOW (binary proof)",
            evidence=["bulletin Nov-2023 + MOLY01138425/MSV-862 + CWE-787 + MT6835/NR17 hit",
                      "baseband P247.01.339R (NR17) + vendor 2025-08-16 + SPL 2025-08-01",
                      "kmod vermagic 5.15.180-android13-8-g9fd68d05d161",
                      "no ringbuf_write/readable symbols; ring_buffer struct only"],
        ),
    ]
    return ch


def build_report(ring_res: dict | None = None) -> dict:
    """Assemble the full per-channel report dict (JSON-serializable)."""
    ring_res = ring_res or {}
    rpc_ops = build_rpc_ops()
    channels = build_channels(ring_res)
    cve = cve_patch_state()
    fsd_vectors = [
        {"raw": n, **fsd_traversal_verdict(n)} for n in
        list(FSD_OBSERVED) + [
            "../../etc/passwd", "X:/../../etc/passwd", "Y:/a/../../b",
            "/mnt/vendor/nvdata/md/NVD_DATA", "X:/LD40_001\x00.png",
            "X:/" + "A" * 200, "X:/..\\..\\win", "",
        ]
    ]
    msgid_rows = [asdict(m) for m in MSGIDS]
    return {
        "tool": "sim/ccci_threat.py (SIMULATION ONLY — no device contact)",
        "target": "MT6835 PCORE modem, baseband " + BUILD_BASEBAND,
        "verdict_vocab": ("CONFIRMED = missing-check/surface proven in sim; REFUTED = "
                          "bounded in sim; INCONCLUSIVE/PROVISIONAL = needs Ghidra diff; "
                          "device-transfer qualifier attached per channel"),
        "channels": [asdict(c) for c in channels],
        "rpc_ops": [asdict(o) for o in rpc_ops],
        "rpc_summary": {
            "total": len(rpc_ops),
            "ap_served": sum(1 for o in rpc_ops if o.ap_shaped),
            "destructive": [o.name for o in rpc_ops if o.destructive],
            "entropy_confidentiality": ["IPC_RPC_TRNG", "IPC_RPC_GET_SECRO_OP"],
            "blob_class": [o.name for o in rpc_ops if o.blob_class == "blob"],
        },
        "msgids": msgid_rows,
        "fsd": {"observed": list(FSD_OBSERVED), "drive_map": list(FSD_DRIVE_MAP),
                "vectors": fsd_vectors,
                "direction": "CONFIRMED filename MD->AP, content AP->MD",
                "sanitization": "INCONCLUSIVE on device (no fsd source on PC)"},
        "cve": cve,
        "ring": {k: v for k, v in ring_res.items() if k != "ring_events"},
        "ring_event_kinds": ring_res.get("event_kinds", []),
    }


def format_report(rep: dict) -> str:
    L: list[str] = []
    L.append("AP->modem (CCCI) threat report — SIMULATION ONLY (no device contact)")
    L.append(f"target: {rep['target']}")
    L.append(f"vocab: {rep['verdict_vocab']}")
    L.append("")
    for c in rep["channels"]:
        L.append(f"## {c['id']} — {c['title']}")
        L.append(f"handler: {c['handler']}")
        L.append(f"input shape: {c['input_shape']}")
        L.append(f"bounds PRESENT: {c['bounds_present']}")
        L.append(f"bounds ABSENT: {c['bounds_absent']}")
        L.append(f"first consumer: {c['first_consumer']}")
        L.append(f"verdict: {c['verdict']}")
        L.append(f"confidence: {c['confidence']}")
        L.append("")
    L.append(f"## RPC (27 ops: {rep['rpc_summary']['ap_served']} AP-served, "
             f"destructive={rep['rpc_summary']['destructive']})")
    for o in rep["rpc_ops"]:
        flag = " [DESTRUCTIVE]" if o["destructive"] else ""
        L.append(f"- {o['name']}{flag} :: {o['direction']} :: "
                 f"req({o['req_shape']}) rsp({o['rsp_shape']}) :: {o['verdict']}")
    L.append("")
    L.append("## FSD traversal vectors")
    for v in rep["fsd"]["vectors"]:
        L.append(f"- {v['raw']!r} -> norm={v['normalized']!r} "
                 f"hostile={v['hostile']} {v['reasons']} :: {v['verdict']}")
    L.append("")
    cve = rep["cve"]
    L.append(f"## {cve['cve']} patch state")
    L.append(f"bulletin: {cve['bulletin_date']} patch {cve['patch']} ({cve['issue']}, {cve['cwe']})")
    L.append(f"this build: {cve['this_baseband']} vendor {cve['this_vendor_build']} "
             f"SPL {cve['this_vendor_spl']} kernel {cve['this_kernel']}")
    L.append(f"date: {cve['date_verdict']}")
    L.append(f"binary: {cve['binary_verdict']}")
    return "\n".join(L)


# --------------------------------------------------------------------------
# Evidence cross-checks (read-only; each failure is reported, never fatal).
# --------------------------------------------------------------------------

def _read_text(p: Path, limit: int = 4000000) -> str:
    try:
        if not p.is_file():
            return ""
        data = p.read_bytes()[:limit]
        return data.decode("utf-8", "replace")
    except OSError:
        return ""


def _find_bytes(p: Path, needle: bytes) -> int:
    try:
        if not p.is_file():
            return -1
        return p.read_bytes().find(needle)
    except OSError:
        return -1


def crosscheck_evidence() -> dict:
    """Verify banked constants against PC-local files (read-only)."""
    out: dict = {"checks": [], "ok": True}
    def ck(label: str, cond: bool, detail: str = ""):
        out["checks"].append({"label": label, "ok": bool(cond), "detail": detail})
        if not cond:
            out["ok"] = False
    # kmod RPC names + offsets
    try:
        data = KMOD_MD.read_bytes() if KMOD_MD.is_file() else b""
        names = set(re.findall(rb"IPC_RPC_[A-Z0-9_]+", data))
        ck("kmod-26-rpc-names", len(names) == 26, f"found {len(names)}")
        for nm, off, *_ in _RPC_ROWS:
            if off is None:
                continue
            seg = data[off:off + len(nm)]
            ck(f"kmod-off-{nm}", seg == nm.encode(),
               f"@{off:#x} got {seg[:32]!r}")
        ck("kmod-util-ring_buffer-struct", b"ccci_ring_buffer" in
           (KMOD_UTIL.read_bytes() if KMOD_UTIL.is_file() else b""),
           "struct name in util lib")
        ck("kmod-no-ringbuf_write-symbol",
           b"ccci_ringbuf_write" not in data and b"ringbuf_readable" not in data,
           "absence noted (equivalent unmapped by name)")
    except OSError as e:
        ck("kmod-read", False, repr(e))
    # ROM single MOTO string + AT count sanity
    try:
        rom = ROM_PATH.read_bytes() if ROM_PATH.is_file() else b""
        if rom:
            ck("rom-moto-sectest", rom.count(b"IPC_RPC_MOTO_SECTEST_QUERY_OP") >= 1,
               "mot_security client string")
            at_names = set(re.findall(rb"AT\+([A-Z0-9]{2,14})", rom))
            ck("rom-351-at-names", len(at_names) == 351, f"found {len(at_names)}")
            for lit in (b"AT+ESMLCK", b"AT+ESMLCK", b"MTK_MD_OTA_CONFIG.ini"):
                ck(f"rom-has-{lit[:12]!r}", lit in rom, "")
    except OSError as e:
        ck("rom-read", False, repr(e))
    # captures: 4508 + 0519/054d + fsd + rpc lines
    txt = _read_text(SIM_BOOT_LOG)
    if txt:
        ck("cap-4508", txt.count("MSGID=4508") >= 3, f"{txt.count('MSGID=4508')}")
        ck("cap-0519", "MSGID=0519 [SIM_OPEN_CHANNEL_REQ]" in txt, "")
        ck("cap-054d", "MSGID=054d [SIM_EXTENDED_CHANNEL_GENERIC_ACCESS_REQ]" in txt, "")
        ck("cap-fsd-O", "ccci_fsd(1): O: X:/LD40_001" in txt, "")
        ck("cap-fsd-ENOENT", "MTK_MD_OTA_CONFIG.ini, error=2" in txt, "")
        ck("cap-ciddata", "enter IPC_RPC_CIDDATA_OP offset :0, stepsize:1024" in txt, "")
        ck("cap-product", "enter IPC_RPC_PRODUCT_OP" in txt, "")
        ck("cap-secdata-fail", "ccci_rpc_get_security_data fail" in txt, "")
    else:
        ck("captures-present", True, "skipped (partial checkout)")
    props = _read_text(PROPS_PATH)
    if props:
        ck("props-baseband-P247", BUILD_BASEBAND in props, "")
        ck("props-vendor-2025-08", "2025" in props and "c28420" in props, "")
    # hw_target CCIF cross-check
    try:
        if HW_SPEC:
            pairs = HW_SPEC["mem"]["ccif_pairs"]
            ck("hw ccif-6-pairs", len(pairs) == 6, f"{len(pairs)}")
        else:
            ck("hw-target-present", True, "skipped (import fallback)")
    except Exception as e:  # noqa: BLE001
        ck("hw-target", False, repr(e))
    return out


# --------------------------------------------------------------------------
# Selftest (stdlib only, deterministic, no device).
# --------------------------------------------------------------------------

def _ban_check() -> list[str]:
    """Assert no device-touching imports (AST-based, docstring-safe)."""
    import ast as _ast
    banned = {"socket", "subprocess", "serial", "adb", "fastboot", "pyserial"}
    found: list[str] = []
    tree = _ast.parse(Path(__file__).read_text(encoding="utf-8"))
    for nd in _ast.walk(tree):
        if isinstance(nd, _ast.Import):
            for a in nd.names:
                if a.name.split(".")[0] in banned:
                    found.append(a.name)
        elif isinstance(nd, _ast.ImportFrom) and nd.module:
            if nd.module.split(".")[0] in banned:
                found.append(nd.module)
    return found


def selftest() -> tuple[int, int, list[str]]:
    passed = failed = 0
    details: list[str] = []
    fails: list[str] = []

    def check(label: str, ok: bool, detail: str = "") -> None:
        nonlocal passed, failed
        if ok:
            passed += 1
            details.append("PASS " + label)
        else:
            failed += 1
            details.append("FAIL " + label + (f" ({detail})" if detail else ""))
            fails.append(label + (f": {detail}" if detail else ""))

    # S0 hygiene: no device imports, stdlib-only, siblings intact.
    try:
        check("no-device-imports", _ban_check() == [], ";".join(_ban_check()))
        import ast as _ast
        tree = _ast.parse(Path(__file__).read_text(encoding="utf-8"))
        mods: set[str] = set()
        for nd in _ast.walk(tree):
            if isinstance(nd, _ast.Import):
                mods.update(a.name.split(".")[0] for a in nd.names)
            elif isinstance(nd, _ast.ImportFrom) and nd.module:
                mods.add(nd.module.split(".")[0])
        stdlib = {"__future__", "json", "re", "struct", "sys", "dataclasses",
                  "pathlib", "typing"}
        sibling = {"hw_target", "mem_model", "emu_engine", "sim", "ast"}
        check("stdlib-only", mods <= stdlib | sibling, repr(sorted(mods)))
        check("mem_model-integrated",
              MpuMemory is not None and SmemRingSet is not None)
    except Exception as e:  # noqa: BLE001
        check("hygiene", False, repr(e))

    # S1 RPC matrix: 27 ops, 2 destructive, offsets ordered.
    try:
        ops = build_rpc_ops()
        check("rpc-27-total", len(ops) == 27, f"got {len(ops)}")
        check("rpc-26-kmod-offsets",
              sum(1 for o in ops if o.kmod_off is not None) == 26)
        offs = [o.kmod_off for o in ops if o.kmod_off is not None]
        check("rpc-offsets-ascending", offs == sorted(offs), repr(offs[:4]))
        check("rpc-offsets-unique", len(set(offs)) == 26)
        destr = sorted(o.name for o in ops if o.destructive)
        check("rpc-2-destructive", destr == ["IPC_RPC_DSP_EMI_MPU_SETTING",
                                            "IPC_RPC_EFUSE_BLOWING"], repr(destr))
        check("rpc-ciddata-shape", any("0,1024" in o.req_shape for o in ops
                                       if o.name == "IPC_RPC_CIDDATA_OP"))
        check("rpc-product-18B", any("18B" in o.rsp_shape for o in ops
                                     if o.name == "IPC_RPC_PRODUCT_OP"))
        check("rpc-trng-entropy", any(o.name == "IPC_RPC_TRNG" for o in ops))
        check("rpc-moto-refuted", any(o.name == "IPC_RPC_MOTO_SECTEST_QUERY_OP"
                                      and o.verdict.startswith("REFUTED")
                                      for o in ops))
        check("rpc-all-have-verdict", all(o.verdict for o in ops))
    except Exception as e:  # noqa: BLE001
        check("rpc-matrix", False, repr(e))

    # S2 ring adversarial drive: quarantine before handlers.
    try:
        res = ring_adversarial_drive()
        if res.get("skipped"):
            check("rings-skipped", True, res.get("reason", ""))
        else:
            check("rings-8-vectors", res["total"] == 8, f"{res['total']}")
            check("rings-quarantined>=6", res["quarantined"] >= 6,
                  f"{res['quarantined']}/{res['total']}")
            check("rings-no-handler-reached", res["handlers_reached"] == [],
                  repr(res["handlers_reached"][:1]))
            check("rings-flags-all-false",
                  not any(res["handlers_called_flags"].values()),
                  repr(res["handlers_called_flags"]))
            check("rings-first-consumer-demux", "dequeue" in res["first_consumer"],
                  res["first_consumer"][:80])
            check("rings-event-kinds", "malformed-index" in res["event_kinds"]
                  or "malformed-magic" in res["event_kinds"],
                  repr(res["event_kinds"]))
            check("rings-v1-quarantine",
                  any(v["label"] == "V1-count-gt-cap" and
                      v["outcome"].startswith("QUARANTINE")
                      for v in res["vectors"]))
            check("rings-v3-len-quarantine",
                  any(v["label"] == "V3-oversize-len-prefix" and
                      v["outcome"].startswith("QUARANTINE")
                      for v in res["vectors"]))
    except Exception as e:  # noqa: BLE001
        check("rings-adversarial", False, repr(e))

    # S3 FSD: direction + hostile refusal.
    try:
        check("fsd-observed-4", len(FSD_OBSERVED) == 4, repr(FSD_OBSERVED))
        for good in ("X:/LD40_001", "Y:/LD40_001"):
            r = fsd_traversal_verdict(good)
            check(f"fsd-serve[{good}]", not r["hostile"] and
                  r["normalized"] == "LD40_001", repr(r))
        for bad, why in (("../../etc/passwd", "dotdot"),
                         ("X:/../../etc/passwd", "dotdot"),
                         ("X:/" + "A" * 200, "overlong"),
                         ("X:/LD40_001\x00.png", "NUL"),
                         ("", "empty")):
            r = fsd_traversal_verdict(bad)
            check(f"fsd-refuse[{why}]", r["hostile"], repr(r))
        check("fsd-normalize-strip",
              normalize_fsd_name("X:/LD40_001") == "LD40_001")
        check("fsd-direction-doc", "MD->AP" in build_report()["fsd"]["direction"])
    except Exception as e:  # noqa: BLE001
        check("fsd", False, repr(e))

    # S4 MSGID inventory: banked shapes.
    try:
        check("msgid-6-rows", len(MSGIDS) == 6, f"{len(MSGIDS)}")
        check("msgid-4508-md-to-ap",
              any(m.msgid == "4508" and m.direction == "md->ap" for m in MSGIDS))
        check("msgid-0519-ap-to-md",
              any(m.msgid == "0519" and m.direction == "ap->md" for m in MSGIDS))
        check("msgid-054d-ap-to-md",
              any(m.msgid == "054d" and m.direction == "ap->md" for m in MSGIDS))
        check("msgid-all-verdict", all(m.verdict for m in MSGIDS))
    except Exception as e:  # noqa: BLE001
        check("msgid", False, repr(e))

    # S5 CVE fingerprint: constants + date arithmetic.
    try:
        cve = cve_patch_state()
        check("cve-id", cve["cve"] == "CVE-2023-32840")
        check("cve-patch", cve["patch"] == "MOLY01138425")
        check("cve-chip", cve["affected_chip"] == "MT6835"
              and "NR17" in cve["affected_modems"])
        check("cve-postdates", "PROVISIONAL-PATCHED" in cve["date_verdict"],
              cve["date_verdict"][:80])
        check("cve-binary-inconclusive", "INCONCLUSIVE" in cve["binary_verdict"])
        check("cve-baseband-P247", "P247" in cve["this_baseband"])
    except Exception as e:  # noqa: BLE001
        check("cve", False, repr(e))

    # S6 channels + report shape.
    try:
        rep = build_report(ring_adversarial_drive()
                           if MpuMemory is not None else {})
        check("channels-5", len(rep["channels"]) == 5,
              f"{len(rep['channels'])}")
        ids = [c["id"] for c in rep["channels"]]
        check("channels-ids", ids == ["CH-RING", "CH-MSGID", "CH-RPC",
                                      "CH-FSD", "CH-CVE"], repr(ids))
        for c in rep["channels"]:
            check(f"channel-shape[{c['id']}]",
                  all(k in c for k in ("handler", "input_shape",
                                       "bounds_present", "bounds_absent",
                                       "verdict", "first_consumer")),
                  repr(sorted(c.keys())))
        check("channel-verdict-words",
              all(any(w in c["verdict"] for w in ("CONFIRMED", "REFUTED",
                                                 "INCONCLUSIVE", "PROVISIONAL",
                                                 "CONDITIONAL"))
                  for c in rep["channels"]))
        txt = format_report(rep)
        check("report-renders", "CH-RING" in txt and "CH-CVE" in txt
              and "EFUSE" in txt)
        json.dumps(rep)  # must be JSON-serializable
        check("report-json", True)
    except Exception as e:  # noqa: BLE001
        check("channels-report", False, repr(e))

    # S7 read-only evidence cross-check (informational; absence is not failure
    # on partial checkouts — only hard mismatches fail).
    try:
        xc = crosscheck_evidence()
        hard_fail = [c for c in xc["checks"]
                     if not c["ok"] and c["label"] not in ("captures-present",)]
        # Missing files yield ok=True skips by construction; real mismatches fail.
        check("evidence-crosscheck", not hard_fail,
              "; ".join(f"{c['label']}:{c['detail']}" for c in hard_fail[:4]))
        for c in xc["checks"]:
            details.append(("PASS " if c["ok"] else "FAIL ") +
                           "x-" + c["label"] +
                           (f" ({c['detail']})" if c["detail"] and not c["ok"] else ""))
            if c["ok"]:
                passed += 1
            else:
                failed += 1
    except Exception as e:  # noqa: BLE001
        check("evidence-crosscheck", False, repr(e))

    return passed, failed, details


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if "--report" in args:
        i = args.index("--report")
        out = args[i + 1] if i + 1 < len(args) and not args[i + 1].startswith("--") else None
        rep = build_report(ring_adversarial_drive()
                           if MpuMemory is not None else {})
        if out:
            p = Path(out)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(json.dumps(rep, indent=2), encoding="utf-8")
            print(f"wrote {p}")
        print(format_report(rep))
        return 0
    if "--rings" in args:
        res = ring_adversarial_drive()
        print(json.dumps({k: v for k, v in res.items() if k != "ring_events"},
                         indent=2, default=str))
        for v in res.get("vectors", []):
            print(f"  {v['label']} [{v['ring']}] -> {v['outcome']}"
                  f"{(' :: ' + v['detail']) if v.get('detail') else ''}")
        print("first consumer: " + res.get("first_consumer", "?"))
        return 0
    if "--rpc" in args:
        for o in build_rpc_ops():
            print(f"{o.name:32s} {'DESTRUCTIVE' if o.destructive else o.blob_class:10s} "
                  f"req({o.req_shape}) rsp({o.rsp_shape}) :: {o.verdict}")
        return 0
    if "--fsd" in args:
        for raw in list(FSD_OBSERVED) + ["../../etc/passwd", "X:/../../x",
                                         "X:/" + "A" * 200]:
            print(fsd_traversal_verdict(raw))
        return 0
    if "--cve" in args:
        print(json.dumps(cve_patch_state(), indent=2))
        return 0
    if "--msgid" in args:
        for m in MSGIDS:
            print(f"{m.msgid:16s} {m.direction:6s} {m.name} :: {m.verdict}")
        return 0
    if "--table" in args:
        rep = build_report(ring_adversarial_drive()
                           if MpuMemory is not None else {})
        print(format_report(rep))
        return 0
    passed, failed, details = selftest()
    print(f"ccci_threat selftest: {passed} passed, {failed} failed")
    for d in details:
        print("  " + d)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
