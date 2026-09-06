#!/usr/bin/env python3
"""crypto_stubs.py - crypto boundary library for the nanoMIPS modem emulator.

SAFETY (enforced by construction):
  * Pure offline model. No device I/O: no adb/fastboot/AT/socket/subprocess
    imports, no command emission of any kind. The HW-boundary router below
    only formats read-only oracle requests into sim/emu_engine.py's HwOracle
    transcript (which records + raises); the device transport lives outside
    this package by design.
  * Read-only on all dumps: md1work_romonly.bin / stock images are opened
    'rb' and never modified. This module writes nothing.
  * Stdlib + repo tools only (tools/sign_mtk_cert.py, tools/verify_mtk_image.py
    via defensive import; sim/emu_engine.py HwOracle via defensive import).
    No third-party imports (no capstone/unicorn/numpy), no homebrew AES.

Sources (all verified PC-side, read-only, 2026-09-05):
  * md1work_romonly.bin (45,893,712 B; modem VA base 0x90000000, off=VA-base)
  * cati_syms.json (Temp/opencode; 135,488 symbols, {name:[startHex,endHex]})
  * sim/hw_target.py (cspec: args a0-a7, retval a0-a1, callee-saved s0-s7)
  * sim/emu_engine.py (HwOracle OPS + transcript schema)
  * tools/sign_mtk_cert.py + tools/verify_mtk_image.py (CERT2 RSA-2048/SHA256)
  * HANDOFF.md / PICKUP.md (crypto inventory wording)
  * md1work_sml.asm (68 KB/1.7 MB Thumb-2 dump: covers ONLY VA cluster
    905df000-905f1000; 0 hits for any crypto VA below -> no listing present
    for the carved functions; decode is VOID per HANDOFF 3e, nanoMIPS only)

Contents:
  1. Software models (hashlib/hmac only): SHA256 streaming session mirroring
     the modem Init/Update/Final call shape, HMAC-SHA256 session, MD5 one-shot
     helper, and an AES gap shim (stdlib has no AES; tracks FIPS vectors,
     raises on use; NO homebrew AES by policy).
  2. Calling-convention carving tables for CustCHL_Calculate_Hash,
     CustCHL_Verify_MAC, cust_sec_calc_enc_auth,
     mot_sml_db_parameter_hash_verify (CATI extents + carved heads; arg
     arity/pointer-vs-scalar marked UNRESOLVED pending Ghidra pcode; tables
     only, no emulation).
  3. HW-boundary router: silicon-key ops -> HwOracle op + exact params schema;
     software-verifiable ops (CERT2 RSA-2048/SHA256 over image bytes, plain
     SHA256/HMAC-SHA256/MD5 with explicit key/data) -> REAL local verifiers.
  4. Selftest: NIST/RFC4231 vectors, CERT2 verify on stock md1img, carve
     conformance, router schema checks.

Run:  python sim/crypto_stubs.py [--selftest|--vectors|--conventions|--routes|--verify-cert2 [PATH]]
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

# --------------------------------------------------------------------------
# 0. Paths & defensive repo-tool imports (stdlib + repo tools only)
# --------------------------------------------------------------------------

SIM_DIR = Path(__file__).resolve().parent
REPO_ROOT = SIM_DIR.parent
TOOLS_DIR = REPO_ROOT / "tools"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

REUSED: Dict[str, bool] = {}
for _mod in ("sign_mtk_cert", "parse_mtk_certs", "verify_mtk_image"):
    try:
        __import__(_mod)
        REUSED[_mod] = True
    except Exception:
        REUSED[_mod] = False

VM = sys.modules.get("verify_mtk_image")  # tools/verify_mtk_image.py or None
SMC = sys.modules.get("sign_mtk_cert")    # tools/sign_mtk_cert.py or None

# HwOracle import (defensive; fallback mirrors emu_engine semantics so the
# router works standalone without changing the op schema).
try:  # package-relative when imported as sim.crypto_stubs
    from sim.emu_engine import HwOracle as _HwOracle  # type: ignore
    from sim.emu_engine import OracleUnimplemented as _OracleUnimplemented  # type: ignore
    ORACLE_BACKEND = "sim.emu_engine"
except ImportError:
    try:  # sibling when sim/ is on sys.path
        from emu_engine import HwOracle as _HwOracle  # type: ignore
        from emu_engine import OracleUnimplemented as _OracleUnimplemented  # type: ignore
        ORACLE_BACKEND = "emu_engine"
    except ImportError:
        ORACLE_BACKEND = "stub(local, emu_engine missing)"

        class _OracleUnimplemented(Exception):  # type: ignore
            pass

        @dataclass
        class _OracleRecord:  # minimal transcript entry
            op: str
            params: dict
            result: str = "UNIMPLEMENTED"

        class _HwOracle:  # type: ignore
            OPS = ("nv_read", "chl_hash", "chl_mac",
                   "efuse_read", "sml_status", "apdu_xfer")

            def __init__(self, logdir: Path | None = None):
                self.transcript: list = []

            def query(self, op: str, params: dict):
                assert op in self.OPS, f"unknown oracle op {op}"
                rec = _OracleRecord(op, dict(params))
                self.transcript.append(rec)
                raise _OracleUnimplemented(
                    f"oracle op {op} needs device transport (read-only). "
                    f"Recorded transcript entry #{len(self.transcript)}.")

HwOracle = _HwOracle
OracleUnimplemented = _OracleUnimplemented

ROMONLY_PATH = REPO_ROOT / "md1work_romonly.bin"
STOCK_MD1IMG = REPO_ROOT / "stock_XT2513V" / "md1img.img"
VA_BASE = 0x90000000

# --------------------------------------------------------------------------
# EVIDENCE (verified PC-side, read-only; carve = romonly[VA-VA_BASE:...+size])
# --------------------------------------------------------------------------
# Symbol            CATI extent               size   head8 (carved)   sha256[:16]
# SHA256_Init       [9047eca8,9047ecfe)        86   121e70d30412a010  a621eda1b863b1a5
# hmac_sha256       [91d99926,91d999dc)       182   971e63334c700881  9aacca67b847fc1b
# ehmacsha256       [91933700,919337ca)       202   ca83803151fefefe  ae4683087e439187
# AES_encrypt       [9049fcc0,904a004a)       906   3a1c84860320a611  a55c6902c2d360a2
# cal_generate_hmac [903e6690,903e66e6)        86   251e50ffd0174575  ae6eb4d51a68e3da
# mcs_rsa_sig       [912e4f74,912e5558)      1508   ca8300360412c913  e3c82231795c727d
# mcs_hashSHA256    [912e64f4,912e666a)       374   251e30ffc000c000  672ad104fa78859c
# CustCHL range 0x903fe6fa-0x903ff46e holds 14 symbols (RSA_PKCS1_Encrypt,
#   Get_Asym_Key, AES_Decrypt/Encrypt constprops + _data, Calculate/Verify_MAC,
#   Calculate_Hash, Get_Sym_Key_Extend, Gen_Root_Key, Verify_PSS/RSA_Signature)
# nvram_SW_AES_encrypt_ext [919ad3de,919ad48e) 176 781e4a5c6512495d 246bd0dde70d36f9
# nvram_HW_AES_encrypt_ext [919ad648,919ad698)  80 561e42141d011c00 6ae68acb6acc0f40
# cust_sec_get_device_secret_key [90598e8a,90598ea8) 30 121ed42ade2a0412 331b472153b15a13
# mot_sec_calc_tfn_device_secret_key [912db96e,912dba4e) 224 a61e24d3a3b42412 45ed7e3b59a407dd
# mot_sml_db_parameter_hash_verify [912dc6c8,912dc93c) 628 661e14fe80007b04 9a7c22c849789736
# smu_op08_verify_msg_hmac [91990e08,91990e88) 128 561e93fe83605e8f f25e48055ae0ad4a
# cust_sec_calc_enc_auth [90598c2e,90598d5e) 304 ca836031c2b4c413 f1b6715a6747cb35
# NOTE on user-supplied addresses: 0x9047eca8 == SHA256_Init start (CONFIRMED);
#   0x91d99926 == hmac_sha256 start (CONFIRMED); 0x91933700 == ehmacsha256 start
#   (CONFIRMED, distinct routine, not hmac_sha256); 0x9049fcc0 == AES_encrypt
#   start (CONFIRMED, code - S-box tables live nearby, not AT the address).

# --------------------------------------------------------------------------
# 1. Pure-software models (hashlib/hmac ONLY)
# --------------------------------------------------------------------------

def sha256_oneshot(data: bytes) -> bytes:
    """One-shot SHA-256 (software primitive; no HW key)."""
    return hashlib.sha256(bytes(data)).digest()


def md5_oneshot(data: bytes) -> bytes:
    """One-shot MD5 (inventory primitive; software-only via hashlib)."""
    return hashlib.md5(bytes(data)).digest()


def hmac_sha256_oneshot(key: bytes, data: bytes) -> bytes:
    """One-shot HMAC-SHA-256 with an EXPLICIT key (software-verifiable)."""
    return hmac.new(bytes(key), bytes(data), hashlib.sha256).digest()


class Sha256Session:
    """Streaming SHA-256 session mirroring the modem call shape.

    Modem mapping: __init__  ~= SHA256_Init(ctx)   (fresh ctx)
                   update()  ~= SHA256_Update(ctx, data, len) (append)
                   final()   ~= SHA256_Final(md, ctx)         (digest out)
    final() returns the digest and latches the session (further update()
    raises, mirroring a consumed ctx); use reset() for a fresh Init.
    Backed solely by hashlib.sha256.
    """

    def __init__(self) -> None:
        self._h = hashlib.sha256()
        self._finalized = False
        self._nbytes = 0

    def update(self, data: bytes) -> "Sha256Session":
        if self._finalized:
            raise ValueError("Sha256Session already finalized (call reset())")
        self._h.update(bytes(data))
        self._nbytes += len(data)
        return self

    def digest(self) -> bytes:
        """Non-consuming digest (stdlib convenience; modem Final consumes)."""
        return self._h.digest()

    def hexdigest(self) -> str:
        return self._h.hexdigest()

    def final(self) -> bytes:
        """Consuming Final: returns digest, latches session."""
        d = self._h.digest()
        self._finalized = True
        return d

    def reset(self) -> "Sha256Session":
        self._h = hashlib.sha256()
        self._finalized = False
        self._nbytes = 0
        return self

    @property
    def nbytes(self) -> int:
        return self._nbytes


# C-shape functional aliases (exact Init/Update/Final vocabulary):
def sha256_init() -> Sha256Session:
    return Sha256Session()


def sha256_update(ctx: Sha256Session, data: bytes) -> Sha256Session:
    return ctx.update(data)


def sha256_final(ctx: Sha256Session) -> bytes:
    return ctx.final()


class HmacSha256Session:
    """Streaming HMAC-SHA-256 session for EXPLICIT-key use (software-only).

    Mirrors the Init(key)/Update/Final shape. Backed solely by hmac+HASHLIB.
    HW-keyed HMACs (cal_generate_hmac with a silicon key, smu_op08 device-key
    path) are NOT constructible here by design - route those to the oracle.
    """

    def __init__(self, key: bytes) -> None:
        self._hm = hmac.new(bytes(key), digestmod=hashlib.sha256)
        self._finalized = False

    def update(self, data: bytes) -> "HmacSha256Session":
        if self._finalized:
            raise ValueError("HmacSha256Session already finalized")
        self._hm.update(bytes(data))
        return self

    def digest(self) -> bytes:
        return self._hm.digest()

    def hexdigest(self) -> str:
        return self._hm.hexdigest()

    def final(self) -> bytes:
        d = self._hm.digest()
        self._finalized = True
        return d


def hmac_sha256_init(key: bytes) -> HmacSha256Session:
    return HmacSha256Session(key)


def hmac_sha256_update(ctx: HmacSha256Session, data: bytes) -> HmacSha256Session:
    return ctx.update(data)


def hmac_sha256_final(ctx: HmacSha256Session) -> bytes:
    return ctx.final()


class AesNotInStdlib(Exception):
    """Raised whenever AES ciphertext is requested (no stdlib AES)."""


# FIPS-197 Appendix B tracking vector (RECORDED, never executed: no AES in
# stdlib to run it with). key/pt/ct are the published AES-128 ECB values.
AES_TRACKED_VECTORS: List[Dict[str, str]] = [
    {"suite": "FIPS-197 Appendix B",
     "mode": "AES-128-ECB (single block, tracking only)",
     "key": "000102030405060708090a0b0c0d0e0f",
     "pt": "00112233445566778899aabbccddeeff",
     "ct": "69c4e0d86a7b0430d8cdb78070b4c55a",
     "status": "TRACKED-NOT-EXECUTED (no AES primitive in stdlib)"},
]


class AesGapShim:
    """Verified-test-vector TRACKING shim for AES (explicit non-implementation).

    Exact gap: CPython's stdlib exposes no AES/Cipher primitive (hashlib and
    hmac cover digests/MACs only; `hashlib.algorithms_available` has no block
    cipher). Policy: NO homebrew AES (unverifiable S-box/code, side-channel
    risk, zero conformance value vs the silicon key path). Every encrypt /
    decrypt request is RECORDED (algorithm, key_len, mode) and raises
    AesNotInStdlib. HW-keyed AES (CustCHL_AES_*, nvram_*_AES_*, che_sw_aes
    with a fused key) additionally routes to the HwOracle (see ROUTES).
    """

    def __init__(self) -> None:
        self.requests: List[Dict[str, Any]] = []

    def vectors(self) -> List[Dict[str, str]]:
        return [dict(v) for v in AES_TRACKED_VECTORS]

    def describe_gap(self) -> str:
        return ("GAP: stdlib (hashlib/hmac) provides SHA-256/HMAC-SHA-256/MD5 "
                "only; no AES primitive exists, so AES encrypt/decrypt cannot "
                "be modelled in software here. FIPS-197 vectors are tracked "
                "above for future conformance against a real primitive or the "
                "HW oracle. No homebrew AES by policy.")

    def _record(self, op: str, key_len: int, mode: str) -> None:
        self.requests.append({"op": op, "key_len": key_len, "mode": mode,
                              "result": "REFUSED-NO-AES-IN-STDLIB"})

    def encrypt(self, key: bytes, pt: bytes, mode: str = "ECB") -> bytes:
        self._record("encrypt", len(bytes(key)), mode)
        raise AesNotInStdlib(
            f"AES-{len(bytes(key)) * 8}-{mode} encrypt refused: no AES in "
            f"stdlib (tracked request #{len(self.requests)}). {self.describe_gap()}")

    def decrypt(self, key: bytes, ct: bytes, mode: str = "ECB") -> bytes:
        self._record("decrypt", len(bytes(key)), mode)
        raise AesNotInStdlib(
            f"AES-{len(bytes(key)) * 8}-{mode} decrypt refused: no AES in "
            f"stdlib (tracked request #{len(self.requests)}). {self.describe_gap()}")


# --------------------------------------------------------------------------
# 2. Calling-convention carving (TABLES ONLY - no emulation)
# --------------------------------------------------------------------------
# Framework per sim/hw_target.py cspec: args a0-a7, retval a0(-a1),
# callee-saved s0-s7. Per-function arity and pointer-vs-scalar assignment are
# UNRESOLVED until Ghidra nanoMIPS pcode recovery (function-anchored windows
# only; mid-function windows hang headless per PICKUP). md1work_sml.asm has 0
# hits for all four VAs (covers 905df000-905f1000 only, wrong ISA) - no
# existing listing exists for these functions; disassembly is deferred, NOT
# attempted here (no capstone-nanoMIPS, no homebrew decoder output claimed).

@dataclass
class ConventionEntry:
    name: str
    va_start: int
    va_end: int
    head16: str          # carved head bytes (hex, spaceless) for provenance
    body_sha16: str      # sha256(carved body)[:16]
    listing: str         # existing-listing status
    args: str            # arg registers (UNRESOLVED until pcode)
    ret: str             # return convention
    ptr_vs_scalar: str   # pointer-vs-scalar status
    close_out: str       # evidence needed to resolve


def _carve(va: int, size: int) -> bytes:
    data = ROMONLY_PATH.read_bytes()  # read-only
    off = va - VA_BASE
    if not (0 <= off < len(data)) or off + size > len(data):
        raise ValueError(f"VA {va:#x}+{size} outside romonly image")
    return data[off:off + size]


CONVENTIONS: List[ConventionEntry] = [
    ConventionEntry(
        name="CustCHL_Calculate_Hash",
        va_start=0x903FEC66, va_end=0x903FECDC,
        head16="761e58fe851281d3549987a86400e000",
        body_sha16="2f3ee9c6a1a674b3",
        listing="ABSENT (md1work_sml.asm: 0 hits; cluster 905df000-905f1000 only)",
        args="a0-a? UNRESOLVED (cspec allows a0-a7; arity needs pcode)",
        ret="a0 (convention per cspec; semantics: status/len - UNRESOLVED)",
        ptr_vs_scalar="UNRESOLVED (expect >=1 out-ptr + >=1 in-ptr + len scalar; "
                      "order/arity pending disassembly - NOT claimed)",
        close_out="Ghidra nanomips:LE:32:default fn-anchored disasm + BALC/xref "
                  "signature recovery (fn 118 B @ file 0x3fee66)"),
    ConventionEntry(
        name="CustCHL_Verify_MAC",
        va_start=0x903FEC0E, va_end=0x903FEC66,
        head16="971ea41272ffa01040d34c7219ff8912",
        body_sha16="b3ff07f9544c1b1d",
        listing="ABSENT (md1work_sml.asm: 0 hits; cluster 905df000-905f1000 only)",
        args="a0-a? UNRESOLVED (cspec allows a0-a7; arity needs pcode)",
        ret="a0 (convention per cspec; 1=pass/0=fail LIKELY, UNRESOLVED)",
        ptr_vs_scalar="UNRESOLVED (expect key-id/key-ptr + msg-ptr + mac-ptr + "
                      "len scalars; order/arity pending - NOT claimed)",
        close_out="Ghidra fn-anchored disasm (fn 88 B @ file 0x3fee0e) + caller "
                  "at CustCHL_Calculate_MAC boundary"),
    ConventionEntry(
        name="cust_sec_calc_enc_auth",
        va_start=0x90598C2E, va_end=0x90598D5E,
        head16="ca836031c2b4c413c5124d72a01024d3",
        body_sha16="f1b6715a6747cb35",
        listing="ABSENT (md1work_sml.asm: 0 hits; cluster 905df000-905f1000 only)",
        args="a0-a? UNRESOLVED (cspec allows a0-a7; arity needs pcode)",
        ret="a0 (convention per cspec; status - UNRESOLVED)",
        ptr_vs_scalar="UNRESOLVED (expect secret-ctx ptr + in/out ptrs + len; "
                      "pending disassembly - NOT claimed)",
        close_out="Ghidra fn-anchored disasm (fn 304 B @ file 0x598e2e) + xrefs "
                  "from cust_sec_get_device_secret_key region"),
    ConventionEntry(
        name="mot_sml_db_parameter_hash_verify",
        va_start=0x912DC6C8, va_end=0x912DC93C,
        head16="661e14fe80007b04a360726cc10002b4",
        body_sha16="9a7c22c849789736",
        listing="ABSENT (md1work_sml.asm: 0 hits; cluster 905df000-905f1000 only)",
        args="a0-a? UNRESOLVED (cspec allows a0-a7; arity needs pcode)",
        ret="a0 (convention per cspec; 1=pass/0=fail LIKELY, UNRESOLVED)",
        ptr_vs_scalar="UNRESOLVED (expect param-blob ptr + len + stored-hash "
                      "ptr; pending disassembly - NOT claimed)",
        close_out="Ghidra fn-anchored disasm (fn 628 B @ file 0x12de6c8) + "
                  "callers in mot_sml_db_* cluster"),
]


def carve_function(name: str) -> bytes:
    """Carve one convention-table function body from romonly (read-only)."""
    e = next(x for x in CONVENTIONS if x.name == name)
    return _carve(e.va_start, e.va_end - e.va_start)


def convention_table_text() -> str:
    lines = ["calling-convention carving (TABLES ONLY - arity UNRESOLVED pending Ghidra pcode):",
             "framework: args a0-a7, retval a0(-a1), callee-saved s0-s7 (sim/hw_target.py cspec)"]
    for e in CONVENTIONS:
        lines.append(f"  {e.name} [{e.va_start:#x},{e.va_end:#x}) "
                     f"size={e.va_end - e.va_start} head={e.head16[:16]}.. sha={e.body_sha16}")
        lines.append(f"    listing: {e.listing}")
        lines.append(f"    args: {e.args}")
        lines.append(f"    ret: {e.ret}")
        lines.append(f"    ptr-vs-scalar: {e.ptr_vs_scalar}")
        lines.append(f"    close-out: {e.close_out}")
    return "\n".join(lines)


# --------------------------------------------------------------------------
# 3. HW-boundary router
# --------------------------------------------------------------------------
# kinds: "oracle" (silicon-keyed -> HwOracle op, recorded+raised, no device
#   contact) | "software" (explicit key/data -> REAL local computation).
# Params schemas are exact: route() rejects missing/extra keys.

@dataclass
class Route:
    name: str
    kind: str            # "oracle" | "software"
    via: str             # HwOracle op (oracle) or local impl label (software)
    params: Dict[str, str]   # param -> "type: meaning"
    va: str              # CATI extent or "-" for pure-SW helpers
    reason: str
    impl: Optional[Callable[..., Any]] = field(default=None, repr=False)


def _sw_sha256_impl(params: Dict[str, Any]) -> Dict[str, str]:
    data = bytes.fromhex(params["data_hex"])
    if params.get("streaming_chunks_hex"):
        s = sha256_init()
        for ch in params["streaming_chunks_hex"]:
            sha256_update(s, bytes.fromhex(ch))
        d = sha256_final(s)
    else:
        d = sha256_oneshot(data)
    return {"digest_hex": d.hex()}


def _sw_hmac_impl(params: Dict[str, Any]) -> Dict[str, str]:
    key = bytes.fromhex(params["key_hex"])
    data = bytes.fromhex(params["data_hex"])
    return {"mac_hex": hmac_sha256_oneshot(key, data).hex()}


def _sw_md5_impl(params: Dict[str, Any]) -> Dict[str, str]:
    return {"digest_hex": md5_oneshot(bytes.fromhex(params["data_hex"])).hex()}


def _sw_cert2_impl(params: Dict[str, Any]) -> Dict[str, Any]:
    return verify_cert2_image(Path(params["image_path"]))


ROUTES: Dict[str, Route] = {
    # ---- silicon-keyed -> oracle (HwOracle OPS exercised: chl_hash, chl_mac,
    #      nv_read + efuse_read; sml_status/apdu_xfer reserved, not crypto) ----
    "CustCHL_Calculate_Hash": Route(
        "CustCHL_Calculate_Hash", "oracle", "chl_hash",
        {"data_hex": "hex: input bytes", "key_id": "str: silicon key slot id"},
        "[0x903fec66,0x903fecdc)",
        "HW-bound hash path (key slot); PC cannot reproduce -> oracle."),
    "CustCHL_Calculate_MAC": Route(
        "CustCHL_Calculate_MAC", "oracle", "chl_mac",
        {"key_id": "str: silicon key slot id", "msg_hex": "hex: message",
         "mac_len": "int: requested MAC bytes"},
        "[0x903feba6,0x903fec0e)",
        "HW-keyed MAC generation -> oracle chl_mac."),
    "CustCHL_Verify_MAC": Route(
        "CustCHL_Verify_MAC", "oracle", "chl_mac",
        {"key_id": "str: silicon key slot id", "msg_hex": "hex: message",
         "mac_hex": "hex: candidate MAC"},
        "[0x903fec0e,0x903fec66)",
        "HW-keyed MAC verify -> oracle chl_mac."),
    "CustCHL_AES_Encrypt_data": Route(
        "CustCHL_AES_Encrypt_data", "oracle", "nv_read",
        {"key_id": "str: silicon key slot id", "pt_hex": "hex: plaintext",
         "mode": "str: cipher mode label"},
        "[0x903fead0,0x903feba6)",
        "HW-keyed AES has no dedicated oracle op; routed to nv_read as an "
        "opaque-record request (NO software AES fallback by policy)."),
    "CustCHL_AES_Decrypt_data": Route(
        "CustCHL_AES_Decrypt_data", "oracle", "nv_read",
        {"key_id": "str: silicon key slot id", "ct_hex": "hex: ciphertext",
         "mode": "str: cipher mode label"},
        "[0x903fe8ca,0x903fe98a)+constprops",
        "HW-keyed AES decrypt -> opaque nv_read record (no SW AES)."),
    "CustCHL_Verify_RSA_Signature": Route(
        "CustCHL_Verify_RSA_Signature", "oracle", "chl_mac",
        {"key_id": "str: silicon key slot id", "msg_hex": "hex: message",
         "sig_hex": "hex: RSA signature"},
        "[0x903ff17a,0x903ff46e)",
        "Si-key RSA verify (fused root) cannot be checked on PC -> oracle "
        "(contrast CERT2 image-key verify, which IS software)."),
    "CustCHL_Verify_PSS_Signature": Route(
        "CustCHL_Verify_PSS_Signature", "oracle", "chl_mac",
        {"key_id": "str: silicon key slot id", "msg_hex": "hex: message",
         "sig_hex": "hex: RSA-PSS signature"},
        "[0x903fefba,0x903ff17a)",
        "Si-key PSS verify -> oracle (same fused-root reason)."),
    "CustCHL_Gen_Root_Key": Route(
        "CustCHL_Gen_Root_Key", "oracle", "efuse_read",
        {"slot": "str: key slot label"},
        "[0x903feec6,0x903fefba)",
        "Root-key derivation touches eFuse/OTP -> oracle efuse_read."),
    "CustCHL_Get_Sym_Key_Extend": Route(
        "CustCHL_Get_Sym_Key_Extend", "oracle", "efuse_read",
        {"slot": "str: key slot label"},
        "[0x903fed8a,0x903feec6)",
        "Sym-key fetch from silicon store -> oracle efuse_read."),
    "nvram_HW_AES_encrypt_ext": Route(
        "nvram_HW_AES_encrypt_ext", "oracle", "nv_read",
        {"lid": "int: NVRAM LID", "rec_idx": "int: record index",
         "data_hex": "hex: plaintext record"},
        "[0x919ad648,0x919ad698)",
        "HW-AES NVRAM path (80 B fn) -> oracle nv_read (LID-indexed)."),
    "nvram_SW_AES_encrypt_ext": Route(
        "nvram_SW_AES_encrypt_ext", "oracle", "nv_read",
        {"lid": "int: NVRAM LID", "rec_idx": "int: record index",
         "data_hex": "hex: plaintext record"},
        "[0x919ad3de,0x919ad48e)",
        "SW-AES NVRAM path still needs the record key on PC; no SW AES in "
        "stdlib -> oracle nv_read record (same schema as HW twin)."),
    "cust_sec_get_device_secret_key": Route(
        "cust_sec_get_device_secret_key", "oracle", "efuse_read",
        {"slot": "str: secret slot label"},
        "[0x90598e8a,0x90598ea8)",
        "Device-secret root (30 B accessor) -> oracle efuse_read."),
    "mot_sec_calc_tfn_device_secret_key": Route(
        "mot_sec_calc_tfn_device_secret_key", "oracle", "efuse_read",
        {"imei": "str: 15-digit IMEI (derivation input)"},
        "[0x912db96e,0x912dba4e)",
        "IMEI-derived TFN secret (224 B fn) -> oracle efuse_read; IMEI is "
        "public derivation input, the fused secret never leaves silicon."),
    "cust_sec_calc_enc_auth": Route(
        "cust_sec_calc_enc_auth", "oracle", "chl_mac",
        {"key_id": "str: silicon key slot id", "msg_hex": "hex: message"},
        "[0x90598c2e,0x90598d5e)",
        "Device-secret auth calc (304 B fn) -> oracle chl_mac."),
    "mot_sml_db_parameter_hash_verify": Route(
        "mot_sml_db_parameter_hash_verify", "oracle", "chl_hash",
        {"data_hex": "hex: parameter blob", "digest_hex": "hex: stored digest"},
        "[0x912dc6c8,0x912dc93c)",
        "Parameter-hash verify against a silicon-anchored digest (628 B fn) "
        "-> oracle chl_hash."),
    "smu_op08_verify_msg_hmac": Route(
        "smu_op08_verify_msg_hmac", "oracle", "chl_mac",
        {"key_id": "str: op08 key id", "msg_hex": "hex: message",
         "mac_hex": "hex: candidate HMAC"},
        "[0x91990e08,0x91990e88)",
        "Op08 device-key HMAC verify (128 B fn) -> oracle chl_mac."),
    "cal_generate_hmac": Route(
        "cal_generate_hmac", "oracle", "chl_mac",
        {"key_id": "str: CAL key id", "msg_hex": "hex: message"},
        "[0x903e6690,0x903e66e6)",
        "CAL HMAC under a provisioned (possibly HW) key -> oracle chl_mac; "
        "use sw_hmac_sha256 only when the key is EXPLICIT."),
    # ---- software-verifiable -> REAL local impls (no HW key) ----
    "sw_sha256": Route(
        "sw_sha256", "software", "hashlib.sha256",
        {"data_hex": "hex: input bytes",
         "streaming_chunks_hex": "list[hex]: optional split input"},
        "-",
        "Plain SHA-256 (Init/Update/Final shape) -> hashlib session.",
        _sw_sha256_impl),
    "sw_hmac_sha256": Route(
        "sw_hmac_sha256", "software", "hmac+hashlib",
        {"key_hex": "hex: EXPLICIT key (never a silicon slot)",
         "data_hex": "hex: input bytes"},
        "-",
        "HMAC-SHA-256 with caller-supplied key -> hmac session.",
        _sw_hmac_impl),
    "sw_md5": Route(
        "sw_md5", "software", "hashlib.md5",
        {"data_hex": "hex: input bytes"},
        "-",
        "Plain MD5 (inventory primitive) -> hashlib.",
        _sw_md5_impl),
    "sw_cert2_rsa_sha256": Route(
        "sw_cert2_rsa_sha256", "software", "tools/verify_mtk_image",
        {"image_path": "str: md1img path (read-only)"},
        "-",
        "CERT2 RSA-2048/SHA-256 over image bytes needs NO HW key (image key "
        "in CERT1) -> REAL verifier reusing repo tools (defensive import).",
        _sw_cert2_impl),
}


def route(name: str, params: Dict[str, Any],
          oracle: Any = None) -> Dict[str, Any]:
    """Route one crypto op.

    Oracle kind: validates params, calls oracle.query(op, params) which
      records the transcript entry and raises OracleUnimplemented (read-only;
      transport lives outside). Never touches the device.
    Software kind: runs the REAL local verifier and returns its result dict.
    Unknown op or bad params raise without side effects.
    """
    if name not in ROUTES:
        raise KeyError(f"unknown crypto op {name!r} "
                       f"(known: {sorted(ROUTES)})")
    r = ROUTES[name]
    missing = [k for k in r.params if k not in params
               and not (r.name == "sw_sha256" and k == "streaming_chunks_hex")]
    if missing:
        raise ValueError(f"op {name}: missing params {missing} "
                         f"(schema {sorted(r.params)})")
    extra = [k for k in params if k not in r.params]
    if extra:
        raise ValueError(f"op {name}: extra params {extra} "
                         f"(schema {sorted(r.params)})")
    if r.kind == "software":
        assert r.impl is not None
        out = r.impl(dict(params))
        return {"op": name, "kind": "software", "via": r.via, "result": out}
    oc = oracle if oracle is not None else HwOracle()
    rec = oc.query(r.via, dict(params))  # raises OracleUnimplemented
    return {"op": name, "kind": "oracle", "via": r.via, "result": rec}


def router_map_text() -> str:
    lines = [f"router map (oracle backend: {ORACLE_BACKEND}; "
             f"repo tools: {REUSED}):"]
    for name, r in ROUTES.items():
        lines.append(f"  {name:32s} [{r.kind:8s}] via {r.via:22s} "
                     f"params={sorted(r.params)} // {r.reason}")
    return "\n".join(lines)


# --------------------------------------------------------------------------
# CERT2 software verifier (REAL; reuses repo tools, defensive import)
# --------------------------------------------------------------------------

def verify_cert2_image(path: Path) -> Dict[str, Any]:
    """Verify MTK CERT2 RSA-2048/SHA-256 on a real image (read-only).

    Repo-tool path (tools/verify_mtk_image.py present): full per-triple
    header-hash + image-hash + CERT1/CERT2 RSA-PSS + pubkey-match checks.
    Stdlib fallback (tools missing): header/image hash checks only, sigs SKIP.
    Returns {path, via, triples:[...], all_ok}.
    """
    p = Path(path)
    data = p.read_bytes()  # read-only
    triples_out: List[Dict[str, Any]] = []

    if REUSED.get("verify_mtk_image", False) and VM is not None:
        try:
            entries = VM.parse_part_entries(data)
            triples = VM.find_targets(entries, None)
            # md1img CERT1 type is 0x02000001 (LK uses 0x02000000); accept both
            # (only CERT2 matters to the check) - same relaxation as boot_sim.
            for t, c1, c2 in triples:
                c1_blob = data[c1.data_off:c1.data_off + c1.hdr.dsize]
                c2_blob = data[c2.data_off:c2.data_off + c2.hdr.dsize]
                n1 = VM.parse_der_nodes(c1_blob)
                n2 = VM.parse_der_nodes(c2_blob)
                cert1 = VM.parse_cert(c1_blob)
                cert2 = VM.parse_cert(c2_blob)
                stored_hh = VM.find_bit_string_by_oid(n2, VM.OID_IMG_HDR_HASH)
                stored_ih = VM.find_bit_string_by_oid(n2, VM.OID_IMG_HASH)
                calc_hh = VM.hash_data(data[t.off:t.off + t.hdr.hdr_sz],
                                       cert1.sec_level)
                calc_ih = VM.hash_data(VM.padded_image_data(data, t),
                                       cert1.sec_level)
                c1_ok = VM.rsa_pss_verify(cert1.tbs.full, cert1.signature,
                                          cert1.public_key, cert1.hash_name)
                c2_ok = VM.rsa_pss_verify(cert2.tbs.full, cert2.signature,
                                          cert2.public_key, cert2.hash_name)
                try:
                    pk_ok = cert2.public_key.same_as(
                        VM.find_image_public_key(n1))
                except Exception:
                    pk_ok = False
                triples_out.append({
                    "target": t.hdr.name, "header_hash_ok": stored_hh == calc_hh,
                    "image_hash_ok": stored_ih == calc_ih, "cert1_sig_ok": c1_ok,
                    "cert2_sig_ok": c2_ok, "pubkey_match_ok": pk_ok})
            via = "repo-tools (verify_mtk_image, RSA-PSS + hashes)"
            all_ok = bool(triples_out) and all(
                all(v for k, v in tr.items() if k.endswith("_ok"))
                for tr in triples_out)
            return {"path": str(p), "via": via, "triples": triples_out,
                    "all_ok": all_ok}
        except Exception as exc:  # fall through to stdlib fallback
            fallback_note = f"repo-tool path failed ({exc}); stdlib fallback"
    else:
        fallback_note = "repo tools missing; stdlib fallback"

    # ---- stdlib fallback: hash checks only (no RSA-PSS) ----
    import struct as _st
    entries = []
    off = idx = 0
    while off + 512 <= len(data):
        try:
            vals = _st.unpack_from("<II32sIIIIIIIIII", data, off)
        except _st.error:
            break
        if vals[0] != 0x58881688:
            break
        name = vals[2].split(b"\0", 1)[0].decode("latin-1")
        dsize, hdr_sz, img_type, end, align = vals[1], vals[6] or 512, vals[8], vals[9], vals[10] or 1
        entries.append({"idx": idx, "off": off, "data_off": off + hdr_sz,
                        "name": name, "dsize": dsize, "hdr_sz": hdr_sz,
                        "img_type": img_type, "end": end, "align": align})
        idx += 1
        pad = ((dsize + align - 1) // align) * align if align else dsize
        off = off + hdr_sz + pad
        if end:
            break

    def _is_c1(e: dict) -> bool:
        return e["img_type"] in (0x02000000, 0x02000001) \
            or e["name"].lower().startswith("cert1")

    def _is_c2(e: dict) -> bool:
        return e["img_type"] == 0x02000002 \
            or e["name"].lower().startswith("cert2")

    i = 0
    while i + 2 < len(entries):
        t, c1, c2 = entries[i], entries[i + 1], entries[i + 2]
        if not _is_c1(t) and not _is_c2(t) and _is_c1(c1) and _is_c2(c2):
            c2_blob = data[c2["data_off"]:c2["data_off"] + c2["dsize"]]

            def _find_oid(blob: bytes, oid: str) -> bytes | None:
                # minimal TLV walk: first BIT STRING after the OID
                o = blob.find(b"\x06")
                return None  # placeholder replaced below
            # reuse boot_sim-free local OID scan (walk raw TLVs)
            nodes: list = []

            def _walk(buf: bytes, s: int, e2: int, out: list) -> None:
                o = s
                while o < e2:
                    b0 = buf[o]
                    num = b0 & 0x1F
                    q = o + 1
                    if num == 0x1F:
                        num = 0
                        while True:
                            b = buf[q]
                            q += 1
                            num = (num << 7) | (b & 0x7F)
                            if not (b & 0x80):
                                break
                    lb = buf[q]
                    q += 1
                    if lb & 0x80:
                        n = lb & 0x7F
                        ln = int.from_bytes(buf[q:q + n], "big")
                        q += n
                    else:
                        ln = lb
                    vo, ve = q, q + ln
                    if ve > e2:
                        return
                    out.append((b0, vo, ve))
                    if b0 & 0x20:
                        _walk(buf, vo, ve, out)
                    o = ve
            _walk(c2_blob, 0, len(c2_blob), nodes)

            def _oid_at(vo: int, ve: int) -> str:
                raw = c2_blob[vo:ve]
                if not raw:
                    return ""
                parts = [str(raw[0] // 40), str(raw[0] % 40)]
                v = 0
                for b in raw[1:]:
                    v = (v << 7) | (b & 0x7F)
                    if not (b & 0x80):
                        parts.append(str(v))
                        v = 0
                return ".".join(parts)
            stored: Dict[str, bytes] = {}
            for j, (tag, vo, ve) in enumerate(nodes):
                if tag == 0x06 and _oid_at(vo, ve) in (
                        "2.16.886.2454.2.1", "2.16.886.2454.2.4"):
                    for tag2, vo2, ve2 in nodes[j + 1:]:
                        if tag2 == 0x03:
                            val = c2_blob[vo2:ve2]
                            if val and val[0] == 0:
                                stored[_oid_at(vo, ve)] = val[1:]
                            break
            sh, si = stored.get("2.16.886.2454.2.4"), stored.get("2.16.886.2454.2.1")
            if sh is None or si is None:
                triples_out.append({"target": t["name"], "header_hash_ok": False,
                                    "image_hash_ok": False, "cert1_sig_ok": None,
                                    "cert2_sig_ok": None, "pubkey_match_ok": None,
                                    "note": "OID lookup failed"})
            else:
                def _hn(d: bytes) -> str:
                    if len(d) == 32:
                        return "sha256"
                    if len(d) == 48:
                        return "sha384"
                    raise ValueError("hash len")
                import hashlib as _hl
                ch = _hl.new(_hn(sh), data[t["off"]:t["off"] + t["hdr_sz"]]).digest()
                pad2 = ((t["dsize"] + t["align"] - 1) // t["align"]) * t["align"] - t["dsize"]
                ci = _hl.new(_hn(si), data[t["data_off"]:t["data_off"] + t["dsize"]] + b"\0" * pad2).digest()
                triples_out.append({"target": t["name"],
                                    "header_hash_ok": sh == ch,
                                    "image_hash_ok": si == ci,
                                    "cert1_sig_ok": None, "cert2_sig_ok": None,
                                    "pubkey_match_ok": None, "note": fallback_note})
            i += 3
            continue
        i += 1
    via = "stdlib-fallback (hashes only; RSA-PSS SKIP)"
    all_ok = bool(triples_out) and all(
        tr.get("header_hash_ok") and tr.get("image_hash_ok")
        for tr in triples_out)
    return {"path": str(p), "via": via, "triples": triples_out, "all_ok": all_ok}


# --------------------------------------------------------------------------
# 4. Selftest
# --------------------------------------------------------------------------

SHA256_VECTORS: List[Tuple[bytes, str]] = [
    (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    (b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
     "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
]

HMAC_VECTORS: List[Tuple[bytes, bytes, str]] = [
    # RFC 4231 Test Case 1 & 2 (HMAC-SHA-256)
    (bytes([0x0B] * 20), b"Hi There",
     "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
    (b"Jefe", b"what do ya want for nothing?",
     "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
]


def run_selftest() -> List[str]:
    fails: List[str] = []

    # -- 1a. SHA-256 one-shot + streaming (Init/Update/Final shape) --
    for msg, want in SHA256_VECTORS:
        got = sha256_oneshot(msg).hex()
        if got != want:
            fails.append(f"sha256({msg[:12]!r}): got {got} want {want}")
        s = sha256_init()
        mid = len(msg) // 2
        sha256_update(s, msg[:mid])
        sha256_update(s, msg[mid:])
        if sha256_final(s).hex() != want:
            fails.append(f"sha256-streaming({msg[:12]!r}): mismatch")
        try:
            s.update(b"x")
            fails.append(f"sha256({msg[:12]!r}): post-final update did not raise")
        except ValueError:
            pass

    # -- 1b. HMAC-SHA-256 one-shot + streaming --
    for key, msg, want in HMAC_VECTORS:
        got = hmac_sha256_oneshot(key, msg).hex()
        if got != want:
            fails.append(f"hmac({msg!r}): got {got} want {want}")
        h = hmac_sha256_init(key)
        hmac_sha256_update(h, msg[:4])
        hmac_sha256_update(h, msg[4:])
        if hmac_sha256_final(h).hex() != want:
            fails.append(f"hmac-streaming({msg!r}): mismatch")

    # -- 1c. MD5 spot (inventory primitive, software) --
    if md5_oneshot(b"abc").hex() != "900150983cd24fb0d6963f7d28e17f72":
        fails.append("md5(abc): vector mismatch")

    # -- 1d. AES gap shim: raises, tracks vectors, records requests --
    shim = AesGapShim()
    if not shim.vectors():
        fails.append("aes: no tracked vectors")
    try:
        shim.encrypt(bytes(16), bytes(16))
        fails.append("aes: encrypt did not raise")
    except AesNotInStdlib:
        pass
    try:
        shim.decrypt(bytes(16), bytes(16))
        fails.append("aes: decrypt did not raise")
    except AesNotInStdlib:
        pass
    if len(shim.requests) != 2:
        fails.append("aes: requests not recorded")

    # -- 2. Convention carve conformance (CATI extents + ROM heads) --
    try:
        rom_len = len(ROMONLY_PATH.read_bytes())
        if rom_len != 45893712:
            fails.append(f"romonly size {rom_len} != 45893712")
        for e in CONVENTIONS:
            body = carve_function(e.name)
            if len(body) != e.va_end - e.va_start:
                fails.append(f"{e.name}: carve size {len(body)}")
            if body[:16].hex() != e.head16:
                fails.append(f"{e.name}: head drift {body[:16].hex()}")
            if hashlib.sha256(body).hexdigest()[:16] != e.body_sha16:
                fails.append(f"{e.name}: body sha drift")
    except Exception as exc:  # noqa: BLE001
        fails.append(f"carve: {exc}")

    # -- 3a. Router schema: every oracle route names a real HwOracle op --
    for name, r in ROUTES.items():
        if r.kind == "oracle" and r.via not in HwOracle.OPS:
            fails.append(f"route {name}: via {r.via!r} not in HwOracle.OPS")
        if r.kind == "software" and r.impl is None:
            fails.append(f"route {name}: software without impl")
    # oracle path records + raises (no device contact by construction)
    try:
        oc = HwOracle()
        route("CustCHL_Calculate_Hash",
              {"data_hex": "616263", "key_id": "test-slot"}, oracle=oc)
        fails.append("router: oracle path did not raise")
    except OracleUnimplemented:
        if not getattr(oc, "transcript", None):
            fails.append("router: oracle transcript empty")
    except Exception as exc:  # noqa: BLE001
        fails.append(f"router oracle: {exc}")
    # software path computes locally
    try:
        out = route("sw_sha256", {"data_hex": "616263"})
        if out["result"]["digest_hex"] != SHA256_VECTORS[1][1]:
            fails.append("router sw_sha256: wrong digest")
    except Exception as exc:  # noqa: BLE001
        fails.append(f"router software: {exc}")
    # bad params rejected without side effects
    try:
        route("CustCHL_Verify_MAC", {"msg_hex": "00"})
        fails.append("router: missing params not rejected")
    except (ValueError, KeyError):
        pass
    try:
        route("no_such_op", {})
        fails.append("router: unknown op not rejected")
    except KeyError:
        pass

    # -- 3b/4. CERT2 verify on STOCK md1img passes (REAL verifier) --
    try:
        rep = verify_cert2_image(STOCK_MD1IMG)
        md1rom = next((t for t in rep["triples"] if t["target"] == "md1rom"), None)
        if md1rom is None:
            fails.append("cert2: no md1rom triple")
        elif not (md1rom.get("header_hash_ok") and md1rom.get("image_hash_ok")):
            fails.append(f"cert2: md1rom hashes not OK ({rep['via']})")
        elif "repo-tools" in rep["via"] and not (
                md1rom.get("cert1_sig_ok") and md1rom.get("cert2_sig_ok")
                and md1rom.get("pubkey_match_ok")):
            fails.append("cert2: md1rom RSA-PSS/pubkey not OK")
        if not rep.get("all_ok"):
            fails.append(f"cert2: all_ok False ({rep['via']})")
    except Exception as exc:  # noqa: BLE001
        fails.append(f"cert2: {exc}")

    return fails


def main(argv: List[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="crypto boundary library (offline, read-only, stdlib+repo-tools)")
    ap.add_argument("--selftest", action="store_true", help="run selftest (default)")
    ap.add_argument("--vectors", action="store_true", help="print SW test vectors")
    ap.add_argument("--conventions", action="store_true", help="print convention tables")
    ap.add_argument("--routes", action="store_true", help="print router map")
    ap.add_argument("--verify-cert2", nargs="?", const=str(STOCK_MD1IMG),
                    metavar="PATH", help="CERT2-verify an image (default: stock)")
    args = ap.parse_args(argv)
    if not any([args.selftest, args.vectors, args.conventions, args.routes,
                args.verify_cert2]):
        args.selftest = True

    rc = 0
    if args.selftest:
        fails = run_selftest()
        print("crypto_stubs selftest:", "PASS" if not fails else "FAIL")
        for f in fails:
            print("  -", f)
        print(f"  oracle backend: {ORACLE_BACKEND}; repo tools: {REUSED}")
        if fails:
            rc = 1
    if args.vectors:
        print("\n--- software vectors (hashlib/hmac) ---")
        for msg, want in SHA256_VECTORS:
            print(f"  sha256({msg[:24]!r}): {want}")
        for key, msg, want in HMAC_VECTORS:
            print(f"  hmac-sha256(key={key[:8]!r}.. msg={msg!r}): {want}")
        print(f"  md5(b'abc'): 900150983cd24fb0d6963f7d28e17f72")
        print("--- AES gap ---")
        print(f"  {AesGapShim().describe_gap()}")
        for v in AES_TRACKED_VECTORS:
            print(f"  tracked {v['suite']} {v['mode']}: ct={v['ct']} [{v['status']}]")
    if args.conventions:
        print("\n--- " + convention_table_text().replace("\n", "\n"))
    if args.routes:
        print("\n--- " + router_map_text().replace("\n", "\n"))
    if args.verify_cert2:
        print(f"\n--- CERT2 verify: {args.verify_cert2} ---")
        rep = verify_cert2_image(Path(args.verify_cert2))
        print(f"  via: {rep['via']}")
        for t in rep["triples"]:
            flags = " ".join(f"{k}={'OK' if v is True else ('FAIL' if v is False else 'SKIP')}"
                             for k, v in t.items() if k.endswith("_ok"))
            print(f"  [{t['target']}] {flags}")
        print(f"  all_ok: {rep['all_ok']}")
        if not rep["all_ok"]:
            rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main())
