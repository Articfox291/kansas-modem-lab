#!/usr/bin/env python3
"""PC-side simulator of the XT2513V (kansas / MT6835) bootchain + MTK image-verification flow.

STRICT-ROLE COMPLIANCE (see module docstring for the full contract):
  * Read-only w.r.t. the repo: real images are opened 'rb' and never modified.
  * All new outputs are written UNDER sim/ only (guarded by _guard_sim_out()).
  * No device contact: no adb/fastboot/subprocess -- pure offline parsing.
  * Stdlib + repo tools only (tools/sign_mtk_cert.py, tools/parse_mtk_certs.py,
    tools/verify_mtk_image.py). No third-party imports.

Contents:
  1. CERT2 parser/verifier -- per-triple (target + CERT1 + CERT2) hash + RSA-PSS
     checks on real images; reuses repo tools when importable, else a minimal
     stdlib DER/sha256 fallback (hashlib/struct).
  2. Boot-stage model -- BootROM -> preloader -> LK -> AVB -> modem checklist.
  3. Re-signability matrix -- every flashable partition from
     stock_XT2513V/flashfile.xml classified as proven / presumed / blocked,
     plus dry_run_patch() which re-signs a patched copy under sim/ only.
  4. Recovery model -- rollback path per stage.

Run:  python sim/boot_sim.py [--all|--verify|--stages|--matrix|--recovery|--dry-run]
"""

from __future__ import annotations

import argparse
import hashlib
import struct
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

# --------------------------------------------------------------------------
# Paths & repo-tool reuse
# --------------------------------------------------------------------------

SIM_DIR = Path(__file__).resolve().parent
REPO_ROOT = SIM_DIR.parent
TOOLS_DIR = REPO_ROOT / "tools"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

REUSED: dict[str, bool] = {}
for _mod in ("sign_mtk_cert", "parse_mtk_certs", "verify_mtk_image"):
    try:
        __import__(_mod)
        REUSED[_mod] = True
    except Exception:
        REUSED[_mod] = False

SMC = sys.modules.get("sign_mtk_cert")      # tools/sign_mtk_cert.py
VM = sys.modules.get("verify_mtk_image")    # tools/verify_mtk_image.py

# --------------------------------------------------------------------------
# Constants (established facts; sources noted per item)
# --------------------------------------------------------------------------

PART_MAGIC = 0x58881688
EXT_MAGIC = 0x58891689
PART_HDR_SIZE = 512
PART_HDR_FORMAT = "<II32sIIIIIIIIII"
IMG_TYPE_GROUP_CERT = 0x02 << 24
IMG_TYPE_CERT1_LK = IMG_TYPE_GROUP_CERT | 0x00    # LK container CERT1
IMG_TYPE_CERT1_MD = IMG_TYPE_GROUP_CERT | 0x01    # md1img cert1md (only CERT2 matters)
IMG_TYPE_CERT2 = IMG_TYPE_GROUP_CERT | 0x02
CERT1_TYPES_ACCEPTED = {IMG_TYPE_CERT1_LK, IMG_TYPE_CERT1_MD}

OID_IMAGE_HASH = "2.16.886.2454.2.1"
OID_IMAGE_HEADER_HASH = "2.16.886.2454.2.4"

# Modem memory map (HANDOFF 3e; DTB md1work.dtb; GFH FILE_INFO load_addr 0x400)
MODEM_AP_PHYS = 0xD0000000        # AP-phys carveout base (mblock-30)
MODEM_VA_BASE = 0x90000000        # modem VA base (MMU offset)
MD1ROM_FILE_DATA_OFF = 0x200      # md1rom payload starts after its 512B part hdr
MD1ROM_SIZE = 45893712            # md1rom dsize (both stock + force1)

# SML "legal_sim_rule" target (HANDOFF 3e / PICKUP Track 1)
SML_FUNC_VA = 0x905DF2FA
SML_FILE_OFF = 0x5DF4FA           # == (VA - 0x90000000) + 0x200
SML_STOCK_BYTES = bytes.fromhex("141e2412")
SML_FORCE1_BYTES = bytes.fromhex("01d2e0db")   # LI a0,1 ; JRC ra (proven live)

STOCK_MD1IMG = REPO_ROOT / "stock_XT2513V" / "md1img.img"
FORCE1_MD1IMG = REPO_ROOT / "md1work_md1force1-signed.img"
FLASHFILE = REPO_ROOT / "stock_XT2513V" / "flashfile.xml"

# Files that must NEVER be modelled for writes (brick risk).
WRITE_BLOCKLIST = {"preloader", "gpt", "pgpt", "efusebackup", "efuse"}


# --------------------------------------------------------------------------
# Minimal stdlib DER / MKIMG helpers (fallback + override-block builder)
# --------------------------------------------------------------------------

def roundup(value: int, align: int) -> int:
    if not align:
        return value
    return ((value + align - 1) // align) * align


def encode_length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    s = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(s)]) + s


def encode_oid(oid: str) -> bytes:
    parts = [int(x) for x in oid.split(".")]
    first = 40 * parts[0] + parts[1]
    out = bytearray([first])
    for p in parts[2:]:
        if p == 0:
            out.append(0)
            continue
        grp: list[int] = []
        while p > 0:
            grp.insert(0, p & 0x7F)
            p >>= 7
        for i, v in enumerate(grp):
            out.append((0x80 | v) if i != len(grp) - 1 else v)
    return bytes(out)


def build_oid_tlv(oid: str) -> bytes:
    b = encode_oid(oid)
    return b"\x06" + encode_length(len(b)) + b


def build_bitstring_tlv(payload: bytes) -> bytes:
    val = b"\x00" + payload  # 0 unused bits
    return b"\x03" + encode_length(len(val)) + val


def build_hash_override_block(header_digest: bytes | None,
                              image_digest: bytes | None) -> bytes:
    """0xA0 sibling block, byte-identical in construction to sign_mtk_cert.py."""
    inner = b""
    if header_digest is not None:
        inner += build_oid_tlv(OID_IMAGE_HEADER_HASH) + build_bitstring_tlv(header_digest)
    if image_digest is not None:
        inner += build_oid_tlv(OID_IMAGE_HASH) + build_bitstring_tlv(image_digest)
    if not inner:
        return b""
    return b"\xa0" + encode_length(len(inner)) + inner


def _rd_tag(data: bytes, off: int):
    b0 = data[off]
    cls = (b0 & 0xC0) >> 6
    cons = bool(b0 & 0x20)
    num = b0 & 0x1F
    pos = off + 1
    if num == 0x1F:
        num = 0
        while True:
            b = data[pos]
            pos += 1
            num = (num << 7) | (b & 0x7F)
            if not (b & 0x80):
                break
    return cls, cons, num, pos - off


def _rd_len(data: bytes, off: int):
    b = data[off]
    if not (b & 0x80):
        return b, 1
    n = b & 0x7F
    if n == 0:
        raise ValueError("indefinite length")
    return int.from_bytes(data[off + 1: off + 1 + n], "big"), 1 + n


def _decode_oid(raw: bytes) -> str:
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


def _walk_tlv(data: bytes, start: int, end: int, depth: int = 0):
    """Yield (tag_byte, constructed, tagnum, value_off, value_end, depth)."""
    off = start
    while off < end:
        cls, cons, num, tag_len = _rd_tag(data, off)
        ln, len_len = _rd_len(data, off + tag_len)
        v_off = off + tag_len + len_len
        v_end = v_off + ln
        if v_end > end:
            raise ValueError(f"truncated TLV at 0x{off:x}")
        yield data[off], cons, num, v_off, v_end, depth
        if cons:
            yield from _walk_tlv(data, v_off, v_end, depth + 1)
        off = v_end


def find_oid_hash_local(cert2_blob: bytes, oid: str) -> bytes | None:
    """First BIT STRING following `oid` in walk order (override block sorts first)."""
    der = cert2_blob
    nodes = list(_walk_tlv(der, 0, len(der)))
    for i, (tag, cons, num, v_off, v_end, _dep) in enumerate(nodes):
        if tag == 0x06 and not cons and _decode_oid(der[v_off:v_end]) == oid:
            for tag2, cons2, num2, v2_off, v2_end, _ in nodes[i + 1:]:
                if tag2 == 0x03 and not cons2:
                    val = der[v2_off:v2_end]
                    if val and val[0] == 0:
                        return val[1:]
            return None
    return None


@dataclass
class PartHdr:
    magic: int
    dsize: int
    name: str
    ext_magic: int
    hdr_sz: int
    img_type: int
    img_list_end: int
    align_sz: int


@dataclass
class Entry:
    index: int
    off: int          # part-header offset
    data_off: int     # blob offset
    next_off: int
    hdr: PartHdr


def parse_entries_local(data: bytes) -> list[Entry]:
    out: list[Entry] = []
    off, idx = 0, 0
    while off + PART_HDR_SIZE <= len(data):
        try:
            vals = struct.unpack_from(PART_HDR_FORMAT, data, off)
        except struct.error:
            break
        if vals[0] != PART_MAGIC:
            break
        hdr = PartHdr(magic=vals[0], dsize=vals[1],
                      name=vals[2].split(b"\0", 1)[0].decode("latin-1"),
                      ext_magic=vals[5], hdr_sz=vals[6] or PART_HDR_SIZE,
                      img_type=vals[8], img_list_end=vals[9],
                      align_sz=vals[10] or 1)
        data_off = off + hdr.hdr_sz
        next_off = off + hdr.hdr_sz + roundup(hdr.dsize, hdr.align_sz)
        if data_off + hdr.dsize > len(data):
            break
        out.append(Entry(idx, off, data_off, next_off, hdr))
        idx += 1
        off = next_off
        if hdr.img_list_end:
            break
    return out


def _is_cert1(e: Entry) -> bool:
    return e.hdr.img_type in (IMG_TYPE_CERT1_LK, IMG_TYPE_CERT1_MD) \
        or e.hdr.name.lower().startswith("cert1")


def _is_cert2(e: Entry) -> bool:
    return e.hdr.img_type == IMG_TYPE_CERT2 or e.hdr.name.lower().startswith("cert2")


def find_triples(entries: list[Entry]):
    """(target, cert1, cert2) runs -- same rule as verify_mtk_image.find_targets."""
    out, i = [], 0
    while i + 2 < len(entries):
        t, c1, c2 = entries[i], entries[i + 1], entries[i + 2]
        if not _is_cert1(t) and not _is_cert2(t) and _is_cert1(c1) and _is_cert2(c2):
            out.append((t, c1, c2))
            i += 3
            continue
        i += 1
    return out


# --------------------------------------------------------------------------
# 1. CERT2 verifier
# --------------------------------------------------------------------------

@dataclass
class TripleResult:
    target: str
    cert1_type: int
    cert1_type_note: str
    cert2_dsize: int
    header_hash_ok: bool | None = None
    image_hash_ok: bool | None = None
    cert1_sig_ok: bool | None = None
    cert2_sig_ok: bool | None = None
    pubkey_match_ok: bool | None = None
    stored_header_hash: str = ""
    calc_header_hash: str = ""
    stored_image_hash: str = ""
    calc_image_hash: str = ""
    notes: list[str] = field(default_factory=list)

    @property
    def all_ok(self) -> bool | None:
        flags = [self.header_hash_ok, self.image_hash_ok,
                 self.cert1_sig_ok, self.cert2_sig_ok, self.pubkey_match_ok]
        if any(f is None for f in flags):
            return None  # partial (hash-only fallback)
        return all(flags)


@dataclass
class ImageReport:
    path: str
    size: int
    n_entries: int
    via: str  # 'repo-tools' or 'stdlib-fallback'
    triples: list[TripleResult] = field(default_factory=list)


def _hash_name_for_digest(d: bytes) -> str:
    if len(d) == 32:
        return "sha256"
    if len(d) == 48:
        return "sha384"
    raise ValueError(f"unknown hash length {len(d)}")


def verify_image(path: Path) -> ImageReport:
    data = Path(path).read_bytes()  # read-only
    rep = ImageReport(path=str(path), size=len(data), n_entries=0, via="")
    use_repo = REUSED.get("verify_mtk_image", False) and REUSED.get("sign_mtk_cert", False)

    if use_repo:
        try:
            assert VM is not None and SMC is not None
            entries = VM.parse_part_entries(data)
            triples = VM.find_targets(entries, None)
            rep.n_entries = len(entries)
            rep.via = "repo-tools (verify_mtk_image + sign_mtk_cert)"
            for t, c1, c2 in triples:
                tr = TripleResult(target=t.hdr.name or f"#{t.index}",
                                  cert1_type=c1.hdr.img_type,
                                  cert1_type_note="",
                                  cert2_dsize=c2.hdr.dsize)
                tr.cert1_type_note = ("LK-type 0x02000000" if c1.hdr.img_type == IMG_TYPE_CERT1_LK
                                      else "md1img-type 0x02000001 (relaxed accept; strict "
                                           "verify_mtk_image.py expects 0x02000000 -- only CERT2 matters)")
                c1_blob = data[c1.data_off: c1.data_off + c1.hdr.dsize]
                c2_blob = data[c2.data_off: c2.data_off + c2.hdr.dsize]
                n1, n2 = VM.parse_der_nodes(c1_blob), VM.parse_der_nodes(c2_blob)
                cert1, cert2 = VM.parse_cert(c1_blob), VM.parse_cert(c2_blob)
                # Stored hashes: first OID hit in walk order = 0xA0 override if present.
                stored_hh = VM.find_bit_string_by_oid(n2, VM.OID_IMG_HDR_HASH)
                stored_ih = VM.find_bit_string_by_oid(n2, VM.OID_IMG_HASH)
                calc_hh = VM.hash_data(data[t.off: t.off + t.hdr.hdr_sz], cert1.sec_level)
                calc_ih = VM.hash_data(VM.padded_image_data(data, t), cert1.sec_level)
                tr.stored_header_hash, tr.calc_header_hash = stored_hh.hex(), calc_hh.hex()
                tr.stored_image_hash, tr.calc_image_hash = stored_ih.hex(), calc_ih.hex()
                tr.header_hash_ok = stored_hh == calc_hh
                tr.image_hash_ok = stored_ih == calc_ih
                tr.cert1_sig_ok = VM.rsa_pss_verify(cert1.tbs.full, cert1.signature,
                                                    cert1.public_key, cert1.hash_name)
                try:
                    tr.pubkey_match_ok = cert2.public_key.same_as(
                        VM.find_image_public_key(n1))
                except Exception as exc:
                    tr.pubkey_match_ok = False
                    tr.notes.append(f"image-pubkey lookup failed: {exc}")
                tr.cert2_sig_ok = VM.rsa_pss_verify(cert2.tbs.full, cert2.signature,
                                                    cert2.public_key, cert2.hash_name)
                if cert2.sec_level != cert1.sec_level:
                    tr.notes.append(f"sec_level mismatch CERT1={cert1.sec_level} "
                                    f"CERT2={cert2.sec_level}")
                # CERT2 override detection: a grown dsize vs stock is reported by
                # compare_reports(); the original TBS signature above still verifies
                # because parse_cert() anchors on the first 0x30 SEQUENCE.
                rep.triples.append(tr)
            return rep
        except Exception as exc:  # fall through to stdlib fallback
            print(f"  (repo-tool path failed: {exc}; using stdlib fallback)",
                  file=sys.stderr)
            use_repo = False

    # ---- stdlib fallback: hash checks only (hashlib), no RSA-PSS ----
    entries = parse_entries_local(data)
    rep.n_entries = len(entries)
    rep.via = "stdlib-fallback (hashlib/struct; RSA-PSS checks skipped)"
    for t, c1, c2 in find_triples(entries):
        tr = TripleResult(target=t.hdr.name or f"#{t.index}",
                          cert1_type=c1.hdr.img_type, cert1_type_note="",
                          cert2_dsize=c2.hdr.dsize,
                          cert1_sig_ok=None, cert2_sig_ok=None, pubkey_match_ok=None,
                          header_hash_ok=None, image_hash_ok=None)
        tr.cert1_type_note = ("LK-type" if c1.hdr.img_type == IMG_TYPE_CERT1_LK
                              else "md1img-type 0x02000001 (relaxed accept)")
        c2_blob = data[c2.data_off: c2.data_off + c2.hdr.dsize]
        stored_hh = find_oid_hash_local(c2_blob, OID_IMAGE_HEADER_HASH)
        stored_ih = find_oid_hash_local(c2_blob, OID_IMAGE_HASH)
        if stored_hh is None or stored_ih is None:
            tr.notes.append("OID hash lookup failed in CERT2")
            rep.triples.append(tr)
            continue
        calc_hh = hashlib.new(_hash_name_for_digest(stored_hh),
                              data[t.off: t.off + t.hdr.hdr_sz]).digest()
        pad = roundup(t.hdr.dsize, t.hdr.align_sz) - t.hdr.dsize
        calc_ih = hashlib.new(_hash_name_for_digest(stored_ih),
                              data[t.data_off: t.data_off + t.hdr.dsize] + b"\0" * pad).digest()
        tr.stored_header_hash, tr.calc_header_hash = stored_hh.hex(), calc_hh.hex()
        tr.stored_image_hash, tr.calc_image_hash = stored_ih.hex(), calc_ih.hex()
        tr.header_hash_ok = stored_hh == calc_hh
        tr.image_hash_ok = stored_ih == calc_ih
        rep.triples.append(tr)
    return rep


def compare_reports(stock: ImageReport, signed: ImageReport) -> dict:
    """CERT2 dsize growth + file growth between two reports."""
    growth = {}
    s_map = {t.target: t for t in stock.triples}
    for t in signed.triples:
        if t.target in s_map:
            growth[t.target] = t.cert2_dsize - s_map[t.target].cert2_dsize
    return {"per_target_dsize_growth": growth,
            "file_size_growth": signed.size - stock.size}


# --------------------------------------------------------------------------
# 2. Boot-stage model
# --------------------------------------------------------------------------

BOOT_STAGES: list[dict] = [
    {"stage": "BootROM",
     "verifier": "SoC ROM code (immutable)",
     "key_source": "eFuse Motorola-PKI (sacred)",
     "bypass": "blocked",
     "live_state": "No BROM/mtkclient path (V6 patched). Nothing bypassed, nothing flashed.",
     "evidence": "HANDOFF §6 / PICKUP Track 4.5 (BROM dead end)"},
    {"stage": "preloader (UFS_BOOT)",
     "verifier": "BootROM via eFuse chain",
     "key_source": "eFuse / preloader chain; sacred, no CERT path",
     "bypass": "blocked",
     "live_state": "Stock preloader untouched. NEVER model preloader/gpt writes (brick).",
     "evidence": "stock_XT2513V/preloader.img present; task brick rule"},
    {"stage": "LK (lk_a)",
     "verifier": "preloader verifies LK container CERT1/CERT2 (RSA-2048/sha256)",
     "key_source": "Motorola PKI via CERT1 root key",
     "bypass": "proven",
     "live_state": "Patched unlock-serial LK live in lk_a (owner LK secret, redacted); stock kept as lk.img.BAK. "
                   "CERT2 hash-override re-sign accepted by preflash.",
     "evidence": "stock_XT2513V/lk*.img; 5 sub-images (lk, bl2_ext, aee, lk_main_dtb, lk_dtbo)"},
    {"stage": "AVB (vbmeta/boot/vendor_boot/init_boot)",
     "verifier": "LK AVB + vbmeta descriptors",
     "key_source": "vbmeta descriptors (Google/Moto AVB, not MTK CERT)",
     "bypass": "proven",
     "live_state": "Unlocked BL (flashing_unlocked) + A15 RETCA vbmeta "
                   "--disable-verity/verification; Lineage GSI + KSU-Next init_boot live.",
     "evidence": "HANDOFF §1/§3b; stock vbmeta*.img on hand"},
    {"stage": "modem (md1img_a)",
     "verifier": "fastboot preflash CERT check + modem-boot SML sign check",
     "key_source": "in-image CERT1/CERT2 RSA-2048/sha256 (cert1md type 0x02000001)",
     "bypass": "proven",
     "live_state": "Slot A = stock + force-1 SML patch (01 d2 e0 db @ file 0x5df4fa), "
                   "CERT2 hash-override re-signed, md1imgpy parses 23 files, EE-clean. "
                   "Slot B = stock.",
     "evidence": "md1work_md1force1-signed.img live; §1 PROVEN END-TO-END flow"},
]


# --------------------------------------------------------------------------
# 3. Re-signability matrix (grounded in stock_XT2513V/flashfile.xml)
# --------------------------------------------------------------------------

def _flashfile_partitions() -> list[tuple[str, str, str]]:
    """(operation, partition, filename) from the real flashfile.xml."""
    rows: list[tuple[str, str, str]] = []
    root = ET.parse(str(FLASHFILE)).getroot()
    for step in root.iter("step"):
        rows.append((step.get("operation", ""), step.get("partition", "") or "-",
                     step.get("filename", "") or "-"))
    return rows


def build_matrix() -> list[dict]:
    """Classify every flashable partition. Statuses: proven / presumed / blocked."""
    proven = {
        "lk": "CERT2 hash-override re-sign PROVEN live (unlock-serial lk_a; stock .BAK kept).",
        "md1img": "CERT2 hash-override re-sign PROVEN live (force-1 md1img_a, EE-clean; slot B stock).",
    }
    # MTK-CERT family siblings: same MKIMG CERT1/CERT2 RSA-2048/sha256 scheme as LK
    # (tools parse it natively), but a patched flash was never attempted -> presumed.
    presumed_reason = ("Same MKIMG CERT1/CERT2 RSA-2048/sha256 family; sign_mtk_cert.py "
                       "parses natively so hash-override should apply, but NO patched "
                       "flash ever attempted on this device.")
    presumed = {"tee", "mcupm", "pi_img", "sspm", "dtbo", "logo", "spmfw", "scp",
                "dpm", "gz", "mcf_ota", "vcp", "connsys_bt"}
    blocked = {
        "gpt": "Singleton partition table; corrupt = brick. NEVER model writes.",
        "preloader": "Sacred UFS_BOOT; BootROM-eFuse verified, no CERT path. NEVER model writes.",
        "efusebackup": "Fused Motorola-PKI root; cannot be re-signed by design.",
        "vbmeta": "AVB descriptors, no MTK CERT path; bypass is PROVEN via "
                  "--disable-verity/verification (A15 RETCA), re-sign N/A.",
        "vbmeta_system": "Same as vbmeta (system descriptors; disabled, not re-signed).",
        "boot": "GKI AVB-signed (Google/Moto), no MTK CERT path; boots via unlocked BL + "
                "disabled vbmeta (proven). CERT re-sign blocked/N/A.",
        "vendor_boot": "Same as boot (RETUS stock vendor_boot_a live via AVB-disable).",
        "init_boot": "Same as boot; live = KSU-Next patched init_boot via AVB-disable (proven).",
        "super": "dm-verity container (system/product); no CERT re-sign path -- GSI flash flow instead.",
        "nvdata": "Erase step only; NVRAM-signed data (protect1/2 SML). Erase bricks modem "
                  "(proven NVRAM assert loop); no hash-override path.",
        "userdata": "Erase step only; no image, nothing to re-sign.",
        "metadata": "Erase step only; no image, nothing to re-sign.",
        "debug_token": "Erase step only; no image, nothing to re-sign.",
    }
    # Singleton backup-only partitions (modem_bak/; not in flashfile but flashable risk).
    extra_singletons = {
        "protect1/protect2": "SML-signed lock data in NVRAM; erase = modem assert loop (proven, "
                             "restored from backup). No CERT override path.",
        "nvram/nvdata-img": "Live NVRAM (254 files in nvram_live/); device-signed, no re-sign path.",
        "persist/proinfo/seccfg": "Backup-only singletons in modem_bak/modem_bak/; keep forever.",
    }
    rows: list[dict] = []
    seen: set[str] = set()
    for op, part, fn in _flashfile_partitions():
        key = part.lower().removesuffix("_a").removesuffix("_b")
        if part == "-" or key in seen:
            continue
        seen.add(key)
        if key in proven:
            status, reason = "re-signable proven", proven[key]
        elif key in presumed:
            status, reason = "re-signable presumed", presumed_reason
        elif key in blocked:
            status, reason = "blocked", blocked[key]
        else:
            status, reason = "blocked", "No known CERT/bypass path on this device."
        rows.append({"partition": key, "slots": "_a/_b (or singleton)",
                     "op": op, "status": status, "reason": reason})
    for part, reason in extra_singletons.items():
        rows.append({"partition": part, "slots": "singleton (backup-only)",
                     "op": "backup", "status": "blocked", "reason": reason})
    # Slot-B policy row (operational, not a partition).
    rows.append({"partition": "slot B policy", "slots": "_b",
                 "op": "keep-stock",
                 "status": "re-signable proven",
                 "reason": "Slot B kept stock (lk backup + stock md1img) as the always-bootable "
                           "fallback; proven recovery anchor."})
    return rows


# --------------------------------------------------------------------------
# dry-run re-sign (writes ONLY under sim/)
# --------------------------------------------------------------------------

def _guard_sim_out(out_name: str) -> Path:
    out = (SIM_DIR / out_name).resolve()
    if SIM_DIR.resolve() not in out.parents:
        raise ValueError(f"refusing to write outside sim/: {out}")
    if out.resolve() == REPO_ROOT.resolve():
        raise ValueError("refusing to overwrite repo root")
    return out


def dry_run_patch(src_image: Path, patch_offset: int, patch_bytes: bytes,
                  out_name: str) -> dict:
    """Patch a COPY in memory, CERT2 hash-override re-sign it, write under sim/.

    Never modifies src_image (opened read-only; size+sha256 asserted unchanged).
    Mirrors `sign_mtk_cert.py -w` but retargets the CERT2 belonging to the patched
    target (repo tool always retargets the first CERT2; identical when the patch
    lies in the first target, e.g. md1rom/SML).
    """
    src = Path(src_image)
    if not src.is_file():
        raise FileNotFoundError(src)
    if src.name.lower().startswith(("preloader", "gpt", "pgpt")) or \
            patch_offset is None:
        raise ValueError("refusing: preloader/gpt must never be modelled for writes")
    out = _guard_sim_out(out_name)

    before = src.read_bytes()
    before_hash = hashlib.sha256(before).hexdigest()
    data = bytearray(before)  # the "copy"

    entries = parse_entries_local(bytes(data))
    triples = find_triples(entries)
    if not triples:
        raise ValueError("no signed (target+CERT1+CERT2) triple found")
    # Find the target containing patch_offset.
    hit = None
    for t, c1, c2 in triples:
        if t.data_off <= patch_offset < t.data_off + t.hdr.dsize:
            hit = (t, c1, c2)
            break
    if hit is None:
        raise ValueError(f"patch offset 0x{patch_offset:x} is not inside a signed target")
    t, c1, c2 = hit
    end = patch_offset + len(patch_bytes)
    if end > t.data_off + t.hdr.dsize:
        raise ValueError("patch overruns target payload")
    if _is_cert1(entries[0]) or _is_cert2(entries[0]):
        raise ValueError("refusing: patch lands in a CERT blob")

    data[patch_offset:end] = patch_bytes

    # Recompute hashes exactly like sign_mtk_cert.py: header = hdr_sz bytes at
    # entry off; image = padded payload; algo by stored-digest length.
    c2_blob = bytes(data[c2.data_off: c2.data_off + c2.hdr.dsize])
    stored_hh = find_oid_hash_local(c2_blob, OID_IMAGE_HEADER_HASH)
    stored_ih = find_oid_hash_local(c2_blob, OID_IMAGE_HASH)
    if stored_hh is None or stored_ih is None:
        raise ValueError("CERT2 OID hashes not found")
    new_hh = hashlib.new(_hash_name_for_digest(stored_hh),
                         bytes(data[t.off: t.off + t.hdr.hdr_sz])).digest()
    pad = roundup(t.hdr.dsize, t.hdr.align_sz) - t.hdr.dsize
    new_ih = hashlib.new(_hash_name_for_digest(stored_ih),
                         bytes(data[t.data_off: t.data_off + t.hdr.dsize]) + b"\0" * pad).digest()

    insert = build_hash_override_block(new_hh, new_ih)
    new_blob = insert + c2_blob
    old_padded = roundup(c2.hdr.dsize, c2.hdr.align_sz)
    new_padded = roundup(len(new_blob), c2.hdr.align_sz)
    new_region = new_blob + b"\x00" * (new_padded - len(new_blob))
    data[c2.data_off: c2.data_off + old_padded] = new_region
    struct.pack_into("<I", data, c2.off + 4, len(new_blob))  # dsize field

    out.write_bytes(bytes(data))

    # Prove the source was untouched.
    after_hash = hashlib.sha256(src.read_bytes()).hexdigest()
    assert after_hash == before_hash, "SOURCE IMAGE MODIFIED -- must never happen"
    return {"out": str(out), "target": t.hdr.name,
            "patch": f"0x{patch_offset:x} <- {patch_bytes.hex()}",
            "cert2_dsize": f"{c2.hdr.dsize} -> {len(new_blob)} "
                           f"(+{len(new_blob) - c2.hdr.dsize})",
            "file_size": f"{len(before)} -> {len(data)} (+{len(data) - len(before)})",
            "header_hash": new_hh.hex(), "image_hash": new_ih.hex(),
            "src_untouched_sha256": after_hash}


# --------------------------------------------------------------------------
# 4. Recovery model
# --------------------------------------------------------------------------

RECOVERY: list[dict] = [
    {"stage": "BootROM",
     "rollback": "N/A -- nothing is ever flashed at this stage (blocked by design)."},
    {"stage": "preloader / gpt",
     "rollback": "N/A -- NEVER flashed. A corrupt preloader/gpt = brick (service-center "
                 "territory); this simulator never models those writes."},
    {"stage": "LK",
     "rollback": "fastboot flash lk_a <stock> using stock_XT2513V/lk.img or lk.img.BAK "
                 "(patched unlock-serial kept separately). Fastboot always reachable via "
                 "Vol-Down+Power (cable-insert trick if bootlooping)."},
    {"stage": "AVB",
     "rollback": "Reflash stock RETUS boot/vendor_boot/init_boot + A15 RETCA disabled-vbmeta "
                 "pair; init_boot stock kept alongside KSU-patched. Slot B holds a bootable set."},
    {"stage": "modem (md1img)",
     "rollback": "Slot B kept stock throughout. On misbehaviour: fastboot flash md1img_a "
                 "stock_XT2513V/md1img.img (proven restore path; pre proven after canary/force "
                 "builds). NVRAM singletons restore from modem_bak/modem_bak/ "
                 "(protect1/2, persist, nvdata, nvram, proinfo, seccfg); verify dmesg EE-clean. "
                 "NEVER erase protect1/2 (proven NVRAM assert loop)."},
    {"stage": "super / product",
     "rollback": "Stock super reflash recreates product_a (proven after earlier deletion); "
                 "GSI system reflash needs product_a delete only on first resize failure."},
]


# --------------------------------------------------------------------------
# Pretty-print + CLI
# --------------------------------------------------------------------------

def _ok(v) -> str:
    return "OK" if v is True else ("FAIL" if v is False else "SKIP")


def print_report(rep: ImageReport) -> None:
    print(f"== {rep.path}  ({rep.size} B, {rep.n_entries} part entries, via {rep.via})")
    for t in rep.triples:
        print(f"  [{t.target}] CERT1 type=0x{t.cert1_type:08x} ({t.cert1_type_note}) "
              f"CERT2 dsize={t.cert2_dsize}")
        print(f"    header-hash: {_ok(t.header_hash_ok)}  image-hash: {_ok(t.image_hash_ok)}  "
              f"CERT1-sig: {_ok(t.cert1_sig_ok)}  CERT2-sig: {_ok(t.cert2_sig_ok)}  "
              f"pubkey-match: {_ok(t.pubkey_match_ok)}")
        if t.header_hash_ok is False:
            print(f"      hdr  cert={t.stored_header_hash} calc={t.calc_header_hash}")
        if t.image_hash_ok is False:
            print(f"      img  cert={t.stored_image_hash} calc={t.calc_image_hash}")
        for n in t.notes:
            print(f"      note: {n}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="XT2513V bootchain + CERT2 simulator (offline, read-only)")
    ap.add_argument("--all", action="store_true", help="full run (default)")
    ap.add_argument("--verify", action="store_true")
    ap.add_argument("--stages", action="store_true")
    ap.add_argument("--matrix", action="store_true")
    ap.add_argument("--recovery", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)
    if not any([args.all, args.verify, args.stages, args.matrix, args.recovery, args.dry_run]):
        args.all = True

    print(f"repo tools reuse: {REUSED}  (sign/parse needed for repo path; verify for RSA-PSS)")
    stock_rep = signed_rep = None

    if args.all or args.verify:
        print("\n--- 1. CERT2 verify: stock md1img ---")
        stock_rep = verify_image(STOCK_MD1IMG)
        print_report(stock_rep)
        print("\n--- 1. CERT2 verify: force-1 signed md1img ---")
        signed_rep = verify_image(FORCE1_MD1IMG)
        print_report(signed_rep)
        cmp = compare_reports(stock_rep, signed_rep)
        print("\n--- dsize growth (signed - stock) ---")
        for tgt, g in cmp["per_target_dsize_growth"].items():
            print(f"  {tgt}: CERT2 dsize growth {g:+d}")
        print(f"  file growth {cmp['file_size_growth']:+d} B "
              f"(padded, align 16: 1024 -> 1120 = +96)")
        print("  md1rom stock bytes @0x5df4fa :",
              STOCK_MD1IMG.read_bytes()[SML_FILE_OFF:SML_FILE_OFF + 4].hex())
        print("  md1rom force1 bytes @0x5df4fa:",
              FORCE1_MD1IMG.read_bytes()[SML_FILE_OFF:SML_FILE_OFF + 4].hex())

    if args.all or args.stages:
        print("\n--- 2. Boot-stage model ---")
        for s in BOOT_STAGES:
            print(f"  [{s['stage']}] bypass={s['bypass']}\n"
                  f"    verifier: {s['verifier']}\n"
                  f"    key:      {s['key_source']}\n"
                  f"    live:     {s['live_state']}")

    if args.all or args.matrix:
        print("\n--- 3. Re-signability matrix (from stock_XT2513V/flashfile.xml) ---")
        for r in build_matrix():
            print(f"  {r['partition']:18s} [{r['status']}] -- {r['reason']}")

    if args.all or args.recovery:
        print("\n--- 4. Recovery model ---")
        for r in RECOVERY:
            print(f"  [{r['stage']}] {r['rollback']}")

    if args.all or args.dry_run:
        print("\n--- dry-run demo: stock + force-1 SML patch -> sim/ only ---")
        if stock_rep is None:
            stock_rep = verify_image(STOCK_MD1IMG)
        if signed_rep is None:
            signed_rep = verify_image(FORCE1_MD1IMG)
        info = dry_run_patch(STOCK_MD1IMG, SML_FILE_OFF, SML_FORCE1_BYTES,
                             "dryrun_md1force1_demo.img")
        for k, v in info.items():
            print(f"  {k}: {v}")
        demo_rep = verify_image(Path(info["out"]))
        print_report(demo_rep)
        # Cross-check: demo md1rom image-hash must equal the live force-1 stored hash
        # (identical 4-byte patch on identical stock base).
        demo_h = next(t for t in demo_rep.triples if t.target == "md1rom")
        live_h = next(t for t in signed_rep.triples if t.target == "md1rom")
        print(f"  demo calc image-hash == live force-1 stored image-hash: "
              f"{demo_h.calc_image_hash == live_h.stored_image_hash}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
