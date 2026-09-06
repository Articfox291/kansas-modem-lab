#!/usr/bin/env python3
"""PC-side offline model of MediaTek NVRAM / SML-blob storage.

STRICT RULES (enforced by construction):
  * Work ONLY from files under <repo> (repo-relative).
  * NEVER touch the live device: no adb/fastboot/AT/socket/subprocess imports,
    no command emission of any kind. Every "AT string" in this file is a
    SIMULATION-ONLY preview rendered for hypothesis testing, never transmitted.
  * Read-only on all dumps: real images are opened 'rb' and never modified.
  * New outputs (if any) go UNDER sim/ only. This module writes nothing.
  * Stdlib only.

Contents:
  1. LID container parser (192 B header + checksum + ciphertext records) from
     BOTH a raw protect img (minimal stdlib ext4 reader: superblock + group
     descriptors + inode table + /md walk + extent reads, depth 0/1) AND
     standalone extracted file bytes.
  2. Oracle-stub decrypt layer: ciphertext is HW-bound (cannot decrypt on PC).
     Ciphertext is modeled as opaque bytes; a policy oracle supplies the
     public Tracfone-locked template for simulation. Clean seam so a future
     key breaks in without refactoring callers.
  3. Offline NCK-attempt simulator: retry-counter decrement / lockout modeled
     in RAM only (query costs 0, wrong code costs 1, 0 -> hard-lock). ZERO cost
     to the real 5 capped modem attempts by construction.
  4. What-if engine over the DECRYPTED model, using sim/sml_sim.py's context
     dataclass when present (else a compatible local definition; seam noted).

Run:
  python sim/nv_model.py [--protect1 PATH] [--protect2 PATH] [--whatif] [--selftest]
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import math
import os
import struct
import sys
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# --------------------------------------------------------------------------
# 0. Repo roots (read-only).
# --------------------------------------------------------------------------

SIM_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.normpath(os.path.join(SIM_DIR, ".."))
DEFAULT_P1 = os.path.join(REPO_ROOT, "modem_bak", "modem_bak", "protect1.img")
DEFAULT_P2 = os.path.join(REPO_ROOT, "modem_bak", "modem_bak", "protect2.img")

# --------------------------------------------------------------------------
# 0b. State seam: sim/sml_sim.py if present, else compatible local stub.
# --------------------------------------------------------------------------
# SEAM NOTE: sim/sml_sim.py EXISTS in this repo and defines the canonical
# SmlContext / SmlCategory dataclass (7 cats x {state,retry,autolock,num,
# key_state,key,allow_list} plus tfn_otp_on / permanent_unlock harness flags)
# and the verdict functions legal_sim_rule / sml_verify / link_sml_with_rule
# with LEGAL==1 / ILLEGAL==0 polarity. We import and reuse it verbatim so the
# what-if engine below shares one context type with the SML decision-path
# simulator. The local fallback below is field-identical and is used ONLY if
# the import fails (e.g. file run standalone outside the repo layout).
_SML_SIM_BACKEND = "unknown"
try:  # package-relative: sim/sml_sim.py when imported as sim.nv_model
    from sim.sml_sim import (  # type: ignore
        CAT_COUNT as _CAT_COUNT,
        CAT_NAMES as _CAT_NAMES,
        FOREIGN_PLMN as _FOREIGN_PLMN,
        ILLEGAL as _ILLEGAL,
        LEGAL as _LEGAL,
        STATE_LOCKED as _STATE_LOCKED,
        STATE_UNLOCKED as _STATE_UNLOCKED,
        TRACFONE_PLMN as _TRACFONE_PLMN,
        SmlCategory as _SmlCategory,
        SmlContext as _SmlContext,
        link_sml_with_rule as _link_fn,
        tracfone_default_context as _tracfone_ctx,
    )
    _SML_SIM_BACKEND = "sim.sml_sim"
except ImportError:
    try:  # sibling: sml_sim.py on sys.path (sim/ dir)
        from sml_sim import (  # type: ignore
            CAT_COUNT as _CAT_COUNT,
            CAT_NAMES as _CAT_NAMES,
            FOREIGN_PLMN as _FOREIGN_PLMN,
            ILLEGAL as _ILLEGAL,
            LEGAL as _LEGAL,
            STATE_LOCKED as _STATE_LOCKED,
            STATE_UNLOCKED as _STATE_UNLOCKED,
            TRACFONE_PLMN as _TRACFONE_PLMN,
            SmlCategory as _SmlCategory,
            SmlContext as _SmlContext,
            link_sml_with_rule as _link_fn,
            tracfone_default_context as _tracfone_ctx,
        )
        _SML_SIM_BACKEND = "sml_sim"
    except ImportError:
        _SML_SIM_BACKEND = "stub(local, sml_sim missing)"

        _CAT_COUNT = 7
        _CAT_NAMES = ("N", "NS", "SP", "C", "SIM", "NS2", "SP2")
        _LEGAL, _ILLEGAL = 1, 0
        _STATE_LOCKED, _STATE_UNLOCKED = 1, 0
        _TRACFONE_PLMN, _FOREIGN_PLMN = "311480", "310260"

        @dataclass
        class _SmlCategory:  # compatible fallback (same field names/order)
            state: int = 0
            retry: int = 5
            autolock: int = 0
            num: int = 0
            key_state: int = 0
            key: str = ""
            allow_list: List[str] = field(default_factory=list)

        @dataclass
        class _SmlContext:
            cats: List["_SmlCategory"] = field(
                default_factory=lambda: [_SmlCategory() for _ in range(7)]
            )
            tfn_otp_on: int = 1
            permanent_unlock: int = 0

        def _tracfone_ctx():  # type: ignore
            ctx = _SmlContext()
            ctx.cats[0] = _SmlCategory(
                state=1, retry=5, autolock=0, num=1,
                key_state=0, key="", allow_list=[_TRACFONE_PLMN],
            )
            return ctx

        def _link_fn(ctx, cat, sim_plmn, patched=False, **kw):  # type: ignore
            # Minimal fallback verdict: locked cat needs allowlist membership.
            if not (0 <= cat < 7):
                return 0
            c = ctx.cats[cat]
            if sim_plmn is None:
                return 0
            if c.state == 0:
                return 1
            return 1 if sim_plmn in c.allow_list else 0

# Public aliases (canonical names for importers of nv_model).
CAT_COUNT = _CAT_COUNT
CAT_NAMES = _CAT_NAMES
LEGAL, ILLEGAL = _LEGAL, _ILLEGAL
STATE_LOCKED, STATE_UNLOCKED = _STATE_LOCKED, _STATE_UNLOCKED
TRACFONE_PLMN, FOREIGN_PLMN = _TRACFONE_PLMN, _FOREIGN_PLMN
SmlCategory, SmlContext = _SmlCategory, _SmlContext
SML_SIM_BACKEND = _SML_SIM_BACKEND


def make_tracfone_context():
    """Default Tracfone-locked policy template (see oracle section)."""
    return _tracfone_ctx()


def link_verdict(ctx, cat: int, sim_plmn: Optional[str], patched: bool = False) -> int:
    """Delegate verdict to sml_sim.link_sml_with_rule (or compat fallback)."""
    try:
        return int(_link_fn(ctx, cat, sim_plmn, patched=patched))
    except TypeError:
        return int(_link_fn(ctx, cat, sim_plmn))

# --------------------------------------------------------------------------
# 1. LID container parser.
# --------------------------------------------------------------------------

LID_MAGIC = b"LID\x00"
HEADER_SIZE = 192
DOMAIN_SECURE_LE = 0x0404BE1D  # bytes on disk: 1D BE 04 04
DOMAIN_SECURE_BE = 0x1DBE0404  # same 4 bytes read big-endian (task shorthand)
DOMAIN_LABELS = {
    DOMAIN_SECURE_LE: "SECURE",
    0x14A5583B: "OTHER(0x14A5583B)",
    0xCC63BBA6: "OTHER(0xCC63BBA6)",
}


class LidParseError(ValueError):
    """192 B NVRAM LID container failed validation."""


@dataclass
class LidHeader:
    magic: bytes
    ver: bytes
    lid: int
    rec_count: int
    rec_size: int
    flags: int
    attr: int
    domain_le: int
    domain_be: int
    domain_label: str
    seed: bytes
    checksum: bytes
    file_size: int
    ct_len: int
    sec_size: int  # ciphertext bytes per record
    overhead: int  # sec_size - rec_size
    entropy: float


@dataclass
class LidContainer:
    name: str
    source: str
    header: LidHeader
    records: List[bytes]  # ciphertext records (opaque, HW-bound)
    raw: bytes  # full file bytes (header + ciphertext)


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return -sum((v / n) * math.log2(v / n) for v in Counter(data).values())


def parse_lid_container(data: bytes, name: str = "<bytes>",
                        source: str = "<bytes>") -> LidContainer:
    """Parse one 192 B NVRAM LID container + secure payload.

    Layout (all u32 LE unless noted): magic 'LID\\0' @0x00, ver ASCII @0x04
    (e.g. b'000\\x00'), LID @0x08, rec_count @0x0C, rec_size @0x10,
    flags @0x14, attr @0x18, domain magic @0x3C (bytes 1D BE 04 04 =
    0x0404BE1D LE / 0x1DBE0404 BE), 32 B seed @0x40, 32 B checksum @0x80,
    ciphertext @0xC0 split into rec_count records of sec_size each.
    """
    if len(data) < HEADER_SIZE:
        raise LidParseError(
            "%s: too short (%d B < 192 B header)" % (name, len(data)))
    magic = data[0:4]
    if magic != LID_MAGIC:
        raise LidParseError("%s: bad magic %r (want b'LID\\x00')" % (name, magic))
    ver = data[4:8]
    if not (ver[:3].isdigit() and ver[3:4] == b"\x00"):
        raise LidParseError("%s: bad ver %r (want ASCII digits + NUL)" % (name, ver))
    lid, rec_count, rec_size, flags, attr = struct.unpack("<5I", data[8:28])
    if not (0 < rec_count <= 256):
        raise LidParseError("%s: bad rec_count %r" % (name, rec_count))
    if not (0 < rec_size <= 16384):
        raise LidParseError("%s: bad rec_size %r" % (name, rec_size))
    # Bytes 0x1C..0x3C are reserved (observed zero); 0xA0..0xC0 reserved zero.
    domain_le = struct.unpack("<I", data[0x3C:0x40])[0]
    domain_be = struct.unpack(">I", data[0x3C:0x40])[0]
    domain_label = DOMAIN_LABELS.get(domain_le, "UNKNOWN(0x%08X)" % domain_le)
    seed = data[0x40:0x60]
    checksum = data[0x80:0xA0]
    if len(seed) != 32 or len(checksum) != 32:
        raise LidParseError("%s: truncated seed/checksum" % name)
    ct = data[HEADER_SIZE:]
    ct_len = len(ct)
    if ct_len == 0 or ct_len % rec_count != 0:
        raise LidParseError(
            "%s: ciphertext len %d not a multiple of rec_count %d"
            % (name, ct_len, rec_count))
    sec_size = ct_len // rec_count
    overhead = sec_size - rec_size
    if sec_size < rec_size:
        raise LidParseError(
            "%s: secure record %d < plaintext rec %d" % (name, sec_size, rec_size))
    records = [ct[i * sec_size:(i + 1) * sec_size] for i in range(rec_count)]
    hdr = LidHeader(
        magic=magic, ver=ver, lid=lid, rec_count=rec_count, rec_size=rec_size,
        flags=flags, attr=attr, domain_le=domain_le, domain_be=domain_be,
        domain_label=domain_label, seed=seed, checksum=checksum,
        file_size=len(data), ct_len=ct_len, sec_size=sec_size,
        overhead=overhead, entropy=_entropy(ct),
    )
    return LidContainer(name=name, source=source, header=hdr, records=records,
                        raw=bytes(data))


def parse_lid_file(path: str) -> LidContainer:
    """Parse a standalone extracted /md/* file (read-only)."""
    with open(path, "rb") as f:
        data = f.read()
    return parse_lid_container(data, name=os.path.basename(path), source=path)


# --------------------------------------------------------------------------
# 1b. Minimal stdlib ext4 reader (protect1/2: 8 MB, 4 K blocks, 512 B inodes).
# --------------------------------------------------------------------------

class Ext4Error(RuntimeError):
    pass


class Ext4Image:
    """Read-only stdlib ext4 accessor sufficient for protect1/2 (+nvdata).

    Parses: superblock (at byte 1024) -> block size, groups, inode size ->
    group-descriptor table (at (first_data_block+1)*block_size) -> inode
    table(s) -> directory walk (root ino 2 -> 'md') -> extent-mapped file
    reads (extent tree depth 0, and depth 1 via index nodes; depth>1 refused).
    """

    EXTENT_MAGIC = 0xF30A

    def __init__(self, path: str):
        self.path = path
        with open(path, "rb") as f:  # read-only; whole 8 MB fits in RAM
            self.data = f.read()
        d = self.data
        if len(d) < 2048:
            raise Ext4Error("%s: too small for ext4" % path)
        sb = d[1024:1024 + 1024]
        self.inodes_count = struct.unpack("<I", sb[0:4])[0]
        self.blocks_count = struct.unpack("<I", sb[4:8])[0]
        self.first_data_block = struct.unpack("<I", sb[20:24])[0]
        self.log_block_size = struct.unpack("<I", sb[24:28])[0]
        self.blocks_per_group = struct.unpack("<I", sb[32:36])[0]
        self.inodes_per_group = struct.unpack("<I", sb[40:44])[0]
        self.magic = struct.unpack("<H", sb[56:58])[0]
        if self.magic != 0xEF53:
            raise Ext4Error("%s: bad ext4 magic 0x%04X" % (path, self.magic))
        self.inode_size = struct.unpack("<H", sb[88:90])[0]
        self.feature_incompat = struct.unpack("<I", sb[96:100])[0]
        if self.inode_size < 128 or self.inode_size > 1024:
            raise Ext4Error("%s: implausible inode_size %d" % (path, self.inode_size))
        self.block_size = 1024 << self.log_block_size
        if self.block_size not in (1024, 2048, 4096):
            raise Ext4Error("%s: bad block_size %d" % (path, self.block_size))
        # Group-descriptor size: 64 B iff 64BIT incompat (0x80) and s_desc_size set.
        desc_size_field = struct.unpack("<H", sb[254:256])[0]
        self.desc_size = 64 if (self.feature_incompat & 0x80
                                and desc_size_field) else 32
        import math as _m
        self.groups = max(1, _m.ceil(self.blocks_count / self.blocks_per_group))
        gd_off = (self.first_data_block + 1) * self.block_size
        self.inode_tables: List[int] = []
        for g in range(self.groups):
            gd = d[gd_off + g * self.desc_size: gd_off + (g + 1) * self.desc_size]
            if len(gd) < 32:
                raise Ext4Error("%s: truncated group descriptor %d" % (path, g))
            lo = struct.unpack("<I", gd[8:12])[0]
            hi = struct.unpack("<I", gd[40:44])[0] if self.desc_size >= 64 else 0
            self.inode_tables.append((hi << 32) | lo)

    # -- inode layer ------------------------------------------------------
    def _inode_offset(self, ino: int) -> int:
        if not (1 <= ino <= self.inodes_count):
            raise Ext4Error("inode %d out of range (1..%d)" % (ino, self.inodes_count))
        g = (ino - 1) // self.inodes_per_group
        idx = (ino - 1) % self.inodes_per_group
        return self.inode_tables[g] * self.block_size + idx * self.inode_size

    def read_inode(self, ino: int) -> Tuple[int, int, int, bytes]:
        """Return (mode, size, flags, i_block[60])."""
        off = self._inode_offset(ino)
        raw = self.data[off:off + self.inode_size]
        if len(raw) < 128:
            raise Ext4Error("truncated inode %d" % ino)
        mode = struct.unpack("<H", raw[0:2])[0]
        size_lo = struct.unpack("<I", raw[4:8])[0]
        size_hi = struct.unpack("<I", raw[108:112])[0]
        flags = struct.unpack("<I", raw[32:36])[0]
        return mode, (size_hi << 32) | size_lo, flags, raw[40:100]

    # -- extent layer -----------------------------------------------------
    def _read_blocks(self, start: int, count: int) -> bytes:
        lo = start * self.block_size
        return self.data[lo:lo + count * self.block_size]

    def read_file_by_inode(self, ino: int) -> bytes:
        _mode, size, _flags, ib = self.read_inode(ino)
        magic, entries, _mx, depth, _gen = struct.unpack("<HHHHI", ib[0:12])
        if magic != self.EXTENT_MAGIC:
            raise Ext4Error("inode %d: not extent-mapped (magic 0x%04X)"
                            % (ino, magic))
        if depth == 0:
            out = bytearray()
            for e in range(entries):
                eblk, elen, eshi, eslo = struct.unpack(
                    "<IHHI", ib[12 + e * 12:12 + e * 12 + 12])
                _ = eblk
                phys = (eshi << 32) | eslo
                out += self._read_blocks(phys, elen)
            return bytes(out[:size])
        if depth == 1:
            # Index entries: ei_block (logical), ei_leaf_lo, ei_leaf_hi, unused.
            idxs: List[Tuple[int, int]] = []
            for e in range(entries):
                ei_block, ei_lo, ei_hi, _un = struct.unpack(
                    "<IIHH", ib[12 + e * 12:12 + e * 12 + 12])
                idxs.append((ei_block, (ei_hi << 32) | ei_lo))
            idxs.sort()
            out = bytearray()
            for _, leaf in idxs:
                lo = leaf * self.block_size
                hdr = self.data[lo:lo + 12]
                lmagic, lentries, _lmx, ldepth, _lg = struct.unpack("<HHHHI", hdr)
                if lmagic != self.EXTENT_MAGIC or ldepth != 0:
                    raise Ext4Error("inode %d: bad leaf @%d" % (ino, leaf))
                for e in range(lentries):
                    base = lo + 12 + e * 12
                    _eb, elen, eshi, eslo = struct.unpack(
                        "<IHHI", self.data[base:base + 12])
                    out += self._read_blocks((eshi << 32) | eslo, elen)
            return bytes(out[:size])
        raise Ext4Error("inode %d: extent depth %d unsupported" % (ino, depth))

    # -- directory layer --------------------------------------------------
    def list_dir(self, ino: int) -> List[Tuple[int, bytes, int]]:
        """List (inode, name, file_type) for a directory inode."""
        data = self.read_file_by_inode(ino)
        off, ents = 0, []
        while off + 8 <= len(data):
            f_ino, rec_len, name_len, ftype = struct.unpack(
                "<IHBB", data[off:off + 8])
            if rec_len == 0:
                break
            ents.append((f_ino, data[off + 8:off + 8 + name_len], ftype))
            off += rec_len
        return ents

    def md_files(self) -> Dict[str, bytes]:
        """Read every live /md/* file: {name: bytes} (read-only)."""
        root = {n: i for i, n, _t in self.list_dir(2)}
        if b"md" not in root:
            raise Ext4Error("%s: no /md directory" % self.path)
        out: Dict[str, bytes] = {}
        for ino, name, _t in self.list_dir(root[b"md"]):
            if name in (b".", b".."):
                continue
            out[name.decode("ascii", "replace")] = self.read_file_by_inode(ino)
        return out


def load_protect(path: str) -> Dict[str, bytes]:
    """Ext4-aware load of all live /md/* files from a protect img."""
    return Ext4Image(path).md_files()


def parse_protect(path: str) -> Dict[str, LidContainer]:
    """Parse every LID container in a protect img; skip non-LID files."""
    out: Dict[str, LidContainer] = {}
    for name, data in load_protect(path).items():
        try:
            out[name] = parse_lid_container(data, name=name, source=path)
        except LidParseError:
            continue  # e.g. nv_mini_dump (modem FS log) / DEV_INFO (16 B)
    return out

# --------------------------------------------------------------------------
# 2. Oracle-stub decrypt layer (HW-bound ciphertext -> opaque + policy).
# --------------------------------------------------------------------------

PROVENANCE_TEMPLATE = "policy-template (NOT derived from ciphertext)"
PROVENANCE_HWBOUND = "ciphertext opaque (HW-bound; PC cannot decrypt)"


class HwBoundDecryptError(RuntimeError):
    """Ciphertext cannot be decrypted on PC (no HW key). Carries opaque bytes."""


class DecryptOracle:
    """Clean seam for a future key break-in.

    Subclass and override decrypt(); callers use decrypt_with_oracle() so no
    refactoring is needed when a real key arrives. decrypt() must return a
    SmlContext (the DECRYPTED model) or raise HwBoundDecryptError.
    """

    name = "base"

    def decrypt(self, container: LidContainer) -> SmlContext:
        raise NotImplementedError

    def check_key(self, cat: int, code: str, ctx: Optional[SmlContext] = None) -> bool:
        """Offline key check against the DECRYPTED model. Base: unknown -> False."""
        return False


class HwBoundOracle(DecryptOracle):
    """Truthful default: every secure blob raises (opaque bytes preserved)."""

    name = "hw-bound (truthful)"

    def decrypt(self, container: LidContainer) -> SmlContext:
        raise HwBoundDecryptError(
            "%s LID 0x%04X: %d opaque ciphertext bytes (entropy %.2f); "
            "HW-bound, PC cannot decrypt. Use the policy template for "
            "simulation instead." % (container.name, container.header.lid,
                                     container.header.ct_len,
                                     container.header.entropy))


class TracfonePolicyOracle(DecryptOracle):
    """Policy template oracle: Tracfone-locked profile for simulation.

    This is NOT a decryption: it returns the public lock-policy template
    (cat0 LOCK / retry 5 / 311480, cats 1..6 UNLOCK, remain 5) established
    from live props (remain.count=5) and the 7-tuple ESMLCK? shape. The real
    NCK is unknown, so check_key() is False for every candidate unless the
    caller registers explicit offline test keys (hypothesis-only, RAM-only).
    """

    name = "tracfone-policy-template"

    def __init__(self, test_keys: Optional[Dict[int, str]] = None):
        self.test_keys: Dict[int, str] = dict(test_keys or {})

    def decrypt(self, container: LidContainer) -> SmlContext:
        ctx = make_tracfone_context()
        return ctx

    def check_key(self, cat: int, code: str, ctx: Optional[SmlContext] = None) -> bool:
        want = self.test_keys.get(cat)
        return want is not None and code == want


_ORACLE: DecryptOracle = TracfonePolicyOracle()


def set_oracle(oracle: DecryptOracle) -> None:
    global _ORACLE
    _ORACLE = oracle


def get_oracle() -> DecryptOracle:
    return _ORACLE


def decrypt_with_oracle(container: LidContainer,
                        oracle: Optional[DecryptOracle] = None) -> SmlContext:
    """Decrypt via `oracle` (default: registered oracle). Seam for HW key."""
    return (oracle or _ORACLE).decrypt(container)

# --------------------------------------------------------------------------
# 3. Offline NCK-attempt simulator (RAM only; ZERO cost to the real counter).
# --------------------------------------------------------------------------

# ESMLCK op forms replayed by the driver. Numeric `at_op` values mirror the
# live test string "+ESMLCK:(0-4),(0-4),<key>,<data_imsi>,<data_gid1>,<data_gid2>"
# (op 0..4, cat subset 0..4 on the AT gateway; the modem SML itself tracks 7
# cats 0..6 per the ESMLCK? 7-tuple shape). UNLOCK/LOCK/ADD/REMOVE/DISABLE are
# modeled strictly in RAM -- the preview strings below are NEVER transmitted.
ESMLCK_OPS = (
    ("QUERY", "status query (cost 0)"),
    ("UNLOCK", "submit NCK for cat (wrong costs 1)"),
    ("LOCK", "re-lock an unlocked cat (model only)"),
    ("ADD_CODE", "provision code slot (model only)"),
    ("REMOVE_CODE", "clear code slot (model only)"),
    ("DISABLE_PERMANENT", "PERMANENT unlock (IRREVERSIBLE on-device; NEVER run)"),
)

DISABLE_WARNING = (
    "!!! WARNING: DISABLE_PERMANENT models the irreversible permanent-unlock "
    "latch (cf. custom_sml_cat_verify_pass_permanent_unlock always-1 stub). "
    "On a live modem this can NEVER be undone. This simulator runs it ONLY on "
    "an in-RAM copy. NEVER type/send any AT+ESMLCK set form on-device: each "
    "wrong key burns one of the 5 capped attempts (remain.count). !!!"
)


@dataclass
class NckResult:
    ok: bool
    outcome: str
    cat: int
    remain_before: int
    remain_after: int
    state_before: int
    state_after: int
    at_preview: str  # SIMULATION-ONLY rendering; never transmitted


class NckSimulator:
    """In-RAM retry-counter / lockout model seeded from a SmlContext.

    * query(cat) costs 0 (read-only status).
    * attempt_unlock(cat, code) with a wrong code costs exactly 1 retry on
      that cat; reaching 0 transitions the cat to HARD-LOCKED (sticky).
    * a correct code (per oracle.check_key) transitions LOCKED -> UNLOCKED
      without consuming a retry.
    The wrapped context is deep-copied at construction; the caller's model
    (and, trivially, the real modem) is never mutated.
    """

    HARDLOCKED = 2  # sticky model state beyond sml_sim's 0/1 (reported, not stored)

    def __init__(self, ctx, oracle: Optional[DecryptOracle] = None,
                 max_retry_default: int = 5):
        self.model = copy.deepcopy(ctx)
        self.oracle = oracle or get_oracle()
        self.max_retry_default = max_retry_default
        self.hardlocked: set = set()
        for i, c in enumerate(self.model.cats):
            if c.retry <= 0 and c.state == STATE_LOCKED:
                self.hardlocked.add(i)

    # -- helpers --------------------------------------------------------
    def _cat(self, cat: int):
        if not (0 <= cat < len(self.model.cats)):
            raise IndexError("cat %r out of 0..%d" % (cat, len(self.model.cats) - 1))
        return self.model.cats[cat]

    @staticmethod
    def render_at_preview(op: str, cat: int, key: str = "<key>",
                          imsi: str = "<data_imsi>", gid1: str = "<data_gid1>",
                          gid2: str = "<data_gid2>") -> str:
        """Render the would-be AT form. SIMULATION ONLY -- never transmitted."""
        op = op.upper()
        tag = "[SIMULATION ONLY -- DO NOT SEND] "
        if op == "QUERY":
            return tag + "AT+ESMLCK?  (read cat %d status; cost 0)" % cat
        if op == "UNLOCK":
            return (tag + 'AT+ESMLCK=<op>,%d,"%s","%s","%s","%s"  (unlock attempt; '
                           "wrong costs 1)" % (cat, key, imsi, gid1, gid2))
        if op == "LOCK":
            return tag + "AT+ESMLCK=<op>,%d  (re-lock; model only)" % cat
        if op == "ADD_CODE":
            return tag + "AT+ESMLCK=<op>,%d  (add code slot; model only)" % cat
        if op == "REMOVE_CODE":
            return tag + "AT+ESMLCK=<op>,%d  (remove code slot; model only)" % cat
        if op == "DISABLE_PERMANENT":
            return (tag + "AT+ESMLCK=<op>,%d  (PERMANENT, IRREVERSIBLE; model only -- "
                           "NEVER run on-device)" % cat)
        return tag + "AT+ESMLCK? (unknown op %r)" % op

    # -- ops ------------------------------------------------------------
    def query(self, cat: int) -> NckResult:
        c = self._cat(cat)
        state = self.HARDLOCKED if cat in self.hardlocked else c.state
        return NckResult(True, "QUERY_OK", cat, c.retry, c.retry,
                         state, state, self.render_at_preview("QUERY", cat))

    def attempt_unlock(self, cat: int, code: str) -> NckResult:
        c = self._cat(cat)
        before_state = self.HARDLOCKED if cat in self.hardlocked else c.state
        rb = c.retry
        prev = self.render_at_preview("UNLOCK", cat, key="********")
        if cat in self.hardlocked:
            return NckResult(False, "HARD_LOCKED", cat, rb, rb,
                             before_state, self.HARDLOCKED, prev)
        if c.state == STATE_UNLOCKED:
            return NckResult(True, "ALREADY_UNLOCKED", cat, rb, rb,
                             before_state, STATE_UNLOCKED, prev)
        if self.oracle.check_key(cat, code, self.model):
            c.state = STATE_UNLOCKED
            return NckResult(True, "UNLOCKED", cat, rb, rb,
                             before_state, STATE_UNLOCKED, prev)
        c.retry = max(0, rb - 1)  # wrong code costs exactly 1
        if c.retry == 0:
            self.hardlocked.add(cat)
            return NckResult(False, "WRONG_CODE_HARD_LOCKED", cat, rb, 0,
                             before_state, self.HARDLOCKED, prev)
        return NckResult(False, "WRONG_CODE_RETRY_LEFT", cat, rb, c.retry,
                         before_state, before_state, prev)

    def lock(self, cat: int) -> NckResult:
        c = self._cat(cat)
        sb = self.HARDLOCKED if cat in self.hardlocked else c.state
        if cat in self.hardlocked:
            return NckResult(False, "HARD_LOCKED", cat, c.retry, c.retry, sb,
                             self.HARDLOCKED, self.render_at_preview("LOCK", cat))
        c.state = STATE_LOCKED
        return NckResult(True, "LOCKED", cat, c.retry, c.retry, sb, STATE_LOCKED,
                         self.render_at_preview("LOCK", cat))

    def add_code(self, cat: int, code: str) -> NckResult:
        c = self._cat(cat)
        sb = self.HARDLOCKED if cat in self.hardlocked else c.state
        if isinstance(self.oracle, TracfonePolicyOracle):
            self.oracle.test_keys[cat] = code  # hypothesis registration, RAM only
        c.key_state = 1
        return NckResult(True, "CODE_ADDED(model-only)", cat, c.retry, c.retry, sb,
                         sb, self.render_at_preview("ADD_CODE", cat))

    def remove_code(self, cat: int) -> NckResult:
        c = self._cat(cat)
        sb = self.HARDLOCKED if cat in self.hardlocked else c.state
        if isinstance(self.oracle, TracfonePolicyOracle):
            self.oracle.test_keys.pop(cat, None)
        c.key_state = 0
        return NckResult(True, "CODE_REMOVED(model-only)", cat, c.retry, c.retry, sb,
                         sb, self.render_at_preview("REMOVE_CODE", cat))

    def disable_permanent(self, cat: int) -> NckResult:
        """Model the irreversible latch on the RAM copy ONLY. See DISABLE_WARNING."""
        c = self._cat(cat)
        sb = self.HARDLOCKED if cat in self.hardlocked else c.state
        c.state = STATE_UNLOCKED
        try:
            self.model.permanent_unlock = 1  # harness latch, if present
        except AttributeError:
            pass
        return NckResult(True, "DISABLED_PERMANENT(model-only, IRREVERSIBLE on-device)",
                         cat, c.retry, c.retry, sb, STATE_UNLOCKED,
                         self.render_at_preview("DISABLE_PERMANENT", cat))

# --------------------------------------------------------------------------
# 4. What-if engine (flip DECRYPTED-model fields -> verdicts).
# --------------------------------------------------------------------------

TEST_PLMNS = {
    "tracfone-311480": TRACFONE_PLMN,
    "foreign-310260": FOREIGN_PLMN,
    "test-99970": "99970",
    "no-sim": None,
}


def what_if(ctx, changes: Dict[int, dict],
            plmns: Optional[Dict[str, Optional[str]]] = None,
            patched: bool = False) -> Dict[str, Dict[str, int]]:
    """Clone `ctx`, apply per-cat field flips, evaluate link verdicts.

    changes: {cat_index: {field: value, ...}} with fields among state, retry,
    autolock, num, key_state, key, allow_list. Returns
    {scenario: {plmn_label: verdict}} with verdict 1 == LEGAL.
    """
    mdl = copy.deepcopy(ctx)
    for cat, fields in changes.items():
        c = mdl.cats[cat]
        for k, v in fields.items():
            if not hasattr(c, k):
                raise AttributeError("SmlCategory has no field %r" % k)
            setattr(c, k, copy.deepcopy(v))
            if k == "allow_list":
                c.num = len(v)
    plmns = plmns if plmns is not None else TEST_PLMNS
    table: Dict[str, Dict[str, int]] = {}
    label = changes_label(changes) if changes else "baseline"
    table[label] = {pl: link_verdict(mdl, 0, p, patched=patched)
                    for pl, p in plmns.items()}
    return table


def changes_label(changes: Dict[int, dict]) -> str:
    bits = []
    for cat in sorted(changes):
        for k, v in changes[cat].items():
            bits.append("cat%d.%s=%r" % (cat, k, v))
    return "; ".join(bits) if bits else "baseline"


def demo_what_if() -> str:
    """Stock-vs-patched what-if demo on the Tracfone template (offline)."""
    base = make_tracfone_context()
    scenarios: List[Tuple[str, dict, bool]] = [
        ("baseline locked (stock)", {}, False),
        ("baseline locked (patched force-LEGAL)", {}, True),
        ("what-if cat0 UNLOCKED (stock)", {0: {"state": STATE_UNLOCKED}}, False),
        ("what-if cat0 allow-list +foreign (stock)",
         {0: {"allow_list": [TRACFONE_PLMN, FOREIGN_PLMN]}}, False),
        ("what-if cat0 retry exhausted (stock)", {0: {"retry": 0}}, False),
    ]
    lines = []
    for title, ch, patched in scenarios:
        tbl = what_if(base, ch, patched=patched)
        row = tbl[changes_label(ch) if ch else "baseline"]
        cells = "  ".join("%s=%s" % (k, "LEGAL(1)" if v == 1 else "ILLEGAL(0)")
                          for k, v in row.items())
        lines.append("%-42s [patched=%s] :: %s" % (title, patched, cells))
    return "\n".join(lines)

# --------------------------------------------------------------------------
# 5. Reporting (geometry table, oracle design, demos).
# --------------------------------------------------------------------------

KEY_BLOBS = {
    "SL00_000": 0xEF28,
    "SL01_000": 0xEF29,
    "LD36_003": 0xEF2F,
    "LD38_010": 0xEF31,
}

PLAINTEXT_NEEDLES = (b"311480", b"310260", b"99970", b"IMSI", b"NCK")


def geometry_table(containers: Dict[str, LidContainer]) -> str:
    hdr = ("%-10s %-8s %-5s %-6s %-8s %-8s %-10s %-8s %-7s %s"
           % ("file", "LID", "ver", "nrec", "rec", "sec/rec",
              "overhead", "ct_len", "entropy", "domain"))
    lines = [hdr, "-" * len(hdr)]
    for name in sorted(containers):
        h = containers[name].header
        lines.append(
            "%-10s 0x%04X   %-5s %-6d %-8d %-8d +%-9d %-8d %-7.2f %s%s"
            % (name, h.lid, h.ver[:3].decode("ascii", "replace"), h.rec_count,
               h.rec_size, h.sec_size, h.overhead, h.ct_len, h.entropy,
               h.domain_label,
               "" if h.domain_le == DOMAIN_SECURE_LE
               else "  (BE 0x%08X)" % h.domain_be))
    return "\n".join(lines)


def key_blob_report(containers: Dict[str, LidContainer]) -> str:
    lines = []
    for name, want_lid in KEY_BLOBS.items():
        c = containers.get(name)
        if c is None:
            lines.append("%-10s MISSING from image" % name)
            continue
        h = c.header
        ok = "OK" if h.lid == want_lid else "LID-MISMATCH(want 0x%04X)" % want_lid
        needles = [n.decode() for n in PLAINTEXT_NEEDLES if n in c.raw]
        lines.append(
            "%-10s LID 0x%04X (%s) nrec=%d rec=%d sec=%d file=%d sha=%.12s "
            "needles=%s" % (name, h.lid, ok, h.rec_count, h.rec_size, h.sec_size,
                            h.file_size, hashlib.sha256(c.raw).hexdigest(),
                            needles if needles else "none"))
    return "\n".join(lines)


def compare_images(p1: Dict[str, LidContainer], raw1: Dict[str, bytes],
                   p2: Dict[str, LidContainer], raw2: Dict[str, bytes]) -> str:
    common = sorted(set(raw1) & set(raw2))
    ident = [n for n in common
             if hashlib.sha256(raw1[n]).digest() == hashlib.sha256(raw2[n]).digest()]
    lines = ["common /md/* files: %d; byte-identical payloads: %d" % (len(common), len(ident))]
    for n in sorted(set(raw1) ^ set(raw2)):
        lines.append("  only-in-one: %s" % n)
    for n in sorted(set(common) - set(ident)):
        lines.append("  DIFF payload: %s (%d vs %d B)" % (n, len(raw1[n]), len(raw2[n])))
    only_lid = sorted(set(p1) ^ set(p2))
    if only_lid:
        lines.append("non-LID extras (expected: nv_mini_dump P1-only, DEV_INFO skipped): %s"
                     % only_lid)
    return "\n".join(lines)


def oracle_design_text() -> str:
    return """oracle design (HW-bound ciphertext -> simulation seam)
  - Ciphertext is opaque: every secure /md/* record has entropy ~7.3-8.0 and
    carries NO on-disk plaintext (no MCC/MNC/keys in the raw bytes; needles
    scan below confirms). PC-side decryption is impossible without the HW key.
  - DecryptOracle (this module): abstract decrypt(container)->SmlContext seam.
    HwBoundOracle.decrypt() always raises HwBoundDecryptError (truthful path).
    TracfonePolicyOracle.decrypt() returns the PUBLIC policy template
    (cat0 LOCK/retry5/311480, cats1..6 UNLOCK, remain 5) with provenance
    '%s'. check_key() is False for all candidates unless the analyst
    registers explicit RAM-only test keys (hypothesis keys, never device keys).
  - Future key break-in: subclass DecryptOracle, override decrypt()/check_key(),
    pass it to decrypt_with_oracle() / NckSimulator(ctx, oracle) / set_oracle().
    No call-site refactoring needed.""" % PROVENANCE_TEMPLATE


def esmlck_driver_demo() -> str:
    lines = []
    lines.append("ESMLCK offline replay driver (SIMULATION ONLY -- nothing transmitted)")
    for op, desc in ESMLCK_OPS:
        lines.append("  %-17s :: %s" % (op, desc))
        lines.append("     e.g. %s" % NckSimulator.render_at_preview(op, 0))
    lines.append(DISABLE_WARNING)
    lines.append("")
    lines.append("-- scripted offline session on a RAM copy (seed remain=5, test key "
                 "registered for cat0 only) --")
    oracle = TracfonePolicyOracle(test_keys={0: "12345678"})
    sim = NckSimulator(make_tracfone_context(), oracle=oracle)
    seq = [("query", (0,), {}),
           ("attempt_unlock wrong #1", (0,), {"code": "00000000"}),
           ("attempt_unlock wrong #2", (0,), {"code": "11111111"}),
           ("query after 2 wrong", (0,), {}),
           ("attempt_unlock correct", (0,), {"code": "12345678"}),
           ("query after unlock", (0,), {})]
    for label, args, kw in seq:
        if label.startswith("query"):
            r = sim.query(*args)
        else:
            r = sim.attempt_unlock(args[0], kw.get("code", ""))
        lines.append("  %-24s -> %-22s remain %d->%d state %s->%s" % (
            label, r.outcome, r.remain_before, r.remain_after,
            "LOCK" if r.state_before == 1 else ("HARD" if r.state_before == 2 else "UNLOCK"),
            "LOCK" if r.state_after == 1 else ("HARD" if r.state_after == 2 else "UNLOCK")))
    lines.append("  device cost of this whole session: 0 attempts (RAM-only copy).")
    # Separate exhaustion demo on a fresh copy to keep the main session readable.
    sim2 = NckSimulator(make_tracfone_context(),
                        oracle=TracfonePolicyOracle(test_keys={}))
    outs = [sim2.attempt_unlock(0, "bad%02d" % i).outcome for i in range(5)]
    lines.append("  exhaustion demo (5x wrong on fresh copy): %s; final remain=%d hardlocked=%s"
                 % (outs, sim2.model.cats[0].retry, 0 in sim2.hardlocked))
    return "\n".join(lines)


def run_selftest() -> None:
    # Geometry spot-checks on the real images (read-only).
    p1 = parse_protect(DEFAULT_P1)
    assert p1["SL00_000"].header.lid == 0xEF28
    assert (p1["SL00_000"].header.rec_size, p1["SL00_000"].header.sec_size) == (777, 832)
    assert p1["SL01_000"].header.lid == 0xEF29
    assert (p1["SL01_000"].header.rec_size, p1["SL01_000"].header.sec_size) == (259, 304)
    assert p1["LD36_003"].header.lid == 0xEF2F
    assert (p1["LD36_003"].header.rec_size, p1["LD36_003"].header.sec_size) == (690, 736)
    assert p1["LD38_010"].header.lid == 0xEF31
    assert (p1["LD38_010"].header.rec_count, p1["LD38_010"].header.rec_size,
            p1["LD38_010"].header.sec_size) == (4, 4516, 4560)
    # Oracle seam: HW path raises, policy path templates.
    try:
        HwBoundOracle().decrypt(p1["SL00_000"])
        raise AssertionError("HwBoundOracle must raise")
    except HwBoundDecryptError:
        pass
    tctx = TracfonePolicyOracle().decrypt(p1["SL00_000"])
    assert tctx.cats[0].state == STATE_LOCKED and tctx.cats[0].retry == 5
    assert tctx.cats[0].allow_list == [TRACFONE_PLMN]
    # NCK costing: 0 / 1 / hard-lock transitions.
    s = NckSimulator(tctx, oracle=TracfonePolicyOracle(test_keys={}))
    assert s.query(0).remain_after == 5
    for _ in range(4):
        r = s.attempt_unlock(0, "wrong")
        assert r.outcome == "WRONG_CODE_RETRY_LEFT"
    r = s.attempt_unlock(0, "wrong")
    assert r.outcome == "WRONG_CODE_HARD_LOCKED" and r.remain_after == 0
    r = s.attempt_unlock(0, "wrong")
    assert r.outcome == "HARD_LOCKED"
    # What-if: unlocking cat0 flips the foreign verdict via the shared seam.
    base = make_tracfone_context()
    assert link_verdict(base, 0, FOREIGN_PLMN) == ILLEGAL
    unlocked = copy.deepcopy(base)
    unlocked.cats[0].state = STATE_UNLOCKED
    assert link_verdict(unlocked, 0, FOREIGN_PLMN) == LEGAL


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="Offline NVRAM/SML-blob model (read-only, no device I/O).")
    ap.add_argument("--protect1", default=DEFAULT_P1)
    ap.add_argument("--protect2", default=DEFAULT_P2)
    ap.add_argument("--no-whatif", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)

    if args.selftest:
        run_selftest()
        print("nv_model selftest: PASS (sml_sim backend: %s)" % SML_SIM_BACKEND)
        return 0

    print("== 1. LID container parser: real-blob geometry (read-only) ==")
    print("sml_sim backend: %s" % SML_SIM_BACKEND)
    raw1, raw2 = load_protect(args.protect1), load_protect(args.protect2)
    p1 = {n: parse_lid_container(b, name=n, source=args.protect1)
          for n, b in raw1.items() if b[:4] == LID_MAGIC}
    print("--- protect1 %s (%d live /md files, %d LID) ---"
          % (args.protect1, len(raw1), len(p1)))
    print(geometry_table({k: p1[k] for k in
                          ("SL00_000", "SL01_000", "LD36_003", "LD38_010") if k in p1}))
    print("--- key-blob detail + plaintext-needle scan ---")
    print(key_blob_report(p1))
    print("--- protect1 vs protect2 (payload parity; metadata may differ) ---")
    p2 = {n: parse_lid_container(b, name=n, source=args.protect2)
          for n, b in raw2.items() if b[:4] == LID_MAGIC}
    print(compare_images(p1, raw1, p2, raw2))
    print("--- seed/checksum spot (seed varies per LID; checksum per file) ---")
    for n in ("SL00_000", "SL01_000", "LD36_003", "LD38_010"):
        if n in p1:
            h = p1[n].header
            print("  %-10s seed=%.16s.. ck=%.16s.. ver=%s flags=0x%08X attr=0x%08X"
                  % (n, h.seed.hex(), h.checksum.hex(),
                     h.ver[:3].decode("ascii", "replace"), h.flags, h.attr))
    print("")
    print("== 2. oracle-stub decrypt layer ==")
    print(oracle_design_text())
    print("")
    print("== 3. offline NCK-attempt simulator (RAM only; device cost 0) ==")
    print(esmlck_driver_demo())
    if not args.no_whatif:
        print("")
        print("== 4. what-if engine over the DECRYPTED model "
              "(SmlContext seam: %s) ==" % SML_SIM_BACKEND)
        print(demo_what_if())
        print("1 == LEGAL (link path), 0 == ILLEGAL (fail path). "
              "Baseline: home 311480 LEGAL, foreign 310260 ILLEGAL (stock); "
              "patched force-LEGAL or cat0 UNLOCK flips foreign to LEGAL.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
