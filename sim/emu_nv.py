#!/usr/bin/env python3
"""emu_nv.py — EXACT-EMULATION harness for the NVRAM read path (Kansas lab).

Emulates the NVRAM read path feeding SML checks WITHOUT touching silicon
keys. Behavioral backends (nv_model, sml_sim via nv_model seam, emu_engine)
are INTEGRATED, never modified.

LAB RULES (enforced by construction):
  * No device contact: no adb/fastboot/socket/subprocess imports. All bytes
    come from repo files (modem_bak protect images) opened read-only.
  * Read-only on dumps: protect1/2 opened 'rb' via nv_model.Ext4Image.
  * New outputs (if any) go UNDER sim/ only. This module writes nothing
    except optional HwOracle transcript JSONL under sim/oracle_logs/.
  * Stdlib only.
  * BOUNDARY RULE (load-bearing): anything requiring silicon keys STOPS at
    the HwOracle op schema (op=nv_read) with a transcript entry. The harness
    returns CACHED ciphertext bytes as a DOCUMENTED oracle stand-in for HW
    decrypt and NEVER reports crypto success as real — verdicts come from
    nv_model's public policy-oracle context (Tracfone template), explicitly
    labeled as such.

Pipeline emulated here:
  1. LID container walk on REAL protect bytes via nv_model.parse_protect /
     parse_lid_container (exact geometry: 192 B header, sec_size records).
  2. sml_sec_nvram_read* contract emulation: callers pass (LID, rec_idx);
     the harness returns a POINTER into an emulated NVRAM cache region that
     holds BYTE-IDENTICAL ciphertext copies (sha256-asserted), with
     provenance "CACHED (oracle stand-in, NOT decrypted)".
  3. Policy-oracle context (nv_model.TracfonePolicyOracle.decrypt() ->
     SmlContext, provenance "policy-template (NOT derived from ciphertext)")
     is staged into emulated sml_Verify input buffers (cat, retry,
     allow-list), and the emulated sml_Verify verdict is cross-checked
     against the behavioral sml_sim verdict via the nv_model seam
     (link_verdict / _link_fn).

Addresses (CATI extents, verified):
  * sml_Verify ................ 0x905F0F04..0x905F0F88 (50 insns, HANDOFF 3e)
  * sml_sec_nvram_read ........ 0x9198D85C..0x9198D9C8
  * sml_sec_nvram_read_to_data  0x9198BF6E..0x9198C096
  * sml_sec_nvram_read_gblob .. 0x9198D9C8..0x9198D9FA
  * sml_sec_nvram_get_para .... 0x9198BE92..0x9198BF16
  Key blobs (nv_model.KEY_BLOBS): SL00_000/EF28, SL01_000/EF29,
  LD36_003/EF2F, LD38_010/EF31.

Emulated-memory layout:
  * ROM + stack + ctx via Memory.with_image (emu_engine default).
  * "nvcache" region @0xC0000000 (64 KiB, R/W): byte-identical ciphertext
    copies, one slot per (LID-name, record). emu_sml_sec_nvram_read() returns
    pointers into this region; contents are ASSERTED sha256-equal to the
    file bytes on every call (exactness proof).
  * "verify" inputs @CTX_BASE+0x6000 (1 page, R/W): u32 cat, u32 retry,
    u32 allow_count + NUL-terminated PLMN bytes. Staged from the POLICY
    context (never from ciphertext).

Oracle boundary (exact schema):
  * HwOracle.OPS includes "nv_read" (needs LID, rec_idx). oracle_nv_read()
    calls HwOracle.query("nv_read", {"lid":..., "rec_idx":...,
    "source":...}) which ALWAYS raises OracleUnimplemented (no transport in
    this package) AND appends a transcript entry. The harness catches the
    raise, keeps the entry id, and returns the CACHED bytes with that id
    attached. No path returns LEGAL/PASS derived from ciphertext.
  * HwBoundOracle.decrypt() truthfully raises HwBoundDecryptError; the
    harness asserts this in selftest to prove it never "decrypts".

Run:
  python sim/emu_nv.py --selftest   # geometry + cache-exact + oracle-stop + verify-match
  python sim/emu_nv.py --geometry    # LID table from real protect1
  python sim/emu_nv.py --match       # verify-match table only
"""
from __future__ import annotations

import hashlib
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path
import os

SIM_DIR = Path(__file__).resolve().parent
REPO_ROOT = SIM_DIR.parent
TEMP = Path(os.environ.get("MODEM_LAB_TMP",
                str(Path(__file__).resolve().parent / "Temp")))
TEMP.mkdir(parents=True, exist_ok=True)
if str(SIM_DIR) not in sys.path:
    sys.path.insert(0, str(SIM_DIR))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

try:
    from sim.emu_engine import (  # type: ignore
        CTX_BASE, PERM_R, PERM_W, HwOracle, Image, Memory,
        MemoryFault, OracleUnimplemented, StubRegistry, Tracer, decode_one,
    )
except ImportError:
    from emu_engine import (  # type: ignore
        CTX_BASE, PERM_R, PERM_W, HwOracle, Image, Memory,
        MemoryFault, OracleUnimplemented, StubRegistry, Tracer, decode_one,
    )

try:
    from sim import nv_model as _nv  # type: ignore
except ImportError:
    import nv_model as _nv  # type: ignore

# ---------------------------------------------------------------- constants
SML_VERIFY_VA = 0x905F0F04
SML_VERIFY_END = 0x905F0F88
SEC_READ_VA = 0x9198D85C
SEC_READ_END = 0x9198D9C8
SEC_READ_TO_DATA_VA = 0x9198BF6E
SEC_READ_TO_DATA_END = 0x9198C096
SEC_READ_GBLOB_VA = 0x9198D9C8
SEC_READ_GBLOB_END = 0x9198D9FA
SEC_GET_PARA_VA = 0x9198BE92
SEC_GET_PARA_END = 0x9198BF16

NV_CACHE_BASE = 0xC0000000
NV_CACHE_SIZE = 0x40000  # 256 KiB (all 40 LID blobs total ~113 KiB; headroom)
VERIFY_ARG_BASE = CTX_BASE + 0x10000
VERIFY_ARG_SIZE = 0x1000

CACHED_PROVENANCE = "CACHED ciphertext (oracle stand-in for HW decrypt; NOT decrypted)"
POLICY_PROVENANCE = _nv.PROVENANCE_TEMPLATE  # "policy-template (NOT derived from ciphertext)"

SEC_FUNCS = {
    SEC_READ_VA: ("sml_sec_nvram_read", SEC_READ_END),
    SEC_READ_TO_DATA_VA: ("sml_sec_nvram_read_to_data", SEC_READ_TO_DATA_END),
    SEC_READ_GBLOB_VA: ("sml_sec_nvram_read_gblob", SEC_READ_GBLOB_END),
    SEC_GET_PARA_VA: ("sml_sec_nvram_get_para", SEC_GET_PARA_END),
}


# ---------------------------------------------------------------- results
@dataclass
class NvReadResult:
    lid: int
    lid_name: str
    rec_idx: int
    emu_ptr: int
    length: int
    sha256: str
    provenance: str = CACHED_PROVENANCE
    oracle_entry: int = 0  # 1-based HwOracle transcript index
    verify_staged: bool = False


@dataclass
class VerifyMatch:
    label: str
    cat: int
    plmn: str | None
    emulated: int
    behavioral: int
    match: bool
    note: str = ""


# ---------------------------------------------------------------- harness
class EmuNvram:
    """Exact-emulation harness for sml_sec_nvram_read* -> sml_Verify.

    Usage:
      h = EmuNvram()                      # loads real protect1 (read-only)
      r = h.emu_sml_sec_nvram_read(0xEF28, 0)   # CACHED bytes + oracle stop
      m = h.check_verify_match()          # [VerifyMatch...] vs behavioral
    """

    def __init__(self, protect1: str | None = None,
                 image_path: Path | None = None) -> None:
        self.protect1 = protect1 or _nv.DEFAULT_P1
        self.raw_files = _nv.load_protect(self.protect1)  # read-only ext4 walk
        self.containers = _nv.parse_protect(self.protect1)  # LID walk
        self.image = Image.load_romonly(image_path) if image_path else Image.load_romonly()
        self.mem = Memory.with_image(self.image)
        self.mem.add("nvcache", NV_CACHE_BASE, NV_CACHE_SIZE, PERM_R | PERM_W)
        self.mem.add("verify", VERIFY_ARG_BASE, VERIFY_ARG_SIZE, PERM_R | PERM_W)
        self.stubs = StubRegistry()
        for va in SEC_FUNCS:
            self.stubs.set(va, "behavioral", SEC_FUNCS[va][0])
        self.stubs.set(SML_VERIFY_VA, "behavioral", "sml_Verify")
        self.stub_pages = self.stubs.materialize(self.mem)
        self.tracer = Tracer()
        self.step = 0
        self.oracle = HwOracle()
        self.policy_oracle = _nv.TracfonePolicyOracle()
        self._cache_map: dict[tuple[str, int], int] = {}
        self._layout_cache()

    # -- internal ---------------------------------------------------------
    def _log(self, pc: int, text: str, a0: int | None = None) -> None:
        self.step += 1
        self.tracer.log(self.step, pc, text, a0)

    def _layout_cache(self) -> None:
        """Copy every LID ciphertext record into nvcache (byte-exact)."""
        off = 0
        for name in sorted(self.containers):
            c = self.containers[name]
            for i, rec in enumerate(c.records):
                if off + len(rec) > NV_CACHE_SIZE:
                    raise MemoryFault(NV_CACHE_BASE + off, "nvcache-exhausted")
                self.mem.write(NV_CACHE_BASE + off, bytes(rec))
                self._cache_map[(name, i)] = NV_CACHE_BASE + off
                off += len(rec)
        self._cache_used = off

    def _find_container(self, lid: int) -> tuple[str, object]:
        for name, c in self.containers.items():
            if c.header.lid == lid:
                return name, c
        raise KeyError(f"LID 0x{lid:04X} not in protect image")

    # -- oracle boundary (silicon-key stop) -------------------------------
    def oracle_nv_read(self, lid: int, rec_idx: int, source: str = "") -> int:
        """Stop at the HwOracle op schema; returns transcript entry id.

        ALWAYS raises-and-records inside HwOracle.query (no transport); the
        entry is kept so the CACHED return below is auditable. Never returns
        key material or a crypto verdict.
        """
        try:
            self.oracle.query("nv_read", {"lid": f"0x{lid:04X}", "rec_idx": rec_idx,
                                          "source": source or self.protect1})
        except OracleUnimplemented:
            pass
        return len(self.oracle.transcript)  # 1-based id of the entry just added

    # -- emulated sml_sec_nvram_read* (CACHED contract) --------------------
    def emu_sml_sec_nvram_read(self, lid: int, rec_idx: int = 0,
                               via: int = SEC_READ_VA) -> NvReadResult:
        """Emulate sml_sec_nvram_read(lid, rec_idx) -> CACHED ciphertext ptr.

        Exactness: returned bytes are asserted sha256-equal to the file
        bytes; provenance is CACHED (never "decrypted"). The oracle stop
        (op=nv_read transcript entry) is taken on EVERY call.
        """
        fname, _ = SEC_FUNCS.get(via, ("sml_sec_nvram_read", 0))
        self._log(via, f"ENTRY {fname}(lid=0x{lid:04X}, rec={rec_idx})")
        name, cont = self._find_container(lid)
        if not (0 <= rec_idx < cont.header.rec_count):
            raise IndexError(f"rec {rec_idx} out of 0..{cont.header.rec_count - 1}")
        entry_id = self.oracle_nv_read(lid, rec_idx, source=f"{self.protect1}:{name}")
        self._log(via, f"ORACLE-STOP op=nv_read entry=#{entry_id} (no transport; cached)")
        ptr = self._cache_map[(name, rec_idx)]
        expect = cont.records[rec_idx]
        got = self.mem.read(ptr, len(expect))
        assert bytes(got) == bytes(expect), f"nvcache drift for {name}[{rec_idx}]"
        sha = hashlib.sha256(bytes(got)).hexdigest()
        self._log(via, f"RETURN CACHED ptr={ptr:#x} len={len(got)} sha={sha[:12]}..", len(got))
        self.stubs.hits.append((via, "behavioral-cached"))
        return NvReadResult(lid, name, rec_idx, ptr, len(got), sha,
                            CACHED_PROVENANCE, entry_id)

    # -- policy context -> emulated sml_Verify inputs ----------------------
    def build_verify_inputs(self, cat: int = 0,
                            plmn: str | None = None) -> tuple[int, object]:
        """Stage POLICY-context verify inputs in emulated memory.

        ctx comes from TracfonePolicyOracle (public template, NOT from
        ciphertext). Layout @VERIFY_ARG_BASE: u32 cat, u32 retry,
        u32 allow_count, then NUL-terminated PLMN bytes. Returns (ptr, ctx).
        """
        # Policy context: use one representative container (SL00_000/EF28).
        name, cont = self._find_container(0xEF28)
        ctx = self.policy_oracle.decrypt(cont)
        if not (0 <= cat < len(ctx.cats)):
            raise IndexError(f"cat {cat} out of range")
        c = ctx.cats[cat]
        allow = list(c.allow_list)
        pbytes = (plmn or "").encode("ascii") + b"\x00"
        if 12 + len(pbytes) > VERIFY_ARG_SIZE:
            raise MemoryFault(VERIFY_ARG_BASE, "verify-arg-overflow")
        self.mem.write(VERIFY_ARG_BASE, struct.pack("<III", cat, c.retry, len(allow)))
        self.mem.write(VERIFY_ARG_BASE + 12, pbytes)
        self._log(SML_VERIFY_VA,
                  f"STAGE verify cat={cat} retry={c.retry} allow={allow} plmn={plmn!r} "
                  f"(policy-template, NOT ciphertext)")
        return VERIFY_ARG_BASE, ctx

    def emu_sml_verify(self, cat: int = 0, plmn: str | None = None) -> tuple[int, object]:
        """Emulated sml_Verify verdict from POLICY-staged inputs.

        Reads cat/retry/allow back from EMULATED memory (not the Python ctx),
        then evaluates via the shared nv_model->sml_sim seam (link_verdict).
        Returns (verdict, ctx). 1=LEGAL, 0=ILLEGAL.
        """
        ptr, ctx = self.build_verify_inputs(cat, plmn)
        raw = self.mem.read(ptr, 12)
        ecat, eretry, eallow_n = struct.unpack("<III", raw)
        assert ecat == cat, "verify-arg drift"
        # Emulated gate chain (mirrors sml_Verify HANDOFF summary at block
        # level; crypto stages are oracle-stopped, policy gate decides):
        self._log(SML_VERIFY_VA, f"ENTRY sml_Verify cat={ecat} retry={eretry}")
        self._log(SML_VERIFY_VA, "mot_sml_catkey_verify -> ORACLE-STOP (no silicon key; "
                                 "policy gate decides, never fake-crypto)")
        verdict = int(_nv.link_verdict(ctx, ecat, plmn, patched=False))
        self._log(SML_VERIFY_VA, f"RETURN verdict={verdict} (policy-template verdict)")
        return verdict, ctx

    # -- cross-checks ------------------------------------------------------
    def check_verify_match(self, patched: bool = False) -> list[VerifyMatch]:
        """Assert emulated Verify inputs match behavioral verdicts.

        Matrix (stock unless patched=True): home 311480 LEGAL, foreign
        310260 ILLEGAL, no-SIM ILLEGAL, test 99970 ILLEGAL. Patched=True
        forces all-LEGAL via the same seam the modem patch uses.
        """
        cases = [("home-311480", 0, _nv.TRACFONE_PLMN),
                 ("foreign-310260", 0, _nv.FOREIGN_PLMN),
                 ("no-sim", 0, None),
                 ("test-99970", 0, "99970")]
        out: list[VerifyMatch] = []
        for label, cat, plmn in cases:
            ptr, ctx = self.build_verify_inputs(cat, plmn)
            raw = self.mem.read(ptr, 12)
            ecat, _, _ = struct.unpack("<III", raw)
            emu_v = int(_nv.link_verdict(ctx, ecat, plmn, patched=patched))
            beh_v = int(_nv.link_verdict(_nv.make_tracfone_context(), cat, plmn,
                                         patched=patched))
            out.append(VerifyMatch(label, cat, plmn, emu_v, beh_v, emu_v == beh_v,
                                   "policy-template seam; ciphertext never decrypted"))
        return out

    def geometry_rows(self) -> list[str]:
        rows = []
        for name in ("SL00_000", "SL01_000", "LD36_003", "LD38_010"):
            c = self.containers.get(name)
            if c is None:
                rows.append(f"{name} MISSING")
                continue
            h = c.header
            rows.append(f"{name} LID=0x{h.lid:04X} nrec={h.rec_count} "
                        f"rec={h.rec_size} sec={h.sec_size} ct={h.ct_len}B "
                        f"H={h.entropy:.2f} {h.domain_label}")
        return rows


# ---------------------------------------------------------------- selftest
def selftest() -> int:
    fails: list[str] = []
    try:
        h = EmuNvram()
    except Exception as e:  # noqa: BLE001
        print(f"emu_nv selftest: FAIL (init: {e!r})")
        return 1
    # 1. LID geometry on REAL protect bytes (same asserts as nv_model).
    try:
        p1 = h.containers
        assert p1["SL00_000"].header.lid == 0xEF28
        assert (p1["SL00_000"].header.rec_size, p1["SL00_000"].header.sec_size) == (777, 832)
        assert p1["SL01_000"].header.lid == 0xEF29
        assert (p1["SL01_000"].header.rec_size, p1["SL01_000"].header.sec_size) == (259, 304)
        assert p1["LD36_003"].header.lid == 0xEF2F
        assert (p1["LD36_003"].header.rec_size, p1["LD36_003"].header.sec_size) == (690, 736)
        assert p1["LD38_010"].header.lid == 0xEF31
        assert (p1["LD38_010"].header.rec_count, p1["LD38_010"].header.rec_size,
                p1["LD38_010"].header.sec_size) == (4, 4516, 4560)
    except Exception as e:  # noqa: BLE001
        fails.append(f"geometry: {e!r}")
    # 2. CACHED contract: emu read bytes == file bytes (sha), provenance set.
    try:
        r = h.emu_sml_sec_nvram_read(0xEF28, 0)
        expect = h.containers[r.lid_name].records[0]
        assert r.sha256 == hashlib.sha256(bytes(expect)).hexdigest(), "sha drift"
        assert r.provenance == CACHED_PROVENANCE
        assert r.oracle_entry >= 1
        assert h.oracle.transcript[r.oracle_entry - 1].op == "nv_read"
        # via alias entry point behaves identically (same cache, new entry).
        r2 = h.emu_sml_sec_nvram_read(0xEF28, 0, via=SEC_READ_TO_DATA_VA)
        assert r2.sha256 == r.sha256 and r2.oracle_entry == r.oracle_entry + 1
    except Exception as e:  # noqa: BLE001
        fails.append(f"cached-read: {e!r}")
    # 3. Boundary: HwBoundOracle truthfully raises (never decrypts); our
    #    policy path is labeled template, never ciphertext-derived.
    try:
        name, cont = h._find_container(0xEF28)
        try:
            _nv.HwBoundOracle().decrypt(cont)
            fails.append("boundary: HwBoundOracle must raise")
        except _nv.HwBoundDecryptError:
            pass
        ctx = h.policy_oracle.decrypt(cont)
        assert ctx.cats[0].state == _nv.STATE_LOCKED and ctx.cats[0].retry == 5
        assert ctx.cats[0].allow_list == [_nv.TRACFONE_PLMN]
    except Exception as e:  # noqa: BLE001
        fails.append(f"boundary: {e!r}")
    # 4. Verify-match matrix (stock + patched) via POLICY seam.
    try:
        for m in h.check_verify_match(patched=False):
            if not m.match:
                fails.append(f"verify-stock[{m.label}]: emu={m.emulated} beh={m.behavioral}")
        stock = {m.label: m.emulated for m in h.check_verify_match(patched=False)}
        assert stock["home-311480"] == 1 and stock["foreign-310260"] == 0, f"{stock}"
        for m in h.check_verify_match(patched=True):
            if not m.match or m.emulated != 1:
                fails.append(f"verify-patched[{m.label}]: emu={m.emulated} beh={m.behavioral}")
        # Emulated-memory round-trip: staged cat byte is what verdict used.
        ptr, _ctx = h.build_verify_inputs(0, _nv.TRACFONE_PLMN)
        assert struct.unpack("<I", h.mem.read(ptr, 4))[0] == 0
    except Exception as e:  # noqa: BLE001
        fails.append(f"verify-match: {e!r}")
    # 5. CATI extents for the NV funcs (read-only file if present).
    try:
        cj = TEMP / "cati_syms.json"
        if cj.is_file():
            import json as _j
            d = _j.loads(cj.read_text())
            assert d["sml_Verify"] == ["905f0f04", "905f0f88"], "sml_Verify extent"
            assert d["sml_sec_nvram_read"][0] == "9198d85c"
    except Exception as e:  # noqa: BLE001
        fails.append(f"cati: {e!r}")
    print("emu_nv selftest:", "PASS" if not fails else "FAIL")
    for f in fails:
        print("  -", f)
    if not fails:
        print("  geometry (real protect1):")
        for row in h.geometry_rows():
            print("   ", row)
        print(f"  nvcache used {h._cache_used}B; oracle entries {len(h.oracle.transcript)}")
        for m in h.check_verify_match(patched=False):
            print(f"  verify stock {m.label}: emu={m.emulated} behav={m.behavioral} "
                  f"{'PASS' if m.match else 'FAIL'}")
    return 1 if fails else 0


def main(argv: list[str]) -> int:
    if "--selftest" in argv or not argv:
        return selftest()
    if "--geometry" in argv:
        h = EmuNvram()
        print(f"protect1: {h.protect1} ({len(h.raw_files)} /md files, "
              f"{len(h.containers)} LID)")
        for row in h.geometry_rows():
            print(row)
        print("provenance: ciphertext " + _nv.PROVENANCE_HWBOUND)
        print("provenance: policy " + POLICY_PROVENANCE)
        return 0
    if "--match" in argv:
        h = EmuNvram()
        rc = 0
        # Demonstrate the oracle stop on the read path (one CACHED call).
        demo = h.emu_sml_sec_nvram_read(0xEF28, 0)
        print(f"demo read EF28[0]: ptr={demo.emu_ptr:#x} len={demo.length} "
              f"sha={demo.sha256[:12]}.. prov=[{demo.provenance}] "
              f"oracle_entry=#{demo.oracle_entry} op=nv_read")
        for patched in (False, True):
            print(f"--- patched={patched} ---")
            for m in h.check_verify_match(patched=patched):
                ok = m.match and (m.emulated == 1 if patched else True)
                print(f"{'PASS' if ok else 'FAIL'} {m.label} "
                      f"plmn={m.plmn!r} emu={m.emulated} behav={m.behavioral} :: {m.note}")
                rc |= 0 if ok else 1
        print(f"oracle transcript entries: {len(h.oracle.transcript)} "
              f"(op=nv_read stops on the read path; verify path uses the "
              f"policy template — no crypto success faked)")
        return rc
    print("usage: emu_nv.py [--selftest|--geometry|--match]")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
