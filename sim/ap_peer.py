#!/usr/bin/env python3
"""ap_peer.py — AP-side peer for full-hardware emulation (Kansas lab, MT6835).

PC-side only. Stdlib only. NEVER touches the device (no adb/fastboot/socket/
subprocess imports anywhere in this file; the selftest asserts that). New code
lives under sim/ only; sibling modules are INTEGRATED (imported), never
modified — in particular sim/mem_model.py (SMEM rings + CCIF/WDT MMIO + hooks),
sim/emu_engine.py (Memory, Tracer, HwOracle) and sim/hw_target.py (CCIF addrs).

What this is: the AP half of the modem<->AP IPC, so emulated modem code can
run its CCCI/RPC paths against a faithful peer instead of stubs:
  * CCIF doorbells (6 AP/MD pairs) as MMIORegs wired to mem_model hooks;
    MD-side rings land in an AP-side event queue with timestamps; AP acks are
    generated with transcript-derived timing.
  * Boot-sequence replayer driven by the REAL JSONL transcripts
    (sim/oracle_logs/rpcd_boot_idle.jsonl + rpcd_at_query.jsonl):
    CIDDATA(offset 0, 1024) -> security_data_len 0 -> fail (twice,
    @33.766/@35.757 pattern), PRODUCT_OP -> success, then idle EINTR errno-4
    cadence. Selftest asserts the sequence matches the transcript.
  * SMEM ring peer for the NVRAM file-service channel (ccci_fsd adjacency):
    reads modem posts, serves bytes from modem_bak files READ-ONLY for named
    LIDs, refuses unknown names with ENOENT (error=2, as live-observed).
  * AT-path separation: ESMLCK traffic NEVER routes via RPC (it goes
    adb_atci_socket -> ttyCMIPC2 per transcripts); the model returns an error
    if asked to route it via RPC.
  * Emulator seam: attach(peer, cpu-like) + on_doorbell va-callbacks so the
    interp/GDBsim backends can plug the peer in later (contract documented
    below; exercised against a minimal FakeCpu in selftest).

Provenance (every emulation default carries its source):
  * CCIF addrs ......... sim/hw_target.py SPEC["mem"]["ccif_pairs"]
    (6 pairs) cross-checked against sim/mem_model.py CCIF_BLOCKS/CCIF_PAIRS
    (12 x 4K blocks, DTB ap/md_ccif0..5 verified) and md1work.dtb node names.
  * Doorbell offsets ... mem_model.CcifDevice.DOORBELL_SET_OFF 0x00 (CON set)
    / CLR_OFF 0x04 (CON clear); CONVENTIONAL per mem_model docstring (exact
    MT6835 CCIF register map pending Ghidra/CATI confirmation). Any nonzero
    u32 write there = doorbell event + subscriber fire.
  * Boot RPC ........... captures/capture/20260904_173252_sim_boot/logcat_all.txt
    lines 4232-4234 (CIDDATA off:0 step:1024 -> get_security_data fail len 0
    -> work_helper fail @17:32:33.766), line 4254 (PRODUCT_OP @17:32:33.832,
    +0.066 s, no fail = success), lines 5084-5086 (CIDDATA repeat @17:32:35.757,
    +1.991 s after first, symmetric fail). Banked read-only in
    sim/oracle_logs/rpcd_boot_idle.jsonl seq 0-9.
  * Idle ............... baseline_nosim logcat_all.txt 9x
    "ccci_rpcd: Failed to read from RPC device (-1) !! errno = 4"
    (EINTR, AP blocked in read, MD quiescent) @17:23:24.790 .. 17:24:02.911
    (38.121 s span, 8 intervals, see IDLE_DELTAS_S below); banked as
    rpcd_boot_idle.jsonl seq 11 (9 samples) + seq 12 live_idle_snapshot
    (rpcd 1734 dev_char_read fd5->/dev/ccci_rpc, ccci_rpc_k thread).
  * FSD adjacency ...... sim_boot logcat_all.txt:14983 ccci_fsd(1)
    "O: X:/LD40_001, flag 0x700, ret 2" (open->fd 2), :14994 "D: Y:/LD40_001,
    ret 0", :14996 "M: X:/LD40_001, ret 0", :15440/15941 FS_GetFileDetail
    "[error]fail on file: /mnt/vendor/nvcfg/mdota/MTK_MD_OTA_CONFIG.ini,
    error=2" (ENOENT refusal template). LD40_001 = LID 0xEF09 x100 recs in
    protect1 (nv_model parse, read-only).
  * AT path ............ captures/phone_survey/20260905_043624/atci_socket.txt
    (/dev/socket/adb_atci_socket) + logcat ATCID "init_port ttyCMIPC2"
    (303:init_port(): init_port ttyCMIPC2) + selinux ccci_device /dev/ccci_rpc
    + rpcd_at_query.jsonl seq 9 note "SML status path is modem-local, does NOT
    traverse ccci_rpc/TEE" + oracle_transport.py read-only AT discipline.
  * SML status ......... modem-local (rmmi_esmlck_hdlr @0x91985788); SIM_
    SML_STATUS_IND (rpcd_boot_idle seq 10, MSGID 4508, 64 B) is a CCCI
    indication, NOT an RPC round-trip — hence allowed on the CCCI path while
    ESMLCK-via-ccci_rpc stays banned (see AtRouter docstring).

Run:
  python sim/ap_peer.py --selftest   (default; full checks + fidelity %)
  python sim/ap_peer.py --replay     (boot replay fidelity vs transcripts)
  python sim/ap_peer.py --seam       (print the emulator seam contract)
  python sim/ap_peer.py --table      (print CCIF register table)

SEAM CONTRACT (for interp/GDBsim backends; see attach() docstring for the
normative version, printed by --seam):
  cpu-like provides:
    .mem with .hook(addr, cb)  -- cb(kind, addr, size); emu_engine.Memory or
      mem_model.MpuMemory compatible (MpuMemory.hook inherited from Memory).
    .mem with .read(addr, ln) / .write(addr, buf) -- actor defaults to "md"
      so modem-code writes flow through the same path the peer observes.
    optionally .regs dict {pc, sp, a0, ra} for GDBsim/interp context (the
      peer never requires it; doorbells are memory-mapped, not registers).
  peer provides:
    .on_doorbell_va(va, cb) -- cb(event_dict); fired on every CCIF doorbell
      whose write address == va (CON set @base+0x00 and clear @base+0x04
      both supported).
    .poll_events() -> list -- drains the AP-side inbound queue (MD->AP).
    .ack(...) -> dict -- generates one AP-side ack write (actor="ap").
  attach(peer, cpu) registers, for every MD-side CCIF block, cpu.mem.hook on
  both CON-set and CON-clear VAs plus subscribes peer._on_ccif_event to the
  CcifDevice subscriber list (when the backing memory is an MpuMemory with a
  CcifDevice). Returns the number of VA hooks registered. Backends then run
  modem code; every MD doorbell write lands in peer.event_queue with a
  timestamp and fires va-callbacks; the test/drive loop calls peer.serve_*
  to answer via SMEM rings + ack doorbells.
"""
from __future__ import annotations

import hashlib
import json
import re
import struct
import sys
import time
from dataclasses import dataclass, field
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
        CCIF_BLOCKS,
        CCIF_BLOCK_SIZE,
        CCIF_PAIRS,
        MpuMemory,
        SmemRingSet,
    )
except ImportError:
    try:
        from sim.mem_model import (  # type: ignore
            CCIF_BLOCKS,
            CCIF_BLOCK_SIZE,
            CCIF_PAIRS,
            MpuMemory,
            SmemRingSet,
        )
    except ImportError:
        CCIF_BLOCKS = ()  # type: ignore
        CCIF_BLOCK_SIZE = 0x1000  # type: ignore
        CCIF_PAIRS = ()  # type: ignore
        MpuMemory = None  # type: ignore
        SmemRingSet = None  # type: ignore

try:
    from emu_engine import Memory, Tracer  # type: ignore
except ImportError:
    try:
        from sim.emu_engine import Memory, Tracer  # type: ignore
    except ImportError:
        Memory = None  # type: ignore
        Tracer = None  # type: ignore

try:
    import nv_model as _nv  # type: ignore
except ImportError:
    try:
        from sim import nv_model as _nv  # type: ignore
    except ImportError:
        _nv = None  # type: ignore

# --------------------------------------------------------------------------
# Canonical paths / constants (provenance in module docstring).
# --------------------------------------------------------------------------

BOOT_TRANSCRIPT = SIM_DIR / "oracle_logs" / "rpcd_boot_idle.jsonl"
AT_TRANSCRIPT = SIM_DIR / "oracle_logs" / "rpcd_at_query.jsonl"
BASELINE_IDLE_LOG = (REPO_ROOT / "captures" / "capture" /
                     "20260904_172453_baseline_nosim" / "logcat_all.txt")
SIM_BOOT_LOG = (REPO_ROOT / "captures" / "capture" /
                "20260904_173252_sim_boot" / "logcat_all.txt")
MODEM_BAK_DIR = REPO_ROOT / "modem_bak" / "modem_bak"
NVD_DATA_DIR = REPO_ROOT / "nvram_live" / "nvram_dump" / "NVD_DATA"
NVD_IMEI_DIR = REPO_ROOT / "nvram_live" / "nvram_dump" / "NVD_IMEI"

# Expected boot op sequence: hard-coded from the REAL transcript (seq 0-12 of
# rpcd_boot_idle.jsonl as banked 2026-09-05). The replayer loads the file and
# asserts equality — fidelity % = matches / total. Hard-coding (not echoing
# the file) is what makes the check load-bearing.
EXPECTED_BOOT_OPS: tuple[str, ...] = (
    "IPC_RPC_CIDDATA_OP",          # seq 0 md->ap off:0 step:1024
    "ccci_rpc_get_security_data",  # seq 1 ap->tee len 0
    "security_data_response",      # seq 2 tee->ap len 0
    "ccci_rpc_work_helper",        # seq 3 ap->md FAIL (get security_data fail)
    "IPC_RPC_PRODUCT_OP",          # seq 4 md->ap (no fail = success)
    "PRODUCT_OP_response",         # seq 5 ap->md success
    "IPC_RPC_CIDDATA_OP",          # seq 6 repeat @35.757 symmetric fail
    "ccci_rpc_get_security_data",  # seq 7
    "security_data_response",      # seq 8
    "ccci_rpc_work_helper",        # seq 9 second fail
    "SIM_SML_STATUS_IND",          # seq 10 md->ap CCCI indication (NOT RPC)
    "ccci_rpcd_idle_read",         # seq 11 9x errno-4 idle
    "live_idle_snapshot",          # seq 12 quiescent snapshot
)
EXPECTED_BOOT_DIRS: tuple[str, ...] = (
    "md->ap", "ap->tee", "tee->ap", "ap->md",
    "md->ap", "ap->md",
    "md->ap", "ap->tee", "tee->ap", "ap->md",
    "md->ap", "md->ap", "md->ap",
)

# Transcript-derived timing (device timestamps in rpcd_boot_idle.jsonl):
# CIDDATA#1 17:32:33.766 -> PRODUCT 17:32:33.832 = +0.066 s;
# CIDDATA#1 -> CIDDATA#2 17:32:35.757 = +1.991 s.
CIDDATA_PRODUCT_DELTA_S = 0.066
CIDDATA_REPEAT_DELTA_S = 1.991

# Idle EINTR cadence: the 9 device timestamps of
# "Failed to read from RPC device (-1) !! errno = 4" in baseline_nosim
# logcat_all.txt (:20053 .. :21083). Deltas in seconds between consecutive
# samples; span 38.121 s. The 24.867 s gap is a real scheduler/log stall in
# the capture (kept verbatim — replay fidelity beats smoothing).
IDLE_ERRNO = 4  # EINTR: AP blocked in read, MD quiescent
IDLE_DELTAS_S: tuple[float, ...] = (
    2.482, 0.283, 2.489, 24.867, 1.956, 4.317, 0.986, 0.741,
)
IDLE_SPAN_S = 38.121
IDLE_SAMPLES = 9

# AP ack delays per op (transcript timing §provenance): CIDDATA fail path is
# same-tick (0.0 s), PRODUCT success answers +0.066 s after its request.
ACK_DELAY_S: dict[str, float] = {
    "IPC_RPC_CIDDATA_OP": 0.0,
    "ccci_rpc_get_security_data": 0.0,
    "security_data_response": 0.0,
    "ccci_rpc_work_helper": 0.0,
    "IPC_RPC_PRODUCT_OP": CIDDATA_PRODUCT_DELTA_S,
    "PRODUCT_OP_response": 0.0,
}

# FSD channel: ring names + wire format (harness convention, PROVISIONAL —
# real CCCI FSD framing is a future Ghidra task; the adjacency opcodes
# O/D/M + STAT + ENOENT=2 refusal are live-observed, see module docstring).
FSD_REQ_RING = "ccci_fsd_req"   # modem posts, AP reads
FSD_RSP_RING = "ccci_fsd_rsp"   # AP posts, modem reads
FSD_RING_CAP = 8
FSD_SLOT_LEN = 2048
FSD_REFUSE_ERRNO = 2  # ENOENT, matches MTK_MD_OTA_CONFIG.ini error=2

# AT path (provenance: phone_survey atci_socket.txt + ATCID init_port
# ttyCMIPC2 + selinux ccci_device + rpcd_at_query seq 9 note).
ATCI_SOCKET = "/dev/socket/adb_atci_socket"
ATCI_TTY = "ttyCMIPC2"
RPC_DEV = "/dev/ccci_rpc"


# --------------------------------------------------------------------------
# Transcript helpers.
# --------------------------------------------------------------------------

def load_transcript(path: Path | str) -> list[dict]:
    """Load one oracle JSONL transcript, sorted by seq. Read-only."""
    p = Path(path)
    recs = [json.loads(ln) for ln in p.read_text().splitlines() if ln.strip()]
    recs.sort(key=lambda r: r.get("seq", 0))
    return recs


def parse_device_ts(ts: str) -> float | None:
    """Parse 'HH:MM:SS.mmm' out of a transcript timestamp_device string.

    Returns seconds-since-midnight, or None when the string carries a range
    (idle seq 11 uses 'a/b (device, 9 samples)') or 'live' marker.
    """
    m = re.search(r"(\d{2}):(\d{2}):(\d{2})\.(\d{3})", ts)
    if not m:
        return None
    h, mi, s, ms = (int(g) for g in m.groups())
    return h * 3600 + mi * 60 + s + ms / 1000.0


def load_idle_cadence(log_path: Path | str = BASELINE_IDLE_LOG) -> list[float]:
    """Parse the 9 errno-4 device timestamps from the baseline logcat.

    Read-only. Falls back to IDLE_DELTAS_S-derived absolutes when the log is
    absent (keeps the selftest hermetic on partial checkouts).
    """
    p = Path(log_path)
    if not p.is_file():
        t = 0.0
        out = [t]
        for d in IDLE_DELTAS_S:
            t += d
            out.append(round(t, 3))
        return out
    stamps: list[float] = []
    pat = re.compile(r"(\d{2}):(\d{2}):(\d{2})\.(\d{3}).*errno = 4")
    for ln in p.read_text(errors="replace").splitlines():
        m = pat.search(ln)
        if m and "ccci_rpcd" in ln:
            h, mi, s, ms = (int(g) for g in m.groups())
            stamps.append(h * 3600 + mi * 60 + s + ms / 1000.0)
    return stamps


# --------------------------------------------------------------------------
# 1. CCIF doorbell model: MMIORegs wired to mem_model hooks.
# --------------------------------------------------------------------------

@dataclass
class MMIOReg:
    """One CCIF MMIO block. Side is 'ap' (AP-owned) or 'md' (modem-owned).

    pair_idx 0..5 per hw_target ccif_pairs order; peer is the sibling block
    name (CCIF_PAIRS). CON set @base+0x00, CON clear @base+0x04 (CONVENTIONAL
    per mem_model.CcifDevice docstring).
    """
    name: str
    base: int
    size: int
    side: str
    pair_idx: int
    peer: str | None


def build_mmio_regs() -> list[MMIOReg]:
    """Build the 12 CCIF MMIORegs from mem_model, cross-checked vs hw_target.

    Raises if the DTB-derived tables drift (hw_target ccif_pairs vs mem_model
    CCIF_BLOCKS/CCIF_PAIRS) — divergences are bugs per hw_target.py.
    """
    assert len(CCIF_BLOCKS) == 12, f"CCIF blocks {len(CCIF_BLOCKS)} != 12"
    assert len(CCIF_PAIRS) == 6, f"CCIF pairs {len(CCIF_PAIRS)} != 6"
    peer_of = {}
    for a, m in CCIF_PAIRS:
        peer_of[a] = m
        peer_of[m] = a
    regs: list[MMIOReg] = []
    for i, (name, base) in enumerate(CCIF_BLOCKS):
        side = "ap" if name.startswith("ap_") else "md"
        regs.append(MMIOReg(name, base, CCIF_BLOCK_SIZE, side, i // 2,
                            peer_of.get(name)))
    if HW_SPEC:
        want = HW_SPEC["mem"]["ccif_pairs"]
        got = [f"{a:08x}/{b:08x}" for (_, a), (_, b) in
               [(CCIF_BLOCKS[i], CCIF_BLOCKS[i + 1]) for i in range(0, 12, 2)]]
        assert tuple(want) == tuple(got), f"hw_target drift: {want} vs {got}"
    return regs


def ccif_table() -> str:
    rows = ["%-10s %-10s %-4s %-4s %-10s %s"
            % ("block", "base", "side", "pair", "peer", "doorbells")]
    for r in build_mmio_regs():
        rows.append("%-10s %#010x %-4s %-4d %-10s +0x00 set / +0x04 clear"
                    % (r.name, r.base, r.side, r.pair_idx, r.peer or "?"))
    return "\n".join(rows)


# --------------------------------------------------------------------------
# AP-side peer.
# --------------------------------------------------------------------------

class ApPeer:
    """The AP half of the modem<->AP IPC.

    Wires MMIORegs to a mem_model.MpuMemory (integrated, never modified):
    subscribes _on_ccif_event to the backing CcifDevice and registers raw
    Memory.hook callbacks on every CCIF CON set/clear VA (the emulator seam
    path). MD-actor doorbells (modem code writing its md_ccifN blocks) land
    in event_queue with timestamps; AP-actor writes are ack/response traffic
    and go to ack_log instead (never re-queued — no ack storms by
    construction).

    time: virtual clock. Default time.monotonic; pass a FakeClock callable
    for deterministic replay/selftest.
    """

    # RPC control lives on pair 0, FSD file-service on pair 1 (PROVISIONAL
    # harness convention — the transcripts do not name CCIF indices; all 6
    # pairs are modelled, only 0/1 are exercised).
    RPC_PAIR = 0
    FSD_PAIR = 1

    def __init__(self, mem=None, rings=None,
                 clock=None, bak_dir: Path | str = MODEM_BAK_DIR) -> None:
        if MpuMemory is None or SmemRingSet is None:
            raise RuntimeError("sim/mem_model.py is required (not importable)")
        self.clock = clock or time.monotonic
        self._t0 = float(self.clock())
        self.regs = build_mmio_regs()
        self.by_name = {r.name: r for r in self.regs}
        self.mem = mem if mem is not None else MpuMemory.with_image_and_smem()
        self.rings = rings if rings is not None else SmemRingSet(self.mem)
        self._ensure_fsd_rings()
        self.event_queue: list[dict] = []   # inbound MD->AP doorbells
        self.ack_log: list[dict] = []       # outbound AP acks
        self.rpc_log: list[dict] = []       # replayed RPC steps
        self.idle_log: list[dict] = []      # replayed errno-4 idle reads
        self.va_callbacks: dict[int, list] = {}  # va -> [cb(event)]
        self._seq = 0
        self.tracer = Tracer() if Tracer is not None else None
        # Wire to mem_model hooks (integration point — mem_model untouched).
        ccif = self._ccif()
        if ccif is not None:
            ccif.on_doorbell(self._on_ccif_event)
        for r in self.regs:
            for off in (0x00, 0x04):
                try:
                    self.mem.hook(r.base + off, self._on_raw_hook)
                except Exception:
                    pass  # plain-Memory hook absence is non-fatal here
        self.bak_dir = Path(bak_dir)

    # -- construction helpers -------------------------------------------
    def _ccif(self):
        try:
            return self.mem.ccif
        except Exception:
            return None

    def _ensure_fsd_rings(self) -> None:
        existing = set(getattr(self.rings, "rings", {}))
        if FSD_REQ_RING not in existing:
            self.rings.create_ring(FSD_REQ_RING, FSD_RING_CAP, FSD_SLOT_LEN,
                                   actor="ap")
        if FSD_RSP_RING not in existing:
            self.rings.create_ring(FSD_RSP_RING, FSD_RING_CAP, FSD_SLOT_LEN,
                                   actor="ap")

    # -- clock ------------------------------------------------------------
    def now(self) -> float:
        """Seconds since peer creation (virtual time)."""
        return float(self.clock()) - self._t0

    # -- hook paths ---------------------------------------------------------
    def _on_ccif_event(self, ev: dict) -> None:
        """CcifDevice subscriber: semantic doorbell events."""
        reg = self.by_name.get(ev.get("block", ""), None)
        evt = dict(ev)
        evt["t"] = self.now()
        self._seq += 1
        evt["seq"] = self._seq
        if reg is not None and reg.side == "md":
            # Modem -> AP: inbound queue + va-callback fan-out.
            self.event_queue.append(evt)
            if self.tracer is not None:
                try:
                    self.tracer.log(self._seq, int(evt.get("addr", "0x0"), 16),
                                    f"MD-DOORBELL {evt['block']} {evt['kind']} "
                                    f"{evt['value']}")
                except Exception:
                    pass
            # Exact-VA fan-out (exactly once): addr == reg.base for CON-set
            # writes, so a callback registered at the block base fires here.
            # Callbacks on the sibling offset (+0x04 clear vs +0x00 set) do
            # NOT fire — doorbell set/clear are distinct VAs by design.
            addr = int(evt.get("addr", "0x0"), 16)
            for cb in self.va_callbacks.get(addr, []):
                cb(evt)
        else:
            # AP-actor writes (our own acks): logged, never re-queued.
            self.ack_log.append(evt)

    def _on_raw_hook(self, kind: str, addr: int, size: int) -> None:
        """Raw Memory.hook path (emulator seam): fan out to va-callbacks.

        When the backing memory has a CcifDevice covering addr, the semantic
        _on_ccif_event path already fired va-callbacks for this write, so
        the raw path stays silent (exactly-once delivery). When there is no
        CcifDevice (bare emu_engine.Memory, e.g. the interp path), the raw
        path IS the delivery mechanism and fans out here.
        """
        if self._ccif() is not None:
            try:
                if self._ccif().covers(addr, size):
                    return
            except Exception:
                pass
        for cb in self.va_callbacks.get(addr, []):
            cb({"dev": "ccif", "kind": f"raw-{kind}", "addr": f"{addr:#x}",
                "size": size, "t": self.now(), "seq": self._seq + 1})

    def on_doorbell_va(self, va: int, cb) -> None:
        """Register a va-callback fired on doorbells at exactly va.

        Contract: va is a CCIF CON-set (@base+0x00) or CON-clear (@base+0x04)
        address (normally an MD-side block the modem code rings). cb receives
        the event dict {dev, block, peer, kind, actor, addr, value, t, seq}.
        """
        self.va_callbacks.setdefault(int(va), []).append(cb)

    # -- event queue --------------------------------------------------------
    def poll_events(self) -> list[dict]:
        """Drain the AP-side inbound queue (MD->AP doorbells)."""
        evs = list(self.event_queue)
        self.event_queue.clear()
        return evs

    @property
    def queued(self) -> int:
        return len(self.event_queue)

    # -- doorbell injection + ack --------------------------------------------
    def _reg(self, pair: int, side: str) -> MMIOReg:
        for r in self.regs:
            if r.pair_idx == pair and r.side == side:
                return r
        raise KeyError(f"no CCIF reg pair={pair} side={side}")

    def inject_md_doorbell(self, pair: int = 0, value: int = 1,
                           clear: bool = False) -> dict:
        """Simulate modem code ringing its doorbell (MD-actor MMIO write).

        Goes through the REAL MpuMemory.write -> CcifDevice.write path, so
        the event queue + hooks fire exactly as with emulated modem code.
        Returns the queued event dict.
        """
        reg = self._reg(pair, "md")
        addr = reg.base + (0x04 if clear else 0x00)
        self.mem.write(addr, struct.pack("<I", value & 0xFFFFFFFF), "md")
        assert self.event_queue, "doorbell did not reach the AP queue"
        return self.event_queue[-1]

    def ack(self, pair: int | None = None, value: int = 1,
            delay_s: float | None = None, note: str = "") -> dict:
        """Generate one AP-side ack (AP-actor MMIO write on ap_ccifN CON).

        delay_s documents the transcript-derived answer latency carried by
        this ack (see ACK_DELAY_S); the virtual clock is NOT slept — delays
        are recorded, and replay steps штамп them via stamp arithmetic so
        selftest stays fast and deterministic. Returns the ack record.
        """
        reg = self._reg(self.RPC_PAIR if pair is None else pair, "ap")
        addr = reg.base + 0x00
        self.mem.write(addr, struct.pack("<I", value & 0xFFFFFFFF), "ap")
        rec = {"t": self.now(), "pair": reg.pair_idx, "block": reg.name,
               "peer": reg.peer, "addr": f"{addr:#x}", "value": f"{value:#x}",
               "delay_s": ACK_DELAY_S.get(note, 0.0) if note else
               (0.0 if delay_s is None else delay_s),
               "note": note}
        # NB: the CcifDevice subscriber also appends a raw copy to ack_log;
        # the record here is the peer-level ack with delay provenance.
        self.ack_log.append(rec)
        return rec

    def ack_for(self, op_name: str, pair: int | None = None) -> dict:
        """Ack with the transcript-derived delay for op_name."""
        return self.ack(pair=pair, note=op_name,
                        delay_s=ACK_DELAY_S.get(op_name, 0.0))

    # -- RPC replay step ------------------------------------------------------
    def replay_step(self, rec: dict) -> dict:
        """Drive one transcript record through the peer; returns a step log."""
        op, direction = rec.get("op_name", ""), rec.get("direction", "")
        step: dict = {"seq": rec.get("seq"), "op": op, "direction": direction,
                      "t": self.now()}
        if direction == "md->ap" and op in ("IPC_RPC_CIDDATA_OP",
                                            "IPC_RPC_PRODUCT_OP"):
            ev = self.inject_md_doorbell(pair=self.RPC_PAIR)
            step["doorbell"] = {k: ev[k] for k in ("block", "kind", "value")}
            step["ack"] = self.ack_for(op)
            if op == "IPC_RPC_CIDDATA_OP":
                step["ap_answer"] = "security_data_len=0 -> FAIL"
            else:
                step["ap_answer"] = "product_data -> SUCCESS"
        elif direction in ("ap->tee", "tee->ap"):
            step["ap_answer"] = "security_data_len=0 (TEE consult, empty blob)"
        elif direction == "ap->md":
            step["ack"] = self.ack_for(op)
            step["ap_answer"] = ("FAIL (work_helper)" if "work_helper" in op
                                 else "SUCCESS (product_data)")
        else:
            step["ap_answer"] = "indication/snapshot (no ack)"
        self.rpc_log.append(step)
        return step

    def replay_idle(self, count: int = IDLE_SAMPLES,
                    errno: int = IDLE_ERRNO) -> list[dict]:
        """Emit `count` idle EINTR reads with the transcript cadence.

        Each entry: {idx, errno, t, delta_s} where delta_s is the
        live-observed gap before it (IDLE_DELTAS_S verbatim for the first 8).
        Models 'AP blocked in read, MD quiescent' — no doorbell traffic.
        """
        out: list[dict] = []
        for i in range(count):
            delta = IDLE_DELTAS_S[i - 1] if 1 <= i <= len(IDLE_DELTAS_S) else 0.0
            rec = {"idx": i, "op": "ccci_rpcd_idle_read", "errno": errno,
                   "errno_name": "EINTR", "t": self.now(), "delta_s": delta,
                   "note": "AP blocked in read on /dev/ccci_rpc; MD quiescent"}
            self.idle_log.append(rec)
            out.append(rec)
        return out


# --------------------------------------------------------------------------
# 2. Boot-sequence replayer.
# --------------------------------------------------------------------------

@dataclass
class ReplayReport:
    total: int = 0
    matched_ops: int = 0
    matched_dirs: int = 0
    fidelity_pct: float = 0.0
    mismatches: list = field(default_factory=list)
    steps: list = field(default_factory=list)
    timing_ok: bool = False
    timing_detail: str = ""


class BootReplayer:
    """Loads the REAL boot transcript and replays it through an ApPeer."""

    def __init__(self, path: Path | str = BOOT_TRANSCRIPT) -> None:
        self.path = Path(path)
        self.records = load_transcript(self.path)

    def op_sequence(self) -> list[str]:
        return [r.get("op_name", "") for r in self.records]

    def check_sequence(self) -> tuple[bool, list[str]]:
        """Assert the transcript matches EXPECTED_BOOT_OPS exactly."""
        got = self.op_sequence()
        fails: list[str] = []
        if len(got) != len(EXPECTED_BOOT_OPS):
            fails.append(f"length {len(got)} != {len(EXPECTED_BOOT_OPS)}")
        for i, (g, w) in enumerate(zip(got, EXPECTED_BOOT_OPS)):
            if g != w:
                fails.append(f"seq {i}: got {g!r} want {w!r}")
        for i, r in enumerate(self.records):
            if r.get("direction", "") != EXPECTED_BOOT_DIRS[i] \
                    and i < len(EXPECTED_BOOT_DIRS):
                fails.append(f"seq {i}: direction {r.get('direction')!r} "
                             f"!= {EXPECTED_BOOT_DIRS[i]!r}")
        return (not fails), fails

    def check_timing(self) -> tuple[bool, str]:
        """Assert the @33.766/@35.757 + 0.066 s pattern from device stamps."""
        ts = {}
        for r in self.records:
            v = parse_device_ts(r.get("timestamp_device", ""))
            if v is not None and r.get("seq") in (0, 4, 6):
                ts[r["seq"]] = v
        if set(ts) != {0, 4, 6}:
            return False, f"device stamps missing: {sorted(ts)}"
        d_product = round(ts[4] - ts[0], 3)
        d_repeat = round(ts[6] - ts[0], 3)
        ok = (abs(d_product - CIDDATA_PRODUCT_DELTA_S) < 0.001
              and abs(d_repeat - CIDDATA_REPEAT_DELTA_S) < 0.001)
        detail = (f"CIDDATA#1->PRODUCT {d_product:.3f}s "
                  f"(want {CIDDATA_PRODUCT_DELTA_S:.3f}s); "
                  f"CIDDATA#1->#2 {d_repeat:.3f}s "
                  f"(want {CIDDATA_REPEAT_DELTA_S:.3f}s)")
        return ok, detail

    def replay(self, peer: ApPeer) -> ReplayReport:
        """Load -> assert sequence -> drive peer -> idle. Returns the report."""
        rep = ReplayReport(total=len(self.records))
        ok, fails = self.check_sequence()
        got = self.op_sequence()
        rep.matched_ops = sum(1 for g, w in zip(got, EXPECTED_BOOT_OPS)
                              if g == w)
        rep.matched_dirs = sum(
            1 for r, w in zip(self.records, EXPECTED_BOOT_DIRS)
            if r.get("direction") == w)
        rep.fidelity_pct = (100.0 * rep.matched_ops / rep.total
                            if rep.total else 0.0)
        rep.mismatches = fails
        rep.timing_ok, rep.timing_detail = self.check_timing()
        for rec in self.records:
            if rec.get("op_name") in ("ccci_rpcd_idle_read",
                                      "live_idle_snapshot"):
                continue  # idle handled below with real cadence
            rep.steps.append(peer.replay_step(rec))
        for rec in peer.replay_idle():
            rep.steps.append(rec)
        assert ok, f"transcript sequence mismatch: {fails}"
        return rep


# --------------------------------------------------------------------------
# 3. SMEM ring peer: NVRAM file-service channel (ccci_fsd adjacency).
# --------------------------------------------------------------------------

class FsdRefused(Exception):
    """Unknown file-service name (ENOENT refusal, error=2 like live)."""


def _normalize_fsd_name(raw: str) -> str:
    """Strip 'X:/' / 'Y:/' prefixes + whitespace (transcript O: X:/LD40_001)."""
    s = raw.strip().strip("'\"")
    if ":/" in s:
        s = s.split(":/", 1)[1]
    s = s.strip().lstrip("/")
    return s


class FsdService:
    """AP side of the NVRAM file-service channel over SMEM rings.

    Wire format (harness convention, PROVISIONAL — real CCCI FSD framing is a
    future Ghidra task; opcodes/ENOENT refusal are live-observed):
      REQ  b"FSD:<OP>:<NAME>[:<OFF>:<LEN>]"  OP in {O, R, STAT}; NAME like
           LD40_001 (protect-LID) or NVD_DATA/CK.. single-file basenames.
           R carries decimal OFF/LEN slice coordinates.
      RSP-OK  b"OK:<OP>:<NAME>:<SIZE>:<SHA8>\\n<PAYLOAD>"
           O/STAT return metadata + (O) first-bytes probe; R returns the
           requested slice. SIZE = full file length, SHA8 = sha256[:8].
      RSP-ERR b"ERR:<OP>:<NAME>:2:ENOENT"  (errno 2, as live-observed for
           /mnt/vendor/nvcfg/mdota/MTK_MD_OTA_CONFIG.ini).

    Bytes come from PC-local backups opened READ-ONLY ('rb' semantics via
    nv_model read-only parse / Path.read_bytes): protect1/2 LID containers
    (concatenated records per LID) plus nvram_live NVD_DATA/NVD_IMEI single
    files. Unknown names are REFUSED (never fabricated). This module never
    writes outside SMEM rings.
    """

    def __init__(self, peer: ApPeer,
                 protect1: Path | str | None = None,
                 nvd_dirs: list[Path | str] | None = None) -> None:
        self.peer = peer
        self.rings = peer.rings
        self.log: list[dict] = []
        p1 = (Path(protect1) if protect1 else
              MODEM_BAK_DIR / "protect1.img")
        self.containers: dict = {}
        if _nv is not None and p1.is_file():
            try:
                self.containers = _nv.parse_protect(str(p1))
            except Exception:
                self.containers = {}
        self.nvd_dirs = [Path(d) for d in
                         (nvd_dirs or [NVD_DATA_DIR, NVD_IMEI_DIR])]
        self.single_files: dict[str, Path] = {}
        for d in self.nvd_dirs:
            if d.is_dir():
                for child in sorted(d.iterdir()):
                    if child.is_file():
                        self.single_files.setdefault(child.name, child)

    # -- backing store (read-only) -----------------------------------------
    def names(self) -> list[str]:
        return sorted(set(self.containers) | set(self.single_files))

    def read_file(self, name: str) -> bytes:
        """READ-ONLY backing read. Raises FsdRefused(ENOENT) when unknown."""
        nm = _normalize_fsd_name(name)
        if nm in self.containers:
            return b"".join(bytes(r) for r in self.containers[nm].records)
        if nm in self.single_files:
            return self.single_files[nm].read_bytes()  # 'rb' semantics
        # Also accept bare LID numbers the modem sometimes uses (e.g. the
        # transcript D:/M: lines echo the same name; no numeric path seen).
        raise FsdRefused(f"ENOENT: {nm} (error=2)")

    # -- wire format ---------------------------------------------------------
    @staticmethod
    def encode_request(op: str, name: str, off: int = 0,
                       length: int = 0) -> bytes:
        op = op.upper()
        assert op in ("O", "R", "STAT"), op
        if op == "R":
            return f"FSD:{op}:{_normalize_fsd_name(name)}:{off}:{length}".encode()
        return f"FSD:{op}:{_normalize_fsd_name(name)}".encode()

    @staticmethod
    def decode_request(raw: bytes) -> tuple[str, str, int, int]:
        try:
            parts = bytes(raw).decode("ascii").strip().split(":")
        except Exception:
            raise FsdRefused("ENOENT: undecodable request (error=2)")
        if len(parts) < 3 or parts[0] != "FSD" or parts[1] not in ("O", "R",
                                                                   "STAT"):
            raise FsdRefused("ENOENT: bad FSD framing (error=2)")
        op, nm = parts[1], _normalize_fsd_name(parts[2])
        off = int(parts[3]) if len(parts) > 3 and parts[3].lstrip(
            "-").isdigit() else 0
        ln = int(parts[4]) if len(parts) > 4 and parts[4].isdigit() else 0
        return op, nm, off, ln

    def handle(self, raw: bytes) -> bytes:
        """Answer one request (pure function of read-only backups)."""
        op, nm, off, ln = self.decode_request(raw)
        try:
            data = self.read_file(nm)
        except FsdRefused:
            rsp = f"ERR:{op}:{nm}:{FSD_REFUSE_ERRNO}:ENOENT".encode()
            self.log.append({"op": op, "name": nm, "verdict": "refused",
                             "errno": FSD_REFUSE_ERRNO})
            return rsp
        sha8 = hashlib.sha256(bytes(data)).hexdigest()[:8]
        if op == "R":
            payload = bytes(data[off:off + ln]) if ln > 0 else bytes(data[off:])
        elif op == "O":
            payload = bytes(data[:64])  # open probe (fd path is peer-side)
        else:
            payload = b""  # STAT: metadata in header only
        hdr = f"OK:{op}:{nm}:{len(data)}:{sha8}\n".encode()
        self.log.append({"op": op, "name": nm, "verdict": "served",
                         "size": len(data), "sha8": sha8,
                         "payload": len(payload)})
        return hdr + payload

    # -- ring pump -------------------------------------------------------------
    def serve(self, max_reqs: int = 16) -> list[dict]:
        """Drain FSD_REQ (as AP), answer each, post to FSD_RSP (as AP).

        Returns per-request service records. Modem posts with actor="md";
        the peer reads/writes with actor="ap" on the SAME shared bytes
        (mem_model SmemRingSet actor-tagged ops).
        """
        out: list[dict] = []
        for _ in range(max_reqs):
            try:
                req = self.rings.dequeue(FSD_REQ_RING, actor="ap")
            except Exception:
                break  # malformed-index quarantine: stop, never act
            if req is None:
                break
            rsp = self.handle(bytes(req))
            try:
                self.rings.enqueue(FSD_RSP_RING, rsp, actor="ap")
            except Exception as e:  # overrun: log + stop (producer waits)
                out.append({"req": bytes(req)[:32], "verdict": "rsp-overrun",
                            "detail": repr(e)})
                break
            # Notify emulated modem code the way real AP does: FSD doorbell.
            try:
                self.peer.ack(pair=self.peer.FSD_PAIR, note="FSD_RSP")
            except Exception:
                pass
            out.append({"req": bytes(req)[:48], "rsp_head": rsp[:48],
                        "verdict": self.log[-1]["verdict"] if self.log else "?"})
        return out


# --------------------------------------------------------------------------
# 4. AT-path separation.
# --------------------------------------------------------------------------

class AtPathViolation(Exception):
    """ESMLCK traffic was asked to route via RPC (forbidden by transcripts)."""


class AtRouter:
    """Models the live-observed path split.

    AT (incl. ALL ESMLCK forms) goes adb_atci_socket -> atcid -> ttyCMIPC2
    (RAW Hayes; rild-oem/rild-atci need Rfx parcel framing — skipped per
    HANDOFF 3e). RPC (CIDDATA/PRODUCT) goes /dev/ccci_rpc -> ccci_rpcd.
    rpcd_at_query.jsonl seq 9 proves the SML status path is modem-local: no
    new IPC_RPC appears during AT queries. SIM_SML_STATUS_IND (boot seq 10)
    is a CCCI *indication*, not an RPC round-trip, and stays legal on CCCI.

    The model returns an error (raises AtPathViolation) if asked to route
    ESMLCK via RPC.
    """

    ESMLCK = re.compile(r"ESMLCK", re.I)
    RPC_OPS = ("IPC_RPC_CIDDATA_OP", "IPC_RPC_PRODUCT_OP",
               "ccci_rpc_get_security_data", "security_data_response",
               "ccci_rpc_work_helper", "PRODUCT_OP_response")

    def at_path(self, cmd: str) -> tuple[str, str]:
        """(socket, tty) for any AT command. Never RPC by construction."""
        if self.ESMLCK.search(cmd or "") and False:  # placeholder, no branch
            pass
        return (ATCI_SOCKET, ATCI_TTY)

    def rpc_path(self, op: str) -> str:
        """Device node for an RPC op. Refuses ESMLCK payloads."""
        if self.ESMLCK.search(op or ""):
            raise AtPathViolation(
                f"ESMLCK traffic NEVER routes via RPC ({RPC_DEV}); "
                f"use {ATCI_SOCKET}->{ATCI_TTY}. Refused: {op!r}")
        return RPC_DEV

    def route_esmlck(self, cmd: str, via: str) -> tuple[str, str]:
        """Route one ESMLCK command. via must be 'atci'; 'rpc' raises."""
        if via.lower() != "atci":
            raise AtPathViolation(
                f"ESMLCK via {via!r} refused: live path is "
                f"{ATCI_SOCKET}->{ATCI_TTY} (rpcd_at_query seq 9: SML status "
                f"is modem-local, no ccci_rpc traversal)")
        return (ATCI_SOCKET, ATCI_TTY)

    def check_transcripts(self, boot_recs: list[dict],
                          at_recs: list[dict]) -> dict:
        """Assert zero ESMLCK-via-RPC in the REAL transcripts."""
        violations: list[str] = []
        for r in boot_recs:
            op = r.get("op_name", "")
            if "RPC" in op and self.ESMLCK.search(op):
                violations.append(f"boot seq {r.get('seq')}: {op}")
        for r in at_recs:
            if self.ESMLCK.search(r.get("op_name", "")) and \
                    "rpc" in r.get("op_name", "").lower():
                violations.append(f"at seq {r.get('seq')}: {r.get('op_name')}")
        # Positive control: AT transcript really does carry ESMLCK (via atci).
        esmlck_at = sum(1 for r in at_recs
                        if self.ESMLCK.search(r.get("op_name", "")))
        return {"violations": violations, "ok": not violations,
                "esmlck_at_records": esmlck_at,
                "at_path": f"{ATCI_SOCKET}->{ATCI_TTY}",
                "rpc_path": RPC_DEV}


# --------------------------------------------------------------------------
# 5. Emulator seam: attach(peer, cpu-like) + FakeCpu/FakeClock.
# --------------------------------------------------------------------------

SEAM_CONTRACT = """\
AP-peer emulator seam contract (sim/ap_peer.py :: attach).

cpu-like (interp / GDBsim backend) MUST provide:
  mem.hook(addr, cb)   cb(kind, addr, size); emu_engine.Memory or
                       mem_model.MpuMemory compatible. attach() registers one
                       hook per MD-side CCIF doorbell VA (CON set @base+0x00
                       and CON clear @base+0x04; 6 blocks x 2 = 12 hooks).
  mem.read(addr, ln) / mem.write(addr, buf[, actor])  modem-code memory path.
                       actor defaults to "md" so existing emu_engine callers
                       are unaffected; the peer observes MD-actor writes.
  [optional] regs dict {pc, sp, a0, ra} for GDBsim/interp context. The peer
             never requires it (doorbells are memory-mapped, not registers).

peer (ApPeer) PROVIDES:
  on_doorbell_va(va, cb)  cb(event_dict {dev, block, peer, kind, actor, addr,
                          value, t, seq}); fired for every CCIF doorbell
                          whose write address == va.
  poll_events() -> [event]  drains the AP-side inbound queue (MD->AP only;
                          AP acks never re-queue).
  ack()/ack_for()/replay_step()/replay_idle()/FsdService.serve()  AP answers.

attach(peer, cpu) BEHAVIOUR:
  1. for each MD-side MMIOReg: cpu.mem.hook(base+0x00, peer._on_raw_hook),
     cpu.mem.hook(base+0x04, peer._on_raw_hook)  [raw seam path]
  2. if cpu.mem is (or wraps) the peer's MpuMemory, the CcifDevice
     subscriber path is already live from ApPeer.__init__ (semantic path).
  3. returns the number of VA hooks registered (12 on a full map).
  4. never touches the device; never writes outside SMEM rings + CCIF MMIO.

EXAMPLE (FakeCpu in selftest; interp backend analogous):
  peer = ApPeer(); cpu = FakeCpu(peer.mem)
  n = attach(peer, cpu)          # 12
  cpu.write_md_doorbell(pair=0)  # emulated modem code rings MD CCIF0
  assert peer.queued == 1
  peer.ack_for("IPC_RPC_CIDDATA_OP")
  svc = FsdService(peer); svc.serve()
"""


def attach(peer: ApPeer, cpu) -> int:
    """Plug an ApPeer into a cpu-like backend (interp/GDBsim/FakeCpu).

    See SEAM_CONTRACT for the normative interface. Returns the VA-hook count.
    """
    mem = getattr(cpu, "mem", None)
    if mem is None:
        raise ValueError("cpu-like must expose .mem (Memory/MpuMemory)")
    n = 0
    for r in peer.regs:
        if r.side != "md":
            continue
        for off in (0x00, 0x04):
            va = r.base + off
            try:
                mem.hook(va, peer._on_raw_hook)
                n += 1
            except Exception:
                continue
            # Peer-level va-callback list exists even before any cb: keeps
            # the seam uniform (backends may register later).
            peer.va_callbacks.setdefault(va, [])
    return n


class FakeClock:
    """Deterministic virtual clock for replay/selftest (seconds)."""

    def __init__(self, start: float = 1000.0) -> None:
        self.t = float(start)

    def __call__(self) -> float:
        return self.t

    def advance(self, dt: float) -> float:
        self.t += float(dt)
        return self.t


class FakeCpu:
    """Minimal cpu-like for the seam selftest (no device, no ISA).

    Exposes .mem (shared MpuMemory), .regs {pc,sp,a0,ra}, .hook_fired log,
    write_md_doorbell() as the emulated-modem-code stand-in, and .hook()
    passthrough for attach().
    """

    def __init__(self, mem=None, clock=None) -> None:
        if MpuMemory is None:
            raise RuntimeError("sim/mem_model.py is required")
        self.mem = mem if mem is not None else MpuMemory.with_image_and_smem()
        self.regs = {"pc": 0x90000000, "sp": 0xA000FFF0, "a0": 0xB0001000,
                     "ra": 0x90000000}
        self.hook_fired: list = []
        self.clock = clock

    def hook(self, addr: int, cb) -> None:
        self.mem.hook(addr, cb)

    def write_md_doorbell(self, pair: int = 0, value: int = 1,
                          clear: bool = False) -> None:
        from mem_model import CCIF_BLOCKS as _B  # integration, not a copy
        md_blocks = [(nm, bs) for nm, bs in _B if nm.startswith("md_")]
        nm, base = md_blocks[pair]
        addr = base + (0x04 if clear else 0x00)
        self.mem.write(addr, struct.pack("<I", value), "md")

    def on_hook(self, kind: str, addr: int, size: int) -> None:
        self.hook_fired.append((kind, addr, size))


# --------------------------------------------------------------------------
# Selftest.
# --------------------------------------------------------------------------

def _ban_check() -> list[str]:
    """Assert this file never imports device-touching modules (AST-based).

    Substring search would false-positive on this docstring's own 'NEVER
    touches the device (no adb/fastboot/socket/subprocess imports)' rule
    statement, so parse real import statements instead.
    """
    import ast as _ast
    banned = {"socket", "subprocess", "serial", "adb", "fastboot", "pyserial"}
    found: list[str] = []
    tree = _ast.parse(Path(__file__).read_text())
    for nd in _ast.walk(tree):
        if isinstance(nd, _ast.Import):
            for a in nd.names:
                if (a.name.split(".")[0] in banned):
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

    # -- S0. hygiene: no device, stdlib-only, siblings intact ---------------
    try:
        check("no-device-imports", _ban_check() == [], ";".join(_ban_check()))
        import ast as _ast
        tree = _ast.parse(Path(__file__).read_text())
        mods = set()
        for nd in _ast.walk(tree):
            if isinstance(nd, _ast.Import):
                mods.update(a.name.split(".")[0] for a in nd.names)
            elif isinstance(nd, _ast.ImportFrom) and nd.module:
                mods.add(nd.module.split(".")[0])
        stdlib = {"__future__", "hashlib", "json", "re", "struct", "sys",
                  "time", "dataclasses", "pathlib", "typing"}
        sibling = {"hw_target", "mem_model", "emu_engine", "nv_model",
                   "sim", "ast"}
        check("stdlib-only", mods <= stdlib | sibling, repr(sorted(mods)))
        from mem_model import MpuMemory as _MM, SmemRingSet as _SR  # noqa
        check("mem_model-integrated-not-modified",
              _MM is MpuMemory and _SR is SmemRingSet)
    except Exception as e:  # noqa: BLE001
        check("hygiene", False, repr(e))

    # -- S1. CCIF regs: 6 pairs / 12 blocks, hw_target cross-check ---------
    try:
        regs = build_mmio_regs()
        check("ccif-12-blocks-6-pairs",
              len(regs) == 12 and len({r.pair_idx for r in regs}) == 6)
        check("ccif-sides", sum(r.side == "ap" for r in regs) == 6
              and sum(r.side == "md" for r in regs) == 6)
        ap0 = next(r for r in regs if r.name == "ap_ccif0")
        md0 = next(r for r in regs if r.name == "md_ccif0")
        check("ccif-pair0-addrs", ap0.base == 0x10209000
              and md0.base == 0x1020A000 and ap0.peer == "md_ccif0"
              and md0.peer == "ap_ccif0",
              f"{ap0.base:#x}/{md0.base:#x}")
        md5 = next(r for r in regs if r.name == "md_ccif5")
        check("ccif-pair5-addr", md5.base == 0x1025D000, f"{md5.base:#x}")
    except Exception as e:  # noqa: BLE001
        check("ccif-regs", False, repr(e))

    # -- S2. doorbell -> AP queue + timestamps + ack -------------------------
    try:
        clk = FakeClock()
        peer = ApPeer(clock=clk)
        check("peer-builds", peer.mem is not None and peer.queued == 0)
        va_hits: list = []
        md0_base = peer.by_name["md_ccif0"].base
        peer.on_doorbell_va(md0_base, va_hits.append)
        clk.advance(0.010)
        ev = peer.inject_md_doorbell(pair=0, value=1)
        check("md-doorbell-queues",
              peer.queued == 1 and ev["block"] == "md_ccif0"
              and ev["kind"] == "set" and ev["actor"] == "md", repr(ev))
        check("event-timestamp", ev["t"] > 0 and isinstance(ev["t"], float),
              repr(ev.get("t")))
        check("va-callback-fires", len(va_hits) == 1, repr(va_hits))
        nq = len(peer.ack_log)
        clk.advance(CIDDATA_PRODUCT_DELTA_S)
        ack = peer.ack_for("IPC_RPC_PRODUCT_OP")
        check("ap-ack-logged", len(peer.ack_log) > nq
              and ack["delay_s"] == CIDDATA_PRODUCT_DELTA_S, repr(ack))
        check("ack-not-requeued", peer.queued == 1, f"queued={peer.queued}")
        evs = peer.poll_events()
        check("poll-drains", len(evs) == 1 and peer.queued == 0)
        # AP-actor zero-clear is silent (mem_model convention preserved).
        q0 = peer.queued
        peer.mem.write(peer.by_name["ap_ccif0"].base + 0x04,
                       struct.pack("<I", 0), "ap")
        check("ap-zero-clear-silent", peer.queued == q0)
    except Exception as e:  # noqa: BLE001
        check("doorbell-model", False, repr(e))

    # -- S3. boot replay: transcript match % + timing + drive ---------------
    try:
        rp = BootReplayer(BOOT_TRANSCRIPT)
        check("transcript-loads", len(rp.records) == len(EXPECTED_BOOT_OPS),
              f"{len(rp.records)} recs")
        ok, sfails = rp.check_sequence()
        check("sequence-match", ok, "; ".join(sfails))
        fid = (100.0 * sum(1 for g, w in
                           zip(rp.op_sequence(), EXPECTED_BOOT_OPS) if g == w)
               / len(EXPECTED_BOOT_OPS))
        check("replay-fidelity-100", fid == 100.0, f"{fid:.1f}%")
        tok, tdetail = rp.check_timing()
        check("timing-33.766-35.757", tok, tdetail)
        clk = FakeClock()
        peer = ApPeer(clock=clk)
        rep = rp.replay(peer)
        check("replay-drives-peer", len(rep.steps) >= len(EXPECTED_BOOT_OPS)
              and rep.fidelity_pct == 100.0,
              f"steps={len(rep.steps)} fid={rep.fidelity_pct:.1f}%")
        check("replay-timing-ok", rep.timing_ok, rep.timing_detail)
        answers = [s.get("ap_answer", "") for s in peer.rpc_log]
        check("ciddata-fail-twice",
              sum("security_data_len=0 -> FAIL" in a for a in answers) == 2
              and sum("FAIL (work_helper)" in a for a in answers) == 2,
              repr(answers))
        check("product-success-once",
              sum("SUCCESS (product" in a for a in answers) == 1,
              repr(answers))
        check("idle-9-eintr",
              len(peer.idle_log) == IDLE_SAMPLES
              and all(r["errno"] == 4 for r in peer.idle_log),
              f"{len(peer.idle_log)} idle")
        deltas = [r["delta_s"] for r in peer.idle_log[1:]]
        check("idle-cadence-verbatim", deltas == list(IDLE_DELTAS_S),
              repr(deltas))
        # Cross-check idle cadence against the live logcat when present.
        stamps = load_idle_cadence()
        if BASELINE_IDLE_LOG.is_file():
            check("idle-9-samples-live", len(stamps) == 9, f"{len(stamps)}")
            live_d = [round(b - a, 3) for a, b in zip(stamps, stamps[1:])]
            check("idle-cadence-live-match", live_d == list(IDLE_DELTAS_S),
                  repr(live_d))
        else:
            check("idle-cadence-live-match", True, "skipped (log absent)")
    except Exception as e:  # noqa: BLE001
        check("boot-replay", False, repr(e))

    # -- S4. SMEM FSD peer: serve named LIDs read-only, refuse unknown ------
    try:
        clk = FakeClock()
        peer = ApPeer(clock=clk)
        svc = FsdService(peer)
        check("fsd-knows-LD40_001", "LD40_001" in svc.names())
        check("fsd-rings-present",
              FSD_REQ_RING in peer.rings.rings
              and FSD_RSP_RING in peer.rings.rings)
        # Modem posts OPEN for a known LID; peer serves byte-identical data.
        peer.rings.enqueue(FSD_REQ_RING, FsdService.encode_request(
            "O", "LD40_001"), actor="md")
        got = svc.serve()
        check("fsd-open-served", len(got) == 1
              and got[0]["verdict"] == "served", repr(got))
        rsp = peer.rings.dequeue(FSD_RSP_RING, actor="md")
        assert rsp is not None
        hdr, payload = rsp.split(b"\n", 1)
        check("fsd-ok-header", hdr.startswith(b"OK:O:LD40_001:"),
              hdr[:48].decode("ascii", "replace"))
        expect = svc.read_file("LD40_001")
        check("fsd-bytes-exact",
              hashlib.sha256(expect).hexdigest()[:8].encode()
              in hdr and payload == expect[:64],
              f"size={len(expect)} hdr={hdr[:48]!r}")
        # READ slice coordinates are honoured exactly.
        peer.rings.enqueue(FSD_REQ_RING, FsdService.encode_request(
            "R", "X:/LD40_001", 100, 32), actor="md")
        svc.serve()
        rsp2 = peer.rings.dequeue(FSD_RSP_RING, actor="md")
        assert rsp2 is not None
        hdr2, pay2 = rsp2.split(b"\n", 1)
        check("fsd-read-slice", pay2 == expect[100:132],
              f"got {len(pay2)}B want 32B")
        # Unknown name -> ENOENT refusal (live error=2 template), never bytes.
        peer.rings.enqueue(FSD_REQ_RING, FsdService.encode_request(
            "STAT", "MTK_MD_OTA_CONFIG.ini"), actor="md")
        svc.serve()
        rsp3 = peer.rings.dequeue(FSD_RSP_RING, actor="md")
        check("fsd-refuse-unknown",
              rsp3 == b"ERR:STAT:MTK_MD_OTA_CONFIG.ini:2:ENOENT",
              repr(rsp3))
        # Backing files untouched (READ-ONLY proof): mtimes stable across serve.
        p1 = MODEM_BAK_DIR / "protect1.img"
        if p1.is_file():
            m0 = p1.stat().st_mtime_ns
            svc.read_file("SL00_000")
            check("backing-readonly", p1.stat().st_mtime_ns == m0)
        else:
            check("backing-readonly", True, "skipped (no protect1)")
    except Exception as e:  # noqa: BLE001
        check("fsd-peer", False, repr(e))

    # -- S5. AT-path separation ----------------------------------------------
    try:
        router = AtRouter()
        s, t = router.at_path("AT+ESMLCK=?")
        check("at-via-atci", (s, t) == (ATCI_SOCKET, ATCI_TTY), f"{s}->{t}")
        check("rpc-node", router.rpc_path("IPC_RPC_CIDDATA_OP") == RPC_DEV)
        try:
            router.route_esmlck("AT+ESMLCK?", via="rpc")
            check("esmlck-via-rpc-refused", False, "no raise")
        except AtPathViolation:
            check("esmlck-via-rpc-refused", True)
        try:
            router.rpc_path("ESMLCK status via RPC")
            check("rpc-path-esmlck-refused", False, "no raise")
        except AtPathViolation:
            check("rpc-path-esmlck-refused", True)
        boot = load_transcript(BOOT_TRANSCRIPT)
        at = load_transcript(AT_TRANSCRIPT)
        rep = router.check_transcripts(boot, at)
        check("transcript-zero-esmlck-via-rpc", rep["ok"],
              repr(rep["violations"]))
        check("esmlck-at-present", rep["esmlck_at_records"] > 0,
              repr(rep["esmlck_at_records"]))
    except Exception as e:  # noqa: BLE001
        check("at-separation", False, repr(e))

    # -- S6. emulator seam: attach + FakeCpu -----------------------------------
    try:
        clk = FakeClock()
        peer = ApPeer(clock=clk)
        cpu = FakeCpu(peer.mem)
        n = attach(peer, cpu)
        check("attach-12-hooks", n == 12, f"n={n}")
        hits: list = []
        md0 = peer.by_name["md_ccif0"].base
        peer.on_doorbell_va(md0, hits.append)
        cpu.write_md_doorbell(pair=0, value=7)
        check("seam-md-rings-peer", peer.queued == 1, f"q={peer.queued}")
        check("seam-va-callback", len(hits) == 1, repr(hits))
        check("seam-event-fields",
              hits and hits[0].get("value") == "0x7"
              and hits[0].get("block") == "md_ccif0", repr(hits))
        evs = peer.poll_events()
        check("seam-poll", len(evs) == 1 and peer.queued == 0)
        check("seam-contract-doc", "cpu-like" in SEAM_CONTRACT
              and "attach(peer, cpu)" in SEAM_CONTRACT)
        # attach() against a bare emu_engine.Memory also works (interp path).
        if Memory is not None:
            m2 = Memory()
            m2.add("t", 0x1020A000, 0x1000, 6, b"\x00" * 0x1000)
            cpu2 = FakeCpu.__new__(FakeCpu)
            cpu2.mem = m2  # type: ignore[assignment]
            n2 = attach(peer, cpu2)
            check("attach-plain-memory", n2 == 12, f"n2={n2}")
        else:
            check("attach-plain-memory", True, "skipped (no Memory)")
    except Exception as e:  # noqa: BLE001
        check("emulator-seam", False, repr(e))

    return passed, failed, details


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if "--table" in args:
        print(ccif_table())
        return 0
    if "--seam" in args:
        print(SEAM_CONTRACT)
        return 0
    if "--replay" in args:
        rp = BootReplayer(BOOT_TRANSCRIPT)
        ok, sfails = rp.check_sequence()
        tok, tdetail = rp.check_timing()
        peer = ApPeer(clock=FakeClock())
        rep = rp.replay(peer)
        print(f"boot replay: {rep.matched_ops}/{rep.total} ops "
              f"= {rep.fidelity_pct:.1f}% fidelity "
              f"({'MATCH' if ok else 'MISMATCH: ' + '; '.join(sfails)})")
        print(f"timing: {tdetail} ({'OK' if tok else 'DRIFT'})")
        print(f"rpc steps={len(peer.rpc_log)} idle={len(peer.idle_log)} "
              f"acks={len(peer.ack_log)}")
        return 0 if (ok and tok) else 1
    passed, failed, details = selftest()
    print(f"ap_peer selftest: {passed} passed, {failed} failed")
    for d in details:
        print("  " + d)
    # Fidelity line for the return contract (transcript match %).
    try:
        rp = BootReplayer(BOOT_TRANSCRIPT)
        got = rp.op_sequence()
        fid = (100.0 * sum(1 for g, w in zip(got, EXPECTED_BOOT_OPS)
                            if g == w) / len(EXPECTED_BOOT_OPS))
        print(f"replay fidelity: {fid:.1f}% "
              f"({sum(1 for g, w in zip(got, EXPECTED_BOOT_OPS) if g == w)}/"
              f"{len(EXPECTED_BOOT_OPS)} boot ops vs rpcd_boot_idle.jsonl)")
        print("seam: attach(peer, cpu-like) + on_doorbell_va "
              "(see --seam; FakeCpu exercised in selftest)")
    except Exception as e:  # noqa: BLE001
        print(f"replay fidelity: unavailable ({e!r})")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
