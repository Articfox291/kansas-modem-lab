#!/usr/bin/env python3
"""mem_model.py — exact-spec memory/MPU model for the modem emulator (Kansas lab, MT6835).

PC-side only. Stdlib only. No device contact (no adb/fastboot/socket/subprocess;
this module never opens anything except repo files read-only for selftest
cross-checks). New code lives under sim/ only; emu_engine.py is EXTENDED
(subclassed), never modified.

Spec sources (every region carries provenance; PROVISIONAL marks emulation
defaults that real HW assigns at boot):
  * sim/hw_target.py SPEC["mem"] ... modem_va 0x90000000, modem_ap_phys
    0xD0000000, modem_size 45893712, vectors [0x90004000,0x90004100,0x90004180],
    modem_temp_share 0x10018000, ccif_pairs 6x (10209000/1020a000 ...),
    dpmaif_cache (0x190000,"1.6M"), dpmaif_nocache (0x50000,"320K").
  * sim/emu_engine.py ................. Memory / MemoryFault / PERM_* (extended
    here as MpuMemory; base-class selftest must stay green), VA_BASE,
    ROM_SIZE, STACK_BASE/CTX_BASE scratch windows.
  * md1work.dtb (verified by raw FDT parse this session):
    modem_temp_share@10018000 reg 0x10018000/0x1000; ap/md_ccif0..5
    (10209000,1020a000,1020b000,1020c000,1023c000,1023d000,1023e000,1023f000,
    1024c000,1024d000,1025c000,1025d000) each 0x1000; dpmaif@10014000 regs
    0x10014000+0x1022c/d/e000 each 0x1000 (+infra_dpmaif@1022f000 0x1000);
    watchdog@1c007000 reg 0x1C007000/0x100; /memory reg base 0x40000000
    (full 0x40000000); ccci-dpmaif-cache/nocache-memory nodes present with
    alloc-ranges 0x40000000-0xF0000000 (base boot-assigned => PROVISIONAL
    emulation defaults below); ssmr/ssheap/trusted_mem exist AP-side only.
  * md1work_layout.dat ................ checked: DHL/OTA trace-definition dump
    (8.3MB text), carries no memory-map facts; not used as a mem source.
  * HANDOFF.md Sec 3e / PICKUP.md Track 1 .. md1rom 45,893,712B @file 0x200,
    AP-phys 0xD0000000 carveout, modem VA 0x90000000 MMU offset, GFH FILE_INFO
    load_addr 0x400, nanoMIPS I7200 PCORE, Nucleus RTOS.
  * Task brief Fig-3 MPU policy ..... MD ROM R-X | MD-RW windows RW- |
    SMEM shared RW both sides | secure NONE (unmapped) | AP NONE-after-load
    (post-load emulator state; load-phase AP access is out of scope).

Contents:
  1. MPU_TABLE — kanak-accurate region list {name, base, size, MDperm, APperm,
     kind, provenance}. Overlapping policy entries (dram_window parent vs
     SMEM/DPMAIF carveouts) resolve by most-specific-match, like real MPU
     prioritised entries.
  2. MpuMemory(Memory) — enforces the table per actor ("md"/"ap"). Any
     violation raises MpuFault (a MemoryFault carrying region names, mirroring
     a real MPU abort). MMIO ranges route to device stubs instead of storage:
     reads return zeros + log, writes are logged, CCIF doorbell writes fire
     hook events.
  3. SmemRingSet — CCCI ring headers + index discipline over the shared-RW
     SMEM windows, written so a future AP-side peer can plug in (same bytes,
     actor-tagged ops). Every index/length loaded from shared memory is
     bounds-checked; malformed indices are LOGGED, never trusted (this is the
     CVE-2022-21765 CCCI-OOB class: modem trusting AP-written shared-memory
     indices/lengths; the model quarantines instead of corrupting).
  4. Device stubs — CcifDevice (doorbell set/clear + hook events), DpmaifDevice
     (reg windows + BAT descriptor table), WdtDevice; each keeps a forensic
     access log.
  5. selftest() — demonstrates ROM-write fault + SMEM shared-RW + CCIF hook
     firing (+ overrun/malformed-index quarantine, BAT/WDT logging, AP
     none-after-load, X-perm fidelity, base-class green).

Run:
  python sim/mem_model.py --selftest   (default)
  python sim/mem_model.py --table      (print MPU region table)
  python sim/mem_model.py --rings      (print ring-header design)
"""
from __future__ import annotations

import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path

SIM_DIR = Path(__file__).resolve().parent
REPO_ROOT = SIM_DIR.parent
if str(SIM_DIR) not in sys.path:
    sys.path.insert(0, str(SIM_DIR))

from emu_engine import (  # noqa: E402
    CTX_BASE,
    PERM_R,
    PERM_W,
    PERM_X,
    ROM_SIZE,
    STACK_BASE,
    Memory,
    MemoryFault,
    VA_BASE,
)

# --------------------------------------------------------------------------
# Canonical addresses / sizes (provenance per item; see module docstring).
# --------------------------------------------------------------------------

MODEM_VA = 0x90000000        # hw_target SPEC mem.modem_va; emu_engine.VA_BASE
MODEM_SIZE = 45893712        # hw_target modem_size; emu_engine.ROM_SIZE
# == 0x2BC4850 (43.77 MiB == 45.89 decimal MB, the "45.9MB ROM" of the brief).
MODEM_END = MODEM_VA + MODEM_SIZE          # 0x92BC4850
MODEM_AP_PHYS = 0xD0000000   # hw_target modem_ap_phys; HANDOFF 3e mblock-30
VECTORS = (0x90004000, 0x90004100, 0x90004180)  # hw_target cpu_proof

# MD-RW heap window: class per Fig-3, bounds PROVISIONAL (emulation default in
# modem VA space just past ROM end 0x92BC4850, rounded to 0x92C00000; exact
# scatter/bss extents pending CATI/ELF section mapping).
MD_RW_BASE = 0x92C00000
MD_RW_SIZE = 0x00400000      # 4 MiB emulation default

# DRAM window modelled by the emulator (task brief: 0x40000000:0x4000000).
# DTB /memory reg confirms base 0x40000000 (full AP DRAM there is 0x40000000).
DRAM_BASE = 0x40000000
DRAM_SIZE = 0x04000000       # 64 MiB modelled window (brief spec)

# SMEM ring area: class=shared-RW per Fig-3; bases are emulation defaults
# inside the DRAM window (real base is boot-assigned via the CCCI handshake;
# SmemRingSet accepts any base so a future AP peer can relocate).
SMEM_CTRL_BASE = 0x40000000
SMEM_CTRL_SIZE = 0x00010000  # 64 KiB ring headers + indices
SMEM_DATA_BASE = 0x40010000
SMEM_DATA_SIZE = 0x00100000  # 1 MiB ring payload buffers

# DPMAIF shared buffers: sizes exact per hw_target (0x190000 = 1600 KiB ~1.6M,
# 0x50000 = 320 KiB); DTB nodes ccci-dpmaif-cache/nocache-memory confirm the
# reservation exists with alloc-ranges 0x40000000-0xF0000000, i.e. base is
# boot-assigned => emulation defaults inside the DRAM window, contiguous.
DPMAIF_CACHE_BASE = 0x40110000
DPMAIF_CACHE_SIZE = 0x190000
DPMAIF_NOCACHE_BASE = 0x402A0000   # == CACHE_BASE + CACHE_SIZE, contiguous
DPMAIF_NOCACHE_SIZE = 0x50000

MODEM_TEMP_SHARE_BASE = 0x10018000  # DTB modem_temp_share@10018000, 0x1000
MODEM_TEMP_SHARE_SIZE = 0x1000

CCIF_BLOCK_SIZE = 0x1000
CCIF_BLOCKS: tuple[tuple[str, int], ...] = (  # DTB ap/md_ccifN nodes, verified
    ("ap_ccif0", 0x10209000), ("md_ccif0", 0x1020A000),
    ("ap_ccif1", 0x1020B000), ("md_ccif1", 0x1020C000),
    ("ap_ccif2", 0x1023C000), ("md_ccif2", 0x1023D000),
    ("ap_ccif3", 0x1023E000), ("md_ccif3", 0x1023F000),
    ("ap_ccif4", 0x1024C000), ("md_ccif4", 0x1024D000),
    ("ap_ccif5", 0x1025C000), ("md_ccif5", 0x1025D000),
)
CCIF_PAIRS: tuple[tuple[str, str], ...] = tuple(
    (CCIF_BLOCKS[i][0], CCIF_BLOCKS[i + 1][0]) for i in range(0, 12, 2)
)  # == hw_target ccif_pairs order

DPMAIF_REG_SIZE = 0x1000
DPMAIF_REG_BLOCKS: tuple[tuple[str, int], ...] = (
    ("dpmaif_cfg", 0x10014000),    # DTB dpmaif@10014000 reg[0]
    ("dpmaif_infra_c", 0x1022C000),
    ("dpmaif_infra_d", 0x1022D000),
    ("dpmaif_infra_e", 0x1022E000),
    ("dpmaif_infra_f", 0x1022F000),  # DTB infra_dpmaif@1022f000 node
)

WDT_BASE = 0x1C007000         # DTB watchdog@1c007000 (mt6835-wdt), 0x100
WDT_SIZE = 0x100

# SML evidence anchors (HANDOFF 3e / boot_sim.py; read-only selftest probe).
SML_FUNC_VA = 0x905DF2FA
SML_STOCK_HEAD = bytes.fromhex("141e2412")

PERM_NONE = 0
MD_ROM_PERM = PERM_R | PERM_X
MD_RW_PERM = PERM_R | PERM_W
SHARED_RW_PERM = PERM_R | PERM_W


def perm_str(p: int) -> str:
    """Render a PERM_* bitmask Fig-3 style: R-X / RW- / R-- / --- etc."""
    return ("R" if p & PERM_R else "-") + ("W" if p & PERM_W else "-") + \
        ("X" if p & PERM_X else "-")


# --------------------------------------------------------------------------
# 1. MPU region table
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class MpuRegion:
    """One MPU policy entry. MDperm/APperm use emu_engine PERM_* bits."""
    name: str
    base: int
    size: int
    md_perm: int
    ap_perm: int
    kind: str        # rom | rom-mirror | md-rw | scratch | dram-window |
                     # smem | dpmaif-shm | temp-share | mmio-ccif |
                     # mmio-dpmaif | mmio-wdt
    provenance: str

    @property
    def end(self) -> int:
        return self.base + self.size

    def contains(self, addr: int, ln: int = 1) -> bool:
        return self.base <= addr and addr + ln <= self.end


def build_mpu_table() -> list[MpuRegion]:
    """Kanak-accurate region list. Overlaps resolve most-specific-first."""
    assert VA_BASE == MODEM_VA and ROM_SIZE == MODEM_SIZE, "emu_engine drift"
    t: list[MpuRegion] = [
        MpuRegion("md_rom_va", MODEM_VA, MODEM_SIZE, MD_ROM_PERM, PERM_NONE,
                  "rom", "hw_target mem.modem_va/size; HANDOFF 3e md1rom "
                         "45,893,712B; vectors @0x90004000/100/180 inside"),
        MpuRegion("md_rom_phys", MODEM_AP_PHYS, MODEM_SIZE, PERM_NONE,
                  PERM_NONE, "rom-mirror",
                  "hw_target mem.modem_ap_phys 0xD0000000 (DTB mblock-30); "
                  "AP NONE-after-load per Fig-3 (post-load emulator state)"),
        MpuRegion("md_rw_heap", MD_RW_BASE, MD_RW_SIZE, MD_RW_PERM, PERM_NONE,
                  "md-rw", "Fig-3 MD-RW class; BASE/SIZE provisional emulation "
                           "default past ROM end 0x92BC4850; exact scatter "
                           "extents pending CATI/ELF mapping"),
        MpuRegion("emu_stack", STACK_BASE, 0x10000, MD_RW_PERM, PERM_NONE,
                  "scratch", "emu_engine STACK_BASE compat; emulator scratch, "
                             "NOT real MPU state"),
        MpuRegion("emu_ctx", CTX_BASE, 0x10000, MD_RW_PERM, PERM_NONE,
                  "scratch", "emu_engine CTX_BASE compat; emulator scratch, "
                             "NOT real MPU state"),
        MpuRegion("dram_window", DRAM_BASE, DRAM_SIZE, PERM_NONE,
                  SHARED_RW_PERM, "dram-window",
                  "brief DRAM 0x40000000:0x4000000 (64M modelled window); DTB "
                  "/memory confirms base 0x40000000 (full 1GB). Policy parent "
                  "only: sub-carveouts below win by most-specific match. MD "
                  "has no direct window access (shared via SMEM entries)."),
        MpuRegion("smem_ctrl", SMEM_CTRL_BASE, SMEM_CTRL_SIZE, SHARED_RW_PERM,
                  SHARED_RW_PERM, "smem",
                  "Fig-3 SMEM shared-RW; base PROVISIONAL emulation default "
                  "(real base boot-assigned via CCCI handshake)"),
        MpuRegion("smem_data", SMEM_DATA_BASE, SMEM_DATA_SIZE, SHARED_RW_PERM,
                  SHARED_RW_PERM, "smem",
                  "Fig-3 SMEM shared-RW ring payload area; base PROVISIONAL, "
                  "see smem_ctrl"),
        MpuRegion("dpmaif_cache", DPMAIF_CACHE_BASE, DPMAIF_CACHE_SIZE,
                  SHARED_RW_PERM, SHARED_RW_PERM, "dpmaif-shm",
                  "hw_target dpmaif_cache 0x190000/1.6M; DTB "
                  "ccci-dpmaif-cache-memory (base boot-assigned, emulation "
                  "default); Fig-3 shared-RW"),
        MpuRegion("dpmaif_nocache", DPMAIF_NOCACHE_BASE, DPMAIF_NOCACHE_SIZE,
                  SHARED_RW_PERM, SHARED_RW_PERM, "dpmaif-shm",
                  "hw_target dpmaif_nocache 0x50000/320K; DTB "
                  "ccci-dpmaif-nocache-memory; contiguous after cache"),
        MpuRegion("modem_temp_share", MODEM_TEMP_SHARE_BASE,
                  MODEM_TEMP_SHARE_SIZE, SHARED_RW_PERM, SHARED_RW_PERM,
                  "temp-share", "DTB modem_temp_share@10018000 reg verified "
                                "0x10018000/0x1000; boot-time AP/MD share"),
    ]
    for wname, wbase in CCIF_BLOCKS:
        t.append(MpuRegion(f"ccif_{wname}", wbase, CCIF_BLOCK_SIZE,
                           MD_RW_PERM, SHARED_RW_PERM, "mmio-ccif",
                           f"DTB {wname}@{wbase:08x} reg verified 4K; MMIO: "
                           "reads return 0+log, writes logged, doorbell "
                           "writes fire hook events"))
    for wname, wbase in DPMAIF_REG_BLOCKS:
        t.append(MpuRegion(f"dpmaif_{wname}", wbase, DPMAIF_REG_SIZE,
                           MD_RW_PERM, SHARED_RW_PERM, "mmio-dpmaif",
                           f"DTB dpmaif/infra_dpmaif reg {wbase:#x}/4K; BAT "
                           "descriptor-area stub with access log"))
    t.append(MpuRegion("wdt", WDT_BASE, WDT_SIZE, MD_RW_PERM, SHARED_RW_PERM,
                       "mmio-wdt", "DTB watchdog@1c007000 (mt6835-wdt) reg "
                                   "verified 0x1C007000/0x100; access log"))
    # NOTE (Fig-3 "secure none"): DTB ssmr/ssheap/trusted_mem exist AP-side
    # only; modem MPU maps NO secure entry, so any such access faults as
    # unmapped here. Deliberately no entry rather than a fake address.
    return t


MPU_TABLE: list[MpuRegion] = build_mpu_table()


def dump_table(table: list[MpuRegion] | None = None) -> str:
    rows = ["%-18s %-10s %-10s %-4s %-4s %-12s %s"
            % ("name", "base", "size", "MD", "AP", "kind", "provenance")]
    for e in (table or MPU_TABLE):
        rows.append("%-18s %#010x %#010x %-4s %-4s %-12s %s"
                    % (e.name, e.base, e.size, perm_str(e.md_perm),
                       perm_str(e.ap_perm), e.kind, e.provenance))
    return "\n".join(rows)


# --------------------------------------------------------------------------
# MPU fault with region names (still a MemoryFault for base-class callers)
# --------------------------------------------------------------------------

class MpuFault(MemoryFault):
    """MPU abort: MemoryFault + offending region name + actor (MD/AP) side."""

    def __init__(self, addr: int, kind: str, region: str | None = None,
                 actor: str = "md", detail: str = ""):
        super().__init__(addr, kind)
        self.region = region
        self.actor = actor
        self.detail = detail
        msg = f"{kind} fault @ {addr:#x} actor={actor}"
        if region:
            msg += f" region={region}"
        if detail:
            msg += f" ({detail})"
        self.args = (msg,)


# --------------------------------------------------------------------------
# 3. MMIO device stubs (CCIF / DPMAIF-BAT / WDT), each with access log
# --------------------------------------------------------------------------

@dataclass
class MmioWindow:
    name: str
    base: int
    size: int

    def contains(self, addr: int, ln: int = 1) -> bool:
        return self.base <= addr and addr + ln <= self.base + self.size


class MmioDevice:
    """MMIO stub: reads return zeros + log; writes logged. Forensics first."""

    def __init__(self, name: str, windows: list[MmioWindow]):
        self.name = name
        self.windows = windows
        self.log: list[dict] = []   # {seq,op,actor,addr,size,data}
        self._seq = 0

    def covers(self, addr: int, ln: int = 1) -> bool:
        return any(w.contains(addr, ln) for w in self.windows)

    def window_of(self, addr: int) -> MmioWindow | None:
        for w in self.windows:
            if w.contains(addr, 1):
                return w
        return None

    def _log(self, op: str, actor: str, addr: int, size: int,
             data: bytes | None = None) -> dict:
        self._seq += 1
        rec = {"seq": self._seq, "dev": self.name, "op": op, "actor": actor,
               "addr": f"{addr:#x}", "size": size,
               "data": (bytes(data[:32]).hex() if data else "")}
        self.log.append(rec)
        return rec

    def read(self, addr: int, ln: int, actor: str = "md") -> bytes:
        self._log("read", actor, addr, ln)
        return b"\x00" * ln

    def write(self, addr: int, data: bytes, actor: str = "md") -> None:
        self._log("write", actor, addr, len(data), bytes(data))


class CcifDevice(MmioDevice):
    """CCIF doorbell stub over the 12 verified 4K blocks (6 AP/MD pairs).

    Doorbell offsets are CONVENTIONAL (CON @+0x00 set, @+0x04 clear;
    exact MT6835 CCIF register map pending Ghidra/CATI confirmation):
    any nonzero u32 write there logs a doorbell event and fires subscriber
    hooks. All other writes are logged without side effects.
    """

    DOORBELL_SET_OFF = 0x00
    DOORBELL_CLR_OFF = 0x04

    def __init__(self) -> None:
        super().__init__("ccif", [MmioWindow(n, b, CCIF_BLOCK_SIZE)
                                  for n, b in CCIF_BLOCKS])
        self.by_name = {n: b for n, b in CCIF_BLOCKS}
        self.doorbell_log: list[dict] = []
        self.subscribers: list = []  # cb(event_dict)

    def peer_of(self, block: str) -> str | None:
        for a, m in CCIF_PAIRS:
            if block == a:
                return m
            if block == m:
                return a
        return None

    def on_doorbell(self, cb) -> None:
        self.subscribers.append(cb)

    def write(self, addr: int, data: bytes, actor: str = "md") -> None:
        self._log("write", actor, addr, len(data), bytes(data))
        w = self.window_of(addr)
        if w is None or len(data) < 4:
            return
        off = addr - w.base
        if off in (self.DOORBELL_SET_OFF, self.DOORBELL_CLR_OFF):
            val = struct.unpack("<I", bytes(data[:4]))[0]
            if val != 0:
                ev = {"dev": self.name, "block": w.name, "peer": self.peer_of(w.name),
                      "kind": "set" if off == 0 else "clear",
                      "actor": actor, "addr": f"{addr:#x}", "value": f"{val:#x}"}
                self.doorbell_log.append(ev)
                for cb in self.subscribers:
                    cb(ev)


class DpmaifDevice(MmioDevice):
    """DPMAIF stub: reg windows (MMIO log) + BAT descriptor table.

    BAT entries are (phys, length, kind) validated against the modelled DRAM
    window; rejects are logged (BAT discipline is the DMA analogue of the
    CCCI index discipline: untrusted descriptors must never become OOB).
    """

    def __init__(self) -> None:
        super().__init__("dpmaif", [MmioWindow(n, b, DPMAIF_REG_SIZE)
                                    for n, b in DPMAIF_REG_BLOCKS])
        self.bat: list[dict] = []
        self.bat_log: list[dict] = []

    def bat_add(self, phys: int, length: int, kind: str = "rx",
                actor: str = "md") -> dict:
        ok = (DRAM_BASE <= phys and phys + length <= DRAM_BASE + DRAM_SIZE
              and 0 < length <= DPMAIF_CACHE_SIZE + DPMAIF_NOCACHE_SIZE)
        rec = {"seq": len(self.bat_log) + 1, "actor": actor, "kind": kind,
               "phys": f"{phys:#x}", "length": length,
               "result": "accepted" if ok else "rejected"}
        self.bat_log.append(rec)
        if not ok:
            raise ValueError(f"BAT reject: phys={phys:#x} len={length:#x} "
                             f"(outside DRAM window or insane length)")
        desc = {"phys": phys, "length": length, "kind": kind, "actor": actor}
        self.bat.append(desc)
        return desc


class WdtDevice(MmioDevice):
    """WDT stub @0x1C007000/0x100: every access logged; reads return 0."""

    def __init__(self) -> None:
        super().__init__("wdt", [MmioWindow("wdt", WDT_BASE, WDT_SIZE)])
        self.kicks = 0

    def write(self, addr: int, data: bytes, actor: str = "md") -> None:
        super().write(addr, data, actor)
        self.kicks += 1


# --------------------------------------------------------------------------
# 2. MPU-enforcing memory (extends emu_engine.Memory; base API compatible)
# --------------------------------------------------------------------------

class MpuMemory(Memory):
    """Flat 32-bit memory with Fig-3 MPU enforcement + MMIO routing.

    read()/write() keep the base-class signature (actor defaults to "md" so
    existing emu_engine callers and its selftest are unaffected) and add an
    explicit actor side. md_read/ap_read/md_write/ap_write spell the side out
    for modem-vs-AP peer code. check_exec() enforces the X bit (ROM R-X
    executes; SMEM/heap RW- must refuse exec, mirroring NX).
    """

    def __init__(self, mpu: list[MpuRegion] | None = None) -> None:
        super().__init__()
        self.mpu: list[MpuRegion] = list(mpu) if mpu is not None else []
        self.mmio: list[MmioDevice] = []
        self.mpu_log: list[dict] = []  # every MPU abort, with region names

    # -- construction ------------------------------------------------------
    @classmethod
    def with_image_and_smem(cls, img=None) -> "MpuMemory":
        """Full map: ROM image (R-X) + heap/scratch + SMEM/DPMAIF/temp-share.

        img: emu_engine.Image (defaults to zeroed ROM_SIZE when omitted, so
        the selftest stays hermetic and fast). MMIO ranges get devices, not
        storage. The AP phys mirror and dram_window are policy-only entries
        (no storage) so strays fault with their region names.
        """
        m = cls(build_mpu_table())
        data = bytes(img.data) if img is not None else b"\x00" * ROM_SIZE
        if len(data) != ROM_SIZE:
            raise ValueError(f"ROM image size {len(data)} != {ROM_SIZE}")
        m.add("md_rom_va", MODEM_VA, len(data), MD_ROM_PERM, data)
        m.add("md_rw_heap", MD_RW_BASE, MD_RW_SIZE, PERM_R | PERM_W)
        m.add("emu_stack", STACK_BASE, 0x10000, PERM_R | PERM_W)
        m.add("emu_ctx", CTX_BASE, 0x10000, PERM_R | PERM_W)
        m.add("smem_ctrl", SMEM_CTRL_BASE, SMEM_CTRL_SIZE, PERM_R | PERM_W)
        m.add("smem_data", SMEM_DATA_BASE, SMEM_DATA_SIZE, PERM_R | PERM_W)
        m.add("dpmaif_cache", DPMAIF_CACHE_BASE, DPMAIF_CACHE_SIZE,
              PERM_R | PERM_W)
        m.add("dpmaif_nocache", DPMAIF_NOCACHE_BASE, DPMAIF_NOCACHE_SIZE,
              PERM_R | PERM_W)
        m.add("modem_temp_share", MODEM_TEMP_SHARE_BASE,
              MODEM_TEMP_SHARE_SIZE, PERM_R | PERM_W)
        m.mmio = [CcifDevice(), DpmaifDevice(), WdtDevice()]
        return m

    @property
    def ccif(self) -> CcifDevice:
        for d in self.mmio:
            if isinstance(d, CcifDevice):
                return d
        raise KeyError("no CcifDevice attached")

    @property
    def dpmaif(self) -> DpmaifDevice:
        for d in self.mmio:
            if isinstance(d, DpmaifDevice):
                return d
        raise KeyError("no DpmaifDevice attached")

    @property
    def wdt(self) -> WdtDevice:
        for d in self.mmio:
            if isinstance(d, WdtDevice):
                return d
        raise KeyError("no WdtDevice attached")

    # -- MPU core ----------------------------------------------------------
    def mpu_find(self, addr: int, ln: int = 1) -> MpuRegion | None:
        """Most-specific entry fully containing [addr, addr+ln), else None."""
        best: MpuRegion | None = None
        for e in self.mpu:
            if e.contains(addr, ln) and (best is None or e.size < best.size):
                best = e
        return best

    def mmio_find(self, addr: int, ln: int = 1) -> MmioDevice | None:
        for d in self.mmio:
            if d.covers(addr, ln):
                return d
        return None

    @staticmethod
    def _need(kind: str) -> int:
        return {  # read->R, write->W, exec->X
            "read": PERM_R, "write": PERM_W, "exec": PERM_X}[kind]

    def _check(self, kind: str, addr: int, ln: int, actor: str) -> MpuRegion:
        if actor not in ("md", "ap"):
            raise ValueError(f"actor must be 'md'/'ap', got {actor!r}")
        e = self.mpu_find(addr, ln)
        if e is None:
            self.fault_log.append((addr, kind))
            self.mpu_log.append({"op": kind, "actor": actor,
                                 "addr": f"{addr:#x}", "size": ln,
                                 "region": None, "verdict": "unmapped"})
            raise MpuFault(addr, kind, None, actor, "unmapped address")
        perm = e.md_perm if actor == "md" else e.ap_perm
        if not (perm & self._need(kind)):
            self.fault_log.append((addr, kind))
            self.mpu_log.append({"op": kind, "actor": actor,
                                 "addr": f"{addr:#x}", "size": ln,
                                 "region": e.name, "verdict": "denied"})
            raise MpuFault(addr, kind, e.name, actor,
                           f"MPU {perm_str(perm)} denies {kind.upper()} "
                           f"(Fig-3 {e.kind})")
        return e

    # -- accessors (base-compatible signatures + explicit-side wrappers) ---
    def read(self, addr: int, ln: int, actor: str = "md") -> bytes:
        e = self._check("read", addr, ln, actor)
        dev = self.mmio_find(addr, ln)
        if dev is not None:
            return dev.read(addr, ln, actor)
        try:
            return super().read(addr, ln)
        except MpuFault:
            raise
        except MemoryFault:
            self.mpu_log.append({"op": "read", "actor": actor,
                                 "addr": f"{addr:#x}", "size": ln,
                                 "region": e.name,
                                 "verdict": "no-backing-storage"})
            raise MpuFault(addr, "read", e.name, actor,
                           "MPU allows but no storage mapped")

    def write(self, addr: int, buf: bytes, actor: str = "md") -> None:
        e = self._check("write", addr, len(buf), actor)
        dev = self.mmio_find(addr, len(buf))
        if dev is not None:
            dev.write(addr, bytes(buf), actor)
            self._fire("write", addr, len(buf))
            return
        try:
            super().write(addr, bytes(buf))
        except MpuFault:
            raise
        except MemoryFault:
            self.mpu_log.append({"op": "write", "actor": actor,
                                 "addr": f"{addr:#x}", "size": len(buf),
                                 "region": e.name,
                                 "verdict": "no-backing-storage"})
            raise MpuFault(addr, "write", e.name, actor,
                           "MPU allows but no storage mapped")
        self._fire("write", addr, len(buf))

    def check_exec(self, addr: int, ln: int = 2, actor: str = "md") -> MpuRegion:
        """Enforce the X bit (mirrors an MPU instruction-fetch abort)."""
        return self._check("exec", addr, ln, actor)

    def md_read(self, addr: int, ln: int) -> bytes:
        return self.read(addr, ln, "md")

    def ap_read(self, addr: int, ln: int) -> bytes:
        return self.read(addr, ln, "ap")

    def md_write(self, addr: int, buf: bytes) -> None:
        self.write(addr, buf, "md")

    def ap_write(self, addr: int, buf: bytes) -> None:
        self.write(addr, buf, "ap")


# --------------------------------------------------------------------------
# 2b. CCCI SMEM ring model (index discipline over shared-RW windows)
# --------------------------------------------------------------------------

class RingError(Exception):
    pass


class RingOverrun(RingError):
    """Enqueue on a full ring (or count > capacity): producer must wait."""

    def __init__(self, name: str, ridx: int, widx: int, cap: int):
        super().__init__(f"ring {name}: overrun r={ridx} w={widx} cap={cap}")
        self.ring, self.ridx, self.widx, self.cap = name, ridx, widx, cap


class MalformedIndex(RingError):
    """Shared-memory index/length failed validation: logged, never trusted."""

    def __init__(self, name: str, detail: str, ridx: int = -1, widx: int = -1):
        super().__init__(f"ring {name}: malformed ({detail})")
        self.ring, self.detail, self.ridx, self.widx = name, detail, ridx, widx


@dataclass
class RingSpec:
    name: str
    capacity: int
    slot_len: int
    ctrl_off: int     # header offset inside the SMEM ctrl window
    data_off: int     # payload-area offset inside the SMEM data window


class SmemRingSet:
    """CCCI ring headers + index discipline in MpuMemory SMEM windows.

    Header (20 B, u32 LE): magic "CCCI" | capacity | slot_len | read_idx |
    write_idx. Slot i: u32 msg_len + payload, padded to slot_len.
    Indices are u32 monotonic counters; position = idx % capacity;
    count = (write - read) & 0xFFFFFFFF. count > capacity is never acted on:
    it is logged as a malformed-index event and raises (CVE-2022-21765
    class: AP-written shared-memory indices/lengths treated as hostile).

    Both sides operate the same bytes through actor-tagged methods, so a
    future AP-side peer plugs in by calling with actor="ap".
    """

    MAGIC = 0x49434343  # LE bytes "CCCI"
    HDR = struct.Struct("<5I")
    HDR_SIZE = HDR.size
    SLOT_HDR = struct.Struct("<I")

    def __init__(self, mem: MpuMemory,
                 ctrl_base: int = SMEM_CTRL_BASE,
                 ctrl_size: int = SMEM_CTRL_SIZE,
                 data_base: int = SMEM_DATA_BASE,
                 data_size: int = SMEM_DATA_SIZE) -> None:
        self.mem = mem
        self.ctrl_base = ctrl_base
        self.ctrl_size = ctrl_size
        self.data_base = data_base
        self.data_size = data_size
        self.rings: dict[str, RingSpec] = {}
        self.events: list[dict] = []  # {seq,ring,kind,...} forensic log
        self._seq = 0
        self._ctrl_cur = 0
        self._data_cur = 0

    # -- helpers -----------------------------------------------------------
    def _ev(self, ring: str, kind: str, **kw) -> dict:
        self._seq += 1
        rec = {"seq": self._seq, "ring": ring, "kind": kind}
        rec.update(kw)
        self.events.append(rec)
        return rec

    def _hdr_addr(self, spec: RingSpec) -> int:
        return self.ctrl_base + spec.ctrl_off

    def _slot_addr(self, spec: RingSpec, pos: int) -> int:
        return self.data_base + spec.data_off + pos * spec.slot_len

    def create_ring(self, name: str, capacity: int, slot_len: int,
                    actor: str = "md") -> RingSpec:
        if name in self.rings:
            raise ValueError(f"ring {name} exists")
        if capacity < 1 or slot_len < 8:
            raise ValueError("capacity>=1 and slot_len>=8 required")
        ctrl_off, data_off = self._ctrl_cur, self._data_cur
        if ctrl_off + self.HDR_SIZE > self.ctrl_size:
            raise ValueError("SMEM ctrl window exhausted")
        need = capacity * slot_len
        if data_off + need > self.data_size:
            raise ValueError("SMEM data window exhausted")
        spec = RingSpec(name, capacity, slot_len, ctrl_off, data_off)
        self.mem.write(self._hdr_addr(spec),
                       self.HDR.pack(self.MAGIC, capacity, slot_len, 0, 0),
                       actor)
        self.rings[name] = spec
        self._ctrl_cur += self.HDR_SIZE
        self._data_cur += need
        self._ev(name, "create", capacity=capacity, slot_len=slot_len,
                 actor=actor)
        return spec

    def _load(self, name: str, actor: str) -> tuple[RingSpec, int, int]:
        spec = self.rings[name]  # KeyError on unknown ring: fail loud
        raw = self.mem.read(self._hdr_addr(spec), self.HDR_SIZE, actor)
        magic, cap, slot, ridx, widx = self.HDR.unpack(raw)
        if magic != self.MAGIC:
            self._ev(name, "malformed-magic", actor=actor,
                     magic=f"{magic:#x}", ridx=ridx, widx=widx)
            raise MalformedIndex(name, f"bad magic {magic:#x}", ridx, widx)
        if (cap, slot) != (spec.capacity, spec.slot_len):
            self._ev(name, "malformed-geometry", actor=actor, cap=cap,
                     slot=slot, ridx=ridx, widx=widx)
            raise MalformedIndex(name, "header geometry != ring spec",
                                 ridx, widx)
        return spec, ridx, widx

    @staticmethod
    def _count(ridx: int, widx: int) -> int:
        return (widx - ridx) & 0xFFFFFFFF

    def _store_indices(self, spec: RingSpec, ridx: int, widx: int,
                       actor: str) -> None:
        self.mem.write(self._hdr_addr(spec) + 12,
                       struct.pack("<2I", ridx & 0xFFFFFFFF,
                                   widx & 0xFFFFFFFF), actor)

    # -- data path ---------------------------------------------------------
    def count(self, name: str, actor: str = "md") -> int:
        spec, ridx, widx = self._load(name, actor)
        n = self._count(ridx, widx)
        if n > spec.capacity:
            self._ev(name, "malformed-index", actor=actor, ridx=ridx,
                     widx=widx, count=n, cap=spec.capacity)
            raise MalformedIndex(name, f"count {n} > cap {spec.capacity}",
                                 ridx, widx)
        return n

    def enqueue(self, name: str, payload: bytes, actor: str = "md") -> int:
        """Append payload; returns queue count after. Raises RingOverrun."""
        spec, ridx, widx = self._load(name, actor)
        n = self._count(ridx, widx)
        if n > spec.capacity:
            self._ev(name, "malformed-index", actor=actor, ridx=ridx,
                     widx=widx, count=n, cap=spec.capacity)
            raise MalformedIndex(name, f"count {n} > cap {spec.capacity}",
                                 ridx, widx)
        if n == spec.capacity:
            self._ev(name, "overrun", actor=actor, ridx=ridx, widx=widx,
                     cap=spec.capacity)
            raise RingOverrun(name, ridx, widx, spec.capacity)
        if len(payload) > spec.slot_len - 4:
            self._ev(name, "malformed-length", actor=actor,
                     length=len(payload), slot=spec.slot_len)
            raise MalformedIndex(name, f"len {len(payload)} > slot payload "
                                 f"{spec.slot_len - 4}")
        pos = widx % spec.capacity
        slot = self._slot_addr(spec, pos)
        buf = self.SLOT_HDR.pack(len(payload)) + bytes(payload)
        buf += b"\x00" * (spec.slot_len - len(buf))
        self.mem.write(slot, buf, actor)
        self._store_indices(spec, ridx, (widx + 1) & 0xFFFFFFFF, actor)
        self._ev(name, "enqueue", actor=actor, pos=pos,
                 length=len(payload))
        return n + 1

    def dequeue(self, name: str, actor: str = "md") -> bytes | None:
        """Next payload, or None when empty. Validates the length prefix."""
        spec, ridx, widx = self._load(name, actor)
        n = self._count(ridx, widx)
        if n > spec.capacity:
            self._ev(name, "malformed-index", actor=actor, ridx=ridx,
                     widx=widx, count=n, cap=spec.capacity)
            raise MalformedIndex(name, f"count {n} > cap {spec.capacity}",
                                 ridx, widx)
        if n == 0:
            return None
        pos = ridx % spec.capacity
        slot = self._slot_addr(spec, pos)
        (mlen,) = self.SLOT_HDR.unpack(
            self.mem.read(slot, 4, actor))
        if mlen > spec.slot_len - 4:
            # Hostile/rotten length prefix: quarantine, do NOT advance.
            self._ev(name, "malformed-length", actor=actor, pos=pos,
                     length=mlen, slot=spec.slot_len, ridx=ridx, widx=widx)
            raise MalformedIndex(name, f"slot len {mlen} > payload "
                                 f"{spec.slot_len - 4}", ridx, widx)
        payload = self.mem.read(slot + 4, mlen, actor)
        self._store_indices(spec, (ridx + 1) & 0xFFFFFFFF, widx, actor)
        self._ev(name, "dequeue", actor=actor, pos=pos, length=mlen)
        return bytes(payload)

    # -- test / peer escape hatch ------------------------------------------
    def set_indices(self, name: str, ridx: int, widx: int,
                    actor: str = "ap") -> None:
        """Directly plant shared-memory indices (simulates the AP peer writing
        them, honest or hostile). Always logged; validation happens on next
        data-path op, exactly like modem code re-reading SMEM."""
        spec = self.rings[name]
        self._store_indices(spec, ridx, widx, actor)
        self._ev(name, "index-inject", actor=actor, ridx=ridx & 0xFFFFFFFF,
                 widx=widx & 0xFFFFFFFF)

    def get_indices(self, name: str, actor: str = "md") -> tuple[int, int]:
        _, ridx, widx = self._load(name, actor)
        return ridx, widx


def ring_design_doc() -> str:
    return "\n".join([
        "CCCI SMEM ring design (SmemRingSet; CVE-2022-21765-class hardening):",
        f"  header 20B u32LE: magic 'CCCI'({SmemRingSet.MAGIC:#x}) | capacity | "
        "slot_len | read_idx | write_idx",
        "  slot i: u32 msg_len + payload, zero-padded to slot_len",
        "  indices: u32 monotonic; pos = idx % capacity; "
        "count = (write - read) & 0xFFFFFFFF",
        "  rules: count > capacity -> malformed-index event + raise (never act);",
        "         enqueue on full -> overrun event + RingOverrun;",
        "         msg_len/slot_len or bad magic/geometry -> malformed event + raise;",
        "         dequeue on empty -> None.",
        "  peer model: both sides share the same bytes via actor-tagged ops",
        "  (md_* / ap_* or enqueue(..., actor=...)); set_indices() simulates the",
        "  AP peer planting indices, honest or hostile.",
    ])


# --------------------------------------------------------------------------
# Selftest
# --------------------------------------------------------------------------

def _check(ok: bool, label: str, fails: list[str], detail: str = "") -> None:
    if not ok:
        fails.append(f"{label}{(': ' + detail) if detail else ''}")


def selftest() -> tuple[int, int, list[str]]:
    """Returns (passed, failed, details). No device, no writes, stdlib only."""
    passed = failed = 0
    details: list[str] = []
    fails: list[str] = []

    def check(label: str, ok: bool, detail: str = "") -> None:
        nonlocal passed, failed
        if ok:
            passed += 1
        else:
            failed += 1
        _check(ok, label, fails, detail)
        details.append(("PASS " if ok else "FAIL ") + label
                       + (f" ({detail})" if detail and not ok else ""))

    # -- 0. base class untouched & green ------------------------------------
    try:
        from emu_engine import decode_conformance
        df = decode_conformance()
        check("base decode_conformance green", df == [], "; ".join(df))
        bm = Memory()
        bm.add("t", 0x1000, 0x100, PERM_R | PERM_W, b"\xAA" * 4)
        bm.write(0x1000, b"\x01\x02")
        check("base Memory R/W intact", bm.read(0x1000, 2) == b"\x01\x02")
        try:
            bm.read(0xDEAD0000, 4)
            check("base Memory still faults off-map", False)
        except MemoryFault:
            check("base Memory still faults off-map", True)
        check("MpuMemory extends Memory", isinstance(MpuMemory(), Memory))
    except Exception as e:  # noqa: BLE001
        check("base-class green", False, repr(e))

    # -- 1. table constants vs files -----------------------------------------
    try:
        check("VA base 0x90000000", MODEM_VA == 0x90000000 == VA_BASE)
        check("ROM size 45893712", MODEM_SIZE == 45893712 == ROM_SIZE)
        check("AP carveout 0xD0000000", MODEM_AP_PHYS == 0xD0000000)
        check("vectors inside ROM", all(MODEM_VA <= v < MODEM_END for v in VECTORS))
        check("DPMAIF cache 0x190000/1.6M",
              DPMAIF_CACHE_SIZE == 0x190000 == 1600 * 1024)
        check("DPMAIF nocache 0x50000/320K",
              DPMAIF_NOCACHE_SIZE == 0x50000 == 320 * 1024)
        check("CCIF 12 blocks / 6 pairs",
              len(CCIF_BLOCKS) == 12 and len(CCIF_PAIRS) == 6)
        check("temp_share 0x10018000/4K",
              MODEM_TEMP_SHARE_BASE == 0x10018000
              and MODEM_TEMP_SHARE_SIZE == 0x1000)
        check("WDT 0x1C007000/0x100", WDT_BASE == 0x1C007000 and WDT_SIZE == 0x100)
        check("DRAM window 0x40000000:0x4000000",
              DRAM_BASE == 0x40000000 and DRAM_SIZE == 0x4000000)
        check("Fig-3 ROM R-X", MPU_TABLE[0].md_perm == (PERM_R | PERM_X)
              and MPU_TABLE[0].ap_perm == 0)
        check("Fig-3 SMEM shared-RW",
              all(e.md_perm == e.ap_perm == (PERM_R | PERM_W)
                  for e in MPU_TABLE if e.kind in ("smem", "dpmaif-shm")))
        check("DPMAIF cache/nocache contiguous",
              DPMAIF_CACHE_BASE + DPMAIF_CACHE_SIZE == DPMAIF_NOCACHE_BASE)
        check("SMEM+DPMAIF inside DRAM window",
              SMEM_CTRL_BASE >= DRAM_BASE and
              DPMAIF_NOCACHE_BASE + DPMAIF_NOCACHE_SIZE <= DRAM_BASE + DRAM_SIZE)
    except Exception as e:  # noqa: BLE001
        check("table constants", False, repr(e))

    # -- 1b. cross-checks against hw_target.py + md1work.dtb (read-only) -----
    try:
        sys.path.insert(0, str(SIM_DIR)) if str(SIM_DIR) not in sys.path else None
        from hw_target import SPEC as HW
        m = HW["mem"]
        check("hw_target VA match", m["modem_va"] == MODEM_VA)
        check("hw_target phys match", m["modem_ap_phys"] == MODEM_AP_PHYS)
        check("hw_target size match", m["modem_size"] == MODEM_SIZE)
        check("hw_target vectors match", tuple(m["vectors"]) == VECTORS)
        check("hw_target temp_share match", m["modem_temp_share"] == MODEM_TEMP_SHARE_BASE)
        check("hw_target ccif pairs match",
              tuple(m["ccif_pairs"]) == tuple(f"{a:08x}/{b:08x}" for (_, a), (_, b) in
                    [((CCIF_BLOCKS[i][0], CCIF_BLOCKS[i][1]),
                      (CCIF_BLOCKS[i + 1][0], CCIF_BLOCKS[i + 1][1]))
                     for i in range(0, 12, 2)]))
        check("hw_target dpmaif sizes match",
              m["dpmaif_cache"][0] == DPMAIF_CACHE_SIZE
              and m["dpmaif_nocache"][0] == DPMAIF_NOCACHE_SIZE)
    except Exception as e:  # noqa: BLE001
        check("hw_target cross-check", False, repr(e))
    try:
        dtb = REPO_ROOT / "md1work.dtb"
        if dtb.is_file():
            blob = dtb.read_bytes()  # read-only
            for needle in (b"modem_temp_share@10018000", b"ap_ccif0@10209000",
                           b"md_ccif0@1020a000", b"ap_ccif5@1025c000",
                           b"md_ccif5@1025d000", b"dpmaif@10014000",
                           b"watchdog@1c007000",
                           b"ccci-dpmaif-cache-memory",
                           b"ccci-dpmaif-nocache-memory"):
                check(f"dtb has {needle.decode()}", needle in blob)
        else:
            check("dtb present", True, "skipped (file absent)")
    except Exception as e:  # noqa: BLE001
        check("dtb cross-check", False, repr(e))

    # -- 2. build map ----------------------------------------------------------
    try:
        mem = MpuMemory.with_image_and_smem()
        check("map builds", True)
    except Exception as e:  # noqa: BLE001
        mem = None  # type: ignore[assignment]
        check("map builds", False, repr(e))
        return passed, failed, details

    # -- 3. MPU-violation fidelity ---------------------------------------------
    assert mem is not None
    try:
        mem.md_write(MODEM_VA, b"\x00")
        check("ROM-write faults (MD)", False, "no fault")
    except MpuFault as f:
        check("ROM-write faults (MD)", f.region == "md_rom_va",
              f"region={getattr(f, 'region', '?')}")
        check("fault is a MemoryFault", isinstance(f, MemoryFault))
    except Exception as e:  # noqa: BLE001
        check("ROM-write faults (MD)", False, repr(e))
    try:
        mem.ap_read(MODEM_AP_PHYS, 4)
        check("AP none-after-load (phys mirror)", False, "no fault")
    except MpuFault as f:
        check("AP none-after-load (phys mirror)", f.region == "md_rom_phys",
              f"region={getattr(f, 'region', '?')}")
    try:
        mem.ap_read(MODEM_VA, 4)
        check("AP cannot read MD ROM", False, "no fault")
    except MpuFault as f:
        check("AP cannot read MD ROM", f.region == "md_rom_va",
              f"region={getattr(f, 'region', '?')}")
    try:
        mem.check_exec(SML_FUNC_VA, 4, "md")
        check("MD exec ROM allowed (R-X)", True)
    except MpuFault as f:
        check("MD exec ROM allowed (R-X)", False, repr(f))
    try:
        mem.check_exec(SMEM_DATA_BASE, 4, "md")
        check("MD exec SMEM denied (RW-, NX)", False, "no fault")
    except MpuFault as f:
        check("MD exec SMEM denied (RW-, NX)", f.region == "smem_data",
              f"region={getattr(f, 'region', '?')}")
    # Optional read-only probe of the real ROM image (never modified).
    try:
        romf = REPO_ROOT / "md1work_romonly.bin"
        if romf.is_file():
            head = romf.read_bytes()[SML_FUNC_VA - MODEM_VA:][:4]
            check("real ROM SML head", head == SML_STOCK_HEAD, head.hex())
            rmem = MpuMemory.with_image_and_smem(
                __import__("emu_engine").Image(romf.read_bytes()))
            check("real ROM maps R-X",
                  rmem.md_read(SML_FUNC_VA, 4) == SML_STOCK_HEAD)
    except Exception as e:  # noqa: BLE001
        check("real ROM probe", False, repr(e))

    # -- 4. SMEM shared-RW (both actors, both directions) -----------------------
    try:
        mem.md_write(SMEM_DATA_BASE, b"MD->AP")
        check("SMEM MD-write/AP-read", mem.ap_read(SMEM_DATA_BASE, 6) == b"MD->AP")
        mem.ap_write(SMEM_DATA_BASE + 0x10, b"AP->MD")
        check("SMEM AP-write/MD-read",
              mem.md_read(SMEM_DATA_BASE + 0x10, 6) == b"AP->MD")
        mem.md_write(MODEM_TEMP_SHARE_BASE, b"T")
        check("temp_share shared", mem.ap_read(MODEM_TEMP_SHARE_BASE, 1) == b"T")
    except Exception as e:  # noqa: BLE001
        check("SMEM shared-RW", False, repr(e))

    # -- 5. CCIF MMIO: reads zero+log, doorbell fires hook -----------------------
    try:
        z = mem.md_read(0x10209000, 8)
        check("CCIF read returns 0", z == b"\x00" * 8)
        check("CCIF read logged", any(r["op"] == "read" for r in mem.ccif.log))
        fired: list[dict] = []
        mem.ccif.on_doorbell(fired.append)
        mem.md_write(0x10209000, struct.pack("<I", 1))  # AP-CCIF0 CON set
        check("CCIF doorbell hook fires",
              len(fired) == 1 and fired[0]["block"] == "ap_ccif0"
              and fired[0]["peer"] == "md_ccif0", repr(fired))
        mem.ap_write(0x1020A004, struct.pack("<I", 0))  # zero clear: no event
        check("CCIF zero-clear silent", len(fired) == 1)
        mem.ap_write(0x1020A004, struct.pack("<I", 0xFFFF))  # MD-CCIF0 clear
        check("CCIF clear-event fires",
              len(fired) == 2 and fired[1]["kind"] == "clear"
              and fired[1]["peer"] == "ap_ccif0", repr(fired))
    except Exception as e:  # noqa: BLE001
        check("CCIF MMIO", False, repr(e))

    # -- 6. ring discipline + AP peer plug-in ------------------------------------
    try:
        rings = SmemRingSet(mem)
        rings.create_ring("ccci0", capacity=4, slot_len=64)
        check("ring create", True)
        rings.enqueue("ccci0", b"hello-md", actor="md")
        check("MD enqueue / AP dequeue (peer)",
              rings.dequeue("ccci0", actor="ap") == b"hello-md")
        check("empty dequeue -> None", rings.dequeue("ccci0", actor="md") is None)
        # Wrap: 6 produce/consume cycles on a 4-slot ring.
        ok = True
        for i in range(6):
            rings.enqueue("ccci0", bytes([i]) * 8, actor="ap")
            if rings.dequeue("ccci0", actor="md") != bytes([i]) * 8:
                ok = False
        r, w = rings.get_indices("ccci0")
        check("ring wraps (idx advances mod cap)",
              ok and (w - r) & 0xFFFFFFFF == 0, f"r={r} w={w}")
        # Overrun: fill to capacity, one more must raise + log.
        for i in range(4):
            rings.enqueue("ccci0", b"x", actor="md")
        try:
            rings.enqueue("ccci0", b"boom", actor="md")
            check("overrun raises", False, "no raise")
        except RingOverrun:
            check("overrun raises", True)
        check("overrun logged",
              any(e["kind"] == "overrun" for e in rings.events))
        for _ in range(4):
            rings.dequeue("ccci0", actor="ap")
        # Malformed index (hostile peer plants widx far ahead): quarantine.
        rings.set_indices("ccci0", 0, 99, actor="ap")
        try:
            rings.dequeue("ccci0", actor="md")
            check("malformed-index raises", False, "no raise")
        except MalformedIndex:
            check("malformed-index raises", True)
        check("malformed-index logged",
              any(e["kind"] == "malformed-index" for e in rings.events))
        # Malformed length prefix: plant a huge len, must not be trusted.
        rings.set_indices("ccci0", 0, 0, actor="ap")
        rings.enqueue("ccci0", b"ok", actor="md")
        r, _ = rings.get_indices("ccci0")
        pos = r % 4
        mem.md_write(SMEM_DATA_BASE + pos * 64, struct.pack("<I", 0xFFFFFF))
        try:
            rings.dequeue("ccci0", actor="md")
            check("malformed-length raises", False, "no raise")
        except MalformedIndex:
            check("malformed-length raises", True)
        check("malformed-length logged",
              any(e["kind"] == "malformed-length" for e in rings.events))
    except Exception as e:  # noqa: BLE001
        check("ring discipline", False, repr(e))

    # -- 7. DPMAIF BAT + WDT logs --------------------------------------------------
    try:
        d = mem.dpmaif.bat_add(DRAM_BASE + 0x1000, 0x800, "rx", actor="ap")
        check("BAT accept in-window", d["phys"] == DRAM_BASE + 0x1000)
        try:
            mem.dpmaif.bat_add(0x10000000, 0x800, "rx")
            check("BAT reject OOB", False, "no raise")
        except ValueError:
            check("BAT reject OOB", True)
        check("BAT log kept", len(mem.dpmaif.bat_log) == 2)
        mem.md_write(0x10014000, struct.pack("<I", 1))
        check("DPMAIF reg write logged",
              any(r["addr"] == f"{0x10014000:#x}" for r in mem.dpmaif.log))
        mem.md_write(WDT_BASE, b"\x55\xAA")
        check("WDT write logged",
              any(r["addr"] == f"{WDT_BASE:#x}" for r in mem.wdt.log))
        check("WDT read returns 0", mem.md_read(WDT_BASE, 4) == b"\x00" * 4)
    except Exception as e:  # noqa: BLE001
        check("BAT/WDT", False, repr(e))

    return passed, failed, details


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if "--table" in args:
        print(dump_table())
        return 0
    if "--rings" in args:
        print(ring_design_doc())
        return 0
    passed, failed, details = selftest()
    print(f"mem_model selftest: {passed} passed, {failed} failed")
    for d in details:
        print("  " + d)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
