#!/usr/bin/env python3
"""chain.py — whole-chain byte-for-byte simulation with code + memory traces.

Runs a full call chain on the REAL ROM image (strict mode: no stub-paving,
no leniency) and records:
  chain_code.jsonl — every executed insn {step, pc, bytes, text}
  chain_mem.jsonl  — every data read/write {step, kind, addr, size, data}
  chain_summary.json — verdict, stops, coverage, boundary list

Memory tracing wraps Cpu.load_bytes/store_bytes (the two funnels ALL data
traffic passes through), so no engine edits were needed.

Presets (entry, size, regs, stubs):
  legal  — legal_sim_rule + REAL helpers
  link   — linker + REAL legal_sim_rule subtree
  esmlck — rmmi_esmlck_hdlr, helpers ret1 (widest real coverage first)
  verify — sml_Verify, helpers ret1

Usage:
  python sim/chain.py --preset legal --out sim/chains/legal_run
  python sim/chain.py --selftest   # determinism + artifact check, no device
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sim import emu_engine, interp  # noqa: E402

VA_BASE = emu_engine.VA_BASE
LEGAL_HELPERS = [0x9198A6F0, 0x9198A744, 0x90ED3222, 0x90ED7CE2]

# V1/V2 JALRC pcs in sml_Verify + statically resolved getItem candidates
# (sec-vtbl: ROM templates => slot+0x10 = getItem; customizers only zero +0x00).
FORK_V1_PC = 0x905F0F28
FORK_V2_PC = 0x905F0F38
FORK_GETITEM = (0x905EC8B2, 0x905EC800, 0x905EC6F4)

PRESETS = {
    "legal": {"va": 0x905DF2FA, "size": 0x5E,
              "regs": {}, "real": list(LEGAL_HELPERS), "ret1": []},
    "link": {"va": 0x905DF3A2, "size": 0x3CC,
             "regs": {}, "real": [0x905DF2FA, *LEGAL_HELPERS], "ret1": []},
    "esmlck": {"va": 0x91985788, "size": 0x1AA,
               "regs": {}, "real": [], "ret1": "auto"},
    "verify": {"va": 0x905F0F04, "size": 0x84,
               "regs": {}, "real": [], "ret1": "auto"},
}


class ChainRunner:
    def __init__(self, va: int, size: int, regs: dict | None = None,
                 real_vas: set[int] | None = None,
                 ret1_vas: set[int] | None = None,
                 auto_ret1: bool = False,
                 step_cap: int = 50000) -> None:
        self.va, self.size = va, size
        self.step_cap = step_cap
        img = emu_engine.Image.load_romonly().data
        off = va - VA_BASE
        carve = img[off:off + size]
        stubs: dict[int, object] = {v: ("real", None) for v in (real_vas or ())}
        for v in (ret1_vas or ()):
            stubs[v] = ("ret1", None)
        self.tracer = emu_engine.Tracer()
        self.cpu = interp.Cpu(img, va, bytes(carve), regs=regs or {},
                              stubs=stubs, tracer=self.tracer,
                              step_cap=step_cap, strict=True)
        if auto_ret1:
            # legacy helper dynamics for wide coverage (documented leniency)
            self._auto_all_ret1()
        self.mem_events: list[dict] = []
        self._wrap_memory()

    def _auto_all_ret1(self) -> None:
        # prescan already stubbed carve BALC targets; keep as-is (ret1).
        pass

    def _wrap_memory(self) -> None:
        cpu, log = self, self.mem_events

        orig_load = cpu.cpu.load_bytes
        orig_store = cpu.cpu.store_bytes

        def load(addr: int, ln: int) -> bytes:
            data = orig_load(addr, ln)
            log.append({"step": cpu.cpu.steps, "kind": "read",
                        "addr": f"{addr:#x}", "size": ln,
                        "data": data.hex() if ln <= 256 else data[:256].hex() + "…"})
            return data

        def store(addr: int, data: bytes) -> None:
            log.append({"step": cpu.cpu.steps, "kind": "write",
                        "addr": f"{addr:#x}", "size": len(data),
                        "data": (data.hex() if len(data) <= 256
                                 else bytes(data[:256]).hex() + "…")})
            return orig_store(addr, data)

        cpu.cpu.load_bytes = load  # type: ignore[method-assign]
        cpu.cpu.store_bytes = store  # type: ignore[method-assign]

    def run(self) -> dict:
        res = self.cpu.run()
        code = []
        for e in getattr(self.tracer, "events", []):
            pc = e.pc if isinstance(getattr(e, "pc", None), int) else e.get("pc")  # type: ignore
            code.append({"step": getattr(e, "step", None), "pc": pc,
                         "text": getattr(e, "text", None)})
        return {"va": self.va, "size": self.size,
                "stop": res.get("stop"), "pc": res.get("pc"),
                "a0": res.get("a0"), "steps": res.get("steps"),
                "gaps": res.get("gaps", []),
                "auto_stubs": [f"{v:#x}" for v in
                               getattr(self.cpu, "auto_stubs", [])],
                "code": code, "mem": self.mem_events}

    def save(self, outdir: Path) -> Path:
        outdir = Path(outdir)
        outdir.mkdir(parents=True, exist_ok=True)
        r = self.run()
        with (outdir / "chain_code.jsonl").open("w") as f:
            for c in r.pop("code"):
                f.write(json.dumps(c) + "\n")
        with (outdir / "chain_mem.jsonl").open("w") as f:
            for m in r.pop("mem"):
                f.write(json.dumps(m) + "\n")
        with (outdir / "chain_summary.json").open("w") as f:
            json.dump(r, f, indent=1)
        return outdir


def _drive(runner, until_pcs, max_steps):
    cpu = runner.cpu
    u32 = interp.u32
    steps = 0
    hit = None
    while steps < max_steps:
        pc = u32(cpu.pc)
        if pc in until_pcs:
            hit = pc
            break
        if pc in cpu.ret_set:
            cpu.stop = "HIT-RET"
            break
        if pc == cpu.ra_init and steps > 0:
            cpu.stop = "HIT-RET"
            break
        try:
            text, size, _raw = cpu._decode_at(pc)
        except interp._MemoryFault as e:
            if cpu.strict or (cpu.fn_va <= pc < cpu.fn_end):
                cpu.stop = f"MEM-FAULT @{pc:#x}"
                cpu.gaps.append(str(e))
                break
            cpu.stub_table[pc] = ("ret1", None)
            cpu._write_stub_bytes(pc, interp.STUB_RET1)
            cpu.auto_stubs.append(pc)
            cpu.gaps.append(f"auto-stub exec @{pc:#x} (was {e})")
            continue
        except interp.EmuUnsupported as e:
            if cpu.strict or (cpu.fn_va <= pc < cpu.fn_end):
                cpu.stop = f"UNSUPPORTED @{pc:#x}"
                cpu.gaps.append(str(e))
                break
            cpu.stub_table[pc] = ("ret1", None)
            cpu._write_stub_bytes(pc, interp.STUB_RET1)
            cpu.auto_stubs.append(pc)
            cpu.gaps.append(f"auto-stub gap @{pc:#x} ({e})")
            continue
        cpu._log(steps, pc, text)
        try:
            npc = cpu.step_once_internal(pc, text, size)
        except interp.EmuUnsupported as e:
            cpu.stop = f"UNSUPPORTED @{pc:#x}"
            cpu.gaps.append(str(e))
            break
        except Exception as e:  # noqa: BLE001
            cpu.stop = f"FAULT @{pc:#x}: {e}"
            cpu.gaps.append(f"{pc:#x} {text}: {e}")
            break
        pc = u32(npc)
        cpu.pc = pc
        steps += 1
        if steps >= max_steps:
            cpu.stop = "STEP-CAP"
            break
    else:
        cpu.stop = "STEP-CAP"
    if not cpu.stop:
        cpu.stop = "STEP-CAP"
    cpu.steps = steps
    return hit, {"stop": cpu.stop, "pc": u32(cpu.pc),
                  "a0": u32(cpu.get("a0")), "steps": steps,
                  "gaps": list(cpu.gaps),
                  "auto_stubs": [f"{v:#x}" for v in cpu.auto_stubs]}


def run_fork_getitem(outdir: Path, step_cap: int = 50000) -> dict:
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    fork_results: list[dict] = []
    for c1 in FORK_GETITEM:
        for c2 in FORK_GETITEM:
            p = PRESETS["verify"]
            regs = {"a0": 0xB0001000, "sp": 0xA000FFF0,
                    "ra": 0xDEAD0000}
            runner = ChainRunner(p["va"], p["size"], regs=regs,
                                 real_vas=set(p["real"]),
                                 ret1_vas=None, auto_ret1=True,
                                 step_cap=step_cap)
            cpu = runner.cpu
            for c in FORK_GETITEM:
                cpu._ensure_region(c, 4)
            tag = f"c1_{c1:08x}_c2_{c2:08x}"
            rec: dict = {"v1_va": f"{c1:#x}", "v2_va": f"{c2:#x}"}
            hit, _r = _drive(runner, {FORK_V1_PC}, step_cap)
            if hit != FORK_V1_PC:
                rec.update(status="no-v1", stop=_r["stop"],
                             pc=f"{_r['pc']:#x}", a0=f"{_r['a0']:#x}",
                             steps=_r["steps"], gaps=_r["gaps"][:4])
                fork_results.append(rec)
                save_fork_traces(runner, outdir / tag, rec)
                continue
            cpu.put("s0", c1)
            hit, _r = _drive(runner, {FORK_V2_PC}, step_cap)
            if hit != FORK_V2_PC:
                rec.update(status="no-v2", stop=_r["stop"],
                             pc=f"{_r['pc']:#x}", a0=f"{_r['a0']:#x}",
                             steps=_r["steps"], gaps=_r["gaps"][:4])
                fork_results.append(rec)
                save_fork_traces(runner, outdir / tag, rec)
                continue
            cpu.put("s1", c2)
            _hit, _r = _drive(runner, set(), step_cap)
            rec.update(status="done", stop=_r["stop"],
                         pc=f"{_r['pc']:#x}", a0=f"{_r['a0']:#x}",
                         steps=_r["steps"], gaps=_r["gaps"][:4],
                         auto_stubs=_r["auto_stubs"])
            fork_results.append(rec)
            save_fork_traces(runner, outdir / tag, rec)
    with (outdir / "fork_results.json").open("w") as f:
        json.dump(fork_results, f, indent=1)
    return fork_results


def save_fork_traces(runner, sub, rec):
    """Persist per-fork code/mem traces + summary (all outcomes)."""
    sub.mkdir(parents=True, exist_ok=True)
    code = []
    for e in getattr(runner.tracer, "events", []):
        epc = e.pc if isinstance(getattr(e, "pc", None), int) \
            else e.get("pc")  # type: ignore
        code.append({"step": getattr(e, "step", None), "pc": epc,
                     "text": getattr(e, "text", None)})
    with (sub / "chain_code.jsonl").open("w") as f:
        for c in code:
            f.write(json.dumps(c) + "\n")
    with (sub / "chain_mem.jsonl").open("w") as f:
        for m in runner.mem_events:
            f.write(json.dumps(m) + "\n")
    with (sub / "chain_summary.json").open("w") as f:
        json.dump(rec, f, indent=1)


def run_preset(name: str, outdir: Path, step_cap: int = 50000) -> dict:
    p = PRESETS[name]
    regs = {"a0": 0xB0001000, "sp": 0xA000FFF0, "ra": 0xDEAD0000}
    regs.update(p["regs"])
    runner = ChainRunner(p["va"], p["size"], regs=regs,
                         real_vas=set(p["real"]),
                         ret1_vas=None if p["ret1"] == "auto" else set(p["ret1"]),
                         auto_ret1=(p["ret1"] == "auto"),
                         step_cap=step_cap)
    runner.save(outdir)
    with (outdir / "chain_summary.json").open() as f:
        return json.load(f)


def selftest() -> int:
    fails: list[str] = []
    import shutil
    tmp = Path("sim/chains/_selftest")
    if tmp.exists():
        shutil.rmtree(tmp)
    s1 = run_preset("legal", tmp / "a", step_cap=3000)
    s2 = run_preset("legal", tmp / "b", step_cap=3000)
    n1 = sum(1 for _ in (tmp / "a" / "chain_code.jsonl").open())
    m1 = sum(1 for _ in (tmp / "a" / "chain_mem.jsonl").open())
    n2 = sum(1 for _ in (tmp / "b" / "chain_code.jsonl").open())
    if n1 == 0:
        fails.append("empty code trace")
    if m1 == 0:
        fails.append("empty mem trace")
    if n1 != n2:
        fails.append(f"nondeterministic: {n1} vs {n2} code events")
    # mem trace sanity: stack writes + ROM-constant reads must appear
    txt = (tmp / "a" / "chain_mem.jsonl").read_text()
    if '"kind": "write"' not in txt:
        fails.append("no write events (SAVE expected)")
    if '"kind": "read"' not in txt:
        fails.append("no read events")
    # determinism on mem too
    if (tmp / "a" / "chain_mem.jsonl").read_text() != \
       (tmp / "b" / "chain_mem.jsonl").read_text():
        fails.append("nondeterministic mem trace")
    shutil.rmtree(tmp, ignore_errors=True)
    print("chain selftest:", "PASS" if not fails else f"FAIL {fails}")
    print(f"  (code events={n1}, mem events={m1}, stop={s1['stop']}, "
          f"a0={s1['a0']:#x})")
    return 1 if fails else 0


def main() -> int:
    ap = argparse.ArgumentParser(description="whole-chain traced simulation")
    ap.add_argument("--preset", choices=sorted(PRESETS))
    ap.add_argument("--out", default="sim/chains/run")
    ap.add_argument("--steps", type=int, default=50000)
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--fork-getitem", action="store_true",
                    help="verify preset x9 with forced getItem targets")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    if args.fork_getitem:
        if args.preset != "verify":
            print("--fork-getitem only applies to --preset verify")
            return 2
        res = run_fork_getitem(Path(args.out), step_cap=args.steps)
        print(f"{'v1':>12} {'v2':>12} {'status':>8} "
              f"{'stop':>28} {'a0':>12} steps")
        for r in res:
            print(f"{r['v1_va']:>12} {r['v2_va']:>12} "
                  f"{r.get('status', '?'):>8} {r.get('stop', '?'):>28} "
                  f"{r.get('a0', '?'):>12} {r.get('steps', '?')}")
        return 0
    s = run_preset(args.preset, Path(args.out), step_cap=args.steps)
    n_code = sum(1 for _ in (Path(args.out) / "chain_code.jsonl").open())
    n_mem = sum(1 for _ in (Path(args.out) / "chain_mem.jsonl").open())
    print(f"stop={s['stop']} a0={s['a0']:#x} steps={s['steps']} "
          f"code={n_code} mem={n_mem}")
    for g in s["gaps"][:6]:
        print(f"  gap: {g}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
