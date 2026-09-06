#!/usr/bin/env python3
"""deep_run.py — full-image deep-call driver (no carves, no new stubs).

Maps the WHOLE md1rom in the interp CPU and executes target functions with
REAL callees (policy 'real': prescan-skipped, never overwritten, decoded from
ROM via image fallback). Anything the CPU cannot do (unmapped HW data,
undecoded insn, step cap) is RECORDED as the hardware boundary — that record
IS the deliverable for hardware modeling.

Usage:
  python sim/deep_run.py --va 0x905df2fa --size 0x5e --real 0x9198a6f0,0x9198a744,0x90ed3222,0x90ed7ce2
  python sim/deep_run.py --va 0x905df3a2 --size 0x3cc --real-link
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sim import emu_engine, interp  # noqa: E402

VA_BASE = emu_engine.VA_BASE

# The 4 helpers of legal_sim_rule (decoded ground truth).
LEGAL_HELPERS = [0x9198A6F0, 0x9198A744, 0x90ED3222, 0x90ED7CE2]


def parse_int(s: str) -> int:
    return int(s, 16) if s.lower().startswith("0x") else int(s)


def deep_run(va: int, size: int, real_vas: set[int],
             extra_stubs: dict | None = None, regs: dict | None = None,
             step_cap: int = 20000) -> dict:
    img = emu_engine.Image.load_romonly().data
    off = va - VA_BASE
    carve = img[off:off + size]
    stubs: dict[int, object] = {v: ("real", None) for v in real_vas}
    for k, v in (extra_stubs or {}).items():
        stubs[int(k)] = v
    tracer = emu_engine.Tracer()
    cpu = interp.Cpu(img, va, bytes(carve), regs=regs or {}, stubs=stubs,
                     tracer=tracer, step_cap=step_cap, strict=True)
    res = cpu.run()
    # executed-VA histogram from tracer
    hist: dict[int, int] = {}
    for e in getattr(tracer, "events", []):
        pc = getattr(e, "pc", None)
        if pc is None and isinstance(e, dict):
            pc = e.get("pc")
        if isinstance(pc, str):
            pc = int(pc, 16)
        if isinstance(pc, int):
            hist[pc] = hist.get(pc, 0) + 1
    # which real callees were reached (any executed PC inside ±2K of target)
    reached = sorted({v for v in real_vas
                      if any(abs(h - v) < 0x2000 for h in hist)})
    return {
        "va": va, "size": size, "stop": res.get("stop"),
        "pc": res.get("pc"), "a0": res.get("a0"), "steps": res.get("steps"),
        "gaps": res.get("gaps", []), "npcs": len(hist),
        "reached_real": [f"{v:#x}" for v in reached],
        "auto_stubs": [f"{v:#x}" for v in getattr(cpu, "auto_stubs", [])],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="full-image deep-call driver")
    ap.add_argument("--va", required=True)
    ap.add_argument("--size", required=True)
    ap.add_argument("--real", default="",
                    help="comma-separated VAs to execute for real")
    ap.add_argument("--real-link", action="store_true",
                    help="linker run: legal_sim_rule + its helpers real")
    ap.add_argument("--steps", type=int, default=20000)
    ap.add_argument("--a0", default="0xb0001000")
    args = ap.parse_args()
    va, size = parse_int(args.va), parse_int(args.size)
    real = {parse_int(x) for x in args.real.split(",") if x.strip()}
    if args.real_link:
        real |= {0x905DF2FA, *LEGAL_HELPERS}
    regs = {"a0": parse_int(args.a0)}
    try:
        r = deep_run(va, size, real, regs=regs, step_cap=args.steps)
    except Exception as e:  # noqa: BLE001
        print(f"DRIVER-ERROR: {type(e).__name__}: {e}")
        return 2
    print(f"stop={r['stop']} pc={r['pc']:#x} a0={r['a0']:#x} "
          f"steps={r['steps']} npcs={r['npcs']}")
    print(f"reached_real: {' '.join(r['reached_real']) or '(none)'}")
    print(f"auto_stubs: {' '.join(r['auto_stubs'][:12])}")
    for g in r["gaps"][:6]:
        print(f"  gap: {g}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
