#!/usr/bin/env python3
"""Ghidra headless emulation backend — reusable Python wrapper (Kansas lab).

Encapsulates the proven EmuSml.java headless pattern as a callable class:

  carve fn bytes from md1work_romonly.bin (off = VA - 0x90000000)
  -> raw-binary import (-processor nanomips:LE:32:default)
  -> postScript rebases via setImageBase(VA,true) + DisassembleCommand
  -> pre-scan BALC targets -> pre-map ret1 stub pages
     (same-page dedupe for block creation, but setBytes ALWAYS at target;
      zero pages trap as SIGRIE otherwise; execute-faults bypass
      unknownAddress so pre-mapping is mandatory)
  -> stack sp=0xa000fff0 / ctx a0=0xb0001000 / ra=0xdead0000
  -> step loop (cap 3000) to first JRC -> read a0.

Proven ground truth (2026-09-05, EmuSml.java + run_emu.cmd):
  stock legal_sim_rule [0x905df2fa,0x905df358): HIT-RET in 25 steps, a0=0x0
  patch (entry 01d2e0db = LI a0,1; JRC ra):     HIT-RET in  1 step,  a0=0x1

Banked pitfalls handled here:
  * execute-faults bypass unknownAddress -> BALC pre-scan pre-maps stubs.
  * unique Ghidra project per run (else LockException on reuse).
  * JDK 21 required (Ghidra 12.x class-file v65); JAVA_HOME forced.
  * stdin < NUL (DEVNULL) so headless never blocks on console input.
  * background launch + poll with timeout; java-process reaper kills the
    tree on hang (taskkill /F /T).

Interoperability (against sim/emu_engine.py interfaces, no import needed):
  * stubs param accepts a plain {va: policy} dict AND a StubRegistry
    instance (uses its .table {va: (policy, arg)}). Policies:
    ret1 | ret0 | behavioral | oracle | trap.
    ret1/ret0 materialize stub bytes; trap writes zeros (SIGRIE);
    behavioral/oracle default to ret1 bytes + an ORACLE-DEFAULT-RET1 log
    line (NO device contact ever — record the need offline via HwOracle).
    Absent/empty stubs => proven auto pre-scan only (all ret1).
  * tracer param accepts a Tracer instance (duck-typed .log method);
    each TRACE event is forwarded as tracer.log(step, pc, text, a0|None).
  * HwOracle transport is deliberately out of scope (see emu_engine.py).
  * Arg encoding: Ghidra headless splits -postScript args on comma, space,
    equals and semicolon, so stubs/regs are encoded with '+' and ':' only
    (stubs "va:policy+...", regs "name:hex+..."), which pass through intact.

API:
  GhidraBackend(...).run(fn_va, size, mode='stock'|'patch',
                         stubs=None, regs=None, tracer=None, ...)
    -> {a0, steps, stop, pc, trace=[(pc:int, text:str)],
        prestubs=[va,...], ret_at, stubs_made, project, log,
        elapsed, attempts, mode, fn_va, size}

Error taxonomy (all subclass GhidraBackendError):
  CarveError, GhidraNotFoundError, JavaNotFoundError, ScriptNotFoundError,
  GhidraTimeoutError (reaped), GhidraLockError (LockException),
  GhidraNoResultError (no RESULT line). Timeout/Lock/NoResult are
  retried (max 2 retries => 3 attempts); carve/config errors are not.

Stdlib only. Local Ghidra/JDK only. Never touches the device.
New code lives under sim/; runtime artifacts (fn bins, logs, ghproj)
live under the Temp workdir, never in the repo.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path

# ---------------------------------------------------------------- constants

REPO = Path(__file__).resolve().parents[1]
SIM = REPO / "sim"
TEMP = Path(os.environ.get("MODEM_LAB_TMP",
                str(Path(__file__).resolve().parent / "Temp")))
TEMP.mkdir(parents=True, exist_ok=True)
ROM_PATH = REPO / "md1work_romonly.bin"

GHIDRA_HOME = REPO / "tools" / "ghidra_12.1.3_PUBLIC"
ANALYZE_HEADLESS = GHIDRA_HOME / "support" / "analyzeHeadless.bat"
DEFAULT_JAVA_HOME = Path(r"C:\Program Files\Eclipse Adoptium\jdk-21.0.11.10-hotspot")

VENDORED_SCRIPT = SIM / "EmuSml.java"          # preferred (this backend's copy)
FALLBACK_SCRIPT = TEMP / "gscripts" / "EmuSml.java"  # proven original location

LANGUAGE = "nanomips:LE:32:default"
VA_BASE = 0x90000000
STEP_CAP = 3000            # enforced inside EmuSml.java step loop
DEFAULT_TIMEOUT = 300.0    # seconds per headless attempt
DEFAULT_RETRIES = 2        # retries after first failure (=> 3 attempts max)

SP_DEFAULT = 0xA000FFF0
A0_DEFAULT = 0xB0001000
RA_DEFAULT = 0xDEAD0000

STUB_POLICIES = ("ret1", "ret0", "behavioral", "oracle", "trap")

# Proven conformance target (legal_sim_rule extent from CATI).
PROVEN_VA = 0x905DF2FA
PROVEN_SIZE = 0x5E  # 94 bytes, [0x905df2fa, 0x905df358)

# ---------------------------------------------------------------- errors


class GhidraBackendError(Exception):
    """Base for all backend failures."""


class CarveError(GhidraBackendError):
    pass


class GhidraNotFoundError(GhidraBackendError):
    pass


class JavaNotFoundError(GhidraBackendError):
    pass


class ScriptNotFoundError(GhidraBackendError):
    pass


class GhidraTimeoutError(GhidraBackendError):
    """Headless run exceeded timeout; java tree was reaped."""

    def __init__(self, msg: str, log: Path | None = None):
        super().__init__(msg)
        self.log = log


class GhidraLockError(GhidraBackendError):
    """Project LockException (stale/duplicate project); retry with fresh name."""

    def __init__(self, msg: str, log: Path | None = None):
        super().__init__(msg)
        self.log = log


class GhidraNoResultError(GhidraBackendError):
    """Headless finished (or was killed) without a RESULT line."""

    def __init__(self, msg: str, log: Path | None = None):
        super().__init__(msg)
        self.log = log


RETRYABLE = (GhidraTimeoutError, GhidraLockError, GhidraNoResultError)

# ---------------------------------------------------------------- parsers

# RESULT steps=25 stop=HIT-RET PC=905df330 a0=0x0 stubs=0 PRESTUB@...
RE_RESULT = re.compile(
    r"RESULT\s+steps=(?P<steps>\d+)\s+stop=(?P<stop>.*?)\s+"
    r"PC=(?P<pc>[0-9a-fA-Fx]+)\s+a0=0x(?P<a0>[0-9a-fA-F]+)\s+stubs=(?P<stubs>\d+)"
)
RE_PRESTUBS = re.compile(r"PRESTUBS=(?P<n>\d+)(?P<rest>.*)")
RE_STUB_AT = re.compile(r"(?:PRESTUB|EXPLICIT)@([0-9a-fA-F]{1,8})(?::([A-Za-z0-9_]+))?")
RE_TRACE = re.compile(r"TRACE\s+step=(?P<step>\d+)\s+pc=(?P<pc>[0-9a-fA-F]+)\s+text=(?P<text>.*)")
RE_RET_AT = re.compile(r"RET-AT\s+([0-9a-fA-Fx]+)")
RE_LOCK = re.compile(r"LockException|ProjectLocked|DuplicateProject|Could not lock", re.I)


def parse_result_line(line: str) -> dict:
    """Parse one RESULT line -> {steps, stop, pc, a0, stubs_made}."""
    m = RE_RESULT.search(line)
    if not m:
        raise ValueError(f"not a RESULT line: {line!r}")
    pc_s = m.group("pc")
    return {
        "steps": int(m.group("steps")),
        "stop": m.group("stop").strip(),
        "pc": int(pc_s, 16) if not pc_s.lower().startswith("0x") else int(pc_s, 16),
        "a0": int(m.group("a0"), 16),
        "stubs_made": int(m.group("stubs")),
    }


def parse_prestubs_line(line: str) -> tuple[int, list[int]]:
    """Parse PRESTUBS line -> (count, [target vas in log order])."""
    m = RE_PRESTUBS.search(line)
    if not m:
        return (0, [])
    vas = [int(x, 16) for x, _ in RE_STUB_AT.findall(m.group("rest"))]
    return (int(m.group("n")), vas)


def parse_trace_line(line: str) -> tuple[int, int, str] | None:
    """Parse one TRACE line -> (step, pc, text) or None."""
    m = RE_TRACE.search(line)
    if not m:
        return None
    text = re.sub(r"\s*\(GhidraScript\)\s*$", "", m.group("text")).strip()
    return (int(m.group("step")), int(m.group("pc"), 16), text)


# ---------------------------------------------------------------- stubs/regs normalization


def normalize_stubs(stubs) -> dict[int, str]:
    """Accept None | {} | {va: policy|(policy,arg)} | StubRegistry -> {va: policy}."""
    if stubs is None:
        return {}
    # StubRegistry duck-type: has .table {va: (policy, arg)}.
    table = getattr(stubs, "table", None)
    if isinstance(table, dict):
        stubs = table
    if not isinstance(stubs, dict):
        raise ValueError(f"stubs must be dict or StubRegistry, got {type(stubs)}")
    out: dict[int, str] = {}
    for va, pol in stubs.items():
        if isinstance(pol, (tuple, list)):
            pol = pol[0]
        if not isinstance(va, int):
            raise ValueError(f"stub VA must be int, got {va!r}")
        if not isinstance(pol, str) or pol not in STUB_POLICIES:
            raise ValueError(f"stub {va:#x}: unknown policy {pol!r} (want {STUB_POLICIES})")
        out[int(va)] = pol
    return out


def normalize_regs(regs) -> dict[str, int]:
    if regs is None:
        return {}
    if not isinstance(regs, dict):
        raise ValueError(f"regs must be dict, got {type(regs)}")
    out: dict[str, int] = {}
    for k, v in regs.items():
        if not isinstance(k, str) or not k:
            raise ValueError(f"reg name must be non-empty str, got {k!r}")
        if not isinstance(v, int) or not (0 <= v <= 0xFFFFFFFF):
            raise ValueError(f"reg {k}: value must be u32 int, got {v!r}")
        out[k] = v
    return out


def format_stubs_arg(stubs: dict[int, str]) -> str:
    # "va:policy+va:policy" (va hex, no 0x) — parsed by EmuSml.java args[2].
    # NOTE: Ghidra headless splits postScript args on comma/space/equals/
    # semicolon, so this backend uses '+' and ':' separators only.
    return "+".join(f"{va:x}:{pol}" for va, pol in sorted(stubs.items()))


def format_regs_arg(regs: dict[str, int]) -> str:
    # "name:hex+..." — parsed by EmuSml.java args[3] (same separator rule).
    return "+".join(f"{k}:{v:x}" for k, v in sorted(regs.items()))


def sanitize_label(s: str) -> str:
    s = re.sub(r"[^0-9A-Za-z_]+", "_", s).strip("_")
    return s or "fn"


# ---------------------------------------------------------------- backend


class GhidraBackend:
    """Reusable Ghidra-headless nanoMIPS emulation backend.

    Proven-pattern wrapper; see module docstring. Typical use:

      be = GhidraBackend()
      r = be.run(0x905DF2FA, 0x5E, mode="stock")
      assert r["a0"] == 0 and r["stop"] == "HIT-RET"

    Pass a sim/emu_engine.py Tracer as tracer= to forward TRACE events
    (duck-typed; only .log(step, pc, text, a0) is used).
    """

    def __init__(
        self,
        ghidra_home: Path | None = None,
        java_home: Path | None = None,
        workdir: Path | None = None,
        script: Path | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        retries: int = DEFAULT_RETRIES,
        rom_path: Path | None = None,
    ) -> None:
        self.ghidra_home = Path(ghidra_home or GHIDRA_HOME)
        self.analyze_headless = self.ghidra_home / "support" / "analyzeHeadless.bat"
        # JDK 21 is mandatory for Ghidra 12.x (class-file v65). Prefer the
        # proven JDK 21 install over a stale JAVA_HOME (e.g. JDK 17).
        if java_home is not None:
            jh = Path(java_home)
        elif (DEFAULT_JAVA_HOME / "bin" / "java.exe").exists():
            jh = DEFAULT_JAVA_HOME
        else:
            jh = Path(os.environ.get("JAVA_HOME") or DEFAULT_JAVA_HOME)
        self.java_home = jh
        self.java_exe = jh / "bin" / "java.exe"
        self.workdir = Path(workdir or TEMP)
        self.projdir = self.workdir / "ghproj"
        self.timeout = float(timeout)
        self.retries = int(retries)
        self.rom_path = Path(rom_path or ROM_PATH)
        if script is not None:
            self.script = Path(script)
        elif VENDORED_SCRIPT.exists():
            self.script = VENDORED_SCRIPT
        else:
            self.script = FALLBACK_SCRIPT
        self._check_paths()

    def _check_paths(self) -> None:
        if not self.analyze_headless.exists():
            raise GhidraNotFoundError(f"analyzeHeadless not found: {self.analyze_headless}")
        if not self.java_exe.exists():
            raise JavaNotFoundError(
                f"JDK 21 java.exe not found: {self.java_exe} "
                f"(set JAVA_HOME; Ghidra 12.x needs JDK 21)"
            )
        if not self.script.exists():
            raise ScriptNotFoundError(f"EmuSml.java not found: {self.script}")
        if not self.rom_path.exists():
            raise CarveError(f"ROM image not found: {self.rom_path}")

    # -- carve ------------------------------------------------------

    def carve(self, fn_va: int, size: int) -> bytes:
        """Carve `size` bytes at modem VA from md1rom (stock bytes; patching
        is done inside Ghidra via the mode= arg, matching the proven flow)."""
        if not isinstance(fn_va, int) or not isinstance(size, int):
            raise CarveError(f"fn_va/size must be ints: {fn_va!r} {size!r}")
        if size <= 0 or size > 0x100000:
            raise CarveError(f"implausible carve size {size}")
        if not (VA_BASE <= fn_va < VA_BASE + 0x4000000):
            raise CarveError(f"VA {fn_va:#x} outside modem window")
        data = self.rom_path.read_bytes()
        off = fn_va - VA_BASE
        if not (0 <= off < len(data)) or off + size > len(data):
            raise CarveError(f"VA {fn_va:#x}+{size:#x} outside image ({len(data)} bytes)")
        return data[off:off + size]

    # -- project uniquifier -----------------------------------------

    @staticmethod
    def unique_project(label: str, mode: str) -> str:
        """Unique Ghidra project per run (avoids LockException on reuse)."""
        ts = time.strftime("%Y%m%d_%H%M%S")
        rand = uuid.uuid4().hex[:8]
        return f"EMU_{sanitize_label(label)}_{mode}_{ts}_{rand}_{os.getpid():x}"

    # -- headless launch + reaper -----------------------------------

    @staticmethod
    def _kill_tree(proc: "subprocess.Popen") -> None:
        """Kill a hung headless run: Popen kill + taskkill whole tree."""
        try:
            proc.kill()
        except Exception:
            pass
        try:
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                capture_output=True,
                timeout=15,
            )
        except Exception:
            pass
        try:
            proc.wait(timeout=15)
        except Exception:
            pass

    def _one_attempt(
        self,
        fn_va: int,
        size: int,
        mode: str,
        stubs_arg: str,
        regs_arg: str,
        label: str,
        project: str,
        timeout: float,
    ) -> tuple[dict, str, float]:
        """Run one headless attempt; return (parsed fields, raw log, elapsed)."""
        self.projdir.mkdir(parents=True, exist_ok=True)
        tag = f"{sanitize_label(label)}_{mode}_{uuid.uuid4().hex[:8]}"
        binpath = self.workdir / f"fn_{tag}.bin"
        logpath = self.workdir / f"emu_{tag}.log"
        binpath.write_bytes(self.carve(fn_va, size))

        basehex = f"{fn_va:x}"
        script_name = self.script.name
        script_dir = str(self.script.parent)
        cmd = [
            "cmd", "/c", str(self.analyze_headless),
            str(self.projdir), project,
            "-import", str(binpath),
            "-processor", LANGUAGE,
            "-postScript", script_name, basehex, mode,
        ]
        # Extra script args are positional: stubs is args[2], regs is args[3].
        # Omit trailing empties so the stock path is byte-identical to proven.
        if stubs_arg and regs_arg:
            cmd += [stubs_arg, regs_arg]
        elif stubs_arg:
            cmd += [stubs_arg]
        elif regs_arg:
            cmd += ["auto", regs_arg]
        cmd += ["-scriptPath", script_dir, "-noanalysis", "-deleteProject"]

        env = dict(os.environ)
        env["JAVA_HOME"] = str(self.java_home)

        t0 = time.perf_counter()
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL,  # == <NUL : never block on console input
            stdout=open(logpath, "w", encoding="utf-8", errors="replace"),
            stderr=subprocess.STDOUT,
            env=env,
            cwd=str(self.workdir),
        )
        try:
            try:
                rc = proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                self._kill_tree(proc)
                raise GhidraTimeoutError(
                    f"headless timeout after {timeout:.0f}s (project {project}); "
                    f"java tree reaped; log: {logpath}", logpath,
                )
        finally:
            try:
                proc.stdout.close()  # type: ignore[union-attr]
            except Exception:
                pass
        elapsed = time.perf_counter() - t0
        raw = logpath.read_text(encoding="utf-8", errors="replace")

        if RE_LOCK.search(raw):
            raise GhidraLockError(
                f"Ghidra project lock failure (project {project}, rc={rc}); "
                f"retry with a fresh unique project; log: {logpath}", logpath,
            )
        m = RE_RESULT.search(raw)
        if not m:
            tail = "\n".join(raw.splitlines()[-15:])
            raise GhidraNoResultError(
                f"no RESULT line (project {project}, rc={rc}); log: {logpath}\n"
                f"--- log tail ---\n{tail}", logpath,
            )
        fields = parse_result_line(m.group(0))
        # PRESTUBS (first occurrence) + TRACE events + RET-AT.
        pm = RE_PRESTUBS.search(raw)
        prestub_count, prestubs = parse_prestubs_line(pm.group(0)) if pm else (0, [])
        trace: list[tuple[int, str]] = []
        for line in raw.splitlines():
            pt = parse_trace_line(line)
            if pt is not None:
                _, pc, text = pt
                trace.append((pc, text))
        rm = RE_RET_AT.search(raw)
        ret_at = int(rm.group(1), 16) if rm else None
        fields.update({
            "prestubs": prestubs,
            "prestub_count": prestub_count,
            "trace": trace,
            "ret_at": ret_at,
            "project": project,
            "log": str(logpath),
            "elapsed": elapsed,
            "rc": rc,
        })
        return fields, raw, elapsed

    # -- public run -------------------------------------------------

    def run(
        self,
        fn_va: int,
        size: int,
        mode: str = "stock",
        stubs=None,
        regs=None,
        tracer=None,
        fn_name: str | None = None,
        timeout: float | None = None,
        retries: int | None = None,
    ) -> dict:
        """Emulate one carved function headlessly.

        Args:
          fn_va: modem VA of function entry (e.g. 0x905DF2FA).
          size: carve length in bytes (e.g. 0x5E).
          mode: 'stock' (carved bytes as-is) | 'patch' (entry forced to
            LI a0,1; JRC ra inside Ghidra, proven force-LEGAL).
          stubs: {va: policy} dict or StubRegistry (policies ret1|ret0|
            behavioral|oracle|trap). None/{} => proven auto pre-scan only.
          regs: {regname: u32} register overrides (defaults sp/a0/ra kept
            unless overridden).
          tracer: optional Tracer-compatible sink (duck-typed .log()).
          fn_name: label for project/bin/log names (default va_<hex>).
          timeout: seconds per attempt (default self.timeout).
          retries: max retries after first failure (default self.retries).

        Returns dict with at least {a0, steps, stop, trace, prestubs}
        plus {pc, ret_at, stubs_made, project, log, elapsed, attempts,
        mode, fn_va, size}. Raises GhidraBackendError subclasses; the
        retryable ones (Timeout/Lock/NoResult) are retried up to `retries`.
        """
        if mode not in ("stock", "patch"):
            raise ValueError(f"mode must be 'stock'|'patch', got {mode!r}")
        stub_map = normalize_stubs(stubs)
        reg_map = normalize_regs(regs)
        stubs_arg = format_stubs_arg(stub_map) if stub_map else ""
        regs_arg = format_regs_arg(reg_map) if reg_map else ""
        label = fn_name or f"va_{fn_va:08x}"
        timeout = self.timeout if timeout is None else float(timeout)
        retries = self.retries if retries is None else int(retries)

        last: GhidraBackendError | None = None
        for attempt in range(retries + 1):
            project = self.unique_project(label, mode)
            try:
                fields, _raw, _el = self._one_attempt(
                    fn_va, size, mode, stubs_arg, regs_arg, label, project, timeout,
                )
            except RETRYABLE as e:
                last = e
                continue
            result = {
                "a0": fields["a0"],
                "steps": fields["steps"],
                "stop": fields["stop"],
                "pc": fields["pc"],
                "trace": fields["trace"],
                "prestubs": fields["prestubs"],
                "ret_at": fields["ret_at"],
                "prestub_count": fields["prestub_count"],
                "stubs_made": fields["stubs_made"],
                "project": fields["project"],
                "log": fields["log"],
                "elapsed": fields["elapsed"],
                "attempts": attempt + 1,
                "mode": mode,
                "fn_va": fn_va,
                "size": size,
            }
            if tracer is not None and hasattr(tracer, "log"):
                for i, (pc, text) in enumerate(result["trace"]):
                    try:
                        tracer.log(i, pc, text,
                                   result["a0"] if i == len(result["trace"]) - 1 else None)
                    except Exception:
                        break
            return result
        assert last is not None
        raise last

    # -- conformance ------------------------------------------------

    def conformance(self, fn_va: int = PROVEN_VA, size: int = PROVEN_SIZE,
                    fn_name: str = "legal_sim_rule") -> dict:
        """Reproduce BOTH proven proofs via this class.

        Returns {stock: {...}, patch: {...}}; raises AssertionError if
        stock a0 != 0 or patch a0 != 1.
        """
        t0 = time.perf_counter()
        stock = self.run(fn_va, size, mode="stock", fn_name=fn_name)
        t1 = time.perf_counter()
        patch = self.run(fn_va, size, mode="patch", fn_name=fn_name)
        t2 = time.perf_counter()
        assert stock["a0"] == 0, f"stock proof broken: a0={stock['a0']:#x} (want 0x0)"
        assert stock["stop"] == "HIT-RET", f"stock stop={stock['stop']!r} (want HIT-RET)"
        assert patch["a0"] == 1, f"patch proof broken: a0={patch['a0']:#x} (want 0x1)"
        assert patch["stop"] == "HIT-RET", f"patch stop={patch['stop']!r} (want HIT-RET)"
        stock["wall"] = t1 - t0
        patch["wall"] = t2 - t1
        return {"stock": stock, "patch": patch, "total_wall": t2 - t0}


# ---------------------------------------------------------------- CLI


def main(argv: list[str]) -> int:
    import argparse

    ap = argparse.ArgumentParser(description="Ghidra headless backend conformance")
    ap.add_argument("--fn-va", default=f"{PROVEN_VA:#x}")
    ap.add_argument("--size", default=f"{PROVEN_SIZE:#x}")
    ap.add_argument("--fn-name", default="legal_sim_rule")
    ap.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    ap.add_argument("--retries", type=int, default=DEFAULT_RETRIES)
    ap.add_argument("--mode", choices=("both", "stock", "patch"), default="both")
    args = ap.parse_args(argv)

    fn_va = int(args.fn_va, 16 if args.fn_va.lower().startswith("0x") else 16)
    size = int(args.size, 16 if str(args.size).lower().startswith("0x") else 16)
    be = GhidraBackend(timeout=args.timeout, retries=args.retries)

    def show(tag: str, r: dict) -> None:
        print(f"[{tag}] a0={r['a0']:#x} steps={r['steps']} stop={r['stop']} "
              f"pc={r['pc']:#x} ret_at={r['ret_at'] and f'{r['ret_at']:#x}'} "
              f"trace={len(r['trace'])} prestubs={len(r['prestubs'])} "
              f"elapsed={r['elapsed']:.1f}s attempts={r['attempts']}")
        print(f"       prestubs: {' '.join(f'{v:#x}' for v in r['prestubs'])}")
        print(f"       log: {r['log']}")

    rc = 0
    t0 = time.perf_counter()
    try:
        if args.mode in ("both", "stock"):
            r = be.run(fn_va, size, mode="stock", fn_name=args.fn_name)
            show("stock", r)
            assert r["a0"] == 0, f"stock a0={r['a0']:#x} != 0x0"
            assert r["stop"] == "HIT-RET", f"stock stop={r['stop']!r}"
        if args.mode in ("both", "patch"):
            r = be.run(fn_va, size, mode="patch", fn_name=args.fn_name)
            show("patch", r)
            assert r["a0"] == 1, f"patch a0={r['a0']:#x} != 0x1"
            assert r["stop"] == "HIT-RET", f"patch stop={r['stop']!r}"
    except (GhidraBackendError, AssertionError) as e:
        print(f"CONFORMANCE FAIL: {type(e).__name__}: {e}")
        rc = 1
    dt = time.perf_counter() - t0
    print(f"conformance: {'PASS' if rc == 0 else 'FAIL'} wall={dt:.1f}s "
          f"(script={be.script} timeout={be.timeout:.0f}s retries={be.retries})")
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
