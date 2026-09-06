#!/usr/bin/env python3
"""decomp.py — batch carve -> headless-disasm -> listing-cache pipeline.

Feeds the emulator (sim/emu_engine.py): carved function bytes become
Ghidra nanoMIPS listings, cached as JSONL, exported as one corpus for the
decode-conformance agent (which grows emu_engine.decode_one against ground
truth in sim/listings/).

HEADLESS RULES (PICKUP.md, proven hang-free — followed exactly):
  * NEVER import the full md1img headless (decompiler-callback spin; kill
    java). Carve fn bytes from md1work_romonly.bin (off = VA-0x90000000).
  * Raw-binary import with `-processor nanomips:LE:32:default`, then the
    postScript rebases via setImageBase(VA,true) (Nmdis2.java, vendored here
    as sim/Nmdis2.java) so absolute BALC targets decode correctly.
  * DisassembleCommand runs on the FN-anchored window only (the whole carve,
    from the function entry). MID-FUNCTION-anchored windows HANG — never do
    sub-ranges; one carve == one function == one JVM run.
  * Each run goes through a per-function .cmd wrapper with <NUL stdin and a
    log file; the batch launcher polls logs/processes in the background
    (bounded-parallel, max 3 JVMs).

LAB RULES: stdlib + local Ghidra only. No device contact of any kind — the
only subprocess this module ever spawns is the LOCAL analyzeHeadless.bat
(no adb/fastboot/socket/serial anywhere). All new files land under sim/
(carves + wrappers + logs default to sim/carves/, listings to sim/listings/).

Pipeline stages:
  1. carve_all(names | all-CATI-sml*) -> sim/carves/fn_<name>.bin (dedupe by VA)
  2. disasm_batch() -> per-function wrapper cmds, bounded-parallel JVMs,
     poll logs, parse Nmdis2 lines -> records {va, size, text, flows}
     (flows = BALC-family absolute targets parsed from the text, as ints)
  3. Listing cache sim/listings/<name>.jsonl, headed by a content hash
     (sha256 of the carved source bytes; incremental: skip unchanged) plus
     a corpus export (<out>/corpus.jsonl, every line, with fn field).

CLI:
  python sim/decomp.py --fns rmmi_esmlck_hdlr,sml_Verify --out sim/listings
  python sim/decomp.py --fns all-CATI-sml* --out sim/listings --max-jvms 3
  python sim/decomp.py --selftest        # no Ghidra: carve + parse saved log
"""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

SIM_DIR = Path(__file__).resolve().parent
REPO_ROOT = SIM_DIR.parent
if str(SIM_DIR) not in sys.path:
    sys.path.insert(0, str(SIM_DIR))

try:
    from emu_engine import Image, load_cati, VA_BASE
    _EMU_OK = True
except Exception as _e:  # noqa: BLE001
    _EMU_OK = False
    _EMU_ERR = _e

try:
    from hw_target import SPEC as HW_SPEC
    _HW_LANG = HW_SPEC.get("language_id", "nanomips:LE:32:default")
except Exception:  # noqa: BLE001
    _HW_LANG = "nanomips:LE:32:default"

# ---------------------------------------------------------------- paths
TEMP = Path(os.environ.get("MODEM_LAB_TMP",
                str(Path(__file__).resolve().parent / "Temp")))
TEMP.mkdir(parents=True, exist_ok=True)
TEMP_GSCRIPTS = TEMP / "gscripts"
VENDORED_NMDIS2 = SIM_DIR / "Nmdis2.java"
GHIDRA_DIR = REPO_ROOT / "tools" / "ghidra_12.1.3_PUBLIC"
ANALYZE_BAT = GHIDRA_DIR / "support" / "analyzeHeadless.bat"
KNOWN_JDK21 = Path(r"C:\Program Files\Eclipse Adoptium\jdk-21.0.11.10-hotspot")
ROMONLY_NAME = "md1work_romonly.bin"

PROCESSOR = "nanomips:LE:32:default"
MAX_JVMS_DEFAULT = 3
TIMEOUT_DEFAULT = 600
POLL_SECS = 5

INSN_RE = re.compile(r"Nmdis2\.java>\s+([0-9a-fA-F]{8})\s+(.*?)\s*\(GhidraScript\)\s*$")
DONE_RE = re.compile(r"Nmdis2\.java>\s*DONE n=(\d+)")
REBASE_RE = re.compile(r"Nmdis2\.java>\s*REBASED to (\S+) size=(\d+)")
EXIT_RE = re.compile(r"WRAPPER-EXIT:(-?\d+)")
ABS_RE = re.compile(r"0[xX][0-9a-fA-F]+")


# ---------------------------------------------------------------- models
@dataclass
class Carve:
    name: str
    va: int
    size: int
    path: Path
    sha256: str
    nbytes: int = 0


@dataclass
class FnStatus:
    name: str
    va: int
    status: str  # ok | skipped-unchanged | failed:<reason>
    records: int = 0
    done_n: int | None = None
    flows: int = 0
    detail: str = ""


@dataclass
class Summary:
    carved: int = 0
    skipped_unchanged: int = 0
    disassembled: int = 0
    failed: int = 0
    records: int = 0
    statuses: list = field(default_factory=list)


# ---------------------------------------------------------------- helpers
def _load_cati() -> dict[str, tuple[int, int]]:
    if not _EMU_OK:
        raise RuntimeError(f"emu_engine import failed: {_EMU_ERR}")
    return load_cati()


def _load_image() -> "Image":
    if not _EMU_OK:
        raise RuntimeError(f"emu_engine import failed: {_EMU_ERR}")
    return Image.load_romonly()


def resolve_names(tokens: list[str], cati: dict[str, tuple[int, int]]) -> list[str]:
    """Resolve CLI --fns tokens to CATI symbol names (order-preserving)."""
    out: list[str] = []

    def _add(nm: str) -> None:
        if nm not in out:
            out.append(nm)

    for tok in tokens:
        t = tok.strip()
        if not t:
            continue
        t = t[len("fn_"):] if t.startswith("fn_") else t
        t = t[:-len(".bin")] if t.lower().endswith(".bin") else t
        low = t.lower()
        if low == "all" or (low.startswith("all-cati-") and low.strip("*") in
                            ("all-cati-sml", "all-cati-", "sml", "")) \
                or low in ("all-cati-sml", "all-cati-sml*"):
            for nm in sorted(cati):
                if "sml" in nm.lower():
                    _add(nm)
            continue
        if low.startswith("all-cati-"):
            sub = t[len("all-cati-"):]
            for nm in sorted(cati):
                if fnmatch.fnmatchcase(nm.lower(), sub.lower()):
                    _add(nm)
            continue
        if "*" in t or "?" in t:
            for nm in sorted(cati):
                if fnmatch.fnmatchcase(nm.lower(), low):
                    _add(nm)
            continue
        if t in cati:
            _add(t)
            continue
        ci = [nm for nm in cati if nm.lower() == low]
        if len(ci) == 1:
            _add(ci[0])
            continue
        end = [nm for nm in cati if nm.lower().endswith(low)]
        if len(end) == 1:
            _add(end[0])
            continue
        sub = [nm for nm in cati if low in nm.lower()]
        if len(sub) == 1:
            _add(sub[0])
            continue
        cands = ci + end + sub
        raise KeyError(f"ambiguous/unknown fn {t!r}" +
                       (f" candidates={cands[:12]}" if cands else
                        " (try --list-sml)"))
    return out


def carve_all(names: list[str], carve_dir: Path,
              image: "Image | None" = None,
              cati: dict[str, tuple[int, int]] | None = None) -> tuple[list[Carve], list[str]]:
    """Carve each named function from md1work_romonly.bin into carve_dir.

    Dedupe by VA: bytes for one VA are carved once even if several names
    (aliases) share it; every name still gets its own fn_<name>.bin.
    """
    cati = cati if cati is not None else _load_cati()
    image = image if image is not None else _load_image()
    carve_dir.mkdir(parents=True, exist_ok=True)
    by_va: dict[int, tuple[bytes, str]] = {}
    carves: list[Carve] = []
    errors: list[str] = []
    for nm in names:
        try:
            start, end = cati[nm]
        except KeyError:
            errors.append(f"{nm}: not in CATI")
            continue
        size = end - start
        if size <= 0 or size > 0x100000:
            errors.append(f"{nm}: bad extent {start:#x}-{end:#x}")
            continue
        if start in by_va:
            blob, sha = by_va[start]
            if len(blob) != size:
                errors.append(f"{nm}: VA alias size clash "
                              f"{size} vs {len(blob)}")
                continue
        else:
            try:
                blob = image.carve(start, size)
            except Exception as e:  # noqa: BLE001
                errors.append(f"{nm}: carve failed: {e}")
                continue
            if len(blob) != size:
                errors.append(f"{nm}: short carve {len(blob)}/{size}")
                continue
            sha = hashlib.sha256(blob).hexdigest()
            by_va[start] = (blob, sha)
        path = carve_dir / f"fn_{nm}.bin"
        path.write_bytes(blob)
        carves.append(Carve(nm, start, size, path, sha, len(blob)))
    return carves, errors


# ---------------------------------------------------------------- parsing
def parse_nmdis_log(log_path: Path, base: int | None = None,
                    span: int | None = None) -> tuple[list[dict], dict]:
    """Parse Nmdis2 output lines into records {va, size, text, flows}.

    flows = BALC-family (BALC, MOVE.BALC) absolute targets parsed from the
    instruction text, as int VAs. Instruction size = next_va - va (nanoMIPS
    insns are 2/4 B, plus 6 B 48-bit long-immediate forms such as ADDIUPC/LI
    pairs); the last insn uses the carve span when known, else 2.
    """
    raw = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
    addrs: list[int] = []
    texts: list[str] = []
    info: dict = {"done_n": None, "rebased": None, "rebased_size": None,
                  "wrapper_exit": None}
    for line in raw:
        m = DONE_RE.search(line)
        if m:
            info["done_n"] = int(m.group(1))
            continue
        m = REBASE_RE.search(line)
        if m:
            info["rebased"] = m.group(1)
            info["rebased_size"] = int(m.group(2))
            continue
        m = EXIT_RE.search(line)
        if m:
            info["wrapper_exit"] = int(m.group(1))
            continue
        m = INSN_RE.search(line)
        if not m:
            continue
        addrs.append(int(m.group(1), 16))
        texts.append(m.group(2).strip())
    records: list[dict] = []
    for i, (va, text) in enumerate(zip(addrs, texts)):
        if i + 1 < len(addrs):
            size = addrs[i + 1] - va
        elif base is not None and span is not None and base + span > va:
            size = base + span - va
        else:
            size = 2
        flows: list[int] = []
        if "BALC" in text.upper():
            flows = [int(x, 16) for x in ABS_RE.findall(text)]
        records.append({"va": va, "size": size, "text": text, "flows": flows})
    info["anomalous_sizes"] = sum(1 for r in records if r["size"] not in (2, 4, 6))
    return records, info


# ---------------------------------------------------------------- cache
def listing_path(out_dir: Path, name: str) -> Path:
    return out_dir / f"{name}.jsonl"


def read_header(path: Path) -> dict | None:
    try:
        with path.open(encoding="utf-8") as f:
            first = f.readline()
        head = json.loads(first)
        return head if isinstance(head, dict) and head.get("kind") == "header" else None
    except Exception:  # noqa: BLE001
        return None


def needs_refresh(carve: Carve, out_dir: Path) -> bool:
    head = read_header(listing_path(out_dir, carve.name))
    return not (head and head.get("sha256") == carve.sha256
                and head.get("va") == carve.va and head.get("size") == carve.size)


def write_listing(out_dir: Path, carve: Carve, records: list[dict]) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = listing_path(out_dir, carve.name)
    with path.open("w", encoding="utf-8") as f:
        f.write(json.dumps({"kind": "header", "name": carve.name,
                            "va": carve.va, "size": carve.size,
                            "sha256": carve.sha256, "source": ROMONLY_NAME,
                            "language": _HW_LANG, "n": len(records)}) + "\n")
        for r in records:
            f.write(json.dumps({"va": r["va"], "size": r["size"],
                                "text": r["text"], "flows": r["flows"]}) + "\n")
    return path


def read_listing_records(out_dir: Path, name: str) -> list[dict]:
    recs: list[dict] = []
    try:
        with listing_path(out_dir, name).open(encoding="utf-8") as f:
            for line in f:
                try:
                    obj = json.loads(line)
                except ValueError:
                    continue
                if isinstance(obj, dict) and obj.get("kind") != "header" and "text" in obj:
                    recs.append(obj)
    except OSError:
        pass
    return recs


def export_corpus(out_dir: Path, names: list[str], corpus_path: Path) -> int:
    """Export every cached line for names (with fn field) for the decode-conformance agent."""
    n = 0
    with corpus_path.open("w", encoding="utf-8") as f:
        for nm in names:
            for r in read_listing_records(out_dir, nm):
                f.write(json.dumps({"fn": nm, "va": r["va"], "size": r["size"],
                                    "text": r["text"], "flows": r["flows"]}) + "\n")
                n += 1
    return n


# ---------------------------------------------------------------- headless
def resolve_java_home() -> Path | None:
    for cand in (os.environ.get("DECOMP_JAVA_HOME"), str(KNOWN_JDK21),
                 os.environ.get("JAVA_HOME")):
        if cand and (Path(cand) / "bin" / "java.exe").exists():
            return Path(cand)
    return None


def resolve_nmdis2() -> Path | None:
    if VENDORED_NMDIS2.exists():
        return VENDORED_NMDIS2
    if (TEMP_GSCRIPTS / "Nmdis2.java").exists():
        return TEMP_GSCRIPTS / "Nmdis2.java"
    return None


def preflight() -> tuple[bool, str, dict]:
    """Check local Ghidra/JDK/script prerequisites (no device, all local)."""
    ctx: dict = {}
    if not ANALYZE_BAT.exists():
        return False, f"missing {ANALYZE_BAT}", ctx
    jh = resolve_java_home()
    if jh is None:
        return False, "no JDK found (DECOMP_JAVA_HOME/JAVA_HOME)", ctx
    ctx["java_home"] = jh
    script = resolve_nmdis2()
    if script is None:
        return False, "Nmdis2.java not found (sim/ nor Temp gscripts)", ctx
    ctx["script_dir"] = script.parent
    return True, "ok", ctx


def build_wrapper(name: str, va: int, bin_path: Path, log_path: Path,
                  proj_dir: Path, script_dir: Path, java_home: Path) -> str:
    base_hex = f"{va:08x}"  # bare hex, no 0x — run_fn.cmd convention
    return (
        "@echo off\r\n"
        f"set JAVA_HOME={java_home}\r\n"
        f'call "{ANALYZE_BAT}" "{proj_dir}" FN_{name} '
        f'-import "{bin_path}" -processor {PROCESSOR} '
        f"-postScript Nmdis2.java {base_hex} "
        f'-scriptPath "{script_dir}" -noanalysis -deleteProject '
        f'< NUL > "{log_path}" 2>&1\r\n'
        f'echo WRAPPER-EXIT:%ERRORLEVEL% >> "{log_path}"\r\n'
    )


def disasm_batch(carves: list[Carve], out_dir: Path,
                 max_jvms: int = MAX_JVMS_DEFAULT,
                 timeout: int = TIMEOUT_DEFAULT,
                 write_corpus: bool = True) -> Summary:
    """Disassemble carved functions via bounded-parallel headless Ghidra."""
    summary = Summary()
    out_dir.mkdir(parents=True, exist_ok=True)
    carve_dir = carves[0].path.parent if carves else (SIM_DIR / "carves")
    proj_dir = carve_dir / "ghproj"
    proj_dir.mkdir(parents=True, exist_ok=True)

    todo: list[Carve] = []
    for cv in carves:
        if not needs_refresh(cv, out_dir):
            summary.skipped_unchanged += 1
            recs = read_listing_records(out_dir, cv.name)
            summary.records += len(recs)
            summary.statuses.append(FnStatus(cv.name, cv.va, "skipped-unchanged",
                                             len(recs), len(recs),
                                             sum(len(r["flows"]) for r in recs),
                                             "cache sha match"))
        else:
            todo.append(cv)
    summary.carved = len(carves)
    if not todo:
        if write_corpus:
            export_corpus(out_dir, [c.name for c in carves], out_dir / "corpus.jsonl")
        return summary

    ok, msg, ctx = preflight()
    if not ok:
        for cv in todo:
            summary.failed += 1
            summary.statuses.append(FnStatus(cv.name, cv.va, f"failed:{msg}"))
        return summary

    jobs: list[dict] = []
    for cv in todo:
        log = carve_dir / f"fn_{cv.name}.log"
        wrap = carve_dir / f"run_{cv.name}.cmd"
        wrap.write_text(build_wrapper(cv.name, cv.va, cv.path, log, proj_dir,
                                      ctx["script_dir"], ctx["java_home"]),
                        encoding="utf-8")
        jobs.append({"carve": cv, "wrap": wrap, "log": log, "proc": None,
                     "started": 0.0})

    # Bounded-parallel launch: at most max_jvms live JVMs; poll, never a
    # single long foreground sleep.
    pending = list(jobs)
    active: list[dict] = []
    while pending or active:
        while pending and len(active) < max(1, max_jvms):
            job = pending.pop(0)
            try:
                job["log"].write_text("", encoding="utf-8")
                job["proc"] = subprocess.Popen(
                    ["cmd", "/c", str(job["wrap"])],
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, cwd=str(REPO_ROOT))
                job["started"] = time.time()
                active.append(job)
            except Exception as e:  # noqa: BLE001
                summary.failed += 1
                summary.statuses.append(FnStatus(job["carve"].name, job["carve"].va,
                                                 f"failed:spawn {e}"))
        time.sleep(POLL_SECS)
        for job in list(active):
            p = job["proc"]
            if p is None:
                active.remove(job)
                continue
            if p.poll() is None and time.time() - job["started"] > timeout:
                try:
                    p.kill()
                except Exception:  # noqa: BLE001
                    pass
                job["timed_out"] = True
            if p.poll() is not None:
                active.remove(job)

    for job in jobs:
        cv = job["carve"]
        if job.get("proc") is None and not job["log"].exists():
            continue  # spawn failure already counted
        timed_out = job.get("timed_out", False)
        try:
            records, info = parse_nmdis_log(job["log"], cv.va, cv.size)
        except Exception as e:  # noqa: BLE001
            summary.failed += 1
            summary.statuses.append(FnStatus(cv.name, cv.va, f"failed:parse {e}"))
            continue
        if timed_out:
            summary.failed += 1
            summary.statuses.append(FnStatus(cv.name, cv.va, "failed:timeout",
                                             len(records), info["done_n"],
                                             sum(len(r["flows"]) for r in records)))
            continue
        if info["wrapper_exit"] not in (0, None) or not records:
            summary.failed += 1
            summary.statuses.append(FnStatus(
                cv.name, cv.va,
                f"failed:exit={info['wrapper_exit']} n={len(records)}",
                len(records), info["done_n"],
                sum(len(r["flows"]) for r in records)))
            continue
        write_listing(out_dir, cv, records)
        summary.disassembled += 1
        summary.records += len(records)
        detail = "ok"
        if info["done_n"] is not None and info["done_n"] != len(records):
            detail = f"WARN done_n={info['done_n']} != parsed={len(records)}"
        summary.statuses.append(FnStatus(cv.name, cv.va, "ok", len(records),
                                         info["done_n"],
                                         sum(len(r["flows"]) for r in records),
                                         detail))
    if write_corpus:
        export_corpus(out_dir, [c.name for c in carves], out_dir / "corpus.jsonl")
    return summary


# ---------------------------------------------------------------- selftest
SYNTH_LOG = """INFO  Nmdis2.java> REBASED to 905f0f04 size=8 (GhidraScript)
INFO  Nmdis2.java> 905f0f04  BALC 0x905df77a (GhidraScript)
INFO  Nmdis2.java> 905f0f08  MOVE.BALC a1,s3,0x91983444 (GhidraScript)
INFO  Nmdis2.java> 905f0f0c  BC 0x905f0f76 (GhidraScript)
INFO  Nmdis2.java> DONE n=3 (GhidraScript)
WRAPPER-EXIT:0
"""


def _find_saved_log(name: str) -> Path | None:
    for cand in (TEMP / f"fn_{name}.log", SIM_DIR / "carves" / f"fn_{name}.log"):
        if cand.exists():
            return cand
    logs = sorted(TEMP.glob("fn_*.log"))
    return logs[0] if logs else None


def selftest() -> int:
    """Offline selftest — NO Ghidra, NO JVM, NO device: carve + parse a saved log."""
    fails: list[str] = []
    notes: list[str] = []
    try:
        cati = _load_cati()
        img = _load_image()
        notes.append(f"cati={len(cati)} rom={len(img.data)}B")
    except Exception as e:  # noqa: BLE001
        print(f"decomp selftest: FAIL (image/cati: {e})")
        return 1

    name = "sml_Verify" if "sml_Verify" in cati else next(
        (k for k in cati if "sml" in k.lower()), None)
    if name is None:
        print("decomp selftest: FAIL (no sml symbol in CATI)")
        return 1
    va, end = cati[name]
    size = end - va
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        carves, errs = carve_all([name], tmp / "carves", image=img, cati=cati)
        if errs or not carves:
            fails.append(f"carve: {errs}")
        else:
            cv = carves[0]
            if cv.nbytes != size:
                fails.append(f"carve size {cv.nbytes} != extent {size}")
            notes.append(f"carve {name} va={va:#x} size={size} "
                         f"sha={cv.sha256[:12]}.. bin={cv.path.name}")

        log = _find_saved_log(name)
        synthetic = False
        if log is None:
            log = tmp / "synth.log"
            log.write_text(SYNTH_LOG, encoding="utf-8")
            synthetic = True
        notes.append(f"log={'SYNTHETIC' if synthetic else log}")
        try:
            if synthetic:
                records, info = parse_nmdis_log(log, 0x905F0F04, 8)
                if len(records) != 3 or info["done_n"] != 3:
                    fails.append("synthetic parse mismatch")
                if [r["flows"] for r in records] != [[0x905DF77A], [0x91983444], []]:
                    fails.append(f"synthetic flows wrong: {[r['flows'] for r in records]}")
                notes.append("synthetic parse: 3/3 recs, BALC-only flows ok "
                             "(BC correctly yields no flows)")
            else:
                lname = log.stem[len("fn_"):] if log.stem.startswith("fn_") else log.stem
                if lname in cati:
                    lva, lend = cati[lname]
                    records, info = parse_nmdis_log(log, lva, lend - lva)
                else:
                    records, info = parse_nmdis_log(log)
                    lva = records[0]["va"] if records else 0
                if not records:
                    fails.append(f"parse: zero records from {log.name}")
                else:
                    acc = (len(records) / info["done_n"]
                           if info["done_n"] else None)
                    nflows = sum(len(r["flows"]) for r in records)
                    span_sum = sum(r["size"] for r in records)
                    notes.append(f"parse {log.name}: {len(records)} recs "
                                 f"done_n={info['done_n']} "
                                 f"accuracy={(f'{acc:.1%}' if acc is not None else 'n/a')} "
                                 f"flows={nflows} span_sum={span_sum}")
                    if info["done_n"] is not None and len(records) != info["done_n"]:
                        fails.append(f"parse accuracy: {len(records)} != DONE {info['done_n']}")
                    if lname in cati and records[0]["va"] != cati[lname][0]:
                        fails.append("first VA != CATI start")
                    if lname in cati and span_sum != cati[lname][1] - cati[lname][0]:
                        fails.append(f"span {span_sum} != carve {cati[lname][1] - cati[lname][0]}")
                    if nflows < 1:
                        fails.append("no BALC flows parsed")
                    # cache roundtrip + incremental skip in temp out dir
                    if carves and lname == name:
                        outd = tmp / "listings"
                        write_listing(outd, carves[0], records)
                        head = read_header(listing_path(outd, name))
                        if not head or head.get("sha256") != carves[0].sha256:
                            fails.append("listing header hash mismatch")
                        elif needs_refresh(carves[0], outd):
                            fails.append("incremental skip failed (should skip)")
                        else:
                            notes.append("cache: header hash ok, skip-unchanged ok")
                        ncorp = export_corpus(outd, [name], outd / "corpus.jsonl")
                        if ncorp != len(records):
                            fails.append(f"corpus {ncorp} != {len(records)}")
                        else:
                            notes.append(f"corpus: {ncorp} lines")
        except Exception as e:  # noqa: BLE001
            fails.append(f"parse: {e}")

    print("decomp selftest:", "PASS" if not fails else "FAIL")
    for s in notes:
        print("  .", s)
    for s in fails:
        print("  -", s)
    return 1 if fails else 0


# ---------------------------------------------------------------- cli
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="batch carve->disasm->listing pipeline (local Ghidra only)")
    ap.add_argument("--fns", default="",
                    help="comma list of CATI fn names, 'all' / 'all-CATI-sml*' / wildcards")
    ap.add_argument("--out", default=str(SIM_DIR / "listings"))
    ap.add_argument("--carve-dir", default=str(SIM_DIR / "carves"))
    ap.add_argument("--max-jvms", type=int, default=MAX_JVMS_DEFAULT)
    ap.add_argument("--timeout", type=int, default=TIMEOUT_DEFAULT)
    ap.add_argument("--carve-only", action="store_true")
    ap.add_argument("--no-corpus", action="store_true")
    ap.add_argument("--list-sml", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)

    if args.selftest:
        return selftest()

    cati = _load_cati()
    if args.list_sml:
        for nm in sorted(k for k in cati if "sml" in k.lower()):
            a, b = cati[nm]
            print(f"{nm:52s} {a:#x}-{b:#x} ({b - a}B)")
        print(f"{sum(1 for k in cati if 'sml' in k.lower())} sml symbols / {len(cati)} total")
        return 0

    if not args.fns.strip():
        ap.error("--fns required (e.g. --fns rmmi_esmlck_hdlr,sml_Verify)")
    try:
        names = resolve_names(args.fns.split(","), cati)
    except KeyError as e:
        print(f"decomp: {e}")
        return 2
    if not names:
        print("decomp: no functions resolved")
        return 2

    out_dir = Path(args.out)
    carve_dir = Path(args.carve_dir)
    carves, errs = carve_all(names, carve_dir)
    for e in errs:
        print(f"  carve-ERR: {e}")
    print(f"carved {len(carves)}/{len(names)} -> {carve_dir}")
    for cv in carves:
        print(f"  {cv.name:48s} va={cv.va:#x} size={cv.size} sha={cv.sha256[:12]}..")

    if args.carve_only or not carves:
        corpus_n = None
        if not args.no_corpus and not args.carve_only:
            corpus_n = export_corpus(out_dir, [c.name for c in carves],
                                     out_dir / "corpus.jsonl")
        print(f"pipeline status: CARVE-ONLY carved={len(carves)} errors={len(errs)}"
              + (f" corpus={corpus_n}" if corpus_n is not None else ""))
        return 1 if errs else 0

    summary = disasm_batch(carves, out_dir, args.max_jvms, args.timeout,
                           write_corpus=not args.no_corpus)
    print("pipeline status:")
    for st in summary.statuses:
        print(f"  [{st.status}] {st.name:48s} recs={st.records} "
              f"done_n={st.done_n} flows={st.flows} {st.detail}")
    cached = sum(1 for c in carves if listing_path(out_dir, c.name).exists())
    corpus_p = out_dir / "corpus.jsonl"
    corpus_n = sum(1 for _ in corpus_p.open(encoding="utf-8")) if corpus_p.exists() else 0
    exact = sum(1 for st in summary.statuses
                if st.done_n is not None and st.done_n == st.records)
    compared = sum(1 for st in summary.statuses if st.done_n is not None)
    print(f"cache counts: listings={cached}/{len(carves)} corpus_lines={corpus_n}")
    print(f"parse accuracy: {exact}/{compared} fns exact DONE-match, "
          f"{summary.records} total records")
    print(f"summary: carved={summary.carved} skipped-unchanged={summary.skipped_unchanged} "
          f"disassembled={summary.disassembled} failed={summary.failed}")
    return 1 if (summary.failed or errs) else 0


if __name__ == "__main__":
    sys.exit(main())
