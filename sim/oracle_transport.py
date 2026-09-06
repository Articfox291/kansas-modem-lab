#!/usr/bin/env python3
"""oracle_transport.py — READ-ONLY device oracle transport (HwOracle bridge).

THIS is the one sim/ module allowed to contact the device, and ONLY for
READ-ONLY queries. Everything else in sim/ is pure PC. Rules enforced here:

  ALLOWED (read-only only):
    * AT query/test forms via the tools/atci.py pattern (adb forward +
      socket to adb_atci_socket; one command per line; 1.5 s pacing).
      Allowed AT: test form `AT+CMD=?`, read form `AT+CMD?`, and the explicit
      read-only status form `AT+CLCK="<fac>",2` (syntactically `=` but costs
      no attempt; live-attested ERROR without SIM context). NOTHING else.
    * getprop / dumpsys READS via adb shell (host-side filtering only).
    * Root file READS of already-backed-up NVRAM names via PC-local
      modem_bak copies (no on-device re-pull, hence NO new root session and
      NO new root writes by construction).

  HARD BAN (enforced in code by the denylist below + dry-run default ON):
    * Any attempt-costing AT: ESMLCK set/unlock/commit forms (AT+ESMLCK=m,..),
      CLCK unlock (mode 0), RSU/ERSUKEY set forms, MOTSMLDB/MOTSMLEVENT writes,
      any NCK trial, any AT set form other than CLCK,2.
    * Any device-state change: setprop, settings put, flash/erase/fastboot,
      reboot, dd (any form; use cat), mount/remount/push, shell redirection
      (>/>>), tee/chmod/chown/chcon, rm/mv/mkdir/touch, input/svc/am/pm state
      verbs, command chaining (;/&&/||/``/$()).
    * Any write anywhere: the transport never opens a local file for writing
      except the HwOracle transcript JSONL under sim/oracle_logs/.

  Dry-run: DRY_RUN_DEFAULT = True. With dry_run=True (the default) NO socket
  is opened and NO subprocess is spawned; canned live-observed values are
  returned and recorded as result="DRYRUN". Pass dry_run=False explicitly to
  perform the live read-only probe (still denylist-guarded).

Ops (HwOracle.OPS lockstep; sim/emu_engine.py):
  sml_status .. AT+ESMLCK=? + AT+ESMLCK? + getprop lock bundle + remain.count
                before/after pair (zero-state-change proof).
  efuse_read .. `adb shell getprop` piped host-side, filtered to fuse/otp/tfn
                + sim_me_lock_mode lines ONLY (mot TFN props only; no dump of
                unrelated props into the transcript).
  nv_read .... PC-local read of an already-backed-up /md/* file
                (modem_bak/modem_bak/<name>): returns sha256/size/geometry,
                never ciphertext plaintext (HW-bound opaque). Params
                {"lid_name": <name>, "rec_idx": <int>}. NO device contact.
  chl_hash / chl_mac / apdu_xfer: NOT implemented here; a transcript entry
                with result="UNIMPLEMENTED" is appended and
                OracleUnimplemented is raised (same contract as HwOracle).

Every response is appended to the HwOracle transcript (OracleRecord) and can
be saved with save(name) -> sim/oracle_logs/<name>.jsonl.

Shape-observed canned values (example session, identifiers redacted; read-only):
  AT+ESMLCK=? -> "+ESMLCK:(0-4), (0-4), <key>, <data_imsi>, <data_gid1>, <data_gid2>" + OK
  AT+ESMLCK?  -> single line "+ESMLCK: (0,2,5,0,0,35,0),(1,2,5,0,0,20,0),
                 (2,1,5,0,8,60,0),(3,1,5,0,8,20,0),(4,2,5,0,0,10,0),
                 (5,2,5,0,0,5,0),(6,2,5,0,0,5,0),\"000000000000000\",0,0,0,0,0" + OK
  remain.count [vendor.gsm.sim.slot.lock.device.lock.remain.count] = [5]
  lock bundle: state 0, policy 983040, card.valid 2/2, service.capability 4/4,
               sim_me_lock_mode 3, EID <redacted>.

Stdlib + repo only (tools/atci.py pattern re-implemented; emu_engine types).
"""

from __future__ import annotations

import json
import re
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

SIM_DIR = Path(__file__).resolve().parent
REPO_ROOT = SIM_DIR.parent
TOOLS_DIR = REPO_ROOT / "tools"
ADB_CANDIDATES = (TOOLS_DIR / "platform-tools" / "adb.exe",
                  TOOLS_DIR / "platform-tools" / "adb")
MODEM_BAK = REPO_ROOT / "modem_bak" / "modem_bak"

try:  # package-relative
    from sim.emu_engine import HwOracle, OracleRecord, OracleUnimplemented  # type: ignore
except ImportError:
    try:  # sibling on sys.path
        from emu_engine import HwOracle, OracleRecord, OracleUnimplemented  # type: ignore
    except ImportError:  # minimal fallback (same schema, for dry-run use)
        HwOracle = None  # type: ignore

        @dataclass
        class OracleRecord:  # type: ignore
            op: str
            params: dict
            result: str = "UNIMPLEMENTED"

        class OracleUnimplemented(Exception):  # type: ignore
            pass

        class HwOracle:  # type: ignore
            OPS = ("nv_read", "chl_hash", "chl_mac", "efuse_read",
                   "sml_status", "apdu_xfer")

            def __init__(self, logdir=None):
                self.logdir = Path(logdir or (SIM_DIR / "oracle_logs"))
                self.transcript = []

            def save(self, name):
                self.logdir.mkdir(parents=True, exist_ok=True)
                p = self.logdir / ("%s.jsonl" % name)
                with p.open("w") as f:
                    for r in self.transcript:
                        f.write(json.dumps({"op": r.op, "params": r.params,
                                            "result": r.result}) + "\n")
                return p


# ------------------------------------------------------------------ switches

DRY_RUN_DEFAULT = True   # HARD REQUIREMENT: dry-run flag defaults ON.
ATCI_HOST = "127.0.0.1"
ATCI_PORT = 7121
AT_PACING_S = 1.5
SHELL_TIMEOUT_S = 20

# ------------------------------------------------------------------ denylist
# HARD BAN lists. Shell/AT inputs are checked against BANNED first (raise),
# then must match the ALLOWLIST (default-deny: anything not explicitly
# read-only raises too).


class BannedOperation(RuntimeError):
    """Raised when an input would change device state or cost an attempt."""


# Any AT set/unlock/commit/write form. The generic '=' rule below is the real
# wall (default-deny all `=` except `=?` and CLCK,2); these named patterns give
# precise errors for the 5 attempt-costing families from sim/rmmi_sim.py.
BANNED_AT = (
    (re.compile(r"AT\+ESMLCK\s*=\s*(?!\?\s*$)", re.I),
     "F1 ESMLCK_SET: AT+ESMLCK set/unlock/commit form (would enter the "
     "rmmi_esmlck_hdlr key/data path and burn a capped attempt)."),
    (re.compile(r"AT\+CLCK\s*=.*,\s*0", re.I),
     "F2 CLCK_UNLOCK: facility-unlock mode 0 (attempt-costing)."),
    (re.compile(r"AT\+ERSUKEY\s*=", re.I),
     "F3 ERSUKEY_SET: RSU key provision (attempt/state-changing)."),
    (re.compile(r"AT\+ESMLRSU\s*=\s*(?!\?\s*$)", re.I),
     "F4 ESMLRSU_SET: RSU submode key/data form (attempt-costing)."),
    (re.compile(r"AT\+MOTSMLDB\s*=", re.I),
     "F5 MOTSMLDB_WRITE: mot_sml_db_handler backend write."),
    (re.compile(r"AT\+MOTSMLEVENT\s*=", re.I),
     "F5 MOTSMLEVENT_WRITE: mot_sml_db_handler backend write."),
    (re.compile(r"AT\+EUULK\s*=", re.I),
     "BANNED AT+EUULK set form (unlock path)."),
    (re.compile(r"NCK|LPIN| ^.*AT\+E(SMLCK|CBML|SSML)", re.I),
     "BANNED NCK/key-material token in AT input."),
)
# Generic AT wall: any '=' that is not `=?` and not the CLCK,2 status form.
_ALLOW_AT_TEST = re.compile(r"^AT\+\w[\w\-]*=\?\s*$", re.I)
_ALLOW_AT_READ = re.compile(r"^AT\+\w[\w\-]*\?\s*$", re.I)
_ALLOW_AT_CLCK2 = re.compile(r"^AT\+CLCK\s*=\s*[\"']?(PN|PU|PP|PC|PF|PS|SC)[\"']?\s*,\s*2\s*$", re.I)
_ALLOW_AT_BASIC = re.compile(r"^ATI\s*$", re.I)  # device-identification only

BANNED_SHELL = (
    (re.compile(r"\bsetprop\b", re.I), "setprop changes device state."),
    (re.compile(r"\bsettings\s+(put|delete)\b", re.I), "settings put/delete writes."),
    (re.compile(r"\b(svc|cmd\s+phone|am\s|pm\s+(install|uninstall|clear|grant|revoke|disable|enable))\b", re.I),
     "service/package/activity-manager state verb."),
    (re.compile(r"\breboot\b|\bshutdown\b|\bset-verity\b|\bdisable-verity\b", re.I),
     "reboot/verity state change."),
    (re.compile(r"\bdd\b", re.I), "dd blocked (use cat for reads; dd risks of= writes)."),
    (re.compile(r"\b(flash|erase|fastboot|heimdall|odin)\b", re.I), "flash/erase path."),
    (re.compile(r"\b(mount|remount|push)\b", re.I), "mount/remount/push write path."),
    (re.compile(r"(>>?|tee\b|chmod|chown|chcon|restorecon|\bmkdir\b|\btouch\b|\brm\b|\bmv\b|\bcp\b)", re.I),
     "filesystem write primitive."),
    (re.compile(r"(;|&&|\|\||`|[$][(])"), "command chaining/substitution (smuggling risk)."),
    (re.compile(r"\binput\b|\bkeyevent\b", re.I), "input injection changes state."),
)

# Default-deny shell allowlist: exactly one simple read command, no metachars.
_ALLOW_SHELL = (
    re.compile(r"^getprop(\s+[\w.\-]+)?\s*$"),
    re.compile(r"^dumpsys\s+[\w.\-]+\s*([\w.\-]+\s*)*$"),
    re.compile(r"^cat\s+[\w\-./]+\s*$"),
    re.compile(r"^ls\s+(-l\s+)?[\w\-./]*\s*$"),
    re.compile(r"^sha256sum\s+[\w\-./]+\s*$"),
    re.compile(r"^getenforce\s*$"),
)
# On-device read paths permitted for cat/ls (informational; nv_read itself is
# PC-local and never executes these -- they bound any future live extension).
ALLOW_READ_PATHS = (
    "/mnt/vendor/nvdata/md/", "/mnt/vendor/protect_f/", "/mnt/vendor/protect_s/",
    "/persist/", "/vendor/build.prop", "/system/build.prop",
)

# efuse_read filter: ONLY fuse/otp/tfn-named props + the SIM-lock mode marker.
EFUSE_FILTER = re.compile(r"fuse|otp|\btfn\b|sim_me_lock", re.I)
# sml_status lock-props filter (read-only lock snapshot).
LOCK_FILTER = re.compile(r"slot\.lock|sim_me_lock|esimid", re.I)

# nv_read allowlist: already-backed-up /md/* names present in modem_bak/.
# (No on-device re-pull: PC-local copies only, hence zero new root writes.)
ALLOW_NV_NAMES = frozenset({
    "SL00_000", "SL01_000", "LD36_003", "LD38_010",
    "NVD_DATA", "NVD_IMEI", "DEV_INFO",
})

# ---------------------------------------------------------------- canned
# Shape-observed (example session, identifiers redacted). Provenance-tagged rehearsal
# values for dry_run=True (no socket/subprocess opened).

CANNED_ESMLCK_TEST = ("+ESMLCK:(0-4), (0-4), <key>, <data_imsi>, "
                      "<data_gid1>, <data_gid2>")
CANNED_ESMLCK_READ = ('+ESMLCK: (0,2,5,0,0,35,0),(1,2,5,0,0,20,0),'
                      '(2,1,5,0,8,60,0),(3,1,5,0,8,20,0),(4,2,5,0,0,10,0),'
                      '(5,2,5,0,0,5,0),(6,2,5,0,0,5,0),'
                      '"000000000000000",0,0,0,0,0')
CANNED_LOCK_PROPS = {
    "vendor.gsm.sim.slot.lock.card.valid": "2",
    "vendor.gsm.sim.slot.lock.card.valid.2": "2",
    "vendor.gsm.sim.slot.lock.device.lock.remain.count": "5",
    "vendor.gsm.sim.slot.lock.policy": "983040",
    "vendor.gsm.sim.slot.lock.service.capability": "4",
    "vendor.gsm.sim.slot.lock.service.capability.2": "4",
    "vendor.gsm.sim.slot.lock.state": "0",
    "ro.vendor.sim_me_lock_mode": "3",
    "ro.vendor.esimid": "89000000000000000000000000000000",
}
CANNED_EFUSE_PROPS = {
    "persist.sys.fflag.override.settings_fuse": "true",
    "persist.sys.fuse": "true",
    "ro.fuse.bpf.enabled": "false",
    "ro.fuse.bpf.is_running": "false",
    "ro.vendor.sim_me_lock_mode": "3",
    "sys.fuse.transcode_enabled": "true",
    "note": ("No ro.vendor.*fuse*/otp/TFN eFuse props are exposed on this "
             "build; TFN-OTP path dormant (matches hardcoded TFN stubs)."),
}


# ---------------------------------------------------------------- guards


def is_readonly_at(cmd: str) -> str:
    """Validate one AT line. Returns 'test'|'read'|'clck2'|'basic'.

    Raises BannedOperation for anything attempt-costing or state-changing.
    Default-deny: a line with '=' that is not `=?` / CLCK,2 is refused.
    """
    s = cmd.strip()
    if not s.upper().startswith("AT"):
        raise BannedOperation("not an AT line: %r" % cmd)
    for rx, msg in BANNED_AT:
        if rx.search(s):
            raise BannedOperation("%s :: %r" % (msg, cmd))
    if _ALLOW_AT_TEST.match(s):
        return "test"
    if _ALLOW_AT_READ.match(s):
        return "read"
    if _ALLOW_AT_CLCK2.match(s):
        return "clck2"
    if _ALLOW_AT_BASIC.match(s):
        return "basic"
    if "=" in s:
        raise BannedOperation(
            "default-deny: AT set form is not read-only (only =? / ? / "
            "CLCK,2 allowed) :: %r" % cmd)
    raise BannedOperation("unknown AT form (refused) :: %r" % cmd)


def check_shell_allowed(cmdline: str) -> str:
    """Validate one adb-shell line. Returns the stripped line.

    Raises BannedOperation on any state-changing token or anything outside
    the read-only allowlist. Unwraps a single `su -c '<inner>'` layer and
    validates the inner command too (reads via su are still reads, but the
    inner command must be allowlisted as well).
    """
    s = cmdline.strip()
    if not s:
        raise BannedOperation("empty shell command")
    for rx, msg in BANNED_SHELL:
        if rx.search(s):
            raise BannedOperation("shell BAN (%s) :: %r" % (msg, cmdline))
    inner = s
    m = re.match(r"^su\s+(?:-c\s+)?['\"]?(.*?)['\"]?\s*$", s)
    if m and ("su" == s.split()[0]):
        inner = m.group(1).strip()
        for rx, msg in BANNED_SHELL:
            if rx.search(inner):
                raise BannedOperation("shell BAN inside su (%s) :: %r" % (msg, cmdline))
    for rx in _ALLOW_SHELL:
        if rx.match(inner):
            return s
    raise BannedOperation(
        "default-deny: shell command not on the read-only allowlist "
        "(getprop/dumpsys/cat/ls/sha256sum/getenforce only) :: %r" % cmdline)


def _adb_bin() -> str:
    for c in ADB_CANDIDATES:
        if c.exists():
            return str(c)
    return "adb"  # fall back to PATH


# ---------------------------------------------------------------- transport


class OracleTransport:
    """Read-only bridge from HwOracle ops to the device (or canned rehearsal).

    Parameters:
      oracle ... HwOracle instance whose transcript receives every response.
      dry_run  DEFAULT True: no socket/subprocess; canned values recorded.
      port ... atci forward port (default 7121, tools/atci.py pattern).
      adb .... adb binary (default tools/platform-tools/adb.exe when present).
    """

    def __init__(self, oracle=None, dry_run: bool = DRY_RUN_DEFAULT,
                 port: int = ATCI_PORT, adb: str | None = None):
        self.oracle = oracle if oracle is not None else HwOracle()
        self.dry_run = bool(dry_run)
        self.port = int(port)
        self.adb = adb or _adb_bin()
        self.at_log: list = []  # commands actually transmitted (audit)

    # -- low-level read-only primitives (both denylist-guarded) -------------

    def at_query(self, cmd: str) -> str:
        """Send ONE read-only AT query. Returns the raw modem text."""
        form = is_readonly_at(cmd)  # raises on anything banned
        _ = form
        if self.dry_run:
            return self._canned_at(cmd)
        s = socket.create_connection((ATCI_HOST, self.port), timeout=14)
        s.settimeout(6)
        try:
            self.at_log.append(cmd)
            s.sendall(cmd.strip().encode() + b"\r")
            time.sleep(AT_PACING_S)
            d = b""
            try:
                while True:
                    c = s.recv(4096)
                    if not c:
                        break
                    d += c
                    if b"OK\r\n" in d or b"ERROR" in d or b"+CME ERROR" in d:
                        break
            except socket.timeout:
                pass
            return d.decode("ascii", "replace")
        finally:
            s.close()

    def _canned_at(self, cmd: str) -> str:
        s = cmd.strip()
        if s == "AT+ESMLCK=?":
            return "\r\n%s\r\n\r\nOK\r\n" % CANNED_ESMLCK_TEST
        if s == "AT+ESMLCK?":
            return "\r\n%s\r\n\r\nOK\r\n" % CANNED_ESMLCK_READ
        if s in ("AT+ESMLRSU=?", "AT+ESMLGEN=?"):
            return "\r\nOK\r\n"
        if _ALLOW_AT_CLCK2.match(s):
            return "\r\nERROR\r\n"
        return "\r\nOK\r\n"

    def shell_read(self, cmdline: str) -> str:
        """Run ONE read-only `adb shell <cmdline>`. Returns stdout text."""
        ok = check_shell_allowed(cmdline)  # raises on anything banned
        _ = ok
        if self.dry_run:
            return self._canned_shell(cmdline)
        out = subprocess.run([self.adb, "shell", cmdline], capture_output=True,
                             text=True, timeout=SHELL_TIMEOUT_S)
        return out.stdout or ""

    def _canned_shell(self, cmdline: str) -> str:
        s = cmdline.strip()
        if s.startswith("getprop"):
            arg = s[len("getprop"):].strip()
            if arg:
                return "[%s]: [%s]\n" % (arg, CANNED_LOCK_PROPS.get(arg, ""))
            lines = ["[%s]: [%s]" % (k, v)
                     for k, v in sorted({**CANNED_LOCK_PROPS,
                                         **CANNED_EFUSE_PROPS}.items())]
            return "\n".join(lines) + "\n"
        if s.startswith("dumpsys"):
            return "(dry-run: dumpsys %s not executed)\n" % s[len("dumpsys"):].strip()
        return "(dry-run: %s not executed)\n" % s

    # -- helpers ------------------------------------------------------------

    @staticmethod
    def _parse_getprop(text: str) -> dict:
        out = {}
        for line in text.splitlines():
            m = re.match(r"\[(.+?)\]:\s*\[(.*)\]", line.strip())
            if m:
                out[m.group(1)] = m.group(2)
        return out

    def read_remain_count(self) -> str:
        """Read-only remain.count (used before AND after for the proof)."""
        if self.dry_run:
            return CANNED_LOCK_PROPS[
                "vendor.gsm.sim.slot.lock.device.lock.remain.count"]
        txt = self.shell_read(
            "getprop vendor.gsm.sim.slot.lock.device.lock.remain.count")
        props = self._parse_getprop(txt)
        if props.get("vendor.gsm.sim.slot.lock.device.lock.remain.count", "").strip():
            return props["vendor.gsm.sim.slot.lock.device.lock.remain.count"].strip()
        # `adb shell getprop <key>` prints the bare value without brackets.
        bare = (txt or "").strip().split()
        return bare[0] if bare else ""

    def _record(self, op: str, params: dict, payload: dict) -> dict:
        assert op in HwOracle.OPS, "unknown oracle op %r" % op
        rec = OracleRecord(op, dict(params),
                           result=json.dumps(payload, sort_keys=True))
        self.oracle.transcript.append(rec)
        return payload

    # -- implemented ops ----------------------------------------------------

    def sml_status(self) -> dict:
        """Op sml_status: ESMLCK=? + ESMLCK? + lock props + remain pair."""
        remain_before = self.read_remain_count()
        esmlck_test = self.at_query("AT+ESMLCK=?")
        esmlck_read = self.at_query("AT+ESMLCK?")
        if self.dry_run:
            lock_props = dict(CANNED_LOCK_PROPS)
        else:
            txt = self.shell_read("getprop")
            lock_props = {k: v for k, v in self._parse_getprop(txt).items()
                          if LOCK_FILTER.search(k)}
        remain_after = self.read_remain_count()
        payload = {
            "at_esmlck_test": esmlck_test.strip(),
            "at_esmlck_read": esmlck_read.strip(),
            "lock_props": lock_props,
            "remain_before": remain_before,
            "remain_after": remain_after,
            "zero_state_change": remain_before == remain_after,
            "mode": "DRYRUN" if self.dry_run else "LIVE-READONLY",
        }
        return self._record("sml_status",
                            {"queries": ["AT+ESMLCK=?", "AT+ESMLCK?",
                                         "getprop lock-bundle"]},
                            payload)

    def efuse_read(self) -> dict:
        """Op efuse_read: getprop filtered to fuse/otp/tfn + sim_me_lock ONLY."""
        if self.dry_run:
            props = dict(CANNED_EFUSE_PROPS)
        else:
            txt = self.shell_read("getprop")
            props = {k: v for k, v in self._parse_getprop(txt).items()
                     if EFUSE_FILTER.search(k)}
            if not props:
                props = {"note": "no fuse/otp/tfn props exposed on this build"}
        payload = {"props": props,
                   "mode": "DRYRUN" if self.dry_run else "LIVE-READONLY"}
        return self._record(
            "efuse_read",
            {"filter": "getprop | grep -i 'fuse|otp|tfn|sim_me_lock' (host-side)"},
            payload)

    def nv_read(self, lid_name: str = "SL00_000", rec_idx: int = 0) -> dict:
        """Op nv_read: PC-local read of an ALREADY-BACKED-UP /md/* file.

        No device contact in any mode (hence zero new root writes by
        construction). Ciphertext stays opaque (HW-bound); only size/sha256
        and public LID geometry are recorded.
        """
        if lid_name not in ALLOW_NV_NAMES:
            raise BannedOperation(
                "nv_read allowlist: %r is not an already-backed-up name %s"
                % (lid_name, sorted(ALLOW_NV_NAMES)))
        if not isinstance(rec_idx, int) or rec_idx < 0:
            raise BannedOperation("nv_read rec_idx must be a non-negative int")
        import hashlib as _hl
        matches = sorted(MODEM_BAK.glob(lid_name + "*"))
        # Also accept exact nvram_live names for NVD_*.
        if not matches:
            alt = sorted((REPO_ROOT / "nvram_live").glob(lid_name + "*"))
            matches = alt
        if matches:
            p = matches[0]
            data = p.read_bytes()  # PC-local backup; read-only ('rb' semantics)
            payload = {"lid_name": lid_name, "rec_idx": rec_idx,
                       "backed_up": True, "path": str(p),
                       "size": len(data),
                       "sha256": _hl.sha256(data).hexdigest(),
                       "magic": data[:4].decode("ascii", "replace"),
                       "mode": "DRYRUN" if self.dry_run else "LOCAL-BACKUP-READ"}
            return self._record("nv_read",
                                {"lid_name": lid_name, "rec_idx": rec_idx},
                                payload)
        # /md/* LID container inside the already-backed-up protect imgs
        # (PC-local ext4 parse via sim/nv_model.py; read-only, no device).
        try:
            if str(SIM_DIR) not in sys.path:
                sys.path.insert(0, str(SIM_DIR))
            import nv_model as _nv  # type: ignore
            for img in (MODEM_BAK / "protect1.img", MODEM_BAK / "protect2.img"):
                if not img.is_file():
                    continue
                try:
                    containers = _nv.parse_protect(str(img))
                except Exception:
                    continue
                if lid_name in containers:
                    c = containers[lid_name]
                    h = c.header
                    payload = {
                        "lid_name": lid_name, "rec_idx": rec_idx,
                        "backed_up": True,
                        "path": "modem_bak/modem_bak/%s:/md/%s" % (img.name, lid_name),
                        "size": h.file_size, "ct_len": h.ct_len,
                        "sha256": _hl.sha256(c.raw).hexdigest(),
                        "magic": "LID\\0",
                        "lid": "0x%04X" % h.lid, "nrec": h.rec_count,
                        "rec_size": h.rec_size, "sec_size": h.sec_size,
                        "ciphertext": "opaque HW-bound (no plaintext on PC)",
                        "mode": "DRYRUN" if self.dry_run else "LOCAL-BACKUP-READ"}
                    return self._record("nv_read",
                                        {"lid_name": lid_name, "rec_idx": rec_idx},
                                        payload)
        except ImportError:
            pass
        payload = {"lid_name": lid_name, "rec_idx": rec_idx,
                   "backed_up": False,
                   "note": "not present in modem_bak/ (no device re-pull "
                           "by policy; consult captures/ instead)",
                   "mode": "DRYRUN" if self.dry_run else "LIVE-READONLY"}
        return self._record("nv_read",
                            {"lid_name": lid_name, "rec_idx": rec_idx},
                            payload)

    # -- unimplemented ops (recorded + raise, HwOracle contract) -------------

    def _unimplemented(self, op: str, params: dict):
        rec = OracleRecord(op, dict(params), result="UNIMPLEMENTED")
        self.oracle.transcript.append(rec)
        raise OracleUnimplemented(
            "oracle op %s not implemented in read-only transport "
            "(recorded transcript entry #%d)."
            % (op, len(self.oracle.transcript)))

    def chl_hash(self, **params):
        return self._unimplemented("chl_hash", params)

    def chl_mac(self, **params):
        return self._unimplemented("chl_mac", params)

    def apdu_xfer(self, **params):
        return self._unimplemented("apdu_xfer", params)

    # -- probe + transcript -------------------------------------------------

    def readonly_probe(self) -> dict:
        """The read-only probe: sml_status (+efuse_read) with remain proof.

        Probe order: remain_before -> AT+ESMLCK=? -> AT+ESMLCK? -> lock props
        -> remain_after. Asserts remain_before == remain_after. Returns the
        summary dict (also fully present in the transcript records).
        """
        s = self.sml_status()
        e = self.efuse_read()
        summary = {
            "remain_before": s["remain_before"],
            "remain_after": s["remain_after"],
            "zero_state_change": bool(s["zero_state_change"]),
            "esmlck_test_ok": "OK" in s["at_esmlck_test"],
            "esmlck_read_ok": "OK" in s["at_esmlck_read"],
            "records": len(self.oracle.transcript),
            "mode": s["mode"],
        }
        assert summary["zero_state_change"], \
            "STATE CHANGED during read-only probe: %r -> %r" % (
                s["remain_before"], s["remain_after"])
        summary["efuse_prop_count"] = len(e["props"])
        return summary

    def save(self, name: str) -> Path:
        return self.oracle.save(name)


# ---------------------------------------------------------------- selftest


def selftest() -> tuple:
    passed, failed, details = 0, 0, []

    def check(label, cond, extra=""):
        nonlocal passed, failed
        if cond:
            passed += 1
            details.append("PASS %s" % label)
        else:
            failed += 1
            details.append("FAIL %s %s" % (label, extra))

    # 1. Dry-run defaults ON (hard requirement).
    check("dryrun-default-True", DRY_RUN_DEFAULT is True)
    import inspect as _insp
    sig = _insp.signature(OracleTransport.__init__)
    check("ctor-dryrun-default-True",
          sig.parameters["dry_run"].default is True,
          "%r" % (sig.parameters["dry_run"].default,))

    # 2. AT allowlist: =? / ? / CLCK,2 pass; everything else raises.
    for good, kind in (("AT+ESMLCK=?", "test"), ("AT+ESMLCK?", "read"),
                       ("AT+ESMLRSU=?", "test"), ("AT+ESMLGEN=?", "test"),
                       ("AT+ESMLCK=?", "test"),
                       ('AT+CLCK="PN",2', "clck2"),
                       ("AT+ECRRST=?", "test")):
        try:
            check("at-allow[%s==%s]" % (good, kind), is_readonly_at(good) == kind)
        except BannedOperation as e:
            check("at-allow[%s]" % good, False, str(e))
    banned_at = [
        'AT+ESMLCK=1,0,"00000000","000000000000000","",""',
        'AT+ESMLCK=4,0,"key"',
        'AT+CLCK="PN",0,"12345678"',
        'AT+ESMLRSU=1,"deadbeef"',
        'AT+ERSUKEY="00:11:22:33"',
        'AT+MOTSMLDB="00112233"',
        'AT+MOTSMLEVENT="00112233"',
        'AT+EUULK="00112233"',
        'AT+ESMLCK=2,0',
    ]
    for raw in banned_at:
        try:
            is_readonly_at(raw)
            check("at-ban[%s]" % raw, False, "no raise")
        except BannedOperation:
            check("at-ban[%s]" % raw, True)
        except Exception as e:  # noqa: BLE001
            check("at-ban[%s]" % raw, False, "wrong exc %r" % e)

    # 3. Shell allowlist / denylist.
    for good in ("getprop",
                 "getprop vendor.gsm.sim.slot.lock.device.lock.remain.count",
                 "dumpsys telephony.registry", "dumpsys isub",
                 "cat /mnt/vendor/nvdata/md/NVD_DATA",
                 "ls /mnt/vendor/nvdata/md"):
        try:
            check("sh-allow[%s]" % good, check_shell_allowed(good) == good.strip())
        except BannedOperation as e:
            check("sh-allow[%s]" % good, False, str(e))
    banned_sh = [
        "setprop persist.vendor.service.atci.autostart 1",
        "settings put global airplane_mode_on 1",
        "reboot", "adb reboot",
        "dd if=/dev/block/by-name/protect1 of=/sdcard/p.img",
        "dd if=/dev/zero of=/dev/block/by-name/nvdata",
        "fastboot flash md1img_a foo.img",
        "mount -o remount,rw /vendor",
        "cat /x > /sdcard/out",
        "echo 1 | tee /sys/x",
        "chmod 777 /data/x", "chcon u:object_r:x:s0 /data/x",
        "rm -rf /data/x", "input keyevent 26",
        "getprop; reboot", "getprop && setprop a b",
        "pm install foo.apk", "am start -a android.settings.SETTINGS",
    ]
    for raw in banned_sh:
        try:
            check_shell_allowed(raw)
            check("sh-ban[%s]" % raw, False, "no raise")
        except BannedOperation:
            check("sh-ban[%s]" % raw, True)
        except Exception as e:  # noqa: BLE001
            check("sh-ban[%s]" % raw, False, "wrong exc %r" % e)

    # 4. Dry-run probe: zero socket/subprocess, remain 5==5, transcript saved
    #    UNDER sim/oracle_logs/ only.
    try:
        t = OracleTransport(dry_run=True)
        opened = []
        _real_create = socket.create_connection
        _real_run = subprocess.run
        socket.create_connection = lambda *a, **k: (_ for _ in ()).throw(
            AssertionError("socket opened during dry-run"))
        subprocess.run = lambda *a, **k: (_ for _ in ()).throw(
            AssertionError("subprocess spawned during dry-run"))
        try:
            summary = t.readonly_probe()
        finally:
            socket.create_connection = _real_create
            subprocess.run = _real_run
        check("dryrun[zero_state_change]", summary["zero_state_change"] is True,
              "%r" % summary)
        check("dryrun[remain5==5]",
              summary["remain_before"] == "5" and summary["remain_after"] == "5",
              "%r" % summary)
        check("dryrun[esmlck_ok]",
              summary["esmlck_test_ok"] and summary["esmlck_read_ok"], "%r" % summary)
        check("dryrun[transcript>=2]", len(t.oracle.transcript) >= 2,
              "%d" % len(t.oracle.transcript))
        check("dryrun[ops]",
              [r.op for r in t.oracle.transcript][:2] == ["sml_status", "efuse_read"],
              "%r" % [r.op for r in t.oracle.transcript])
        p = t.save("selftest_dryrun_probe")
        check("dryrun[saved-under-sim]",
              SIM_DIR.resolve() in p.resolve().parents, str(p))
        check("dryrun[jsonl>=2]",
              len(p.read_text().strip().splitlines()) >= 2)
        # nv_read is PC-local backup read (allowed names only).
        nv = t.nv_read("SL00_000", 0)
        check("dryrun[nv_read-SL00-backed]", nv.get("backed_up") is True,
              "%r" % nv)
        check("dryrun[nv_read-SL00-geometry]",
              nv.get("lid") == "0xEF28" and nv.get("rec_size") == 777
              and nv.get("sec_size") == 832, "%r" % nv)
        try:
            t.nv_read("/etc/passwd", 0)
            check("nv_read[ban-path]", False, "no raise")
        except BannedOperation:
            check("nv_read[ban-path]", True)
        # Unimplemented ops record + raise (HwOracle contract).
        for op in ("chl_hash", "chl_mac", "apdu_xfer"):
            try:
                getattr(t, op)(foo=1)
                check("unimpl[%s-raises]" % op, False, "no raise")
            except OracleUnimplemented:
                check("unimpl[%s-raises]" % op, True)
        check("unimpl[recorded]",
              t.oracle.transcript[-1].result == "UNIMPLEMENTED")
    except Exception as e:  # noqa: BLE001
        check("dryrun-probe", False, repr(e))

    return passed, failed, details


def main(argv=None) -> int:
    argv = list(argv or [])
    if "--selftest" in argv or "--dryrun-probe" in argv or not argv:
        passed, failed, details = selftest()
        print("oracle_transport selftest: %d passed, %d failed "
              "(dry_run default=%s)" % (passed, failed, DRY_RUN_DEFAULT))
        for d in details:
            print("  " + d)
        if "--dryrun-probe" in argv or not argv:
            t = OracleTransport(dry_run=True)
            summary = t.readonly_probe()
            p = t.save("dryrun_probe")
            print()
            print("dry-run read-only probe summary:")
            print("  " + json.dumps(summary, indent=2).replace("\n", "\n  "))
            print("  transcript: %s (%d records)" % (p, len(t.oracle.transcript)))
            print("  remain.count before==after: %s==%s (zero_state_change=%s)"
                  % (summary["remain_before"], summary["remain_after"],
                     summary["zero_state_change"]))
        return 1 if failed else 0
    if "--live-probe" in argv:
        # Explicit opt-in live read-only probe (still denylist-guarded).
        name = "live_readonly_probe"
        for a in argv[1:]:
            if not a.startswith("--"):
                name = a
        t = OracleTransport(dry_run=False)
        summary = t.readonly_probe()
        p = t.save(name)
        print("live read-only probe summary:")
        print("  " + json.dumps(summary, indent=2).replace("\n", "\n  "))
        print("  transcript: %s (%d records)" % (p, len(t.oracle.transcript)))
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
