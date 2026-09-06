# Path A — Verbose eSIM Retry Runbook (read-only capture, one fresh BPP)

Goal: capture the exact failing STORE-DATA bytes + PIR to confirm or kill the
chunking hypothesis. One fresh matchingID. No AT sets, no NCK, no flashes.

## 0. Preconditions (all must hold — abort otherwise)
- [ ] Fresh matchingID re-issued (old codes are single-use — spent)
- [ ] remain.count == 5: `adb shell getprop vendor.gsm.sim.slot.lock.device.lock.remain.count`
- [ ] Slot `_a`, baseband `...P247...`, `sys.boot_completed=1` (same commands as §0)
- [ ] PC disk: >2 GB free (radio log + BPP captures;81MB+ per full logcat)
- [ ] atci forward UP (needed only for the post-run ESMLCK? read): see §2

## 1. Start clean capture (PC side, TWO shells)
Shell 1 (main+radio, verbose):
  tools\platform-tools\adb.exe logcat -b main,radio,system -v threadtime > esim_retry_<ts>_logcat.txt
Shell 2 (rild tags live tail, optional watch):
  tools\platform-tools\adb.exe logcat -b radio -v threadtime | Select-String "054d|054e|ES10|Euicc|BPP|STORE"
Do NOT run `logcat -c` (never clear — forensic continuity).

## 2. Baseline snapshot (before touching LPA)
  tools\platform-tools\adb.exe shell getprop > esim_retry_<ts>_props_before.txt
  tools\platform-tools\adb.exe shell dumpsys telephony.registry > esim_retry_<ts>_telreg.txt
  (atci forward if down: adb forward tcp:7121 localfilesystem:/dev/socket/adb_atci_socket)
  python tools/atci.py "AT+ESMLCK?" > esim_retry_<ts>_esmlck.txt   (read-only ? form)

## 3. LPA verbose setup (pick ONE app per attempt, note which)
- EasyEUICC: Settings → Developer options → Verbose logging ON, Ignore-TLS OFF
  (prod SM-DP+ needs valid TLS), MSS default.
- OpenEUICC (privileged): Settings → enable debug/verbose if present.
Screenshot or note every toggle.

## 4. The attempt
- Enter ONLY the fresh matchingID. Start Shell-1 capture FIRST, then download.
- Do NOT retry a second time on the same matchingID (single-use; replay
  desyncs SCP03t and poisons the evidence).
- On failure: screenshot the app's error screen (must show: last APDU SW,
  ES10B reason, transactionId if shown), leave phone untouched 60 s (drain URCs).

## 5. Post snapshot + pull
  tools\platform-tools\adb.exe shell getprop > esim_retry_<ts>_props_after.txt
  (Ctrl-C Shell-1 AFTER post snapshot.)
  python tools/atci.py "AT+ESMLCK?" > esim_retry_<ts>_esmlck_after.txt
  remain check: same getprop as §0 — must read 5 (else STOP, report).
  Save app-side export if offered (EasyEUICC diagnostics / OpenEUICC logs).

## 6. Hand-off bundle (one folder per attempt)
  esim_retry_<ts>/{logcat, props_before/after, telreg, esmlck x2, screenshots,
  app export, NOTES.txt (app used, toggles, matchingID first-4…last-2 only,
  wall-clock of download tap, observed error text verbatim)}
NEVER paste a full unused matchingID into chat (single-use secret).

## 7. Decision tree (lab evaluates the bundle)
- 6A80 + ES10B_ERROR_REASON_UNDEFINED + no PIR + death on an 86 segment
  (bppCommandId in A3 range)  →  CHUNKING CONFIRMED → LPA segmentation fix.
- 6A80 + decoded PIR (pprNotAllowed/invalidSignature/…) → POLICY/TRUST →
  Path B (carrier QR) or Path C (test-eUICC); Path A closed.
- 6700/6A86/6985 → different bug (extended/P1-P2/order) → new spec.
- ES9+ error / no BPP issued → matchingID/account issue, NOT an install bug.
- remain.count != 5 at any point → STOP EVERYTHING, report immediately.
