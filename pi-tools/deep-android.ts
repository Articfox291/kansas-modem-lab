/**
 * Deep-Android analysis tools for the Kansas lab (pi extension, project-local).
 *
 * READ-ONLY + DRY-RUN ONLY. No tool in this file executes a device write:
 * no flash, no erase, no setprop, no reboot, no AT set/unlock/commit,
 * no NCK trials, no key/secret output. `deep_flashplan` validates
 * preconditions and PRINTS the exact manual fastboot commands for a human
 * to run; it never runs them. Attempt floor (remain.count 5) is enforced
 * by the shared AT denylist in `deep_atquery` (same rules as modem-tools).
 */

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, resolve, sep } from "node:path";

// Repo root: run pi from <repo> (or set VAL_PROTOCOL_REPO).
const REPO = process.env.VAL_PROTOCOL_REPO ?? process.cwd();

// ---------------------------------------------------------------------------
// Shared: AT read-only guard (identical policy to modem-tools.ts).
// ---------------------------------------------------------------------------
const DENY_AT = [
	/=([^?]|$)/, // any set form except =? (checked separately below)
	/CLCK[^"]*"[^"]*",\s*0/i,
	/ERSUKEY/i,
	/ESMLRSU\s*=/i,
	/MOTSMLDB/i,
	/MOTSMLEVENT/i,
	/EUULK/i,
	/NCK/i,
];

function isReadOnlyAt(cmd: string): boolean {
	const c = cmd.trim();
	if (/=\?$/.test(c)) return true; // test form
	if (/\?$/.test(c) && !/=/.test(c.slice(0, -1))) return true; // query form
	if (/CLCK[^"]*"[^"]*",\s*2\s*$/.test(c)) return true; // facility status
	for (const re of DENY_AT) {
		// allow the =? test form explicitly whitelisted above
		if (re.test(c) && !/=\?$/.test(c)) return false;
	}
	// Anything with '=' that is not a whitelisted query is denied.
	if (c.includes("=")) return false;
	return true; // bare AT / ATI etc.
}

// ---------------------------------------------------------------------------
// Shared: offline python runner (repo sim/* CLIs only, never adb/fastboot).
// ---------------------------------------------------------------------------
function runPy(
	args: string[],
	timeoutMs: number,
): { ok: boolean; out: string; ms: number } {
	const t0 = Date.now();
	try {
		const out = execFileSync("python", args, {
			cwd: REPO,
			timeout: timeoutMs,
			maxBuffer: 4 * 1024 * 1024,
			windowsHide: true,
		}).toString("utf8");
		return { ok: true, out, ms: Date.now() - t0 };
	} catch (e: unknown) {
		const err = e as { stdout?: Buffer; message?: string };
		const out = err.stdout ? err.stdout.toString("utf8") : String(err.message ?? e);
		return { ok: false, out, ms: Date.now() - t0 };
	}
}

function verdict(out: string): { pass: boolean; line: string } {
	const lines = out.split(/\r?\n/).filter((l) => l.trim().length > 0);
	const tail = lines.slice(-8).join(" | ");
	const hardFail = /Traceback|ERROR REPORT|SCRIPT ERROR|GhidraScriptLoadException/.test(
		tail,
	);
	const confirmed =
		/selftest: PASS|ALL PASS|PASS EXIT|conform: PASS|corpus: PASS|reproduces the live|demo calc image-hash == live|misses=NONE|hits/.test(
			out,
		);
	return { pass: !hardFail && confirmed, line: tail.slice(-280) };
}

// Gate verdict for repo selftest CLIs. These CLIs signal failure via exit
// code / assert-Traceback (sml_sim prints no PASS line at all on success;
// hw_target prints "hw_target: PASS"; rmmi prints "N passed, 0 failed"),
// so the generic confirm-phrase list is too strict for them. A gate passes
// when the process exited cleanly, no failure marker is present, and a
// recognized ok-signal was printed.
function gateVerdict(out: string): { pass: boolean; line: string } {
	const lines = out.split(/\r?\n/).filter((l) => l.trim().length > 0);
	const tail = lines.slice(-8).join(" | ");
	const bad =
		/Traceback|AssertionError|ERROR REPORT|SCRIPT ERROR|GhidraScriptLoadException|\bFAIL\b|failed [1-9]|MISMATCH|NOT OK/.test(
			out,
		);
	const good =
		/selftest: PASS|ALL PASS|PASS EXIT|conform: PASS|corpus: PASS|: PASS|passed, 0 failed|CERT2-sig: OK|== LEGAL/.test(
			out,
		);
	return { pass: !bad && good, line: tail.slice(-280) };
}

// AT-query verdict: success = the channel delivered a (possibly ERROR)
// response. A modem "ERROR" reply is informative data, not tool failure;
// only an empty reply or a dead channel fails.
function atVerdict(r: { ok: boolean; out: string }): { pass: boolean; line: string } {
	if (!r.ok || r.out.trim().length === 0) return { pass: false, line: "process failed" };
	const first = r.out
		.split(/\r?\n/)
		.map((l) => l.replace(/\0/g, "").trim())
		.filter((l) => l.length > 0)
		.slice(0, 3)
		.join(" | ");
	return { pass: true, line: first.slice(-280) };
}

// ---------------------------------------------------------------------------
// deep_logparse: offline parsing of saved capture bundles.
// ---------------------------------------------------------------------------
const MAX_FILE_BYTES = 8 * 1024 * 1024;
const MAX_FILES = 40;

const EE_MARKERS = [
	"SML data sign check",
	"lid_error",
	"MD exception",
	"modem exception",
	"NVRAM assert",
	"fatal exception",
	"watchdog",
	"ES10B_ERROR_REASON",
];

function decodeText(buf: Buffer): string {
	// Saved dumps are a mix of UTF-8 logcat and UTF-16 props dumps.
	const sample = buf.subarray(0, Math.min(buf.length, 4096));
	let nulEven = 0;
	let nulOdd = 0;
	for (let i = 0; i < sample.length; i++) {
		if (sample[i] === 0) {
			if (i % 2 === 0) nulEven++;
			else nulOdd++;
		}
	}
	if (nulOdd > nulEven && nulOdd > 8) return buf.toString("utf16le");
	return buf.toString("utf8");
}

function collectFiles(root: string): string[] {
	const out: string[] = [];
	const walk = (dir: string): void => {
		if (out.length >= MAX_FILES) return;
		let entries: string[];
		try {
			entries = readdirSync(dir);
		} catch {
			return;
		}
		for (const e of entries) {
			if (out.length >= MAX_FILES) return;
			const p = join(dir, e);
			let st: { isDirectory(): boolean; isFile(): boolean; size: number };
			try {
				st = statSync(p);
			} catch {
				continue;
			}
			if (st.isDirectory()) walk(p);
			else if (st.isFile() && /\.(txt|log|json|xml)$/i.test(e)) out.push(p);
		}
	};
	walk(root);
	return out;
}

function parseLogBundle(roots: string[]): string {
	const perFile: string[] = [];
	const esmlckTuples = new Set<string>();
	const remainVals: string[] = [];
	const rejectHist = new Map<string, number>();
	const eeHits = new Map<string, number>();
	let filesRead = 0;
	let readErrors = 0;

	for (const root of roots) {
		for (const f of collectFiles(root)) {
			let stSize = 0;
			try {
				stSize = statSync(f).size;
			} catch {
				readErrors++;
				continue;
			}
			if (stSize > MAX_FILE_BYTES) {
				perFile.push(`${relative(REPO, f)}: SKIPPED oversize (${stSize}B)`);
				continue;
			}
			let text: string;
			try {
				text = decodeText(readFileSync(f));
			} catch {
				readErrors++;
				continue;
			}
			filesRead++;
			const short = relative(REPO, f);

			// ESMLCK tuples: +ESMLCK: (a,b,c,...),(...),... plus trailing key/flags.
			for (const m of text.matchAll(/\+ESMLCK:\s*([^\r\n]{1,600})/g)) {
				const line = m[1].trim();
				for (const t of line.matchAll(/\((\d+,\d+,\d+,\d+,\d+,\d+,\d+)\)/g)) {
					esmlckTuples.add(t[1]);
				}
				perFile.push(
					`${short}: ESMLCK line (${line.length} chars, ${[...line.matchAll(/\(\d+,\d+,\d+,\d+,\d+,\d+,\d+\)/g)].length} tuples)`,
				);
			}
			// remain.count extraction (lock props + banked 5==5 notes).
			for (const m of text.matchAll(
				/(?:device\.lock\.remain\.count|remain\.count)[^\d]{0,12}(\d)/g,
			)) {
				remainVals.push(`${short}=${m[1]}`);
			}
			// rejectCause trend histogram.
			for (const m of text.matchAll(/rejectCause=(\d+)/g)) {
				rejectHist.set(m[1], (rejectHist.get(m[1]) ?? 0) + 1);
			}
			// Modem-exception / EE markers.
			for (const marker of EE_MARKERS) {
				const n = text.split(marker).length - 1;
				if (n > 0) {
					eeHits.set(marker, (eeHits.get(marker) ?? 0) + n);
					perFile.push(`${short}: marker "${marker}" x${n}`);
				}
			}
			// Bare 6A80 (eUICC refusal signature) outside already-counted markers.
			const sw6a80 = text.split("6A80").length - 1;
			if (sw6a80 > 0) perFile.push(`${short}: 6A80 x${sw6a80}`);
		}
	}

	const lines: string[] = [];
	lines.push(`files read: ${filesRead}, read errors: ${readErrors}`);
	lines.push(
		`ESMLCK distinct tuples (${esmlckTuples.size}): ${[...esmlckTuples].slice(0, 14).join(" | ") || "none"}`,
	);
	lines.push(`remain.count sightings: ${remainVals.slice(0, 12).join(", ") || "none"}`);
	const rej = [...rejectHist.entries()]
		.sort((a, b) => b[1] - a[1])
		.slice(0, 5)
		.map(([k, v]) => `${k}x${v}`)
		.join(", ");
	lines.push(`rejectCause top: ${rej || "none"}`);
	const ee = [...eeHits.entries()]
		.map(([k, v]) => `"${k}"x${v}`)
		.join(", ");
	lines.push(`EE markers: ${ee || "none"}`);
	lines.push(`--- per-file (${perFile.length}) ---`);
	lines.push(...perFile.slice(0, 30));
	return lines.join("\n");
}

// ---------------------------------------------------------------------------
// deep_flashplan: DRY-RUN preflight + manual command sheet. Never executes.
// ---------------------------------------------------------------------------
const BACKUP_FILES = [
	"protect1.img",
	"protect2.img",
	"nvdata.img",
	"nvram.img",
	"persist.img",
	"proinfo.img",
	"seccfg.img",
];
const BACKUP_ROOTS = ["modem_bak", join("modem_bak", "modem_bak")];
const STOCK_MD1 = join("stock_XT2513V", "md1img.img");
const LK_BACKUPS = [
	join("stock_XT2513V", "lk.img.BAK"),
	join("stock_XT2513V", "lk.img"),
];

function sha256File(abs: string): string | null {
	try {
		return createHash("sha256").update(readFileSync(abs)).digest("hex");
	} catch {
		return null;
	}
}

function flashPlan(imageRel: string, slot: string): { pass: boolean; text: string } {
	const fail = (reason: string): { pass: boolean; text: string } => ({
		pass: false,
		text: `deep_flashplan: REFUSED (dry-run, nothing executed)\nreason: ${reason}`,
	});
	// 1. Slot guard: slot B always stays stock. Only _a may be flashed.
	if (slot !== "a") {
		return fail(`slot must be "a" (slot B stays stock); requested slot="${slot}"`);
	}
	// 2. Target image must live inside the repo and look like a modem image.
	const abs = resolve(REPO, imageRel);
	if (!abs.startsWith(REPO + sep) && abs !== REPO) {
		return fail(`target must be inside the repo; got "${imageRel}"`);
	}
	if (!/\.img$/i.test(abs)) {
		return fail(`target must be a .img file; got "${imageRel}"`);
	}
	if (!existsSync(abs)) {
		return fail(`target image not found: "${imageRel}"`);
	}
	// 3. Backup inventory: every modem backup + an LK backup must exist.
	const missing: string[] = [];
	const foundRoots: string[] = [];
	for (const f of BACKUP_FILES) {
		const hit = BACKUP_ROOTS.map((r) => join(REPO, r, f)).find((p) => existsSync(p));
		if (hit) foundRoots.push(relative(REPO, hit));
		else missing.push(f);
	}
	const lkHit = LK_BACKUPS.map((p) => join(REPO, p)).find((p) => existsSync(p));
	if (!lkHit) missing.push("stock_XT2513V/lk.img.BAK (LK backup)");
	if (missing.length > 0) {
		return fail(`missing backups (refusing to plan any flash): ${missing.join(", ")}`);
	}
	// 4. Stock reference must exist and the CERT2 chain must verify.
	const stockAbs = join(REPO, STOCK_MD1);
	if (!existsSync(stockAbs)) {
		return fail(`stock reference missing: ${STOCK_MD1} (slot-B-stock check impossible)`);
	}
	const stockHash = sha256File(stockAbs);
	const targetHash = sha256File(abs);
	if (!stockHash || !targetHash) {
		return fail("could not hash stock/target images");
	}
	const v = runPy(["sim/boot_sim.py", "--verify"], 180000);
	if (!v.ok || !gateVerdict(v.out).pass) {
		return fail(
			`CERT2 verify gate failed; refusing to plan flash. tail: ${v.out.split(/\r?\n/).filter((l) => l.trim()).slice(-4).join(" | ")}`,
		);
	}
	// 5. Emit the manual command sheet. NOTHING here is executed.
	const sameAsStock = stockHash === targetHash;
	const text = [
		"deep_flashplan: PLAN ISSUED (dry-run only — nothing was executed)",
		`target: ${imageRel} (sha256 ${targetHash.slice(0, 16)}…, ${statSync(abs).size}B)${sameAsStock ? " [IDENTICAL TO STOCK — this is a recovery flash]" : ""}`,
		`stock ref: ${STOCK_MD1} (sha256 ${stockHash.slice(0, 16)}…)`,
		`backups: OK (${foundRoots.length} modem files + ${relative(REPO, lkHit as string)})`,
		"CERT2 verify gate (--verify): PASS",
		"",
		"PREFLIGHT (human, in order — abort on any NO):",
		"  [ ] 1. Backups above are copied OFF this PC (second copy).",
		"  [ ] 2. Cable is data-capable; battery > 50%.",
		'  [ ] 3. `fastboot getvar current-slot` notes which slot is active (plan flashes md1img_a only).',
		"  [ ] 4. `fastboot getvar securestate` reads flashing_unlocked.",
		"  [ ] 5. Slot B is untouched stock (never flash md1img_b).",
		"  [ ] 6. Patched LK is in place; the flash set below contains NO lk/efuseBackup/preloader/gpt.",
		"",
		"MANUAL COMMANDS (run yourself from the repo root, one at a time):",
		"  adb reboot bootloader",
		"  tools\\platform-tools\\fastboot.exe getvar current-slot",
		"  tools\\platform-tools\\fastboot.exe getvar securestate",
		`  tools\\platform-tools\\fastboot.exe flash md1img_a "${imageRel}"`,
		"  tools\\platform-tools\\fastboot.exe reboot",
		"  adb wait-for-device",
		'  adb shell "dmesg | grep -iE \\"modem|MD exception|SML|NVRAM\\" | tail -n 30"',
		"  (expect: zero modem exceptions; baseband alive)",
		"",
		"ROLLBACK (if any modem exception or boot issue):",
		`  tools\\platform-tools\\fastboot.exe flash md1img_a "${STOCK_MD1}"`,
		"  tools\\platform-tools\\fastboot.exe reboot",
		"",
		"NOTE: this tool never executes anything. It has no flash/erase/setprop/reboot path by construction — a human runs the commands above by hand.",
	].join("\n");
	return { pass: true, text };
}

// ---------------------------------------------------------------------------
// Extension registration.
// ---------------------------------------------------------------------------
export default function deepAndroidExtension(pi: ExtensionAPI) {
	const notifyPass = (
		ctx: { ui: { notify: (msg: string, level: string) => void } },
		label: string,
	) => ctx.ui.notify(`SUCCESS: ${label} — verdict PASS`, "info");

	pi.registerTool({
		name: "deep_logparse",
		label: "Deep capture-bundle log parse",
		description:
			"Offline parse of saved capture bundles (logcat/props/dumpsys/telreg): ESMLCK tuples, remain.count sightings, rejectCause trends, modem EE markers. Reads repo files only; never touches the device.",
		parameters: Type.Object({
			bundle: Type.Optional(
				Type.String({
					description:
						"Bundle subdir under captures/ (e.g. esim_retry_20260905_130857). Omit to scan all capture roots.",
				}),
			),
		}),
		async execute(_id, params, ctx) {
			const p = params as { bundle?: string };
			let roots: string[];
			if (p.bundle) {
				if (!/^[A-Za-z0-9_.\-]+$/.test(p.bundle)) {
					return {
						content: [{ type: "text", text: "deep_logparse: FAIL bad bundle name" }],
						details: { tool: "deep_logparse", pass: false },
					};
				}
				const abs = resolve(REPO, "captures", p.bundle);
				if (!abs.startsWith(join(REPO, "captures") + sep) && abs !== join(REPO, "captures")) {
					return {
						content: [{ type: "text", text: "deep_logparse: FAIL bundle escapes captures/" }],
						details: { tool: "deep_logparse", pass: false },
					};
				}
				if (!existsSync(abs)) {
					return {
						content: [{ type: "text", text: `deep_logparse: FAIL unknown bundle ${p.bundle}` }],
						details: { tool: "deep_logparse", pass: false },
					};
				}
				roots = [abs];
			} else {
				roots = [join(REPO, "captures", "capture"), join(REPO, "captures")].filter((r) =>
					existsSync(r),
				);
			}
			const body = parseLogBundle(roots);
			const pass = /files read: [1-9]/.test(body);
			const text = `deep_logparse: ${pass ? "PASS" : "FAIL"}\n${body}`;
			if (pass) notifyPass(ctx as never, "log parse");
			return { content: [{ type: "text", text }], details: { tool: "deep_logparse", pass } };
		},
	});

	pi.registerTool({
		name: "deep_gates",
		label: "Deep verification gate bundle",
		description:
			"Run the sim gate bundle offline (emu_engine, hw_target, sml/nv/rmmi selftests, interp conformance). PASS/FAIL table. No device contact.",
		parameters: Type.Object({}),
		async execute(_id, _params, ctx) {
			const cmds: string[][] = [
				["sim/emu_engine.py"],
				["sim/hw_target.py"],
				["sim/sml_sim.py", "--selftest"],
				["sim/rmmi_sim.py", "--selftest"],
				["sim/nv_model.py", "--selftest"],
				["sim/interp.py", "--conform"],
			];
			const outs: string[] = [];
			let allPass = true;
			for (const c of cmds) {
				const r = runPy(c, 180000);
				const v = r.ok ? gateVerdict(r.out) : { pass: false, line: "failed" };
				outs.push(`${c.join(" ")} => ${v.pass ? "PASS" : "FAIL"}`);
				if (!v.pass) allPass = false;
			}
			const text = `deep_gates: ${allPass ? "PASS" : "FAIL"}\n${outs.join("\n")}`;
			if (allPass) notifyPass(ctx as never, "all gates");
			return { content: [{ type: "text", text }], details: { tool: "deep_gates", pass: allPass } };
		},
	});

	pi.registerTool({
		name: "deep_flashplan",
		label: "Dry-run modem flash planner",
		description:
			"DRY-RUN ONLY: validate backups + stock reference + CERT2 verify gate, then print exact manual fastboot commands with a preflight checklist. Refuses if backups are missing or slot is not _a. Never executes anything.",
		parameters: Type.Object({
			image: Type.String({
				description: 'Repo-relative modem image, e.g. md1work_md1force1-signed.img',
			}),
			slot: Type.Optional(Type.String({ description: 'Must be "a" (slot B stays stock)' })),
		}),
		async execute(_id, params) {
			const p = params as { image: string; slot?: string };
			const r = flashPlan(p.image, p.slot ?? "a");
			return { content: [{ type: "text", text: r.text }], details: { tool: "deep_flashplan", pass: r.pass } };
		},
	});

	pi.registerTool({
		name: "deep_atquery",
		label: "Guarded read-only AT query (deep)",
		description:
			"Send ONE read-only AT query (test =? / query ? / CLCK mode-2 only) via the live AT channel. Set/unlock/commit/NCK forms are hard-blocked by guard before any subprocess runs.",
		parameters: Type.Object({
			cmd: Type.String({ description: "AT command, e.g. AT+ESMLCK?" }),
		}),
		async execute(_id, params) {
			const p = params as { cmd: string };
			if (!isReadOnlyAt(p.cmd)) {
				return {
					content: [{ type: "text", text: `deep_atquery: BLOCKED by guard (not a read-only query): ${p.cmd}` }],
					details: { tool: "deep_atquery", pass: false, blocked: true },
				};
			}
			const r = runPy(["tools/atci.py", p.cmd], 90000);
			const v = atVerdict(r);
			return {
				content: [
					{
						type: "text",
						text: `deep_atquery: ${v.pass ? "PASS" : "FAIL"} (${r.ms}ms)\n${v.line}\n--- tail ---\n${r.out.split(/\r?\n/).slice(-12).join("\n")}`,
					},
				],
				details: { tool: "deep_atquery", pass: v.pass, ms: r.ms, cmd: p.cmd },
			};
		},
	});

	pi.on("session_start", (_event, ctx) => {
		ctx.ui.notify(
			"Deep-android tools armed: deep_logparse, deep_gates, deep_flashplan (dry-run only, never executes), deep_atquery (guarded read-only). No flash/erase/setprop/reboot path exists in this extension.",
			"info",
		);
	});
}
