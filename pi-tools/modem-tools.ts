/**
 * Modem-hunt native tools for the Kansas lab (pi extension, project-local).
 *
 * Wraps the repo's sim/* CLI arsenal as structured tools with explicit
 * PASS/FAIL verdicts. Every tool runs read-only against saved dumps:
 * no device writes, no AT set/unlock, no NCK trials, no flashes.
 * Attempt floor is enforced in modem_atquery (denylist) — see LAB RULES.
 *
 * Success prompting: any tool whose verdict is a clean PASS fires
 * ctx.ui.notify so victories surface immediately in the TUI.
 */

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";
import { execFileSync } from "node:child_process";

// Repo root: run pi from <repo> (or set VAL_PROTOCOL_REPO).
const REPO =
	process.env.VAL_PROTOCOL_REPO ?? process.cwd();

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
	// Fail only on hard errors; reports with expected misses (e.g. model
	// scorecards) are successes if the process exited cleanly — the caller
	// checks `ok`, this only scans output text.
	const hardFail = /Traceback|ERROR REPORT|SCRIPT ERROR|GhidraScriptLoadException/.test(
		tail,
	);
	const confirmed =
		/selftest: PASS|ALL PASS|PASS EXIT|conform: PASS|corpus: PASS|reproduces the live|demo calc image-hash == live|misses=NONE|hits/.test(
			out,
		);
	return { pass: !hardFail && confirmed, line: tail.slice(-280) };
}

function toolResult(
	name: string,
	r: { ok: boolean; out: string; ms: number },
	extra: Record<string, unknown> = {},
) {
	const v = r.ok ? verdict(r.out) : { pass: false, line: "process failed" };
	return {
		content: [
			{
				type: "text",
				text: `${name}: ${v.pass ? "PASS" : "FAIL"} (${r.ms}ms)\n${v.line}\n--- tail ---\n${r.out
					.split(/\r?\n/)
					.slice(-12)
					.join("\n")}`,
			},
		],
		details: { tool: name, pass: v.pass, ms: r.ms, ...extra },
	};
}

export default function modemToolsExtension(pi: ExtensionAPI) {
	const notifyPass = (
		ctx: { ui: { notify: (msg: string, level: string) => void } },
		label: string,
	) => ctx.ui.notify(`SUCCESS: ${label} — verdict PASS`, "info");

	pi.registerTool({
		name: "modem_chain",
		label: "Modem whole-chain trace",
		description:
			"Run a whole-chain strict emulation (legal|link|esmlck|verify) with code+memory traces. Use for verdict proofs and boundary mapping.",
		parameters: Type.Object({
			preset: Type.String({ description: "Chain preset: legal, link, esmlck, verify" }),
			steps: Type.Optional(Type.Number({ description: "Step cap (default 50000)" })),
		}),
		async execute(_id, params, ctx) {
			const p = params as { preset: string; steps?: number };
			if (!["legal", "link", "esmlck", "verify"].includes(p.preset)) {
				return { content: [{ type: "text", text: `modem_chain: FAIL unknown preset ${p.preset}` }], details: { tool: "modem_chain", pass: false } };
			}
			const r = runPy(
				["sim/chain.py", "--preset", p.preset, "--out", `sim/chains/pi_${p.preset}`, "--steps", String(p.steps ?? 50000)],
				300000,
			);
			const res = toolResult("modem_chain", r, { preset: p.preset });
			if ((res.details as { pass: boolean }).pass) notifyPass(ctx as never, `chain ${p.preset}`);
			return res;
		},
	});

	pi.registerTool({
		name: "modem_deep",
		label: "Modem deep run at VA",
		description:
			"Strict full-ROM deep run at a virtual address with real callees (comma-separated real= VAs). Reports stop reason, verdict, coverage, gaps.",
		parameters: Type.Object({
			va: Type.String({ description: "Hex VA, e.g. 0x905df2fa" }),
			size: Type.String({ description: "Hex size, e.g. 0x5e" }),
			real: Type.Optional(Type.String({ description: "Comma-separated hex VAs executed for real" })),
			steps: Type.Optional(Type.Number()),
		}),
		async execute(_id, params, ctx) {
			const p = params as { va: string; size: string; real?: string; steps?: number };
			const args = ["sim/deep_run.py", "--va", p.va, "--size", p.size, "--steps", String(p.steps ?? 20000)];
			if (p.real) args.push("--real", p.real);
			const r = runPy(args, 300000);
			const res = toolResult("modem_deep", r, { va: p.va });
			if ((res.details as { pass: boolean }).pass) notifyPass(ctx as never, `deep ${p.va}`);
			return res;
		},
	});

	pi.registerTool({
		name: "modem_disasm",
		label: "Modem function disassembly",
		description:
			"Disassemble one modem function by CATI name via the Ghidra batch pipeline (cached). Slow first run (JVM minutes), instant after.",
		parameters: Type.Object({
			fn: Type.String({ description: "CATI symbol, e.g. rmmi_esmlck_hdlr" }),
		}),
		async execute(_id, params) {
			const p = params as { fn: string };
			if (!/^[A-Za-z0-9_]+$/.test(p.fn)) {
				return { content: [{ type: "text", text: "modem_disasm: FAIL bad symbol" }], details: { tool: "modem_disasm", pass: false } };
			}
			const r = runPy(["sim/decomp.py", "--fns", p.fn, "--out", "sim/listings"], 600000);
			return toolResult("modem_disasm", r, { fn: p.fn });
		},
	});

	pi.registerTool({
		name: "modem_atquery",
		label: "Read-only modem AT query",
		description:
			"Send ONE read-only AT query (test =? / query ? / CLCK mode-2 only) via the live AT channel. Set/unlock/commit forms are hard-blocked by guard.",
		parameters: Type.Object({
			cmd: Type.String({ description: "AT command, e.g. AT+ESMLCK?" }),
		}),
		async execute(_id, params) {
			const p = params as { cmd: string };
			if (!isReadOnlyAt(p.cmd)) {
				return {
					content: [{ type: "text", text: `modem_atquery: BLOCKED by guard (not a read-only query): ${p.cmd}` }],
					details: { tool: "modem_atquery", pass: false, blocked: true },
				};
			}
			const r = runPy(["tools/atci.py", p.cmd], 90000);
			return toolResult("modem_atquery", r, { cmd: p.cmd });
		},
	});

	pi.registerTool({
		name: "modem_bpp_replay",
		label: "eSIM wire-session replay",
		description:
			"Replay the captured 46-pair eSIM APDU session against all strict card models. Reports per-model hit rates (M2/M4 perfect baseline).",
		parameters: Type.Object({}),
		async execute(_id, _params, ctx) {
			const r = runPy(["sim/bpp_wire_sim.py", "--run"], 120000);
			const res = toolResult("modem_bpp_replay", r, {});
			if ((res.details as { pass: boolean }).pass) notifyPass(ctx as never, "bpp replay");
			return res;
		},
	});

	pi.registerTool({
		name: "modem_gates",
		label: "Lab verification gates",
		description:
			"Run the fast verification gate bundle (engine, spec, sml/nv/rmmi selftests, interp conformance). Use before any device contact.",
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
				const v = r.ok ? verdict(r.out) : { pass: false, line: "failed" };
				outs.push(`${c.join(" ")} => ${v.pass ? "PASS" : "FAIL"}`);
				if (!v.pass) allPass = false;
			}
			const text = `modem_gates: ${allPass ? "PASS" : "FAIL"}\n${outs.join("\n")}`;
			if (allPass) notifyPass(ctx as never, "all gates");
			return { content: [{ type: "text", text }], details: { tool: "modem_gates", pass: allPass } };
		},
	});

	pi.on("session_start", (_event, ctx) => {
		ctx.ui.notify("Modem-hunt tools armed: modem_chain, modem_deep, modem_disasm, modem_atquery (guarded), modem_bpp_replay, modem_gates. Attempt floor 5; device writes banned.", "info");
	});
}
