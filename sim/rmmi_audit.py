#!/usr/bin/env python3
"""rmmi_audit.py — RMMI AT-parser cluster sweep (local-only, no device).

Reads sim/listings/*.jsonl produced by sim/decomp.py (exact DONE-match),
resolves BALC flows to CATI names, flags indirect branches, string/parse
helpers, AT-text pointer roles, length fields and attacker-length loops.

New files only under sim/. No device contact.
"""
from __future__ import annotations
import json
import re
from pathlib import Path

SIM = Path(__file__).resolve().parent
REPO = SIM.parent
import sys
sys.path.insert(0, str(SIM))
from emu_engine import load_cati

TARGETS = [
 "rmmi_general_command_parsing",
 "rmmi_find_cmd_class",
 "rmmi_basic_cmd_processor",
 "rmmi_extended_cmd_processor",
 "rmmi_extended_command_analyzer",
 "rmmi_comptue_extended_cmd_hash_value",
 "rmmi_basic_command_analyzer",
 "rmmi_set_cmd_class_and_index",
 "rmmi_compute_basic_cmd_hash_value",
 "rmmi_esmlck_hdlr",
 "rmmi_esmlrsu_hdlr",
 "rmmi_esmlrsuf_hdlr",
 "rmmi_esmlgen_hdlr",
 "rmmi_ecrrst_hdlr",
 "rmmi_ecsmlck_hdlr",
 "rmmi_eslblob_hdlr",
 "rmmi_eslblobf_hdlr",
 "rmmi_ersukey_hdlr",
 "rmmi_clck_hdlr",
 "rmmi_tfn_handler",
 "rmmi_sml_parse_imsi",
 "rmmi_sml_parse_gid",
 "rmmi_sml_parse_binary_gid",
 "rmmi_sml_add_data",
 "rmmi_sml_add_data_op07",
 "rmmi_sml_add_data_op08",
 "rmmi_sml_add_data_op12",
 "rmmi_sml_get_data",
 "rmmi_sml_get_data_op07",
 "rmmi_sml_get_data_op08_rsu",
 "rmmi_sml_get_data_op12",
 "rmmi_sml_get_crrst_data",
 "rmmi_sml_raw_data_to_string",
 "rmmi_clck_interrogate_rsp_fmttr",
 "rmmi_parse_op07_rsu_factory_cmd",
 "rmmi_parse_op08_rsu_cmd",
 "rmmi_parse_op08_rsu_factory_cmd",
 "rmmi_parse_op12_rsu_factory_cmd",
 "rmmi_parse_op12t_rsu_cmd",
 "rmmi_parse_op12t_rsu_factory_cmd",
 "rmmi_parse_op129_rsu_cmd",
 "rmmi_op12_rsu_hdlr",
]

HELPER_KEYS = ["strcpy","strncpy","strcat","strncat","strcmp","strncmp","strlen",
 "sprintf","snprintf","vsprintf","sscanf","atoi","atol","strtoul","strtol",
 "memcpy","memmove","memset","memcmp","strchr","strstr","strtok","isdigit",
 "isalpha","toupper","tolower","kal_mem","rmmi_sml","l4c_smu","smu_","sml_",
 "custom_sml","malloc","kal_get_buffer","get_buffer"]

INDIRECT_RE = re.compile(r"\b(JALRC|JALRC\.HB|BRSC|BALRSC|JRC|JR|JALR)\b", re.I)
LOAD_RE = re.compile(r"\b(LB|LBU|LH|LHU|LW|LD|SB|SH|SW|LBUX|SBX|LWXS|LWPC|SWPC)\b[^;]*\((a[0-7]|s[0-7]|fp|zero|t[0-9]|v[01])\)", re.I)
ARGUSE_RE = re.compile(r"\b(a[0-3])\b")
BACKBR_RE = re.compile(r",\s*(0x[0-9a-fA-F]+)\s*$")
ABS_RE = re.compile(r"0[xX][0-9a-fA-F]+")


def load_listing(name):
    p = SIM / "listings" / f"{name}.jsonl"
    head = None
    recs = []
    with p.open(encoding="utf-8") as f:
        for line in f:
            try:
                o = json.loads(line)
            except ValueError:
                continue
            if isinstance(o, dict) and o.get("kind") == "header":
                head = o
            elif isinstance(o, dict) and "text" in o:
                recs.append(o)
    return head, recs


def build_index(cati):
    # sorted by start for containment lookup
    items = sorted(((s, e, n) for n, (s, e) in cati.items()))
    starts = [s for s, e, n in items]
    return items


def resolve(va, items):
    # binary search containment
    lo, hi = 0, len(items) - 1
    best = None
    while lo <= hi:
        mid = (lo + hi) // 2
        s, e, n = items[mid]
        if va < s:
            hi = mid - 1
        elif va >= e:
            lo = mid + 1
        else:
            return n, s, e
    return None, None, None


def audit_one(name, cati, items):
    head, recs = load_listing(name)
    if head is None:
        return {"name": name, "error": "no listing"}
    va0 = head["va"]; size = head["size"]
    n = len(recs)
    span = sum(r["size"] for r in recs)
    # arg register roles: first 12 insns mentioning a0-a3 + loads via aX
    arg_hits = {f"a{i}": [] for i in range(4)}
    at_ptr_cands = {}
    for r in recs[:16]:
        for m in ARGUSE_RE.finditer(r["text"]):
            reg = m.group(1)
            if reg in arg_hits and len(arg_hits[reg]) < 6:
                arg_hits[reg].append((r["va"], r["text"]))
        lm = LOAD_RE.search(r["text"])
        if lm:
            base = lm.group(2)
            if base in ("a0","a1","a2","a3"):
                at_ptr_cands.setdefault(base, []).append((r["va"], r["text"]))
    # full-scan AT-text derefs (byte loads off aX anywhere)
    byte_derefs = {}
    for r in recs:
        t = r["text"]
        if re.search(r"\bLB[U]?\b", t, re.I):
            m2 = re.search(r"\((a[0-3]|s[0-7]|fp)\)", t)
            if m2:
                byte_derefs.setdefault(m2.group(1), []).append((r["va"], t))
    # helper calls: BALC flows resolved
    helpers = []
    for r in recs:
        for fl in r.get("flows", []):
            nm, s, e = resolve(fl, items)
            tag = nm if nm else f"UNK_{fl:#x}"
            helpers.append({"at": r["va"], "text": r["text"], "target": fl, "name": tag})
    # string/parse helper subset
    parse_hits = [h for h in helpers if any(k.lower() in (h["name"] or "").lower() for k in HELPER_KEYS)]
    # indirect branches
    indirect = []
    for r in recs:
        m = INDIRECT_RE.search(r["text"])
        if m:
            # register source = last reg token
            regs = re.findall(r"\b(a[0-7]|s[0-7]|t[0-9]|v[01]|ra|fp|zero)\b", r["text"])
            indirect.append({"va": r["va"], "text": r["text"], "op": m.group(1), "regs": regs})
    # backward-branch loops
    loops = []
    for r in recs:
        m = BACKBR_RE.search(r["text"])
        if m:
            try:
                tgt = int(m.group(1), 16)
            except ValueError:
                continue
            if tgt < r["va"] and tgt >= va0:
                loops.append({"at": r["va"], "text": r["text"], "target": tgt, "back": r["va"] - tgt})
    # length-ish ops: SLTIU/SLTI + ANDI 0xff + strlen flows + SEQI
    lenops = []
    for r in recs:
        t = r["text"]
        if re.search(r"\b(SLTIU|SLTI|SEQI|ANDI|BGEIUC|BLTIUC|BNEIC|BEQIC)\b", t):
            lenops.append((r["va"], t))
    return {
        "name": name, "va": va0, "size": size, "n": n, "span": span,
        "done_n": head.get("n"), "arg_hits": arg_hits, "at_ptr_cands": at_ptr_cands,
        "byte_derefs": {k: v[:8] for k, v in byte_derefs.items()},
        "helpers": helpers, "parse_hits": parse_hits, "indirect": indirect,
        "loops": loops, "lenops": lenops[:24], "recs": recs,
    }


def main():
    cati = load_cati()
    items = build_index(cati)
    out = SIM / "rmmi_audit.jsonl"
    with out.open("w", encoding="utf-8") as f:
        for nm in TARGETS:
            try:
                a = audit_one(nm, cati, items)
                # strip recs for file (keep separately readable)
                recs = a.pop("recs", [])
                f.write(json.dumps(a) + "\n")
                print(f"{nm:42s} va={a['va']:#x} size={a['size']} n={a['n']} span={a['span']} helpers={len(a['helpers'])} parse={len(a['parse_hits'])} indirect={len(a['indirect'])} loops={len(a['loops'])}")
            except Exception as e:
                print(f"{nm}: ERROR {e}")
                f.write(json.dumps({"name": nm, "error": str(e)}) + "\n")
    print(f"wrote {out}")

if __name__ == "__main__":
    main()
