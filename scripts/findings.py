#!/usr/bin/env python3
"""Findings database and report generator for fintech-security-audit.

One JSON file holds every finding once. Each finding carries a product module
(bug bounty view) and a control domain (security review view), so marking it
fixed updates both reports. Reports are generated, never hand-edited.

Python 3.9+, standard library only.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

# ── Fixed rules (see references/scoring.md). Never change between phases. ──

SEVERITIES = ["Informational", "Low", "Medium", "High", "Critical"]
POINTS = {"Critical": 40, "High": 20, "Medium": 8, "Low": 3, "Informational": 0}
CONFIDENCE = {"confirmed": 1.0, "likely": 0.5, "unconfirmed": 0.0}
STATUSES = ["open", "fixed", "mitigated", "accepted"]
GRADES = [(90, "A", "Launch ready"), (75, "B", "Acceptable, minor items tracked"),
          (60, "C", "Fix before launch"), (40, "D", "Significant exposure"),
          (0, "F", "Not safe to launch")]

DEFAULT_MODULES = {
    "AUTH": ("Authentication and sessions", 3),
    "WAL": ("Wallet and transfers", 3),
    "CARD": ("Cards and top-ups", 3),
    "LPAY": ("Loans: disbursement, repayments and pay-off", 3),
    "HOOK": ("Webhooks and payment integrations", 3),
    "KYC": ("Onboarding and identity checks", 2),
    "LOAN": ("Loans: application, assessment and approval", 2),
    "SAV": ("Savings and investments", 2),
    "BIZ": ("Business accounts, team and roles", 2),
    "ADMIN": ("Staff back office", 2),
    "PART": ("Partner, agent or broker portal", 2),
    "NOTIF": ("Notifications and email", 1),
    "FILE": ("Files and documents", 1),
    "PUB": ("Public website and public endpoints", 1),
    "MOB": ("Mobile app specifics", 1),
}

DOMAINS = {
    "D1": ("Authentication and sessions", 3),
    "D2": ("Access control", 3),
    "D3": ("Payment and transaction integrity", 3),
    "D4": ("Secrets, keys and cryptography", 3),
    "D5": ("Data protection and privacy", 3),
    "D6": ("Input validation and injection", 2),
    "D7": ("API and web configuration", 2),
    "D8": ("Infrastructure and environments", 2),
    "D9": ("Logging, monitoring and response", 2),
    "D10": ("Third parties and dependencies", 1),
    "D11": ("Mobile application", 1),
}

OWASP = {
    "A01": "Broken Access Control", "A02": "Cryptographic Failures", "A03": "Injection",
    "A04": "Insecure Design", "A05": "Security Misconfiguration",
    "A06": "Vulnerable and Outdated Components",
    "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Integrity Failures",
    "A09": "Security Logging and Monitoring Failures", "A10": "Server-Side Request Forgery",
}

TEXT_FIELDS = ["title", "what", "impact", "fix", "bump_reason", "status_note", "found_by"]

# ── Masking: a safety net so secrets and personal numbers never reach a report ──

MASKS = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S), lambda m: "[private key removed]"),
    (re.compile(r"\b((?:sk|pk|rk|whsec)_(?:live|test)_)[A-Za-z0-9]{4,}"), lambda m: m.group(1) + "****"),
    (re.compile(r"\b(gh[pousr]_)[A-Za-z0-9]{16,}"), lambda m: m.group(1) + "****"),
    (re.compile(r"\b(xox[abpr]-)[A-Za-z0-9-]{10,}"), lambda m: m.group(1) + "****"),
    (re.compile(r"\b(AKIA)[0-9A-Z]{16}\b"), lambda m: m.group(1) + "****"),
    (re.compile(r"\b(AIza)[0-9A-Za-z_-]{30,}"), lambda m: m.group(1) + "****"),
    (re.compile(r"\beyJ[\w-]{8,}\.[\w-]{8,}\.[\w-]{4,}"), lambda m: "eyJ****(token)"),
    (re.compile(r"\b([a-z][a-z0-9+.-]*://)[^\s:/@]+:[^\s@/]+@"), lambda m: m.group(1) + "****:****@"),
    (re.compile(r"(?i)\b((?:api[_-]?key|secret|password|passwd|token)\s*[:=]\s*[\"']?)[^\s\"',;]{6,}"), lambda m: m.group(1) + "****"),
    (re.compile(r"\b[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b"), lambda m: "****@" + m.group(1)),
    (re.compile(r"(?<![\w.:/-])\d{10,19}(?!\w|[.:/-]\w)"), lambda m: "*" * len(m.group(0))),
]


def mask(text):
    if not isinstance(text, str):
        return text
    for rx, rep in MASKS:
        text = rx.sub(rep, text)
    return text


def mask_finding(f: dict) -> dict:
    for k in TEXT_FIELDS:
        if k in f:
            f[k] = mask(f[k])
    if isinstance(f.get("affected"), list):
        f["affected"] = [mask(a) for a in f["affected"]]
    return f


# ── Storage ──

def today() -> str:
    return dt.date.today().isoformat()


def load(path: Path) -> dict:
    if not path.exists():
        sys.exit(f"No findings database at {path}. Run: findings.py init ...")
    return json.loads(path.read_text(encoding="utf-8"))


def save(path: Path, db: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(db, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def find(db: dict, fid: str) -> dict:
    for f in db["findings"]:
        if fid in (f.get("bb_id"), f.get("sec_id")):
            return f
    sys.exit(f"No finding with ID {fid}")


# ── Rules applied ──

def reported_severity(f: dict) -> str:
    i = SEVERITIES.index(f["severity"])
    return SEVERITIES[min(i + 1, 4)] if f.get("bump") else SEVERITIES[i]


def in_phase(f: dict, phase: str) -> bool:
    return phase != "before" or f.get("found_phase", "before") == "before"


def status_factor(f: dict, phase: str) -> float:
    if phase == "before":
        return 1.0
    s = f.get("status", "open")
    if s == "fixed":
        return 0.0 if f.get("retest") == "pass" else 0.25
    return {"mitigated": 0.5, "accepted": 0.75}.get(s, 1.0)


def deduction(f: dict, phase: str) -> float:
    if not in_phase(f, phase):
        return 0.0
    return POINTS[reported_severity(f)] * CONFIDENCE[f.get("confidence", "confirmed")] * status_factor(f, phase)


def grade(score: float):
    for floor, letter, reading in GRADES:
        if score >= floor:
            return letter, reading
    return "F", GRADES[-1][2]


def area_scores(db: dict, phase: str, key: str) -> dict:
    """Score per module (key='module') or domain (key='domain')."""
    areas = db["modules"] if key == "module" else {k: {"name": v[0], "weight": v[1]} for k, v in DOMAINS.items()}
    out = {}
    for aid, a in areas.items():
        fs = [f for f in db["findings"] if f.get(key) == aid and in_phase(f, phase)]
        counts = {s: 0 for s in SEVERITIES}
        for f in fs:
            counts[reported_severity(f)] += 1
        score = max(0.0, 100.0 - sum(deduction(f, phase) for f in fs))
        out[aid] = {"name": a["name"], "weight": a["weight"], "counts": counts,
                    "score": round(score), "grade": grade(score)[0]}
    return out


def overall(scores: dict) -> int:
    w = sum(a["weight"] for a in scores.values())
    return round(sum(a["score"] * a["weight"] for a in scores.values()) / w) if w else 100


def risk_exposure(db: dict, phase: str) -> int:
    return round(sum(deduction(f, phase) for f in db["findings"]))


def gate(db: dict, phase: str) -> tuple[bool, list[str]]:
    reasons = []
    blockers = [f for f in db["findings"]
                if reported_severity(f) in ("Critical", "High") and deduction(f, phase) > 0]
    if blockers:
        reasons.append(f"{len(blockers)} Critical or High finding(s) still counted: "
                       + ", ".join(label(f) for f in blockers[:12]) + (" ..." if len(blockers) > 12 else ""))
    for key, title in (("module", "module"), ("domain", "domain")):
        low = [f"{aid} ({a['score']})" for aid, a in area_scores(db, phase, key).items() if a["score"] < 60]
        if low:
            reasons.append(f"{title}s below grade C: " + ", ".join(low))
    return (not reasons), reasons


def label(f: dict) -> str:
    return f.get("bb_id") or f.get("sec_id") or "?"


def severity_counts(db: dict, phase: str, only_counted=False, key=None) -> dict:
    c = {s: 0 for s in SEVERITIES}
    for f in db["findings"]:
        if key and not f.get(key):
            continue
        if in_phase(f, phase) and (not only_counted or deduction(f, phase) > 0):
            c[reported_severity(f)] += 1
    return c


# ── Commands ──

def git_exposed(path: Path):
    """The repo root when `path` sits in a git repo and is not ignored, else None.
    Findings describe weaknesses, so they must never be committed by accident."""
    probe = path.resolve().parent
    while not probe.exists():
        probe = probe.parent
    top = subprocess.run(["git", "-C", str(probe), "rev-parse", "--show-toplevel"], capture_output=True, text=True)
    if top.returncode != 0:
        return None
    root = top.stdout.strip()
    ignored = subprocess.run(["git", "-C", root, "check-ignore", "-q", str(path.resolve())], capture_output=True)
    return None if ignored.returncode == 0 else root


def cmd_init(a, path: Path):
    if path.exists() and not a.force:
        sys.exit(f"{path} already exists. Use --force to start over.")
    root = shutil.which("git") and git_exposed(path)
    if root and not a.allow_tracked:
        sys.exit(f"{path} is inside the git repository at {root} and is not ignored.\n"
                 f"Findings describe weaknesses and must not be committed. Ignore the folder locally (never committed):\n"
                 f"  echo '/{os.path.relpath(path.resolve().parent, root)}/' >> \"{root}/.git/info/exclude\"\n"
                 f"or add it to .gitignore, then run init again.")
    mods = {}
    for mid in [m.strip().upper() for m in a.modules.split(",") if m.strip()]:
        if mid in DEFAULT_MODULES:
            mods[mid] = {"name": DEFAULT_MODULES[mid][0], "weight": DEFAULT_MODULES[mid][1]}
        else:
            sys.exit(f"Unknown module {mid}. Add custom ones with --custom-module 'ID:Name:weight'.")
    for cm in a.custom_module or []:
        mid, name, weight = cm.split(":", 2)
        mods[mid.strip().upper()] = {"name": name.strip(), "weight": int(weight)}
    db = {
        "meta": {"product": a.product, "environment": a.environment, "platforms": a.platforms,
                 "depth": a.depth, "started": today(), "prepared_by": a.prepared_by,
                 "scope_note": "", "method_note": "", "attackers": [], "assets": [], "entry_points": []},
        "modules": mods, "findings": [], "chains": [], "coverage": {},
    }
    save(path, db)
    print(f"Created {path} with {len(mods)} modules.")


def cmd_meta(a, path: Path):
    db = load(path)
    data = json.loads(Path(a.file).read_text(encoding="utf-8"))
    for k, v in data.items():
        db["meta"][k] = mask(v) if isinstance(v, str) else v
    save(path, db)
    print("Meta updated: " + ", ".join(data.keys()))


def next_id(db: dict, prefix: str, field: str) -> str:
    nums = [int(f[field].rsplit("-", 1)[1]) for f in db["findings"]
            if f.get(field, "").startswith(prefix + "-")]
    return f"{prefix}-{(max(nums) + 1 if nums else 1):02d}"


def validate(f: dict, db: dict) -> list[str]:
    errs = []
    for k in ("title", "severity", "what", "impact", "fix"):
        if not f.get(k):
            errs.append(f"missing {k}")
    if f.get("severity") not in SEVERITIES:
        errs.append(f"severity must be one of {SEVERITIES}")
    if f.get("module") is None and f.get("domain") is None:
        errs.append("needs a module or a domain (or both)")
    if f.get("module") is not None and f["module"] not in db["modules"]:
        errs.append(f"module {f['module']} not in this audit ({', '.join(db['modules'])})")
    if f.get("domain") is not None and f["domain"] not in DOMAINS:
        errs.append(f"domain must be one of {', '.join(DOMAINS)}")
    if f.get("confidence", "confirmed") not in CONFIDENCE:
        errs.append(f"confidence must be one of {list(CONFIDENCE)}")
    if f.get("bump") and not f.get("bump_reason"):
        errs.append("bump needs a bump_reason")
    for o in f.get("owasp", []):
        if o not in OWASP:
            errs.append(f"unknown OWASP code {o}")
    if f.get("found_phase", "before") not in ("before", "after"):
        errs.append("found_phase must be before or after")
    return errs


def cmd_add(a, path: Path):
    db = load(path)
    data = json.loads(Path(a.file).read_text(encoding="utf-8"))
    items = data if isinstance(data, list) else [data]
    added, problems = [], []
    for i, f in enumerate(items):
        errs = validate(f, db)
        if errs:
            problems.append(f"item {i + 1} ({f.get('title', 'untitled')}): " + "; ".join(errs))
            continue
        f = mask_finding(dict(f))
        f.setdefault("confidence", "confirmed")
        f.setdefault("found_phase", "before")
        f.setdefault("found_on", today())
        f.setdefault("affected", [])
        f.setdefault("owasp", [])
        f["status"] = "open"
        f["verified_by_hand"] = False
        f["retest"] = None
        if f.get("module"):
            f["bb_id"] = next_id(db, f"BB-{f['module']}", "bb_id")
        if f.get("domain"):
            f["sec_id"] = next_id(db, f"SEC-{f['domain']}", "sec_id")
        db["findings"].append(f)
        added.append(" / ".join(x for x in (f.get("bb_id"), f.get("sec_id")) if x))
    save(path, db)
    for x in added:
        print("Added", x)
    if problems:
        print("\nNot added:\n  " + "\n  ".join(problems))
        sys.exit(1)


def cmd_edit(a, path: Path):
    db = load(path)
    f = find(db, a.id)
    changes = json.loads(Path(a.file).read_text(encoding="utf-8"))
    for k in ("bb_id", "sec_id", "module", "domain"):
        if k in changes:
            sys.exit(f"{k} cannot be edited (IDs are permanent). Add a new finding and mark this one accepted with a note instead.")
    merged = {**f, **changes}
    errs = validate(merged, db)
    if errs:
        sys.exit("; ".join(errs))
    f.update(mask_finding(changes))
    save(path, db)
    print("Updated", label(f))


def cmd_status(a, path: Path):
    db = load(path)
    f = find(db, a.id)
    if a.status in ("accepted", "mitigated", "fixed") and not a.note:
        sys.exit(f"{a.status} needs --note (what changed, or why and who accepted it)")
    f["status"] = a.status
    f["status_note"] = mask(a.note or "")
    f["status_date"] = a.date or today()
    f["retest"] = None
    save(path, db)
    print(f"{label(f)} is now {a.status}" + ("; recheck it in retest mode" if a.status in ("fixed", "mitigated") else ""))


def cmd_verify(a, path: Path):
    db = load(path)
    f = find(db, a.id)
    if a.by_hand:
        f["verified_by_hand"] = True
        print(f"{label(f)} verified by hand")
    if a.retest:
        if f.get("status") not in ("fixed", "mitigated"):
            sys.exit(f"{label(f)} is {f.get('status')}; only fixed or mitigated findings are retested")
        f["retest"] = a.retest
        f["retest_date"] = today()
        if a.retest == "fail":
            f["status"] = "open"
            f["status_note"] = (f.get("status_note") or "") + f" Retest failed {today()}, reopened."
        print(f"{label(f)} retest {a.retest}" + (", reopened" if a.retest == "fail" else ""))
    save(path, db)


def cmd_cover(a, path: Path):
    db = load(path)
    key = a.module.upper()
    if key not in db["modules"] and key not in DOMAINS:
        sys.exit(f"Unknown module or domain {key}")
    c = db["coverage"].setdefault(key, {"reviewed": [], "gaps": []})
    if a.reviewed:
        c["reviewed"].append(mask(a.reviewed))
    if a.gap:
        c["gaps"].append(mask(a.gap))
    save(path, db)
    print("Coverage recorded for", key)


def cmd_chain(a, path: Path):
    db = load(path)
    data = json.loads(Path(a.file).read_text(encoding="utf-8"))
    for ch in (data if isinstance(data, list) else [data]):
        for step in ch["steps"]:
            find(db, step)
        db["chains"].append({k: mask(v) if isinstance(v, str) else v for k, v in ch.items()})
    save(path, db)
    print(f"{len(db['chains'])} chain(s) on record")


def cmd_list(a, path: Path):
    db = load(path)
    for f in sorted(db["findings"], key=sort_key):
        if a.status and f.get("status") != a.status:
            continue
        if a.severity and reported_severity(f) != a.severity:
            continue
        if a.module and f.get("module") != a.module.upper():
            continue
        if a.domain and f.get("domain") != a.domain.upper():
            continue
        ids = " / ".join(x for x in (f.get("bb_id"), f.get("sec_id")) if x)
        flags = ("" if f.get("verified_by_hand") else " [not hand-verified]") if reported_severity(f) in ("Critical", "High") else ""
        print(f"{ids:24} {reported_severity(f):13} {f.get('status'):9} {f.get('confidence'):11} {f['title']}{flags}")


def cmd_score(a, path: Path):
    db = load(path)
    p = a.phase
    for key, title in (("module", "Bug bounty modules"), ("domain", "Security domains")):
        s = area_scores(db, p, key)
        print(f"\n{title} ({p})")
        for aid, x in s.items():
            c = x["counts"]
            print(f"  {aid:6} w{x['weight']} {x['score']:>3} {x['grade']}  C{c['Critical']} H{c['High']} M{c['Medium']} L{c['Low']} I{c['Informational']}  {x['name']}")
        print(f"  Overall: {overall(s)} ({grade(overall(s))[0]})")
    ok, reasons = gate(db, p)
    print(f"\nRisk Exposure Index: {risk_exposure(db, p)}")
    print("Launch gate: " + ("PASS" if ok else "FAIL"))
    for r in reasons:
        print("  - " + r)
    unverified = [label(f) for f in db["findings"] if reported_severity(f) in ("Critical", "High") and not f.get("verified_by_hand")]
    if unverified:
        print("\nNot yet verified by hand (do this before rendering): " + ", ".join(unverified))


def cmd_retest(a, path: Path):
    db = load(path)
    todo = [f for f in db["findings"] if f.get("status") in ("fixed", "mitigated") and not f.get("retest")]
    if not todo:
        print("Nothing waiting for a retest.")
        return
    for f in sorted(todo, key=sort_key):
        print(f"{label(f):14} {reported_severity(f):9} {f['title']}")
        print(f"{'':14} fix: {f.get('status_note', '')}")
        print(f"{'':14} check: {', '.join(f.get('affected', [])) or 'see finding'}")


# ── Rendering ──

def sort_key(f: dict):
    return (-SEVERITIES.index(reported_severity(f)), label(f))


def esc(s) -> str:
    return mask(str(s if s is not None else "")).replace("|", "\\|").replace("\n", " ")


def status_text(f: dict) -> str:
    s = f.get("status", "open")
    if s == "fixed":
        return {"pass": "Fixed and retested", "fail": "Retest failed"}.get(f.get("retest") or "", "Fixed, awaiting retest")
    return {"open": "Open", "mitigated": "Mitigated", "accepted": "Accepted risk"}[s]


def header(db: dict, report: str) -> list[str]:
    m = db["meta"]
    return ["| | |", "|---|---|",
            f"| **Product** | {esc(m['product'])} |",
            f"| **Report** | {report} |",
            f"| **Date** | {today()} |",
            f"| **Environment** | {esc(m['environment'])} |",
            f"| **Platforms in scope** | {esc(m['platforms'])} |",
            f"| **Depth** | {m['depth'].capitalize()} |",
            f"| **Prepared by** | {esc(m.get('prepared_by') or 'TBC')} |",
            "| **Scoring** | Fixed rules, identical for Before and After (see Appendix) |", ""]


def counts_line(c: dict) -> str:
    return " · ".join(f"{c[s]} {s}" for s in reversed(SEVERITIES))


def top_risks(db: dict, phase: str, key: str, n=5) -> list[dict]:
    weight = {k: v["weight"] for k, v in db["modules"].items()}
    fs = [f for f in db["findings"] if f.get(key) and in_phase(f, phase) and deduction(f, phase) > 0]
    return sorted(fs, key=lambda f: (-SEVERITIES.index(reported_severity(f)), -weight.get(f.get("module"), 0), label(f)))[:n]


def detail(f: dict, phase: str, view: str) -> list[str]:
    primary = f.get("bb_id") if view == "bb" else f.get("sec_id")
    other = f.get("sec_id") if view == "bb" else f.get("bb_id")
    sev = reported_severity(f)
    sev_cell = f"**{sev}**" + (f" (raised from {f['severity']}: {esc(f['bump_reason'])})" if f.get("bump") else "")
    rows = ["| | |", "|---|---|", f"| **Severity** | {sev_cell} |"]
    if f.get("cvss"):
        rows.append(f"| **CVSS 3.1** | {esc(f['cvss'])}" + (f" (`{esc(f['vector'])}`)" if f.get("vector") else "") + " |")
    rows.append(f"| **Confidence** | {f.get('confidence', 'confirmed').capitalize()} |")
    if f.get("affected"):
        rows.append(f"| **Affected** | {'; '.join(esc(x) for x in f['affected'])} |")
    if f.get("owasp"):
        rows.append(f"| **OWASP** | {', '.join(f'{o} {OWASP[o]}' for o in f['owasp'])} |")
    if other:
        rows.append(f"| **Same finding in the other report** | {other} |")
    if f.get("found_by"):
        rows.append(f"| **Found by** | {esc(f['found_by'])}, {f.get('found_on', '')} |")
    out = [f"### {primary}: {esc(f['title'])}", ""] + rows + [
        "", f"**What happens:** {mask(f['what'])}", "",
        f"**Why it matters:** {mask(f['impact'])}", "",
        f"**Recommended fix:** {mask(f['fix'])}", ""]
    if phase == "after":
        note = f" {mask(f['status_note'])}" if f.get("status_note") else ""
        out += [f"**Status:** {status_text(f)}" + (f" ({f['status_date']})" if f.get("status_date") else "") + f".{note}", ""]
    out += ["---", ""]
    return out


def score_table(db: dict, phase: str, key: str) -> list[str]:
    now = area_scores(db, phase, key)
    before = area_scores(db, "before", key) if phase == "after" else None
    label_col = "Module" if key == "module" else "Control domain"
    if before:
        lines = [f"| ID | {label_col} | Weight | Counted now (C/H/M/L/I) | Before | After | Change | Grade |",
                 "|---|---|:-:|:-:|:-:|:-:|:-:|:-:|"]
    else:
        lines = [f"| ID | {label_col} | Weight | Findings (C/H/M/L/I) | Score | Grade |", "|---|---|:-:|:-:|:-:|:-:|"]
    for aid, x in now.items():
        if before:
            counted = {s: 0 for s in SEVERITIES}
            for f in db["findings"]:
                if f.get(key) == aid and deduction(f, phase) > 0:
                    counted[reported_severity(f)] += 1
            cc = "/".join(str(counted[s]) for s in reversed(SEVERITIES))
            ch = x["score"] - before[aid]["score"]
            lines.append(f"| {aid} | {x['name']} | {x['weight']} | {cc} | {before[aid]['score']} | {x['score']} | {'+' if ch > 0 else ''}{ch} | {x['grade']} |")
        else:
            cc = "/".join(str(x["counts"][s]) for s in reversed(SEVERITIES))
            lines.append(f"| {aid} | {x['name']} | {x['weight']} | {cc} | {x['score']} | {x['grade']} |")
    o = overall(now)
    if before:
        ob = overall(before)
        lines.append(f"| | **Overall (weighted)** | | | **{ob}** | **{o}** | **{'+' if o - ob > 0 else ''}{o - ob}** | **{grade(o)[0]}** |")
    else:
        lines.append(f"| | **Overall (weighted)** | | | **{o}** | **{grade(o)[0]}** |")
    return lines + [""]


def scorecard(db: dict, phase: str, key: str) -> list[str]:
    o = overall(area_scores(db, phase, key))
    ok, reasons = gate(db, phase)
    lines = ["| | " + phase.capitalize() + " |", "|---|---|",
             f"| **Overall weighted score** | **{o} / 100** |",
             f"| **Grade** | **{grade(o)[0]}**, " + (grade(o)[1].lower() if ok or grade(o)[0] != "A" else "high score, but the launch gate fails") + " |"]
    if key == "domain":
        lines.append(f"| **Risk Exposure Index** | {risk_exposure(db, phase)} (lower is better) |")
    lines.append(f"| **Launch gate** | **{'Pass' if ok else 'Fail'}** |")
    lines += ["", "**Findings by severity:** " + counts_line(severity_counts(db, phase, key=key)), ""]
    if not ok:
        lines += ["**Why the gate fails:**", ""] + [f"- {esc(r)}" for r in reasons] + [""]
    return lines


def scoring_appendix() -> list[str]:
    return ["## Appendix: Scoring rules", "",
            "Severity follows CVSS 3.1, raised one level when a finding touches money movement, a PIN or credential that authorises money, a credit decision, or identity and financial data. "
            "Each module and domain starts at 100 and loses 40 per Critical, 20 per High, 8 per Medium and 3 per Low. "
            "Likely findings count half; unconfirmed ones are listed but not scored. "
            "In the After report a fixed and retested finding counts 0%, fixed but not yet retested 25%, mitigated 50%, accepted 75%, open 100%. "
            "Grades: A 90 and above, B 75, C 60, D 40, F below 40. "
            "The launch gate passes only when no Critical or High finding still counts and no module or domain is below C.", ""]


def coverage_section(db: dict) -> list[str]:
    if not db["coverage"]:
        return ["No coverage recorded.", ""]
    lines = ["| Area | Reviewed | Not reached |", "|---|---|---|"]
    for k, c in db["coverage"].items():
        lines.append(f"| {k} | {esc('; '.join(c['reviewed'])) or 'TBC'} | {esc('; '.join(c['gaps'])) or 'None recorded'} |")
    return lines + [""]


def render_bug_bounty(db: dict, phase: str) -> str:
    title = "Before" if phase == "before" else "After"
    m = db["meta"]
    L = [f"# Bug Bounty Report: {title} Remediation", ""] + header(db, f"Bug bounty, {title.lower()} remediation")
    L += ["## 1. Executive Summary", ""]
    c = severity_counts(db, phase, key="module")
    total = sum(c.values())
    L += [f"We reviewed {len(db['modules'])} modules of {esc(m['product'])} and recorded **{total} findings**: {counts_line(c)}.", ""]
    L += ["### Scorecard", ""] + scorecard(db, phase, "module")
    tr = top_risks(db, phase, "module")
    if tr:
        L += ["### Top risks" if phase == "before" else "### Top remaining risks", ""]
        L += [f"{i}. **{label(f)}** ({reported_severity(f)}): {esc(f['title'])}" for i, f in enumerate(tr, 1)] + [""]
    L += ["### Module scoreboard", ""] + score_table(db, phase, "module")
    L += ["## 2. Scope and Approach", ""]
    if m.get("scope_note"):
        L += [esc(m["scope_note"]), ""]
    if m.get("method_note"):
        L += [esc(m["method_note"]), ""]
    L += ["### Coverage", ""] + coverage_section(db)
    L += ["## 3. Findings by Module", ""]
    for mid, mod in db["modules"].items():
        fs = sorted([f for f in db["findings"] if f.get("module") == mid and in_phase(f, phase)], key=sort_key)
        L += [f"### {mid}: {mod['name']} · Weight {mod['weight']}", ""]
        if not fs:
            L += ["No findings.", ""]
            continue
        hdr = "| ID | Finding | Severity |" + (" Status |" if phase == "after" else "")
        L += [hdr, "|---|---|---|" + ("---|" if phase == "after" else "")]
        for f in fs:
            L.append(f"| {f['bb_id']} | {esc(f['title'])} | {reported_severity(f)} |" + (f" {status_text(f)} |" if phase == "after" else ""))
        L.append("")
    L += ["## 4. Finding Details", ""]
    for f in sorted([f for f in db["findings"] if f.get("bb_id") and in_phase(f, phase)], key=lambda f: (list(db["modules"]).index(f["module"]), f["bb_id"])):
        L += detail(f, phase, "bb")
    L += scoring_appendix()
    return "\n".join(L)


def render_security(db: dict, phase: str) -> str:
    title = "Before" if phase == "before" else "After"
    m = db["meta"]
    L = [f"# Security Review: {title} Remediation", ""] + header(db, f"Security review, {title.lower()} remediation")
    L += ["## 1. Executive Summary", ""] + scorecard(db, phase, "domain")
    tr = top_risks(db, phase, "domain")
    if tr:
        L += ["### Top risks" if phase == "before" else "### Top remaining risks", ""]
        L += [f"{i}. **{f.get('sec_id') or label(f)}** ({reported_severity(f)}): {esc(f['title'])}" for i, f in enumerate(tr, 1)] + [""]
    L += ["## 2. Control Domain Scores", ""] + score_table(db, phase, "domain")
    L += ["## 3. Threat Model", ""]
    for key, ttl, cols in (("attackers", "Attacker profiles", ("profile", "access", "wants")),
                           ("assets", "Sensitive assets", ("asset", "where", "why")),
                           ("entry_points", "Entry points and trust boundaries", ("entry", "who", "boundary"))):
        rows = m.get(key) or []
        L += [f"### {ttl}", ""]
        if not rows:
            L += ["TBC", ""]
            continue
        L += ["| " + " | ".join(c.replace("_", " ").capitalize() for c in cols) + " |", "|" + "---|" * len(cols)]
        L += ["| " + " | ".join(esc(r.get(c, "")) for c in cols) + " |" for r in rows] + [""]
    L += ["## 4. OWASP Top 10 (2021) Map", "", "| Category | Findings | Result |", "|---|---|:-:|"]
    for code, name in OWASP.items():
        fs = [f for f in db["findings"] if code in f.get("owasp", []) and in_phase(f, phase)]
        open_ = [f for f in fs if deduction(f, phase) > 0]
        ids = ", ".join(f.get("sec_id") or label(f) for f in sorted(fs, key=sort_key)) or "None found"
        L.append(f"| {code} {name} | {ids} | {'Fail' if open_ else 'Pass'} |")
    L += ["", "## 5. Attack Chains", ""]
    if db["chains"]:
        L += ["Several smaller findings combined. Fixing any one step breaks the chain.", "",
              "| Chain | Steps | Attacker | Outcome | Severity |" + (" Status |" if phase == "after" else ""),
              "|---|---|---|---|:-:|" + (":-:|" if phase == "after" else "")]
        for ch in db["chains"]:
            row = f"| {esc(ch['name'])} | {' + '.join(ch['steps'])} | {esc(ch.get('attacker', ''))} | {esc(ch.get('outcome', ''))} | {esc(ch.get('severity', ''))} |"
            if phase == "after":
                broken = any(deduction(find(db, s), phase) == 0 for s in ch["steps"])
                row += f" {'Broken' if broken else 'Still possible'} |"
            L.append(row)
        L.append("")
    else:
        L += ["None recorded.", ""]
    L += ["## 6. Findings by Severity", ""]
    for sev in reversed(SEVERITIES):
        fs = sorted([f for f in db["findings"] if f.get("sec_id") and in_phase(f, phase) and reported_severity(f) == sev], key=lambda f: f["sec_id"])
        L += [f"### {sev} ({len(fs)})", ""]
        L += [f"- **{f['sec_id']}**: {esc(f['title'])}" + (f" · {status_text(f)}" if phase == "after" else "") for f in fs] or ["None."]
        L.append("")
    L += ["## 7. Finding Details", ""]
    for f in sorted([f for f in db["findings"] if f.get("sec_id") and in_phase(f, phase)], key=sort_key):
        L += detail(f, phase, "sec")
    L += ["## Appendix: Coverage", ""] + coverage_section(db) + scoring_appendix()
    return "\n".join(L)


def render_summary(db: dict) -> str:
    m = db["meta"]
    bb_b, bb_a = overall(area_scores(db, "before", "module")), overall(area_scores(db, "after", "module"))
    sr_b, sr_a = overall(area_scores(db, "before", "domain")), overall(area_scores(db, "after", "domain"))
    ok, reasons = gate(db, "after")
    fs = db["findings"]
    fixed = [f for f in fs if f.get("status") == "fixed" and f.get("retest") == "pass"]
    pending = [f for f in fs if f.get("status") == "fixed" and f.get("retest") != "pass"]
    mitigated = [f for f in fs if f.get("status") == "mitigated"]
    accepted = [f for f in fs if f.get("status") == "accepted"]
    open_ = [f for f in fs if f.get("status", "open") == "open"]
    new = [f for f in fs if f.get("found_phase") == "after"]
    L = [f"# Security Audit Summary: {esc(m['product'])}", "",
         f"{today()} · {esc(m['environment'])} · {m['depth'].capitalize()} depth", "",
         "## Decision", "",
         f"**{'Ready to launch' if ok else 'Not ready to launch'}.** " +
         ("No Critical or High finding is left and every area scores C or better." if ok else
          "The launch gate still fails for the reasons below."), ""]
    if not ok:
        L += [f"- {esc(r)}" for r in reasons] + [""]
    L += ["## Scores", "", "| | Before | After | Change |", "|---|:-:|:-:|:-:|",
          f"| Bug bounty | {bb_b} ({grade(bb_b)[0]}) | {bb_a} ({grade(bb_a)[0]}) | {'+' if bb_a - bb_b > 0 else ''}{bb_a - bb_b} |",
          f"| Security review | {sr_b} ({grade(sr_b)[0]}) | {sr_a} ({grade(sr_a)[0]}) | {'+' if sr_a - sr_b > 0 else ''}{sr_a - sr_b} |",
          f"| Risk Exposure Index (lower is better) | {risk_exposure(db, 'before')} | {risk_exposure(db, 'after')} | {risk_exposure(db, 'after') - risk_exposure(db, 'before')} |", "",
          "## What happened", "",
          f"- **Found:** {len([f for f in fs if f.get('found_phase', 'before') == 'before'])} findings at the start ({counts_line(severity_counts(db, 'before'))})" + (f", and {len(new)} more during the retest." if new else "."),
          f"- **Fixed and retested:** {len(fixed)}",
          f"- **Fixed, awaiting retest:** {len(pending)}",
          f"- **Mitigated:** {len(mitigated)}",
          f"- **Accepted as a known risk:** {len(accepted)}",
          f"- **Still open:** {len(open_)}", ""]
    if accepted:
        L += ["## Accepted risks", ""] + [f"- **{label(f)}** ({reported_severity(f)}) {esc(f['title'])}. {esc(f.get('status_note', ''))}" for f in sorted(accepted, key=sort_key)] + [""]
    still = sorted(open_ + pending + mitigated, key=sort_key)
    if still:
        L += ["## Still to do", ""] + [f"- **{label(f)}** ({reported_severity(f)}, {status_text(f).lower()}) {esc(f['title'])}" for f in still[:15]]
        if len(still) > 15:
            L.append(f"- and {len(still) - 15} more of lower severity, listed in the full reports.")
        L.append("")
    L += ["Full detail is in the bug bounty and security review reports, Before and After."]
    return "\n".join(L)


def to_docx(md_path: Path) -> str:
    if not shutil.which("pandoc"):
        return ""
    out = md_path.with_suffix(".docx")
    r = subprocess.run(["pandoc", str(md_path), "-o", str(out)], capture_output=True, text=True)
    return str(out) if r.returncode == 0 else ""


def cmd_render(a, path: Path):
    db = load(path)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    unverified = [label(f) for f in db["findings"] if reported_severity(f) in ("Critical", "High") and not f.get("verified_by_hand")]
    if unverified and not a.allow_unverified:
        sys.exit("These Critical or High findings are not verified by hand yet: " + ", ".join(unverified)
                 + "\nVerify them (findings.py verify ID --by-hand) or pass --allow-unverified for a draft.")
    files = []
    if a.phase in ("before", "after"):
        files.append((out / f"bug-bounty-{a.phase}.md", render_bug_bounty(db, a.phase)))
        files.append((out / f"security-review-{a.phase}.md", render_security(db, a.phase)))
    else:
        files.append((out / "summary.md", render_summary(db)))
    for p, text in files:
        p.write_text(mask(text) + "\n", encoding="utf-8")
        d = "" if a.no_docx else to_docx(p)
        print(f"Wrote {p}" + (f" and {d}" if d else ""))


def main():
    ap = argparse.ArgumentParser(description="Findings database and reports for fintech-security-audit")
    ap.add_argument("--db", default="audit/findings.json", help="path to the findings database")
    sp = ap.add_subparsers(dest="cmd", required=True)

    p = sp.add_parser("init"); p.add_argument("--product", required=True); p.add_argument("--environment", default="Staging")
    p.add_argument("--platforms", default="TBC"); p.add_argument("--depth", choices=["quick", "standard", "deep"], default="standard")
    p.add_argument("--modules", default=",".join(DEFAULT_MODULES)); p.add_argument("--custom-module", action="append")
    p.add_argument("--prepared-by", default=""); p.add_argument("--force", action="store_true")
    p.add_argument("--allow-tracked", action="store_true", help="skip the git-ignore check (not recommended)")
    p = sp.add_parser("meta"); p.add_argument("--file", required=True)
    p = sp.add_parser("add"); p.add_argument("--file", required=True)
    p = sp.add_parser("edit"); p.add_argument("id"); p.add_argument("--file", required=True)
    p = sp.add_parser("status"); p.add_argument("id"); p.add_argument("--status", choices=STATUSES, required=True)
    p.add_argument("--note"); p.add_argument("--date")
    p = sp.add_parser("verify"); p.add_argument("id"); p.add_argument("--by-hand", action="store_true")
    p.add_argument("--retest", choices=["pass", "fail"])
    p = sp.add_parser("cover"); p.add_argument("--module", required=True); p.add_argument("--reviewed"); p.add_argument("--gap")
    p = sp.add_parser("chain"); p.add_argument("--file", required=True)
    p = sp.add_parser("list"); p.add_argument("--status", choices=STATUSES); p.add_argument("--severity", choices=SEVERITIES)
    p.add_argument("--module"); p.add_argument("--domain")
    p = sp.add_parser("score"); p.add_argument("--phase", choices=["before", "after"], default="after")
    sp.add_parser("retest")
    p = sp.add_parser("render"); p.add_argument("--phase", choices=["before", "after", "summary"], required=True)
    p.add_argument("--out", default="audit/reports"); p.add_argument("--no-docx", action="store_true")
    p.add_argument("--allow-unverified", action="store_true")

    a = ap.parse_args()
    path = Path(a.db)
    {"init": cmd_init, "meta": cmd_meta, "add": cmd_add, "edit": cmd_edit, "status": cmd_status,
     "verify": cmd_verify, "cover": cmd_cover, "chain": cmd_chain, "list": cmd_list, "score": cmd_score,
     "retest": cmd_retest, "render": cmd_render}[a.cmd](a, path)


if __name__ == "__main__":
    main()
