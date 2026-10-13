---
name: fintech-security-audit
description: Run a bug bounty and security review on a fintech codebase (wallets, transfers, cards, savings, lending, KYC, payment webhooks, staff back office), score it with fixed rules, and produce Before, After and summary reports with a clear launch decision. Use when the user asks for a security audit, bug bounty, pentest-style review, launch readiness check or retest of a fintech, payments, banking, lending or wallet product.
---

# Fintech security audit

You are running a structured security audit of a fintech product. The work produces five reports from one findings database:

1. Bug bounty, Before (findings grouped by product module)
2. Security review, Before (findings by severity and control domain, threat model, attack chains, OWASP map)
3. Bug bounty, After
4. Security review, After
5. Summary (one to two pages: scores before and after, fixed, accepted, launch decision)

Every finding is stored once in `audit/findings.json` and carries both a module (bug bounty view) and a control domain (security view). Reports are generated from it with `scripts/findings.py`. Never hand-edit a generated report: change the database and render again.

**Paths:** `scripts/` and `references/` are in this skill's own folder (the folder holding this SKILL.md), not in the user's project. Call scripts by their full path, for example `python3 ~/.claude/skills/fintech-security-audit/scripts/findings.py`, and run them from the root of the project being audited so `audit/` is created there. In the examples below, `scripts/` is short for that full path. Check that `audit/` is git-ignored in the audited project and suggest adding it if not.

Read these before starting:
- `references/safety.md`: the rules that apply to every step. Non-negotiable.
- `references/scoring.md`: severity, deductions, grades and the launch gate.
- `references/modules-and-domains.md`: default modules, control domains and weights.
- `references/checklists.md`: what to look for, per area, in fintech code.
- `references/writing-findings.md`: how a finding is worded.

## Step 0. Authorisation and scope

Before reading any code, ask the user, in one message:

1. Do you own this code, or have written permission to test it?
2. Which environments may be used? (local, staging; production is never tested)
3. Depth: **Quick** (top risks only), **Standard** (full Before reports) or **Deep** (Standard plus tool scans and a retest).
4. Platforms in scope (for example API, web app, mobile app, admin back office, partner portals, public site).
5. Product name to print on the reports.

Do not continue without a clear yes to question 1. Record the answers with `findings.py init` (see below).

## Step 1. Map the product

Work out, briefly and from the code:
- Stack, repos, how each platform talks to the API.
- Every way money moves in and out (top-ups, transfers, card charges, payouts, disbursements, repayments, interest, refunds, fees) and which provider handles each.
- Entry points: customer routes, staff routes, partner routes, webhooks, file uploads, deep links, scheduled jobs, AI or document parsers.
- Who the attackers are: anonymous, customer, business member, partner, staff insider, stolen phone, leaked credential, compromised provider.
- Sensitive assets: balances, keys, database credentials, identity numbers, statements, credit reports, sessions, PINs.

Choose the modules that exist in this product from `references/modules-and-domains.md`, drop the rest, add product-specific ones if needed, and initialise:

```bash
python3 scripts/findings.py init --product "Acme Pay" --environment "Staging" \
  --platforms "API, Web app, Mobile app, Admin" --depth standard \
  --modules AUTH,KYC,WAL,CARD,SAV,LOAN,LPAY,BIZ,HOOK,ADMIN,NOTIF,FILE,PUB,MOB
```

Write the threat model (attackers, assets, entry points) to a JSON file and load it with `findings.py meta --file threat.json` (shape in `references/writing-findings.md`).

## Step 2. Hunt

Go module by module using `references/checklists.md`. For each module:
- Read the routes, controllers, services and the screens that call them. Follow money and identity data end to end.
- Record what you reviewed and what you did not reach: `findings.py cover --module WAL --reviewed "src/services/wallet/*, transfer routes" --gap "statement PDF generator not read"`.
- Record each finding as JSON and add it: `findings.py add --file f.json` (one object or a list). Shape and wording rules are in `references/writing-findings.md`.

If you can launch subagents, hunt modules in parallel: one subagent per one to three modules, each given the safety rules, the checklist for its modules, and the finding JSON shape, and each returning findings as JSON only. You then add them. Quick depth: skip parallel hunting; cover authentication, money movement, access control and webhooks only, and stop at the top ten risks.

## Step 3. Verify

Subagents and first passes over-rate. Before any report is written:
- Re-read the code for **every Critical and High** yourself and confirm it is real, current and reachable. Then `findings.py verify ID --by-hand`.
- Set `confidence` honestly: `confirmed` (seen in code or reproduced on staging), `likely` (strong evidence, one link unproven), `unconfirmed` (an idea worth checking). Unconfirmed findings are listed but not scored.
- Merge duplicates: the same root cause is one finding with one module and one domain, not two findings.
- Check that nothing you report was already fixed in the current code.

## Step 4. Tool evidence (Standard optional, Deep required)

```bash
bash scripts/scan.sh /path/to/repo [https://staging.example.com ...]
```

It runs what is installed: dependency audit (npm, pnpm, yarn, pip), secret scanning of the working tree and git history (gitleaks if present, otherwise a pattern scan that prints masked hits only), semgrep if present, and security header checks against the staging URLs given. Output goes to `audit/evidence/`. Turn real hits into findings; ignore noise. Never run it against production URLs.

## Step 5. Security review extras

- **Attack chains:** combine findings that together give a bigger outcome (for example guessable sign-in code + no PIN lockout + no alert = wallet drained unnoticed). Add with `findings.py chain --file chains.json`.
- **OWASP Top 10:** give each finding its `owasp` categories; the map is generated.

## Step 6. Render the Before reports

```bash
python3 scripts/findings.py render --phase before --out audit/reports
```

This writes `bug-bounty-before.md` and `security-review-before.md`, and Word copies when `pandoc` is installed. Read both once, end to end, as the reader would. Fix wording in the database, not in the files, and render again.

Present the results to the user in plain words: overall grades, the launch gate result, the top five risks, and the order you suggest fixing them in. Group fixes into batches that share a root cause.

## Step 7. Fix and retest

The user (or you, if asked) fixes findings. For each fix:
- `findings.py status ID --status fixed --note "what changed, where" ` (or `mitigated` / `accepted` with the reason and who accepted it).
- Suggest a small automated test that would fail if the problem came back, and add it when you are making the fix.

Retest mode: `findings.py retest` lists every finding marked fixed or mitigated that has not been rechecked. Recheck only those, against the current code or staging, then `findings.py verify ID --retest pass` (or `fail`, which reopens it). New issues found while retesting are added with `"found_phase": "after"`.

## Step 8. Render the After reports and the summary

```bash
python3 scripts/findings.py render --phase after --out audit/reports
python3 scripts/findings.py render --phase summary --out audit/reports
```

The summary is for a boss or board: scores before and after, what was fixed, what was accepted and by whom, what is still open, and the launch decision from the gate. Keep it to two pages.

## Commands

| Command | What it does |
|---|---|
| `init` | Create `audit/findings.json` with product, scope and modules |
| `meta --file` | Load threat model, scope notes, method notes |
| `add --file` | Add findings (validated, secrets masked) |
| `edit ID --file` | Change fields of a finding |
| `status ID --status` | fixed / mitigated / accepted / open, with a note |
| `verify ID` | `--by-hand` for the Step 3 check, `--retest pass|fail` for Step 7 |
| `cover --module` | Record what was reviewed and the gaps |
| `chain --file` | Add attack chains |
| `list` | Filter by `--status`, `--severity`, `--module`, `--domain` |
| `score --phase` | Print scores and the gate |
| `retest` | List fixes waiting for a recheck |
| `render --phase` | before / after / summary |

Run `python3 scripts/findings.py --help` for options. Python 3.9+ standard library only.
