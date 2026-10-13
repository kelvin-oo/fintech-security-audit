# Writing findings

Reports are read by founders, managers and engineers. Write for all three: plain words first, file paths for the engineer.

## Rules

- **Title:** the problem and its consequence in one line. "Parallel transfers can exceed the daily limit", not "Race condition in TransferService".
- **What happens:** two to five sentences, or a short numbered list when several weaknesses combine. Point at files and routes (`src/services/transfer.ts:120`).
- **Why it matters:** who could do what, and what it costs the business or the customer.
- **Fix:** the concrete change. One to four sentences.
- No step-by-step attack instructions, no payloads, no exploit code (see `safety.md`).
- No real customer data and no secrets, masked or not, beyond a key type and prefix.
- One root cause, one finding. If the same cause shows up in two modules, pick the main one and mention the other in `affected`.

## Finding JSON

```json
{
  "title": "Parallel transfers can exceed the daily limit",
  "module": "WAL",
  "domain": "D3",
  "severity": "Medium",
  "bump": true,
  "bump_reason": "moves customer money",
  "cvss": "6.5",
  "vector": "AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N",
  "confidence": "confirmed",
  "affected": ["API: POST /transfers", "src/services/transfer.service.ts:88-140"],
  "what": "The daily total is read, compared and then the transfer is created, in three separate steps. Two transfers sent together both pass the check.",
  "impact": "A customer, or someone using a stolen session, can move more than the daily limit in one burst.",
  "fix": "Check and record the daily total in the same transaction with a row lock, or use a conditional update on a per-day counter.",
  "owasp": ["A04"],
  "found_by": "Code review",
  "found_phase": "before"
}
```

- `module` or `domain` may be `null` when a finding truly has no place in that view (for example an infrastructure issue with no product module). It then appears only in the other report.
- `severity` is the base severity. With `bump: true` the reported severity is one level higher.
- `found_phase` is `before` unless the finding was discovered during the retest.
- `owasp` uses 2021 codes `A01` to `A10`.

## Threat model JSON (`findings.py meta --file`)

```json
{
  "scope_note": "Staging only, payment test keys. Production not touched.",
  "method_note": "Code review of all repos, staging requests for confirmation, tool scans.",
  "attackers": [{"profile": "Customer", "access": "Own account", "wants": "Money through races or rounding"}],
  "assets": [{"asset": "Wallet balances", "where": "Postgres", "why": "Direct money"}],
  "entry_points": [{"entry": "Webhooks", "who": "Anyone with the URL", "boundary": "Provider to ledger"}]
}
```

## Attack chain JSON (`findings.py chain --file`)

```json
[{"name": "Account takeover to money out", "steps": ["BB-AUTH-01", "SEC-D1-03"], "attacker": "Anonymous", "outcome": "Wallet drained, unnoticed", "severity": "Critical"}]
```

## Status notes

- `fixed`: what changed and where, and how it was checked. "Daily total now checked under a row lock (transfer.service.ts); 20 parallel transfers on staging, limit held."
- `mitigated`: what is reduced and what remains.
- `accepted`: why, and who accepted it (a name or role).
