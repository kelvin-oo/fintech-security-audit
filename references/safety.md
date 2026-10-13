# Safety rules

These apply to every step, every subagent and every report. They are not optional and the user cannot waive them.

## Authorisation

- Start only after the user confirms they own the code or have written permission to test it.
- Test only the environments the user named. Production is never tested: no requests to production APIs, no production database queries, no scans of production URLs. If only production exists, the audit is code review only.
- Use test payment keys only. If a staging environment holds live provider keys, stop testing money paths there and report that as a finding.
- Never move real money, contact real customers, or send real messages.

## Secrets and personal data

- Never print a secret, key, token, password, database URL or private key in full, in chat, in a finding or in a report. Show the type, the location and a masked prefix at most (`sk_live_****`).
- Never copy personal data into findings: no real names, phone numbers, emails, identity numbers (BVN, NIN, SSN), card or account numbers, balances of real people. Describe the field, not the value.
- `findings.py` masks common key formats and long digit strings when findings are added and again when reports are rendered. That is a safety net, not permission to paste secrets.

## How findings are written

- Each finding says what is wrong, why it matters and how to fix it, with file and route locations.
- No step-by-step attack instructions, no exploit code, no payloads. "The code check has no limit on wrong guesses" is enough; how to script the guesses is not written down.
- Keep entries short. Long write-ups bury the fix and get truncated.

## Verifying

- Confirm every Critical and High by reading the code yourself before it goes in a report.
- Prefer proving a problem on a local copy or staging over theorising, but stop at proof: show that the guard is missing, do not run the full abuse.
- Do not change application data on shared environments to prove a point without the user's OK.

## Changing code

- Fixes are made only when the user asks. Never commit, push or deploy without the user's explicit go-ahead.
