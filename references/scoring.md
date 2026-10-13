# Scoring

The Before and After scores are only comparable because these rules never change between them. `scripts/findings.py` applies them; this page explains them.

## Severity

Each finding gets one severity, based on CVSS 3.1, then one fintech adjustment.

| Severity | CVSS 3.1 | Plain meaning | Fix target |
|---|---|---|---|
| Critical | 9.0 to 10.0 | Money can be stolen or created, another customer's account taken over, or identity or financial data read at scale | Before launch, no exceptions |
| High | 7.0 to 8.9 | Serious abuse with some effort: acting as another user or business, bypassing a PIN or approval, reading someone else's records | Before launch |
| Medium | 4.0 to 6.9 | Real weakness with limited impact or unusual conditions | Before launch, or a dated plan signed off |
| Low | 0.1 to 3.9 | Minor weakness or best-practice gap | After launch, scheduled |
| Informational | 0.0 | Observation or hardening advice | Optional |

**Fintech adjustment:** a finding that touches money movement, a PIN or credential that authorises money, a credit or loan decision, or government identity and financial data (identity numbers, statements, credit reports) moves one level up, capped at Critical. Set `"bump": true` and say why in `bump_reason`. The base severity stays on record.

## Confidence

| Confidence | Meaning | Counts toward score |
|---|---|---|
| confirmed | Seen in code and reachable, or shown on staging | 100% |
| likely | Strong evidence, one link not proven | 50% |
| unconfirmed | Worth checking, not yet shown | 0% (listed only) |

## Deductions

Each module and each control domain starts at 100 and loses points for its findings, floor 0.

| Severity | Points |
|---|---|
| Critical | 40 |
| High | 20 |
| Medium | 8 |
| Low | 3 |
| Informational | 0 |

**Status in the After report**

| Status | Deduction kept |
|---|---|
| fixed (and retest passed) | 0% |
| fixed (not yet retested) | 25% |
| mitigated | 50% |
| accepted (signed off, reason recorded) | 75% |
| open | 100% |

The Before report scores every finding found in the Before phase as open, whatever its status today, so the Before score never moves after it is published.

## Grades

| Score | Grade | Reading |
|---|---|---|
| 90 to 100 | A | Launch ready |
| 75 to 89 | B | Acceptable, minor items tracked |
| 60 to 74 | C | Fix before launch |
| 40 to 59 | D | Significant exposure |
| 0 to 39 | F | Not safe to launch |

## Overall scores

- **Bug bounty:** weighted average of module scores (weights in `modules-and-domains.md`).
- **Security review:** weighted average of control-domain scores, plus the **Risk Exposure Index** (REI): the sum of the deductions still counted. REI shows the size of what is left even when grades are already at zero, so progress is visible from the first fix.

## Launch gate

Pass only when both hold:
1. No Critical or High finding at confirmed or likely confidence still carries a deduction. Open, mitigated, accepted, and fixed-but-not-retested all still carry one.
2. No module and no domain is below grade C.

So a Critical or High must be fixed and retested to pass. If the team believes a High is really a Medium once a control is in place, change its severity with the reasoning recorded (`findings.py edit`), rather than accepting it.

## Worked example

Wallet module Before: one High and two Medium. 100 - 20 - 8 - 8 = 64, grade C.
After: High fixed and retested, one Medium fixed and retested, one Medium mitigated. 100 - 0 - 0 - 4 = 96, grade A. Change +32.
