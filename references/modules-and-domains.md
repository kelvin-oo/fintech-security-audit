# Modules and control domains

Every finding has one module (where in the product it lives, for the bug bounty report) and one domain (what kind of control failed, for the security review). Drop modules the product does not have. Add product-specific ones with a short ID, a name and a weight.

## Modules (bug bounty view)

Weight 3 = moves money or holds identity. Weight 2 = can lead there. Weight 1 = supporting.

| ID | Module | Weight |
|---|---|:-:|
| AUTH | Authentication and sessions | 3 |
| WAL | Wallet and transfers | 3 |
| CARD | Cards and top-ups | 3 |
| LPAY | Loans: disbursement, repayments and pay-off | 3 |
| HOOK | Webhooks and payment integrations | 3 |
| KYC | Onboarding and identity checks | 2 |
| LOAN | Loans: application, assessment and approval | 2 |
| SAV | Savings and investments | 2 |
| BIZ | Business accounts, team and roles | 2 |
| ADMIN | Staff back office | 2 |
| PART | Partner, agent or broker portal | 2 |
| NOTIF | Notifications and email | 1 |
| FILE | Files and documents | 1 |
| PUB | Public website and public endpoints | 1 |
| MOB | Mobile app specifics | 1 |

## Control domains (security review view)

| ID | Domain | Covers | Weight |
|---|---|---|:-:|
| D1 | Authentication and sessions | Sign-in, codes, PINs, passwords, tokens, lockout, session end | 3 |
| D2 | Access control | Ownership checks, roles, business context, staff separation | 3 |
| D3 | Payment and transaction integrity | Idempotency, atomic balance updates, double spend, races, reconciliation, rounding | 3 |
| D4 | Secrets, keys and cryptography | Key storage and rotation, environment separation, hashing, token signing | 3 |
| D5 | Data protection and privacy | Identity and financial data handling, masking, retention, consent, transfers to processors | 3 |
| D6 | Input validation and injection | SQL and NoSQL, XSS, template and email injection, uploads, SSRF, prompt injection | 2 |
| D7 | API and web configuration | TLS, headers, CORS, rate limits, error handling | 2 |
| D8 | Infrastructure and environments | Hosting, database and storage exposure, staging versus production, backups | 2 |
| D9 | Logging, monitoring and response | Audit trail, alerts, sensitive data in logs, incident readiness | 2 |
| D10 | Third parties and dependencies | Webhook verification, vendor keys, vulnerable packages, AI providers | 1 |
| D11 | Mobile application | Secure storage, embedded keys, release configuration, deep links | 1 |

## IDs

- Bug bounty ID: `BB-<MODULE>-nn`, for example `BB-WAL-03`.
- Security ID: `SEC-<DOMAIN>-nn`, for example `SEC-D3-07`.
- One finding gets both IDs. Either ID works in every command.
