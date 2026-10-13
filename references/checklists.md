# Fintech checklists

What to look for, by module. These are prompts for reading code, not a script to run. Each line is a question; a "no" is a candidate finding.

## AUTH: Authentication and sessions

- Are sign-in codes generated with a cryptographic generator, single use, short-lived, and cancelled when a new one is sent?
- Is there a per-account limit on wrong code, password and PIN guesses that holds under parallel requests (counted before checking, atomically)?
- Do rate limits key on an address the client cannot set? (`X-Forwarded-For` read directly is a classic miss; check how many proxies sit in front.)
- Can a user end all their sessions? Does freezing or deleting a user, or downgrading a staff role, take effect immediately, or does an old token keep working until it expires?
- Are session tokens, codes and invite links stored hashed, not in plain form?
- Is the session token kept out of reach of page scripts (httpOnly cookie, not localStorage)? Do staff sessions time out when idle?
- Are there leftover master logins, test bypasses, fixed codes or "dev mode" switches that a single setting could turn on in production?
- Do sign-in and sign-up reveal which emails, phones or identity numbers have accounts?
- Is there a working, rate-limited password or PIN recovery for every user type, including staff?

## WAL: Wallet and transfers

- Does every transfer carry an idempotency key that the server requires, so a double tap or retry cannot send twice?
- Is the balance check and debit one atomic step (row lock or conditional update), so parallel transfers cannot overdraw or exceed the daily limit?
- When the provider times out or returns an unclear answer, is the transfer held as pending and reconciled, rather than refunded while it may still complete?
- Is a reversal after success handled (money returned to the customer)?
- Are daily and per-transaction limits enforced on the server, in the right time zone, under concurrency?
- Is there a minimum amount and a check that amounts are positive with at most two decimals?
- Is the PIN required on the server for every outgoing movement, not just in the UI?
- Can a business member send statements or money beyond their role?
- Is there an alert when the payout balance at the provider runs low?

## CARD: Cards and top-ups

- Is a card payment credited only after confirming with the provider, for the amount actually charged, to the wallet that started it?
- Can a payment made outside the app (a raw provider link or reference) be credited to any wallet?
- Are late charges (completed after the app gave up) credited or refunded, not lost?
- Are recurring card debits idempotent and limited?

## LPAY: Loan disbursement, repayments and pay-off

- Can a loan be disbursed twice (double click, retry, two staff at once)? Is disbursement guarded by status in the same transaction?
- Are repayments posted exactly once per provider event? Is a debit that times out treated as unknown and reconciled, not as failed and retried?
- Is the amount owed calculated on the server with exact decimal arithmetic, and never taken from the client?
- Can a borrower pay off with less than owed through rounding or a stale quote?
- Are mandate or direct-debit references unique and safe to retry?

## HOOK: Webhooks and payment integrations

- Is every webhook signature verified with a constant-time comparison, against the raw body, with the right secret per environment?
- Is the event stored before acknowledging, processed once (unique event ID), and is the amount and status confirmed with the provider API rather than trusted from the payload?
- Does an unknown reference fail safely? Does the handler return quickly and do heavy work in a queue?
- Can staging receive production webhooks, or the reverse?

## KYC: Onboarding and identity checks

- Is the identity check tied to the person signing up (name and date of birth match, phone matches, liveness or selfie), or can someone pass with another person's identity number?
- Can a business pass company checks with another company's registration number?
- Are identity numbers and photos stored encrypted or at least access-logged, and kept out of logs and error reports?
- Are verification results reusable by the same user only?

## LOAN: Application, assessment and approval

- Can a borrower influence their own assessment: edit income after the check, upload a doctored statement that is trusted blindly, inject instructions into an AI parser?
- Are approval and disbursement limited to the right staff roles on the server?
- Can a borrower see or change another borrower's application, guarantors or documents by changing an ID?
- Do guarantor and consent links expire, work once, and confirm the right person?

## SAV: Savings and investments

- Can withdrawals sent at the same time each pay out?
- Do scheduled jobs (interest, auto-save, maturity) race with customer actions, debit twice, or pay interest twice?
- Is interest calculated on the server with exact decimals, for the time actually elapsed? Are there test settings that compress time and could be left on?
- Can a locked plan be broken early without the penalty?

## BIZ: Business accounts, team and roles

- Is every business action checked against the member's role on the server, for that business?
- Can a removed or downgraded member still act? Can an invite be accepted by the wrong person?
- Can one member attach another member's personal bank account or identity without their consent?

## ADMIN: Staff back office

- Does every staff route check the staff role on the server, not just the menu?
- Can any staff member read identity numbers, statements and credit reports in full? Is viewing logged?
- Can staff plant script in comments, notes or names that runs in a colleague's browser?
- Are high-impact actions (approve, disburse, refund, change limits, freeze) logged with who did them, and is self-approval blocked?
- Is staff sign-in rate limited with lockout, and does it avoid confirming which part (password or code) was wrong?

## PART: Partner, agent or broker portal

- Can a partner pull credit reports or identity data on people without their consent?
- Is a partner limited to their own clients on every route?

## NOTIF: Notifications and email

- Can user input reach email templates unescaped (HTML or link injection)?
- Do emails and SMS leak sensitive data (full account numbers, balances, codes in subject lines)?
- Can someone trigger unlimited emails or SMS to any address (cost and harassment)?

## FILE: Files and documents

- Are uploads checked by content, size limited, and stored privately? Are download links short-lived and tied to the owner?
- Can one user fetch another's document by guessing a key or ID?
- Are old files cleaned up per the retention policy?

## PUB: Public website and public endpoints

- Are calculators, rate endpoints and lead forms rate limited and free of internal data?
- Are framework versions current (public RCEs in web frameworks are common)?
- Are security headers set: HSTS, CSP, frame-ancestors, nosniff, referrer policy?

## MOB: Mobile app specifics

- Are tokens and PINs kept in the platform's secure storage, not plain storage?
- Are live keys or secrets embedded in the app bundle?
- Is request and response logging off in release builds?
- Are deep links validated before they open screens or prefill payments?
- Does the app lock or ask again after time in the background?

## Cross-cutting (feed D4, D5, D7, D8, D9, D10)

- Keys: are any live keys in git history, logs, error messages or a developer laptop's .env that also points at production? Are staging and production keys separate?
- Data: are identity numbers, statements and bureau reports written to logs or sent to AI providers? Is there consent and a basis for that?
- Config: CORS limited to own domains, errors without stack traces, TLS everywhere.
- Infra: databases and caches not reachable from the internet, backups with point-in-time restore, least-privilege database users.
- Monitoring: alerts for failed payouts, low provider balances, repeated failed sign-ins, admin actions; a second alert channel.
- Dependencies: known vulnerable packages, unpinned versions, install scripts.
