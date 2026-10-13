# fintech-security-audit

A Claude skill that audits a fintech codebase the way a careful security team would, and tells you plainly whether it is safe to launch.

## Why I built this

I've spent the last seven years building fintech products.

Before AI, we wrote every line by hand. We had peer reviews, checklists and release meetings, and we still shipped bugs. Some of them were security holes: a transfer that could run twice, an endpoint that showed one customer another customer's data, a key that ended up in a log file. Nobody was careless. Money software is just hard, and the mistakes hide in the places nobody thinks to look.

Now we ship in a day what used to take a month. AI writes a lot of that code, and it writes it fast and confidently. The volume went up ten times. The number of people reviewing it didn't. Every new endpoint, webhook and background job is another place for money to leak or data to slip out, and a quick skim in a pull request won't find most of it.

So security matters more now, not less.

The method in this skill comes from a real pre-launch audit of a fintech product: a bug bounty that went module by module, and a security review sorted by severity. The first pass turned up a long list, some of it serious. The team fixed it in batches, retested, and the product went from failing to passing in three days.

The method worked, but running it was messy. Findings lived in two reports that had to be kept in sync by hand. Scores were hard to compare. Retesting meant redoing work. This skill is that process cleaned up, so I can run it again on the next product, and so you can run it on yours.

## What it does

You point it at a codebase. It works through the product the way an attacker and an auditor would, then writes up what it found.

It looks at the things that actually hurt fintech companies:

- Money moving twice, or not at all, or to the wrong place
- Customers seeing or changing each other's accounts
- Sign-in, codes and PINs that can be guessed or skipped
- Staff tools with more power than they should have
- Webhooks from payment providers that can be faked
- Keys and personal data (BVN, NIN, card and account numbers) leaking into logs, errors or files
- Outdated packages with known holes

## What you get

Five reports, written for people, not just engineers:

1. **Bug bounty, before.** Every issue, grouped by part of the product (wallets, transfers, loans, savings, sign-in, and so on).
2. **Security review, before.** The same codebase seen by severity, with the areas of control it covers and the attack paths that chain small issues into big ones.
3. **Bug bounty, after.** Rerun once you have fixed things.
4. **Security review, after.** Same.
5. **A one or two page summary** for your boss or your board: the score before and after, what was fixed, what you chose to accept, and a clear launch or don't launch.

Every finding is stored once. Mark it fixed and it updates everywhere. The scoring rules never change between before and after, so the improvement you show is real.

## How it scores

Each finding gets a severity from Critical to Informational, using CVSS with one extra rule: anything touching money, PINs, loan decisions or identity data is bumped up a level. Each severity takes points off 100, and the result is a letter grade.

To pass, there must be no open Critical or High findings. Fixed items count fully. Items you've decided to live with count partly, and the report says so.

## How to use it

Install it as a Claude skill, open your project, and ask:

> Run a fintech security audit on this codebase.

It will ask you to confirm you own the code or are allowed to test it. Then it asks how deep to go:

- **Quick:** the top risks only, in about an hour.
- **Standard:** the full before reports.
- **Deep:** standard, plus dependency and secret scans, header checks, and a retest after you fix things.

When you have fixed some findings, ask it to retest. It only rechecks what you changed and writes the after reports for you.

## Ground rules it follows

- It never runs anything against production. It reads code and tests on staging or local copies.
- It hides keys, passwords and personal data in everything it writes.
- It describes each problem, why it matters and how to fix it. It never writes step-by-step attack instructions.
- It checks every Critical and High finding by hand before reporting it. AI reviewers over-rate things, and a false alarm wastes a team's day.

## Who it's for

Small fintech teams without a security department. Founders about to launch. Engineers who are shipping fast with AI and want a second pair of eyes that knows where money software breaks.

It is not a replacement for a professional penetration test before you handle real money at scale. It is the thing you run every week so the pen testers find less.

---

Made by Kelvin. Seven years of moving money around.
