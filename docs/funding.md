# Funding and sponsorship policy (draft)

**Status: draft for the owner to review.** EggMail is open source under the [MIT](../LICENSE-MIT) or [Apache-2.0](../LICENSE-APACHE) license, at your option. Sponsorship is optional and never changes that. Platform facts below are marked **verified** (checked against the platform's own documentation on 2026-10-12) or **unverified** (not confirmed, or taken from a secondary source).

## What sponsorship funds

- **Maintenance:** review, releases, dependency updates, issue triage.
- **Security work:** including the **external security audit** recommended before first production-critical use ([design.md §9.2](design.md#92-in-house-security-review)), fuzzing time and a future bug bounty.
- **Benchmark hardware:** the reproducible, published benchmark runs on identical hardware ([benchmarks.md](benchmarks.md)).
- **Documentation:** guides, runbooks and examples.
- **Project costs:** domain and similar fixed costs, if any appear (the container registry is free for public images; see [release.md](release.md)).

## Policy

1. **Transparency.** Once money is received, publish a short summary of income and how it was used (at least yearly). Where the platform provides a public ledger, point to it; whether a given platform does is **unverified** for the options below.
2. **No feature gating, no priority code.** Sponsors get no features, no private builds, no paid-only options and no priority for their issues or pull requests. The project stays 100% MIT open source. Support and roadmap decisions are not for sale.
3. **Optional recognition.** Sponsors who want it may be listed in the README (name or logo, in a single "Sponsors" list, by tier at most). Listing is opt-in and removable on request. Recognition carries no influence.
4. **No conflicts.** Sponsorship is not a way to buy design decisions; the decisions record ([decisions.md](decisions.md)) stays the place where project decisions are made and explained.

These are a draft policy; the owner decides the final wording.

## Platform options

| Platform | Notes | Status |
|---|---|---|
| **GitHub Sponsors** (primary; `github: [eggspot]`) | Native button on the repository and org page. Organizations can receive sponsorships. See "Setting up GitHub Sponsors for the eggspot organization" below. Fees: GitHub states no fees for sponsorships from personal accounts and a fee of up to 6% (3% card processing, 3% GitHub processing; the card part avoidable by invoice) for sponsorships from organization accounts | Fees and setup steps **verified** |
| **Open Collective** | Needs a **fiscal host** unless the project has its own legal entity: the host holds the money, provides the legal entity and handles taxes, accounting and compliance, and pays approved expenses. Open Source Collective is a host for open source software projects with a 10% host fee (as listed in Open Collective's documentation). Each host sets its own fee. Processing fees are not stated on the pages checked | Host role, Open Source Collective's 10% and the open-source-only restriction **verified**; processing fees and any public-ledger transparency **unverified** |
| **Ko-fi** | Simple one-off tips and optional memberships, run by an individual. A search summary of Ko-fi's own page says 0% platform fee on one-time donations and 5% on shop, membership and commission sales on the free plan (Ko-fi Gold removes that 5%), with payment-processor fees (Stripe or PayPal) on top. Ko-fi's own page returned an access error when fetched, so this is not confirmed first-hand | **Unverified** (secondary); Gold price disagrees between sources |
| **Liberapay** | Recurring donations, non-profit-structured. Its FAQ says it does not take a cut of payments (funded by donations to its own account), but payment-processor fees apply (recent averages about 3% for Stripe and 5% for PayPal; they vary by processor, method, country and currency). Money goes straight to the recipient's Stripe or PayPal account. The FAQ does not say whether teams or organizations can receive donations | Fees **verified** from the FAQ; organization support **unverified** |
| **Stripe** (a payment link under `custom:`) | A direct payment page that the owner runs and accounts for personally (receipts, taxes). Needs a Stripe account in a supported country. Fees and eligibility were not checked | **Unverified** |

`FUNDING.yml` supports one username or slug per external platform and up to four custom URLs (verified in GitHub's documentation). GitHub also describes a Sponsors-for-organizations path with a **fiscal host** as an alternative to a bank account (see below).

## The GitHub button only works once Sponsors is enabled

`.github/FUNDING.yml` contains `github: [eggspot]`. GitHub's documentation describes the file's format and location (the `.github` folder on the default branch) but does **not** say what the button does when the named account has no GitHub Sponsors profile; the expected behavior is that the entry only becomes useful once GitHub Sponsors is enabled and approved for the **eggspot organization** (**unverified**; test it after enabling). Likewise the badge in the README points to `https://github.com/sponsors/eggspot`, which will not show a profile until then.

## Setting up GitHub Sponsors for the eggspot organization

Facts from GitHub's documentation (verified); the account owner has to do these steps.

1. **Eligibility:** the organization must contribute to an open source project and **legally operate in a supported region**; the person setting it up must live in the same supported region. For an unsupported region the route is the waitlist.
2. **Enable two-factor authentication** on the GitHub account used to set up Sponsors (required before the organization can become a sponsored organization).
3. **Join / apply:** after receiving an invitation, join from the organization's Sponsors page, enter contact information, and **request approval**. GitHub reviews the application; the documentation says this may take a few days.
4. **Choose how to be paid** at signup: a **bank account** in a supported region (payouts set up through a Stripe Connect account in the dashboard) **or a fiscal host**. Fiscal-host details can only be set at signup; changing later needs GitHub Support.
5. **Complete the tax form** from the dashboard's Overview page.
6. **Fill in the profile** (short bio, introduction, optional featured repositories and members) and optionally create sponsorship tiers. After approval the profile goes live automatically.

## Owner action items

- [ ] Enable and get approved for **GitHub Sponsors for the eggspot organization** (steps above). Until then the `FUNDING.yml` button and the README badge point at a profile that does not exist yet.
- [ ] Decide the payout route: bank account in a supported region, or a fiscal host (for example Open Source Collective, 10% fee). This is chosen at signup.
- [ ] Optional: enable other platforms. Create the account first, then uncomment and fill the matching line in `.github/FUNDING.yml` (`open_collective`, `ko_fi`, `liberapay`, `custom`). No usernames or URLs have been invented for platforms not named by the owner.
- [ ] Review this policy draft and the README wording.
- [ ] Add sponsors to the README only after they opt in.
- [ ] After enabling Sponsors, open the repository page and confirm the button works.
- [ ] Optional: put one `FUNDING.yml` in the organization's `.github` repository as a default for all repositories (mentioned in a GitHub blog post; **unverified** here).

## Unverified summary

Ko-fi fees and Gold price; Open Collective processing fees and public ledger; Liberapay organization support; Stripe eligibility and fees; the button's behavior without an enabled Sponsors profile; the organization-wide `FUNDING.yml` default; whether any platform offers a public ledger that satisfies the transparency rule.
