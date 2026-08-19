# site-audit

Point it at a website. It loads the page in a real browser as a phone would,
measures what actually happens, and gives you back:

- **findings written for a business owner**, not a developer
- **screenshots** proving each one
- **a first-contact email** drafted from the three worst problems
- **an HTML report** you can attach or send as a link

Built to make cold outreach concrete. "Hi, I'm a web developer looking for
work" gets ignored. "Your homepage loads 16MB and scrolls sideways on an
iPhone, screenshots attached" gets a reply.

## Install

```bash
npm install
npx playwright install chromium
```

## Use

```bash
node audit.js https://example.com
node audit.js example.com --name "Sarah" --from "Owais Khan — owaisikhan.dev"
```

Everything lands in `reports/<domain>/`:

```
report.html        the full write-up, styled, sendable
email.txt          first-contact email using the top three findings
phone.png          how it looks on an iPhone
phone-overflow.png only if the page scrolls sideways — the money shot
desktop.png        how it looks on a laptop
findings.json      raw data, with --json
```

| Flag | Meaning |
|---|---|
| `--name` | Who you're writing to, for the email draft |
| `--from` | Your sign-off |
| `--out` | Output directory (default `reports`) |
| `--json` | Also dump raw findings as JSON |
| `--timeout` | Navigation timeout in ms (default 45000) |

## What it checks

| Check | Catches |
|---|---|
| Page weight | Total download, and the specific files responsible |
| Video weight | Auto-loading background video, the usual worst offender |
| Mobile overflow | Page scrolls sideways on a phone, and which element causes it |
| Dead controls | Buttons made unclickable by CSS, links to `#`, forms with nowhere to send |
| Metadata | Missing title, description, link-preview image, favicon |
| Mobile viewport | Site not set up for phones at all |
| Images | Missing alt text; images served far larger than displayed |
| Tap targets | Buttons too small to hit with a thumb |
| Broken requests | 404s and failed loads |
| JavaScript errors | Scripts throwing, which silently kills everything after them |
| Security headers | Missing HSTS, CSP, clickjacking protection, nosniff, version disclosure |
| Cookies | Session cookies a script can steal (no HttpOnly), or ride (no SameSite/Secure) |
| Passwords | Login form that sends the password without encryption |
| Certificate | Invalid or untrusted TLS certificate |
| Libraries | Front-end libraries whose version has a known, published vulnerability |
| CORS | A wide-open policy that lets any site read logged-in responses |
| Exposed files | (--probe only) A downloadable .git folder or .env file |
| Transport | Plain HTTP, or insecure assets on a secure page |

## Security checks, and where the line is

The security checks are **passive**. They read what the site already returns on
a normal load — its headers, its cookies, the library versions it ships, whether
the login form is encrypted — and report the *conditions* that make an attack
possible. None of them attack anything.

That is a deliberate and important limit. Actively testing whether a site can be
broken into — injection payloads, login-bypass attempts, credential guessing — is
**penetration testing**, and doing it to a site you have not been authorised to
test is a crime in most countries, however good your intentions. Authorisation is
the whole difference: a bug-bounty program or a signed contract grants it; a cold
prospect has not. This tool stays firmly on the passive side of that line so you
can run it on anyone's public site without crossing it.

If you want to do the active side legitimately, that is what bug-bounty programs
are for — they publish a scope and a safe-harbour promise, which is your written
permission. It is a real and respected path; it is just a different activity from
this.

### --probe

`--probe` makes a handful of extra GET requests to well-known exposure points
(`/.git/HEAD`, `/.env`). It still only *reads* — it never exploits — but even
reading another server's files edges toward territory you should only enter on
sites you are allowed to audit. It is off by default for that reason. An exposed
`.git` or `.env` is one of the most serious things you can find (it can hand over
your entire source and your database password), so the check is worth having —
used responsibly.

## It is read-only, deliberately

It loads the page and measures. It never clicks, never submits a form, never
logs in. You can run it against a stranger's site without touching their data
or triggering their contact form.

That is also its main limitation: **a form handled entirely by JavaScript looks
inert to a static scan.** React and similar frameworks attach handlers at the
root of the page rather than to each button, so the scan cannot see them. The
dead-controls finding carries a caveat saying so. Click them yourself before
you send anything.

## Before you send a report to anyone

1. **Open the screenshots.** If a finding is real it will be visible.
2. **Click the controls it flagged.** Rule out the framework limitation above.
3. **Cut anything you cannot defend on a call.** Three findings you are certain
   of beat twelve you are guessing at. One wrong claim ends the conversation.
4. **Audit the live site, not a dev server.** A local `npm run dev` serves
   unminified bundles and will inflate page weight several times over.

## Why the wording is the way it is

Findings avoid developer vocabulary on purpose. "Largest Contentful Paint is
4.2s" means nothing to someone running a dental practice. "Your page takes
eight seconds to appear on a phone, and about half of visitors leave before
three" is the same fact in language that decides whether they reply.

Severity is a judgement about lost business, not technical purity:

- **high** — visitors are actively bouncing or cannot complete an action
- **medium** — quietly costing traffic or conversions
- **low** — worth fixing, not worth leading with

## Licence

MIT.
