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
| Security | Plain HTTP, or insecure assets on a secure page |

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
