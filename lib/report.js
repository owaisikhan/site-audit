import { fmtBytes } from "./checks.js";

const RANK = { high: 0, medium: 1, low: 2 };
const esc = (s) =>
  String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

// Within a severity band, security findings come first -- an exposed .git or a
// cleartext password is what earns a reply, so it should lead the report and the
// email even when a UX issue shares its severity.
const SECURITY_IDS = new Set([
  "tls-invalid", "no-https", "mixed-content", "password-cleartext",
  "cookie-httponly", "cookie-secure", "cookie-samesite", "cors-wildcard",
  "no-hsts", "no-csp", "clickjacking", "no-nosniff", "version-disclosure",
  "outdated-libraries", "exposed--git-head", "exposed--env", "exposed--git-config",
]);

export function sortFindings(findings) {
  return [...findings].sort((a, b) => {
    if (RANK[a.severity] !== RANK[b.severity]) return RANK[a.severity] - RANK[b.severity];
    return (SECURITY_IDS.has(b.id) ? 1 : 0) - (SECURITY_IDS.has(a.id) ? 1 : 0);
  });
}

export function terminalReport(result) {
  const { url, findings, stats } = result;
  const c = {
    dim: "\x1b[2m", red: "\x1b[31m", yellow: "\x1b[33m", blue: "\x1b[34m",
    green: "\x1b[32m", bold: "\x1b[1m", off: "\x1b[0m",
  };
  const colour = { high: c.red, medium: c.yellow, low: c.blue };
  const lines = [];

  lines.push("");
  lines.push(`${c.bold}${url}${c.off}`);
  lines.push(
    `${c.dim}${fmtBytes(stats.totalBytes)} · ${stats.requests} requests · ` +
      `loaded in ${stats.loadMs}ms · ~${stats.mobileSeconds}s on mobile data${c.off}`
  );
  lines.push("");

  if (!findings.length) {
    lines.push(`${c.green}No significant issues found.${c.off}`);
    lines.push("");
    return lines.join("\n");
  }

  for (const f of sortFindings(findings)) {
    lines.push(`${colour[f.severity]}${c.bold}[${f.severity.toUpperCase()}]${c.off} ${c.bold}${f.title}${c.off}`);
    if (f.detail) lines.push(`${c.dim}${f.detail}${c.off}`);
    lines.push(`  ${f.why}`);
    if (f.caveat) lines.push(`  ${c.dim}Note: ${f.caveat}${c.off}`);
    lines.push("");
  }

  const counts = findings.reduce((a, f) => ((a[f.severity] = (a[f.severity] || 0) + 1), a), {});
  lines.push(
    `${c.bold}${findings.length} ${findings.length === 1 ? "finding" : "findings"}${c.off} — ` +
      `${counts.high || 0} high, ${counts.medium || 0} medium, ${counts.low || 0} low`
  );
  lines.push("");
  return lines.join("\n");
}

/** A first-contact email built from the top three findings. Deliberately short,
 *  specific, and offering the fix rather than asking for a meeting. */
export function outreachEmail(result, { name = "there", from = "" } = {}) {
  const top = sortFindings(result.findings).slice(0, 3);
  if (!top.length) return null;
  const host = new URL(result.url).hostname;

  // Keep the subject short and concrete; long subjects get truncated in the
  // inbox preview, which is the only thing deciding whether it is opened.
  let subject = top[0].title.replace(/^The /, "").replace(/ — .*$/, "");
  if (subject.length > 52) subject = subject.slice(0, 49).trimEnd() + "…";

  // If the lead finding is a security one, open with that framing instead of
  // "costing you enquiries" -- a data-exposure issue is not a marketing problem,
  // and treating it as one reads as either naive or alarmist.
  const leadIsSecurity = SECURITY_IDS.has(top[0].id);
  const intro = leadIsSecurity
    ? `I was looking at ${host} and noticed a couple of things worth flagging — the first is a security issue you'll probably want to fix quickly:`
    : `I was looking at ${host} and spotted a few things that are likely costing you enquiries:`;

  const body = [
    `Subject: ${host} — ${subject.charAt(0).toLowerCase() + subject.slice(1)}`,
    ``,
    `Hi ${name},`,
    ``,
    intro,
    ``,
    ...top.map((f, i) => `${i + 1}. ${f.title}. ${f.why.split(". ")[0].replace(/\.$/, "")}.`),
    ``,
    `I've attached screenshots showing each one on a phone.`,
    ``,
    `I fix exactly this kind of thing. Happy to quote for all three, or if you'd rather`,
    `hand it to whoever built the site, tell them those three points and they'll know`,
    `what to do — no charge either way.`,
    ``,
    `${from}`,
  ];
  return body.join("\n");
}

export function htmlReport(result) {
  const { url, findings, stats, screenshots } = result;
  const host = new URL(url).hostname;
  const counts = findings.reduce((a, f) => ((a[f.severity] = (a[f.severity] || 0) + 1), a), {});

  const rows = sortFindings(findings)
    .map(
      (f) => `
      <article class="f ${f.severity}">
        <header>
          <span class="sev">${f.severity}</span>
          <h3>${esc(f.title)}</h3>
        </header>
        ${f.detail ? `<pre>${esc(f.detail)}</pre>` : ""}
        <p class="why">${esc(f.why)}</p>
        ${f.caveat ? `<p class="caveat">${esc(f.caveat)}</p>` : ""}
      </article>`
    )
    .join("");

  const shots = (screenshots || [])
    .map(
      (s) => `<figure><img src="${esc(s.file)}" alt="${esc(s.label)}"><figcaption>${esc(s.label)}</figcaption></figure>`
    )
    .join("");

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Site review — ${esc(host)}</title>
<style>
  :root{--ink:#16130f;--muted:#6b6257;--line:#e4ded4;--bg:#faf7f2;--card:#fff;
        --high:#9a3412;--medium:#a16207;--low:#3f6212}
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--ink);
       font:16px/1.6 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
  .wrap{max-width:820px;margin:0 auto;padding:clamp(24px,5vw,56px)}
  h1{font-size:clamp(26px,4.5vw,36px);margin:0 0 6px;letter-spacing:-.02em}
  .sub{color:var(--muted);margin:0 0 28px}
  .stats{display:flex;flex-wrap:wrap;gap:10px;margin:0 0 36px;padding:0;list-style:none}
  .stats li{background:var(--card);border:1px solid var(--line);padding:10px 14px;border-radius:8px;font-size:14px}
  .stats b{display:block;font-size:19px}
  .f{background:var(--card);border:1px solid var(--line);border-left:4px solid var(--line);
     border-radius:8px;padding:18px 20px;margin:0 0 16px}
  .f.high{border-left-color:var(--high)} .f.medium{border-left-color:var(--medium)} .f.low{border-left-color:var(--low)}
  .f header{display:flex;align-items:baseline;gap:10px;flex-wrap:wrap}
  .f h3{font-size:17px;margin:0}
  .sev{font-size:11px;text-transform:uppercase;letter-spacing:.07em;padding:3px 7px;border-radius:4px;color:#fff}
  .high .sev{background:var(--high)} .medium .sev{background:var(--medium)} .low .sev{background:var(--low)}
  pre{background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:12px;
      overflow-x:auto;font-size:13px;margin:12px 0;white-space:pre-wrap}
  .why{margin:10px 0 0;color:#3d372f}
  .caveat{margin:8px 0 0;color:var(--muted);font-size:14px;font-style:italic}
  figure{margin:0 0 20px}
  figure img{width:100%;border:1px solid var(--line);border-radius:8px;display:block}
  figcaption{color:var(--muted);font-size:13px;margin-top:6px}
  h2{font-size:20px;margin:40px 0 16px}
  footer{color:var(--muted);font-size:13px;border-top:1px solid var(--line);margin-top:40px;padding-top:16px}
</style></head>
<body><div class="wrap">
  <h1>Site review: ${esc(host)}</h1>
  <p class="sub">${esc(url)} · ${new Date().toLocaleDateString("en-GB", { day: "numeric", month: "long", year: "numeric" })}</p>
  <ul class="stats">
    <li><b>${fmtBytes(stats.totalBytes)}</b>downloaded</li>
    <li><b>${stats.requests}</b>requests</li>
    <li><b>~${stats.mobileSeconds}s</b>to load on mobile</li>
    <li><b>${counts.high || 0}</b>high priority</li>
  </ul>
  ${findings.length ? rows : "<p>No significant issues found.</p>"}
  ${shots ? `<h2>What it looks like on a phone</h2>${shots}` : ""}
  <footer>Measured with a real browser at 390&times;844 (phone) and 1440&times;900 (desktop).
  Figures are transfer sizes on a cold load.</footer>
</div></body></html>`;
}
