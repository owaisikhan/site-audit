// Passive security-posture checks.
//
// Every check here reads what the site already hands back on a normal page
// load. Nothing attacks: no injection payloads, no login attempts, no fuzzing.
// It reports the *conditions* that make a site easy to attack -- missing
// headers, stealable cookies, an exposed .git folder, ancient libraries with
// known holes -- which is what a professional non-intrusive assessment does.
//
// The one exception, checkExposedPaths, makes a few extra GET requests and is
// off unless you pass --probe. Even that only reads well-known URLs; it never
// exploits. Run it only on sites you are allowed to audit.

const has = (headers, name) => name.toLowerCase() in headers;
const val = (headers, name) => headers[name.toLowerCase()];

/** Response headers that a browser relies on to contain an attack. Their
 *  absence does not mean the site is hacked -- it means the guardrails a
 *  modern site is expected to set are missing. */
export function checkSecurityHeaders(url, headers) {
  const findings = [];
  const isHttps = url.startsWith("https://");

  if (isHttps && !has(headers, "strict-transport-security")) {
    findings.push({
      id: "no-hsts",
      severity: "medium",
      title: "No HSTS header — the secure connection can be stripped",
      detail: "    Strict-Transport-Security is not set.",
      why:
        "Without it, a visitor's first request can be silently downgraded to plain " +
        "HTTP on a shared or hostile network (a café, an airport), and everything they " +
        "type — including a password — can be read in transit.",
      evidence: { header: "Strict-Transport-Security", present: false },
    });
  }

  const csp = val(headers, "content-security-policy");
  if (!csp) {
    findings.push({
      id: "no-csp",
      severity: "medium",
      title: "No Content-Security-Policy — nothing contains a script injection",
      detail: "    Content-Security-Policy is not set.",
      why:
        "A CSP is the main defence that stops an injected or third-party script from " +
        "running. Without one, a single cross-site-scripting hole anywhere on the site " +
        "can read logged-in sessions and form data with nothing to slow it down.",
      evidence: { header: "Content-Security-Policy", present: false },
    });
  }

  const xfo = val(headers, "x-frame-options");
  const framesAllowed = csp && /frame-ancestors/i.test(csp);
  if (!xfo && !framesAllowed) {
    findings.push({
      id: "clickjacking",
      severity: "medium",
      title: "The site can be framed by any other site (clickjacking)",
      detail: "    Neither X-Frame-Options nor a CSP frame-ancestors rule is set.",
      why:
        "An attacker can load your site invisibly inside their own page and trick a " +
        "logged-in user into clicking buttons they cannot see — approving a payment, " +
        "changing a setting, deleting data — thinking they are clicking something else.",
      evidence: { xFrameOptions: false, frameAncestors: false },
    });
  }

  if (!has(headers, "x-content-type-options")) {
    findings.push({
      id: "no-nosniff",
      severity: "low",
      title: "Missing X-Content-Type-Options: nosniff",
      detail: "    Browsers are left to guess file types.",
      why:
        "Lets a browser treat an uploaded image or text file as a script if it looks " +
        "like one, which is one route a malicious upload turns into code execution.",
      evidence: { header: "X-Content-Type-Options", present: false },
    });
  }

  // Version disclosure: not a hole itself, but it hands an attacker the exact
  // software version to look up known exploits for.
  const server = val(headers, "server");
  const powered = val(headers, "x-powered-by");
  const leaks = [server, powered].filter((v) => v && /\d/.test(v));
  if (leaks.length) {
    findings.push({
      id: "version-disclosure",
      severity: "low",
      title: "The server advertises its exact software version",
      detail: [server && `    Server: ${server}`, powered && `    X-Powered-By: ${powered}`]
        .filter(Boolean)
        .join("\n"),
      why:
        "Publishing the precise version tells an attacker exactly which known exploits " +
        "to try first. It costs nothing to remove and removes an easy head start.",
      evidence: { server, xPoweredBy: powered },
    });
  }

  return findings;
}

/** Cookies are how a site remembers you are logged in. If the flags that protect
 *  them are missing, the session can be stolen or ridden. */
export function checkCookies(cookies, url) {
  const findings = [];
  const isHttps = url.startsWith("https://");
  // Heuristic: cookies that look like they carry a login/session.
  const sessionish = /sess|sid|token|auth|login|jwt|remember/i;
  const session = cookies.filter((c) => sessionish.test(c.name));
  const pool = session.length ? session : cookies;

  const noHttpOnly = pool.filter((c) => !c.httpOnly);
  const noSecure = isHttps ? pool.filter((c) => !c.secure) : [];
  const noSameSite = pool.filter((c) => !c.sameSite || c.sameSite === "None");

  if (noHttpOnly.length) {
    findings.push({
      id: "cookie-httponly",
      severity: session.length ? "high" : "medium",
      title: `${noHttpOnly.length} cookie(s) can be read by JavaScript (no HttpOnly)`,
      detail: noHttpOnly.slice(0, 6).map((c) => `    ${c.name}`).join("\n"),
      why:
        "If any script on the page is compromised — including a third-party one you do " +
        "not control — it can read these cookies and copy a logged-in session straight " +
        "to an attacker, who is then signed in as that user without a password.",
      evidence: { cookies: noHttpOnly.map((c) => c.name) },
    });
  }

  if (noSecure.length) {
    findings.push({
      id: "cookie-secure",
      severity: "medium",
      title: `${noSecure.length} cookie(s) are sent over plain HTTP too (no Secure flag)`,
      detail: noSecure.slice(0, 6).map((c) => `    ${c.name}`).join("\n"),
      why:
        "The cookie will travel unencrypted on any downgraded request, where it can be " +
        "captured on a shared network and used to impersonate the user.",
      evidence: { cookies: noSecure.map((c) => c.name) },
    });
  }

  if (noSameSite.length) {
    findings.push({
      id: "cookie-samesite",
      severity: "low",
      title: `${noSameSite.length} cookie(s) have no SameSite protection`,
      detail: noSameSite.slice(0, 6).map((c) => `    ${c.name}`).join("\n"),
      why:
        "Leaves the door open to cross-site request forgery, where another site makes a " +
        "logged-in user's browser perform an action on yours without their intent.",
      evidence: { cookies: noSameSite.map((c) => c.name) },
    });
  }

  return findings;
}

/** A password field on a page that is not itself served over HTTPS, or that
 *  posts to a plain-HTTP address, means the password is sent in the clear. */
export async function checkPasswordSecurity(page, url) {
  const r = await page.evaluate(() => {
    const out = { pageInsecure: location.protocol === "http:", insecureForms: [] };
    document.querySelectorAll('input[type="password"]').forEach((inp) => {
      const form = inp.closest("form");
      const action = form?.getAttribute("action") || "";
      if (/^http:\/\//i.test(action)) out.insecureForms.push(action);
    });
    out.hasPassword = document.querySelectorAll('input[type="password"]').length > 0;
    return out;
  });

  const findings = [];
  if (r.hasPassword && (r.pageInsecure || r.insecureForms.length)) {
    findings.push({
      id: "password-cleartext",
      severity: "high",
      title: "A password is submitted without encryption",
      detail: r.pageInsecure
        ? `    The login page itself is served over plain HTTP: ${url}`
        : `    The form sends the password to an http:// address:\n` +
          r.insecureForms.slice(0, 3).map((a) => `    ${a}`).join("\n"),
      why:
        "Every password typed here travels in plain text and can be read by anyone " +
        "between the visitor and the server — on shared Wi-Fi, that is trivial. This is " +
        "one of the most direct routes to a stolen account.",
      evidence: r,
    });
  }
  return findings;
}

// Reliably version-detectable libraries with a floor below which well-known,
// exploitable holes exist. Conservative on purpose -- only clearly dangerous
// gaps, reported as a signal to verify, never as proof of compromise.
const LIB_FLOORS = [
  { name: "jQuery", get: "window.jQuery && window.jQuery.fn && window.jQuery.fn.jquery", safeBelow: "3.5.0", cve: "XSS via jQuery.htmlPrefilter (CVE-2020-11022/11023)" },
  { name: "AngularJS", get: "window.angular && window.angular.version && window.angular.version.full", safeBelow: "999", cve: "AngularJS 1.x is end-of-life and no longer patched" },
  { name: "Lodash", get: "window._ && window._.VERSION", safeBelow: "4.17.21", cve: "prototype pollution (CVE-2021-23337 and earlier)" },
  { name: "Bootstrap", get: "window.bootstrap && window.bootstrap.Tooltip && window.bootstrap.Tooltip.VERSION", safeBelow: "4.3.1", cve: "XSS in data-template / tooltips" },
];

const lt = (a, b) => {
  const pa = String(a).split(".").map(Number);
  const pb = String(b).split(".").map(Number);
  for (let i = 0; i < 3; i++) {
    if ((pa[i] || 0) < (pb[i] || 0)) return true;
    if ((pa[i] || 0) > (pb[i] || 0)) return false;
  }
  return false;
};

/** Reads library versions already present on the page. Passive -- it inspects
 *  what the site loaded, it does not fetch or test anything. */
export async function checkVulnerableLibraries(page) {
  const found = await page.evaluate((floors) => {
    return floors
      .map((f) => {
        let v;
        try {
          // eslint-disable-next-line no-eval
          v = eval(f.get);
        } catch {
          v = undefined;
        }
        return v ? { name: f.name, version: String(v), safeBelow: f.safeBelow, cve: f.cve } : null;
      })
      .filter(Boolean);
  }, LIB_FLOORS);

  const outdated = found.filter((f) => f.safeBelow === "999" || lt(f.version, f.safeBelow));
  if (!outdated.length) return [];

  return [
    {
      id: "outdated-libraries",
      severity: "medium",
      title: `${outdated.length} front-end librar${outdated.length === 1 ? "y has" : "ies have"} a known security hole`,
      detail: outdated
        .map((f) => `    ${f.name} ${f.version} — ${f.cve}`)
        .join("\n"),
      why:
        "These versions have publicly documented vulnerabilities with ready-made exploit " +
        "code. An attacker does not need any skill to use them — just to notice the " +
        "version, which is visible to anyone. Updating is usually a one-line change.",
      evidence: { outdated },
      caveat:
        "Detected from the version the page reports. Confirm the running version before " +
        "citing a specific CVE — a backported patch can fix the hole without changing the number.",
    },
  ];
}

/** A wide-open CORS policy combined with credentials lets any website read a
 *  logged-in user's data from yours. */
export function checkCors(resources) {
  const bad = resources.filter((r) => {
    const h = r.headers || {};
    const acao = h["access-control-allow-origin"];
    const creds = h["access-control-allow-credentials"];
    return acao === "*" && String(creds).toLowerCase() === "true";
  });
  if (!bad.length) return [];
  return [
    {
      id: "cors-wildcard",
      severity: "high",
      title: "Any website is allowed to read logged-in responses (CORS misconfiguration)",
      detail: bad.slice(0, 4).map((r) => `    ${r.url.slice(0, 80)}`).join("\n"),
      why:
        "Access-Control-Allow-Origin: * together with credentials means a malicious site " +
        "a logged-in user visits can make requests to yours as them and read the private " +
        "responses — their account data, handed to an attacker's page.",
      evidence: { urls: bad.map((r) => r.url) },
    },
  ];
}

// High-value, well-known exposures. A GET to these reads only what the server
// chooses to serve; it never exploits. Off unless --probe is passed, because
// even reading them should be limited to sites you are authorised to audit.
const PROBE_PATHS = [
  { path: "/.git/HEAD", marker: /^ref:\s/, label: ".git repository", sev: "high",
    why: "The .git folder is downloadable, which means your entire source history — and any passwords, keys or tokens ever committed to it — can be reconstructed by anyone." },
  { path: "/.env", marker: /^\s*[A-Z0-9_]+\s*=/m, label: ".env file", sev: "high",
    why: "The environment file is world-readable. These files hold database passwords, API keys and secrets; exposing one is often a direct path to full data loss." },
  { path: "/.git/config", marker: /\[core\]|\[remote/, label: ".git/config", sev: "high",
    why: "The Git config is exposed, confirming the repository is served and often leaking the remote URL and structure." },
];

/** Opt-in, light path probe. Makes a few GETs to well-known exposure points.
 *  fetchUrl(path) must return { status, body } or null. */
export async function checkExposedPaths(baseUrl, fetchUrl) {
  const origin = new URL(baseUrl).origin;
  const findings = [];
  for (const p of PROBE_PATHS) {
    let res;
    try {
      res = await fetchUrl(origin + p.path);
    } catch {
      res = null;
    }
    if (res && res.status === 200 && p.marker.test(res.body || "")) {
      findings.push({
        id: `exposed${p.path.replace(/[^a-z]/gi, "-")}`,
        severity: p.sev,
        title: `${p.label} is publicly accessible`,
        detail: `    ${origin + p.path} returned 200 with the expected contents.`,
        why: p.why,
        evidence: { url: origin + p.path },
      });
    }
  }
  return findings;
}
