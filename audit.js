#!/usr/bin/env node
// Point it at a URL, get findings a business owner can understand, screenshots
// that prove them, and a first-contact email built from the worst three.
//
//   node audit.js https://example.com
//   node audit.js https://example.com --out reports --name "Sarah" --from "Owais"
//
// Read-only: it loads the page the way a visitor would and measures what
// happens. It never clicks anything, submits anything, or logs in, so it is
// safe to run against a stranger's site.

import { chromium } from "playwright";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import {
  checkDeadControls, checkErrors, checkImages, checkMetadata,
  checkMobileOverflow, checkPageWeight, checkSecurity, checkTapTargets,
} from "./lib/checks.js";
import {
  checkCookies, checkCors, checkExposedPaths, checkPasswordSecurity,
  checkSecurityHeaders, checkVulnerableLibraries,
} from "./lib/security.js";
import { htmlReport, outreachEmail, terminalReport } from "./lib/report.js";

const MOBILE = { width: 390, height: 844 };
const DESKTOP = { width: 1440, height: 900 };
const MOBILE_BYTES_PER_SEC = 200 * 1024;

function parseArgs(argv) {
  const args = { out: "reports", name: "there", from: "", timeout: 45000 };
  const rest = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--out") args.out = argv[++i];
    else if (a === "--name") args.name = argv[++i];
    else if (a === "--from") args.from = argv[++i];
    else if (a === "--timeout") args.timeout = Number(argv[++i]);
    else if (a === "--json") args.json = true;
    else if (a === "--probe") args.probe = true;
    else if (a.startsWith("-")) throw new Error(`Unknown option: ${a}`);
    else rest.push(a);
  }
  args.url = rest[0];
  return args;
}

/** Collects transfer sizes, failures and console errors for one page load. */
function instrument(page) {
  const resources = [];
  const failed = [];
  const consoleErrors = [];

  page.on("response", async (res) => {
    const req = res.request();
    if (res.status() >= 400) failed.push({ url: res.url(), status: res.status() });
    let bytes = 0;
    try {
      // Transfer size where the browser reports it; fall back to the body.
      const len = res.headers()["content-length"];
      bytes = len ? Number(len) : (await res.body().catch(() => Buffer.alloc(0))).length;
    } catch {
      bytes = 0;
    }
    resources.push({
      url: res.url(),
      name: decodeURIComponent(res.url().split("/").pop().split("?")[0]) || res.url(),
      bytes: Number.isFinite(bytes) ? bytes : 0,
      type: req.resourceType(),
      headers: res.headers(),
    });
  });
  page.on("requestfailed", (req) => {
    // Browsers routinely abort media requests part-way (range requests, pausing
    // an off-screen video). That is normal, not a broken file -- reporting it
    // would be a false claim on a prospect's site.
    const aborted = (req.failure()?.errorText || "").includes("ERR_ABORTED");
    if (aborted && ["media", "image"].includes(req.resourceType())) return;
    failed.push({ url: req.url(), status: "failed" });
  });
  page.on("pageerror", (err) => consoleErrors.push(String(err.message || err)));
  page.on("console", (m) => {
    if (m.type() !== "error") return;
    const t = m.text();
    // Resource 404s surface here too, but the broken-requests check already
    // covers them; counting both inflates the findings.
    if (/Failed to load resource/i.test(t)) return;
    consoleErrors.push(t);
  });

  return { resources, failed, consoleErrors };
}

async function run() {
  const args = parseArgs(process.argv.slice(2));
  if (!args.url) {
    console.error(`Usage: node audit.js <url> [--out dir] [--name "Sarah"] [--from "Owais"]`);
    process.exit(1);
  }
  const url = /^https?:\/\//.test(args.url) ? args.url : `https://${args.url}`;
  const parsed = new URL(url);
  const host = parsed.hostname.replace(/^www\./, "");
  // Keep the port in the folder name so two local fixtures do not overwrite
  // each other's reports.
  const slug = parsed.port ? `${host}-${parsed.port}` : host;
  const outDir = path.resolve(args.out, slug);
  await mkdir(outDir, { recursive: true });

  const browser = await chromium.launch();
  const findings = [];
  const screenshots = [];
  let stats;

  try {
    // ---- phone pass: where nearly all the damning findings come from -------
    const mob = await browser.newContext({
      viewport: MOBILE, isMobile: true, hasTouch: true, deviceScaleFactor: 2,
      userAgent:
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 " +
        "(KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    });
    const mPage = await mob.newPage();
    const mInstr = instrument(mPage);

    const started = Date.now();
    let response;
    try {
      response = await mPage.goto(url, { waitUntil: "load", timeout: args.timeout });
    } catch (err) {
      // A certificate error is a finding, not a crash: the visitor sees a full
      // "your connection is not private" interstitial and most turn back.
      if (/ERR_CERT|SSL|CERT_/i.test(err.message)) {
        findings.push({
          id: "tls-invalid",
          severity: "high",
          title: "The site's security certificate is invalid",
          detail: `    The browser refused to load ${url}:\n    ${err.message}`,
          why:
            "Visitors are stopped by a full-page \"your connection is not private\" " +
            "warning before they see anything, and almost all of them leave. It also " +
            "means traffic may not actually be encrypted.",
          evidence: { error: err.message },
        });
        stats = { totalBytes: 0, requests: 0, loadMs: Date.now() - started, mobileSeconds: 0 };
        const partial = { url, host, findings, stats, screenshots: [], checkedAt: new Date().toISOString() };
        await writeFile(path.join(outDir, "report.html"), htmlReport(partial), "utf8");
        console.log(terminalReport(partial));
        console.log(`  report     ${path.join(outDir, "report.html")}`);
        await mob.close();
        await browser.close();
        return;
      }
      throw err;
    }
    const loadMs = Date.now() - started;
    const mainHeaders = response ? response.headers() : {};
    if (!response) throw new Error("No response from the server");
    if (response.status() >= 400) throw new Error(`Server returned ${response.status()}`);
    // Let lazy assets and any entrance animation settle before measuring.
    await mPage.waitForTimeout(2500);

    const mobShot = path.join(outDir, "phone.png");
    await mPage.screenshot({ path: mobShot });
    screenshots.push({ file: "phone.png", label: `${host} on an iPhone (390px wide)` });

    findings.push(...(await checkMobileOverflow(mPage)));
    findings.push(...(await checkTapTargets(mPage)));
    findings.push(...(await checkDeadControls(mPage)));
    findings.push(...(await checkMetadata(mPage)));
    findings.push(...(await checkImages(mPage)));
    findings.push(...checkErrors(mInstr.failed, dedupe(mInstr.consoleErrors)));
    findings.push(...checkSecurity(url, mInstr.resources));
    findings.push(...checkPageWeight(mInstr.resources));

    // ---- passive security posture (reads what the load already returned) ----
    findings.push(...checkSecurityHeaders(url, mainHeaders));
    findings.push(...checkCookies(await mob.cookies(), url));
    findings.push(...(await checkPasswordSecurity(mPage, url)));
    findings.push(...(await checkVulnerableLibraries(mPage)));
    findings.push(...checkCors(mInstr.resources));

    // ---- opt-in path probe: a few extra GETs, only with --probe ------------
    if (args.probe) {
      const fetchUrl = async (u) => {
        try {
          const res = await mPage.request.get(u, { timeout: 8000, failOnStatusCode: false });
          return { status: res.status(), body: await res.text().catch(() => "") };
        } catch {
          return null;
        }
      };
      findings.push(...(await checkExposedPaths(url, fetchUrl)));
    }

    const totalBytes = mInstr.resources.reduce((s, r) => s + r.bytes, 0);
    stats = {
      totalBytes,
      requests: mInstr.resources.length,
      loadMs,
      mobileSeconds: +(totalBytes / MOBILE_BYTES_PER_SEC).toFixed(1),
    };

    // If the page scrolls sideways, capture proof of it.
    if (findings.some((f) => f.id === "mobile-overflow")) {
      await mPage.evaluate(() => window.scrollTo(document.documentElement.scrollWidth, 0));
      await mPage.waitForTimeout(400);
      await mPage.screenshot({ path: path.join(outDir, "phone-overflow.png") });
      screenshots.push({
        file: "phone-overflow.png",
        label: "Scrolled fully right — this is content spilling off the screen",
      });
    }
    await mob.close();

    // ---- desktop pass: mainly for the screenshot to include in the email ---
    const desk = await browser.newContext({ viewport: DESKTOP });
    const dPage = await desk.newPage();
    await dPage.goto(url, { waitUntil: "load", timeout: args.timeout }).catch(() => {});
    await dPage.waitForTimeout(2000);
    await dPage.screenshot({ path: path.join(outDir, "desktop.png") });
    screenshots.push({ file: "desktop.png", label: `${host} on a laptop (1440px wide)` });
    await desk.close();
  } finally {
    await browser.close();
  }

  const result = { url, host, findings, stats, screenshots, checkedAt: new Date().toISOString() };

  await writeFile(path.join(outDir, "report.html"), htmlReport(result), "utf8");
  const email = outreachEmail(result, { name: args.name, from: args.from });
  if (email) await writeFile(path.join(outDir, "email.txt"), email, "utf8");
  if (args.json) await writeFile(path.join(outDir, "findings.json"), JSON.stringify(result, null, 2), "utf8");

  console.log(terminalReport(result));
  console.log(`  report     ${path.join(outDir, "report.html")}`);
  if (email) console.log(`  email      ${path.join(outDir, "email.txt")}`);
  console.log(`  screenshots ${outDir}`);
  console.log("");
}

const dedupe = (arr) => [...new Set(arr)];

run().catch((err) => {
  console.error(`\n  Could not audit that site: ${err.message}\n`);
  process.exit(1);
});
