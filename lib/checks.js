// Each check returns findings shaped for a non-technical reader:
//   severity  how much money it is plausibly costing them
//   title     the headline a business owner understands
//   detail    the specific evidence, with numbers
//   why       why it matters to them, not to a developer
//
// Anything that cannot be measured confidently is left out. A finding you
// cannot defend on a call is worse than no finding at all.

const KB = 1024;
const MB = 1024 * 1024;

/** Rough real-world mobile throughput. Slower than the headline "4G" figure
 *  because handshakes, latency and contention eat most of it. */
const MOBILE_BYTES_PER_SEC = 200 * KB;

/** "1 button" / "2 buttons". The "(s)" form reads like a form letter, and this
 *  copy is going in front of prospects. */
export function plural(n, one, many = `${one}s`) {
  return `${n} ${n === 1 ? one : many}`;
}

export function fmtBytes(n) {
  if (n >= MB) return `${(n / MB).toFixed(1)}MB`;
  if (n >= KB) return `${Math.round(n / KB)}KB`;
  return `${n}B`;
}

/** Total transfer size, and the handful of assets responsible for it. */
export function checkPageWeight(resources) {
  const findings = [];
  const total = resources.reduce((s, r) => s + r.bytes, 0);
  const seconds = total / MOBILE_BYTES_PER_SEC;

  const heavy = [...resources].sort((a, b) => b.bytes - a.bytes).slice(0, 5);
  const videos = resources.filter((r) => r.type === "media");
  const videoBytes = videos.reduce((s, r) => s + r.bytes, 0);
  const images = resources.filter((r) => r.type === "image");
  const imageBytes = images.reduce((s, r) => s + r.bytes, 0);

  if (total > 3 * MB) {
    findings.push({
      id: "page-weight",
      severity: total > 8 * MB ? "high" : "medium",
      title: `The page downloads ${fmtBytes(total)} before it is usable`,
      detail:
        `Total transfer is ${fmtBytes(total)}. On a typical mobile connection that is ` +
        `roughly ${seconds.toFixed(1)} seconds of loading. Largest items:\n` +
        heavy.map((r) => `    ${fmtBytes(r.bytes).padStart(7)}  ${r.name}`).join("\n"),
      why:
        "Around half of mobile visitors abandon a page that takes more than three " +
        "seconds. This is usually the single cheapest thing to fix on a site.",
      evidence: { totalBytes: total, estimatedMobileSeconds: +seconds.toFixed(1), heavy },
    });
  }

  if (videoBytes > 2 * MB) {
    findings.push({
      id: "video-weight",
      severity: videoBytes > 6 * MB ? "high" : "medium",
      title: `${fmtBytes(videoBytes)} of video loads automatically`,
      detail:
        `${plural(videos.length, "video file")}, ${fmtBytes(videoBytes)} in total:\n` +
        videos
          .sort((a, b) => b.bytes - a.bytes)
          .slice(0, 4)
          .map((r) => `    ${fmtBytes(r.bytes).padStart(7)}  ${r.name}`)
          .join("\n"),
      why:
        "Background video is almost always encoded far larger than it needs to be, and " +
        "on mobile it burns the visitor's data allowance and battery before they have " +
        "read a word. It can normally be cut by 60-80% with no visible difference.",
      evidence: { videoBytes, count: videos.length },
    });
  }

  if (imageBytes > 2 * MB) {
    findings.push({
      id: "image-weight",
      severity: "medium",
      title: `Images account for ${fmtBytes(imageBytes)}`,
      detail:
        `${images.length} images totalling ${fmtBytes(imageBytes)}. Largest:\n` +
        images
          .sort((a, b) => b.bytes - a.bytes)
          .slice(0, 4)
          .map((r) => `    ${fmtBytes(r.bytes).padStart(7)}  ${r.name}`)
          .join("\n"),
      why:
        "Photos are usually uploaded straight from a camera or stock site at print " +
        "resolution. Serving them at the size they are actually displayed, in a modern " +
        "format, typically cuts them by 70% with no visible change.",
      evidence: { imageBytes, count: images.length },
    });
  }

  return findings;
}

/** Content wider than the screen: the page scrolls sideways on a phone. */
export async function checkMobileOverflow(page) {
  const result = await page.evaluate(() => {
    const de = document.documentElement;
    const overflow = de.scrollWidth - de.clientWidth;
    if (overflow <= 1) return { overflow: 0, culprits: [] };
    const culprits = [];
    document.querySelectorAll("*").forEach((el) => {
      const r = el.getBoundingClientRect();
      if (r.width === 0 || r.height === 0) return;
      if (r.right > de.clientWidth + 1) {
        culprits.push({
          tag: el.tagName.toLowerCase(),
          cls: (el.className || "").toString().trim().slice(0, 40),
          width: Math.round(r.width),
          overhang: Math.round(r.right - de.clientWidth),
          text: (el.textContent || "").trim().replace(/\s+/g, " ").slice(0, 45),
        });
      }
    });
    // Innermost elements are the real cause; parents just inherit the overflow.
    culprits.sort((a, b) => b.overhang - a.overhang);
    return { overflow, culprits: culprits.slice(0, 5) };
  });

  if (!result.overflow) return [];
  return [
    {
      id: "mobile-overflow",
      severity: "high",
      title: `The page scrolls sideways on a phone (${result.overflow}px too wide)`,
      detail:
        `Content extends ${result.overflow}px past the right edge of the screen. ` +
        `Elements sticking out:\n` +
        result.culprits
          .map((c) => `    +${String(c.overhang).padStart(4)}px  <${c.tag}> ${c.text || c.cls}`)
          .join("\n"),
      why:
        "Visitors get a page that slides around under their thumb and text cut off at " +
        "the edge. It reads as broken, and most traffic to a small business site is mobile.",
      evidence: result,
    },
  ];
}

/** Controls that cannot be used, or lead nowhere. */
export async function checkDeadControls(page) {
  const result = await page.evaluate(() => {
    const dead = [];
    const label = (el) =>
      (el.getAttribute("aria-label") || el.textContent || "").trim().replace(/\s+/g, " ").slice(0, 40) ||
      el.tagName.toLowerCase();

    // A control the visitor cannot currently see is not a broken control. Closed
    // modals, collapsed menus and off-screen drawers are all legitimately
    // inert -- flagging them would be a false accusation on someone's site, so
    // walk the ancestors and skip anything hidden by any of the usual means.
    const visibleToUser = (el) => {
      const r = el.getBoundingClientRect();
      if (r.width === 0 || r.height === 0) return false;
      if (r.bottom < -2000 || r.right < -2000) return false;
      for (let n = el; n && n !== document.documentElement; n = n.parentElement) {
        if (n.getAttribute && n.getAttribute("aria-hidden") === "true") return false;
        if (n.hasAttribute && n.hasAttribute("inert")) return false;
        const cs = getComputedStyle(n);
        if (cs.display === "none" || cs.visibility === "hidden") return false;
        if (parseFloat(cs.opacity) === 0) return false;
      }
      return true;
    };

    // Interactive elements the CSS has made unclickable while on screen.
    document.querySelectorAll("button, a, input[type=submit], [role=button]").forEach((el) => {
      if (!visibleToUser(el)) return;
      if (getComputedStyle(el).pointerEvents === "none") {
        dead.push({ kind: "unclickable", label: label(el), reason: "pointer-events: none" });
      }
    });

    // Links that go nowhere.
    document.querySelectorAll("a").forEach((el) => {
      const href = el.getAttribute("href");
      if (!visibleToUser(el)) return;
      if (href === null) dead.push({ kind: "no-target", label: label(el), reason: "no href" });
      else if (["#", "", "javascript:void(0)", "javascript:;"].includes(href.trim()))
        dead.push({ kind: "no-target", label: label(el), reason: `href="${href}"` });
    });

    // Forms with nowhere to send data and no script handling them.
    document.querySelectorAll("form").forEach((f) => {
      if (!f.getAttribute("action") && !f.onsubmit) {
        dead.push({
          kind: "form",
          label: label(f.querySelector("button, input[type=submit]") || f),
          reason: "form has no action and no inline handler",
        });
      }
    });
    return dead;
  });

  if (!result.length) return [];
  const unclickable = result.filter((d) => d.kind === "unclickable");
  const nowhere = result.length - unclickable.length;
  const parts = [];
  if (unclickable.length) parts.push(`${unclickable.length} cannot be clicked at all`);
  if (nowhere) parts.push(`${nowhere} lead nowhere`);
  return [
    {
      id: "dead-controls",
      severity: unclickable.length ? "high" : "medium",
      title:
        result.length === 1
          ? `A ${unclickable.length ? "button that cannot be clicked" : "link that leads nowhere"}`
          : `${result.length} buttons and links do nothing — ${parts.join(", ")}`,
      detail: result
        .slice(0, 8)
        .map((d) => `    "${d.label}" — ${d.reason}`)
        .join("\n"),
      why:
        "Every one of these is a visitor who tried to do business with you and got " +
        "nothing back. Forms that submit into a void are the expensive version: the " +
        "customer thinks they got in touch and is waiting for a reply that never comes.",
      evidence: { controls: result },
      caveat:
        "Some may be handled by JavaScript in ways a static scan cannot see. Worth " +
        "clicking them yourself before you send this.",
    },
  ];
}

/** Search-result and link-preview basics. */
export async function checkMetadata(page) {
  const m = await page.evaluate(() => {
    const meta = (sel, attr = "content") => document.querySelector(sel)?.getAttribute(attr) || null;
    return {
      title: document.title || null,
      description: meta('meta[name="description"]'),
      ogImage: meta('meta[property="og:image"]'),
      ogTitle: meta('meta[property="og:title"]'),
      favicon: meta('link[rel~="icon"]', "href"),
      viewport: meta('meta[name="viewport"]'),
      canonical: meta('link[rel="canonical"]', "href"),
      h1Count: document.querySelectorAll("h1").length,
      lang: document.documentElement.getAttribute("lang"),
    };
  });

  const findings = [];
  const missing = [];
  if (!m.title) missing.push("page title");
  if (!m.description) missing.push("search description");
  if (!m.ogImage) missing.push("link preview image");
  if (!m.favicon) missing.push("favicon");

  if (missing.length) {
    // Say only what is actually true of this page -- claiming the search listing
    // is broken when the title is present would be caught on the first call.
    const reasons = [];
    if (!m.title || !m.description)
      reasons.push(
        "Google has nothing to show for the listing, so it invents one from whatever " +
          "text it finds — usually the navigation menu."
      );
    if (!m.ogImage)
      reasons.push(
        "Shared on WhatsApp, Facebook or LinkedIn, the link appears as plain text with " +
          "no picture, while competitors get a full preview card and the click."
      );
    if (!m.favicon)
      reasons.push("There is no icon in the browser tab, which looks unfinished next to other tabs.");

    findings.push({
      id: "metadata",
      severity: !m.title || !m.description ? "medium" : "low",
      title: `Missing ${missing.join(", ")}`,
      detail:
        `    title:         ${m.title ?? "MISSING"}\n` +
        `    description:   ${m.description ?? "MISSING"}\n` +
        `    preview image: ${m.ogImage ? "present" : "MISSING"}\n` +
        `    favicon:       ${m.favicon ?? "MISSING"}`,
      why: reasons.join(" "),
      evidence: m,
    });
  }

  if (!m.viewport) {
    findings.push({
      id: "no-viewport",
      severity: "high",
      title: "The site is not set up for mobile at all",
      detail: "    No mobile viewport tag — phones will render the desktop layout shrunk to fit.",
      why:
        "Text comes out too small to read and the visitor has to pinch and zoom. " +
        "Google also ranks sites down for this.",
      evidence: m,
    });
  }

  if (m.h1Count === 0) {
    findings.push({
      id: "no-h1",
      severity: "low",
      title: "No main heading on the page",
      detail: "    The page has no <h1>, so search engines cannot tell what it is about.",
      why: "Weakens search ranking for the terms you most want to be found for.",
      evidence: m,
    });
  }
  return findings;
}

/** Images with no alternative text. */
export async function checkImages(page) {
  const r = await page.evaluate(() => {
    const imgs = [...document.querySelectorAll("img")].filter((i) => {
      const b = i.getBoundingClientRect();
      return b.width > 40 && b.height > 40;
    });
    const noAlt = imgs.filter((i) => !i.hasAttribute("alt")).map((i) => i.currentSrc.split("/").pop());
    // Served far larger than displayed: wasted bytes.
    const oversized = imgs
      .filter((i) => i.naturalWidth > 0)
      .map((i) => ({
        name: i.currentSrc.split("/").pop(),
        natural: i.naturalWidth,
        displayed: Math.round(i.getBoundingClientRect().width * (window.devicePixelRatio || 1)),
      }))
      .filter((o) => o.displayed > 0 && o.natural > o.displayed * 2);
    return { total: imgs.length, noAlt, oversized };
  });

  const findings = [];
  if (r.noAlt.length) {
    findings.push({
      id: "img-alt",
      severity: "low",
      title: `${r.noAlt.length} of ${r.total} images have no alt text`,
      detail: r.noAlt.slice(0, 6).map((n) => `    ${n}`).join("\n"),
      why:
        "Screen readers cannot describe them, and search engines cannot index them. " +
        "In several countries this is also an accessibility compliance issue.",
      evidence: r.noAlt,
    });
  }
  if (r.oversized.length) {
    findings.push({
      id: "img-oversized",
      severity: "medium",
      title: `${plural(r.oversized.length, "image")} served much larger than they are shown`,
      detail: r.oversized
        .slice(0, 6)
        .map((o) => `    ${o.name} — ${o.natural}px wide, displayed at ${o.displayed}px`)
        .join("\n"),
      why:
        "The visitor downloads several times more data than the screen can use. " +
        "Resizing these is invisible to the eye and immediate on the loading time.",
      evidence: r.oversized,
    });
  }
  return findings;
}

/** Buttons and links too small to hit with a thumb. */
export async function checkTapTargets(page) {
  const small = await page.evaluate(() => {
    const MIN = 40; // px; Apple and Google both recommend >= 44
    const out = [];
    document.querySelectorAll("a, button, input[type=submit], [role=button]").forEach((el) => {
      const r = el.getBoundingClientRect();
      if (r.width === 0 || r.height === 0) return;
      if (r.top > window.innerHeight * 3) return; // only judge what is near the top
      if (r.width < MIN || r.height < MIN) {
        out.push({
          label: (el.getAttribute("aria-label") || el.textContent || "").trim().replace(/\s+/g, " ").slice(0, 30),
          size: `${Math.round(r.width)}x${Math.round(r.height)}`,
        });
      }
    });
    return out;
  });

  if (small.length < 3) return [];
  return [
    {
      id: "tap-targets",
      severity: "low",
      title: `${small.length} tap targets are too small for a thumb`,
      detail: small.slice(0, 6).map((s) => `    "${s.label}" — ${s.size}px`).join("\n"),
      why:
        "Anything under about 44px square gets mis-tapped on a phone. Visitors hit the " +
        "wrong link, go back, and often give up.",
      evidence: small,
    },
  ];
}

/** Requests that failed, and errors thrown in the browser. */
export function checkErrors(failedRequests, consoleErrors) {
  const findings = [];
  if (failedRequests.length) {
    findings.push({
      id: "broken-requests",
      severity: failedRequests.some((f) => f.status === 404) ? "medium" : "low",
      title: `${plural(failedRequests.length, "file")} on the page ${failedRequests.length === 1 ? "fails" : "fail"} to load`,
      detail: failedRequests
        .slice(0, 6)
        .map((f) => `    ${f.status}  ${f.url.slice(0, 80)}`)
        .join("\n"),
      why:
        "Usually a missing image or a stylesheet that never arrives, so part of the " +
        "page silently renders wrong for every visitor.",
      evidence: failedRequests,
    });
  }
  if (consoleErrors.length) {
    findings.push({
      id: "js-errors",
      severity: "medium",
      title: `The page throws ${plural(consoleErrors.length, "JavaScript error")}`,
      detail: consoleErrors.slice(0, 4).map((e) => `    ${e.slice(0, 100)}`).join("\n"),
      why:
        "When a script fails partway, everything after it stops running — which is " +
        "often exactly the menu, slider or form the visitor needed.",
      evidence: consoleErrors,
    });
  }
  return findings;
}

/** Plain HTTP, or secure pages pulling insecure assets. */
export function checkSecurity(url, resources) {
  const findings = [];
  if (url.startsWith("http://")) {
    findings.push({
      id: "no-https",
      severity: "high",
      title: "The site is not served over HTTPS",
      detail: `    ${url}`,
      why:
        "Browsers show a “Not secure” warning in the address bar. It costs trust " +
        "immediately, and Google ranks insecure sites lower.",
      evidence: { url },
    });
  } else {
    const insecure = resources.filter((r) => r.url.startsWith("http://"));
    if (insecure.length) {
      findings.push({
        id: "mixed-content",
        severity: "medium",
        title: `${plural(insecure.length, "file")} loading insecurely on a secure page`,
        detail: insecure.slice(0, 5).map((r) => `    ${r.url.slice(0, 80)}`).join("\n"),
        why: "Browsers block these, so parts of the page quietly fail to appear.",
        evidence: insecure,
      });
    }
  }
  return findings;
}
