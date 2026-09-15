#!/usr/bin/env node
/**
 * generate_report.js — Build a client-ready .docx compliance report from
 * findings.json (produced by analyze_har.py).
 *
 * This renders the FULL audit: every tracker, every cookie, and every
 * third-party domain observed is written into the document. Nothing observed in
 * the capture is filtered out; the allowlist only changes how a row is labelled.
 *
 * Usage:
 *   node generate_report.js <findings.json> <site-name> <site-url> [--out report.docx]
 */
const {
  Document, Packer, Paragraph, TextRun, HeadingLevel, Table, TableRow, TableCell,
  WidthType, ShadingType, AlignmentType, BorderStyle, Footer, PageNumber,
} = require("docx");
const fs = require("fs");
const JSZip = require("jszip");

// Ink, not decoration: one accent, a warm neutral for rules, and three status
// colors that stay distinguishable in greyscale print as well as on screen.
const NAVY = "15304F";      // headings and the cover band
const ACCENT = "2D6A9F";    // secondary accent
const INK = "1A1A1A";       // body text
const MUTED = "6B7280";     // captions and secondary text
const LIGHT = "F7F8FA";     // zebra fill
const RULE = "DFE3E8";      // hairline rules
const RED = "B3261E";
const AMBER = "9A6700";
const GREEN = "1B6E3C";
const TOTAL_W = 10080; // exactly the text column: 12240 page - 2 x 1080 margin

const NO_BORDER = { style: BorderStyle.NONE, size: 0, color: "FFFFFF" };
const HAIRLINE = { style: BorderStyle.SINGLE, size: 2, color: RULE };
const STATUS_COLOR = { red: RED, amber: AMBER, green: GREEN };
const STATUS_MARK = { red: "\u25CF", amber: "\u25CF", green: "\u25CF" };

// keepNext/keepLines stop a heading being stranded at the foot of a page with
// its table overleaf — the most visible flaw in a generated document. Each
// top-level section starts on its own page, so a reader can hand one section to
// a colleague without it beginning halfway down a sheet.
function h1(text, { pageBreak = true } = {}) {
  return new Paragraph({
    heading: HeadingLevel.HEADING_1,
    spacing: { before: 300, after: 150 },
    keepNext: true,
    keepLines: true,
    pageBreakBefore: pageBreak,
    children: [new TextRun({ text, bold: true, color: NAVY })],
  });
}
function h2(text) {
  return new Paragraph({
    heading: HeadingLevel.HEADING_2,
    spacing: { before: 240, after: 120 },
    keepNext: true,
    keepLines: true,
    children: [new TextRun({ text, bold: true, color: NAVY })],
  });
}
function p(text, opts = {}) {
  return new Paragraph({ spacing: { after: 160 }, children: [new TextRun({ text, ...opts })] });
}
function bullet(text, opts = {}) {
  return new Paragraph({ bullet: { level: 0 }, spacing: { after: 80 }, children: [new TextRun({ text, ...opts })] });
}
function cell(text, { header = false, width, shading, color, bold, align, size } = {}) {
  return new TableCell({
    width: { size: width, type: WidthType.DXA },
    shading: shading ? { type: ShadingType.CLEAR, fill: shading } : undefined,
    margins: { top: 90, bottom: 90, left: 120, right: 120 },
    borders: header
      ? { top: NO_BORDER, bottom: { style: BorderStyle.SINGLE, size: 6, color: NAVY }, left: NO_BORDER, right: NO_BORDER }
      : { top: NO_BORDER, bottom: HAIRLINE, left: NO_BORDER, right: NO_BORDER },
    children: [new Paragraph({
      alignment: align,
      children: [new TextRun({
        text: String(text),
        bold: header || bold,
        color: header ? NAVY : (color || INK),
        size: size || (header ? 17 : 18),
        allCaps: header,
      })],
    })],
  });
}

// A status dot reads faster than a word, and the Status column is the one a
// client scans first. The action column carries the meaning in words.
function statusCell(status, width) {
  return new TableCell({
    width: { size: width, type: WidthType.DXA },
    margins: { top: 90, bottom: 90, left: 120, right: 120 },
    borders: { top: NO_BORDER, bottom: HAIRLINE, left: NO_BORDER, right: NO_BORDER },
    children: [new Paragraph({
      alignment: AlignmentType.CENTER,
      children: [new TextRun({ text: STATUS_MARK[status] || "\u25CB", color: STATUS_COLOR[status] || MUTED, size: 22 })],
    })],
  });
}

function makeTable(headers, rows, widths, rowColors = []) {
  const headerRow = new TableRow({ tableHeader: true, cantSplit: true, children: headers.map((t, i) => cell(t, { header: true, width: widths[i] })) });
  const bodyRows = rows.map((r, idx) => new TableRow({
    cantSplit: true,
    children: r.map((v, i) => (v && v.__status
      ? statusCell(v.__status, widths[i])
      : cell(v, { width: widths[i], shading: idx % 2 === 1 ? LIGHT : undefined, color: i === 0 ? undefined : rowColors[idx], bold: i === 0 }))),
  }));
  return new Table({
    width: { size: widths.reduce((a, b) => a + b, 0), type: WidthType.DXA },
    columnWidths: widths,
    borders: { top: NO_BORDER, bottom: NO_BORDER, left: NO_BORDER, right: NO_BORDER, insideHorizontal: NO_BORDER, insideVertical: NO_BORDER },
    rows: [headerRow, ...bodyRows],
  });
}

// KPI band: the numbers a reader wants before they read anything else.
function scorecard(tiles) {
  const w = Math.floor(TOTAL_W / tiles.length);
  return new Table({
    width: { size: TOTAL_W, type: WidthType.DXA },
    columnWidths: tiles.map(() => w),
    borders: { top: NO_BORDER, bottom: NO_BORDER, left: NO_BORDER, right: NO_BORDER, insideHorizontal: NO_BORDER, insideVertical: NO_BORDER },
    rows: [new TableRow({
      children: tiles.map((t) => new TableCell({
        width: { size: w, type: WidthType.DXA },
        shading: { type: ShadingType.CLEAR, fill: LIGHT },
        margins: { top: 160, bottom: 160, left: 140, right: 140 },
        borders: { top: NO_BORDER, bottom: NO_BORDER, left: { style: BorderStyle.SINGLE, size: 12, color: t.color || ACCENT }, right: NO_BORDER },
        children: [
          new Paragraph({ spacing: { after: 40 }, children: [new TextRun({ text: String(t.value), bold: true, size: 40, color: t.color || NAVY })] }),
          new Paragraph({ children: [new TextRun({ text: t.label, size: 15, color: MUTED, allCaps: true })] }),
        ],
      })),
    })],
  });
}
const yn = (b) => (b ? "Yes" : "No");
const sevColor = (s) => (s === "high" ? RED : s === "medium" ? AMBER : s === "review" ? AMBER : undefined);

function main() {
  const [, , findingsPath, siteName, siteUrl, ...rest] = process.argv;
  if (!findingsPath || !siteName || !siteUrl) {
    console.error("Usage: node generate_report.js <findings.json> <site-name> <site-url> [--out report.docx]");
    process.exit(1);
  }
  const outFlagIdx = rest.indexOf("--out");
  const outPath = outFlagIdx !== -1 ? rest[outFlagIdx + 1] : "Cookie_Consent_Compliance_Review.docx";

  const findings = JSON.parse(fs.readFileSync(findingsPath, "utf-8"));
  const { states, summary } = findings;
  const dateStr = new Date().toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" });

  const gaps = summary.consent_gaps || [];
  const hasGaps = gaps.length > 0;
  const matrix = summary.tracker_matrix || [];
  const cookieGapsPre = summary.cookie_gaps_pre_consent || [];
  const cookieGapsReject = summary.cookie_gaps_after_reject || [];
  const storageCaptured = !!summary.storage_captured;
  const necessary = summary.necessary_services_active || [];
  const catTests = summary.category_tests || [];
  const catViolations = summary.category_violations || [];
  const catInconclusive = catTests.filter((c) => !c.configured);
  // A state that never loaded observed nothing. Absent the flag (findings from
  // an older analyzer), assume the capture was fine rather than crying wolf.
  const captureUsable = summary.capture_usable !== false;
  const captureErrors = summary.capture_errors || [];
  const consentExercised = summary.consent_exercised !== false;
  const notExercised = summary.consent_not_exercised_states || [];
  // Loading the pages and actually clicking the banner are separate things, and
  // either one failing makes an empty finding list meaningless.
  const authoritative = captureUsable && consentExercised;
  const techMatrix = summary.technology_matrix || [];
  const duplicates = summary.duplicate_tags || [];
  const legacyTags = summary.legacy_tags || [];
  const healthScore = summary.health_score;
  const healthDeductions = summary.health_deductions || [];
  // Necessary services are infrastructure, not marketing technology, so the
  // headline platform count leaves them out - it is what a client recognizes.
  const platforms = techMatrix.filter((r) => !r.allowlisted_as_necessary);
  const scoreColor = healthScore == null ? MUTED : healthScore >= 85 ? GREEN : healthScore >= 60 ? AMBER : RED;
  const pagesVisited = summary.pages_visited || [];

  const children = [
    new Paragraph({ spacing: { before: 1600, after: 80 }, children: [new TextRun({ text: "COMPLIANCE REVIEW", size: 20, color: ACCENT, bold: true, allCaps: true })] }),
    new Paragraph({ spacing: { after: 120 }, children: [new TextRun({ text: "Cookie Consent & Tracking Audit", bold: true, size: 52, color: NAVY })] }),
    new Paragraph({
      spacing: { after: 400 },
      border: { bottom: { style: BorderStyle.SINGLE, size: 12, color: ACCENT, space: 8 } },
      children: [new TextRun({ text: "" })],
    }),
    new Paragraph({ spacing: { after: 60 }, children: [new TextRun({ text: siteName, size: 30, color: INK, bold: true })] }),
    new Paragraph({ spacing: { after: 400 }, children: [new TextRun({ text: siteUrl, size: 22, color: MUTED })] }),
    healthScore == null
      ? null
      : new Paragraph({ spacing: { after: 40 }, children: [new TextRun({ text: `${healthScore}`, bold: true, size: 96, color: scoreColor })] }),
    healthScore == null
      ? null
      : new Paragraph({ spacing: { after: 500 }, children: [new TextRun({ text: "OVERALL TRACKING HEALTH  /  100", size: 17, color: MUTED, allCaps: true })] }),
    captureUsable
      ? null
      : new Paragraph({ spacing: { before: 200, after: 400 }, children: [new TextRun({ text: "INCONCLUSIVE — CAPTURE INCOMPLETE, DO NOT RELY ON THESE RESULTS", bold: true, size: 24, color: RED })] }),
    captureUsable && !consentExercised
      ? new Paragraph({ spacing: { before: 200, after: 400 }, children: [new TextRun({ text: "INCONCLUSIVE — NO CONSENT BANNER WAS EXERCISED", bold: true, size: 24, color: RED })] })
      : null,
    new Paragraph({ spacing: { after: 40 }, children: [new TextRun({ text: `Prepared ${dateStr}`, size: 20, color: MUTED })] }),
    new Paragraph({ children: [new TextRun({ text: "Network traffic, cookies and web storage captured before consent, after accept, and after reject", size: 19, color: MUTED, italics: true })] }),

    h1("Executive Summary"),
    captureUsable
      ? scorecard([
          ...(healthScore == null ? [] : [{ value: `${healthScore}`, label: "Health / 100", color: scoreColor }]),
          { value: platforms.length, label: "Platforms", color: ACCENT },
          { value: gaps.length + catViolations.length, label: "Consent violations", color: (gaps.length + catViolations.length) ? RED : GREEN },
          { value: duplicates.length, label: "Duplicate tags", color: duplicates.length ? AMBER : GREEN },
          { value: legacyTags.length, label: "Legacy scripts", color: legacyTags.length ? AMBER : GREEN },
        ])
      : null,
    captureUsable ? p("", { size: 10 }) : null,
    p(`This review assessed the cookie/tracking consent behavior of ${siteName} (${siteUrl}) using live captures taken before any consent decision, immediately after accepting, and immediately after rejecting. Each state used a fresh, isolated browser session and visited the same set of pages, so the three states are directly comparable.`),
    captureUsable
      ? null
      : p(`CAPTURE INCONCLUSIVE — the site failed to load in ${captureErrors.length} of 3 consent states, so this run observed no traffic to judge. Nothing below is a pass: an empty finding means "not tested", not "nothing fired". The capture must be repaired and re-run before this document is relied upon for any compliance conclusion.`, { bold: true, color: RED }),
    captureUsable && !consentExercised
      ? p(`CAPTURE INCONCLUSIVE — no consent banner was found or clicked for the ${notExercised.join(" and ")} state(s), so no consent choice was ever made. Those captures are the pre-consent capture again under a different name, and agreement between them says nothing about whether this site gates its trackers. Either the site presents no consent banner at all, or automatic detection missed it; both need checking by hand before any conclusion is drawn.`, { bold: true, color: RED })
      : null,
    hasGaps
      ? p(`${gaps.length} third-party tracker(s) were found firing outside of proper consent gating.`, { bold: true, color: RED })
      : (authoritative
          ? p("No tracker consent gaps were found: every detected third-party tracker only activated after the visitor accepted, and none fired before consent or after rejection.", { bold: true, color: GREEN })
          : null),
    catViolations.length
      ? p(`${catViolations.length} tracker(s) fired despite their consent category being explicitly denied.`, { bold: true, color: RED })
      : (catTests.some((c) => c.configured)
          ? p("Per-category consent choices were honored: no tracker fired while its category was denied.", { color: GREEN })
          : null),
    catInconclusive.length
      ? p(`${catInconclusive.length} per-category scenario(s) could not be reliably configured and are reported as inconclusive rather than as passes.`, { italics: true, color: AMBER })
      : null,
    cookieGapsPre.length
      ? p(`${cookieGapsPre.length} tracking or third-party cookie(s) were set before any consent decision.`, { bold: true, color: RED })
      : (storageCaptured && authoritative
          ? p("No tracking or third-party cookies were set before a consent decision.", { color: GREEN })
          : (captureUsable
              ? p("Cookie/web-storage capture was not available for this run; findings below are based on network traffic only.", { italics: true, color: AMBER })
              : null)),
  ];

  // ---- Capture integrity: only present when something went wrong ----
  if (captureUsable && !consentExercised) {
    children.push(
      h1("Capture Integrity — Consent Was Never Exercised"),
      p(`No consent banner was found or clicked for the ${notExercised.join(" and ")} state(s). Those captures therefore repeat the pre-consent capture, and the fact that they agree with it is not evidence of correct gating.`, { bold: true, color: RED }),
      p("Two very different situations produce this result, and they cannot be told apart automatically: the site may present no consent banner at all, which is itself a significant finding; or it may use a banner that automatic detection did not recognize, in which case the capture simply needs re-running with the banner's real selectors. Confirm which before relying on anything in this report.", { italics: true }),
    );
  }

  if (!captureUsable) {
    children.push(
      h1("Capture Integrity — Results Not Valid"),
      p("This audit depends on loading the site in each consent state and recording what it does. The state(s) below did not load, so they contribute no observations. Any state listed here was not tested, and the absence of findings for it carries no meaning.", { bold: true, color: RED }),
      makeTable(
        ["State", "Outcome"],
        captureErrors.map((e) => [e.state, e.error]),
        [3477, 6603]
      ),
      p("Common causes: the network blocked the site or its trackers, the URL was wrong or redirected, or the browser could not start. Resolve the cause, re-run the capture, and confirm every state reports traffic before issuing this report.", { italics: true }),
    );
  }

  // ---- Scope of what was examined ----
  children.push(
    h2("Scope of This Audit"),
    makeTable(
      ["Measure", "Pre-consent", "Post-reject", "Post-accept"],
      [
        ["Network requests", String(states.pre.requests), String(states.postreject.requests), String(states.postaccept.requests)],
        ["Distinct trackers detected", String(Object.keys(states.pre.trackers).length), String(Object.keys(states.postreject.trackers).length), String(Object.keys(states.postaccept.trackers).length)],
        ["Third-party domains contacted", String(Object.keys(states.pre.third_party_domains || {}).length), String(Object.keys(states.postreject.third_party_domains || {}).length), String(Object.keys(states.postaccept.third_party_domains || {}).length)],
        ["Unclassified domains", String(states.pre.unknown_domain_count || 0), String(states.postreject.unknown_domain_count || 0), String(states.postaccept.unknown_domain_count || 0)],
        ["Cookies set", String((summary.cookie_counts || {}).pre ?? "n/a"), String((summary.cookie_counts || {}).postreject ?? "n/a"), String((summary.cookie_counts || {}).postaccept ?? "n/a")],
      ],
      [3477, 2201, 2201, 2201]
    ),
  );

  // ---- Technology inventory: the table a client reads first ----
  children.push(
    h1("Technology Inventory"),
    p("Every technology observed, what it is for, how many pages it was found on, and what it did at each stage of the consent flow. Services labelled \"necessary\" are expected to run before consent and are not counted in the headline violation total, but are listed here in full so the classification can be reviewed rather than taken on trust."),
  );
  if (techMatrix.length) {
    children.push(makeTable(
      ["Technology", "Vendor", "Purpose", "Pages", "Before consent", "After accept", "After reject", "Status", "Action"],
      techMatrix.map((r) => [
        r.technology, r.vendor, r.purpose,
        r.pages_found == null ? "\u2014" : String(r.pages_found),
        r.before_consent, r.after_accept, r.after_reject,
        { __status: r.status },
        r.action,
      ]),
      [1740, 990, 1210, 572, 1266, 990, 990, 616, 1706]
    ));
    children.push(p("\u25CF red = fires when it should not, or is obsolete   \u25CF amber = review needed   \u25CF green = behaving correctly", { size: 16, color: MUTED }));
    if (pagesVisited.length) {
      children.push(p(`Pages crawled in each state: ${pagesVisited.join(", ")}. "Pages" counts the distinct pages a technology was observed on; a technology gated until Accept is naturally absent from the pre-consent crawl.`, { size: 16, color: MUTED }));
    } else {
      children.push(p("Per-page attribution was not available for this capture, so the Pages column is shown as \u2014.", { size: 16, color: MUTED, italics: true }));
    }
    if (duplicates.length) {
      children.push(
        h2("Duplicate Deployments"),
        p("These technologies were loaded more than once with different container or measurement IDs. Duplicate tags double-count traffic and can fire outside the consent logic attached to the primary tag."),
        makeTable(["Technology", "IDs found"], duplicates.map((d) => [d.tracker, d.ids.join(", ")]), [3301, 6779]),
      );
    }
    if (legacyTags.length) {
      children.push(
        h2("Legacy Tags Still Collecting"),
        p("Universal Analytics stopped processing data in 2023. A tag still firing collects nothing useful while continuing to set cookies and contact the vendor, so it carries the compliance cost of tracking with none of the benefit.", { color: AMBER }),
        makeTable(["Technology", "IDs found"], legacyTags.map((d) => [d.tracker, d.ids.join(", ") || "\u2014"]), [3301, 6779]),
      );
    }
  }

  // ---- Underlying firing matrix, kept for full disclosure ----
  children.push(
    h1("Full Tracker Inventory"),
    p("The same technologies as the table above, expressed as the raw firing pattern the analysis is derived from."),
  );
  if (matrix.length) {
    children.push(makeTable(
      ["Tracker", "Pre", "Reject", "Accept", "Classification"],
      matrix.map((m) => [m.tracker, yn(m.pre_consent), yn(m.post_reject), yn(m.post_accept), m.classification]),
      [3081, 770, 880, 880, 4469],
      matrix.map((m) => sevColor(m.severity))
    ));
    children.push(p("Request volume per tracker, per state:", { bold: true }));
    children.push(makeTable(
      ["Tracker", "Pre-consent", "Post-reject", "Post-accept", "Example endpoint"],
      matrix.map((m) => [m.tracker, String(m.requests.pre), String(m.requests.postreject), String(m.requests.postaccept), (m.example_url || "").slice(0, 60)]),
      [2421, 1210, 1210, 1210, 4029]
    ));
  } else {
    children.push(p("No trackers from the signature list were observed in any state."));
  }

  // ---- Consent gaps ----
  children.push(h1("Consent Gap Analysis"));
  children.push(hasGaps
    ? makeTable(["Tracker", "Fired Pre-Consent", "Fired After Reject", "Severity"],
        gaps.map((g) => [g.tracker, yn(g.fired_pre_consent), yn(g.fired_after_reject), g.severity]),
        [3521, 2201, 2201, 2157], gaps.map((g) => sevColor(g.severity)))
    : p("No trackers fired before consent or after rejection was recorded."));

  // ---- Necessary services, shown in full ----
  children.push(
    h2("Services Classified as Necessary"),
    p("These were treated as strictly necessary (e.g. anti-spam, CAPTCHA, fraud prevention, payments) and so are excluded from the gap count above — but they did run, and their firing pattern is shown here. Whether each genuinely qualifies as \"strictly necessary\" is a legal determination that should be confirmed by whoever signs off on this audit."),
  );
  const necRows = matrix.filter((m) => m.allowlisted_as_necessary)
    .map((m) => [m.tracker, yn(m.pre_consent), yn(m.post_reject), yn(m.post_accept), m.severity === "review" ? "Confirm classification" : "Not observed pre-consent"]);
  children.push(necRows.length
    ? makeTable(["Service", "Pre", "Reject", "Accept", "Action"], necRows, [2861, 770, 880, 880, 4689])
    : p("No allowlisted necessary services were observed."));

  // ---- Per-category consent testing ----
  children.push(h1("Per-Category Consent Testing"));
  if (!catTests.length) {
    children.push(p("Not performed. No per-category controls were detected on this site's consent banner, or per-category testing was disabled for this run. Only all-accept and all-reject were exercised.", { italics: true, color: AMBER }));
  } else {
    children.push(p("Each scenario below granted exactly one consent category and denied every other non-necessary category, then re-captured traffic. A tracker belonging to a denied category that still fired is a violation of the visitor's stated choice \u2014 the failure mode that all-accept and all-reject testing cannot detect."));

    children.push(makeTable(
      ["Scenario (granted only)", "Result", "Trackers fired", "Violations"],
      catTests.map((c) => [
        c.granted,
        c.configured ? (c.violations.length ? "FAIL" : "Pass") : "Inconclusive",
        String((c.trackers_detected || []).length),
        c.configured ? String(c.violations.length) : "n/a",
      ]),
      [2861, 2201, 2421, 2597],
      catTests.map((c) => (!c.configured ? AMBER : c.violations.length ? RED : GREEN))
    ));

    if (catViolations.length) {
      children.push(h2("Category Violations"));
      children.push(p("These trackers fired while the visitor had explicitly declined their category.", { color: RED }));
      children.push(makeTable(
        ["Tracker", "Its category", "Fired when only this was granted", "Requests"],
        catViolations.map((v) => [v.tracker, v.category, v.granted_category, String(v.requests)]),
        [3081, 2201, 3081, 1717],
        catViolations.map(() => RED)
      ));
    }

    if (catInconclusive.length) {
      children.push(h2("Inconclusive Scenarios"));
      children.push(p("The consent preferences panel could not be driven reliably for these scenarios, so they prove nothing either way and are excluded from the results above. They are NOT passes. Re-run with explicit --settings-selector / --save-selector values, or test these categories by hand.", { color: AMBER }));
      children.push(makeTable(
        ["Scenario", "Why it could not be tested"],
        catInconclusive.map((c) => [c.granted, c.inconclusive_reason || "unknown"]),
        [2641, 7439]
      ));
    }

    const uncategorized = [...new Set(catTests.flatMap((c) => (c.uncategorized || []).map((u) => u.tracker)))];
    if (uncategorized.length) {
      children.push(h2("Services With No Category Assigned"));
      children.push(p(`These fired during per-category testing but are not mapped to a consent category, so no automated verdict was reached for them. Review manually against the site's declared categories: ${uncategorized.join(", ")}.`, { color: AMBER }));
    }

    for (const c of catTests.filter((x) => x.configured && (x.toggles || []).length)) {
      children.push(h2(`Consent State Applied \u2014 granted "${c.granted}" only`));
      children.push(makeTable(
        ["Category control", "Detected as", "Set to"],
        c.toggles.map((t) => [t.label || "(unlabelled)", t.category, t.wanted ? "Allowed" : "Denied"]),
        [5062, 2509, 2509]
      ));
    }
  }

  // ---- Cookies ----
  children.push(h1("Cookies and Web Storage"));
  if (!storageCaptured) {
    children.push(p("Cookie and web-storage capture was not available for this run. Re-run the capture step to include this section.", { italics: true, color: AMBER }));
  } else {
    children.push(p("Captured directly from the browser, so this covers cookies written by JavaScript (document.cookie) as well as those set via HTTP headers."));

    if (cookieGapsPre.length) {
      children.push(h2("Cookies Set Before Consent"), p("These are set before the visitor makes any choice, and are the most direct evidence of a consent failure.", { color: RED }));
      children.push(makeTable(
        ["Cookie", "Domain", "Attributed To", "Lifetime", "Third-party"],
        cookieGapsPre.map((c) => [c.name, c.registrable_domain, c.attributed_to || "Unidentified", c.session_cookie ? "Session" : `${c.expires_days} days`, yn(c.third_party)]),
        [2420, 2421, 2421, 1541, 1277], cookieGapsPre.map(() => RED)
      ));
    } else {
      children.push(h2("Cookies Set Before Consent"), p("None — no tracking or third-party cookies were present before a consent decision.", { color: GREEN }));
    }

    if (cookieGapsReject.length) {
      children.push(h2("Cookies Still Present After Reject"));
      children.push(makeTable(
        ["Cookie", "Domain", "Attributed To", "Lifetime", "Third-party"],
        cookieGapsReject.map((c) => [c.name, c.registrable_domain, c.attributed_to || "Unidentified", c.session_cookie ? "Session" : `${c.expires_days} days`, yn(c.third_party)]),
        [2420, 2421, 2421, 1541, 1277], cookieGapsReject.map(() => AMBER)
      ));
    }

    for (const [key, label] of [["pre", "Pre-consent"], ["postreject", "Post-reject"], ["postaccept", "Post-accept"]]) {
      const st = states[key].storage || {};
      const cookies = st.cookies || [];
      children.push(h2(`All Cookies — ${label} (${cookies.length})`));
      children.push(cookies.length
        ? makeTable(
            ["Cookie", "Domain", "Lifetime", "Third-party", "Attributed To"],
            cookies.map((c) => [c.name, c.registrable_domain, c.session_cookie ? "Session" : `${c.expires_days}d`, yn(c.third_party), c.attributed_to || "—"]),
            [2640, 2421, 1541, 1431, 2047],
            cookies.map((c) => (c.long_lived ? AMBER : undefined)))
        : p("No cookies observed in this state."));
      const ls = st.local_storage || [];
      if (ls.length) {
        children.push(p(`localStorage keys (${ls.length}): ${ls.map((i) => i.name).join(", ")}`, { size: 18 }));
      }
      const ss = st.session_storage || [];
      if (ss.length) {
        children.push(p(`sessionStorage keys (${ss.length}): ${ss.map((i) => i.name).join(", ")}`, { size: 18 }));
      }
    }
    children.push(p(`Cookies with a lifetime over 180 days are highlighted. Long retention periods are a common regulator finding even when consent gating itself is correct.`, { italics: true, size: 18, color: "555555" }));
  }

  // ---- Every third-party domain ----
  const tpAll = summary.third_party_domains_all_states || {};
  const tpKeys = Object.keys(tpAll);
  children.push(
    h1("All Third-Party Domains Contacted"),
    p(`Every non-first-party domain contacted in any state (${tpKeys.length} total). Domains with no entry in the tracker signature list are marked "Unclassified" — these are undeclared third parties that warrant manual review, and are a frequent source of audit findings.`),
  );
  children.push(tpKeys.length
    ? makeTable(
        ["Domain", "Pre", "Reject", "Accept", "Identified As"],
        tpKeys.map((d) => [d, String(tpAll[d].pre || 0), String(tpAll[d].postreject || 0), String(tpAll[d].postaccept || 0), tpAll[d].tracker || "Unclassified"]),
        [3521, 770, 880, 880, 4029],
        tpKeys.map((d) => (!tpAll[d].tracker && tpAll[d].pre ? AMBER : undefined)))
    : p("No third-party domains were contacted."));

  // ---- Recommendations ----
  if (healthScore != null) {
    children.push(
      h1("How the Health Score Was Calculated"),
      p("The score is a transparent deduction rubric, not a legal grade or a certification. It starts at 100 and subtracts for each finding below, so every point lost maps to something named in this report and can be argued with. A high score is not a statement of legal compliance, which depends on jurisdiction and on how the site declares its own cookie categories."),
    );
    children.push(healthDeductions.length
      ? makeTable(["Points", "Finding"], healthDeductions.map((d) => [`-${d.points}`, d.reason]), [1321, 8759])
      : p("No deductions were applied: no consent gaps, duplicate tags or legacy tags were observed.", { color: GREEN }));
    children.push(p(`Starting score 100, less ${healthDeductions.reduce((a, d) => a + d.points, 0)} points, gives ${healthScore}.`, { bold: true }));
  }

  children.push(h1("Recommendations"));
  const recs = [];
  if (captureUsable && !consentExercised) {
    recs.push(bullet(`Establish whether ${siteName} presents a consent banner at all. If it does, re-run this audit with explicit --accept-selector and --reject-selector values so the banner is actually exercised; if it does not, that absence is the finding, and the pre-consent behavior recorded here is what every visitor gets.`));
  }
  if (!captureUsable) {
    recs.push(bullet(`Re-run the capture: the site did not load in ${captureErrors.length} of 3 consent states, so this audit reached no conclusion. Every other item in this report is limited to what the states that did load revealed.`));
  }
  if (hasGaps) {
    recs.push(bullet("Move any tracker listed with 'Fired Pre-Consent: Yes' behind the consent management platform's gating logic immediately — this is the highest-severity finding."));
    recs.push(bullet("For trackers still active after rejection, confirm the CMP's 'Reject All' action is correctly wired to block that specific tag."));
  }
  if (catViolations.length) {
    const byCat = [...new Set(catViolations.map((v) => v.category))];
    recs.push(bullet(`Fix the per-category gating for: ${byCat.join(", ")}. A tracker firing when its own category was declined means the CMP's category mapping is wrong or the tag is not registered with the CMP at all \u2014 a visitor-facing promise the site is not keeping.`));
  }
  if (catInconclusive.length) {
    recs.push(bullet(`Re-test the inconclusive scenario(s) (${catInconclusive.map((c) => c.granted).join(", ")}) with explicit preference-panel selectors, or manually. They are untested, not passing.`));
  }
  if (duplicates.length) {
    recs.push(bullet(`Remove the duplicate deployment of ${duplicates.map((d) => d.tracker).join(", ")}. Two containers double-count traffic, and the second one is rarely wired into the same consent logic as the first.`));
  }
  if (legacyTags.length) {
    recs.push(bullet(`Remove the legacy tag(s) for ${legacyTags.map((d) => d.tracker).join(", ")}. Universal Analytics no longer processes data, so these collect nothing while still setting cookies and contacting the vendor.`));
  }
  const consentModeRows = techMatrix.filter((r) => r.action === "Verify consent mode configuration");
  if (consentModeRows.length) {
    recs.push(bullet(`Confirm with counsel whether the cookieless pings sent before consent by ${consentModeRows.map((r) => r.technology).join(", ")} are acceptable in the relevant jurisdictions. These requests carry no storage access, which is consent mode working as designed, but they are still a contact with the vendor before the visitor has chosen.`));
  }
  if (cookieGapsPre.length) {
    recs.push(bullet("Remove or defer the cookies listed under 'Cookies Set Before Consent'. Note that blocking a tracker's network requests does not by itself stop a cookie already written by inline JavaScript."));
  }
  if (cookieGapsReject.length) {
    recs.push(bullet("Cookies persisting after 'Reject All' should be actively deleted by the CMP, not merely left un-refreshed."));
  }
  if (necessary.length) {
    recs.push(bullet(`Confirm with counsel that each service classified as strictly necessary (${necessary.join(", ")}) genuinely meets that bar in the relevant jurisdictions — this classification suppresses them from the gap count.`));
  }
  const unclassifiedPre = tpKeys.filter((d) => !tpAll[d].tracker && tpAll[d].pre);
  if (unclassifiedPre.length) {
    recs.push(bullet(`Manually review the ${unclassifiedPre.length} unclassified third-party domain(s) contacted before consent: ${unclassifiedPre.slice(0, 12).join(", ")}${unclassifiedPre.length > 12 ? ", …" : ""}.`));
  }
  recs.push(bullet("Confirm the consent management platform's declared cookie categories list every tracker and cookie observed here — undisclosed trackers are a common audit finding even when gating itself works correctly."));
  recs.push(bullet("Re-run this audit after any fixes, and periodically thereafter, since tag managers can introduce new trackers without a corresponding banner update."));
  children.push(...recs);

  // ---- Methodology ----
  children.push(
    h1("Methodology"),
    bullet("Captured full HAR (HTTP Archive) network traffic in three fresh, isolated browser sessions: no interaction, immediately after Accept All, and immediately after Reject All."),
    bullet("Each state visited the same set of pages, so request counts and tracker sets are directly comparable between states."),
    bullet("Read cookies, localStorage and sessionStorage directly from each browser context, capturing client-side storage that HTTP-level traffic alone does not reveal."),
    bullet("Classified requests and cookie domains against a signature list of common analytics, advertising, and marketing services."),
    bullet("Cross-referenced each tracker, cookie and third-party domain across states to identify consent-gating gaps."),
    ...(catTests.length ? [bullet("Additionally exercised each consent category individually: opened the preferences panel, granted exactly one category, denied the rest, saved, and re-captured. Scenarios where the panel could not be driven reliably are reported as inconclusive rather than as passes.")] : []),
    p("Limitations: a state that fails to load produces no observations, and is reported as inconclusive rather than as a clean result. Category assignment for each service is a judgment call and should be checked against the site's own declared cookie categories. First/third-party classification uses a best-effort registrable-domain heuristic. Trackers absent from the signature list appear as unclassified domains rather than named services, and require manual review. A capture reflects one point in time; tag manager changes can alter behavior at any point after it.", { italics: true, color: "555555", size: 18 }),
  );

  const doc = new Document({
    styles: { default: { document: { run: { font: "Calibri", size: 22 } } } },
    sections: [
      {
        properties: {
          titlePage: true, // the cover carries no page number
          page: { size: { width: 12240, height: 15840 }, margin: { top: 1080, bottom: 1080, left: 1080, right: 1080 } },
        },
        footers: {
          first: new Footer({ children: [new Paragraph({ children: [] })] }),
          default: new Footer({
            children: [new Paragraph({
              alignment: AlignmentType.RIGHT,
              children: [new TextRun({
                children: [`${siteName}  \u00B7  Page `, PageNumber.CURRENT, " of ", PageNumber.TOTAL_PAGES],
                size: 16,
                color: MUTED,
              })],
            })],
          }),
        },
        // Conditional summary lines above evaluate to null when they don't apply.
        children: children.filter(Boolean),
      },
    ],
  });

  Packer.toBuffer(doc)
    .then((buf) => collapseHeadings(buf, COLLAPSED_SECTIONS))
    .then((buf) => {
      fs.writeFileSync(outPath, buf);
      console.log(`Report written to ${outPath}`);
    })
    .catch((err) => {
      console.error(`Failed to write report: ${err.message}`);
      process.exitCode = 1;
    });
}

// Sections that open folded away. These are exhaustive reference dumps: a
// reader needs them to check a specific cookie, not to understand the finding,
// and at full length they bury the sections that carry the conclusions.
//
// This is a reading convenience in Word on the desktop only. Word Online,
// LibreOffice, Google Docs and every PDF export ignore it and show the section
// expanded, so it never hides anything from the record — the content is present
// and complete either way.
const COLLAPSED_SECTIONS = ["Cookies and Web Storage"];

// Word folds a heading when its paragraph carries <w:collapsed/>. The docx
// library has no API for it, so the packed file is patched after the fact.
async function collapseHeadings(buf, headings) {
  if (!headings || !headings.length) return buf;
  const zip = await JSZip.loadAsync(buf);
  const entry = zip.file("word/document.xml");
  if (!entry) return buf;

  let xml = await entry.async("string");
  for (const heading of headings) {
    const patched = withCollapsed(xml, heading);
    if (patched === null) {
      // Worth saying out loud: a renamed section would otherwise silently stop
      // collapsing, and the only symptom is a report that reads as too long.
      console.warn(`  Note: "${heading}" not found as a heading; it will open expanded.`);
    } else {
      xml = patched;
    }
  }

  zip.file("word/document.xml", xml);
  return zip.generateAsync({ type: "nodebuffer", compression: "DEFLATE" });
}

// Returns the patched XML, or null if the heading could not be located — never
// a silently unchanged document.
function withCollapsed(xml, headingText) {
  const escaped = headingText.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  const at = xml.indexOf(`<w:t xml:space="preserve">${escaped}</w:t>`);
  if (at === -1) return null;

  const pStart = xml.lastIndexOf("<w:p>", at);
  if (pStart === -1) return null;
  const pPrStart = xml.indexOf("<w:pPr>", pStart);
  const pPrEnd = xml.indexOf("</w:pPr>", pStart);
  if (pPrStart === -1 || pPrEnd === -1 || pPrStart > at || pPrEnd > at) return null;

  const pPr = xml.slice(pPrStart, pPrEnd);
  if (!/<w:pStyle w:val="Heading/.test(pPr)) return null; // only real headings fold
  if (pPr.includes("<w:collapsed/>")) return xml;

  // Immediately after <w:pStyle/>, which is where Word itself writes it.
  const styleClose = xml.indexOf("/>", xml.indexOf("<w:pStyle", pPrStart)) + 2;
  return xml.slice(0, styleClose) + "<w:collapsed/>" + xml.slice(styleClose);
}

main();
