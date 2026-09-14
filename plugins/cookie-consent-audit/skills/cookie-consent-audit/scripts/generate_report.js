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
  WidthType, ShadingType, AlignmentType, PageBreak,
} = require("docx");
const fs = require("fs");

const NAVY = "1F3864";
const LIGHT = "F2F2F2";
const RED = "B00020";
const AMBER = "8A6100";
const GREEN = "1B5E20";
const TOTAL_W = 9160;

function h1(text) {
  return new Paragraph({ heading: HeadingLevel.HEADING_1, spacing: { before: 300, after: 150 }, children: [new TextRun({ text, bold: true, color: NAVY })] });
}
function h2(text) {
  return new Paragraph({ heading: HeadingLevel.HEADING_2, spacing: { before: 240, after: 120 }, children: [new TextRun({ text, bold: true, color: NAVY })] });
}
function p(text, opts = {}) {
  return new Paragraph({ spacing: { after: 160 }, children: [new TextRun({ text, ...opts })] });
}
function bullet(text, opts = {}) {
  return new Paragraph({ bullet: { level: 0 }, spacing: { after: 80 }, children: [new TextRun({ text, ...opts })] });
}
function cell(text, { header = false, width, shading, color } = {}) {
  return new TableCell({
    width: { size: width, type: WidthType.DXA },
    shading: shading ? { type: ShadingType.CLEAR, fill: shading } : undefined,
    children: [new Paragraph({ children: [new TextRun({ text: String(text), bold: header, color: header ? "FFFFFF" : color, size: header ? 20 : 18 })] })],
  });
}
function makeTable(headers, rows, widths, rowColors = []) {
  const headerRow = new TableRow({ tableHeader: true, children: headers.map((t, i) => cell(t, { header: true, width: widths[i], shading: NAVY })) });
  const bodyRows = rows.map((r, idx) => new TableRow({
    children: r.map((v, i) => cell(v, { width: widths[i], shading: idx % 2 === 1 ? LIGHT : undefined, color: i === 0 ? undefined : rowColors[idx] })),
  }));
  return new Table({ width: { size: widths.reduce((a, b) => a + b, 0), type: WidthType.DXA }, columnWidths: widths, rows: [headerRow, ...bodyRows] });
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

  const children = [
    new Paragraph({ spacing: { before: 1400 }, alignment: AlignmentType.CENTER, children: [new TextRun({ text: "Cookie Consent Compliance Review", bold: true, size: 44, color: NAVY })] }),
    new Paragraph({ spacing: { before: 200 }, alignment: AlignmentType.CENTER, children: [new TextRun({ text: `${siteName} — ${siteUrl}`, size: 28, color: "444444" })] }),
    new Paragraph({ spacing: { before: 600 }, alignment: AlignmentType.CENTER, children: [new TextRun({ text: `Prepared ${dateStr}`, size: 22, color: "666666" })] }),
    new Paragraph({ spacing: { before: 100 }, alignment: AlignmentType.CENTER, children: [new TextRun({ text: "Full audit — network traffic, cookies and web storage across pre-consent, post-accept and post-reject states", size: 20, color: "666666", italics: true })] }),
    new Paragraph({ children: [new PageBreak()] }),

    h1("Executive Summary"),
    p(`This review assessed the cookie/tracking consent behavior of ${siteName} (${siteUrl}) using live captures taken before any consent decision, immediately after accepting, and immediately after rejecting. Each state used a fresh, isolated browser session and visited the same set of pages, so the three states are directly comparable.`),
    hasGaps
      ? p(`${gaps.length} third-party tracker(s) were found firing outside of proper consent gating.`, { bold: true, color: RED })
      : p("No tracker consent gaps were found: every detected third-party tracker only activated after the visitor accepted, and none fired before consent or after rejection.", { bold: true, color: GREEN }),
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
      : (storageCaptured
          ? p("No tracking or third-party cookies were set before a consent decision.", { color: GREEN })
          : p("Cookie/web-storage capture was not available for this run; findings below are based on network traffic only.", { italics: true, color: AMBER })),
  ];

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
      [3160, 2000, 2000, 2000]
    ),
  );

  // ---- Full tracker inventory: every tracker, every state ----
  children.push(
    h1("Full Tracker Inventory"),
    p("Every tracker observed in any state, with its complete firing pattern. Services labelled \"necessary\" are expected to run pre-consent and are not counted in the headline gap total, but are listed here in full so the classification can be reviewed rather than taken on trust."),
  );
  if (matrix.length) {
    children.push(makeTable(
      ["Tracker", "Pre", "Reject", "Accept", "Classification"],
      matrix.map((m) => [m.tracker, yn(m.pre_consent), yn(m.post_reject), yn(m.post_accept), m.classification]),
      [2800, 700, 800, 800, 4060],
      matrix.map((m) => sevColor(m.severity))
    ));
    children.push(p("Request volume per tracker, per state:", { bold: true }));
    children.push(makeTable(
      ["Tracker", "Pre-consent", "Post-reject", "Post-accept", "Example endpoint"],
      matrix.map((m) => [m.tracker, String(m.requests.pre), String(m.requests.postreject), String(m.requests.postaccept), (m.example_url || "").slice(0, 60)]),
      [2200, 1100, 1100, 1100, 3660]
    ));
  } else {
    children.push(p("No trackers from the signature list were observed in any state."));
  }

  // ---- Consent gaps ----
  children.push(h1("Consent Gap Analysis"));
  children.push(hasGaps
    ? makeTable(["Tracker", "Fired Pre-Consent", "Fired After Reject", "Severity"],
        gaps.map((g) => [g.tracker, yn(g.fired_pre_consent), yn(g.fired_after_reject), g.severity]),
        [3200, 2000, 2000, 1960], gaps.map((g) => sevColor(g.severity)))
    : p("No trackers fired before consent or after rejection was recorded."));

  // ---- Necessary services, shown in full ----
  children.push(
    h2("Services Classified as Necessary"),
    p("These were treated as strictly necessary (e.g. anti-spam, CAPTCHA, fraud prevention, payments) and so are excluded from the gap count above — but they did run, and their firing pattern is shown here. Whether each genuinely qualifies as \"strictly necessary\" is a legal determination that should be confirmed by whoever signs off on this audit."),
  );
  const necRows = matrix.filter((m) => m.allowlisted_as_necessary)
    .map((m) => [m.tracker, yn(m.pre_consent), yn(m.post_reject), yn(m.post_accept), m.severity === "review" ? "Confirm classification" : "Not observed pre-consent"]);
  children.push(necRows.length
    ? makeTable(["Service", "Pre", "Reject", "Accept", "Action"], necRows, [2600, 700, 800, 800, 4260])
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
      [2600, 2000, 2200, 2360],
      catTests.map((c) => (!c.configured ? AMBER : c.violations.length ? RED : GREEN))
    ));

    if (catViolations.length) {
      children.push(h2("Category Violations"));
      children.push(p("These trackers fired while the visitor had explicitly declined their category.", { color: RED }));
      children.push(makeTable(
        ["Tracker", "Its category", "Fired when only this was granted", "Requests"],
        catViolations.map((v) => [v.tracker, v.category, v.granted_category, String(v.requests)]),
        [2800, 2000, 2800, 1560],
        catViolations.map(() => RED)
      ));
    }

    if (catInconclusive.length) {
      children.push(h2("Inconclusive Scenarios"));
      children.push(p("The consent preferences panel could not be driven reliably for these scenarios, so they prove nothing either way and are excluded from the results above. They are NOT passes. Re-run with explicit --settings-selector / --save-selector values, or test these categories by hand.", { color: AMBER }));
      children.push(makeTable(
        ["Scenario", "Why it could not be tested"],
        catInconclusive.map((c) => [c.granted, c.inconclusive_reason || "unknown"]),
        [2400, 6760]
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
        [4600, 2280, 2280]
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
        [2200, 2200, 2200, 1400, 1160], cookieGapsPre.map(() => RED)
      ));
    } else {
      children.push(h2("Cookies Set Before Consent"), p("None — no tracking or third-party cookies were present before a consent decision.", { color: GREEN }));
    }

    if (cookieGapsReject.length) {
      children.push(h2("Cookies Still Present After Reject"));
      children.push(makeTable(
        ["Cookie", "Domain", "Attributed To", "Lifetime", "Third-party"],
        cookieGapsReject.map((c) => [c.name, c.registrable_domain, c.attributed_to || "Unidentified", c.session_cookie ? "Session" : `${c.expires_days} days`, yn(c.third_party)]),
        [2200, 2200, 2200, 1400, 1160], cookieGapsReject.map(() => AMBER)
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
            [2400, 2200, 1400, 1300, 1860],
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
        [3200, 700, 800, 800, 3660],
        tpKeys.map((d) => (!tpAll[d].tracker && tpAll[d].pre ? AMBER : undefined)))
    : p("No third-party domains were contacted."));

  // ---- Recommendations ----
  children.push(h1("Recommendations"));
  const recs = [];
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
    p("Limitations: category assignment for each service is a judgment call and should be checked against the site's own declared cookie categories. First/third-party classification uses a best-effort registrable-domain heuristic. Trackers absent from the signature list appear as unclassified domains rather than named services, and require manual review. A capture reflects one point in time; tag manager changes can alter behavior at any point after it.", { italics: true, color: "555555", size: 18 }),
  );

  const doc = new Document({
    styles: { default: { document: { run: { font: "Calibri", size: 22 } } } },
    sections: [
      {
        properties: { page: { size: { width: 12240, height: 15840 }, margin: { top: 1080, bottom: 1080, left: 1080, right: 1080 } } },
        // Conditional summary lines above evaluate to null when they don't apply.
        children: children.filter(Boolean),
      },
    ],
  });

  Packer.toBuffer(doc).then((buf) => {
    fs.writeFileSync(outPath, buf);
    console.log(`Report written to ${outPath}`);
  });
}

main();
