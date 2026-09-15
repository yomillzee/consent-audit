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
  Bookmark, InternalHyperlink,
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
// The swatch is derived from the same verdict as everything else, so it cannot
// disagree with the row it sits in.
const STATUS_COLOR = { red: RED, amber: AMBER, green: GREEN, grey: MUTED };
const STATUS_MARK = { red: "\u25CF", amber: "\u25CF", green: "\u25CF", grey: "\u25CB" };

// keepNext/keepLines stop a heading being stranded at the foot of a page with
// its table overleaf — the most visible flaw in a generated document. Each
// top-level section starts on its own page, so a reader can hand one section to
// a colleague without it beginning halfway down a sheet.
// Every top-level section is bookmarked as it is built, and the contents list
// is assembled from that registry afterwards. Sections appear conditionally, so
// deriving the list from what was actually emitted keeps the two in step.
const tocSections = [];

function anchorFor(text) {
  return "sec_" + text.toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "");
}

function h1(text, { pageBreak = true } = {}) {
  const anchor = anchorFor(text);
  tocSections.push({ text, anchor });
  return new Paragraph({
    heading: HeadingLevel.HEADING_1,
    spacing: { before: 300, after: 150 },
    keepNext: true,
    keepLines: true,
    pageBreakBefore: pageBreak,
    children: [new Bookmark({ id: anchor, children: [new TextRun({ text, bold: true, color: NAVY })] })],
  });
}

// Built from bookmarks rather than a Word TOC field on purpose: a TOC field
// renders blank until fields are refreshed, and forcing a refresh makes Word
// open the document with an "update fields?" prompt, which on a compliance
// deliverable reads as though the file is damaged. Static links cost the page
// numbers and keep everything else, including live links in exported PDFs.
function contentsPage() {
  return [
    new Paragraph({
      heading: HeadingLevel.HEADING_1,
      spacing: { before: 300, after: 200 },
      keepNext: true,
      keepLines: true,
      pageBreakBefore: true,
      children: [new TextRun({ text: "Contents", bold: true, color: NAVY })],
    }),
    ...tocSections.map((sec) => new Paragraph({
      spacing: { after: 90 },
      children: [new InternalHyperlink({
        anchor: sec.anchor,
        children: [new TextRun({ text: sec.text, color: ACCENT, underline: {} })],
      })],
    })),
  ];
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
// Every table, swatch, count and recommendation is meant to derive from one
// verdict per technology. When that slipped, the report disagreed with itself
// in print — the firing matrix called a technology a gap while the findings
// called it a pass — and nothing caught it. Contradictions now stop the build.
const VALID_RESULTS = ["PASS", "CONFIRMED GAP", "REVIEW REQUIRED", "INCONCLUSIVE"];
const EXPECTED_STATUS = {
  "PASS": "green", "CONFIRMED GAP": "red",
  "REVIEW REQUIRED": "amber", "INCONCLUSIVE": "grey",
};

function validateConsistency(summary, findings) {
  const problems = [];
  const canonical = new Map(findings.map((f) => [f.technology, f]));

  for (const f of findings) {
    if (!VALID_RESULTS.includes(f.technical_result)) {
      problems.push(`${f.technology}: unknown technical_result ${JSON.stringify(f.technical_result)}`);
    }
    if (f.result !== f.technical_result) {
      problems.push(`${f.technology}: result ${f.result} disagrees with technical_result ${f.technical_result}`);
    }
    if (f.technical_result === "CONFIRMED GAP" && !(f.evidence || []).length) {
      problems.push(`${f.technology}: a confirmed gap with no supporting evidence`);
    }
  }

  const counted = new Map([["CONFIRMED GAP", "confirmed"], ["REVIEW REQUIRED", "review"],
                           ["PASS", "passed"], ["INCONCLUSIVE", "inconclusive"]]);
  const counts = summary.result_counts || {};
  for (const [result, key] of counted) {
    const actual = findings.filter((f) => f.technical_result === result).length;
    if ((counts[key] ?? actual) !== actual) {
      problems.push(`result_counts.${key} says ${counts[key]} but ${actual} findings are ${result}`);
    }
  }

  for (const m of summary.tracker_matrix || []) {
    const f = canonical.get(m.tracker);
    if (!f) continue;
    if (m.classification !== f.technical_result) {
      problems.push(`${m.tracker}: firing matrix says "${m.classification}", findings say "${f.technical_result}"`);
    }
  }

  for (const r of summary.technology_matrix || []) {
    const want = EXPECTED_STATUS[r.technical_result];
    if (want && r.status !== want) {
      problems.push(`${r.technology}: ${r.technical_result} should be ${want}, status is ${r.status}`);
    }
    if (r.legal_note && r.technical_result !== "PASS") {
      problems.push(`${r.technology}: a legal note is attached to a ${r.technical_result}, which conflates the two`);
    }
  }

  const gapNames = new Set((summary.consent_gaps || []).map((g) => g.tracker));
  for (const f of findings) {
    if (f.technical_result === "CONFIRMED GAP" && canonical.has(f.technology) && !gapNames.has(f.technology)
        && (summary.tracker_matrix || []).some((m) => m.tracker === f.technology)) {
      problems.push(`${f.technology} is a confirmed gap but is missing from consent_gaps`);
    }
  }

  const scen = summary.scenario_counts || {};
  const listed = (summary.category_scenarios_inconclusive || []).length;
  if (scen.inconclusive !== undefined && scen.inconclusive !== listed) {
    problems.push(`scenario_counts.inconclusive says ${scen.inconclusive} but ${listed} scenarios are listed inconclusive`);
  }

  if (problems.length) {
    console.error("Report not generated: the findings contradict each other.");
    for (const p of problems) console.error(`  - ${p}`);
    console.error("This is a bug in the analyzer, not in the site. Every section must");
    console.error("derive from one verdict per technology.");
    process.exit(1);
  }
}

function glossaryEntry(term, definition) {
  return new Paragraph({
    spacing: { after: 140 },
    children: [
      new TextRun({ text: `${term} — `, bold: true, color: NAVY }),
      new TextRun({ text: definition, color: INK }),
    ],
  });
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
  // A band, not a number. The old 0-100 score could deduct past 100 and floor
  // at zero, so a site with six problems and one with twenty both read 0/100 —
  // precision the evidence never supported. Bands rest on CONFIRMED findings;
  // uncertainty moves the status to "Minor Issues" at worst, never to failure.
  const overallStatus = summary.overall_status || "Inconclusive";
  const counts = summary.result_counts || { confirmed: 0, review: 0, passed: 0, inconclusive: 0 };
  const techFindings = summary.findings || [];
  validateConsistency(summary, techFindings);
  const confirmedFindings = techFindings.filter((f) => f.result === "CONFIRMED GAP");
  const reviewFindings = techFindings.filter((f) => f.result === "REVIEW REQUIRED");
  const STATUS_COLORS = {
    "Healthy": GREEN, "Minor Issues": AMBER,
    "Action Required": RED, "Significant Issues": RED, "Inconclusive": MUTED,
  };
  // Necessary services are infrastructure, not marketing technology, so the
  // headline platform count leaves them out - it is what a client recognizes.
  const platforms = techMatrix.filter((r) => !r.allowlisted_as_necessary);
  const pagesVisited = summary.pages_visited || [];

  // Reference tables collected while the body is built, emitted at the end.
  const appendix = [];

  // Held in a variable so the contents list can be spliced in ahead of it once
  // every section has registered itself.
  const execSummaryHeading = h1("Executive Summary");

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
    new Paragraph({ spacing: { after: 40 }, children: [new TextRun({ text: overallStatus, bold: true, size: 56, color: STATUS_COLORS[overallStatus] || MUTED })] }),
    new Paragraph({ spacing: { after: 500 }, children: [new TextRun({ text: "OVERALL STATUS", size: 17, color: MUTED, allCaps: true })] }),
    captureUsable
      ? null
      : new Paragraph({ spacing: { before: 200, after: 400 }, children: [new TextRun({ text: "INCONCLUSIVE — CAPTURE INCOMPLETE, DO NOT RELY ON THESE RESULTS", bold: true, size: 24, color: RED })] }),
    captureUsable && !consentExercised
      ? new Paragraph({ spacing: { before: 200, after: 400 }, children: [new TextRun({ text: "INCONCLUSIVE — NO CONSENT BANNER WAS EXERCISED", bold: true, size: 24, color: RED })] })
      : null,
    new Paragraph({ spacing: { after: 40 }, children: [new TextRun({ text: `Prepared ${dateStr}`, size: 20, color: MUTED })] }),
    new Paragraph({ children: [new TextRun({ text: "Network traffic, cookies and web storage captured before consent, after accept, and after reject", size: 19, color: MUTED, italics: true })] }),

    execSummaryHeading,
    captureUsable
      ? scorecard([
          { value: counts.confirmed, label: "Confirmed gaps", color: counts.confirmed ? RED : GREEN },
          { value: counts.review, label: "Review required", color: counts.review ? AMBER : GREEN },
          { value: counts.passed, label: "Passed checks", color: GREEN },
          { value: counts.inconclusive, label: "Inconclusive", color: counts.inconclusive ? AMBER : MUTED },
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
      ? p((() => {
          // "third-party" was misleading: these are usually first-party
          // cookies written by a vendor's script. Naming the owner and the
          // cookies is both more accurate and more actionable.
          const owners = [...new Set(cookieGapsPre.map((c) => c.attributed_to).filter(Boolean))];
          const names = [...new Set(cookieGapsPre.map((c) => c.name))];
          const survived = cookieGapsReject.length ? " They remained after Reject All." : "";
          const who = owners.length === 1 ? `${owners[0]} ` : owners.length ? `${owners.join(", ")} ` : "";
          return `${cookieGapsPre.length} non-essential ${who}cookie(s) were set before any consent decision: ${names.join(", ")}.${survived}`;
        })(), { bold: true, color: RED })
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
        r.display_name || r.technology, r.vendor, r.purpose,
        r.pages_found == null ? "\u2014" : String(r.pages_found),
        r.before_consent, r.after_accept, r.after_reject,
        { __status: r.status },
        r.action,
      ]),
      [1740, 990, 1210, 572, 1266, 990, 990, 616, 1706]
    ));
    children.push(p("\u25CF red = confirmed gap, evidence contradicts the consent state   \u25CF amber = review required, observed but not established   \u25CF green = passed the technical checks   \u25CB grey = inconclusive, not tested", { size: 16, color: MUTED }));
    if (techMatrix.some((r) => r.legal_note)) {
      children.push(p("A green result means the implementation behaves correctly. Where a legal question applies to correct behaviour it is noted against that technology rather than counted as a fault: this is a technical audit, not a legal opinion.", { size: 16, color: MUTED, italics: true }));
    }
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

  // ---- Confirmed findings, each with the evidence behind it ----
  children.push(h1("Confirmed Findings"));
  if (!captureUsable || !consentExercised) {
    children.push(p("The capture did not establish a consent decision, so nothing has been confirmed either way. Repair the capture and re-run before treating any part of this report as a finding.", { bold: true, color: RED }));
  } else if (!confirmedFindings.length) {
    children.push(p("Nothing met the evidence bar for a confirmed gap. Items that were observed but could not be established either way are listed under Items Requiring Review.", { color: GREEN }));
  } else {
    children.push(p("One entry per root problem, with the observations supporting it listed underneath. A technology appears once however many symptoms it produced: a request before consent, a cookie created, and that cookie surviving rejection are usually three faces of one misconfiguration, and listing them separately would treble the apparent workload without adding a single fix.", { size: 18, color: "555555" }));
    for (const f of confirmedFindings) {
      children.push(h2(`${f.technology} — ${f.purpose}`));
      children.push(p(`Expected consent category: ${f.expected_category}.   Confidence: ${f.confidence}.`, { size: 18, color: MUTED }));
      for (const line of f.evidence) children.push(bullet(line));
      children.push(p(`Recommended fix: ${f.action}`, { bold: true, color: NAVY }));
    }
  }

  // ---- Observed, but not established either way ----
  children.push(h1("Items Requiring Review"));
  if (!reviewFindings.length) {
    children.push(p("Nothing was left unresolved.", { color: GREEN }));
  } else {
    children.push(p("These were observed but the evidence does not support calling them violations. They are listed so they can be checked, not so they can be counted against the site. Uncertainty is not failure, and none of these contributed to the overall status beyond \u201CMinor Issues\u201D.", { size: 18, color: "555555" }));
    for (const f of reviewFindings) {
      children.push(h2(`${f.technology}${f.purpose && f.purpose !== "Unidentified" ? ` \u2014 ${f.purpose}` : ""}`));
      children.push(p(`Confidence: ${f.confidence}.`, { size: 18, color: MUTED }));
      for (const line of f.evidence) children.push(bullet(line));
      if (f.action && f.action !== "None") {
        children.push(p(`Suggested check: ${f.action}`, { bold: true, color: NAVY }));
      }
    }
  }

  // ---- Legal notes on technically correct implementations ----
  const legalNoteRows = techMatrix.filter((r) => r.legal_note);
  if (legalNoteRows.length) {
    children.push(
      h1("Legal Notes"),
      p("These technologies passed the technical checks: the implementation behaves as it should. They are listed because correct behaviour can still raise a question that is legal rather than technical, and that question belongs to counsel, not to an engineer. Nothing here is a defect, and nothing here counts towards the overall status.", { size: 18, color: "555555" }),
    );
    for (const r of legalNoteRows) {
      children.push(h2(r.display_name || r.technology));
      children.push(p(`Technical result: ${r.technical_result}.`, { size: 18, color: GREEN, bold: true }));
      children.push(p(r.legal_note));
    }
  }

  // ---- How the status was reached ----
  children.push(
    h1("How the Overall Status Was Reached"),
    p(`This report is graded ${overallStatus}.`, { bold: true, size: 24, color: STATUS_COLORS[overallStatus] || MUTED }),
    p("The status rests on confirmed findings only. Items under review cannot push a site past \u201CMinor Issues\u201D, because an observation the audit could not resolve is a reason to look, not a verdict. Equally, a confirmed finding cannot be offset by passing checks elsewhere.", { size: 18, color: "555555" }),
    makeTable(
      ["Status", "When it applies"],
      [
        ["Healthy", "No confirmed gaps and nothing requiring review"],
        ["Minor Issues", "No confirmed gaps, but items need checking"],
        ["Action Required", "One or two confirmed gaps"],
        ["Significant Issues", "Three or more confirmed gaps"],
        ["Inconclusive", "The capture did not establish a consent decision, so no grade is issued"],
      ],
      [3020, 7060],
      ["Healthy", "Minor Issues", "Action Required", "Significant Issues", "Inconclusive"].map(
        (b) => (b === overallStatus ? (STATUS_COLORS[b] || MUTED) : undefined)),
    ),
    p(`Confirmed gaps: ${counts.confirmed}    Review required: ${counts.review}    Passed checks: ${counts.passed}    Inconclusive: ${counts.inconclusive}`, { bold: true }),
    p("This is a prioritisation aid, not a legal grade or a certification. Whether any given behaviour is lawful depends on jurisdiction and on how the site declares its own cookie categories.", { italics: true, size: 18, color: "555555" }),
  );

  // ---- Underlying firing matrix, kept for full disclosure ----
  children.push(
    h1("Full Tracker Inventory"),
    p("The same technologies as the table above, expressed as the raw firing pattern the analysis is derived from."),
  );
  if (matrix.length) {
    children.push(makeTable(
      ["Tracker", "Pre", "Reject", "Accept", "Classification"],
      matrix.map((m) => [m.display_name || m.tracker, yn(m.pre_consent), yn(m.post_reject), yn(m.post_accept), m.classification]),
      [3081, 770, 880, 880, 4469],
      matrix.map((m) => sevColor(m.severity))
    ));
    children.push(p("Request volume per tracker, per state:", { bold: true }));
    children.push(makeTable(
      ["Tracker", "Pre-consent", "Post-reject", "Post-accept", "Example endpoint"],
      matrix.map((m) => [m.display_name || m.tracker, String(m.requests.pre), String(m.requests.postreject), String(m.requests.postaccept), (m.example_url || "").slice(0, 60)]),
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
    .map((m) => [m.display_name || m.tracker, yn(m.pre_consent), yn(m.post_reject), yn(m.post_accept), m.severity === "review" ? "Confirm classification" : "Not observed pre-consent"]);
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

    // The complete per-state inventory is reference material: needed to check a
    // named cookie, not to understand a finding. It goes to the appendix so the
    // two tables above — the ones that carry the evidence — are what a reader
    // meets here. Nothing is dropped; the h2 headings below are built now and
    // placed at the end, which keeps them out of the contents list (only
    // top-level sections register there).
    for (const [key, label] of [["pre", "Pre-consent"], ["postreject", "Post-reject"], ["postaccept", "Post-accept"]]) {
      const st = states[key].storage || {};
      const cookies = st.cookies || [];
      appendix.push(h2(`All Cookies — ${label} (${cookies.length})`));
      appendix.push(cookies.length
        ? makeTable(
            ["Cookie", "Domain", "Lifetime", "Third-party", "Attributed To"],
            cookies.map((c) => [c.name, c.registrable_domain, c.session_cookie ? "Session" : `${c.expires_days}d`, yn(c.third_party), c.attributed_to || "—"]),
            [2640, 2421, 1541, 1431, 2047],
            cookies.map((c) => (c.long_lived ? AMBER : undefined)))
        : p("No cookies observed in this state."));
      const ls = st.local_storage || [];
      if (ls.length) {
        appendix.push(p(`localStorage keys (${ls.length}): ${ls.map((i) => i.name).join(", ")}`, { size: 18 }));
      }
      const ss = st.session_storage || [];
      if (ss.length) {
        appendix.push(p(`sessionStorage keys (${ss.length}): ${ss.map((i) => i.name).join(", ")}`, { size: 18 }));
      }
    }
    appendix.push(p(`Cookies with a lifetime over 180 days are highlighted. Long retention periods are a common regulator finding even when consent gating itself is correct.`, { italics: true, size: 18, color: "555555" }));
    children.push(p("The complete cookie and web-storage inventory for each consent state is in the appendix at the end of this report.", { italics: true, size: 18, color: MUTED }));
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

  // ---- Run-to-run stability (only when the audit was run more than once) ----
  const multiRun = summary.multi_run;
  if (multiRun && multiRun.runs > 1) {
    const n = multiRun.runs;
    children.push(
      h1("Run-to-Run Stability"),
      p(`The capture was repeated ${n} times. The figures elsewhere in this report come from run ${multiRun.base_run}, the run with the most consent gaps; the rest of the runs are used here to show which findings held every time.`),
      p("A gap seen in any run is real — the request was observed, and repeating the capture cannot unfind it. A finding that appears in some runs but not others is not noise to be averaged away: a tag that gates correctly only sometimes is broken, and is the harder version of the same fault. Conversely, a clean result is only as strong as the number of runs behind it.", { size: 18, color: "555555", italics: true }),
    );

    // Runs that never exercised the banner agree with each other by
    // construction — they are the same pre-consent capture under other names.
    // Presenting "2 of 2 runs" from those as corroboration would manufacture
    // confidence out of nothing, so say so before the table, not after it.
    if (multiRun.stability_meaningful === false) {
      const bad = (multiRun.runs_inconclusive || []).join(", ");
      children.push(
        p(`These counts are NOT corroboration. ${(multiRun.runs_inconclusive || []).length} of ${n} runs (${bad}) never exercised the consent banner, so those runs are the pre-consent capture under another name and agree with each other by construction.`, { bold: true, color: RED }),
        p("What still holds: a tracker seen firing before consent did fire before consent — no click was needed for that to be true. What does not hold: anything resting on Reject, which was never pressed. Re-run with explicit Accept/Reject selectors before treating the repeat runs as evidence of anything.", { size: 18, color: "555555" }),
      );
    }

    const gapRows = (multiRun.gap_stability || []);
    children.push(gapRows.length
      ? makeTable(
          ["Tracker", "Gap seen in", "Verdict"],
          gapRows.map((r) => [
            r.tracker,
            `${r.seen_in} of ${r.of} runs`,
            multiRun.stability_meaningful === false
              ? "Not corroborated — runs were inconclusive"
              : (r.stable ? "Consistent" : "Intermittent — still a fault"),
          ]),
          [4600, 2240, 3240],
          gapRows.map((r) => (r.stable ? RED : AMBER)))
      : p(`No consent gaps were found in any of the ${n} runs.`, { color: GREEN }));

    if ((multiRun.gaps_only_in_other_runs || []).length) {
      children.push(p(`Seen firing outside consent in another run, but not in run ${multiRun.base_run}, so absent from the tables above: ${multiRun.gaps_only_in_other_runs.join(", ")}. These fired before consent at least once and should be treated as gaps.`, { color: AMBER }));
    }

    const violRows = (multiRun.violation_stability || []).filter((r) => !r.stable);
    if (violRows.length) {
      children.push(
        h2("Intermittent Category Violations"),
        makeTable(
          ["Violation", "Seen in"],
          violRows.map((r) => [r.violation, `${r.seen_in} of ${r.of} runs`]),
          [7080, 3000], violRows.map(() => AMBER)),
      );
    }

    if (!(multiRun.unstable || []).length && multiRun.stability_meaningful !== false) {
      children.push(p(`Every finding reproduced in all ${n} runs.`, { color: GREEN }));
    }
  }

  children.push(h1("Recommendations"));
  const recs = [];
  if (captureUsable && !consentExercised) {
    recs.push(bullet(`Establish whether ${siteName} presents a consent banner at all. If it does, re-run this audit with explicit --accept-selector and --reject-selector values so the banner is actually exercised; if it does not, that absence is the finding, and the pre-consent behavior recorded here is what every visitor gets.`));
  }
  if (!captureUsable) {
    recs.push(bullet(`Re-run the capture: the site did not load in ${captureErrors.length} of 3 consent states, so this audit reached no conclusion. Every other item in this report is limited to what the states that did load revealed.`));
  }
  // Derived from each technology's own verdict. The previous rule told the
  // reader to gate "any tracker listed with Fired Pre-Consent: Yes", which
  // under this engine would mean blocking a container that has to load early
  // and traffic that consent mode is handling correctly — breaking a working
  // implementation on the strength of a request having been seen.
  for (const f of confirmedFindings) {
    recs.push(bullet(`${f.display_name || f.technology}: ${f.action}. ${f.evidence[0] || ""}`));
  }
  for (const f of reviewFindings) {
    recs.push(bullet(`${f.display_name || f.technology}: ${f.action}. This is not a confirmed fault \u2014 it is what still needs establishing.`));
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
  // Legal notes attach to technologies that PASSED. They are raised as
  // questions for counsel, never as remediation, because there is nothing here
  // for an engineer to fix.
  const withLegalNotes = techMatrix.filter((r) => r.legal_note);
  if (withLegalNotes.length) {
    recs.push(bullet(`No change is required for ${withLegalNotes.map((r) => r.display_name || r.technology).join(", ")}: these passed the technical checks. Counsel may still wish to consider the data transmitted by their cookieless requests \u2014 see the legal notes against each.`));
  }
  if (cookieGapsPre.length && !confirmedFindings.length) {
    // Only when no technology finding already covers them; otherwise this
    // repeats a root finding as though it were a separate problem.
    recs.push(bullet("Remove or defer the cookies listed under 'Cookies Set Before Consent'. Note that blocking a tracker's network requests does not by itself stop a cookie already written by inline JavaScript."));
  }
  if (cookieGapsReject.length && !confirmedFindings.length) {
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

  // ---- Glossary ----
  // Terms the body of the report uses without stopping to define, and the two
  // techniques a cookie-only review would miss entirely.
  children.push(
    h1("Glossary"),
    glossaryEntry("Consent gating", "Holding a tracking technology back until the visitor has actively agreed to it. A banner that records a choice but loads the trackers regardless is not gating anything."),
    glossaryEntry("Pre-consent", "The state of the page before the visitor has made any choice. Under GDPR only strictly necessary technologies may run here."),
    glossaryEntry("Consent Management Platform (CMP)", "The software that presents the banner, records the choice and is supposed to enforce it. CookieYes, OneTrust, Cookiebot and Termly are common examples. Installing one does not by itself gate anything; it has to be wired to the tags."),
    glossaryEntry("First-party / third-party", "First-party is served from the site's own domain, third-party from someone else's. The distinction matters legally and technically, but it is not a reliable guide to who ends up with the data - see server-side tagging."),
    glossaryEntry("Tag manager", "A container, usually Google Tag Manager, that loads other tracking tags. Because tags are configured inside it rather than in the site's code, a tag can be added or changed without any website release."),
    glossaryEntry("Pixel", "A small request to an advertising platform that reports a visit or an action. It needs no visible content on the page; the request itself carries the data."),
    glossaryEntry("Cookieless ping", "A tracking request that sends data without reading or writing a conventional analytics or advertising cookie. It may still involve processing personal data, such as the visitor's IP address, the page URL and browser or device characteristics. Whether consent or another legal basis is required depends on the jurisdiction, the purpose and the implementation. Because it leaves no cookie behind, a cookie-only check misses it entirely; this audit inspects network requests as well as cookies, so these are captured."),
    glossaryEntry("Server-side tagging", "Routing tracking data through the site's own servers, or a subdomain of the site, before forwarding it to the advertising platform. It makes third-party tracking look first-party. Where the forwarded request still carries a recognisable signature this audit detects it; where data is sent server-to-server and never touches the browser, such as Meta's Conversions API or GA4's Measurement Protocol, no browser-based audit can observe it and confirming it requires access to the tag configuration."),
    glossaryEntry("Remarketing", "Tagging a visitor so they can be shown adverts for this site elsewhere on the internet. It is advertising rather than analytics, and it requires consent."),
    glossaryEntry("Session and persistent cookies", "A session cookie is discarded when the browser closes. A persistent cookie has a fixed lifetime, shown in this report in days."),
    glossaryEntry("Infrastructure cookie", "A cookie set by a hosting, security or anti-spam service rather than by a tracker - the Cloudflare __cf_bm cookie is the common example. These are usually defensible as necessary, and are listed in full so the classification can be reviewed rather than taken on trust."),
    glossaryEntry("Strictly necessary", "The legal category of technologies a site may run without consent, because the service the visitor asked for would not work without them. It is a narrow test and a legal determination. Analytics and advertising do not qualify, and convenience is not the same as necessity."),
    glossaryEntry("Health score", "The prioritisation rubric used in this report, with its arithmetic shown in full. It is a way of ranking what to fix first, not a legal grade or a certification."),
  );

  if (appendix.length) {
    children.push(h1(APPENDIX_TITLE), ...appendix);
  }

  const coverEnd = children.indexOf(execSummaryHeading);
  if (coverEnd !== -1) children.splice(coverEnd, 0, ...contentsPage());

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
const APPENDIX_TITLE = "Appendix — Full Cookie and Storage Inventory";
const COLLAPSED_SECTIONS = [APPENDIX_TITLE];

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
  const needle = `<w:t xml:space="preserve">${escaped}</w:t>`;

  // The contents list repeats every section title, and it comes first in the
  // document, so the earliest match is a hyperlink rather than the heading.
  // Walk the occurrences and take the one that sits in a heading paragraph.
  for (let from = 0; ; ) {
    const at = xml.indexOf(needle, from);
    if (at === -1) return null;
    from = at + needle.length;

    const pStart = xml.lastIndexOf("<w:p>", at);
    if (pStart === -1) continue;
    const pPrStart = xml.indexOf("<w:pPr>", pStart);
    const pPrEnd = xml.indexOf("</w:pPr>", pStart);
    if (pPrStart === -1 || pPrEnd === -1 || pPrStart > at || pPrEnd > at) continue;

    const pPr = xml.slice(pPrStart, pPrEnd);
    if (!/<w:pStyle w:val="Heading/.test(pPr)) continue;
    if (pPr.includes("<w:collapsed/>")) return xml;

    // Immediately after <w:pStyle/>, which is where Word itself writes it.
    const styleClose = xml.indexOf("/>", xml.indexOf("<w:pStyle", pPrStart)) + 2;
    return xml.slice(0, styleClose) + "<w:collapsed/>" + xml.slice(styleClose);
  }
}


main();
