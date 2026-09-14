#!/usr/bin/env node
/**
 * generate_report.js — Build a client-ready .docx compliance report from
 * findings.json (produced by analyze_har.py).
 *
 * Usage:
 *   node generate_report.js <findings.json> <site-name> <site-url> [--out report.docx]
 */
const {
  Document, Packer, Paragraph, TextRun, HeadingLevel, Table, TableRow, TableCell,
  WidthType, ShadingType, AlignmentType, PageBreak,
} = require("docx");
const fs = require("fs");
const path = require("path");

const NAVY = "1F3864";
const LIGHT = "F2F2F2";

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
function cell(text, { header = false, width, shading } = {}) {
  return new TableCell({
    width: { size: width, type: WidthType.DXA },
    shading: shading ? { type: ShadingType.CLEAR, fill: shading } : undefined,
    children: [new Paragraph({ children: [new TextRun({ text: String(text), bold: header })] })],
  });
}
function makeTable(headers, rows, widths) {
  const headerRow = new TableRow({ tableHeader: true, children: headers.map((t, i) => cell(t, { header: true, width: widths[i], shading: NAVY })) });
  const bodyRows = rows.map((r, idx) => new TableRow({ children: r.map((v, i) => cell(v, { width: widths[i], shading: idx % 2 === 1 ? LIGHT : undefined })) }));
  return new Table({ width: { size: widths.reduce((a, b) => a + b, 0), type: WidthType.DXA }, columnWidths: widths, rows: [headerRow, ...bodyRows] });
}

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

  const stateRows = [
    ["Pre-consent", String(states.pre.requests), Object.keys(states.pre.trackers).join(", ") || "None detected"],
    ["Post-reject", String(states.postreject.requests), Object.keys(states.postreject.trackers).join(", ") || "None detected"],
    ["Post-accept", String(states.postaccept.requests), Object.keys(states.postaccept.trackers).join(", ") || "None detected"],
  ];

  const gapRows = gaps.map((g) => [
    g.tracker,
    g.fired_pre_consent ? "Yes" : "No",
    g.fired_after_reject ? "Yes" : "No",
    g.severity,
  ]);

  const gatedList = summary.trackers_correctly_gated.length
    ? summary.trackers_correctly_gated.join(", ")
    : "None detected";
  const necessaryList = (summary.necessary_services_active || []).length
    ? summary.necessary_services_active.join(", ")
    : "None detected";

  const children = [
    new Paragraph({ spacing: { before: 1400 }, alignment: AlignmentType.CENTER, children: [new TextRun({ text: "Cookie Consent Compliance Review", bold: true, size: 44, color: NAVY })] }),
    new Paragraph({ spacing: { before: 200 }, alignment: AlignmentType.CENTER, children: [new TextRun({ text: `${siteName} — ${siteUrl}`, size: 28, color: "444444" })] }),
    new Paragraph({ spacing: { before: 600 }, alignment: AlignmentType.CENTER, children: [new TextRun({ text: `Prepared ${dateStr}`, size: 22, color: "666666" })] }),
    new Paragraph({ spacing: { before: 100 }, alignment: AlignmentType.CENTER, children: [new TextRun({ text: "Scope: Live network capture — pre-consent, post-accept, post-reject", size: 20, color: "666666", italics: true })] }),
    new Paragraph({ children: [new PageBreak()] }),

    h1("Executive Summary"),
    p(`This review assessed the cookie/tracking consent behavior of ${siteName} (${siteUrl}) using live network captures taken before any consent decision, immediately after accepting, and immediately after rejecting.`),
    hasGaps
      ? p(`${gaps.length} third-party tracker(s) were found firing outside of proper consent gating. Details follow below.`, { bold: true })
      : p("No consent gaps were found: every detected third-party tracker only activated after the visitor accepted, and none fired before consent or after rejection."),

    h2("Key Findings at a Glance"),
    makeTable(
      ["State", "Requests Captured", "Trackers Detected"],
      stateRows,
      [2000, 2000, 5160]
    ),

    h1("Consent Gap Analysis"),
    hasGaps
      ? makeTable(["Tracker", "Fired Pre-Consent", "Fired After Reject", "Severity"], gapRows, [3200, 2000, 2000, 1960])
      : p("No trackers fired before consent or after rejection was recorded."),

    h2("Correctly Gated Trackers"),
    p(`The following trackers were only observed after the visitor accepted, indicating correct consent gating: ${gatedList}.`),

    h2("Necessary Services (Expected Pre-Consent)"),
    p(`The following were treated as necessary/security services and expected to run regardless of consent (e.g. anti-spam, fraud prevention, payments), so they are not counted as gaps: ${necessaryList}.`),

    h1("Recommendations"),
    ...(hasGaps
      ? [
          bullet("Move any tracker listed above with 'Fired Pre-Consent: Yes' behind the consent management platform's gating logic immediately — this is the highest-severity finding."),
          bullet("For trackers still active after rejection, confirm the CMP's 'Reject All' action is correctly wired to block that specific tag."),
          bullet("Re-run this capture after fixes to confirm the gaps are closed."),
        ]
      : [
          bullet("Confirm the consent management platform's declared cookie categories list every tracker observed here — undisclosed trackers are a common audit finding even when gating itself works correctly."),
          bullet("Periodically re-run this capture, especially after marketing/analytics tag changes, since tag managers can introduce new trackers without a corresponding banner update."),
        ]),

    h1("Methodology"),
    bullet("Captured full HAR (HTTP Archive) network traffic in three fresh, isolated browser sessions: no interaction, immediately after Accept All, and immediately after Reject All."),
    bullet("Classified requests against a signature list of common analytics, advertising, and marketing trackers."),
    bullet("Cross-referenced each tracker's activity across the three states to identify consent-gating gaps."),
    p("Note: cookies set purely client-side via JavaScript (not via HTTP Set-Cookie headers) are not always visible in HAR captures. Tracker presence here is inferred primarily from network requests to known tracking endpoints.", { italics: true, color: "555555" }),
  ];

  const doc = new Document({
    styles: { default: { document: { run: { font: "Calibri", size: 22 } } } },
    sections: [
      {
        properties: { page: { size: { width: 12240, height: 15840 }, margin: { top: 1080, bottom: 1080, left: 1080, right: 1080 } } },
        children,
      },
    ],
  });

  Packer.toBuffer(doc).then((buf) => {
    fs.writeFileSync(outPath, buf);
    console.log(`Report written to ${outPath}`);
  });
}

main();
