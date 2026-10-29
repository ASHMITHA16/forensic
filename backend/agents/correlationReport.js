/**
 * correlationReport.js
 * ─────────────────────────────────────────────────────────────
 * JSON / Markdown / PDF reports from a correlation envelope
 * (correlationAgent.js). Same shape as the log agent's reportAgent.js.
 * ─────────────────────────────────────────────────────────────
 */

import PDFDocument from "pdfkit";

const safe = (value) => (value === undefined || value === null || value === "" ? "-" : String(value));
const pct = (v) => `${Math.round((Number(v) || 0) * 100)}%`;

const generateCorrelationReport = (envelope) => {
  if (!envelope || !Array.isArray(envelope.correlations)) {
    throw new Error("A correlation envelope is required to generate a report");
  }

  const a = envelope.assessment || {};
  const json = {
    reportType: "Cross-Domain Correlation Report",
    generatedAt: new Date().toISOString(),
    run: envelope.agent || {},
    coreDigest: envelope.core_digest || null,
    assessment: a,
    inputs: envelope.inputs || {},
    hypotheses: envelope.hypotheses || [],
    attackChain: envelope.attack_chain || {},
    correlations: envelope.correlations,
    timeline: envelope.timeline || [],
    limitations: envelope.limitations || [],
  };

  const inputRows = Object.entries(json.inputs).map(([d, i]) =>
    `| ${d} | ${i.supplied ? "yes" : "**no**"} | ${i.findings} | ${safe(i.file_name)} | ${i.admissible === true ? "yes" : i.admissible === false ? "**NO**" : "not established"} |`);

  const markdown = [
    `# ${json.reportType}`,
    `**Generated:** ${json.generatedAt}  `,
    `**Run:** ${safe(json.run.run_id)} · ${safe(json.run.mode)} · status **${safe(json.run.status)}** · rule pack ${safe(json.run.rule_pack)}  `,
    `**Core digest:** \`${safe(json.coreDigest)}\``,
    "",
    ...(json.run.mode === "demo" ? ["> **DEMO CASE — NOT EVIDENCE.** Built from bundled fixtures and a memory replay.", ""] : []),
    ...(a.admissible === false ? ["> **Includes non-admissible evidence.** Correlations citing it are flagged and down-weighted.", ""] : []),
    "## Executive Assessment",
    `- Risk: **${safe(a.risk_level)}** (${safe(a.risk_score)}/100)`,
    `- Assessment confidence: **${pct(a.confidence)}** — ${safe(a.confidence_basis)}`,
    ...(a.risk_basis || []).map((b) => `  - ${b}`),
    "",
    "## Evidence Sources",
    "| Domain | Supplied | Findings | File | Admissible |",
    "|---|---|---|---|---|",
    ...inputRows,
    "",
    "## Hypotheses",
    ...json.hypotheses.flatMap((h) => [
      `### ${h.hypothesis_id} — ${h.statement} (${pct(h.confidence)})`,
      `_${h.confidence_basis}_`,
      ...h.supporting.map((s) => `- ✔ ${s}`),
      ...h.weakening.map((s) => `- ✖ ${s}`),
      "",
    ]),
    "## Attack Chain",
    json.attackChain.narrative || "-",
    "",
    ...(json.attackChain.phases || []).map((p) => `- **${p.tactic}** (${p.domains.join(", ")}) — ${p.techniques.join(", ") || "-"} · ${p.evidence_refs.length} finding(s)${p.first_seen_utc ? ` · first ${p.first_seen_utc}` : ""}`),
    "",
    "## Correlations",
    ...json.correlations.flatMap((c) => [
      `### ${c.correlation_id} · ${c.title} [${c.severity.toUpperCase()}, ${pct(c.confidence)}]`,
      `Rule ${c.rule_id} v${c.rule_version} · ${c.domains.join(" ↔ ")} · ${c.link_basis}${c.admissible === false ? " · **not admissible**" : ""}`,
      "",
      `- **Observed:** ${c.observation_statement}`,
      `- **Interpretation:** ${c.interpretation}`,
      `- **Alternative explanations:**`,
      ...c.alternative_explanations.map((x) => `  - ${x}`),
      `- **Analyst action:** ${c.analyst_action}`,
      `- **Confidence basis:** ${c.confidence_basis}`,
      `- **Evidence:** ${c.evidence_refs.join(", ")}`,
      ...(c.mitre_attack.length ? [`- **ATT&CK:** ${c.mitre_attack.join(", ")}`] : []),
      "",
    ]),
    "## Unified Timeline (real timestamps only)",
    ...json.timeline.filter((t) => t.kind === "finding").map((t) => `- ${t.timestamp_utc} [${t.source_domain}] **${safe(t.type)}** — ${safe(t.description)}${t.correlation_refs.length ? ` (${t.correlation_refs.join(", ")})` : ""}`),
    "",
    `Untimed findings (not placed): ${Object.entries(envelope.untimed_findings || {}).map(([d, n]) => `${d} ${n}`).join(", ")}`,
    "",
    "## Limitations",
    ...json.limitations.map((l) => `- ${l}`),
  ].join("\n");

  return { json, markdown, riskLevel: a.risk_level, summary: envelope.summary };
};

const generateCorrelationPdf = (report) => new Promise((resolve, reject) => {
  const doc = new PDFDocument({ margin: 48 });
  const chunks = [];
  doc.on("data", (chunk) => chunks.push(chunk));
  doc.on("end", () => resolve(Buffer.concat(chunks)));
  doc.on("error", reject);

  const { json } = report;
  const a = json.assessment || {};
  const heading = (text) => doc.moveDown().fontSize(13).fillColor("black").text(text);

  doc.fontSize(18).text(json.reportType);
  doc.moveDown(0.5).fontSize(9).text(`Generated: ${json.generatedAt}`);
  doc.text(`Run: ${safe(json.run.run_id)} | mode ${safe(json.run.mode)} | status ${safe(json.run.status)} | ${safe(json.run.rule_pack)}`);
  doc.text(`Core digest: ${safe(json.coreDigest)}`);
  if (json.run.mode === "demo") doc.fillColor("#b45309").text("DEMO CASE — NOT EVIDENCE").fillColor("black");
  if (a.admissible === false) doc.fillColor("#b91c1c").text("Includes non-admissible evidence").fillColor("black");

  heading("Executive Assessment");
  doc.fontSize(10).text(`Risk: ${safe(a.risk_level)} (${safe(a.risk_score)}/100)`);
  doc.text(`Assessment confidence: ${pct(a.confidence)} — ${safe(a.confidence_basis)}`);
  (a.risk_basis || []).forEach((b) => doc.fontSize(8).text(`  • ${b}`));

  heading("Evidence Sources");
  Object.entries(json.inputs).forEach(([d, i]) => {
    doc.fontSize(9).text(`${d}: ${i.supplied ? `${i.findings} finding(s)` : "not supplied"}${i.file_name ? ` — ${i.file_name}` : ""} | admissible: ${i.admissible === null ? "not established" : i.admissible}`);
  });

  heading("Hypotheses");
  json.hypotheses.forEach((h) => {
    doc.fontSize(10).text(`${h.hypothesis_id} (${pct(h.confidence)}): ${h.statement}`);
    h.supporting.forEach((s) => doc.fontSize(8).text(`  + ${s}`));
    h.weakening.forEach((s) => doc.fontSize(8).text(`  − ${s}`));
  });

  heading("Attack Chain");
  doc.fontSize(9).text(json.attackChain.narrative || "-");

  heading("Correlations");
  json.correlations.forEach((c) => {
    doc.moveDown(0.4).fontSize(10).text(`${c.correlation_id} ${c.title} [${c.severity.toUpperCase()}, ${pct(c.confidence)}]${c.admissible === false ? " — not admissible" : ""}`);
    doc.fontSize(8).text(`Observed: ${c.observation_statement}`);
    doc.text(`Interpretation: ${c.interpretation}`);
    doc.text(`Alternatives: ${c.alternative_explanations.join(" | ")}`);
    doc.text(`Action: ${c.analyst_action}`);
    doc.text(`Basis: ${c.confidence_basis}`);
  });

  heading("Limitations");
  json.limitations.forEach((l) => doc.fontSize(8).text(`• ${l}`));
  doc.end();
});

export { generateCorrelationPdf };
export default generateCorrelationReport;
