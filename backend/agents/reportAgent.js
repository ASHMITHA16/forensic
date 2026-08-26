import PDFDocument from "pdfkit";

const safe = (value) => value === undefined || value === null ? "-" : String(value);

const generateReport = (analysis, fileName = "log-evidence") => {
  if (!analysis || typeof analysis !== "object") {
    throw new Error("Log analysis is required to generate a report");
  }

  const findings = Array.isArray(analysis.findings) ? analysis.findings : [];
  const meta = analysis.meta || {};
  const json = {
    reportType: "Automated Log Forensic Investigation Report",
    generatedAt: new Date().toISOString(),
    evidence: { fileName, format: meta.format || "Unknown", linesInspected: meta.totalLines || 0 },
    assessment: { risk: meta.risk || "LOW", score: meta.riskScore || 0, confidence: meta.confidence || 0 },
    metrics: meta,
    findings,
    timeline: meta.timeline || [],
  };
  const markdown = [
    `# ${json.reportType}`,
    `**Evidence:** ${fileName}`,
    `**Generated:** ${json.generatedAt}`,
    "",
    "## Executive Assessment",
    `- Risk: **${json.assessment.risk}** (${json.assessment.score}/100)`,
    `- Confidence: **${json.assessment.confidence}%**`,
    `- Format: **${json.evidence.format}**`,
    `- Lines inspected: **${json.evidence.linesInspected}**`,
    "",
    "## Findings",
    ...findings.map((finding, index) => `${index + 1}. **${safe(finding.type)}** [${safe(finding.severity)}] - ${safe(finding.explanation)} (line ${safe(finding.lineNumber)}, IP ${safe(finding.ip)})`),
    "",
    "## Timeline",
    ...json.timeline.map((event) => `- ${safe(event.timestamp)}: **${safe(event.type)}** - ${safe(event.detail)}`),
  ].join("\n");

  return { json, markdown, riskLevel: json.assessment.risk, summary: meta.summary || "Log investigation completed." };
};

const generatePdf = (report) => new Promise((resolve) => {
  const document = new PDFDocument({ margin: 48 });
  const chunks = [];
  document.on("data", (chunk) => chunks.push(chunk));
  document.on("end", () => resolve(Buffer.concat(chunks)));
  document.fontSize(18).text(report.json.reportType);
  document.moveDown().fontSize(10).text(`Evidence: ${report.json.evidence.fileName}`);
  document.text(`Generated: ${report.json.generatedAt}`);
  document.moveDown().fontSize(13).text("Executive Assessment");
  document.fontSize(10).text(`Risk: ${report.json.assessment.risk} (${report.json.assessment.score}/100)`);
  document.text(`Confidence: ${report.json.assessment.confidence}%`);
  document.text(`Format: ${report.json.evidence.format}`);
  document.moveDown().fontSize(13).text("Findings");
  report.json.findings.forEach((finding, index) => {
    document.fontSize(9).text(`${index + 1}. ${safe(finding.type)} [${safe(finding.severity)}] - ${safe(finding.explanation)}`);
    document.text(`   Line: ${safe(finding.lineNumber)} | IP: ${safe(finding.ip)} | User: ${safe(finding.user)}`);
  });
  document.end();
});

export { generatePdf };
export default generateReport;