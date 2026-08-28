import PDFDocument from "pdfkit";

const safe = (value) =>
  value === undefined || value === null ? "-" : String(value);

const generateNReport = (analysis, fileName = "evidence") => {
  if (!analysis || typeof analysis !== "object") {
    throw new Error("Analysis data is required");
  }
  console.log("Generating report for analysis:", analysis);
  const findings = Array.isArray(analysis.findings)
    ? analysis.findings
    : [];

  const meta = analysis.meta || {};

  const json = {
    reportType: `Automated ${
      meta.agent
        ? meta.agent.charAt(0).toUpperCase() +
          meta.agent.slice(1)
        : "Forensic"
    } Investigation Report`,
    generatedAt: new Date().toISOString(),

    evidence: {
      fileName,
      format: meta.format || "Unknown",
      linesInspected: meta.totalLines || 0,
    },

    assessment: {
      risk: meta.risk || "LOW",
      score: meta.riskScore || 0,
      confidence: meta.confidence || 0,
    },

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
    `- Risk: **${json.assessment.risk}**`,
    `- Confidence: **${json.assessment.confidence}%**`,
    "",
    "## Findings",
    ...findings.map((finding, index) => {
      if (meta.agent === "network") {
        return `${index + 1}. **${safe(
          finding.type
        )}** | IP: ${safe(finding.ip)} | ${safe(
          finding.detail
        )}`;
      }

      return `${index + 1}. **${safe(
        finding.type
      )}** [${safe(finding.severity)}] - ${safe(
        finding.explanation
      )}`;
    }),
  ].join("\n");

  return {
    json,
    markdown,
    riskLevel: json.assessment.risk,
    summary:
      meta.summary || "Forensic investigation completed.",
  };
};

const generatePdf = (report) =>
  new Promise((resolve) => {
    const document = new PDFDocument({
      margin: 48,
    });

    const chunks = [];

    document.on("data", (chunk) =>
      chunks.push(chunk)
    );

    document.on("end", () =>
      resolve(Buffer.concat(chunks))
    );

    document
      .fontSize(18)
      .text(report.json.reportType);

    document.moveDown();

    document
      .fontSize(10)
      .text(
        `Evidence: ${report.json.evidence.fileName}`
      );

    document.text(
      `Generated: ${report.json.generatedAt}`
    );

    document.moveDown();

    document
      .fontSize(13)
      .text("Executive Assessment");

    document
      .fontSize(10)
      .text(
        `Risk Level: ${report.json.assessment.risk}`
      );

    document.text(
      `Confidence: ${report.json.assessment.confidence}%`
    );

    document.moveDown();

    document.fontSize(13).text("Findings");

    report.json.findings.forEach(
      (finding, index) => {
        if (finding.detail) {
          document
            .fontSize(10)
            .text(`${index + 1}. ${safe(finding.type)}`);

          document.text(
            `IP Address: ${safe(finding.ip)}`
          );

          document.text(
            `Details: ${safe(finding.detail)}`
          );

          document.moveDown(0.5);
        } else {
          document
            .fontSize(10)
            .text(
              `${index + 1}. ${safe(
                finding.type
              )} [${safe(finding.severity)}]`
            );

          document.text(
            `${safe(finding.explanation)}`
          );

          document.text(
            `Line: ${safe(
              finding.lineNumber
            )} | IP: ${safe(
              finding.ip
            )} | User: ${safe(
              finding.user
            )}`
          );

          document.moveDown(0.5);
        }
      }
    );

    document.end();
  });

export { generatePdf };
export default generateNReport;