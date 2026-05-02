/**
 * generateReport(correlationOutput)
 *
 * Returns:
 * {
 *   json:     object   — structured machine-readable report
 *   text:     string   — human-readable plain-text report
 *   riskLevel: string  — "LOW" | "MEDIUM" | "HIGH" (convenience accessor)
 *   summary:  string   — one-paragraph executive summary
 * }
 */
function generateReport(correlationOutput) {
  if (!correlationOutput || typeof correlationOutput !== "object") {
    throw new Error("reportAgent.generateReport: correlationOutput must be a non-null object.");
  }
 
  const jsonReport = buildJsonReport(correlationOutput);
  const textReport = buildTextReport(jsonReport);
 
  return {
    json:      jsonReport,
    text:      textReport,
    riskLevel: jsonReport.riskAssessment.level,
    summary:   jsonReport.executiveSummary,
  };
}
 
module.exports = { generateReport };