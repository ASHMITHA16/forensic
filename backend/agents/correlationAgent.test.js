// Bridge tests: the analysis itself is tested in correlation_agent/tests (Python).
import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import runCorrelation, { runCorrelationDemo, listRules } from "./correlationAgent.js";
import generateCorrelationReport, { generateCorrelationPdf } from "./correlationReport.js";

const memoryEnvelope = {
  schema_version: "1.0.0",
  agent: { status: "COMPLETE", status_basis: "Evidence verified." },
  integrity: { integrity_verified: true },
  environment: { clock_skew_seconds: 0 },
  findings: [{
    finding_id: "FND-0010", rule_id: "MEM-N-001", title: "Established connection to an external host",
    severity: "MEDIUM", confidence: 0.55, first_seen_utc: "2026-04-12T02:18:09Z",
    entities: { pids: [2456], processes: ["data_transfer.exe"], ips: ["185.77.22.90"] },
    observation_statement: "PID 2456 holds a socket to 185.77.22.90:4444.", interpretation: "Outbound connection.",
    alternative_explanations: ["Legitimate traffic."], mitre_attack: ["T1071"],
  }],
  timeline: [], limitations: [],
};

test("correlates through the Python agent and keeps the legacy fields", async () => {
  const env = await runCorrelation({
    memory: { envelope: memoryEnvelope },
    network: { findings: [{ type: "Beaconing Activity", ip: "185.77.22.90", detail: "412 packets" }] },
  });
  assert.equal(env.correlations[0].rule_id, "COR-001");
  assert.ok(env.correlations[0].alternative_explanations.length > 0);
  assert.equal(env.agent.status, "PARTIAL");
  assert.ok(fs.existsSync(env.workspace.envelope_path), "full envelope written to the case workspace");
  assert.equal(env.riskLevel, env.assessment.risk_level);
  assert.equal(env.patterns.length, env.correlations.length);
});

test("bad input comes back as a structured 400", async () => {
  await assert.rejects(runCorrelation({ memory: { envelope_path: "/does/not/exist.json" } }),
    (err) => err.code === "CA-E-101" && err.status === 400);
});

test("demo case and rule pack", async () => {
  const env = await runCorrelationDemo();
  assert.equal(env.agent.mode, "demo");
  assert.equal(env.assessment.admissible, false);
  const { rules } = await listRules();
  assert.equal(rules.length, 8);

  const report = generateCorrelationReport(env);
  assert.match(report.markdown, /DEMO CASE — NOT EVIDENCE/);
  assert.equal((await generateCorrelationPdf(report)).subarray(0, 5).toString(), "%PDF-");
});
