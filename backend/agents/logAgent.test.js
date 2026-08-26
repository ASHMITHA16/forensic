import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import analyzeLogs from "./logAgent.js";
import generateReport, { generatePdf } from "./reportAgent.js";

const writeLog = async (content) => {
  const filePath = path.join(os.tmpdir(), `log-agent-${Date.now()}-${Math.random()}.log`);
  await fs.writeFile(filePath, content, "utf8");
  return filePath;
};

const withLog = async (content, callback) => {
  const filePath = await writeLog(content);
  try { return await callback(filePath); } finally { await fs.unlink(filePath); }
};

test("detects clean logs with high analysis confidence", async () => {
  await withLog("2026-08-27T10:00:00Z host=lab user=alice systemd: service started\n", async (filePath) => {
    const result = await analyzeLogs(filePath);
    assert.equal(result.meta.risk, "LOW");
    assert.ok(result.meta.confidence >= 90);
  });
});

test("parses JSON events and extracts structured fields", async () => {
  await withLog('{"timestamp":"2026-08-27T10:00:00Z","eventId":4625,"user":"alice","sourceIp":"203.0.113.10","message":"failed password"}\n', async (filePath) => {
    const result = await analyzeLogs(filePath);
    assert.equal(result.meta.format, "JSON Lines");
    assert.equal(result.findings[0].eventId, 4625);
    assert.equal(result.findings[0].user, "alice");
    assert.equal(result.findings[0].ip, "203.0.113.10");
  });
});

test("detects Windows events and malformed timestamps safely", async () => {
  await withLog("EventID=4625 Time=not-a-date User=alice failed login\n", async (filePath) => {
    const result = await analyzeLogs(filePath);
    assert.equal(result.meta.format, "Windows Event Log");
    assert.equal(result.findings[0].timestamp, null);
    assert.equal(result.findings[0].eventId, "4625");
  });
});

test("aggregates five failures from one source within five minutes", async () => {
  const lines = Array.from({ length: 5 }, (_, index) => `2026-08-27T10:0${index}:00Z sshd: Failed password for alice from 203.0.113.10`);
  await withLog(lines.join("\n"), async (filePath) => {
    const result = await analyzeLogs(filePath);
    const bruteForce = result.findings.find((finding) => finding.type === "Brute Force Activity");
    assert.equal(bruteForce.eventCount, 5);
    assert.equal(bruteForce.severity, "high");
  });
});

test("does not flag harmless curl documentation as suspicious command", async () => {
  await withLog("2026-08-27T10:00:00Z documentation: use curl https://example.com to test connectivity\n", async (filePath) => {
    const result = await analyzeLogs(filePath);
    assert.equal(result.findings.length, 0);
  });
});

test("generates JSON, Markdown, and PDF reports", async () => {
  const analysis = { findings: [], meta: { format: "Plain Text Log", risk: "LOW", riskScore: 0, confidence: 80, timeline: [] } };
  const report = generateReport(analysis, "sample.log");
  const pdf = await generatePdf(report);
  assert.equal(report.json.evidence.fileName, "sample.log");
  assert.match(report.markdown, /Automated Log Forensic Investigation Report/);
  assert.ok(pdf.subarray(0, 5).toString() === "%PDF-");
});
