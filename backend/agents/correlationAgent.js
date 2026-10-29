/**
 * correlationAgent.js
 * ─────────────────────────────────────────────────────────────
 * Bridge to the Python correlation & reasoning agent in
 * ../correlation_agent (see correlation_agent/docs/DESIGN.md).
 *
 * correlate : runs `python -m correlation_agent correlate` on the
 *             outputs of the log / network / memory / disk agents
 * demo      : bundled demo case (memory replay + captured agent output)
 * rules     : the rule pack, for review
 *
 * The payload goes to the agent on stdin; the agent writes the full
 * envelope to a case workspace and prints a compact copy (cited evidence
 * only) that is small enough for History.
 * ─────────────────────────────────────────────────────────────
 */

import { spawn } from "child_process";
import path from "path";
import { fileURLToPath } from "url";

const BACKEND_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const REPO_ROOT   = path.resolve(BACKEND_DIR, "..");

// Override with env variables if Python / the case store live elsewhere
const PYTHON_BIN = process.env.PYTHON_BIN || "python";
const CASES_DIR  = path.resolve(process.env.CORRELATION_CASES_DIR || path.join(BACKEND_DIR, "correlation_cases"));

// Exit codes documented in correlation_agent/cli.py
const EXIT_CONTRACT = 2;

class CorrelationAgentError extends Error {
  constructor(message, { code = null, status = 500 } = {}) {
    super(message);
    this.code = code;
    this.status = status;
  }
}

// ─── Run the Python CLI and parse its JSON output ──────────────
function runAgent(args, stdinPayload = null) {
  return new Promise((resolve, reject) => {
    const child = spawn(PYTHON_BIN, ["-m", "correlation_agent", ...args], {
      cwd: REPO_ROOT,
      env: { ...process.env, PYTHONIOENCODING: "utf-8" },
      windowsHide: true,
    });

    const stdout = [];
    const stderr = [];
    child.stdout.on("data", (chunk) => stdout.push(chunk));
    child.stderr.on("data", (chunk) => stderr.push(chunk));

    child.on("error", (err) => {
      reject(new CorrelationAgentError(
        `Could not start Python (${PYTHON_BIN}): ${err.message}. Install Python 3.10+ or set PYTHON_BIN.`,
        { code: "PYTHON_NOT_FOUND", status: 503 }
      ));
    });

    child.on("close", (exitCode) => {
      const out = Buffer.concat(stdout).toString("utf-8").trim();
      const errText = Buffer.concat(stderr).toString("utf-8").trim();

      let payload = null;
      try {
        payload = out ? JSON.parse(out) : null;
      } catch {
        payload = null;
      }

      if (exitCode === 0 && payload) return resolve(payload);

      // The CLI printed a structured error ({ error_code, message, ... })
      const message = payload?.message || errText.split("\n").pop() || `correlation agent exited with code ${exitCode}`;
      const code = payload?.error_code || null;
      // CA-E-1xx: the request carried bad input; anything else is ours
      const status = code?.startsWith("CA-E-1") ? 400 : exitCode === EXIT_CONTRACT ? 500 : 500;
      reject(new CorrelationAgentError(message, { code, status }));
    });

    if (stdinPayload !== null) {
      child.stdin.on("error", () => {}); // the child may exit before reading everything
      child.stdin.end(JSON.stringify(stdinPayload));
    } else {
      child.stdin.end();
    }
  });
}

// ─── Pre-2.0 fields some callers (Upload.jsx) still read ───────
function withLegacyFields(envelope) {
  return {
    ...envelope,
    riskLevel: envelope.assessment.risk_level,
    riskScore: envelope.assessment.risk_score,
    confidence: Math.round(envelope.assessment.confidence * 100),
    patterns: envelope.correlations.map((c) => ({
      type: c.title, message: c.interpretation, severity: c.severity,
      confidence: Math.round(c.confidence * 100), agents: c.domains,
    })),
    agentStatus: Object.fromEntries(Object.entries(envelope.inputs).map(([d, i]) => [d, i.supplied])),
  };
}

// ─── Public API ────────────────────────────────────────────────

/**
 * input   : { log, network, memory, disk } each { findings, meta?, provenance? }
 *           (memory meta.envelopePath is followed to memory_agent_output.json)
 *           or the legacy { logData, networkData, memoryData, diskData }
 * options : { windowSeconds?, caseId? }
 */
const runCorrelation = async (input = {}, { windowSeconds, caseId } = {}) => {
  const envelope = await runAgent([
    "correlate", "--input", "-",
    "-o", CASES_DIR,
    "--case-id", caseId || `DF-CORR-${Date.now()}`,
    ...(windowSeconds ? ["--window", String(windowSeconds)] : []),
    "--json", "--compact", "-q",
  ], input);
  return withLegacyFields(envelope);
};

const runCorrelationDemo = async () => {
  const envelope = await runAgent(["demo", "-o", CASES_DIR, "--json", "--compact", "-q"]);
  return withLegacyFields(envelope);
};

const listRules = async () => runAgent(["rules", "--json"]);

export { runCorrelationDemo, listRules, CorrelationAgentError };
export default runCorrelation;
