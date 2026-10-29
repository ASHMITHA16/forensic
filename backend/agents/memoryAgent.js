/**
 * memoryAgent.js
 * ─────────────────────────────────────────────────────────────
 * Bridge to the Python memory analysis agent in ../memory_agent.
 *
 * analyze : seals the dump, runs Volatility 3, detects, re-verifies
 * replay  : runs the same detection pipeline on the bundled captured
 *           plugin output (demo — no memory image is read)
 *
 * Output : { findings[], meta{} }  — compatible with correlationAgent
 * ─────────────────────────────────────────────────────────────
 */

import { spawn } from "child_process";
import crypto from "crypto";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const BACKEND_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const REPO_ROOT   = path.resolve(BACKEND_DIR, "..");

// Override with env variables if Python / the case store live elsewhere
const PYTHON_BIN  = process.env.PYTHON_BIN || "python";
const CASES_DIR   = path.resolve(process.env.MEMORY_CASES_DIR || path.join(BACKEND_DIR, "memory_cases"));
const DEMO_RAW_DIR = path.join(REPO_ROOT, "memory_agent", "tests", "fixtures", "windows_case");
// Base per-plugin budget in seconds (agent default 300); raise it for very large dumps
const PLUGIN_TIMEOUT_S = process.env.MEMORY_PLUGIN_TIMEOUT_S;

// ─── Severity scoring weights (same scale as the log/disk agents) ──
const SEVERITY_SCORE = { info: 1, low: 3, medium: 8, high: 20, critical: 35 };
const SUSPICIOUS_SEVERITIES = new Set(["critical", "high", "medium"]);

// A real image yields thousands of timeline events and IOCs. The UI keeps
// meta in sessionStorage (~5 MB), so it gets the first N; the full set
// stays in the envelope on disk.
const MAX_UI_TIMELINE = 500;
const MAX_UI_IOCS = 300;

// Exit codes documented in memory_agent/cli.py
const EXIT_INTEGRITY_FAILURE = 2;
const EXIT_NOT_IMPLEMENTED   = 3;

class MemoryAgentError extends Error {
  constructor(message, { code = null, status = 500 } = {}) {
    super(message);
    this.code = code;
    this.status = status;
  }
}

// ─── Run the Python CLI and parse its JSON envelope ────────────
function runMemoryAgent(args) {
  return new Promise((resolve, reject) => {
    const child = spawn(PYTHON_BIN, ["-m", "memory_agent", ...args], {
      cwd: REPO_ROOT,
      env: { ...process.env, PYTHONIOENCODING: "utf-8" },
      windowsHide: true,
    });

    const stdout = [];
    const stderr = [];
    child.stdout.on("data", (chunk) => stdout.push(chunk));
    child.stderr.on("data", (chunk) => stderr.push(chunk));

    child.on("error", (err) => {
      reject(new MemoryAgentError(
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

      // A full envelope is returned on success and on integrity failure
      if (payload && payload.schema_version && payload.findings) {
        return resolve({ envelope: payload, exitCode });
      }

      // Otherwise the CLI printed a structured error ({ error_code, message, ... })
      const message = payload?.message || errText.split("\n").pop() || `memory agent exited with code ${exitCode}`;
      const code = payload?.error_code || null;
      // MA-E-4xx: toolchain (Volatility missing or unusable) — a setup problem, not a bad request
      const status = code?.startsWith("MA-E-4") ? 503 : exitCode === EXIT_NOT_IMPLEMENTED ? 422 : 500;
      reject(new MemoryAgentError(message, { code, status }));
    });
  });
}

// ─── Envelope → UI / correlation shape ─────────────────────────
function toFinding(f) {
  const severity = String(f.severity || "info").toLowerCase();
  const pids = f.entities?.pids || [];
  const processes = f.entities?.processes || [];

  return {
    type:          f.title,
    findingId:     f.finding_id,
    ruleId:        f.rule_id,
    category:      f.category,
    severity,
    confidence:    Math.round((f.confidence || 0) * 100),
    confidenceBasis: f.confidence_basis,
    process:       processes.join(", "),
    pid:           pids[0] ?? null,
    pids,
    ips:           f.entities?.ips || [],
    // Entities beyond pid/process/ip, kept so the correlation agent can link domains
    files:         f.entities?.files || [],
    urls:          f.entities?.urls || [],
    ports:         f.entities?.ports || [],
    services:      f.entities?.services || [],
    modules:       f.entities?.modules || [],
    explanation:   f.interpretation,
    observation:   f.observation_statement,
    alternatives:  f.alternative_explanations || [],
    analystAction: f.analyst_action,
    mitre:         f.mitre_attack || [],
    timestamp:     f.first_seen_utc || null,
    suspicious:    SUSPICIOUS_SEVERITIES.has(severity),
  };
}

function buildMeta(envelope, mode, exitCode) {
  const findings = envelope.findings || [];
  const coverage = envelope.coverage || {};
  const severities = findings.map((f) => String(f.severity || "info").toLowerCase());

  const riskScore = Math.min(100, severities.reduce((total, s) => total + (SEVERITY_SCORE[s] || 0), 0));
  const risk = severities.some((s) => s === "critical" || s === "high")
    ? "HIGH"
    : severities.includes("medium") ? "MEDIUM" : "LOW";

  const os = envelope.environment?.os || {};
  const integrityVerified = Boolean(envelope.integrity?.integrity_verified);
  const status = envelope.agent?.status || "UNKNOWN";
  // Keep events tied to a finding when capping, then show the kept set in time order
  const byTime = (a, b) => String(a.timestamp_utc).localeCompare(String(b.timestamp_utc));
  const timedEvents = (envelope.timeline || []).filter((t) => t.timestamp_utc);
  const linked = timedEvents.filter((t) => t.finding_refs?.length);
  const unlinked = timedEvents.filter((t) => !t.finding_refs?.length).sort(byTime);
  const uiTimeline = [...linked, ...unlinked].slice(0, MAX_UI_TIMELINE).sort(byTime);

  return {
    agent:            "memory",
    mode,
    status,
    statusBasis:      envelope.agent?.status_basis || "",
    risk,
    riskScore,
    caseId:           envelope.case?.case_id,
    runId:            envelope.agent?.run_id,
    os:               [os.family, os.version, os.arch].filter(Boolean).join(" ") || "Unknown",
    dumpSystemTime:   envelope.environment?.dump_system_time_utc || null,
    clockSkewSeconds: envelope.environment?.clock_skew_seconds ?? null,
    evidence: {
      fileName: envelope.evidence?.file_name || null,
      sha256:   envelope.evidence?.hashes?.sha256_before || null,
      sizeBytes: envelope.evidence?.size_bytes || 0,
    },
    integrityVerified,
    integrityFailure: exitCode === EXIT_INTEGRITY_FAILURE && mode === "analyze",
    discrepancies:    envelope.integrity?.discrepancies || [],
    coverage: {
      pluginsAttempted: coverage.plugins_attempted?.length ?? coverage.plugins_attempted ?? 0,
      pluginsSucceeded: coverage.plugins_succeeded?.length ?? coverage.plugins_succeeded ?? 0,
      rulesTotal:       coverage.rules_total ?? 0,
      rulesEvaluated:   coverage.rules_evaluated?.length ?? coverage.rules_evaluated ?? 0,
    },
    findingsBySeverity: coverage.findings_by_severity || {},
    iocs: (envelope.iocs || []).slice(0, MAX_UI_IOCS).map((i) => ({
      type: i.type, value: i.value, context: i.context,
      confidence: Math.round((i.confidence || 0) * 100), falsePositiveRisk: i.false_positive_risk,
    })),
    totalIocs: (envelope.iocs || []).length,
    timeline: uiTimeline.map((t) => ({ timestamp: t.timestamp_utc, type: t.artifact_type, detail: t.description, precision: t.precision })),
    totalTimelineEvents: timedEvents.length,
    limitations:  envelope.limitations || [],
    envelopePath: envelope.workspace?.envelope_path || null,
    summary: `${findings.length} memory findings (${risk} risk). Envelope status ${status}`
      + (mode === "replay" ? " — demo replay of bundled Volatility output, not evidence." : "."),
  };
}

function toResult(envelope, mode, exitCode) {
  return {
    findings: (envelope.findings || []).map(toFinding),
    meta: buildMeta(envelope, mode, exitCode),
  };
}

// ─── Public API ────────────────────────────────────────────────
const analyzeMemory = async (filePath, { caseId } = {}) => {
  const fullPath = path.resolve(filePath);
  const { envelope, exitCode } = await runMemoryAgent([
    "analyze", fullPath,
    "--case-id", caseId || `DF-${Date.now()}`,
    "-o", CASES_DIR,
    ...(PLUGIN_TIMEOUT_S ? ["--timeout", String(PLUGIN_TIMEOUT_S)] : []),
    "--json", "-q",
  ]);
  return toResult(envelope, "analyze", exitCode);
};

const replayMemoryDemo = async () => {
  const { envelope, exitCode } = await runMemoryAgent([
    "replay", DEMO_RAW_DIR,
    "--case-id", "DF-DEMO-MEMORY",
    "-o", CASES_DIR,
    "--json", "-q",
  ]);
  return toResult(envelope, "replay", exitCode);
};

// ─── Background jobs ───────────────────────────────────────────
// A real dump takes minutes to hours, far past Node's 5-minute HTTP
// request timeout. The route starts a job and the UI polls it.
const jobs = new Map();
const JOB_TTL_MS = 6 * 60 * 60 * 1000;

// Audit-trail events (memory_agent/core/audit.py) → stage shown in the UI
const STAGE_LABELS = {
  "run.begin":             "Starting memory agent",
  "evidence.seal.begin":   "Sealing evidence (SHA-256 + MD5)",
  "toolchain.ready":       "Volatility 3 located",
  "profile.begin":         "Identifying operating system",
  "plan.built":            "Running Volatility plugins",
  "extract.begin":         "Normalising plugin output",
  "detect.begin":          "Applying detection rules",
  "timeline.built":        "Building timeline",
  "iocs.extracted":        "Extracting indicators",
  "evidence.verify.begin": "Re-verifying evidence integrity",
  "run.end":               "Writing output envelope",
};

// Progress is read from the run's audit.jsonl, which the agent appends as it works
function readProgress(caseId) {
  const caseDir = path.join(CASES_DIR, caseId);
  let auditPath;
  try {
    const runDir = fs.readdirSync(caseDir).find((d) => fs.existsSync(path.join(caseDir, d, "audit.jsonl")));
    if (!runDir) return null;
    auditPath = path.join(caseDir, runDir, "audit.jsonl");
  } catch {
    return null;
  }

  const progress = { stage: "Starting memory agent", pluginsTotal: 0, pluginsDone: 0, currentPlugin: null };
  let planned = false;
  for (const line of fs.readFileSync(auditPath, "utf-8").split("\n")) {
    if (!line.trim()) continue;
    let entry;
    try { entry = JSON.parse(line); } catch { continue; }
    const { event, data = {} } = entry;

    if (STAGE_LABELS[event]) progress.stage = STAGE_LABELS[event];
    if (event === "plan.built") {
      planned = true;
      progress.pluginsTotal = (data.plugins || []).length;
    }
    if (event === "plugin.begin") progress.currentPlugin = data.plugin || null;
    // OS identification runs plugins too; only count the planned ones
    if (planned && (event === "plugin.end" || event === "plugin.unavailable")) progress.pluginsDone += 1;
  }
  return progress;
}

function pruneJobs() {
  const cutoff = Date.now() - JOB_TTL_MS;
  for (const [id, job] of jobs) {
    if (job.finishedAt && Date.parse(job.finishedAt) < cutoff) jobs.delete(id);
  }
}

/**
 * Start `work(caseId)` in the background. `key` de-duplicates: a second
 * request for the same evidence while it is running gets the same job.
 */
const startMemoryJob = (key, work) => {
  pruneJobs();
  for (const job of jobs.values()) {
    if (job.key === key && job.status === "running") return job;
  }

  const job = {
    id: crypto.randomUUID(),
    key,
    caseId: `DF-${Date.now()}`,
    status: "running",
    startedAt: new Date().toISOString(),
    finishedAt: null,
    result: null,
    error: null,
  };
  jobs.set(job.id, job);

  work(job.caseId)
    .then((result) => {
      job.result = result;
      job.status = "done";
    })
    .catch((err) => {
      job.status = "failed";
      job.error = { message: err.message, code: err.code || null, status: err.status || 500 };
    })
    .finally(() => {
      job.finishedAt = new Date().toISOString();
    });

  return job;
};

const getMemoryJob = (id) => {
  const job = jobs.get(id);
  if (!job) return null;
  return {
    jobId:     job.id,
    status:    job.status,
    caseId:    job.caseId,
    startedAt: job.startedAt,
    elapsedS:  Math.round(((job.finishedAt ? Date.parse(job.finishedAt) : Date.now()) - Date.parse(job.startedAt)) / 1000),
    progress:  job.status === "running" ? readProgress(job.caseId) : null,
    result:    job.result,
    error:     job.error,
  };
};

export { replayMemoryDemo, startMemoryJob, getMemoryJob, MemoryAgentError };
export default analyzeMemory;
