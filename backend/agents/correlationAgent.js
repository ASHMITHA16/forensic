/**
 * correlationAgent.js
 * ─────────────────────────────────────────────────────────────
 * Receives outputs from all four analysis agents, cross-references
 * every finding, builds a unified event timeline, detects suspicious
 * patterns, and calculates an overall risk level + confidence score.
 * ─────────────────────────────────────────────────────────────
 */

"use strict";

// ─── Constants ────────────────────────────────────────────────

const RISK = { LOW: "LOW", MEDIUM: "MEDIUM", HIGH: "HIGH" };

/**
 * Known-bad patterns we look for when cross-referencing agents.
 * Each rule has:
 *   agents   – which agents must both have a hit for this pattern to fire
 *   test     – predicate(logData, networkData, memoryData, diskData) → bool
 *   type     – short label surfaced in the output
 *   message  – human-readable description
 *   weight   – how much this pattern adds to the risk score (0-100)
 */
const CORRELATION_RULES = [
  {
    agents:  ["log", "network"],
    type:    "Brute Force + Port Scan",
    message: "Log entries show repeated failed authentication while network data reveals active port scanning — consistent with a credential-stuffing campaign.",
    weight:  40,
    test: (log, net) =>
      log.some(l => /brute|fail|invalid|unauthorized/i.test(JSON.stringify(l))) &&
      net.some(n => /scan|sweep|probe/i.test(JSON.stringify(n))),
  },
  {
    agents:  ["memory", "network"],
    type:    "C2 Beacon Detected",
    message: "A suspicious process in memory is communicating with an anomalous external IP — possible Command & Control (C2) activity.",
    weight:  50,
    test: (_, net, mem) =>
      mem.some(m => m.type === "Suspicious Process") &&
      net.some(n => /c2|beacon|tunnel|exfil|suspicious/i.test(JSON.stringify(n))),
  },
  {
    agents:  ["disk", "memory"],
    type:    "Malware Persistence",
    message: "A deleted or hidden file on disk correlates with an active suspicious process in memory — likely malware establishing persistence.",
    weight:  55,
    test: (_, __, mem, disk) =>
      disk.some(d => d.deleted) &&
      mem.some(m => m.type === "Suspicious Process"),
  },
  {
    agents:  ["log", "disk"],
    type:    "Log Tampering + File Deletion",
    message: "Log events indicate modification of system logs while disk analysis found deleted files — suggests an attacker covering their tracks.",
    weight:  45,
    test: (log, _, __, disk) =>
      log.some(l => /tamper|modify|clear|wipe|erase/i.test(JSON.stringify(l))) &&
      disk.some(d => d.deleted),
  },
  {
    agents:  ["network", "disk"],
    type:    "Data Exfiltration Attempt",
    message: "Unusual outbound network connections coincide with file-system artifacts — possible data exfiltration in progress.",
    weight:  50,
    test: (_, net, __, disk) =>
      net.some(n => /exfil|upload|outbound|transfer/i.test(JSON.stringify(n))) &&
      disk.length > 0,
  },
  {
    agents:  ["log", "memory"],
    type:    "Privilege Escalation",
    message: "Log entries show privilege escalation attempts correlated with a suspicious process running at elevated context.",
    weight:  45,
    test: (log, _, mem) =>
      log.some(l => /privilege|escalat|root|sudo|admin/i.test(JSON.stringify(l))) &&
      mem.some(m => m.type === "Suspicious Process"),
  },
  {
    agents:  ["log", "network", "memory", "disk"],
    type:    "Full Compromise Indicator",
    message: "Findings across ALL four agents are consistent with a full system compromise: intrusion, lateral movement, persistence, and exfiltration.",
    weight:  80,
    test: (log, net, mem, disk) =>
      log.length > 0 && net.length > 0 && mem.length > 0 && disk.length > 0,
  },
];

// ─── Helpers ──────────────────────────────────────────────────

/**
 * Safely stringify any value for pattern matching.
 */
function safeStr(v) {
  try { return JSON.stringify(v).toLowerCase(); } catch { return ""; }
}

/**
 * Extract the most meaningful "label" from a heterogeneous finding.
 */
function findingLabel(item, source) {
  const s = source.toLowerCase();
  if (s === "log")     return item.type  || item.line || "Log event";
  if (s === "network") return item.type  || item.detail || "Network event";
  if (s === "memory")  return `${item.type || "Memory event"} — ${item.process || ""}`;
  if (s === "disk")    return item.name  || item.file  || "Disk artifact";
  return "Finding";
}

/**
 * Assign a relative timestamp offset so every finding gets a
 * plausible position in the unified timeline (real timestamps come
 * from the actual data when available).
 */
function extractTimestamp(item) {
  // Prefer any real timestamp the agent already embedded
  const candidates = ["timestamp", "time", "date", "ts", "datetime", "at"];
  for (const key of candidates) {
    if (item[key]) return new Date(item[key]);
  }
  return null; // will be assigned a synthetic offset later
}

/**
 * Build a flat list of timeline events from all agent outputs.
 * Events without real timestamps are ordered after real ones,
 * grouped by agent in collection order.
 */
function buildTimeline(logData, networkData, memoryData, diskData) {
  const allEvents = [];
  const baseTime = new Date();

  const sources = [
    { name: "Log",     icon: "📊", data: logData,     offsetBase: -120 },
    { name: "Network", icon: "🌐", data: networkData,  offsetBase: -90  },
    { name: "Disk",    icon: "💾", data: diskData,     offsetBase: -60  },
    { name: "Memory",  icon: "🧠", data: memoryData,   offsetBase: -30  },
  ];

  sources.forEach(({ name, icon, data, offsetBase }) => {
    if (!Array.isArray(data)) return;
    data.forEach((item, idx) => {
      const real = extractTimestamp(item);
      const ts = real || new Date(baseTime.getTime() + (offsetBase + idx * 5) * 1000);
      allEvents.push({
        timestamp:   ts.toISOString(),
        source:      name,
        icon,
        label:       findingLabel(item, name),
        detail:      item.line || item.detail || item.type || "",
        ip:          item.ip   || null,
        severity:    item.deleted || item.type === "Suspicious Process" ? "HIGH" : "INFO",
        raw:         item,
      });
    });
  });

  // Sort chronologically
  allEvents.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
  return allEvents;
}

/**
 * Run every correlation rule and collect matching patterns.
 */
function detectPatterns(logData, networkData, memoryData, diskData) {
  const matched = [];
  for (const rule of CORRELATION_RULES) {
    try {
      if (rule.test(logData, networkData, memoryData, diskData)) {
        matched.push({
          type:    rule.type,
          message: rule.message,
          weight:  rule.weight,
          agents:  rule.agents,
        });
      }
    } catch (_) { /* rule errors must not crash the agent */ }
  }
  return matched;
}

/**
 * Compute a 0-100 risk score from:
 *   • volume of findings per agent
 *   • severity flags (deleted files, suspicious processes, etc.)
 *   • matched correlation patterns
 */
function computeRiskScore(logData, networkData, memoryData, diskData, patterns) {
  let score = 0;

  // Volume contribution (max 30 pts)
  const total = logData.length + networkData.length + memoryData.length + diskData.length;
  score += Math.min(total * 2, 30);

  // Severity flags (max 20 pts)
  if (diskData.some(d => d.deleted))                     score += 10;
  if (memoryData.some(m => m.type === "Suspicious Process")) score += 10;

  // Pattern weights (capped at 70 pts total)
  const patternScore = patterns.reduce((acc, p) => acc + p.weight, 0);
  score += Math.min(patternScore, 70);

  return Math.min(Math.round(score), 100);
}

/**
 * Map numeric score → RISK enum + label.
 */
function scoreToRisk(score) {
  if (score >= 65) return RISK.HIGH;
  if (score >= 35) return RISK.MEDIUM;
  return RISK.LOW;
}

/**
 * Flatten all raw findings into a single deduplicated evidence list
 * so the report agent has a clean, source-tagged array to work with.
 */
function buildEvidenceList(logData, networkData, memoryData, diskData) {
  const evidence = [];

  const push = (source, item) => {
    evidence.push({ source, ...item });
  };

  (logData     || []).forEach(i => push("Log",     i));
  (networkData || []).forEach(i => push("Network", i));
  (memoryData  || []).forEach(i => push("Memory",  i));
  (diskData    || []).forEach(i => push("Disk",    i));

  return evidence;
}

// ─── Main export ──────────────────────────────────────────────

/**
 * runCorrelation({ logData, networkData, memoryData, diskData })
 *
 * Returns:
 * {
 *   riskLevel:   "LOW" | "MEDIUM" | "HIGH",
 *   riskScore:   number (0-100),
 *   confidence:  number (0-100),   // how much data was present
 *   patterns:    CorrelationPattern[],
 *   timeline:    TimelineEvent[],
 *   evidence:    Evidence[],
 *   summary:     string,
 *   agentStatus: { log, network, memory, disk }   // presence flags
 * }
 */
function runCorrelation({ logData = [], networkData = [], memoryData = [], diskData = [] } = {}) {
  // ── 1. Build unified timeline
  const timeline = buildTimeline(logData, networkData, memoryData, diskData);

  // ── 2. Detect cross-agent patterns
  const patterns = detectPatterns(logData, networkData, memoryData, diskData);

  // ── 3. Score and classify risk
  const riskScore = computeRiskScore(logData, networkData, memoryData, diskData, patterns);
  const riskLevel = scoreToRisk(riskScore);

  // ── 4. Confidence: how many of the 4 agents contributed data
  const agentsWithData = [logData, networkData, memoryData, diskData].filter(a => a.length > 0).length;
  const confidence = Math.round((agentsWithData / 4) * 100);

  // ── 5. Flatten evidence
  const evidence = buildEvidenceList(logData, networkData, memoryData, diskData);

  // ── 6. Agent status flags (useful for the report)
  const agentStatus = {
    log:     logData.length     > 0,
    network: networkData.length > 0,
    memory:  memoryData.length  > 0,
    disk:    diskData.length    > 0,
  };

  // ── 7. One-line summary
  const activeAgents = Object.entries(agentStatus)
    .filter(([, v]) => v)
    .map(([k]) => k)
    .join(", ");

  const summary =
    evidence.length === 0
      ? "No findings were detected across any agent. System appears clean."
      : `${evidence.length} finding(s) collected from ${agentsWithData} agent(s) ` +
        `[${activeAgents}]. ${patterns.length} cross-agent pattern(s) matched. ` +
        `Risk assessed as ${riskLevel} (score ${riskScore}/100, confidence ${confidence}%).`;

  return {
    riskLevel,
    riskScore,
    confidence,
    patterns,
    timeline,
    evidence,
    summary,
    agentStatus,
  };
}

export default runCorrelation;