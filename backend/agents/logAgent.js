import fs from "fs";
import readline from "readline";

const MAX_FILE_BYTES = Number(process.env.LOG_MAX_BYTES || 50 * 1024 * 1024);
const MAX_FINDINGS = Number(process.env.LOG_MAX_FINDINGS || 10000);
const IPV4_PATTERN = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const TIMESTAMP_PATTERNS = [
  /\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b/,
  /\b\d{4}-\d{2}-\d{2}\b/,
  /\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b/i,
];
const RULES = [
  { type: "Failed Login", category: "Authentication", severity: "medium", confidence: 0.9, pattern: /failed password|failed login|authentication failure|login failed|invalid password|logon failure/i, explanation: "A failed authentication attempt was detected." },
  { type: "Brute Force Activity", category: "Authentication Attack", severity: "high", confidence: 0.95, pattern: /brute.?force|too many authentication failures|account locked/i, explanation: "The event indicates repeated authentication activity against an account." },
  { type: "Unauthorized Access", category: "Access Control", severity: "high", confidence: 0.85, pattern: /unauthorized|access denied|permission denied|forbidden|privilege violation/i, explanation: "The event indicates access was denied or attempted without authorization." },
  { type: "Privilege Escalation", category: "Privilege", severity: "high", confidence: 0.85, pattern: /sudo|privilege escalat|elevat(?:ed|ion)|became root|admin privilege|added to administrators/i, explanation: "The event contains a possible privilege change or elevation." },
  { type: "Suspicious Command", category: "Execution", severity: "high", confidence: 0.8, pattern: /powershell|cmd\.exe|certutil|\bwget\b|\bcurl\b|encodedcommand|base64|rundll32|regsvr32/i, explanation: "The event contains a command or utility commonly associated with suspicious execution." },
  { type: "Log Tampering", category: "Defense Evasion", severity: "high", confidence: 0.9, pattern: /clear(?:ed)? logs?|audit policy change|log tamper|wevtutil|history -c|erase logs?/i, explanation: "The event suggests an attempt to alter, clear, or disable audit evidence." },
  { type: "Persistence Indicator", category: "Persistence", severity: "high", confidence: 0.8, pattern: /scheduled task|cron|startup|run key|service installed|autorun|registry run/i, explanation: "The event contains a possible persistence mechanism." },
  { type: "Malware Indicator", category: "Malware", severity: "critical", confidence: 0.75, pattern: /malware|ransomware|trojan|backdoor|keylogger|rootkit|virus|cryptominer|meterpreter/i, explanation: "The event contains a malware-related indicator." },
  { type: "System Error", category: "System", severity: "low", confidence: 0.55, pattern: /\berror\b|critical|fatal|segmentation fault|service failed/i, explanation: "A system or service error was found and may require investigation." },
];
const SEVERITY_SCORE = { info: 1, low: 3, medium: 8, high: 20, critical: 35 };
const SEVERITY_RANK = { info: 1, low: 2, medium: 3, high: 4, critical: 5 };
const ALLOWED_COMMANDS = new Set(["curl", "wget"]);

const isValidIp = (ip) => ip.split(".").every((part) => Number(part) <= 255);
const parseJsonLine = (line) => {
  try { const value = JSON.parse(line); return value && typeof value === "object" ? value : null; } catch { return null; }
};
const extractValue = (line, patterns) => {
  for (const pattern of patterns) { const match = line.match(pattern); if (match?.[1]) return match[1]; }
  return null;
};
const toIsoTimestamp = (value) => {
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? null : parsed.toISOString();
};
const extractTimestamp = (line) => {
  const value = TIMESTAMP_PATTERNS.map((pattern) => line.match(pattern)?.[0]).find(Boolean);
  if (!value) return null;
  const withYear = /^[A-Z][a-z]{2}\s/.test(value) ? `${new Date().getUTCFullYear()} ${value}` : value;
  const parsed = new Date(withYear.includes("T") ? withYear : withYear.replace(" ", "T"));
  return Number.isNaN(parsed.getTime()) ? null : parsed.toISOString();
};
const detectFormat = (stats) => {
  if (stats.lines === 0) return "Empty Log";
  if (stats.json === stats.lines) return "JSON Lines";
  if (stats.json > 0) return "Mixed Log";
  if (stats.syslog > 0) return "Syslog / Unix";
  if (stats.windows > 0) return "Windows Event Log";
  return "Plain Text Log";
};

const isContextualRuleMatch = (rule, source) => {
  if (rule.type === "Suspicious Command") {
    const command = source.match(/\b(curl|wget)\b/i)?.[1]?.toLowerCase();
    if (command && ALLOWED_COMMANDS.has(command) && !/(?:executed|running|spawned|shell|command|download|payload|encoded)/i.test(source)) return false;
  }
  if (rule.type === "Malware Indicator" && !/(?:detected|blocked|executed|infected|payload|sample|process|alert|quarantined)/i.test(source)) return false;
  return rule.pattern.test(source);
};
const normalizeRecord = (line, lineNumber) => {
  const json = parseJsonLine(line);
  const source = json ? JSON.stringify(json) : line;
  const rawTimestamp = json?.timestamp || json?.time || json?.datetime || json?.date;
  const timestamp = rawTimestamp ? toIsoTimestamp(rawTimestamp) : extractTimestamp(line);
  const indicators = [...new Set((source.match(IPV4_PATTERN) || []).filter(isValidIp))];
  const user = json?.user || json?.username || json?.account || extractValue(line, [/(?:user|account|for)\s*[=: ]\s*["']?([\w.-]+)/i]);
  const host = json?.host || json?.hostname || extractValue(line, [/(?:host|hostname)\s*[=: ]\s*["']?([\w.-]+)/i]);
  const process = json?.process || json?.command || extractValue(line, [/(?:process|proc|program|image)\s*[=: ]\s*["']?([\w.-]+)/i]);
  const eventId = json?.eventId || json?.event_id || extractValue(line, [/event.?id\s*[=: ]\s*["']?(\d+)/i]);
  const matchedRules = RULES.filter((rule) => isContextualRuleMatch(rule, source));
  const strongestRule = matchedRules.sort((left, right) => SEVERITY_RANK[right.severity] - SEVERITY_RANK[left.severity])[0];
  if (!strongestRule && indicators.length === 0) return null;
  return {
    type: strongestRule?.type || "IP Detected",
    category: strongestRule?.category || "Network Indicator",
    severity: strongestRule?.severity || "info",
    ruleConfidence: strongestRule?.confidence || 0.7,
    explanation: strongestRule?.explanation || "An IPv4 address was found in the log event.",
    line, rawLine: line, lineNumber, timestamp,
    ip: indicators[0] || null, sourceIp: indicators[0] || null,
    destinationIp: indicators[1] || null, allIps: indicators,
    indicators, user, host, process, eventId,
    matchedRules: matchedRules.map((rule) => rule.type),
  };
};
const buildTimeline = (findings) => findings.filter((finding) => finding.timestamp).map((finding) => ({
  timestamp: finding.timestamp, type: finding.type, category: finding.category,
  severity: finding.severity, detail: finding.explanation, ip: finding.ip,
  user: finding.user, lineNumber: finding.lineNumber,
})).sort((left, right) => new Date(left.timestamp) - new Date(right.timestamp));

const analyzeLogs = async (filePath) => {
  const size = fs.statSync(filePath).size;
  if (size === 0) throw new Error("The log file is empty");
  if (size > MAX_FILE_BYTES) throw new Error(`Log file exceeds the ${Math.round(MAX_FILE_BYTES / 1024 / 1024)} MB limit`);

  const findings = [];
  const failedEvents = new Map();
  const stats = { lines: 0, json: 0, syslog: 0, windows: 0, timestamped: 0, structured: 0, truncated: false };
  const input = readline.createInterface({ input: fs.createReadStream(filePath, { encoding: "utf8" }), crlfDelay: Infinity });

  for await (const line of input) {
    if (!line.trim()) continue;
    stats.lines += 1;
    const json = parseJsonLine(line);
    if (json) stats.json += 1;
    if (/\b(?:sshd|sudo|kernel|systemd)\b/i.test(line)) stats.syslog += 1;
    if (/event.?id|winlog|security-auditing|4624|4625/i.test(line)) stats.windows += 1;
    if (extractTimestamp(line) || json?.timestamp || json?.time) stats.timestamped += 1;
    if (json?.user || json?.username || json?.host || json?.hostname || json?.process || json?.eventId || /\b(?:\d{1,3}\.){3}\d{1,3}\b/.test(line) || /(?:user|account|host|process|event.?id)\s*[=:]/i.test(line)) stats.structured += 1;
    const finding = normalizeRecord(line, stats.lines);
    if (!finding) continue;
    if (findings.length < MAX_FINDINGS) findings.push(finding); else stats.truncated = true;
    if (finding.type === "Failed Login" && finding.timestamp) {
      const key = `${finding.sourceIp || "unknown"}:${finding.user || "unknown"}`;
      const events = failedEvents.get(key) || [];
      events.push({ timestamp: finding.timestamp, finding });
      failedEvents.set(key, events.filter((event) => new Date(finding.timestamp) - new Date(event.timestamp) <= 5 * 60 * 1000));
    }
  }

  for (const [key, events] of failedEvents) {
    if (events.length < 5) continue;
    const separator = key.indexOf(":");
    const sourceIp = key.slice(0, separator);
    const user = key.slice(separator + 1);
    if (findings.length >= MAX_FINDINGS) break;
    findings.push({ type: "Brute Force Activity", category: "Authentication Attack", severity: "high", ruleConfidence: 0.98,
      explanation: `${events.length} failed login events occurred within five minutes for ${user} from ${sourceIp}.`,
      line: "Aggregated detection across normalized log events", rawLine: null, lineNumber: null, timestamp: events.at(-1).timestamp,
      ip: sourceIp === "unknown" ? null : sourceIp, sourceIp: sourceIp === "unknown" ? null : sourceIp, destinationIp: null,
      allIps: sourceIp === "unknown" ? [] : [sourceIp], indicators: sourceIp === "unknown" ? [] : [sourceIp], user: user === "unknown" ? null : user,
      host: null, process: null, eventId: null, matchedRules: ["Failed Login", "Brute Force Activity"], aggregate: true, eventCount: events.length });
  }

  const format = detectFormat(stats);
  const bySeverity = findings.reduce((counts, finding) => { counts[finding.severity] = (counts[finding.severity] || 0) + 1; return counts; }, {});
  const byCategory = findings.reduce((counts, finding) => { counts[finding.category] = (counts[finding.category] || 0) + 1; return counts; }, {});
  const uniqueIndicators = [...new Set(findings.flatMap((finding) => finding.indicators || []))];
  const timestamps = findings.map((finding) => finding.timestamp).filter(Boolean).sort();
  const riskScore = Math.min(100, findings.reduce((total, finding) => total + (SEVERITY_SCORE[finding.severity] || 0), 0));
  const risk = riskScore >= 65 ? "HIGH" : riskScore >= 30 ? "MEDIUM" : "LOW";
  const formatScore = { "JSON Lines": 95, "Windows Event Log": 90, "Syslog / Unix": 90, "Mixed Log": 82, "Plain Text Log": 75, "Empty Log": 0 }[format] || 60;
  const parseCoverage = stats.lines === 0 ? 0 : stats.truncated ? Math.round((MAX_FINDINGS / stats.lines) * 100) : 100;
  const timestampQuality = stats.lines === 0 ? 0 : Math.round((stats.timestamped / stats.lines) * 100);
  const structureQuality = stats.lines === 0 ? 0 : Math.max(75, Math.round((stats.structured / stats.lines) * 100));
  const consistency = findings.every((finding) => Array.isArray(finding.indicators) && typeof finding.line === "string") ? 100 : 70;
  const confidence = stats.lines === 0 ? 0 : Math.round(formatScore * 0.35 + parseCoverage * 0.25 + timestampQuality * 0.15 + structureQuality * 0.15 + consistency * 0.10);

  return { findings, meta: { format, totalLines: stats.lines, findings: findings.length, truncated: stats.truncated, risk, riskScore, confidence,
    confidenceBasis: { format: formatScore, parseCoverage, timestampQuality, structureQuality, consistency }, bySeverity, byCategory, uniqueIndicators,
    uniqueUsers: [...new Set(findings.map((finding) => finding.user).filter(Boolean))], timeRange: { from: timestamps[0] || null, to: timestamps.at(-1) || null },
    timeline: buildTimeline(findings), summary: findings.length ? `${findings.length} normalized finding(s) detected in ${format}. Risk assessed as ${risk} (${riskScore}/100).` : `No suspicious events detected in ${format}.`,
    rulesApplied: RULES.map((rule) => rule.type) } };
};

export default analyzeLogs;
