import React from "react";
import axios from "axios";
import { useNavigate } from "react-router-dom";
import Icon from "../components/Icon";
import PageHeader from "../components/PageHeader";

const RESULT_CONFIG = {
  disk: {
    icon: "disk", title: "Disk Analysis Results",
    renderCard: (item, i) => (
      <div key={i} className={`forensic-card ${item.deleted ? "disk-deleted" : item.suspicious ? "mem-suspicious" : "disk-ok"}`}
           style={{ animationDelay: `${i * 0.05}s` }}>
        <div className="log-finding-header">
          <strong>{item.type || "Disk Artifact"}</strong>
          <span className={`severity-chip ${item.severity || "info"}`}>{(item.severity || "info").toUpperCase()}</span>
        </div>
        <p className="log-explanation">{item.explanation}</p>
        <div className="log-detail-grid">
          <span><b>File</b>{item.fileName || "Unknown"}</span>
          <span><b>Extension</b>{item.ext || "-"}</span>
          <span><b>Category</b>{item.category || "-"}</span>
          <span><b>Status</b>{item.deleted ? "Deleted" : item.suspicious ? "Suspicious" : "Present"}</span>
        </div>
        <p className="log-raw"><strong>Path:</strong> {item.filePath || "-"}</p>
        {item.deleted   && <span className="badge-deleted">⚠ Deleted File</span>}
        {item.suspicious && !item.deleted && <span className="badge-deleted">🚨 Suspicious</span>}
      </div>
    ),
  },
  log: {
    icon: "log", title: "Log Analysis Results",
    renderCard: (item, i) => (
      <div key={i} className={`forensic-card log-finding log-${item.severity || "info"}`} style={{ animationDelay: `${i * 0.05}s` }}>
        <div className="log-finding-header">
          <strong>{item.type}</strong>
          <span className={`severity-chip ${item.severity || "info"}`}>{(item.severity || "info").toUpperCase()}</span>
        </div>
        <p className="log-explanation">{item.explanation}</p>
        <div className="log-detail-grid">
          <span><b>Category</b>{item.category || "Event"}</span>
          <span><b>Line</b>{item.lineNumber || "-"}</span>
          <span><b>IP</b>{item.ip || "None"}</span>
          <span><b>User</b>{item.user || "Unknown"}</span>
        </div>
        <p className="log-raw"><strong>Raw event:</strong> {item.line}</p>
      </div>
    ),
  },
  memory: {
    icon: "memory", title: "Memory Analysis Results",
    renderCard: (item, i) => item.ruleId ? (
      <div key={i} className={`forensic-card log-finding log-${item.severity || "info"}`}
           style={{ animationDelay: `${i * 0.05}s` }}>
        <div className="log-finding-header">
          <strong>{item.type}</strong>
          <span className={`severity-chip ${item.severity || "info"}`}>{(item.severity || "info").toUpperCase()}</span>
        </div>
        <p className="log-explanation">{item.explanation}</p>
        <div className="log-detail-grid">
          <span><b>Rule</b>{item.ruleId}</span>
          <span><b>Process</b>{item.process || "-"}</span>
          <span><b>PID</b>{item.pids?.length ? item.pids.join(", ") : "-"}</span>
          <span><b>Confidence</b>{item.confidence}%</span>
        </div>
        <p className="log-raw"><strong>Observed:</strong> {item.observation}</p>
        {item.alternatives?.length > 0 && (
          <div className="mem-alternatives">
            <strong>Benign explanations to rule out</strong>
            <ul>{item.alternatives.map((alt, j) => <li key={j}>{alt}</li>)}</ul>
          </div>
        )}
        {item.analystAction && <p className="log-raw"><strong>Next step:</strong> {item.analystAction}</p>}
        {item.mitre?.length > 0 && (
          <div className="log-coverage-list mem-mitre">
            {item.mitre.map((t) => <span key={t}>{t}</span>)}
          </div>
        )}
      </div>
    ) : (
      <div key={i} className={`forensic-card ${item.type === "Suspicious Process" ? "mem-suspicious" : "mem-ok"}`}
           style={{ animationDelay: `${i * 0.05}s` }}>
        <p><strong>Process:</strong> {item.process}</p>
        <strong>{item.type}</strong>
        {item.pid && <p>PID: {item.pid}</p>}
      </div>
    ),
  },
  network: {
    icon: "network", title: "Network Analysis Results",
    renderCard: (item, i) => (
      <div key={i} className="forensic-card network" style={{ animationDelay: `${i * 0.05}s` }}>
        <h4>{item.type}</h4>
        <p><strong>IP:</strong> {item.ip}</p>
        <p>{item.detail}</p>
      </div>
    ),
  },
};

const DUMMY_TIMELINE = [
  { time: "00:00:01", event: <><strong>Scan initiated</strong> — file ingested by engine</> },
  { time: "00:00:03", event: <><strong>Entropy analysis</strong> — checking for packed/encrypted sections</> },
  { time: "00:00:07", event: <><strong>Pattern matching</strong> — comparing against known IOC signatures</> },
  { time: "00:00:12", event: <><strong>Findings compiled</strong> — risk score calculated</> },
  { time: "00:00:14", event: <><strong>Report generated</strong> — ready for review</> },
];

function readStoredObject(key) {
  try {
    const value = sessionStorage.getItem(key);
    return value ? JSON.parse(value) : null;
  } catch {
    return null;
  }
}

function deriveRisk(data) {
  if (!data || data.length === 0) return "none";
  const hasCritical = data.some(d =>
    d.deleted || d.type === "Suspicious Process" ||
    d.severity === "critical" || d.severity === "high" ||
    (d.type && d.type.toLowerCase().includes("brute")) ||
    (d.type && d.type.toLowerCase().includes("malware"))
  );
  if (hasCritical) return "high";
  if (data.length > 5) return "medium";
  return "low";
}

function getLogConfidence(meta, data) {
  if (Number.isFinite(meta?.confidence) && meta.confidence > 0) return meta.confidence;
  if (!meta?.totalLines && data.length === 0) return 0;

  if (meta?.confidenceBasis) {
    const basis = meta.confidenceBasis;
    return Math.round(
      (basis.format || 0) * 0.35 +
      (basis.parseCoverage || 0) * 0.25 +
      (basis.timestampQuality || 0) * 0.15 +
      (basis.structureQuality || 0) * 0.15 +
      (basis.consistency || 0) * 0.10
    );
  }

  const formatScore = {
    "JSON Lines": 95,
    "Windows Event Log": 90,
    "Syslog / Unix": 90,
    "Mixed Log": 82,
    "Plain Text Log": 75,
  }[meta?.format] || 60;
  const timestampScore = data.length === 0
    ? 80
    : Math.round((data.filter((item) => item.timestamp).length / data.length) * 100);
  const structureScore = data.length === 0
    ? 80
    : Math.round((data.filter((item) => item.ip || item.user || item.host || item.process || item.eventId).length / data.length) * 100);

  return Math.round(formatScore * 0.35 + 100 * 0.25 + timestampScore * 0.15 + structureScore * 0.15 + 100 * 0.10);
}

const ResultPage = ({ type }) => {
  const config = RESULT_CONFIG[type];
  const navigate = useNavigate();
  const raw = sessionStorage.getItem(`result_${type}`);
  const fileName = sessionStorage.getItem(`result_${type}_file`) || "unknown";
 const logMeta = type === "log" ? readStoredObject("result_log_meta") : null;
const networkMeta = type === "network" ? readStoredObject("result_network_meta") : null;
const diskMeta = type === "disk" ? readStoredObject("result_disk_meta") : null;
const memoryMeta = type === "memory" ? readStoredObject("result_memory_meta") : null;
const memoryAnalysisId = type === "memory" ? sessionStorage.getItem("result_memory_id") : null;

const logAnalysisId =
  type === "log"
    ? sessionStorage.getItem("result_log_id")
    : null;

const networkAnalysisId =
  type === "network"
    ? sessionStorage.getItem("result_network_id")
    : null;

let data = [];

try {
  const parsed = raw ? JSON.parse(raw) : [];
  data = Array.isArray(parsed) ? parsed : [];
} catch {
  data = [];
}

const networkRisk = networkMeta?.risk || "none";

const risk =
  type === "log" && logMeta?.risk
    ? logMeta.risk.toLowerCase()
    : type === "network"
    ? networkRisk.toLowerCase()
    : type === "memory" && memoryMeta?.risk
    ? (data.length === 0 ? "none" : memoryMeta.risk.toLowerCase())
    : deriveRisk(data);

const logConfidence =
  type === "log"
    ? getLogConfidence(logMeta, data)
    : null;

  const riskLabel = { high: "HIGH RISK", medium: "MEDIUM RISK", low: "LOW RISK", none: "CLEAN" }[risk];

  const downloadLogReport = async (format) => {
    try {
      const response = await axios.get(
        `http://localhost:5000/api/analyze/log/report/${logAnalysisId}?format=${format}`,
        { responseType: format === "json" ? "json" : "blob" }
      );
      const content = format === "json" ? JSON.stringify(response.data, null, 2) : response.data;
      const blob = new Blob([content], { type: format === "pdf" ? "application/pdf" : format === "markdown" ? "text/markdown" : "application/json" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `${fileName.replace(/[^a-z0-9._-]/gi, "_")}-forensic-report.${format === "markdown" ? "md" : format}`;
      link.click();
      URL.revokeObjectURL(url);
    } catch (error) {
      console.error(error);
      alert(`${format.toUpperCase()} report generation failed.`);
    }
  };

  const downloadMemoryEnvelope = async () => {
    try {
      const response = await axios.get(
        `http://localhost:5000/api/analyze/memory/envelope/${memoryAnalysisId}`,
        { responseType: "blob" }
      );
      const url = URL.createObjectURL(response.data);
      const link = document.createElement("a");
      link.href = url;
      link.download = `${fileName.replace(/[^a-z0-9._-]/gi, "_")}-memory_agent_output.json`;
      link.click();
      URL.revokeObjectURL(url);
    } catch (error) {
      console.error(error);
      alert("Memory envelope download failed.");
    }
  };

  const downloadNetworkReport = async (format) => {
  try {

    const response = await axios.get(
      `http://localhost:5000/api/analyze/network/report/${networkAnalysisId}?format=${format}`,
      {
        responseType: format === "json" ? "json" : "blob"
      }
    );

    const content =
      format === "json"
        ? JSON.stringify(response.data, null, 2)
        : response.data;

    const blob = new Blob(
      [content],
      {
        type:
          format === "pdf"
            ? "application/pdf"
            : format === "markdown"
            ? "text/markdown"
            : "application/json"
      }
    );

    const url = URL.createObjectURL(blob);

    const link = document.createElement("a");

    link.href = url;

    link.download =
      `${fileName.replace(/[^a-z0-9._-]/gi, "_")}-network-report.${
        format === "markdown" ? "md" : format
      }`;

    link.click();

    URL.revokeObjectURL(url);

  } catch (error) {

    console.error(error);

    alert(`${format.toUpperCase()} report generation failed.`);
  }
};

  return (
    <>
      <PageHeader icon={config.icon} eyebrow="Results" title={config.title} subtitle={fileName}>
        <span className={`risk-badge ${risk}`}>{riskLabel}</span>
        <button className="btn btn-ghost" onClick={() => navigate(`/agent/${type}`)}>
          <Icon name="arrowLeft" size={16} /> New scan
        </button>
      </PageHeader>

      <div className="page-body">

        {/* SUMMARY */}
        <h2 className="section-title">Summary</h2>
        <div className="summary-box">
          <div className="summary-meta">
            <div className="meta-item">
              <div className="meta-key">Agent</div>
              <div className="meta-val">{config.title.replace(" Results", "")}</div>
            </div>
            <div className="meta-item">
              <div className="meta-key">File Analyzed</div>
              <div className="meta-val mono">{fileName}</div>
            </div>
            <div className="meta-item">
              <div className="meta-key">Total Findings</div>
              <div className="meta-val">{data.length}</div>
            </div>
            {type === "log" && (
              <div className="meta-item">
                <div className="meta-key">Unique Indicators</div>
                <div className="meta-val">{logMeta?.uniqueIndicators?.length ?? new Set(data.flatMap((item) => item.indicators || [])).size}</div>
              </div>
            )}
            {type === "log" && logMeta && (
              <div className="meta-item">
                <div className="meta-key">Confidence</div>
                <div className="meta-val">{logConfidence}%</div>
              </div>
            )}
{type === "network" && networkMeta && (
  <>
    <div className="meta-item">
      <div className="meta-key">Network Traffic</div>
      <div className="meta-val">{networkMeta.totalPackets} packets</div>
    </div>

    <div className="meta-item">
      <div className="meta-key">External Connections</div>
      <div className="meta-val">{networkMeta.externalConnections}</div>
    </div>

    <div className="meta-item">
      <div className="meta-key">Malicious IPs</div>
      <div className="meta-val">{networkMeta.maliciousIPs}</div>
    </div>

    <div className="meta-item">
      <div className="meta-key">Port Scans</div>
      <div className="meta-val">{networkMeta.portScans}</div>
    </div>

    <div className="meta-item">
      <div className="meta-key">Beaconing</div>
      <div className="meta-val">{networkMeta.beaconingActivities}</div>
    </div>
  </>
)}
            {type === "memory" && memoryMeta && (
              <>
                <div className="meta-item">
                  <div className="meta-key">Envelope Status</div>
                  <div className="meta-val">{memoryMeta.status}</div>
                </div>
                <div className="meta-item">
                  <div className="meta-key">Evidence Integrity</div>
                  <div className="meta-val">
                    {memoryMeta.mode === "replay" ? "Not sealed (demo)" : memoryMeta.integrityVerified ? "Verified" : "FAILED"}
                  </div>
                </div>
                <div className="meta-item">
                  <div className="meta-key">Risk Score</div>
                  <div className="meta-val">{memoryMeta.riskScore ?? "-"} / 100</div>
                </div>
              </>
            )}
            {type === "disk" && diskMeta && (
              <>
                <div className="meta-item">
                  <div className="meta-key">Entries Scanned</div>
                  <div className="meta-val">{diskMeta.totalEntries ?? "-"}</div>
                </div>
                <div className="meta-item">
                  <div className="meta-key">Deleted Files</div>
                  <div className="meta-val">{diskMeta.deletedFiles ?? "-"}</div>
                </div>
                <div className="meta-item">
                  <div className="meta-key">Risk Score</div>
                  <div className="meta-val">{diskMeta.riskScore ?? "-"} / 100</div>
                </div>
              </>
            )}
            <div className="meta-item">
              <div className="meta-key">Risk Level</div>
              <div className="meta-val">
                <span className={`risk-badge ${risk}`}>{riskLabel}</span>
              </div>
            </div>
            <div className="meta-item">
              <div className="meta-key">Timestamp</div>
              <div className="meta-val mono">
                {new Date().toLocaleString()}
              </div>
            </div>
          </div>
        </div>

        {/* FINDINGS */}
        <h2 className="section-title">Findings <span className="section-count">{data.length}</span></h2>
        <div className="result-section">
          {data.length === 0
            ? <p className="result-empty">No findings detected in this evidence.</p>
            : data.map((item, i) => config.renderCard(item, i))
          }
        </div>

        {type === "log" && logMeta && (
          <>
            <h2 className="section-title">Detection metrics</h2>
            <div className="summary-box log-metrics-box">
              <div className="log-metric-row">
                <span>Format <b>{logMeta.format}</b></span>
                <span>Lines inspected <b>{logMeta.totalLines}</b></span>
                <span>Risk score <b>{logMeta.riskScore}/100</b></span>
                <span>Users <b>{logMeta.uniqueUsers?.length || 0}</b></span>
              </div>
              <p>{logMeta.summary}</p>
            </div>
          </>
        )}
      {type === "network" && networkMeta && (
  <>
    <h2 className="section-title">Network metrics</h2>
<div className="summary-box log-metrics-box">
  <div className="log-metric-row">
    <span>
      Packets <b>{networkMeta.totalPackets}</b>
    </span>

    <span>
      External <b>{networkMeta.externalConnections}</b>
    </span>

    <span>
      Malicious <b>{networkMeta.maliciousIPs}</b>
    </span>

    <span>
      Port Scans <b>{networkMeta.portScans}</b>
    </span>

    <span>
      Beaconing <b>{networkMeta.beaconingActivities}</b>
    </span>
  </div>

<p>{networkMeta.summary}</p>
</div>
</>
)}




        {type === "memory" && memoryMeta && (
          <>
            {(memoryMeta.mode === "replay" || memoryMeta.status === "INVALID") && (
              <div className="mem-status-banner">
                <strong>{memoryMeta.mode === "replay" ? "DEMO REPLAY — NOT EVIDENCE" : "INTEGRITY FAILURE — NOT ADMISSIBLE"}</strong>
                <p>{memoryMeta.statusBasis}</p>
              </div>
            )}
            <h2 className="section-title">Memory analysis metrics</h2>
            <div className="summary-box log-metrics-box">
              <div className="log-metric-row">
                <span>Case <b>{memoryMeta.caseId}</b></span>
                <span>OS <b>{memoryMeta.os}</b></span>
                <span>Plugins <b>{memoryMeta.coverage?.pluginsSucceeded}/{memoryMeta.coverage?.pluginsAttempted}</b></span>
                <span>Rules evaluated <b>{memoryMeta.coverage?.rulesEvaluated}/{memoryMeta.coverage?.rulesTotal}</b></span>
              </div>
              <div className="log-metric-row" style={{ marginTop: "12px" }}>
                {["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((s) => (
                  <span key={s}>{s.toLowerCase()} <b>{memoryMeta.findingsBySeverity?.[s] || 0}</b></span>
                ))}
              </div>
              {memoryMeta.evidence?.sha256 && (
                <p>SHA-256: <b style={{ fontFamily: "var(--mono)", overflowWrap: "anywhere" }}>{memoryMeta.evidence.sha256}</b></p>
              )}
              {memoryMeta.discrepancies?.length > 0 && memoryMeta.mode !== "replay" && (
                <p>Discrepancies: {memoryMeta.discrepancies.join("; ")}</p>
              )}
              <p>{memoryMeta.summary}</p>
            </div>

            {memoryMeta.iocs?.length > 0 && (
              <>
                <h2 className="section-title">Indicators of compromise <span className="section-count">{memoryMeta.iocs.length}</span></h2>
                <div className="summary-box">
                  <div className="mem-ioc-list">
                    {memoryMeta.iocs.map((ioc, i) => (
                      <div key={i} className="mem-ioc">
                        <span className="severity-chip info">{ioc.type}</span>
                        <code>{ioc.value}</code>
                        <small>{ioc.confidence}% · FP risk {ioc.falsePositiveRisk}</small>
                      </div>
                    ))}
                  </div>
                </div>
              </>
            )}

            {memoryMeta.limitations?.length > 0 && (
              <>
                <h2 className="section-title">Limitations</h2>
                <div className="summary-box">
                  <ul className="mem-limitations">
                    {memoryMeta.limitations.map((l, i) => <li key={i}>{l}</li>)}
                  </ul>
                </div>
              </>
            )}
          </>
        )}

        {type === "disk" && diskMeta && (
          <>
            <h2 className="section-title">Disk analysis metrics</h2>
            <div className="summary-box log-metrics-box">
              <div className="log-metric-row">
                <span>Filesystem <b>{diskMeta.volumeInfo?.fileSystemType || "Unknown"}</b></span>
                <span>Entries scanned <b>{diskMeta.totalEntries}</b></span>
                <span>Deleted files <b>{diskMeta.deletedFiles}</b></span>
                <span>Suspicious files <b>{diskMeta.suspiciousFiles}</b></span>
                <span>Risk score <b>{diskMeta.riskScore}/100</b></span>
              </div>
              {diskMeta.volumeInfo?.volumeName && (
                <p>Volume: <b>{diskMeta.volumeInfo.volumeName}</b>
                  {diskMeta.volumeInfo.lastMountTime && ` — Last mount: ${diskMeta.volumeInfo.lastMountTime}`}
                </p>
              )}
              <p>{diskMeta.summary}</p>
            </div>
          </>
        )}


        {/* TIMELINE */}
        <h2 className="section-title">Analysis timeline</h2>
        <div className="timeline">
          {(type === "log" && logMeta?.timeline?.length ? logMeta.timeline
            : type === "memory" && memoryMeta?.timeline?.length ? memoryMeta.timeline
            : DUMMY_TIMELINE).map((t, i) => (
            <div key={i} className="timeline-item" style={{ animationDelay: `${i * 0.08}s` }}>
              <div className="timeline-time">{t.timestamp ? new Date(t.timestamp).toLocaleString() : t.time}</div>
              <div className="timeline-event">
                {t.type ? <><strong>{t.type}</strong> — {t.detail} {t.ip && `(${t.ip})`}</> : t.event}
              </div>
            </div>
          ))}
        </div>

        <div className="btn-group">
          <button className="btn btn-ghost" onClick={() => navigate("/dashboard")}><Icon name="arrowLeft" size={16} /> Dashboard</button>
          <button className="btn btn-ghost" onClick={() => navigate("/history")}>View history</button>
          {type === "log" && (
  <>
    <button
      className="btn btn-ghost"
      onClick={() => downloadLogReport("json")}
    >
      <Icon name="download" size={16} /> JSON report
    </button>

    <button
      className="btn btn-ghost"
      onClick={() => downloadLogReport("markdown")}
    >
      <Icon name="download" size={16} /> Markdown report
    </button>

    <button
      className="btn btn-ghost"
      onClick={() => downloadLogReport("pdf")}
    >
      <Icon name="download" size={16} /> PDF report
    </button>
  </>
)}

{type === "memory" && memoryMeta?.envelopePath && memoryAnalysisId && (
  <button className="btn btn-ghost" onClick={downloadMemoryEnvelope}>
    <Icon name="download" size={16} /> Output envelope (JSON)
  </button>
)}

{type === "network" && (
  <>
    <button
      className="btn btn-ghost"
      onClick={() => downloadNetworkReport("json")}
    >
      <Icon name="download" size={16} /> JSON report
    </button>

    <button
      className="btn btn-ghost"
      onClick={() => downloadNetworkReport("markdown")}
    >
      <Icon name="download" size={16} /> Markdown report
    </button>

    <button
      className="btn btn-ghost"
      onClick={() => downloadNetworkReport("pdf")}
    >
      <Icon name="download" size={16} /> PDF report
    </button>
  </>
)}
          <button className="btn btn-primary" onClick={() => navigate(`/agent/${type}`)}>Run new scan</button>
        </div>
      </div>
    
    </>
  );
};

export default ResultPage;
