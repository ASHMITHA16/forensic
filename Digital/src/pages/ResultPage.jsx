import React from "react";
import axios from "axios";
import { useNavigate } from "react-router-dom";

const RESULT_CONFIG = {
  disk: {
    icon: "💾", title: "Disk Analysis Results",
    renderCard: (item, i) => (
      <div key={i} className={`forensic-card ${item.deleted ? "disk-deleted" : "disk-ok"}`}
           style={{ animationDelay: `${i * 0.05}s` }}>
        <p><strong>{item.name || item.file || "Unknown file"}</strong></p>
        {item.size   && <p>Size: {item.size}</p>}
        {item.type   && <p>Type: {item.type}</p>}
        {item.deleted && <span className="badge-deleted">⚠ Deleted File</span>}
      </div>
    ),
  },
  log: {
    icon: "📊", title: "Log Analysis Results",
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
    icon: "🧠", title: "Memory Analysis Results",
    renderCard: (item, i) => (
      <div key={i} className={`forensic-card ${item.type === "Suspicious Process" ? "mem-suspicious" : "mem-ok"}`}
           style={{ animationDelay: `${i * 0.05}s` }}>
        <p><strong>Process:</strong> {item.process}</p>
        <strong>{item.type}</strong>
        {item.pid && <p>PID: {item.pid}</p>}
      </div>
    ),
  },
  network: {
    icon: "🌐", title: "Network Analysis Results",
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
  const logAnalysisId = type === "log" ? sessionStorage.getItem("result_log_id") : null;
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

const networkRisk =
  networkMeta?.risk || "none";

const risk =
  type === "log" && logMeta?.risk
    ? logMeta.risk.toLowerCase()
    : type === "network"
    ? networkRisk
    : deriveRisk(data);
  
  const logConfidence = type === "log" ? getLogConfidence(logMeta, data) : null;
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
      <div className="page-header">
        <div>
          <div className="page-title">{config.icon} // {type}_results</div>
          <div className="page-subtitle">{config.title}</div>
        </div>
        <div style={{ display: "flex", gap: "10px", alignItems: "center" }}>
          <span className={`risk-badge ${risk}`}>● {riskLabel}</span>
          <button className="btn btn-ghost" onClick={() => navigate(`/agent/${type}`)}>
            ← New Scan
          </button>
        </div>
      </div>

      <div className="page-body">

        {/* SUMMARY */}
        <div className="section-title">📋 Summary</div>
        <div className="summary-box">
          <div className="summary-meta">
            <div className="meta-item">
              <div className="meta-key">Agent</div>
              <div className="meta-val">{config.title.replace(" Results", "")}</div>
            </div>
            <div className="meta-item">
              <div className="meta-key">File Analyzed</div>
              <div className="meta-val" style={{ fontFamily: "var(--mono)", fontSize: "0.8rem" }}>{fileName}</div>
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
            
            <div className="meta-item">
              <div className="meta-key">Risk Level</div>
              <div className="meta-val">
                <span className={`risk-badge ${risk}`}>● {riskLabel}</span>
              </div>
            </div>
            <div className="meta-item">
              <div className="meta-key">Timestamp</div>
              <div className="meta-val" style={{ fontFamily: "var(--mono)", fontSize: "0.8rem" }}>
                {new Date().toLocaleString()}
              </div>
            </div>
          </div>
        </div>

        {/* FINDINGS */}
        <div className="section-title">🔍 Findings</div>
        <div className="result-section">
          {data.length === 0
            ? <p className="result-empty">— no findings detected —</p>
            : data.map((item, i) => config.renderCard(item, i))
          }
        </div>

        {type === "log" && logMeta && (
          <>
            <div className="section-title">📈 Detection Metrics</div>
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
    <div className="section-title">🌐 Network Metrics</div>

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
      
        {/* TIMELINE */}
        <div className="section-title">⏱ Analysis Timeline</div>
        <div className="timeline" style={{ marginBottom: "32px" }}>
          {(type === "log" && logMeta?.timeline?.length ? logMeta.timeline : DUMMY_TIMELINE).map((t, i) => (
            <div key={i} className="timeline-item" style={{ animationDelay: `${i * 0.08}s` }}>
              <div className="timeline-time">{t.timestamp ? new Date(t.timestamp).toLocaleString() : t.time}</div>
              <div className="timeline-event">
                {t.type ? <><strong>{t.type}</strong> — {t.detail} {t.ip && `(${t.ip})`}</> : t.event}
              </div>
            </div>
          ))}
        </div>

        <div className="btn-group">
          <button className="btn btn-ghost" onClick={() => navigate("/dashboard")}>← Dashboard</button>
          <button className="btn btn-ghost" onClick={() => navigate("/history")}>View History</button>
          {type === "log" && (
  <>
    <button
      className="btn btn-success"
      onClick={() => downloadLogReport("json")}
    >
      JSON Report
    </button>

    <button
      className="btn btn-ghost"
      onClick={() => downloadLogReport("markdown")}
    >
      Markdown Report
    </button>

    <button
      className="btn btn-danger"
      onClick={() => downloadLogReport("pdf")}
    >
      PDF Report
    </button>
  </>
)}

{type === "network" && (
  <>
    <button
      className="btn btn-success"
      onClick={() => downloadNetworkReport("json")}
    >
      JSON Report
    </button>

    <button
      className="btn btn-ghost"
      onClick={() => downloadNetworkReport("markdown")}
    >
      Markdown Report
    </button>

    <button
      className="btn btn-danger"
      onClick={() => downloadNetworkReport("pdf")}
    >
      PDF Report
    </button>
  </>
)}
          <button className="btn btn-primary" onClick={() => navigate(`/agent/${type}`)}>Run New Scan</button>
        </div>
      </div>
    </>
  );
};

export default ResultPage;
