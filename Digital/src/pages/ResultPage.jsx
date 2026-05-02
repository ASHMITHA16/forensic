import React, { useEffect, useState } from "react";
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
      <div key={i} className="forensic-card" style={{ animationDelay: `${i * 0.05}s` }}>
        <p><strong>Type:</strong> {item.type}</p>
        <p><strong>IP:</strong> {item.ip}</p>
        <p><strong>Details:</strong> {item.line}</p>
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

function deriveRisk(data) {
  if (!data || data.length === 0) return "none";
  const hasCritical = data.some(d =>
    d.deleted || d.type === "Suspicious Process" ||
    (d.type && d.type.toLowerCase().includes("brute")) ||
    (d.type && d.type.toLowerCase().includes("malware"))
  );
  if (hasCritical) return "high";
  if (data.length > 5) return "medium";
  return "low";
}

const ResultPage = ({ type }) => {
  const config = RESULT_CONFIG[type];
  const navigate = useNavigate();
  const [data, setData] = useState([]);
  const [fileName, setFileName] = useState("unknown");

  useEffect(() => {
    const raw = sessionStorage.getItem(`result_${type}`);
    const name = sessionStorage.getItem(`result_${type}_file`);
    if (raw) setData(JSON.parse(raw));
    if (name) setFileName(name);
  }, [type]);

  const risk = deriveRisk(data);
  const riskLabel = { high: "HIGH RISK", medium: "MEDIUM RISK", low: "LOW RISK", none: "CLEAN" }[risk];

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

        {/* TIMELINE */}
        <div className="section-title">⏱ Analysis Timeline</div>
        <div className="timeline" style={{ marginBottom: "32px" }}>
          {DUMMY_TIMELINE.map((t, i) => (
            <div key={i} className="timeline-item" style={{ animationDelay: `${i * 0.08}s` }}>
              <div className="timeline-time">{t.time}</div>
              <div className="timeline-event">{t.event}</div>
            </div>
          ))}
        </div>

        <div className="btn-group">
          <button className="btn btn-ghost" onClick={() => navigate("/dashboard")}>← Dashboard</button>
          <button className="btn btn-ghost" onClick={() => navigate("/history")}>View History</button>
          <button className="btn btn-primary" onClick={() => navigate(`/agent/${type}`)}>Run New Scan</button>
        </div>
      </div>
    </>
  );
};

export default ResultPage;
