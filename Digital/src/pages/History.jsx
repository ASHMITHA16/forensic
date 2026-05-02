import React from "react";
import { useNavigate } from "react-router-dom";

const HISTORY = [
  { id: 1, agent: "disk",    file: "evidence_drive.img",    date: "2025-07-12 14:32",  risk: "high",   findings: 14 },
  { id: 2, agent: "log",     file: "apache_access.log",     date: "2025-07-11 09:17",  risk: "medium", findings: 7  },
  { id: 3, agent: "network", file: "capture_session.pcap",  date: "2025-07-10 22:05",  risk: "high",   findings: 21 },
  { id: 4, agent: "memory",  file: "memdump_01.raw",        date: "2025-07-09 16:44",  risk: "low",    findings: 3  },
  { id: 5, agent: "log",     file: "syslog_july8.log",      date: "2025-07-08 11:20",  risk: "none",   findings: 0  },
  { id: 6, agent: "disk",    file: "usb_forensic.dd",       date: "2025-07-07 08:50",  risk: "medium", findings: 5  },
  { id: 7, agent: "network", file: "wan_traffic.pcap",      date: "2025-07-06 19:33",  risk: "low",    findings: 2  },
  { id: 8, agent: "memory",  file: "process_dump.raw",      date: "2025-07-05 13:15",  risk: "high",   findings: 9  },
  { id: 9, agent: "log",     file: "auth.log",              date: "2025-07-04 07:02",  risk: "medium", findings: 6  },
];

const AGENT_ICONS = { disk: "💾", log: "📊", memory: "🧠", network: "🌐" };

const riskLabel = {
  high:   "HIGH",
  medium: "MEDIUM",
  low:    "LOW",
  none:   "CLEAN",
};

const History = () => {
  const navigate = useNavigate();

  const handleRowClick = (item) => {
    // Load a placeholder so result page shows something
    const placeholder = Array.from({ length: item.findings }, (_, i) => ({
      type: "Historical Finding",
      ip: `10.0.0.${i + 1}`,
      line: `Entry from archived investigation #${item.id}`,
      process: `proc_${i}`,
      name: `file_artifact_${i}.bin`,
    }));
    sessionStorage.setItem(`result_${item.agent}`, JSON.stringify(placeholder));
    sessionStorage.setItem(`result_${item.agent}_file`, item.file);
    navigate(`/result/${item.agent}`);
  };

  return (
    <>
      <div className="page-header">
        <div>
          <div className="page-title">🕒 // history</div>
          <div className="page-subtitle">Past investigations · Click any row to review results</div>
        </div>
      </div>

      <div className="page-body">
        <div className="stat-grid" style={{ gridTemplateColumns: "repeat(4, 1fr)", marginBottom: "28px" }}>
          <div className="stat-card accent">
            <div className="stat-icon">📁</div>
            <div className="stat-value">{HISTORY.length}</div>
            <div className="stat-label">Total Cases</div>
          </div>
          <div className="stat-card danger">
            <div className="stat-icon">⚠️</div>
            <div className="stat-value">{HISTORY.filter(h => h.risk === "high").length}</div>
            <div className="stat-label">High Risk</div>
          </div>
          <div className="stat-card warn">
            <div className="stat-icon">🔶</div>
            <div className="stat-value">{HISTORY.filter(h => h.risk === "medium").length}</div>
            <div className="stat-label">Medium Risk</div>
          </div>
          <div className="stat-card success">
            <div className="stat-icon">✅</div>
            <div className="stat-value">{HISTORY.filter(h => h.risk === "none" || h.risk === "low").length}</div>
            <div className="stat-label">Clear</div>
          </div>
        </div>

        <div className="section-title">📂 Investigation Log</div>

        <div className="summary-box" style={{ padding: 0, overflow: "hidden" }}>
          <table className="history-table">
            <thead>
              <tr>
                <th>#</th>
                <th>Agent</th>
                <th>File</th>
                <th>Date / Time</th>
                <th>Findings</th>
                <th>Risk</th>
              </tr>
            </thead>
            <tbody>
              {HISTORY.map((item, i) => (
                <tr key={item.id} onClick={() => handleRowClick(item)}
                    style={{ animationDelay: `${i * 0.04}s` }}>
                  <td style={{ fontFamily: "var(--mono)", fontSize: "0.7rem", color: "var(--text-muted)" }}>
                    {String(item.id).padStart(3, "0")}
                  </td>
                  <td>
                    <span className="agent-tag">
                      {AGENT_ICONS[item.agent]} {item.agent.toUpperCase()}
                    </span>
                  </td>
                  <td style={{ fontFamily: "var(--mono)", fontSize: "0.78rem" }}>{item.file}</td>
                  <td style={{ fontFamily: "var(--mono)", fontSize: "0.75rem", color: "var(--text-muted)" }}>
                    {item.date}
                  </td>
                  <td style={{ fontFamily: "var(--mono)", fontSize: "0.82rem" }}>
                    {item.findings}
                  </td>
                  <td>
                    <span className={`risk-badge ${item.risk}`}>
                      ● {riskLabel[item.risk]}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </>
  );
};

export default History;
