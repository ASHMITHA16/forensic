import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import axios from "axios";

const AGENT_ICONS = {
  disk: "💾",
  log: "📊",
  memory: "🧠",
  network: "🌐",
};

const riskLabel = {
  high: "HIGH",
  medium: "MEDIUM",
  low: "LOW",
  none: "CLEAN",
};

const History = () => {
  const navigate = useNavigate();

  const [history, setHistory] = useState([]);

  useEffect(() => {
    const fetchHistory = async () => {
      try {
        const res = await axios.get(
          "http://localhost:5000/api/history"
        );

        setHistory(res.data);
      } catch (err) {
        console.error(err);
      }
    };

    fetchHistory();
  }, []);

  const handleRowClick = (item) => {
    sessionStorage.setItem(
      `result_${item.agent}`,
      JSON.stringify(item.results)
    );

    sessionStorage.setItem(
      `result_${item.agent}_file`,
      item.fileName
    );

    navigate(`/result/${item.agent}`);
  };

  return (
    <>
      <div className="page-header">
        <div>
          <div className="page-title">🕒 // history</div>
          <div className="page-subtitle">
            Past investigations · Click any row to review results
          </div>
        </div>
      </div>

      <div className="page-body">
        <div
          className="stat-grid"
          style={{
            gridTemplateColumns: "repeat(4, 1fr)",
            marginBottom: "28px",
          }}
        >
          <div className="stat-card accent">
            <div className="stat-icon">📁</div>
            <div className="stat-value">{history.length}</div>
            <div className="stat-label">Total Cases</div>
          </div>

          <div className="stat-card danger">
            <div className="stat-icon">⚠️</div>
            <div className="stat-value">
              {history.filter((h) => h.risk === "high").length}
            </div>
            <div className="stat-label">High Risk</div>
          </div>

          <div className="stat-card warn">
            <div className="stat-icon">🔶</div>
            <div className="stat-value">
              {history.filter((h) => h.risk === "medium").length}
            </div>
            <div className="stat-label">Medium Risk</div>
          </div>

          <div className="stat-card success">
            <div className="stat-icon">✅</div>
            <div className="stat-value">
              {
                history.filter(
                  (h) => h.risk === "low" || h.risk === "none"
                ).length
              }
            </div>
            <div className="stat-label">Clear</div>
          </div>
        </div>

        <div className="section-title">
          📂 Investigation Log
        </div>

        <div
          className="summary-box"
          style={{
            padding: 0,
            overflow: "hidden",
          }}
        >
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
              {history.map((item, i) => (
                <tr
                  key={item._id}
                  onClick={() => handleRowClick(item)}
                  style={{
                    animationDelay: `${i * 0.04}s`,
                    cursor: "pointer",
                  }}
                >
                  <td
                    style={{
                      fontFamily: "var(--mono)",
                      fontSize: "0.7rem",
                      color: "var(--text-muted)",
                    }}
                  >
                    {String(i + 1).padStart(3, "0")}
                  </td>

                  <td>
                    <span className="agent-tag">
                      {AGENT_ICONS[item.agent]}{" "}
                      {item.agent.toUpperCase()}
                    </span>
                  </td>

                  <td
                    style={{
                      fontFamily: "var(--mono)",
                      fontSize: "0.78rem",
                    }}
                  >
                    {item.fileName}
                  </td>

                  <td
                    style={{
                      fontFamily: "var(--mono)",
                      fontSize: "0.75rem",
                      color: "var(--text-muted)",
                    }}
                  >
                    {new Date(
                      item.createdAt
                    ).toLocaleString()}
                  </td>

                  <td
                    style={{
                      fontFamily: "var(--mono)",
                      fontSize: "0.82rem",
                    }}
                  >
                    {item.findings}
                  </td>

                  <td>
                    <span
                      className={`risk-badge ${item.risk}`}
                    >
                      ● {riskLabel[item.risk]}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          {history.length === 0 && (
            <div
              style={{
                padding: "30px",
                textAlign: "center",
              }}
            >
              No investigations found.
            </div>
          )}
        </div>
      </div>
    </>
  );
};

export default History;