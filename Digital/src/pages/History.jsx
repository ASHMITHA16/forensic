import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import axios from "axios";
import Icon from "../components/Icon";
import PageHeader from "../components/PageHeader";

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
    // Correlation runs have their own page, which loads the saved envelope by id
    if (item.agent === "correlation") {
      navigate("/agent/correlation", { state: { analysisId: item._id } });
      return;
    }

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

  const stats = [
    { icon: "file",  cls: "accent",  label: "Total cases",      value: history.length },
    { icon: "alert", cls: "danger",  label: "High risk",        value: history.filter((h) => h.risk === "high").length },
    { icon: "alert", cls: "warn",    label: "Medium risk",      value: history.filter((h) => h.risk === "medium").length },
    { icon: "check", cls: "success", label: "Low risk / clean", value: history.filter((h) => h.risk === "low" || h.risk === "none").length },
  ];

  return (
    <>
      <PageHeader
        icon="history"
        eyebrow="Records"
        title="Investigation history"
        subtitle="Every completed analysis. Select a row to reopen its results."
      />

      <div className="page-body">
        <div className="stat-grid">
          {stats.map((s) => (
            <div key={s.label} className={`stat-card ${s.cls}`}>
              <div className="stat-top">
                <div className="stat-icon"><Icon name={s.icon} size={16} /></div>
              </div>
              <div className="stat-value">{s.value}</div>
              <div className="stat-label">{s.label}</div>
            </div>
          ))}
        </div>

        <h2 className="section-title">
          Investigation log <span className="section-count">{history.length}</span>
        </h2>

        {history.length === 0 ? (
          <div className="empty-state">
            No investigations yet. Run one of the agents to see it here.
          </div>
        ) : (
          <div className="summary-box flush">
            <div className="table-wrap">
              <table className="history-table clickable">
                <thead>
                  <tr>
                    <th>#</th>
                    <th>Agent</th>
                    <th>File</th>
                    <th>Date / time</th>
                    <th>Findings</th>
                    <th>Risk</th>
                  </tr>
                </thead>

                <tbody>
                  {history.map((item, i) => (
                    <tr
                      key={item._id}
                      tabIndex={0}
                      onClick={() => handleRowClick(item)}
                      onKeyDown={(e) => e.key === "Enter" && handleRowClick(item)}
                    >
                      <td className="cell-mono cell-muted">
                        {String(i + 1).padStart(3, "0")}
                      </td>

                      <td>
                        <span className="agent-tag">
                          <Icon name={item.agent} size={13} />
                          {item.agent}
                        </span>
                      </td>

                      <td className="cell-mono cell-file" title={item.fileName}>
                        {item.fileName}
                      </td>

                      <td className="cell-mono cell-muted">
                        {new Date(item.createdAt).toLocaleString()}
                      </td>

                      <td className="cell-mono">{item.findings}</td>

                      <td>
                        <span className={`risk-badge ${item.risk}`}>
                          {riskLabel[item.risk] || item.risk}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </>
  );
};

export default History;
