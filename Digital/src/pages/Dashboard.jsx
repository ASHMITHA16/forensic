import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import axios from "axios";
import Icon from "../components/Icon";
import PageHeader from "../components/PageHeader";

const agents = [
  { icon: "disk",        title: "Disk Agent",        desc: "Analyze file system artifacts, recover deleted files, detect anomalies.",   path: "/agent/disk" },
  { icon: "log",         title: "Log Agent",         desc: "Parse system and application logs for suspicious events and intrusions.",   path: "/agent/log"  },
  { icon: "memory",      title: "Memory Agent",      desc: "Inspect memory dumps for malicious processes and injected code.",          path: "/agent/memory" },
  { icon: "network",     title: "Network Agent",     desc: "Identify anomalous traffic, port scans, and C2 communication attempts.",   path: "/agent/network" },
  { icon: "correlation", title: "Correlation Agent", desc: "Link findings across all four agents into an evidence-cited attack chain.", path: "/agent/correlation" },
];

const Dashboard = () => {
  const navigate = useNavigate();
  const [history, setHistory] = useState(null);

  useEffect(() => {
    axios.get("http://localhost:5000/api/history")
      .then((res) => setHistory(Array.isArray(res.data) ? res.data : []))
      .catch((err) => {
        console.error(err);
        setHistory([]);
      });
  }, []);

  const count = (fn) => (history ? history.filter(fn).length : "–");

  const stats = [
    { icon: "file",    value: history ? history.length : "–",                            label: "Investigations", cls: "accent" },
    { icon: "alert",   value: count((h) => h.risk === "high"),                           label: "High risk",      cls: "danger" },
    { icon: "alert",   value: count((h) => h.risk === "medium"),                         label: "Medium risk",    cls: "warn" },
    { icon: "check",   value: count((h) => h.risk === "low" || h.risk === "none"),       label: "Low risk / clean", cls: "success" },
  ];

  return (
    <>
      <PageHeader eyebrow="Overview" title="Dashboard" subtitle="Start a new investigation or review past cases." />

      <div className="page-body">
        <div className="welcome-banner">
          <div>
            <div className="welcome-title">Welcome to ForensicOS</div>
            <p className="welcome-sub">
              Upload evidence to one of the analysis agents, then combine their results with the
              Correlation Agent to build an evidence-cited attack chain.
            </p>
          </div>
          <div className="btn-group">
            <button className="btn btn-ghost" onClick={() => navigate("/history")}>
              <Icon name="history" size={16} /> View history
            </button>
            <button className="btn btn-primary" onClick={() => navigate("/agent/correlation")}>
              <Icon name="correlation" size={16} /> Correlate findings
            </button>
          </div>
        </div>

        <h2 className="section-title">Case overview</h2>
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

        <h2 className="section-title">Forensic agents</h2>
        <div className="agent-grid">
          {agents.map((a) => (
            <button key={a.path} type="button" className="agent-card" onClick={() => navigate(a.path)}>
              <div className="agent-card-icon"><Icon name={a.icon} size={20} /></div>
              <div className="agent-card-title">{a.title}</div>
              <div className="agent-card-desc">{a.desc}</div>
              <span className="agent-card-cta">Open agent <Icon name="arrowRight" size={14} /></span>
            </button>
          ))}
        </div>
      </div>
    </>
  );
};

export default Dashboard;
