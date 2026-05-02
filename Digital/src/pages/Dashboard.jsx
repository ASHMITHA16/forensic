import React from "react";
import { useNavigate } from "react-router-dom";

const agents = [
  { icon: "💾", title: "Disk Agent",    desc: "Analyze file system artifacts, recover deleted files, detect anomalies.",   path: "/agent/disk" },
  { icon: "📊", title: "Log Agent",     desc: "Parse system and application logs for suspicious events and intrusions.",     path: "/agent/log"  },
  { icon: "🧠", title: "Memory Agent",  desc: "Inspect memory dumps for malicious processes and injected code.",            path: "/agent/memory" },
  { icon: "🌐", title: "Network Agent", desc: "Identify anomalous traffic, port scans, and C2 communication attempts.",     path: "/agent/network" },
];

const stats = [
  { icon: "🔬", value: "142",  label: "Investigations", cls: "accent" },
  { icon: "⚠️", value: "23",   label: "High Risk",       cls: "danger" },
  { icon: "✅", value: "119",  label: "Resolved",        cls: "success" },
  { icon: "🕒", value: "9",    label: "Pending",         cls: "warn"   },
];

const Dashboard = () => {
  const navigate = useNavigate();

  return (
    <>
      <div className="page-header">
        <div>
          <div className="page-title">ForensiX</div>
          <div className="page-subtitle">ForensicOS · Digital Investigation Platform</div>
        </div>
      </div>

      <div className="page-body">
        <div className="welcome-banner">
          <div className="welcome-title">
            Welcome to <span>ForensicOS</span>
          </div>
          <p className="welcome-sub">
            Select an agent below to begin a new investigation, or review past cases in History.
          </p>
        </div>

        {/* STATS */}
        <div className="section-title">📡 Overview</div>
        <div className="stat-grid">
          {stats.map((s, i) => (
            <div key={i} className={`stat-card ${s.cls}`} style={{ animationDelay: `${i * 0.07}s` }}>
              <div className="stat-icon">{s.icon}</div>
              <div className="stat-value">{s.value}</div>
              <div className="stat-label">{s.label}</div>
            </div>
          ))}
        </div>

        {/* AGENTS */}
        <div className="section-title">🤖 Forensic Agents</div>
        <div className="agent-grid">
          {agents.map((a, i) => (
            <div
              key={i}
              className="agent-card"
              style={{ animationDelay: `${i * 0.08}s` }}
              onClick={() => navigate(a.path)}
            >
              <div className="agent-card-icon">{a.icon}</div>
              <div className="agent-card-title">{a.title}</div>
              <div className="agent-card-desc">{a.desc}</div>
            </div>
          ))}
        </div>
      </div>
    </>
  );
};

export default Dashboard;
