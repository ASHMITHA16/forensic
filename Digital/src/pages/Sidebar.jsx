import React from "react";
import { useNavigate, useLocation } from "react-router-dom";

const navItems = [
  { label: "Dashboard",   path: "/dashboard",     icon: "⬡" },
  { divider: true, label: "AGENTS" },
  { label: "Disk Agent",    path: "/agent/disk",    icon: "💾" },
  { label: "Log Agent",     path: "/agent/log",     icon: "📊" },
  { label: "Memory Agent",  path: "/agent/memory",  icon: "🧠" },
  { label: "Network Agent", path: "/agent/network", icon: "🌐" },
  { divider: true, label: "RECORDS" },
  { label: "History",     path: "/history",       icon: "🕒", badge: "9" },
];

const Sidebar = () => {
  const navigate = useNavigate();
  const { pathname } = useLocation();

  return (
    <aside className="sidebar">
      <div className="sidebar-logo">
        <div className="logo-mark">// SYS_FORENSIC</div>
        <div className="logo-title">ForensicOS</div>
        <div className="logo-sub">Digital Investigation Platform</div>
      </div>

      <nav className="sidebar-nav">
        {navItems.map((item, i) => {
          if (item.divider) {
            return (
              <React.Fragment key={i}>
                <div className="sidebar-divider" />
                <div className="sidebar-section-label">{item.label}</div>
              </React.Fragment>
            );
          }
          const isActive = pathname === item.path ||
            (item.path !== "/dashboard" && pathname.startsWith(item.path.replace("/agent/", "/result/")));

          return (
            <div
              key={item.path}
              className={`nav-item ${isActive ? "active" : ""}`}
              onClick={() => navigate(item.path)}
            >
              <span className="nav-icon">{item.icon}</span>
              {item.label}
              {item.badge && <span className="nav-badge">{item.badge}</span>}
            </div>
          );
        })}
      </nav>

      <div className="sidebar-footer">
        <div className="sidebar-status">
          <div className="status-dot" />
          SYSTEM ONLINE — v2.4.1
        </div>
      </div>
    </aside>
  );
};

export default Sidebar;
