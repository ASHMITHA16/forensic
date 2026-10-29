import React from "react";
import { NavLink, useLocation } from "react-router-dom";
import Icon from "./Icon";

const navSections = [
  { items: [{ label: "Dashboard", path: "/dashboard", icon: "dashboard" }] },
  {
    label: "Agents",
    items: [
      { label: "Disk Agent",        path: "/agent/disk",        icon: "disk" },
      { label: "Log Agent",         path: "/agent/log",         icon: "log" },
      { label: "Memory Agent",      path: "/agent/memory",      icon: "memory" },
      { label: "Network Agent",     path: "/agent/network",     icon: "network" },
      { label: "Correlation Agent", path: "/agent/correlation", icon: "correlation" },
    ],
  },
  { label: "Records", items: [{ label: "History", path: "/history", icon: "history" }] },
];

const Sidebar = () => {
  const { pathname } = useLocation();

  // A result page belongs to its agent, so keep that agent highlighted
  const isActive = (path) =>
    pathname === path ||
    (path.startsWith("/agent/") && pathname === path.replace("/agent/", "/result/"));

  return (
    <aside className="sidebar">
      <div className="sidebar-logo">
        <div className="logo-mark"><Icon name="shield" size={18} /></div>
        <div>
          <div className="logo-title">ForensicOS</div>
          <div className="logo-sub">Digital Investigation Platform</div>
        </div>
      </div>

      <nav className="sidebar-nav" aria-label="Main">
        {navSections.map((section, i) => (
          <React.Fragment key={i}>
            {section.label && <div className="sidebar-section-label">{section.label}</div>}
            {section.items.map((item) => (
              <NavLink
                key={item.path}
                to={item.path}
                className={() => `nav-item ${isActive(item.path) ? "active" : ""}`}
              >
                <Icon name={item.icon} />
                {item.label}
              </NavLink>
            ))}
          </React.Fragment>
        ))}
      </nav>

      <div className="sidebar-footer">
        <div className="sidebar-status">
          <div className="status-dot" />
          System online · v2.4.1
        </div>
      </div>
    </aside>
  );
};

export default Sidebar;
