import { NavLink } from "react-router-dom";

import Icon from "./Icon.jsx";

const groups = [
  {
    label: "INVESTIGATION",
    items: [
      { label: "Dashboard", icon: "dashboard", to: "/", end: true },
      { label: "Cases", icon: "cases", to: "/cases" },
      { label: "Case Timeline", icon: "timeline", to: "/case-timeline" },
    ],
  },
  {
    label: "EVIDENCE",
    items: [
      { label: "Evidence Repository", icon: "evidence", to: "/evidence" },
      { label: "Evidence Integrity", icon: "integrity", to: "/evidence/integrity" },
      { label: "Chain of Custody", icon: "custody", to: "/evidence/chain-of-custody" },
    ],
  },
  {
    label: "ANALYSIS",
    items: [
      { label: "Digital Footprint", icon: "footprint", to: "/analysis/digital-footprint" },
      { label: "Log Analysis", icon: "logs", to: "/analysis/log-analysis" },
      { label: "Event Correlation", icon: "correlate", to: "/analysis/event-correlation" },
      { label: "Forensic Findings", icon: "findings", to: "/analysis/findings" },
    ],
  },
  {
    label: "MANAGEMENT",
    items: [
      { label: "Reports", icon: "reports", to: "/reports" },
      { label: "Investigators", icon: "investigators", to: "/investigators" },
      { label: "Audit Logs", icon: "audit", to: "/audit-logs" },
      { label: "Settings", icon: "settings", to: "/settings" },
    ],
  },
];

export default function DashboardSidebar({ mode }) {
  const modeLabels = {
    live: "CONNECTED DATA",
    loading: "LOADING SOURCE",
    unavailable: "API UNAVAILABLE",
    "not-implemented": "MODULE NOT IMPLEMENTED",
    demo: "DEMO WORKSPACE",
  };

  return (
    <aside className="sidebar">
      <NavLink className="brand" to="/" aria-label="CyberTrace dashboard">
        <span className="brand-mark"><Icon name="shield" size={20} /></span>
        <span className="brand-name">CYBER<span>TRACE</span></span>
      </NavLink>
      <div className={`mode-indicator mode-${mode}`}>
        <span />
        {modeLabels[mode] ?? modeLabels.loading}
      </div>
      <nav className="sidebar-nav" aria-label="Main navigation">
        {groups.map((group) => (
          <div className="nav-group" key={group.label}>
            <p className="nav-label">{group.label}</p>
            {group.items.map((item) => (
              <NavLink
                key={item.label}
                className={({ isActive }) => `nav-item${isActive ? " nav-item-active" : ""}`}
                to={item.to}
                end={item.end}
                title={item.label}
              >
                <Icon name={item.icon} size={16} />
                <span>{item.label}</span>
              </NavLink>
            ))}
          </div>
        ))}
      </nav>
      <div className="sidebar-footer">
        <span className="sidebar-status-dot" />
        <span>Workspace status</span>
        <strong>Secure</strong>
      </div>
    </aside>
  );
}
