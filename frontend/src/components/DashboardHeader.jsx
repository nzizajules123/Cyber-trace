import { useEffect, useRef, useState } from "react";
import { Link, useNavigate } from "react-router-dom";

import Icon from "./Icon.jsx";
import { useAuth } from "../context/AuthContext.jsx";

function getInitials(name = "") {
  return name
    .trim()
    .split(/\s+/)
    .slice(0, 2)
    .map((part) => part[0]?.toUpperCase() ?? "")
    .join("") || "ID";
}

export default function DashboardHeader({
  currentUser,
  cases,
  selectedCaseId,
  onSelectCase,
  query,
  onQueryChange,
  notifications = [],
  pageTitle = "Dashboard",
  showSearch = true,
}) {
  const { user, organization, role: authRole, logout } = useAuth();
  const navigate = useNavigate();
  const [profileOpen, setProfileOpen] = useState(false);
  const [notificationsOpen, setNotificationsOpen] = useState(false);
  const menusRef = useRef(null);
  const displayName = user?.fullName || currentUser?.displayName || "Identity unavailable";
  const formattedRole = authRole
    ? authRole.toLowerCase().replaceAll("_", " ").replace(/\b\w/g, (c) => c.toUpperCase())
    : currentUser?.role || "No authenticated session";
  const orgName = organization?.name || currentUser?.organizationName || "";

  const handleLogout = async () => {
    setProfileOpen(false);
    await logout();
    navigate("/login", { replace: true });
  };

  useEffect(() => {
    if (!profileOpen && !notificationsOpen) return undefined;

    const handlePointerDown = (event) => {
      if (menusRef.current && !menusRef.current.contains(event.target)) {
        setProfileOpen(false);
        setNotificationsOpen(false);
      }
    };
    const handleKeyDown = (event) => {
      if (event.key === "Escape") {
        setProfileOpen(false);
        setNotificationsOpen(false);
      }
    };

    document.addEventListener("mousedown", handlePointerDown);
    window.addEventListener("keydown", handleKeyDown);
    return () => {
      document.removeEventListener("mousedown", handlePointerDown);
      window.removeEventListener("keydown", handleKeyDown);
    };
  }, [profileOpen, notificationsOpen]);

  return (
    <header className="topbar">
      <div className="breadcrumb">
        <span>Investigation workspace</span>
        <Icon name="chevron" size={14} />
        <strong>{pageTitle}</strong>
      </div>
      <div className="topbar-actions">
        {showSearch && <label className="search-box">
          <Icon name="search" size={16} />
          <input
            type="search"
            value={query}
            onChange={(event) => onQueryChange(event.target.value)}
            placeholder={pageTitle === "Cases" ? "Search cases" : "Search cases and events"}
            aria-label={pageTitle === "Cases" ? "Search cases" : "Search cases and events"}
          />
        </label>}
        <label className="case-selector">
          <span>Current case</span>
          <select
            aria-label="Current investigation"
            value={selectedCaseId}
            onChange={(event) => onSelectCase(event.target.value)}
            disabled={cases.length === 0}
          >
            <option value="">{cases.length ? "Select a case" : "No cases available"}</option>
            {cases.length === 0 ? (
              null
            ) : cases.map((item) => (
              <option value={item.caseNumber ?? item.id} key={item.caseNumber ?? item.id}>
                {item.caseNumber ?? item.id}
              </option>
            ))}
          </select>
        </label>
        <div className="header-menus" ref={menusRef} style={{ display: "flex", alignItems: "center", gap: "10px" }}>
        <div className="header-menu-wrap">
          <button
            className="icon-button notification-button"
            aria-label={`Notifications${notifications.length ? `, ${notifications.length} unread` : ""}`}
            aria-expanded={notificationsOpen}
            onClick={() => {
              setNotificationsOpen((open) => !open);
              setProfileOpen(false);
            }}
          >
            <Icon name="bell" size={18} />
            {notifications.length > 0 && <span className="notification-dot" />}
          </button>
          {notificationsOpen && (
            <div className="header-popover notification-popover">
              <strong>Notifications</strong>
              {notifications.length === 0 ? (
                <p>No notifications were returned for this workspace.</p>
              ) : notifications.map((item) => <p key={item.id}>{item.message}</p>)}
            </div>
          )}
        </div>
        <div className="header-menu-wrap">
          <button
            className="profile-button"
            aria-expanded={profileOpen}
            onClick={() => {
              setProfileOpen((open) => !open);
              setNotificationsOpen(false);
            }}
          >
            <span className="avatar">{getInitials(displayName)}</span>
            <span className="profile-copy">
              <strong>{displayName}</strong>
              <small>{formattedRole}</small>
            </span>
            <Icon name="down" size={14} />
          </button>
          {profileOpen && (
            <div className="header-popover profile-popover">
              <strong>{displayName}</strong>
              <p>{formattedRole}{orgName ? ` · ${orgName}` : ""}</p>
              <div style={{ display: "flex", gap: "8px", marginTop: "8px" }}>
                <Link className="secondary-button" to="/settings" onClick={() => setProfileOpen(false)}>Settings</Link>
                {user && (
                  <button className="danger-button" type="button" onClick={handleLogout}>Sign out</button>
                )}
              </div>
            </div>
          )}
        </div>
        </div>
      </div>
    </header>
  );
}
