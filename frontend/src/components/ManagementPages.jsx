import { useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";

import { formatDate, formatLabel } from "./CaseFormFields.jsx";
import Icon from "./Icon.jsx";
import WorkspaceLayout from "./WorkspaceLayout.jsx";
import { useAuth } from "../context/AuthContext.jsx";
import { getCases } from "../services/casesApi.js";
import {
  addInvestigator,
  analyzeEvidence,
  downloadEvidence,
  enableMfa,
  getCurrentOrganization,
  getEventCorrelations,
  getEvidenceDetail,
  getInvestigators,
  getSystemAuditLogs,
  setupMfa,
  updateCurrentOrganization,
  updateInvestigator,
  updateMyProfile,
  verifyEvidence,
} from "../services/forensicsApi.js";

const ROLES = [
  "SYSTEM_ADMIN",
  "ORG_ADMIN",
  "LEAD_INVESTIGATOR",
  "INVESTIGATOR",
  "EVIDENCE_ANALYST",
  "READ_ONLY_AUDITOR",
];

export function EventCorrelationPage() {
  const navigate = useNavigate();
  const [cases, setCases] = useState([]);
  const [caseFilter, setCaseFilter] = useState("");
  const [correlations, setCorrelations] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setError("");
    Promise.all([
      getCases({ page: 1, size: 100, signal: controller.signal }),
      getEventCorrelations({ caseId: caseFilter, signal: controller.signal }),
    ])
      .then(([casesRes, corrRes]) => {
        setCases(casesRes.items);
        setCorrelations(corrRes.items || []);
      })
      .catch((cause) => {
        if (!controller.signal.aborted) setError(cause instanceof Error ? cause.message : "Failed to load correlations.");
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, [caseFilter]);

  return (
    <WorkspaceLayout
      mode={loading ? "loading" : error ? "unavailable" : "live"}
      cases={cases}
      pageTitle="Event Correlation"
      showSearch={false}
      onSelectCase={(c) => c && navigate(`/cases/${encodeURIComponent(c)}`)}
    >
      <div className="page-heading">
        <div>
          <span className="eyebrow"><span className="eyebrow-dot" /> CROSS-ARTIFACT CORRELATION</span>
          <h1>Event Correlation</h1>
          <p>Compares recorded events across timestamps, source IPs, accounts, and evidence items with explicit reasoning.</p>
        </div>
        <label className="filter-control">
          <select value={caseFilter} onChange={(e) => setCaseFilter(e.target.value)} aria-label="Filter by case">
            <option value="">All cases</option>
            {cases.map((c) => <option key={c.caseNumber} value={c.caseNumber}>{c.caseNumber}</option>)}
          </select>
        </label>
      </div>

      {error && <div className="dashboard-error" role="alert"><Icon name="findings" size={18} /><div><strong>Error</strong><p>{error}</p></div></div>}

      {loading ? (
        <div className="case-loading">Correlating recorded forensic events…</div>
      ) : correlations.length === 0 ? (
        <section className="panel case-empty">
          <strong>No event correlations detected yet</strong>
          <p>Ingest and analyze log files in Log Analysis to correlate shared IPs, accounts, and temporal bursts.</p>
          <Link className="secondary-button" to="/analysis/log-analysis">Open Log Analysis</Link>
        </section>
      ) : (
        <div className="findings-stack">
          {correlations.map((item) => (
            <article className="panel finding-card" key={item.id}>
              <div className="finding-card-header">
                <div>
                  <div className="finding-badges">
                    <span className="event-type">{formatLabel(item.correlationType)}</span>
                    <span className="analysis-status">Confidence: {formatLabel(item.confidence)}</span>
                    <span className="forensic-submeta">{item.eventCount} linked events</span>
                  </div>
                  <h3>{item.key}</h3>
                </div>
                <div className="forensic-submeta">
                  {formatDate(item.firstSeenAt, true)} → {formatDate(item.lastSeenAt, true)}
                </div>
              </div>
              <p className="finding-summary">{item.explanation}</p>
              <div className="ioc-chip-grid">
                {item.caseNumbers?.map((c) => (
                  <Link className="ioc-chip" key={c} to={`/cases/${encodeURIComponent(c)}`}>
                    <small>Case</small><code>{c}</code>
                  </Link>
                ))}
                {item.evidenceCodes?.map((ev) => (
                  <Link className="ioc-chip" key={ev} to={`/evidence/${encodeURIComponent(ev)}`}>
                    <small>Evidence</small><code>{ev}</code>
                  </Link>
                ))}
              </div>
            </article>
          ))}
        </div>
      )}
    </WorkspaceLayout>
  );
}

export function EvidenceDetailPage() {
  const { evidenceCode = "" } = useParams();
  const [item, setItem] = useState(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setError("");
    getEvidenceDetail(evidenceCode, { signal: controller.signal })
      .then(setItem)
      .catch((cause) => {
        if (!controller.signal.aborted) setError(cause instanceof Error ? cause.message : "Evidence not found.");
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, [evidenceCode, reloadKey]);

  const handleVerify = async () => {
    setBusy(true);
    try {
      const res = await verifyEvidence(item.evidenceCode);
      setNotice(res.sha256Matches ? "SHA-256 verified against vault file (MATCH)." : "WARNING: SHA-256 MISMATCH!");
      setReloadKey((k) => k + 1);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Verification failed.");
    } finally {
      setBusy(false);
    }
  };

  const handleAnalyze = async () => {
    setBusy(true);
    try {
      const res = await analyzeEvidence(item.evidenceCode);
      setNotice(`Parsed ${res.eventsParsed} events, ${res.uniqueIocs} IOCs, ${res.findingsGenerated} findings.`);
      setReloadKey((k) => k + 1);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Analysis failed.");
    } finally {
      setBusy(false);
    }
  };

  const handleDownload = async () => {
    setBusy(true);
    try {
      await downloadEvidence(item.evidenceCode, item.originalFilename);
      setNotice("Secure audited download initiated (custody EXPORTED event recorded).");
      setReloadKey((k) => k + 1);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Download failed.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <WorkspaceLayout mode={loading ? "loading" : error ? "unavailable" : "live"} pageTitle="Evidence Details" showSearch={false}>
      <div className="page-heading">
        <div>
          <span className="eyebrow"><span className="eyebrow-dot" /> EVIDENCE ARTIFACT</span>
          <h1>{item ? item.originalFilename : "Evidence details"}</h1>
          <p>{item ? `${item.evidenceCode} · Case ${item.caseNumber}` : "Inspect hashes, verifications, and custody chain."}</p>
        </div>
        {item && (
          <div className="case-detail-header-actions">
            <button className="primary-button" type="button" onClick={handleVerify} disabled={busy}>Verify SHA-256</button>
            <button className="secondary-button" type="button" onClick={handleAnalyze} disabled={busy}>Analyze Log</button>
            <button className="secondary-button" type="button" onClick={handleDownload} disabled={busy}>Secure Download</button>
          </div>
        )}
      </div>

      {notice && <div className="case-success-notice" role="status">{notice}</div>}
      {error && <div className="dashboard-error" role="alert"><Icon name="findings" size={18} /><div><strong>Error</strong><p>{error}</p></div></div>}

      {loading ? (
        <div className="case-loading">Loading evidence artifact…</div>
      ) : item && (
        <div className="case-detail-grid">
          <section className="panel case-detail-panel">
            <h2>Cryptographic &amp; Acquisition Metadata</h2>
            <dl className="case-detail-list">
              <div><dt>Evidence ID</dt><dd>{item.evidenceCode}</dd></div>
              <div><dt>Case</dt><dd><Link className="case-id case-title-link" to={`/cases/${encodeURIComponent(item.caseNumber)}`}>{item.caseNumber}</Link></dd></div>
              <div><dt>Type</dt><dd>{formatLabel(item.evidenceType)}</dd></div>
              <div><dt>MIME / Size</dt><dd>{item.mimeType} ({item.fileSize} bytes)</dd></div>
              <div><dt>Collected by</dt><dd>{item.collectedBy || "—"}</dd></div>
              <div><dt>Source</dt><dd>{item.acquisitionSource || "—"}</dd></div>
              <div><dt>Custody Chain</dt><dd>{item.custodyChainValid ? "INTACT" : "BROKEN"}</dd></div>
              <div className="case-description"><dt>SHA-256</dt><dd><code className="mono-hash">{item.sha256}</code></dd></div>
              <div className="case-description"><dt>SHA-512</dt><dd><code className="mono-hash">{item.sha512}</code></dd></div>
              <div className="case-description"><dt>MD5</dt><dd><code className="mono-hash">{item.md5}</code></dd></div>
            </dl>
          </section>

          <section className="panel case-detail-panel">
            <h2>Verification History ({item.verifications?.length || 0})</h2>
            <ol className="case-audit-timeline">
              {(item.verifications || []).map((v) => (
                <li key={v.id}>
                  <span className="case-audit-marker" />
                  <div>
                    <strong>{v.sha256Matches ? "SHA-256 MATCH" : "SHA-256 MISMATCH"}</strong>
                    <p>Verified by: {v.verifiedBy}</p>
                    {v.notes && <p className="forensic-submeta">{v.notes}</p>}
                    <time dateTime={v.verifiedAt}>{formatDate(v.verifiedAt, true)}</time>
                  </div>
                </li>
              ))}
            </ol>
          </section>

          <section className="panel case-detail-panel case-audit-panel">
            <h2>Chain of Custody ({item.custodyEvents?.length || 0})</h2>
            <ol className="case-audit-timeline">
              {(item.custodyEvents || []).map((ev) => (
                <li key={ev.id}>
                  <span className="case-audit-marker" />
                  <div>
                    <strong>{formatLabel(ev.action)}</strong>
                    <p>Actor: {ev.actor} {ev.location ? `· ${ev.location}` : ""}</p>
                    {ev.notes && <p className="forensic-submeta">{ev.notes}</p>}
                    <div className="forensic-submeta">Hash: <code>{ev.entryHash.slice(0, 24)}…</code></div>
                    <time dateTime={ev.occurredAt}>{formatDate(ev.occurredAt, true)}</time>
                  </div>
                </li>
              ))}
            </ol>
          </section>
        </div>
      )}
    </WorkspaceLayout>
  );
}

export function InvestigatorsPage() {
  const { role, refreshAuth } = useAuth();
  const isAdmin = role === "SYSTEM_ADMIN" || role === "ORG_ADMIN";

  const [org, setOrg] = useState(null);
  const [members, setMembers] = useState([]);
  const [orgName, setOrgName] = useState("");
  const [orgDesc, setOrgDesc] = useState("");
  const [allowReg, setAllowReg] = useState(true);

  const [newEmail, setNewEmail] = useState("");
  const [newName, setNewName] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [newRole, setNewRole] = useState("INVESTIGATOR");

  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setError("");
    Promise.all([
      getCurrentOrganization({ signal: controller.signal }),
      getInvestigators({ signal: controller.signal }),
    ])
      .then(([orgRes, invRes]) => {
        setOrg(orgRes);
        setOrgName(orgRes.name);
        setOrgDesc(orgRes.description ?? "");
        setAllowReg(Boolean(orgRes.allowRegistration));
        setMembers(invRes);
      })
      .catch((cause) => {
        if (!controller.signal.aborted) setError(cause instanceof Error ? cause.message : "Failed to load organization.");
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, [reloadKey]);

  const handleSaveOrg = async (e) => {
    e.preventDefault();
    setSaving(true);
    setError("");
    try {
      await updateCurrentOrganization({ name: orgName, description: orgDesc || null, allowRegistration: allowReg });
      setNotice("Organization profile updated.");
      await refreshAuth();
      setReloadKey((k) => k + 1);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Update failed.");
    } finally {
      setSaving(false);
    }
  };

  const handleAddMember = async (e) => {
    e.preventDefault();
    setSaving(true);
    setError("");
    try {
      await addInvestigator({ email: newEmail, fullName: newName, password: newPassword, role: newRole });
      setNotice(`Added investigator ${newEmail} (${formatLabel(newRole)}).`);
      setNewEmail("");
      setNewName("");
      setNewPassword("");
      setReloadKey((k) => k + 1);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not add investigator.");
    } finally {
      setSaving(false);
    }
  };

  const handleRoleChange = async (membershipId, nextRole) => {
    try {
      await updateInvestigator(membershipId, { role: nextRole });
      setNotice("Investigator role updated.");
      setReloadKey((k) => k + 1);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Role update failed.");
    }
  };

  const handleToggleActive = async (member) => {
    try {
      await updateInvestigator(member.membershipId, { isActive: !member.isActive });
      setNotice(`${member.email} ${member.isActive ? "deactivated" : "activated"}.`);
      setReloadKey((k) => k + 1);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Status update failed.");
    }
  };

  return (
    <WorkspaceLayout mode={loading ? "loading" : "live"} pageTitle="Investigators & Organization" showSearch={false}>
      <div className="page-heading">
        <div>
          <span className="eyebrow"><span className="eyebrow-dot" /> ACCESS CONTROL &amp; ORGANIZATION</span>
          <h1>Investigators &amp; Organization</h1>
          <p>Manage organization isolation, investigator accounts, and backend-enforced RBAC roles.</p>
        </div>
        {org && <span className="page-context">Slug: {org.slug} · {org.deploymentMode}</span>}
      </div>

      {notice && <div className="case-success-notice" role="status">{notice}</div>}
      {error && <div className="dashboard-error" role="alert"><Icon name="findings" size={18} /><div><strong>Error</strong><p>{error}</p></div></div>}

      <div className="forensics-two-col">
        <section className="panel case-detail-panel">
          <h2>Organization Profile</h2>
          <form className="case-form" onSubmit={handleSaveOrg}>
            <label>
              <span>Organization name</span>
              <input value={orgName} onChange={(e) => setOrgName(e.target.value)} disabled={!isAdmin || saving} required />
            </label>
            <label>
              <span>Description</span>
              <textarea value={orgDesc} onChange={(e) => setOrgDesc(e.target.value)} disabled={!isAdmin || saving} rows={2} />
            </label>
            <label className="footprint-checkbox">
              <input type="checkbox" checked={allowReg} onChange={(e) => setAllowReg(e.target.checked)} disabled={!isAdmin || saving} />
              <span>Allow self-registration by organization slug</span>
            </label>
            {isAdmin && (
              <button className="primary-button" type="submit" disabled={saving}>Save organization</button>
            )}
          </form>

          {isAdmin && (
            <>
              <hr className="panel-divider" />
              <h2>Add Investigator</h2>
              <form className="case-form" onSubmit={handleAddMember}>
                <label>
                  <span>Full name</span>
                  <input value={newName} onChange={(e) => setNewName(e.target.value)} required />
                </label>
                <label>
                  <span>Email</span>
                  <input type="email" value={newEmail} onChange={(e) => setNewEmail(e.target.value)} required />
                </label>
                <label>
                  <span>Initial password (min. 8 chars)</span>
                  <input type="password" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} required minLength={8} />
                </label>
                <label>
                  <span>Role</span>
                  <select value={newRole} onChange={(e) => setNewRole(e.target.value)}>
                    {ROLES.map((r) => <option key={r} value={r}>{formatLabel(r)}</option>)}
                  </select>
                </label>
                <button className="primary-button" type="submit" disabled={saving}>Add investigator</button>
              </form>
            </>
          )}
        </section>

        <section className="panel case-list-panel">
          <div className="case-list-toolbar">
            <div>
              <h2>Organization Members ({members.length})</h2>
              <p>All API endpoints enforce these roles server-side.</p>
            </div>
          </div>
          <div className="table-scroll case-list-table-wrap">
            <table className="cases-table">
              <thead>
                <tr>
                  <th scope="col">INVESTIGATOR</th>
                  <th scope="col">ROLE</th>
                  <th scope="col">MFA</th>
                  <th scope="col">STATUS</th>
                  {isAdmin && <th scope="col">ACTION</th>}
                </tr>
              </thead>
              <tbody>
                {members.map((m) => (
                  <tr key={m.membershipId}>
                    <td>
                      <strong className="case-title">{m.fullName}</strong>
                      <div className="forensic-submeta">{m.email}</div>
                    </td>
                    <td>
                      {isAdmin ? (
                        <select value={m.role} onChange={(e) => handleRoleChange(m.membershipId, e.target.value)}>
                          {ROLES.map((r) => <option key={r} value={r}>{formatLabel(r)}</option>)}
                        </select>
                      ) : formatLabel(m.role)}
                    </td>
                    <td>{m.mfaEnabled ? "Enabled" : "Off"}</td>
                    <td><span className={`status-badge ${m.isActive ? "status-resolved" : "status-closed"}`}><i />{m.isActive ? "Active" : "Inactive"}</span></td>
                    {isAdmin && (
                      <td>
                        <button className="table-action-link" type="button" onClick={() => handleToggleActive(m)}>
                          {m.isActive ? "Deactivate" : "Activate"}
                        </button>
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      </div>
    </WorkspaceLayout>
  );
}

export function AuditLogsPage() {
  const [logs, setLogs] = useState([]);
  const [actionFilter, setActionFilter] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    getSystemAuditLogs({ action: actionFilter, signal: controller.signal })
      .then(setLogs)
      .catch((cause) => {
        if (!controller.signal.aborted) setError(cause instanceof Error ? cause.message : "Failed to load audit logs.");
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, [actionFilter]);

  return (
    <WorkspaceLayout mode={loading ? "loading" : error ? "unavailable" : "live"} pageTitle="Audit Logs" showSearch={false}>
      <div className="page-heading">
        <div>
          <span className="eyebrow"><span className="eyebrow-dot" /> SECURITY &amp; ACCESS AUDIT</span>
          <h1>System Audit Logs</h1>
          <p>Organization-scoped record of authentication events, role changes, and audited evidence downloads.</p>
        </div>
        <label className="filter-control">
          <select value={actionFilter} onChange={(e) => setActionFilter(e.target.value)} aria-label="Filter by action">
            <option value="">All actions</option>
            <option value="AUTH_LOGIN">Login</option>
            <option value="AUTH_LOGOUT">Logout</option>
            <option value="AUTH_REGISTER">Registration</option>
            <option value="AUTH_MFA_ENABLED">MFA Enabled</option>
            <option value="EVIDENCE_DOWNLOADED">Evidence Downloaded</option>
            <option value="INVESTIGATOR_ADDED">Investigator Added</option>
          </select>
        </label>
      </div>

      {error && <div className="dashboard-error" role="alert"><Icon name="findings" size={18} /><div><strong>Error</strong><p>{error}</p></div></div>}

      <section className="panel case-list-panel">
        {loading ? (
          <div className="case-loading">Loading system audit log…</div>
        ) : (
          <div className="table-scroll case-list-table-wrap">
            <table className="cases-table">
              <thead>
                <tr>
                  <th scope="col">TIMESTAMP</th>
                  <th scope="col">ACTION</th>
                  <th scope="col">ACTOR</th>
                  <th scope="col">RESOURCE</th>
                  <th scope="col">IP ADDRESS</th>
                </tr>
              </thead>
              <tbody>
                {logs.map((row) => (
                  <tr key={row.id}>
                    <td>{formatDate(row.createdAt, true)}</td>
                    <td><span className="event-type">{formatLabel(row.action)}</span></td>
                    <td>{row.actorEmail}</td>
                    <td>{row.resourceType}{row.resourceId ? `: ${row.resourceId}` : ""}</td>
                    <td><code>{row.ipAddress || "—"}</code></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </WorkspaceLayout>
  );
}

export function SettingsPage() {
  const { auth, user, organization, role, refreshAuth } = useAuth();
  const [fullName, setFullName] = useState(user?.fullName || "");
  const [mfaSecret, setMfaSecret] = useState("");
  const [mfaUri, setMfaUri] = useState("");
  const [mfaCode, setMfaCode] = useState("");
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const handleSaveProfile = async (e) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      await updateMyProfile({ fullName });
      await refreshAuth();
      setNotice("Profile updated.");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Failed to update profile.");
    } finally {
      setBusy(false);
    }
  };

  const handleStartMfa = async () => {
    setBusy(true);
    setError("");
    try {
      const res = await setupMfa();
      setMfaSecret(res.secret);
      setMfaUri(res.otpauthUri);
      setNotice("Add this TOTP secret to your authenticator app, then enter the 6-digit code to enable MFA.");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "MFA setup failed.");
    } finally {
      setBusy(false);
    }
  };

  const handleEnableMfa = async (e) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      await enableMfa(mfaCode);
      await refreshAuth();
      setMfaSecret("");
      setMfaCode("");
      setNotice("Multi-Factor Authentication (TOTP) is now enabled on your account.");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Invalid MFA code.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <WorkspaceLayout mode="live" pageTitle="Settings" showSearch={false}>
      <div className="page-heading">
        <div>
          <span className="eyebrow"><span className="eyebrow-dot" /> ACCOUNT &amp; HYBRID ENVIRONMENT</span>
          <h1>Settings</h1>
          <p>Manage investigator profile, TOTP Multi-Factor Authentication, and hybrid Local/Cloud security posture.</p>
        </div>
      </div>

      {notice && <div className="case-success-notice" role="status">{notice}</div>}
      {error && <div className="dashboard-error" role="alert"><Icon name="findings" size={18} /><div><strong>Error</strong><p>{error}</p></div></div>}

      <div className="forensics-two-col">
        <section className="panel case-detail-panel">
          <h2>Investigator Profile</h2>
          <form className="case-form" onSubmit={handleSaveProfile}>
            <label>
              <span>Email</span>
              <input value={user?.email || ""} disabled />
            </label>
            <label>
              <span>Full name</span>
              <input value={fullName} onChange={(e) => setFullName(e.target.value)} required minLength={2} />
            </label>
            <label>
              <span>Role &amp; Organization</span>
              <input value={`${formatLabel(role || "")} · ${organization?.name || ""}`} disabled />
            </label>
            <button className="primary-button" type="submit" disabled={busy}>Save profile</button>
          </form>
        </section>

        <section className="panel case-detail-panel">
          <h2>Multi-Factor Authentication (TOTP)</h2>
          <p>Status: <strong>{user?.mfaEnabled ? "Enabled" : "Not enabled"}</strong></p>
          {!mfaSecret ? (
            <button className="secondary-button" type="button" onClick={handleStartMfa} disabled={busy}>
              {user?.mfaEnabled ? "Rotate MFA secret" : "Configure TOTP MFA"}
            </button>
          ) : (
            <form className="case-form" onSubmit={handleEnableMfa}>
              <div className="hash-drawer">
                <div><strong>Secret:</strong> <code>{mfaSecret}</code></div>
                <div><strong>URI:</strong> <code>{mfaUri}</code></div>
              </div>
              <label>
                <span>Enter 6-digit verification code</span>
                <input value={mfaCode} onChange={(e) => setMfaCode(e.target.value)} required maxLength={8} placeholder="123456" />
              </label>
              <button className="primary-button" type="submit" disabled={busy}>Verify &amp; Enable MFA</button>
            </form>
          )}

          <hr className="panel-divider" />
          <h2>Hybrid Deployment &amp; AI Policy</h2>
          <dl className="footprint-dl">
            <div><dt>Deployment Mode</dt><dd><code>{auth?.deploymentMode || "LOCAL"}</code></dd></div>
            <div><dt>External Evidence Sync</dt><dd>Disabled by default (explicit authorization required)</dd></div>
            <div><dt>AI Assistant Mode</dt><dd>Local evidence-backed synthesis (no external data transmitted)</dd></div>
          </dl>
        </section>
      </div>
    </WorkspaceLayout>
  );
}
