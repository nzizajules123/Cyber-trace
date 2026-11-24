import { useEffect, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";

import { SeverityBadge, formatDate } from "./CaseFormFields.jsx";
import Icon from "./Icon.jsx";
import WorkspaceLayout from "./WorkspaceLayout.jsx";
import { getCases } from "../services/casesApi.js";
import { getUrlInvestigations, researchWebsiteUrl } from "../services/forensicsApi.js";

export default function DigitalFootprintPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const preselectedCase = searchParams.get("case") || "";

  const [cases, setCases] = useState([]);
  const [investigations, setInvestigations] = useState([]);
  const [selected, setSelected] = useState(null);

  const [url, setUrl] = useState("");
  const [caseId, setCaseId] = useState(preselectedCase);
  const [submittedBy, setSubmittedBy] = useState("");
  const [notes, setNotes] = useState("");
  const [sealAsEvidence, setSealAsEvidence] = useState(true);

  const [loading, setLoading] = useState(true);
  const [researching, setResearching] = useState(false);
  const [loadError, setLoadError] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setLoadError("");
    Promise.all([
      getCases({ page: 1, size: 100, signal: controller.signal }),
      getUrlInvestigations({ signal: controller.signal }),
    ])
      .then(([casesRes, invRes]) => {
        setCases(casesRes.items);
        setInvestigations(invRes.items);
        if (!caseId && casesRes.items[0]) {
          setCaseId(preselectedCase || casesRes.items[0].caseNumber);
        }
        if (!selected && invRes.items[0]) {
          setSelected(invRes.items[0]);
        }
      })
      .catch((cause) => {
        if (!controller.signal.aborted) {
          setLoadError(cause instanceof Error ? cause.message : "Failed to load URL research history.");
        }
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, [reloadKey]);

  const handleSubmit = async (event) => {
    event.preventDefault();
    if (!url.trim() || !caseId) return;
    setResearching(true);
    setError("");
    setNotice("");
    try {
      const result = await researchWebsiteUrl({
        url: url.trim(),
        caseId,
        submittedBy: submittedBy.trim(),
        sealAsEvidence,
        notes: notes.trim(),
      });
      setSelected(result);
      setUrl("");
      setNotes("");
      setNotice(
        `Research ${result.investigationCode} completed for ${result.domain} (Risk: ${result.riskLevel}, Score: ${result.riskScore}/100` +
          (result.evidenceCode ? `, sealed as ${result.evidenceCode}` : "") +
          `).`,
      );
      setReloadKey((k) => k + 1);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Website research failed.");
    } finally {
      setResearching(false);
    }
  };

  return (
    <WorkspaceLayout
      mode={loading ? "loading" : loadError ? "unavailable" : "live"}
      cases={cases}
      selectedCaseId={caseId}
      onSelectCase={(c) => c && navigate(`/cases/${encodeURIComponent(c)}`)}
      pageTitle="Digital Footprint"
      showSearch={false}
    >
      <div className="page-heading">
        <div>
          <span className="eyebrow"><span className="eyebrow-dot" /> AUTOMATED WEBSITE & OSINT RESEARCH</span>
          <h1>Digital Footprint & URL Research</h1>
          <p>Submit a reported website URL to automatically inspect DNS, TLS certificates, redirect chains, security headers, forms, and IOCs — with SSRF protection and optional Evidence Vault sealing.</p>
        </div>
      </div>

      {notice && <div className="case-success-notice" role="status">{notice}</div>}
      {(loadError || error) && (
        <div className="dashboard-error" role="alert">
          <Icon name="findings" size={18} />
          <div><strong>Research error</strong><p>{loadError || error}</p></div>
        </div>
      )}

      <section className="panel analysis-runner-panel">
        <form className="case-form" onSubmit={handleSubmit}>
          <div className="case-form-row">
            <label>
              <span>Website URL to research <b aria-hidden="true">*</b></span>
              <input
                type="text"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="https://example.com"
                required
                disabled={researching}
              />
            </label>
            <label>
              <span>Linked investigation case <b aria-hidden="true">*</b></span>
              <select value={caseId} onChange={(e) => setCaseId(e.target.value)} required disabled={researching}>
                {cases.length === 0 ? (
                  <option value="">No cases available — create a case first</option>
                ) : (
                  cases.map((c) => (
                    <option key={c.caseNumber} value={c.caseNumber}>
                      {c.caseNumber} — {c.title}
                    </option>
                  ))
                )}
              </select>
            </label>
          </div>
          <div className="case-form-row">
            <label>
              <span>Reporter / Submitted by</span>
              <input
                type="text"
                value={submittedBy}
                onChange={(e) => setSubmittedBy(e.target.value)}
                placeholder="e.g. Reporter Alex"
                disabled={researching}
              />
            </label>
            <label>
              <span>Context / Notes</span>
              <input
                type="text"
                value={notes}
                onChange={(e) => setNotes(e.target.value)}
                placeholder="e.g. Reported phishing link from email campaign"
                disabled={researching}
              />
            </label>
          </div>
          <div className="footprint-submit-row">
            <label className="footprint-checkbox">
              <input
                type="checkbox"
                checked={sealAsEvidence}
                onChange={(e) => setSealAsEvidence(e.target.checked)}
                disabled={researching}
              />
              <span>Seal forensic dossier &amp; SHA-256 digest into Evidence Vault + Chain of Custody</span>
            </label>
            <button className="primary-button" type="submit" disabled={researching || !cases.length}>
              <Icon name="footprint" size={15} />
              {researching ? "Researching Website…" : "Run URL Research"}
            </button>
          </div>
        </form>
      </section>

      {selected && (
        <section className="panel footprint-report-panel">
          <div className="finding-card-header">
            <div>
              <div className="finding-badges">
                <span className="case-id">{selected.investigationCode}</span>
                <SeverityBadge severity={selected.riskLevel} />
                <span className="analysis-status">Risk Score: {selected.riskScore}/100</span>
                {selected.httpStatus && <span className="event-type">HTTP {selected.httpStatus}</span>}
                {selected.evidenceCode && (
                  <Link className="case-id case-title-link" to="/evidence">
                    Vault: {selected.evidenceCode}
                  </Link>
                )}
              </div>
              <h2>{selected.pageTitle || selected.domain}</h2>
              <p className="forensic-submeta">
                Target: <code>{selected.targetUrl}</code>
                {selected.finalUrl && selected.finalUrl !== selected.targetUrl && (
                  <> → Final: <code>{selected.finalUrl}</code></>
                )}
              </p>
            </div>
            <div className="forensic-submeta">
              Submitted by <strong>{selected.submittedBy}</strong> · {formatDate(selected.createdAt, true)}
            </div>
          </div>

          <div className="footprint-grid">
            <article className="footprint-card">
              <h3>DNS &amp; Infrastructure</h3>
              <dl className="footprint-dl">
                <div><dt>Domain</dt><dd><code>{selected.dnsInfo?.hostname || selected.domain}</code></dd></div>
                <div>
                  <dt>IPv4</dt>
                  <dd>{selected.dnsInfo?.ipv4?.length ? selected.dnsInfo.ipv4.map((ip) => <code key={ip} className="inline-code">{ip}</code>) : "—"}</dd>
                </div>
                <div>
                  <dt>IPv6</dt>
                  <dd>{selected.dnsInfo?.ipv6?.length ? selected.dnsInfo.ipv6.slice(0, 2).join(", ") : "None"}</dd>
                </div>
                <div><dt>Server</dt><dd>{selected.httpInfo?.server || "Not disclosed"}</dd></div>
                <div><dt>Response time</dt><dd>{selected.httpInfo?.elapsedMs != null ? `${selected.httpInfo.elapsedMs} ms` : "—"}</dd></div>
                <div><dt>Redirects</dt><dd>{selected.httpInfo?.redirectChain?.length || 0} hop(s)</dd></div>
              </dl>
            </article>

            <article className="footprint-card">
              <h3>TLS / SSL Certificate</h3>
              {selected.tlsInfo?.available ? (
                <dl className="footprint-dl">
                  <div>
                    <dt>Status</dt>
                    <dd>
                      <span className={`status-badge ${selected.tlsInfo.valid ? "status-resolved" : "status-escalated"}`}>
                        <i />{selected.tlsInfo.valid ? "Valid Certificate" : "Invalid / Expired"}
                      </span>
                    </dd>
                  </div>
                  <div><dt>Subject CN</dt><dd>{selected.tlsInfo.subjectCn || "—"}</dd></div>
                  <div><dt>Issuer</dt><dd>{selected.tlsInfo.issuerOrg || selected.tlsInfo.issuerCn || "—"}</dd></div>
                  <div><dt>TLS / Cipher</dt><dd>{selected.tlsInfo.tlsVersion || "—"} {selected.tlsInfo.cipher ? `(${selected.tlsInfo.cipher})` : ""}</dd></div>
                  <div>
                    <dt>Expires</dt>
                    <dd>
                      {selected.tlsInfo.notAfter || "—"}
                      {selected.tlsInfo.daysRemaining != null ? ` (${selected.tlsInfo.daysRemaining}d left)` : ""}
                    </dd>
                  </div>
                </dl>
              ) : (
                <p className="forensic-submeta">No TLS certificate available ({selected.tlsInfo?.error || "HTTP only"}).</p>
              )}
            </article>

            <article className="footprint-card">
              <h3>HTTP Security Headers</h3>
              <ul className="header-audit-list">
                {Object.entries(selected.securityHeaders || {}).map(([name, info]) => (
                  <li key={name}>
                    <code>{name}</code>
                    <span className={`header-pill ${info?.present ? "header-ok" : "header-miss"}`}>
                      {info?.present ? "Present" : "Missing"}
                    </span>
                  </li>
                ))}
              </ul>
            </article>

            <article className="footprint-card">
              <h3>Page Artifacts &amp; Indicators</h3>
              <dl className="footprint-dl">
                <div><dt>HTML Snapshot SHA-256</dt><dd><code className="mono-hash">{selected.snapshotSha256 ? `${selected.snapshotSha256.slice(0, 24)}…` : "—"}</code></dd></div>
                <div><dt>Outbound Domains</dt><dd>{selected.artifacts?.outboundDomains?.length || 0}</dd></div>
                <div><dt>External Scripts</dt><dd>{selected.artifacts?.externalScripts?.length || 0}</dd></div>
                <div><dt>HTML Forms</dt><dd>{selected.artifacts?.forms?.length || 0}</dd></div>
                <div><dt>Findings Triggered</dt><dd>{selected.findingsCount}</dd></div>
              </dl>
              {selected.artifacts?.outboundDomains?.length > 0 && (
                <div className="ioc-chip-grid">
                  {selected.artifacts.outboundDomains.slice(0, 8).map((dom) => (
                    <span className="ioc-chip" key={dom}><small>Domain</small><code>{dom}</code></span>
                  ))}
                </div>
              )}
            </article>
          </div>
        </section>
      )}

      <section className="panel case-list-panel">
        <div className="case-list-toolbar">
          <div>
            <h2>URL Research History ({investigations.length})</h2>
            <p>Click any past investigation to inspect its DNS, TLS, headers, and extracted artifacts.</p>
          </div>
        </div>
        {loading ? (
          <div className="case-loading">Loading URL research history…</div>
        ) : investigations.length === 0 ? (
          <div className="case-empty">
            <strong>No website investigations yet</strong>
            <p>Enter a reported URL above to run your first automated digital footprint dossier.</p>
          </div>
        ) : (
          <div className="table-scroll case-list-table-wrap">
            <table className="cases-table">
              <thead>
                <tr>
                  <th scope="col">ID</th>
                  <th scope="col">TARGET URL</th>
                  <th scope="col">CASE</th>
                  <th scope="col">RISK</th>
                  <th scope="col">HTTP</th>
                  <th scope="col">EVIDENCE</th>
                  <th scope="col">DATE</th>
                </tr>
              </thead>
              <tbody>
                {investigations.map((item) => (
                  <tr
                    key={item.investigationCode}
                    className={selected?.investigationCode === item.investigationCode ? "row-selected" : ""}
                    style={{ cursor: "pointer" }}
                    onClick={() => setSelected(item)}
                  >
                    <td><span className="case-id">{item.investigationCode}</span></td>
                    <td>
                      <strong className="case-title">{item.domain}</strong>
                      <div className="forensic-submeta">{item.targetUrl}</div>
                    </td>
                    <td>{item.caseNumber}</td>
                    <td><SeverityBadge severity={item.riskLevel} /> <span className="forensic-submeta">({item.riskScore})</span></td>
                    <td>{item.httpStatus || "—"}</td>
                    <td>{item.evidenceCode || "—"}</td>
                    <td>{formatDate(item.createdAt, true)}</td>
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
