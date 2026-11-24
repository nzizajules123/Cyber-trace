import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";

import { formatDate, formatLabel } from "./CaseFormFields.jsx";
import Icon from "./Icon.jsx";
import WorkspaceLayout from "./WorkspaceLayout.jsx";
import { getCases } from "../services/casesApi.js";
import {
  addCustodyEvent,
  analyzeEvidence,
  getCustodyLedger,
  getEvidenceList,
  getIntegritySummary,
  uploadEvidenceFile,
  verifyEvidence,
} from "../services/forensicsApi.js";

const EVIDENCE_TYPES = [
  "LOG_FILE",
  "DISK_IMAGE",
  "MEMORY_DUMP",
  "NETWORK_CAPTURE",
  "DOCUMENT",
  "OTHER",
];

const CUSTODY_ACTIONS = ["TRANSFERRED", "ANALYZED", "VERIFIED", "EXPORTED", "SEALED"];

function formatBytes(bytes = 0) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function IntegrityPill({ verification }) {
  if (!verification || !verification.comparisonPerformed) {
    return <span className="status-badge status-open"><i />Pending</span>;
  }
  if (verification.sha256Matches) {
    return <span className="status-badge status-resolved"><i />SHA-256 Verified</span>;
  }
  return <span className="status-badge status-escalated"><i />Hash Mismatch</span>;
}

function UploadEvidenceModal({ cases, onClose, onUploaded }) {
  const [caseId, setCaseId] = useState(cases[0]?.caseNumber || "");
  const [evidenceType, setEvidenceType] = useState("LOG_FILE");
  const [acquisitionSource, setAcquisitionSource] = useState("");
  const [collectedBy, setCollectedBy] = useState("");
  const [description, setDescription] = useState("");
  const [file, setFile] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    const onKey = (e) => {
      if (e.key === "Escape" && !uploading) onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose, uploading]);

  const handleSubmit = async (event) => {
    event.preventDefault();
    if (!file) {
      setError("Please select an evidence file to ingest.");
      return;
    }
    setUploading(true);
    setError("");
    try {
      const created = await uploadEvidenceFile({
        caseId,
        evidenceType,
        acquisitionSource,
        collectedBy,
        description,
        file,
      });
      onUploaded(
        `Evidence ${created.evidenceCode} ingested & sealed (SHA-256: ${created.sha256.slice(0, 16)}…).`,
      );
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Upload failed.");
    } finally {
      setUploading(false);
    }
  };

  return (
    <div
      className="case-modal-backdrop"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget && !uploading) onClose();
      }}
    >
      <section className="panel case-modal" role="dialog" aria-modal="true" aria-labelledby="upload-ev-title">
        <div className="case-modal-heading">
          <div>
            <h2 id="upload-ev-title">Ingest digital evidence</h2>
            <p>Computes SHA-256, SHA-512, and MD5 digests and seals a genesis Chain of Custody record.</p>
          </div>
          <button className="icon-button" type="button" onClick={onClose} disabled={uploading} aria-label="Close">
            ×
          </button>
        </div>
        {error && (
          <div className="dashboard-error" role="alert">
            <Icon name="findings" size={16} />
            <div><strong>Ingest failed</strong><p>{error}</p></div>
          </div>
        )}
        <form className="case-form case-modal-form" onSubmit={handleSubmit}>
          <label>
            <span>Linked investigation case <b aria-hidden="true">*</b></span>
            <select value={caseId} onChange={(e) => setCaseId(e.target.value)} required>
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
          <label>
            <span>Evidence file <b aria-hidden="true">*</b></span>
            <input
              type="file"
              onChange={(e) => setFile(e.target.files?.[0] ?? null)}
              required
            />
          </label>
          <div className="case-form-row">
            <label>
              <span>Evidence type</span>
              <select value={evidenceType} onChange={(e) => setEvidenceType(e.target.value)}>
                {EVIDENCE_TYPES.map((t) => (
                  <option key={t} value={t}>{formatLabel(t)}</option>
                ))}
              </select>
            </label>
            <label>
              <span>Collected by</span>
              <input
                value={collectedBy}
                onChange={(e) => setCollectedBy(e.target.value)}
                placeholder="e.g. Investigator Maya"
                maxLength={160}
              />
            </label>
          </div>
          <label>
            <span>Acquisition source / host</span>
            <input
              value={acquisitionSource}
              onChange={(e) => setAcquisitionSource(e.target.value)}
              placeholder="e.g. bastion-01.corp / /var/log/auth.log"
              maxLength={200}
            />
          </label>
          <label>
            <span>Acquisition notes</span>
            <textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              rows={3}
              placeholder="Context on how and when this evidence was acquired."
            />
          </label>
          <div className="case-form-actions">
            <button className="secondary-button" type="button" onClick={onClose} disabled={uploading}>
              Cancel
            </button>
            <button className="primary-button" type="submit" disabled={uploading || !cases.length}>
              {uploading ? "Hashing & Sealing…" : "Ingest evidence"}
            </button>
          </div>
        </form>
      </section>
    </div>
  );
}

export function EvidenceRepositoryPage() {
  const navigate = useNavigate();
  const [cases, setCases] = useState([]);
  const [items, setItems] = useState([]);
  const [caseFilter, setCaseFilter] = useState("");
  const [query, setQuery] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [showUpload, setShowUpload] = useState(false);
  const [busyCode, setBusyCode] = useState("");
  const [expandedCode, setExpandedCode] = useState("");
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setError("");
    Promise.all([
      getCases({ page: 1, size: 100, signal: controller.signal }),
      getEvidenceList({ caseId: caseFilter, query, signal: controller.signal }),
    ])
      .then(([casesRes, evRes]) => {
        setCases(casesRes.items);
        setItems(evRes.items);
      })
      .catch((cause) => {
        if (!controller.signal.aborted) {
          setError(cause instanceof Error ? cause.message : "Failed to load evidence.");
        }
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, [caseFilter, query, reloadKey]);

  const handleVerify = async (code) => {
    setBusyCode(code);
    setError("");
    try {
      const res = await verifyEvidence(code);
      setNotice(
        res.sha256Matches
          ? `${code}: SHA-256 verified against vault file (MATCH).`
          : `${code}: WARNING — SHA-256 MISMATCH DETECTED!`,
      );
      setReloadKey((k) => k + 1);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Verification failed.");
    } finally {
      setBusyCode("");
    }
  };

  const handleAnalyze = async (code) => {
    setBusyCode(code);
    setError("");
    try {
      const res = await analyzeEvidence(code);
      setNotice(
        `Analyzed ${code} (${res.detectedFormat}): ${res.eventsParsed} events parsed, ${res.uniqueIocs} IOCs extracted, ${res.findingsGenerated} findings generated.`,
      );
      setReloadKey((k) => k + 1);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Analysis failed.");
    } finally {
      setBusyCode("");
    }
  };

  return (
    <WorkspaceLayout
      mode={loading ? "loading" : error ? "unavailable" : "live"}
      cases={cases}
      pageTitle="Evidence Repository"
      query={query}
      onQueryChange={setQuery}
      onSelectCase={(c) => c && navigate(`/cases/${encodeURIComponent(c)}`)}
    >
      <div className="page-heading">
        <div>
          <span className="eyebrow"><span className="eyebrow-dot" /> DIGITAL EVIDENCE VAULT</span>
          <h1>Evidence Repository</h1>
          <p>Ingest forensic artifacts with automatic SHA-256/SHA-512/MD5 hashing and tamper-evident custody.</p>
        </div>
        <button className="primary-button" type="button" onClick={() => setShowUpload(true)}>
          <Icon name="plus" size={15} /> Ingest evidence
        </button>
      </div>

      {notice && <div className="case-success-notice" role="status">{notice}</div>}
      {error && (
        <div className="dashboard-error" role="alert">
          <Icon name="findings" size={18} />
          <div><strong>Evidence repository error</strong><p>{error}</p></div>
        </div>
      )}

      <section className="panel case-list-panel">
        <div className="case-list-toolbar">
          <div>
            <h2>Vault items</h2>
            <p>{loading ? "Loading evidence…" : `${items.length} evidence item${items.length === 1 ? "" : "s"} in vault`}</p>
          </div>
          <div className="case-list-controls">
            <label className="filter-control">
              <span className="sr-only">Filter by case</span>
              <select value={caseFilter} onChange={(e) => setCaseFilter(e.target.value)} aria-label="Filter by case">
                <option value="">All cases</option>
                {cases.map((c) => (
                  <option key={c.caseNumber} value={c.caseNumber}>{c.caseNumber}</option>
                ))}
              </select>
            </label>
            <button className="secondary-button" type="button" onClick={() => setReloadKey((k) => k + 1)} disabled={loading}>
              <Icon name="refresh" size={14} /> Refresh
            </button>
          </div>
        </div>

        {loading ? (
          <div className="case-loading">Loading vault items…</div>
        ) : items.length === 0 ? (
          <div className="case-empty">
            <span className="empty-state-mark"><Icon name="evidence" size={18} /></span>
            <strong>No evidence ingested yet</strong>
            <p>Upload a log file, CSV, JSONL, or forensic artifact to compute cryptographic hashes and run automated analysis.</p>
            <button className="secondary-button" type="button" onClick={() => setShowUpload(true)}>
              Ingest your first evidence item
            </button>
          </div>
        ) : (
          <div className="table-scroll case-list-table-wrap">
            <table className="cases-table">
              <thead>
                <tr>
                  <th scope="col">EVIDENCE ID</th>
                  <th scope="col">FILE</th>
                  <th scope="col">CASE</th>
                  <th scope="col">SHA-256 DIGEST</th>
                  <th scope="col">INTEGRITY</th>
                  <th scope="col">STATUS</th>
                  <th scope="col">ACTIONS</th>
                </tr>
              </thead>
              <tbody>
                {items.map((item) => (
                  <tr key={item.evidenceCode}>
                    <td><span className="case-id">{item.evidenceCode}</span></td>
                    <td>
                      <strong className="case-title">{item.originalFilename}</strong>
                      <div className="forensic-submeta">
                        {formatLabel(item.evidenceType)} · {formatBytes(item.fileSize)}
                      </div>
                    </td>
                    <td>
                      <Link className="case-id case-title-link" to={`/cases/${encodeURIComponent(item.caseNumber)}`}>
                        {item.caseNumber}
                      </Link>
                    </td>
                    <td>
                      <button
                        type="button"
                        className="hash-chip"
                        title="Click to toggle full SHA-256 / SHA-512 / MD5 hashes"
                        onClick={() => setExpandedCode((c) => (c === item.evidenceCode ? "" : item.evidenceCode))}
                      >
                        {item.sha256.slice(0, 16)}…
                      </button>
                      {expandedCode === item.evidenceCode && (
                        <div className="hash-drawer">
                          <div><strong>SHA-256:</strong> <code>{item.sha256}</code></div>
                          <div><strong>SHA-512:</strong> <code>{item.sha512.slice(0, 64)}…</code></div>
                          <div><strong>MD5:</strong> <code>{item.md5}</code></div>
                        </div>
                      )}
                    </td>
                    <td><IntegrityPill verification={item.latestVerification} /></td>
                    <td><span className="analysis-status">{formatLabel(item.status)}</span></td>
                    <td className="case-row-actions">
                      <button
                        className="table-action-link"
                        type="button"
                        disabled={busyCode === item.evidenceCode}
                        onClick={() => handleVerify(item.evidenceCode)}
                      >
                        {busyCode === item.evidenceCode ? "Working…" : "Verify"}
                      </button>
                      <button
                        className="table-action-link"
                        type="button"
                        disabled={busyCode === item.evidenceCode}
                        onClick={() => handleAnalyze(item.evidenceCode)}
                      >
                        Analyze
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {showUpload && (
        <UploadEvidenceModal
          cases={cases}
          onClose={() => setShowUpload(false)}
          onUploaded={(msg) => {
            setShowUpload(false);
            setNotice(msg);
            setReloadKey((k) => k + 1);
          }}
        />
      )}
    </WorkspaceLayout>
  );
}

export function EvidenceIntegrityPage() {
  const [summary, setSummary] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [verifyingCode, setVerifyingCode] = useState("");
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setError("");
    getIntegritySummary({ signal: controller.signal })
      .then(setSummary)
      .catch((cause) => {
        if (!controller.signal.aborted) setError(cause instanceof Error ? cause.message : "Failed to load integrity status.");
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, [reloadKey]);

  const handleVerify = async (code) => {
    setVerifyingCode(code);
    try {
      const res = await verifyEvidence(code);
      setNotice(res.sha256Matches ? `${code} passed SHA-256 re-verification.` : `${code} FAILED SHA-256 verification!`);
      setReloadKey((k) => k + 1);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Verification failed.");
    } finally {
      setVerifyingCode("");
    }
  };

  return (
    <WorkspaceLayout mode={loading ? "loading" : error ? "unavailable" : "live"} pageTitle="Evidence Integrity" showSearch={false}>
      <div className="page-heading">
        <div>
          <span className="eyebrow"><span className="eyebrow-dot" /> CRYPTOGRAPHIC INTEGRITY</span>
          <h1>Evidence Integrity Monitor</h1>
          <p>Re-compute SHA-256 digests directly from stored vault files to prove zero alteration since acquisition.</p>
        </div>
        <button className="secondary-button" type="button" onClick={() => setReloadKey((k) => k + 1)}>
          <Icon name="refresh" size={14} /> Refresh
        </button>
      </div>

      {notice && <div className="case-success-notice" role="status">{notice}</div>}
      {error && <div className="dashboard-error" role="alert"><Icon name="findings" size={18} /><div><strong>Error</strong><p>{error}</p></div></div>}

      <section className="case-kpi-grid">
        {[
          { label: "Total evidence items", val: summary?.totalItems ?? 0, tone: "cyan", icon: "evidence" },
          { label: "Verified SHA-256 matches", val: summary?.verifiedCount ?? 0, tone: "green", icon: "integrity" },
          { label: "Hash mismatches", val: summary?.mismatchCount ?? 0, tone: "amber", icon: "findings" },
          { label: "Pending verification", val: summary?.pendingCount ?? 0, tone: "blue", icon: "timeline" },
        ].map((card) => (
          <article className="case-kpi-card" key={card.label}>
            <span className={`metric-icon metric-${card.tone}`}><Icon name={card.icon} size={16} /></span>
            <span className="case-kpi-label">{card.label}</span>
            <strong>{loading ? "…" : card.val}</strong>
          </article>
        ))}
      </section>

      <section className="panel case-list-panel">
        <div className="case-list-toolbar">
          <div>
            <h2>Per-item SHA-256 verification log</h2>
            <p>Every verification reads the actual bytes on disk and appends a Chain of Custody record.</p>
          </div>
        </div>
        {loading ? (
          <div className="case-loading">Checking integrity records…</div>
        ) : !summary?.items?.length ? (
          <div className="case-empty">
            <strong>No evidence items to verify</strong>
            <p>Ingest evidence in the Evidence Repository first.</p>
            <Link className="secondary-button" to="/evidence">Open Evidence Repository</Link>
          </div>
        ) : (
          <div className="table-scroll case-list-table-wrap">
            <table className="cases-table">
              <thead>
                <tr>
                  <th scope="col">EVIDENCE</th>
                  <th scope="col">ACQUISITION SHA-256</th>
                  <th scope="col">LAST VERIFIED</th>
                  <th scope="col">STATUS</th>
                  <th scope="col">ACTION</th>
                </tr>
              </thead>
              <tbody>
                {summary.items.map((item) => (
                  <tr key={item.evidenceCode}>
                    <td>
                      <span className="case-id">{item.evidenceCode}</span>
                      <div className="forensic-submeta">{item.originalFilename}</div>
                    </td>
                    <td><code className="mono-hash">{item.sha256}</code></td>
                    <td>{formatDate(item.latestVerification?.verifiedAt, true)}</td>
                    <td><IntegrityPill verification={item.latestVerification} /></td>
                    <td>
                      <button
                        className="secondary-button"
                        type="button"
                        disabled={verifyingCode === item.evidenceCode}
                        onClick={() => handleVerify(item.evidenceCode)}
                      >
                        {verifyingCode === item.evidenceCode ? "Verifying…" : "Verify now"}
                      </button>
                    </td>
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

export function ChainOfCustodyPage() {
  const [evidenceItems, setEvidenceItems] = useState([]);
  const [ledger, setLedger] = useState(null);
  const [selectedEvidence, setSelectedEvidence] = useState("");
  const [action, setAction] = useState("TRANSFERRED");
  const [actor, setActor] = useState("");
  const [fromCustodian, setFromCustodian] = useState("");
  const [toCustodian, setToCustodian] = useState("");
  const [location, setLocation] = useState("");
  const [notes, setNotes] = useState("");
  const [saving, setSaving] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setError("");
    Promise.all([
      getEvidenceList({ signal: controller.signal }),
      getCustodyLedger({ signal: controller.signal }),
    ])
      .then(([evRes, ledgerRes]) => {
        setEvidenceItems(evRes.items);
        setLedger(ledgerRes);
        if (!selectedEvidence && evRes.items[0]) {
          setSelectedEvidence(evRes.items[0].evidenceCode);
        }
      })
      .catch((cause) => {
        if (!controller.signal.aborted) setError(cause instanceof Error ? cause.message : "Failed to load custody ledger.");
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, [reloadKey]);

  const handleAddCustody = async (e) => {
    e.preventDefault();
    if (!selectedEvidence) return;
    setSaving(true);
    setError("");
    try {
      await addCustodyEvent(selectedEvidence, {
        action,
        actor,
        fromCustodian: fromCustodian || null,
        toCustodian: toCustodian || null,
        location: location || null,
        notes: notes || null,
      });
      setNotice(`Hash-chained custody event (${formatLabel(action)}) appended to ${selectedEvidence}.`);
      setNotes("");
      setReloadKey((k) => k + 1);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Failed to record custody event.");
    } finally {
      setSaving(false);
    }
  };

  return (
    <WorkspaceLayout mode={loading ? "loading" : error ? "unavailable" : "live"} pageTitle="Chain of Custody" showSearch={false}>
      <div className="page-heading">
        <div>
          <span className="eyebrow"><span className="eyebrow-dot" /> TAMPER-EVIDENT LEDGER</span>
          <h1>Chain of Custody</h1>
          <p>Every custody transfer, verification, and analysis step is cryptographically SHA-256 hash-chained.</p>
        </div>
        {ledger && (
          <span className={`integrity-state ${ledger.allChainsValid ? "integrity-checked" : ""}`}>
            <Icon name="shield" size={14} />
            {ledger.allChainsValid ? "ALL CHAINS INTACT" : `TAMPER DETECTED (${ledger.brokenEvidenceCodes.join(", ")})`}
          </span>
        )}
      </div>

      {notice && <div className="case-success-notice" role="status">{notice}</div>}
      {error && <div className="dashboard-error" role="alert"><Icon name="findings" size={18} /><div><strong>Error</strong><p>{error}</p></div></div>}

      <div className="forensics-two-col">
        <section className="panel case-detail-panel">
          <h2>Record custody event</h2>
          <p>Append a new cryptographically linked entry to an evidence item&apos;s chain of custody.</p>
          <form className="case-form" onSubmit={handleAddCustody}>
            <label>
              <span>Evidence item</span>
              <select value={selectedEvidence} onChange={(e) => setSelectedEvidence(e.target.value)} required>
                {evidenceItems.length === 0 ? (
                  <option value="">No evidence items available</option>
                ) : (
                  evidenceItems.map((ev) => (
                    <option key={ev.evidenceCode} value={ev.evidenceCode}>
                      {ev.evidenceCode} — {ev.originalFilename}
                    </option>
                  ))
                )}
              </select>
            </label>
            <div className="case-form-row">
              <label>
                <span>Action</span>
                <select value={action} onChange={(e) => setAction(e.target.value)}>
                  {CUSTODY_ACTIONS.map((a) => <option key={a} value={a}>{formatLabel(a)}</option>)}
                </select>
              </label>
              <label>
                <span>Actor / Investigator *</span>
                <input value={actor} onChange={(e) => setActor(e.target.value)} required placeholder="e.g. Analyst Maya" />
              </label>
            </div>
            <div className="case-form-row">
              <label>
                <span>From custodian</span>
                <input value={fromCustodian} onChange={(e) => setFromCustodian(e.target.value)} placeholder="Optional" />
              </label>
              <label>
                <span>To custodian</span>
                <input value={toCustodian} onChange={(e) => setToCustodian(e.target.value)} placeholder="Optional" />
              </label>
            </div>
            <label>
              <span>Location / Lab</span>
              <input value={location} onChange={(e) => setLocation(e.target.value)} placeholder="e.g. Forensics Lab B" />
            </label>
            <label>
              <span>Notes</span>
              <textarea value={notes} onChange={(e) => setNotes(e.target.value)} rows={2} placeholder="Transfer purpose or handling notes." />
            </label>
            <button className="primary-button" type="submit" disabled={saving || !evidenceItems.length}>
              {saving ? "Sealing entry…" : "Append custody record"}
            </button>
          </form>
        </section>

        <section className="panel case-detail-panel">
          <h2>Cryptographic ledger ({ledger?.totalEvents ?? 0} entries)</h2>
          <p>Each entry&apos;s SHA-256 hash incorporates the previous entry&apos;s hash.</p>
          {loading ? (
            <div className="case-loading">Verifying hash chains…</div>
          ) : !ledger?.events?.length ? (
            <div className="case-empty">
              <strong>No custody events recorded</strong>
              <p>Ingest an evidence file to create its genesis custody entry.</p>
            </div>
          ) : (
            <ol className="case-audit-timeline">
              {ledger.events.map((ev) => (
                <li key={ev.id}>
                  <span className="case-audit-marker" />
                  <div>
                    <strong>{formatLabel(ev.action)} · <span className="case-id">{ev.evidenceCode}</span></strong>
                    <p>
                      Actor: {ev.actor}
                      {ev.fromCustodian || ev.toCustodian
                        ? ` (${ev.fromCustodian || "—"} → ${ev.toCustodian || "—"})`
                        : ""}
                      {ev.location ? ` · ${ev.location}` : ""}
                    </p>
                    {ev.notes && <p className="forensic-submeta">{ev.notes}</p>}
                    <div className="forensic-submeta">
                      Entry hash: <code>{ev.entryHash.slice(0, 24)}…</code>
                    </div>
                    <time dateTime={ev.occurredAt}>{formatDate(ev.occurredAt, true)}</time>
                  </div>
                </li>
              ))}
            </ol>
          )}
        </section>
      </div>
    </WorkspaceLayout>
  );
}
