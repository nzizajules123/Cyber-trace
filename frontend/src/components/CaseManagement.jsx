import { useEffect, useState } from "react";
import { Link, useLocation, useNavigate, useParams } from "react-router-dom";

import {
  CASE_SEVERITIES,
  CASE_STATUSES,
  CaseFormFields,
  EMPTY_CASE_FORM,
  SeverityBadge,
  StatusBadge,
  formatDate,
  formatLabel,
  getInitialCaseValues,
} from "./CaseFormFields.jsx";
import Icon from "./Icon.jsx";
import WorkspaceLayout from "./WorkspaceLayout.jsx";
import {
  addCaseNote,
  createCase,
  deleteCase,
  getCase,
  getCaseMetrics,
  getCaseNotes,
  getCases,
  updateCase,
} from "../services/casesApi.js";
import { askAiAssistant } from "../services/forensicsApi.js";

function PageError({ message, onRetry }) {
  return (
    <div className="dashboard-error" role="alert">
      <Icon name="findings" size={18} />
      <div>
        <strong>Case data is unavailable</strong>
        <p>{message}</p>
      </div>
      {onRetry && (
        <button className="secondary-button" type="button" onClick={onRetry}>
          <Icon name="refresh" size={14} /> Retry
        </button>
      )}
    </div>
  );
}

function CaseFormModal({ caseRecord, onClose, onSaved }) {
  const editing = Boolean(caseRecord);
  const [values, setValues] = useState(() => getInitialCaseValues(caseRecord));
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    const handleKeyDown = (event) => {
      if (event.key === "Escape" && !saving) onClose();
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [onClose, saving]);

  const handleChange = (event) => {
    setValues((current) => ({ ...current, [event.target.name]: event.target.value }));
  };

  const handleSubmit = async (event) => {
    event.preventDefault();
    setSaving(true);
    setError("");
    try {
      const saved = editing
        ? await updateCase(caseRecord.caseNumber, values)
        : await createCase(values);
      onSaved(editing ? `${saved.caseNumber} was updated.` : `${saved.caseNumber} was created.`);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "The case could not be saved.");
    } finally {
      setSaving(false);
    }
  };

  return (
    <div
      className="case-modal-backdrop"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget && !saving) onClose();
      }}
    >
      <section className="panel case-modal" role="dialog" aria-modal="true" aria-labelledby="case-modal-title">
        <div className="case-modal-heading">
          <div>
            <h2 id="case-modal-title">{editing ? "Edit case" : "Create investigation case"}</h2>
            <p>{editing ? caseRecord.caseNumber : "Save a new case to the workspace database."}</p>
          </div>
          <button className="icon-button" type="button" aria-label="Close dialog" disabled={saving} onClick={onClose}>
            ×
          </button>
        </div>
        {error && <PageError message={error} />}
        <form className="case-form case-modal-form" onSubmit={handleSubmit}>
          <CaseFormFields values={values} onChange={handleChange} rows={4} autoFocus />
          <div className="case-form-actions">
            <button className="secondary-button" type="button" onClick={onClose} disabled={saving}>
              Cancel
            </button>
            <button className="primary-button" type="submit" disabled={saving}>
              {saving ? "Saving…" : editing ? "Save changes" : "Create case"}
            </button>
          </div>
        </form>
      </section>
    </div>
  );
}

function AuditChangesList({ changesJson }) {
  const entries = Object.entries(changesJson ?? {});
  if (!entries.length) return null;

  return (
    <ul className="case-audit-changes">
      {entries.map(([field, diff]) => {
        const oldVal = diff && typeof diff === "object" ? diff.old : null;
        const newVal = diff && typeof diff === "object" ? diff.new : diff;
        const formatVal = (val) => {
          if (val === null || val === undefined || val === "") return "None";
          if (typeof val === "boolean") return val ? "Yes" : "No";
          return String(val);
        };
        return (
          <li key={field}>
            <span className="audit-field">{formatLabel(field)}</span>
            {oldVal !== null && oldVal !== undefined ? (
              <span className="audit-diff">
                <del>{formatVal(oldVal)}</del> → <strong>{formatVal(newVal)}</strong>
              </span>
            ) : (
              <span className="audit-diff">
                <strong>{formatVal(newVal)}</strong>
              </span>
            )}
          </li>
        );
      })}
    </ul>
  );
}

function CaseListPage() {
  const navigate = useNavigate();
  const location = useLocation();
  const [query, setQuery] = useState("");
  const [status, setStatus] = useState("");
  const [severity, setSeverity] = useState("");
  const [page, setPage] = useState(1);
  const [reloadKey, setReloadKey] = useState(0);
  const [result, setResult] = useState(null);
  const [metrics, setMetrics] = useState(null);
  const [metricsError, setMetricsError] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [modalCase, setModalCase] = useState(undefined);
  const [notice, setNotice] = useState(location.state?.notice ?? "");
  const pageSize = 50;

  useEffect(() => {
    const controller = new AbortController();
    const load = () => {
      setLoading(true);
      setError("");
      getCases({ query, status, severity, page, size: pageSize, signal: controller.signal })
        .then(setResult)
        .catch((cause) => {
          if (controller.signal.aborted) return;
          setResult(null);
          setError(cause instanceof Error ? cause.message : "An unexpected error occurred.");
        })
        .finally(() => {
          if (!controller.signal.aborted) setLoading(false);
        });
      getCaseMetrics({ signal: controller.signal })
        .then((summary) => {
          setMetrics(summary);
          setMetricsError("");
        })
        .catch((cause) => {
          if (controller.signal.aborted) return;
          setMetrics(null);
          setMetricsError(cause instanceof Error ? cause.message : "Metrics are unavailable.");
        });
    };

    const timer = window.setTimeout(load, query ? 250 : 0);
    return () => {
      window.clearTimeout(timer);
      controller.abort();
    };
  }, [query, status, severity, page, reloadKey]);

  const handleSearch = (value) => {
    setQuery(value);
    setPage(1);
  };
  const handleStatus = (value) => {
    setStatus(value);
    setPage(1);
  };
  const handleSeverity = (value) => {
    setSeverity(value);
    setPage(1);
  };
  const pageCount = Math.max(1, Math.ceil((result?.total ?? 0) / pageSize));
  const startOffset = (page - 1) * pageSize;

  return (
    <WorkspaceLayout
      mode={loading ? "loading" : error ? "unavailable" : "live"}
      cases={result?.items ?? []}
      pageTitle="Cases"
      query={query}
      onQueryChange={handleSearch}
      onSelectCase={(caseNumber) => caseNumber && navigate(`/cases/${encodeURIComponent(caseNumber)}`)}
    >
      <div className="page-heading">
        <div>
          <span className="eyebrow">
            <span className="eyebrow-dot" /> CASE MANAGEMENT
          </span>
          <h1>Investigation cases</h1>
          <p>Create and manage case records stored in the configured CyberTrace database.</p>
        </div>
        <button className="primary-button" type="button" onClick={() => setModalCase(null)}>
          <Icon name="plus" size={15} /> New case
        </button>
      </div>

      <section className="case-kpi-grid" aria-label="Case metrics" aria-busy={loading}>
        {[
          { key: "totalCases", label: "Total cases", tone: "cyan", icon: "cases" },
          { key: "openCases", label: "Active cases", tone: "blue", icon: "timeline" },
          { key: "criticalCases", label: "Critical cases", tone: "amber", icon: "findings" },
          { key: "resolvedCases", label: "Resolved cases", tone: "green", icon: "integrity" },
        ].map((item) => (
          <article className="case-kpi-card" key={item.key}>
            <span className={`metric-icon metric-${item.tone}`}>
              <Icon name={item.icon} size={16} />
            </span>
            <span className="case-kpi-label">{item.label}</span>
            {metricsError ? (
              <strong className="case-kpi-unavailable" title={metricsError}>
                Unavailable
              </strong>
            ) : metrics ? (
              <strong>{metrics[item.key].toLocaleString()}</strong>
            ) : (
              <span className="skeleton case-kpi-skeleton" aria-label="Loading case metric" />
            )}
          </article>
        ))}
      </section>
      {metricsError && (
        <p className="case-metrics-error" role="status">
          Case metrics are unavailable: {metricsError}
        </p>
      )}
      {notice && (
        <div className="case-success-notice" role="status">
          {notice}
        </div>
      )}

      <section className="panel case-list-panel" aria-label="Investigation cases">
        <div className="case-list-toolbar">
          <div>
            <h2>Cases</h2>
            <p>
              {loading
                ? "Loading case records…"
                : error
                  ? "Case records could not be loaded."
                  : `${result.total} case${result.total === 1 ? "" : "s"} returned by the API`}
            </p>
          </div>
          <div className="case-list-controls">
            <label className="filter-control">
              <span className="sr-only">Filter cases by status</span>
              <select
                value={status}
                onChange={(event) => handleStatus(event.target.value)}
                aria-label="Filter cases by status"
              >
                <option value="">All statuses</option>
                {CASE_STATUSES.map((item) => (
                  <option key={item} value={item}>
                    {formatLabel(item)}
                  </option>
                ))}
              </select>
            </label>
            <label className="filter-control">
              <span className="sr-only">Filter cases by severity</span>
              <select
                value={severity}
                onChange={(event) => handleSeverity(event.target.value)}
                aria-label="Filter cases by severity"
              >
                <option value="">All severities</option>
                {CASE_SEVERITIES.map((item) => (
                  <option key={item} value={item}>
                    {formatLabel(item)}
                  </option>
                ))}
              </select>
            </label>
            <button
              className="secondary-button"
              type="button"
              onClick={() => setReloadKey((key) => key + 1)}
              disabled={loading}
            >
              <Icon name="refresh" size={14} /> Refresh
            </button>
          </div>
        </div>

        {error ? (
          <PageError message={error} onRetry={() => setReloadKey((key) => key + 1)} />
        ) : loading ? (
          <div className="case-loading" aria-live="polite">
            Loading cases from the database…
          </div>
        ) : result?.items.length === 0 ? (
          <div className="case-empty">
            <span className="empty-state-mark">
              <Icon name="cases" size={18} />
            </span>
            <strong>
              {result.total === 0 && !query && !status && !severity
                ? "No investigation cases yet"
                : "No cases match these filters"}
            </strong>
            <p>
              {result.total === 0 && !query && !status && !severity
                ? "Create your first investigation to get started."
                : "Try another search term or status filter."}
            </p>
            {result.total === 0 && !query && !status && !severity && (
              <button className="secondary-button" type="button" onClick={() => setModalCase(null)}>
                Create your first investigation
              </button>
            )}
          </div>
        ) : (
          <>
            <div className="table-scroll case-list-table-wrap">
              <table className="cases-table case-management-table">
                <thead>
                  <tr>
                    <th scope="col">CASE ID</th>
                    <th scope="col">TITLE</th>
                    <th scope="col">ASSIGNED TO</th>
                    <th scope="col">SEVERITY</th>
                    <th scope="col">STATUS</th>
                    <th scope="col">CREATED</th>
                    <th scope="col">LAST UPDATED</th>
                    <th scope="col">
                      <span className="sr-only">Actions</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {result.items.map((item) => (
                    <tr key={item.caseNumber}>
                      <td>
                        <Link
                          className="case-id case-title-link"
                          to={`/cases/${encodeURIComponent(item.caseNumber)}`}
                        >
                          {item.caseNumber}
                        </Link>
                      </td>
                      <td>
                        <Link
                          className="case-title case-title-link"
                          to={`/cases/${encodeURIComponent(item.caseNumber)}`}
                        >
                          {item.title}
                        </Link>
                      </td>
                      <td>{item.assignedTo || "Unassigned"}</td>
                      <td>
                        <SeverityBadge severity={item.severity} />
                      </td>
                      <td>
                        <StatusBadge status={item.status} />
                      </td>
                      <td>{formatDate(item.createdAt)}</td>
                      <td>{formatDate(item.updatedAt)}</td>
                      <td className="case-row-actions">
                        <Link
                          className="table-action-link"
                          to={`/cases/${encodeURIComponent(item.caseNumber)}`}
                        >
                          Details
                        </Link>
                        <button
                          className="table-action-link"
                          type="button"
                          onClick={() => setModalCase(item)}
                        >
                          Edit
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="case-pagination">
              <span>
                Showing {startOffset + 1}–{Math.min(startOffset + result.items.length, result.total)} of{" "}
                {result.total}
              </span>
              <div>
                <button
                  className="secondary-button"
                  type="button"
                  onClick={() => setPage((current) => Math.max(1, current - 1))}
                  disabled={loading || page <= 1}
                >
                  Previous
                </button>
                <span>
                  Page {page} of {pageCount}
                </span>
                <button
                  className="secondary-button"
                  type="button"
                  onClick={() => setPage((current) => Math.min(pageCount, current + 1))}
                  disabled={loading || page >= pageCount}
                >
                  Next
                </button>
              </div>
            </div>
          </>
        )}
      </section>
      {modalCase !== undefined && (
        <CaseFormModal
          caseRecord={modalCase}
          onClose={() => setModalCase(undefined)}
          onSaved={(message) => {
            setModalCase(undefined);
            setNotice(message);
            setReloadKey((key) => key + 1);
          }}
        />
      )}
    </WorkspaceLayout>
  );
}

function CaseFormPage({ editing = false }) {
  const navigate = useNavigate();
  const { caseNumber = "" } = useParams();
  const [record, setRecord] = useState(null);
  const [values, setValues] = useState(EMPTY_CASE_FORM);
  const [loading, setLoading] = useState(editing);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!editing) return undefined;
    const controller = new AbortController();
    setLoading(true);
    getCase(caseNumber, { signal: controller.signal })
      .then((item) => {
        setRecord(item);
        setValues(getInitialCaseValues(item));
      })
      .catch((cause) => {
        if (!controller.signal.aborted) {
          setError(cause instanceof Error ? cause.message : "An unexpected error occurred.");
        }
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, [caseNumber, editing]);

  const handleChange = (event) => {
    setValues((current) => ({ ...current, [event.target.name]: event.target.value }));
  };

  const handleSubmit = async (event) => {
    event.preventDefault();
    setSaving(true);
    setError("");
    try {
      const saved = editing
        ? await updateCase(record?.caseNumber ?? caseNumber, values)
        : await createCase(values);
      navigate(`/cases/${encodeURIComponent(saved.caseNumber)}`, { replace: true });
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "An unexpected error occurred.");
    } finally {
      setSaving(false);
    }
  };

  return (
    <WorkspaceLayout
      mode={loading ? "loading" : error ? "unavailable" : "live"}
      cases={record ? [record] : []}
      selectedCaseId={record?.caseNumber ?? ""}
      onSelectCase={(selected) => selected && navigate(`/cases/${encodeURIComponent(selected)}`)}
      pageTitle={editing ? "Edit case" : "New case"}
      showSearch={false}
    >
      <div className="page-heading">
        <div>
          <span className="eyebrow">
            <span className="eyebrow-dot" /> CASE MANAGEMENT
          </span>
          <h1>{editing ? "Edit case" : "Create a case"}</h1>
          <p>
            {editing
              ? `Update the information for ${record?.caseNumber ?? caseNumber}.`
              : "Create a case record in the configured database."}
          </p>
        </div>
        {record && (
          <span className="page-context">
            <Icon name="cases" size={15} />
            {record.caseNumber}
          </span>
        )}
      </div>

      {error && <PageError message={error} />}
      {loading ? (
        <div className="case-loading">Loading case information…</div>
      ) : editing && !record ? null : (
        <form className="panel case-form" onSubmit={handleSubmit}>
          <CaseFormFields values={values} onChange={handleChange} rows={5} />
          <div className="case-form-actions">
            <Link
              className="secondary-button"
              to={editing && record ? `/cases/${encodeURIComponent(record.caseNumber)}` : "/cases"}
            >
              Cancel
            </Link>
            <button className="primary-button" type="submit" disabled={saving}>
              {saving ? "Saving…" : editing ? "Save changes" : "Create case"}
            </button>
          </div>
        </form>
      )}
    </WorkspaceLayout>
  );
}

function CaseDetailPage() {
  const navigate = useNavigate();
  const { caseNumber = "" } = useParams();
  const [record, setRecord] = useState(null);
  const [status, setStatus] = useState("");
  const [loading, setLoading] = useState(true);
  const [savingStatus, setSavingStatus] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [notes, setNotes] = useState([]);
  const [noteInput, setNoteInput] = useState("");
  const [savingNote, setSavingNote] = useState(false);
  const [aiQuestion, setAiQuestion] = useState("");
  const [aiResult, setAiResult] = useState(null);
  const [loadingAi, setLoadingAi] = useState(false);
  const [error, setError] = useState("");
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setError("");
    Promise.all([
      getCase(caseNumber, { signal: controller.signal }),
      getCaseNotes(caseNumber, { signal: controller.signal }).catch(() => []),
    ])
      .then(([item, caseNotes]) => {
        setRecord(item);
        setStatus(item.status);
        setNotes(Array.isArray(caseNotes) ? caseNotes : []);
      })
      .catch((cause) => {
        if (!controller.signal.aborted) {
          setError(cause instanceof Error ? cause.message : "An unexpected error occurred.");
        }
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, [caseNumber, reloadKey]);

  const handleAddNote = async (event) => {
    event.preventDefault();
    if (!noteInput.trim()) return;
    setSavingNote(true);
    setError("");
    try {
      const created = await addCaseNote(record.caseNumber, noteInput.trim());
      setNotes((prev) => [created, ...prev]);
      setNoteInput("");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Failed to save case note.");
    } finally {
      setSavingNote(false);
    }
  };

  const handleAskAi = async (event) => {
    event.preventDefault();
    setLoadingAi(true);
    setError("");
    try {
      const res = await askAiAssistant({ caseId: record.caseNumber, question: aiQuestion.trim() });
      setAiResult(res);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "AI assistant unavailable.");
    } finally {
      setLoadingAi(false);
    }
  };

  const saveStatus = async (event) => {
    event.preventDefault();
    setSavingStatus(true);
    setError("");
    try {
      const updated = await updateCase(record?.caseNumber ?? caseNumber, { status });
      setRecord(updated);
      setStatus(updated.status);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "An unexpected error occurred.");
    } finally {
      setSavingStatus(false);
    }
  };

  const handleArchive = async () => {
    setDeleting(true);
    setError("");
    try {
      await deleteCase(record.caseNumber);
      navigate("/cases", {
        replace: true,
        state: { notice: `${record.caseNumber} was archived (audit history retained).` },
      });
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "The case could not be archived.");
      setConfirmDelete(false);
    } finally {
      setDeleting(false);
    }
  };

  return (
    <WorkspaceLayout
      mode={loading ? "loading" : error ? "unavailable" : "live"}
      cases={record ? [record] : []}
      selectedCaseId={record?.caseNumber ?? ""}
      onSelectCase={(selected) => selected && navigate(`/cases/${encodeURIComponent(selected)}`)}
      pageTitle="Case details"
      showSearch={false}
    >
      <div className="page-heading">
        <div>
          <span className="eyebrow">
            <span className="eyebrow-dot" /> CASE MANAGEMENT
          </span>
          <h1>{loading ? "Case details" : record?.title ?? "Case not found"}</h1>
          <p>
            {record
              ? `Case ${record.caseNumber} · Created ${formatDate(record.createdAt, true)}`
              : "Review and update a saved case record."}
          </p>
        </div>
        {record && (
          <div className="case-detail-header-actions">
            <Link
              className="secondary-button"
              to={`/analysis/digital-footprint?case=${encodeURIComponent(record.caseNumber)}`}
            >
              <Icon name="footprint" size={14} /> Research URL
            </Link>
            <Link
              className="primary-button"
              to={`/cases/${encodeURIComponent(record.caseNumber)}/edit`}
            >
              Edit case
            </Link>
            {!confirmDelete ? (
              <button
                className="danger-button"
                type="button"
                onClick={() => setConfirmDelete(true)}
                disabled={deleting}
              >
                Archive case
              </button>
            ) : (
              <div className="case-delete-confirm" role="alertdialog" aria-label="Confirm archive case">
                <span>Archive?</span>
                <button
                  className="danger-button"
                  type="button"
                  onClick={handleArchive}
                  disabled={deleting}
                >
                  {deleting ? "Archiving…" : "Confirm"}
                </button>
                <button
                  className="secondary-button"
                  type="button"
                  onClick={() => setConfirmDelete(false)}
                  disabled={deleting}
                >
                  Cancel
                </button>
              </div>
            )}
          </div>
        )}
      </div>

      {error && <PageError message={error} onRetry={() => setReloadKey((key) => key + 1)} />}
      {loading ? (
        <div className="case-loading">Loading case details…</div>
      ) : (
        record && (
          <div className="case-detail-grid">
            <section className="panel case-detail-panel">
              <h2>Case information</h2>
              <dl className="case-detail-list">
                <div>
                  <dt>Case ID</dt>
                  <dd>{record.caseNumber}</dd>
                </div>
                <div>
                  <dt>Title</dt>
                  <dd>{record.title}</dd>
                </div>
                <div>
                  <dt>Assigned to</dt>
                  <dd>{record.assignedTo || "Unassigned"}</dd>
                </div>
                <div>
                  <dt>Reporter</dt>
                  <dd>{record.reporterName || "Not specified"}</dd>
                </div>
                <div>
                  <dt>Severity</dt>
                  <dd>
                    <SeverityBadge severity={record.severity} />
                  </dd>
                </div>
                <div>
                  <dt>Status</dt>
                  <dd>
                    <StatusBadge status={record.status} />
                  </dd>
                </div>
                <div>
                  <dt>Created</dt>
                  <dd>{formatDate(record.createdAt, true)}</dd>
                </div>
                <div>
                  <dt>Last updated</dt>
                  <dd>{formatDate(record.updatedAt, true)}</dd>
                </div>
                <div className="case-description">
                  <dt>Description</dt>
                  <dd>{record.description || "No description provided."}</dd>
                </div>
              </dl>
            </section>
            <section className="panel case-detail-panel">
              <h2>Update case status</h2>
              <p>Changes are saved to the case database.</p>
              <form className="status-update-form" onSubmit={saveStatus}>
                <label>
                  <span>Status</span>
                  <select value={status} onChange={(event) => setStatus(event.target.value)}>
                    {CASE_STATUSES.map((item) => (
                      <option key={item} value={item}>
                        {formatLabel(item)}
                      </option>
                    ))}
                  </select>
                </label>
                <button
                  className="primary-button"
                  type="submit"
                  disabled={savingStatus || status === record.status}
                >
                  {savingStatus ? "Saving…" : "Update status"}
                </button>
              </form>
              <Link className="case-back-link" to="/cases">
                Back to all cases
              </Link>
            </section>
            <section className="panel case-detail-panel case-audit-panel">
              <h2>Investigator Case Notes ({notes.length})</h2>
              <form className="case-form" onSubmit={handleAddNote} style={{ marginBottom: "14px" }}>
                <label>
                  <span>Add investigation note</span>
                  <textarea
                    value={noteInput}
                    onChange={(e) => setNoteInput(e.target.value)}
                    rows={2}
                    placeholder="Document observations, hypotheses, or investigative steps…"
                  />
                </label>
                <button className="secondary-button" type="submit" disabled={savingNote || !noteInput.trim()}>
                  {savingNote ? "Saving note…" : "Save note"}
                </button>
              </form>
              {notes.length > 0 && (
                <ol className="case-audit-timeline">
                  {notes.map((n) => (
                    <li key={n.id}>
                      <span className="case-audit-marker" />
                      <div>
                        <strong>{n.authorName}</strong>
                        <p>{n.content}</p>
                        <time dateTime={n.createdAt}>{formatDate(n.createdAt, true)}</time>
                      </div>
                    </li>
                  ))}
                </ol>
              )}
            </section>
            <section className="panel case-detail-panel case-audit-panel">
              <h2>AI Investigation Assistant (Evidence-Backed)</h2>
              <p>Generates grounded case summaries, identifies missing evidence, and suggests follow-up questions using only authorized records.</p>
              <form className="finding-review-bar" style={{ borderTop: "none", paddingTop: 0 }} onSubmit={handleAskAi}>
                <input
                  value={aiQuestion}
                  onChange={(e) => setAiQuestion(e.target.value)}
                  placeholder="Optional question (e.g. What evidence gaps remain?)"
                />
                <button className="primary-button" type="submit" disabled={loadingAi}>
                  {loadingAi ? "Synthesizing…" : "Generate AI Brief"}
                </button>
              </form>
              {aiResult && (
                <div className="ai-brief-box">
                  <div className="ai-disclaimer">{aiResult.disclaimer}</div>
                  <p>{aiResult.summary}</p>
                  {aiResult.missingEvidenceOrGaps?.length > 0 && (
                    <div>
                      <strong>Evidence Gaps &amp; Next Steps:</strong>
                      <ul>
                        {aiResult.missingEvidenceOrGaps.map((g, idx) => <li key={idx}>{g}</li>)}
                      </ul>
                    </div>
                  )}
                  <div className="forensic-submeta">
                    Citations: {aiResult.citations.join(", ")} · Mode: {aiResult.mode} · External data transmitted: {aiResult.externalDataTransmitted ? "Yes" : "No"}
                  </div>
                </div>
              )}
            </section>
            <section className="panel case-detail-panel case-audit-panel">
              <h2>Case activity</h2>
              <p>Changes recorded in the case audit history.</p>
              {record.auditHistory?.length ? (
                <ol className="case-audit-timeline">
                  {record.auditHistory.map((entry) => (
                    <li key={entry.id}>
                      <span className="case-audit-marker" />
                      <div>
                        <strong>{formatLabel(entry.action.replace("CASE_", ""))}</strong>
                        <p>Actor: {entry.actor}</p>
                        <AuditChangesList changesJson={entry.changesJson} />
                        <time dateTime={entry.createdAt}>{formatDate(entry.createdAt, true)}</time>
                      </div>
                    </li>
                  ))}
                </ol>
              ) : (
                <p className="case-audit-empty">No case activity has been recorded.</p>
              )}
            </section>
          </div>
        )
      )}
    </WorkspaceLayout>
  );
}

export function CasesPage() {
  return <CaseListPage />;
}

export function NewCasePage() {
  return <CaseFormPage />;
}

export function EditCasePage() {
  return <CaseFormPage editing />;
}

export function CaseDetailsPage() {
  return <CaseDetailPage />;
}
