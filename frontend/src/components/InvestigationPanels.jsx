import { useMemo, useState } from "react";
import { Link } from "react-router-dom";

import Icon from "./Icon.jsx";
import { EmptyState, SectionHeading } from "./DashboardSections.jsx";

const STATUS_OPTIONS = [
  { value: "OPEN", label: "Open" },
  { value: "IN_PROGRESS", label: "In Progress" },
  { value: "ESCALATED", label: "Escalated" },
  { value: "RESOLVED", label: "Resolved" },
  { value: "CLOSED", label: "Closed" },
];

function normalizeStatus(status = "") {
  return status.trim().toUpperCase().replaceAll(" ", "_");
}

function formatStatusLabel(status = "") {
  if (!status) return "Unknown";
  return status
    .toLowerCase()
    .replaceAll("_", " ")
    .split(" ")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function formatDate(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium" }).format(date);
}

function formatDateTime(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(date);
}

function StatusBadge({ status }) {
  const modifier = normalizeStatus(status).toLowerCase().replaceAll("_", "-") || "unknown";
  return <span className={`status-badge status-${modifier}`}><i />{formatStatusLabel(status)}</span>;
}

function PanelSkeleton({ rows = 4 }) {
  return (
    <div className="panel-skeleton" aria-label="Loading dashboard data">
      {Array.from({ length: rows }, (_, index) => <span className="skeleton" key={index} />)}
    </div>
  );
}

export function CasesPanel({ cases, query, loading }) {
  const [statusFilter, setStatusFilter] = useState("ALL");
  const filteredCases = useMemo(() => cases.filter((item) => {
    const matchesStatus = statusFilter === "ALL" || normalizeStatus(item.status) === statusFilter;
    const caseRef = item.caseNumber ?? item.id ?? "";
    const assignee = item.assignedTo ?? item.assignedInvestigator ?? "";
    const searchable = `${caseRef} ${item.title} ${assignee}`.toLowerCase();
    return matchesStatus && searchable.includes(query.trim().toLowerCase());
  }), [cases, query, statusFilter]);

  return (
    <section className="panel cases-panel" id="cases">
      <SectionHeading
        title="Recent investigations"
        subtitle="Case records returned for this workspace"
        action={
          <label className="filter-control">
            <span className="sr-only">Filter cases by status</span>
            <select value={statusFilter} onChange={(event) => setStatusFilter(event.target.value)} aria-label="Filter cases by status">
              <option value="ALL">All statuses</option>
              {STATUS_OPTIONS.map((status) => <option key={status.value} value={status.value}>{status.label}</option>)}
            </select>
          </label>
        }
      />
      {loading ? <PanelSkeleton /> : filteredCases.length === 0 ? (
        <EmptyState
          title={cases.length === 0 ? "No cases available" : "No cases match these filters"}
          detail={cases.length === 0 ? "Create a case in Case Management to see it here." : "Try another search term or status filter."}
        />
      ) : (
        <>
          <div className="table-scroll">
            <table className="cases-table">
              <thead>
                <tr>
                  <th scope="col">CASE ID</th>
                  <th scope="col">INVESTIGATION</th>
                  <th scope="col">ASSIGNED TO</th>
                  <th scope="col">STATUS</th>
                  <th scope="col">CREATED</th>
                  <th scope="col">LAST UPDATED</th>
                </tr>
              </thead>
              <tbody>
                {filteredCases.map((item) => {
                  const caseRef = item.caseNumber ?? item.id;
                  const assignee = item.assignedTo ?? item.assignedInvestigator;
                  return (
                    <tr key={caseRef}>
                      <td>
                        <Link className="case-id case-title-link" to={`/cases/${encodeURIComponent(caseRef)}`}>
                          {caseRef || "—"}
                        </Link>
                      </td>
                      <td>
                        <Link className="case-title case-title-link" to={`/cases/${encodeURIComponent(caseRef)}`}>
                          {item.title || "Untitled case"}
                        </Link>
                      </td>
                      <td>{assignee || "Unassigned"}</td>
                      <td><StatusBadge status={item.status} /></td>
                      <td>{formatDate(item.createdAt)}</td>
                      <td>{formatDate(item.updatedAt)}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          <div className="panel-footnote">Showing {filteredCases.length} of {cases.length} returned case records.</div>
        </>
      )}
    </section>
  );
}

function summarizeChecks(integrity) {
  const checks = Array.isArray(integrity?.verificationChecks) ? integrity.verificationChecks : [];
  const performed = checks.filter((check) =>
    check?.comparisonPerformed === true &&
    typeof check?.algorithm === "string" &&
    check.algorithm.toUpperCase() === "SHA-256" &&
    typeof check.evidenceItemId === "string" &&
    check.evidenceItemId.length > 0 &&
    typeof check.sha256Matches === "boolean",
  );
  const verified = performed.filter((check) =>
    check?.sha256Matches === true,
  ).length;
  const failures = performed.filter((check) =>
    check?.sha256Matches === false,
  ).length;
  const totalItems = Number.isFinite(integrity?.totalItems) ? integrity.totalItems : null;
  const pending = totalItems === null ? null : Math.max(0, totalItems - new Set(performed.map((check) => check.evidenceItemId).filter(Boolean)).size);

  return {
    verified,
    failures: performed.length ? failures : null,
    pending,
    totalItems,
    performed: performed.length,
  };
}

export function EvidenceIntegrityPanel({ integrity, loading }) {
  const summary = summarizeChecks(integrity);

  return (
    <section className="panel integrity-panel" id="integrity">
      <SectionHeading
        title="Evidence integrity"
        subtitle="SHA-256 verification is shown only when the API reports a completed comparison."
        action={<span className={`integrity-state${summary.performed ? " integrity-checked" : ""}`}><Icon name="shield" size={14} />{summary.performed ? "Checks reported" : "Not performed"}</span>}
      />
      {loading ? (
        <div className="integrity-skeleton">{[1, 2, 3].map((item) => <span className="skeleton" key={item} />)}</div>
      ) : (
        <>
          <div className="integrity-summary">
            <div><strong>{summary.totalItems === null ? "—" : summary.totalItems}</strong><span>Total evidence items</span></div>
            <div><strong>{summary.verified}</strong><span>Verified SHA-256 matches</span></div>
            <div><strong>{summary.failures === null ? "—" : summary.failures}</strong><span>SHA-256 mismatches</span></div>
            <div><strong>{summary.pending === null ? "—" : summary.pending}</strong><span>Pending verification</span></div>
          </div>
          <p className="integrity-disclaimer">
            {summary.performed === 0
              ? "No SHA-256 comparisons have been reported. Demo evidence has no real file hashes."
              : `Counts reflect ${summary.performed} comparison record${summary.performed === 1 ? "" : "s"} returned by the API.`}
          </p>
        </>
      )}
    </section>
  );
}

const eventTypes = [
  "All event types",
  "Authentication",
  "File access",
  "Application activity",
  "Evidence collection",
  "Investigation update",
];

export function ActivityTimelinePanel({ events, query, loading }) {
  const [typeFilter, setTypeFilter] = useState("All event types");
  const filteredEvents = useMemo(() => events.filter((event) => {
    const matchesType = typeFilter === "All event types" || event.eventType === typeFilter;
    const searchable = `${event.description} ${event.sourceEvidence} ${event.caseId}`.toLowerCase();
    return matchesType && searchable.includes(query.trim().toLowerCase());
  }), [events, query, typeFilter]);

  return (
    <section className="panel timeline-panel" id="timeline">
      <div id="findings">
        <SectionHeading
          title="Activity timeline"
          subtitle="Recorded facts and analytical findings are labeled separately."
          action={
            <label className="filter-control">
              <span className="sr-only">Filter timeline by event type</span>
              <select value={typeFilter} onChange={(event) => setTypeFilter(event.target.value)} aria-label="Filter timeline by event type">
                {eventTypes.map((type) => <option key={type}>{type}</option>)}
              </select>
            </label>
          }
        />
      </div>
      {loading ? <PanelSkeleton rows={5} /> : filteredEvents.length === 0 ? (
        <EmptyState
          title={events.length === 0 ? "No recorded events" : "No events match these filters"}
          detail={events.length === 0 ? "Activity will appear when event records are returned by the workspace API." : "Try another search term or event type."}
        />
      ) : (
        <div className="timeline-list">
          {filteredEvents.map((event) => (
            <article className="timeline-event" key={event.id}>
              <span className={`timeline-marker${event.recordType === "Analytical finding" ? " marker-finding" : ""}`} />
              <div className="timeline-event-main">
                <div className="timeline-event-heading">
                  <span className="event-type">{event.eventType || "Unspecified event"}</span>
                  <span className={`record-kind${event.recordType === "Analytical finding" ? " record-finding" : ""}`}>
                    {event.recordType === "Analytical finding"
                      ? "Analytical finding"
                      : event.recordType === "Recorded fact"
                        ? "Recorded fact"
                        : "Record type not reported"}
                  </span>
                </div>
                <p>{event.description || "No event description returned."}</p>
                <div className="event-metadata">
                  <span><Icon name="evidence" size={13} />{event.sourceEvidence || "Source not specified"}</span>
                  <span><Icon name="cases" size={13} />{event.caseId || "No case linked"}</span>
                  <span className="analysis-status">{event.analysisStatus || "Status not reported"}</span>
                </div>
              </div>
              <time dateTime={event.occurredAt || undefined}>{formatDateTime(event.occurredAt)}</time>
            </article>
          ))}
        </div>
      )}
    </section>
  );
}
