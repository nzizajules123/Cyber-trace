export const CASE_STATUSES = ["OPEN", "IN_PROGRESS", "ESCALATED", "RESOLVED", "CLOSED"];
export const CASE_SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
export const EMPTY_CASE_FORM = {
  title: "",
  description: "",
  assignedTo: "",
  reporterName: "",
  status: "OPEN",
  severity: "MEDIUM",
};

export function formatLabel(value = "") {
  if (!value) return "—";
  return String(value)
    .replace(/([a-z])([A-Z])/g, "$1 $2")
    .replaceAll("_", " ")
    .toLowerCase()
    .split(/\s+/)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

export function formatDate(value, withTime = false) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return new Intl.DateTimeFormat(
    undefined,
    withTime
      ? { dateStyle: "medium", timeStyle: "short" }
      : { dateStyle: "medium" },
  ).format(date);
}

export function getInitialCaseValues(caseRecord) {
  if (!caseRecord) return EMPTY_CASE_FORM;
  return {
    title: caseRecord.title,
    description: caseRecord.description ?? "",
    assignedTo: caseRecord.assignedTo ?? "",
    reporterName: caseRecord.reporterName ?? "",
    status: caseRecord.status,
    severity: caseRecord.severity,
  };
}

export function StatusBadge({ status }) {
  const modifier = status.toLowerCase().replaceAll("_", "-");
  return (
    <span className={`status-badge status-${modifier}`}>
      <i />
      {formatLabel(status)}
    </span>
  );
}

export function SeverityBadge({ severity }) {
  const modifier = severity.toLowerCase();
  return <span className={`severity-badge severity-${modifier}`}>{formatLabel(severity)}</span>;
}

export function CaseFormFields({ values, onChange, rows = 4, autoFocus = false }) {
  return (
    <>
      <label>
        <span>
          Case title <b aria-hidden="true">*</b>
        </span>
        <input
          name="title"
          value={values.title}
          onChange={onChange}
          required
          minLength={1}
          maxLength={200}
          autoComplete="off"
          autoFocus={autoFocus}
        />
      </label>
      <label>
        <span>Description</span>
        <textarea
          name="description"
          value={values.description}
          onChange={onChange}
          maxLength={10000}
          rows={rows}
        />
      </label>
      <div className="case-form-row">
        <label>
          <span>Assigned to</span>
          <input
            name="assignedTo"
            value={values.assignedTo}
            onChange={onChange}
            maxLength={160}
            autoComplete="off"
            placeholder="Optional"
          />
        </label>
        <label>
          <span>Reporter name</span>
          <input
            name="reporterName"
            value={values.reporterName}
            onChange={onChange}
            maxLength={160}
            autoComplete="off"
            placeholder="Optional"
          />
        </label>
      </div>
      <div className="case-form-row">
        <label>
          <span>Severity</span>
          <select name="severity" value={values.severity} onChange={onChange}>
            {CASE_SEVERITIES.map((item) => (
              <option key={item} value={item}>
                {formatLabel(item)}
              </option>
            ))}
          </select>
        </label>
        <label>
          <span>Status</span>
          <select name="status" value={values.status} onChange={onChange}>
            {CASE_STATUSES.map((item) => (
              <option key={item} value={item}>
                {formatLabel(item)}
              </option>
            ))}
          </select>
        </label>
      </div>
    </>
  );
}
