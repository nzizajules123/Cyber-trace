import Icon from "./Icon.jsx";

const metricDefinitions = [
  {
    key: "activeInvestigations",
    label: "Active investigations",
    description: "Cases currently open, in progress, or under review.",
    icon: "cases",
    tone: "cyan",
  },
  {
    key: "evidenceItems",
    label: "Evidence items",
    description: "Items registered in the workspace.",
    icon: "evidence",
    tone: "blue",
  },
  {
    key: "eventsAnalyzed",
    label: "Events analyzed",
    description: "Events processed by the investigation workflow.",
    icon: "timeline",
    tone: "violet",
  },
  {
    key: "findingsRequiringReview",
    label: "Findings requiring review",
    description: "Analytical findings awaiting investigator review.",
    icon: "findings",
    tone: "amber",
  },
];

const numberFormat = new Intl.NumberFormat();

export function SectionHeading({ title, subtitle, action }) {
  return (
    <div className="section-heading">
      <div>
        <h2>{title}</h2>
        {subtitle && <p>{subtitle}</p>}
      </div>
      {action}
    </div>
  );
}

export function EmptyState({ title, detail }) {
  return (
    <div className="empty-state">
      <span className="empty-state-mark"><Icon name="evidence" size={18} /></span>
      <strong>{title}</strong>
      <p>{detail}</p>
    </div>
  );
}

function Skeleton({ className = "" }) {
  return <span aria-hidden="true" className={`skeleton ${className}`} />;
}

export function MetricCards({ metrics, loading }) {
  return (
    <div className="metric-grid" aria-label="Investigation metrics" aria-busy={loading}>
      {metricDefinitions.map((metric) => {
        const value = metrics?.[metric.key]?.value;
        const hasValue = typeof value === "number" && Number.isFinite(value);
        return (
          <article className="metric-card" key={metric.key} title={metric.description}>
            <div className="metric-card-heading">
              <span className={`metric-icon metric-${metric.tone}`}><Icon name={metric.icon} size={17} /></span>
              <span className="metric-help" title={metric.description} aria-label={metric.description}>i</span>
            </div>
            <p>{metric.label}</p>
            {loading ? (
              <Skeleton className="metric-skeleton" />
            ) : (
              <strong className="metric-value">{hasValue ? numberFormat.format(value) : "—"}</strong>
            )}
            <small>{loading ? <Skeleton className="metric-caption-skeleton" /> : metric.description}</small>
          </article>
        );
      })}
    </div>
  );
}

function ChartPanel({ title, detail, children, className = "" }) {
  return (
    <article className={`panel chart-panel ${className}`}>
      <div className="panel-title-row">
        <div>
          <h3>{title}</h3>
          <p>{detail}</p>
        </div>
      </div>
      {children}
    </article>
  );
}

function TrendChart({ points, loading }) {
  if (loading) return <div className="chart-skeleton"><Skeleton /></div>;
  if (!points?.length) {
    return <EmptyState title="No event-volume data" detail="The API has not returned event totals for this period." />;
  }

  const width = 520;
  const height = 145;
  const inset = 12;
  const max = Math.max(1, ...points.map((point) => point.count));
  const coordinates = points.map((point, index) => {
    const x = inset + (index * (width - inset * 2)) / Math.max(points.length - 1, 1);
    const y = height - inset - (point.count / max) * (height - inset * 2);
    return { ...point, x, y };
  });
  const path = coordinates.map((point, index) => `${index === 0 ? "M" : "L"}${point.x},${point.y}`).join(" ");

  return (
    <div className="trend-chart">
      <div className="chart-y-labels"><span>{numberFormat.format(max)}</span><span>{numberFormat.format(Math.round(max / 2))}</span><span>0</span></div>
      <svg viewBox={`0 0 ${width} ${height}`} role="img" aria-label="Event volume over time, shown as event counts">
        {[inset, height / 2, height - inset].map((y) => <line key={y} x1={inset} y1={y} x2={width - inset} y2={y} className="chart-gridline" />)}
        <path d={path} className="trend-line" />
        {coordinates.map((point) => <circle key={point.label} cx={point.x} cy={point.y} r="3" className="trend-point"><title>{point.label}: {numberFormat.format(point.count)} events</title></circle>)}
      </svg>
      <div className="chart-x-labels">
        {coordinates.map((point) => <span key={point.label}>{point.label}</span>)}
      </div>
    </div>
  );
}

function CountBars({ items, loading, emptyTitle, emptyDetail, color = "cyan" }) {
  if (loading) return <div className="bars-skeleton">{[68, 42, 84, 55].map((width, index) => <Skeleton key={index} style={{ width: `${width}%` }} />)}</div>;
  if (!items?.length) return <EmptyState title={emptyTitle} detail={emptyDetail} />;

  const max = Math.max(1, ...items.map((item) => item.count));
  return (
    <div className="count-bars">
      {items.map((item) => (
        <div className="count-bar-row" key={item.label}>
          <span className="count-bar-label">{item.label}</span>
          <span className="count-bar-track" title={`${item.label}: ${numberFormat.format(item.count)}`}>
            <span className={`count-bar-fill fill-${color}`} style={{ width: `${(item.count / max) * 100}%` }} />
          </span>
          <strong>{numberFormat.format(item.count)}</strong>
        </div>
      ))}
    </div>
  );
}

function EvidenceTrend({ points, loading }) {
  if (loading) return <div className="evidence-trend-skeleton">{[38, 63, 47, 80, 56, 90].map((height, index) => <Skeleton key={index} style={{ height: `${height}%` }} />)}</div>;
  if (!points?.length) {
    return <EmptyState title="No collection trend" detail="The API has not returned evidence collection totals for this period." />;
  }

  const max = Math.max(1, ...points.map((point) => point.count));
  return (
    <div className="evidence-trend">
      <div className="trend-bars" role="img" aria-label="Evidence items collected by period, shown as counts">
        {points.map((point) => (
          <div className="trend-bar-column" key={point.label}>
            <span className="trend-bar-value">{numberFormat.format(point.count)}</span>
            <span className="trend-bar-track" title={`${point.label}: ${numberFormat.format(point.count)} evidence items`}>
              <span style={{ height: `${Math.max(3, (point.count / max) * 100)}%` }} />
            </span>
            <small>{point.label}</small>
          </div>
        ))}
      </div>
    </div>
  );
}

function normalizeStatus(status = "") {
  return status.trim().toUpperCase().replaceAll(" ", "_");
}

function StatusDistribution({ cases, loading }) {
  if (loading) return <div className="bars-skeleton">{[50, 75, 35, 60].map((width, index) => <Skeleton key={index} style={{ width: `${width}%` }} />)}</div>;
  if (!cases.length) {
    return <EmptyState title="No case statuses" detail="There are no returned cases to summarize." />;
  }

  const statuses = [
    { key: "OPEN", label: "Open" },
    { key: "IN_PROGRESS", label: "In Progress" },
    { key: "ESCALATED", label: "Escalated" },
    { key: "RESOLVED", label: "Resolved" },
    { key: "CLOSED", label: "Closed" },
  ];
  const counts = statuses.map((item) => ({
    label: item.label,
    count: cases.filter((record) => normalizeStatus(record.status) === item.key).length,
  }));
  return (
    <div className="status-distribution">
      <p className="chart-context">Counts among the {cases.length} cases listed here.</p>
      <CountBars items={counts} color="blue" />
    </div>
  );
}

export function AnalyticsPanels({ analytics, cases, loading }) {
  return (
    <section className="dashboard-section" id="analytics">
      <SectionHeading title="Analysis overview" subtitle="Counts returned for this workspace; no inferred percentages." />
      <div className="analytics-grid">
        <ChartPanel title="Event volume over time" detail="Events by recorded period">
          <TrendChart points={analytics?.eventVolume} loading={loading} />
        </ChartPanel>
        <ChartPanel title="Authentication event distribution" detail="Event counts by category">
          <CountBars
            items={analytics?.authenticationDistribution}
            loading={loading}
            emptyTitle="No authentication data"
            emptyDetail="No authentication event counts were returned."
            color="cyan"
          />
        </ChartPanel>
        <ChartPanel title="Evidence collection trend" detail="Evidence items registered by period">
          <EvidenceTrend points={analytics?.evidenceCollectionTrend} loading={loading} />
        </ChartPanel>
        <ChartPanel title="Investigation status distribution" detail="Cases grouped by workflow status">
          <StatusDistribution cases={cases} loading={loading} />
        </ChartPanel>
      </div>
    </section>
  );
}
