const iconPaths = {
  dashboard: <><rect x="3" y="3" width="7" height="7" rx="1.5" /><rect x="14" y="3" width="7" height="7" rx="1.5" /><rect x="14" y="14" width="7" height="7" rx="1.5" /><rect x="3" y="14" width="7" height="7" rx="1.5" /></>,
  cases: <><rect x="3" y="7" width="18" height="14" rx="2" /><path d="M8 7V5a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2M3 12h18M10 12v2h4v-2" /></>,
  timeline: <><circle cx="12" cy="12" r="9" /><path d="M12 7v5l3 2" /></>,
  evidence: <><path d="M3 6a2 2 0 0 1 2-2h5l2 2h7a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V6Z" /><path d="M8 13h8M8 16h5" /></>,
  integrity: <><path d="M12 22s8-4 8-11V5l-8-3-8 3v6c0 7 8 11 8 11Z" /><path d="m9 12 2 2 4-4" /></>,
  custody: <><circle cx="6" cy="5" r="2" /><circle cx="18" cy="19" r="2" /><path d="M6 7v4a3 3 0 0 0 3 3h6a3 3 0 0 1 3 3v0M18 17v-4a3 3 0 0 0-3-3H9a3 3 0 0 1-3-3" /></>,
  footprint: <><circle cx="12" cy="12" r="9" /><path d="M3 12h18M12 3a15 15 0 0 1 0 18M12 3a15 15 0 0 0 0 18" /></>,
  logs: <><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" /><path d="M14 2v6h6M8 13h8M8 17h8" /></>,
  correlate: <><circle cx="6" cy="7" r="2" /><circle cx="18" cy="7" r="2" /><circle cx="12" cy="17" r="2" /><path d="m8 8 3 7m5-7-3 7m-5-8h8" /></>,
  findings: <><path d="M10 2h4M12 14v4m-7.5 4h15a2 2 0 0 0 1.7-3L14 5a2 2 0 0 0-3.4 0l-7.2 14a2 2 0 0 0 1.7 3Z" /></>,
  reports: <><path d="M3 3v18h18M8 15l4-4 4 3 5-7" /></>,
  investigators: <><circle cx="9" cy="8" r="3" /><path d="M3 20a6 6 0 0 1 12 0m3-12a3 3 0 0 1 0 6m1 2a5 5 0 0 1 2 4" /></>,
  audit: <><path d="M12 8v4l3 2" /><circle cx="12" cy="12" r="9" /><path d="M4 4 2 6" /></>,
  settings: <><circle cx="12" cy="12" r="3" /><path d="m19.4 15 .1.1 1.4 1.1-1.4 2.4-1.7-.6a8 8 0 0 1-1.5.9l-.3 1.8h-2.8l-.3-1.8a8 8 0 0 1-1.5-.9l-1.7.6-1.4-2.4L7.5 15a8 8 0 0 1 0-1.8l-1.4-1.1 1.4-2.4 1.7.6a8 8 0 0 1 1.5-.9l.3-1.8h2.8l.3 1.8a8 8 0 0 1 1.5.9l1.7-.6 1.4 2.4-1.4 1.1a8 8 0 0 1 .1 1.8Z" /></>,
  search: <><circle cx="10.8" cy="10.8" r="6.8" /><path d="m16 16 4.5 4.5" /></>,
  bell: <><path d="M18 8a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9M10 21h4" /></>,
  down: <path d="m7 10 5 5 5-5" />,
  chevron: <path d="m9 18 6-6-6-6" />,
  menu: <><path d="M4 6h16M4 12h16M4 18h16" /></>,
  shield: <><path d="M12 22s8-4 8-11V5l-8-3-8 3v6c0 7 8 11 8 11Z" /><path d="m9 12 2 2 4-4" /></>,
  plus: <><path d="M12 5v14M5 12h14" /></>,
  refresh: <><path d="M20 7v5h-5M4 17v-5h5" /><path d="M5.5 9A7 7 0 0 1 18 6l2 2m-16 8 2 2a7 7 0 0 0 12.5-3" /></>,
};

export default function Icon({ name, size = 18, className = "" }) {
  return (
    <svg
      aria-hidden="true"
      className={className}
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.7"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      {iconPaths[name] ?? iconPaths.dashboard}
    </svg>
  );
}
