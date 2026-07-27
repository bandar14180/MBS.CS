// Lightweight inline stroke icons (currentColor) for services & agents.
type P = { className?: string };
const base = "none";
function Svg({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <svg viewBox="0 0 24 24" fill={base} stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden>
      {children}
    </svg>
  );
}

export const Icons = {
  ai: (p: P) => (
    <Svg className={p.className}>
      <rect x="4" y="4" width="16" height="16" rx="4" />
      <circle cx="12" cy="12" r="2.5" />
      <path d="M12 2v2M12 20v2M2 12h2M20 12h2" />
    </Svg>
  ),
  web: (p: P) => (
    <Svg className={p.className}>
      <circle cx="12" cy="12" r="9" />
      <path d="M3 12h18M12 3c2.5 2.5 2.5 15 0 18M12 3c-2.5 2.5-2.5 15 0 18" />
    </Svg>
  ),
  api: (p: P) => (
    <Svg className={p.className}>
      <path d="M8 8l-4 4 4 4M16 8l4 4-4 4M13 6l-2 12" />
    </Svg>
  ),
  cloud: (p: P) => (
    <Svg className={p.className}>
      <path d="M7 18a4 4 0 010-8 5 5 0 019.6-1.3A3.5 3.5 0 1117.5 18H7z" />
    </Svg>
  ),
  network: (p: P) => (
    <Svg className={p.className}>
      <circle cx="12" cy="5" r="2" />
      <circle cx="5" cy="19" r="2" />
      <circle cx="19" cy="19" r="2" />
      <path d="M12 7v4M12 11l-5 6M12 11l5 6" />
    </Svg>
  ),
  vuln: (p: P) => (
    <Svg className={p.className}>
      <path d="M12 3l8 4v5c0 5-3.5 8-8 9-4.5-1-8-4-8-9V7l8-4z" />
      <path d="M12 8v4M12 15h.01" />
    </Svg>
  ),
  report: (p: P) => (
    <Svg className={p.className}>
      <path d="M7 3h7l5 5v13H7z" />
      <path d="M14 3v5h5M9 13h6M9 17h6" />
    </Svg>
  ),
  recon: (p: P) => (
    <Svg className={p.className}>
      <circle cx="11" cy="11" r="6" />
      <path d="M20 20l-4.5-4.5M11 8v6M8 11h6" />
    </Svg>
  ),
  validate: (p: P) => (
    <Svg className={p.className}>
      <path d="M12 3l8 4v5c0 5-3.5 8-8 9-4.5-1-8-4-8-9V7l8-4z" />
      <path d="M9 12l2 2 4-4" />
    </Svg>
  ),
  risk: (p: P) => (
    <Svg className={p.className}>
      <path d="M10.3 4l-8 14h16z" />
      <path d="M10.3 10v3M10.3 16h.01" />
      <path d="M14 6l7 0M17.5 3l3.5 3-3.5 3" />
    </Svg>
  ),
  shield: (p: P) => (
    <Svg className={p.className}>
      <path d="M12 3l8 4v5c0 5-3.5 8-8 9-4.5-1-8-4-8-9V7l8-4z" />
    </Svg>
  ),
  lock: (p: P) => (
    <Svg className={p.className}>
      <rect x="5" y="10" width="14" height="10" rx="2" />
      <path d="M8 10V7a4 4 0 018 0v3" />
    </Svg>
  ),
  database: (p: P) => (
    <Svg className={p.className}>
      <ellipse cx="12" cy="5" rx="7" ry="3" />
      <path d="M5 5v14c0 1.7 3.1 3 7 3s7-1.3 7-3V5M5 12c0 1.7 3.1 3 7 3s7-1.3 7-3" />
    </Svg>
  ),
  frameworks: (p: P) => (
    <Svg className={p.className}>
      <rect x="3" y="3" width="7" height="7" rx="1.5" />
      <rect x="14" y="3" width="7" height="7" rx="1.5" />
      <rect x="3" y="14" width="7" height="7" rx="1.5" />
      <path d="M14 17.5h7M17.5 14v7" />
    </Svg>
  ),
};

export type IconKey = keyof typeof Icons;
