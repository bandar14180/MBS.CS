// Abstract AI-shield mark: a hexagonal security shield with a neural node core.
export function Logo({ className = "" }: { className?: string }) {
  return (
    <svg viewBox="0 0 40 40" fill="none" className={className} aria-hidden>
      <defs>
        <linearGradient id="mbsLogo" x1="0" y1="0" x2="40" y2="40" gradientUnits="userSpaceOnUse">
          <stop stopColor="#22d3ee" />
          <stop offset="1" stopColor="#7c5cff" />
        </linearGradient>
      </defs>
      <path
        d="M20 3l13 5.2v9.3c0 8.3-5.4 15.2-13 19.2-7.6-4-13-10.9-13-19.2V8.2L20 3z"
        stroke="url(#mbsLogo)"
        strokeWidth="2"
        fill="rgba(34,211,238,0.06)"
      />
      <circle cx="20" cy="18" r="3.2" fill="url(#mbsLogo)" />
      <g stroke="url(#mbsLogo)" strokeWidth="1.6" strokeLinecap="round">
        <path d="M20 18l-6 5" />
        <path d="M20 18l6 5" />
        <path d="M20 18v-6" />
      </g>
      <g fill="url(#mbsLogo)">
        <circle cx="14" cy="23" r="1.8" />
        <circle cx="26" cy="23" r="1.8" />
        <circle cx="20" cy="12" r="1.8" />
      </g>
    </svg>
  );
}
