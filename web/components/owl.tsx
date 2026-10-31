/** myOwl logo mark — a watchful owl drawn with the current text colour. */
export function OwlMark({ size = 24, className = "" }: { size?: number; className?: string }) {
  return (
    <svg width={size} height={size} viewBox="0 0 64 64" fill="none" stroke="currentColor" strokeWidth={3.2} strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden>
      <path d="M13 9l9 9q10-4 20 0l9-9v22q0 22-19 26Q13 53 13 31Z" />
      <circle cx="23.5" cy="30" r="7" />
      <circle cx="40.5" cy="30" r="7" />
      <circle cx="23.5" cy="30" r="2.4" fill="currentColor" stroke="none" />
      <circle cx="40.5" cy="30" r="2.4" fill="currentColor" stroke="none" />
      <path d="M29 39l3 4.5 3-4.5Z" fill="currentColor" strokeWidth={2} />
      <path d="M24 48.5l4 2.5 4-2.5 4 2.5 4-2.5" strokeWidth={2.4} />
    </svg>
  );
}
