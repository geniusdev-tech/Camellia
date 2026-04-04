'use client'

export function Skeleton({ className }: { className: string }) {
  return (
    <div
      role="presentation"
      aria-hidden="true"
      className={`animate-pulse rounded-xl bg-white/5 ${className}`}
    />
  );
}
