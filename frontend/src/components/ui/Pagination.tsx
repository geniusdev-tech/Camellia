'use client'

interface PaginationProps {
  page: number
  pages: number
  onPageChange: (page: number) => void
}

export function Pagination({ page, pages, onPageChange }: PaginationProps) {
  if (pages <= 1) return null

  const items = Array.from({ length: pages }, (_, index) => index + 1).slice(
    Math.max(0, page - 3),
    Math.max(5, Math.min(pages, page + 2)),
  )

  return (
    <div className="flex items-center justify-between gap-3 pt-4">
      <button
        onClick={() => onPageChange(page - 1)}
        disabled={page <= 1}
        className="rounded-xl border border-white/10 bg-white/5 px-3 py-2 text-sm text-white disabled:opacity-40"
      >
        Anterior
      </button>
      <div className="flex flex-wrap items-center justify-center gap-2">
        {items.map((item) => (
          <button
            key={item}
            onClick={() => onPageChange(item)}
            className={`h-9 min-w-9 rounded-xl px-3 text-sm ${
              item === page
                ? 'bg-accent text-dark-950'
                : 'border border-white/10 bg-white/5 text-white'
            }`}
          >
            {item}
          </button>
        ))}
      </div>
      <button
        onClick={() => onPageChange(page + 1)}
        disabled={page >= pages}
        className="rounded-xl border border-white/10 bg-white/5 px-3 py-2 text-sm text-white disabled:opacity-40"
      >
        Próxima
      </button>
    </div>
  )
}
