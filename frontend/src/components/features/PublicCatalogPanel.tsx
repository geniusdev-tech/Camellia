'use client'

import { useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { Globe2, PackageSearch, Rocket } from 'lucide-react'
import { publicPackagesAPI } from '@/lib/api'
import { FeedbackBanner } from '@/components/ui/FeedbackBanner'
import { Pagination } from '@/components/ui/Pagination'

export function PublicCatalogPanel() {
  const [search, setSearch] = useState('')
  const [selectedPackage, setSelectedPackage] = useState('')
  const [page, setPage] = useState(1)
  const [message, setMessage] = useState<{ tone: 'success' | 'error' | 'info'; text: string } | null>(null)

  const listQuery = useQuery({
    queryKey: ['public-packages', search, page],
    queryFn: () => publicPackagesAPI.list({ search: search || undefined, latest: 1, page, page_size: 10 }),
  })

  const detailQuery = useQuery({
    queryKey: ['public-package-detail', selectedPackage],
    enabled: !!selectedPackage,
    queryFn: () => publicPackagesAPI.detail(selectedPackage),
  })

  const downloadMutation = useMutation({
    mutationFn: ({ packageName, version }: { packageName: string; version: string }) =>
      publicPackagesAPI.download(packageName, version),
    onSuccess: (payload) => {
      if (payload.download_url && typeof window !== 'undefined') {
        window.open(payload.download_url, '_blank', 'noopener,noreferrer')
      }
      setMessage({ tone: 'info', text: `Signed URL gerada por ${payload.expires_in}s.` })
    },
    onError: (err) => setMessage({ tone: 'error', text: err instanceof Error ? err.message : 'Falha no download público.' }),
  })

  const packages = listQuery.data?.packages ?? []
  const detail = detailQuery.data
  const pagination = listQuery.data?.pagination

  return (
    <section className="glass rounded-2xl p-5">
      <div className="mb-5 flex items-start justify-between gap-3">
        <div>
          <h2 className="text-lg font-semibold text-white">Catálogo público</h2>
          <p className="text-sm text-gray-400">Consome a API pública de pacotes, latest e versões publicadas.</p>
        </div>
        <div className="flex h-11 w-11 items-center justify-center rounded-2xl bg-primary-600/15 text-primary-300">
          <Globe2 className="h-5 w-5" />
        </div>
      </div>

      {message ? <div className="mb-4"><FeedbackBanner tone={message.tone} message={message.text} /></div> : null}

      <div className="grid gap-5 xl:grid-cols-[0.95fr_1.05fr]">
        <div>
          <label className="mb-3 flex items-center gap-2 rounded-xl border border-white/10 bg-dark-900/60 px-3 py-2">
            <PackageSearch className="h-4 w-4 text-gray-500" />
              <input
                value={search}
                onChange={(e) => {
                  setSearch(e.target.value)
                  setPage(1)
                }}
                placeholder="buscar pacote público"
                className="w-full bg-transparent text-white outline-none"
              />
          </label>

          <div className="space-y-2">
            {packages.map((pkg) => (
              <button
                key={pkg.id}
                onClick={() => setSelectedPackage(pkg.package_name)}
                className={`w-full rounded-2xl border px-4 py-3 text-left ${
                  selectedPackage === pkg.package_name
                    ? 'border-accent/30 bg-accent/10'
                    : 'border-white/[0.08] bg-dark-900/50'
                }`}
              >
                <div className="text-sm font-semibold text-white">{pkg.package_name}</div>
                <div className="text-xs text-gray-500">
                  latest {pkg.package_version} · {pkg.download_count} downloads
                </div>
              </button>
            ))}
          </div>
          <Pagination page={pagination?.page || page} pages={pagination?.pages || 0} onPageChange={setPage} />
        </div>

        <div className="rounded-2xl border border-white/[0.08] bg-dark-900/50 p-4">
          {detail ? (
            <>
              <div className="mb-3 flex items-center justify-between gap-3">
                <div>
                  <div className="text-lg font-semibold text-white">{detail.package_name}</div>
                  <div className="text-sm text-gray-400">{detail.latest.description || 'Sem descrição pública.'}</div>
                </div>
                <span className="rounded-full border border-accent/20 bg-accent/10 px-2 py-1 text-[10px] text-accent">
                  latest {detail.latest.package_version}
                </span>
              </div>

              <div className="mb-3 rounded-xl border border-white/[0.06] bg-dark-950/50 p-3 text-xs text-gray-300">
                {detail.latest.changelog || 'Sem changelog.'}
              </div>

              <div className="space-y-2">
                {detail.versions.map((version) => (
                  <div key={version.id} className="flex items-center justify-between rounded-xl border border-white/[0.06] bg-dark-950/50 px-3 py-2">
                    <div>
                      <div className="text-sm font-medium text-white">{version.package_version}</div>
                      <div className="text-xs text-gray-500">{version.checksum_sha256.slice(0, 16)}...</div>
                    </div>
                    <button
                      onClick={() => downloadMutation.mutate({ packageName: version.package_name, version: version.package_version })}
                      className="inline-flex items-center gap-2 rounded-xl bg-accent px-3 py-2 text-xs font-medium text-dark-950"
                    >
                      <Rocket className="h-3.5 w-3.5" />
                      Download
                    </button>
                  </div>
                ))}
              </div>
            </>
          ) : (
            <div className="text-sm text-gray-500">Selecione um pacote para abrir o detalhe público.</div>
          )}
        </div>
      </div>
    </section>
  )
}
