'use client'

import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Activity, BarChart3, Gauge, PlayCircle } from 'lucide-react'
import { opsAPI, projectsAPI } from '@/lib/api'
import { useAuthStore } from '@/store/auth'
import { FeedbackBanner } from '@/components/ui/FeedbackBanner'
import { Pagination } from '@/components/ui/Pagination'
import { StatusBadge } from '@/components/ui/StatusBadge'
import { canManageOwnerActions, nextJobsPollInterval } from '@/lib/ui'

export function OpsPanel() {
  const qc = useQueryClient()
  const user = useAuthStore((state) => state.user)
  const [projectId, setProjectId] = useState('')
  const [message, setMessage] = useState<{ tone: 'success' | 'error' | 'info'; text: string } | null>(null)
  const [jobPage, setJobPage] = useState(1)
  const isOwner = canManageOwnerActions(user?.role)

  const metricsQuery = useQuery({
    queryKey: ['metrics'],
    queryFn: opsAPI.metrics,
    enabled: user?.role === 'owner',
  })

  const jobsQuery = useQuery({
    queryKey: ['jobs'],
    queryFn: () => opsAPI.listJobs(),
    refetchInterval: (query) => nextJobsPollInterval((query.state.data?.jobs ?? []).map((job) => job.status)),
  })

  const projectsQuery = useQuery({
    queryKey: ['projects', 'ops'],
    queryFn: () => projectsAPI.list({ page_size: 100, sort_by: 'created_at', sort_dir: 'desc' }),
  })

  const scanMutation = useMutation({
    mutationFn: opsAPI.enqueueProjectScan,
    onSuccess: () => {
      setMessage({ tone: 'success', text: 'Job de scan enfileirado.' })
      qc.invalidateQueries({ queryKey: ['jobs'] })
    },
    onError: (err) => setMessage({ tone: 'error', text: err instanceof Error ? err.message : 'Falha ao enfileirar scan.' }),
  })

  const publishMutation = useMutation({
    mutationFn: opsAPI.enqueueProjectPublish,
    onSuccess: () => {
      setMessage({ tone: 'success', text: 'Job de publish enfileirado.' })
      qc.invalidateQueries({ queryKey: ['jobs'] })
      qc.invalidateQueries({ queryKey: ['projects'] })
    },
    onError: (err) => setMessage({ tone: 'error', text: err instanceof Error ? err.message : 'Falha ao enfileirar publish.' }),
  })

  const jobs = jobsQuery.data?.jobs ?? []
  const projects = projectsQuery.data?.projects ?? []
  const metrics = metricsQuery.data?.metrics
  const pagedJobs = jobs.slice((jobPage - 1) * 10, jobPage * 10)
  const totalJobPages = Math.max(1, Math.ceil(jobs.length / 10))

  return (
    <section className="glass rounded-2xl p-5">
      <div className="mb-5 flex items-start justify-between gap-3">
        <div>
          <h2 className="text-lg font-semibold text-white">Operações</h2>
          <p className="text-sm text-gray-400">Jobs assíncronos, scans, publish e métricas por rota.</p>
        </div>
        <div className="flex h-11 w-11 items-center justify-center rounded-2xl bg-accent/10 text-accent">
          <Gauge className="h-5 w-5" />
        </div>
      </div>

      {message ? <div className="mb-4"><FeedbackBanner tone={message.tone} message={message.text} /></div> : null}

      <div className="grid gap-5 xl:grid-cols-[0.9fr_1.1fr]">
        <div className="space-y-4">
          <div className="rounded-2xl border border-white/[0.08] bg-dark-900/50 p-4">
            <div className="mb-2 text-sm font-medium text-white">Enfileirar operação</div>
            <div className="grid gap-2">
              <select
                value={projectId}
                onChange={(e) => setProjectId(e.target.value)}
                className="h-input"
              >
                <option value="">Selecione um projeto</option>
                {projects.map((project) => (
                  <option key={project.id} value={project.id}>
                    {project.package_name}@{project.package_version} · {project.lifecycle_status}
                  </option>
                ))}
              </select>
              <div className="grid gap-2 sm:grid-cols-2">
                <button
                  onClick={() => scanMutation.mutate(projectId)}
                  className="inline-flex items-center justify-center gap-2 rounded-xl border border-white/10 bg-white/5 px-4 py-2 text-sm text-white"
                >
                  <Activity className="h-4 w-4" />
                  Scan
                </button>
                {isOwner ? (
                  <button
                    onClick={() => publishMutation.mutate(projectId)}
                    className="h-btn-primary"
                  >
                    <PlayCircle className="h-4 w-4" />
                    Publish async
                  </button>
                ) : (
                  <div className="rounded-xl border border-white/10 bg-white/5 px-4 py-2 text-sm text-gray-500">
                    Publish async visível apenas para owner.
                  </div>
                )}
              </div>
            </div>
          </div>

          <div className="rounded-2xl border border-white/[0.08] bg-dark-900/50 p-4">
            <div className="mb-2 flex items-center gap-2 text-sm font-medium text-white">
              <BarChart3 className="h-4 w-4 text-accent" />
              Métricas por rota
            </div>
            {!isOwner ? (
              <div className="text-sm text-gray-500">Somente owner visualiza métricas operacionais.</div>
            ) : (
              <div className="max-h-64 space-y-2 overflow-y-auto">
                {Object.entries(metrics?.requests || {}).map(([route, total]) => (
                  <div key={route} className="rounded-xl border border-white/[0.06] bg-dark-950/50 px-3 py-2 text-xs">
                    <div className="text-white">{route}</div>
                    <div className="text-gray-500">{total} requests</div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        <div className="rounded-2xl border border-white/[0.08] bg-dark-900/50 p-4">
          <div className="mb-2 text-sm font-medium text-white">Fila de jobs</div>
          <div className="max-h-80 space-y-2 overflow-y-auto">
            {pagedJobs.map((job) => (
              <div key={job.id} className="rounded-xl border border-white/[0.06] bg-dark-950/50 px-3 py-2 text-xs">
                <div className="flex items-center justify-between gap-3">
                  <div className="font-medium text-white">{job.job_type}</div>
                  <StatusBadge status={job.status} />
                </div>
                <div className="mt-1 text-gray-500">
                  job {job.id.slice(0, 8)} · project {job.project_id?.slice(0, 8) || '-'} · attempts {job.attempts}
                </div>
                {job.error_message ? <div className="mt-1 text-rose-300">{job.error_message}</div> : null}
              </div>
            ))}
            {!jobs.length ? <div className="text-sm text-gray-500">Nenhum job encontrado.</div> : null}
          </div>
          <Pagination page={jobPage} pages={totalJobPages} onPageChange={setJobPage} />
        </div>
      </div>
    </section>
  )
}
