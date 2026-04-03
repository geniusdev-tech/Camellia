'use client'

import { useEffect, useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { usePathname, useRouter, useSearchParams } from 'next/navigation'
import { ArrowDownToLine, Clock3, FolderSearch, ShieldCheck, Trash2, Workflow } from 'lucide-react'
import { opsAPI, projectsAPI } from '@/lib/api'
import { useAuthStore } from '@/store/auth'
import { canChangeVisibility, canManageOwnerActions, nextJobsPollInterval, visibleWorkflowTargets } from '@/lib/ui'
import type { ShareGrantInput } from '@/lib/types'
import { EmptyState } from '@/components/ui/EmptyState'
import { FeedbackBanner } from '@/components/ui/FeedbackBanner'
import { Modal } from '@/components/ui/Modal'
import { Pagination } from '@/components/ui/Pagination'
import { Skeleton } from '@/components/ui/Skeleton'
import { StatusBadge } from '@/components/ui/StatusBadge'
import { useToastStore } from '@/store/toast'
import { AuditLogPanel } from './AuditLogPanel'

function InfoRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between gap-4 border-b border-white/[0.04] py-2 text-sm last:border-b-0">
      <span className="text-gray-500">{label}</span>
      <span className="text-right font-mono text-white">{value}</span>
    </div>
  )
}

type FeedbackState = { tone: 'success' | 'error' | 'info'; message: string } | null

export function RepositoryControlCenter({ currentProjectId }: { currentProjectId?: string } = {}) {
  const qc = useQueryClient()
  const router = useRouter()
  const pathname = usePathname()
  const searchParams = useSearchParams()
  const authUser = useAuthStore((state) => state.user)
  const isOwner = canManageOwnerActions(authUser?.role)
  const pushToast = useToastStore((state) => state.push)

  const [selectedId, setSelectedId] = useState<string | null>(currentProjectId ?? null)
  const [feedback, setFeedback] = useState<FeedbackState>(null)
  const [statusModalOpen, setStatusModalOpen] = useState(false)
  const [metadataModalOpen, setMetadataModalOpen] = useState(false)
  const [shareModalOpen, setShareModalOpen] = useState(false)
  const [deleteModalOpen, setDeleteModalOpen] = useState(false)
  const [pendingStatus, setPendingStatus] = useState('')
  const [statusReason, setStatusReason] = useState('')
  const [metadataForm, setMetadataForm] = useState({ description: '', changelog: '', metadata: '{}' })
  const [shareForm, setShareForm] = useState<ShareGrantInput[]>([])

  const page = Math.max(Number(searchParams.get('page') || '1') || 1, 1)
  const search = searchParams.get('search') || ''
  const statusFilter = searchParams.get('status') || ''
  const visibilityFilter = searchParams.get('visibility') || ''

  function currentBasePath(projectId?: string | null) {
    return projectId ? `/repository/${projectId}` : '/repository'
  }

  function replaceQuery(next: Record<string, string | number | null | undefined>, projectId?: string | null) {
    const params = new URLSearchParams(searchParams.toString())
    Object.entries(next).forEach(([key, value]) => {
      if (value === null || value === undefined || value === '') {
        params.delete(key)
      } else {
        params.set(key, String(value))
      }
    })
    const qs = params.toString()
    const basePath = currentBasePath(projectId ?? currentProjectId ?? selectedId)
    router.replace(qs ? `${basePath}?${qs}` : basePath)
  }

  const listQuery = useQuery({
    queryKey: ['projects', { page, search, statusFilter, visibilityFilter }],
    queryFn: () => projectsAPI.list({
      page,
      page_size: 12,
      search: search || undefined,
      status: statusFilter || undefined,
      visibility: visibilityFilter || undefined,
      sort_by: 'created_at',
      sort_dir: 'desc',
    }),
  })

  const projects = listQuery.data?.projects ?? []
  const pagination = listQuery.data?.pagination
  const selectedProject = useMemo(
    () => projects.find((project) => project.id === selectedId) ?? projects[0] ?? null,
    [projects, selectedId],
  )
  const detailTargetId = currentProjectId || selectedId || selectedProject?.id || null

  useEffect(() => {
    if (selectedProject) {
      setSelectedId(selectedProject.id)
    }
  }, [selectedProject])

  useEffect(() => {
    if (currentProjectId) {
      setSelectedId(currentProjectId)
    }
  }, [currentProjectId])

  const detailQuery = useQuery({
    queryKey: ['project-detail', detailTargetId],
    enabled: !!detailTargetId,
    queryFn: () => projectsAPI.get(detailTargetId!),
  })

  const versionMatrixQuery = useQuery({
    queryKey: ['project-versions', detailQuery.data?.project?.package_name ?? selectedProject?.package_name],
    enabled: !!(detailQuery.data?.project?.package_name ?? selectedProject?.package_name),
    queryFn: () => projectsAPI.versionMatrix((detailQuery.data?.project?.package_name ?? selectedProject?.package_name)!),
  })

  const jobsQuery = useQuery({
    queryKey: ['jobs', detailTargetId],
    enabled: !!detailTargetId,
    queryFn: () => opsAPI.listJobs(detailTargetId!),
    refetchInterval: (query) => nextJobsPollInterval((query.state.data?.jobs ?? []).map((job) => job.status)),
  })

  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ['projects'] })
    qc.invalidateQueries({ queryKey: ['jobs'] })
      if (detailTargetId) qc.invalidateQueries({ queryKey: ['project-detail', detailTargetId] })
    if (selectedProject?.package_name) qc.invalidateQueries({ queryKey: ['project-versions', selectedProject.package_name] })
  }

  const updateMutation = useMutation({
    mutationFn: ({ projectId, payload }: { projectId: string; payload: Record<string, unknown> }) =>
      projectsAPI.update(projectId, payload),
    onSuccess: () => {
      setFeedback({ tone: 'success', message: 'Projeto atualizado.' })
      pushToast('success', 'Projeto atualizado.')
      invalidate()
      setStatusModalOpen(false)
      setMetadataModalOpen(false)
      setShareModalOpen(false)
    },
    onError: (err) => setFeedback({ tone: 'error', message: err instanceof Error ? err.message : 'Falha ao atualizar projeto.' }),
  })

  const deleteMutation = useMutation({
    mutationFn: (projectId: string) => projectsAPI.remove(projectId),
    onSuccess: () => {
      setFeedback({ tone: 'success', message: 'Projeto removido.' })
      pushToast('success', 'Projeto removido.')
      invalidate()
      setSelectedId(null)
      setDeleteModalOpen(false)
      router.replace('/repository')
    },
    onError: (err) => setFeedback({ tone: 'error', message: err instanceof Error ? err.message : 'Falha ao remover projeto.' }),
  })

  const downloadMutation = useMutation({
    mutationFn: (projectId: string) => projectsAPI.download(projectId),
    onSuccess: (payload) => {
      if (payload.download_url && typeof window !== 'undefined') {
        window.open(payload.download_url, '_blank', 'noopener,noreferrer')
      }
      setFeedback({ tone: 'info', message: `Signed URL gerada por ${payload.expires_in}s.` })
      pushToast('info', `Signed URL gerada por ${payload.expires_in}s.`)
      invalidate()
    },
    onError: (err) => setFeedback({ tone: 'error', message: err instanceof Error ? err.message : 'Falha no download.' }),
  })

  const enqueuePublishMutation = useMutation({
    mutationFn: (projectId: string) => opsAPI.enqueueProjectPublish(projectId),
    onSuccess: (payload) => {
      setFeedback({ tone: 'success', message: `Publish async enfileirado. Job ${String(payload.job_id || '').slice(0, 8)}.` })
      pushToast('success', 'Publish async enfileirado.')
      invalidate()
    },
    onError: (err) => setFeedback({ tone: 'error', message: err instanceof Error ? err.message : 'Falha ao enfileirar publish.' }),
  })

  const detail = detailQuery.data?.project ?? selectedProject
  const history = detailQuery.data?.history ?? []
  const versions = versionMatrixQuery.data?.versions ?? []
  const projectJobs = jobsQuery.data?.jobs ?? []

  useEffect(() => {
    if (!detail) return
      setMetadataForm({
        description: detail.description || '',
        changelog: detail.changelog || '',
        metadata: JSON.stringify(detail.metadata || {}, null, 2),
      })
      setShareForm(detail.share_grants.map((grant) => ({
        user_id: grant.user_id,
        grant_role: grant.grant_role,
        expires_at: grant.expires_at ?? null,
      })))
  }, [detail?.id])

  const visibleTargets = visibleWorkflowTargets(authUser?.role)

  return (
    <>
      <section className="grid gap-5 xl:grid-cols-[1.1fr_0.9fr]">
        <div className="glass rounded-2xl p-5">
          <div className="mb-4 flex items-end justify-between gap-4">
            <div>
              <h2 className="text-lg font-semibold text-white">Repositório</h2>
              <p className="text-sm text-gray-400">Tabela paginada com filtros persistidos na URL.</p>
            </div>
          </div>

          {feedback ? <div className="mb-4"><FeedbackBanner tone={feedback.tone} message={feedback.message} /></div> : null}

          <div className="mb-4 grid gap-3 md:grid-cols-3">
            <label className="space-y-1 text-sm md:col-span-2">
              <span className="text-gray-400">Busca</span>
              <div className="flex items-center gap-2 rounded-xl border border-white/10 bg-dark-900/70 px-3 py-2">
                <FolderSearch className="h-4 w-4 text-gray-500" />
                <input
                  value={search}
                  onChange={(e) => replaceQuery({ search: e.target.value, page: 1 })}
                  placeholder="pacote, versão, checksum, descrição"
                  className="w-full bg-transparent text-white outline-none"
                />
              </div>
            </label>

            <label className="space-y-1 text-sm">
              <span className="text-gray-400">Status</span>
              <select
                value={statusFilter}
                onChange={(e) => replaceQuery({ status: e.target.value, page: 1 })}
                className="w-full rounded-xl border border-white/10 bg-dark-900/70 px-3 py-2 text-white outline-none"
              >
                <option value="">todos</option>
                <option value="draft">draft</option>
                <option value="submitted">submitted</option>
                <option value="approved">approved</option>
                <option value="published">published</option>
                <option value="archived">archived</option>
                <option value="rejected">rejected</option>
              </select>
            </label>

            <label className="space-y-1 text-sm">
              <span className="text-gray-400">Visibilidade</span>
              <select
                value={visibilityFilter}
                onChange={(e) => replaceQuery({ visibility: e.target.value, page: 1 })}
                className="w-full rounded-xl border border-white/10 bg-dark-900/70 px-3 py-2 text-white outline-none"
              >
                <option value="">todas</option>
                <option value="private">private</option>
                <option value="public">public</option>
                <option value="shared">shared</option>
              </select>
            </label>
          </div>

            <div className="space-y-3">
              {projects.map((project) => (
                <button
                  key={project.id}
                  onClick={() => {
                    setSelectedId(project.id)
                    replaceQuery({}, project.id)
                  }}
                  className={`w-full rounded-2xl border px-4 py-3 text-left transition-all ${
                    selectedProject?.id === project.id
                      ? 'border-accent/30 bg-accent/10'
                    : 'border-white/[0.08] bg-dark-900/50 hover:border-white/15'
                }`}
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <div className="truncate text-sm font-semibold text-white">
                      {project.package_name}@{project.package_version}
                    </div>
                    <div className="truncate text-xs text-gray-500">{project.filename}</div>
                    <div className="mt-2 flex flex-wrap gap-2">
                      <StatusBadge status={project.lifecycle_status} />
                      <span className="rounded-full border border-white/10 px-2 py-1 text-[10px] text-gray-300">{project.visibility}</span>
                      {project.is_latest ? <span className="rounded-full border border-accent/20 bg-accent/10 px-2 py-1 text-[10px] text-accent">latest</span> : null}
                    </div>
                  </div>
                  <div className="text-right text-xs text-gray-500">
                    <div>{(project.size_bytes / 1024 / 1024).toFixed(2)} MB</div>
                    <div>{project.download_count} downloads</div>
                  </div>
                </div>
              </button>
              ))}

              {listQuery.isLoading ? (
                <>
                  <Skeleton className="h-24 w-full" />
                  <Skeleton className="h-24 w-full" />
                  <Skeleton className="h-24 w-full" />
                </>
              ) : null}

              {!projects.length && !listQuery.isLoading ? (
                <EmptyState
                  title="Nenhum projeto encontrado"
                  text="Ajuste os filtros, mude a paginação ou publique um novo pacote."
                />
              ) : null}
            </div>

          <Pagination
            page={pagination?.page || page}
            pages={pagination?.pages || 0}
            onPageChange={(nextPage) => replaceQuery({ page: nextPage })}
          />
        </div>

        <div className="space-y-5">
          <section className="glass rounded-2xl p-5">
            <div className="mb-4 flex items-center justify-between gap-3">
              <div>
                <h3 className="text-base font-semibold text-white">Detalhe do release</h3>
                <p className="text-sm text-gray-400">Metadados, ACL, workflow e jobs do projeto selecionado.</p>
              </div>
              {detail ? <StatusBadge status={detail.lifecycle_status} /> : null}
            </div>

            {detail ? (
              <>
                <div className="mb-4 rounded-2xl border border-white/[0.08] bg-dark-900/60 p-4">
                  <div className="text-lg font-semibold text-white">{detail.package_name}@{detail.package_version}</div>
                  <div className="mt-1 text-sm text-gray-400">{detail.description || 'Sem descrição.'}</div>
                </div>

                <div className="space-y-1">
                  <InfoRow label="Checksum SHA-256" value={detail.checksum_sha256 || '-'} />
                  <InfoRow label="Entries ZIP" value={String(detail.zip_entry_count)} />
                  <InfoRow label="Uncompressed" value={`${(detail.uncompressed_size_bytes / 1024 / 1024).toFixed(2)} MB`} />
                  <InfoRow label="Downloads" value={String(detail.download_count)} />
                  <InfoRow label="Share grants" value={String(detail.share_grants.length)} />
                  <InfoRow label="Team grants" value={String(detail.team_grants.length)} />
                </div>

                <div className="mt-4 grid gap-2 sm:grid-cols-2">
                  <button
                    onClick={() => downloadMutation.mutate(detail.id)}
                    className="inline-flex items-center justify-center gap-2 rounded-xl bg-accent px-4 py-2 text-sm font-medium text-dark-950"
                  >
                    <ArrowDownToLine className="h-4 w-4" />
                    Download
                  </button>
                  <button
                    onClick={() => setDeleteModalOpen(true)}
                    className="inline-flex items-center justify-center gap-2 rounded-xl border border-rose-400/20 bg-rose-400/10 px-4 py-2 text-sm font-medium text-rose-200"
                  >
                    <Trash2 className="h-4 w-4" />
                    Remover
                  </button>
                </div>

                <div className="mt-4 grid gap-2 sm:grid-cols-2">
                  <button
                    onClick={() => setMetadataModalOpen(true)}
                    className="rounded-xl border border-white/10 bg-white/5 px-4 py-2 text-sm text-white"
                  >
                    Editar metadata
                  </button>
                  <button
                    onClick={() => setShareModalOpen(true)}
                    className="rounded-xl border border-white/10 bg-white/5 px-4 py-2 text-sm text-white"
                  >
                    Configurar grants
                  </button>
                </div>

                <div className="mt-4 grid gap-2 sm:grid-cols-3">
                  {['private', 'public', 'shared'].map((visibility) => (
                    <button
                      key={visibility}
                      onClick={() => updateMutation.mutate({ projectId: detail.id, payload: { visibility } })}
                      disabled={!canChangeVisibility(authUser?.role)}
                      className={`rounded-xl border px-3 py-2 text-xs ${detail.visibility === visibility ? 'border-accent/30 bg-accent/10 text-accent' : 'border-white/10 bg-white/5 text-gray-300'}`}
                    >
                      visibility: {visibility}
                    </button>
                  ))}
                </div>

                <div className="mt-4">
                  <div className="mb-2 flex items-center gap-2 text-sm font-medium text-white">
                    <Workflow className="h-4 w-4 text-accent" />
                    Workflow
                  </div>
                  <div className="grid gap-2 sm:grid-cols-3">
                    {visibleTargets.map((status) => (
                      <button
                        key={status}
                        onClick={() => {
                          setPendingStatus(status)
                          setStatusReason(detail.status_reason || '')
                          setStatusModalOpen(true)
                        }}
                        className="rounded-xl border border-white/10 bg-white/5 px-3 py-2 text-xs text-gray-300"
                      >
                        {status}
                      </button>
                    ))}
                  </div>
                  {isOwner ? (
                    <button
                      onClick={() => enqueuePublishMutation.mutate(detail.id)}
                      className="mt-3 inline-flex items-center gap-2 rounded-xl bg-primary-600/20 px-4 py-2 text-sm text-primary-200"
                    >
                      Publish async
                    </button>
                  ) : null}
                </div>

                <div className="mt-4">
                  <div className="mb-2 flex items-center gap-2 text-sm font-medium text-white">
                    <Clock3 className="h-4 w-4 text-accent" />
                    Histórico
                  </div>
                  <div className="max-h-52 space-y-2 overflow-y-auto">
                    {history.map((event) => (
                      <div key={event.id} className="rounded-xl border border-white/[0.06] bg-dark-900/50 px-3 py-2 text-xs">
                        <div className="text-white">{event.from_status || 'none'} → {event.to_status}</div>
                        <div className="text-gray-500">{new Date(event.created_at).toLocaleString('pt-BR')}</div>
                        {event.reason ? <div className="mt-1 text-gray-300">{event.reason}</div> : null}
                      </div>
                    ))}
                  </div>
                </div>

                <div className="mt-4">
                  <div className="mb-2 flex items-center gap-2 text-sm font-medium text-white">
                    <ShieldCheck className="h-4 w-4 text-accent" />
                    Jobs ligados ao projeto
                  </div>
                  <div className="max-h-44 space-y-2 overflow-y-auto">
                    {projectJobs.map((job) => (
                      <div key={job.id} className="flex items-start justify-between rounded-xl border border-white/[0.06] bg-dark-900/50 px-3 py-2 text-xs">
                        <div>
                          <div className="text-white">{job.job_type}</div>
                          <div className="text-gray-500">{job.id.slice(0, 8)} · attempts {job.attempts}</div>
                        </div>
                        <StatusBadge status={job.status} />
                      </div>
                    ))}
                    {!projectJobs.length ? <div className="text-xs text-gray-500">Nenhum job relacionado.</div> : null}
                  </div>
                </div>

                <div className="mt-4">
                  <div className="mb-2 flex items-center gap-2 text-sm font-medium text-white">
                    <ShieldCheck className="h-4 w-4 text-accent" />
                    Matriz de versões do pacote
                  </div>
                  <div className="max-h-44 space-y-2 overflow-y-auto">
                    {versions.map((project) => (
                      <div key={project.id} className="flex items-center justify-between rounded-xl border border-white/[0.06] bg-dark-900/50 px-3 py-2 text-xs">
                        <span className="text-white">{project.package_version}</span>
                        <StatusBadge status={project.lifecycle_status} />
                      </div>
                    ))}
                  </div>
                </div>

                <div className="mt-4">
                  <div className="mb-2 text-sm font-medium text-white">Auditoria relacionada</div>
                  <AuditLogPanel projectId={detail.id} packageName={detail.package_name} />
                </div>
              </>
            ) : (
              <div className="text-sm text-gray-500">Selecione um projeto para ver o detalhe.</div>
            )}
          </section>
        </div>
      </section>

      <Modal
        open={statusModalOpen}
        title={`Alterar status para ${pendingStatus}`}
        onClose={() => setStatusModalOpen(false)}
        footer={(
          <>
            <button onClick={() => setStatusModalOpen(false)} className="rounded-xl border border-white/10 bg-white/5 px-4 py-2 text-sm text-white">Cancelar</button>
            <button
              onClick={() => detail && updateMutation.mutate({
                projectId: detail.id,
                payload: {
                  lifecycle_status: pendingStatus,
                  status_reason: statusReason || undefined,
                },
              })}
              className="rounded-xl bg-accent px-4 py-2 text-sm font-medium text-dark-950"
            >
              Aplicar
            </button>
          </>
        )}
      >
        <label className="space-y-1 text-sm">
          <span className="text-gray-400">Motivo / anotação</span>
          <textarea
            value={statusReason}
            onChange={(event) => setStatusReason(event.target.value)}
            rows={4}
            className="w-full rounded-xl border border-white/10 bg-dark-900/70 px-3 py-2 text-white outline-none"
          />
        </label>
      </Modal>

      <Modal
        open={metadataModalOpen}
        title="Editar metadata"
        onClose={() => setMetadataModalOpen(false)}
        footer={(
          <>
            <button onClick={() => setMetadataModalOpen(false)} className="rounded-xl border border-white/10 bg-white/5 px-4 py-2 text-sm text-white">Cancelar</button>
            <button
              onClick={() => {
                if (!detail) return
                try {
                  const metadata = metadataForm.metadata.trim() ? JSON.parse(metadataForm.metadata) as Record<string, unknown> : {}
                  updateMutation.mutate({
                    projectId: detail.id,
                    payload: {
                      description: metadataForm.description,
                      changelog: metadataForm.changelog,
                      metadata,
                    },
                  })
                } catch {
                  setFeedback({ tone: 'error', message: 'Metadata deve ser JSON válido.' })
                }
              }}
              className="rounded-xl bg-accent px-4 py-2 text-sm font-medium text-dark-950"
            >
              Salvar
            </button>
          </>
        )}
      >
        <div className="grid gap-3">
          <label className="space-y-1 text-sm">
            <span className="text-gray-400">Descrição</span>
            <input
              value={metadataForm.description}
              onChange={(event) => setMetadataForm((state) => ({ ...state, description: event.target.value }))}
              className="w-full rounded-xl border border-white/10 bg-dark-900/70 px-3 py-2 text-white outline-none"
            />
          </label>
          <label className="space-y-1 text-sm">
            <span className="text-gray-400">Changelog</span>
            <textarea
              value={metadataForm.changelog}
              onChange={(event) => setMetadataForm((state) => ({ ...state, changelog: event.target.value }))}
              rows={3}
              className="w-full rounded-xl border border-white/10 bg-dark-900/70 px-3 py-2 text-white outline-none"
            />
          </label>
          <label className="space-y-1 text-sm">
            <span className="text-gray-400">Metadata JSON</span>
            <textarea
              value={metadataForm.metadata}
              onChange={(event) => setMetadataForm((state) => ({ ...state, metadata: event.target.value }))}
              rows={8}
              className="w-full rounded-xl border border-white/10 bg-dark-900/70 px-3 py-2 font-mono text-xs text-white outline-none"
            />
          </label>
        </div>
      </Modal>

      <Modal
        open={shareModalOpen}
        title="Grants por usuário"
        onClose={() => setShareModalOpen(false)}
        footer={(
          <>
            <button onClick={() => setShareModalOpen(false)} className="rounded-xl border border-white/10 bg-white/5 px-4 py-2 text-sm text-white">Cancelar</button>
            <button
              onClick={() => {
                if (!detail) return
                const grants = shareForm
                  .filter((grant) => Number.isFinite(grant.user_id) && grant.user_id > 0)
                  .map((grant) => ({
                    user_id: grant.user_id,
                    grant_role: grant.grant_role || 'viewer',
                    expires_at: grant.expires_at || undefined,
                  }))

                updateMutation.mutate({
                  projectId: detail.id,
                  payload: {
                    visibility: grants.length ? 'shared' : detail.visibility,
                    share_grants: grants,
                  },
                })
              }}
              className="rounded-xl bg-accent px-4 py-2 text-sm font-medium text-dark-950"
            >
              Salvar
            </button>
          </>
        )}
      >
        <div className="space-y-3">
          {shareForm.map((grant, index) => (
            <div key={`${grant.user_id}-${index}`} className="grid gap-2 rounded-xl border border-white/[0.06] bg-dark-900/50 p-3 md:grid-cols-[1fr_1fr_1fr_auto]">
              <input
                type="number"
                value={grant.user_id}
                onChange={(event) => setShareForm((state) => state.map((item, current) => current === index ? { ...item, user_id: Number(event.target.value) } : item))}
                placeholder="user_id"
                className="w-full rounded-xl border border-white/10 bg-dark-900/70 px-3 py-2 text-white outline-none"
              />
              <select
                value={grant.grant_role}
                onChange={(event) => setShareForm((state) => state.map((item, current) => current === index ? { ...item, grant_role: event.target.value } : item))}
                className="w-full rounded-xl border border-white/10 bg-dark-900/70 px-3 py-2 text-white outline-none"
              >
                <option value="viewer">viewer</option>
                <option value="editor">editor</option>
              </select>
              <input
                type="datetime-local"
                value={grant.expires_at ? grant.expires_at.slice(0, 16) : ''}
                onChange={(event) => setShareForm((state) => state.map((item, current) => current === index ? { ...item, expires_at: event.target.value ? new Date(event.target.value).toISOString() : null } : item))}
                className="w-full rounded-xl border border-white/10 bg-dark-900/70 px-3 py-2 text-white outline-none"
              />
              <button
                onClick={() => setShareForm((state) => state.filter((_, current) => current !== index))}
                className="rounded-xl border border-rose-400/20 bg-rose-400/10 px-3 py-2 text-sm text-rose-200"
              >
                Remover
              </button>
            </div>
          ))}
          <button
            onClick={() => setShareForm((state) => [...state, { user_id: 0, grant_role: 'viewer', expires_at: null }])}
            className="rounded-xl border border-white/10 bg-white/5 px-4 py-2 text-sm text-white"
          >
            Adicionar grant
          </button>
        </div>
      </Modal>

      <Modal
        open={deleteModalOpen}
        title="Remover projeto"
        onClose={() => setDeleteModalOpen(false)}
        footer={(
          <>
            <button onClick={() => setDeleteModalOpen(false)} className="rounded-xl border border-white/10 bg-white/5 px-4 py-2 text-sm text-white">Cancelar</button>
            <button
              onClick={() => detail && deleteMutation.mutate(detail.id)}
              className="rounded-xl border border-rose-400/20 bg-rose-400/10 px-4 py-2 text-sm font-medium text-rose-200"
            >
              Confirmar remoção
            </button>
          </>
        )}
      >
        <p className="text-sm text-gray-300">
          Esta ação remove o projeto selecionado do banco e do storage remoto.
        </p>
      </Modal>
    </>
  )
}
