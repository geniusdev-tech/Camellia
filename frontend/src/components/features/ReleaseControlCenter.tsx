'use client'

import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { releasesAPI } from '@/lib/api'
import type { CreateReleaseRequest, DeploymentEnv, GateRelease, ReleaseChannel } from '@/lib/types'
import { useAuthStore } from '@/store/auth'
import { StatusBadge } from '@/components/ui/StatusBadge'
import { FeedbackBanner } from '@/components/ui/FeedbackBanner'
import { useToastStore } from '@/store/toast'

type Feedback = { tone: 'success' | 'error' | 'info'; message: string } | null

const EMPTY_FORM: CreateReleaseRequest = {
  packageName: '',
  packageVersion: '',
  releaseChannel: 'stable',
  deploymentEnv: 'dev',
  maxCvss: 0,
  complianceScore: 0,
  riskScore: 100,
}

function errMessage(err: unknown, fallback: string) {
  if (err instanceof Error && err.message.trim()) return err.message
  return fallback
}

function roleCanCreate(role?: string | null) {
  return role === 'admin' || role === 'writer'
}

function roleCanPublish(role?: string | null) {
  return role === 'admin'
}

export function ReleaseControlCenter() {
  const qc = useQueryClient()
  const pushToast = useToastStore((s) => s.push)
  const role = useAuthStore((s) => s.user?.role)

  const [feedback, setFeedback] = useState<Feedback>(null)
  const [form, setForm] = useState<CreateReleaseRequest>(EMPTY_FORM)
  const [rollbackTargetByRelease, setRollbackTargetByRelease] = useState<Record<string, string>>({})

  const releasesQuery = useQuery({
    queryKey: ['releases'],
    queryFn: () => releasesAPI.list(),
    refetchInterval: 5000,
  })

  const releases = releasesQuery.data?.releases ?? []
  const sortedReleases = useMemo(
    () => [...releases].sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()),
    [releases],
  )

  const createMutation = useMutation({
    mutationFn: (payload: CreateReleaseRequest) => releasesAPI.create(payload),
    onSuccess: () => {
      setFeedback({ tone: 'success', message: 'Release criada com sucesso.' })
      pushToast('success', 'Release criada com sucesso.')
      setForm(EMPTY_FORM)
      qc.invalidateQueries({ queryKey: ['releases'] })
    },
    onError: (err) => {
      setFeedback({ tone: 'error', message: errMessage(err, 'Falha ao criar release.') })
    },
  })

  const publishMutation = useMutation({
    mutationFn: (releaseId: string) => releasesAPI.publish(releaseId),
    onSuccess: () => {
      setFeedback({ tone: 'success', message: 'Publish enfileirado.' })
      pushToast('success', 'Publish enfileirado.')
      qc.invalidateQueries({ queryKey: ['releases'] })
    },
    onError: (err) => {
      setFeedback({ tone: 'error', message: errMessage(err, 'Falha ao enfileirar publish.') })
    },
  })

  const rollbackMutation = useMutation({
    mutationFn: ({ releaseId, targetReleaseId }: { releaseId: string; targetReleaseId: string }) =>
      releasesAPI.rollback(releaseId, targetReleaseId),
    onSuccess: () => {
      setFeedback({ tone: 'success', message: 'Rollback enfileirado.' })
      pushToast('success', 'Rollback enfileirado.')
      qc.invalidateQueries({ queryKey: ['releases'] })
    },
    onError: (err) => {
      setFeedback({ tone: 'error', message: errMessage(err, 'Falha ao enfileirar rollback.') })
    },
  })

  function submitCreate() {
    if (!roleCanCreate(role)) {
      setFeedback({ tone: 'error', message: 'Seu perfil não permite criar release.' })
      return
    }

    if (!form.packageName.trim() || !form.packageVersion.trim()) {
      setFeedback({ tone: 'error', message: 'Informe packageName e packageVersion.' })
      return
    }

    if (form.maxCvss < 0 || form.maxCvss > 10) {
      setFeedback({ tone: 'error', message: 'maxCvss deve estar entre 0 e 10.' })
      return
    }

    if (form.complianceScore < 0 || form.complianceScore > 100 || form.riskScore < 0 || form.riskScore > 100) {
      setFeedback({ tone: 'error', message: 'Scores devem estar entre 0 e 100.' })
      return
    }

    createMutation.mutate({ ...form, packageName: form.packageName.trim(), packageVersion: form.packageVersion.trim() })
  }

  function rolloutCandidates(current: GateRelease) {
    return sortedReleases.filter((item) => item.id !== current.id && item.packageName === current.packageName)
  }

  return (
    <section className="grid gap-5 xl:grid-cols-[0.95fr_1.05fr]">
      <div className="glass rounded-2xl p-5">
        <h2 className="text-lg font-semibold text-white">Nova release</h2>
        <p className="mt-1 text-sm text-gray-400">Campos alinhados ao backend Node/TS atual.</p>

        {feedback ? <div className="mt-4"><FeedbackBanner tone={feedback.tone} message={feedback.message} /></div> : null}

        <div className="mt-4 grid gap-3">
          <label className="space-y-1 text-sm">
            <span className="text-gray-400">Package name</span>
            <input
              value={form.packageName}
              onChange={(e) => setForm((s) => ({ ...s, packageName: e.target.value }))}
              className="h-input"
              placeholder="security-kit"
            />
          </label>

          <label className="space-y-1 text-sm">
            <span className="text-gray-400">Package version</span>
            <input
              value={form.packageVersion}
              onChange={(e) => setForm((s) => ({ ...s, packageVersion: e.target.value }))}
              className="h-input"
              placeholder="1.0.0"
            />
          </label>

          <div className="grid gap-3 sm:grid-cols-2">
            <label className="space-y-1 text-sm">
              <span className="text-gray-400">Release channel</span>
              <select
                value={form.releaseChannel}
                onChange={(e) => setForm((s) => ({ ...s, releaseChannel: e.target.value as ReleaseChannel }))}
                className="h-input"
              >
                <option value="alpha">alpha</option>
                <option value="beta">beta</option>
                <option value="stable">stable</option>
              </select>
            </label>

            <label className="space-y-1 text-sm">
              <span className="text-gray-400">Deployment env</span>
              <select
                value={form.deploymentEnv}
                onChange={(e) => setForm((s) => ({ ...s, deploymentEnv: e.target.value as DeploymentEnv }))}
                className="h-input"
              >
                <option value="dev">dev</option>
                <option value="staging">staging</option>
                <option value="prod">prod</option>
              </select>
            </label>
          </div>

          <div className="grid gap-3 sm:grid-cols-3">
            <label className="space-y-1 text-sm">
              <span className="text-gray-400">Max CVSS</span>
              <input
                type="number"
                min={0}
                max={10}
                step={0.1}
                value={form.maxCvss}
                onChange={(e) => setForm((s) => ({ ...s, maxCvss: Number(e.target.value) }))}
                className="h-input"
              />
            </label>

            <label className="space-y-1 text-sm">
              <span className="text-gray-400">Compliance</span>
              <input
                type="number"
                min={0}
                max={100}
                value={form.complianceScore}
                onChange={(e) => setForm((s) => ({ ...s, complianceScore: Number(e.target.value) }))}
                className="h-input"
              />
            </label>

            <label className="space-y-1 text-sm">
              <span className="text-gray-400">Risk</span>
              <input
                type="number"
                min={0}
                max={100}
                value={form.riskScore}
                onChange={(e) => setForm((s) => ({ ...s, riskScore: Number(e.target.value) }))}
                className="h-input"
              />
            </label>
          </div>

          <button
            onClick={submitCreate}
            disabled={createMutation.isPending || !roleCanCreate(role)}
            className="mt-1 rounded-xl bg-accent px-4 py-2 text-sm font-medium text-dark-950 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {createMutation.isPending ? 'Criando...' : 'Criar release'}
          </button>
        </div>
      </div>

      <div className="glass rounded-2xl p-5">
        <h2 className="text-lg font-semibold text-white">Releases</h2>
        <p className="mt-1 text-sm text-gray-400">Lista com canal, ambiente, risco e ações de rollout.</p>

        <div className="mt-4 space-y-3">
          {releasesQuery.isLoading ? <div className="text-sm text-gray-400">Carregando releases...</div> : null}
          {releasesQuery.isError ? <div className="text-sm text-rose-300">Falha ao carregar releases.</div> : null}

          {!sortedReleases.length && !releasesQuery.isLoading ? (
            <div className="rounded-xl border border-white/10 bg-dark-900/50 px-4 py-3 text-sm text-gray-400">
              Nenhuma release cadastrada.
            </div>
          ) : null}

          {sortedReleases.map((release) => {
            const rollbackTarget = rollbackTargetByRelease[release.id] || ''
            const candidates = rolloutCandidates(release)

            return (
              <div key={release.id} className="rounded-xl border border-white/10 bg-dark-900/50 p-4">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div>
                    <div className="text-sm font-semibold text-white">{release.packageName}@{release.packageVersion}</div>
                    <div className="mt-1 flex flex-wrap gap-2 text-xs text-gray-400">
                      <span>channel: {release.releaseChannel}</span>
                      <span>env: {release.deploymentEnv}</span>
                      <span>cvss: {release.maxCvss}</span>
                      <span>compliance: {release.complianceScore}</span>
                      <span>risk: {release.riskScore}</span>
                    </div>
                  </div>
                  <StatusBadge status={release.status} />
                </div>

                <div className="mt-3 flex flex-wrap gap-2">
                  <button
                    onClick={() => publishMutation.mutate(release.id)}
                    disabled={!roleCanPublish(role) || publishMutation.isPending}
                    className="rounded-xl border border-primary-400/20 bg-primary-500/10 px-3 py-1.5 text-xs text-primary-200 disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    Publish
                  </button>

                  <select
                    value={rollbackTarget}
                    onChange={(e) => setRollbackTargetByRelease((s) => ({ ...s, [release.id]: e.target.value }))}
                    className="rounded-xl border border-white/10 bg-dark-900/70 px-3 py-1.5 text-xs text-white outline-none"
                  >
                    <option value="">target rollback</option>
                    {candidates.map((item) => (
                      <option key={item.id} value={item.id}>
                        {item.packageVersion} ({item.status})
                      </option>
                    ))}
                  </select>

                  <button
                    onClick={() => rollbackTarget && rollbackMutation.mutate({ releaseId: release.id, targetReleaseId: rollbackTarget })}
                    disabled={!roleCanPublish(role) || !rollbackTarget || rollbackMutation.isPending}
                    className="rounded-xl border border-amber-400/20 bg-amber-400/10 px-3 py-1.5 text-xs text-amber-200 disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    Rollback
                  </button>
                </div>
              </div>
            )
          })}
        </div>
      </div>
    </section>
  )
}
