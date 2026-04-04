'use client'

import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { CalendarClock, KeyRound, Share2, Users } from 'lucide-react'
import { accessAPI, projectsAPI } from '@/lib/api'
import { EmptyState } from '@/components/ui/EmptyState'
import { FeedbackBanner } from '@/components/ui/FeedbackBanner'
import { Modal } from '@/components/ui/Modal'
import { StatusBadge } from '@/components/ui/StatusBadge'
import { useToastStore } from '@/store/toast'

type FeedbackState = { tone: 'success' | 'error' | 'info'; message: string } | null

export function TeamsPanel() {
  const qc = useQueryClient()
  const pushToast = useToastStore((state) => state.push)
  const [teamName, setTeamName] = useState('')
  const [selectedTeamId, setSelectedTeamId] = useState('')
  const [inviteToken, setInviteToken] = useState('')
  const [grantProjectId, setGrantProjectId] = useState('')
  const [grantTeamId, setGrantTeamId] = useState('')
  const [feedback, setFeedback] = useState<FeedbackState>(null)
  const [inviteModalOpen, setInviteModalOpen] = useState(false)
  const [inviteForm, setInviteForm] = useState({
    email: '',
    role: 'member',
    expiresAt: '',
  })

  const teamsQuery = useQuery({
    queryKey: ['teams'],
    queryFn: accessAPI.listTeams,
  })

  const projectsQuery = useQuery({
    queryKey: ['projects', 'sharing'],
    queryFn: () => projectsAPI.list({ page_size: 100, sort_by: 'created_at', sort_dir: 'desc' }),
  })

  const createTeam = useMutation({
    mutationFn: accessAPI.createTeam,
    onSuccess: () => {
      setTeamName('')
      setFeedback({ tone: 'success', message: 'Time criado.' })
      pushToast('success', 'Time criado.')
      qc.invalidateQueries({ queryKey: ['teams'] })
    },
    onError: (err) => setFeedback({ tone: 'error', message: err instanceof Error ? err.message : 'Falha ao criar time.' }),
  })

  const createInvite = useMutation({
    mutationFn: ({ teamId, email, role, expiresAt }: { teamId: string; email: string; role: string; expiresAt?: string }) =>
      accessAPI.createInvite(teamId, email, role, expiresAt),
    onSuccess: (payload) => {
      setInviteForm({ email: '', role: 'member', expiresAt: '' })
      setInviteModalOpen(false)
      setFeedback({ tone: 'success', message: `Convite criado. Token: ${payload.invite.token}` })
      pushToast('success', 'Convite criado.')
    },
    onError: (err) => setFeedback({ tone: 'error', message: err instanceof Error ? err.message : 'Falha ao convidar.' }),
  })

  const acceptInvite = useMutation({
    mutationFn: accessAPI.acceptInvite,
    onSuccess: () => {
      setInviteToken('')
      setFeedback({ tone: 'success', message: 'Convite aceito.' })
      pushToast('success', 'Convite aceito.')
      qc.invalidateQueries({ queryKey: ['teams'] })
    },
    onError: (err) => setFeedback({ tone: 'error', message: err instanceof Error ? err.message : 'Falha ao aceitar convite.' }),
  })

  const addGrant = useMutation({
    mutationFn: ({ projectId, teamId }: { projectId: string; teamId: string }) => accessAPI.addProjectTeamGrant(projectId, teamId),
    onSuccess: () => {
      setFeedback({ tone: 'success', message: 'Team grant aplicado ao projeto.' })
      pushToast('success', 'Team grant aplicado.')
      qc.invalidateQueries({ queryKey: ['projects'] })
    },
    onError: (err) => setFeedback({ tone: 'error', message: err instanceof Error ? err.message : 'Falha ao aplicar team grant.' }),
  })

  const teams = teamsQuery.data?.teams ?? []
  const projects = projectsQuery.data?.projects ?? []
  const selectedTeam = teams.find((team) => team.id === selectedTeamId) ?? teams[0] ?? null
  const teamGrants = useMemo(
    () => projects.filter((project) => project.team_grants.some((grant) => grant.team_id === selectedTeam?.id)),
    [projects, selectedTeam?.id],
  )

  return (
    <>
      <section className="glass rounded-2xl p-5">
        <div className="mb-5 flex items-start justify-between gap-3">
          <div>
            <h2 className="text-lg font-semibold text-white">Times e compartilhamento</h2>
            <p className="text-sm text-gray-400">Criação de times, convites ricos, membros e grants por equipe.</p>
          </div>
          <div className="flex h-11 w-11 items-center justify-center rounded-2xl bg-primary-600/15 text-primary-300">
            <Users className="h-5 w-5" />
          </div>
        </div>

        {feedback ? <div className="mb-4"><FeedbackBanner tone={feedback.tone} message={feedback.message} /></div> : null}

        <div className="grid gap-5 xl:grid-cols-[0.95fr_1.05fr]">
          <div className="space-y-4">
            <div className="rounded-2xl border border-white/[0.08] bg-dark-900/50 p-4">
              <div className="mb-2 text-sm font-medium text-white">Criar time</div>
              <div className="flex gap-2">
                <input
                  value={teamName}
                  onChange={(e) => setTeamName(e.target.value)}
                  placeholder="platform-core"
                  className="h-input"
                />
                <button
                  onClick={() => createTeam.mutate(teamName)}
                  disabled={createTeam.isPending}
                  className="rounded-xl bg-accent px-4 py-2 text-sm font-medium text-dark-950 disabled:opacity-50"
                >
                  Criar
                </button>
              </div>
            </div>

            <div className="rounded-2xl border border-white/[0.08] bg-dark-900/50 p-4">
              <div className="mb-3 text-sm font-medium text-white">Times atuais</div>
              <div className="space-y-2">
                {teams.map((team) => (
                  <button
                    key={team.id}
                    onClick={() => setSelectedTeamId(team.id)}
                    className={`w-full rounded-xl border px-3 py-3 text-left ${selectedTeam?.id === team.id ? 'border-accent/30 bg-accent/10' : 'border-white/[0.06] bg-dark-950/50'}`}
                  >
                    <div className="text-sm font-medium text-white">{team.name}</div>
                    <div className="text-xs text-gray-500">
                      owner #{team.owner_user_id} · {team.members.length} membros
                    </div>
                  </button>
                ))}
                {!teams.length ? <EmptyState title="Nenhum time encontrado" text="Crie um time para começar a compartilhar pacotes." /> : null}
              </div>
            </div>

            <div className="rounded-2xl border border-white/[0.08] bg-dark-900/50 p-4">
              <div className="mb-2 text-sm font-medium text-white">Aceitar convite</div>
              <div className="flex gap-2">
                <input
                  value={inviteToken}
                  onChange={(e) => setInviteToken(e.target.value)}
                  placeholder="token do convite"
                  className="w-full rounded-xl border border-white/10 bg-dark-950/60 px-3 py-2 font-mono text-white outline-none"
                />
                <button
                  onClick={() => acceptInvite.mutate(inviteToken)}
                  disabled={acceptInvite.isPending}
                  className="inline-flex items-center gap-2 rounded-xl border border-white/10 bg-white/5 px-4 py-2 text-sm text-white disabled:opacity-50"
                >
                  <KeyRound className="h-4 w-4" />
                  Aceitar
                </button>
              </div>
            </div>
          </div>

          <div className="space-y-4">
            <div className="rounded-2xl border border-white/[0.08] bg-dark-900/50 p-4">
              <div className="mb-3 flex items-center justify-between gap-3">
                <div className="text-sm font-medium text-white">Convites e grants</div>
                <button
                  onClick={() => setInviteModalOpen(true)}
                  disabled={!selectedTeam}
                  className="inline-flex items-center gap-2 rounded-xl border border-white/10 bg-white/5 px-3 py-2 text-sm text-white disabled:opacity-40"
                >
                  <Share2 className="h-4 w-4" />
                  Novo convite
                </button>
              </div>

              <div className="grid gap-2">
                <select
                  value={grantProjectId}
                  onChange={(e) => setGrantProjectId(e.target.value)}
                  className="h-input"
                >
                  <option value="">Projeto</option>
                  {projects.map((project) => (
                    <option key={project.id} value={project.id}>
                      {project.package_name}@{project.package_version}
                    </option>
                  ))}
                </select>
                <select
                  value={grantTeamId}
                  onChange={(e) => setGrantTeamId(e.target.value)}
                  className="h-input"
                >
                  <option value="">Time</option>
                  {teams.map((team) => (
                    <option key={team.id} value={team.id}>{team.name}</option>
                  ))}
                </select>
                <button
                  onClick={() => addGrant.mutate({ projectId: grantProjectId, teamId: grantTeamId })}
                  disabled={addGrant.isPending}
                  className="rounded-xl bg-primary-500/15 px-4 py-2 text-sm font-medium text-primary-200 disabled:opacity-50"
                >
                  Aplicar team grant
                </button>
              </div>
            </div>

            <div className="rounded-2xl border border-white/[0.08] bg-dark-900/50 p-4">
              <div className="mb-2 text-sm font-medium text-white">Membros do time</div>
              {selectedTeam ? (
                <div className="space-y-2">
                  {selectedTeam.members.map((member) => (
                    <div key={`${selectedTeam.id}-${member.user_id}`} className="flex items-center justify-between rounded-xl border border-white/[0.06] bg-dark-950/50 px-3 py-2">
                      <div>
                        <div className="text-sm text-white">Usuário #{member.user_id}</div>
                        <div className="text-xs text-gray-500">{new Date(member.created_at).toLocaleString('pt-BR')}</div>
                      </div>
                      <StatusBadge status={member.role} />
                    </div>
                  ))}
                </div>
              ) : (
                <EmptyState title="Selecione um time" text="Abra um time para ver seus membros e grants." />
              )}
            </div>

            <div className="rounded-2xl border border-white/[0.08] bg-dark-900/50 p-4">
              <div className="mb-2 text-sm font-medium text-white">Grants aplicados ao time</div>
              {selectedTeam ? (
                teamGrants.length ? (
                  <div className="space-y-2">
                    {teamGrants.map((project) => (
                      <div key={project.id} className="rounded-xl border border-white/[0.06] bg-dark-950/50 px-3 py-2">
                        <div className="text-sm text-white">{project.package_name}@{project.package_version}</div>
                        <div className="mt-1 flex flex-wrap gap-2">
                          {project.team_grants
                            .filter((grant) => grant.team_id === selectedTeam.id)
                            .map((grant, index) => (
                              <div key={`${grant.team_id}-${index}`} className="flex items-center gap-2 text-xs text-gray-400">
                                <StatusBadge status={grant.grant_role} />
                                {grant.expires_at ? (
                                  <span className="inline-flex items-center gap-1">
                                    <CalendarClock className="h-3.5 w-3.5" />
                                    {new Date(grant.expires_at).toLocaleString('pt-BR')}
                                  </span>
                                ) : (
                                  <span>sem expiração</span>
                                )}
                              </div>
                            ))}
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <EmptyState title="Sem grants aplicados" text="Nenhum projeto foi compartilhado com este time ainda." />
                )
              ) : (
                <EmptyState title="Selecione um time" text="Abra um time para ver quais projetos foram compartilhados." />
              )}
            </div>
          </div>
        </div>
      </section>

      <Modal
        open={inviteModalOpen}
        title="Novo convite"
        onClose={() => setInviteModalOpen(false)}
        footer={(
          <>
            <button onClick={() => setInviteModalOpen(false)} className="h-btn">Cancelar</button>
            <button
              onClick={() => selectedTeam && createInvite.mutate({
                teamId: selectedTeam.id,
                email: inviteForm.email,
                role: inviteForm.role,
                expiresAt: inviteForm.expiresAt ? new Date(inviteForm.expiresAt).toISOString() : undefined,
              })}
              className="h-btn-primary"
            >
              Criar convite
            </button>
          </>
        )}
      >
        <div className="grid gap-3">
          <label className="space-y-1 text-sm">
            <span className="text-gray-400">Email</span>
            <input
              value={inviteForm.email}
              onChange={(event) => setInviteForm((state) => ({ ...state, email: event.target.value }))}
              className="h-input"
            />
          </label>
          <label className="space-y-1 text-sm">
            <span className="text-gray-400">Role do convite</span>
            <select
              value={inviteForm.role}
              onChange={(event) => setInviteForm((state) => ({ ...state, role: event.target.value }))}
              className="h-input"
            >
              <option value="member">member</option>
              <option value="manager">manager</option>
            </select>
          </label>
          <label className="space-y-1 text-sm">
            <span className="text-gray-400">Expira em</span>
            <input
              type="datetime-local"
              value={inviteForm.expiresAt}
              onChange={(event) => setInviteForm((state) => ({ ...state, expiresAt: event.target.value }))}
              className="h-input"
            />
          </label>
        </div>
      </Modal>
    </>
  )
}
