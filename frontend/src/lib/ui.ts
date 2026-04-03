export function nextJobsPollInterval(statuses: string[]): number {
  if (statuses.some((status) => status === 'queued' || status === 'running' || status === 'retry')) {
    return 2000
  }
  if (statuses.length > 0) {
    return 10000
  }
  return 15000
}

export function canManageOwnerActions(role?: string | null) {
  return role === 'owner'
}

export function visibleWorkflowTargets(role?: string | null) {
  if (role === 'owner') {
    return ['draft', 'submitted', 'approved', 'published', 'archived', 'rejected']
  }
  return ['draft', 'submitted', 'archived']
}

export function canUseOps(role?: string | null) {
  return role === 'owner'
}

export function canChangeVisibility(role?: string | null) {
  return role === 'owner' || role === 'user'
}

export function isProjectLikelyReferenced(projectId: string, details: Record<string, unknown> | undefined) {
  if (!details) return false
  return JSON.stringify(details).includes(projectId)
}
