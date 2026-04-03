import { describe, expect, it } from 'vitest'
import { canManageOwnerActions, nextJobsPollInterval, visibleWorkflowTargets } from './ui'

describe('ui helpers', () => {
  it('uses faster polling while there are active jobs', () => {
    expect(nextJobsPollInterval(['queued'])).toBe(2000)
    expect(nextJobsPollInterval(['running', 'completed'])).toBe(2000)
  })

  it('uses slower polling when jobs are idle or absent', () => {
    expect(nextJobsPollInterval(['completed', 'failed'])).toBe(10000)
    expect(nextJobsPollInterval([])).toBe(15000)
  })

  it('exposes owner workflow targets and limited user targets', () => {
    expect(visibleWorkflowTargets('owner')).toContain('published')
    expect(visibleWorkflowTargets('user')).not.toContain('published')
    expect(visibleWorkflowTargets('user')).toEqual(['draft', 'submitted', 'archived'])
  })

  it('gates owner-only actions correctly', () => {
    expect(canManageOwnerActions('owner')).toBe(true)
    expect(canManageOwnerActions('user')).toBe(false)
    expect(canManageOwnerActions(null)).toBe(false)
  })
})
