import { test, expect } from '@playwright/test'

test('login page renders primary auth form', async ({ page }) => {
  await page.goto('/login')
  await expect(page.getByRole('heading', { name: 'GateStack' })).toBeVisible()
  await expect(page.getByLabel('Email')).toBeVisible()
  await expect(page.getByLabel('Senha')).toBeVisible()
})
