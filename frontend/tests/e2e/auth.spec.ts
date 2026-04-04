import { test, expect } from '@playwright/test'

test('login page renders primary auth form', async ({ page }) => {
  await page.goto('/login')
  await expect(page.getByRole('heading', { name: 'GateStack' })).toBeVisible()
  await expect(page.getByLabel('Email')).toBeVisible()
  await expect(page.getByLabel('Senha')).toBeVisible()
})

test('MFA setup modal flow', async ({ page }) => {
  await page.goto('/dashboard')

  // Simulate opening the MFA setup modal
  await page.click('button[aria-label="Configurar 2FA"]');
  await expect(page.getByRole('dialog', { name: 'Configurar 2FA' })).toBeVisible()

  // Simulate QR code step
  await expect(page.getByText('Escaneie o QR Code com Google Authenticator, Authy ou similar:')).toBeVisible()
  await page.click('button:has-text("Já escaneei → Verificar")')

  // Simulate verification step
  await page.fill('input[aria-label="Digite o código de autenticação de 6 dígitos"]', '123456')
  await page.click('button[aria-label="Confirmar código de autenticação"]')

  // Expect success
  await expect(page.getByText('Configuração concluída com sucesso')).toBeVisible()
})
