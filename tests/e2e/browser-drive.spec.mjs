import { test, expect } from '@playwright/test';
import fs from 'node:fs/promises';
import crypto from 'node:crypto';

async function signIn(page, phone = '+15550004004') {
  await page.goto('/login');
  await expect(page.getByRole('heading', { name: 'Sign in to your drive' })).toBeVisible();
  await page.getByLabel('Phone number').fill(phone);
  await page.getByRole('button', { name: 'Continue securely' }).click();
  await expect(page.getByLabel('Login code')).toBeVisible();
  await page.getByLabel('Login code').fill('12345');
  await page.getByRole('button', { name: 'Verify code' }).click();
  await expect(page).toHaveURL(/\/drive$/);
  await expect(page.getByText('Welcome to Salvage Cloud.txt')).toBeVisible();
}

test('login headline renders a line break instead of markup text', async ({ page }) => {
  const response = await page.goto('/login');
  expect(response.status()).toBe(200);
  const headline = page.locator('.story-content h1');
  await expect(headline).toContainText('kept within reach.');
  await expect(headline).not.toContainText('<br/>');
});

test('a rebuilt Trunk bootstrap updates CSP without restarting the server', async ({ page }) => {
  const indexPath = new URL('../../dist/index.html', import.meta.url).pathname;
  const original = await fs.readFile(indexPath, 'utf8');
  const updated = original.replace('</script>', '\n// rebuilt asset\n</script>');
  expect(updated).not.toBe(original);
  try {
    await fs.writeFile(indexPath, updated);
    const bootstrap = updated.match(/<script type="module">([\s\S]*?)<\/script>/)[1];
    const expectedHash = crypto.createHash('sha256').update(bootstrap).digest('base64');
    const response = await page.goto('/login');
    expect(response.headers()['content-security-policy']).toContain(`sha256-${expectedHash}`);
    await expect(page.getByRole('heading', { name: 'Sign in to your drive' })).toBeVisible();
  } finally {
    await fs.writeFile(indexPath, original);
  }
});

test('QR login issues and restores the normal secure web session', async ({ page }) => {
  await page.goto('/login');
  await page.getByRole('button', { name: 'Use QR code instead' }).click();
  await expect(page.getByRole('heading', { name: 'Scan with your Telegram app' })).toBeVisible();
  await expect(page.locator('.qr-login-code svg')).toBeVisible();
  await expect(page).toHaveURL(/\/drive$/, { timeout: 15_000 });
  await expect(page.getByText('Welcome to Salvage Cloud.txt')).toBeVisible();
  const persisted = await page.evaluate(() => JSON.stringify(Object.entries(localStorage)));
  expect(persisted).not.toContain('fixture-qr-token');
  await page.reload();
  await expect(page.getByText('Welcome to Salvage Cloud.txt')).toBeVisible();
});

test('compiled WASM login, folder mutations, search, reload and logout', async ({ page }) => {
  const phone = '+15550004004';
  await signIn(page, phone);

  await page.getByRole('button', { name: 'New channel' }).click();
  await page.getByLabel('Channel name').fill('Browser journey');
  await page.getByRole('button', { name: 'Create channel', exact: true }).click();
  await expect(page.getByText('Browser journey', { exact: true })).toBeVisible();

  await page.getByRole('button', { name: 'Rename Browser journey' }).click();
  await page.getByLabel('Channel name').fill('Renamed in WASM');
  await page.getByRole('button', { name: 'Save changes' }).click();
  await expect(page.getByText('Renamed in WASM', { exact: true })).toBeVisible();

  await page.getByLabel('Search files in this folder').fill('Welcome');
  await page.getByRole('button', { name: 'Search', exact: true }).click();
  await expect(page.getByText('Welcome to Salvage Cloud.txt')).toBeVisible();
  await expect(page.getByText('Reading list.txt')).toHaveCount(0);
  await page.getByRole('button', { name: 'Clear search' }).click();

  await page.reload();
  await expect(page.getByText('Renamed in WASM', { exact: true })).toBeVisible();
  const persisted = await page.evaluate(() => ({
    local: Object.entries(localStorage),
    session: Object.entries(sessionStorage),
  }));
  const serialized = JSON.stringify(persisted);
  expect(serialized).not.toContain(phone);
  expect(serialized).not.toContain('salvage_session');
  expect(serialized).not.toContain('csrf_token');

  await page.getByRole('button', { name: 'Delete Renamed in WASM' }).click();
  await page.getByRole('button', { name: 'Delete channel', exact: true }).click();
  await expect(page.getByText('Renamed in WASM', { exact: true })).toHaveCount(0);
  await page.getByRole('button', { name: 'Sign out' }).click();
  await expect(page.getByRole('heading', { name: 'Sign in to your drive' })).toBeVisible();
});

test('individual files and populated channels can be deleted and synchronized', async ({ page }) => {
  await signIn(page, '+15550004444');
  await page.getByRole('button', { name: 'New channel' }).click();
  await page.getByLabel('Channel name').fill('Removal channel');
  await page.getByRole('button', { name: 'Create channel', exact: true }).click();
  await page.getByRole('link', { name: /Removal channel/ }).click();
  await page.getByRole('link', { name: 'Upload files' }).click();
  await page.locator('input[type="file"][aria-label="Upload files"]').setInputFiles([
    { name: 'remove-first.txt', mimeType: 'text/plain', buffer: Buffer.from('first') },
    { name: 'remove-second.txt', mimeType: 'text/plain', buffer: Buffer.from('second') },
  ]);
  await expect(page.getByText('Completed', { exact: true })).toHaveCount(2, { timeout: 30_000 });

  await page.getByRole('link', { name: 'My drive' }).click();
  await page.getByRole('link', { name: /Removal channel/ }).click();
  await page.getByRole('button', { name: 'Delete remove-first.txt', exact: true }).click();
  await page.getByRole('button', { name: 'Delete file', exact: true }).click();
  await expect(page.getByText('remove-first.txt', { exact: true })).toHaveCount(0);
  await expect(page.getByText('remove-second.txt', { exact: true })).toBeVisible();

  await page.getByRole('link', { name: 'My drive' }).first().click();
  await page.getByRole('button', { name: 'Delete Removal channel', exact: true }).click();
  await page.getByRole('button', { name: 'Delete channel', exact: true }).click();
  await expect(page.getByRole('link', { name: /Removal channel/ })).toHaveCount(0);
  await page.getByRole('button', { name: 'Sync channels' }).click();
  await expect(page.getByRole('link', { name: /Removal channel/ })).toHaveCount(0);
});

test('cloud-password login and responsive navigation use the real WASM application', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto('/login');
  await page.getByLabel('Phone number').fill('+15550002222');
  await page.getByRole('button', { name: 'Continue securely' }).click();
  await page.getByLabel('Login code').fill('12345');
  await page.getByRole('button', { name: 'Verify code' }).click();
  await expect(page.getByLabel('Cloud password')).toBeVisible();
  await page.getByLabel('Cloud password').fill('salvage-test-password');
  await page.getByRole('button', { name: 'Open my drive' }).click();
  await expect(page).toHaveURL(/\/drive$/);
  await page.getByRole('button', { name: 'Open navigation' }).click();
  await expect(page.getByRole('link', { name: 'Settings' })).toBeVisible();
  await page.getByRole('link', { name: 'Settings' }).click();
  await expect(page).toHaveURL(/\/settings$/);
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth + 1);
  expect(overflow).toBe(false);
});
