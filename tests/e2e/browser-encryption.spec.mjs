import { test, expect } from '@playwright/test';
import fs from 'node:fs/promises';

async function signIn(page, phone) {
  await page.goto('/login');
  await page.getByLabel('Phone number').fill(phone);
  await page.getByRole('button', { name: 'Continue securely' }).click();
  await page.getByLabel('Login code').fill('12345');
  await page.getByRole('button', { name: 'Verify code' }).click();
  await expect(page).toHaveURL(/\/drive$/);
}

async function openTransfers(page) {
  await page.getByRole('link', { name: 'Transfer center' }).click();
  await expect(page).toHaveURL(/\/transfers/);
}

async function openSettings(page) {
  await page.getByRole('link', { name: 'Settings' }).click();
  await expect(page).toHaveURL(/\/settings/);
}

async function uploadProtected(page, name, content, mode, credential) {
  await openTransfers(page);
  await page.locator('#upload-protection').selectOption(mode);
  await page.locator('input[type="file"][aria-label="Upload files"]').setInputFiles({
    name, mimeType: 'text/plain', buffer: Buffer.from(content),
  });
  const prompt = page.locator('#protected-upload-passphrase');
  await expect(prompt).toBeVisible();
  if (credential) await prompt.fill(credential);
  await page.locator('.protected-upload-prompt button.button-primary').click();
  const row = page.locator('.transfer-row').filter({ hasText: name });
  await expect(row.getByText('Completed', { exact: true })).toBeVisible({ timeout: 30_000 });
}

async function downloadProtected(page, credential, useVault = false) {
  const file = page.locator('article').filter({ hasText: '.tdenc2' }).first();
  await file.getByRole('button', { name: /Download/ }).click();
  const input = page.locator('#protected-download-passphrase');
  await expect(input).toBeVisible();
  if (credential) await input.fill(credential);
  await page.getByRole('button', { name: useVault ? 'Use unlocked vault' : 'Use passphrase' }).click();
}

test('passphrase upload and OPFS decrypt download restore original content without secret network leakage', async ({ page }, testInfo) => {
  const content = 'browser encrypted text payload';
  const passphrase = 'correct horse battery staple';
  const requests = [];
  page.on('request', (request) => {
    const body = request.postData();
    if (body) requests.push(body);
  });
  await signIn(page, '+15550003131');
  await uploadProtected(page, 'passphrase-secret.txt', content, 'passphrase', passphrase);
  await page.getByRole('link', { name: 'My drive' }).click();
  const protectedFile = page.locator('article').filter({ hasText: '.tdenc2' }).first();
  await expect(protectedFile).toBeVisible();
  expect(requests.join('\n')).not.toContain(passphrase);
  expect(requests.join('\n')).not.toContain(content);

  const downloadEvent = page.waitForEvent('download');
  await downloadProtected(page, passphrase);
  const download = await downloadEvent;
  const destination = testInfo.outputPath('decrypted-passphrase.txt');
  await download.saveAs(destination);
  expect(await fs.readFile(destination, 'utf8')).toBe(content);
});

test('vault encryption and recovery export/import work without persisting plaintext secrets', async ({ page }, testInfo) => {
  test.setTimeout(120_000);
  const content = 'vault protected payload';
  const vaultPassphrase = 'vault secret one';
  const recoveryPassphrase = 'recovery secret two';
  await signIn(page, '+15550003232');
  await openSettings(page);
  await page.locator('#vault-passphrase').fill(vaultPassphrase);
  await page.getByRole('button', { name: 'Create vault' }).click();
  await expect(page.getByText('Vault unlocked', { exact: true })).toBeVisible({ timeout: 30_000 });
  await uploadProtected(page, 'vault-secret.txt', content, 'vault', null);
  await page.getByRole('link', { name: 'My drive' }).click();
  const downloadEvent = page.waitForEvent('download');
  await downloadProtected(page, null, true);
  const download = await downloadEvent;
  const destination = testInfo.outputPath('decrypted-vault.txt');
  await download.saveAs(destination);
  expect(await fs.readFile(destination, 'utf8')).toBe(content);

  await openSettings(page);
  await page.locator('summary').filter({ hasText: 'Export recovery' }).click();
  await page.locator('#recovery-export-passphrase').fill(recoveryPassphrase);
  const recoveryDownloadEvent = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Export recovery' }).click();
  const recoveryDownload = await recoveryDownloadEvent;
  const recoveryPath = testInfo.outputPath('vault-recovery.tdrec2');
  await recoveryDownload.saveAs(recoveryPath);
  expect((await fs.readFile(recoveryPath)).subarray(0, 6).toString()).toBe('TDREC2');
  expect((await fs.readFile(recoveryPath)).includes(Buffer.from(vaultPassphrase))).toBe(false);
  const persisted = await page.evaluate(() => JSON.stringify(Object.entries(localStorage)));
  expect(persisted).not.toContain(vaultPassphrase);

  await page.getByRole('button', { name: 'Lock vault', exact: true }).click();
  await page.locator('summary').filter({ hasText: 'Import recovery' }).click();
  await page.locator('#recovery-file').setInputFiles(recoveryPath);
  await page.waitForTimeout(250);
  await page.locator('#recovery-passphrase').fill(recoveryPassphrase);
  await page.locator('#new-vault-passphrase').fill('replacement vault secret');
  await page.getByLabel('Replace an existing encrypted vault for this account').check();
  await page.getByRole('button', { name: 'Import recovery' }).click();
  await expect(page.getByText('Vault unlocked', { exact: true })).toBeVisible({ timeout: 30_000 });
});

async function selectSyntheticProtectedFile(page, name, size, lastModified, byteOffset = 0) {
  await page.locator('input[type="file"][aria-label="Upload files"]').evaluate((input, fixture) => {
    const bytes = new Uint8Array(fixture.size);
    for (let index = 0; index < bytes.length; index += 1) bytes[index] = (index + fixture.byteOffset) % 251;
    const file = new File([bytes], fixture.name, { type: 'text/plain', lastModified: fixture.lastModified });
    const transfer = new DataTransfer();
    transfer.items.add(file);
    input.files = transfer.files;
    input.dispatchEvent(new Event('change', { bubbles: true }));
  }, { name, size, lastModified, byteOffset });
}

test('interrupted encrypted upload resumes from its original header', async ({ page, browser }, testInfo) => {
  test.setTimeout(180_000);
  const passphrase = 'resume encryption passphrase';
  await signIn(page, '+15550003434');
  await openTransfers(page);
  await page.locator('#upload-protection').selectOption('passphrase');
  let requests = 0;
  await page.route('**/api/v1/transfers/uploads/*/content', async (route) => {
    requests += 1;
    if (requests === 3) {
      await route.abort();
      await page.unroute('**/api/v1/transfers/uploads/*/content');
    } else {
      await route.continue();
    }
  });
  const size = 1024 * 1024 + 17;
  const lastModified = 1_700_000_000_000;
  await selectSyntheticProtectedFile(page, 'resume-encrypted.txt', size, lastModified);
  await page.locator('#protected-upload-passphrase').fill(passphrase);
  await page.locator('.protected-upload-prompt button.button-primary').click();
  const row = page.locator('.transfer-row').filter({ hasText: 'resume-encrypted.txt' });
  await expect(row.getByText('Needs attention', { exact: true })).toBeVisible({ timeout: 30_000 });
  expect(requests).toBe(3);

  await page.close();
  const resumedPage = await page.context().newPage();
  await resumedPage.goto('/transfers');
  await expect(resumedPage.locator('#upload-protection')).toBeVisible({ timeout: 30_000 });
  await resumedPage.locator('#upload-protection').selectOption('passphrase');
  await selectSyntheticProtectedFile(resumedPage, 'resume-encrypted.txt', size, lastModified);
  await resumedPage.locator('#protected-upload-passphrase').fill(passphrase);
  await resumedPage.locator('.protected-upload-prompt button.button-primary').click();
  await expect(resumedPage.locator('.transfer-row').filter({ hasText: 'resume-encrypted.txt' }).getByText('Completed', { exact: true })).toBeVisible({ timeout: 60_000 });
  await resumedPage.getByRole('link', { name: 'My drive' }).click();
  const downloadEvent = resumedPage.waitForEvent('download');
  await downloadProtected(resumedPage, passphrase);
  const download = await downloadEvent;
  const destination = testInfo.outputPath('resume-decrypted.txt');
  await download.saveAs(destination);
  const plaintext = await fs.readFile(destination);
  expect(plaintext.length).toBe(size);
  const expected = Buffer.allocUnsafe(size);
  for (let index = 0; index < expected.length; index += 1) expected[index] = index % 251;
  expect(plaintext.equals(expected)).toBe(true);
});

test('changed source requires a fresh encrypted restart instead of mixing ciphertext', async ({ page }, testInfo) => {
  test.setTimeout(120_000);
  const passphrase = 'changed source encryption passphrase';
  await signIn(page, '+15550003535');
  await openTransfers(page);
  await page.locator('#upload-protection').selectOption('passphrase');
  let requests = 0;
  await page.route('**/api/v1/transfers/uploads/*/content', async (route) => {
    requests += 1;
    if (requests === 3) {
      await route.abort();
      await page.unroute('**/api/v1/transfers/uploads/*/content');
    } else {
      await route.continue();
    }
  });
  const size = 1024 * 1024 + 17;
  const lastModified = 1_700_000_000_000;
  await selectSyntheticProtectedFile(page, 'changed-encrypted.txt', size, lastModified);
  await page.locator('#protected-upload-passphrase').fill(passphrase);
  await page.locator('.protected-upload-prompt button.button-primary').click();
  await expect(page.locator('.transfer-row').filter({ hasText: 'changed-encrypted.txt' }).getByText('Needs attention', { exact: true })).toBeVisible({ timeout: 30_000 });

  await page.close();
  const resumedPage = await page.context().newPage();
  await resumedPage.goto('/transfers');
  await expect(resumedPage.locator('#upload-protection')).toBeVisible({ timeout: 30_000 });
  await resumedPage.locator('#upload-protection').selectOption('passphrase');
  await selectSyntheticProtectedFile(resumedPage, 'changed-encrypted.txt', size, lastModified, 1);
  await resumedPage.locator('#protected-upload-passphrase').fill(passphrase);
  await resumedPage.locator('.protected-upload-prompt button.button-primary').click();
  const row = resumedPage.locator('.transfer-row').filter({ hasText: 'changed-encrypted.txt' });
  await expect(row.getByText('Restart required', { exact: true })).toBeVisible({ timeout: 30_000 });
  await row.getByRole('button', { name: 'Restart upload' }).click();
  await expect(row.getByText('Completed', { exact: true })).toBeVisible({ timeout: 30_000 });

  await resumedPage.getByRole('link', { name: 'My drive' }).click();
  const downloadEvent = resumedPage.waitForEvent('download');
  await downloadProtected(resumedPage, passphrase);
  const download = await downloadEvent;
  const destination = testInfo.outputPath('changed-source-decrypted.txt');
  await download.saveAs(destination);
  const plaintext = await fs.readFile(destination);
  const expected = Buffer.allocUnsafe(size);
  for (let index = 0; index < expected.length; index += 1) expected[index] = (index + 1) % 251;
  expect(plaintext.equals(expected)).toBe(true);
});

test('ciphertext corruption refuses browser publication and removes OPFS artifacts', async ({ page }) => {
  const passphrase = 'corruption detection passphrase';
  await signIn(page, '+15550003636');
  await uploadProtected(page, 'corruption-check.txt', 'authenticated browser payload', 'passphrase', passphrase);
  await page.getByRole('link', { name: 'My drive' }).click();
  let downloaded = false;
  page.on('download', () => { downloaded = true; });
  await page.route('**/api/v1/transfers/*/content*', async (route) => {
    const response = await route.fetch();
    const corrupted = Buffer.from(await response.body());
    corrupted[Math.floor(corrupted.length / 2)] ^= 1;
    await route.fulfill({ response, body: corrupted });
    await page.unroute('**/api/v1/transfers/*/content*');
  });
  await downloadProtected(page, passphrase);
  await expect(page.getByRole('alert')).toBeVisible({ timeout: 30_000 });
  const entries = await page.evaluate(async () => {
    const root = await navigator.storage.getDirectory();
    const names = [];
    for await (const [name] of root.entries()) names.push(name);
    return names;
  });
  expect(entries).toHaveLength(0);
  expect(downloaded).toBe(false);
});

test('browser worker decrypts the frozen golden envelope through an imported vault', async ({ page }, testInfo) => {
  test.setTimeout(120_000);
  const vaultPassphrase = 'public v3.9.8 vault fixture passphrase';
  await signIn(page, '+15550003737');
  await openSettings(page);
  await page.locator('summary').filter({ hasText: 'Open an encrypted vault container' }).click();
  await page.locator('#vault-container').setInputFiles(new URL('../../fixtures/tdenc2/v3.9.8-vault.bin', import.meta.url).pathname);
  await page.waitForTimeout(250);
  await page.locator('#vault-passphrase').fill(vaultPassphrase);
  await page.getByRole('button', { name: 'Open vault', exact: true }).click();
  await expect(page.getByText('Vault unlocked', { exact: true })).toBeVisible({ timeout: 30_000 });

  const golden = await fs.readFile(new URL('../../fixtures/tdenc2/v3.9.8-envelope.tdenc', import.meta.url));
  const session = await (await page.request.get('/api/v1/auth/session')).json();
  const created = await page.request.post('/api/v1/transfers/uploads', {
    data: {
      name: 'golden-envelope.tdenc2', folder_id: null, size: golden.length,
      mime_type: 'application/octet-stream', source_modified_ms: 1_700_000_000_000,
      prefix_sha256: null, protected: true,
    },
    headers: { 'X-CSRF-Token': session.csrf_token, Origin: 'http://127.0.0.1:4173' },
  });
  expect(created.status()).toBe(200);
  const upload = await created.json();
  const appended = await page.request.put(`/api/v1/transfers/uploads/${upload.transfer.id}/content`, {
    data: golden,
    headers: {
      'X-CSRF-Token': session.csrf_token,
      'X-Upload-Offset': '0',
      'Content-Type': 'application/octet-stream',
      Origin: 'http://127.0.0.1:4173',
    },
  });
  expect(appended.status()).toBe(200);
  const completed = await page.request.post(`/api/v1/transfers/uploads/${upload.transfer.id}/complete`, {
    headers: { 'X-CSRF-Token': session.csrf_token, Origin: 'http://127.0.0.1:4173' },
  });
  expect(completed.status()).toBe(200);

  await page.getByRole('link', { name: 'My drive' }).click();
  const downloadEvent = page.waitForEvent('download');
  await downloadProtected(page, null, true);
  const download = await downloadEvent;
  const destination = testInfo.outputPath('golden-browser-decrypted.bin');
  await download.saveAs(destination);
  const plaintext = await fs.readFile(destination);
  const expected = Buffer.allocUnsafe(1024 * 1024 + 17);
  for (let index = 0; index < expected.length; index += 1) expected[index] = index % 251;
  expect(plaintext.equals(expected)).toBe(true);
});

test('encrypted vault containers and unlocked keys remain isolated across account switches', async ({ page }) => {
  test.setTimeout(120_000);
  const vaultPassphrase = 'public v3.9.8 vault fixture passphrase';
  await signIn(page, '+15550003939');
  await openSettings(page);
  await page.locator('summary').filter({ hasText: 'Open an encrypted vault container' }).click();
  await page.locator('#vault-container').setInputFiles(new URL('../../fixtures/tdenc2/v3.9.8-vault.bin', import.meta.url).pathname);
  await page.waitForTimeout(250);
  await page.locator('#vault-passphrase').fill(vaultPassphrase);
  await page.getByRole('button', { name: 'Open vault', exact: true }).click();
  await expect(page.getByText('Vault unlocked', { exact: true })).toBeVisible({ timeout: 30_000 });

  await page.getByLabel('Sign out', { exact: true }).click();
  await signIn(page, '+15550004040');
  await openSettings(page);
  await expect(page.getByText('Vault locked', { exact: true })).toBeVisible();
  await page.locator('#vault-passphrase').fill(vaultPassphrase);
  await page.getByRole('button', { name: 'Unlock vault', exact: true }).click();
  await expect(page.getByRole('alert')).toBeVisible({ timeout: 30_000 });
  await expect(page.getByText('Vault unlocked', { exact: true })).toHaveCount(0);

  await page.getByLabel('Sign out', { exact: true }).click();
  await signIn(page, '+15550003939');
  await openSettings(page);
  await expect(page.getByText('Vault locked', { exact: true })).toBeVisible();
  await page.locator('#vault-passphrase').fill(vaultPassphrase);
  await page.getByRole('button', { name: 'Unlock vault', exact: true }).click();
  await expect(page.getByText('Vault unlocked', { exact: true })).toBeVisible({ timeout: 30_000 });
});

test('account switch cancels an active protected job without resuming its journal', async ({ page }, testInfo) => {
  test.setTimeout(120_000);
  const passphrase = 'account switch encryption passphrase';
  await signIn(page, '+15550004141');
  await openTransfers(page);
  await page.locator('#upload-protection').selectOption('passphrase');
  let requests = 0;
  let markThirdStarted;
  const thirdStarted = new Promise((resolve) => { markThirdStarted = resolve; });
  let releaseThird;
  const thirdReleased = new Promise((resolve) => { releaseThird = resolve; });
  await page.route('**/api/v1/transfers/uploads/*/content', async (route) => {
    requests += 1;
    if (requests === 3) {
      markThirdStarted();
      await thirdReleased;
      await route.abort().catch((error) => {
        if (!String(error).includes('Route is already handled')) throw error;
      });
    } else {
      await route.continue();
    }
  });
  const size = 1024 * 1024 + 17;
  const lastModified = 1_700_000_000_000;
  await selectSyntheticProtectedFile(page, 'account-switch-encrypted.txt', size, lastModified);
  await page.locator('#protected-upload-passphrase').fill(passphrase);
  await page.locator('.protected-upload-prompt button.button-primary').click();
  await thirdStarted;
  const logoutResponse = page.waitForResponse('**/api/v1/auth/logout');
  await page.getByLabel('Sign out', { exact: true }).click();
  await expect(page).toHaveURL(/\/login$/);
  await logoutResponse;
  releaseThird();
  await page.unroute('**/api/v1/transfers/uploads/*/content');

  await signIn(page, '+15550004242');
  await openTransfers(page);
  await expect(page.locator('.transfer-row')).toHaveCount(0);
  const opfsEntries = await page.evaluate(async () => {
    const root = await navigator.storage.getDirectory();
    const names = [];
    for await (const [name] of root.entries()) names.push(name);
    return names;
  });
  expect(opfsEntries).toHaveLength(0);
  await page.locator('#upload-protection').selectOption('passphrase');
  await selectSyntheticProtectedFile(page, 'account-switch-encrypted.txt', size, lastModified);
  await page.locator('#protected-upload-passphrase').fill(passphrase);
  await page.locator('.protected-upload-prompt button.button-primary').click();
  const row = page.locator('.transfer-row').filter({ hasText: 'account-switch-encrypted.txt' });
  await expect(row.getByText('Completed', { exact: true })).toBeVisible({ timeout: 30_000 });

  await page.getByRole('link', { name: 'My drive' }).click();
  const downloadEvent = page.waitForEvent('download');
  await downloadProtected(page, passphrase);
  const download = await downloadEvent;
  const destination = testInfo.outputPath('account-switch-decrypted.txt');
  await download.saveAs(destination);
  const plaintext = await fs.readFile(destination);
  const expected = Buffer.allocUnsafe(size);
  for (let index = 0; index < expected.length; index += 1) expected[index] = index % 251;
  expect(plaintext.equals(expected)).toBe(true);
});

test('wrong passphrase refuses publication and leaves no plaintext OPFS artifact', async ({ page }) => {
  const content = 'must never be published incorrectly';
  await signIn(page, '+15550003333');
  await uploadProtected(page, 'wrong-key.txt', content, 'passphrase', 'right passphrase');
  await page.getByRole('link', { name: 'My drive' }).click();
  await downloadProtected(page, 'wrong passphrase');
  await expect(page.getByRole('alert')).toBeVisible({ timeout: 30_000 });
  const entries = await page.evaluate(async () => {
    const root = await navigator.storage.getDirectory();
    const names = [];
    for await (const [name] of root.entries()) names.push(name);
    return names;
  });
  expect(entries).toHaveLength(0);
});