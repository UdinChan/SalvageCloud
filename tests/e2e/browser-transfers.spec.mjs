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

async function selectSyntheticFile(page, name, size, lastModified) {
  await page.locator('input[type="file"]').evaluate((input, fixture) => {
    const bytes = new Uint8Array(fixture.size);
    for (let index = 0; index < bytes.length; index += 1) bytes[index] = index % 251;
    const file = new File([bytes], fixture.name, { type: 'text/plain', lastModified: fixture.lastModified });
    const transfer = new DataTransfer();
    transfer.items.add(file);
    input.files = transfer.files;
    input.dispatchEvent(new Event('change', { bubbles: true }));
  }, { name, size, lastModified });
}

test('WASM upload, drive download and transfer history use real files', async ({ page }, testInfo) => {
  await signIn(page, '+15550009009');
  await openTransfers(page);
  const content = Buffer.from('uploaded through the Rust WASM interface', 'utf8');
  await page.locator('input[type="file"][aria-label="Upload files"]').setInputFiles({
    name: 'browser-upload.txt', mimeType: 'text/plain', buffer: content,
  });
  const uploadRow = page.locator('.transfer-row').filter({ hasText: 'browser-upload.txt' });
  await expect(uploadRow.locator('.transfer-status')).toHaveText('Completed');

  await page.getByRole('link', { name: 'My drive' }).click();
  await expect(page.getByText('browser-upload.txt', { exact: true })).toBeVisible();
  const downloadEvent = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Download browser-upload.txt' }).click();
  const download = await downloadEvent;
  const destination = testInfo.outputPath('browser-upload-downloaded.txt');
  await download.saveAs(destination);
  expect(await fs.readFile(destination, 'utf8')).toBe(content.toString('utf8'));

  await openTransfers(page);
  await expect(page.locator('.transfer-row').filter({ hasText: 'browser-upload.txt' })).toHaveCount(2);
  await expect(page.locator('.transfer-status').filter({ hasText: /Completed|Ready/ })).toHaveCount(2);
});

test('bot settings and active-channel selection publish through the compiled WASM UI', async ({ page }) => {
  await signIn(page, '+15550004343');
  await page.getByRole('link', { name: 'Settings' }).click();
  await page.locator('#bot-label').fill('UI channel bot');
  await page.locator('#bot-token').fill('fixture-bot-token');
  await page.getByRole('button', { name: 'Add bot' }).click();
  await expect(page.getByText('@salvage_fixture_bot')).toBeVisible();
  await page.getByRole('button', { name: 'Sync access' }).click();
  await expect(page.getByText('Bot access synchronized across current channels.')).toBeVisible();

  await page.getByRole('link', { name: 'My drive' }).click();
  await page.getByRole('button', { name: 'New channel' }).click();
  await page.getByLabel('Channel name').fill('UI bot channel');
  await page.getByRole('button', { name: 'Create channel', exact: true }).click();
  await page.getByRole('link', { name: /UI bot channel/ }).click();
  await page.getByRole('link', { name: 'Upload files' }).click();
  await expect(page.locator('#upload-bot')).toBeVisible();
  await page.locator('#upload-bot').selectOption({ label: 'UI channel bot' });
  await page.locator('input[type="file"][aria-label="Upload files"]').setInputFiles({
    name: 'ui-bot-upload.txt', mimeType: 'text/plain', buffer: Buffer.from('published by UI bot'),
  });
  const row = page.locator('.transfer-row').filter({ hasText: 'ui-bot-upload.txt' });
  await expect(row.getByText('Completed', { exact: true })).toBeVisible({ timeout: 30_000 });
  await page.getByRole('link', { name: 'My drive' }).click();
  await page.getByRole('link', { name: /UI bot channel/ }).click();
  await expect(page.getByText('ui-bot-upload.txt', { exact: true })).toBeVisible();

  await page.getByRole('link', { name: 'Settings' }).click();
  await page.getByRole('button', { name: 'Remove', exact: true }).click();
  await expect(page.getByText('UI channel bot', { exact: true })).toHaveCount(0);
});

test('interrupted browser upload resumes after reload with the original file', async ({ page }) => {
  await signIn(page, '+15550001010');
  await openTransfers(page);
  const size = 5 * 1024 * 1024 + 17;
  const lastModified = 1_700_000_000_000;
  let aborted = false;
  await page.route('**/api/v1/transfers/uploads/*/content', async (route) => {
    if (!aborted && route.request().headers()['x-upload-offset'] === '4194304') {
      aborted = true;
      await route.abort();
    } else {
      await route.continue();
    }
  });
  await selectSyntheticFile(page, 'resume-browser.txt', size, lastModified);
  const interruptedRow = page.locator('.transfer-row').filter({ hasText: 'resume-browser.txt' });
  await expect(interruptedRow.locator('.transfer-status')).toHaveText('Needs attention');
  expect(aborted).toBe(true);
  const resumeMetadata = await page.evaluate(() => localStorage.getItem('salvage-cloud.upload-resume-metadata.v1'));
  expect(resumeMetadata).toContain('4194304');

  await page.unroute('**/api/v1/transfers/uploads/*/content');
  await page.reload();
  await expect(page.locator('input[type="file"][aria-label="Upload files"]')).toBeVisible();
  await selectSyntheticFile(page, 'resume-browser.txt', size, lastModified);
  await expect(interruptedRow.locator('.transfer-status')).toHaveText('Completed');
  const remainingMetadata = await page.evaluate(() => localStorage.getItem('salvage-cloud.upload-resume-metadata.v1'));
  expect(remainingMetadata).not.toContain('resume-browser.txt');
});
