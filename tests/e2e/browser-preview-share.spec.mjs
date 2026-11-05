import { test, expect } from '@playwright/test';

async function signIn(page, phone) {
  await page.goto('/login');
  await page.getByLabel('Phone number').fill(phone);
  await page.getByRole('button', { name: 'Continue securely' }).click();
  await page.getByLabel('Login code').fill('12345');
  await page.getByRole('button', { name: 'Verify code' }).click();
  await expect(page).toHaveURL(/\/drive$/);
}

async function upload(page, name, content, mimeType = 'text/plain') {
  await page.getByRole('link', { name: 'Transfer center' }).click();
  await page.locator('input[type="file"][aria-label="Upload files"]').setInputFiles({
    name, mimeType, buffer: Buffer.isBuffer(content) ? content : Buffer.from(content),
  });
  const row = page.locator('.transfer-row').filter({ hasText: name });
  await expect(row.locator('.transfer-status')).toHaveText('Completed');
  await page.getByRole('link', { name: 'My drive' }).click();
  await expect(page.getByText(name, { exact: true })).toBeVisible();
}

test('text preview and one-time share creation/revocation work in the WASM UI', async ({ page, browser }) => {
  const content = 'previewed directly in the browser';
  await signIn(page, '+15550001717');
  await upload(page, 'browser-preview.txt', content);
  await page.getByRole('button', { name: 'Preview browser-preview.txt' }).click();
  await expect(page.locator('dialog pre')).toContainText(content);
  await page.getByRole('button', { name: 'Close dialog' }).click();

  await page.getByRole('button', { name: 'Share browser-preview.txt' }).click();
  await page.getByLabel('Link expires after').selectOption('0');
  await page.getByRole('button', { name: 'Create share link' }).click();
  const input = page.locator('#created-share-url');
  await expect(input).toBeVisible();
  const url = await input.inputValue();
  expect(url).toContain('/s/');
  const anonymousContext = await browser.newContext();
  const publicPage = await anonymousContext.newPage();
  await publicPage.goto(url);
  await expect(publicPage.locator('body')).toContainText(content);
  const token = url.split('/').pop();
  const persisted = await page.evaluate(() => JSON.stringify(Object.entries(localStorage)));
  expect(persisted).not.toContain(token);
  await expect(page.locator('.share-metadata-row')).toContainText('Never');

  await page.getByRole('button', { name: /Revoke share/ }).click();
  await expect.poll(async () => (await publicPage.request.get(url)).status()).toBe(404);
  await anonymousContext.close();
});

test('protected files disable preview and share actions in the UI', async ({ page }) => {
  await signIn(page, '+15550001919');
  await upload(page, 'private.tdenc2', 'ciphertext', 'application/octet-stream');
  await expect(page.getByRole('button', { name: 'Preview private.tdenc2' })).toBeDisabled();
  await expect(page.getByRole('button', { name: 'Share private.tdenc2' })).toBeDisabled();
  await expect(page.getByText('Preview and sharing are unavailable for this protected file.')).toBeVisible();
});

test('raster image preview renders the actual file', async ({ page }) => {
  const png = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=', 'base64');
  await signIn(page, '+15550001818');
  await upload(page, 'preview-image.png', png, 'image/png');
  await page.getByRole('button', { name: 'Preview preview-image.png' }).click();
  const image = page.locator('dialog img');
  await expect(image).toBeVisible();
  await expect.poll(() => image.evaluate((element) => element.naturalWidth)).toBeGreaterThan(0);
});
