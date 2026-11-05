import { test, expect } from '@playwright/test';
import { apiContext, baseURL, login, uploadFile } from './helpers.mjs';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

test('public snapshots support anonymous reads, Range, logout, and owner revocation', async ({ playwright }) => {
  const owner = await apiContext(playwright);
  const other = await apiContext(playwright);
  const anonymous = await playwright.request.newContext({ baseURL });
  const ownerSession = await login(owner, '+15550001313');
  const otherSession = await login(other, '+15550001414');
  const content = 'public snapshot text';
  const uploaded = await uploadFile(owner, ownerSession, 'public-note.txt', content);
  const createdResponse = await owner.post(`/api/v1/files/${uploaded.file.id}/shares`, {
    data: { expires_in_hours: 2 },
    headers: { 'X-CSRF-Token': ownerSession.csrf_token },
  });
  expect(createdResponse.status()).toBe(200);
  const created = await createdResponse.json();
  expect(created.share.name).toBe('public-note.txt');
  expect(created.share.revoked_at).toBeNull();
  const token = created.url_path.split('/').pop();
  expect(token).toHaveLength(43);

  const listed = await owner.get(`/api/v1/files/${uploaded.file.id}/shares`);
  expect(listed.status()).toBe(200);
  expect(JSON.stringify(await listed.json())).not.toContain(token);
  const publicRead = await anonymous.get(created.url_path);
  expect(publicRead.status()).toBe(200);
  expect(await publicRead.text()).toBe(content);
  expect(publicRead.headers()['content-disposition']).toContain('inline');
  expect(publicRead.headers()['cache-control']).toContain('no-store');
  expect(publicRead.headers()['referrer-policy']).toBe('no-referrer');
  const range = await anonymous.get(created.url_path, { headers: { Range: 'bytes=0-5' } });
  expect(range.status()).toBe(206);
  const attachment = await anonymous.get(`${created.url_path}?download=1`);
  expect(attachment.headers()['content-disposition']).toContain('attachment');

  const foreignRevoke = await other.delete(`/api/v1/shares/${created.share.id}`, {
    headers: { 'X-CSRF-Token': otherSession.csrf_token },
  });
  expect(foreignRevoke.status()).toBe(404);
  expect((await anonymous.get(created.url_path)).status()).toBe(200);
  const logout = await owner.post('/api/v1/auth/logout', {
    headers: { 'X-CSRF-Token': ownerSession.csrf_token },
  });
  expect(logout.status()).toBe(204);
  expect((await anonymous.get(created.url_path)).status()).toBe(200);

  const ownerAgain = await login(owner, '+15550001313');
  const revoked = await owner.delete(`/api/v1/shares/${created.share.id}`, {
    headers: { 'X-CSRF-Token': ownerAgain.csrf_token },
  });
  expect(revoked.status()).toBe(200);
  expect((await revoked.json()).revoked_at).not.toBeNull();
  expect((await anonymous.get(created.url_path)).status()).toBe(404);
  expect((await anonymous.get('/s/not-a-real-share')).status()).toBe(404);

  const pending = [path.join(root, '.e2e-data')];
  while (pending.length) {
    const current = pending.pop();
    for (const entry of await fs.readdir(current, { withFileTypes: true })) {
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) pending.push(full);
      else expect((await fs.readFile(full)).includes(Buffer.from(token))).toBe(false);
    }
  }
  await Promise.all([owner.dispose(), other.dispose(), anonymous.dispose()]);
});

test('non-expiring links remain public until revoked', async ({ playwright }) => {
  const owner = await apiContext(playwright);
  const anonymous = await playwright.request.newContext({ baseURL });
  const session = await login(owner, '+15550002020');
  const uploaded = await uploadFile(owner, session, 'never-expires.txt', 'no expiry');
  const createdResponse = await owner.post(`/api/v1/files/${uploaded.file.id}/shares`, {
    data: { expires_in_hours: 0 }, headers: { 'X-CSRF-Token': session.csrf_token },
  });
  expect(createdResponse.status()).toBe(200);
  const created = await createdResponse.json();
  expect(created.share.expires_at).toBeNull();
  expect((await anonymous.get(created.url_path)).status()).toBe(200);
  const listed = await owner.get(`/api/v1/files/${uploaded.file.id}/shares`);
  expect((await listed.json())[0].expires_at).toBeNull();
  const revoked = await owner.delete(`/api/v1/shares/${created.share.id}`, {
    headers: { 'X-CSRF-Token': session.csrf_token },
  });
  expect(revoked.status()).toBe(200);
  expect((await anonymous.get(created.url_path)).status()).toBe(404);
  await Promise.all([owner.dispose(), anonymous.dispose()]);
});

test('expiring links stop resolving through the public endpoint', async ({ playwright }) => {
  const owner = await apiContext(playwright);
  const anonymous = await playwright.request.newContext({ baseURL });
  const session = await login(owner, '+15550001616');
  const uploaded = await uploadFile(owner, session, 'short-lived.txt', 'one second only');
  const created = await owner.post(`/api/v1/files/${uploaded.file.id}/shares`, {
    data: { expires_in_seconds: 1 }, headers: { 'X-CSRF-Token': session.csrf_token },
  });
  expect(created.status()).toBe(200);
  const share = await created.json();
  expect((await anonymous.get(share.url_path)).status()).toBe(200);
  await expect.poll(async () => (await anonymous.get(share.url_path)).status(), { timeout: 5_000 }).toBe(404);
  await Promise.all([owner.dispose(), anonymous.dispose()]);
});

test('active content is attachment-only, PDF frames are same-origin, and protected files cannot share', async ({ playwright }) => {
  const owner = await apiContext(playwright);
  const anonymous = await playwright.request.newContext({ baseURL });
  const session = await login(owner, '+15550001515');
  const html = await uploadFile(owner, session, 'active.html', '<script>alert(1)</script>', 'text/html');
  const htmlShareResponse = await owner.post(`/api/v1/files/${html.file.id}/shares`, {
    data: {}, headers: { 'X-CSRF-Token': session.csrf_token },
  });
  const htmlShare = await htmlShareResponse.json();
  const htmlPublic = await anonymous.get(htmlShare.url_path);
  expect(htmlPublic.headers()['content-disposition']).toContain('attachment');
  expect(htmlPublic.headers()['x-content-type-options']).toBe('nosniff');

  const pdf = await uploadFile(owner, session, 'preview.pdf', '%PDF-1.4\n', 'application/pdf');
  const pdfShareResponse = await owner.post(`/api/v1/files/${pdf.file.id}/shares`, {
    data: {}, headers: { 'X-CSRF-Token': session.csrf_token },
  });
  const pdfShare = await pdfShareResponse.json();
  const pdfPublic = await anonymous.get(pdfShare.url_path);
  expect(pdfPublic.headers()['content-disposition']).toContain('inline');
  expect(pdfPublic.headers()['x-frame-options']).toBe('SAMEORIGIN');
  expect(pdfPublic.headers()['content-security-policy']).toContain("frame-ancestors 'self'");

  const protectedFile = await uploadFile(owner, session, 'private.tdenc2', 'ciphertext', 'application/octet-stream');
  const protectedShare = await owner.post(`/api/v1/files/${protectedFile.file.id}/shares`, {
    data: {}, headers: { 'X-CSRF-Token': session.csrf_token },
  });
  expect(protectedShare.status()).toBe(400);
  const protectedDownloadResponse = await owner.post(`/api/v1/transfers/downloads/${protectedFile.file.id}`, {
    headers: { 'X-CSRF-Token': session.csrf_token },
  });
  expect(protectedDownloadResponse.status()).toBe(200);
  const protectedDownload = await protectedDownloadResponse.json();
  const protectedPreview = await owner.get(`${protectedDownload.download_url}?inline=1`);
  expect(protectedPreview.status()).toBe(400);
  expect((await owner.get(protectedDownload.download_url)).status()).toBe(200);
  await Promise.all([owner.dispose(), anonymous.dispose()]);
});
