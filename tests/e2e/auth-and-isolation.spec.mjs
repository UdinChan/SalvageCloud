import { test, expect } from '@playwright/test';
import { apiContext, createFolder, login } from './helpers.mjs';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

test('health, phone login, cloud password, restore and logout use real HTTP and storage', async ({ playwright }) => {
  const context = await apiContext(playwright);
  const health = await context.get('/api/health');
  expect(health.status()).toBe(200);
  expect((await health.json()).status).toBe('ok');

  const badCodeAttempt = await context.post('/api/v1/auth/phone', { data: { phone: '+15550009999' } });
  const badAttempt = await badCodeAttempt.json();
  const badCode = await context.post('/api/v1/auth/code', {
    data: { attempt_id: badAttempt.attempt_id, code: '00000' },
  });
  expect(badCode.status()).toBe(401);

  const session = await login(context, '+15550002222');
  expect(session.account.display_name).toContain('22');
  const restored = await context.get('/api/v1/auth/session');
  expect(restored.status()).toBe(200);
  expect((await restored.json()).account.id).toBe(session.account.id);

  const rootFiles = await context.get('/api/v1/files');
  expect(rootFiles.status()).toBe(200);
  expect((await rootFiles.json()).files.map((file) => file.name)).toContain('Welcome to Salvage Cloud.txt');

  const logout = await context.post('/api/v1/auth/logout', {
    headers: { 'X-CSRF-Token': session.csrf_token },
  });
  expect(logout.status()).toBe(204);
  expect((await context.get('/api/v1/auth/session')).status()).toBe(401);
  await context.dispose();
});

test('phone requests and verification failures are rate-limited without affecting another account', async ({ playwright }) => {
  const context = await apiContext(playwright);
  for (let attempt = 0; attempt < 5; attempt += 1) {
    const response = await context.post('/api/v1/auth/phone', { data: { phone: '+15550009990' } });
    expect(response.status()).toBe(200);
  }
  const throttled = await context.post('/api/v1/auth/phone', { data: { phone: '+15550009990' } });
  expect(throttled.status()).toBe(429);

  const started = await context.post('/api/v1/auth/phone', { data: { phone: '+15550009991' } });
  expect(started.status()).toBe(200);
  const { attempt_id: attemptId } = await started.json();
  for (let failure = 0; failure < 4; failure += 1) {
    const rejected = await context.post('/api/v1/auth/code', {
      data: { attempt_id: attemptId, code: '00000' },
    });
    expect(rejected.status()).toBe(401);
  }
  const finalFailure = await context.post('/api/v1/auth/code', {
    data: { attempt_id: attemptId, code: '00000' },
  });
  expect(finalFailure.status()).toBe(429);
  const invalidated = await context.post('/api/v1/auth/code', {
    data: { attempt_id: attemptId, code: '12345' },
  });
  expect(invalidated.status()).toBe(401);

  const otherAccount = await login(context, '+15550009992');
  expect(otherAccount.account.display_name).toContain('92');
  await context.dispose();
});

test('two accounts cannot mutate each other\'s objects and CSRF/origin checks are enforced', async ({ playwright }) => {
  const first = await apiContext(playwright);
  const second = await apiContext(playwright);
  const firstSession = await login(first, '+15550001001');
  const secondSession = await login(second, '+15550002002');
  const privateFolder = await createFolder(first, firstSession, 'First account private folder');

  const foreignRename = await second.patch(`/api/v1/folders/${privateFolder.id}`, {
    data: { name: 'Cross-account overwrite' },
    headers: { 'X-CSRF-Token': secondSession.csrf_token },
  });
  expect(foreignRename.status()).toBe(404);
  const foreignDelete = await second.delete(`/api/v1/folders/${privateFolder.id}`, {
    headers: { 'X-CSRF-Token': secondSession.csrf_token },
  });
  expect(foreignDelete.status()).toBe(404);

  const noCsrf = await first.post('/api/v1/folders', {
    data: { name: 'Missing CSRF', parent_id: null },
    headers: { 'X-CSRF-Token': '' },
  });
  expect(noCsrf.status()).toBe(401);
  const wrongOrigin = await first.post('/api/v1/folders', {
    data: { name: 'Wrong origin', parent_id: null },
    headers: { 'X-CSRF-Token': firstSession.csrf_token, Origin: 'https://attacker.invalid' },
  });
  expect(wrongOrigin.status()).toBe(403);

  const stillThere = await first.get('/api/v1/folders');
  expect((await stillThere.json()).some((folder) => folder.id === privateFolder.id)).toBe(true);
  const secondFolders = await second.get('/api/v1/folders');
  expect((await secondFolders.json()).some((folder) => folder.id === privateFolder.id)).toBe(false);
  await Promise.all([first.dispose(), second.dispose()]);
});

test('loopback tunnels are accepted only without allowing external origins', async ({ playwright }) => {
  const context = await apiContext(playwright);
  const session = await login(context, '+15550001111');
  const response = await context.post('/api/v1/folders', {
    data: { name: 'Loopback tunnel folder', parent_id: null },
    headers: { 'X-CSRF-Token': session.csrf_token, Origin: 'http://localhost:3000' },
  });
  expect(response.status()).toBe(200);
  const rejected = await context.post('/api/v1/folders', {
    data: { name: 'External origin folder', parent_id: null },
    headers: { 'X-CSRF-Token': session.csrf_token, Origin: 'https://attacker.invalid' },
  });
  expect(rejected.status()).toBe(403);
  await context.dispose();
});

test('web and Telegram session secrets are not written in plaintext', async ({ playwright }) => {
  const context = await apiContext(playwright);
  const session = await login(context, '+15550003003');
  const { cookies } = await context.storageState();
  const token = cookies.find((cookie) => cookie.name === 'salvage_session')?.value;
  expect(token).toBeTruthy();

  const dataRoot = path.join(root, '.e2e-data');
  const pending = [dataRoot];
  const files = [];
  while (pending.length) {
    const current = pending.pop();
    for (const entry of await fs.readdir(current, { withFileTypes: true })) {
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) pending.push(full);
      else files.push(full);
    }
  }
  expect(files.some((file) => file.endsWith('telegram.session.scse'))).toBe(true);
  for (const file of files) {
    const bytes = await fs.readFile(file);
    expect(bytes.includes(Buffer.from(token))).toBe(false);
    if (file.endsWith('telegram.session.scse')) {
      expect(bytes.subarray(0, 6).toString()).toBe('SCSES1');
      expect(bytes.includes(Buffer.from(session.account.telegram_user_id.toString()))).toBe(false);
    }
  }
  await context.dispose();
});
