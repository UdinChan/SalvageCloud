import { test, expect } from '@playwright/test';
import { spawn } from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { login, uploadFile } from './helpers.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const dataDir = path.join(root, '.e2e-restart');
const origin = 'http://127.0.0.1:4174';

async function startServer() {
  const child = spawn(path.join(root, 'target/debug/salvage-server'), {
    cwd: root,
    env: {
      ...process.env,
      SALVAGE_BIND: '127.0.0.1:4174',
      SALVAGE_DATA_DIR: dataDir,
      SALVAGE_WEB_DIST: path.join(root, 'dist'),
      SALVAGE_PUBLIC_ORIGIN: origin,
      SALVAGE_COOKIE_SECURE: 'false',
      SALVAGE_SESSION_KEY: '33'.repeat(32),
      SALVAGE_TELEGRAM_TRANSPORT: 'fixture',
      RUST_LOG: 'info',
    },
    stdio: 'ignore',
  });
  const deadline = Date.now() + 20_000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error('restart fixture server exited early');
    try {
      const response = await fetch(`${origin}/api/health`);
      if (response.ok) return child;
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  child.kill('SIGTERM');
  throw new Error('restart fixture server did not become ready');
}

async function stopServer(child) {
  if (child.exitCode !== null) return;
  const exited = new Promise((resolve) => child.once('exit', resolve));
  child.kill('SIGTERM');
  await exited;
}

test('backend restart preserves web session and resumable staged upload', async ({ playwright }) => {
  test.setTimeout(120_000);
  await fs.rm(dataDir, { recursive: true, force: true });
  let server = await startServer();
  const context = await playwright.request.newContext({ baseURL: origin, extraHTTPHeaders: { Origin: origin } });
  const anonymous = await playwright.request.newContext({ baseURL: origin });
  try {
    const session = await login(context, '+15550008008');
    const content = Buffer.from('restart-safe-content', 'utf8');
    const request = {
      name: 'restart.txt', folder_id: null, size: content.length, mime_type: 'text/plain',
      source_modified_ms: 1_700_000_000_000, prefix_sha256: null,
    };
    const created = await context.post('/api/v1/transfers/uploads', {
      data: request, headers: { 'X-CSRF-Token': session.csrf_token },
    });
    expect(created.status()).toBe(200);
    const upload = await created.json();
    const prefix = content.subarray(0, 7);
    const chunk = await context.put(`/api/v1/transfers/uploads/${upload.transfer.id}/content`, {
      data: prefix,
      headers: { 'X-CSRF-Token': session.csrf_token, 'X-Upload-Offset': '0' },
    });
    expect(chunk.status()).toBe(200);
    const shared = await uploadFile(context, session, 'shared-restart.txt', 'snapshot survives restart');
    const shareResponse = await context.post(`/api/v1/files/${shared.file.id}/shares`, {
      data: { expires_in_hours: 1 }, headers: { 'X-CSRF-Token': session.csrf_token },
    });
    expect(shareResponse.status()).toBe(200);
    const share = await shareResponse.json();

    await stopServer(server);
    server = await startServer();
    const restored = await context.get('/api/v1/auth/session');
    expect(restored.status()).toBe(200);
    const publicRead = await anonymous.get(share.url_path);
    expect(publicRead.status()).toBe(200);
    expect(await publicRead.text()).toBe('snapshot survives restart');

    const resumed = await context.post('/api/v1/transfers/uploads', {
      data: { ...request, prefix_sha256: crypto.createHash('sha256').update(prefix).digest('hex') },
      headers: { 'X-CSRF-Token': session.csrf_token },
    });
    expect(resumed.status()).toBe(200);
    expect((await resumed.json()).next_offset).toBe(7);
    const remainder = await context.put(`/api/v1/transfers/uploads/${upload.transfer.id}/content`, {
      data: content.subarray(7),
      headers: { 'X-CSRF-Token': session.csrf_token, 'X-Upload-Offset': '7' },
    });
    expect(remainder.status()).toBe(200);
    const completed = await context.post(`/api/v1/transfers/uploads/${upload.transfer.id}/complete`, {
      headers: { 'X-CSRF-Token': session.csrf_token },
    });
    expect(completed.status()).toBe(200);
    expect((await completed.json()).transfer.status).toBe('completed');
  } finally {
    await context.dispose();
    await anonymous.dispose();
    await stopServer(server);
    await fs.rm(dataDir, { recursive: true, force: true });
  }
});
