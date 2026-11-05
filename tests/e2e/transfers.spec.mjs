import { test, expect } from '@playwright/test';
import { apiContext, createFolder, login } from './helpers.mjs';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

async function createUpload(request, session, name, size, modified = 1_700_000_000_000) {
  const response = await request.post('/api/v1/transfers/uploads', {
    data: {
      name,
      folder_id: null,
      size,
      mime_type: 'text/plain',
      source_modified_ms: modified,
      prefix_sha256: null,
    },
    headers: { 'X-CSRF-Token': session.csrf_token },
  });
  expect(response.status()).toBe(200);
  return response.json();
}

async function putChunk(request, session, upload, offset, bytes) {
  const response = await request.put(`/api/v1/transfers/uploads/${upload.transfer.id}/content`, {
    data: bytes,
    headers: {
      'X-CSRF-Token': session.csrf_token,
      'X-Upload-Offset': String(offset),
      'Content-Type': 'application/octet-stream',
    },
  });
  expect(response.status()).toBe(200);
  return response.json();
}

async function complete(request, session, id) {
  const response = await request.post(`/api/v1/transfers/uploads/${id}/complete`, {
    headers: { 'X-CSRF-Token': session.csrf_token },
  });
  expect(response.status()).toBe(200);
  return response.json();
}

test('chunked upload, verified download and Range work through real storage', async ({ playwright }) => {
  const first = await apiContext(playwright);
  const second = await apiContext(playwright);
  const firstSession = await login(first, '+15550005005');
  await login(second, '+15550006006');
  const content = Buffer.from('hello durable world', 'utf8');
  const upload = await createUpload(first, firstSession, 'durable.txt', content.length);
  await putChunk(first, firstSession, upload, 0, content.subarray(0, 5));
  await putChunk(first, firstSession, upload, 5, content.subarray(5));
  const completed = await complete(first, firstSession, upload.transfer.id);
  expect(completed.transfer.status).toBe('completed');
  expect(completed.file.size).toBe(content.length);

  const downloadResponse = await first.post(`/api/v1/transfers/downloads/${completed.file.id}`, {
    headers: { 'X-CSRF-Token': firstSession.csrf_token },
  });
  expect(downloadResponse.status()).toBe(200);
  const download = await downloadResponse.json();
  const full = await first.get(download.download_url);
  expect(full.status()).toBe(200);
  expect(await full.text()).toBe(content.toString('utf8'));
  expect(full.headers()['content-type']).toBe('text/plain');
  expect(full.headers()['content-disposition']).toContain('attachment');
  const inline = await first.get(`${download.download_url}?inline=1`);
  expect(inline.status()).toBe(200);
  expect(inline.headers()['content-disposition']).toContain('inline');
  expect(inline.headers()['cache-control']).toContain('no-store');
  const range = await first.get(download.download_url, { headers: { Range: 'bytes=0-4' } });
  expect(range.status()).toBe(206);
  expect(await range.text()).toBe('hello');

  const foreignComplete = await second.post(`/api/v1/transfers/uploads/${upload.transfer.id}/complete`, {
    headers: { 'X-CSRF-Token': (await second.get('/api/v1/auth/session').then((r) => r.json())).csrf_token },
  });
  expect(foreignComplete.status()).toBe(404);
  const foreignDownload = await second.get(download.download_url);
  expect(foreignDownload.status()).toBe(404);
  await Promise.all([first.dispose(), second.dispose()]);
});

test('protected upload contract stores only generic ciphertext metadata', async ({ playwright }) => {
  const context = await apiContext(playwright);
  const session = await login(context, '+15550002323');
  const ciphertext = Buffer.from('client-produced-ciphertext');
  const created = await context.post('/api/v1/transfers/uploads', {
    data: {
      name: 'TDENC2-contract.tdenc2', folder_id: null, size: ciphertext.length,
      mime_type: 'application/octet-stream', source_modified_ms: 1_700_000_000_000,
      prefix_sha256: null, protected: true,
    },
    headers: { 'X-CSRF-Token': session.csrf_token },
  });
  expect(created.status()).toBe(200);
  const upload = await created.json();
  const chunk = await context.put(`/api/v1/transfers/uploads/${upload.transfer.id}/content`, {
    data: ciphertext,
    headers: { 'X-CSRF-Token': session.csrf_token, 'X-Upload-Offset': '0' },
  });
  expect(chunk.status()).toBe(200);
  const completed = await complete(context, session, upload.transfer.id);
  expect(completed.transfer.protected).toBe(true);
  expect(completed.file.protected).toBe(true);
  expect(completed.file.name).toBe('TDENC2-contract.tdenc2');

  const invalid = await context.post('/api/v1/transfers/uploads', {
    data: {
      name: 'original-secret-name.txt', folder_id: null, size: 4,
      mime_type: 'application/octet-stream', source_modified_ms: 1_700_000_000_000,
      prefix_sha256: null, protected: true,
    },
    headers: { 'X-CSRF-Token': session.csrf_token },
  });
  expect(invalid.status()).toBe(400);
  await context.dispose();
});

test('per-account bots publish only to authorized channels without exposing tokens', async ({ playwright }) => {
  const context = await apiContext(playwright);
  const other = await apiContext(playwright);
  const session = await login(context, '+15550008080');
  await login(other, '+15550008081');
  const rejected = await context.post('/api/v1/bots', {
    data: { label: 'Invalid bot', token: 'invalid-token' },
    headers: { 'X-CSRF-Token': session.csrf_token },
  });
  expect(rejected.status()).toBe(401);
  const added = await context.post('/api/v1/bots', {
    data: { label: 'Channel publisher', token: 'fixture-bot-token' },
    headers: { 'X-CSRF-Token': session.csrf_token },
  });
  expect(added.status()).toBe(200);
  const bot = await added.json();
  expect(bot.bot_username).toBe('salvage_fixture_bot');
  const listed = await context.get('/api/v1/bots');
  expect((await listed.json()).map((item) => item.id)).toContain(bot.id);

  const folder = await createFolder(context, session, 'Bot destination');
  const content = Buffer.from('bot published channel content');
  const created = await context.post('/api/v1/transfers/uploads', {
    data: {
      name: 'bot-upload.txt', folder_id: folder.id, size: content.length,
      mime_type: 'text/plain', source_modified_ms: 1_700_000_000_000,
      prefix_sha256: null, protected: false, bot_id: bot.id,
    },
    headers: { 'X-CSRF-Token': session.csrf_token },
  });
  expect(created.status()).toBe(200);
  const upload = await created.json();
  expect(upload.transfer.bot_id).toBe(bot.id);
  await putChunk(context, session, upload, 0, content);
  const completed = await complete(context, session, upload.transfer.id);
  expect(completed.file.folder_id).toBe(folder.id);
  expect(completed.file.id).toContain('bot-file-');
  const prepared = await context.post(`/api/v1/transfers/downloads/${completed.file.id}`, {
    headers: { 'X-CSRF-Token': session.csrf_token },
  });
  const download = await prepared.json();
  expect(await (await context.get(download.download_url)).text()).toBe(content.toString());

  const automatic = await context.post('/api/v1/transfers/uploads', {
    data: {
      name: 'auto-bot-upload.txt', folder_id: folder.id, size: content.length,
      mime_type: 'text/plain', source_modified_ms: 1_700_000_000_000,
      prefix_sha256: null, protected: false, bot_auto: true,
    },
    headers: { 'X-CSRF-Token': session.csrf_token },
  });
  expect(automatic.status()).toBe(200);
  const autoUpload = await automatic.json();
  expect(autoUpload.transfer.bot_id).toBe(bot.id);
  await putChunk(context, session, autoUpload, 0, content);
  await complete(context, session, autoUpload.transfer.id);

  const rootAttempt = await context.post('/api/v1/transfers/uploads', {
    data: {
      name: 'bot-root.txt', folder_id: null, size: 4, mime_type: 'text/plain',
      source_modified_ms: 1_700_000_000_000, prefix_sha256: null, bot_id: bot.id,
    },
    headers: { 'X-CSRF-Token': session.csrf_token },
  });
  expect(rootAttempt.status()).toBe(400);
  const deniedFolder = await createFolder(context, session, 'No bot access');
  const denied = await context.post('/api/v1/transfers/uploads', {
    data: {
      name: 'bot-denied.txt', folder_id: deniedFolder.id, size: 4, mime_type: 'text/plain',
      source_modified_ms: 1_700_000_000_000, prefix_sha256: null, bot_id: bot.id,
    },
    headers: { 'X-CSRF-Token': session.csrf_token },
  });
  expect(denied.status()).toBe(409);
  const foreign = await other.post('/api/v1/transfers/uploads', {
    data: {
      name: 'foreign-bot.txt', folder_id: folder.id, size: 4, mime_type: 'text/plain',
      source_modified_ms: 1_700_000_000_000, prefix_sha256: null, bot_id: bot.id,
    },
    headers: { 'X-CSRF-Token': (await other.get('/api/v1/auth/session').then((response) => response.json())).csrf_token },
  });
  expect(foreign.status()).toBe(404);

  const oversized = await context.post('/api/v1/transfers/uploads', {
    data: {
      name: 'too-large-for-bot.txt', folder_id: folder.id, size: 50 * 1024 * 1024 + 1,
      mime_type: 'text/plain', source_modified_ms: 1_700_000_000_000,
      prefix_sha256: null, bot_id: bot.id,
    },
    headers: { 'X-CSRF-Token': session.csrf_token },
  });
  expect(oversized.status()).toBe(400);

  const removed = await context.delete(`/api/v1/bots/${bot.id}`, {
    headers: { 'X-CSRF-Token': session.csrf_token },
  });
  expect(removed.status()).toBe(200);
  const afterRemoval = await context.post('/api/v1/transfers/uploads', {
    data: {
      name: 'removed-bot.txt', folder_id: folder.id, size: 4, mime_type: 'text/plain',
      source_modified_ms: 1_700_000_000_000, prefix_sha256: null, bot_id: bot.id,
    },
    headers: { 'X-CSRF-Token': session.csrf_token },
  });
  expect(afterRemoval.status()).toBe(404);
  const workspace = await fs.readFile(new URL('../../.e2e-data/accounts/' + session.account.id + '/workspace.db', import.meta.url));
  expect(workspace.includes(Buffer.from('fixture-bot-token'))).toBe(false);
  await Promise.all([context.dispose(), other.dispose()]);
});

test('active channel rollover creates and activates a new channel at its part limit', async ({ playwright }) => {
  const context = await apiContext(playwright);
  const session = await login(context, '+15550008282');
  const folder = await createFolder(context, session, 'Rollover source');
  const activated = await context.post(`/api/v1/channels/${folder.id}/activate`, {
    headers: { 'X-CSRF-Token': session.csrf_token },
  });
  expect(activated.status()).toBe(200);
  expect((await activated.json()).active).toBe(true);
  for (const name of ['part-one.txt', 'part-two.txt']) {
    const created = await context.post('/api/v1/transfers/uploads', {
      data: {
        name, folder_id: folder.id, size: 4, mime_type: 'text/plain',
        source_modified_ms: 1_700_000_000_000, prefix_sha256: null,
      },
      headers: { 'X-CSRF-Token': session.csrf_token },
    });
    expect(created.status()).toBe(200);
    const upload = await created.json();
    await putChunk(context, session, upload, 0, Buffer.from('data'));
    await complete(context, session, upload.transfer.id);
  }
  const created = await context.post('/api/v1/transfers/uploads', {
    data: {
      name: 'part-three.txt', folder_id: folder.id, size: 4, mime_type: 'text/plain',
      source_modified_ms: 1_700_000_000_000, prefix_sha256: null,
    },
    headers: { 'X-CSRF-Token': session.csrf_token },
  });
  expect(created.status()).toBe(200);
  const upload = await created.json();
  expect(upload.transfer.folder_id).not.toBe(folder.id);
  await putChunk(context, session, upload, 0, Buffer.from('data'));
  const completed = await complete(context, session, upload.transfer.id);
  expect(completed.file.folder_id).toBe(upload.transfer.folder_id);
  const folders = await (await context.get('/api/v1/folders')).json();
  const active = folders.find((item) => item.active);
  expect(active.id).toBe(upload.transfer.folder_id);
  await context.dispose();
});

test('resuming a reselected source requires the exact staged-prefix hash', async ({ playwright }) => {
  const context = await apiContext(playwright);
  const session = await login(context, '+15550007007');
  const content = Buffer.from('abcdefghij', 'utf8');
  const upload = await createUpload(context, session, 'resume.txt', content.length);
  await putChunk(context, session, upload, 0, content.subarray(0, 4));

  const resumeResponse = await context.post('/api/v1/transfers/uploads', {
    data: {
      name: 'resume.txt', folder_id: null, size: content.length, mime_type: 'text/plain',
      source_modified_ms: 1_700_000_000_000, prefix_sha256: sha256(content.subarray(0, 4)),
    },
    headers: { 'X-CSRF-Token': session.csrf_token },
  });
  expect(resumeResponse.status()).toBe(200);
  const resumed = await resumeResponse.json();
  expect(resumed.transfer.id).toBe(upload.transfer.id);
  expect(resumed.next_offset).toBe(4);

  const wrongSource = await context.post('/api/v1/transfers/uploads', {
    data: {
      name: 'resume.txt', folder_id: null, size: content.length, mime_type: 'text/plain',
      source_modified_ms: 1_700_000_000_000, prefix_sha256: sha256('WXYZ'),
    },
    headers: { 'X-CSRF-Token': session.csrf_token },
  });
  expect(wrongSource.status()).toBe(409);
  await putChunk(context, session, resumed, 4, content.subarray(4));
  const completed = await complete(context, session, upload.transfer.id);
  expect(completed.transfer.status).toBe('completed');
  await context.dispose();
});
