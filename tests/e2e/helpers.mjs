import { expect } from '@playwright/test';

export const baseURL = 'http://127.0.0.1:4173';

export async function apiContext(playwright) {
  return playwright.request.newContext({
    baseURL,
    extraHTTPHeaders: { Origin: baseURL },
  });
}

export async function login(request, phone = '+15550001001') {
  const phoneResponse = await request.post('/api/v1/auth/phone', {
    data: { phone },
  });
  expect(phoneResponse.status()).toBe(200);
  const attempt = await phoneResponse.json();
  const codeResponse = await request.post('/api/v1/auth/code', {
    data: { attempt_id: attempt.attempt_id, code: '12345' },
  });
  expect(codeResponse.status()).toBe(200);
  const outcome = await codeResponse.json();
  if (outcome.status === 'password_required') {
    const passwordResponse = await request.post('/api/v1/auth/password', {
      data: { attempt_id: attempt.attempt_id, password: 'salvage-test-password' },
    });
    expect(passwordResponse.status()).toBe(200);
    return (await passwordResponse.json()).session;
  }
  expect(outcome.status).toBe('authenticated');
  return outcome.session;
}

export async function createFolder(request, session, name) {
  const response = await request.post('/api/v1/folders', {
    data: { name, parent_id: null },
    headers: { 'X-CSRF-Token': session.csrf_token },
  });
  expect(response.status()).toBe(200);
  return response.json();
}

export async function uploadFile(request, session, name, content, mimeType = 'text/plain') {
  const bytes = Buffer.isBuffer(content) ? content : Buffer.from(content);
  const created = await request.post('/api/v1/transfers/uploads', {
    data: {
      name, folder_id: null, size: bytes.length, mime_type: mimeType,
      source_modified_ms: 1_700_000_000_000, prefix_sha256: null,
    },
    headers: { 'X-CSRF-Token': session.csrf_token },
  });
  expect(created.status()).toBe(200);
  const upload = await created.json();
  if (bytes.length) {
    const chunk = await request.put(`/api/v1/transfers/uploads/${upload.transfer.id}/content`, {
      data: bytes,
      headers: { 'X-CSRF-Token': session.csrf_token, 'X-Upload-Offset': '0' },
    });
    expect(chunk.status()).toBe(200);
  }
  const completed = await request.post(`/api/v1/transfers/uploads/${upload.transfer.id}/complete`, {
    headers: { 'X-CSRF-Token': session.csrf_token },
  });
  expect(completed.status()).toBe(200);
  return completed.json();
}
