import { expect, it, vi } from 'vitest';
import { VaultApiError, vaultRequest } from './api.js';

it('sends same-origin JSON POST requests with the required vault header', async () => {
  const fetchMock = vi.fn(async () => ({ ok: true, json: async () => ({ ok: true }) }));
  vi.stubGlobal('fetch', fetchMock);
  await vaultRequest('unlock', { master_password: 'secret' });
  expect(fetchMock).toHaveBeenCalledWith('/api/unlock', expect.objectContaining({
    method: 'POST', credentials: 'same-origin', cache: 'no-store',
    headers: { 'Content-Type': 'application/json', 'X-Vault-Request': '1' },
    body: JSON.stringify({ master_password: 'secret' }),
  }));
});

it('uses GET for status and passes the startup cancellation signal', async () => {
  const fetchMock = vi.fn(async () => ({ ok: true, json: async () => ({ locked: true }) }));
  vi.stubGlobal('fetch', fetchMock);
  const controller = new AbortController();
  await vaultRequest('status', {}, { signal: controller.signal });
  expect(fetchMock).toHaveBeenCalledWith('/api/status', {
    signal: controller.signal, credentials: 'same-origin', cache: 'no-store',
  });
});

it('preserves API errors and handles a non-JSON server failure', async () => {
  vi.stubGlobal('fetch', vi.fn(async () => ({
    ok: false, status: 401, json: async () => ({ error: 'Unlock the vault first' }),
  })));
  await expect(vaultRequest('entries')).rejects.toMatchObject({
    message: 'Unlock the vault first', status: 401,
  });
  fetch.mockResolvedValueOnce({ ok: false, status: 500, json: async () => { throw new SyntaxError(); } });
  await expect(vaultRequest('entries')).rejects.toBeInstanceOf(VaultApiError);
});
