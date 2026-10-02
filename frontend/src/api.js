export class VaultApiError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
  }
}

export async function vaultRequest(action, data = {}, { signal } = {}) {
  const multipart = data instanceof FormData;
  const response = await fetch(`/api/${action}`, action === 'status' ? {
    signal, credentials: 'same-origin', cache: 'no-store',
  } : {
    method: 'POST',
    credentials: 'same-origin',
    cache: 'no-store',
    headers: multipart ? { 'X-Vault-Request': '1' } : {
      'Content-Type': 'application/json', 'X-Vault-Request': '1',
    },
    body: multipart ? data : JSON.stringify(data),
    signal,
  });
  if (!response.ok) {
    const result = await response.json().catch(() => ({}));
    throw new VaultApiError(result.error || 'Request failed. Please try again.', response.status);
  }
  return action === 'export' ? response.blob() : response.json();
}
