import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { implForWrapper } from 'jsdom/lib/generated/idl/utils.js';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import App from './App.jsx';

const account = {
  id: 'email', title: 'Email', username: 'private-user', url: 'https://example.com',
  overdue: true, due_at: '2026-01-01T00:00:00Z',
};
const response = (data, status = 200) => ({
  ok: status >= 200 && status < 300, status,
  json: async () => data, blob: async () => data,
});

function mockServer({ initialized = true, locked = false, entries = [account] } = {}) {
  const state = { initialized, locked, entries: [...entries] };
  const fetchMock = vi.fn(async (url, options) => {
    const action = url.replace('/api/', '');
    const data = typeof options.body === 'string' ? JSON.parse(options.body) : options.body;
    switch (action) {
      case 'status': return response({ initialized: state.initialized, locked: state.locked });
      case 'create':
      case 'unlock': state.initialized = true; state.locked = false; return response({ ok: true });
      case 'entries': return response({ entries: [...state.entries] });
      case 'generate': return response({ password: 'generated-password-12345' });
      case 'save':
        state.entries.push({ ...data, id: 'new', due_at: account.due_at, overdue: false, password: undefined });
        return response({ ok: true }, 201);
      case 'reveal': return response({ password: 'private-secret' });
      case 'rotate': return response({ ok: true });
      case 'delete': state.entries = state.entries.filter(entry => entry.id !== data.id); return response({ ok: true });
      case 'lock': state.locked = true; return response({ ok: true });
      case 'master-password': return response({ ok: true });
      case 'import': return response({ imported: 1 });
      case 'export': return response(new Blob(['encrypted-vault']));
      default: throw new Error(`Unexpected API request: ${url}`);
    }
  });
  vi.stubGlobal('fetch', fetchMock);
  return fetchMock;
}

function requests(action) {
  return fetch.mock.calls.filter(([url]) => url === `/api/${action}`);
}

async function openWorkspace() {
  await act(async () => { render(<App />); });
  expect(screen.getByRole('heading', { name: 'Add a password' })).toBeInTheDocument();
}

beforeEach(() => { mockServer(); });

describe('vault workflows', () => {
  it('creates a vault only when the master passwords match and clears the unlock form', async () => {
    mockServer({ initialized: false, locked: true, entries: [] });
    const user = userEvent.setup();
    render(<App />);
    await screen.findByRole('heading', { name: 'Create your vault' });
    await user.type(screen.getByLabelText('Master password'), 'long master passphrase');
    await user.type(screen.getByLabelText('Confirm master password'), 'another long passphrase');
    await user.click(screen.getByRole('button', { name: 'Create vault' }));
    expect(screen.getByRole('status')).toHaveTextContent('Master passwords must match.');
    expect(requests('create')).toHaveLength(0);
    await user.clear(screen.getByLabelText('Confirm master password'));
    await user.type(screen.getByLabelText('Confirm master password'), 'long master passphrase');
    await user.click(screen.getByRole('button', { name: 'Create vault' }));
    await screen.findByText('No passwords yet. Add your first account above.');
    expect(screen.queryByLabelText('Master password')).not.toBeInTheDocument();
    expect(JSON.parse(requests('create')[0][1].body)).toEqual({ master_password: 'long master passphrase' });
  });

  it('restores an unlocked session without fetching passwords', async () => {
    await openWorkspace();
    expect(screen.getByRole('heading', { name: 'Email' })).toBeInTheDocument();
    expect(screen.getByText(/Rotation due/)).toBeInTheDocument();
    expect(screen.queryByText('private-secret')).not.toBeInTheDocument();
    expect(requests('reveal')).toHaveLength(0);
  });

  it('generates and saves an account, converts the rotation interval, and searches metadata', async () => {
    const user = userEvent.setup();
    await openWorkspace();
    await user.type(screen.getByLabelText('Account name'), 'Work');
    await user.type(screen.getByLabelText('Username'), 'work-user');
    await user.click(screen.getByRole('button', { name: 'Generate password' }));
    await user.click(screen.getByRole('button', { name: 'Save password' }));
    await screen.findByRole('heading', { name: 'Work' });
    expect(JSON.parse(requests('save')[0][1].body)).toMatchObject({
      title: 'Work', password: 'generated-password-12345', rotation_days: 90,
    });
    expect(screen.getByLabelText('Password', { exact: true })).toHaveValue('');
    await user.type(screen.getByRole('searchbox'), 'EXAMPLE.COM');
    expect(screen.queryByRole('heading', { name: 'Work' })).not.toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Email' })).toBeInTheDocument();
    await user.clear(screen.getByRole('searchbox'));
    await user.type(screen.getByRole('searchbox'), 'missing');
    expect(screen.getByText('No matching accounts.')).toBeInTheDocument();
  });

  it('hides a revealed password after 30 seconds and supports manual hiding', async () => {
    vi.useFakeTimers();
    await openWorkspace();
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Reveal' })); });
    expect(screen.getByText('private-secret')).toBeInTheDocument();
    await act(async () => { vi.advanceTimersByTime(30000); });
    expect(screen.queryByText('private-secret')).not.toBeInTheDocument();
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Reveal' })); });
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Hide' })); });
    expect(screen.queryByText('private-secret')).not.toBeInTheDocument();
  });

  it('saves a rotation only after confirmation and clears cancelled replacements', async () => {
    const user = userEvent.setup();
    await openWorkspace();
    await user.click(screen.getByRole('button', { name: 'Rotate' }));
    expect(screen.getByRole('dialog')).toHaveAttribute('open');
    await user.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(requests('rotate')).toHaveLength(0);
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Rotate' }));
    await user.clear(screen.getByLabelText('Replacement password'));
    await user.type(screen.getByLabelText('Replacement password'), 'replacement-secret');
    await user.click(screen.getByRole('button', { name: 'Save replacement' }));
    await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent('Replacement password saved.'));
    expect(JSON.parse(requests('rotate')[0][1].body)).toEqual({ id: 'email', password: 'replacement-secret' });
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });

  it('validates master password confirmation and clears it after a change', async () => {
    const user = userEvent.setup();
    await openWorkspace();
    await user.click(screen.getByText('Change master password', { selector: 'summary' }));
    await user.type(screen.getByLabelText('New master password', { exact: true }), 'a new master passphrase');
    await user.type(screen.getByLabelText('Confirm new master password'), 'a different master passphrase');
    await user.click(screen.getByRole('button', { name: 'Change master password' }));
    expect(requests('master-password')).toHaveLength(0);
    await user.clear(screen.getByLabelText('Confirm new master password'));
    await user.type(screen.getByLabelText('Confirm new master password'), 'a new master passphrase');
    await user.click(screen.getByRole('button', { name: 'Change master password' }));
    await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent('Master password changed.'));
    expect(screen.getByLabelText('New master password', { exact: true })).toHaveValue('');
    expect(screen.getByLabelText('Confirm new master password')).toHaveValue('');
  });

  it('requires confirmation to delete a saved account', async () => {
    const user = userEvent.setup();
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(false);
    await openWorkspace();
    await user.click(screen.getByRole('button', { name: 'Delete' }));
    expect(requests('delete')).toHaveLength(0);
    confirm.mockReturnValue(true);
    await user.click(screen.getByRole('button', { name: 'Delete' }));
    await screen.findByText('No passwords yet. Add your first account above.');
  });

  it('exports an encrypted download and imports a file as multipart data', async () => {
    vi.useFakeTimers();
    const createUrl = vi.fn(() => 'blob:encrypted-backup');
    const revokeUrl = vi.fn();
    vi.stubGlobal('URL', Object.assign(class extends URL {}, {
      createObjectURL: createUrl, revokeObjectURL: revokeUrl,
    }));
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});
    await openWorkspace();
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Export encrypted vault' })); });
    expect(createUrl).toHaveBeenCalled();
    expect(click.mock.instances[0].download).toBe('passwords.vault');
    expect(click.mock.instances[0].href).toBe('blob:encrypted-backup');
    const file = new File(['encrypted'], 'backup.vault', { type: 'application/octet-stream' });
    const upload = screen.getByLabelText('Encrypted vault file');
    // Populate jsdom's native file list so validation, FormData, and reset all see it.
    // user-event upload overrides the wrapper, leaving the native file list empty.
    implForWrapper(upload).files.push(implForWrapper(file));
    fireEvent.change(upload);
    expect(upload.files).toHaveLength(1);
    fireEvent.change(screen.getByLabelText('Imported vault’s master password'), {
      target: { value: 'backup master password' },
    });
    expect(upload.form.checkValidity()).toBe(true);
    const reset = vi.spyOn(upload.form, 'reset');
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Import entries' })); });
    expect(screen.getByRole('status')).toHaveTextContent('Imported 1 password.');
    const options = requests('import')[0][1];
    expect(options.body.get('vault_file')).toBe(file);
    expect(options.body.get('master_password')).toBe('backup master password');
    expect(options.headers).toEqual({ 'X-Vault-Request': '1' });
    expect(screen.getByLabelText('Imported vault’s master password')).toHaveValue('');
    expect(reset).toHaveBeenCalled();
    await act(async () => { vi.advanceTimersByTime(60000); });
    expect(revokeUrl).toHaveBeenCalledWith('blob:encrypted-backup');
  });

  it('removes forms, revealed passwords, and rotation secrets on manual lock', async () => {
    const user = userEvent.setup();
    await openWorkspace();
    await user.click(screen.getByRole('button', { name: 'Reveal' }));
    await user.type(screen.getByLabelText('Password', { exact: true }), 'unsaved-secret');
    await user.click(screen.getByRole('button', { name: 'Rotate' }));
    await user.click(screen.getByRole('button', { name: 'Lock vault' }));
    await screen.findByRole('heading', { name: 'Unlock your vault' });
    expect(screen.queryByText('private-secret')).not.toBeInTheDocument();
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(screen.queryByLabelText('Password', { exact: true })).not.toBeInTheDocument();
    expect(screen.getByLabelText('Master password')).toHaveValue('');
    await user.type(screen.getByLabelText('Master password'), 'long master passphrase');
    await user.click(screen.getByRole('button', { name: 'Unlock', exact: true }));
    await screen.findByRole('heading', { name: 'Add a password' });
    expect(screen.getByLabelText('Password', { exact: true })).toHaveValue('');
    expect(screen.queryByText('private-secret')).not.toBeInTheDocument();
  });

  it('clears the workspace when an API request reports an expired session', async () => {
    const user = userEvent.setup();
    await openWorkspace();
    await user.click(screen.getByRole('button', { name: 'Reveal' }));
    fetch.mockImplementationOnce(async () => response({ error: 'Unlock the vault first' }, 401));
    await user.click(screen.getByRole('button', { name: 'Generate password' }));
    await screen.findByRole('heading', { name: 'Unlock your vault' });
    expect(screen.queryByText('private-secret')).not.toBeInTheDocument();
    expect(screen.getByRole('status')).toHaveTextContent('Unlock the vault first');
  });

  it('allows manual locking during a pending request and aborts that request', async () => {
    await openWorkspace();
    let resolveReveal;
    let signal;
    fetch.mockImplementationOnce((url, options) => new Promise(resolve => {
      resolveReveal = resolve;
      signal = options.signal;
    }));
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Reveal' })); });
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Lock vault' })); });
    expect(signal.aborted).toBe(true);
    expect(screen.getByRole('heading', { name: 'Unlock your vault' })).toBeInTheDocument();
    await act(async () => { resolveReveal(response({ password: 'late-secret' })); });
    expect(screen.queryByText('late-secret')).not.toBeInTheDocument();
    expect(screen.getByRole('status')).toHaveTextContent('Vault locked.');
  });

  it('locks after inactivity and ignores a password response arriving after the lock', async () => {
    vi.useFakeTimers();
    await openWorkspace();
    let resolveReveal;
    fetch.mockImplementationOnce(() => new Promise(resolve => { resolveReveal = resolve; }));
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Reveal' })); });
    await act(async () => { vi.advanceTimersByTime(300000); });
    expect(screen.getByRole('heading', { name: 'Unlock your vault' })).toBeInTheDocument();
    expect(requests('lock')).toHaveLength(1);
    await act(async () => { resolveReveal(response({ password: 'late-secret' })); });
    expect(screen.queryByText('late-secret')).not.toBeInTheDocument();
    expect(screen.getByRole('status')).toHaveTextContent('Vault locked after inactivity.');
    expect(screen.getByRole('button', { name: 'Unlock', exact: true })).toBeEnabled();
  });
});
