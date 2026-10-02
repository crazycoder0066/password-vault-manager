import { useEffect, useRef, useState } from 'react';

export function UnlockForm({ initialized, busy, run, unlock }) {
  const submit = (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    run(async () => {
      if (!initialized && data.get('master_password') !== data.get('confirmation')) {
        throw new Error('Master passwords must match.');
      }
      form.reset();
      await unlock(data.get('master_password'));
    });
  };
  return (
    <section>
      <h2>{initialized ? 'Unlock your vault' : 'Create your vault'}</h2>
      <p>Use a memorable master passphrase. You’ll need it every time you open the vault.</p>
      <form onSubmit={submit}>
        <fieldset disabled={busy}>
          <label>Master password<input name="master_password" type="password" required
            minLength={initialized ? 1 : 12} maxLength={1024}
            autoComplete={initialized ? 'current-password' : 'new-password'} autoFocus /></label>
          {!initialized && <label>Confirm master password<input name="confirmation" type="password"
            required minLength={12} maxLength={1024} autoComplete="new-password" /></label>}
          <button type="submit">{initialized ? 'Unlock' : 'Create vault'}</button>
        </fieldset>
      </form>
    </section>
  );
}

function AddPassword({ api, refresh, run, busy, message }) {
  const [password, setPassword] = useState('');
  const submit = (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const data = Object.fromEntries(new FormData(form));
    data.rotation_days = Number(data.rotation_days);
    run(async () => {
      await api('save', data);
      form.reset();
      setPassword('');
      await refresh();
      message('Password saved.');
    });
  };
  return (
    <section>
      <h2>Add a password</h2>
      <form onSubmit={submit}>
        <fieldset disabled={busy}>
          <div className="grid">
            <label>Account name<input name="title" required maxLength={4096} placeholder="e.g. Email" /></label>
            <label>Username<input name="username" maxLength={4096} autoComplete="off" /></label>
            <label>Website<input name="url" maxLength={4096} placeholder="https://example.com" /></label>
            <label>Rotation interval (days)<input name="rotation_days" type="number" min={1}
              max={3650} defaultValue={90} required /></label>
          </div>
          <label>Password<input name="password" type="password" maxLength={4096}
            autoComplete="new-password" required value={password}
            onChange={event => setPassword(event.target.value)} /></label>
          <div className="actions">
            <button type="button" className="secondary" onClick={() => run(async () => {
              setPassword((await api('generate')).password);
              message('Generated a 24-character password.');
            })}>Generate password</button>
            <button type="submit">Save password</button>
          </div>
        </fieldset>
      </form>
    </section>
  );
}

function EntryCard({ entry, api, refresh, run, busy, message, rotate }) {
  const [secret, setSecret] = useState(null);
  useEffect(() => {
    if (secret === null) return;
    const timer = setTimeout(() => setSecret(null), 30000);
    return () => clearTimeout(timer);
  }, [secret]);
  const metadata = [entry.username, entry.url,
    `${entry.overdue ? 'Rotation due · ' : 'Rotate by '}${new Date(entry.due_at).toLocaleDateString()}`,
  ].filter(Boolean).join(' · ');
  return (
    <article>
      <h3>{entry.title}</h3>
      <p className={entry.overdue ? 'due' : undefined}>{metadata}</p>
      <div className="actions">
        <button className="secondary" disabled={busy} onClick={() => run(async () => {
          setSecret(secret === null ? (await api('reveal', { id: entry.id })).password : null);
        })}>{secret === null ? 'Reveal' : 'Hide'}</button>
        <button className="secondary" disabled={busy} onClick={() => run(async () => {
          rotate(entry, (await api('generate')).password);
        })}>Rotate</button>
        <button className="danger" disabled={busy} onClick={() => {
          if (window.confirm(`Delete the saved password for ${entry.title}?`)) {
            run(async () => {
              await api('delete', { id: entry.id });
              await refresh();
              message('Password deleted.');
            });
          }
        }}>Delete</button>
      </div>
      {secret !== null && <div className="secret">{secret}</div>}
    </article>
  );
}

function RotationDialog({ rotation, close, api, refresh, run, busy, message }) {
  const dialog = useRef(null);
  const [password, setPassword] = useState(rotation.password);
  useEffect(() => {
    const element = dialog.current;
    element.showModal();
    return () => element.close();
  }, []);
  const submit = (event) => {
    event.preventDefault();
    run(async () => {
      await api('rotate', { id: rotation.entry.id, password });
      close();
      await refresh();
      message('Replacement password saved.');
    });
  };
  return (
    <dialog ref={dialog} aria-labelledby="rotation-title" onCancel={close}>
      <form onSubmit={submit}>
        <h2 id="rotation-title">Rotate password</h2>
        <p>{rotation.entry.title}</p>
        <p>First apply the replacement to the account, then save it here. The previous saved password will be replaced.</p>
        <fieldset disabled={busy}>
          <label>Replacement password<input type="text" required maxLength={4096}
            autoComplete="new-password" value={password} onChange={event => setPassword(event.target.value)} /></label>
          <div className="actions">
            <button type="button" className="secondary" onClick={close}>Cancel</button>
            <button type="submit">Save replacement</button>
          </div>
        </fieldset>
      </form>
    </dialog>
  );
}

function MasterPassword({ api, run, busy, message }) {
  const submit = (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    run(async () => {
      if (data.get('master_password') !== data.get('confirmation')) {
        throw new Error('Master passwords must match.');
      }
      await api('master-password', { master_password: data.get('master_password') });
      form.reset();
      message('Master password changed.');
    });
  };
  return (
    <section>
      <details>
        <summary>Change master password</summary>
        <form onSubmit={submit}>
          <fieldset disabled={busy}>
            <label>New master password<input name="master_password" type="password"
              minLength={12} maxLength={1024} autoComplete="new-password" required /></label>
            <label>Confirm new master password<input name="confirmation" type="password"
              minLength={12} maxLength={1024} autoComplete="new-password" required /></label>
            <button type="submit">Change master password</button>
          </fieldset>
        </form>
      </details>
    </section>
  );
}

function EncryptedBackup({ api, refresh, run, busy, message }) {
  const exportVault = async () => {
    const url = URL.createObjectURL(await api('export'));
    const link = document.createElement('a');
    link.href = url;
    link.download = 'passwords.vault';
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 60000);
    message('Encrypted vault exported.');
  };
  const importVault = (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    run(async () => {
      const result = await api('import', data);
      form.reset();
      await refresh();
      message(`Imported ${result.imported} password${result.imported === 1 ? '' : 's'}.`);
    });
  };
  return (
    <section>
      <h2>Encrypted backup</h2>
      <p>Download your vault as an encrypted file, or import entries from another vault.
        Import adds entries without replacing existing ones. You need the imported file’s master password.</p>
      <div className="actions">
        <button type="button" className="secondary" disabled={busy}
          onClick={() => run(exportVault)}>Export encrypted vault</button>
      </div>
      <form onSubmit={importVault}>
        <fieldset disabled={busy}>
          <label>Encrypted vault file<input name="vault_file" type="file"
            accept=".vault,application/octet-stream" required /></label>
          <label>Imported vault’s master password<input name="master_password" type="password"
            maxLength={1024} autoComplete="off" required /></label>
          <button type="submit">Import entries</button>
        </fieldset>
      </form>
    </section>
  );
}

export function Workspace(props) {
  const [query, setQuery] = useState('');
  const [rotation, setRotation] = useState(null);
  const visible = props.entries.filter(entry => [entry.title, entry.username, entry.url]
    .join(' ').toLowerCase().includes(query.toLowerCase()));
  return (
    <div>
      <AddPassword {...props} />
      <section>
        <div className="section-heading">
          <h2>Saved accounts <span>({props.entries.length})</span></h2>
          <input type="search" placeholder="Search accounts" aria-label="Search accounts"
            value={query} onChange={event => setQuery(event.target.value)} />
        </div>
        <p className="muted">Rotation updates the password saved here. Apply the replacement to the account yourself.</p>
        {visible.length ? visible.map(entry => (
          <EntryCard key={`${props.revision}:${entry.id}`} {...props} entry={entry}
            rotate={(account, password) => setRotation({ entry: account, password })} />
        )) : <p>{props.entries.length ? 'No matching accounts.' : 'No passwords yet. Add your first account above.'}</p>}
      </section>
      <MasterPassword {...props} />
      <EncryptedBackup {...props} />
      {rotation && <RotationDialog {...props} rotation={rotation} close={() => setRotation(null)} />}
    </div>
  );
}
