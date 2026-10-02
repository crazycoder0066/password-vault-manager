import { useCallback, useEffect, useRef, useState } from 'react';
import { vaultRequest } from './api.js';
import { UnlockForm, Workspace } from './components.jsx';

const IDLE_TIMEOUT = 5 * 60 * 1000;
class SupersededRequest extends Error {}

export default function App() {
  const [loading, setLoading] = useState(true);
  const [initialized, setInitialized] = useState(false);
  const [unlocked, setUnlocked] = useState(false);
  const [entries, setEntries] = useState([]);
  const [revision, setRevision] = useState(0);
  const [message, setMessage] = useState('');
  const [busy, setBusy] = useState(false);
  const busyRef = useRef(0);
  const requests = useRef(new Set());
  const epoch = useRef(0);
  const lastActivity = useRef(Date.now());

  const clearVault = useCallback(() => {
    epoch.current += 1;
    for (const controller of requests.current) controller.abort();
    requests.current.clear();
    setUnlocked(false);
    setEntries([]);
  }, []);

  const api = useCallback(async (action, data) => {
    const started = epoch.current;
    const controller = new AbortController();
    requests.current.add(controller);
    try {
      const result = await vaultRequest(action, data, { signal: controller.signal });
      // A response from before a lock must never repopulate credentials.
      if (started !== epoch.current) throw new SupersededRequest();
      lastActivity.current = Date.now();
      return result;
    } catch (error) {
      if (started !== epoch.current) throw new SupersededRequest();
      if (error.status === 401) clearVault();
      throw error;
    } finally {
      requests.current.delete(controller);
    }
  }, [clearVault]);

  const refresh = useCallback(async () => {
    const result = await api('entries');
    setEntries(result.entries);
    setRevision(value => value + 1);
  }, [api]);

  const run = async (operation, interrupt = false) => {
    if (busyRef.current && !interrupt) return;
    busyRef.current += 1;
    setBusy(true);
    try {
      await operation();
    } catch (error) {
      if (!(error instanceof SupersededRequest)) setMessage(error.message);
    } finally {
      busyRef.current -= 1;
      setBusy(busyRef.current > 0);
    }
  };

  useEffect(() => {
    const controller = new AbortController();
    async function start() {
      try {
        const status = await vaultRequest('status', {}, { signal: controller.signal });
        if (controller.signal.aborted) return;
        setInitialized(status.initialized);
        if (!status.locked) {
          await refresh();
          if (!controller.signal.aborted) setUnlocked(true);
        }
      } catch (error) {
        if (!controller.signal.aborted) setMessage(error.message);
      } finally {
        if (!controller.signal.aborted) setLoading(false);
      }
    }
    start();
    return () => {
      controller.abort();
      epoch.current += 1;
      for (const pending of requests.current) pending.abort();
      requests.current.clear();
    };
  }, [refresh]);

  useEffect(() => {
    if (!unlocked) return;
    const timer = setInterval(() => {
      if (Date.now() - lastActivity.current >= IDLE_TIMEOUT) {
        clearVault();
        vaultRequest('lock').catch(() => {});
        setMessage('Vault locked after inactivity.');
      }
    }, 1000);
    return () => clearInterval(timer);
  }, [unlocked, clearVault]);

  const unlock = async (password) => {
    await api(initialized ? 'unlock' : 'create', { master_password: password });
    setInitialized(true);
    await refresh();
    setUnlocked(true);
    setMessage('Vault unlocked.');
  };

  const lock = async () => {
    // Unmount forms and revealed passwords as soon as locking begins.
    clearVault();
    await api('lock');
    setMessage('Vault locked.');
  };

  return (
    <main>
      <header>
        <div>
          <p className="eyebrow">LOCAL PASSWORD MANAGER</p>
          <h1>Your password vault</h1>
          <p>Keep credentials together. Rotate them when it’s time.</p>
        </div>
        {unlocked && <button onClick={() => run(lock, true)}>Lock vault</button>}
      </header>
      <p id="message" role="status" aria-live="polite">{message}</p>
      {loading ? <p>Connecting to your vault…</p> : unlocked ? (
        <Workspace entries={entries} revision={revision} api={api} refresh={refresh}
          run={run} busy={busy} message={setMessage} />
      ) : (
        <UnlockForm key={epoch.current} initialized={initialized} busy={busy} run={run} unlock={unlock} />
      )}
      <footer>Stored encrypted on this device · Locks after 5 minutes without vault activity</footer>
    </main>
  );
}
