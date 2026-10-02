'use strict';
const $ = id => document.getElementById(id);
let initialized = false, entries = [], rotating = null, lastActivity = Date.now();
const message = text => { $('message').textContent = text; };
function clearSecrets() {
  $('master').value = ''; $('confirm-master').value = ''; $('new-password').value = '';
  $('master-form').reset(); $('import-form').reset(); $('replacement').value = ''; rotating = null;
  $('rotate-dialog').close(); $('entries').replaceChildren(); entries = [];
}
function lockedView() {
  clearSecrets(); $('workspace').hidden = true; $('locked').hidden = false; $('lock').hidden = true;
  $('unlock-title').textContent = initialized ? 'Unlock your vault' : 'Create your vault';
  $('unlock-button').textContent = initialized ? 'Unlock' : 'Create vault';
  $('confirm-label').hidden = initialized; $('confirm-master').required = !initialized;
  $('master').minLength = initialized ? 1 : 12;
}
async function api(path, data = {}) {
  const response = await fetch('/api/' + path, {method:'POST', headers:{'Content-Type':'application/json','X-Vault-Request':'1'}, body:JSON.stringify(data)});
  const result = await response.json();
  if (!response.ok) {
    if (response.status === 401) lockedView();
    throw new Error(result.error || 'Request failed');
  }
  lastActivity = Date.now();
  return result;
}
function action(button, handler) {
  button.addEventListener('click', async () => {
    button.disabled = true;
    try { await handler(); } catch (error) { message(error.message); }
    finally { button.disabled = false; }
  });
}
function button(text, handler, kind = 'secondary') {
  const node = document.createElement('button'); node.textContent = text; node.className = kind;
  action(node, handler); return node;
}
function render() {
  $('entries').replaceChildren(); $('count').textContent = '(' + entries.length + ')';
  const query = $('search').value.toLowerCase();
  const visible = entries.filter(e => [e.title,e.username,e.url].join(' ').toLowerCase().includes(query));
  if (!visible.length) {
    const p = document.createElement('p'); p.textContent = entries.length ? 'No matching accounts.' : 'No passwords yet. Add your first account above.'; $('entries').append(p);
  }
  for (const entry of visible) {
    const card = document.createElement('article'), title = document.createElement('h3'), meta = document.createElement('p');
    title.textContent = entry.title;
    meta.textContent = [entry.username, entry.url, (entry.overdue ? 'Rotation due · ' : 'Rotate by ') + new Date(entry.due_at).toLocaleDateString()].filter(Boolean).join(' · ');
    if (entry.overdue) meta.className = 'due';
    const controls = document.createElement('div'); controls.className = 'actions';
    const secret = document.createElement('div'); secret.className = 'secret'; secret.hidden = true;
    const reveal = button('Reveal', async () => {
      if (!secret.hidden) { secret.textContent = ''; secret.hidden = true; reveal.textContent = 'Reveal'; return; }
      secret.textContent = (await api('reveal', {id:entry.id})).password;
      secret.hidden = false; reveal.textContent = 'Hide';
      setTimeout(() => { secret.textContent = ''; secret.hidden = true; reveal.textContent = 'Reveal'; }, 30000);
    });
    controls.append(reveal, button('Rotate', async () => {
      const generated = await api('generate'); rotating = entry.id; $('replacement').value = generated.password;
      $('rotate-account').textContent = entry.title; $('rotate-dialog').showModal();
    }), button('Delete', async () => {
      if (confirm('Delete the saved password for ' + entry.title + '?')) { await api('delete', {id:entry.id}); await refresh(); message('Password deleted.'); }
    }, 'danger'));
    card.append(title,meta,controls,secret); $('entries').append(card);
  }
}
async function refresh() { entries = (await api('entries')).entries; render(); }
function form(id, handler) {
  $(id).addEventListener('submit', async event => {
    event.preventDefault(); const submit = $(id).querySelector('button[type="submit"]'); submit.disabled = true;
    try { await handler(); } catch (error) { message(error.message); }
    finally { submit.disabled = false; }
  });
}
form('unlock-form', async () => {
  if (!initialized && $('master').value !== $('confirm-master').value) throw new Error('Master passwords must match.');
  const password = $('master').value; $('master').value = ''; $('confirm-master').value = '';
  await api(initialized ? 'unlock' : 'create', {master_password:password}); initialized = true;
  $('locked').hidden = true; $('workspace').hidden = false; $('lock').hidden = false;
  await refresh(); message('Vault unlocked.');
});
form('add-form', async () => {
  const data = Object.fromEntries(new FormData($('add-form'))); data.rotation_days = Number(data.rotation_days);
  await api('save', data); $('add-form').reset(); await refresh(); message('Password saved.');
});
form('rotate-form', async () => {
  await api('rotate', {id:rotating, password:$('replacement').value});
  $('rotate-dialog').close(); $('replacement').value = ''; rotating = null;
  await refresh(); message('Replacement password saved.');
});
form('master-form', async () => {
  const data = Object.fromEntries(new FormData($('master-form')));
  if (data.master_password !== data.confirmation) throw new Error('Master passwords must match.');
  await api('master-password', {master_password:data.master_password}); $('master-form').reset(); message('Master password changed.');
});
action($('export'), async () => {
  const response = await fetch('/api/export', {method:'POST', headers:{'Content-Type':'application/json','X-Vault-Request':'1'}, body:'{}'});
  if (!response.ok) {
    const result = await response.json();
    if (response.status === 401) lockedView();
    throw new Error(result.error || 'Export failed.');
  }
  const url = URL.createObjectURL(await response.blob());
  const link = document.createElement('a'); link.href = url; link.download = 'passwords.vault'; link.click();
  setTimeout(() => URL.revokeObjectURL(url), 60000);
  lastActivity = Date.now(); message('Encrypted vault exported.');
});
form('import-form', async () => {
  const response = await fetch('/api/import', {method:'POST', headers:{'X-Vault-Request':'1'}, body:new FormData($('import-form'))});
  const result = await response.json();
  if (!response.ok) {
    if (response.status === 401) lockedView();
    throw new Error(result.error || 'Import failed.');
  }
  $('import-form').reset(); lastActivity = Date.now();
  await refresh(); message(`Imported ${result.imported} password${result.imported === 1 ? '' : 's'}.`);
});
action($('generate'), async () => { $('new-password').value = (await api('generate')).password; message('Generated a 24-character password.'); });
action($('lock'), async () => { await api('lock'); lockedView(); message('Vault locked.'); });
$('search').addEventListener('input', render);
$('rotate-cancel').addEventListener('click', () => $('rotate-dialog').close());
$('rotate-dialog').addEventListener('close', () => { $('replacement').value = ''; rotating = null; });
setInterval(() => {
  if (!$('workspace').hidden && Date.now() - lastActivity >= 300000) {
    lockedView(); api('lock').catch(() => {}); message('Vault locked after inactivity.');
  }
}, 1000);
async function start() {
  const response = await fetch('/api/status');
  if (!response.ok) throw new Error('Could not connect to the vault.');
  const status = await response.json(); initialized = status.initialized;
  $('unlock-title').textContent = initialized ? 'Unlock your vault' : 'Create your vault';
  $('unlock-button').textContent = initialized ? 'Unlock' : 'Create vault';
  $('confirm-label').hidden = initialized; $('confirm-master').required = !initialized;
  $('master').minLength = initialized ? 1 : 12;
  if (!status.locked) { $('locked').hidden = true; $('workspace').hidden = false; $('lock').hidden = false; await refresh(); }
}
start().catch(error => message(error.message));
