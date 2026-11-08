let csrf, impact;
const $ = id => document.getElementById(id);
let savedSignature;
let signatureOpenSequence = 0;
const el = (tag, text) => { const n = document.createElement(tag); n.textContent = text; return n; };
const seenAuthenticationErrors = new Set();
async function api(path, body, form = false, raw = false) {
  const r = await fetch('/api/' + path, { method: body === undefined ? 'GET' : 'POST',
    headers: body === undefined ? {} : form ? { 'X-CSRF-TOKEN': csrf } : { 'X-CSRF-TOKEN': csrf, 'Content-Type': raw ? 'text/plain; charset=utf-8' : 'application/json' },
    body: body === undefined ? undefined : form || raw ? body : JSON.stringify(body) });
  if (!r.ok) { let message = 'Request failed'; try { message = (await r.json()).error || message; } catch {} throw Error(message); }
  if (r.headers.get('content-length') === '0') return;
  return r.headers.get('content-type')?.includes('application/json') ? r.json() : r.text();
}
function notify(message) { $('notice').textContent = message; }
async function run(fn) { try { await fn(); } catch (e) { notify(e.message); } }
function action(label, callback, disabled = false) { const button = el('button', label); button.disabled = disabled; button.onclick = () => run(callback); return button; }
const labelFor = account => account.mailbox + ' (' + account.id.slice(0, 8) + ')';
async function status() {
  const s = await api('status');
  const authenticating = s.authenticationOperations.some(x => x.running);
  $('mode').textContent = s.dryRun ? 'DryRun' : 'Live quarantine';
  $('scan').disabled = s.scanner === 'Running' || !s.accounts.some(x => x.enabled);
  $('addAccount').disabled = authenticating;
  $('scanError').textContent = [s.migrationError, s.error].filter(Boolean).join(' ');
  $('accounts').replaceChildren();
  for (const account of s.accounts) {
    const card = el('article', '');
    card.append(el('h3', labelFor(account)), el('p', account.authentication + ' - ' + (account.enabled ? 'Enabled' : 'Disabled')),
      el('p', 'Scan status: ' + account.scanStatus), el('p', 'Last successful scan: ' + (account.lastScan ? new Date(account.lastScan.completed).toLocaleString() : 'Never')));
    if (account.lastScan) card.append(el('p', `Scanned: ${account.lastScan.scanned} | Spam: ${account.lastScan.spam} | Review: ${account.lastScan.review}`));
    if (account.error) card.append(el('p', account.error));
    card.append(action('Re-authenticate', async () => { await api(`accounts/${account.id}/reauthenticate`, {}); notify('Starting sign-in for ' + labelFor(account) + '. Sign in with this same Microsoft account.'); await status(); }, authenticating),
      action(account.enabled ? 'Disable' : 'Enable', async () => { await api(`accounts/${account.id}/enabled`, { enabled: !account.enabled }); await route(); }, s.scanner === 'Running'),
      action('Wipe quarantine mails', async () => {
        const preview = await api(`accounts/${account.id}/quarantine/preview`, {});
        if (!preview.count) { notify('The quarantine folder is empty or does not exist for ' + labelFor(account) + '.'); return; }
        const operation = preview.dryRun ? 'DryRun: simulate moving' : 'Move';
        if (!window.confirm(`${operation} all ${preview.count} messages from "${preview.folderName}" for ${labelFor(account)} to Deleted Items? This clears the current contents of that quarantine folder, including any messages manually placed there. ${preview.dryRun ? 'DryRun makes no mailbox changes.' : 'Messages remain recoverable in Deleted Items.'}`)) return;
        const result = await api(`accounts/${account.id}/quarantine/wipe`, { token: preview.token, confirmed: true });
        notify(result.message); await route();
      }, s.scanner === 'Running' || account.authentication === 'Storage unavailable'),
      action('Remove', async () => {
        if (!window.confirm('Remove ' + labelFor(account) + ' from MailSentry? Its saved authentication and review state will be removed. Email in the mailbox will remain untouched.')) return;
        await api(`accounts/${account.id}/remove`, { confirmed: true }); notify('Account removed. Email was left untouched.'); await route();
      }, s.scanner === 'Running'));
    $('accounts').append(card);
  }
  if (!s.accounts.length) $('accounts').append(el('p', 'No Microsoft accounts yet. Select Add Microsoft Account to connect your first mailbox.'));
  $('authenticationOperations').replaceChildren();
  for (const operation of s.authenticationOperations) {
    const target = s.accounts.find(a => a.id === operation.targetAccountId);
    const block = el('article', '');
    block.append(el('h3', target ? 'Sign-in: ' + labelFor(target) : 'Add Microsoft Account'), el('p', operation.status));
    if (operation.running && operation.prompt) {
      block.append(el('p', 'Open Microsoft sign-in and enter this code:'), el('strong', operation.prompt.userCode));
      const link = el('a', 'Open Microsoft sign-in');
      const url = new URL(operation.prompt.verificationUri);
      if (url.protocol === 'https:') link.href = url.href;
      link.target = '_blank'; link.rel = 'noopener noreferrer'; block.append(el('p', ''), link);
    }
    if (operation.error) {
      block.append(el('p', operation.error));
      if (!seenAuthenticationErrors.has(operation.id)) { seenAuthenticationErrors.add(operation.id); notify(operation.error); }
    }
    $('authenticationOperations').append(block);
  }
  $('stats').replaceChildren(); const x = s.lastScan;
  for (const [name, value] of [['Scanner', s.scanner], ['Mailboxes', s.accounts.length], ['Connected', s.accounts.filter(a => a.authentication === 'Connected').length],
    ['Authentication needed', s.accounts.filter(a => a.authentication === 'Authentication required').length], ['Last scan outcome', s.lastRun?.outcome || 'Never'],
    ['Scanned', x?.scanned ?? 0], ['Spam matched', x?.spam ?? 0], ['Unmatched', s.unmatched], ['Signatures', s.signatures.rules.length]]) {
    const box = el('div', name); box.className = 'stat'; box.append(el('strong', value)); $('stats').append(box);
  }
  $('signatureList').replaceChildren(...s.signatureFiles.map(fileName => {
    const row = el('p', '');
    row.append(document.createTextNode(s.signatures.errors.length ? 'Inactive - ' : 'Active - '));
    const link = action(fileName, () => openSavedSignature(fileName)); link.className = 'signature-link';
    row.append(link); return row;
  }), ...s.signatures.errors.map(e => el('p', e)));
  if (!s.signatureFiles.length) $('signatureList').append(el('p', 'No saved signature files.'));
}
function closeSavedSignature() {
  signatureOpenSequence++; savedSignature = null;
  $('savedSignature').hidden = true; $('savedSignatureJson').value = ''; $('deleteSignature').disabled = true;
}
async function openSavedSignature(fileName) {
  const sequence = ++signatureOpenSequence; savedSignature = null;
  $('savedSignature').hidden = false; $('savedSignatureName').textContent = fileName;
  $('savedSignatureJson').value = 'Loading...'; $('deleteSignature').disabled = true;
  try {
    const file = await api('signatures/file?fileName=' + encodeURIComponent(fileName));
    if (sequence !== signatureOpenSequence) return;
    savedSignature = file; $('savedSignatureJson').value = file.json; $('deleteSignature').disabled = false;
    $('savedSignatureJson').focus();
  } catch (error) { if (sequence === signatureOpenSequence) closeSavedSignature(); throw error; }
}
$('closeSignature').onclick = closeSavedSignature;
$('deleteSignature').onclick = () => run(async () => {
  const selected = savedSignature;
  if (!selected || !confirm(`Delete ${selected.fileName}? Its rules will be removed for every mailbox. Existing emails will not be changed.`)) return;
  $('deleteSignature').disabled = true;
  try {
    await api('signatures/delete', { fileName: selected.fileName, fingerprint: selected.fingerprint, confirmed: true });
    closeSavedSignature(); impact = null; $('impact').hidden = true;
    notify(`Deleted ${selected.fileName}. Scan again to refresh unmatched messages.`); await status();
  } finally { $('deleteSignature').disabled = !savedSignature; }
});
async function messages() {
  const items = await api('unmatched'); $('messages').replaceChildren();
  for (const x of items) {
    const a = el('article', ''); const label = el('label', ''); const checkbox = document.createElement('input');
    checkbox.type = 'checkbox'; checkbox.value = x.selectionKey; checkbox.name = 'message'; label.append(checkbox, document.createTextNode(' ' + x.message.subject));
    a.append(el('p', 'Mailbox: ' + x.mailbox + ' (' + x.accountId.slice(0, 8) + ')'), label,
      el('p', x.message.senderName + ' - ' + x.message.senderAddress), el('p', 'Score: ' + x.result.score), el('p', 'Matched: ' + (x.result.reasons.join(', ') || 'None')));
    const auth = x.message.authentication;
    a.append(el('p', auth ? `Email authentication: SPF ${auth.spf}; DKIM ${auth.dkim}; DMARC ${auth.dmarc} (${auth.source})` : 'Email authentication: unavailable. Scan again to collect results.'));
    if (x.message.senderNameHasConfusables) a.append(el('p', 'Sender name contains lookalike or hidden characters. Comparison: ' + x.message.senderNameSkeleton));
    const preview = el('p', x.message.bodyPreview); preview.className = 'preview'; a.append(preview);
    a.append(action('Copy', () => copyMessages([x.selectionKey]))); $('messages').append(a);
  }
  if (!items.length) $('messages').append(el('p', 'No unmatched messages from enabled mailboxes.'));
}
async function copyMessages(keys) {
  const text = await api('copy', keys); $('export').value = text;
  try { await navigator.clipboard.writeText(text); notify('Sanitised messages copied. Review before sharing.'); }
  catch { $('export').focus(); $('export').select(); notify('Copy preview is ready. Use your browser copy command.'); }
}
async function route() {
  const name = ['dashboard', 'unmatched', 'signatures'].includes(location.hash.slice(1)) ? location.hash.slice(1) : 'dashboard';
  for (const id of ['dashboard', 'unmatched', 'signatures']) $(id).hidden = id !== name;
  document.querySelectorAll('nav a').forEach(a => a.setAttribute('aria-current', a.hash === '#' + name ? 'page' : 'false'));
  await status(); if (name === 'unmatched') await messages();
}
$('addAccount').onclick = () => run(async () => { await api('accounts/add', {}); notify('Starting Microsoft sign-in. Choose the Microsoft account you want to add.'); await status(); });
$('scan').onclick = () => run(async () => {
  $('scan').disabled = true; notify('Scanning enabled mailboxes...');
  try { const result = await api('scan', {}); notify(result.success ? 'All enabled mailboxes scanned successfully.' : result.error || result.run?.outcome || 'Scan did not complete.'); }
  finally { await route(); }
});
$('refresh').onclick = () => run(route);
$('selectAll').onclick = () => document.querySelectorAll('input[name=message]').forEach(c => c.checked = true);
$('copySelected').onclick = () => run(() => copyMessages([...document.querySelectorAll('input[name=message]:checked')].map(c => c.value)));
async function clearPreview() { const previous = impact; impact = null; $('impact').hidden = true; if (previous) await api('signatures/cancel/' + previous.token, {}); }
async function previewSignature(submit) {
  const controls = [...$('upload').querySelectorAll('button'), ...$('pasteSignature').querySelectorAll('button'), $('file'), $('signatureJson')];
  controls.forEach(c => c.disabled = true);
  try {
    await clearPreview(); impact = await submit(); $('impact').hidden = false;
    $('impactSummary').textContent = `Validation successful. File: ${impact.fileName}. ${impact.rules} rules, ${impact.conditions} conditions. Tested ${impact.tested}; new SPAM ${impact.newSpam}; still unmatched ${impact.stillUnmatched}. Confirm Install & Activate to save this shared pack. No mail has been moved.`;
    $('impactAccounts').replaceChildren(...(impact.accounts || []).map(a => el('li', `${a.mailbox} (${a.accountId.slice(0, 8)}): ${a.newSpam} new SPAM, ${a.tested} tested`)));
    $('impactSubjects').replaceChildren(...(impact.matches || impact.subjects.map(subject => ({ subject }))).map(m => el('li', (m.mailbox ? m.mailbox + ': ' : '') + m.subject)));
    notify('Review the impact across enabled mailboxes before saving and activating.');
  } finally { controls.forEach(c => c.disabled = false); }
}
$('upload').onsubmit = e => { e.preventDefault(); const form = new FormData($('upload')); run(() => previewSignature(() => api('signatures/preview', form, true))); };
$('pasteSignature').onsubmit = e => { e.preventDefault(); const json = $('signatureJson').value; run(() => previewSignature(() => api('signatures/preview-pasted', json, false, true))); };
$('signatureJson').addEventListener('input', () => run(clearPreview));
$('file').addEventListener('change', () => run(clearPreview));
$('cancel').onclick = () => run(async () => { await clearPreview(); notify('Preview cancelled.'); });
$('activate').onclick = () => run(async () => {
  if (!impact) return; $('activate').disabled = true;
  try {
    const i = impact; await api('signatures/activate/' + i.token, {});
    notify(`Installed ${i.fileName}. ${i.rules} rules active for all accounts. Previously unmatched: ${i.tested}; now matched as spam: ${i.newSpam}; still unmatched: ${i.stillUnmatched}. Mail moves on the next live scan.`);
    impact = null; $('impact').hidden = true; await route();
  } finally { $('activate').disabled = false; }
});
window.addEventListener('hashchange', () => run(route));
run(async () => { csrf = (await api('session')).token; await route(); });
setInterval(() => run(status), 5000);
