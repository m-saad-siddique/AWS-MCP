import {splitCommand,parseAwsCommand,parseSessionCommand} from './commands.js';
const $ = id => document.getElementById(id);
const hash = location.hash.slice(1);
if (hash) { sessionStorage.setItem('aws-mcp-token', hash); history.replaceState(null, '', '/'); }
let token = sessionStorage.getItem('aws-mcp-token') || '';
let databases = [];
let historyOffset=0,historyEventOffset=0,historyMode='requests',historyFilters={},historyLoading=false,historyReloadQueued=false,historyRecord;
let mfaState={rememberAcrossRestarts:true,storage:'memory',warning:'',sessions:[]};
let policyState, policyDraft, previewRevision, policyDirty = false;
let reviewing, lastResultField = 'review-stdout';
const reviewDrafts = new Map();
const selectedRequests=new Set();let batchSnapshot=[],batchRunning=false,batchStopRequested=false,individualQueue=[];const commandDrafts=[];
let setup, activeClient = 'codex';
let profiles = [], requests = [], profileFilter = '', statusFilter = 'pending', selected, busy = false;
function el(tag, text, className) { const node = document.createElement(tag); if (text !== undefined) node.textContent = text; if (className) node.className = className; return node; }
function error(message) { $('error').textContent = message; $('error').hidden = !message; $('dialog-error').textContent = message; $('dialog-error').hidden = !message; $('result-error').textContent = message; $('result-error').hidden = !message; }
async function api(path, body) {
  const response = await fetch('/api/' + path, { method: body ? 'POST' : 'GET', headers: { Authorization: `Bearer ${token}`, ...(body ? { 'Content-Type': 'application/json' } : {}) }, body: body ? JSON.stringify(body) : undefined });
  const result = await response.json(); if (!response.ok) throw new Error(result.error || 'Request failed.'); return result;
}
function displayCommand(r) {
  if (r.kind === 'sql') return r.sql + (r.params?.length ? '\n\nBound parameters: ' + JSON.stringify(r.params) : '');
  if (r.kind === 'tunnel') return 'aws ssm start-session --target ' + r.target.instanceId + '\n  --document-name AWS-StartPortForwardingSessionToRemoteHost\n  --parameters ' + JSON.stringify({host:[r.target.host],portNumber:[String(r.target.port)],localPortNumber:[String(r.target.localPort||'auto')]}) + '\n  --profile ' + JSON.stringify(r.profile) + ' --region ' + r.region;
  return 'aws ' + r.args.map(a => /^[a-zA-Z0-9_./:@=-]+$/.test(a) ? a : JSON.stringify(a)).join(' ') + ' --profile ' + JSON.stringify(r.profile) + (r.region ? ' --region ' + r.region : ''); }
function renderProfiles() {
  $('profiles').replaceChildren();
  const search = $('profile-search').value.toLowerCase();
  for (const p of profiles.filter(p => p.name.toLowerCase().includes(search))) {
    const button = el('button', undefined, 'profile-item' + (profileFilter === p.name ? ' selected' : ''));
    button.append(el('span', p.sso ? 'S' : p.roleArn ? 'R' : 'P', 'profile-icon'));
    button.dataset.profile=p.name;
    const label = el('span', p.name, 'profile-name'); label.title = p.name;
    label.append(el('small', p.sso ? 'IAM Identity Center' : p.mfaSerial ? 'MFA protected' : p.roleArn ? 'Assume role' : p.region || 'AWS profile')); button.append(label);
    button.onclick = () => { showView('queue'); profileFilter = p.name; $('profile').value = p.name; renderProfiles(); renderRequests(); }; $('profiles').append(button);
  }
  if (!profiles.length) $('profiles').append(el('p', 'No profiles found. Configure AWS CLI in your terminal.'));
  const previous = $('profile').value; $('profile').replaceChildren(...profiles.map(p => { const option = el('option', p.name); option.value = p.name; return option; }));
  if (profiles.some(p => p.name === previous)) $('profile').value = previous;
  const previousDbProfile = $('db-profile').value; $('db-profile').replaceChildren(...profiles.map(p => { const option = el('option', p.name); option.value = p.name; return option; })); if (profiles.some(p=>p.name===previousDbProfile)) $('db-profile').value=previousDbProfile;
  for (const id of ['rule-profile','preview-profile']) { const previous=$(id).value; const options=profiles.map(p=>{const o=el('option',p.name);o.value=p.name;return o;}); if(id==='rule-profile'){const all=el('option','All profiles');all.value='*';options.unshift(all);} $(id).replaceChildren(...options); if(options.some(o=>o.value===previous))$(id).value=previous; }
  $('profile-count').textContent = profiles.length; $('submit-command').disabled = !profiles.length;updateMfaProfileLabels();
}
function renderRequests() {
  const pending = requests.filter(r => ['pending', 'awaiting_review', 'releasing'].includes(r.status)).length;
  $('pending-count').textContent = pending; $('queue-count').textContent = pending;
  $('running-count').textContent = requests.filter(r => ['running', 'authorizing'].includes(r.status)).length;
  $('completed-count').textContent = requests.filter(r => r.status === 'completed').length;
  $('filter-label').textContent = profileFilter ? '/ ' + profileFilter : '';
  const expanded = new Set([...document.querySelectorAll('details[open]')].map(n => n.dataset.id));
  $('requests').replaceChildren();
  const visible = requests.filter(r => (!profileFilter || r.profile === profileFilter) && (statusFilter === 'all' || ['pending', 'awaiting_review', 'releasing'].includes(r.status)));
  if (!visible.length) { const empty = el('div', undefined, 'empty'); empty.append(el('div', '▤', 'empty-icon'), el('h2', statusFilter === 'pending' ? 'No commands or results waiting for review' : 'No command activity yet'), el('p', 'Connect your agent to get started. Requests needing your approval will appear here.')); $('requests').append(empty); }
  for(const id of selectedRequests)if(!requests.some(r=>r.id===id&&r.status==='pending'))selectedRequests.delete(id);
  updateQueueSelection(visible);
  const groups=new Map();
  for(const r of visible){if(!groups.has(r.profile))groups.set(r.profile,[]);groups.get(r.profile).push(r);}
  for(const [profile,items] of [...groups].sort(([a],[b])=>a.localeCompare(b))){
    const group=el('section',undefined,'profile-group');group.dataset.profile=profile;
    const heading=el('div',undefined,'profile-group-heading'),name=el('div');name.append(el('h2',profile),el('span',items.length+' request'+(items.length===1?'':'s'),'muted'));
    const pendingIds=items.filter(r=>r.status==='pending').map(r=>r.id);heading.append(name);
    if(pendingIds.length){const review=el('button','Review all · '+pendingIds.length);review.setAttribute('aria-label','Review all pending for '+profile);review.onclick=()=>openBatch(pendingIds);heading.append(review);}
    group.append(heading);$('requests').append(group);
  for (const r of items) {
    const card = el('article', undefined, 'request-card'); const top = el('div', undefined, 'request-top');
    const meta = el('div', undefined, 'request-meta'); meta.append(el('span', r.kind === 'sql' ? 'SQL' : r.kind === 'tunnel' ? 'SSM tunnel' : 'AWS', 'pill'), el('span', r.connectionName || r.profile, 'pill'), el('span', r.status === 'awaiting_review' ? 'Result needs review' : r.status === 'releasing' ? 'Sending result' : r.status, 'pill ' + r.status), el('span', r.risk === 'read' ? 'Read · may expose data' : r.risk === 'write' ? (r.kind === 'tunnel' ? 'Open connection' : 'May change resources') : 'Needs confirmation', 'pill ' + r.risk));
    if(r.status==='pending'){const select=el('input');select.type='checkbox';select.className='request-select';select.setAttribute('aria-label','Select request '+r.id);select.checked=selectedRequests.has(r.id);select.onchange=()=>{if(select.checked)selectedRequests.add(r.id);else selectedRequests.delete(r.id);updateQueueSelection(visible);};meta.prepend(select);}
    top.append(meta, el('span', new Date(r.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }), 'request-time'));
    const bottom = el('div', undefined, 'request-bottom'); bottom.append(el('p', r.reason || 'Manual command'));
    const actions = el('div', undefined, 'request-actions');
    if (r.autoApproved) meta.append(el('span','Auto-approved','pill allow'));
    if (r.status === 'pending') { const deny = el('button', 'Deny'); deny.onclick = () => act(() => api(`requests/${r.id}/decision`, { decision: 'deny' })); const review = el('button', 'Review request ↗', 'primary'); review.onclick = () => reviewRequest(r); actions.append(deny, review); }
    if (r.status === 'awaiting_review') { const review = el('button', 'Review & mask result', 'primary'); review.onclick = () => reviewResult(r); actions.append(review); }
    if (['running', 'authorizing'].includes(r.status)) { const cancel = el('button', 'Cancel'); cancel.onclick = () => act(() => api(`requests/${r.id}/cancel`, {})); actions.append(cancel); }
    bottom.append(actions); card.append(top, el('pre', displayCommand(r)), bottom, el('div', r.id, 'request-id'));
    if (r.target) card.append(el('p', `${r.target.engine} · ${r.target.host}:${r.target.port} / ${r.target.database} · user ${r.target.username} · ${r.profile}`, 'target-detail'));
    if (r.result) { const details = el('details', undefined, 'result'); details.dataset.id = r.id; details.open = expanded.has(r.id); details.append(el('summary', `View result · exit ${r.result.exitCode}`), el('pre', [r.result.stdout, r.result.stderr].filter(Boolean).join('\n') || '(No output)')); card.append(details); }
    if (r.status === 'awaiting_review') card.append(el('p', 'Command executed. Output is held locally and has not been sent to the agent.', 'held-note'));
    if (r.status === 'withheld') card.append(el('p', 'Command executed. You chose not to send its result to the agent.', 'delivery-note'));
    if (r.result && r.kind === 'aws') card.append(el('p', r.outputReviewed ? 'Reviewed result sent to agent.' : 'Result sent directly to agent.', 'delivery-note'));
    if (r.policy) card.append(el('p',r.policy.reason,'policy-note'));
    if(r.historyError)card.append(el('p',r.historyError,'history-recovery'));
    if (r.auditError) card.append(el('p', r.auditError));
    if (r.status === 'canceled') card.append(el('p', 'Canceled locally. Remote operations may already have completed.'));
    group.append(card);
  }
  }
  for (const id of reviewDrafts.keys()) if (!requests.some(r => r.id === id && r.status === 'awaiting_review')) reviewDrafts.delete(id);
  if (reviewing && !requests.some(r => r.id === reviewing.id && r.status === 'awaiting_review')) closeResult();
  if (selected) {
    const current = requests.find(r => r.id === selected.id);
    if (!current || current.status !== 'pending') closeDialog();
  }
}
function reviewRequest(r) {
  selected = r; error(''); $('approval-form').reset(); $('dialog-reason').textContent = r.reason;
  $('dialog-command').textContent = displayCommand(r);
  const p = profiles.find(p => p.name === r.profile);
  $('dialog-heading').textContent = r.kind === 'sql' ? 'Run this SQL query?' : r.kind === 'tunnel' ? 'Open this database tunnel?' : 'Run this AWS command?';
  $('dialog-warning').textContent = r.kind === 'sql' ? `Database: ${r.target.database} · ${r.target.host} · user ${r.target.username}. Results are returned to the requester. Every query needs a separate approval.` : r.kind === 'tunnel' ? `Forward a local port through ${r.target.instanceId} to ${r.target.host}:${r.target.port}. The tunnel closes after 15 minutes; SQL queries still need separate approval.` : 'The command runs on the selected profile. Choose below how its result will be delivered.';
  $('result-delivery').hidden = r.kind !== 'aws'; $('send-directly').checked = policyState?.defaultDelivery !== 'review';
  updateDeliveryHelp();
  $('confirm-label').firstChild.nodeValue = r.kind === 'sql' ? 'Type the connection name to confirm' : 'Type the profile name to confirm';
  const cached=mfaState.sessions.find(s=>s.profile===r.profile&&s.status==='active');
  $('mfa-fields').open = !!p?.mfaSerial&&!cached; $('mfa-section').hidden = r.kind === 'sql' || !!p?.sso; $('mfa-serial').value = cached?.mfaSerial || p?.mfaSerial || '';
  $('mfa-session-hint').hidden=!cached;$('mfa-session-hint').textContent=cached?`MFA active until ${new Date(cached.expiresAt).toLocaleString()} · ${cached.storage==='keychain'?'saved in Keychain':'memory only'}. Leave the code blank to reuse it.`:'';
  $('remember-mfa').checked=mfaState.rememberAcrossRestarts&&mfaState.storage==='keychain';$('remember-mfa').disabled=mfaState.storage!=='keychain'||!mfaState.rememberAcrossRestarts;
  $('confirm-label').hidden = r.risk !== 'destructive'; $('confirmation').required = r.risk === 'destructive';
  $('confirmation').placeholder = r.confirmationTarget || r.profile; $('approval-dialog').showModal();
}
function closeDialog(completed=false) { $('approval-dialog').close(); $('approval-form').reset(); selected = undefined;if(completed===true&&individualQueue.length){queueMicrotask(reviewNextIndividual);}else individualQueue=[]; }
function reviewNextIndividual(){const id=individualQueue.shift(),request=requests.find(r=>r.id===id&&r.status==='pending');if(request)reviewRequest(request);else if(individualQueue.length)reviewNextIndividual();}
async function refresh() {
  try { const result = await Promise.all([api('requests'), api('databases'), api('policies'), api('sessions')]); requests = result[0]; databases = result[1]; policyState=result[2];mfaState=result[3];renderMfaSessions();updateMfaProfileLabels(); renderPolicySummary(); renderRequests(); renderDatabases(); $('connection').textContent = 'Connected to local server';if(!$('history-view').hidden&&historyOffset===0&&!$('history-dialog').open&&!historyLoading)loadHistory().catch(e=>error(e.message)); } catch (e) { $('connection').textContent = 'Disconnected'; error(e.message); }
}
async function loadProfiles() { profiles = await api('profiles'); renderProfiles(); }
async function act(action) { try { error(''); await action(); await refresh(); } catch (e) { error(e.message); } }
$('close-dialog').onclick = ()=>closeDialog();
$('approval-dialog').addEventListener('cancel', closeDialog);
$('approval-dialog').addEventListener('click', e => { if (e.target === $('approval-dialog')) closeDialog(); });
$('deny').onclick = () => { const id = selected?.id; if (id) act(async () => { await api(`requests/${id}/decision`, { decision: 'deny' }); closeDialog(true); }); };
$('approval-form').onsubmit = async e => {
  e.preventDefault(); if (!selected || busy) return;
  busy = true; $('approve').disabled = true;
  try {
    error(''); await api(`requests/${selected.id}/decision`, { decision: 'approve', mfaCode: $('mfa-code').value, mfaSerial: $('mfa-serial').value, rememberMfa:$('remember-mfa').checked, confirmation: $('confirmation').value, deliveryMode: $('send-directly').checked ? 'direct' : 'review' }); closeDialog(true); await refresh();
  } catch (e) { error(e.message); } finally { busy = false; $('approve').disabled = false; }
};
function updateDeliveryHelp() { $('delivery-help').textContent = $('send-directly').checked ? 'The result will be returned to the agent immediately after execution.' : 'Unchecked: hold the result so you can review and mask it before sending.'; }
$('send-directly').onchange = updateDeliveryHelp;
function saveReviewDraft() {
  if (reviewing && requests.some(r => r.id === reviewing.id && r.status === 'awaiting_review')) reviewDrafts.set(reviewing.id, { stdout: $('review-stdout').value, stderr: $('review-stderr').value });
}
function reviewResult(r) {
  if (!r.heldResult) { error('Result is no longer available for review. Refresh the dashboard.'); return; }
  error(''); reviewing = r;
  const draft = reviewDrafts.get(r.id) || r.heldResult;
  $('result-context').textContent = `${r.profile} · exit ${r.heldResult.exitCode} · ${r.args[0]} ${r.args[1]}`;
  $('review-stdout').value = draft.stdout; $('review-stderr').value = draft.stderr; $('mask-value').value = '';
  $('send-result').disabled = false; $('withhold-result').disabled = false;
  $('result-dialog').showModal();
}
function closeResult() { saveReviewDraft(); $('result-dialog').close(); $('review-stdout').value = ''; $('review-stderr').value = ''; $('mask-value').value = ''; reviewing = undefined; }
$('close-result').onclick = closeResult;
$('result-dialog').addEventListener('cancel', closeResult);
for (const id of ['review-stdout', 'review-stderr']) { $(id).onfocus = () => { lastResultField = id; }; $(id).oninput = saveReviewDraft; }
function maskEverywhere(value) {
  if (!value) { error('Select text or enter a value to mask.'); return; }
  for (const id of ['review-stdout', 'review-stderr']) $(id).value = $(id).value.split(value).join('[MASKED]');
  saveReviewDraft(); error(''); $('mask-value').value = '';
}
$('mask-selection').onclick = () => { const field = $(lastResultField); maskEverywhere(field.value.slice(field.selectionStart, field.selectionEnd)); };
$('mask-all').onclick = () => maskEverywhere($('mask-value').value);
$('mask-value').onkeydown = e => { if (e.key === 'Enter') { e.preventDefault(); maskEverywhere($('mask-value').value); } };
$('withhold-result').onclick = () => {
  if (!reviewing) return;
  const id = reviewing.id;
  act(async () => { await api(`requests/${id}/release`, { decision: 'withhold' }); reviewDrafts.delete(id); reviewing = undefined; closeResult(); });
};
$('result-form').onsubmit = async e => {
  e.preventDefault(); if (!reviewing) return;
  const id = reviewing.id;
  $('send-result').disabled = true; $('withhold-result').disabled = true;
  try {
    error(''); await api(`requests/${id}/release`, { decision: 'send', stdout: $('review-stdout').value, stderr: $('review-stderr').value });
    reviewDrafts.delete(id); reviewing = undefined; closeResult(); await refresh();
  } catch (e) { error(e.message); }
  finally { $('send-result').disabled = false; $('withhold-result').disabled = false; }
};
$('command-form').onsubmit = e => { e.preventDefault(); act(async () => { const request=composerRequest();if(routeForwardingCommand(request))return;await api('requests',request); setActivityFilter('pending'); }); };
$('clear-sessions').onclick = () => act(() => api('sessions/clear', {}));
$('refresh').onclick = () => act(loadProfiles);
$('profile-search').oninput = renderProfiles;
$('all-requests').onclick = () => { showView('queue'); profileFilter = ''; renderProfiles(); renderRequests(); };
function setActivityFilter(filter) { statusFilter = filter; for (const b of document.querySelectorAll('[data-filter]')) b.classList.toggle('selected', b.dataset.filter === filter); renderRequests(); }
for (const button of document.querySelectorAll('[data-filter]')) button.onclick = () => setActivityFilter(button.dataset.filter);
for (const button of document.querySelectorAll('[data-command]')) button.onclick = () => { $('command').value = button.dataset.command; $('reason').focus(); };
function showView(view) {
  const isQueue = view === 'queue';
  $('queue-view').hidden = !isQueue; $('connect-view').hidden = view !== 'connect'; $('databases-view').hidden = view !== 'databases'; $('policies-view').hidden=view!=='policies';$('sessions-view').hidden=view!=='sessions';$('history-view').hidden=view!=='history';
  $('page-title').textContent = isQueue ? 'Approvals' : view === 'databases' ? 'Databases' : view==='policies'?'Policies':view==='sessions'?'MFA sessions':view==='history'?'History':'Connect an agent';
  $('all-requests').classList.toggle('active', isQueue); $('connect-nav').classList.toggle('active', view === 'connect'); $('databases-nav').classList.toggle('active', view === 'databases'); $('policies-nav').classList.toggle('active',view==='policies');$('sessions-nav').classList.toggle('active',view==='sessions');$('history-nav').classList.toggle('active',view==='history');
  if(view==='history')loadHistory().catch(e=>error(e.message));
  if (view==='policies') loadPolicies().catch(e=>error(e.message));
  if (view === 'connect') loadSetup().catch(e => error(e.message));
}
function renderSetup() {
  $('client-tabs').replaceChildren();
  for (const client of setup.clients) {
    const button = el('button', client.name); button.role = 'tab'; button.id = 'client-' + client.id;
    button.setAttribute('aria-selected', String(client.id === activeClient));
    button.setAttribute('aria-controls', 'setup-panel'); button.tabIndex = client.id === activeClient ? 0 : -1;
    button.onclick = () => { activeClient = client.id; renderSetup(); };
    button.onkeydown = e => {
      if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(e.key)) return;
      e.preventDefault(); const index = setup.clients.findIndex(c => c.id === activeClient);
      const next = e.key === 'Home' ? 0 : e.key === 'End' ? setup.clients.length - 1 : (index + (e.key === 'ArrowRight' ? 1 : -1) + setup.clients.length) % setup.clients.length;
      activeClient = setup.clients[next].id; renderSetup(); $('client-' + activeClient).focus();
    };
    $('client-tabs').append(button);
  }
  const client = setup.clients.find(c => c.id === activeClient);
  $('setup-panel').setAttribute('aria-labelledby', 'client-' + client.id);
  $('setup-location').textContent = client.location; $('setup-code-label').textContent = client.label;
  $('setup-code').textContent = client.code; $('setup-note').textContent = client.note;
  $('setup-docs').href = client.docs; $('copy-setup').textContent = 'Copy';
}
async function loadSetup() { if (!setup) setup = await api('setup'); renderSetup(); }
$('connect-nav').onclick = () => showView('connect');
$('connect-prompt-button').onclick = () => { showView('connect'); window.scrollTo({ top: 0, behavior: 'smooth' }); };
$('new-command').onclick = () => { $('command-compose').open = true; $('command').focus(); };
$('copy-setup').onclick = async () => {
  try { await navigator.clipboard.writeText($('setup-code').textContent); $('copy-setup').textContent = 'Copied!'; }
  catch { error('Copy was unavailable. Select and copy the configuration below.'); }
};
function renderDatabases() {
  const list = $('database-list'); list.replaceChildren();
  const previous = $('query-connection').value;
  $('query-connection').replaceChildren(...databases.map(c => { const o = el('option', c.name); o.value = c.id; return o; }));
  if (databases.some(c=>c.id===previous)) $('query-connection').value = previous;
  $('submit-query').disabled = !databases.length;
  if (!databases.length) { const empty = el('div', undefined, 'empty'); empty.append(el('h2', 'No database connections yet'), el('p', 'Add your RDS endpoint and the EC2 instance you use with Session Manager.')); list.append(empty); }
  for (const c of databases) {
    const card = el('article', undefined, 'database-card'); card.dataset.connection = c.id;
    const heading = el('div', undefined, 'database-card-heading'); heading.append(el('h2', c.name), el('span', c.engine === 'postgres' ? 'PostgreSQL' : 'MySQL', 'pill'), el('span', c.readOnly ? 'Read-only' : 'Writes enabled', 'pill'), el('span', 'Tunnel ' + c.tunnel.status, 'pill ' + (c.tunnel.status === 'open' ? 'completed' : '')));
    card.append(heading, el('p', `${c.host}:${c.port} / ${c.database} · user ${c.username}\n${c.profile} · ${c.region} · via ${c.instanceId}`, 'database-meta'));
    const actions = el('div', undefined, 'database-actions');
    if (c.tunnel.status === 'closed') {
      const open = el('button', 'Request tunnel', 'primary'); open.onclick = () => act(async()=>{ await api('requests', { kind:'tunnel', connectionId:c.id, reason:`Open Session Manager tunnel for ${c.name}` }); showView('queue'); setActivityFilter('pending'); }); actions.append(open);
      const edit = el('button', 'Edit connection'); edit.onclick = () => editDatabase(c); actions.append(edit);
    } else { const close = el('button', 'Close tunnel'); close.onclick = () => act(()=>api(`databases/${c.id}/close`, {})); actions.append(close); }
    const query = el('button', 'Write a query'); query.onclick = () => { $('query-connection').value = c.id; $('query-sql').focus(); }; actions.append(query);
    const remove = el('button', 'Delete'); remove.onclick = () => { if (window.confirm(`Delete ${c.name}? Its tunnel and pending requests will be closed.`)) act(()=>api(`databases/${c.id}/delete`, {})); }; actions.append(remove);
    card.append(actions, el('p', (c.passwordReady ? 'Password available in server memory or environment.' : 'Password needed before querying. Edit connection to enter it.') + (c.tunnel.expiresAt ? ' Tunnel closes at ' + new Date(c.tunnel.expiresAt).toLocaleTimeString() + '.' : ''), 'database-ready')); list.append(card);
  }
}
function editDatabase(c) {
  $('database-form').reset();resetSessionImport();
  const fields={id:'id',name:'name',engine:'engine',profile:'profile',region:'region',instance:'instanceId',host:'host',port:'port','local-port':'localPort',database:'database',username:'username','password-env':'passwordEnv'};
  for(const [field,key] of Object.entries(fields)) $('db-'+field).value=c[key]||'';
  $('db-read-only').checked=c.readOnly; $('db-confirm-writes-label').hidden=c.readOnly; $('db-confirm-writes').required=!c.readOnly;
  $('database-settings').open=true;updateSessionPreview(); $('db-name').focus();
}
$('databases-nav').onclick=()=>showView('databases');
$('add-database').onclick=()=>{ $('database-form').reset(); $('db-id').value='';resetSessionImport(); $('db-confirm-writes-label').hidden=true; $('db-confirm-writes').required=false; $('database-settings').open=true;updateSessionPreview(); $('db-name').focus(); };
$('db-engine').onchange=()=>{ $('db-port').value=$('db-engine').value==='mysql'?'3306':'5432'; };
$('db-profile').onchange=()=>{ const p=profiles.find(p=>p.name===$('db-profile').value); if(p?.region) $('db-region').value=p.region; };
$('db-read-only').onchange=()=>{ $('db-confirm-writes-label').hidden=$('db-read-only').checked; $('db-confirm-writes').required=!$('db-read-only').checked; };
$('database-form').onsubmit=e=>{ e.preventDefault(); act(async()=>{
  $('save-database').disabled=true;
  try {
    const value=await api('databases',{id:$('db-id').value||undefined,name:$('db-name').value,engine:$('db-engine').value,profile:$('db-profile').value,region:$('db-region').value,instanceId:$('db-instance').value,host:$('db-host').value,port:Number($('db-port').value),localPort:Number($('db-local-port').value||0),database:$('db-database').value,username:$('db-username').value,password:$('db-password').value,passwordEnv:$('db-password-env').value,readOnly:$('db-read-only').checked,confirmWrites:$('db-confirm-writes').value});
    $('db-password').value=''; $('database-form').reset(); $('db-id').value=''; $('database-settings').open=false; $('db-confirm-writes-label').hidden=true; $('db-confirm-writes').required=false;
    await refresh(); $('query-connection').value=value.id;
  } finally { $('save-database').disabled=false; }
}); };
$('database-query-form').onsubmit=e=>{ e.preventDefault(); act(async()=>{
  await api('requests',{kind:'sql',connectionId:$('query-connection').value,sql:$('query-sql').value,params:JSON.parse($('query-params').value||'[]'),reason:$('query-reason').value});
  showView('queue'); setActivityFilter('pending');
}); };
const historyStatus={completed:'Completed',failed:'Failed',denied:'Denied',blocked:'Blocked',canceled:'Canceled',interrupted:'Interrupted',outcome_unknown:'Outcome unknown',result_unavailable:'Output unavailable',awaiting_review:'Result needs review',pending:'Pending',running:'Running',authorizing:'Authorizing',releasing:'Releasing output',expired:'Expired',withheld:'Output withheld'};
const historyEvents={submitted:'Request submitted',approved:'Manually approved',auto_approved:'Policy auto-approved',policy_blocked:'Blocked by policy',execution_started:'Execution started',completed:'Execution completed',failed:'Execution failed',awaiting_review:'Result held for review',result_released:'Result release authorized',result_withheld:'Withholding authorized',result_sent:'Reviewed result sent',result_discarded:'Result withheld',denied:'Request denied',expired:'Approval expired',canceled:'Request canceled',broker_stopped_request:'Interrupted by broker stop',recovered_after_restart:'Recovered after restart',broker_started:'Broker started',broker_stopped:'Broker stopped',broker_unclean_stop_detected:'Previous unclean stop detected',policy_changed:'Approval policies changed',database_connection_saved:'Database connection saved',database_connection_deleted:'Database connection deleted',database_tunnel_closed:'Database tunnel closed',mfa_remember_setting_changed:'MFA remember setting changed',mfa_active_sessions_saved:'MFA sessions saved',mfa_sessions_forgotten:'MFA sessions forgotten',imported_existing_activity:'Existing activity imported',existing_activity_imported:'Existing request import finished'};
function historyTime(value){return value?new Date(value).toLocaleString():'—';}
function historyDuration(value){return value===null||value===undefined?'—':value<1000?value+' ms':(value/1000).toFixed(1)+' s';}
function historyDetailsText(details){return Object.entries(details||{}).filter(([,v])=>v!==undefined&&v!==null).map(([k,v])=>k+': '+(typeof v==='object'?JSON.stringify(v):String(v))).join(' · ');}
async function loadHistory(){
  if(historyLoading){historyReloadQueued=true;return;}historyLoading=true;
  try{
    const query=new URLSearchParams({...historyFilters,offset:String(historyOffset),limit:'50'});
    const [data,events]=await Promise.all([api('history?'+query),api('history/events?offset='+historyEventOffset+'&limit=30')]);
    $('history-total').textContent=data.summary.total;$('history-completed').textContent=data.summary.counts.completed||0;
    $('history-attention').textContent=(data.summary.counts.failed||0)+(data.summary.counts.outcome_unknown||0)+(data.summary.counts.result_unavailable||0);
    $('history-storage-note').textContent=data.summary.persistent?'History is saved locally and survives broker/app restarts. Records are kept until you remove the history database.':'History is in memory only for this server session. A runtime directory is required for persistence.';
    $('history-warning').hidden=!data.summary.warning;$('history-warning').textContent=data.summary.warning;
    $('history-rows').replaceChildren();$('history-empty').hidden=data.items.length>0;
    for(const record of data.items){
      const row=el('tr');row.dataset.historyId=record.id;
      const time=el('td',historyTime(record.createdAt));time.append(el('small',record.source==='dashboard'?'Dashboard':record.source==='legacy'?'Imported activity':record.clientName||'Agent'));
      const command=el('td');command.append(el('strong',record.kind==='sql'?'SQL query':record.kind==='tunnel'?'SSM tunnel':'AWS command'),el('code',record.command));
      const target=el('td',record.connectionName||record.profile);target.append(el('small',record.connectionName?record.profile:record.region||'Profile region'));
      const outcome=el('td');outcome.append(el('span',historyStatus[record.status]||record.status,'pill '+record.status));outcome.append(el('small',(record.exitCode===null?'':`Exit ${record.exitCode} · `)+historyDuration(record.durationMs)+(record.autoApproved?' · auto-approved':'')));
      const action=el('td');const view=el('button','View details');view.onclick=()=>openHistoryRecord(record.id).catch(e=>error(e.message));action.append(view);row.append(time,command,target,outcome,action);$('history-rows').append(row);
    }
    $('history-page-label').textContent=data.total?`${data.offset+1}–${Math.min(data.total,data.offset+data.items.length)} of ${data.total} records`:'0 records';$('history-previous').disabled=data.offset<=0;$('history-next').disabled=data.offset+data.limit>=data.total;
    $('history-system-events').replaceChildren();
    for(const entry of events.items){const card=el('article',undefined,'history-event'),heading=el('div');heading.append(el('strong',historyEvents[entry.event]||entry.event),el('time',historyTime(entry.at)));card.append(heading,el('p',historyDetailsText(entry.details)));$('history-system-events').append(card);}
    $('history-system-page-label').textContent=events.total?`${historyEventOffset+1}–${Math.min(events.total,historyEventOffset+events.items.length)} of ${events.total} events`:'0 server events';$('history-system-previous').disabled=historyEventOffset<=0;$('history-system-next').disabled=historyEventOffset+30>=events.total;
  }finally{historyLoading=false;if(historyReloadQueued){historyReloadQueued=false;queueMicrotask(()=>loadHistory().catch(e=>error(e.message)));}}
}
async function openHistoryRecord(id){
  const data=await api('history/'+id);historyRecord=data;const r=data.request;
  $('history-detail-title').textContent=r.kind==='sql'?'SQL query record':r.kind==='tunnel'?'SSM tunnel record':'AWS command record';$('history-detail-id').textContent=r.id;
  const metadata=[['Outcome',historyStatus[r.status]||r.status],['Submitted',historyTime(r.createdAt)],['Started',historyTime(r.startedAt)],['Finished',historyTime(r.finishedAt)],['Duration',r.startedAt&&r.finishedAt?historyDuration(r.finishedAt-r.startedAt):'—'],['Profile',r.profile],['Database',r.connectionName||r.target?.database||'—'],['Source',r.source==='dashboard'?'Dashboard':r.clientName||r.source||'Agent'],['Approval',r.autoApproved?'Automatically approved':data.events.some(event=>event.event==='approved')?'Manually approved':'No approval recorded'],['Policy decision',r.policy?.reason||'—'],['MFA',r.mfaUsed?'New code supplied':r.mfaSessionReused?'Cached session reused':'Profile authentication'],['Delivery',r.outputReviewed?'Reviewed output released':r.deliveryMode||'Not executed']];
  $('history-detail-meta').replaceChildren();for(const [key,value] of metadata)$('history-detail-meta').append(el('dt',key),el('dd',value));
  $('history-recovery-note').hidden=!r.recoveryNote;$('history-recovery-note').textContent=r.recoveryNote||'';
  $('history-detail-command').textContent=displayCommand(r);$('history-detail-reason').textContent=r.reason||'';
  $('history-output-note').textContent=r.result?`Exit ${r.result.exitCode}. Only released output is saved; recognizable credential fields are redacted in history.`:r.status==='withheld'?'You chose not to release the output. Its contents were not stored.':['awaiting_review','releasing','result_unavailable'].includes(r.status)?'Unreleased output is not stored in history. After a restart, it cannot be recovered.':'No output was recorded for this request.';
  $('history-detail-output').hidden=!r.result;$('history-detail-output').textContent=r.result?[r.result.stdout,r.result.stderr].filter(Boolean).join('\n')||'(No output)':'';
  $('history-detail-events').replaceChildren();for(const entry of data.events){const item=el('li');item.append(el('strong',historyEvents[entry.event]||entry.event),el('time',historyTime(entry.at)),el('p',historyDetailsText(entry.details)));$('history-detail-events').append(item);}
  $('history-dialog').showModal();
}
function setHistoryTab(mode){historyMode=mode;$('history-requests-panel').hidden=mode!=='requests';$('history-server-panel').hidden=mode!=='server';$('history-requests-tab').classList.toggle('selected',mode==='requests');$('history-server-tab').classList.toggle('selected',mode==='server');loadHistory().catch(e=>error(e.message));}
$('history-nav').onclick=()=>showView('history');$('refresh-history').onclick=()=>loadHistory().catch(e=>error(e.message));
$('history-requests-tab').onclick=()=>setHistoryTab('requests');$('history-server-tab').onclick=()=>setHistoryTab('server');
$('history-filter-form').onsubmit=e=>{e.preventDefault();historyOffset=0;historyFilters={q:$('history-search').value,kind:$('history-kind').value,status:$('history-status').value,profile:$('history-profile').value};loadHistory().catch(e=>error(e.message));};
$('reset-history').onclick=()=>{$('history-filter-form').reset();historyFilters={};historyOffset=0;loadHistory().catch(e=>error(e.message));};
$('history-previous').onclick=()=>{historyOffset=Math.max(0,historyOffset-50);loadHistory().catch(e=>error(e.message));};$('history-next').onclick=()=>{historyOffset+=50;loadHistory().catch(e=>error(e.message));};
$('history-system-previous').onclick=()=>{historyEventOffset=Math.max(0,historyEventOffset-30);loadHistory().catch(e=>error(e.message));};$('history-system-next').onclick=()=>{historyEventOffset+=30;loadHistory().catch(e=>error(e.message));};
$('close-history').onclick=()=>{$('history-dialog').close();historyRecord=undefined;};
$('history-dialog').addEventListener('close',()=>{historyRecord=undefined;});
$('download-history-record').onclick=()=>{if(!historyRecord)return;const url=URL.createObjectURL(new Blob([JSON.stringify(historyRecord,null,2)],{type:'application/json'}));const link=el('a');link.href=url;link.download='aws-mcp-history-'+historyRecord.request.id+'.json';link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);};
function updateMfaProfileLabels(){
  for(const button of $('profiles').querySelectorAll('[data-profile]')){
    const p=profiles.find(p=>p.name===button.dataset.profile),s=mfaState.sessions.find(s=>s.profile===p?.name&&s.status==='active');
    const label=button.querySelector('small');if(!label||!p)continue;
    label.textContent=s?`MFA ${s.storage==='keychain'?'saved':'active'} · ${new Date(s.expiresAt).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'})}`:p.sso?'IAM Identity Center':p.mfaSerial?'MFA protected':p.roleArn?'Assume role':p.region||'AWS profile';
  }
}
function renderMfaSessions(){
  $('mfa-session-count').textContent=mfaState.sessions.filter(s=>s.status==='active').length;
  $('remember-sessions').checked=mfaState.rememberAcrossRestarts;$('remember-sessions').disabled=mfaState.storage!=='keychain';
  $('save-active-sessions').disabled=mfaState.storage!=='keychain'||!mfaState.rememberAcrossRestarts||!mfaState.sessions.some(s=>s.status==='active');
  $('mfa-storage-note').textContent=mfaState.storage==='keychain'?'Secure persistence is available through macOS Keychain. Active credentials are reused until shortly before their AWS expiry.':'Persistent storage requires macOS Keychain. MFA credentials are kept in memory on this platform.';
  $('mfa-storage-warning').hidden=!mfaState.warning;$('mfa-storage-warning').textContent=mfaState.warning;
  $('mfa-session-list').replaceChildren();
  if(!mfaState.sessions.length){const empty=el('div',undefined,'empty');empty.append(el('h2','No AWS sessions yet'),el('p','Configured profiles and their MFA session status will appear here.'));$('mfa-session-list').append(empty);}
  const names={active:'MFA active',expired:'Refresh MFA',needs_mfa:'MFA required',aws_cli:'AWS CLI / SSO',profile_credentials:'Profile credentials'};
  for(const s of mfaState.sessions){
    const card=el('article',undefined,'database-card mfa-card');card.dataset.sessionProfile=s.profile;const heading=el('div',undefined,'database-card-heading');heading.append(el('h2',s.profile),el('span',names[s.status]||s.status,'pill '+(s.status==='active'?'completed':'')));
    if(s.status==='active')heading.append(el('span',s.storage==='keychain'?'Saved in Keychain':'Memory only','pill'));
    card.append(heading);if(s.expiresAt)card.append(el('p',`AWS expiration: ${new Date(s.expiresAt).toLocaleString()}${s.restored?' · restored after restart':''}`,'database-meta'));
    if(s.status==='active'){const actions=el('div',undefined,'database-actions');const forget=el('button','Forget session');forget.onclick=()=>act(()=>api('sessions/clear',{profile:s.profile}));actions.append(forget);card.append(actions);}else card.append(el('p',s.status==='aws_cli'?'AWS CLI manages login and expiry for this SSO profile.':s.status==='profile_credentials'?'This profile uses its configured credential provider.':'Enter a fresh MFA code when approving an AWS command.','database-meta'));
    $('mfa-session-list').append(card);
  }
}
$('sessions-nav').onclick=()=>showView('sessions');
$('remember-sessions').onchange=()=>act(()=>api('sessions/settings',{rememberAcrossRestarts:$('remember-sessions').checked}));
$('save-active-sessions').onclick=()=>act(()=>api('sessions/save',{}));
$('forget-all-sessions').onclick=()=>act(()=>api('sessions/clear',{}));
const modeHelp={manual:'Commands wait for approval unless an explicit Allow rule matches. Deny and Ask rules take precedence.',auto_reads:'Recognized reads run automatically. Unknown commands, changes, and sensitive reads wait for approval unless an explicit rule allows them.',read_only:'Recognized reads can run. Other AWS operations are blocked, even if an Allow rule matches. Sensitive recognized reads still need approval or an explicit rule.'};
function renderPolicySummary(){
  if(!policyState)return;
  if(previewRevision&&previewRevision!==policyState.revision)$('policy-preview-result').hidden=true;
  const label=policyState.paused?'Automation paused':policyState.mode==='auto_reads'?'Automatic reads':policyState.mode==='read_only'?'Read-only AWS':'Custom approval rules';
  $('policy-badge-label').textContent=label+' · '+(policyState.defaultDelivery==='direct'?'direct results':'review results');
  $('queue-description').textContent=policyState.paused?'Automatic approvals are paused. Review each allowed command manually.':modeHelp[policyState.mode];
  $('pause-automation').textContent=policyState.paused?'Resume automation':'Pause automation';
}
function markPolicyDirty(){policyDirty=true;$('policy-save-state').textContent='Unsaved changes — save policies to activate them.';document.querySelector('.policy-savebar').dataset.dirty='true';}
function settingsFromForm(){
  return {...policyDraft,mode:$('policy-mode').value,paused:$('policy-paused').checked,defaultDelivery:$('policy-delivery').value,protectedProfiles:[...$('protected-profiles').querySelectorAll('input:checked')].map(input=>input.value)};
}
function renderPolicyRules(){
  $('policy-rules').replaceChildren();
  if(!policyDraft.rules.length)$('policy-rules').append(el('p','No rules yet. Unmatched commands follow the selected approval mode.','rule-empty'));
  for(const rule of policyDraft.rules){
    const expired=rule.expiresAt!==null&&rule.expiresAt<=Date.now();
    const card=el('article',undefined,'rule-card'+(expired?' expired':'')); const header=el('header');
    header.append(el('strong',rule.name),el('span',rule.action==='allow'?'Allow automatically':rule.action==='ask'?'Always ask':'Block','pill '+rule.action));
    const enabled=el('label',undefined,'checkbox-label');const check=el('input');check.type='checkbox';check.checked=rule.enabled;check.setAttribute('aria-label','Enable rule '+rule.name);check.onchange=()=>{rule.enabled=check.checked;markPolicyDirty();};enabled.append(check,document.createTextNode('Enabled'));
    const remove=el('button','Remove');remove.type='button';remove.onclick=()=>{policyDraft.rules=policyDraft.rules.filter(r=>r.id!==rule.id);renderPolicyRules();markPolicyDirty();};header.append(enabled,remove);
    card.append(header,el('pre','aws '+rule.args.map(a=>/^[\w./:@=-]+$/.test(a)?a:JSON.stringify(a)).join(' ')+(rule.match==='operation'?' [any arguments]':'')),el('p',`${rule.profile==='*'?'All profiles':rule.profile} · ${rule.region||'Any region'} · ${rule.match==='exact'?'Exact arguments':'Operation-wide'} · ${expired?'Expired':rule.expiresAt?'Expires '+new Date(rule.expiresAt).toLocaleString():'No expiry'}`));
    $('policy-rules').append(card);
  }
}
function setPolicyBusy(busy){for(const id of ['policy-fields','rule-fields','preview-fields'])$(id).disabled=busy||!policyDraft;$('save-policies').disabled=busy||!policyDraft;$('pause-automation').disabled=busy;}
function renderPolicyForm(){
  policyDraft=structuredClone(policyState);delete policyDraft.catalog;delete policyDraft.sensitiveReads;policyDirty=false;
  $('policy-mode').value=policyDraft.mode;$('policy-paused').checked=policyDraft.paused;$('policy-delivery').value=policyDraft.defaultDelivery;
  $('policy-mode-help').textContent=modeHelp[policyDraft.mode];$('protected-profiles').replaceChildren();
  const names=[...new Set([...profiles.map(p=>p.name),...policyDraft.protectedProfiles])];
  for(const name of names){const label=el('label',undefined,'checkbox-label');const check=el('input');check.type='checkbox';check.value=name;check.checked=policyDraft.protectedProfiles.includes(name);check.onchange=markPolicyDirty;label.append(check,document.createTextNode(name));$('protected-profiles').append(label);}
  if(!names.length)$('protected-profiles').append(el('p','No AWS profiles are configured.'));
  $('policy-catalog').textContent='Automatically recognized reads\n'+policyState.catalog.join('\n')+'\n\nSensitive reads (manual unless explicitly allowed)\n'+policyState.sensitiveReads.join('\n');renderPolicyRules();
  $('policy-save-state').textContent='Saved policies loaded. Changes take effect only after saving.';document.querySelector('.policy-savebar').dataset.dirty='false';
  renderPolicySummary();updateRuleConfirmation();setPolicyBusy(false);
}
async function loadPolicies(force=false){if(policyDirty&&!force)return;setPolicyBusy(true);try{policyState=await api('policies');renderPolicyForm();}finally{setPolicyBusy(false);}}
function updateRuleConfirmation(){
  let args=[];try{args=splitCommand($('rule-command').value);}catch{}
  const needs=$('rule-action').value==='allow'&&args.length>=2&&!policyState?.catalog.includes(args.slice(0,2).join(' '));
  $('rule-confirm-label').hidden=!needs;$('rule-confirm').required=needs;$('rule-confirm').placeholder=args.slice(0,2).join(' ')||'ec2 start-instances';
}
$('policies-nav').onclick=()=>showView('policies');
$('policy-settings-form').oninput=markPolicyDirty;
$('policy-mode').onchange=()=>{$('policy-mode-help').textContent=modeHelp[$('policy-mode').value];markPolicyDirty();};
$('rule-command').oninput=updateRuleConfirmation;$('rule-action').onchange=updateRuleConfirmation;
$('policy-rule-form').onsubmit=e=>{e.preventDefault();try{
  error('');const args=splitCommand($('rule-command').value);if(args.length<2)throw new Error('Enter an AWS service and operation.');
  const duration=Number($('rule-expiry').value);
  policyDraft.rules.push({id:crypto.randomUUID(),name:$('rule-name').value.trim(),profile:$('rule-profile').value,region:$('rule-region').value.trim(),args:$('rule-match').value==='operation'?args.slice(0,2):args,match:$('rule-match').value,action:$('rule-action').value,enabled:true,expiresAt:duration?Date.now()+duration:null,confirmCommand:$('rule-confirm').value});
  renderPolicyRules();markPolicyDirty();$('policy-rule-form').reset();updateRuleConfirmation();$('rule-compose').open=false;
}catch(e){error(e.message);}};
$('policy-settings-form').onsubmit=e=>{e.preventDefault();act(async()=>{
  $('save-policies').disabled=true;
  try{policyState=await api('policies',settingsFromForm());renderPolicyForm();$('policy-save-state').textContent='Policies saved and active.';}finally{$('save-policies').disabled=false;}
});};
$('reload-policies').onclick=()=>act(()=>loadPolicies(true));
$('pause-automation').onclick=()=>act(async()=>{const current=await api('policies');policyState=await api('policies',{...current,paused:!current.paused});renderPolicyForm();$('policy-save-state').textContent=policyState.paused?'Automation paused. Blocking rules still apply.':'Automation resumed.';});
$('policy-preview-form').onsubmit=e=>{e.preventDefault();act(async()=>{const decision=await api('policies/preview',{profile:$('preview-profile').value,region:$('preview-region').value.trim(),args:splitCommand($('preview-command').value)});previewRevision=decision.revision;$('policy-preview-result').textContent=(decision.action==='allow'?'AUTO-ALLOW':decision.action==='deny'?'BLOCK':'ASK')+' · '+decision.reason;$('policy-preview-result').hidden=false;});};
(async () => { try { await loadProfiles(); await refresh(); } catch (e) { error(e.message); } setInterval(refresh, 1500); })();

function visiblePending(){return requests.filter(r=>r.status==='pending'&&(!profileFilter||r.profile===profileFilter));}
function updateQueueSelection(visible){
  const pending=visible.filter(r=>r.status==='pending');$('selection-count').textContent=selectedRequests.size+' selected';$('review-selected').disabled=!selectedRequests.size;$('approve-visible').disabled=!pending.length;
  $('select-pending').disabled=!pending.length;$('select-pending').checked=!!pending.length&&pending.every(r=>selectedRequests.has(r.id));$('select-pending').indeterminate=pending.some(r=>selectedRequests.has(r.id))&&!$('select-pending').checked;
}
$('select-pending').onchange=()=>{for(const r of visiblePending()){if($('select-pending').checked)selectedRequests.add(r.id);else selectedRequests.delete(r.id);}renderRequests();};
$('review-selected').onclick=()=>openBatch([...selectedRequests]);$('approve-visible').onclick=()=>openBatch(visiblePending().map(r=>r.id));
function openBatch(ids){
  if(batchRunning)return;$('approve-batch').disabled=false;$('batch-individual').disabled=false;$('batch-direct').disabled=false;
  batchSnapshot=[...requests].reverse().filter(r=>ids.includes(r.id)&&r.status==='pending').sort((a,b)=>a.createdAt-b.createdAt).map(r=>structuredClone(r));
  if(!batchSnapshot.length)return;
  batchStopRequested=false;$('stop-batch').hidden=true;$('batch-form').reset();$('batch-direct').checked=policyState?.defaultDelivery!=='review';$('batch-error').hidden=true;$('batch-progress').textContent='';$('batch-requests').replaceChildren();$('batch-auth').replaceChildren();
  $('batch-title').textContent='Review '+batchSnapshot.length+' pending request'+(batchSnapshot.length===1?'':'s');
  for(const r of batchSnapshot){const row=el('article',undefined,'batch-request');row.append(el('strong',r.profile+(r.connectionName?' / '+r.connectionName:'')),el('pre',displayCommand(r)),el('p',r.reason));
    if(r.risk==='destructive'){const label=el('label','Type '+(r.confirmationTarget||r.profile)+' to confirm this request'),input=el('input');input.dataset.confirmRequest=r.id;input.setAttribute('aria-label','Confirm request '+r.id);input.required=true;input.autocomplete='off';label.append(input);row.append(label);} $('batch-requests').append(row);}
  for(const name of new Set(batchSnapshot.filter(r=>r.kind!=='sql').map(r=>r.profile))){
    const p=profiles.find(p=>p.name===name),cached=mfaState.sessions.find(s=>s.profile===name&&s.status==='active');if(p?.sso)continue;
    const auth=el('fieldset');auth.dataset.authProfile=name;auth.append(el('legend',name+' authentication'));
    if(cached)auth.append(el('p','Reuse active MFA session until '+new Date(cached.expiresAt).toLocaleTimeString()+'.'));
    const serialLabel=el('label','MFA device ARN (optional)'),serial=el('input');serial.dataset.authField='serial';serial.value=p?.mfaSerial||'';serialLabel.append(serial);
    const codeLabel=el('label','MFA code for '+name),code=el('input');code.type='password';code.inputMode='numeric';code.autocomplete='one-time-code';code.pattern='[0-9]{6}';code.dataset.authField='code';code.required=!!p?.mfaSerial&&!cached;codeLabel.append(code);
    const rememberLabel=el('label',undefined,'checkbox-label'),remember=el('input');remember.type='checkbox';remember.dataset.authField='remember';remember.checked=mfaState.rememberAcrossRestarts&&mfaState.storage==='keychain';remember.disabled=mfaState.storage!=='keychain'||!mfaState.rememberAcrossRestarts;rememberLabel.append(remember,document.createTextNode('Remember MFA session in Keychain'));
    auth.append(serialLabel,codeLabel,rememberLabel);$('batch-auth').append(auth);
  }
  for(const input of $('batch-form').querySelectorAll('input'))input.disabled=false;
  for(const input of $('batch-auth').querySelectorAll('[data-auth-field="remember"]'))input.disabled=mfaState.storage!=='keychain'||!mfaState.rememberAcrossRestarts;
  $('batch-dialog').showModal();
}
function closeBatch(){if(batchRunning)return;$('batch-dialog').close();$('batch-form').reset();$('batch-auth').replaceChildren();batchSnapshot=[];}
$('close-batch').onclick=closeBatch;$('batch-dialog').addEventListener('cancel',e=>{e.preventDefault();closeBatch();});
$('batch-individual').onclick=()=>{individualQueue=batchSnapshot.map(r=>r.id);closeBatch();reviewNextIndividual();};
function batchError(message){$('batch-error').textContent=message;$('batch-error').hidden=!message;}
$('stop-batch').onclick=()=>{batchStopRequested=true;$('stop-batch').disabled=true;$('batch-progress').textContent='Stopping after the current request finishes. Remaining requests will stay pending.';};
$('batch-form').onsubmit=async e=>{
  e.preventDefault();if(batchRunning||!batchSnapshot.length)return;
  // Check every confirmation before approving the first request.
  for(const r of batchSnapshot){const input=$('batch-requests').querySelector('[data-confirm-request="'+r.id+'"]');if(input&&input.value!==(r.confirmationTarget||r.profile)){batchError('Confirm each destructive request before approving the batch.');input.focus();return;}}
  const jobs=[...batchSnapshot],usedProfiles=new Set();batchRunning=true;batchStopRequested=false;$('stop-batch').hidden=false;$('stop-batch').disabled=false;batchError('');for(const id of ['approve-batch','batch-individual','close-batch'])$(id).disabled=true;
  // Freeze inputs so the reviewed delivery and confirmation choices cannot change mid-batch.
  const delivery=$('batch-direct').checked?'direct':'review';$('batch-direct').disabled=true;
  for(const input of $('batch-form').querySelectorAll('input'))input.disabled=true;
  let approved=0;
  try{
    for(const r of jobs){
      if(batchStopRequested){$('batch-progress').textContent=`Stopped after ${approved} requests. Remaining requests are still pending.`;break;}
      $('batch-progress').textContent=`${approved+1} of ${jobs.length}: ${r.profile} · ${r.kind==='sql'?'SQL query':r.args.slice(0,2).join(' ')}`;
      const auth=[...$('batch-auth').children].find(n=>n.dataset.authProfile===r.profile),code=auth?.querySelector('[data-auth-field="code"]');
      const confirmation=$('batch-requests').querySelector('[data-confirm-request="'+r.id+'"]')?.value||'';
      const body={decision:'approve',confirmation,deliveryMode:delivery,mfaCode:usedProfiles.has(r.profile)?'':code?.value||'',mfaSerial:auth?.querySelector('[data-auth-field="serial"]')?.value||'',rememberMfa:auth?.querySelector('[data-auth-field="remember"]')?.checked||false};
      let result=await api(`requests/${r.id}/decision`,body);selectedRequests.delete(r.id);approved++;
      // Wait for authentication/execution so the next request can reuse this profile's new session.
      while(['authorizing','running'].includes(result.status)){await new Promise(resolve=>setTimeout(resolve,400));result=await api('requests/'+r.id);}
      if(code)code.value='';if(r.kind!=='sql')usedProfiles.add(r.profile);
      if(!['completed','awaiting_review'].includes(result.status))throw new Error(`Stopped at ${r.id}: ${result.status}. Inspect this request before retrying. Remaining requests were not approved.`);
    }
    if(!batchStopRequested)$('batch-progress').textContent=`Finished ${approved} request${approved===1?'':'s'}. Held results still need individual review.`;else $('batch-progress').textContent=`Stopped after ${approved} requests. Remaining requests are still pending.`;batchSnapshot=[];
  }catch(e){batchError(e.message+' No failed or uncertain request was retried. Close and review the remaining pending requests.');batchSnapshot=[];}
  finally{batchRunning=false;$('stop-batch').hidden=true;for(const id of ['batch-individual','close-batch'])$(id).disabled=false;$('approve-batch').disabled=true;$('batch-individual').disabled=true;$('batch-auth').replaceChildren();await refresh();}
};
$('use-built-command').onclick=()=>{
  try{const service=$('build-service').value.trim(),operation=$('build-operation').value.trim(),args=JSON.parse($('build-arguments').value||'[]');
    if(!/^[a-z][a-z0-9-]*$/.test(service)||!/^[a-z][a-z0-9-]*$/.test(operation))throw new Error('Enter an AWS service and operation.');
    if(!Array.isArray(args)||args.some(a=>typeof a!=='string'))throw new Error('Arguments must be a JSON array of strings.');
    $('command').value=JSON.stringify([service,operation,...args]);$('builder-error').hidden=true;$('command').focus();
  }catch(e){$('builder-error').textContent=e.message;$('builder-error').hidden=false;}
};
function renderCommandDrafts(){
  $('draft-batch').hidden=!commandDrafts.length;$('command-drafts').replaceChildren();
  for(const [index,draft] of commandDrafts.entries()){const row=el('article',undefined,'command-draft');row.append(el('strong',draft.profile),el('pre',displayCommand(draft)),el('p',draft.reason));const remove=el('button','Remove');remove.type='button';remove.setAttribute('aria-label','Remove draft '+(index+1));remove.onclick=()=>{if($('submit-command-batch').disabled)return;commandDrafts.splice(index,1);renderCommandDrafts();};row.append(remove);$('command-drafts').append(row);}
}
$('add-command-draft').onclick=()=>{
  if(!$('command-form').reportValidity())return;
  try{if(commandDrafts.length>=20)throw new Error('A batch can contain up to 20 commands.');const request=composerRequest();if(routeForwardingCommand(request))return;if(request.args.length<2)throw new Error('Enter a service and operation.');commandDrafts.push({kind:'aws',...request});$('draft-message').textContent='';renderCommandDrafts();}catch(e){error(e.message);}
};
$('submit-command-batch').onclick=async()=>{
  if(!commandDrafts.length)return;$('submit-command-batch').disabled=true;$('add-command-draft').disabled=true;let submitted=0;for(const button of $('command-drafts').querySelectorAll('button'))button.disabled=true;
  try{while(commandDrafts.length){const draft=commandDrafts[0];await api('requests',draft);commandDrafts.shift();submitted++;}profileFilter='';renderProfiles();setActivityFilter('pending');}
  catch(e){$('draft-message').textContent=`${submitted} submitted. Stopped: ${e.message} Remaining drafts were kept. Check the queue before resubmitting after a connection error.`;}
  finally{renderCommandDrafts();$('submit-command-batch').disabled=false;$('add-command-draft').disabled=false;await refresh();}
};

function updateSessionPreview(){
  const port=$('db-local-port').value||'auto';
  $('db-session-preview').textContent=displayCommand({kind:'tunnel',profile:$('db-profile').value,region:$('db-region').value,target:{instanceId:$('db-instance').value||'i-example',host:$('db-host').value||'your-db.rds.amazonaws.com',port:$('db-port').value||5432,localPort:port}});
}
$('database-form').addEventListener('input',updateSessionPreview);$('database-form').addEventListener('change',updateSessionPreview);
$('import-session-command').onclick=()=>{
  try{const fields=parseSessionCommand($('ssm-command').value);
    if(!profiles.some(p=>p.name===fields.profile))throw new Error('Profile '+fields.profile+' is not configured locally. Configure it with AWS CLI, then refresh profiles.');
    for(const [field,key] of Object.entries({profile:'profile',region:'region',instance:'instanceId',host:'host',port:'port','local-port':'localPort'}))$('db-'+field).value=fields[key]||'';
    if(fields.port===5432)$('db-engine').value='postgres';else if(fields.port===3306)$('db-engine').value='mysql';
    updateSessionPreview();$('ssm-import-message').textContent='Imported forwarding settings. Enter the database name and credentials, save, then request tunnel approval. Nothing has executed.';
  }catch(e){$('ssm-import-message').textContent=e.message;}
};

function composerRequest(){
 const value=parseAwsCommand($('command').value,{profile:$('profile').value,region:$('region').value.trim()});
 if(!profiles.some(p=>p.name===value.profile))throw new Error('Choose a configured AWS profile.');
 $('profile').value=value.profile;$('region').value=value.region;
 return {...value,reason:$('reason').value};
}
function routeForwardingCommand(request){
 if(request.args[0]!=='ssm'||request.args[1]!=='start-session'||!request.args.some(arg=>arg==='AWS-StartPortForwardingSessionToRemoteHost'||arg==='--document-name=AWS-StartPortForwardingSessionToRemoteHost'))return false;
 showView('databases');$('add-database').click();$('ssm-command').closest('details').open=true;
 $('ssm-command').value=JSON.stringify([...request.args,'--profile',request.profile,'--region',request.region||profiles.find(p=>p.name===request.profile)?.region||'']);
 $('import-session-command').click();return true;
}

function resetSessionImport(){ $('ssm-command').value='';$('ssm-import-message').textContent='';$('ssm-command').closest('details').open=false; }
