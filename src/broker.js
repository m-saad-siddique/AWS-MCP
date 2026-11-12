import http from 'node:http';
import { randomBytes, randomUUID, timingSafeEqual, createHash } from 'node:crypto';
import { readFile, appendFile, mkdir, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import { HistoryStore, historyFinalStates } from './history.js';
import { PolicyService, classifyCommand } from './policy.js';
import { DatabaseService } from './database.js';
import { connectionSetup } from './setup.js';
import { AwsRunner, readProfiles, validateCommand, commandRisk, redact } from './aws.js';

const publicDir = fileURLToPath(new URL('../public/', import.meta.url));
const terminal = historyFinalStates;
export const isTerminal = status => terminal.has(status);
const equal = (a, b) => typeof a === 'string' && a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b));
export class Broker {
  constructor({ runner = new AwsRunner(), profiles = readProfiles, approvalMs = 300000, auditFile, databases, policies, history, notify = () => {}, now = Date.now } = {}) {
    Object.assign(this, { runner, profiles, approvalMs, auditFile, notify, now });
    this.databases = databases || new DatabaseService({ aws: runner, profiles });
    this.policies = policies || new PolicyService({ now });
    this.history=history||new HistoryStore({now});
    this.requests = new Map(); this.heldResults = new Map(); this.auditQueue = Promise.resolve();
    this.agentToken = randomBytes(32).toString('hex'); this.approvalToken = randomBytes(32).toString('hex');
    this.timer = setInterval(() => this.expire(), 1000); this.timer.unref();
  }
  async audit(r, event, {recordHistory=true}={}) {
    if(recordHistory)this.history.record(r,event);
    if (!this.auditFile) return;
    const row = { time: new Date(this.now()).toISOString(), id: r.id, event, kind: r.kind || 'aws', connectionId: r.connectionId, profile: r.profile, service: r.args[0], operation: r.args[1], commandHash: createHash('sha256').update(JSON.stringify({ profile: r.profile, region: r.region, args: r.args, kind: r.kind, sql: r.sql, params: r.params, target: r.target })).digest('hex'), policy: r.policy, autoApproved: r.autoApproved, policySummary: r.policySummary, deliveryMode: r.deliveryMode, exitCode: r.result?.exitCode ?? this.heldResults.get(r.id)?.result.exitCode };
    // No arguments, output, MFA codes, or credentials in persistent audit records.
    this.auditQueue = this.auditQueue.catch(() => {}).then(() => appendFile(this.auditFile, JSON.stringify(row) + '\n', { mode: 0o600 }));
    await this.auditQueue;
  }
  public(r, { operator = false } = {}) {
    const { controller, ...view } = r;
    // Unreleased output lives outside request objects. Agent serialization never includes it.
    if (operator && this.heldResults.has(r.id)) view.heldResult = this.heldResults.get(r.id).result;
    return view;
  }
  finish(r, result) {
    if (this.closing||['canceled','interrupted','outcome_unknown','result_unavailable'].includes(r.status)) return;
    const clean = { exitCode: result.exitCode, stdout: redact(result.stdout || ''), stderr: redact(result.stderr || '') };
    const status = clean.exitCode === 0 ? 'completed' : 'failed';
    r.finishedAt=this.now();r.executionExitCode=clean.exitCode;
    if (r.deliveryMode === 'review') {
      this.heldResults.set(r.id, { result: clean, status });
      r.status = 'awaiting_review';
      if (r.autoApproved) this.notify();
    } else { r.result = clean; r.status = status; }
    try{this.history.record(r,r.status);}catch{r.historyError='Execution finished, but its history could not be saved. Do not repeat the operation just to recreate history.';}
  }
  async release(id, body) {
    const r = this.requests.get(id), held = this.heldResults.get(id);
    if (!r || r.status !== 'awaiting_review' || !held) throw new Error('This result is no longer awaiting review.');
    if (!['send', 'withhold'].includes(body.decision)) throw new Error('Choose send or withhold.');
    let result;
    if (body.decision === 'send') {
      if (typeof body.stdout !== 'string' || typeof body.stderr !== 'string' || Buffer.byteLength(body.stdout) + Buffer.byteLength(body.stderr) > 2 * 1024 * 1024) throw new Error('Reviewed stdout and stderr must be text, at most 2 MiB combined.');
      result = { exitCode: held.result.exitCode, stdout: redact(body.stdout), stderr: redact(body.stderr) };
    }
    r.status = 'releasing'; // Reserve before the audit write to prevent duplicate releases.
    try { await this.audit(r, body.decision === 'send' ? 'result_released' : 'result_withheld'); }
    catch (e) { if (r.status === 'releasing') r.status = 'awaiting_review'; throw new Error('Audit write failed. No result was sent.'); }
    if (r.status !== 'releasing'||this.closing) return this.public(r);
    const next={...r,reviewedAt:this.now(),status:body.decision==='send'?held.status:'withheld'};
    if(body.decision==='send'){next.result=result;next.outputReviewed=true;}
    try{this.history.record(next,body.decision==='send'?'result_sent':'result_discarded');}
    catch{r.status='awaiting_review';throw new Error('History write failed. No result was sent.');}
    this.heldResults.delete(id);Object.assign(r,next);
    return this.public(r);
  }
  expire() {
    if(this.runner.pruneSessions&&!this.pruning&&this.now()-(this.lastPrune||0)>30000){this.lastPrune=this.now();this.pruning=this.runner.pruneSessions().catch(()=>{}).finally(()=>{this.pruning=null;});}
    for (const r of this.requests.values()) if (r.status === 'pending' && r.expiresAt <= this.now()) { r.status = 'expired'; this.audit(r, 'expired').catch(() => {}); }
  }
  async submit(input, {source='agent'}={}) {
    if(this.closing)throw new Error('Broker is stopping. No new request was accepted.');
    this.expire();
    const kind = input?.kind || 'aws';
    if (!['aws', 'tunnel', 'sql'].includes(kind)) throw new Error('Invalid request type.');
    const profiles = kind === 'aws' ? await this.profiles() : [];
    const command = kind === 'aws' ? { ...validateCommand(input, profiles), kind, risk: commandRisk(input.args) } : this.databases.prepare(input, kind);
    if ([...this.requests.values()].filter(r => !isTerminal(r.status)).length >= 20) throw new Error('Queue is full. Resolve existing requests first.');
    while (this.requests.size >= 100) {
      const old = [...this.requests.values()].find(r => isTerminal(r.status));
      if (!old) break; this.requests.delete(old.id);
    }
    const r = { ...command, source, clientName:source==='agent'&&typeof input.clientName==='string'?input.clientName.slice(0,100):'', id: randomUUID(), status: 'pending', risk: command.risk, createdAt: this.now(), expiresAt: this.now() + this.approvalMs };
    r.policy = this.policyFor(r, profiles.find(p => p.name === r.profile));
    if (r.policy.action === 'deny') r.status = 'blocked';
    await this.audit(r, 'submitted');
    if (r.status === 'blocked') await this.audit(r, 'policy_blocked');
    this.requests.set(r.id, r);
    if (r.policy.action === 'allow') await this.decide(r.id, { decision:'approve' }, { automatic:true });
    else if (r.status === 'pending') this.notify();
    return this.public(r);
  }
  policyFor(r, profile = {}) {
    const decision = this.policies.evaluate(r, profile);
    if (decision.action === 'allow' && profile.mfaSerial && !this.runner.hasSession?.(r.profile,profile)) return { ...decision, action:'ask', reason:'MFA is required. Enter its code in the approval dialog before execution.' };
    return decision;
  }
  async decide(id, body, { automatic = false } = {}) {
    this.expire();
    const r = this.requests.get(id);
    if (!r || r.status !== 'pending') throw new Error('Request is no longer pending.');
    if (body.decision === 'deny') { r.status = 'denied'; await this.audit(r, 'denied'); return this.public(r); }
    if (body.decision !== 'approve') throw new Error('Invalid decision.');
    const profile = r.kind === 'aws' ? (await this.profiles()).find(p => p.name === r.profile) : undefined;
    if (r.status !== 'pending') throw new Error('Request is no longer pending.');
    r.policy = this.policyFor(r, profile);
    if (r.policy.action === 'deny') { r.status = 'blocked'; await this.audit(r, 'policy_blocked'); return this.public(r); }
    if (automatic && r.policy.action !== 'allow') { this.notify(); return this.public(r); }
    if (!automatic && r.risk === 'destructive' && body.confirmation !== (r.confirmationTarget || r.profile)) throw new Error('Type the profile name or database connection name to confirm this destructive command.');
    if(body.rememberMfa!==undefined&&typeof body.rememberMfa!=='boolean')throw new Error('Invalid MFA session storage preference.');
    for (const key of ['mfaCode', 'mfaSerial']) if (body[key] !== undefined && typeof body[key] !== 'string') throw new Error('Invalid MFA input.');
    if (body.deliveryMode !== undefined && !['direct', 'review'].includes(body.deliveryMode)) throw new Error('Invalid result delivery mode.');
    r.deliveryMode = r.kind === 'aws' ? (body.deliveryMode || this.policies.current.defaultDelivery) : 'direct';
    r.autoApproved = automatic;r.mfaUsed=r.kind!=='sql'&&!!body.mfaCode;r.rememberMfa=body.rememberMfa!==false;r.mfaSessionReused=r.kind!=='sql'&&!body.mfaCode&&!!this.runner.hasSession?.(r.profile,profile);
    r.status = 'authorizing'; // Reserve synchronously: concurrent approval cannot execute twice.
    const approvedRevision = r.policy.revision;
    try { await this.audit(r, automatic ? 'auto_approved' : 'approved'); } catch (e) { r.status = 'failed'; r.result = { exitCode: 1, stdout: '', stderr: 'Audit write failed; command was not started.' }; throw e; }
    // The agent may cancel while the approval audit is being written.
    if (r.status !== 'authorizing'||this.closing) return this.public(r);
    if (this.policies.current.revision !== approvedRevision) {
      r.policy = this.policyFor(r, profile);
      if (r.policy.action === 'deny') { r.status = 'blocked'; await this.audit(r, 'policy_blocked'); return this.public(r); }
      if (automatic) { r.status = 'pending'; r.autoApproved = false; r.policy = { ...r.policy, action:'ask', reason:'Policies changed before execution. Review this request manually.' }; this.notify(); return this.public(r); }
    }
    r.status = 'running'; r.startedAt=this.now();r.controller = new AbortController();
    try{this.history.record(r,'execution_started');}catch{r.status='failed';r.result={exitCode:1,stdout:'',stderr:'History could not be saved; the command was not started.'};throw new Error(r.result.stderr);}
    const executor = r.kind === 'sql' || r.kind === 'tunnel' ? this.databases : this.runner;
    executor.execute(r, { mfaCode: body.mfaCode || '', mfaSerial: body.mfaSerial || '', rememberMfa:body.rememberMfa!==false, signal: r.controller.signal })
      .then(result => this.finish(r, result))
      .catch(e => this.finish(r, { exitCode: 1, stdout: '', stderr: e.message }))
      .finally(async () => { r.finishedAt ||= this.now(); delete r.controller; try { await this.audit(r, r.status,{recordHistory:false}); } catch { r.auditError = 'Failed to persist completion audit.'; } });
    return this.public(r);
  }
  async cancel(id) {
    const r = this.requests.get(id);
    if (!r) {const historical=this.history.request(id);if(historical&&isTerminal(historical.status))return this.public({...historical,fromHistory:true});throw new Error('Request not found.');}
    if (!isTerminal(r.status)) { r.status = 'canceled'; this.heldResults.delete(id); r.controller?.abort(); await this.audit(r, 'canceled'); }
    return this.public(r);
  }
  async listen({ port = 0, stateDir } = {}) {
    this.stateDir = stateDir;
    if (stateDir) { await mkdir(stateDir, { recursive: true, mode: 0o700 }); this.auditFile ||= join(stateDir, 'audit.jsonl'); }
    await this.databases.init(stateDir);
    await this.policies.init(stateDir);
    await this.runner.initSessions?.(stateDir);
    this.server = http.createServer((req, res) => this.handle(req, res).catch(e => {
      if (!res.headersSent) this.json(res, 400, { error: e.message }); else res.end();
    }));
    this.server.requestTimeout = 15000; this.server.headersTimeout = 10000;
    try{await new Promise((resolve, reject) => { this.server.once('error', reject); this.server.listen(port, '127.0.0.1', resolve); });}
    catch(e){clearInterval(this.timer);if(this.runner.close)await this.runner.close();this.databases.close();throw e;}
    this.origin = `http://127.0.0.1:${this.server.address().port}`;
    try{await this.history.init(stateDir);}catch(e){clearInterval(this.timer);await new Promise(resolve=>this.server.close(resolve));throw e;}
    return this;
  }
  json(res, code, value) { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(value)); }
  async body(req, maxBytes = 131072) {
    if (!req.headers['content-type']?.startsWith('application/json')) throw new Error('Expected application/json.');
    const chunks = []; let size = 0;
    for await (const part of req) { size += part.length; if (size > maxBytes) throw new Error('Request body too large.'); chunks.push(part); }
    return JSON.parse(Buffer.concat(chunks, size).toString('utf8') || '{}');
  }
  async handle(req, res) {
    res.setHeader('Cache-Control', 'no-store'); res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer'); res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'");
    if (req.headers.host !== new URL(this.origin).host) return this.json(res, 403, { error: 'Invalid host.' });
    if (req.headers.origin && req.headers.origin !== this.origin) return this.json(res, 403, { error: 'Cross-origin requests are blocked.' });
    const path = new URL(req.url, this.origin).pathname;
    if (req.method === 'GET' && ['/', '/app.js', '/style.css'].includes(path)) {
      const file = path === '/' ? 'index.html' : path.slice(1);
      res.setHeader('Content-Type', file.endsWith('.js') ? 'text/javascript' : file.endsWith('.css') ? 'text/css' : 'text/html');
      return res.end(await readFile(join(publicDir, file)));
    }
    const token = req.headers.authorization?.replace(/^Bearer /, '');
    const operator = equal(token, this.approvalToken), agent = equal(token, this.agentToken);
    if (!operator && !agent) return this.json(res, 401, { error: 'Open the dashboard using npm start to authenticate.' });
    if (req.method === 'GET' && path === '/api/health') return this.json(res, 200, { ok: true, version: '1.0.0' });
    if (req.method === 'GET' && path === '/api/setup' && operator) return this.json(res, 200, connectionSetup({ stateDir: this.stateDir }));
    if (path === '/api/policies' && operator) {
      if (req.method === 'GET') return this.json(res, 200, this.policies.view());
      if (req.method === 'POST') return this.json(res, 200, await this.policies.save(await this.body(req), { audit: async config => {
        await this.audit({ id:randomUUID(), kind:'policy', profile:'local', args:['policy','update'], target:config, policySummary:{revision:config.revision,mode:config.mode,paused:config.paused,ruleCount:config.rules.length} }, 'policy_changed');
      } }));
    }
    if (req.method === 'POST' && path === '/api/policies/preview' && operator) {
      const input = await this.body(req), profiles = await this.profiles();
      const command = { ...validateCommand(input, profiles), kind:'aws' };
      return this.json(res, 200, { ...this.policyFor(command, profiles.find(p => p.name === command.profile)), classification:classifyCommand(command.args) });
    }
    if(req.method==='GET'&&operator&&path==='/api/history')return this.json(res,200,{...this.history.list(Object.fromEntries(new URL(req.url,this.origin).searchParams)),summary:this.history.summary()});
    if(req.method==='GET'&&operator&&path==='/api/history/events')return this.json(res,200,this.history.activity(Object.fromEntries(new URL(req.url,this.origin).searchParams)));
    const historyMatch=path.match(/^\/api\/history\/([a-f0-9-]{36})$/);
    if(req.method==='GET'&&operator&&historyMatch){const record=this.history.detail(historyMatch[1]);return this.json(res,record?200:404,record||{error:'History record not found.'});}
    if (req.method === 'GET' && path === '/api/profiles') return this.json(res, 200, (await this.profiles()).map(({_authFingerprint,...profile})=>profile));
    if (req.method === 'GET' && path === '/api/databases') return this.json(res, 200, this.databases.list());
    if (req.method === 'POST' && path === '/api/databases' && operator) {const connection=await this.databases.save(await this.body(req));this.logSystem('database_connection_saved',{id:connection.id,name:connection.name,profile:connection.profile,engine:connection.engine,host:connection.host,database:connection.database,readOnly:connection.readOnly});return this.json(res,200,connection);}
    const databaseRoute = path.match(/^\/api\/databases\/([a-f0-9-]{36})\/(close|delete)$/);
    if (req.method === 'POST' && databaseRoute && operator) {
      const [, id, action] = databaseRoute;
      for (const r of this.requests.values()) if (r.connectionId === id && !isTerminal(r.status)) await this.cancel(r.id);
      if (action === 'delete') await this.databases.remove(id); else this.databases.tunnels.close(id);
      this.logSystem(action==='delete'?'database_connection_deleted':'database_tunnel_closed',{connectionId:id});
      return this.json(res, 200, { ok: true });
    }
    if (req.method === 'POST' && path === '/api/requests') return this.json(res, 201, await this.submit(await this.body(req),{source:operator?'dashboard':'agent'}));
    if (req.method === 'GET' && path === '/api/requests' && operator) { this.expire(); return this.json(res, 200, [...this.requests.values()].map(r => this.public(r, { operator: true })).reverse()); }
    const match = path.match(/^\/api\/requests\/([a-f0-9-]{36})(?:\/(decision|cancel|release))?$/);
    if (match) {
      const [, id, action] = match;
      if (req.method === 'POST' && action === 'decision') {
        if (!operator) return this.json(res, 403, { error: 'Only the approval UI can approve a request.' });
        return this.json(res, 200, await this.decide(id, await this.body(req)));
      }
      if (req.method === 'POST' && action === 'release') {
        if (!operator) return this.json(res, 403, { error: 'Only the operator can review and release a result.' });
        return this.json(res, 200, await this.release(id, await this.body(req, 4 * 1024 * 1024)));
      }
      if (req.method === 'POST' && action === 'cancel') return this.json(res, 200, await this.cancel(id));
      if (req.method === 'GET' && !action) {
        this.expire(); const live=this.requests.get(id),stored=live?undefined:this.history.request(id);const r=live||(stored?{...stored,fromHistory:true}:undefined); return this.json(res, r ? 200 : 404, r ? this.public(r, { operator }) : { error: 'Request not found.' });
      }
    }
    if(req.method==='GET'&&path==='/api/sessions'&&operator)return this.json(res,200,this.runner.sessionStatus?await this.runner.sessionStatus():{rememberAcrossRestarts:false,storage:'memory',warning:'',sessions:[]});
    if(req.method==='POST'&&path==='/api/sessions/settings'&&operator){const body=await this.body(req);if(!this.runner.sessionCache)throw new Error('MFA storage is unavailable.');await this.runner.pruneSessions?.();await this.runner.sessionCache.setRemember(body.rememberAcrossRestarts);this.logSystem('mfa_remember_setting_changed',{enabled:body.rememberAcrossRestarts});return this.json(res,200,await this.runner.sessionStatus());}
    if(req.method==='POST'&&path==='/api/sessions/save'&&operator){if(!this.runner.sessionCache)throw new Error('MFA storage is unavailable.');await this.runner.pruneSessions?.();await this.runner.sessionCache.saveActive();this.logSystem('mfa_active_sessions_saved',{});return this.json(res,200,await this.runner.sessionStatus());}
    if (req.method === 'POST' && path === '/api/sessions/clear' && operator) { const body=await this.body(req);if(body.profile!==undefined&&(typeof body.profile!=='string'||!(await this.profiles()).some(p=>p.name===body.profile)))throw new Error('Select an existing AWS profile.');await this.runner.clearSessions(body.profile);this.logSystem('mfa_sessions_forgotten',{profile:body.profile||'all'}); return this.json(res, 200, { ok: true }); }
    return this.json(res, 404, { error: 'Not found.' });
  }
  logSystem(event,details){try{this.history.system(event,details);}catch{this.history.warning='A configuration change completed but its history could not be saved.';}}
  async close() {
    this.closing=true;clearInterval(this.timer);
    for (const r of this.requests.values()) {
      if(!isTerminal(r.status)){
        r.controller?.abort();const previousStatus=r.status;
        r.status=previousStatus==='running'?'outcome_unknown':['awaiting_review','releasing'].includes(previousStatus)?'result_unavailable':'interrupted';r.finishedAt ||= this.now();
        r.recoveryNote=r.status==='outcome_unknown'?'Broker stopped during execution. Remote changes may already have completed. Check the remote state before retrying.':r.status==='result_unavailable'?'Broker stopped while output was held or pending release. Unreleased output was discarded; the operation was not replayed.':'Broker stopped before execution began. This request was not replayed.';
        try{this.history.record(r,'broker_stopped_request',{previousStatus});}catch{}
      }
    }
    this.heldResults.clear();
    if(this.runner.close)await this.runner.close();else await this.runner.clearSessions();
    this.databases.close();
    if (this.server) await new Promise(resolve => {
      // A browser may still have an unfinished request when restart begins.
      const drainTimer=setTimeout(()=>this.server.closeAllConnections(),1000);
      this.server.close(()=>{clearTimeout(drainTimer);resolve();});
      this.server.closeIdleConnections();
    });
    await this.auditQueue.catch(() => {});
    this.history.close();
  }
}
