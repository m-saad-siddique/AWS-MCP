#!/usr/bin/env node
import { spawn } from 'node:child_process';
import { mkdir, readFile, writeFile, rm, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { Broker, isTerminal } from './broker.js';

const self = fileURLToPath(import.meta.url);
const stateDir = process.env.AWS_MCP_STATE_DIR || fileURLToPath(new URL('../.runtime/', import.meta.url));
const stateFile = join(stateDir, 'broker.json');
function openBrowser(url) {
  if (process.env.AWS_MCP_NO_OPEN === '1') return;
  const [program, args] = process.platform === 'darwin' ? ['open', [url]] : process.platform === 'win32' ? ['rundll32', ['url.dll,FileProtocolHandler', url]] : ['xdg-open', [url]];
  const p = spawn(program, args, { stdio: 'ignore', detached: true }); p.on('error', () => {}); p.unref();
}
export async function api(state, path, { method = 'GET', body, operator = false } = {}) {
  if (!/^http:\/\/127\.0\.0\.1:\d+$/.test(state.origin)) throw new Error('Invalid local broker address.');
  const response = await fetch(state.origin + path, { method, headers: { Authorization: `Bearer ${operator ? state.approvalToken : state.agentToken}`, ...(body ? { 'Content-Type': 'application/json' } : {}) }, body: body ? JSON.stringify(body) : undefined, signal: AbortSignal.timeout(5000), redirect: 'error' });
  const value = await response.json(); if (!response.ok) throw new Error(value.error || 'Broker error.'); return value;
}
async function existing() {
  try { const state = JSON.parse(await readFile(stateFile, 'utf8')); await api(state, '/api/health'); return state; } catch { return null; }
}
async function ensureBroker() {
  await mkdir(stateDir, { recursive: true, mode: 0o700 });
  const lock = join(stateDir, 'startup.lock');
  for (let attempt = 0; attempt < 100; attempt++) {
    const state = await existing(); if (state) return state;
    let acquired = false;
    try { await mkdir(lock); acquired = true; } catch (e) {
      if (e.code !== 'EEXIST') throw e;
      if (Date.now() - (await stat(lock).catch(() => ({ mtimeMs: Date.now() }))).mtimeMs > 30000) await rm(lock, { recursive: true, force: true });
    }
    if (acquired) {
      try {
        const state = await existing(); if (state) return state;
        const child = spawn(process.execPath, [self, 'daemon'], { detached: true, stdio: 'ignore', env: process.env });
        let spawnError; child.on('error', e => { spawnError = e; }); child.unref();
        for (let i = 0; i < 50; i++) { if (spawnError) throw spawnError; await delay(100); const ready = await existing(); if (ready) return ready; }
        throw new Error('Could not start broker. Run node src/cli.js daemon to see the error.');
      } finally { await rm(lock, { recursive: true, force: true }); }
    }
    await delay(100);
  }
  throw new Error('Broker startup timed out.');
}
async function daemon() {
  let lastOpen = 0;
  // Port: AWS_MCP_PORT if set, else the port used last time, else a random free port.
  const portFile = join(stateDir, 'port');
  const savedPort = Number(await readFile(portFile, 'utf8').catch(() => '')) || 0;
  const wantedPort = Number(process.env.AWS_MCP_PORT) || savedPort;
  const makeBroker = () => new Broker({ notify: () => {
    if (Date.now() - lastOpen > 15000) { lastOpen = Date.now(); openBrowser(`${broker.origin}/#${broker.approvalToken}`); }
  } });
  let broker;
  try { broker = await makeBroker().listen({ port: wantedPort, stateDir }); } catch (e) {
    if (e.code !== 'EADDRINUSE' || process.env.AWS_MCP_PORT) throw e;
    broker = await makeBroker().listen({ port: 0, stateDir });
  }
  await writeFile(portFile, String(new URL(broker.origin).port), { mode: 0o600 });
  await writeFile(stateFile, JSON.stringify({ origin: broker.origin, agentToken: broker.agentToken, approvalToken: broker.approvalToken, pid: process.pid }), { mode: 0o600 });
  process.stderr.write(`AWS approval dashboard: ${broker.origin}\n`);
  let closing = false;
  const shutdown = async () => { if (closing) return; closing = true; await broker.close(); await rm(stateFile, { force: true }); process.exit(0); };
  process.on('SIGTERM', shutdown); process.on('SIGINT', shutdown);
}
async function mcp() {
  const [{ McpServer }, { StdioServerTransport }, { z }] = await Promise.all([
    import('@modelcontextprotocol/sdk/server/mcp.js'), import('@modelcontextprotocol/sdk/server/stdio.js'), import('zod'),
  ]);
  let state = await ensureBroker();
  // Re-resolve the broker on every call so a restarted broker (new tokens) keeps working.
  const fresh = async () => (state = await ensureBroker());
  const server = new McpServer({ name: 'aws-approval', version: '1.0.0' }, { instructions: 'AWS commands follow operator-configured approval policies: requests may run automatically, wait for approval, or be blocked. Database tunnels and SQL queries require manual approval. Agents cannot modify approval policies. Never ask for MFA codes in chat. Use execute_aws for AWS operations. An approval does not authorize any other command. Request status and released results are retained across restarts. outcome_unknown means execution was interrupted and the remote outcome must be checked before retrying; interrupted and result_unavailable are never automatically replayed. AWS output may be held for operator review; awaiting_review means the command ran but its output is not released. Poll the same request ID and never rerun it just to obtain output.' });
  const result = value => ({ content: [{ type: 'text', text: JSON.stringify(value, null, 2) }] });
  const guarded = fn => async (...args) => { try { return await fn(...args); } catch (e) { return { ...result({ error: e.message }), isError: true }; } };
  server.registerTool('list_aws_profiles', { description: 'List configured AWS profile names and authentication metadata. Does not return credentials or contact AWS.', inputSchema: {}, annotations: { readOnlyHint: true } }, guarded(async () => result(await api(await fresh(), '/api/profiles'))));
  const submitRequest=async input=>api(await fresh(),'/api/requests',{method:'POST',body:{...input,clientName:server.server.getClientVersion()?.name||'MCP client'}});
  const commandSchema = { profile: z.string(), args: z.array(z.string()).min(2).max(256), region: z.string().optional(), reason: z.string().min(1).max(2000) };
  server.registerTool('request_aws', { description: 'Queue one AWS CLI command under the operator’s approval policy and return its request ID immediately. Use this instead of execute_aws when the host has short tool timeouts. Poll get_aws_request for the result; never resubmit merely because approval is still pending.', inputSchema: commandSchema, annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true } }, guarded(async input => result(await submitRequest(input))));
  server.registerTool('execute_aws', {
    description: 'Submit one AWS CLI command under the operator’s approval policy, wait, and return its result. Use an argument array without the aws prefix. The operator’s policy decides whether a command is auto-approved, blocked, or queued for manual approval. Never supply MFA codes or credentials. For SSO use args ["sso","login"]. If output is held, returns awaiting_review without output; poll get_aws_request until the operator releases or withholds it. If the host times out, inspect the returned request using get_aws_request rather than resubmitting.',
    inputSchema: commandSchema,
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
  }, guarded(async (input, extra) => {
    const request = await submitRequest(input);
    let progress = 0;
    try {
      for (;;) {
        if (extra.signal.aborted) throw new Error('MCP request canceled.');
        const current = await api(await fresh(), `/api/requests/${request.id}`);
        if (current.status === 'awaiting_review' || current.status === 'releasing') return result(current);
        if (isTerminal(current.status)) return { ...result(current), isError: current.status !== 'completed' };
        const token = extra._meta?.progressToken;
        if (token !== undefined) await extra.sendNotification({ method: 'notifications/progress', params: { progressToken: token, progress: progress++, message: `AWS request ${request.id}: ${current.status}. Approve in the local dashboard.` } });
        await delay(1000, undefined, { signal: extra.signal });
      }
    } catch (e) { await api(await fresh(), `/api/requests/${request.id}/cancel`, { method: 'POST' }).catch(() => {}); throw e; }
  }));
  server.registerTool('get_aws_request', { description: 'Get the status/output of an existing request by ID. Never re-executes it.', inputSchema: { requestId: z.string().uuid() }, annotations: { readOnlyHint: true } }, guarded(async ({ requestId }) => result(await api(await fresh(), `/api/requests/${requestId}`))));
  server.registerTool('cancel_aws_request', { description: 'Cancel a pending or running command. Remote changes may already have completed.', inputSchema: { requestId: z.string().uuid() } }, guarded(async ({ requestId }) => result(await api(await fresh(), `/api/requests/${requestId}/cancel`, { method: 'POST' }))));
  server.registerTool('list_database_connections', { description: 'List operator-configured RDS connections and tunnel status. Does not return database passwords or execute queries.', inputSchema: {}, annotations: { readOnlyHint: true } }, guarded(async () => result(await api(await fresh(), '/api/databases'))));
  server.registerTool('request_database_tunnel', {
    description: 'Queue opening an SSM port-forwarding tunnel for a saved RDS connection. Requires separate human approval and optional MFA in the UI. Returns a request ID immediately. Poll get_request. A tunnel never grants query approval.',
    inputSchema: { connectionId: z.string().uuid(), reason: z.string().min(1).max(2000) }, annotations: { readOnlyHint: false, idempotentHint: false, openWorldHint: true },
  }, guarded(async input => result(await submitRequest({...input,kind:'tunnel'}))));
  server.registerTool('request_database_query', {
    description: 'Queue exactly one SQL statement for an operator-configured RDS connection. EVERY query, including SELECT, requires its own human approval. The tunnel must already be open. Supply bound parameters ($1 for PostgreSQL, ? for MySQL). Returns request ID immediately; poll get_request for rows/results. Never ask for database passwords in chat or retry an uncertain write.',
    inputSchema: { connectionId: z.string().uuid(), sql: z.string().min(1).max(32768), params: z.array(z.union([z.string(), z.number(), z.boolean(), z.null()])).max(100).optional(), reason: z.string().min(1).max(2000) }, annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
  }, guarded(async input => result(await submitRequest({...input,kind:'sql'}))));
  server.registerTool('get_request', { description: 'Get status and results for an AWS command, database tunnel, or SQL query. Never re-executes it.', inputSchema: { requestId: z.string().uuid() }, annotations: { readOnlyHint: true } }, guarded(async ({ requestId }) => result(await api(await fresh(), `/api/requests/${requestId}`))));
  server.registerTool('cancel_request', { description: 'Cancel a pending or running AWS, database tunnel, or SQL request. Completed remote changes cannot be undone.', inputSchema: { requestId: z.string().uuid() } }, guarded(async ({ requestId }) => result(await api(await fresh(), `/api/requests/${requestId}/cancel`, { method: 'POST' }))));
  // stdout belongs exclusively to the MCP transport.
  process.stderr.write(`AWS approvals: ${state.origin} (run npm start to open)\n`);
  await server.connect(new StdioServerTransport());
}
async function main() {
  const command = process.argv[2] || 'mcp';
  if (command === 'daemon') return daemon();
  if (command === 'mcp') return mcp();
  if (command === 'ui') { const state = await ensureBroker(); const url = `${state.origin}/#${state.approvalToken}`; console.log(`AWS approval dashboard: ${url}`); openBrowser(url); return; }
  if (command === 'stop') { const state = await existing(); if (state) process.kill(state.pid, 'SIGTERM'); console.log(state ? 'Broker stopping.' : 'Broker is not running.'); return; }
  if (command === 'status') { const state = await existing(); console.log(state ? `Running: ${state.origin}` : 'Not running.'); return; }
  throw new Error('Usage: node src/cli.js [ui|mcp|status|stop|daemon]');
}
main().catch(e => { process.stderr.write(`${e.message}\n`); process.exitCode = 1; });
