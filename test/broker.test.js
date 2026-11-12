import test from 'node:test';
import http from 'node:http';
import assert from 'node:assert/strict';
import { Broker } from '../src/broker.js';
import { setTimeout as delay } from 'node:timers/promises';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
const command = { profile: 'dev', args: ['sts', 'get-caller-identity'], reason: 'Verify account' };
const make = options => new Broker({ profiles: async () => [{ name: 'dev' }], runner: { execute: async () => ({ exitCode: 0, stdout: '{"Account":"123"}', stderr: '' }), clearSessions() {} }, ...options });
test('requests require approval; simultaneous approvals execute once', async () => {
  let executions = 0;
  const b = make({ runner: { execute: async () => { executions++; return { exitCode: 0, stdout: 'ok', stderr: '' }; }, clearSessions() {} } });
  try {
    const request = await b.submit(command); assert.equal(executions, 0);
    const decisions = await Promise.allSettled([b.decide(request.id, { decision: 'approve', deliveryMode: 'direct' }), b.decide(request.id, { decision: 'approve', deliveryMode: 'direct' })]);
    assert.equal(decisions.filter(d => d.status === 'fulfilled').length, 1); await delay(10); assert.equal(executions, 1); assert.equal(b.requests.get(request.id).status, 'completed');
  } finally { await b.close(); }
});
test('denial and expiration never execute; destructive commands require typed confirmation', async () => {
  let now = 0, executions = 0;
  const b = make({ now: () => now, approvalMs: 100, runner: { execute: async () => { executions++; return { exitCode: 0 }; }, clearSessions() {} } });
  try {
    const denied = await b.submit(command); await b.decide(denied.id, { decision: 'deny' }); await assert.rejects(b.decide(denied.id, { decision: 'approve', deliveryMode: 'direct' }));
    const expired = await b.submit(command); now = 101; await assert.rejects(b.decide(expired.id, { decision: 'approve', deliveryMode: 'direct' })); assert.equal(b.requests.get(expired.id).status, 'expired');
    const destructive = await b.submit({ ...command, args: ['ec2', 'terminate-instances'] }); await assert.rejects(b.decide(destructive.id, { decision: 'approve', deliveryMode: 'direct' }), /profile name/); assert.equal(executions, 0);
  } finally { await b.close(); }
});
test('HTTP separates agent and approval credentials, rejects cross-origin access and bad Host', async () => {
  const b = await make().listen();
  const call = async (path, token, body, headers = {}) => fetch(b.origin + path, { method: body ? 'POST' : 'GET', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', ...headers }, body: body ? JSON.stringify(body) : undefined });
  try {
    assert.equal((await call('/api/profiles', 'bad')).status, 401);
    assert.equal((await call('/api/profiles', b.agentToken, undefined, { Origin: 'https://evil.test' })).status, 403);
    const badHostStatus = await new Promise((resolve, reject) => { const req = http.get(b.origin + '/api/profiles', { headers: { Host: 'evil.test', Authorization: `Bearer ${b.agentToken}` } }, res => { res.resume(); resolve(res.statusCode); }); req.on('error', reject); });
    assert.equal(badHostStatus, 403);
    assert.equal((await call('/api/setup', b.agentToken)).status, 404);
    const setup = await (await call('/api/setup', b.approvalToken)).json();
    assert.equal(setup.clients.length, 4);
    const cursor = JSON.parse(setup.clients.find(c => c.id === 'cursor').code);
    assert.equal(cursor.mcpServers.aws_approval.command, process.execPath);
    assert.ok(cursor.mcpServers.aws_approval.args[0].endsWith('/src/cli.js'));
    assert.ok(!JSON.stringify(setup).includes(b.approvalToken));
    const request = await (await call('/api/requests', b.agentToken, command)).json();
    assert.equal((await call(`/api/requests/${request.id}/decision`, b.agentToken, { decision: 'approve', deliveryMode: 'direct' })).status, 403);
    assert.equal((await call('/api/requests', b.agentToken)).status, 404);
    assert.equal((await call(`/api/requests/${request.id}/decision`, b.approvalToken, { decision: 'approve', deliveryMode: 'direct' })).status, 200);
    await delay(10); assert.equal((await (await call(`/api/requests/${request.id}`, b.agentToken)).json()).status, 'completed');
    const page = await fetch(b.origin); assert.equal(page.status, 200); assert.match(page.headers.get('content-security-policy'), /frame-ancestors 'none'/);
  } finally { await b.close(); }
});
test('persistent audit contains command hashes but no arguments, output, or MFA codes', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'aws-audit-'));
  const b = make({ auditFile: join(dir, 'audit.jsonl') });
  try {
    const r = await b.submit({ ...command, args: ['ssm', 'get-parameter', '--name', 'PRIVATE_ARGUMENT'] });
    await b.decide(r.id, { decision: 'approve', deliveryMode: 'direct', mfaCode: '123456' }); await delay(20);
    const audit = await readFile(join(dir, 'audit.jsonl'), 'utf8'); assert.match(audit, /commandHash/); assert.ok(!audit.includes('PRIVATE_ARGUMENT')); assert.ok(!audit.includes('123456')); assert.ok(!audit.includes('stdout'));
  } finally { await b.close(); await rm(dir, { recursive: true }); }
});
test('cancel while approval audit is pending prevents execution', async () => {
  let executions = 0, release;
  const b = make({ runner: { execute: async () => { executions++; return { exitCode: 0 }; }, clearSessions() {} } });
  try {
    const r = await b.submit(command);
    b.audit = async (_, event) => { if (event === 'approved') await new Promise(resolve => { release = resolve; }); };
    const approval = b.decide(r.id, { decision: 'approve', deliveryMode: 'direct' }); while (!release) await delay(1); await b.cancel(r.id); release(); await approval; assert.equal(executions, 0);
  } finally { await b.close(); }
});

// Approval policy applies to every AWS CLI operation, regardless of risk label.
test('reads, writes, destructive commands, and SSO each need their own approval', async () => {
  let executions = 0;
  const b = make({ runner: { execute: async () => { executions++; return { exitCode: 0, stdout: 'ok', stderr: '' }; }, clearSessions() {} } });
  try {
    for (const args of [['sts', 'get-caller-identity'], ['s3', 'ls'], ['ec2', 'describe-instances'], ['ec2', 'start-instances'], ['ec2', 'terminate-instances'], ['sso', 'login']]) {
      const before = executions;
      const r = await b.submit({ ...command, args });
      await delay(5);
      assert.equal(executions, before, `${args.join(' ')} ran without approval`);
      assert.equal(b.requests.get(r.id).status, 'pending');
      await b.decide(r.id, { decision: 'approve', deliveryMode: 'direct', confirmation: 'dev' });
      await delay(5);
      assert.equal(executions, before + 1);
    }
  } finally { await b.close(); }
});
