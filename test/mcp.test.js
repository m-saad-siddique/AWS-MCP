import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

test('real stdio MCP → shared broker → approval → fake AWS → agent result', { timeout: 20000 }, async () => {
  const dir = await mkdtemp(join(tmpdir(), 'aws-mcp-e2e-'));
  const cli = fileURLToPath(new URL('../src/cli.js', import.meta.url));
  const config = join(dir, 'config'), credentials = join(dir, 'credentials'), fake = join(dir, 'fake-aws');
  await writeFile(config, '[profile demo]\nregion=us-east-1\n'); await writeFile(credentials, '');
  await writeFile(fake, '#!/usr/bin/env node\nprocess.stdout.write(JSON.stringify({Account:"000000000000", TestOnly:true, args:process.argv.slice(2)}));\n', { mode: 0o700 });
  const env = { ...process.env, AWS_MCP_STATE_DIR: dir, AWS_CONFIG_FILE: config, AWS_SHARED_CREDENTIALS_FILE: credentials, AWS_MCP_AWS_BIN: fake, AWS_MCP_NO_OPEN: '1' };
  const transport = new StdioClientTransport({ command: process.execPath, args: [cli, 'mcp'], env, stderr: 'pipe' });
  const client = new Client({ name: 'test-agent', version: '1.0.0' });
  let state;
  try {
    await client.connect(transport); state = JSON.parse(await readFile(join(dir, 'broker.json'), 'utf8'));
    const tools = await client.listTools(); assert.deepEqual(tools.tools.map(t => t.name).sort(), ['cancel_aws_request', 'cancel_request', 'execute_aws', 'get_aws_request', 'get_request', 'list_aws_profiles', 'list_database_connections', 'request_aws', 'request_database_query', 'request_database_tunnel']);
    const profileResult = await client.callTool({ name: 'list_aws_profiles', arguments: {} }); assert.equal(JSON.parse(profileResult.content[0].text)[0].name, 'demo');
    const call = client.callTool({ name: 'execute_aws', arguments: { profile: 'demo', args: ['sts', 'get-caller-identity'], reason: 'Integration test' } });
    const op = async (path, body) => { const response = await fetch(state.origin + path, { method: body ? 'POST' : 'GET', headers: { Authorization: `Bearer ${state.approvalToken}`, 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : undefined }); return response.json(); };
    let request;
    for (let i = 0; i < 50; i++) { request = (await op('/api/requests'))[0]; if (request) break; await delay(50); }
    assert.equal(request.status, 'pending'); assert.equal(request.result, undefined);
    await op(`/api/requests/${request.id}/decision`, { decision: 'approve', deliveryMode: 'direct' });
    const response = await call; const result = JSON.parse(response.content[0].text);
    assert.equal(response.isError, false); assert.equal(result.status, 'completed');
    const output = JSON.parse(result.result.stdout); assert.equal(output.TestOnly, true); assert.ok(output.args.includes('demo'));
    const followup = await client.callTool({ name: 'get_aws_request', arguments: { requestId: request.id } }); assert.equal(JSON.parse(followup.content[0].text).status, 'completed');
    const heldCall = client.callTool({ name: 'execute_aws', arguments: { profile: 'demo', args: ['sts', 'get-caller-identity'], reason: 'Held result integration test' } });
    let heldRequest;
    for (let i=0;i<50;i++) { heldRequest=(await op('/api/requests')).find(r=>r.reason==='Held result integration test'); if(heldRequest)break;await delay(50); }
    await op(`/api/requests/${heldRequest.id}/decision`,{decision:'approve',deliveryMode:'review'});
    const heldResponse=await heldCall;const heldView=JSON.parse(heldResponse.content[0].text);
    assert.equal(heldView.status,'awaiting_review');assert.equal(heldView.result,undefined);assert.equal(heldView.heldResult,undefined);assert.ok(!heldResponse.content[0].text.includes('TestOnly'));
    const heldPoll=await client.callTool({name:'get_request',arguments:{requestId:heldRequest.id}});assert.equal(JSON.parse(heldPoll.content[0].text).result,undefined);
    await op(`/api/requests/${heldRequest.id}/release`,{decision:'send',stdout:'{"Account":"[MASKED]","Reviewed":true}',stderr:''});
    for (const tool of ['get_aws_request','get_request']) {const sent=JSON.parse((await client.callTool({name:tool,arguments:{requestId:heldRequest.id}})).content[0].text);assert.equal(sent.status,'completed');assert.equal(JSON.parse(sent.result.stdout).Account,'[MASKED]');assert.ok(!JSON.stringify(sent).includes('000000000000'));}
    const queued = await client.callTool({ name: 'request_aws', arguments: { profile: 'demo', args: ['s3', 'ls'], reason: 'Async test' } });
    const pending = JSON.parse(queued.content[0].text); assert.equal(pending.status, 'pending');
    const canceled = await client.callTool({ name: 'cancel_aws_request', arguments: { requestId: pending.id } }); assert.equal(JSON.parse(canceled.content[0].text).status, 'canceled');
    const dbList = await client.callTool({ name: 'list_database_connections', arguments: {} });
    assert.deepEqual(JSON.parse(dbList.content[0].text), []);
    const db = await op('/api/databases', { name: 'test-rds', engine: 'postgres', profile: 'demo', region: 'us-east-1', host: 'example.rds.amazonaws.com', instanceId: 'i-0123456789abcdef0', database: 'app', username: 'reporter', password: 'TEST_ONLY_PASSWORD', readOnly: true });
    const sqlCall = await client.callTool({ name: 'request_database_query', arguments: { connectionId: db.id, sql: 'SELECT 1', reason: 'MCP SQL test' } });
    const sqlRequest = JSON.parse(sqlCall.content[0].text); assert.equal(sqlRequest.status, 'pending');
    assert.ok(!JSON.stringify(sqlRequest).includes('TEST_ONLY_PASSWORD'));
    const statusCall = await client.callTool({ name: 'get_request', arguments: { requestId: sqlRequest.id } }); assert.equal(JSON.parse(statusCall.content[0].text).status, 'pending');
    await client.callTool({ name: 'cancel_request', arguments: { requestId: sqlRequest.id } });
    const tunnelCall = await client.callTool({ name: 'request_database_tunnel', arguments: { connectionId: db.id, reason: 'MCP tunnel test' } });
    const tunnelRequest = JSON.parse(tunnelCall.content[0].text); assert.equal(tunnelRequest.status, 'pending');
    await client.callTool({ name: 'cancel_request', arguments: { requestId: tunnelRequest.id } });
    const policy = await op('/api/policies');
    await op('/api/policies',{...policy,mode:'auto_reads'});
    const automatic=await client.callTool({name:'execute_aws',arguments:{profile:'demo',args:['sts','get-caller-identity'],reason:'Auto-approved MCP test'}});
    const automaticView=JSON.parse(automatic.content[0].text);assert.equal(automatic.isError,false);assert.equal(automaticView.status,'completed');assert.equal(automaticView.autoApproved,true);assert.equal(JSON.parse(automaticView.result.stdout).TestOnly,true);
    await op('/api/policies',{...(await op('/api/policies')),mode:'read_only'});
    const blocked=await client.callTool({name:'execute_aws',arguments:{profile:'demo',args:['ec2','terminate-instances','--instance-ids','i-test'],reason:'Blocked MCP test'}});
    const blockedView=JSON.parse(blocked.content[0].text);assert.equal(blocked.isError,true);assert.equal(blockedView.status,'blocked');assert.equal(blockedView.result,undefined);
    await op('/api/policies',{...(await op('/api/policies')),mode:'manual'});
    // A second bridge reuses the same daemon rather than creating a second dashboard.
    const t2 = new StdioClientTransport({ command: process.execPath, args: [cli, 'mcp'], env, stderr: 'pipe' }); const c2 = new Client({ name: 'test-agent-2', version: '1.0.0' });
    try { await c2.connect(t2); assert.equal(JSON.parse(await readFile(join(dir, 'broker.json'), 'utf8')).pid, state.pid); } finally { await c2.close(); }
    // Existing MCP clients must refresh daemon credentials and retrieve persisted records.
    const beforeRestart=await client.callTool({name:'request_aws',arguments:{profile:'demo',args:['s3','ls'],reason:'Pending during restart'}});
    const interruptedId=JSON.parse(beforeRestart.content[0].text).id,previousPid=state.pid;
    process.kill(previousPid,'SIGTERM');
    for(let i=0;i<80;i++){try{await readFile(join(dir,'broker.json'));}catch(e){if(e.code==='ENOENT')break;throw e;}await delay(25);}
    const historical=JSON.parse((await client.callTool({name:'get_request',arguments:{requestId:request.id}})).content[0].text);
    state=JSON.parse(await readFile(join(dir,'broker.json'),'utf8'));
    assert.notEqual(state.pid,previousPid);assert.equal(historical.status,'completed');assert.equal(historical.fromHistory,true);assert.equal(JSON.parse(historical.result.stdout).TestOnly,true);
    const reviewed=JSON.parse((await client.callTool({name:'get_request',arguments:{requestId:heldRequest.id}})).content[0].text);
    assert.equal(reviewed.result.stdout,'{"Account":"[MASKED]","Reviewed":true}');
    const interrupted=JSON.parse((await client.callTool({name:'get_request',arguments:{requestId:interruptedId}})).content[0].text);
    assert.equal(interrupted.status,'interrupted');assert.equal(interrupted.result,undefined);
    const records=await op('/api/history');assert.ok(records.total>=8);
    assert.equal((await op('/api/requests')).length,0);

  } finally {
    await client.close().catch(() => {});
    if (state) { try { process.kill(state.pid, 'SIGTERM'); } catch {} }
    await delay(200); await rm(dir, { recursive: true, force: true });
  }
});
