import test from 'node:test';
import {connect} from 'node:net';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { randomUUID } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { Broker } from '../src/broker.js';
import { HistoryStore,historySnapshot } from '../src/history.js';
const command={profile:'dev',args:['sts','get-caller-identity'],reason:'History execution test'};
function fixture(options={}){let executions=0;const runner={execute:async()=>{executions++;return {exitCode:0,stdout:'{"Account":"TEST_ACCOUNT"}',stderr:''};},clearSessions(){},...options.runner};const b=new Broker({profiles:async()=>[{name:'dev'}],runner,...options});return {b,count:()=>executions};}
async function call(b,path,body,operator=true){const response=await fetch(b.origin+'/api/'+path,{method:body?'POST':'GET',headers:{Authorization:'Bearer '+(operator?b.approvalToken:b.agentToken),'Content-Type':'application/json'},body:body?JSON.stringify(body):undefined});return {status:response.status,body:await response.json()};}
test('completed request, SQL text, results, and timeline survive a real broker restart without replay',async()=>{
 const dir=await mkdtemp(join(tmpdir(),'history-restart-'));let first,second;
 try{
  const f=fixture();first=await f.b.listen({stateDir:dir});const r=await first.submit({...command,clientName:'history-test-agent'});await first.decide(r.id,{decision:'approve'});await delay(10);
  const before=first.history.detail(r.id);assert.equal(before.request.status,'completed');assert.equal(before.request.clientName,'history-test-agent');assert.ok(before.events.some(e=>e.event==='execution_started'));assert.equal(f.count(),1);
  await first.close();first=undefined;const f2=fixture();second=await f2.b.listen({stateDir:dir});
  const restored=await call(second,`requests/${r.id}`,undefined,false);assert.equal(restored.body.fromHistory,true);assert.equal(restored.body.status,'completed');assert.equal(JSON.parse(restored.body.result.stdout).Account,'TEST_ACCOUNT');assert.equal(f2.count(),0);
  const archive=await call(second,'history?q=History%20execution');assert.equal(archive.body.total,1);assert.equal(archive.body.items[0].id,r.id);
  const events=second.history.activity({limit:100}).items.map(e=>e.event);assert.equal(events.filter(e=>e==='broker_started').length,2);assert.ok(events.includes('broker_stopped'));
 }finally{await first?.close();await second?.close();await rm(dir,{recursive:true,force:true});}
});
test('held output never reaches disk; only the edited released result is archived',async()=>{
 const dir=await mkdtemp(join(tmpdir(),'history-privacy-'));const {b}=fixture({runner:{execute:async()=>({exitCode:0,stdout:'PRIVATE_ORIGINAL_OUTPUT',stderr:'PRIVATE_ORIGINAL_ERROR'}),clearSessions(){}}});await b.listen({stateDir:dir});
 try{
  const r=await b.submit(command);await b.decide(r.id,{decision:'approve',deliveryMode:'review',mfaCode:'654321'});await delay(10);
  let detail=b.history.detail(r.id);assert.equal(detail.request.status,'awaiting_review');assert.equal(detail.request.result,undefined);assert.ok(!JSON.stringify(detail).includes('PRIVATE_ORIGINAL'));
  for(const suffix of ['','-wal']){try{const data=await readFile(join(dir,'history.sqlite'+suffix));assert.ok(!data.includes(Buffer.from('PRIVATE_ORIGINAL')));assert.ok(!data.includes(Buffer.from('654321')));}catch(e){if(e.code!=='ENOENT')throw e;}}
  await b.release(r.id,{decision:'send',stdout:'[MASKED]',stderr:'[MASKED]'});detail=b.history.detail(r.id);assert.equal(detail.request.result.stdout,'[MASKED]');assert.ok(!JSON.stringify(detail).includes('PRIVATE_ORIGINAL'));
  assert.ok(detail.events.some(e=>e.event==='result_sent'));assert.equal(detail.request.outputReviewed,true);
 }finally{await b.close();await rm(dir,{recursive:true,force:true});}
});
test('crash recovery distinguishes pending, executing and held output, and never reenqueues work',async()=>{
 const dir=await mkdtemp(join(tmpdir(),'history-crash-'));const first=new HistoryStore();await first.init(dir);
 const records=['pending','authorizing','running','awaiting_review','releasing'].map(status=>({...command,kind:'aws',id:randomUUID(),createdAt:Date.now(),status}));
 try{
  for(const r of records)first.record(r,statusEvent(r.status));
  // Simulate an unclean stop: close SQLite without writing the graceful broker-stop marker.
  first.db.close();first.db=undefined;
  const restored=new HistoryStore();await restored.init(dir);
  try{
   for(const r of records){const saved=restored.request(r.id);assert.equal(saved.status,r.status==='running'?'outcome_unknown':['awaiting_review','releasing'].includes(r.status)?'result_unavailable':'interrupted');assert.equal(saved.result,undefined);assert.equal(saved.recovered,true);assert.ok(restored.detail(r.id).events.some(e=>e.event==='recovered_after_restart'));}
   assert.ok(restored.activity().items.some(e=>e.event==='broker_unclean_stop_detected'));
  }finally{restored.close();}
 }finally{await rm(dir,{recursive:true,force:true});}
});
function statusEvent(status){return status==='running'?'execution_started':status;}
test('graceful shutdown records interrupted work instead of claiming it completed or replaying it',async()=>{
 const dir=await mkdtemp(join(tmpdir(),'history-stop-'));const {b}=fixture();await b.listen({stateDir:dir});const r=await b.submit(command);await b.close();
 const restored=new HistoryStore();await restored.init(dir);try{const detail=restored.detail(r.id);assert.equal(detail.request.status,'interrupted');assert.match(detail.request.recoveryNote,/before execution/);assert.ok(detail.events.some(e=>e.event==='broker_stopped_request'));}finally{restored.close();await rm(dir,{recursive:true,force:true});}
});
test('SQL, parameters and released rows are recorded but authentication envelopes are excluded',async()=>{
 const h=new HistoryStore();await h.init();
 try{const r={id:randomUUID(),kind:'sql',args:['database','query'],profile:'dev',connectionName:'Reporting',createdAt:Date.now(),status:'completed',sql:'SELECT $1 AS answer',params:[42],target:{host:'db.rds.amazonaws.com',database:'app',username:'reader',password:'AUTH_PASSWORD'},mfaCode:'AUTH_CODE',env:{AWS_SECRET_ACCESS_KEY:'AUTH_SECRET'},heldResult:{stdout:'HELD_SECRET'},result:{exitCode:0,stdout:'{"rows":[{"answer":42,"password":"ROW_PASSWORD"}]}',stderr:''}};
  h.record(r,'completed');const detail=h.detail(r.id);assert.equal(detail.request.sql,r.sql);assert.deepEqual(detail.request.params,[42]);assert.equal(JSON.parse(detail.request.result.stdout).rows[0].answer,42);
  for(const value of ['AUTH_PASSWORD','AUTH_CODE','AUTH_SECRET','HELD_SECRET','ROW_PASSWORD'])assert.ok(!JSON.stringify(detail).includes(value));
  const credential=historySnapshot({...r,sql:"ALTER USER reader PASSWORD 'CREDENTIAL_LITERAL'",params:['CREDENTIAL_PARAM'],args:['sts','get-session-token','--token-code','OTP_LITERAL','--password=PASSWORD_LITERAL']});
  for(const value of ['CREDENTIAL_LITERAL','CREDENTIAL_PARAM','OTP_LITERAL','PASSWORD_LITERAL'])assert.ok(!JSON.stringify(credential).includes(value));
 }finally{h.close();}
});
test('history search, filters and pagination use literal parameter binding; agents cannot enumerate history',async()=>{
 const {b}=fixture();await b.listen();
 try{
  for(let i=0;i<5;i++)b.history.record({...command,kind:i<3?'sql':'aws',sql:i<3?'SELECT '+i:undefined,id:randomUUID(),createdAt:100+i,status:i%2?'failed':'completed'},'completed');
  assert.equal(b.history.list({kind:'sql'}).total,3);assert.equal(b.history.list({limit:2,offset:2}).items.length,2);assert.equal(b.history.list({q:"' OR 1=1; DROP TABLE requests; --"}).total,0);assert.equal(b.history.list({q:'%'}).total,0);assert.equal(b.history.list().total,5);
  assert.equal((await call(b,'history',undefined,false)).status,404);assert.equal((await call(b,'history/events',undefined,false)).status,404);
  const id=b.history.list().items[0].id;assert.equal((await call(b,`history/${id}`,undefined,false)).status,404);assert.equal((await call(b,`history/${id}`)).status,200);
 }finally{await b.close();}
});
test('history persistence failure blocks new execution and never releases held output',async()=>{
 const {b,count}=fixture();await b.listen();
 try{
  const r=await b.submit(command),record=b.history.record.bind(b.history);b.history.record=(request,event,...rest)=>{if(event==='execution_started')throw new Error('disk full');return record(request,event,...rest);};
  await assert.rejects(b.decide(r.id,{decision:'approve'}),/not started/);assert.equal(count(),0);
  b.history.record=record;const held=await b.submit(command);await b.decide(held.id,{decision:'approve',deliveryMode:'review'});await delay(10);
  b.history.record=(request,event,...rest)=>{if(event==='result_sent')throw new Error('disk full');return record(request,event,...rest);};
  await assert.rejects(b.release(held.id,{decision:'send',stdout:'clean',stderr:''}),/No result was sent/);assert.equal(b.requests.get(held.id).status,'awaiting_review');assert.equal(b.public(b.requests.get(held.id)).result,undefined);
 }finally{await b.close();}
});
test('legacy import persists existing records once and never imports held/authentication payloads',async()=>{
 const h=new HistoryStore();await h.init();try{const r={...command,kind:'aws',id:randomUUID(),createdAt:Date.now(),status:'completed',result:{exitCode:0,stdout:'ok',stderr:''},heldResult:{stdout:'HIDDEN'},mfaCode:'OTP',password:'AUTH'};assert.equal(h.importRecords([r]),1);assert.equal(h.importRecords([r]),0);const detail=h.detail(r.id);assert.equal(detail.request.source,'legacy');for(const value of ['HIDDEN','OTP','AUTH'])assert.ok(!JSON.stringify(detail).includes(value));}finally{h.close();}
});

test('broker restart closes unfinished browser requests instead of hanging shutdown', {timeout:5000}, async()=>{
 const {b}=fixture();await b.listen();const url=new URL(b.origin),socket=connect(Number(url.port),url.hostname);
 try{
  await new Promise(resolve=>socket.once('connect',resolve));
  socket.write('POST /api/requests HTTP/1.1\r\nHost: '+url.host+'\r\nAuthorization: Bearer '+b.agentToken+'\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{');
  await delay(30);const started=Date.now();await b.close();assert.ok(Date.now()-started<2500);
 }finally{socket.destroy();if(b.history.db)await b.close();}
});
