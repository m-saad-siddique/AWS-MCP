import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { setTimeout as delay } from 'node:timers/promises';
import { DatabaseService, validateConnection } from '../src/database.js';
import { Broker } from '../src/broker.js';
const profiles = async () => [{ name: 'dev' }];
const input = { name: 'reports', engine: 'postgres', profile: 'dev', region: 'us-east-1', host: 'example.us-east-1.rds.amazonaws.com', instanceId: 'i-0123456789abcdef0', database: 'app', username: 'reader', password: 'SECRET_PASSWORD', readOnly: true };
function fixture() {
 const calls = [];
 const tunnels = { opened: false, status() {return {status:this.opened?'open':'closed'};}, async open(c, auth) { calls.push({type:'tunnel',c,auth}); this.opened=true; return {localPort:15432};}, getPort() {if(!this.opened)throw new Error('No open tunnel.');return 15432;}, close(){this.opened=false;}, closeAll(){this.opened=false;} };
 const databases = new DatabaseService({ profiles, tunnels, query: async (...args) => { calls.push({type:'query',args}); return {rows:[{answer:42}],truncated:false}; } });
 const runner = { execute: async()=>{throw new Error('Wrong execution path');}, clearSessions(){} };
 const broker = new Broker({ runner, profiles, databases }); return { calls, tunnels, databases, broker };
}
test('connection metadata persists; password stays in memory and is absent after restart', async()=>{
 const {databases,broker}=fixture(); const dir=await mkdtemp(join(tmpdir(),'rds-test-'));
 try {
  await databases.init(dir); const c=await databases.save(input); assert.equal(c.passwordReady,true);
  const disk=await readFile(join(dir,'databases.json'),'utf8'); assert.ok(!disk.includes('SECRET_PASSWORD')); assert.ok(!JSON.stringify(databases.list()).includes('SECRET_PASSWORD'));
  const second=new DatabaseService({profiles}); await second.init(dir); assert.equal(second.list()[0].passwordReady,false); second.close();
 }finally{await broker.close();await rm(dir,{recursive:true});}
});
test('opening the tunnel never authorizes SELECT; each query separately waits for approval', async()=>{
 const {databases,broker,calls}=fixture();
 try {
  const c=await databases.save(input);
  const tunnel=await broker.submit({kind:'tunnel',connectionId:c.id,reason:'Open reports tunnel'}); assert.equal(calls.length,0);
  await broker.decide(tunnel.id,{decision:'approve',mfaCode:'123456'}); await delay(5);
  assert.equal(calls.length,1); assert.equal(calls[0].auth.mfaCode,'123456');
  const query=await broker.submit({kind:'sql',connectionId:c.id,sql:'SELECT $1 AS answer',params:[42],reason:'Read report'});
  await delay(5); assert.equal(calls.length,1); assert.equal(query.status,'pending');
  assert.ok(!JSON.stringify(query).includes('SECRET_PASSWORD'));
  await broker.decide(query.id,{decision:'approve'}); await delay(5);
  assert.equal(calls.length,2); assert.equal(calls[1].args[2],'SECRET_PASSWORD'); assert.deepEqual(calls[1].args[4],[42]);
  const again=await broker.submit({kind:'sql',connectionId:c.id,sql:'SELECT 2',reason:'Second query'});
  await broker.decide(again.id,{decision:'deny'}); await delay(5); assert.equal(calls.length,2);
 }finally{await broker.close();}
});
test('read-only connection rejects mutations; writes need connection-name confirmation', async()=>{
 const {databases,broker,calls}=fixture();
 try {
  let c=await databases.save(input);
  await assert.rejects(broker.submit({kind:'sql',connectionId:c.id,sql:'DELETE FROM users',reason:'Delete'}),/read-only/);
  await assert.rejects(databases.save({...input,id:c.id,readOnly:false}),/connection name/);
  c=await databases.save({...input,id:c.id,readOnly:false,confirmWrites:'reports'});
  const r=await broker.submit({kind:'sql',connectionId:c.id,sql:'DELETE FROM users WHERE id = $1',params:[123],reason:'Remove test row'});
  await assert.rejects(broker.decide(r.id,{decision:'approve',confirmation:'dev'}),/connection name/); assert.equal(calls.length,0);
  await broker.decide(r.id,{decision:'approve',confirmation:'reports'}); await delay(5);
  assert.equal(broker.requests.get(r.id).status,'failed'); assert.match(broker.requests.get(r.id).result.stderr,/No open tunnel/);
 }finally{await broker.close();}
});
test('changed connection invalidates old approval and query failures mask passwords', async()=>{
 const {databases,broker,tunnels,calls}=fixture();
 try {
  const c=await databases.save(input);
  const r=await broker.submit({kind:'sql',connectionId:c.id,sql:'SELECT 1',reason:'Snapshot test'});
  await databases.save({...input,id:c.id,host:'different.rds.amazonaws.com'});
  await broker.decide(r.id,{decision:'approve'}); await delay(5); assert.equal(calls.length,0); assert.match(broker.requests.get(r.id).result.stderr,/changed/);
  tunnels.opened=true; databases.query=async()=>{throw new Error('Bad password SECRET_PASSWORD');};
  const q=await broker.submit({kind:'sql',connectionId:c.id,sql:'SELECT 1',reason:'Error redaction'});
  await broker.decide(q.id,{decision:'approve'}); await delay(5); assert.equal(broker.requests.get(q.id).status,'failed'); assert.ok(!broker.requests.get(q.id).result.stderr.includes('SECRET_PASSWORD'));
 }finally{await broker.close();}
});
test('agents can list metadata and queue SQL but cannot configure or approve databases', async()=>{
 const {broker,databases,calls}=fixture(); await broker.listen();
 const api=async(path,body,operator=false)=>fetch(broker.origin+'/api/'+path,{method:body?'POST':'GET',headers:{Authorization:'Bearer '+(operator?broker.approvalToken:broker.agentToken),'Content-Type':'application/json'},body:body?JSON.stringify(body):undefined});
 try {
  assert.equal((await api('databases',input)).status,404);
  const c=await databases.save(input);
  const list=await (await api('databases')).json(); assert.equal(list[0].name,'reports'); assert.ok(!JSON.stringify(list).includes('SECRET_PASSWORD'));
  const r=await (await api('requests',{kind:'sql',connectionId:c.id,sql:'SELECT 1',reason:'test'})).json();
  assert.equal((await api(`requests/${r.id}/decision`,{decision:'approve'})).status,403);
  assert.equal((await api(`databases/${c.id}/close`,{})).status,404); assert.equal(calls.length,0);
  await api(`databases/${c.id}/close`,{},true); assert.equal(broker.requests.get(r.id).status,'canceled');
 }finally{await broker.close();}
});
test('connection validation rejects malformed tunnel targets and non-scalar SQL parameters',async()=>{
 assert.throws(()=>validateConnection({...input,host:'https://db.rds.amazonaws.com'},[{name:'dev'}]));
 assert.throws(()=>validateConnection({...input,instanceId:'i-$(whoami)'},[{name:'dev'}]));
 const {databases,broker}=fixture();try{const c=await databases.save(input);assert.throws(()=>databases.prepare({connectionId:c.id,sql:'SELECT $1',params:[{}],reason:'test'},'sql'),/scalar/);}finally{await broker.close();}
});

test('editing the destination without a new password discards the old cached password',async()=>{
 const {databases,broker}=fixture();
 try {
  const c=await databases.save(input);assert.equal(c.passwordReady,true);
  const changed=await databases.save({...input,id:c.id,host:'different.rds.amazonaws.com',password:''});assert.equal(changed.passwordReady,false);
 }finally{await broker.close();}
});
