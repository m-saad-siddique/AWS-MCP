import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { randomUUID } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { Broker, isTerminal } from '../src/broker.js';
import { PolicyService, classifyCommand } from '../src/policy.js';
const profiles=[{name:'dev',region:'us-east-1'},{name:'prod',region:'us-west-2'},{name:'mfa',region:'us-east-1',mfaSerial:'arn:aws:iam::123456789012:mfa/user'}];
const command={kind:'aws',profile:'dev',args:['ec2','describe-instances'],region:'',reason:'Inspect inventory'};
const rule=(patch={})=>({id:randomUUID(),name:'Inventory',profile:'dev',region:'',args:['ec2','describe-instances'],match:'operation',action:'allow',enabled:true,expiresAt:null,...patch});
const save=(p,patch)=>p.save({...p.view(),...patch});
function fixture(options={}){const calls=[];const runner={execute:async(r)=>{calls.push(r.id);return {exitCode:0,stdout:'test result',stderr:''};},hasSession:()=>false,clearSessions(){},...options.runner};const broker=new Broker({profiles:async()=>profiles,runner,...options});return {broker,calls};}
test('catalog does not confuse credential creation, downloads, or unknown get names with reads',()=>{
 assert.equal(classifyCommand(['ec2','describe-instances']).read,true);
 assert.equal(classifyCommand(['sts','get-session-token']).read,false);
 assert.equal(classifyCommand(['s3api','get-object']).read,false);
 assert.equal(classifyCommand(['s3api','get-object']).manualOnly,true);
 assert.equal(classifyCommand(['lambda','invoke']).manualOnly,true);
 assert.equal(classifyCommand(['future','get-delete-everything']).read,false);
 assert.equal(classifyCommand(['secretsmanager','get-secret-value']).sensitive,true);
});
test('manual mode queues, auto-read mode executes a catalog read, and unknown/sensitive operations stay manual',async()=>{
 const {broker:b,calls}=fixture();try{
  assert.equal((await b.submit(command)).status,'pending');assert.equal(calls.length,0);
  await save(b.policies,{mode:'auto_reads'});const read=await b.submit(command);await delay(5);assert.equal(b.requests.get(read.id).status,'completed');assert.equal(b.requests.get(read.id).autoApproved,true);assert.equal(b.requests.get(read.id).deliveryMode,'direct');assert.equal(calls.length,1);
  for(const args of [['sts','get-session-token'],['secretsmanager','get-secret-value','--secret-id','test'],['future','get-delete-everything'],['ec2','start-instances','--instance-ids','i-test']])assert.equal((await b.submit({...command,args})).status,'pending');
  assert.equal(calls.length,1);
 }finally{await b.close();}
});
test('read-only mode blocks writes and unknown APIs even when an Allow rule matches',async()=>{
 const {broker:b,calls}=fixture();try{
  await save(b.policies,{mode:'read_only',rules:[rule({args:['ec2','start-instances'],confirmCommand:'ec2 start-instances'})]});
  for(const args of [['ec2','start-instances'],['sts','get-session-token'],['s3api','get-object','out.txt']]){const r=await b.submit({...command,args});assert.equal(r.status,'blocked');assert.equal(isTerminal(r.status),true);await assert.rejects(b.decide(r.id,{decision:'approve'}));}
  assert.equal((await b.submit({...command,args:['ssm','get-parameter','--name','secret']})).status,'pending');assert.equal(calls.length,0);
 }finally{await b.close();}
});
test('rules scope exact arguments, profile and effective region; deny wins over ask and allow',async()=>{
 const p=new PolicyService();const exact=rule({match:'exact',region:'us-east-1',args:['ec2','describe-instances','--instance-ids','i-one']});await save(p,{rules:[exact]});
 assert.equal(p.evaluate({...command,args:exact.args},profiles[0]).action,'allow');
 assert.equal(p.evaluate({...command,args:[...exact.args.slice(0,3),'i-two']},profiles[0]).action,'ask');
 assert.equal(p.evaluate({...command,args:exact.args,region:'us-west-2'},profiles[0]).action,'ask');
 assert.equal(p.evaluate({...command,args:exact.args,profile:'prod'},profiles[1]).action,'ask');
 await save(p,{rules:[rule(),rule({action:'ask'})]});assert.equal(p.evaluate(command,profiles[0]).action,'ask');
 await save(p,{rules:[rule(),rule({action:'ask'}),rule({action:'deny'})]});assert.equal(p.evaluate(command,profiles[0]).action,'deny');
});
test('expired/disabled rules do not execute, and protected profiles or paused automation always ask',async()=>{
 let now=100;const p=new PolicyService({now:()=>now});await save(p,{rules:[rule({expiresAt:101})]});assert.equal(p.evaluate(command).action,'allow');now=102;assert.equal(p.evaluate(command).action,'ask');
 await save(p,{rules:[rule({enabled:false})]});assert.equal(p.evaluate(command).action,'ask');
 await save(p,{mode:'auto_reads',protectedProfiles:['dev'],rules:[rule()]});assert.equal(p.evaluate(command).action,'ask');
 await save(p,{protectedProfiles:[],paused:true});assert.equal(p.evaluate(command).action,'ask');
 await save(p,{rules:[rule({action:'deny'})]});assert.equal(p.evaluate(command).action,'deny');
});
test('unsafe automatic rules need operator confirmation and cannot reuse confirmation after widening scope',async()=>{
 const p=new PolicyService();const write=rule({args:['ec2','terminate-instances'],confirmed:true});
 await assert.rejects(save(p,{rules:[write]}),/Type the service/);
 await save(p,{rules:[{...write,confirmCommand:'ec2 terminate-instances'}]});assert.equal(p.evaluate({...command,args:['ec2','terminate-instances']}).action,'allow');
 await assert.rejects(save(p,{rules:[{...p.current.rules[0],profile:'*'}]}),/Type the service/);
 await assert.rejects(save(p,{rules:[rule({args:['ssm','start-session'],confirmCommand:'ssm start-session'})]}),/always requires/);
 await assert.rejects(save(p,{rules:[rule({args:['ec2','describe-instances','--endpoint-url','https://example.com']})]}),/Unsupported/);
});
test('MFA without a cached session falls back to a popup even for an allowed read',async()=>{
 const {broker:b,calls}=fixture();try{await save(b.policies,{mode:'auto_reads'});const r=await b.submit({...command,profile:'mfa'});assert.equal(r.status,'pending');assert.match(r.policy.reason,/MFA/);assert.equal(calls.length,0);}finally{await b.close();}
 const cached=fixture({runner:{execute:async()=>({exitCode:0,stdout:'ok',stderr:''}),hasSession:()=>true,clearSessions(){}}});try{await save(cached.broker.policies,{mode:'auto_reads'});const r=await cached.broker.submit({...command,profile:'mfa'});await delay(5);assert.equal(cached.broker.requests.get(r.id).autoApproved,true);}finally{await cached.broker.close();}
});
test('policy changes during approval auditing prevent stale automatic execution',async()=>{
 const {broker:b,calls}=fixture();try{
  await save(b.policies,{mode:'auto_reads'});let release;b.audit=async(_,event)=>{if(event==='auto_approved')await new Promise(resolve=>{release=resolve;});};
  const submission=b.submit(command);while(!release)await delay(1);await save(b.policies,{paused:true});release();const r=await submission;
  assert.equal(r.status,'pending');assert.equal(r.autoApproved,false);assert.equal(calls.length,0);assert.match(r.policy.reason,/changed/);
 }finally{await b.close();}
});
test('a newly denied pending request cannot be approved manually and automatic audit failures fail closed',async()=>{
 const {broker:b,calls}=fixture();try{
  const r=await b.submit(command);await save(b.policies,{rules:[rule({action:'deny'})]});assert.equal((await b.decide(r.id,{decision:'approve'})).status,'blocked');assert.equal(calls.length,0);
  await save(b.policies,{rules:[],mode:'auto_reads'});b.audit=async(_,event)=>{if(event==='auto_approved')throw new Error('disk unavailable');};await assert.rejects(b.submit(command));assert.equal(calls.length,0);
 }finally{await b.close();}
});
test('policy persistence is private, stale edits are rejected, and failed audit cannot activate new settings',async()=>{
 const dir=await mkdtemp(join(tmpdir(),'aws-policies-'));const p=new PolicyService();await p.init(dir);
 try{
  const old=p.view();await save(p,{mode:'auto_reads',defaultDelivery:'review',rules:[rule()]});const reloaded=new PolicyService();await reloaded.init(dir);assert.equal(reloaded.current.mode,'auto_reads');assert.equal(reloaded.current.defaultDelivery,'review');
  await assert.rejects(p.save(old),/another tab/);const revision=p.current.revision;
  await assert.rejects(p.save({...p.view(),mode:'read_only'},{audit:async()=>{throw new Error('audit failure');}}));assert.equal(p.current.revision,revision);
 }finally{await rm(dir,{recursive:true});}
});
test('agents cannot edit or preview policies; operator preview does not execute and policy decisions are audited',async()=>{
 const dir=await mkdtemp(join(tmpdir(),'aws-policy-api-'));const {broker:b,calls}=fixture();await b.listen({stateDir:dir});
 const api=async(path,body,operator=false)=>{const response=await fetch(b.origin+'/api/'+path,{method:body?'POST':'GET',headers:{Authorization:'Bearer '+(operator?b.approvalToken:b.agentToken),'Content-Type':'application/json'},body:body?JSON.stringify(body):undefined});return {status:response.status,body:await response.json()};};
 try{
  assert.equal((await api('policies')).status,404);assert.equal((await api('policies',b.policies.view())).status,404);assert.equal((await api('policies/preview',command)).status,404);
  const settings=(await api('policies',undefined,true)).body;
  assert.equal((await api('policies',{...settings,mode:'auto_reads'},true)).status,200);
  const preview=await api('policies/preview',command,true);assert.equal(preview.body.action,'allow');assert.equal(calls.length,0);
  const r=(await api('requests',{...command,autoApproved:false,policy:{action:'deny'}})).body;await delay(5);assert.equal(b.requests.get(r.id).autoApproved,true);assert.equal(calls.length,1);
  const audit=await readFile(join(dir,'audit.jsonl'),'utf8');assert.match(audit,/policy_changed/);assert.match(audit,/auto_approved/);assert.ok(!audit.includes('test result'));
 }finally{await b.close();await rm(dir,{recursive:true});}
});

test('automatic commands respect reviewed-output defaults and database operations remain manual',async()=>{
 let notifications=0;const {broker:b,calls}=fixture({notify:()=>{notifications++;}});
 try{
  await save(b.policies,{mode:'auto_reads',defaultDelivery:'review'});
  const r=await b.submit(command);await delay(5);assert.equal(b.requests.get(r.id).status,'awaiting_review');assert.equal(b.public(b.requests.get(r.id)).result,undefined);assert.equal(notifications,1);assert.equal(calls.length,1);
  await b.release(r.id,{decision:'send',stdout:'reviewed',stderr:''});assert.equal(b.requests.get(r.id).result.stdout,'reviewed');
  const connection=await b.databases.save({name:'test',engine:'postgres',profile:'dev',region:'us-east-1',host:'example.rds.amazonaws.com',instanceId:'i-0123456789abcdef0',database:'app',username:'reader',password:'TEST_ONLY'});
  const tunnel=await b.submit({kind:'tunnel',connectionId:connection.id,reason:'Tunnel test'});assert.equal(tunnel.status,'pending');
  const query=await b.submit({kind:'sql',connectionId:connection.id,sql:'SELECT 1',reason:'Query test'});assert.equal(query.status,'pending');assert.equal(calls.length,1);
 }finally{await b.close();}
});
