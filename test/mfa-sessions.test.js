import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { MfaSessionCache, profileFingerprint } from '../src/mfa-sessions.js';
import { AwsRunner, readProfiles } from '../src/aws.js';
import { Broker } from '../src/broker.js';
const profile={name:'dev',region:'us-east-1',mfaSerial:'arn:aws:iam::123456789012:mfa/dev'};
const credentials=(now=Date.now())=>({fingerprint:profileFingerprint(profile),serial:profile.mfaSerial,expires:now+3600000,env:{AWS_ACCESS_KEY_ID:'TEST_ACCESS',AWS_SECRET_ACCESS_KEY:'TEST_SECRET',AWS_SESSION_TOKEN:'TEST_TOKEN'}});
class FakeStore {
 available=true;records=[];failWrite=false;failRead=false;failRemove=false;
 async read(){if(this.failRead)throw new Error('locked');return structuredClone(this.records);}
 async write(rows){if(this.failWrite)throw new Error('locked');this.records=structuredClone(rows);}
 async remove(){if(this.failRemove)throw new Error('locked');this.records=[];}
}
async function fixture(){const dir=await mkdtemp(join(tmpdir(),'mfa-cache-')),store=new FakeStore(),cache=new MfaSessionCache({store});await cache.init(dir,[profile]);return {dir,store,cache,cleanup:async()=>{await cache.close();await rm(dir,{recursive:true,force:true});}};}
test('saved MFA sessions survive restart using Keychain data, with no credentials in metadata or status',async()=>{
 const f=await fixture();try{
  await f.cache.put('dev',credentials());
  const metadata=await readFile(join(f.dir,'mfa-sessions.json'),'utf8');
  for(const value of ['TEST_ACCESS','TEST_SECRET','TEST_TOKEN','AWS_SECRET_ACCESS_KEY','654321'])assert.ok(!metadata.includes(value));
  assert.equal(f.cache.status([profile]).sessions[0].storage,'keychain');
  const status=JSON.stringify(f.cache.status([profile]));assert.ok(!status.includes('TEST_SECRET'));assert.ok(!status.includes('fingerprint'));assert.ok(!status.includes('env'));
  await f.cache.close();const restored=new MfaSessionCache({store:f.store});await restored.init(f.dir,[profile]);
  assert.equal(restored.valid('dev',profileFingerprint(profile)).env.AWS_SESSION_TOKEN,'TEST_TOKEN');assert.equal(restored.status([profile]).sessions[0].restored,true);await restored.close();
 }finally{await f.cleanup();}
});
test('expiry and changed profile identity prevent reuse and permanently remove stale restore references',async()=>{
 const f=await fixture();try{
  await f.cache.put('dev',credentials());const other={...profile,roleArn:'arn:aws:iam::123456789012:role/other'};
  assert.equal(f.cache.valid('dev',profileFingerprint(other)),undefined);
  const changed=new MfaSessionCache({store:f.store});await changed.init(f.dir,[other]);assert.equal(changed.sessions.size,0);await changed.close();
  const reverted=new MfaSessionCache({store:f.store});await reverted.init(f.dir,[profile]);assert.equal(reverted.sessions.size,0);await reverted.close();
  await f.cache.put('dev',credentials());const future=new MfaSessionCache({store:f.store,now:()=>Date.now()+3600001});await future.init(f.dir,[profile]);assert.equal(future.sessions.size,0);assert.equal(f.store.records.length,0);await future.close();
 }finally{await f.cleanup();}
});
test('memory-only preference and disabling persistence keep active credentials usable without restoring them',async()=>{
 const f=await fixture();try{
  await f.cache.put('dev',credentials(),{remember:false});assert.equal(f.cache.status([profile]).sessions[0].storage,'memory');assert.equal(f.store.records.length,0);
  await f.cache.saveActive();assert.equal(f.cache.status([profile]).sessions[0].storage,'keychain');
  await f.cache.setRemember(false);assert.ok(f.cache.valid('dev'));assert.equal(f.store.records.length,0);assert.equal(f.cache.status([profile]).sessions[0].storage,'memory');
  const restored=new MfaSessionCache({store:f.store});await restored.init(f.dir,[profile]);assert.equal(restored.sessions.size,0);assert.equal(restored.remember,false);await restored.close();
 }finally{await f.cleanup();}
});
test('forgetting one or all sessions deletes both active credentials and eligible restore entries',async()=>{
 const f=await fixture();try{
  await f.cache.put('dev',credentials());await f.cache.forget('dev');assert.equal(f.cache.sessions.size,0);assert.equal(f.store.records.length,0);
  const restored=new MfaSessionCache({store:f.store});await restored.init(f.dir,[profile]);assert.equal(restored.sessions.size,0);await restored.close();
  await f.cache.put('dev',credentials());await f.cache.forget();assert.equal(f.cache.sessions.size,0);assert.equal(f.store.records.length,0);
 }finally{await f.cleanup();}
});
test('a failed Keychain deletion cannot resurrect a forgotten session after restart',async()=>{
 const f=await fixture();try{
  await f.cache.put('dev',credentials());f.store.failRemove=true;await assert.rejects(f.cache.forget(),/cleared locally/);assert.equal(f.cache.sessions.size,0);assert.equal(f.store.records.length,1);
  const restored=new MfaSessionCache({store:f.store});await restored.init(f.dir,[profile]);assert.equal(restored.sessions.size,0);await restored.close();
 }finally{await f.cleanup();}
});
test('Keychain save errors preserve the approved session in memory and do not restore stale older credentials',async()=>{
 const f=await fixture();try{
  await f.cache.put('dev',credentials());f.store.failWrite=true;await f.cache.put('dev',{...credentials(),env:{...credentials().env,AWS_SESSION_TOKEN:'NEW_TEST_TOKEN'}});
  assert.equal(f.cache.valid('dev').env.AWS_SESSION_TOKEN,'NEW_TEST_TOKEN');assert.equal(f.cache.status([profile]).sessions[0].storage,'memory');assert.match(f.cache.warning,/saving failed/);
  const restored=new MfaSessionCache({store:f.store});await restored.init(f.dir,[profile]);assert.equal(restored.sessions.size,0);await restored.close();
 }finally{await f.cleanup();}
});
test('MFA authentication started before Clear cannot save credentials or execute the AWS command afterward',async()=>{
 const f=await fixture();let resolveAuth,authStarted=false,executions=0;
 const runner=new AwsRunner({profiles:async()=>[profile],sessionCache:f.cache,run:async(args)=>{if(args[1]==='get-session-token'){authStarted=true;return new Promise(resolve=>{resolveAuth=()=>resolve({exitCode:0,stdout:JSON.stringify({Credentials:{AccessKeyId:'TEST_ACCESS',SecretAccessKey:'TEST_SECRET',SessionToken:'TEST_TOKEN',Expiration:new Date(Date.now()+3600000).toISOString()}})});});}executions++;return {exitCode:0,stdout:'ok',stderr:''};}});
 try{
  const command=runner.execute({profile:'dev',args:['sts','get-caller-identity']},{mfaCode:'654321'});while(!authStarted)await new Promise(resolve=>setTimeout(resolve,1));await runner.clearSessions();resolveAuth();await assert.rejects(command,/changed during authentication/);assert.equal(executions,0);assert.equal(f.cache.sessions.size,0);assert.equal(f.store.records.length,0);
 }finally{await f.cleanup();}
});
test('restored credentials skip MFA authentication but still run the approved command with the selected session',async()=>{
 const f=await fixture();try{
  await f.cache.put('dev',credentials());await f.cache.close();const restored=new MfaSessionCache({store:f.store});await restored.init(f.dir,[profile]);const calls=[];
  const runner=new AwsRunner({sessionCache:restored,profiles:async()=>[profile],run:async(args,opts)=>{calls.push({args,opts});return {exitCode:0,stdout:'ok',stderr:''};}});
  assert.equal(runner.hasSession('dev',profile),true);await runner.execute({profile:'dev',args:['sts','get-caller-identity']});assert.equal(calls.length,1);assert.equal(calls[0].args[1],'get-caller-identity');assert.equal(calls[0].opts.env.AWS_SESSION_TOKEN,'TEST_TOKEN');assert.ok(!calls[0].args.includes('--profile'));await runner.close();
 }finally{await f.cleanup();}
});
test('session API is operator-only, exposes metadata only, and never returns profile credential fingerprints',async()=>{
 const dir=await mkdtemp(join(tmpdir(),'mfa-api-')),cache=new MfaSessionCache({store:new FakeStore()});
 const runner=new AwsRunner({profiles:async()=>[{...profile,_authFingerprint:'INTERNAL_HASH'}],sessionCache:cache,run:async()=>{throw new Error('No AWS command expected');}});
 const b=await new Broker({profiles:runner.profiles,runner}).listen({stateDir:dir});
 const call=async(path,body,operator=false)=>{const res=await fetch(b.origin+'/api/'+path,{method:body?'POST':'GET',headers:{Authorization:'Bearer '+(operator?b.approvalToken:b.agentToken),'Content-Type':'application/json'},body:body?JSON.stringify(body):undefined});return {status:res.status,body:await res.json()};};
 try{
  await cache.put('dev',{...credentials(),fingerprint:profileFingerprint({...profile,_authFingerprint:'INTERNAL_HASH'})});
  assert.equal((await call('sessions')).status,404);assert.equal((await call('sessions/settings',{rememberAcrossRestarts:false})).status,404);assert.equal((await call('sessions/clear',{})).status,404);
  const status=await call('sessions',undefined,true);assert.equal(status.body.sessions[0].status,'active');assert.ok(!JSON.stringify(status.body).includes('TEST_SECRET'));assert.ok(!JSON.stringify((await call('profiles')).body).includes('INTERNAL_HASH'));
  await call('sessions/clear',{profile:'dev'},true);assert.equal(runner.hasSession('dev'),false);
 }finally{await b.close();await rm(dir,{recursive:true,force:true});}
});

test('expiry cleanup drops active credentials and saved restore references before AWS expiration',async()=>{
 const dir=await mkdtemp(join(tmpdir(),'mfa-expiry-')),store=new FakeStore();let now=100000;
 const cache=new MfaSessionCache({store,now:()=>now});await cache.init(dir,[profile]);
 try{await cache.put('dev',credentials(now));now+=3600000-30000;assert.equal(cache.valid('dev'),undefined);await cache.prune([profile]);assert.equal(cache.sessions.size,0);assert.equal(store.records.length,0);assert.equal(cache.status([profile]).sessions[0].status,'expired');assert.deepEqual(JSON.parse(await readFile(join(dir,'mfa-sessions.json'),'utf8')).saved,[]);}finally{await cache.close();await rm(dir,{recursive:true,force:true});}
});
test('rotating source-profile credentials changes the role fingerprint without exposing key material',async()=>{
 const dir=await mkdtemp(join(tmpdir(),'mfa-profile-')),config=join(dir,'config'),creds=join(dir,'credentials');
 try{await writeFile(config,'[profile role]\nrole_arn=arn:aws:iam::123456789012:role/test\nsource_profile=base\nmfa_serial=arn:aws:iam::123456789012:mfa/test\n');await writeFile(creds,'[base]\naws_access_key_id=TEST_ACCESS_ONE\naws_secret_access_key=TEST_SECRET_ONE\n');
  const before=(await readProfiles({AWS_CONFIG_FILE:config,AWS_SHARED_CREDENTIALS_FILE:creds})).find(p=>p.name==='role');
  await writeFile(creds,'[base]\naws_access_key_id=TEST_ACCESS_TWO\naws_secret_access_key=TEST_SECRET_TWO\n');const after=(await readProfiles({AWS_CONFIG_FILE:config,AWS_SHARED_CREDENTIALS_FILE:creds})).find(p=>p.name==='role');
  assert.notEqual(profileFingerprint(before),profileFingerprint(after));assert.ok(!JSON.stringify(before).includes('TEST_SECRET'));assert.ok(!JSON.stringify(after).includes('TEST_ACCESS'));
 }finally{await rm(dir,{recursive:true,force:true});}
});
