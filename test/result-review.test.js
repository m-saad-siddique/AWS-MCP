import test from 'node:test';
import assert from 'node:assert/strict';
import { setTimeout as delay } from 'node:timers/promises';
import { Broker, isTerminal } from '../src/broker.js';
const command = {profile:'dev',args:['sts','get-caller-identity'],reason:'Test result delivery'};
function make({result={exitCode:0,stdout:'{"Account":"PRIVATE_ACCOUNT"}',stderr:'PRIVATE_ERROR'},failure,...options}={}) {
 return new Broker({profiles:async()=>[{name:'dev'}],runner:{execute:async()=>{if(failure)throw new Error(failure);return result;},clearSessions(){}},...options});
}
const wait=async()=>delay(10);
test('operator-selected review keeps unreleased stdout and stderr out of agent views',async()=>{
 const b=make();try{
  const r=await b.submit({...command,deliveryMode:'direct'}); // Agents cannot select their own delivery mode.
  await b.decide(r.id,{decision:'approve',deliveryMode:'review'});await wait();
  const stored=b.requests.get(r.id);assert.equal(stored.deliveryMode,'review');assert.equal(stored.status,'awaiting_review');assert.equal(isTerminal(stored.status),false);
  assert.equal(stored.result,undefined);assert.equal(b.public(stored).heldResult,undefined);
  assert.ok(!JSON.stringify(b.public(stored)).includes('PRIVATE_'));
  const operator=b.public(stored,{operator:true});assert.match(operator.heldResult.stdout,/PRIVATE_ACCOUNT/);assert.match(operator.heldResult.stderr,/PRIVATE_ERROR/);
  const released=await b.release(r.id,{decision:'send',stdout:'{"Account":"[MASKED]"}',stderr:'[MASKED]'});
  assert.equal(released.status,'completed');assert.equal(released.outputReviewed,true);assert.equal(b.heldResults.size,0);
  assert.ok(!JSON.stringify(b.public(stored)).includes('PRIVATE_'));assert.match(b.public(stored).result.stdout,/MASKED/);
  await assert.rejects(b.release(r.id,{decision:'send',stdout:'again',stderr:''}),/no longer/);
 }finally{await b.close();}
});
test('direct delivery is enabled by default and the agent cannot override it',async()=>{
 const b=make();try{const r=await b.submit({...command,deliveryMode:'review'});await b.decide(r.id,{decision:'approve'});await wait();const view=b.public(b.requests.get(r.id));assert.equal(view.status,'completed');assert.match(view.result.stdout,/PRIVATE_ACCOUNT/);assert.equal(b.heldResults.size,0);}finally{await b.close();}
});
test('failed commands and thrown errors are held too; release preserves the real exit code',async()=>{
 for(const opts of [{result:{exitCode:7,stdout:'PRIVATE_OUT',stderr:'PRIVATE_ERR'}},{failure:'PRIVATE_FAILURE'}]){
  const b=make(opts);try{const r=await b.submit(command);await b.decide(r.id,{decision:'approve',deliveryMode:'review'});await wait();const view=b.public(b.requests.get(r.id));assert.equal(view.status,'awaiting_review');assert.ok(!JSON.stringify(view).includes('PRIVATE_'));
   const original=b.public(b.requests.get(r.id),{operator:true}).heldResult;
   const released=await b.release(r.id,{decision:'send',stdout:'clean',stderr:'clean error',exitCode:0});assert.equal(released.status,'failed');assert.equal(released.result.exitCode,original.exitCode);
  }finally{await b.close();}
 }
});
test('withholding or canceling a held result never publishes it',async()=>{
 for(const action of ['withhold','cancel']){
  const b=make();try{const r=await b.submit(command);await b.decide(r.id,{decision:'approve',deliveryMode:'review'});await wait();
   const final=action==='withhold'?await b.release(r.id,{decision:'withhold'}):await b.cancel(r.id);
   assert.equal(final.status,action==='withhold'?'withheld':'canceled');assert.equal(isTerminal(final.status),true);assert.equal(final.result,undefined);assert.equal(b.heldResults.size,0);assert.ok(!JSON.stringify(final).includes('PRIVATE_'));
  }finally{await b.close();}
 }
});
test('HTTP agent token cannot fetch held output, release it, or trick cancellation into exposing it',async()=>{
 const b=await make().listen();
 const call=async(path,{body,operator=false}={})=>{const res=await fetch(b.origin+'/api/'+path,{method:body?'POST':'GET',headers:{Authorization:'Bearer '+(operator?b.approvalToken:b.agentToken),'Content-Type':'application/json'},body:body?JSON.stringify(body):undefined});return {status:res.status,body:await res.json()};};
 try{
  const r=(await call('requests',{body:command})).body;
  await call(`requests/${r.id}/decision`,{operator:true,body:{decision:'approve',deliveryMode:'review'}});await wait();
  const held=await call(`requests/${r.id}`);assert.equal(held.body.status,'awaiting_review');assert.ok(!JSON.stringify(held.body).includes('PRIVATE_'));
  assert.ok(JSON.stringify((await call(`requests/${r.id}`,{operator:true})).body).includes('PRIVATE_ACCOUNT'));
  assert.equal((await call(`requests/${r.id}/release`,{body:{decision:'send',stdout:'bad',stderr:''}})).status,403);
  assert.equal((await call('requests')).status,404);
  const final=await call(`requests/${r.id}/release`,{operator:true,body:{decision:'send',stdout:'safe output',stderr:'safe error'}});assert.equal(final.status,200);
  assert.equal((await call(`requests/${r.id}`)).body.result.stdout,'safe output');
  const large=(await call('requests',{body:command})).body;
  await call(`requests/${large.id}/decision`,{operator:true,body:{decision:'approve',deliveryMode:'review'}});await wait();
  const unicode='Reviewed name: مثال 👋\n'.repeat(12000);
  const largeSend=await call(`requests/${large.id}/release`,{operator:true,body:{decision:'send',stdout:unicode,stderr:''}});
  assert.equal(largeSend.status,200);assert.equal((await call(`requests/${large.id}`)).body.result.stdout,unicode);
 }finally{await b.close();}
});
test('release audit failure fails closed and concurrent cancellation wins over release',async()=>{
 const b=make();try{
  const r=await b.submit(command);await b.decide(r.id,{decision:'approve',deliveryMode:'review'});await wait();
  b.audit=async()=>{throw new Error('disk unavailable');};
  await assert.rejects(b.release(r.id,{decision:'send',stdout:'safe',stderr:''}),/No result was sent/);assert.equal(b.requests.get(r.id).status,'awaiting_review');assert.equal(b.public(b.requests.get(r.id)).result,undefined);
  let allow;
  b.audit=async(_,event)=>{if(event==='result_released')await new Promise(resolve=>{allow=resolve;});};
  const release=b.release(r.id,{decision:'send',stdout:'safe',stderr:''});
  await assert.rejects(b.release(r.id,{decision:'send',stdout:'duplicate',stderr:''}),/no longer/);
  await b.cancel(r.id);allow();const final=await release;assert.equal(final.status,'canceled');assert.equal(final.result,undefined);assert.equal(b.heldResults.size,0);
 }finally{await b.close();}
});
test('large edited outputs are rejected and known credential fields remain redacted on release',async()=>{
 const b=make();try{const r=await b.submit(command);await b.decide(r.id,{decision:'approve',deliveryMode:'review'});await wait();
  await assert.rejects(b.release(r.id,{decision:'send',stdout:'x'.repeat(2*1024*1024+1),stderr:''}),/2 MiB/);
  const result=await b.release(r.id,{decision:'send',stdout:'{"SecretAccessKey":"SHOULD_NOT_BE_SENT"}',stderr:''});assert.ok(!result.result.stdout.includes('SHOULD_NOT_BE_SENT'));
 }finally{await b.close();}
});
