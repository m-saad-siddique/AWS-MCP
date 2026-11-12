import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { setTimeout as delay } from 'node:timers/promises';
import { TunnelManager } from '../src/tunnel.js';
const c={id:'test',profile:'dev',region:'us-east-1',instanceId:'i-0123456789abcdef0',host:'example.rds.amazonaws.com',port:5432};
test('managed tunnel passes exact remote forwarding arguments, stays open, and closes on expiry',async()=>{
 const dir=await mkdtemp(join(tmpdir(),'ssm-tunnel-')); const script=join(dir,'plugin.mjs');
 await writeFile(script,`import net from 'node:net';const p=JSON.parse(process.argv[process.argv.indexOf('--parameters')+1]);net.createServer(s=>s.end()).listen(Number(p.localPortNumber[0]),'127.0.0.1',()=>console.log('Port '+p.localPortNumber[0]+' opened for sessionId test'));`);
 let call;
 const tunnels=new TunnelManager({idleMs:100,aws:{context:async()=>({p:{name:'dev'},base:{PATH:process.env.PATH},session:{env:{AWS_ACCESS_KEY_ID:'TEST_SESSION'}}})},spawnProcess:(bin,args,opts)=>{call={bin,args,opts};return spawn(process.execPath,[script,...args],opts);}});
 try{
  const result=await tunnels.open(c); assert.ok(result.localPort>0);assert.equal(tunnels.status(c.id).status,'open');assert.equal(call.opts.shell,false);
  const parameters=JSON.parse(call.args[call.args.indexOf('--parameters')+1]);assert.deepEqual(parameters.host,[c.host]);assert.deepEqual(parameters.portNumber,['5432']);assert.ok(!call.args.includes('--profile'));assert.equal(call.opts.env.AWS_ACCESS_KEY_ID,'TEST_SESSION');assert.ok(!JSON.stringify(result).includes('TEST_SESSION'));
  await assert.rejects(tunnels.open(c),/already exists/);
  await delay(150);assert.equal(tunnels.status(c.id).status,'closed');assert.throws(()=>tunnels.getPort(c.id),/No open tunnel/);
 }finally{tunnels.closeAll();await delay(50);await rm(dir,{recursive:true});}
});
test('canceling during authentication prevents a tunnel subprocess from starting',async()=>{
 let release,spawned=false;const signal=new AbortController();
 const tunnels=new TunnelManager({aws:{context:()=>new Promise(resolve=>{release=()=>resolve({p:{name:'dev'},base:{}});})},spawnProcess:()=>{spawned=true;throw new Error('should not spawn');}});
 const opening=tunnels.open(c,{signal:signal.signal});signal.abort();release();await assert.rejects(opening,/canceled/);assert.equal(spawned,false);assert.equal(tunnels.status(c.id).status,'closed');
});
