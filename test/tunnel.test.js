import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import net from 'node:net';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { setTimeout as delay } from 'node:timers/promises';
import { TunnelManager, tunnelDiagnostic } from '../src/tunnel.js';
const c={id:'test',profile:'dev',region:'us-east-1',instanceId:'i-0123456789abcdef0',host:'example.rds.amazonaws.com',port:5432};
test('managed tunnel passes exact remote forwarding arguments, stays open, and closes on expiry',async()=>{
 const dir=await mkdtemp(join(tmpdir(),'ssm-tunnel-')); const script=join(dir,'plugin.mjs');
 await writeFile(script,`import net from 'node:net';const p=JSON.parse(process.argv[process.argv.indexOf('--parameters')+1]);net.createServer(s=>s.end()).listen(Number(p.localPortNumber[0]),'127.0.0.1',()=>console.log('Port '+p.localPortNumber[0]+' opened for sessionId test'));`);
 let call;
 const tunnels=new TunnelManager({idleMs:100,aws:{context:async()=>({p:{name:'dev'},base:{PATH:process.env.PATH},session:{env:{AWS_ACCESS_KEY_ID:'TEST_SESSION'}}})},spawnProcess:(bin,args,opts)=>{call={bin,args,opts};return spawn(process.execPath,[script,...args],opts);}});
 try{
  const probe=net.createServer();await new Promise(resolve=>probe.listen(0,'127.0.0.1',resolve));const requested=probe.address().port;await new Promise(resolve=>probe.close(resolve));
  const result=await tunnels.open({...c,localPort:requested});assert.equal(result.localPort,requested); assert.ok(result.localPort>0);assert.equal(tunnels.status(c.id).status,'open');assert.equal(call.opts.shell,false);
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

test('an occupied requested local port fails before starting a second SSM session',async()=>{
 const occupied=net.createServer();await new Promise(resolve=>occupied.listen(0,'127.0.0.1',resolve));let spawned=false;
 const manager=new TunnelManager({aws:{context:async()=>({p:{name:'dev'},base:{}})},spawnProcess:()=>{spawned=true;throw new Error('Unexpected subprocess');}});
 try{await assert.rejects(manager.open({...c,localPort:occupied.address().port}),/already in use/);assert.equal(spawned,false);assert.equal(manager.status(c.id).status,'closed');}finally{manager.closeAll();await new Promise(resolve=>occupied.close(resolve));}
});

test('IPv6-only plugin listeners are detected and their loopback address is retained',async t=>{
 const check=net.createServer();
 try{await new Promise((resolve,reject)=>{check.once('error',reject);check.listen({host:'::1',port:0,ipv6Only:true},resolve);});}catch(e){if(['EAFNOSUPPORT','EADDRNOTAVAIL'].includes(e.code))return t.skip('IPv6 loopback is unavailable');throw e;}
 await new Promise(resolve=>check.close(resolve));
 const dir=await mkdtemp(join(tmpdir(),'ssm-ipv6-')),script=join(dir,'plugin.mjs');
 await writeFile(script,`import net from 'node:net';const p=JSON.parse(process.argv[process.argv.indexOf('--parameters')+1]);net.createServer(s=>s.end()).listen({port:Number(p.localPortNumber[0]),host:'::1',ipv6Only:true},()=>console.log('Port '+p.localPortNumber[0]+' opened for sessionId synthetic'));`);
 const manager=new TunnelManager({startupMs:3000,aws:{context:async()=>({p:{name:'dev'},base:{PATH:process.env.PATH}})},spawnProcess:(bin,args,opts)=>spawn(process.execPath,[script,...args],opts)});
 try{const result=await manager.open(c);assert.equal(result.localHost,'::1');assert.equal(manager.getHost(c.id),'::1');assert.equal(manager.status(c.id).localHost,'::1');}finally{manager.closeAll();await delay(50);await rm(dir,{recursive:true});}
});
test('plugin startup errors survive process exit and redact temporary credentials',async()=>{
 const dir=await mkdtemp(join(tmpdir(),'ssm-failure-')),script=join(dir,'plugin.mjs');
 await writeFile(script,`process.stderr.write('An error occurred (TargetNotConnected) when calling StartSession. '+JSON.stringify({TokenValue:'SYNTHETIC_TOKEN',StreamUrl:'wss://example.invalid/?token=SYNTHETIC_URL_TOKEN',SessionToken:'SYNTHETIC_SESSION_TOKEN'})+' SYNTHETIC_ACCESS_KEY 123456');process.exit(3);`);
 const manager=new TunnelManager({startupMs:2000,aws:{context:async()=>({p:{name:'dev'},base:{PATH:process.env.PATH},session:{env:{AWS_ACCESS_KEY_ID:'SYNTHETIC_ACCESS_KEY',AWS_SESSION_TOKEN:'SYNTHETIC_SESSION_TOKEN'}}})},spawnProcess:(bin,args,opts)=>spawn(process.execPath,[script,...args],opts)});
 try{await assert.rejects(manager.open(c,{mfaCode:'123456'}),e=>{assert.match(e.message,/TargetNotConnected/);assert.match(e.message,/exit code 3/);for(const secret of ['SYNTHETIC_TOKEN','SYNTHETIC_URL_TOKEN','SYNTHETIC_SESSION_TOKEN','SYNTHETIC_ACCESS_KEY','123456'])assert.ok(!e.message.includes(secret));return true;});assert.equal(manager.status(c.id).status,'closed');}finally{manager.closeAll();await delay(50);await rm(dir,{recursive:true});}
});
test('a live but stalled plugin reports bounded startup output on timeout',async()=>{
 const dir=await mkdtemp(join(tmpdir(),'ssm-stalled-')),script=join(dir,'plugin.mjs');
 await writeFile(script,`console.log('Starting session: websocket handshake pending');setInterval(()=>{},1000);`);
 const manager=new TunnelManager({startupMs:400,aws:{context:async()=>({p:{name:'dev'},base:{PATH:process.env.PATH}})},spawnProcess:(bin,args,opts)=>spawn(process.execPath,[script,...args],opts)});
 try{await assert.rejects(manager.open(c),/did not confirm.*[\s\S]*websocket handshake pending/);assert.equal(manager.status(c.id).status,'closed');}finally{manager.closeAll();await delay(50);await rm(dir,{recursive:true});}
});
test('an unrelated port announcement cannot mark a tunnel ready',async()=>{
 const dir=await mkdtemp(join(tmpdir(),'ssm-wrong-port-')),script=join(dir,'plugin.mjs');let probed=false;
 await writeFile(script,`console.log('Port 9 opened for sessionId synthetic');setInterval(()=>{},1000);`);
 const manager=new TunnelManager({startupMs:400,probe:async()=>{probed=true;return true;},aws:{context:async()=>({p:{name:'dev'},base:{PATH:process.env.PATH}})},spawnProcess:(bin,args,opts)=>spawn(process.execPath,[script,...args],opts)});
 try{await assert.rejects(manager.open(c),/did not confirm opening the requested/);assert.equal(probed,false);}finally{manager.closeAll();await delay(50);await rm(dir,{recursive:true});}
});

test('diagnostics redact incomplete session tokens and strip terminal controls',()=>{
 const value=tunnelDiagnostic('\u001b[31mfailed\u001b[0m {"TokenValue":"PARTIAL_SECRET');assert.ok(value.includes('failed'));assert.ok(!value.includes('PARTIAL_SECRET'));assert.ok(!value.includes('\u001b'));
});
