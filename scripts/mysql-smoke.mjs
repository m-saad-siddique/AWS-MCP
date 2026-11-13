// Optional MySQL/TLS check using a disposable container; never contacts AWS.
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, readFile, chmod, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { randomUUID } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { runDatabaseQuery } from '../src/database.js';
import {checkProxyTrust,proxyTestHost} from './proxy-trust-smoke.mjs';
const run=promisify(execFile),dir=await mkdtemp(join(tmpdir(),'aws-mcp-mysql-'));
const cert=join(dir,'cert.pem'),key=join(dir,'key.pem'),name='aws-mcp-test-'+randomUUID().slice(0,8);
let created=false;
try{
 await run('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',key,'-out',cert,'-days','1','-subj','/CN=example.rds.amazonaws.com','-addext','subjectAltName=DNS:example.rds.amazonaws.com,DNS:'+proxyTestHost]);
 // Public disposable test key; the container's mysql user must be able to read it.
 await chmod(dir,0o755);await chmod(key,0o644);
 await run('docker',['run','--rm','-d','--name',name,'-e','MYSQL_ROOT_PASSWORD=TEST_ONLY_PASSWORD','-e','MYSQL_ROOT_HOST=%','-e','MYSQL_DATABASE=app','-p','127.0.0.1::3306','--mount',`type=bind,source=${dir},target=/tls,readonly`,'mysql:8.4','--ssl-cert=/tls/cert.pem','--ssl-key=/tls/key.pem']);created=true;
 const binding=(await run('docker',['port',name,'3306/tcp'])).stdout.trim();const port=Number(binding.split(':').at(-1));
 const c={engine:'mysql',host:'example.rds.amazonaws.com',port:3306,database:'app',username:'root',readOnly:true};
 const opts={ca:await readFile(cert,'utf8')};
 let result,last;
 for(let i=0;i<45;i++) {try{result=await runDatabaseQuery(c,port,'TEST_ONLY_PASSWORD','SELECT ? AS answer',[42],opts);break;}catch(e){last=e;await delay(1000);}}
 if(!result)throw last;assert.deepEqual(result.rows,[{answer:42}]);
 await assert.rejects(runDatabaseQuery({...c,host:'wrong.rds.amazonaws.com'},port,'TEST_ONLY_PASSWORD','SELECT 1',[],opts),/certificate|altname|Hostname/i);
 await assert.rejects(runDatabaseQuery(c,port,'TEST_ONLY_PASSWORD','SELECT 1; SELECT 2',[],opts),/syntax|parse/i);
 const writable={...c,readOnly:false};
 await runDatabaseQuery(writable,port,'TEST_ONLY_PASSWORD','CREATE TABLE smoke(id INT)',[],opts);
 await assert.rejects(runDatabaseQuery(c,port,'TEST_ONLY_PASSWORD','INSERT INTO smoke VALUES (8)',[],opts),/read.only|READ ONLY/i);
 const write=await runDatabaseQuery(writable,port,'TEST_ONLY_PASSWORD','INSERT INTO smoke VALUES (?)',[7],opts);assert.equal(write.affectedRows,1);
 const saved=await runDatabaseQuery(c,port,'TEST_ONLY_PASSWORD','SELECT * FROM smoke',[],opts);assert.deepEqual(saved.rows,[{id:7}]);
 const named=await runDatabaseQuery(c,port,'TEST_ONLY_PASSWORD','SELECT 42 AS affectedRows',[],opts);assert.equal(String(named.rows[0].affectedRows),'42');
 const huge=await runDatabaseQuery(c,port,'TEST_ONLY_PASSWORD',"SELECT REPEAT('x',600000) AS value",[],opts);assert.equal(huge.rows.length,0);assert.equal(huge.truncated,true);
 await assert.rejects(runDatabaseQuery(c,port,'TEST_ONLY_PASSWORD','SELECT SLEEP(5)',[],{...opts,timeoutMs:50}),/timed out|timeout/i);
 const abort=new AbortController();const pending=runDatabaseQuery(c,port,'TEST_ONLY_PASSWORD','SELECT SLEEP(5)',[],{...opts,signal:abort.signal});setTimeout(()=>abort.abort(),50);await assert.rejects(pending,/canceled/);
 await checkProxyTrust(c,port,'TEST_ONLY_PASSWORD',cert);
 console.log('MySQL passed: proxy public trust, rejected wrong hostname/direct untrusted CA, verified TLS/hostname through local stream, bound parameters, single-statement enforcement, read-only transaction, write result headers, committed writes, byte limits, timeout, cancellation. No AWS connection used.');
}finally{
 if(created)await run('docker',['rm','-f',name]).catch(()=>{});
 await rm(dir,{recursive:true,force:true});
}
