// Optional real PostgreSQL/TLS integration check. Uses a disposable local cluster only.
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, readFile, chmod, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import net from 'node:net';
import { runDatabaseQuery } from '../src/database.js';
const run=promisify(execFile), dir=await mkdtemp(join(tmpdir(),'aws-mcp-pg-'));
const data=join(dir,'data'), cert=join(dir,'cert.pem'), key=join(dir,'key.pem');
let started=false;
try{
 await run('initdb',['-D',data,'-U','mcp_test','-A','trust','--no-locale']);
 await run('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',key,'-out',cert,'-days','1','-subj','/CN=example.rds.amazonaws.com','-addext','subjectAltName=DNS:example.rds.amazonaws.com']);await chmod(key,0o600);
 const probe=net.createServer();await new Promise(resolve=>probe.listen(0,'127.0.0.1',resolve));const port=probe.address().port;await new Promise(resolve=>probe.close(resolve));
 await run('pg_ctl',['-D',data,'-l',join(dir,'server.log'),'-o',`-h 127.0.0.1 -p ${port} -k ${dir} -c ssl=on -c ssl_cert_file=${cert} -c ssl_key_file=${key}`,'-w','start']);started=true;
 const c={engine:'postgres',host:'example.rds.amazonaws.com',database:'postgres',username:'mcp_test',readOnly:true};
 const opts={ca:await readFile(cert,'utf8')};
 const result=await runDatabaseQuery(c,port,'TEST_ONLY','SELECT $1::int AS answer',[42],opts);assert.deepEqual(result.rows,[{answer:42}]);
 await assert.rejects(runDatabaseQuery({...c,host:'wrong.rds.amazonaws.com'},port,'TEST_ONLY','SELECT 1',[],opts),/certificate|altname|Hostname/i);
 await assert.rejects(runDatabaseQuery(c,port,'TEST_ONLY','SELECT 1; SELECT 2',[],opts),/multiple commands/);
 await assert.rejects(runDatabaseQuery(c,port,'TEST_ONLY','CREATE TABLE denied(id int)',[],opts),/read-only/);
 const limited=await runDatabaseQuery(c,port,'TEST_ONLY','SELECT * FROM generate_series(1,500)',[],opts);assert.equal(limited.rows.length,200);assert.equal(limited.truncated,true);
 const huge=await runDatabaseQuery(c,port,'TEST_ONLY',"SELECT repeat('x',600000) AS value",[],opts);assert.equal(huge.rows.length,0);assert.equal(huge.truncated,true);
 await runDatabaseQuery({...c,readOnly:false},port,'TEST_ONLY','CREATE TABLE smoke(id int)',[],opts);
 const write=await runDatabaseQuery({...c,readOnly:false},port,'TEST_ONLY','INSERT INTO smoke VALUES ($1)',[7],opts);assert.equal(write.affectedRows,1);
 const returning=await runDatabaseQuery({...c,readOnly:false},port,'TEST_ONLY','INSERT INTO smoke SELECT generate_series(10,509) RETURNING id',[],opts);assert.equal(returning.rows.length,200);assert.equal(returning.truncated,true);
 const count=await runDatabaseQuery(c,port,'TEST_ONLY','SELECT count(*)::int AS total FROM smoke',[],opts);assert.equal(count.rows[0].total,501);
 const saved=await runDatabaseQuery(c,port,'TEST_ONLY','SELECT * FROM smoke WHERE id=7',[],opts);assert.deepEqual(saved.rows,[{id:7}]);
 await assert.rejects(runDatabaseQuery(c,port,'TEST_ONLY','SELECT pg_sleep(5)',[],{...opts,timeoutMs:50}),/timed out|statement timeout/);
 const abort=new AbortController();const pending=runDatabaseQuery(c,port,'TEST_ONLY','SELECT pg_sleep(5)',[],{...opts,signal:abort.signal});setTimeout(()=>abort.abort(),50);await assert.rejects(pending,/canceled/);
 console.log('PostgreSQL passed: verified TLS/hostname, bound parameters, one statement, read-only transaction, row/byte limits, committed writes, timeout, cancellation. No AWS connection used.');
}finally{
 if(started)await run('pg_ctl',['-D',data,'-m','immediate','-w','stop']).catch(()=>{});
 await rm(dir,{recursive:true,force:true});
}
