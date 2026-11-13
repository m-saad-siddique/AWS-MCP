import test from 'node:test';
import assert from 'node:assert/strict';
import pg from 'pg';
import {runDatabaseQuery} from '../src/database.js';
const connection={engine:'postgres',host:'example.proxy-test.us-east-1.rds.amazonaws.com',username:'reader',database:'app',readOnly:true};
test('PostgreSQL startup uses proxy-supported parameters and applies a transaction-local timeout after connecting',async t=>{
 const OriginalClient=pg.Client,calls=[];let startup;
 t.mock.method(pg,'Client',function(config){
  const client=new OriginalClient(config);startup=client.getStartupConf();
  client.connect=async()=>{calls.push('connected');};client.end=async()=>{};
  client.query=async(query,values)=>{
   if(typeof query==='string'){calls.push({query,values});return;}
   calls.push('user query');queueMicrotask(()=>{query.emit('row',{answer:42});query.emit('end',{fields:[{name:'answer'}],rowCount:1});});
  };
  return client;
 });
 const result=await runDatabaseQuery(connection,15432,'SYNTHETIC_PASSWORD','SELECT 42 AS answer',[],{timeoutMs:1000});
 const supported=new Set(['user','database','application_name','client_encoding','DateStyle','TimeZone','extra_float_digits','search_path']);
 assert.ok(Object.keys(startup).every(key=>supported.has(key)),JSON.stringify(Object.keys(startup)));
 assert.equal(calls[0],'connected');assert.equal(calls[1].query,'BEGIN READ ONLY');
 assert.match(calls[2].query,/set_config\('statement_timeout', \$1, true\)/);assert.deepEqual(calls[2].values,['1000']);
 assert.equal(calls[3],'user query');assert.equal(calls[4].query,'COMMIT');assert.deepEqual(result.rows,[{answer:42}]);
});
test('the local deadline still closes a stalled PostgreSQL request without retrying it',async t=>{
 const OriginalClient=pg.Client;let destroyed=false,queries=0;
 t.mock.method(pg,'Client',function(config){
  const client=new OriginalClient(config);client.connect=()=>new Promise(()=>{});client.end=async()=>{};
  client.connection.stream.destroy=()=>{destroyed=true;};client.query=()=>{queries++;};return client;
 });
 await assert.rejects(runDatabaseQuery(connection,15432,'SYNTHETIC_PASSWORD','SELECT 1',[],{timeoutMs:30}),/timed out/);
 assert.equal(destroyed,true);assert.equal(queries,0);
});
