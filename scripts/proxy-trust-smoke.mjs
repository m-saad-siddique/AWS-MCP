// Shared real-protocol regression check, using only disposable local databases.
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
export const proxyTestHost='example.proxy-localtest.us-east-1.rds.amazonaws.com';
export async function checkProxyTrust(connection,port,password,caFile){
 const script=`
 import assert from 'node:assert/strict';
 import {runDatabaseQuery} from ${JSON.stringify(new URL('../src/database.js',import.meta.url).href)};
 const c=JSON.parse(process.env.MCP_TLS_SMOKE_CONNECTION),port=Number(process.env.MCP_TLS_SMOKE_PORT),password=process.env.MCP_TLS_SMOKE_PASSWORD;
 const result=await runDatabaseQuery(c,port,password,'SELECT 42 AS answer',[]);
 assert.equal(String(result.rows[0].answer),'42');
 await assert.rejects(runDatabaseQuery({...c,host:'wrong.proxy-localtest.us-east-1.rds.amazonaws.com'},port,password,'SELECT 1',[]),/certificate|altname|Hostname/i);
 await assert.rejects(runDatabaseQuery({...c,host:'example.rds.amazonaws.com'},port,password,'SELECT 1',[]),/certificate|self.signed|issuer|verify/i);
 `;
 await promisify(execFile)(process.execPath,['--input-type=module','-e',script],{env:{...process.env,NODE_EXTRA_CA_CERTS:caFile,NODE_TLS_REJECT_UNAUTHORIZED:'1',MCP_TLS_SMOKE_CONNECTION:JSON.stringify({...connection,host:proxyTestHost}),MCP_TLS_SMOKE_PORT:String(port),MCP_TLS_SMOKE_PASSWORD:password},timeout:45000});
}
