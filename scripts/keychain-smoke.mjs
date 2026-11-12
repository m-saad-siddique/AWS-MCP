// Uses only the app's isolated TEST service and synthetic credentials; never reads AWS data.
import assert from 'node:assert/strict';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {MfaSessionCache,profileFingerprint} from '../src/mfa-sessions.js';
import { MacKeychainStore } from '../src/keychain.js';
const store=new MacKeychainStore({stateDir:new URL('../.runtime/',import.meta.url).pathname,service:'com.aws-approval-mcp.mfa-sessions.test',interactive:false});
const value=[{profile:'TEST_ONLY',expires:Date.now()+3600000,env:{AWS_ACCESS_KEY_ID:'TEST_ONLY_ACCESS',AWS_SECRET_ACCESS_KEY:'TEST_ONLY_SECRET',AWS_SESSION_TOKEN:'TEST_ONLY_TOKEN'}}];
try{
 await store.write(value);assert.deepEqual(await store.read(),value);
 await store.write([{...value[0],expires:value[0].expires+1000}]);assert.equal((await store.read())[0].expires,value[0].expires+1000);
 await store.remove();assert.deepEqual(await store.read(),[]);
 const dir=await mkdtemp(join(tmpdir(),'mfa-native-'));const isolated=new MacKeychainStore({stateDir:dir,service:'com.aws-approval-mcp.mfa-sessions.test',interactive:false});
 try{const p={name:'TEST_ONLY',mfaSerial:'arn:aws:iam::000000000000:mfa/test'};const cache=new MfaSessionCache({store:isolated});await cache.init(dir,[p]);await cache.put(p.name,{...value[0],fingerprint:profileFingerprint(p),serial:p.mfaSerial});await cache.close();const restored=new MfaSessionCache({store:isolated});await restored.init(dir,[p]);assert.equal(restored.valid(p.name).env.AWS_SESSION_TOKEN,'TEST_ONLY_TOKEN');assert.equal(restored.status([p]).sessions[0].restored,true);await restored.forget();await restored.close();}finally{await isolated.remove().catch(()=>{});await rm(dir,{recursive:true,force:true});}
 console.log('Native macOS Keychain passed: real saved-session restoration after restart, write, read, update, delete. Only synthetic test credentials were used; no AWS calls or existing credentials were accessed.');
}finally{await store.remove().catch(()=>{});}
