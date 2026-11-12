import { createHash, randomUUID } from 'node:crypto';
import { readFile, writeFile, rename } from 'node:fs/promises';
import { join } from 'node:path';
import { MacKeychainStore } from './keychain.js';
export function profileFingerprint(p) {
  return createHash('sha256').update(JSON.stringify({name:p.name,auth:p._authFingerprint||'',roleArn:p.roleArn||'',sourceProfile:p.sourceProfile||'',mfaSerial:p.mfaSerial||'',sso:!!p.sso,credentialProcess:!!p.credentialProcess,externalId:p.externalId||'',roleSessionName:p.roleSessionName||''})).digest('hex');
}
const validEnv=env=>env&&['AWS_ACCESS_KEY_ID','AWS_SECRET_ACCESS_KEY','AWS_SESSION_TOKEN'].every(key=>typeof env[key]==='string'&&env[key].length>0&&env[key].length<32768);
export class MfaSessionCache {
  constructor({store,now=Date.now}={}) {
    this.store=store;this.now=now;this.sessions=new Map();this.saved=new Map();this.savedIds=new Set();this.remember=true;this.generation=0;this.profileGenerations=new Map();this.queue=Promise.resolve();this.expired=new Map();this.warning='';this.keychainMayExist=false;
  }
  epoch(profile){return `${this.generation}:${this.profileGenerations.get(profile)||0}`;}
  async init(stateDir,profiles) {
    this.file=stateDir?join(stateDir,'mfa-sessions.json'):undefined;
    this.store ||= new MacKeychainStore({stateDir});
    if(!this.file)return;
    let metadata;
    try{metadata=JSON.parse(await readFile(this.file,'utf8'));}catch(e){if(e.code!=='ENOENT')this.warning='Saved MFA metadata could not be loaded. Authenticate again; no credentials were restored.';return;}
    this.remember=metadata.remember!==false;this.keychainMayExist=metadata.keychainMayExist===true||(Array.isArray(metadata.saved)&&metadata.saved.length>0);
    // The index is an allowlist: stale Keychain data cannot restore a forgotten session.
    if(!this.remember||!Array.isArray(metadata.saved)||!metadata.saved.length){if(this.keychainMayExist)try{await this.sync();}catch{this.warning='Forgotten sessions remain in Keychain pending cleanup. They will not be restored; unlock Keychain and retry clearing.';}return;}
    const eligible=metadata.saved.filter(row=>typeof row.profile==='string'&&typeof row.id==='string'&&row.expires>this.now()+60000&&profiles.some(p=>p.name===row.profile&&profileFingerprint(p)===row.fingerprint));
    if(!eligible.length){try{await this.sync();}catch{this.warning='Expired or changed-profile sessions were ignored; Keychain cleanup needs attention.';}return;}
    if(!this.store.available){this.warning='Keychain is unavailable. Saved MFA sessions were not restored.';return;}
    try{
      const records=await this.store.read();if(!Array.isArray(records))throw new Error('Invalid saved MFA sessions.');
      for(const row of eligible){
        const item=records.find(record=>record.id===row.id&&record.profile===row.profile&&record.fingerprint===row.fingerprint&&record.expires===row.expires);
        if(!item||!validEnv(item.env))continue;
        const record={id:item.id,profile:item.profile,fingerprint:item.fingerprint,expires:item.expires,serial:typeof item.serial==='string'?item.serial:'',env:{AWS_ACCESS_KEY_ID:item.env.AWS_ACCESS_KEY_ID,AWS_SECRET_ACCESS_KEY:item.env.AWS_SECRET_ACCESS_KEY,AWS_SESSION_TOKEN:item.env.AWS_SESSION_TOKEN},restored:true};
        this.sessions.set(record.profile,record);this.saved.set(record.profile,record);this.savedIds.add(record.id);
      }
      if(metadata.saved.length!==this.saved.size||metadata.saved.some(row=>!this.savedIds.has(row.id)))await this.sync();
    }catch{this.warning='Saved MFA sessions could not be restored from Keychain. Unlock your login Keychain or authenticate again.';}
  }
  valid(profile,fingerprint){const s=this.sessions.get(profile);return s&&s.expires>this.now()+60000&&(!fingerprint||s.fingerprint===fingerprint)?s:undefined;}
  serial(task){const operation=this.queue.catch(()=>{}).then(task);this.queue=operation.catch(()=>{});return operation;}
  async writeMetadata(){if(this.file){const data={version:1,remember:this.remember,keychainMayExist:this.keychainMayExist||this.saved.size>0,saved:[...this.saved.values()].map(({id,profile,fingerprint,expires,serial})=>({id,profile,fingerprint,expires,serial}))};await writeFile(this.file+'.tmp',JSON.stringify(data,null,2),{mode:0o600});await rename(this.file+'.tmp',this.file);}}
  async sync({interactive=false}={}){
    // Invalidate old Keychain entries durably BEFORE trying to replace/delete them.
    await this.writeMetadata();
    if(!this.store?.available){if(this.saved.size||this.keychainMayExist)throw new Error('Keychain is unavailable.');return;}
    if(this.saved.size){this.keychainMayExist=true;await this.store.write([...this.saved.values()].map(({restored,...record})=>record),{interactive});}else if(this.keychainMayExist){await this.store.remove();this.keychainMayExist=false;await this.writeMetadata();}
    this.savedIds=new Set([...this.saved.values()].map(s=>s.id));this.warning='';
  }
  async put(profile,credentials,{remember=true,epoch=this.epoch(profile)}={}) {
    if(epoch!==this.epoch(profile))throw new Error('MFA sessions changed during authentication. Submit a new request.');
    if(!validEnv(credentials.env)||!Number.isFinite(credentials.expires)||credentials.expires<=this.now()+60000)throw new Error('STS returned expired or incomplete credentials.');
    const record={...credentials,profile,id:randomUUID(),restored:false};
    this.sessions.set(profile,record);this.expired.delete(profile);
    await this.serial(async()=>{
      if(epoch!==this.epoch(profile))throw new Error('MFA session was cleared during authentication.');
      if(remember&&this.remember&&this.store?.available&&this.file)this.saved.set(profile,record);else this.saved.delete(profile);
      try{if(this.file)await this.sync({interactive:true});}catch{this.savedIds.delete(record.id);this.warning='MFA is active in memory, but Keychain saving failed. It may need to be entered again after restart.';}
    });
    if(epoch!==this.epoch(profile))throw new Error('MFA session was cleared during authentication.');
    return record;
  }
  async forget(profile) {
    if(profile){this.profileGenerations.set(profile,(this.profileGenerations.get(profile)||0)+1);this.sessions.delete(profile);this.expired.delete(profile);}
    else{this.generation++;this.sessions.clear();this.expired.clear();}
    return this.serial(async()=>{
      if(profile)this.saved.delete(profile);else this.saved.clear();
      this.savedIds=new Set([...this.saved.values()].map(s=>s.id).filter(id=>this.savedIds.has(id)));
      try{await this.sync();}catch{this.warning='Sessions were cleared locally, but secure-store cleanup failed. Retry after unlocking Keychain.';throw new Error(this.warning);}
    });
  }
  async saveActive(){return this.serial(async()=>{if(!this.remember)throw new Error('Enable remembering MFA sessions first.');for(const s of this.sessions.values())if(s.expires>this.now()+60000)this.saved.set(s.profile,s);await this.sync({interactive:true});});}
  async setRemember(value){
    if(typeof value!=='boolean')throw new Error('Choose whether to remember MFA sessions.');
    return this.serial(async()=>{this.remember=value;if(!value){this.saved.clear();this.savedIds.clear();}else for(const s of this.sessions.values())if(s.expires>this.now()+60000)this.saved.set(s.profile,s);try{await this.sync({interactive:value});}catch{this.warning='The MFA storage setting or Keychain cleanup could not be completed.';throw new Error(this.warning);}});
  }
  async prune(profiles){
    const stale=[...this.sessions.values()].filter(s=>s.expires<=this.now()+60000||!profiles.some(p=>p.name===s.profile&&profileFingerprint(p)===s.fingerprint));
    if(!stale.length)return;
    for(const s of stale){this.sessions.delete(s.profile);this.saved.delete(s.profile);this.savedIds.delete(s.id);if(s.expires<=this.now()+60000)this.expired.set(s.profile,s.expires);}
    await this.serial(async()=>{try{await this.sync();}catch{this.warning='Expired sessions are not reused; Keychain cleanup needs attention.';}});
  }
  status(profiles){return {rememberAcrossRestarts:this.remember,storage:this.store?.available?'keychain':'memory',warning:this.warning,sessions:profiles.map(p=>{const s=this.valid(p.name,profileFingerprint(p));return {profile:p.name,status:s?'active':p.sso?'aws_cli':this.expired.has(p.name)?'expired':p.mfaSerial?'needs_mfa':'profile_credentials',expiresAt:s?.expires||this.expired.get(p.name)||null,storage:s?(this.savedIds.has(s.id)?'keychain':'memory'):null,restored:!!s?.restored,mfaSerial:s?.serial||p.mfaSerial||''};})};}
  async close(){await this.queue;this.sessions.clear();this.saved.clear();this.savedIds.clear();}
}
