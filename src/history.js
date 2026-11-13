import { DatabaseSync } from 'node:sqlite';
import { randomUUID, createHash } from 'node:crypto';
import { open, chmod } from 'node:fs/promises';
import { join } from 'node:path';
import { redact } from './aws.js';

const requestKinds = new Set(['aws','sql','tunnel']);
const finalStates = new Set(['completed','failed','denied','expired','canceled','withheld','blocked','interrupted','outcome_unknown','result_unavailable']);
const credentialKey = /^(?:password|passwd|secret|secretaccesskey|sessiontoken|accesskeyid|api[-_]?key|private[-_]?key|aws[-_](?:access[-_]key[-_]id|secret[-_]access[-_]key|session[-_]token))$/i;
const secretFlag = /^--(?:token-code|password|secret-access-key|session-token|access-key-id|secret-string|secret-binary|client-secret|auth-token|master-user-password)$/;
export function safeText(value) {
  if(typeof value!=='string')return value;
  try{return JSON.stringify(safeValue(JSON.parse(value)));}catch{return redact(value);}
}
function safeValue(value) {
  if(Array.isArray(value))return value.map(safeValue);
  if(value&&typeof value==='object')return Object.fromEntries(Object.entries(value).map(([key,v])=>[key,credentialKey.test(key)?'[REDACTED]':safeValue(v)]));
  return typeof value==='string'?redact(value):value;
}
function safeArgs(args=[]) {
  let hideNext=false;
  return args.map(arg=>{if(hideNext){hideNext=false;return '[REDACTED]';}const [flag,...rest]=arg.split('=');if(secretFlag.test(flag)){if(rest.length)return flag+'=[REDACTED]';hideNext=true;}return safeText(arg);});
}
export function historySnapshot(r) {
  // Explicit allowlist: controller, MFA code, auth envelopes, and held output never enter storage.
  const keys=['id','kind','profile','region','reason','connectionId','connectionName','risk','createdAt','expiresAt','startedAt','finishedAt','reviewedAt','status','deliveryMode','outputReviewed','autoApproved','policy','recoveryNote','source','clientName','historyError','recovered','historySessionId','executionExitCode','mfaUsed','mfaSessionReused','rememberMfa'];
  const result=Object.fromEntries(keys.filter(key=>r[key]!==undefined).map(key=>[key,safeValue(r[key])]));
  result.args=safeArgs(r.args);
  if(r.target)result.target=Object.fromEntries(['host','port','localPort','database','engine','instanceId','username','readOnly'].filter(key=>r.target[key]!==undefined).map(key=>[key,safeValue(r.target[key])]));
  if(r.sql!==undefined){
    const credentialSql=/\b(?:CREATE|ALTER)\s+(?:USER|ROLE|LOGIN)\b|\bSET\s+PASSWORD\b/i.test(r.sql);
    result.sql=credentialSql?'[Credential-management SQL omitted from history]':safeText(r.sql);
    result.params=credentialSql?(r.params||[]).map(()=>'[REDACTED]'):safeValue(r.params||[]);
    if(credentialSql)result.historyRedacted=true;
  }
  if(r.result&&['completed','failed'].includes(r.status))result.result={exitCode:r.result.exitCode,stdout:safeText(r.result.stdout||''),stderr:safeText(r.result.stderr||'')};
  return result;
}
export class HistoryStore {
  constructor({now=Date.now}={}){this.now=now;this.sessionId=randomUUID();this.warning='';}
  async init(stateDir) {
    this.file=stateDir?join(stateDir,'history.sqlite'):undefined;
    if(this.file){const file=await open(this.file,'a',0o600);await file.close();await chmod(this.file,0o600);}
    try{
      this.db=new DatabaseSync(this.file||':memory:');
      this.db.exec('PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;');
      const version=this.db.prepare('PRAGMA user_version').get().user_version;
      if(version>1)throw new Error('Newer history schema.');
      this.db.exec(`CREATE TABLE IF NOT EXISTS requests (
        id TEXT PRIMARY KEY, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
        status TEXT NOT NULL, kind TEXT NOT NULL, profile TEXT NOT NULL, connection_name TEXT NOT NULL,
        summary TEXT NOT NULL, search_text TEXT NOT NULL, snapshot TEXT NOT NULL, last_event TEXT NOT NULL, digest TEXT NOT NULL
      ); CREATE INDEX IF NOT EXISTS request_time ON requests(created_at DESC,id DESC);
      CREATE INDEX IF NOT EXISTS request_filter ON requests(kind,status,profile);
      CREATE TABLE IF NOT EXISTS events (seq INTEGER PRIMARY KEY AUTOINCREMENT, request_id TEXT, at INTEGER NOT NULL,
        event TEXT NOT NULL, session_id TEXT NOT NULL, details TEXT NOT NULL);
      CREATE INDEX IF NOT EXISTS event_request ON events(request_id,seq);
      CREATE TABLE IF NOT EXISTS broker_runs (id TEXT PRIMARY KEY,started_at INTEGER NOT NULL,stopped_at INTEGER,state TEXT NOT NULL);
      PRAGMA user_version=1;`);
      this.transaction(()=>{
        for(const old of this.db.prepare("SELECT id FROM broker_runs WHERE stopped_at IS NULL").all()){
          this.system('broker_unclean_stop_detected',{previousSessionId:old.id});
          this.db.prepare("UPDATE broker_runs SET stopped_at=?,state='unclean_stop_detected' WHERE id=?").run(this.now(),old.id);
        }
        // Recovery changes records only. It never restores work into the execution queue.
        for(const row of this.db.prepare("SELECT snapshot FROM requests WHERE status NOT IN ('completed','failed','denied','expired','canceled','withheld','blocked','interrupted','outcome_unknown','result_unavailable')").all()){
          const r=JSON.parse(row.snapshot),previousStatus=r.status;
          r.status=previousStatus==='running'?'outcome_unknown':['awaiting_review','releasing'].includes(previousStatus)?'result_unavailable':'interrupted';
          r.recovered=true;r.finishedAt ||= this.now();
          r.recoveryNote=r.status==='outcome_unknown'?'Broker stopped during execution. The remote operation may have completed. Inspect AWS/database state before retrying.':r.status==='result_unavailable'?'Execution finished or release was pending, but unreleased output was not stored. The operation was not replayed.':'Broker stopped before execution began. The request was not replayed; submit a new request if still needed.';
          delete r.result;this.write(r,'recovered_after_restart',{previousStatus});
        }
        this.db.prepare('INSERT INTO broker_runs(id,started_at,state) VALUES(?,?,?)').run(this.sessionId,this.now(),'running');
        this.system('broker_started',{sessionId:this.sessionId,persistent:!!this.file});
      });
      if(this.file)await Promise.all(['-wal','-shm'].map(suffix=>chmod(this.file+suffix,0o600).catch(()=>{})));
    }catch{try{this.db?.close();}catch{}this.db=undefined;throw new Error('Activity history could not be opened. Check the runtime directory and preserve history.sqlite for recovery.');}
  }
  transaction(fn){this.db.exec('BEGIN IMMEDIATE');try{const value=fn();this.db.exec('COMMIT');return value;}catch(e){try{this.db.exec('ROLLBACK');}catch{}throw e;}}
  system(event,details={}){if(!this.db)return;this.db.prepare('INSERT INTO events(request_id,at,event,session_id,details) VALUES(NULL,?,?,?,?)').run(this.now(),event,this.sessionId,JSON.stringify(safeValue(details)));}
  write(r,event,details={}) {
    const snapshot=historySnapshot({...r,historySessionId:r.historySessionId||this.sessionId});
    const data=JSON.stringify(snapshot),digest=createHash('sha256').update(data).digest('hex');
    const old=this.db.prepare('SELECT last_event,digest FROM requests WHERE id=?').get(r.id);
    if(old?.last_event===event&&old.digest===digest)return;
    const command=r.kind==='sql'?snapshot.sql:snapshot.args.join(' ');
    const summary={id:r.id,createdAt:r.createdAt,updatedAt:this.now(),status:r.status,kind:r.kind,profile:r.profile,region:r.region||'',connectionName:r.connectionName||'',command:command.slice(0,240),reason:snapshot.reason||'',source:r.source||'agent',clientName:snapshot.clientName||'',autoApproved:!!r.autoApproved,exitCode:r.result?.exitCode??r.executionExitCode??null,durationMs:r.startedAt&&r.finishedAt?Math.max(0,r.finishedAt-r.startedAt):null,hasOutput:!!snapshot.result,recovered:!!r.recovered};
    const search=[snapshot.sql||snapshot.args.join(' '),snapshot.reason,snapshot.profile,snapshot.connectionName,snapshot.clientName,r.id].filter(Boolean).join('\n');
    this.db.prepare(`INSERT INTO requests(id,created_at,updated_at,status,kind,profile,connection_name,summary,search_text,snapshot,last_event,digest)
      VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET updated_at=excluded.updated_at,status=excluded.status,summary=excluded.summary,search_text=excluded.search_text,snapshot=excluded.snapshot,last_event=excluded.last_event,digest=excluded.digest`).run(r.id,r.createdAt||this.now(),this.now(),r.status,r.kind,r.profile||'',r.connectionName||'',JSON.stringify(summary),search,data,event,digest);
    this.db.prepare('INSERT INTO events(request_id,at,event,session_id,details) VALUES(?,?,?,?,?)').run(r.id,this.now(),event,this.sessionId,JSON.stringify(safeValue({actor:['approved','denied','result_released','result_withheld','result_sent','result_discarded'].includes(event)?'operator':event==='auto_approved'?'policy':event==='submitted'?(r.source==='dashboard'?'operator':'agent'):'broker',status:r.status,autoApproved:!!r.autoApproved,mfaUsed:!!r.mfaUsed,mfaSessionReused:!!r.mfaSessionReused,deliveryMode:r.deliveryMode,policy:r.policy,exitCode:r.result?.exitCode??r.executionExitCode,...details})));
  }
  record(r,event,details={}) {
    if(!this.db)return;
    try{this.transaction(()=>{if(requestKinds.has(r.kind))this.write(r,event,details);else this.system(event,{id:r.id,profile:r.profile,kind:r.kind,...(r.policySummary||{}),...details});});this.warning='';}
    catch{this.warning='Some activity could not be saved. Check runtime storage before retrying any operation.';throw new Error('Activity history could not be saved.');}
  }
  request(id){const row=this.db?.prepare('SELECT snapshot FROM requests WHERE id=?').get(id);return row?JSON.parse(row.snapshot):undefined;}
  detail(id){const request=this.request(id);if(!request)return undefined;return {request,events:this.db.prepare('SELECT seq,at,event,session_id AS sessionId,details FROM events WHERE request_id=? ORDER BY at,seq').all(id).map(row=>({...row,details:JSON.parse(row.details)}))};}
  list(filters={}) {
    if(!this.db)return {items:[],total:0,limit:50,offset:0};
    const limit=Math.max(1,Math.min(100,Math.floor(Number(filters.limit)||50))),offset=Math.max(0,Math.min(1000000,Math.floor(Number(filters.offset)||0)));
    const where=[],values=[];
    for(const key of ['kind','status','profile'])if(filters[key]){where.push(key+'=?');values.push(String(filters[key]).slice(0,256));}
    if(filters.q){where.push("search_text LIKE ? ESCAPE '\\'");values.push('%'+String(filters.q).slice(0,500).replace(/[\\%_]/g,'\\$&')+'%');}
    const clause=where.length?' WHERE '+where.join(' AND '):'';
    return {items:this.db.prepare('SELECT summary FROM requests'+clause+' ORDER BY created_at DESC,id DESC LIMIT ? OFFSET ?').all(...values,limit,offset).map(row=>JSON.parse(row.summary)),total:this.db.prepare('SELECT count(*) AS total FROM requests'+clause).get(...values).total,limit,offset};
  }
  activity({offset=0,limit=30}={}){if(!this.db)return {items:[],total:0};limit=Math.max(1,Math.min(100,Number(limit)||30));offset=Math.max(0,Number(offset)||0);return {items:this.db.prepare('SELECT seq,at,event,session_id AS sessionId,details FROM events WHERE request_id IS NULL ORDER BY seq DESC LIMIT ? OFFSET ?').all(limit,offset).map(row=>({...row,details:JSON.parse(row.details)})),total:this.db.prepare('SELECT count(*) AS total FROM events WHERE request_id IS NULL').get().total,limit,offset};}
  importRecords(records){if(!this.db)return 0;let count=0;this.transaction(()=>{for(const r of records){if(!requestKinds.has(r.kind)||!r.id||this.request(r.id))continue;this.write({...r,source:r.source||'legacy'},'imported_existing_activity');count++;}this.system('existing_activity_imported',{count});});return count;}
  summary(){const counts=Object.fromEntries((this.db?.prepare('SELECT status,count(*) AS count FROM requests GROUP BY status').all()||[]).map(row=>[row.status,row.count]));return {counts,persistent:!!this.file,warning:this.warning,sessionId:this.sessionId,total:this.db?.prepare('SELECT count(*) AS total FROM requests').get().total||0,retention:'until_deleted'};}
  close(){if(!this.db)return;try{this.transaction(()=>{this.system('broker_stopped',{sessionId:this.sessionId});this.db.prepare("UPDATE broker_runs SET stopped_at=?,state='stopped' WHERE id=?").run(this.now(),this.sessionId);});this.db.exec('PRAGMA wal_checkpoint(TRUNCATE)');}finally{this.db.close();this.db=undefined;}}
}
export {finalStates as historyFinalStates};
