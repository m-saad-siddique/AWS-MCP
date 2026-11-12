import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFile, mkdir, access, rename, chmod, realpath } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
const source = fileURLToPath(new URL('../native/keychain.m', import.meta.url));
export function privateProcess(executable, args, { input = '', timeoutMs = 15000, maxBytes = 2 * 1024 * 1024 } = {}) {
  return new Promise((resolve,reject)=>{
    const child=spawn(executable,args,{shell:false,stdio:['pipe','pipe','pipe'],windowsHide:true});
    const chunks=[];let size=0,done=false;
    const finish=(error,value)=>{if(done)return;done=true;clearTimeout(timer);error?reject(error):resolve(value);};
    const timer=setTimeout(()=>{child.kill('SIGKILL');finish(new Error('Secure credential storage timed out.'));},timeoutMs);
    child.stdout.on('data',data=>{size+=data.length;if(size>maxBytes){child.kill('SIGKILL');finish(new Error('Secure credential storage returned too much data.'));}else chunks.push(data);});
    child.stderr.on('data',()=>{}); // Never include subprocess diagnostics or payloads in API errors.
    child.stdin.on('error',()=>{});child.on('error',()=>finish(new Error('Secure credential helper could not start.')));
    child.on('close',code=>finish(null,{code,stdout:Buffer.concat(chunks).toString('utf8')}));
    child.stdin.end(input);
  });
}
export class MacKeychainStore {
  constructor({ stateDir, service='com.aws-approval-mcp.mfa-sessions', interactive=true }={}) {
    this.stateDir=stateDir;this.service=service;this.interactive=interactive;
    this.available=process.platform==='darwin'&&!!stateDir&&process.env.AWS_MCP_NO_KEYCHAIN!=='1';
  }
  async prepare() {
    if(!this.available)throw new Error('macOS Keychain storage is unavailable.');
    if(this.preparing)return this.preparing;
    this.preparing=(async()=>{
      const root=await realpath(this.stateDir);
      this.account=createHash('sha256').update(root).digest('hex');
      const hash=createHash('sha256').update(await readFile(source)).digest('hex').slice(0,16);
      const bin=join(root,'native');await mkdir(bin,{recursive:true,mode:0o700});
      this.executable=join(bin,'keychain-'+hash);
      try{await access(this.executable);}catch{
        const result=await privateProcess('/usr/bin/xcrun',['clang',source,'-O2','-fobjc-arc','-fno-modules','-framework','Foundation','-framework','Security','-o',this.executable+'.tmp'],{timeoutMs:60000});
        if(result.code!==0)throw new Error('Could not build the Keychain helper. Install Apple Command Line Tools to save MFA sessions.');
        await chmod(this.executable+'.tmp',0o700);await rename(this.executable+'.tmp',this.executable);
      }
    })();
    try{return await this.preparing;}catch(e){this.preparing=undefined;throw e;}
  }
  async invoke(operation,value,interactive=false) {
    await this.prepare();
    const result=await privateProcess(this.executable,[],{input:JSON.stringify({operation,service:this.service,account:this.account,value,interactive:interactive&&this.interactive}),timeoutMs:15000});
    let message;try{message=JSON.parse(result.stdout);}catch{throw new Error('Keychain helper returned an invalid response.');}
    if(result.code!==0||!message.ok)throw new Error('Keychain access was denied or unavailable. Unlock your login Keychain and try again.');
    return message.value;
  }
  async read(){const value=await this.invoke('get');return value===null?[]:JSON.parse(value);}
  async write(value,{interactive=true}={}){await this.invoke('set',JSON.stringify(value),interactive);}
  async remove(){await this.invoke('delete');}
}
