import net from 'node:net';
import { spawn } from 'node:child_process';
import { setTimeout as delay } from 'node:timers/promises';
import { stripVTControlCharacters } from 'node:util';
import { redact } from './aws.js';

async function freePort(requested=0) {
  const servers=[];
  const bind=async(host,port)=>{
    const server=net.createServer();
    await new Promise((resolve,reject)=>{server.once('error',reject);server.listen({port,host,ipv6Only:host==='::1'},resolve);});
    servers.push(server);return server.address().port;
  };
  let selected=requested;
  try{
    selected=await bind('127.0.0.1',requested);
    try{await bind('::1',selected);}catch(e){if(!['EAFNOSUPPORT','EADDRNOTAVAIL','EPROTONOSUPPORT'].includes(e.code))throw e;}
    return selected;
  }catch(e){if(e.code==='EADDRINUSE')throw new Error(`Local port ${selected} is already in use. Close the other session or choose another local port.`);throw e;}
  finally{await Promise.all(servers.map(server=>new Promise(resolve=>server.close(resolve))));}
}
function listeningAt(host,port){
  return new Promise(resolve=>{
    const socket=net.connect({host,port});let finished=false;
    const done=value=>{if(finished)return;finished=true;socket.destroy();resolve(value);};
    socket.once('connect',()=>done(true));socket.once('error',()=>done(false));socket.setTimeout(300,()=>done(false));
  });
}
async function listening(port){
  const [ipv4,ipv6]=await Promise.all([listeningAt('127.0.0.1',port),listeningAt('::1',port)]);
  return ipv4?'127.0.0.1':ipv6?'::1':false;
}
export function tunnelDiagnostic(output,secrets=[]){
  let value=stripVTControlCharacters(output);
  for(const secret of secrets)if(typeof secret==='string'&&secret)value=value.replaceAll(secret,'[REDACTED]');
  value=redact(value).replace(/((?:"?(?:SecretAccessKey|SessionToken|AccessKeyId|TokenValue|StreamUrl|aws_secret_access_key|aws_session_token|aws_access_key_id)"?)\s*[:=]\s*")[^"]*(?:"|$)/gi,'$1[REDACTED]"')
    .replace(/wss?:\/\/[^\s"'<>]+/gi,'[REDACTED_SESSION_URL]')
    .replace(/(Authorization\s*:\s*(?:Bearer|Basic)\s+)\S+/gi,'$1[REDACTED]');
  return value.trim().slice(-4000);
}
export class TunnelManager {
  constructor({ aws, spawnProcess = spawn, port = freePort, probe = listening, idleMs = 15 * 60 * 1000, startupMs = 60000 } = {}) {
    Object.assign(this, { aws, spawnProcess, port, probe, idleMs, startupMs }); this.tunnels = new Map();
  }
  status(id) {
    const t = this.tunnels.get(id);
    return t ? { status: t.status, localPort: t.status === 'open' ? t.port : undefined, localHost:t.status==='open'?t.host:undefined, expiresAt: t.expiresAt } : { status: 'closed' };
  }
  async open(connection, auth = {}) {
    if (this.tunnels.has(connection.id)) throw new Error('A tunnel already exists or is opening. Close it before opening another.');
    const t = { status: 'opening' }; this.tunnels.set(connection.id, t);
    try {
      const { p, base, session } = await this.aws.context({ profile: connection.profile, args: ['ssm', 'start-session'] }, auth);
      if (auth.signal?.aborted || this.tunnels.get(connection.id) !== t) throw new Error('Tunnel opening canceled.');
      t.port = await this.port(connection.localPort||0);
      const args = ['ssm', 'start-session', '--target', connection.instanceId, '--document-name', 'AWS-StartPortForwardingSessionToRemoteHost', '--parameters', JSON.stringify({ host: [connection.host], portNumber: [String(connection.port)], localPortNumber: [String(t.port)] }), '--region', connection.region];
      if (!session) args.push('--profile', p.name);
      t.child = this.spawnProcess(process.env.AWS_MCP_AWS_BIN || 'aws', args, { shell: false, detached: process.platform !== 'win32', windowsHide: true, env: { ...base, ...session?.env, PYTHONUNBUFFERED:'1' }, stdio: ['pipe', 'pipe', 'pipe'] });
      let output='',failure,announced=false;
      const secrets=[...Object.values(session?.env||{}),auth.mfaCode];
      const diagnostics=()=>tunnelDiagnostic(output,secrets);
      const message=summary=>{const detail=diagnostics();return detail?summary+'\nSession Manager output:\n'+detail:summary+' No startup output was received from AWS CLI or the Session Manager plugin.';};
      const capture=data=>{
        // Retain a bounded prefix so partially printed credential fields retain
        // their labels and can still be redacted before error publication.
        output=(output+data.toString()).slice(0,16384);
        const text=stripVTControlCharacters(output);
        if(new RegExp('\\bPort\\s+'+t.port+'\\s+opened\\b','i').test(text))announced=true;
      };
      t.child.stdout.on('data',capture);t.child.stderr.on('data',capture);
      t.child.on('error',error=>{failure=error.code==='ENOENT'?'AWS CLI not found in the broker environment.':'Could not start Session Manager.';});
      t.child.on('close',(code,signal)=>{
        failure ||= `Session Manager exited (${signal?'signal '+signal:'exit code '+code}).`;
        if(this.tunnels.get(connection.id)===t){clearTimeout(t.timer);this.tunnels.delete(connection.id);}
      });
      const abort = () => this.close(connection.id);
      auth.signal?.addEventListener('abort', abort, { once: true });
      try {
        const deadline = Date.now() + this.startupMs;
        while (Date.now() < deadline) {
          if(auth.signal?.aborted)throw new Error('Tunnel opening canceled.');
          if(failure)throw new Error(message(failure));
          if(this.tunnels.get(connection.id)!==t)throw new Error('Tunnel opening canceled.');
          const ready=announced&&await this.probe(t.port);
          if(ready){
            if(auth.signal?.aborted)throw new Error('Tunnel opening canceled.');
            if(failure)throw new Error(message(failure));
            if(this.tunnels.get(connection.id)!==t)throw new Error('Tunnel opening canceled.');
            t.host=ready==='::1'?'::1':'127.0.0.1';t.status = 'open'; t.expiresAt = Date.now() + this.idleMs;
            t.timer = setTimeout(() => this.close(connection.id), this.idleMs); t.timer.unref();
            return { localPort: t.port, localHost:t.host, expiresAt: t.expiresAt, message: 'SSM tunnel is open. Database authentication will be checked by your first approved query.' };
          }
          await delay(100);
        }
        if(failure)throw new Error(message(failure));
        throw new Error(message(`Tunnel did not open within ${Math.ceil(this.startupMs/1000)} seconds. ${announced?'The plugin reported the port open, but neither loopback address accepted a connection.':'The plugin did not confirm opening the requested local port.'} Check AWS authentication, SSM target connectivity, and access to the Session Manager data channel.`));
      } finally { auth.signal?.removeEventListener('abort', abort); }
    } catch (error) { this.close(connection.id); throw error; }
  }
  getHost(id){const t=this.tunnels.get(id);if(t?.status!=='open')throw new Error('No open tunnel.');return t.host||'127.0.0.1';}
  getPort(id) {
    const t = this.tunnels.get(id);
    if (t?.status !== 'open') throw new Error('No open tunnel. Request and approve opening the database tunnel first.');
    return t.port;
  }
  close(id) {
    const t = this.tunnels.get(id); if (!t) return;
    this.tunnels.delete(id); clearTimeout(t.timer);
    if (t.child?.pid) {
      const kill = signal => { try { if (process.platform === 'win32') t.child.kill(signal); else process.kill(-t.child.pid, signal); } catch {} };
      kill('SIGTERM'); const timer = setTimeout(() => kill('SIGKILL'), 1000); timer.unref(); if (process.platform === 'win32') t.child.once('close', () => clearTimeout(timer));
    }
  }
  closeAll() { for (const id of this.tunnels.keys()) this.close(id); }
}
