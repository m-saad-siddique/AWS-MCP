import net from 'node:net';
import { spawn } from 'node:child_process';
import { setTimeout as delay } from 'node:timers/promises';

async function freePort() {
  const server = net.createServer();
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  const port = server.address().port;
  await new Promise(resolve => server.close(resolve));
  return port;
}
function listening(port) {
  return new Promise(resolve => {
    const socket = net.connect({ host: '127.0.0.1', port });
    socket.once('connect', () => { socket.destroy(); resolve(true); });
    socket.once('error', () => resolve(false));
    socket.setTimeout(300, () => { socket.destroy(); resolve(false); });
  });
}
export class TunnelManager {
  constructor({ aws, spawnProcess = spawn, port = freePort, probe = listening, idleMs = 15 * 60 * 1000 } = {}) {
    Object.assign(this, { aws, spawnProcess, port, probe, idleMs }); this.tunnels = new Map();
  }
  status(id) {
    const t = this.tunnels.get(id);
    return t ? { status: t.status, localPort: t.status === 'open' ? t.port : undefined, expiresAt: t.expiresAt } : { status: 'closed' };
  }
  async open(connection, auth = {}) {
    if (this.tunnels.has(connection.id)) throw new Error('A tunnel already exists or is opening. Close it before opening another.');
    const t = { status: 'opening' }; this.tunnels.set(connection.id, t);
    try {
      const { p, base, session } = await this.aws.context({ profile: connection.profile, args: ['ssm', 'start-session'] }, auth);
      if (auth.signal?.aborted || this.tunnels.get(connection.id) !== t) throw new Error('Tunnel opening canceled.');
      t.port = await this.port();
      const args = ['ssm', 'start-session', '--target', connection.instanceId, '--document-name', 'AWS-StartPortForwardingSessionToRemoteHost', '--parameters', JSON.stringify({ host: [connection.host], portNumber: [String(connection.port)], localPortNumber: [String(t.port)] }), '--region', connection.region];
      if (!session) args.push('--profile', p.name);
      t.child = this.spawnProcess(process.env.AWS_MCP_AWS_BIN || 'aws', args, { shell: false, detached: process.platform !== 'win32', windowsHide: true, env: { ...base, ...session?.env }, stdio: ['pipe', 'pipe', 'pipe'] });
      let output = '', failure, announced = false;
      const capture = data => { output = (output + data.toString()).slice(-16384); if (/Port \d+ opened|Waiting for connections/i.test(output)) announced = true; };
      t.child.stdout.on('data', capture); t.child.stderr.on('data', capture);
      t.child.on('error', error => { failure = error.code === 'ENOENT' ? 'AWS CLI not found.' : 'Could not start Session Manager.'; });
      t.child.on('close', () => { failure ||= 'Session Manager exited. Check AWS authentication, SSM permissions, the plugin, and EC2 connectivity.'; if (this.tunnels.get(connection.id) === t) { clearTimeout(t.timer); this.tunnels.delete(connection.id); } });
      const abort = () => this.close(connection.id);
      auth.signal?.addEventListener('abort', abort, { once: true });
      try {
        const deadline = Date.now() + 30000;
        while (Date.now() < deadline) {
          if (auth.signal?.aborted || this.tunnels.get(connection.id) !== t) throw new Error('Tunnel opening canceled or Session Manager exited.');
          if (failure) throw new Error(failure);
          if (announced && await this.probe(t.port)) {
            if (auth.signal?.aborted || this.tunnels.get(connection.id) !== t) throw new Error('Tunnel opening canceled.');
            t.status = 'open'; t.expiresAt = Date.now() + this.idleMs;
            t.timer = setTimeout(() => this.close(connection.id), this.idleMs); t.timer.unref();
            return { localPort: t.port, expiresAt: t.expiresAt, message: 'SSM tunnel is open. Database authentication will be checked by your first approved query.' };
          }
          await delay(100);
        }
        throw new Error('Tunnel did not open within 30 seconds. Check the Session Manager plugin, AWS login, EC2 SSM Agent, and network access.');
      } finally { auth.signal?.removeEventListener('abort', abort); }
    } catch (error) { this.close(connection.id); throw error; }
  }
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
