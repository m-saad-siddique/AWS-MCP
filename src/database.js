import { randomUUID } from 'node:crypto';
import { readFile, writeFile, rename } from 'node:fs/promises';
import net from 'node:net';
import tls from 'node:tls';
import { join } from 'node:path';
import pg from 'pg';
import mysql from 'mysql2';
import { TunnelManager } from './tunnel.js';

const caPath = new URL('../assets/rds-global-bundle.pem', import.meta.url);
const maxRows = 200, maxBytes = 512 * 1024;
export function sqlRisk(sql) {
  let text = sql.trimStart();
  // Only remove leading comments; never rewrite the SQL sent to the database.
  for (;;) {
    const next = text.replace(/^(?:--[^\n]*(?:\n|$)|\/\*[\s\S]*?\*\/)\s*/, '');
    if (next === text) break; text = next;
  }
  return /^(SELECT|SHOW|DESCRIBE)\b/i.test(text) ? 'read' : 'destructive';
}
export function validateConnection(input, profiles) {
  if (!input || typeof input !== 'object') throw new Error('Connection settings are required.');
  const text = (key, max = 256) => { const v = input[key]; if (typeof v !== 'string' || !v.trim() || v.length > max || /[\x00-\x1f\x7f]/.test(v)) throw new Error(`Invalid ${key}.`); return v.trim(); };
  const name = text('name', 80), engine = text('engine'), profile = text('profile'), region = text('region', 40), host = text('host'), instanceId = text('instanceId'), database = text('database'), username = text('username');
  if (!['postgres', 'mysql'].includes(engine)) throw new Error('Choose PostgreSQL or MySQL.');
  if (!profiles.some(p => p.name === profile)) throw new Error('Choose an existing AWS profile.');
  if (!/^[a-z0-9-]{3,40}$/.test(region) || !/^i-[a-f0-9]{8,17}$/.test(instanceId)) throw new Error('Provide a valid AWS region and EC2 instance ID.');
  if (!/^[a-zA-Z0-9][a-zA-Z0-9.-]{1,252}$/.test(host) || host.includes('..')) throw new Error('Use the RDS hostname without a protocol or port.');
  const port = Number(input.port || (engine === 'postgres' ? 5432 : 3306));
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Invalid database port.');
  const passwordEnv = input.passwordEnv || '';
  if (typeof passwordEnv !== 'string' || (passwordEnv && !/^[A-Z_][A-Z0-9_]{0,100}$/.test(passwordEnv))) throw new Error('Invalid password environment variable.');
  if (input.readOnly !== undefined && typeof input.readOnly !== 'boolean') throw new Error('Invalid read-only setting.');
  if (input.password !== undefined && (typeof input.password !== 'string' || input.password.length > 4096)) throw new Error('Invalid password.');
  if (input.readOnly === false && input.confirmWrites !== name) throw new Error('Type the connection name to enable database writes.');
  return { name, engine, profile, region, host, port, instanceId, database, username, passwordEnv, readOnly: input.readOnly !== false };
}
function json(value) { return JSON.stringify(value, (_, v) => typeof v === 'bigint' ? v.toString() : v); }
export async function runDatabaseQuery(c, port, password, sql, params, { signal, timeoutMs = 30000, ca: testCa } = {}) {
  const ca = testCa || await readFile(caPath, 'utf8');
  if (signal?.aborted) throw new Error('Query canceled.');
  let destroy = () => {}, timeout, abort, stopped;
  // Race the full operation, including authentication, so a stalled driver cannot keep a request running.
  const interrupted = new Promise((_, reject) => {
    abort = () => { stopped = true; destroy(); reject(new Error('Query canceled. Remote changes may already have committed.')); };
    signal?.addEventListener('abort', abort, { once: true });
    timeout = setTimeout(() => { stopped = true; destroy(); reject(new Error('Query timed out after 30 seconds. Remote changes may already have committed.')); }, timeoutMs);
  });
  const operation = async () => {
    if (c.engine === 'postgres') {
      const client = new pg.Client({ host: '127.0.0.1', port, user: c.username, password, database: c.database, application_name: 'aws-approval-mcp', connectionTimeoutMillis: 10000, statement_timeout: timeoutMs, ssl: { ca, rejectUnauthorized: true, servername: c.host, checkServerIdentity: (_, cert) => tls.checkServerIdentity(c.host, cert) } });
      client.on('error', () => {});
      destroy = () => { client.connection?.stream?.destroy(); void client.end().catch(() => {}); };
      try {
        await client.connect(); if (stopped) throw new Error('Query interrupted.');
        await client.query(c.readOnly ? 'BEGIN READ ONLY' : 'BEGIN');
        // Extended protocol parses one statement. Consume it fully before commit,
        // retaining only a bounded result so RETURNING queries never stop mid-command.
        const result = await new Promise((resolve, reject) => {
          const rows = []; let bytes = 0, truncated = false;
          const query = new pg.Query({ text: sql, values: params, queryMode: 'extended' });
          query.on('row', row => {
            const size = Buffer.byteLength(json(row));
            if (!truncated && rows.length < maxRows && bytes + size <= maxBytes) { rows.push(row); bytes += size; }
            else truncated = true;
          });
          query.on('error', reject);
          query.on('end', value => resolve({ rows, fields: value.fields.map(f => f.name), affectedRows: value.rowCount, truncated }));
          client.query(query);
        });
        if (stopped) throw new Error('Query interrupted.');
        await client.query('COMMIT');
        return result;
      } finally { destroy(); }
    }
    const client = mysql.createConnection({ host: c.host, user: c.username, password, database: c.database, port: c.port, stream: () => net.connect({ host: '127.0.0.1', port }), ssl: { ca, rejectUnauthorized: true, verifyIdentity: true }, multipleStatements: false, connectTimeout: 10000, supportBigNumbers: true, bigNumberStrings: true, infileStreamFactory: () => { throw new Error('Local file loading is disabled.'); } });
    client.on('error', () => {}); destroy = () => client.destroy();
    const query = (text) => new Promise((resolve, reject) => client.query({ sql: text, timeout: timeoutMs }, (e, result) => e ? reject(e) : resolve(result)));
    try {
      await new Promise((resolve, reject) => client.connect(e => e ? reject(e) : resolve()));
      if (stopped) throw new Error('Query interrupted.');
      await query(c.readOnly ? 'START TRANSACTION READ ONLY' : 'START TRANSACTION');
      const result = await new Promise((resolve, reject) => {
        const rows = []; let bytes = 0, fields = [], affectedRows = 0, truncated = false;
        // Execute uses the prepared statement protocol: parameters are bound and batches are rejected.
        const q = client.execute({ sql, values: params, timeout: timeoutMs });
        q.on('fields', list => { fields = (list || []).map(f => f.name); });
        q.on('result', row => {
          if (row?.constructor?.name !== 'ResultSetHeader') {
            const size = Buffer.byteLength(json(row));
            if (!truncated && rows.length < maxRows && bytes + size <= maxBytes) { rows.push(row); bytes += size; } else truncated = true;
          } else if (typeof row?.affectedRows === 'number') affectedRows += row.affectedRows;
        });
        q.on('error', reject); q.on('end', () => resolve({ rows, fields, affectedRows, truncated }));
      });
      if (!stopped) await query('COMMIT'); return result;
    } finally { destroy(); }
  };
  try { return await Promise.race([operation(), interrupted]); }
  finally { clearTimeout(timeout); signal?.removeEventListener('abort', abort); }
}
export class DatabaseService {
  constructor({ aws, profiles, tunnels, query = runDatabaseQuery } = {}) {
    this.profiles = profiles; this.query = query; this.tunnels = tunnels || new TunnelManager({ aws }); this.connections = new Map(); this.passwords = new Map(); this.writeQueue = Promise.resolve();
  }
  async init(stateDir) {
    this.file = stateDir ? join(stateDir, 'databases.json') : undefined;
    if (!this.file) return;
    try { const rows = JSON.parse(await readFile(this.file, 'utf8')); for (const c of rows) this.connections.set(c.id, c); }
    catch (e) { if (e.code !== 'ENOENT') throw new Error('Could not load saved database connections.'); }
  }
  list() { return [...this.connections.values()].map(c => ({ ...c, passwordReady: this.passwords.has(c.id) || !!(c.passwordEnv && process.env[c.passwordEnv]), tunnel: this.tunnels.status(c.id) })); }
  async persist() {
    if (!this.file) return;
    const data = json([...this.connections.values()]);
    this.writeQueue = this.writeQueue.catch(() => {}).then(async () => { await writeFile(this.file + '.tmp', data, { mode: 0o600 }); await rename(this.file + '.tmp', this.file); });
    await this.writeQueue;
  }
  async save(input) {
    const fields = validateConnection(input, await this.profiles());
    const old = input.id ? this.connections.get(input.id) : undefined;
    if (input.id && !old) throw new Error('Connection not found.');
    if ([...this.connections.values()].some(c => c.name === fields.name && c.id !== old?.id)) throw new Error('Connection name is already in use.');
    if (old && this.tunnels.status(old.id).status !== 'closed') throw new Error('Close the tunnel before editing this connection.');
    const c = { ...fields, id: old?.id || randomUUID(), revision: randomUUID() };
    this.connections.set(c.id, c);
    try { await this.persist(); } catch (e) { if (old) this.connections.set(old.id, old); else this.connections.delete(c.id); throw new Error('Failed to save database connection.'); }
    if (input.password) this.passwords.set(c.id, input.password);
    else if (old && ['host', 'port', 'username', 'database', 'passwordEnv'].some(key => old[key] !== c[key])) this.passwords.delete(c.id);
    return this.list().find(row => row.id === c.id);
  }
  async remove(id) { this.tunnels.close(id); const c = this.connections.get(id); this.connections.delete(id); try { await this.persist(); } catch { if(c) this.connections.set(id, c); throw new Error('Failed to delete connection.'); } this.passwords.delete(id); }
  prepare(input, kind) {
    const c = this.connections.get(input?.connectionId);
    if (!c) throw new Error('Choose a saved database connection.');
    if (typeof input.reason !== 'string' || !input.reason.trim() || input.reason.length > 2000) throw new Error('Provide a reason of at most 2000 characters.');
    const common = { kind, connectionId: c.id, connectionName: c.name, connectionRevision: c.revision, profile: c.profile, region: c.region, reason: input.reason, target: { host: c.host, port: c.port, database: c.database, engine: c.engine, instanceId: c.instanceId, username: c.username, readOnly: c.readOnly }, confirmationTarget: c.name };
    if (kind === 'tunnel') return { ...common, args: ['ssm', 'start-session'], risk: 'write' };
    if (typeof input.sql !== 'string' || !input.sql.trim() || input.sql.length > 32768 || input.sql.includes('\0')) throw new Error('SQL must be between 1 and 32768 characters.');
    const params = input.params ?? [];
    if (!Array.isArray(params) || params.length > 100 || params.some(p => p !== null && !['string', 'number', 'boolean'].includes(typeof p)) || Buffer.byteLength(json(params)) > 32768) throw new Error('Parameters must be an array of up to 100 scalar values (32 KiB maximum).');
    const risk = sqlRisk(input.sql);
    if (c.readOnly && risk !== 'read') throw new Error('This connection is read-only. Only SELECT, SHOW, and DESCRIBE are accepted; enable writes in connection settings for other statements.');
    return { ...common, args: ['database', 'query'], sql: input.sql, params: [...params], risk };
  }
  async execute(request, auth) {
    const c = this.connections.get(request.connectionId);
    if (!c || c.revision !== request.connectionRevision) throw new Error('Connection settings changed after submission. Submit a new request.');
    let result;
    if (request.kind === 'tunnel') result = await this.tunnels.open(c, auth);
    else {
      const port = this.tunnels.getPort(c.id);
      const password = this.passwords.get(c.id) || (c.passwordEnv ? process.env[c.passwordEnv] : '');
      if (!password) throw new Error('Set the database password in connection settings or its configured environment variable.');
      try { result = await this.query(c, port, password, request.sql, request.params, auth); }
      catch (e) { throw new Error(String(e.message).replaceAll(password, '[REDACTED]')); }
    }
    return { exitCode: 0, stdout: json(result), stderr: '' };
  }
  close() { this.tunnels.closeAll(); this.passwords.clear(); }
}
