import { createHash } from 'node:crypto';
import { MfaSessionCache, profileFingerprint } from './mfa-sessions.js';
import { readFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';

// Read only profile metadata; credentials never become part of an API response.
export function parseIni(text) {
  const sections = Object.create(null);
  let current;
  for (const line of text.split(/\r?\n/)) {
    const section = line.match(/^\s*\[([^\]]+)\]\s*$/);
    if (section) current = sections[section[1]] ??= Object.create(null);
    else {
      const pair = line.match(/^\s*([^#;\s][^=]*?)\s*=\s*(.*?)\s*$/);
      if (current && pair) current[pair[1]] = pair[2];
    }
  }
  return sections;
}
export async function readProfiles(env = process.env) {
  const read = async (path) => { try { return parseIni(await readFile(path, 'utf8')); } catch (e) { if (e.code === 'ENOENT') return {}; throw e; } };
  const [config, credentials] = await Promise.all([
    read(env.AWS_CONFIG_FILE || join(homedir(), '.aws/config')),
    read(env.AWS_SHARED_CREDENTIALS_FILE || join(homedir(), '.aws/credentials')),
  ]);
  const profiles = new Map();
  for (const [name, values] of Object.entries(credentials)) profiles.set(name, values);
  for (const [section, values] of Object.entries(config)) {
    const name = section === 'default' ? section : section.startsWith('profile ') ? section.slice(8) : null;
    if (name) profiles.set(name, { ...profiles.get(name), ...values });
  }
  return [...profiles].map(([name, p]) => ({
    name, region: p.region || '', roleArn: p.role_arn || '', sourceProfile: p.source_profile || '',
    mfaSerial: p.mfa_serial || '', sso: !!(p.sso_session || p.sso_start_url),
    credentialProcess: !!p.credential_process,
    _authFingerprint: createHash('sha256').update(JSON.stringify((()=>{const rows=[];const seen=new Set();let current=name;while(current&&!seen.has(current)&&rows.length<16){seen.add(current);const values=profiles.get(current)||{};rows.push([current,Object.entries(values).sort(([a],[b])=>a.localeCompare(b)),Object.entries(config['sso-session '+values.sso_session]||{}).sort(([a],[b])=>a.localeCompare(b))]);current=values.source_profile;}return rows;})())).digest('hex'),
    externalId: p.external_id || '', roleSessionName: p.role_session_name || '',
  })).sort((a, b) => a.name.localeCompare(b.name));
}

const forbidden = new Set(['--profile', '--region', '--output', '--query', '--debug', '--endpoint-url', '--no-verify-ssl', '--ca-bundle', '--cli-auto-prompt', '--cli-input-json', '--cli-input-yaml']);
export function validateCommand(input, profiles) {
  if (!input || typeof input !== 'object') throw new Error('Command is required.');
  const { profile, args, region = '', reason = '' } = input;
  if (!profiles.some(p => p.name === profile)) throw new Error('Select an existing AWS profile.');
  if (!Array.isArray(args) || args.length < 2 || args.length > 256 || args.some(v => typeof v !== 'string' || !v || v.length > 32768 || /[\x00-\x08\x0b-\x1f\x7f]/.test(v))) throw new Error('args must contain an AWS service and operation, followed by argument strings.');
  if (!/^[a-z][a-z0-9-]*$/.test(args[0]) || !/^[a-z][a-z0-9-]*$/.test(args[1])) throw new Error('Use an AWS service and operation, without the aws prefix.');
  if (['configure', 'login', 'logout'].includes(args[0]) || args.includes('export-credentials')) throw new Error('Credential/configuration management must be done in your terminal.');
  for (const arg of args) {
    if ((arg.startsWith('--') && [...forbidden].some(flag => flag.startsWith(arg.split('=')[0]))) || /fileb?:\/\//i.test(arg)) throw new Error(`Unsupported argument: ${arg.split('=')[0]}. Profile, region, and output are controlled by the server; local file references are disabled.`);
  }
  if (typeof region !== 'string' || (region && !/^[a-z0-9-]{3,40}$/.test(region))) throw new Error('Invalid AWS region.');
  if (typeof reason !== 'string' || reason.length > 2000) throw new Error('Reason must be at most 2000 characters.');
  return { profile, args: [...args], region, reason };
}
export function commandRisk(args) {
  const action = args[1];
  if (/^(delete|terminate|remove|purge|destroy|revoke|disable|stop|reboot|detach|deregister|release|reset)/.test(action) || (args[0] === 's3' && ['rm', 'mv', 'sync'].includes(action))) return 'destructive';
  if (/^(get|list|describe|head|lookup|search|scan|query|count|help)/.test(action) || (args[0] === 's3' && action === 'ls')) return 'read';
  return 'write';
}
export function cleanEnv(env = process.env) {
  const next = { ...env };
  for (const key of Object.keys(next)) if (/^AWS_(ACCESS_KEY|SECRET|SESSION|SECURITY_TOKEN|PROFILE|DEFAULT_PROFILE|ENDPOINT_URL|ROLE_ARN|ROLE_SESSION_NAME|WEB_IDENTITY_TOKEN_FILE|CONTAINER_CREDENTIALS|CREDENTIAL_EXPIRATION)/.test(key)) delete next[key];
  return { ...next, AWS_PAGER: '', AWS_CLI_AUTO_PROMPT: 'off', AWS_EC2_METADATA_DISABLED: 'true', AWS_IGNORE_CONFIGURED_ENDPOINT_URLS: 'true' };
}
export function redact(text) {
  return text.replace(/((?:"?(?:SecretAccessKey|SessionToken|AccessKeyId|aws_secret_access_key|aws_session_token|aws_access_key_id)"?)\s*[:=]\s*")[^"]*"/gi, '$1[REDACTED]"')
    .replace(/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g, '[REDACTED_ACCESS_KEY]');
}
export function runProcess(args, { env = cleanEnv(), timeoutMs = 120000, signal, executable = process.env.AWS_MCP_AWS_BIN || 'aws', maxBytes = 1024 * 1024 } = {}) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(new Error('Command canceled.'));
    const child = spawn(executable, args, { shell: false, env, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
    let stdout = '', stderr = '', bytes = 0, failure, killTimer;
    const stop = (message) => { if (failure) return; failure = message; child.kill('SIGTERM'); killTimer = setTimeout(() => child.kill('SIGKILL'), 1000); killTimer.unref(); };
    const timer = setTimeout(() => stop('Command timed out; remote operations may already have completed.'), timeoutMs);
    const abort = () => stop('Command canceled; remote operations may already have completed.');
    signal?.addEventListener('abort', abort, { once: true });
    const capture = (key, data) => {
      bytes += data.length;
      if (bytes > maxBytes) { stop('Output exceeded 1 MiB. Narrow the command with service filters or --max-items.'); return; }
      if (key === 'out') stdout += data.toString(); else stderr += data.toString();
    };
    child.stdout.on('data', data => capture('out', data)); child.stderr.on('data', data => capture('err', data));
    const cleanup = () => { clearTimeout(timer); clearTimeout(killTimer); signal?.removeEventListener('abort', abort); };
    child.on('error', error => { cleanup(); reject(new Error(error.code === 'ENOENT' ? 'AWS CLI not found. Install AWS CLI v2 or set AWS_MCP_AWS_BIN.' : error.message)); });
    child.on('close', code => { cleanup(); resolve({ exitCode: failure ? 1 : (code ?? 1), stdout, stderr: failure || stderr }); });
  });
}
export class AwsRunner {
  constructor({ profiles = readProfiles, run = runProcess, sessionCache = new MfaSessionCache() } = {}) { this.profiles = profiles; this.run = run; this.sessionCache=sessionCache;this.sessions=sessionCache.sessions; }
  async initSessions(stateDir){await this.sessionCache.init(stateDir,await this.profiles());}
  clearSessions(profile){return this.sessionCache.forget(profile);}
  hasSession(name,profile){return !!this.sessionCache.valid(name,profile?profileFingerprint(profile):undefined);}
  async sessionStatus(){return this.sessionCache.status(await this.profiles());}
  async pruneSessions(){return this.sessionCache.prune(await this.profiles());}
  async close(){await this.sessionCache.close();}
  async context(command, { mfaCode = '', mfaSerial = '', rememberMfa = true, signal } = {}) {
    const profiles = await this.profiles();
    const p = profiles.find(p => p.name === command.profile);
    if (!p) throw new Error('Profile no longer exists.');
    const base = cleanEnv();
    const fingerprint=profileFingerprint(p), epoch=this.sessionCache.epoch(p.name);
    let session = this.sessionCache.valid(p.name,fingerprint);
    const serial = mfaSerial || p.mfaSerial;
    if (mfaCode) {
      if (!/^\d{6}$/.test(mfaCode) || !serial || serial.length > 256 || !/^[\w+=/:,.@-]+$/.test(serial)) throw new Error('Provide a valid MFA device ARN/serial and six-digit code.');
      if (p.sso) throw new Error('Use SSO login for this profile.');
      const authArgs = p.roleArn ? ['sts', 'assume-role', '--role-arn', p.roleArn, '--role-session-name', p.roleSessionName || 'aws-mcp', '--serial-number', serial, '--token-code', mfaCode, '--duration-seconds', '3600'] : ['sts', 'get-session-token', '--serial-number', serial, '--token-code', mfaCode, '--duration-seconds', '3600'];
      if (p.roleArn && !p.sourceProfile) throw new Error('MFA role profiles require source_profile. Use AWS SSO or authenticate this credential source in your terminal.');
      if (p.roleArn && p.externalId) authArgs.push('--external-id', p.externalId);
      authArgs.push('--profile', p.roleArn ? p.sourceProfile : p.name, '--output', 'json');
      const result = await this.run(authArgs, { env: base, signal });
      if (result.exitCode !== 0) throw new Error('MFA authentication failed. Check the device, code, source profile, and permissions.');
      let c; try { c = JSON.parse(result.stdout).Credentials; } catch { throw new Error('Invalid STS credential response.'); }
      if (!c?.AccessKeyId || !c.SecretAccessKey || !c.SessionToken || !Number.isFinite(Date.parse(c.Expiration))) throw new Error('Incomplete STS credential response.');
      session = { fingerprint, serial, env: { AWS_ACCESS_KEY_ID: c.AccessKeyId, AWS_SECRET_ACCESS_KEY: c.SecretAccessKey, AWS_SESSION_TOKEN: c.SessionToken }, expires: Date.parse(c.Expiration) };
      if(signal?.aborted)throw new Error('Authentication canceled. No MFA session was saved.');
      session=await this.sessionCache.put(p.name,session,{remember:rememberMfa,epoch});
    }
    if (p.mfaSerial && !session && !(command.args[0] === 'sso' && command.args[1] === 'login')) throw new Error('This profile requires MFA. Submit a new request and enter its code in the approval dialog.');
    return { p, base, session };
  }
  async execute(command, auth = {}) {
    const { p, base, session } = await this.context(command, auth);
    const signal = auth.signal;
    const args = [...command.args, '--output', 'json', '--no-cli-pager'];
    // Temporary credentials already represent the selected profile/role.
    if (!session) args.push('--profile', p.name);
    const region = command.region || p.region;
    if (region) args.push('--region', region);
    const result = await this.run(args, { env: { ...base, ...session?.env }, signal });
    return { ...result, stdout: redact(result.stdout), stderr: redact(result.stderr) };
  }
}
