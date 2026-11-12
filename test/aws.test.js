import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AwsRunner, validateCommand, parseIni, readProfiles, cleanEnv, runProcess, commandRisk, redact } from '../src/aws.js';
const profiles = [{ name: 'dev', region: 'us-east-1' }];
test('profile discovery combines files without exposing access keys', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'aws-profiles-'));
  try {
    await writeFile(join(dir, 'config'), '[profile dev]\nregion = us-west-2\nmfa_serial = arn:aws:iam::123:mfa/dev\n[sso-session work]\nsso_region=us-east-1\n');
    await writeFile(join(dir, 'credentials'), '[dev]\naws_access_key_id = secret\n[default]\naws_secret_access_key = another-secret\n');
    const p = await readProfiles({ AWS_CONFIG_FILE: join(dir, 'config'), AWS_SHARED_CREDENTIALS_FILE: join(dir, 'credentials') });
    assert.equal(p.length, 2); assert.equal(p.find(p => p.name === 'dev').region, 'us-west-2'); assert.ok(!JSON.stringify(p).includes('secret'));
    assert.equal(Object.getPrototypeOf(parseIni('[__proto__]\nx=y')), null);
  } finally { await rm(dir, { recursive: true }); }
});
test('validation prevents profile overrides, endpoint overrides and file references', () => {
  for (const arg of ['--profile=prod', '--region', '--debug', '--endpoint-url=https://evil.test', 'file:///etc/passwd', 'fileb://key']) assert.throws(() => validateCommand({ profile: 'dev', args: ['s3', 'ls', arg] }, profiles));
  assert.throws(() => validateCommand({ profile: 'other', args: ['s3', 'ls'] }, profiles));
  assert.throws(() => validateCommand({ profile: 'dev', args: ['configure', 'get'] }, profiles));
  assert.deepEqual(validateCommand({ profile: 'dev', args: ['s3', 'ls'] }, profiles).args, ['s3', 'ls']);
  assert.equal(commandRisk(['ec2', 'terminate-instances']), 'destructive'); assert.equal(commandRisk(['s3', 'sync']), 'destructive');
});
test('ambient credentials cannot override selected profile', () => {
  const env = cleanEnv({ PATH: '/usr/bin', AWS_ACCESS_KEY_ID: 'secret', AWS_DEFAULT_PROFILE: 'prod', AWS_ENDPOINT_URL_S3: 'https://evil.test', AWS_ROLE_ARN: 'arn', AWS_CONFIG_FILE: '/test/config' });
  assert.equal(env.AWS_ACCESS_KEY_ID, undefined); assert.equal(env.AWS_DEFAULT_PROFILE, undefined); assert.equal(env.AWS_ENDPOINT_URL_S3, undefined); assert.equal(env.AWS_ROLE_ARN, undefined); assert.equal(env.AWS_CONFIG_FILE, '/test/config');
});
test('MFA credentials stay in memory and are used for approved execution', async () => {
  const calls = [], p = [{ name: 'dev', mfaSerial: 'arn:aws:iam::123456789012:mfa/dev', region: 'us-east-1' }];
  const runner = new AwsRunner({ profiles: async () => p, run: async (args, options) => {
    calls.push({ args, options }); return args[1] === 'get-session-token' ? { exitCode: 0, stdout: JSON.stringify({ Credentials: { AccessKeyId: 'key', SecretAccessKey: 'secret', SessionToken: 'token', Expiration: new Date(Date.now() + 3600000).toISOString() } }) } : { exitCode: 0, stdout: '{"Account":"123"}', stderr: '' };
  } });
  const command = { profile: 'dev', args: ['sts', 'get-caller-identity'] };
  await assert.rejects(runner.execute(command), /requires MFA/);
  const result = await runner.execute(command, { mfaCode: '123456' });
  assert.equal(result.exitCode, 0); assert.equal(calls.length, 2); assert.equal(calls[1].options.env.AWS_SECRET_ACCESS_KEY, 'secret'); assert.ok(!calls[1].args.includes('--profile'));
  assert.ok(!JSON.stringify(result).includes('secret'));
  await runner.execute(command); assert.equal(calls.length, 3);
  runner.clearSessions(); await assert.rejects(runner.execute(command), /requires MFA/);
});
test('role MFA uses source profile, external ID, and assumes selected role', async () => {
  const calls = [];
  const runner = new AwsRunner({ profiles: async () => [{ name: 'role', roleArn: 'arn:aws:iam::123456789012:role/test', sourceProfile: 'base', externalId: 'external', mfaSerial: 'arn:aws:iam::123456789012:mfa/test' }], run: async (args) => { calls.push(args); return { exitCode: 0, stdout: JSON.stringify({ Credentials: { AccessKeyId: 'key', SecretAccessKey: 'secret', SessionToken: 'token', Expiration: new Date(Date.now() + 3600000).toISOString() } }), stderr: '' }; } });
  await runner.execute({ profile: 'role', args: ['sts', 'get-caller-identity'] }, { mfaCode: '123456' });
  assert.deepEqual(calls[0].slice(0, 2), ['sts', 'assume-role']); assert.ok(calls[0].includes('base')); assert.ok(calls[0].includes('external'));
});
test('runner passes shell syntax literally, limits output and kills timed out commands', async () => {
  const run = (args, options) => runProcess(args, { ...options, executable: process.execPath });
  const result = await run(['-e', 'process.stdout.write(process.argv[1])', '$(touch /tmp/SHOULD_NOT_EXIST); echo test']);
  assert.equal(result.stdout, '$(touch /tmp/SHOULD_NOT_EXIST); echo test');
  const large = await run(['-e', 'process.stdout.write("a".repeat(5000))'], { maxBytes: 100 }); assert.match(large.stderr, /exceeded/);
  const slow = await run(['-e', 'setInterval(()=>{},1000)'], { timeoutMs: 30 }); assert.match(slow.stderr, /timed out/);
});
test('STS credential fields and access key IDs are masked', () => {
  assert.ok(!redact('{"SecretAccessKey": "sensitive", "SessionToken":"session", "AccessKeyId":"key"}').includes('sensitive'));
  assert.match(redact('AKIA1234567890123456'), /REDACTED/);
});
