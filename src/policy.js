import { randomUUID } from 'node:crypto';
import { readFile, writeFile, rename } from 'node:fs/promises';
import { join } from 'node:path';
import { validateCommand } from './aws.js';

// Deliberate operation names, not prefix matching. Unknown/new APIs never become
// automatic merely because their names look like reads. This is not IAM enforcement.
const reads = {
  sts: ['get-caller-identity'],
  ec2: ['describe-instances', 'describe-vpcs', 'describe-subnets', 'describe-security-groups', 'describe-regions', 'describe-availability-zones', 'describe-volumes', 'describe-snapshots', 'describe-images', 'describe-tags', 'describe-network-interfaces', 'describe-route-tables', 'describe-addresses'],
  rds: ['describe-db-instances', 'describe-db-clusters', 'describe-db-snapshots', 'describe-db-subnet-groups', 'describe-events', 'list-tags-for-resource'],
  s3: ['ls'],
  s3api: ['list-buckets', 'list-objects-v2', 'head-object', 'get-bucket-location', 'get-bucket-tagging'],
  ecs: ['list-clusters', 'list-services', 'list-tasks', 'describe-clusters', 'describe-services'],
  eks: ['list-clusters', 'describe-cluster', 'list-nodegroups', 'describe-nodegroup'],
  lambda: ['list-functions', 'list-versions-by-function', 'list-aliases'],
  cloudformation: ['list-stacks', 'describe-stack-events', 'describe-stack-resources', 'list-stack-resources'],
  cloudwatch: ['list-metrics', 'describe-alarms', 'get-metric-data', 'get-metric-statistics'],
  logs: ['describe-log-groups', 'describe-log-streams'],
  iam: ['list-users', 'list-roles', 'list-policies', 'get-role', 'get-user', 'list-attached-role-policies'],
  dynamodb: ['list-tables', 'describe-table'],
  ssm: ['describe-instance-information', 'describe-parameters'],
  secretsmanager: ['list-secrets', 'describe-secret'],
};
const sensitive = new Set(['lambda/get-function-configuration', 'ecs/describe-task-definition', 'ecs/describe-tasks', 'cloudformation/describe-stacks', 'secretsmanager/get-secret-value', 'secretsmanager/batch-get-secret-value', 'ssm/get-parameter', 'ssm/get-parameters', 'ssm/get-parameters-by-path', 'logs/get-log-events', 'logs/filter-log-events', 'ec2/get-password-data', 'lambda/get-function']);
const neverAuto = new Set(['s3api/get-object', 'lambda/invoke', 'bedrock-runtime/invoke-model', 'ssm/start-session', 'sso/login', 'sso/logout', 'cloudformation/package', 'cloudformation/deploy']);
export function classifyCommand(args) {
  const key = args.slice(0, 2).join('/');
  return { read: !!reads[args[0]]?.includes(args[1]) || sensitive.has(key), sensitive: sensitive.has(key), manualOnly: neverAuto.has(key) || (args[0] === 's3' && args[1] !== 'ls') };
}
const same = (a,b) => JSON.stringify(a) === JSON.stringify(b);
const text = (value, max = 256) => typeof value === 'string' && value.length <= max && !/[\x00-\x1f\x7f]/.test(value);
function ruleScope(rule) { return { name:rule.name, profile:rule.profile, region:rule.region, args:rule.args, match:rule.match, action:rule.action, expiresAt:rule.expiresAt }; }
export class PolicyService {
  constructor({ now = Date.now } = {}) {
    this.now = now;
    this.current = { revision:randomUUID(), mode:'manual', paused:false, defaultDelivery:'direct', protectedProfiles:[], rules:[] };
    this.saving = false;
  }
  view() { return structuredClone({ ...this.current, sensitiveReads:[...sensitive].map(key=>key.replace('/',' ')), catalog: Object.entries(reads).flatMap(([service, ops]) => ops.map(op => `${service} ${op}`)) }); }
  async init(stateDir) {
    this.file = stateDir ? join(stateDir, 'policies.json') : undefined;
    if (!this.file) return;
    try {
      const saved = JSON.parse(await readFile(this.file, 'utf8'));
      this.current = { ...this.validate(saved, { trusted: true }), revision:saved.revision || randomUUID() };
    } catch (e) { if (e.code !== 'ENOENT') throw new Error('Could not load approval policies. Repair policies.json before restarting.'); }
  }
  validate(input, { trusted = false } = {}) {
    if (!input || !['manual','auto_reads','read_only'].includes(input.mode)) throw new Error('Choose a valid approval mode.');
    if (typeof input.paused !== 'boolean' || !['direct','review'].includes(input.defaultDelivery)) throw new Error('Invalid automation or result-delivery setting.');
    if (!Array.isArray(input.protectedProfiles) || input.protectedProfiles.length > 100 || input.protectedProfiles.some(p => !text(p) || !p)) throw new Error('Invalid protected profiles.');
    if (!Array.isArray(input.rules) || input.rules.length > 100) throw new Error('At most 100 command rules are supported.');
    const ids = new Set();
    const rules = input.rules.map(raw => {
      if (!raw || !text(raw.name,80) || !raw.name.trim() || !text(raw.profile) || !raw.profile || !['allow','ask','deny'].includes(raw.action) || !['exact','operation'].includes(raw.match) || typeof raw.enabled !== 'boolean') throw new Error('Invalid command rule.');
      const region = raw.region || '';
      const command = validateCommand({ profile:raw.profile, args:raw.args, region }, [{name:raw.profile}]);
      if (raw.match === 'operation' && command.args.length !== 2) throw new Error('An operation-wide rule must contain only its service and operation.');
      const expiresAt = raw.expiresAt ?? null;
      if (expiresAt !== null && (!Number.isSafeInteger(expiresAt) || expiresAt < 0)) throw new Error('Invalid rule expiry.');
      const id = raw.id || randomUUID();
      if (!/^[a-f0-9-]{36}$/.test(id) || ids.has(id)) throw new Error('Invalid or duplicate rule ID.'); ids.add(id);
      const rule = { id, name:raw.name.trim(), profile:raw.profile, region, args:command.args, match:raw.match, action:raw.action, enabled:raw.enabled, expiresAt };
      const classification = classifyCommand(rule.args);
      if (rule.action === 'allow' && classification.manualOnly) throw new Error('This operation interacts with local files or sessions and always requires a popup.');
      if (rule.action === 'allow' && (!classification.read || classification.sensitive)) {
        const old = this.current.rules.find(r => r.id === id);
        const alreadyConfirmed = old?.confirmed && same(ruleScope(old),ruleScope(rule));
        if (!trusted && !alreadyConfirmed && raw.confirmCommand !== rule.args.slice(0,2).join(' ')) throw new Error('Type the service and operation to confirm automatic approval of a change or sensitive read.');
        rule.confirmed = true;
      }
      return rule;
    });
    return { mode:input.mode, paused:input.paused, defaultDelivery:input.defaultDelivery, protectedProfiles:[...new Set(input.protectedProfiles)], rules };
  }
  async save(input, { audit = async()=>{} } = {}) {
    if (this.saving) throw new Error('Another policy save is in progress. Try again.');
    if (input.revision !== this.current.revision) throw new Error('Policies changed in another tab. Reload policies before saving.');
    const next = { ...this.validate(input), revision:randomUUID() };
    this.saving = true;
    try {
      await audit(next); // Fail closed: an unaudited policy is never activated.
      if (this.file) { await writeFile(this.file+'.tmp',JSON.stringify(next,null,2),{mode:0o600}); await rename(this.file+'.tmp',this.file); }
      this.current = next;
      return this.view();
    } finally { this.saving = false; }
  }
  evaluate(request, profile = {}) {
    const c = this.current;
    const decision = (action,reason,rule) => ({ action, reason, revision:c.revision, ...(rule ? {ruleId:rule.id,ruleName:rule.name} : {}) });
    if (request.kind !== 'aws') return decision('ask','Database queries and managed tunnels require manual approval.');
    const category = classifyCommand(request.args);
    const region = request.region || profile.region || '';
    const matches = c.rules.filter(r => r.enabled && (r.expiresAt === null || r.expiresAt > this.now()) && (r.profile === '*' || r.profile === request.profile) && (!r.region || r.region === region) && (r.match === 'exact' ? same(r.args,request.args) : same(r.args,request.args.slice(0,2))));
    if (c.mode === 'read_only' && !category.read) return decision('deny','Read-only mode blocks writes and operations outside the recognized read catalog.');
    const denied = matches.find(r => r.action === 'deny'); if (denied) return decision('deny',`Blocked by rule: ${denied.name}`,denied);
    if (category.manualOnly) return decision('ask','Local-file and interactive-session operations always require manual approval.');
    if (c.paused) return decision('ask','Automatic approvals are paused.');
    if (c.protectedProfiles.includes(request.profile)) return decision('ask','This profile is protected: always ask before execution.');
    const asked = matches.find(r => r.action === 'ask'); if (asked) return decision('ask',`Manual approval required by rule: ${asked.name}`,asked);
    const allowed = matches.find(r => r.action === 'allow'); if (allowed) return decision('allow',`Automatically allowed by rule: ${allowed.name}`,allowed);
    if (category.sensitive) return decision('ask','This read may expose secrets or application data. Add an explicit rule or approve it manually.');
    if (c.mode !== 'manual' && category.read) return decision('allow','Recognized read operation automatically allowed by your policy.');
    return decision('ask',category.read ? 'Manual approval is selected; no Allow rule matched.' : 'No Allow rule matched. Unknown operations and changes need manual approval.');
  }
}
