import test from 'node:test';
import assert from 'node:assert/strict';
import {parseSessionCommand,splitCommand,parseAwsCommand} from '../public/commands.js';
const params={portNumber:['5432'],localPortNumber:['5447'],host:['example.proxy-test123.ap-northeast-1.rds.amazonaws.com']};
const command=`aws ssm start-session \\\n --profile dev\\\n --region ap-northeast-1 \\\n --target i-0123456789abcdef0 \\\n --document-name AWS-StartPortForwardingSessionToRemoteHost \\\n --parameters '${JSON.stringify(params)}'`;
test('multiline full SSM command imports exact forwarding settings without a shell',()=>{
 assert.deepEqual(parseSessionCommand(command),{profile:'dev',region:'ap-northeast-1',instanceId:'i-0123456789abcdef0',host:params.host[0],port:5432,localPort:5447});
 assert.deepEqual(parseSessionCommand(command.replaceAll('\n','\r\n')),parseSessionCommand(command));
 const argv=splitCommand(command);assert.equal(argv[0],'ssm');assert.equal(argv[argv.indexOf('--profile')+1],'dev');assert.ok(!argv.some(arg=>arg.includes('\n')));
});
test('SSM import supports global options, equals options and argv JSON with auto local port',()=>{
 const value='aws --profile=dev --region=us-east-1 ssm start-session --target=i-0123456789abcdef0 --document-name=AWS-StartPortForwardingSessionToRemoteHost --parameters='+"'"+JSON.stringify({...params,localPortNumber:undefined})+"'";
 const imported=parseSessionCommand(value);assert.equal(imported.localPort,0);assert.equal(imported.port,5432);
 assert.deepEqual(parseSessionCommand(JSON.stringify(splitCommand(value))),imported);
});
test('SSM import rejects chained commands, duplicate flags, other documents and invalid parameters',()=>{
 for(const value of [command+' && echo unsafe',command+' --profile other',command.replace('AWS-StartPortForwardingSessionToRemoteHost','AWS-StartSSHSession'),command+' --endpoint-url https://example.com',command.replace('5447','99999'),command.replace('5432','-1'),command.replace('"5447"','"5447","5448"'),command.replace('"host":','"unknown":'),command.replace('i-0123456789abcdef0','not-an-instance')])assert.throws(()=>parseSessionCommand(value));
 assert.throws(()=>parseSessionCommand(command.replace(' --profile dev\\\n',' ')),/Include/);
});
test('command text preserves quoted empty arguments and literal shell expressions without executing',()=>{
 assert.deepEqual(splitCommand(`aws sts example '' "a b" '$HOME' '$(not-executed)'`),['sts','example','','a b','$HOME','$(not-executed)']);
 assert.throws(()=>splitCommand('aws sts example "open'),/Close/);assert.throws(()=>splitCommand('["sts",42]'),/string/);
});

test('full AWS command input extracts controlled profile/region without forwarding override flags',()=>{
 assert.deepEqual(parseAwsCommand('aws --profile dev sts get-caller-identity --region=us-east-1',{profile:'other',region:'us-west-2'}),{args:['sts','get-caller-identity'],profile:'dev',region:'us-east-1'});
 assert.deepEqual(parseAwsCommand('sts get-caller-identity',{profile:'dev'}),{args:['sts','get-caller-identity'],profile:'dev',region:''});
 assert.throws(()=>parseAwsCommand('aws sts get-caller-identity --profile dev --profile other'),/Duplicate/);
 assert.throws(()=>parseAwsCommand('aws sts get-caller-identity --region'),/Missing/);
});
