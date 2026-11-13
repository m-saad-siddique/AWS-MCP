// Parse text into argv only. Nothing in this module invokes a shell.
export function splitCommand(value) {
  if (value.trim().startsWith('[')) {
    const args=JSON.parse(value);
    if(!Array.isArray(args)||args.some(arg=>typeof arg!=='string'))throw new Error('Expected a JSON array of string arguments.');
    return args;
  }
  const args=[];let word='',quote='',started=false;
  const input=value.trim();
  for(let i=0;i<input.length;i++){
    const char=input[i];
    if(char==='\\'&&quote!=="'"){
      if(input[i+1]==='\n'){i++;continue;}
      if(input[i+1]==='\r'&&input[i+2]==='\n'){i+=2;continue;}
      if(i+1===input.length)throw new Error('Close the quote or escape in your command.');
      word+=input[++i];started=true;continue;
    }
    if(quote){if(char===quote)quote='';else word+=char;started=true;continue;}
    if(char==='"'||char==="'"){quote=char;started=true;continue;}
    if(/\s/.test(char)){if(started){args.push(word);word='';started=false;}}else{word+=char;started=true;}
  }
  if(quote)throw new Error('Close the quote or escape in your command.');
  if(started)args.push(word);
  if(args[0]==='aws')args.shift();
  return args;
}

export function parseSessionCommand(value) {
  const args=splitCommand(value);if(args[0]==='aws')args.shift();
  const allowed=new Set(['profile','region','target','document-name','parameters']),flags={},positionals=[];
  for(let i=0;i<args.length;i++){
    const arg=args[i];
    if(!arg.startsWith('--')){positionals.push(arg);continue;}
    const equal=arg.indexOf('='),key=arg.slice(2,equal<0?undefined:equal);
    if(!allowed.has(key))throw new Error('Unsupported SSM option: --'+key+'. Use the forwarding options shown below.');
    if(Object.hasOwn(flags,key))throw new Error('Duplicate SSM option: --'+key+'.');
    const value=equal<0?args[++i]:arg.slice(equal+1);
    if(!value||value.startsWith('--'))throw new Error('Missing value for --'+key+'.');
    flags[key]=value;
  }
  if(positionals.length!==2||positionals[0]!=='ssm'||positionals[1]!=='start-session')throw new Error('Paste one aws ssm start-session command. Shell scripts and chained commands are not supported.');
  if(flags['document-name']!=='AWS-StartPortForwardingSessionToRemoteHost')throw new Error('Use the AWS-StartPortForwardingSessionToRemoteHost document.');
  if(!flags.profile||!flags.region||!flags.target)throw new Error('Include --profile, --region and --target in the command.');
  if(!/^[a-z0-9-]{3,40}$/.test(flags.region)||!/^i-[a-f0-9]{8,17}$/.test(flags.target))throw new Error('Invalid AWS region or EC2 target.');
  let params;try{params=JSON.parse(flags.parameters);}catch{throw new Error('--parameters must contain a quoted JSON object.');}
  if(!params||Array.isArray(params)||typeof params!=='object'||Object.keys(params).some(k=>!['host','portNumber','localPortNumber'].includes(k)))throw new Error('Use only host, portNumber and localPortNumber parameters.');
  const single=key=>{const values=params[key];if(!Array.isArray(values)||values.length!==1||typeof values[0]!=='string')throw new Error(key+' must contain exactly one string.');return values[0];};
  const host=single('host');
  if(!/^[a-zA-Z0-9][a-zA-Z0-9.-]{1,252}$/.test(host)||host.includes('..'))throw new Error('Use a database hostname without a protocol or port.');
  const portValue=key=>{const value=single(key),port=Number(value);if(!/^\d+$/.test(value)||!Number.isInteger(port)||port<1||port>65535)throw new Error('Invalid '+key+'. Choose a port from 1 to 65535.');return port;};
  return {profile:flags.profile,region:flags.region,instanceId:flags.target,host,port:portValue('portNumber'),localPort:params.localPortNumber===undefined?0:portValue('localPortNumber')};
}

export function parseAwsCommand(value,{profile='',region=''}={}){
 const input=splitCommand(value),args=[],seen=new Set();if(input[0]==='aws')input.shift();
 for(let i=0;i<input.length;i++){
  const token=input[i],match=token.match(/^--(profile|region)(?:=(.*))?$/s);
  if(!match){args.push(token);continue;}
  const key=match[1];if(seen.has(key))throw new Error('Duplicate --'+key+'.');seen.add(key);
  const field=match[2]===undefined?input[++i]:match[2];if(!field||field.startsWith('--'))throw new Error('Missing value for --'+key+'.');
  if(key==='profile')profile=field;else region=field;
 }
 return {args,profile,region};
}
