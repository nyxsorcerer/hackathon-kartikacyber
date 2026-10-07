import type { ExtensionAPI } from '@earendil-works/pi-coding-agent';
import { readFile, writeFile, mkdir, readdir, realpath } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import { constants } from 'node:fs';
import { execFile } from 'node:child_process';
// A build run clones and installs under /workspace, so reads span it. Its shell can already
// write anywhere there, so scratch files (a dev build context, notes) may be written there too:
// only outputs/ is ever published, and the read-only evidence under inputs/ is never a target.
// Other runs write their artifacts under outputs/ only.
const roots = process.env.DOCKER_HOST
  ? ['/workspace','/opt/resources']
  : ['/workspace/inputs','/workspace/outputs','/opt/resources'];
const WRITE_ROOT = process.env.DOCKER_HOST ? '/workspace' : '/workspace/outputs';
const READ_ONLY = '/workspace/inputs';
const within = (path: string, root: string) => path===root || path.startsWith(root+'/');
const writable = (path: string) => within(path, WRITE_ROOT) && !within(path, READ_ONLY);
const result = (text: string) => ({content:[{type:'text' as const,text}],details:{}});
async function allowed(path: string, writing = false) {
  const absolute = resolve('/workspace', path);
  const read = roots.find(r=>within(absolute, r));
  const root = writing ? WRITE_ROOT : read;
  if (!read || (writing && !writable(absolute))) throw new Error('Workspace path denied');
  if (!writing) {
    const canonical = await realpath(absolute);
    if (!within(canonical, root!)) throw new Error('Symlink path denied');
  } else {
    // Verify the nearest existing ancestor before creating any directories. A denied symlink
    // must not cause mkdir to mutate a private path before the later containment check.
    let ancestor = dirname(absolute);
    for (;;) {
      try {
        const canonical = await realpath(ancestor);
        if (!writable(canonical) && canonical!==WRITE_ROOT) throw new Error('Output path denied');
        break;
      } catch (error: any) {
        if (error.code !== 'ENOENT' || ancestor===root) throw error;
        ancestor = dirname(ancestor);
      }
    }
    await mkdir(dirname(absolute),{recursive:true});
    const canonical = await realpath(dirname(absolute));
    if (!writable(canonical)) throw new Error('Output path denied');
  }
  return absolute;
}
const SHELL_BUFFER = 16777216;  // A build's own output, which would otherwise kill the command.
const SHELL_REPLY = 262144;     // What is handed back: the tail, where a failure reports itself.
function shell(command: string, timeout: number) {
  return new Promise<string>((done)=>{
    execFile('/bin/sh',['-c',command],{cwd:'/workspace',timeout:timeout*1000,maxBuffer:SHELL_BUFFER,killSignal:'SIGKILL'},
      (error,stdout,stderr)=>{
        const output = `${stdout}${stderr}`;
        const kept = output.length > SHELL_REPLY ? `[earlier output truncated]\n${output.slice(-SHELL_REPLY)}` : output;
        done(`exit=${error?((error as any).code ?? 'signal'):0}\n${kept}`);
      });
  });
}
export default function(api: ExtensionAPI) {
  api.registerTool({name:'numen_read',label:'Read source evidence',description:'Read a bounded source or bundled audit resource file. Paths under inputs/, outputs/, /opt/resources only.',
    parameters:{type:'object',properties:{path:{type:'string'}},required:['path'],additionalProperties:false} as any,
    async execute(_id,args:any) {const data=await readFile(await allowed(args.path));if(data.length>1048576)throw new Error('File exceeds read limit');return result(data.toString('utf8'));}});
  api.registerTool({name:'numen_list',label:'List evidence files',description:'List files within the supplied evidence/resources directories.',
    parameters:{type:'object',properties:{path:{type:'string'}},required:['path'],additionalProperties:false} as any,
    async execute(_id,args:any) {return result((await readdir(await allowed(args.path))).slice(0,1000).join('\n'));}});
  api.registerTool({name:'numen_write',label:'Write artifact',description:'Write a bounded file. In a build run any path in the writable /workspace except inputs/ (scratch files there are never published; only outputs/ is). Otherwise under outputs/ only.',
    parameters:{type:'object',properties:{path:{type:'string'},content:{type:'string'}},required:['path','content'],additionalProperties:false} as any,
    async execute(_id,args:any) {if(Buffer.byteLength(args.content)>1048576)throw new Error('Artifact exceeds write limit');const path=await allowed(args.path,true);await writeFile(path,args.content,{flag:constants.O_WRONLY|constants.O_CREAT|constants.O_TRUNC|constants.O_NOFOLLOW});return result('Artifact written');}});
  api.registerTool({name:'numen_shell',label:'Run a build command',description:'Run one shell command in the writable /workspace of a build-enabled run. git, docker (DOCKER_HOST) and dependency installers are available. Output and runtime are bounded; the command cannot be interactive.',
    parameters:{type:'object',properties:{command:{type:'string'},timeout_seconds:{type:'number'}},required:['command'],additionalProperties:false} as any,
    async execute(_id,args:any) {if(!process.env.DOCKER_HOST)throw new Error('No build capability for this job');return result(await shell(args.command,Math.min(Math.max(Number(args.timeout_seconds)||600,1),3600)));}});
  api.registerTool({name:'target_fetch',label:'Fetch scoped target',description:'Read the registered target via its request-budgeted capability gateway. Only GET or HEAD.',
    parameters:{type:'object',properties:{url:{type:'string'},method:{type:'string',enum:['GET','HEAD']}},required:['url'],additionalProperties:false} as any,
    async execute(_id,args:any) {if(!process.env.NUMEN_FETCH_URL)throw new Error('No target capability for this job');const response=await fetch(process.env.NUMEN_FETCH_URL,{method:'POST',headers:{'Content-Type':'application/json','X-Fetch-Token':process.env.NUMEN_FETCH_TOKEN!},body:JSON.stringify({url:args.url,method:args.method||'GET'})});if(!response.ok)throw new Error('Scoped target request denied or unavailable');return result(JSON.stringify(await response.json()));}});
}
