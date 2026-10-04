import type { ExtensionAPI } from '@earendil-works/pi-coding-agent';
import { readFile, writeFile, mkdir, readdir, realpath } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import { constants } from 'node:fs';
const roots = ['/workspace/inputs','/workspace/outputs','/opt/resources'];
const result = (text: string) => ({content:[{type:'text' as const,text}],details:{}});
async function allowed(path: string, writing = false) {
  const absolute = resolve('/workspace', path);
  const root = roots.find(r=>absolute===r || absolute.startsWith(r+'/'));
  if (!root || (writing && root !== '/workspace/outputs')) throw new Error('Workspace path denied');
  if (!writing) {
    const canonical = await realpath(absolute);
    if (!(canonical===root || canonical.startsWith(root+'/'))) throw new Error('Symlink path denied');
  } else {
    // Verify the nearest existing ancestor before creating any directories. A denied symlink
    // must not cause mkdir to mutate a private path before the later containment check.
    let ancestor = dirname(absolute);
    for (;;) {
      try {
        const canonical = await realpath(ancestor);
        if (!(canonical===root || canonical.startsWith(root+'/'))) throw new Error('Output path denied');
        break;
      } catch (error: any) {
        if (error.code !== 'ENOENT' || ancestor===root) throw error;
        ancestor = dirname(ancestor);
      }
    }
    await mkdir(dirname(absolute),{recursive:true});
    const canonical = await realpath(dirname(absolute));
    if (!(canonical===root || canonical.startsWith(root+'/'))) throw new Error('Output path denied');
  }
  return absolute;
}
export default function(api: ExtensionAPI) {
  api.registerTool({name:'numen_read',label:'Read source evidence',description:'Read a bounded source or bundled audit resource file. Paths under inputs/, outputs/, /opt/resources only.',
    parameters:{type:'object',properties:{path:{type:'string'}},required:['path'],additionalProperties:false} as any,
    async execute(_id,args:any) {const data=await readFile(await allowed(args.path));if(data.length>1048576)throw new Error('File exceeds read limit');return result(data.toString('utf8'));}});
  api.registerTool({name:'numen_list',label:'List evidence files',description:'List files within the supplied evidence/resources directories.',
    parameters:{type:'object',properties:{path:{type:'string'}},required:['path'],additionalProperties:false} as any,
    async execute(_id,args:any) {return result((await readdir(await allowed(args.path))).slice(0,1000).join('\n'));}});
  api.registerTool({name:'numen_write',label:'Write artifact',description:'Write a bounded artifact under outputs/ only.',
    parameters:{type:'object',properties:{path:{type:'string'},content:{type:'string'}},required:['path','content'],additionalProperties:false} as any,
    async execute(_id,args:any) {if(Buffer.byteLength(args.content)>1048576)throw new Error('Artifact exceeds write limit');const path=await allowed(args.path,true);await writeFile(path,args.content,{flag:constants.O_WRONLY|constants.O_CREAT|constants.O_TRUNC|constants.O_NOFOLLOW});return result('Artifact written');}});
  api.registerTool({name:'target_fetch',label:'Fetch scoped target',description:'Read the registered target via its request-budgeted capability gateway. Only GET or HEAD.',
    parameters:{type:'object',properties:{url:{type:'string'},method:{type:'string',enum:['GET','HEAD']}},required:['url'],additionalProperties:false} as any,
    async execute(_id,args:any) {if(!process.env.NUMEN_FETCH_URL)throw new Error('No target capability for this job');const response=await fetch(process.env.NUMEN_FETCH_URL,{method:'POST',headers:{'Content-Type':'application/json','X-Fetch-Token':process.env.NUMEN_FETCH_TOKEN!},body:JSON.stringify({url:args.url,method:args.method||'GET'})});if(!response.ok)throw new Error('Scoped target request denied or unavailable');return result(JSON.stringify(await response.json()));}});
}
