import { createAgentSession, DefaultResourceLoader, ModelRuntime, SessionManager, SettingsManager } from '@earendil-works/pi-coding-agent';
import { clampThinkingLevel, getSupportedThinkingLevels } from '@earendil-works/pi-ai/compat';
// Read the pinned SDK default rather than describing its explicit native default as managed.
const { DEFAULT_THINKING_LEVEL } = await import(new URL('./core/defaults.js', import.meta.resolve('@earendil-works/pi-coding-agent')));
const provider = process.argv[2];
const agentDir = process.env.PI_CODING_AGENT_DIR;
if (provider === 'commandcode') {
  // The extension's /provider/v1/models catalog is public. Its pinned quota adapter
  // uses this free authenticated endpoint to distinguish valid API-key access.
  const apiKey = process.env.COMMAND_CODE_API_KEY;
  try {
    if (!apiKey) throw new Error('API key missing');
    const response = await fetch('https://api.commandcode.ai/alpha/whoami', {
      headers: {accept:'application/json',Authorization:`Bearer ${apiKey}`},
      signal: AbortSignal.timeout(15000), redirect:'error',
    });
    if (!response.ok) throw new Error('Connection rejected');
    const identity = await response.json();
    const login = identity?.org?.login ?? identity?.user?.userName ?? identity?.user?.name;
    if (typeof login !== 'string' || !login.trim()) throw new Error('Identity unavailable');
  } catch {
    console.log(JSON.stringify({error:'credential_unavailable',models:[],usage:null,status:'unavailable'}));
    process.exit(2);
  }
}
const modelRuntime = await ModelRuntime.create({authPath:`${agentDir}/auth.json`, modelsPath:`${agentDir}/models.json`});
const settingsManager = SettingsManager.create('/workspace', agentDir);
const resourceLoader = new DefaultResourceLoader({cwd:'/workspace', agentDir, settingsManager, noExtensions:true, noSkills:true, noPromptTemplates:true, noThemes:true, noContextFiles:true,
  additionalExtensionPaths: provider === 'commandcode' ? ['/opt/numen/node_modules/pi-commandcode-provider/index.ts'] : []});
await resourceLoader.reload();
if (resourceLoader.getExtensions().errors?.length) { console.log(JSON.stringify({error:"plugin_incompatible"})); process.exit(2); }
const {session} = await createAgentSession({cwd:'/workspace', agentDir, modelRuntime, settingsManager, resourceLoader, sessionManager:SessionManager.inMemory(), tools:[]});
await session.bindExtensions({mode:'rpc'});
const models = await modelRuntime.getAvailable(provider === 'claude' ? 'anthropic' : provider);
console.log(JSON.stringify({models:models.map(m=>{
  const efforts = getSupportedThinkingLevels(m).filter(e=>e!=='off');
  const nativeDefault = clampThinkingLevel(m, settingsManager.getModelThinkingLevel(m.provider,m.id) ?? settingsManager.getDefaultThinkingLevel() ?? DEFAULT_THINKING_LEVEL);
  return {id:m.id,name:m.name,reasoning_efforts:efforts,default_effort:efforts.includes(nativeDefault)?nativeDefault:null};
}),usage:null,status:models.length?'ready':'unavailable'}));
await session.dispose();
