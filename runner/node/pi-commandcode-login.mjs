import { createInterface } from 'node:readline';
import { createAgentSession, DefaultResourceLoader, ModelRuntime, SessionManager, SettingsManager } from '@earendil-works/pi-coding-agent';
// Runs the bundled plugin's own /login through pi. Studio cannot reach a localhost callback inside
// the managed container, so skip straight to the plugin's paste fallback once the URL is shown.
process.env.COMMANDCODE_AUTH_TIMEOUT_MS = '1';
const agentDir = process.env.PI_CODING_AGENT_DIR;
const modelRuntime = await ModelRuntime.create({authPath:`${agentDir}/auth.json`, modelsPath:`${agentDir}/models.json`});
const settingsManager = SettingsManager.create('/workspace', agentDir);
const resourceLoader = new DefaultResourceLoader({cwd:'/workspace', agentDir, settingsManager, noExtensions:true, noSkills:true, noPromptTemplates:true, noThemes:true, noContextFiles:true,
  additionalExtensionPaths:['/opt/numen/node_modules/pi-commandcode-provider/index.ts']});
await resourceLoader.reload();
if (resourceLoader.getExtensions().errors?.length) { console.log(JSON.stringify({error:'plugin_incompatible'})); process.exit(3); }
const {session} = await createAgentSession({cwd:'/workspace', agentDir, modelRuntime, settingsManager, resourceLoader, sessionManager:SessionManager.inMemory(), tools:[]});
await session.bindExtensions({mode:'rpc'});
const lines = createInterface({input:process.stdin})[Symbol.asyncIterator]();
let prompts = 0;
// Only the Studio URL reaches stdout. The pasted key arrives as one stdin line and pi stores the
// resulting credential in its private auth.json; neither is printed.
await modelRuntime.login('commandcode', 'oauth', {
  notify(event) {
    if (event.type === 'auth_url' && typeof event.url === 'string') console.log(event.url);
  },
  async prompt() {
    // The first prompt selects the flow; an empty answer chooses browser login.
    if (prompts++ === 0) return '';
    const next = await lines.next();
    if (next.done) throw new Error('No Command Code API key provided');
    return next.value;
  },
});
await session.dispose();
process.exit(0);
