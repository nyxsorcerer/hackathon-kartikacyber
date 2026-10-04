// Native Node fetch/undici use the broker proxy; socket-level direct egress is also denied by the job network.
if (process.env.HTTPS_PROXY) {
  const { ProxyAgent, setGlobalDispatcher } = require('/opt/numen/node_modules/undici');
  setGlobalDispatcher(new ProxyAgent(process.env.HTTPS_PROXY));
}
