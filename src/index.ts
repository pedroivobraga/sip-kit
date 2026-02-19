import { loadConfig } from './config';
import { SipProxy } from './sip-proxy';
import { ManagementApi } from './api-server';

async function main(): Promise<void> {
  console.log('=== sip-kit: SIP Proxy with ICE Activation ===');
  console.log();

  const config = loadConfig();
  const proxy = new SipProxy(config);

  // Start SIP proxy
  await proxy.start();

  // Start management API
  const apiPort = parseInt(process.env.API_PORT ?? '8080', 10);
  const apiHost = process.env.API_HOST ?? '0.0.0.0';
  const apiKey = process.env.API_KEY;

  const api = new ManagementApi({
    getServers: () => proxy.getServers(),
    setServers: (servers) => proxy.setServers(servers),
    addOrUpdateServer: (server) => proxy.addOrUpdateServer(server),
    removeServer: (name) => proxy.removeServer(name),
    getActiveSessions: () => proxy.getActiveSessions(),
    getRegistrations: () => proxy.getRegistrations(),
  }, apiKey);

  await api.start(apiHost, apiPort);

  // Graceful shutdown
  const shutdown = () => {
    console.log('\nShutting down...');
    api.stop();
    proxy.stop();
    process.exit(0);
  };

  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);

  console.log();
  console.log('Proxy is running. Press Ctrl+C to stop.');
  console.log();
  console.log(`SIP Proxy:      ${config.externalIp}:${config.sipPort} (UDP)`);
  console.log(`Management API: http://${apiHost}:${apiPort}`);
  if (apiKey) {
    console.log(`API Key:        configured (use X-Api-Key header)`);
  } else {
    console.log(`API Key:        not set (API is open - set API_KEY env var to secure it)`);
  }
}

main().catch((err) => {
  console.error('Fatal error:', err);
  process.exit(1);
});
