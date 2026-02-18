import { loadConfig } from './config';
import { SipProxy } from './sip-proxy';

async function main(): Promise<void> {
  console.log('=== sip-kit: SIP Proxy with ICE Activation ===');
  console.log();

  const config = loadConfig();
  const proxy = new SipProxy(config);

  // Graceful shutdown
  const shutdown = () => {
    console.log('\nShutting down...');
    proxy.stop();
    process.exit(0);
  };

  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);

  await proxy.start();

  console.log();
  console.log('Proxy is running. Press Ctrl+C to stop.');
  console.log();
  console.log('Usage:');
  console.log('  Configure your SIP client to use this proxy as its outbound proxy.');
  console.log(`  Proxy address: ${config.externalIp}:${config.sipPort}`);
  console.log();
  console.log('  The proxy will:');
  console.log('  - Intercept INVITE messages and inject ICE into SDP');
  console.log('  - Relay media (RTP/RTCP) between client and server');
  console.log('  - Respond to STUN connectivity checks from the client');
  console.log('  - Forward all other SIP messages transparently');
}

main().catch((err) => {
  console.error('Fatal error:', err);
  process.exit(1);
});
