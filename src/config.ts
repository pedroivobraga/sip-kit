import * as fs from 'fs';
import * as path from 'path';
import { ProxyConfig, SipServer } from './types';

const DEFAULT_CONFIG_PATH = path.join(process.cwd(), 'config', 'servers.json');

interface ServerConfigFile {
  servers: Array<{
    name: string;
    host: string;
    port?: number;
    transport?: 'udp' | 'tcp';
    realm?: string;
    username?: string;
    password?: string;
  }>;
}

/**
 * Load proxy configuration from environment variables and config file.
 */
export function loadConfig(): ProxyConfig {
  const configPath = process.env.SIP_CONFIG_PATH ?? DEFAULT_CONFIG_PATH;

  let servers: SipServer[] = [];

  if (fs.existsSync(configPath)) {
    const raw = fs.readFileSync(configPath, 'utf-8');
    const file: ServerConfigFile = JSON.parse(raw);
    servers = file.servers.map(s => ({
      name: s.name,
      host: s.host,
      port: s.port ?? 5060,
      transport: s.transport ?? 'udp',
      realm: s.realm,
      username: s.username,
      password: s.password,
    }));
    console.log(`[Config] Loaded ${servers.length} server(s) from ${configPath}`);
  } else {
    console.warn(`[Config] No server config found at ${configPath}, using empty server list`);
  }

  const config: ProxyConfig = {
    localIp: process.env.SIP_LOCAL_IP ?? '0.0.0.0',
    externalIp: process.env.SIP_EXTERNAL_IP ?? getLocalIp(),
    sipPort: parseInt(process.env.SIP_PORT ?? '5060', 10),
    rtpPortMin: parseInt(process.env.RTP_PORT_MIN ?? '10000', 10),
    rtpPortMax: parseInt(process.env.RTP_PORT_MAX ?? '10100', 10),
    stunServer: process.env.STUN_SERVER,
    servers,
    verbose: process.env.SIP_VERBOSE === 'true' || process.env.SIP_VERBOSE === '1',
  };

  return config;
}

/**
 * Try to determine the local IP address.
 */
function getLocalIp(): string {
  const os = require('os');
  const interfaces = os.networkInterfaces();

  for (const name of Object.keys(interfaces)) {
    for (const iface of interfaces[name] ?? []) {
      if (iface.family === 'IPv4' && !iface.internal) {
        return iface.address;
      }
    }
  }

  return '127.0.0.1';
}
