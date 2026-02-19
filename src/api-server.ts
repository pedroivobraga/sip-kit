/**
 * HTTP Management API for sip-kit.
 *
 * Allows external applications (e.g. .NET) to dynamically manage
 * the server list, credentials, and monitor active sessions.
 *
 * Endpoints:
 *   POST   /api/servers          - Replace entire server list
 *   GET    /api/servers          - List all configured servers
 *   PUT    /api/servers/:name    - Add or update a single server
 *   DELETE /api/servers/:name    - Remove a server by name
 *   GET    /api/sessions         - List active media/call sessions
 *   GET    /api/status           - Health check
 */

import * as http from 'http';
import { SipServer } from './types';

export interface ApiDependencies {
  getServers: () => SipServer[];
  setServers: (servers: SipServer[]) => void;
  addOrUpdateServer: (server: SipServer) => void;
  removeServer: (name: string) => boolean;
  getActiveSessions: () => object[];
  getRegistrations: () => object[];
}

export class ManagementApi {
  private server: http.Server;
  private deps: ApiDependencies;
  private apiKey: string | undefined;

  constructor(deps: ApiDependencies, apiKey?: string) {
    this.deps = deps;
    this.apiKey = apiKey;
    this.server = http.createServer((req, res) => {
      this.handleRequest(req, res).catch(err => {
        console.error('[API] Unhandled error:', err);
        this.json(res, 500, { error: 'Internal server error' });
      });
    });
  }

  async start(host: string, port: number): Promise<void> {
    return new Promise((resolve) => {
      this.server.listen(port, host, () => {
        console.log(`[API] Management API listening on http://${host}:${port}`);
        console.log(`[API] Endpoints:`);
        console.log(`  GET    /api/status`);
        console.log(`  GET    /api/servers`);
        console.log(`  POST   /api/servers`);
        console.log(`  PUT    /api/servers/:name`);
        console.log(`  DELETE /api/servers/:name`);
        console.log(`  GET    /api/sessions`);
        console.log(`  GET    /api/registrations`);
        resolve();
      });
    });
  }

  stop(): void {
    this.server.close();
  }

  private async handleRequest(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    // CORS headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Api-Key');

    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    // API key authentication (if configured)
    if (this.apiKey) {
      const providedKey = req.headers['x-api-key'];
      if (providedKey !== this.apiKey) {
        this.json(res, 401, { error: 'Invalid or missing API key. Set X-Api-Key header.' });
        return;
      }
    }

    const url = new URL(req.url ?? '/', `http://${req.headers.host}`);
    const path = url.pathname;
    const method = req.method ?? 'GET';

    // Route matching
    if (path === '/api/status' && method === 'GET') {
      return this.handleStatus(res);
    }

    if (path === '/api/servers' && method === 'GET') {
      return this.handleGetServers(res);
    }

    if (path === '/api/servers' && method === 'POST') {
      return this.handleSetServers(req, res);
    }

    // /api/servers/:name
    const serverMatch = path.match(/^\/api\/servers\/(.+)$/);
    if (serverMatch) {
      const name = decodeURIComponent(serverMatch[1]);
      if (method === 'PUT') {
        return this.handlePutServer(req, res, name);
      }
      if (method === 'DELETE') {
        return this.handleDeleteServer(res, name);
      }
    }

    if (path === '/api/sessions' && method === 'GET') {
      return this.handleGetSessions(res);
    }

    if (path === '/api/registrations' && method === 'GET') {
      return this.handleGetRegistrations(res);
    }

    this.json(res, 404, { error: 'Not found' });
  }

  // --- Handlers ---

  private handleStatus(res: http.ServerResponse): void {
    this.json(res, 200, {
      status: 'ok',
      uptime: process.uptime(),
      servers: this.deps.getServers().length,
      sessions: this.deps.getActiveSessions().length,
    });
  }

  private handleGetServers(res: http.ServerResponse): void {
    const servers = this.deps.getServers().map(s => ({
      name: s.name,
      host: s.host,
      port: s.port,
      transport: s.transport,
      realm: s.realm,
      username: s.username,
      // Credentials masked for security
      hasPassword: !!s.password,
      hasHa1Digest: !!s.ha1Digest,
      authMode: s.ha1Digest ? 'ha1Digest' : s.password ? 'password' : 'none',
    }));
    this.json(res, 200, { servers });
  }

  private async handleSetServers(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const body = await this.readBody(req);
    if (!body) {
      this.json(res, 400, { error: 'Empty request body' });
      return;
    }

    let data: any;
    try {
      data = JSON.parse(body);
    } catch {
      this.json(res, 400, { error: 'Invalid JSON' });
      return;
    }

    if (!Array.isArray(data.servers)) {
      this.json(res, 400, { error: 'Expected { servers: [...] }' });
      return;
    }

    const servers: SipServer[] = [];
    for (const s of data.servers) {
      const validation = this.validateServer(s);
      if (validation) {
        this.json(res, 400, { error: validation });
        return;
      }
      servers.push({
        name: s.name,
        host: s.host,
        port: s.port ?? 5060,
        transport: s.transport ?? 'udp',
        realm: s.realm,
        username: s.username,
        password: s.password,
        ha1Digest: s.ha1Digest,
      });
    }

    this.deps.setServers(servers);
    console.log(`[API] Server list replaced: ${servers.length} server(s)`);
    this.json(res, 200, { message: `Updated ${servers.length} server(s)`, count: servers.length });
  }

  private async handlePutServer(
    req: http.IncomingMessage,
    res: http.ServerResponse,
    name: string,
  ): Promise<void> {
    const body = await this.readBody(req);
    if (!body) {
      this.json(res, 400, { error: 'Empty request body' });
      return;
    }

    let data: any;
    try {
      data = JSON.parse(body);
    } catch {
      this.json(res, 400, { error: 'Invalid JSON' });
      return;
    }

    // Use the URL name if not in body
    data.name = data.name ?? name;

    const validation = this.validateServer(data);
    if (validation) {
      this.json(res, 400, { error: validation });
      return;
    }

    const server: SipServer = {
      name: data.name,
      host: data.host,
      port: data.port ?? 5060,
      transport: data.transport ?? 'udp',
      realm: data.realm,
      username: data.username,
      password: data.password,
      ha1Digest: data.ha1Digest,
    };

    this.deps.addOrUpdateServer(server);
    console.log(`[API] Server added/updated: ${server.name} (${server.host}:${server.port})`);
    this.json(res, 200, { message: `Server '${server.name}' saved` });
  }

  private handleDeleteServer(res: http.ServerResponse, name: string): void {
    const removed = this.deps.removeServer(name);
    if (removed) {
      console.log(`[API] Server removed: ${name}`);
      this.json(res, 200, { message: `Server '${name}' removed` });
    } else {
      this.json(res, 404, { error: `Server '${name}' not found` });
    }
  }

  private handleGetSessions(res: http.ServerResponse): void {
    this.json(res, 200, { sessions: this.deps.getActiveSessions() });
  }

  private handleGetRegistrations(res: http.ServerResponse): void {
    this.json(res, 200, { registrations: this.deps.getRegistrations() });
  }

  // --- Helpers ---

  private validateServer(s: any): string | null {
    if (!s.name || typeof s.name !== 'string') return 'Missing or invalid "name"';
    if (!s.host || typeof s.host !== 'string') return 'Missing or invalid "host"';
    if (s.port !== undefined && (typeof s.port !== 'number' || s.port < 1 || s.port > 65535)) {
      return '"port" must be a number between 1 and 65535';
    }
    if (s.transport !== undefined && s.transport !== 'udp' && s.transport !== 'tcp') {
      return '"transport" must be "udp" or "tcp"';
    }
    return null;
  }

  private json(res: http.ServerResponse, status: number, body: object): void {
    res.writeHead(status, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(body, null, 2));
  }

  private readBody(req: http.IncomingMessage): Promise<string> {
    return new Promise((resolve) => {
      const chunks: Buffer[] = [];
      req.on('data', (chunk: Buffer) => chunks.push(chunk));
      req.on('end', () => resolve(Buffer.concat(chunks).toString('utf-8')));
    });
  }
}
