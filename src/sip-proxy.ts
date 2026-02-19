/**
 * SIP Proxy with synthetic ICE activation.
 *
 * Flow:
 * 1. Client sends SIP messages to the proxy
 * 2. For INVITE: proxy modifies SDP to inject ICE, allocates media relay
 * 3. For other messages: proxy forwards transparently
 * 4. Responses from server are modified (ICE injected in SDP) and forwarded to client
 * 5. Media is relayed through the allocated relay ports
 *
 * The proxy maintains a mapping of dialogs to route responses correctly.
 */

import * as dgram from 'dgram';
import * as crypto from 'crypto';
import { ProxyConfig, SipServer, SipDialog } from './types';
import {
  parseSipMessage,
  serializeSipMessage,
  getCallId,
  getHeader,
  setHeader,
  getFromTag,
  getToTag,
  getCSeqMethod,
  parseSipUri,
  SipMessage,
} from './sip-parser';
import {
  injectIceIntoSdp,
  stripIceFromSdp,
  extractMediaEndpoint,
  rewriteSdpEndpoint,
  generateIceCredentials,
} from './sdp-ice-injector';
import { MediaRelay } from './media-relay';
import {
  isAuthChallenge,
  extractChallenge,
  computeDigestResponse,
  getAuthHeaderName,
} from './sip-auth';

export class SipProxy {
  private config: ProxyConfig;
  private socket!: dgram.Socket;
  private mediaRelay: MediaRelay;
  private dialogs = new Map<string, SipDialog>();
  // Map branch -> transaction info for routing responses
  private transactions = new Map<string, { addr: string; port: number; callId: string }>();
  // Map branch -> original request + target server (for auth retry on 401/407)
  private pendingRequests = new Map<string, { msg: SipMessage; target: SipServer; authAttempted: boolean }>();

  constructor(config: ProxyConfig) {
    this.config = config;
    this.mediaRelay = new MediaRelay(
      config.localIp,
      config.rtpPortMin,
      config.rtpPortMax,
      config.verbose,
    );
  }

  // --- Dynamic server management ---

  getServers(): SipServer[] {
    return [...this.config.servers];
  }

  setServers(servers: SipServer[]): void {
    this.config.servers = [...servers];
  }

  addOrUpdateServer(server: SipServer): void {
    const idx = this.config.servers.findIndex(s => s.name === server.name);
    if (idx >= 0) {
      this.config.servers[idx] = server;
    } else {
      this.config.servers.push(server);
    }
  }

  removeServer(name: string): boolean {
    const idx = this.config.servers.findIndex(s => s.name === name);
    if (idx < 0) return false;
    this.config.servers.splice(idx, 1);
    return true;
  }

  getActiveSessions(): object[] {
    const sessions: object[] = [];
    for (const [callId, dialog] of this.dialogs) {
      sessions.push({
        callId,
        fromTag: dialog.fromTag,
        toTag: dialog.toTag,
        client: `${dialog.clientAddr}:${dialog.clientPort}`,
        server: `${dialog.serverAddr}:${dialog.serverPort}`,
        media: dialog.mediaSession ? {
          clientRelay: `${dialog.mediaSession.localClientRtpPort}/${dialog.mediaSession.localClientRtcpPort}`,
          serverRelay: `${dialog.mediaSession.localServerRtpPort}/${dialog.mediaSession.localServerRtcpPort}`,
          clientEndpoint: `${dialog.mediaSession.clientAddr}:${dialog.mediaSession.clientPort}`,
          serverEndpoint: `${dialog.mediaSession.serverAddr}:${dialog.mediaSession.serverPort}`,
          iceUfrag: dialog.mediaSession.iceUfrag,
          lastActivity: new Date(dialog.mediaSession.lastActivity).toISOString(),
        } : null,
      });
    }
    return sessions;
  }

  async start(): Promise<void> {
    this.socket = dgram.createSocket('udp4');

    this.socket.on('message', (msg, rinfo) => {
      this.handleMessage(msg, rinfo).catch(err => {
        this.log(`Error handling message from ${rinfo.address}:${rinfo.port}: ${err.message}`);
      });
    });

    this.socket.on('error', (err) => {
      console.error(`[SipProxy] Socket error: ${err.message}`);
    });

    return new Promise((resolve) => {
      this.socket.bind(this.config.sipPort, this.config.localIp, () => {
        console.log(`[SipProxy] Listening on ${this.config.localIp}:${this.config.sipPort} (UDP)`);
        console.log(`[SipProxy] External IP: ${this.config.externalIp}`);
        console.log(`[SipProxy] RTP port range: ${this.config.rtpPortMin}-${this.config.rtpPortMax}`);
        console.log(`[SipProxy] Configured servers:`);
        for (const s of this.config.servers) {
          console.log(`  - ${s.name}: ${s.host}:${s.port}`);
        }
        resolve();
      });
    });
  }

  stop(): void {
    this.mediaRelay.destroy();
    this.socket.close();
    console.log('[SipProxy] Stopped');
  }

  private async handleMessage(raw: Buffer, rinfo: dgram.RemoteInfo): Promise<void> {
    let msg: SipMessage;
    try {
      msg = parseSipMessage(raw);
    } catch (err: any) {
      this.log(`Failed to parse SIP message from ${rinfo.address}:${rinfo.port}: ${err.message}`);
      return;
    }

    if (msg.isRequest) {
      await this.handleRequest(msg, rinfo);
    } else {
      await this.handleResponse(msg, rinfo);
    }
  }

  private async handleRequest(msg: SipMessage, rinfo: dgram.RemoteInfo): Promise<void> {
    const method = msg.method!;
    const callId = getCallId(msg);

    this.log(`<-- ${method} from ${rinfo.address}:${rinfo.port} (Call-ID: ${callId})`);

    // Determine target server from the Request-URI
    const target = this.resolveTarget(msg);
    if (!target) {
      this.log(`No matching server for request URI: ${msg.requestUri}`);
      this.sendResponse(msg, 404, 'Not Found', rinfo);
      return;
    }

    // Decrement Max-Forwards
    const maxFwd = parseInt(getHeader(msg, 'max-forwards') ?? '70', 10);
    if (maxFwd <= 0) {
      this.sendResponse(msg, 483, 'Too Many Hops', rinfo);
      return;
    }
    setHeader(msg, 'max-forwards', String(maxFwd - 1));

    // Add our Via header at the top
    const branch = this.generateBranch();
    const viaValue = `SIP/2.0/UDP ${this.config.externalIp}:${this.config.sipPort};branch=${branch};rport`;
    const existingVias = msg.headers['via'] ?? [];
    msg.headers['via'] = [viaValue, ...existingVias];

    // Store transaction for routing responses back
    this.transactions.set(branch, {
      addr: rinfo.address,
      port: rinfo.port,
      callId,
    });

    // Store a deep copy of the original request for auth retry
    // (before SDP modifications, so we keep the copy pre-Via insertion too)
    const originalCopy = this.cloneMessage(msg);
    this.pendingRequests.set(branch, { msg: originalCopy, target, authAttempted: false });

    // Track dialog
    if (method === 'INVITE') {
      const dialog: SipDialog = {
        callId,
        fromTag: getFromTag(msg),
        toTag: '',
        clientAddr: rinfo.address,
        clientPort: rinfo.port,
        serverAddr: target.host,
        serverPort: target.port,
      };
      this.dialogs.set(callId, dialog);

      await this.handleInviteRequest(msg, rinfo, target, dialog);
      return;
    }

    if (method === 'BYE' || method === 'CANCEL') {
      // Release media relay on BYE
      if (method === 'BYE') {
        this.mediaRelay.release(callId);
        this.dialogs.delete(callId);
      }
    }

    // Forward as-is for all other methods
    this.forwardToServer(msg, target);
  }

  /**
   * Handle INVITE request: strip ICE from client SDP, rewrite media endpoint
   * to point at our server-facing relay, then forward to server.
   */
  private async handleInviteRequest(
    msg: SipMessage,
    rinfo: dgram.RemoteInfo,
    target: SipServer,
    dialog: SipDialog,
  ): Promise<void> {
    const callId = getCallId(msg);
    const contentType = getHeader(msg, 'content-type') ?? '';

    if (contentType.includes('sdp') && msg.body) {
      // Extract client's original media endpoint
      const clientMedia = extractMediaEndpoint(msg.body);
      if (!clientMedia) {
        this.log(`[${callId}] No audio media in SDP`);
        this.forwardToServer(msg, target);
        return;
      }

      this.log(`[${callId}] Client media endpoint: ${clientMedia.ip}:${clientMedia.port}`);

      // Generate ICE credentials for this session
      const ice = generateIceCredentials();

      // Allocate media relay
      const mediaSession = await this.mediaRelay.allocate(
        callId,
        clientMedia.ip,
        clientMedia.port,
        clientMedia.rtcpPort,
        ice.ufrag,
        ice.pwd,
      );

      // Store in dialog
      dialog.mediaSession = mediaSession;

      // Update the SDP:
      // 1. Strip any existing ICE from client SDP
      // 2. Rewrite media endpoint to point to our server-facing relay port
      // This way, the server will send media to our relay, and we forward to the client
      let modifiedSdp = stripIceFromSdp(msg.body);
      modifiedSdp = rewriteSdpEndpoint(
        modifiedSdp,
        this.config.externalIp,
        mediaSession.localServerRtpPort,
      );

      msg.body = modifiedSdp;
      this.log(`[${callId}] Rewrote INVITE SDP: media -> ${this.config.externalIp}:${mediaSession.localServerRtpPort}`);

      // The server-side relay now also knows where the client sends media initially
      // (we set serverAddr/serverPort to the client's original endpoint so the server-facing
      // sockets relay back to the client through client-facing sockets)
      // But actually, we'll learn the server's real endpoint from the 200 OK SDP
      // So for now, leave serverAddr/serverPort as placeholders
      mediaSession.serverAddr = '';
      mediaSession.serverPort = 0;
      mediaSession.serverRtcpPort = 0;

      // Set the client's direct info for the relay
      mediaSession.clientAddr = clientMedia.ip;
      mediaSession.clientPort = clientMedia.port;
      mediaSession.clientRtcpPort = clientMedia.rtcpPort;
    }

    this.forwardToServer(msg, target);
  }

  private async handleResponse(msg: SipMessage, rinfo: dgram.RemoteInfo): Promise<void> {
    const statusCode = msg.statusCode!;
    const cseqMethod = getCSeqMethod(msg);
    const callId = getCallId(msg);

    this.log(`<-- ${statusCode} ${msg.reasonPhrase} (${cseqMethod}) from ${rinfo.address}:${rinfo.port}`);

    // Find and remove our Via header (the topmost one should be ours)
    const vias = msg.headers['via'] ?? [];
    if (vias.length === 0) {
      this.log('No Via headers in response, dropping');
      return;
    }

    const topVia = vias[0];
    const branchMatch = topVia.match(/branch=([^\s;]+)/);
    if (!branchMatch) {
      this.log('No branch in top Via, dropping');
      return;
    }

    const branch = branchMatch[1];

    // Check if this is our Via
    if (!topVia.includes(this.config.externalIp)) {
      this.log('Top Via is not ours, forwarding as-is');
    }

    // Remove our Via
    msg.headers['via'] = vias.slice(1);

    // Look up where to send this response
    const txn = this.transactions.get(branch);
    if (!txn) {
      this.log(`No transaction found for branch ${branch}, using dialog info`);
      // Try dialog
      const dialog = this.dialogs.get(callId);
      if (dialog) {
        this.forwardToClient(msg, dialog.clientAddr, dialog.clientPort);
      }
      return;
    }

    // Handle 401/407 authentication challenges transparently
    if (isAuthChallenge(msg)) {
      const handled = await this.handleAuthChallenge(msg, branch, rinfo);
      if (handled) {
        // Auth retry sent; don't forward the 401/407 to the client
        return;
      }
      // If we couldn't handle it (no credentials), forward to client
    }

    // For INVITE 200 OK: inject ICE into the response SDP
    if (cseqMethod === 'INVITE' && statusCode >= 200 && statusCode < 300) {
      await this.handleInviteResponse(msg, callId);

      // Store the To tag for dialog
      const dialog = this.dialogs.get(callId);
      if (dialog) {
        dialog.toTag = getToTag(msg);
      }
    }

    // Clean up transaction on final response
    if (statusCode >= 200) {
      this.transactions.delete(branch);
      this.pendingRequests.delete(branch);
    }

    this.forwardToClient(msg, txn.addr, txn.port);
  }

  /**
   * Handle INVITE 200 OK: inject ICE into the SDP so the client
   * will perform ICE negotiation with our relay.
   */
  private async handleInviteResponse(msg: SipMessage, callId: string): Promise<void> {
    const contentType = getHeader(msg, 'content-type') ?? '';
    if (!contentType.includes('sdp') || !msg.body) return;

    const dialog = this.dialogs.get(callId);
    const mediaSession = dialog?.mediaSession;

    if (!mediaSession) {
      this.log(`[${callId}] No media session for INVITE response, passing through`);
      return;
    }

    // Extract the server's actual media endpoint
    const serverMedia = extractMediaEndpoint(msg.body);
    if (serverMedia) {
      mediaSession.serverAddr = serverMedia.ip;
      mediaSession.serverPort = serverMedia.port;
      mediaSession.serverRtcpPort = serverMedia.rtcpPort;
      this.log(`[${callId}] Server media endpoint: ${serverMedia.ip}:${serverMedia.port}`);
    }

    // Inject ICE into the SDP for the client
    // The client-facing relay port will be the ICE candidate
    const modifiedSdp = injectIceIntoSdp(
      msg.body,
      this.config.externalIp,
      mediaSession.localClientRtpPort,
      { ufrag: mediaSession.iceUfrag, pwd: mediaSession.icePwd },
    );

    msg.body = modifiedSdp;
    this.log(`[${callId}] Injected ICE into 200 OK SDP: relay=${this.config.externalIp}:${mediaSession.localClientRtpPort}, ufrag=${mediaSession.iceUfrag}`);
  }

  /**
   * Handle a 401/407 authentication challenge from the server.
   *
   * The proxy intercepts the challenge, computes the digest response using
   * the server credentials (password or pre-computed HA1), and resends the
   * original request with the Authorization header. The client never sees
   * the 401/407.
   *
   * @returns true if auth retry was sent, false if no credentials available
   */
  private async handleAuthChallenge(
    response: SipMessage,
    originalBranch: string,
    rinfo: dgram.RemoteInfo,
  ): Promise<boolean> {
    const pending = this.pendingRequests.get(originalBranch);
    if (!pending) {
      this.log('No pending request for auth challenge');
      return false;
    }

    // Prevent infinite auth loops
    if (pending.authAttempted) {
      this.log('Auth already attempted for this request, forwarding 401/407 to client');
      return false;
    }

    const { target } = pending;

    // Check if we have credentials for this server
    if (!target.username || (!target.password && !target.ha1Digest)) {
      this.log(`No credentials for server ${target.name} (${target.host}), forwarding 401/407 to client`);
      return false;
    }

    // Parse the challenge
    const challenge = extractChallenge(response);
    if (!challenge) {
      this.log('Could not parse digest challenge from response');
      return false;
    }

    this.log(`Auth challenge from ${target.host}: realm="${challenge.realm}", nonce="${challenge.nonce}", qop="${challenge.qop ?? 'none'}"`);

    // Rebuild the original request with a new branch and the auth header
    const retryMsg = this.cloneMessage(pending.msg);
    const method = retryMsg.method!;
    const uri = retryMsg.requestUri!;

    // Compute digest response
    const authValue = computeDigestResponse(challenge, target, method, uri);
    if (!authValue) {
      this.log('Failed to compute digest response');
      return false;
    }

    // Add Authorization or Proxy-Authorization header
    const authHeaderName = getAuthHeaderName(response.statusCode!);
    retryMsg.headers[authHeaderName] = [authValue];

    // Generate a new Via with new branch for the retry
    const newBranch = this.generateBranch();
    const viaValue = `SIP/2.0/UDP ${this.config.externalIp}:${this.config.sipPort};branch=${newBranch};rport`;
    const existingVias = retryMsg.headers['via'] ?? [];

    // Replace the top Via (ours) with the new branch
    if (existingVias.length > 0 && existingVias[0].includes('sipkit')) {
      retryMsg.headers['via'] = [viaValue, ...existingVias.slice(1)];
    } else {
      retryMsg.headers['via'] = [viaValue, ...existingVias];
    }

    // Increment CSeq number
    const cseq = getHeader(retryMsg, 'cseq') ?? '';
    const cseqParts = cseq.trim().split(/\s+/);
    if (cseqParts.length >= 2) {
      const newSeq = parseInt(cseqParts[0], 10) + 1;
      setHeader(retryMsg, 'cseq', `${newSeq} ${cseqParts[1]}`);
    }

    // Map the original client transaction to the new branch
    const txn = this.transactions.get(originalBranch);
    if (txn) {
      this.transactions.set(newBranch, txn);
      this.transactions.delete(originalBranch);
    }

    // Store the retry as pending (with authAttempted = true to prevent loops)
    this.pendingRequests.delete(originalBranch);
    this.pendingRequests.set(newBranch, { msg: retryMsg, target, authAttempted: true });

    this.log(`Retrying ${method} to ${target.host}:${target.port} with ${authHeaderName} (ha1=${target.ha1Digest ? 'pre-computed' : 'from-password'})`);

    // Send the authenticated request
    this.forwardToServer(retryMsg, target);
    return true;
  }

  private cloneMessage(msg: SipMessage): SipMessage {
    return {
      isRequest: msg.isRequest,
      method: msg.method,
      requestUri: msg.requestUri,
      statusCode: msg.statusCode,
      reasonPhrase: msg.reasonPhrase,
      version: msg.version,
      headers: Object.fromEntries(
        Object.entries(msg.headers).map(([k, v]) => [k, [...v]])
      ),
      body: msg.body,
    };
  }

  /**
   * Resolve a SIP request to a target server based on the Request-URI.
   */
  private resolveTarget(msg: SipMessage): SipServer | undefined {
    const uri = msg.requestUri ?? '';
    try {
      const parsed = parseSipUri(uri);
      // Find a matching server
      const server = this.config.servers.find(
        s => s.host === parsed.host || s.host === `${parsed.host}:${parsed.port}`,
      );
      if (server) return server;

      // If no exact match, use the URI host directly as a pass-through target
      return {
        name: parsed.host,
        host: parsed.host,
        port: parsed.port,
        transport: 'udp',
      };
    } catch {
      return undefined;
    }
  }

  private forwardToServer(msg: SipMessage, target: SipServer): void {
    const data = Buffer.from(serializeSipMessage(msg), 'utf-8');
    this.log(`--> ${msg.isRequest ? msg.method : msg.statusCode} to ${target.host}:${target.port} (${data.length} bytes)`);
    this.socket.send(data, target.port, target.host, (err) => {
      if (err) {
        this.log(`Error forwarding to ${target.host}:${target.port}: ${err.message}`);
      }
    });
  }

  private forwardToClient(msg: SipMessage, addr: string, port: number): void {
    const data = Buffer.from(serializeSipMessage(msg), 'utf-8');
    this.log(`--> ${msg.isRequest ? msg.method : msg.statusCode} to ${addr}:${port} (${data.length} bytes)`);
    this.socket.send(data, port, addr, (err) => {
      if (err) {
        this.log(`Error forwarding to ${addr}:${port}: ${err.message}`);
      }
    });
  }

  private sendResponse(req: SipMessage, code: number, reason: string, rinfo: dgram.RemoteInfo): void {
    const resp: SipMessage = {
      isRequest: false,
      statusCode: code,
      reasonPhrase: reason,
      version: 'SIP/2.0',
      headers: {
        via: req.headers['via'] ?? [],
        from: req.headers['from'] ?? [],
        to: req.headers['to'] ?? [],
        'call-id': req.headers['call-id'] ?? [],
        cseq: req.headers['cseq'] ?? [],
        'content-length': ['0'],
      },
      body: '',
    };

    const data = Buffer.from(serializeSipMessage(resp), 'utf-8');
    this.socket.send(data, rinfo.port, rinfo.address);
  }

  private generateBranch(): string {
    return 'z9hG4bK-sipkit-' + crypto.randomBytes(8).toString('hex');
  }

  private log(msg: string): void {
    if (this.config.verbose) {
      const ts = new Date().toISOString();
      console.log(`[${ts}] [SipProxy] ${msg}`);
    }
  }
}
