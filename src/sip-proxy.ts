/**
 * SIP Proxy with synthetic ICE activation.
 *
 * Routing logic:
 *
 *  ┌──────────┐                    ┌──────────┐
 *  │  Client  │ ───REGISTER/───►   │          │ ──── forward ────►  ┌──────────┐
 *  │          │    INVITE/etc      │  Proxy   │                     │  Server  │
 *  │          │ ◄── responses ──── │          │ ◄── responses ───── │          │
 *  └──────────┘                    │          │                     └──────────┘
 *                                  │          │
 *  ┌──────────┐                    │          │
 *  │  Client  │ ◄─ incoming ────── │          │ ◄── INVITE ──────── ┌──────────┐
 *  │          │    INVITE          │          │     (incoming call)  │  Server  │
 *  │          │ ── 200 OK ───────► │          │ ──── 200 OK ──────► │          │
 *  └──────────┘                    └──────────┘                     └──────────┘
 *
 * How the proxy knows where to route:
 *
 * 1. OUTGOING (client → server):
 *    - Client sends request to proxy
 *    - Proxy resolves target server from Request-URI (matched against config.servers)
 *    - Proxy stores Via branch → client addr:port (transaction map)
 *    - Responses follow the Via chain back to the client
 *
 * 2. REGISTER (builds the routing table):
 *    - Client sends REGISTER sip:server.com through proxy
 *    - Proxy rewrites Contact header: client's addr → proxy's addr
 *    - Server now thinks the client lives at the proxy
 *    - On 200 OK, proxy stores: AOR "user@server" → client addr:port
 *
 * 3. INCOMING (server → client):
 *    - Server sends INVITE to proxy (because Contact pointed here)
 *    - Proxy detects the source is a known server (isFromServer)
 *    - Proxy extracts the target user from the Request-URI
 *    - Looks up user in registration table → finds client addr:port
 *    - Forwards INVITE to client (with ICE injection on the response)
 */

import * as dgram from 'dgram';
import * as crypto from 'crypto';
import { ProxyConfig, SipServer, SipDialog, Registration } from './types';
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

// Contact header URI regex: <sip:user@host:port;params> or <sip:host:port>
const CONTACT_URI_RE = /<(sips?:[^>]+)>/;

export class SipProxy {
  private config: ProxyConfig;
  private socket!: dgram.Socket;
  private mediaRelay: MediaRelay;
  private dialogs = new Map<string, SipDialog>();
  // Map branch -> transaction info for routing responses
  private transactions = new Map<string, { addr: string; port: number; callId: string }>();
  // Map branch -> original request + target (for auth retry on 401/407)
  private pendingRequests = new Map<string, { msg: SipMessage; target: SipServer; authAttempted: boolean }>();
  // Map branch -> info needed to complete REGISTER processing on 200 OK
  private pendingRegisters = new Map<string, {
    aor: string;
    clientAddr: string;
    clientPort: number;
    originalContact: string;
    serverName: string;
    serverHost: string;
    serverPort: number;
    expires: number;
  }>();
  // Registration table: "user@serverHost" -> Registration
  private registrations = new Map<string, Registration>();

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
        direction: dialog.direction,
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

  getRegistrations(): object[] {
    this.cleanExpiredRegistrations();
    const result: object[] = [];
    for (const [, reg] of this.registrations) {
      result.push({
        aor: reg.aor,
        client: `${reg.clientAddr}:${reg.clientPort}`,
        server: `${reg.serverHost}:${reg.serverPort}`,
        originalContact: reg.originalContact,
        expiresIn: Math.max(0, Math.round((reg.expiresAt - Date.now()) / 1000)),
      });
    }
    return result;
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

  // ======================================================================
  // Message handling - entry point
  // ======================================================================

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

  // ======================================================================
  // REQUEST handling
  // ======================================================================

  private async handleRequest(msg: SipMessage, rinfo: dgram.RemoteInfo): Promise<void> {
    const method = msg.method!;
    const callId = getCallId(msg);
    const fromServer = this.isFromServer(rinfo);

    this.log(`<-- ${method} from ${rinfo.address}:${rinfo.port} [${fromServer ? 'SERVER' : 'CLIENT'}] (Call-ID: ${callId})`);

    if (fromServer) {
      await this.handleIncomingRequest(msg, rinfo);
    } else {
      await this.handleOutgoingRequest(msg, rinfo);
    }
  }

  /**
   * Handle a request FROM the CLIENT going TO a server (outgoing direction).
   */
  private async handleOutgoingRequest(msg: SipMessage, rinfo: dgram.RemoteInfo): Promise<void> {
    const method = msg.method!;
    const callId = getCallId(msg);

    // Determine target server from the Request-URI
    const target = this.resolveTargetServer(msg);
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
    const originalCopy = this.cloneMessage(msg);
    this.pendingRequests.set(branch, { msg: originalCopy, target, authAttempted: false });

    // --- Method-specific handling ---

    if (method === 'REGISTER') {
      await this.handleOutgoingRegister(msg, rinfo, target, branch);
      return;
    }

    if (method === 'INVITE') {
      const dialog: SipDialog = {
        callId,
        fromTag: getFromTag(msg),
        toTag: '',
        clientAddr: rinfo.address,
        clientPort: rinfo.port,
        serverAddr: target.host,
        serverPort: target.port,
        direction: 'outgoing',
      };
      this.dialogs.set(callId, dialog);
      await this.handleOutgoingInvite(msg, rinfo, target, dialog);
      return;
    }

    if (method === 'BYE') {
      this.mediaRelay.release(callId);
      this.dialogs.delete(callId);
    }

    // Forward as-is for all other methods
    this.forwardToServer(msg, target);
  }

  /**
   * Handle a request FROM a SERVER coming TO a client (incoming direction).
   * This happens for incoming calls (INVITE), in-dialog requests (BYE), etc.
   */
  private async handleIncomingRequest(msg: SipMessage, rinfo: dgram.RemoteInfo): Promise<void> {
    const method = msg.method!;
    const callId = getCallId(msg);

    // Find which client this request is for
    const clientEndpoint = this.resolveTargetClient(msg);
    if (!clientEndpoint) {
      this.log(`No registered client for incoming ${method}: ${msg.requestUri}`);
      this.sendResponse(msg, 404, 'Not Found', rinfo);
      return;
    }

    this.log(`Routing incoming ${method} to client ${clientEndpoint.addr}:${clientEndpoint.port}`);

    // Decrement Max-Forwards
    const maxFwd = parseInt(getHeader(msg, 'max-forwards') ?? '70', 10);
    if (maxFwd <= 0) {
      this.sendResponse(msg, 483, 'Too Many Hops', rinfo);
      return;
    }
    setHeader(msg, 'max-forwards', String(maxFwd - 1));

    // Add our Via so we get the response back
    const branch = this.generateBranch();
    const viaValue = `SIP/2.0/UDP ${this.config.externalIp}:${this.config.sipPort};branch=${branch};rport`;
    const existingVias = msg.headers['via'] ?? [];
    msg.headers['via'] = [viaValue, ...existingVias];

    // Store transaction - responses from the CLIENT should go back to the SERVER
    this.transactions.set(branch, {
      addr: rinfo.address,
      port: rinfo.port,
      callId,
    });

    if (method === 'INVITE') {
      const dialog: SipDialog = {
        callId,
        fromTag: getFromTag(msg),
        toTag: '',
        clientAddr: clientEndpoint.addr,
        clientPort: clientEndpoint.port,
        serverAddr: rinfo.address,
        serverPort: rinfo.port,
        direction: 'incoming',
      };
      this.dialogs.set(callId, dialog);

      // For incoming INVITE, inject ICE into the server's SDP offer
      await this.handleIncomingInvite(msg, rinfo, clientEndpoint, dialog);
      return;
    }

    if (method === 'BYE') {
      this.mediaRelay.release(callId);
      this.dialogs.delete(callId);
    }

    // Forward to the client
    this.forwardToClient(msg, clientEndpoint.addr, clientEndpoint.port);
  }

  // ======================================================================
  // REGISTER handling
  // ======================================================================

  /**
   * Handle outgoing REGISTER from client to server.
   * Rewrites the Contact header to point to the proxy, so the server
   * will route incoming calls through us.
   */
  private async handleOutgoingRegister(
    msg: SipMessage,
    rinfo: dgram.RemoteInfo,
    target: SipServer,
    branch: string,
  ): Promise<void> {
    const contactHeader = getHeader(msg, 'contact');

    // Extract the original Contact URI
    let originalContact = '';
    if (contactHeader) {
      const match = contactHeader.match(CONTACT_URI_RE);
      originalContact = match ? match[1] : contactHeader;
    }

    // Extract the AOR from the To header (this is what the client is registering as)
    const toHeader = getHeader(msg, 'to') ?? '';
    const toMatch = toHeader.match(/<(sips?:[^>]+)>/) ?? toHeader.match(/(sips?:\S+)/);
    const aorUri = toMatch ? toMatch[1] : '';

    let aor = '';
    if (aorUri) {
      const parsed = parseSipUri(aorUri);
      aor = parsed.user ? `${parsed.user}@${target.host}` : target.host;
    }

    // Get expiration
    const expiresHeader = getHeader(msg, 'expires');
    let expires = expiresHeader ? parseInt(expiresHeader, 10) : 3600;
    if (contactHeader?.includes('expires=')) {
      const expMatch = contactHeader.match(/expires=(\d+)/);
      if (expMatch) expires = parseInt(expMatch[1], 10);
    }

    // Rewrite Contact to point to the proxy
    if (contactHeader && expires > 0) {
      const parsed = parseSipUri(originalContact || aorUri);
      const userPart = parsed.user ? `${parsed.user}@` : '';
      const proxyContact = `<sip:${userPart}${this.config.externalIp}:${this.config.sipPort};transport=udp>`;
      setHeader(msg, 'contact', proxyContact);
      this.log(`REGISTER Contact rewritten: ${contactHeader} -> ${proxyContact}`);
    }

    // Store pending register info (completed on 200 OK)
    this.pendingRegisters.set(branch, {
      aor,
      clientAddr: rinfo.address,
      clientPort: rinfo.port,
      originalContact,
      serverName: target.name,
      serverHost: target.host,
      serverPort: target.port,
      expires,
    });

    this.forwardToServer(msg, target);
  }

  /**
   * Complete a REGISTER on successful 200 OK from server.
   */
  private completeRegistration(branch: string): void {
    const pending = this.pendingRegisters.get(branch);
    if (!pending) return;
    this.pendingRegisters.delete(branch);

    if (pending.expires === 0) {
      this.registrations.delete(pending.aor);
      this.log(`Registration removed: ${pending.aor}`);
      return;
    }

    const reg: Registration = {
      aor: pending.aor,
      clientAddr: pending.clientAddr,
      clientPort: pending.clientPort,
      originalContact: pending.originalContact,
      serverName: pending.serverName,
      serverHost: pending.serverHost,
      serverPort: pending.serverPort,
      expiresAt: Date.now() + (pending.expires * 1000),
    };

    this.registrations.set(pending.aor, reg);
    this.log(`Registration stored: ${reg.aor} -> ${reg.clientAddr}:${reg.clientPort} (expires in ${pending.expires}s)`);
  }

  // ======================================================================
  // INVITE handling (outgoing - client to server)
  // ======================================================================

  private async handleOutgoingInvite(
    msg: SipMessage,
    rinfo: dgram.RemoteInfo,
    target: SipServer,
    dialog: SipDialog,
  ): Promise<void> {
    const callId = getCallId(msg);
    const contentType = getHeader(msg, 'content-type') ?? '';

    if (contentType.includes('sdp') && msg.body) {
      const clientMedia = extractMediaEndpoint(msg.body);
      if (!clientMedia) {
        this.log(`[${callId}] No audio media in SDP`);
        this.forwardToServer(msg, target);
        return;
      }

      this.log(`[${callId}] Client media endpoint: ${clientMedia.ip}:${clientMedia.port}`);

      const ice = generateIceCredentials();
      const mediaSession = await this.mediaRelay.allocate(
        callId,
        clientMedia.ip,
        clientMedia.port,
        clientMedia.rtcpPort,
        ice.ufrag,
        ice.pwd,
      );

      dialog.mediaSession = mediaSession;

      let modifiedSdp = stripIceFromSdp(msg.body);
      modifiedSdp = rewriteSdpEndpoint(
        modifiedSdp,
        this.config.externalIp,
        mediaSession.localServerRtpPort,
      );

      msg.body = modifiedSdp;
      this.log(`[${callId}] Rewrote INVITE SDP: media -> ${this.config.externalIp}:${mediaSession.localServerRtpPort}`);

      mediaSession.serverAddr = '';
      mediaSession.serverPort = 0;
      mediaSession.serverRtcpPort = 0;
      mediaSession.clientAddr = clientMedia.ip;
      mediaSession.clientPort = clientMedia.port;
      mediaSession.clientRtcpPort = clientMedia.rtcpPort;
    }

    this.forwardToServer(msg, target);
  }

  // ======================================================================
  // INVITE handling (incoming - server to client)
  // ======================================================================

  private async handleIncomingInvite(
    msg: SipMessage,
    rinfo: dgram.RemoteInfo,
    clientEndpoint: { addr: string; port: number },
    dialog: SipDialog,
  ): Promise<void> {
    const callId = getCallId(msg);
    const contentType = getHeader(msg, 'content-type') ?? '';

    if (contentType.includes('sdp') && msg.body) {
      const serverMedia = extractMediaEndpoint(msg.body);
      if (!serverMedia) {
        this.log(`[${callId}] No audio media in incoming INVITE SDP`);
        this.forwardToClient(msg, clientEndpoint.addr, clientEndpoint.port);
        return;
      }

      this.log(`[${callId}] Server (caller) media endpoint: ${serverMedia.ip}:${serverMedia.port}`);

      const ice = generateIceCredentials();
      const mediaSession = await this.mediaRelay.allocate(
        callId,
        serverMedia.ip,
        serverMedia.port,
        serverMedia.rtcpPort,
        ice.ufrag,
        ice.pwd,
      );

      dialog.mediaSession = mediaSession;

      mediaSession.serverAddr = serverMedia.ip;
      mediaSession.serverPort = serverMedia.port;
      mediaSession.serverRtcpPort = serverMedia.rtcpPort;
      mediaSession.clientAddr = '';
      mediaSession.clientPort = 0;
      mediaSession.clientRtcpPort = 0;

      const modifiedSdp = injectIceIntoSdp(
        msg.body,
        this.config.externalIp,
        mediaSession.localClientRtpPort,
        { ufrag: ice.ufrag, pwd: ice.pwd },
      );

      msg.body = modifiedSdp;
      this.log(`[${callId}] Injected ICE into incoming INVITE SDP: relay=${this.config.externalIp}:${mediaSession.localClientRtpPort}`);
    }

    this.forwardToClient(msg, clientEndpoint.addr, clientEndpoint.port);
  }

  // ======================================================================
  // RESPONSE handling
  // ======================================================================

  private async handleResponse(msg: SipMessage, rinfo: dgram.RemoteInfo): Promise<void> {
    const statusCode = msg.statusCode!;
    const cseqMethod = getCSeqMethod(msg);
    const callId = getCallId(msg);

    this.log(`<-- ${statusCode} ${msg.reasonPhrase} (${cseqMethod}) from ${rinfo.address}:${rinfo.port}`);

    // Find and remove our Via header
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

    if (!topVia.includes(this.config.externalIp)) {
      this.log('Top Via is not ours, forwarding as-is');
    }

    // Remove our Via
    msg.headers['via'] = vias.slice(1);

    // Look up where to send this response
    const txn = this.transactions.get(branch);
    if (!txn) {
      this.log(`No transaction found for branch ${branch}, using dialog info`);
      const dialog = this.dialogs.get(callId);
      if (dialog) {
        if (dialog.direction === 'outgoing') {
          this.forwardToClient(msg, dialog.clientAddr, dialog.clientPort);
        } else {
          this.sendTo(msg, dialog.serverAddr, dialog.serverPort);
        }
      }
      return;
    }

    // Handle 401/407 authentication challenges transparently
    if (isAuthChallenge(msg)) {
      const handled = await this.handleAuthChallenge(msg, branch, rinfo);
      if (handled) return;
    }

    // REGISTER 200 OK: complete the registration
    if (cseqMethod === 'REGISTER' && statusCode >= 200 && statusCode < 300) {
      this.completeRegistration(branch);
    }

    // INVITE 200 OK: handle SDP based on dialog direction
    if (cseqMethod === 'INVITE' && statusCode >= 200 && statusCode < 300) {
      const dialog = this.dialogs.get(callId);
      if (dialog) {
        dialog.toTag = getToTag(msg);

        if (dialog.direction === 'outgoing') {
          await this.handleOutgoingInviteResponse(msg, callId);
        } else {
          await this.handleIncomingInviteResponse(msg, callId);
        }
      }
    }

    // Clean up transaction on final response
    if (statusCode >= 200) {
      this.transactions.delete(branch);
      this.pendingRequests.delete(branch);
      this.pendingRegisters.delete(branch);
    }

    this.sendTo(msg, txn.addr, txn.port);
  }

  /**
   * Handle 200 OK for an outgoing INVITE (from server, going to client).
   * Inject ICE into the server's SDP.
   */
  private async handleOutgoingInviteResponse(msg: SipMessage, callId: string): Promise<void> {
    const contentType = getHeader(msg, 'content-type') ?? '';
    if (!contentType.includes('sdp') || !msg.body) return;

    const dialog = this.dialogs.get(callId);
    const mediaSession = dialog?.mediaSession;
    if (!mediaSession) {
      this.log(`[${callId}] No media session for outgoing INVITE response`);
      return;
    }

    const serverMedia = extractMediaEndpoint(msg.body);
    if (serverMedia) {
      mediaSession.serverAddr = serverMedia.ip;
      mediaSession.serverPort = serverMedia.port;
      mediaSession.serverRtcpPort = serverMedia.rtcpPort;
      this.log(`[${callId}] Server media endpoint: ${serverMedia.ip}:${serverMedia.port}`);
    }

    const modifiedSdp = injectIceIntoSdp(
      msg.body,
      this.config.externalIp,
      mediaSession.localClientRtpPort,
      { ufrag: mediaSession.iceUfrag, pwd: mediaSession.icePwd },
    );

    msg.body = modifiedSdp;
    this.log(`[${callId}] Injected ICE into 200 OK SDP: relay=${this.config.externalIp}:${mediaSession.localClientRtpPort}`);
  }

  /**
   * Handle 200 OK for an incoming INVITE (from client, going to server).
   * Strip ICE from client's SDP and rewrite media to relay.
   */
  private async handleIncomingInviteResponse(msg: SipMessage, callId: string): Promise<void> {
    const contentType = getHeader(msg, 'content-type') ?? '';
    if (!contentType.includes('sdp') || !msg.body) return;

    const dialog = this.dialogs.get(callId);
    const mediaSession = dialog?.mediaSession;
    if (!mediaSession) {
      this.log(`[${callId}] No media session for incoming INVITE response`);
      return;
    }

    const clientMedia = extractMediaEndpoint(msg.body);
    if (clientMedia) {
      mediaSession.clientAddr = clientMedia.ip;
      mediaSession.clientPort = clientMedia.port;
      mediaSession.clientRtcpPort = clientMedia.rtcpPort;
      this.log(`[${callId}] Client media endpoint: ${clientMedia.ip}:${clientMedia.port}`);
    }

    let modifiedSdp = stripIceFromSdp(msg.body);
    modifiedSdp = rewriteSdpEndpoint(
      modifiedSdp,
      this.config.externalIp,
      mediaSession.localServerRtpPort,
    );

    msg.body = modifiedSdp;
    this.log(`[${callId}] Rewrote incoming 200 OK SDP: media -> ${this.config.externalIp}:${mediaSession.localServerRtpPort}`);
  }

  // ======================================================================
  // Auth challenge handling
  // ======================================================================

  private async handleAuthChallenge(
    response: SipMessage,
    originalBranch: string,
    _rinfo: dgram.RemoteInfo,
  ): Promise<boolean> {
    const pending = this.pendingRequests.get(originalBranch);
    if (!pending) {
      this.log('No pending request for auth challenge');
      return false;
    }

    if (pending.authAttempted) {
      this.log('Auth already attempted for this request, forwarding 401/407 to client');
      return false;
    }

    const { target } = pending;

    if (!target.username || (!target.password && !target.ha1Digest)) {
      this.log(`No credentials for server ${target.name} (${target.host}), forwarding 401/407 to client`);
      return false;
    }

    const challenge = extractChallenge(response);
    if (!challenge) {
      this.log('Could not parse digest challenge from response');
      return false;
    }

    this.log(`Auth challenge from ${target.host}: realm="${challenge.realm}", nonce="${challenge.nonce}", qop="${challenge.qop ?? 'none'}"`);

    const retryMsg = this.cloneMessage(pending.msg);
    const method = retryMsg.method!;
    const uri = retryMsg.requestUri!;

    const authValue = computeDigestResponse(challenge, target, method, uri);
    if (!authValue) {
      this.log('Failed to compute digest response');
      return false;
    }

    const authHeaderName = getAuthHeaderName(response.statusCode!);
    retryMsg.headers[authHeaderName] = [authValue];

    const newBranch = this.generateBranch();
    const viaValue = `SIP/2.0/UDP ${this.config.externalIp}:${this.config.sipPort};branch=${newBranch};rport`;
    const existingVias = retryMsg.headers['via'] ?? [];

    if (existingVias.length > 0 && existingVias[0].includes('sipkit')) {
      retryMsg.headers['via'] = [viaValue, ...existingVias.slice(1)];
    } else {
      retryMsg.headers['via'] = [viaValue, ...existingVias];
    }

    const cseq = getHeader(retryMsg, 'cseq') ?? '';
    const cseqParts = cseq.trim().split(/\s+/);
    if (cseqParts.length >= 2) {
      const newSeq = parseInt(cseqParts[0], 10) + 1;
      setHeader(retryMsg, 'cseq', `${newSeq} ${cseqParts[1]}`);
    }

    const txn = this.transactions.get(originalBranch);
    if (txn) {
      this.transactions.set(newBranch, txn);
      this.transactions.delete(originalBranch);
    }

    // Migrate pendingRegister if this was a REGISTER
    const pendingReg = this.pendingRegisters.get(originalBranch);
    if (pendingReg) {
      this.pendingRegisters.set(newBranch, pendingReg);
      this.pendingRegisters.delete(originalBranch);
    }

    this.pendingRequests.delete(originalBranch);
    this.pendingRequests.set(newBranch, { msg: retryMsg, target, authAttempted: true });

    this.log(`Retrying ${method} to ${target.host}:${target.port} with ${authHeaderName} (ha1=${target.ha1Digest ? 'pre-computed' : 'from-password'})`);

    this.forwardToServer(retryMsg, target);
    return true;
  }

  // ======================================================================
  // Routing helpers
  // ======================================================================

  /**
   * Check if a message comes from a known configured server.
   */
  private isFromServer(rinfo: dgram.RemoteInfo): boolean {
    return this.config.servers.some(s => s.host === rinfo.address);
  }

  /**
   * Resolve a target server for an outgoing request (from client).
   */
  private resolveTargetServer(msg: SipMessage): SipServer | undefined {
    const uri = msg.requestUri ?? '';
    try {
      const parsed = parseSipUri(uri);
      const server = this.config.servers.find(
        s => s.host === parsed.host || s.host === `${parsed.host}:${parsed.port}`,
      );
      if (server) return server;

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

  /**
   * Resolve a target client for an incoming request (from server).
   *
   * Lookup chain:
   * 1. Registration table: "user@serverHost"
   * 2. Registration table: match by user part only
   * 3. Existing dialog for the Call-ID
   */
  private resolveTargetClient(msg: SipMessage): { addr: string; port: number } | null {
    this.cleanExpiredRegistrations();

    const uri = msg.requestUri ?? '';
    const callId = getCallId(msg);

    try {
      const parsed = parseSipUri(uri);
      const user = parsed.user ?? '';

      // 1. Exact AOR match: "user@serverHost"
      for (const server of this.config.servers) {
        const aor = user ? `${user}@${server.host}` : server.host;
        const reg = this.registrations.get(aor);
        if (reg) {
          return { addr: reg.clientAddr, port: reg.clientPort };
        }
      }

      // 2. Match by user part across all registrations
      if (user) {
        for (const [, reg] of this.registrations) {
          if (reg.aor.startsWith(`${user}@`)) {
            return { addr: reg.clientAddr, port: reg.clientPort };
          }
        }
      }
    } catch {
      // Fall through to dialog lookup
    }

    // 3. Existing dialog for this Call-ID
    const dialog = this.dialogs.get(callId);
    if (dialog) {
      return { addr: dialog.clientAddr, port: dialog.clientPort };
    }

    return null;
  }

  // ======================================================================
  // Transport helpers
  // ======================================================================

  private forwardToServer(msg: SipMessage, target: SipServer): void {
    this.sendTo(msg, target.host, target.port);
  }

  private forwardToClient(msg: SipMessage, addr: string, port: number): void {
    this.sendTo(msg, addr, port);
  }

  private sendTo(msg: SipMessage, addr: string, port: number): void {
    const data = Buffer.from(serializeSipMessage(msg), 'utf-8');
    const label = msg.isRequest ? msg.method : String(msg.statusCode);
    this.log(`--> ${label} to ${addr}:${port} (${data.length} bytes)`);
    this.socket.send(data, port, addr, (err) => {
      if (err) {
        this.log(`Error sending to ${addr}:${port}: ${err.message}`);
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

  // ======================================================================
  // Utility
  // ======================================================================

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

  private cleanExpiredRegistrations(): void {
    const now = Date.now();
    for (const [aor, reg] of this.registrations) {
      if (reg.expiresAt < now) {
        this.registrations.delete(aor);
        this.log(`Registration expired: ${aor}`);
      }
    }
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
