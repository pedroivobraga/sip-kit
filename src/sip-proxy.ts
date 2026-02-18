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

export class SipProxy {
  private config: ProxyConfig;
  private socket!: dgram.Socket;
  private mediaRelay: MediaRelay;
  private dialogs = new Map<string, SipDialog>();
  // Map branch -> { clientAddr, clientPort } for routing responses
  private transactions = new Map<string, { addr: string; port: number; callId: string }>();

  constructor(config: ProxyConfig) {
    this.config = config;
    this.mediaRelay = new MediaRelay(
      config.localIp,
      config.rtpPortMin,
      config.rtpPortMax,
      config.verbose,
    );
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
