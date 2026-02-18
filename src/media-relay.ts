/**
 * Media Relay - Relays RTP/RTCP packets between client and server.
 *
 * For each call, we allocate two UDP socket pairs:
 * - Client-facing: receives RTP/RTCP from the client (after ICE negotiation)
 * - Server-facing: sends/receives RTP/RTCP to/from the actual SIP server
 *
 * The relay also handles STUN binding requests on the client-facing sockets
 * to support ICE connectivity checks.
 */

import * as dgram from 'dgram';
import { EventEmitter } from 'events';
import { MediaSession } from './types';
import { isStunMessage, isBindingRequest, createBindingResponse, extractUsername } from './stun-handler';

export interface RelaySession {
  callId: string;
  mediaSession: MediaSession;
  clientRtpSocket: dgram.Socket;
  clientRtcpSocket: dgram.Socket;
  serverRtpSocket: dgram.Socket;
  serverRtcpSocket: dgram.Socket;
  timeout: NodeJS.Timeout;
}

const SESSION_TIMEOUT_MS = 120_000; // 2 minutes of inactivity

export class MediaRelay extends EventEmitter {
  private sessions = new Map<string, RelaySession>();
  private portPool: number[] = [];
  private localIp: string;
  private verbose: boolean;

  constructor(localIp: string, rtpPortMin: number, rtpPortMax: number, verbose = false) {
    super();
    this.localIp = localIp;
    this.verbose = verbose;

    // Build pool of available even ports for RTP (RTCP = RTP + 1)
    for (let port = rtpPortMin; port < rtpPortMax; port += 2) {
      this.portPool.push(port);
    }
  }

  /**
   * Allocate relay ports for a new call session.
   * Returns the allocated MediaSession info.
   */
  async allocate(
    callId: string,
    serverAddr: string,
    serverPort: number,
    serverRtcpPort: number,
    iceUfrag: string,
    icePwd: string,
  ): Promise<MediaSession> {
    if (this.portPool.length < 2) {
      throw new Error('No available relay ports');
    }

    // Allocate two even ports: one for client-facing, one for server-facing
    const clientRtpPort = this.portPool.shift()!;
    const serverRtpPort = this.portPool.shift()!;

    const session: MediaSession = {
      callId,
      clientAddr: '',
      clientPort: 0,
      clientRtcpPort: 0,
      serverAddr,
      serverPort,
      serverRtcpPort,
      localClientRtpPort: clientRtpPort,
      localClientRtcpPort: clientRtpPort + 1,
      localServerRtpPort: serverRtpPort,
      localServerRtcpPort: serverRtpPort + 1,
      iceUfrag,
      icePwd,
      lastActivity: Date.now(),
    };

    // Create sockets
    const clientRtpSocket = await this.createBoundSocket(clientRtpPort);
    const clientRtcpSocket = await this.createBoundSocket(clientRtpPort + 1);
    const serverRtpSocket = await this.createBoundSocket(serverRtpPort);
    const serverRtcpSocket = await this.createBoundSocket(serverRtpPort + 1);

    const relaySession: RelaySession = {
      callId,
      mediaSession: session,
      clientRtpSocket,
      clientRtcpSocket,
      serverRtpSocket,
      serverRtcpSocket,
      timeout: this.createTimeout(callId),
    };

    // Wire up packet forwarding

    // Client RTP -> Server RTP
    clientRtpSocket.on('message', (msg, rinfo) => {
      session.lastActivity = Date.now();
      this.resetTimeout(relaySession);

      // Handle STUN on RTP port
      if (isStunMessage(msg)) {
        this.handleStun(msg, rinfo, clientRtpSocket, session);
        return;
      }

      // Learn client address from first RTP packet (or STUN)
      if (!session.clientAddr || session.clientPort === 0) {
        session.clientAddr = rinfo.address;
        session.clientPort = rinfo.port;
        this.log(`[${callId}] Learned client RTP endpoint: ${rinfo.address}:${rinfo.port}`);
      }

      // Forward to server
      serverRtpSocket.send(msg, session.serverPort, session.serverAddr);
    });

    // Client RTCP -> Server RTCP
    clientRtcpSocket.on('message', (msg, rinfo) => {
      session.lastActivity = Date.now();
      this.resetTimeout(relaySession);

      if (isStunMessage(msg)) {
        this.handleStun(msg, rinfo, clientRtcpSocket, session);
        return;
      }

      if (!session.clientRtcpPort) {
        session.clientRtcpPort = rinfo.port;
        this.log(`[${callId}] Learned client RTCP endpoint: ${rinfo.address}:${rinfo.port}`);
      }

      serverRtcpSocket.send(msg, session.serverRtcpPort, session.serverAddr);
    });

    // Server RTP -> Client RTP
    serverRtpSocket.on('message', (msg, rinfo) => {
      session.lastActivity = Date.now();
      this.resetTimeout(relaySession);

      if (session.clientAddr && session.clientPort) {
        clientRtpSocket.send(msg, session.clientPort, session.clientAddr);
      }
    });

    // Server RTCP -> Client RTCP
    serverRtcpSocket.on('message', (msg, rinfo) => {
      session.lastActivity = Date.now();
      this.resetTimeout(relaySession);

      if (session.clientAddr && session.clientRtcpPort) {
        clientRtcpSocket.send(msg, session.clientRtcpPort, session.clientAddr);
      }
    });

    this.sessions.set(callId, relaySession);
    this.log(`[${callId}] Media relay allocated: client-facing=${clientRtpPort}/${clientRtpPort + 1}, server-facing=${serverRtpPort}/${serverRtpPort + 1}`);

    return session;
  }

  /**
   * Release a relay session (on BYE or timeout).
   */
  release(callId: string): void {
    const rs = this.sessions.get(callId);
    if (!rs) return;

    clearTimeout(rs.timeout);

    rs.clientRtpSocket.close();
    rs.clientRtcpSocket.close();
    rs.serverRtpSocket.close();
    rs.serverRtcpSocket.close();

    // Return ports to pool
    this.portPool.push(rs.mediaSession.localClientRtpPort);
    this.portPool.push(rs.mediaSession.localServerRtpPort);

    this.sessions.delete(callId);
    this.log(`[${callId}] Media relay released`);
  }

  /**
   * Get a relay session by call ID.
   */
  getSession(callId: string): RelaySession | undefined {
    return this.sessions.get(callId);
  }

  /**
   * Destroy all sessions and clean up.
   */
  destroy(): void {
    for (const [callId] of this.sessions) {
      this.release(callId);
    }
  }

  // --- Private helpers ---

  private handleStun(
    msg: Buffer,
    rinfo: dgram.RemoteInfo,
    socket: dgram.Socket,
    session: MediaSession,
  ): void {
    if (!isBindingRequest(msg)) return;

    const username = extractUsername(msg);
    this.log(`[${session.callId}] STUN Binding Request from ${rinfo.address}:${rinfo.port} (user=${username})`);

    // Learn client address from STUN
    if (!session.clientAddr || session.clientPort === 0) {
      session.clientAddr = rinfo.address;
      session.clientPort = rinfo.port;
      this.log(`[${session.callId}] Learned client endpoint via STUN: ${rinfo.address}:${rinfo.port}`);
    }

    // Create and send binding response
    const response = createBindingResponse(msg, rinfo.address, rinfo.port, session.icePwd);
    socket.send(response, rinfo.port, rinfo.address, (err) => {
      if (err) {
        this.log(`[${session.callId}] Error sending STUN response: ${err.message}`);
      }
    });
  }

  private createBoundSocket(port: number): Promise<dgram.Socket> {
    return new Promise((resolve, reject) => {
      const socket = dgram.createSocket('udp4');
      socket.on('error', reject);
      socket.bind(port, this.localIp, () => {
        socket.removeListener('error', reject);
        resolve(socket);
      });
    });
  }

  private createTimeout(callId: string): NodeJS.Timeout {
    return setTimeout(() => {
      this.log(`[${callId}] Session timed out`);
      this.release(callId);
      this.emit('timeout', callId);
    }, SESSION_TIMEOUT_MS);
  }

  private resetTimeout(rs: RelaySession): void {
    clearTimeout(rs.timeout);
    rs.timeout = this.createTimeout(rs.callId);
  }

  private log(msg: string): void {
    if (this.verbose) {
      console.log(`[MediaRelay] ${msg}`);
    }
  }
}
