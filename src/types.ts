/** SIP message representation */
export interface SipMessage {
  /** True if this is a request, false for response */
  isRequest: boolean;

  // Request fields
  method?: string;
  requestUri?: string;

  // Response fields
  statusCode?: number;
  reasonPhrase?: string;

  /** SIP version string */
  version: string;

  /** Headers (keys are lowercased, values are arrays for multi-value headers) */
  headers: Record<string, string[]>;

  /** Raw body (SDP or other content) */
  body: string;
}

/** A target SIP server the client wants to communicate with */
export interface SipServer {
  /** Display name for logging */
  name: string;

  /** Server hostname or IP */
  host: string;

  /** Server SIP port (default 5060) */
  port: number;

  /** Transport protocol */
  transport: 'udp' | 'tcp';

  /** SIP digest authentication realm */
  realm?: string;

  /** SIP digest username */
  username?: string;

  /**
   * SIP digest password (plain-text).
   * If provided, HA1 will be computed as MD5(username:realm:password).
   * Use EITHER password OR ha1Digest, not both.
   */
  password?: string;

  /**
   * Pre-computed HA1 digest: MD5(username:realm:password).
   * Use this when you already have the digest and don't want to store the plain password.
   * Takes priority over password if both are provided.
   */
  ha1Digest?: string;
}

/** Proxy configuration */
export interface ProxyConfig {
  /** Local IP to bind the proxy */
  localIp: string;

  /** External/public IP for SDP and Via headers */
  externalIp: string;

  /** SIP listening port */
  sipPort: number;

  /** RTP port range start (even numbers only) */
  rtpPortMin: number;

  /** RTP port range end */
  rtpPortMax: number;

  /** STUN server to advertise to clients (optional) */
  stunServer?: string;

  /** Target SIP servers */
  servers: SipServer[];

  /** Enable verbose logging */
  verbose: boolean;
}

/** Tracks an active media relay session */
export interface MediaSession {
  /** Unique call identifier */
  callId: string;

  /** Client-side address */
  clientAddr: string;
  clientPort: number;
  clientRtcpPort: number;

  /** Server-side address */
  serverAddr: string;
  serverPort: number;
  serverRtcpPort: number;

  /** Local relay ports */
  localClientRtpPort: number;
  localClientRtcpPort: number;
  localServerRtpPort: number;
  localServerRtcpPort: number;

  /** ICE credentials for this session */
  iceUfrag: string;
  icePwd: string;

  /** Timestamp of last activity */
  lastActivity: number;
}

/** Tracks a SIP dialog/transaction for routing */
export interface SipDialog {
  callId: string;
  fromTag: string;
  toTag: string;

  /** The original client remote info */
  clientAddr: string;
  clientPort: number;

  /** The target server info */
  serverAddr: string;
  serverPort: number;

  /** Which side originated the dialog ('client' = outgoing, 'server' = incoming) */
  direction: 'outgoing' | 'incoming';

  /** Associated media session */
  mediaSession?: MediaSession;
}

/**
 * Tracks a client registration.
 *
 * When a client REGISTERs through the proxy, we store the mapping
 * so we can route incoming requests from the server back to the client.
 *
 * Key = "user@serverHost" (the AOR the client registered on the server)
 */
export interface Registration {
  /** The AOR (Address of Record) on the server, e.g. "1000@pbx.example.com" */
  aor: string;

  /** The client's real transport address */
  clientAddr: string;
  clientPort: number;

  /** The client's original Contact URI */
  originalContact: string;

  /** Which server this registration is associated with */
  serverName: string;
  serverHost: string;
  serverPort: number;

  /** When this registration expires */
  expiresAt: number;
}
