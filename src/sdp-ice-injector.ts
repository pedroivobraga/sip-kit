import * as sdpTransform from 'sdp-transform';
import * as crypto from 'crypto';

export interface IceParams {
  ufrag: string;
  pwd: string;
}

/**
 * Generate random ICE credentials.
 */
export function generateIceCredentials(): IceParams {
  return {
    ufrag: crypto.randomBytes(4).toString('hex'),
    pwd: crypto.randomBytes(16).toString('base64url'),
  };
}

/**
 * Inject ICE attributes into an SDP body.
 *
 * This modifies the SDP so that:
 * - The connection address points to the proxy relay
 * - ICE credentials (ufrag, pwd) are added
 * - A host candidate for the relay is added
 * - The media port points to the relay port
 *
 * @param sdpBody - Raw SDP string
 * @param relayIp - The proxy's external IP to use as relay
 * @param relayRtpPort - The relay RTP port for the client side
 * @param ice - ICE credentials to use
 * @returns Modified SDP string
 */
export function injectIceIntoSdp(
  sdpBody: string,
  relayIp: string,
  relayRtpPort: number,
  ice: IceParams,
): string {
  const sdp = sdpTransform.parse(sdpBody);

  // Set session-level connection to relay
  if (sdp.origin) {
    sdp.origin.address = relayIp;
  }

  if (sdp.connection) {
    sdp.connection.ip = relayIp;
  }

  // Process each media section
  for (const media of sdp.media ?? []) {
    // Change media port to relay port
    media.port = relayRtpPort;

    // Set connection to relay IP
    media.connection = { version: 4, ip: relayIp };

    // Remove existing ICE attributes if present
    media.iceUfrag = ice.ufrag;
    media.icePwd = ice.pwd;

    // Add ICE candidates via raw attributes
    if (!media.invalid) {
      media.invalid = [];
    }

    media.invalid.push(
      { value: `candidate:1 1 UDP 2130706431 ${relayIp} ${relayRtpPort} typ host` },
      { value: `candidate:1 2 UDP 2130706430 ${relayIp} ${relayRtpPort + 1} typ host` },
    );

    // Remove any existing candidate attributes that sdp-transform may have parsed
    delete (media as any).candidates;

    // Ensure rtcp attribute points to relay RTCP port
    media.rtcp = { port: relayRtpPort + 1, netType: 'IN', ipVer: 4, address: relayIp };
  }

  return sdpTransform.write(sdp);
}

/**
 * Extract the original media address and port from an SDP.
 * Returns info about the first audio media section.
 */
export function extractMediaEndpoint(sdpBody: string): { ip: string; port: number; rtcpPort: number } | null {
  const sdp = sdpTransform.parse(sdpBody);
  const audioMedia = sdp.media?.find(m => m.type === 'audio');

  if (!audioMedia) return null;

  // Get IP from media connection, then session connection, then origin
  const ip =
    audioMedia.connection?.ip ??
    sdp.connection?.ip ??
    sdp.origin?.address ??
    '0.0.0.0';

  const port = audioMedia.port;
  const rtcpPort = audioMedia.rtcp?.port ?? port + 1;

  return { ip, port, rtcpPort };
}

/**
 * Strip ICE attributes from an SDP (for forwarding to servers that don't support ICE).
 */
export function stripIceFromSdp(sdpBody: string): string {
  const sdp = sdpTransform.parse(sdpBody);

  // Remove session-level ICE
  delete (sdp as any).iceUfrag;
  delete (sdp as any).icePwd;
  delete (sdp as any).iceOptions;

  for (const media of sdp.media ?? []) {
    delete media.iceUfrag;
    delete media.icePwd;
    delete (media as any).iceOptions;
    delete media.candidates;
    delete media.fingerprint;
    delete (media as any).setup;
  }

  return sdpTransform.write(sdp);
}

/**
 * Replace the connection address and media port in an SDP
 * to route media through the proxy relay.
 */
export function rewriteSdpEndpoint(
  sdpBody: string,
  newIp: string,
  newPort: number,
): string {
  const sdp = sdpTransform.parse(sdpBody);

  if (sdp.origin) {
    sdp.origin.address = newIp;
  }

  if (sdp.connection) {
    sdp.connection.ip = newIp;
  }

  for (const media of sdp.media ?? []) {
    media.port = newPort;
    media.connection = { version: 4, ip: newIp };
    if (media.rtcp) {
      media.rtcp.port = newPort + 1;
      media.rtcp.address = newIp;
    }
  }

  return sdpTransform.write(sdp);
}
