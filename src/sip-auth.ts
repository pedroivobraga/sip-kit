/**
 * SIP Digest Authentication (RFC 2617 / RFC 3261 Section 22).
 *
 * Handles 401 (WWW-Authenticate) and 407 (Proxy-Authenticate) challenges
 * by computing the digest response and adding Authorization /
 * Proxy-Authorization headers.
 *
 * Supports both:
 *   - Plain password: computes HA1 = MD5(username:realm:password)
 *   - Pre-computed HA1 digest: uses it directly (for when the .NET app
 *     already has the digest and doesn't want to expose the password)
 */

import * as crypto from 'crypto';
import { SipServer } from './types';
import { SipMessage, getHeader } from './sip-parser';

/** Parsed WWW-Authenticate / Proxy-Authenticate challenge */
export interface DigestChallenge {
  realm: string;
  nonce: string;
  opaque?: string;
  algorithm?: string;
  qop?: string;
  stale?: string;
}

/**
 * Parse a WWW-Authenticate or Proxy-Authenticate header value.
 *
 * Example header:
 *   Digest realm="example.com", nonce="abc123", qop="auth", algorithm=MD5
 */
export function parseDigestChallenge(header: string): DigestChallenge | null {
  if (!header.toLowerCase().startsWith('digest')) return null;

  const params = header.substring(6).trim();
  const result: Record<string, string> = {};

  // Parse key=value or key="value" pairs
  const re = /(\w+)\s*=\s*(?:"([^"]*)"|([\w]+))/g;
  let match: RegExpExecArray | null;
  while ((match = re.exec(params)) !== null) {
    result[match[1].toLowerCase()] = match[2] ?? match[3];
  }

  if (!result.realm || !result.nonce) return null;

  return {
    realm: result.realm,
    nonce: result.nonce,
    opaque: result.opaque,
    algorithm: result.algorithm,
    qop: result.qop,
    stale: result.stale,
  };
}

/**
 * Compute the digest Authorization header value for a given challenge.
 *
 * @param challenge - The parsed challenge from the server
 * @param server    - The SipServer config with credentials (password or ha1Digest)
 * @param method    - The SIP method (INVITE, REGISTER, etc.)
 * @param uri       - The request URI
 * @returns The full Authorization header value, or null if no credentials
 */
export function computeDigestResponse(
  challenge: DigestChallenge,
  server: SipServer,
  method: string,
  uri: string,
): string | null {
  const username = server.username;
  if (!username) return null;

  // Compute or use pre-computed HA1
  let ha1: string;

  if (server.ha1Digest) {
    // Use the pre-computed HA1 directly
    ha1 = server.ha1Digest;
  } else if (server.password) {
    // Compute HA1 from username:realm:password
    const realm = challenge.realm;
    ha1 = md5(`${username}:${realm}:${server.password}`);
  } else {
    return null;
  }

  // HA2 = MD5(method:digestURI)
  const ha2 = md5(`${method}:${uri}`);

  let response: string;
  let authParams: string;

  if (challenge.qop === 'auth' || challenge.qop?.includes('auth')) {
    // RFC 2617 with qop=auth
    const nc = '00000001';
    const cnonce = crypto.randomBytes(8).toString('hex');
    response = md5(`${ha1}:${challenge.nonce}:${nc}:${cnonce}:auth:${ha2}`);
    authParams = [
      `Digest username="${username}"`,
      `realm="${challenge.realm}"`,
      `nonce="${challenge.nonce}"`,
      `uri="${uri}"`,
      `qop=auth`,
      `nc=${nc}`,
      `cnonce="${cnonce}"`,
      `response="${response}"`,
      `algorithm=MD5`,
    ].join(', ');
  } else {
    // RFC 2069 (no qop)
    response = md5(`${ha1}:${challenge.nonce}:${ha2}`);
    authParams = [
      `Digest username="${username}"`,
      `realm="${challenge.realm}"`,
      `nonce="${challenge.nonce}"`,
      `uri="${uri}"`,
      `response="${response}"`,
      `algorithm=MD5`,
    ].join(', ');
  }

  if (challenge.opaque) {
    authParams += `, opaque="${challenge.opaque}"`;
  }

  return authParams;
}

/**
 * Check if a SIP response is an authentication challenge (401 or 407).
 */
export function isAuthChallenge(msg: SipMessage): boolean {
  return msg.statusCode === 401 || msg.statusCode === 407;
}

/**
 * Extract the digest challenge from a 401/407 response.
 */
export function extractChallenge(msg: SipMessage): DigestChallenge | null {
  // 401 uses WWW-Authenticate, 407 uses Proxy-Authenticate
  const headerName = msg.statusCode === 407 ? 'proxy-authenticate' : 'www-authenticate';
  const headerValue = getHeader(msg, headerName);
  if (!headerValue) return null;
  return parseDigestChallenge(headerValue);
}

/**
 * Get the appropriate authorization header name for the challenge type.
 */
export function getAuthHeaderName(statusCode: number): string {
  return statusCode === 407 ? 'proxy-authorization' : 'authorization';
}

function md5(input: string): string {
  return crypto.createHash('md5').update(input).digest('hex');
}
