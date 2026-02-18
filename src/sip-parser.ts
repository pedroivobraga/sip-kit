export { SipMessage } from './types';
import { SipMessage } from './types';

const REQUEST_LINE_RE = /^(\w+)\s+(.+)\s+(SIP\/2\.0)\s*$/;
const STATUS_LINE_RE = /^(SIP\/2\.0)\s+(\d{3})\s+(.*)\s*$/;

/**
 * Parse a raw SIP message buffer into a structured SipMessage.
 */
export function parseSipMessage(raw: Buffer | string): SipMessage {
  const text = typeof raw === 'string' ? raw : raw.toString('utf-8');

  // Split head and body by double CRLF
  const separatorIdx = text.indexOf('\r\n\r\n');
  const head = separatorIdx >= 0 ? text.substring(0, separatorIdx) : text;
  const body = separatorIdx >= 0 ? text.substring(separatorIdx + 4) : '';

  const lines = head.split('\r\n');
  const firstLine = lines[0];

  const msg: SipMessage = {
    isRequest: false,
    version: 'SIP/2.0',
    headers: {},
    body,
  };

  // Parse first line (request or status)
  const reqMatch = firstLine.match(REQUEST_LINE_RE);
  if (reqMatch) {
    msg.isRequest = true;
    msg.method = reqMatch[1];
    msg.requestUri = reqMatch[2];
    msg.version = reqMatch[3];
  } else {
    const statusMatch = firstLine.match(STATUS_LINE_RE);
    if (statusMatch) {
      msg.isRequest = false;
      msg.version = statusMatch[1];
      msg.statusCode = parseInt(statusMatch[2], 10);
      msg.reasonPhrase = statusMatch[3];
    } else {
      throw new Error(`Invalid SIP first line: ${firstLine}`);
    }
  }

  // Parse headers (handle header folding with leading whitespace)
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i];
    if (!line) continue;

    // Header continuation (folding): line starts with space or tab
    if (line[0] === ' ' || line[0] === '\t') {
      // Append to the last header value
      const lastKey = Object.keys(msg.headers).pop();
      if (lastKey && msg.headers[lastKey].length > 0) {
        const arr = msg.headers[lastKey];
        arr[arr.length - 1] += ' ' + line.trim();
      }
      continue;
    }

    const colonIdx = line.indexOf(':');
    if (colonIdx < 0) continue;

    const rawName = line.substring(0, colonIdx).trim();
    const value = line.substring(colonIdx + 1).trim();

    // Normalize compact form headers to full names
    const name = expandCompactHeader(rawName).toLowerCase();

    if (!msg.headers[name]) {
      msg.headers[name] = [];
    }
    msg.headers[name].push(value);
  }

  return msg;
}

/**
 * Serialize a SipMessage back into a raw string (Buffer-ready).
 */
export function serializeSipMessage(msg: SipMessage): string {
  const lines: string[] = [];

  // First line
  if (msg.isRequest) {
    lines.push(`${msg.method} ${msg.requestUri} ${msg.version}`);
  } else {
    lines.push(`${msg.version} ${msg.statusCode} ${msg.reasonPhrase}`);
  }

  // Update Content-Length to match body
  const bodyBytes = Buffer.byteLength(msg.body, 'utf-8');
  msg.headers['content-length'] = [String(bodyBytes)];

  // Serialize headers
  for (const [name, values] of Object.entries(msg.headers)) {
    const displayName = formatHeaderName(name);
    for (const val of values) {
      lines.push(`${displayName}: ${val}`);
    }
  }

  // Empty line + body
  lines.push('');
  lines.push(msg.body);

  return lines.join('\r\n');
}

/**
 * Extract the Call-ID from a SIP message.
 */
export function getCallId(msg: SipMessage): string {
  return getHeader(msg, 'call-id') ?? '';
}

/**
 * Get the first value of a header (case-insensitive).
 */
export function getHeader(msg: SipMessage, name: string): string | undefined {
  return msg.headers[name.toLowerCase()]?.[0];
}

/**
 * Set a header value (replaces all existing values).
 */
export function setHeader(msg: SipMessage, name: string, value: string): void {
  msg.headers[name.toLowerCase()] = [value];
}

/**
 * Add a header value (appends to existing).
 */
export function addHeader(msg: SipMessage, name: string, value: string): void {
  const key = name.toLowerCase();
  if (!msg.headers[key]) {
    msg.headers[key] = [];
  }
  msg.headers[key].push(value);
}

/**
 * Get the From tag from a SIP message.
 */
export function getFromTag(msg: SipMessage): string {
  const from = getHeader(msg, 'from') ?? '';
  const match = from.match(/tag=([^\s;]+)/);
  return match ? match[1] : '';
}

/**
 * Get the To tag from a SIP message.
 */
export function getToTag(msg: SipMessage): string {
  const to = getHeader(msg, 'to') ?? '';
  const match = to.match(/tag=([^\s;]+)/);
  return match ? match[1] : '';
}

/**
 * Get the CSeq method from a SIP message.
 */
export function getCSeqMethod(msg: SipMessage): string {
  const cseq = getHeader(msg, 'cseq') ?? '';
  const parts = cseq.trim().split(/\s+/);
  return parts.length >= 2 ? parts[1] : '';
}

/**
 * Get the branch from the topmost Via header.
 */
export function getTopViaBranch(msg: SipMessage): string {
  const via = getHeader(msg, 'via') ?? '';
  const match = via.match(/branch=([^\s;]+)/);
  return match ? match[1] : '';
}

/**
 * Extract host:port from a SIP URI.
 */
export function parseSipUri(uri: string): { user?: string; host: string; port: number; params: string } {
  // sip:user@host:port;params or sip:host:port;params
  const stripped = uri.replace(/^sips?:/, '');
  const [userHost, ...paramParts] = stripped.split(';');
  const params = paramParts.length > 0 ? ';' + paramParts.join(';') : '';

  let user: string | undefined;
  let hostPort: string;

  if (userHost.includes('@')) {
    const atIdx = userHost.indexOf('@');
    user = userHost.substring(0, atIdx);
    hostPort = userHost.substring(atIdx + 1);
  } else {
    hostPort = userHost;
  }

  // Handle IPv6
  let host: string;
  let port = 5060;

  if (hostPort.startsWith('[')) {
    const bracketEnd = hostPort.indexOf(']');
    host = hostPort.substring(1, bracketEnd);
    const afterBracket = hostPort.substring(bracketEnd + 1);
    if (afterBracket.startsWith(':')) {
      port = parseInt(afterBracket.substring(1), 10);
    }
  } else {
    const lastColon = hostPort.lastIndexOf(':');
    if (lastColon >= 0) {
      host = hostPort.substring(0, lastColon);
      port = parseInt(hostPort.substring(lastColon + 1), 10);
    } else {
      host = hostPort;
    }
  }

  return { user, host, port, params };
}

/** SIP compact header forms -> full names */
const COMPACT_HEADERS: Record<string, string> = {
  i: 'call-id',
  m: 'contact',
  e: 'content-encoding',
  l: 'content-length',
  c: 'content-type',
  f: 'from',
  s: 'subject',
  k: 'supported',
  t: 'to',
  v: 'via',
};

function expandCompactHeader(name: string): string {
  if (name.length === 1) {
    return COMPACT_HEADERS[name.toLowerCase()] ?? name;
  }
  return name;
}

/** Convert lowercase header name to proper casing */
function formatHeaderName(name: string): string {
  // Special cases
  const specials: Record<string, string> = {
    'call-id': 'Call-ID',
    'cseq': 'CSeq',
    'www-authenticate': 'WWW-Authenticate',
    'content-type': 'Content-Type',
    'content-length': 'Content-Length',
    'max-forwards': 'Max-Forwards',
    'user-agent': 'User-Agent',
    'proxy-authenticate': 'Proxy-Authenticate',
    'proxy-authorization': 'Proxy-Authorization',
  };
  if (specials[name]) return specials[name];

  return name
    .split('-')
    .map(part => part.charAt(0).toUpperCase() + part.slice(1))
    .join('-');
}
