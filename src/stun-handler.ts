/**
 * Minimal STUN implementation for handling ICE connectivity checks.
 *
 * STUN message format (RFC 5389):
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |0 0|     STUN Message Type     |         Message Length        |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                         Magic Cookie                         |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                   Transaction ID (96 bits)                    |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

import * as crypto from 'crypto';

const STUN_MAGIC_COOKIE = 0x2112a442;
const STUN_HEADER_SIZE = 20;

// Message types
const STUN_BINDING_REQUEST = 0x0001;
const STUN_BINDING_RESPONSE = 0x0101;

// Attribute types
const ATTR_MAPPED_ADDRESS = 0x0001;
const ATTR_XOR_MAPPED_ADDRESS = 0x0020;
const ATTR_USERNAME = 0x0006;
const ATTR_MESSAGE_INTEGRITY = 0x0008;
const ATTR_FINGERPRINT = 0x8028;
const ATTR_SOFTWARE = 0x8022;

/**
 * Check if a buffer looks like a STUN message.
 * STUN messages have the first two bits as 0 and the magic cookie at bytes 4-7.
 */
export function isStunMessage(buf: Buffer): boolean {
  if (buf.length < STUN_HEADER_SIZE) return false;
  // First two bits must be 0
  if ((buf[0] & 0xc0) !== 0) return false;
  // Magic cookie
  const cookie = buf.readUInt32BE(4);
  return cookie === STUN_MAGIC_COOKIE;
}

/**
 * Check if a STUN message is a Binding Request.
 */
export function isBindingRequest(buf: Buffer): boolean {
  if (!isStunMessage(buf)) return false;
  const type = buf.readUInt16BE(0);
  return type === STUN_BINDING_REQUEST;
}

/**
 * Extract the USERNAME attribute from a STUN Binding Request.
 * ICE uses format: "remote-ufrag:local-ufrag"
 */
export function extractUsername(buf: Buffer): string | null {
  const attrs = parseAttributes(buf);
  const usernameAttr = attrs.find(a => a.type === ATTR_USERNAME);
  if (!usernameAttr) return null;
  return usernameAttr.value.toString('utf-8');
}

/**
 * Create a STUN Binding Response for a given request.
 *
 * @param request - The original STUN Binding Request buffer
 * @param sourceIp - The IP address the request came from
 * @param sourcePort - The port the request came from
 * @param icePassword - The ICE password for MESSAGE-INTEGRITY (optional)
 */
export function createBindingResponse(
  request: Buffer,
  sourceIp: string,
  sourcePort: number,
  icePassword?: string,
): Buffer {
  const transactionId = request.subarray(8, 20);

  // Build XOR-MAPPED-ADDRESS attribute
  const xorMapped = buildXorMappedAddress(sourceIp, sourcePort, transactionId);

  // Build SOFTWARE attribute
  const software = buildSoftwareAttribute('sip-kit');

  // Calculate attributes size
  let attrsSize = xorMapped.length + software.length;

  // If we have an ICE password, add space for MESSAGE-INTEGRITY (24 bytes) and FINGERPRINT (8 bytes)
  if (icePassword) {
    attrsSize += 24 + 8;
  }

  // Build response
  const response = Buffer.alloc(STUN_HEADER_SIZE + attrsSize);

  // Header
  response.writeUInt16BE(STUN_BINDING_RESPONSE, 0);
  response.writeUInt16BE(attrsSize, 2);
  response.writeUInt32BE(STUN_MAGIC_COOKIE, 4);
  transactionId.copy(response, 8);

  // Copy attributes
  let offset = STUN_HEADER_SIZE;
  xorMapped.copy(response, offset);
  offset += xorMapped.length;
  software.copy(response, offset);
  offset += software.length;

  if (icePassword) {
    // Update message length for MESSAGE-INTEGRITY calculation (exclude FINGERPRINT)
    response.writeUInt16BE(attrsSize - 8, 2);

    // Compute HMAC-SHA1 for MESSAGE-INTEGRITY
    const hmac = crypto.createHmac('sha1', icePassword);
    hmac.update(response.subarray(0, offset));
    const digest = hmac.digest();

    // Write MESSAGE-INTEGRITY attribute
    response.writeUInt16BE(ATTR_MESSAGE_INTEGRITY, offset);
    response.writeUInt16BE(20, offset + 2);
    digest.copy(response, offset + 4);
    offset += 24;

    // Restore full message length for FINGERPRINT
    response.writeUInt16BE(attrsSize, 2);

    // Compute CRC32 for FINGERPRINT
    const crc = crc32(response.subarray(0, offset)) ^ 0x5354554e;
    response.writeUInt16BE(ATTR_FINGERPRINT, offset);
    response.writeUInt16BE(4, offset + 2);
    response.writeInt32BE(crc, offset + 4);
  }

  return response;
}

// --- Internal helpers ---

interface StunAttribute {
  type: number;
  value: Buffer;
}

function parseAttributes(buf: Buffer): StunAttribute[] {
  const attrs: StunAttribute[] = [];
  const msgLen = buf.readUInt16BE(2);
  let offset = STUN_HEADER_SIZE;
  const end = STUN_HEADER_SIZE + msgLen;

  while (offset + 4 <= end && offset + 4 <= buf.length) {
    const type = buf.readUInt16BE(offset);
    const length = buf.readUInt16BE(offset + 2);
    const value = buf.subarray(offset + 4, offset + 4 + length);
    attrs.push({ type, value });
    // Attributes are padded to 4-byte boundaries
    offset += 4 + Math.ceil(length / 4) * 4;
  }

  return attrs;
}

function buildXorMappedAddress(ip: string, port: number, transactionId: Buffer): Buffer {
  const parts = ip.split('.').map(Number);
  const isIPv4 = parts.length === 4 && parts.every(p => !isNaN(p));

  if (!isIPv4) {
    throw new Error('Only IPv4 XOR-MAPPED-ADDRESS is supported');
  }

  // XOR the port with the most significant 16 bits of the magic cookie
  const xorPort = port ^ (STUN_MAGIC_COOKIE >> 16);

  // XOR the IP with the magic cookie
  const ipInt =
    ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
  const xorIp = ipInt ^ STUN_MAGIC_COOKIE;

  // Attribute: type(2) + length(2) + reserved(1) + family(1) + port(2) + ip(4) = 12 bytes
  const buf = Buffer.alloc(12);
  buf.writeUInt16BE(ATTR_XOR_MAPPED_ADDRESS, 0);
  buf.writeUInt16BE(8, 2); // value length
  buf.writeUInt8(0x00, 4); // reserved
  buf.writeUInt8(0x01, 5); // IPv4 family
  buf.writeUInt16BE(xorPort, 6);
  buf.writeUInt32BE(xorIp, 8);

  return buf;
}

function buildSoftwareAttribute(name: string): Buffer {
  const nameBytes = Buffer.from(name, 'utf-8');
  const paddedLen = Math.ceil(nameBytes.length / 4) * 4;
  const buf = Buffer.alloc(4 + paddedLen);
  buf.writeUInt16BE(ATTR_SOFTWARE, 0);
  buf.writeUInt16BE(nameBytes.length, 2);
  nameBytes.copy(buf, 4);
  return buf;
}

/** Simple CRC32 implementation */
function crc32(buf: Buffer): number {
  let crc = 0xffffffff;
  for (let i = 0; i < buf.length; i++) {
    crc ^= buf[i];
    for (let j = 0; j < 8; j++) {
      if (crc & 1) {
        crc = (crc >>> 1) ^ 0xedb88320;
      } else {
        crc = crc >>> 1;
      }
    }
  }
  return (crc ^ 0xffffffff) | 0;
}
