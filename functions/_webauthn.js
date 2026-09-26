// Apex WebAuthn / Passkey 核心
// 参考：W3C WebAuthn Level 2, RFC 8949 (CBOR), RFC 8152 (COSE)
//
// 支持：ES256 (ECDSA P-256 + SHA-256) — 现代设备的默认算法

import { decodeCbor } from './_cbor.js';

// Authenticator Data flags (W3C §6.1)
export const AUTH_FLAGS = {
  UP: 0x01, // User Present
  UV: 0x04, // User Verified
  BE: 0x08, // Backup Eligible
  BS: 0x10, // Backup State
  AT: 0x40, // Attested Credential Data included
  ED: 0x80, // Extension Data included
};

// base64url 编码/解码（本地实现，避免循环 import）
export function b64uEncode(input) {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  let str = '';
  for (const b of bytes) str += String.fromCharCode(b);
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function b64uDecode(s) {
  const str = String(s || '').replace(/-/g, '+').replace(/_/g, '/');
  const pad = str.length % 4 === 0 ? '' : '='.repeat(4 - (str.length % 4));
  const binary = atob(str + pad);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

// ============================================================
// 1) 生成 32 字节挑战（base64url 编码）
// ============================================================
export function generateChallenge() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return b64uEncode(bytes);
}

// ============================================================
// 2) 解析 Authenticator Data（W3C §6.1）
//   结构：
//     rpIdHash        32 bytes
//     flags            1 byte
//     signCount        4 bytes (big-endian)
//     [attestedCredentialData]  (if AT)
//     [extensions]               (if ED)
// ============================================================
export function parseAuthenticatorData(rawBytes) {
  const bytes = rawBytes instanceof Uint8Array ? rawBytes : new Uint8Array(rawBytes);
  if (bytes.length < 37) throw new Error('authdata_too_short');

  const rpIdHash = bytes.slice(0, 32);
  const flags = bytes[32];
  const signCount = (bytes[33] << 24) | (bytes[34] << 16) | (bytes[35] << 8) | bytes[36];

  let offset = 37;
  let aaguid = null;
  let credentialId = null;
  let credentialPublicKey = null;
  let extensions = null;

  if (flags & AUTH_FLAGS.AT) {
    if (bytes.length < offset + 18) throw new Error('authdata_at_truncated');
    aaguid = bytes.slice(offset, offset + 16);
    offset += 16;
    const credIdLen = (bytes[offset] << 8) | bytes[offset + 1];
    offset += 2;
    if (bytes.length < offset + credIdLen) throw new Error('authdata_credid_truncated');
    credentialId = bytes.slice(offset, offset + credIdLen);
    offset += credIdLen;
    // credentialPublicKey 是 CBOR 编码的 COSE key，长度自描述
    // 我们不知道它多长，所以尝试解析（解码器会消耗到合适位置）
    // 简单方案：截取剩余部分，由 caller 用 decodeCbor 解析
    credentialPublicKey = bytes.slice(offset);
    // 注意：这里 credentialPublicKey 包含后续 extensions（如果有）
    // 但 decodeCbor 遇到尾部多余字节时会忽略（我们的实现允许）
    offset = bytes.length;
  }

  return {
    rpIdHash,
    flags,
    signCount,
    userPresent:   !!(flags & AUTH_FLAGS.UP),
    userVerified:  !!(flags & AUTH_FLAGS.UV),
    backupEligible: !!(flags & AUTH_FLAGS.BE),
    backupState:   !!(flags & AUTH_FLAGS.BS),
    attestedDataIncluded: !!(flags & AUTH_FLAGS.AT),
    extensionDataIncluded: !!(flags & AUTH_FLAGS.ED),
    aaguid,
    credentialId,
    credentialPublicKey,
    extensions,
  };
}

// ============================================================
// 3) 从 COSE Key 提取 JWK（仅支持 ES256）
//   COSE key 是 CBOR map，形如：
//     1  : 2      (kty = EC2)
//     3  : -7     (alg = ES256)
//    -1  : 1      (crv = P-256)
//    -2  : <x>    (32 bytes)
//    -3  : <y>    (32 bytes)
// ============================================================
export function coseKeyToJwk(coseKey) {
  if (!coseKey || typeof coseKey !== 'object') throw new Error('cose_invalid');
  const kty = coseKey['1'];
  const alg = coseKey['3'];
  const crv = coseKey['-1'];
  const x   = coseKey['-2'];
  const y   = coseKey['-3'];

  if (kty !== 2) throw new Error('cose_unsupported_kty_' + kty);
  if (alg !== -7) throw new Error('cose_unsupported_alg_' + alg);
  if (crv !== 1) throw new Error('cose_unsupported_crv_' + crv);
  if (!(x instanceof Uint8Array) || x.length !== 32) throw new Error('cose_x_invalid');
  if (!(y instanceof Uint8Array) || y.length !== 32) throw new Error('cose_y_invalid');

  return {
    kty: 'EC',
    crv: 'P-256',
    x: b64uEncode(x),
    y: b64uEncode(y),
    ext: true,
  };
}

// ============================================================
// 4) DER → IEEE P1363 (raw r||s) 转换
//   部分旧浏览器返回 DER 格式签名，需要转换才能被 Web Crypto 接受
//   P-256: 每个分量 32 字节
// ============================================================
function derToRaw(derBytes) {
  const bytes = derBytes instanceof Uint8Array ? derBytes : new Uint8Array(derBytes);
  if (bytes.length < 8) throw new Error('der_too_short');
  if (bytes[0] !== 0x30) throw new Error('der_no_seq');

  // 读 SEQUENCE 长度
  let pos = 1;
  let totalLen;
  if (bytes[pos] < 0x80) { totalLen = bytes[pos]; pos += 1; }
  else { const n = bytes[pos] & 0x7f; pos += 1; totalLen = 0; for (let i = 0; i < n; i += 1) totalLen = (totalLen << 8) | bytes[pos++]; }

  // INTEGER r
  if (bytes[pos] !== 0x02) throw new Error('der_no_int_r');
  pos += 1;
  const rLen = bytes[pos]; pos += 1;
  let r = bytes.slice(pos, pos + rLen); pos += rLen;
  // 去掉前导 0
  if (r.length > 32 && r[0] === 0) r = r.slice(r.length - 32);
  // 左侧补 0
  const rPad = new Uint8Array(32);
  rPad.set(r, 32 - r.length);

  // INTEGER s
  if (bytes[pos] !== 0x02) throw new Error('der_no_int_s');
  pos += 1;
  const sLen = bytes[pos]; pos += 1;
  let s = bytes.slice(pos, pos + sLen); pos += sLen;
  if (s.length > 32 && s[0] === 0) s = s.slice(s.length - 32);
  const sPad = new Uint8Array(32);
  sPad.set(s, 32 - s.length);

  const out = new Uint8Array(64);
  out.set(rPad, 0);
  out.set(sPad, 32);
  return out;
}

// ============================================================
// 5) ES256 签名验证
//   data       : 待验证的字节（authData || SHA-256(clientDataJSON)）
//   signature  : 64 字节 r||s 或 DER
//   jwk        : COSE → JWK
// ============================================================
export async function verifyEs256Signature(jwk, signature, data) {
  const sigBytes = signature instanceof Uint8Array ? signature : new Uint8Array(signature);
  const dataBytes = data instanceof Uint8Array ? data : new Uint8Array(data);

  // 检测格式
  let rawSig;
  if (sigBytes.length === 64) rawSig = sigBytes;
  else if (sigBytes[0] === 0x30) rawSig = derToRaw(sigBytes);
  else throw new Error('sig_unknown_format');

  const key = await crypto.subtle.importKey(
    'jwk',
    { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y, ext: true },
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['verify']
  );

  return crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    key,
    rawSig,
    dataBytes
  );
}

// ============================================================
// 6) 验证 clientDataJSON
// ============================================================
export function verifyClientData(clientDataJSON, opts) {
  const { expectedType, expectedChallenge, expectedOrigins } = opts;
  let data;
  try { data = JSON.parse(clientDataJSON); }
  catch { throw new Error('clientdata_invalid_json'); }

  if (data.type !== expectedType) throw new Error('clientdata_wrong_type');
  if (data.challenge !== expectedChallenge) throw new Error('clientdata_wrong_challenge');

  const origins = Array.isArray(expectedOrigins) ? expectedOrigins : [expectedOrigins];
  const cleanOrigin = String(data.origin || '').replace(/\/+$/, '');
  if (!origins.some((o) => String(o).replace(/\/+$/, '') === cleanOrigin)) {
    throw new Error('clientdata_wrong_origin');
  }

  return data;
}

// ============================================================
// 7) 便捷函数：SHA-256
// ============================================================
export async function sha256(bytes) {
  const buf = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  const hash = await crypto.subtle.digest('SHA-256', buf);
  return new Uint8Array(hash);
}

// ============================================================
// 8) 拼接 authData || SHA-256(clientDataJSON)
// ============================================================
export async function buildSignatureBase(authDataBytes, clientDataJSON) {
  const authData = authDataBytes instanceof Uint8Array ? authDataBytes : new Uint8Array(authDataBytes);
  const clientHash = await sha256(new TextEncoder().encode(clientDataJSON));
  const out = new Uint8Array(authData.length + clientHash.length);
  out.set(authData, 0);
  out.set(clientHash, authData.length);
  return out;
}
