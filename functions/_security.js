export function constantTimeEqual(a, b) {
  const left = new TextEncoder().encode(String(a ?? ''));
  const right = new TextEncoder().encode(String(b ?? ''));
  if (left.length !== right.length) return false;
  let diff = 0;
  for (let i = 0; i < left.length; i += 1) diff |= left[i] ^ right[i];
  return diff === 0;
}

export async function sha256Hex(input) {
  const data = typeof input === 'string' ? new TextEncoder().encode(input) : input;
  const digest = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, '0')).join('');
}

export function base64UrlEncode(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function base64UrlDecode(value) {
  let str = String(value || '').replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

export async function hmacSha256Base64Url(data, secret) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(String(secret || '')), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const signature = await crypto.subtle.sign('HMAC', key, enc.encode(String(data || '')));
  return base64UrlEncode(new Uint8Array(signature));
}

export async function hashIP(ip, salt = '') {
  const value = `${String(ip || '')}_apex_ip_${String(salt || '')}`;
  return (await sha256Hex(value)).slice(0, 32);
}

export function getClientIP(request) {
  const direct = request.headers.get('CF-Connecting-IP');
  if (direct) return direct.trim();
  const forwarded = request.headers.get('X-Forwarded-For');
  if (forwarded) return forwarded.split(',')[0].trim();
  return 'unknown';
}

export function generateNumericCode(length = 6) {
  const max = 10 ** length;
  const random = new Uint32Array(1);
  crypto.getRandomValues(random);
  return String(random[0] % max).padStart(length, '0');
}

export function randomToken(bytes = 32) {
  const random = new Uint8Array(bytes);
  crypto.getRandomValues(random);
  return Array.from(random).map((b) => b.toString(16).padStart(2, '0')).join('');
}

export function redactSensitive(input) {
  return String(input || '')
    .replace(/password[=:][^\s,}]*/gi, 'password=[REDACTED]')
    .replace(/token[=:][^\s,}]*/gi, 'token=[REDACTED]')
    .replace(/Bearer\s+[A-Za-z0-9_\-]+/g, 'Bearer [REDACTED]')
    .replace(/cookie[=:][^\s,}]*/gi, 'cookie=[REDACTED]')
    .replace(/code[=:][^\s,}]*/gi, 'code=[REDACTED]')
    .replace(/secret[=:][^\s,}]*/gi, 'secret=[REDACTED]');
}

export function safeJsonParse(text) {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}
