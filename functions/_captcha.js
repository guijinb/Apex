// 自研行为验证系统
// - Challenge 使用 HMAC-SHA256 签名，防止重放
// - Token 使用 HMAC-SHA256 签名，绑定 IP hash + purpose
// - Token 存储在 captcha_tokens 表，一次性消费
import {
  base64UrlEncode,
  base64UrlDecode,
  hmacSha256Base64Url,
  sha256Hex,
  constantTimeEqual,
  hashIP,
  getClientIP,
} from './_security.js';

export const CAPTCHA_PURPOSES = new Set(['login', 'register', 'reset-password']);
export const CAPTCHA_THRESHOLD = 50;

export async function generateChallenge(secret) {
  if (!secret) throw new Error('captcha_secret_missing');
  const nonceBytes = crypto.getRandomValues(new Uint8Array(16));
  const nonce = base64UrlEncode(nonceBytes);
  const timestamp = Date.now();
  const payload = `${nonce}.${timestamp}`;
  const signature = await hmacSha256Base64Url(payload, secret);
  return { challenge: payload, signature };
}

export async function verifyChallenge(challenge, signature, secret, maxAgeMs = 120000) {
  if (!secret || !challenge || !signature) return false;
  const parts = String(challenge).split('.');
  if (parts.length !== 2) return false;
  const ts = Number.parseInt(parts[1], 10);
  if (!Number.isFinite(ts)) return false;
  const now = Date.now();
  if (now - ts > maxAgeMs) return false;
  if (ts > now + 5000) return false;
  const expected = await hmacSha256Base64Url(challenge, secret);
  return constantTimeEqual(expected, signature);
}

export function calculateScore(signals) {
  let score = 0;
  const s = signals || {};

  if (!s.webdriver) score += 15;
  if (Array.isArray(s.languages) && s.languages.length > 0) score += 5;
  if (s.platform && s.platform !== '') score += 5;
  if (s.hardwareConcurrency >= 2) score += 5;
  if (s.deviceMemory >= 2) score += 5;
  if (s.screenWidth >= 320 && s.screenHeight >= 480) score += 5;

  if (s.mouseMoves >= 5) score += 10;
  else if (s.mouseMoves >= 1) score += 5;

  if (s.touches >= 3) score += 10;
  else if (s.touches >= 1) score += 5;

  if (s.keypresses >= 3) score += 5;
  if (s.scrolls >= 1) score += 5;

  if (s.dwellTime >= 2000) score += 15;
  else if (s.dwellTime >= 500) score += 8;

  const totalEvents = (s.mouseMoves || 0) + (s.touches || 0) + (s.keypresses || 0);
  if (totalEvents >= 20) score += 15;
  else if (totalEvents >= 10) score += 10;
  else if (totalEvents >= 3) score += 5;

  return Math.min(score, 100);
}

export function passesVerification(score, threshold = CAPTCHA_THRESHOLD) {
  return Number(score) >= threshold;
}

export async function issueToken(env, secret, { ipHash, purpose, score }, ttlMs = 5 * 60 * 1000) {
  if (!secret) throw new Error('captcha_secret_missing');
  if (!CAPTCHA_PURPOSES.has(String(purpose || ''))) throw new Error('captcha_invalid_purpose');

  const nonceBytes = crypto.getRandomValues(new Uint8Array(16));
  const nonce = base64UrlEncode(nonceBytes);
  const exp = Date.now() + ttlMs;
  const payload = `${nonce}.${exp}.${ipHash || 'none'}.${purpose}.${score}`;
  const signature = await hmacSha256Base64Url(payload, secret);
  const payloadEncoded = base64UrlEncode(new TextEncoder().encode(payload));
  const token = `${payloadEncoded}.${signature}`;
  const tokenHash = await sha256Hex(token);

  await env.apex_db.prepare(
    `INSERT INTO captcha_tokens (token_hash, purpose, ip_hash, score, expires_at)
     VALUES (?, ?, ?, ?, ?)`
  ).bind(tokenHash, purpose, ipHash || 'none', score, new Date(exp).toISOString()).run();

  return token;
}

export async function consumeToken(env, token, secret, { ipHash, purpose } = {}) {
  if (!token) return { valid: false, reason: 'missing_token' };
  if (!secret) return { valid: false, reason: 'no_secret' };

  const value = String(token);
  const idx = value.lastIndexOf('.');
  if (idx <= 0 || idx === value.length - 1) return { valid: false, reason: 'format' };

  const payloadEncoded = value.slice(0, idx);
  const signature = value.slice(idx + 1);

  let payload;
  try {
    payload = new TextDecoder().decode(base64UrlDecode(payloadEncoded));
  } catch {
    return { valid: false, reason: 'decode' };
  }

  const parts = payload.split('.');
  if (parts.length !== 5) return { valid: false, reason: 'payload' };

  const [, expStr, tokenIpHashed, tokenPurpose, scoreStr] = parts;
  const exp = Number.parseInt(expStr, 10);
  if (!Number.isFinite(exp)) return { valid: false, reason: 'exp' };
  if (Date.now() > exp) return { valid: false, reason: 'expired' };

  const expected = await hmacSha256Base64Url(payload, secret);
  if (!constantTimeEqual(expected, signature)) return { valid: false, reason: 'bad_signature' };

  if (ipHash && tokenIpHashed && tokenIpHashed !== 'none' && tokenIpHashed !== ipHash) {
    return { valid: false, reason: 'ip_mismatch' };
  }

  if (purpose && tokenPurpose !== purpose) {
    return { valid: false, reason: 'purpose_mismatch' };
  }

  const tokenHash = await sha256Hex(value);
  let consumed = null;
  try {
    consumed = await env.apex_db.prepare(
      `UPDATE captcha_tokens
       SET used_at = CURRENT_TIMESTAMP
       WHERE token_hash = ?
         AND used_at IS NULL
         AND expires_at > CURRENT_TIMESTAMP
       RETURNING token_hash`
    ).bind(tokenHash).first();
  } catch (error) {
    console.error('[Captcha] consume error:', error.message);
    return { valid: false, reason: 'storage_error' };
  }

  if (!consumed) return { valid: false, reason: 'used_or_unknown' };
  return { valid: true, score: Number.parseInt(scoreStr, 10) || 0, purpose: tokenPurpose };
}

export async function cleanupExpiredTokens(env) {
  try {
    await env.apex_db.prepare(
      `DELETE FROM captcha_tokens WHERE expires_at < datetime('now', '-1 hour')`
    ).run();
  } catch (error) {
    console.error('[Captcha] cleanup failed:', error.message);
  }
}

export function extractClientIP(request) {
  return getClientIP(request);
}

export { hashIP };
