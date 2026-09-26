import { verifyToken as _verifyCaptchaToken, hashIP as _hashIP } from './_captcha.js';

// 密码哈希（PBKDF2 + SHA-256，10万次迭代）
export async function hashPassword(password) {
  const ITERATIONS = 600000;
  const encoder = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey(
    'raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']
  );
  const hash = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: ITERATIONS, hash: 'SHA-256' },
    keyMaterial, 256
  );
  const saltHex = Array.from(salt).map(b => b.toString(16).padStart(2, '0')).join('');
  const hashHex = Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
  return `v1:${ITERATIONS}:${saltHex}:${hashHex}`;
}

export async function verifyPassword(password, stored) {
  const encoder = new TextEncoder();
  let saltHex, hashHex, iterations;

  if (stored.startsWith('v1:')) {
    const parts = stored.split(':');
    iterations = parseInt(parts[1]);
    saltHex = parts[2];
    hashHex = parts[3];
  } else {
    const [oldSalt, oldHash] = stored.split(':');
    saltHex = oldSalt;
    hashHex = oldHash;
    iterations = 100000;
  }

  const salt = new Uint8Array(saltHex.match(/.{1,2}/g).map(b => parseInt(b, 16)));
  const keyMaterial = await crypto.subtle.importKey(
    'raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']
  );
  const hash = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    keyMaterial, 256
  );
  const newHashHex = Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
  return newHashHex === hashHex;
}

export function needsRehash(stored) {
  if (!stored) return true;
  if (!stored.startsWith('v1:')) return true;
  const parts = stored.split(':');
  return parseInt(parts[1]) < 600000;
}

export function generateToken() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// 生成 6 位数字验证码
export function generateCode() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

// 输入清理（防 XSS / SQL 注入）
export function sanitize(str) {
  if (typeof str !== 'string') return '';
  return str.replace(/[<>"'`;\\]/g, '').trim().substring(0, 200);
}

// 统一 JSON 响应格式
export function jsonResponse(data, status = 200) {
  // 204 No Content / 304 Not Modified 不允许有 body
  if (status === 204 || status === 304) {
    return new Response(null, {
      status,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, X-CSRF-Token',
      },
    });
  }
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, X-CSRF-Token',
    },
  });
}

// 校验函数
export function validateEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}
export function validateUsername(username) {
  return /^[a-zA-Z0-9_]{6,20}$/.test(username);
}
export function validatePassword(pwd) {
  return /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]).{8,}$/.test(pwd);
}

// 速率限制检查：同一 IP 在 windowSec 秒内最多允许 maxCount 次请求
export async function checkRateLimit(env, ip, action, maxCount, windowSec) {
  const since = new Date(Date.now() - windowSec * 1000).toISOString();
  const result = await env.apex_db.prepare(
    'SELECT COUNT(*) as cnt FROM rate_limits WHERE ip = ? AND action = ? AND created_at > ?'
  ).bind(ip, action, since).first();
  if (result && result.cnt >= maxCount) {
    return { allowed: false, remaining: 0 };
  }
  await env.apex_db.prepare(
    'INSERT INTO rate_limits (ip, action) VALUES (?, ?)'
  ).bind(ip, action).run();
  return { allowed: true, remaining: maxCount - result.cnt - 1 };
}
export function parseCookies(request) {
  const cookieHeader = request.headers.get('Cookie') || '';
  const cookies = {};
  cookieHeader.split(';').forEach(cookie => {
    const [name, ...rest] = cookie.trim().split('=');
    if (name) cookies[name] = rest.join('=');
  });
  return cookies;
}

// 生成 Set-Cookie 头（HttpOnly + Secure + SameSite=Strict）
export function buildSessionCookie(token, maxAgeSec = 7 * 24 * 60 * 60) {
  return `apex_session=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAgeSec}`;
}

// 生成清除 Cookie 的头
export function buildClearCookie() {
  return 'apex_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0';
}


// 校验自研人机验证 Token
export async function verifyCaptchaTokenV2(env, token, ip) {
  if (!token) return { valid: false, reason: 'missing_token' };
  const secret = env.CAPTCHA_SECRET;
  if (!secret) return { valid: false, reason: 'no_secret' };
  const ipHash = await _hashIP(ip || '');
  return await _verifyCaptchaToken(token, secret, ipHash);
}
