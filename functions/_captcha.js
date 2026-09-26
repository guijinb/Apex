// 自研行为验证系统核心
// 使用 HMAC-SHA256 签名 Token，服务端无状态验证

// Base64 URL 安全编码
function b64url(bytes) {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64urlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return atob(str);
}

// HMAC-SHA256 签名
async function hmacSign(data, secret) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(data));
  return b64url(new Uint8Array(sig));
}

// 生成挑战（challenge）
export async function generateChallenge(secret) {
  const nonce = b64url(crypto.getRandomValues(new Uint8Array(16)));
  const timestamp = Date.now();
  const payload = `${nonce}.${timestamp}`;
  const signature = await hmacSign(payload, secret);
  return { challenge: payload, signature };
}

// 验证挑战签名（防止重放）
export async function verifyChallenge(challenge, signature, secret, maxAgeMs = 120000) {
  const parts = challenge.split('.');
  if (parts.length !== 2) return false;
  const timestamp = parseInt(parts[1]);
  if (Date.now() - timestamp > maxAgeMs) return false; // 挑战过期
  const expected = await hmacSign(challenge, secret);
  return expected === signature;
}

// 签发验证通过 Token（有效期 5 分钟）
export async function issueToken(secret, ipHash, score, ttlMs = 5 * 60 * 1000) {
  const nonce = b64url(crypto.getRandomValues(new Uint8Array(8)));
  const exp = Date.now() + ttlMs;
  const payload = `${nonce}.${exp}.${ipHash}.${score}`;
  const signature = await hmacSign(payload, secret);
  return `${b64url(new TextEncoder().encode(payload))}.${signature}`;
}

// 验证 Token
export async function verifyToken(token, secret, ipHash) {
  try {
    const [payloadEncoded, signature] = token.split('.');
    if (!payloadEncoded || !signature) return { valid: false };

    const payload = new TextDecoder().decode(
      new Uint8Array(b64urlDecode(payloadEncoded).split('').map(c => c.charCodeAt(0)))
    );
    const parts = payload.split('.');
    if (parts.length !== 4) return { valid: false };

    const [, expStr, tokenIpHashed, scoreStr] = parts;
    const exp = parseInt(expStr);

    // 过期检查
    if (Date.now() > exp) return { valid: false, reason: 'expired' };

    // 签名校验
    const expected = await hmacSign(payload, secret);
    if (expected !== signature) return { valid: false, reason: 'bad_signature' };

    // IP 绑定校验（可选，防 Token 盗用）
    if (ipHash && tokenIpHashed && tokenIpHashed !== 'none' && tokenIpHashed !== ipHash) {
      return { valid: false, reason: 'ip_mismatch' };
    }

    return { valid: true, score: parseInt(scoreStr) };
  } catch (e) {
    return { valid: false, reason: 'parse_error' };
  }
}

// IP 简单哈希（不存明文）
export async function hashIP(ip) {
  if (!ip) return 'none';
  const enc = new TextEncoder();
  const buf = await crypto.subtle.digest('SHA-256', enc.encode(ip + '_apex_salt'));
  return b64url(new Uint8Array(buf).slice(0, 8));
}

// 风控评分算法（0-100）
export function calculateScore(signals) {
  let score = 0;

  // ============ 环境指纹（基础分，最多 40 分）============
  if (!signals.webdriver) score += 15;                    // 非 webdriver
  if (signals.languages && signals.languages.length > 0) score += 5;
  if (signals.platform && signals.platform !== '') score += 5;
  if (signals.hardwareConcurrency >= 2) score += 5;
  if (signals.deviceMemory >= 2) score += 5;
  if (signals.screenWidth >= 320 && signals.screenHeight >= 480) score += 5;

  // ============ 行为轨迹（核心分，最多 45 分）============
  if (signals.mouseMoves >= 5) score += 10;
  else if (signals.mouseMoves >= 1) score += 5;

  if (signals.touches >= 3) score += 10;                  // 触屏交互
  else if (signals.touches >= 1) score += 5;

  if (signals.keypresses >= 3) score += 5;
  if (signals.scrolls >= 1) score += 5;

  // 页面停留时间（超过 2 秒认为是真人）
  if (signals.dwellTime >= 2000) score += 15;
  else if (signals.dwellTime >= 500) score += 8;

  // ============ 交互密度（进阶分，最多 15 分）============
  const totalEvents = (signals.mouseMoves || 0) + (signals.touches || 0) + (signals.keypresses || 0);
  if (totalEvents >= 20) score += 15;
  else if (totalEvents >= 10) score += 10;
  else if (totalEvents >= 3) score += 5;

  return Math.min(score, 100);
}

// 判断是否通过（阈值可调）
export function passesVerification(score, threshold = 50) {
  return score >= threshold;
}
