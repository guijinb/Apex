// 双重 Cookie 模式 CSRF 防护
// 1. 生成随机 CSRF token，写入 Cookie（非 HttpOnly，JS 可读）
// 2. 前端每次请求携带 X-CSRF-Token header
// 3. 服务端比对 Cookie 和 header 是否一致（恒定时间比较）
//
// 安全要点：
//  - token 由 crypto.getRandomValues 生成（32 字节 / 64 hex）
//  - 只保存到 Cookie（非 HttpOnly），不下发到 body
//  - 比较使用恒定时间算法，避免时序侧信道
//  - 缺失 / 长度不符 → 直接拒绝

const CSRF_COOKIE_NAME = 'apex_csrf';
const CSRF_COOKIE_MAX_AGE = 30 * 24 * 60 * 60; // 30 天

export function generateCsrfToken() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

export function buildCsrfCookie(token) {
  // 非 HttpOnly：前端 JS 需要读取并放入 header
  // Secure + SameSite=Strict：防跨站发送
  return `${CSRF_COOKIE_NAME}=${token}; Path=/; Secure; SameSite=Strict; Max-Age=${CSRF_COOKIE_MAX_AGE}`;
}

export function buildClearCsrfCookie() {
  return `${CSRF_COOKIE_NAME}=; Path=/; Secure; SameSite=Strict; Max-Age=0`;
}

// 恒定时间字符串比较
function timingSafeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

// 严格解析 Cookie（避免 a=1; apex_csrf_x=2 之类误匹配）
function readCookie(request, name) {
  const header = request.headers.get('Cookie') || '';
  if (!header) return null;
  const parts = header.split(';');
  for (const part of parts) {
    const trimmed = part.trim();
    const eq = trimmed.indexOf('=');
    if (eq === -1) continue;
    const k = trimmed.slice(0, eq);
    if (k === name) {
      return trimmed.slice(eq + 1);
    }
  }
  return null;
}

export function getCsrfCookie(request) {
  return readCookie(request, CSRF_COOKIE_NAME);
}

export function verifyCsrf(request) {
  const cookieToken = readCookie(request, CSRF_COOKIE_NAME);
  const headerToken = request.headers.get('X-CSRF-Token');
  if (!cookieToken || !headerToken) return false;
  return timingSafeEqual(cookieToken, headerToken);
}
