// 双重 Cookie 模式 CSRF 防护
// 1. 生成随机 CSRF token，写入 Cookie（非 HttpOnly，JS 可读）
// 2. 前端每次请求携带 X-CSRF-Token header
// 3. 服务端比对 Cookie 和 header 是否一致

export function generateCsrfToken() {
  const bytes = crypto.getRandomValues(new Uint8Array(24));
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

export function buildCsrfCookie(token) {
  return `apex_csrf=${token}; Path=/; Secure; SameSite=Strict; Max-Age=${30 * 24 * 60 * 60}`;
}

export function verifyCsrf(request) {
  const cookieHeader = request.headers.get('Cookie') || '';
  const csrfCookie = cookieHeader.match(/apex_csrf=([^;]+)/);
  const csrfHeader = request.headers.get('X-CSRF-Token');
  if (!csrfCookie || !csrfHeader) return false;
  return csrfCookie[1] === csrfHeader;
}
