// 邮箱验证 Token 工具
// 独立 salt：与 Session token 隔离，避免跨用途 hash 复用
// 数据库只存 hash，不存明文 token

const EMAIL_VERIFY_PREFIX = 'apex_email_verify_v1_';

export async function hashEmailVerifyToken(token) {
  const enc = new TextEncoder();
  const buf = await crypto.subtle.digest('SHA-256', enc.encode(EMAIL_VERIFY_PREFIX + String(token || '')));
  return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, '0')).join('');
}
