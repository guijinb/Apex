import { getConfig } from './_config.js';
import { hashSessionToken } from './_session.js';
import { generateToken, parseCookies } from './_utils.js';
import { getClientIP, hashIP } from './_security.js';

export function buildSessionCookie(token, maxAgeSec, env = {}) {
  const config = getConfig(env);
  return `${config.sessionCookie}=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAgeSec}`;
}

export function buildClearSessionCookie(env = {}) {
  const config = getConfig(env);
  return `${config.sessionCookie}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`;
}

export function buildAdminCookie(token, maxAgeSec, env = {}) {
  const config = getConfig(env);
  return `${config.adminCookie}=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAgeSec}`;
}

export function buildClearAdminCookie(env = {}) {
  const config = getConfig(env);
  return `${config.adminCookie}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`;
}

export async function createUserSession(env, userId, request) {
  const config = getConfig(env);
  const token = generateToken();
  const tokenHash = await hashSessionToken(token);
  const expiresAt = new Date(Date.now() + config.sessionMaxAge * 1000).toISOString();
  const ipHash = await hashIP(getClientIP(request), env.SESSION_SALT || env.CAPTCHA_SECRET || '');
  const userAgent = String(request.headers.get('User-Agent') || '').substring(0, 200);

  await env.apex_db.prepare(
    `INSERT INTO sessions (id, user_id, created_at, expires_at, last_seen_at, ip_hash, user_agent)
     VALUES (?, ?, CURRENT_TIMESTAMP, ?, CURRENT_TIMESTAMP, ?, ?)`
  ).bind(tokenHash, userId, expiresAt, ipHash, userAgent).run();

  return { token, tokenHash, expiresAt, maxAge: config.sessionMaxAge };
}

export async function getCurrentUser(env, request) {
  const config = getConfig(env);
  const cookies = parseCookies(request);
  const token = cookies[config.sessionCookie] || cookies[config.legacySessionCookie];
  if (!token) return null;

  const tokenHash = await hashSessionToken(token);
  const row = await env.apex_db.prepare(
    `SELECT s.id, s.user_id, s.expires_at, s.revoked_at,
            u.username, u.email, u.email_verified, u.status
     FROM sessions s
     JOIN users u ON u.id = s.user_id
     WHERE s.id = ?`
  ).bind(tokenHash).first();

  if (!row) return null;
  if (row.revoked_at) return null;
  if (new Date(row.expires_at) < new Date()) return null;
  if (row.status && row.status !== 'active') return null;

  env.apex_db.prepare('UPDATE sessions SET last_seen_at = CURRENT_TIMESTAMP WHERE id = ?').bind(tokenHash).run().catch(() => {});

  return {
    sessionId: row.id,
    userId: row.user_id,
    username: row.username,
    email: row.email,
    emailVerified: Boolean(row.email_verified),
    status: row.status || 'active',
    tokenHash,
  };
}

export async function destroyCurrentSession(env, request) {
  const config = getConfig(env);
  const cookies = parseCookies(request);
  const token = cookies[config.sessionCookie] || cookies[config.legacySessionCookie];
  if (!token) return;
  const tokenHash = await hashSessionToken(token);
  await env.apex_db.prepare('DELETE FROM sessions WHERE id = ?').bind(tokenHash).run();
}

export async function destroyAllUserSessions(env, userId) {
  await env.apex_db.prepare('DELETE FROM sessions WHERE user_id = ?').bind(userId).run();
}


// 清理 legacy cookie 名字（迁移用）
export function buildClearLegacySessionCookie(env = {}) {
  const config = getConfig(env);
  return `${config.legacySessionCookie}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`;
}

// 同时返回新旧两个清理 cookie
export function buildClearAllSessionCookies(env = {}) {
  return [buildClearSessionCookie(env), buildClearLegacySessionCookie(env)];
}

// 清理过期 / 已撤销 session（opportunistic 调用）
export async function cleanupExpiredSessions(env) {
  try {
    await env.apex_db.prepare(
      'DELETE FROM sessions WHERE revoked_at IS NOT NULL OR expires_at < CURRENT_TIMESTAMP'
    ).run();
  } catch (e) {
    console.error('[cleanupExpiredSessions] failed:', e && e.message ? e.message : e);
  }
}
