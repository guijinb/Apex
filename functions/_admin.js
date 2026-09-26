// Admin 权限矩阵 + 审计 + Cookie 工具
// 说明：所有敏感操作必须调用 hasPermission() 并写 audit

import { getConfig } from './_config.js';
import { writeAudit as _writeAudit } from './_audit.js';
import { generateToken } from './_utils.js';
import { hashSessionToken } from './_session.js';
import { getClientIP, hashIP } from './_security.js';

export const PERMISSIONS = {
  super_admin: [
    'users.read', 'users.write', 'users.delete',
    'logs.read', 'audit.read', 'sessions.revoke',
    'system.read', 'system.write',
    'admin.create', 'admin.delete',
  ],
  admin: [
    'users.read', 'users.write',
    'logs.read', 'audit.read', 'sessions.revoke',
    'system.read',
  ],
  support: [
    'users.read', 'logs.read', 'sessions.revoke',
  ],
  analyst: [
    'users.read', 'logs.read', 'audit.read', 'system.read',
  ],
  viewer: [
    'users.read', 'logs.read',
  ],
};

export function hasPermission(role, permission) {
  const perms = PERMISSIONS[role] || [];
  return perms.includes(permission);
}

// Admin Cookie 名称与生命周期
export function buildAdminCookie(token, env = {}) {
  const config = getConfig(env);
  return `${config.adminCookie}=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${config.adminSessionMaxAge}`;
}

export function buildClearAdminCookie(env = {}) {
  const config = getConfig(env);
  return `${config.adminCookie}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`;
}

// 清理 legacy cookie 名字（迁移用）
export function buildClearLegacyAdminCookie(env = {}) {
  const config = getConfig(env);
  return `${config.legacyAdminCookie}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`;
}

// 同时返回新旧两个清理 cookie
export function buildClearAllAdminCookies(env = {}) {
  return [buildClearAdminCookie(env), buildClearLegacyAdminCookie(env)];
}

// 审计日志（对外 API 保持旧名，内部走统一 _audit.js）
export async function audit(env, entry = {}, request = null) {
  return _writeAudit(env, entry, request);
}


// ============================================================
// Admin Session 创建（记录 ip_hash / user_agent）
// ============================================================
export async function createAdminSession(env, adminId, request) {
  const config = getConfig(env);
  const token = generateToken();
  const tokenHash = await hashSessionToken(token);
  const expiresAt = new Date(Date.now() + config.adminSessionMaxAge * 1000).toISOString();
  const ipHash = await hashIP(getClientIP(request), env.SESSION_SALT || env.CAPTCHA_SECRET || '');
  const userAgent = String(request.headers.get('User-Agent') || '').substring(0, 200);

  await env.apex_db.prepare(
    `INSERT INTO admin_sessions (id, admin_id, created_at, expires_at, last_seen_at, ip_hash, user_agent)
     VALUES (?, ?, CURRENT_TIMESTAMP, ?, CURRENT_TIMESTAMP, ?, ?)`
  ).bind(tokenHash, adminId, expiresAt, ipHash, userAgent).run();

  return { token, tokenHash, expiresAt, maxAge: config.adminSessionMaxAge };
}

// ============================================================
// Admin Session 清理（opportunistic 调用）
// ============================================================
export async function cleanupExpiredAdminSessions(env) {
  try {
    await env.apex_db.prepare(
      'DELETE FROM admin_sessions WHERE revoked_at IS NOT NULL OR expires_at < CURRENT_TIMESTAMP'
    ).run();
  } catch (e) {
    console.error('[cleanupExpiredAdminSessions] failed:', e && e.message ? e.message : e);
  }
}
