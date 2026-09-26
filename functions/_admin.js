import { generateToken, hashPassword, verifyPassword } from './_utils.js';
import { hashSessionToken } from './_session.js';

// 管理员 Session Cookie
export function buildAdminCookie(token, maxAgeSec = 8 * 60 * 60) {
  return `apex_admin_session=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAgeSec}`;
}
export function buildClearAdminCookie() {
  return 'apex_admin_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0';
}

// 权限矩阵
export const PERMISSIONS = {
  super_admin: ['users.read','users.write','users.delete','logs.read','audit.read','sessions.revoke','system.read','system.write','admin.create','admin.delete'],
  admin:       ['users.read','users.write','logs.read','audit.read','sessions.revoke','system.read'],
  support:     ['users.read','logs.read','sessions.revoke'],
  analyst:     ['users.read','logs.read','audit.read','system.read'],
  viewer:      ['users.read','logs.read'],
};

export function hasPermission(role, permission) {
  const perms = PERMISSIONS[role] || [];
  return perms.includes(permission);
}

// 记录审计日志
export async function audit(env, { actorId, actorType, action, targetType, targetId, ip, userAgent, metadata }) {
  try {
    await env.apex_db.prepare(
      `INSERT INTO audit_logs (actor_id, actor_type, action, target_type, target_id, ip, user_agent, metadata)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(
      actorId || null, actorType || 'system', action,
      targetType || null, targetId || null,
      ip || null, (userAgent || '').substring(0, 200),
      metadata ? JSON.stringify(metadata) : null
    ).run();
  } catch (e) {
    console.error('[Audit] 写日志失败：', e.message);
  }
}
