import { jsonResponse, parseCookies } from '../../_utils.js';
import { hashSessionToken } from '../../_session.js';

export async function onRequest(context) {
  const { request, env, next } = context;

  // 放行登录接口
  const url = new URL(request.url);
  if (url.pathname === '/api/admin/login') {
    return next();
  }

  const cookies = parseCookies(request);
  const token = cookies['apex_admin_session'];
  if (!token) return jsonResponse({ success: false, message: '未登录' }, 401);

  const tokenHash = await hashSessionToken(token);
  const session = await env.apex_db.prepare(
    `SELECT s.id, s.expires_at, a.id as admin_id, a.username, a.role
     FROM admin_sessions s JOIN admin_users a ON s.admin_id = a.id
     WHERE s.id = ?`
  ).bind(tokenHash).first();

  if (!session || new Date(session.expires_at) < new Date()) {
    return jsonResponse({ success: false, message: '登录已过期' }, 401);
  }

  context.data = context.data || {};
  context.data.admin = {
    id: session.admin_id,
    username: session.username,
    role: session.role,
  };
  return next();
}
