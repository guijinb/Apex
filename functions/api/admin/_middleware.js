import { jsonResponse, errorResponse } from '../../_response.js';
import { hashSessionToken } from '../../_session.js';
import { parseCookies } from '../../_utils.js';
import { getConfig } from '../../_config.js';
import { buildClearAllAdminCookies } from '../../_admin.js';

function unauthenticatedResponse(env, requestId, message, code) {
  const headers = new Headers();
  headers.set('Content-Type', 'application/json; charset=utf-8');
  headers.set('Cache-Control', 'no-store');
  headers.set('X-Content-Type-Options', 'nosniff');
  if (requestId) headers.set('X-Request-ID', requestId);
  for (const c of buildClearAllAdminCookies(env)) {
    headers.append('Set-Cookie', c);
  }
  return new Response(JSON.stringify({
    success: false,
    message,
    code,
    request_id: requestId || undefined,
  }), { status: 401, headers });
}

const PUBLIC_PATHS = new Set([
  '/api/admin/login',
]);

export async function onRequest(context) {
  const { request, env, next } = context;
  const requestId = context.data && context.data.requestId ? context.data.requestId : '';
  const url = new URL(request.url);
  const config = getConfig(env);

  // 放行登录接口
  if (PUBLIC_PATHS.has(url.pathname)) {
    return next();
  }

  const cookies = parseCookies(request);
  const token = cookies[config.adminCookie] || cookies[config.legacyAdminCookie];
  if (!token) {
    return unauthenticatedResponse(env, requestId, '未登录', 'unauthenticated');
  }

  const tokenHash = await hashSessionToken(token);

  let session;
  try {
    session = await env.apex_db.prepare(
      `SELECT s.id, s.expires_at, s.revoked_at,
              a.id as admin_id, a.username, a.role, a.status
       FROM admin_sessions s
       JOIN admin_users a ON s.admin_id = a.id
       WHERE s.id = ?
       LIMIT 1`
    ).bind(tokenHash).first();
  } catch (error) {
    console.error('[AdminMiddleware] db error:', error.message);
    return errorResponse('服务器内部错误，请稍后重试。', 500, 'internal_error', requestId);
  }

  if (!session) {
    return unauthenticatedResponse(env, requestId, '未登录', 'unauthenticated');
  }
  if (session.revoked_at) {
    return unauthenticatedResponse(env, requestId, '登录已失效', 'session_revoked');
  }
  if (new Date(session.expires_at) < new Date()) {
    return unauthenticatedResponse(env, requestId, '登录已过期', 'session_expired');
  }
  if (session.status && session.status !== 'active') {
    return errorResponse('管理员账号已禁用', 403, 'admin_disabled', requestId);
  }

  // 异步更新 last_seen_at，不阻塞主流程
  env.apex_db.prepare(
    'UPDATE admin_sessions SET last_seen_at = CURRENT_TIMESTAMP WHERE id = ?'
  ).bind(tokenHash).run().catch(() => {});

  context.data = context.data || {};
  context.data.admin = {
    id: session.admin_id,
    username: session.username,
    role: session.role,
    tokenHash,
  };

  return next();
}
