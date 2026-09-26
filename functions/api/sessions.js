import { jsonResponse, errorResponse, optionsResponse } from '../_response.js';
import { getCurrentUser } from '../_auth.js';
import { hashSessionToken } from '../_session.js';

function maskUserAgent(ua) {
  const s = String(ua || '');
  if (!s) return '未知设备';
  if (/iPhone|iPad|iPod/i.test(s)) return 'iOS 设备';
  if (/Android/i.test(s)) return 'Android 设备';
  if (/Macintosh/i.test(s)) return 'Mac 设备';
  if (/Windows/i.test(s)) return 'Windows 设备';
  if (/Linux/i.test(s)) return 'Linux 设备';
  return '未知设备';
}

export async function onRequestGet(context) {
  const { request, env } = context;
  const requestId = context.data && context.data.requestId ? context.data.requestId : '';

  const user = await getCurrentUser(env, request);
  if (!user) return errorResponse('未登录', 401, 'unauthenticated', requestId);

  const rows = await env.apex_db.prepare(
    `SELECT id, created_at, expires_at, last_seen_at, user_agent
     FROM sessions
     WHERE user_id = ? AND revoked_at IS NULL AND expires_at > CURRENT_TIMESTAMP
     ORDER BY created_at DESC`
  ).bind(user.userId).all();

  const list = (rows.results || []).map((s) => ({
    isCurrent: s.id === user.tokenHash,
    createdAt: s.created_at,
    expiresAt: s.expires_at,
    lastSeenAt: s.last_seen_at,
    device: maskUserAgent(s.user_agent),
  }));

  return jsonResponse({ success: true, sessions: list }, 200, requestId);
}

export async function onRequestDelete(context) {
  const { request, env } = context;
  const requestId = context.data && context.data.requestId ? context.data.requestId : '';

  const user = await getCurrentUser(env, request);
  if (!user) return errorResponse('未登录', 401, 'unauthenticated', requestId);

  await env.apex_db.prepare(
    'UPDATE sessions SET revoked_at = CURRENT_TIMESTAMP WHERE user_id = ? AND id != ?'
  ).bind(user.userId, user.tokenHash).run();

  return jsonResponse({ success: true, message: '已撤销其他所有设备' }, 200, requestId);
}

export async function onRequestOptions(context) {
  const requestId = context.data && context.data.requestId ? context.data.requestId : '';
  return optionsResponse(requestId);
}
