import { jsonResponse, parseCookies } from '../_utils.js';
import { hashSessionToken } from '../_session.js';

// GET：列出所有活跃会话
export async function onRequestGet(context) {
  try {
    const { request, env } = context;
    const cookies = parseCookies(request);
    const token = cookies['apex_session'];
    if (!token) return jsonResponse({ success: false, message: '未登录' }, 401);

    const tokenHash = await hashSessionToken(token);
    const current = await env.apex_db.prepare(
      'SELECT user_id FROM sessions WHERE id = ?'
    ).bind(tokenHash).first();
    if (!current) return jsonResponse({ success: false, message: '未登录' }, 401);

    const sessions = await env.apex_db.prepare(
      `SELECT id, expires_at, created_at FROM sessions
       WHERE user_id = ? AND expires_at > datetime('now')
       ORDER BY created_at DESC`
    ).bind(current.user_id).all();

    const list = (sessions.results || []).map(s => ({
      id: s.id === tokenHash ? 'current' : s.id.substring(0, 12) + '...',
      isCurrent: s.id === tokenHash,
      expiresAt: s.expires_at,
      createdAt: s.created_at,
    }));

    return jsonResponse({ success: true, sessions: list });
  } catch (err) {
    return jsonResponse({ success: false, message: '服务器错误：' + err.message }, 500);
  }
}

// DELETE：撤销所有其他会话（保留当前）
export async function onRequestDelete(context) {
  try {
    const { request, env } = context;
    const cookies = parseCookies(request);
    const token = cookies['apex_session'];
    if (!token) return jsonResponse({ success: false, message: '未登录' }, 401);

    const tokenHash = await hashSessionToken(token);
    const current = await env.apex_db.prepare(
      'SELECT user_id FROM sessions WHERE id = ?'
    ).bind(tokenHash).first();
    if (!current) return jsonResponse({ success: false, message: '未登录' }, 401);

    await env.apex_db.prepare(
      'DELETE FROM sessions WHERE user_id = ? AND id != ?'
    ).bind(current.user_id, tokenHash).run();

    return jsonResponse({ success: true, message: '已撤销其他所有设备' });
  } catch (err) {
    return jsonResponse({ success: false, message: '服务器错误：' + err.message }, 500);
  }
}

export async function onRequestOptions() { return jsonResponse({}, 204); }
