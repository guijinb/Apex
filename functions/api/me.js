import { jsonResponse } from '../_utils.js';

export async function onRequestGet(context) {
  try {
    const { request, env } = context;
    const auth = request.headers.get('Authorization') || '';
    const token = auth.replace('Bearer ', '').trim();

    if (!token) {
      return jsonResponse({ success: false, message: '未提供登录凭证' }, 401);
    }

    const session = await env.apex_db.prepare(
      `SELECT s.id, s.expires_at, u.id as user_id, u.username, u.email
       FROM sessions s JOIN users u ON s.user_id = u.id
       WHERE s.id = ?`
    ).bind(token).first();

    if (!session || new Date(session.expires_at) < new Date()) {
      return jsonResponse({ success: false, message: '登录已过期' }, 401);
    }

    return jsonResponse({
      success: true,
      user: { id: session.user_id, username: session.username, email: session.email },
    });
  } catch (err) {
    return jsonResponse({ success: false, message: '服务器错误：' + err.message }, 500);
  }
}

export async function onRequestOptions() {
  return jsonResponse({}, 204);
}
