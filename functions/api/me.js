import { hashSessionToken } from '../_session.js';
import { jsonResponse, parseCookies } from '../_utils.js';

export async function onRequestGet(context) {
  try {
    const { request, env } = context;
    const cookies = parseCookies(request);
    const token = cookies['apex_session'];

    if (!token) {
      return jsonResponse({ success: false, message: '未登录' }, 401);
    }

    const tokenHash = await hashSessionToken(token);
    const session = await env.apex_db.prepare(
      `SELECT s.id, s.expires_at, u.id as user_id, u.username, u.email
       FROM sessions s JOIN users u ON s.user_id = u.id
       WHERE s.id = ?`
    ).bind(tokenHash).first();

    if (!session || new Date(session.expires_at) < new Date()) {
      return new Response(JSON.stringify({ success: false, message: '登录已过期' }), {
        status: 401,
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
          'Set-Cookie': 'apex_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0',
        }
      });
    }

    return jsonResponse({
      success: true,
      user: { id: session.user_id, username: session.username, email: session.email },
    });
  } catch (err) {
    return jsonResponse({ success: false, message: '服务器错误：' + err.message }, 500);
  }
}
export async function onRequestOptions() { return jsonResponse({}, 204); }
