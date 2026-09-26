import { jsonResponse, parseCookies, verifyPassword } from '../_utils.js';
import { hashSessionToken } from '../_session.js';

export async function onRequestPost(context) {
  try {
    const { request, env } = context;
    const cookies = parseCookies(request);
    const token = cookies['apex_session'];
    if (!token) return jsonResponse({ success: false, message: '未登录' }, 401);

    const tokenHash = await hashSessionToken(token);
    const session = await env.apex_db.prepare(
      'SELECT user_id FROM sessions WHERE id = ?'
    ).bind(tokenHash).first();
    if (!session) return jsonResponse({ success: false, message: '未登录' }, 401);

    const body = await request.json();
    const password = body.password || '';
    if (!password) return jsonResponse({ success: false, message: '请提供密码确认' }, 400);

    const user = await env.apex_db.prepare(
      'SELECT id, password_hash FROM users WHERE id = ?'
    ).bind(session.user_id).first();
    if (!user || !(await verifyPassword(password, user.password_hash))) {
      return jsonResponse({ success: false, message: '密码错误' }, 401);
    }

    // 删除所有关联数据（外键级联会处理 sessions/email_verifications/password_resets）
    await env.apex_db.prepare('DELETE FROM sessions WHERE user_id = ?').bind(user.id).run();
    await env.apex_db.prepare('DELETE FROM email_verifications WHERE user_id = ?').bind(user.id).run();
    await env.apex_db.prepare('DELETE FROM users WHERE id = ?').bind(user.id).run();

    return new Response(JSON.stringify({ success: true, message: '账号已删除' }), {
      status: 200,
      headers: {
        'Content-Type': 'application/json; charset=utf-8',
        'Set-Cookie': 'apex_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0',
      }
    });
  } catch (err) {
    return jsonResponse({ success: false, message: '服务器错误：' + err.message }, 500);
  }
}
export async function onRequestOptions() { return jsonResponse({}, 204); }
