import { jsonResponse, parseCookies, buildClearCookie } from '../_utils.js';

export async function onRequestPost(context) {
  try {
    const { request, env } = context;
    const cookies = parseCookies(request);
    const token = cookies['apex_session'];

    if (token) {
      // 从数据库中删除这个 Session
      await env.apex_db.prepare('DELETE FROM sessions WHERE id = ?').bind(token).run();
    }

    return new Response(JSON.stringify({ success: true, message: '已登出' }), {
      status: 200,
      headers: {
        'Content-Type': 'application/json; charset=utf-8',
        'Set-Cookie': buildClearCookie(),
      }
    });
  } catch (err) {
    return jsonResponse({ success: false, message: '服务器错误：' + err.message }, 500);
  }
}

export async function onRequestOptions() { return jsonResponse({}, 204); }
