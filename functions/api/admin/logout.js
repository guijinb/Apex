import { jsonResponse, parseCookies } from '../../_utils.js';
import { hashSessionToken } from '../../_session.js';
import { buildClearAdminCookie, audit } from '../../_admin.js';

export async function onRequestPost(context) {
  try {
    const { request, env } = context;
    const cookies = parseCookies(request);
    const token = cookies['apex_admin_session'];
    if (token) {
      const tokenHash = await hashSessionToken(token);
      await env.apex_db.prepare('DELETE FROM admin_sessions WHERE id = ?').bind(tokenHash).run();
      if (context.data && context.data.admin) {
        await audit(env, {
          actorId: context.data.admin.id, actorType: 'admin',
          action: 'admin_logout',
          ip: request.headers.get('CF-Connecting-IP') || '',
        });
      }
    }
    return new Response(JSON.stringify({ success: true }), {
      status: 200,
      headers: {
        'Content-Type': 'application/json; charset=utf-8',
        'Set-Cookie': buildClearAdminCookie(),
      }
    });
  } catch (err) {
    return jsonResponse({ success: false, message: '服务器错误' }, 500);
  }
}
