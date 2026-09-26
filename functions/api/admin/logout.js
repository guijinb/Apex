import { jsonResponse, optionsResponse } from '../../_response.js';
import { hashSessionToken } from '../../_session.js';
import { parseCookies } from '../../_utils.js';
import { buildClearAllAdminCookies, cleanupExpiredAdminSessions, audit } from '../../_admin.js';
import { getConfig } from '../../_config.js';

export async function onRequestPost(context) {
  const { request, env } = context;
  const requestId = context.data && context.data.requestId ? context.data.requestId : '';
  const config = getConfig(env);

  try {
    const cookies = parseCookies(request);
    const token = cookies[config.adminCookie] || cookies[config.legacyAdminCookie];
    if (token) {
      const tokenHash = await hashSessionToken(token);
      await env.apex_db.prepare('DELETE FROM admin_sessions WHERE id = ?').bind(tokenHash).run();
    }
    if (context.data && context.data.admin) {
      await audit(env, {
        action: 'admin_logout',
        actorId: context.data.admin.id,
        actorType: 'admin',
      }, request);
    }
  } catch (error) {
    console.error('[AdminLogout] failed:', error.message);
  }

  // 顺手清理过期 admin session
  cleanupExpiredAdminSessions(env);

  return jsonResponse({ success: true, message: '已登出' }, 200, requestId, {
    'Set-Cookie': buildClearAllAdminCookies(env),
  });
}

export async function onRequestOptions(context) {
  const requestId = context.data && context.data.requestId ? context.data.requestId : '';
  return optionsResponse(requestId);
}
