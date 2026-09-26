import { jsonResponse, optionsResponse } from '../_response.js';
import {
  destroyCurrentSession,
  buildClearAllSessionCookies,
  cleanupExpiredSessions,
} from '../_auth.js';
import { writeAudit } from '../_audit.js';

export async function onRequestPost(context) {
  const { request, env } = context;
  const requestId = context.data && context.data.requestId ? context.data.requestId : '';

  try {
    await destroyCurrentSession(env, request);
    await writeAudit(env, { action: 'logout' }, request);
  } catch (error) {
    console.error('[Logout] failed:', error && error.message ? error.message : error);
  }

  // 顺手清理过期 session（不阻塞主流程，出错也不影响 logout）
  cleanupExpiredSessions(env);

  const headers = new Headers();
  headers.set('Content-Type', 'application/json; charset=utf-8');
  if (requestId) headers.set('X-Request-ID', requestId);
  for (const c of buildClearAllSessionCookies(env)) {
    headers.append('Set-Cookie', c);
  }

  return new Response(JSON.stringify({ success: true, message: '已登出' }), {
    status: 200,
    headers,
  });
}

export async function onRequestOptions(context) {
  const requestId = context.data && context.data.requestId ? context.data.requestId : '';
  return optionsResponse(requestId);
}
