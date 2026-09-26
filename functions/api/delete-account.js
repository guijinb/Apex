import { jsonResponse, errorResponse, optionsResponse } from '../_response.js';
import { parseJsonBody } from '../_validation.js';
import { verifyPassword } from '../_utils.js';
import { getCurrentUser, buildClearAllSessionCookies } from '../_auth.js';
import { writeAudit } from '../_audit.js';

export async function onRequestPost(context) {
  const { request, env } = context;
  const requestId = context.data && context.data.requestId ? context.data.requestId : '';

  const user = await getCurrentUser(env, request);
  if (!user) return errorResponse('未登录', 401, 'unauthenticated', requestId);

  const parsed = await parseJsonBody(request, 2048);
  if (!parsed.ok) return errorResponse(parsed.message, parsed.status, 'bad_request', requestId);
  const password = typeof parsed.data.password === 'string' ? parsed.data.password : '';
  if (!password) return errorResponse('请提供密码确认', 400, 'missing_password', requestId);

  const row = await env.apex_db.prepare(
    'SELECT id, password_hash FROM users WHERE id = ?'
  ).bind(user.userId).first();
  if (!row) return errorResponse('账号不存在', 404, 'not_found', requestId);

  const ok = await verifyPassword(password, row.password_hash);
  if (!ok) return errorResponse('密码错误', 401, 'invalid_password', requestId);

  try {
    // 4 条 DELETE 必须原子提交：要么全部成功，要么全部回滚，
    // 避免出现「用户已删除但关联数据残留」的不一致状态。
    await env.apex_db.batch([
      env.apex_db.prepare('DELETE FROM sessions WHERE user_id = ?').bind(user.userId),
      env.apex_db.prepare('DELETE FROM email_verifications WHERE user_id = ?').bind(user.userId),
      env.apex_db.prepare('DELETE FROM password_resets WHERE email = ?').bind(user.email),
      env.apex_db.prepare('DELETE FROM users WHERE id = ?').bind(user.userId),
    ]);

    await writeAudit(env, {
      action: 'account_deleted',
      actorId: user.userId,
      actorType: 'user',
    }, request);

    const headers = new Headers();
    headers.set('Content-Type', 'application/json; charset=utf-8');
    if (requestId) headers.set('X-Request-ID', requestId);
    for (const c of buildClearAllSessionCookies(env)) {
      headers.append('Set-Cookie', c);
    }
    return new Response(JSON.stringify({ success: true, message: '账号已删除' }), {
      status: 200,
      headers,
    });
  } catch (error) {
    console.error('[DeleteAccount] failed:', error.message);
    return errorResponse('服务器内部错误，请稍后重试。', 500, 'internal_error', requestId);
  }
}

export async function onRequestOptions(context) {
  const requestId = context.data && context.data.requestId ? context.data.requestId : '';
  return optionsResponse(requestId);
}
