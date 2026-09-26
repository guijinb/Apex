import { jsonResponse, errorResponse, optionsResponse } from '../../_response.js';
import { parseJsonBody, sanitize } from '../../_validation.js';
import { verifyPassword } from '../../_utils.js';
import { buildAdminCookie, buildClearAllAdminCookies, createAdminSession, audit } from '../../_admin.js';
import { getConfig } from '../../_config.js';
import { enforceIpRateLimit, enforceKeyRateLimit } from '../../_rateLimit.js';

async function verifyTotpSafe(secret, code) {
  if (!secret || !code) return false;
  try {
    const mod = await import('../../_totp.js');
    return await mod.verifyTotp(secret, code);
  } catch (error) {
    console.error('[AdminLogin] totp error:', error.message);
    return false;
  }
}

export async function onRequestPost(context) {
  const { request, env } = context;
  const requestId = context.data && context.data.requestId ? context.data.requestId : '';
  const config = getConfig(env);

  const ipLimited = await enforceIpRateLimit(env, request, 'admin-login-ip', 10, 300);
  if (ipLimited) return ipLimited;

  const parsed = await parseJsonBody(request, 2048);
  if (!parsed.ok) return errorResponse(parsed.message, parsed.status, 'bad_request', requestId);

  const username = sanitize(parsed.data.username, 64);
  const password = typeof parsed.data.password === 'string' ? parsed.data.password : '';
  const totpCode = sanitize(parsed.data.totpCode, 8);

  if (!username || !password) {
    return errorResponse('账号和密码不能为空', 400, 'missing_fields', requestId);
  }

  const accLimited = await enforceKeyRateLimit(env, 'admin-login-account', `admin:${username}`, 10, 900);
  if (accLimited) return accLimited;

  const admin = await env.apex_db.prepare(
    'SELECT id, username, password_hash, role, totp_secret, totp_enabled, status FROM admin_users WHERE username = ? LIMIT 1'
  ).bind(username).first();

  if (!admin) {
    await audit(env, { action: 'admin_login_failed', metadata: { reason: 'no_user' } }, request);
    return errorResponse('账号或密码错误', 401, 'invalid_credentials', requestId);
  }
  if (admin.status && admin.status !== 'active') {
    await audit(env, { action: 'admin_login_blocked', actorId: admin.id, actorType: 'admin' }, request);
    return errorResponse('管理员账号已禁用', 403, 'admin_disabled', requestId);
  }

  const pwdOk = await verifyPassword(password, admin.password_hash);
  if (!pwdOk) {
    await audit(env, { action: 'admin_login_failed', actorId: admin.id, actorType: 'admin', metadata: { reason: 'bad_password' } }, request);
    return errorResponse('账号或密码错误', 401, 'invalid_credentials', requestId);
  }

  // MFA 检查
  if (admin.totp_enabled) {
    if (!totpCode) {
      return errorResponse('请输入 MFA 验证码', 401, 'need_mfa', requestId);
    }
    const mfaOk = await verifyTotpSafe(admin.totp_secret, totpCode);
    if (!mfaOk) {
      await audit(env, { action: 'admin_mfa_failed', actorId: admin.id, actorType: 'admin' }, request);
      return errorResponse('MFA 验证码错误', 401, 'invalid_mfa', requestId);
    }
  }

  const session = await createAdminSession(env, admin.id, request);
  const token = session.token;

  await env.apex_db.prepare(
    'UPDATE admin_users SET last_login_at = CURRENT_TIMESTAMP WHERE id = ?'
  ).bind(admin.id).run();

  await audit(env, {
    action: 'admin_login_success',
    actorId: admin.id,
    actorType: 'admin',
    metadata: { role: admin.role },
  }, request);

  return jsonResponse({
    success: true,
    message: '登录成功',
    admin: { id: admin.id, username: admin.username, role: admin.role },
  }, 200, requestId, {
    'Set-Cookie': [buildAdminCookie(token, env), ...buildClearAllAdminCookies(env)],
  });
}

export async function onRequestOptions(context) {
  const requestId = context.data && context.data.requestId ? context.data.requestId : '';
  return optionsResponse(requestId);
}
