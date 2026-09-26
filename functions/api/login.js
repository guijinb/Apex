import { jsonResponse, errorResponse, optionsResponse } from '../_response.js';
import { parseJsonBody, sanitize } from '../_validation.js';
import { hashPassword, verifyPassword, needsRehash, generateToken } from '../_utils.js';
import { getConfig } from '../_config.js';
import { buildSessionCookie, createUserSession } from '../_auth.js';
import { enforceIpRateLimit, enforceKeyRateLimit } from '../_rateLimit.js';
import { verifyCaptchaTokenV2 } from '../_utils.js';
import { writeAudit } from '../_audit.js';
import { getClientIP } from '../_security.js';
import { hashSessionToken } from '../_session.js';

async function upgradePasswordHashIfNeeded(env, user, plainPassword) {
  try {
    if (!needsRehash(user.password_hash)) return;
    const newHash = await hashPassword(plainPassword);
    await env.apex_db.prepare('UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?')
      .bind(newHash, user.id).run();
  } catch (error) {
    console.error('[Login] hash upgrade failed:', error.message);
  }
}

export async function onRequestPost(context) {
  const { request, env } = context;
  const requestId = context.data && context.data.requestId ? context.data.requestId : '';

  const limited = await enforceIpRateLimit(env, request, 'login-ip', 20, 60);
  if (limited) return limited;

  const parsed = await parseJsonBody(request, 4096);
  if (!parsed.ok) return errorResponse(parsed.message, parsed.status, 'bad_request', requestId);
  const body = parsed.data || {};

  const account = sanitize(body.account, 200);
  const password = typeof body.password === 'string' ? body.password : '';
  const captchaToken = typeof body.captchaToken === 'string' ? body.captchaToken : '';

  if (!account || !password) {
    return errorResponse('账号和密码不能为空', 400, 'missing_fields', requestId);
  }
  if (!captchaToken) {
    return errorResponse('请先完成人机验证', 400, 'captcha_missing', requestId);
  }

  const captchaIp = getClientIP(request);
  const captcha = await verifyCaptchaTokenV2(env, captchaToken, captchaIp, 'login');
  if (!captcha.valid) {
    return errorResponse('人机验证无效或已过期，请重新验证', 400, 'captcha_invalid', requestId);
  }

  const accountLimited = await enforceKeyRateLimit(env, 'login-account', `acc:${account.toLowerCase()}`, 10, 300);
  if (accountLimited) return accountLimited;

  const user = await env.apex_db.prepare(
    'SELECT id, username, email, password_hash, email_verified, status FROM users WHERE username = ? OR email = ? LIMIT 1'
  ).bind(account, account).first();

  if (!user) {
    await writeAudit(env, { action: 'login_failed', metadata: { reason: 'no_user' } }, request);
    return errorResponse('账号或密码错误', 401, 'invalid_credentials', requestId);
  }
  if (user.status && user.status !== 'active') {
    await writeAudit(env, { action: 'login_blocked', actorId: user.id, actorType: 'user', metadata: { status: user.status } }, request);
    return errorResponse('账号已被禁用，请联系管理员', 403, 'account_disabled', requestId);
  }

  const validPassword = await verifyPassword(password, user.password_hash);
  if (!validPassword) {
    await writeAudit(env, { action: 'login_failed', actorId: user.id, actorType: 'user', metadata: { reason: 'bad_password' } }, request);
    return errorResponse('账号或密码错误', 401, 'invalid_credentials', requestId);
  }

  await upgradePasswordHashIfNeeded(env, user, password);

  const session = await createUserSession(env, user.id, request);
  const config = getConfig(env);

  await env.apex_db.prepare(
    'UPDATE users SET last_login_at = CURRENT_TIMESTAMP WHERE id = ?'
  ).bind(user.id).run();

  await writeAudit(env, { action: 'login_success', actorId: user.id, actorType: 'user' }, request);

  return jsonResponse({
    success: true,
    message: '登录成功',
    user: {
      id: user.id,
      username: user.username,
      email: user.email,
      emailVerified: Boolean(user.email_verified),
    },
  }, 200, requestId, {
    'Set-Cookie': buildSessionCookie(session.token, config.sessionMaxAge, env),
  });
}

export async function onRequestOptions(context) {
  const requestId = context.data && context.data.requestId ? context.data.requestId : '';
  return optionsResponse(requestId);
}
