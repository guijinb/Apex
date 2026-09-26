import { jsonResponse, errorResponse, optionsResponse } from '../_response.js';
import {
  parseJsonBody,
  sanitize,
  validateEmail,
  validateUsername,
  validatePassword,
} from '../_validation.js';
import { hashPassword, verifyCaptchaTokenV2 } from '../_utils.js';
import { enforceIpRateLimit, enforceKeyRateLimit } from '../_rateLimit.js';
import { writeAudit } from '../_audit.js';
import { getClientIP } from '../_security.js';

export async function onRequestPost(context) {
  const { request, env } = context;
  const requestId = context.data && context.data.requestId ? context.data.requestId : '';

  const limited = await enforceIpRateLimit(env, request, 'register-ip', 10, 3600);
  if (limited) return limited;

  const parsed = await parseJsonBody(request, 4096);
  if (!parsed.ok) return errorResponse(parsed.message, parsed.status, 'bad_request', requestId);
  const body = parsed.data || {};

  const username = sanitize(body.username, 32);
  const email = sanitize(body.email, 200).toLowerCase();
  const password = typeof body.password === 'string' ? body.password : '';
  const captchaToken = typeof body.captchaToken === 'string' ? body.captchaToken : '';

  if (!captchaToken) return errorResponse('请先完成人机验证', 400, 'captcha_missing', requestId);
  const captchaIp = getClientIP(request);
  const captcha = await verifyCaptchaTokenV2(env, captchaToken, captchaIp, 'register');
  if (!captcha.valid) return errorResponse('人机验证无效或已过期，请重新验证', 400, 'captcha_invalid', requestId);

  if (!validateUsername(username)) {
    return errorResponse('账号需 6-20 位，仅限字母、数字、下划线', 400, 'invalid_username', requestId);
  }
  if (!validateEmail(email)) {
    return errorResponse('请输入有效的邮箱地址', 400, 'invalid_email', requestId);
  }
  const pwd = validatePassword(password, username);
  if (!pwd.valid) return errorResponse(pwd.message, 400, 'weak_password', requestId);

  const emailLimited = await enforceKeyRateLimit(env, 'register-email', `email:${email}`, 3, 3600);
  if (emailLimited) return emailLimited;

  const existing = await env.apex_db.prepare(
    'SELECT id FROM users WHERE username = ? OR email = ? LIMIT 1'
  ).bind(username, email).first();
  if (existing) {
    return errorResponse('账号或邮箱已被注册', 409, 'already_exists', requestId);
  }

  const hash = await hashPassword(password);
  const result = await env.apex_db.prepare(
    'INSERT INTO users (username, email, password_hash, password_changed_at, status, email_verified) VALUES (?, ?, ?, CURRENT_TIMESTAMP, ?, 0)'
  ).bind(username, email, hash, 'active').run();

  const userId = result && result.meta ? result.meta.last_row_id : null;
  await writeAudit(env, { action: 'register_success', actorId: userId, actorType: 'user', metadata: { username } }, request);

  return jsonResponse({
    success: true,
    message: '注册成功',
    userId,
  }, 200, requestId);
}

export async function onRequestOptions(context) {
  const requestId = context.data && context.data.requestId ? context.data.requestId : '';
  return optionsResponse(requestId);
}
