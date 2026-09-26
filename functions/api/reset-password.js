import { jsonResponse, errorResponse, optionsResponse } from '../_response.js';
import { parseJsonBody, sanitize, validateEmail, validatePassword } from '../_validation.js';
import { hashPassword, verifyCaptchaTokenV2 } from '../_utils.js';
import { sha256Hex, getClientIP } from '../_security.js';
import { enforceIpRateLimit, enforceKeyRateLimit } from '../_rateLimit.js';
import { writeAudit } from '../_audit.js';

const MAX_ATTEMPTS_PER_ROW = 5;
const MAX_IP_FAILURES = 20;
const MAX_EMAIL_FAILURES = 5;
const FAILURE_WINDOW_SEC = 600;

export async function onRequestPost(context) {
  const { request, env } = context;
  const requestId = context.data && context.data.requestId ? context.data.requestId : '';

  const ipLimited = await enforceIpRateLimit(env, request, 'reset-submit-ip', 20, FAILURE_WINDOW_SEC);
  if (ipLimited) return ipLimited;

  const parsed = await parseJsonBody(request, 4096);
  if (!parsed.ok) return errorResponse(parsed.message, parsed.status, 'bad_request', requestId);

  const captchaToken = typeof parsed.data.captchaToken === 'string' ? parsed.data.captchaToken : '';
  if (!captchaToken) {
    return errorResponse('请先完成人机验证', 400, 'captcha_missing', requestId);
  }
  const captchaIp = getClientIP(request);
  const captcha = await verifyCaptchaTokenV2(env, captchaToken, captchaIp, 'reset-password');
  if (!captcha.valid) {
    await writeAudit(env, { action: 'reset_captcha_invalid', targetType: 'email' }, request);
    return errorResponse('人机验证无效或已过期，请重新验证', 400, 'captcha_invalid', requestId);
  }

  const email = sanitize(parsed.data.email, 200).toLowerCase();
  const code = sanitize(parsed.data.code, 16);
  const newPassword = typeof parsed.data.newPassword === 'string' ? parsed.data.newPassword : '';

  if (!validateEmail(email)) return errorResponse('请输入有效的邮箱地址', 400, 'invalid_email', requestId);
  if (!/^\d{6}$/.test(code)) return errorResponse('验证码格式错误', 400, 'invalid_code', requestId);
  const pwd = validatePassword(newPassword, email);
  if (!pwd.valid) return errorResponse(pwd.message, 400, 'weak_password', requestId);

  const emailLimited = await enforceKeyRateLimit(env, 'reset-submit-email', `email:${email}`, MAX_EMAIL_FAILURES, FAILURE_WINDOW_SEC);
  if (emailLimited) return emailLimited;

  const codeHash = await sha256Hex(`apex_reset_v1_${email}_${code}`);

  const row = await env.apex_db.prepare(
    `SELECT id, user_id, expires_at, used_at, attempts
     FROM password_resets
     WHERE email = ? AND code_hash = ?
     ORDER BY id DESC LIMIT 1`
  ).bind(email, codeHash).first();

  if (!row) {
    await writeAudit(env, { action: 'reset_code_invalid', targetType: 'email' }, request);
    return errorResponse('验证码错误', 400, 'invalid_code', requestId);
  }
  if (row.used_at) {
    return errorResponse('验证码已被使用', 400, 'code_used', requestId);
  }
  if (new Date(row.expires_at) < new Date()) {
    return errorResponse('验证码已过期', 400, 'code_expired', requestId);
  }
  if (Number(row.attempts || 0) >= MAX_ATTEMPTS_PER_ROW) {
    return errorResponse('尝试次数过多，请重新发送验证码', 429, 'too_many_attempts', requestId);
  }

  await env.apex_db.prepare(
    'UPDATE password_resets SET attempts = attempts + 1 WHERE id = ?'
  ).bind(row.id).run();

  const user = await env.apex_db.prepare(
    'SELECT id FROM users WHERE email = ? LIMIT 1'
  ).bind(email).first();
  if (!user) {
    return errorResponse('账号不存在', 404, 'not_found', requestId);
  }

  const newHash = await hashPassword(newPassword);

  // 3 条 UPDATE 必须原子提交：要么全部成功，要么全部回滚，
  // 避免出现「密码已更新但旧 session 未撤销」或「验证码已标记已用但密码未更新」的中间态。
  await env.apex_db.batch([
    env.apex_db.prepare(
      'UPDATE users SET password_hash = ?, password_changed_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = ?'
    ).bind(newHash, user.id),
    env.apex_db.prepare(
      'UPDATE password_resets SET used_at = CURRENT_TIMESTAMP WHERE id = ?'
    ).bind(row.id),
    env.apex_db.prepare(
      'UPDATE sessions SET revoked_at = CURRENT_TIMESTAMP WHERE user_id = ? AND revoked_at IS NULL'
    ).bind(user.id),
  ]);

  await writeAudit(env, { action: 'reset_password_success', actorId: user.id, actorType: 'user' }, request);

  return jsonResponse({ success: true, message: '密码重置成功，请使用新密码登录' }, 200, requestId);
}

export async function onRequestOptions(context) {
  const requestId = context.data && context.data.requestId ? context.data.requestId : '';
  return optionsResponse(requestId);
}
