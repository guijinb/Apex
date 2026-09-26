import { jsonResponse, errorResponse, optionsResponse } from '../_response.js';
import { parseJsonBody, sanitize, validateEmail } from '../_validation.js';
import { generateNumericCode, hashIP } from '../_security.js';
import { sha256Hex } from '../_security.js';
import { enforceIpRateLimit, enforceKeyRateLimit } from '../_rateLimit.js';
import { sendEmail, emailTemplate } from '../_email.js';
import { getConfig } from '../_config.js';
import { writeAudit } from '../_audit.js';

export async function onRequestPost(context) {
  const { request, env } = context;
  const requestId = context.data && context.data.requestId ? context.data.requestId : '';
  const config = getConfig(env);

  const limited = await enforceIpRateLimit(env, request, 'send-reset-ip', 10, 60);
  if (limited) return limited;

  const parsed = await parseJsonBody(request, 2048);
  if (!parsed.ok) return errorResponse(parsed.message, parsed.status, 'bad_request', requestId);

  const email = sanitize(parsed.data.email, 200).toLowerCase();
  if (!validateEmail(email)) return errorResponse('请输入有效的邮箱地址', 400, 'invalid_email', requestId);

  const emailLimited = await enforceKeyRateLimit(env, 'send-reset-email', `email:${email}`, 3, 600);
  if (emailLimited) return emailLimited;

  // 统一响应，避免枚举
  const genericOk = jsonResponse({ success: true, message: '若邮箱已注册，验证码已发送' }, 200, requestId);

  const user = await env.apex_db.prepare(
    'SELECT id FROM users WHERE email = ? LIMIT 1'
  ).bind(email).first();
  if (!user) return genericOk;

  const code = generateNumericCode(6);
  const codeHash = await sha256Hex(`apex_reset_v1_${email}_${code}`);
  const expiresAt = new Date(Date.now() + config.resetCodeTtlMs).toISOString();

  // 使该邮箱旧的未使用验证码失效
  await env.apex_db.prepare(
    'UPDATE password_resets SET used_at = CURRENT_TIMESTAMP WHERE email = ? AND used_at IS NULL'
  ).bind(email).run();

  await env.apex_db.prepare(
    'INSERT INTO password_resets (user_id, email, code_hash, expires_at, attempts) VALUES (?, ?, ?, ?, 0)'
  ).bind(user.id, email, codeHash, expiresAt).run();

  const idempotencyKey = `reset-password/${email}/${code}`;

  const emailRes = await sendEmail(
    env,
    email,
    '【Apex】密码重置验证码',
    `您的密码重置验证码是：${code}\n\n验证码 10 分钟内有效，请勿泄露给他人。\n\n如果这不是您的操作，请忽略此邮件。`,
    emailTemplate(
      '您的密码重置验证码是：',
      '验证码 10 分钟内有效，请勿泄露给他人。<br>如果这不是您的操作，请忽略此邮件。',
      code
    ),
    idempotencyKey
  );

  await writeAudit(env, { action: 'reset_code_sent', targetType: 'email', metadata: { sent: emailRes.sent } }, request);

  if (!emailRes.sent) {
    // 生产环境绝不返回 code；development 允许显式辅助
    if (config.isDevelopment) {
      return jsonResponse({ success: true, message: '邮件发送失败（开发模式）', devCode: code }, 200, requestId);
    }
    return errorResponse('验证码发送失败，请稍后重试', 500, 'email_failed', requestId);
  }

  return genericOk;
}

export async function onRequestOptions(context) {
  const requestId = context.data && context.data.requestId ? context.data.requestId : '';
  return optionsResponse(requestId);
}
