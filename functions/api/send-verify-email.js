import { jsonResponse, errorResponse, optionsResponse } from '../_response.js';
import { parseJsonBody, sanitize, validateEmail } from '../_validation.js';
import { generateToken } from '../_utils.js';
import { hashEmailVerifyToken } from '../_emailVerify.js';
import { enforceIpRateLimit, enforceKeyRateLimit } from '../_rateLimit.js';
import { sendEmail, emailTemplate } from '../_email.js';
import { getConfig } from '../_config.js';
import { writeAudit } from '../_audit.js';

export async function onRequestPost(context) {
  const { request, env } = context;
  const requestId = context.data && context.data.requestId ? context.data.requestId : '';
  const config = getConfig(env);

  // IP 维度限流
  const limited = await enforceIpRateLimit(env, request, 'send-verify-ip', 10, 60);
  if (limited) return limited;

  const parsed = await parseJsonBody(request, 2048);
  if (!parsed.ok) return errorResponse(parsed.message, parsed.status, 'bad_request', requestId);

  const email = sanitize(parsed.data.email, 200).toLowerCase();
  if (!validateEmail(email)) {
    return errorResponse('请输入有效的邮箱地址', 400, 'invalid_email', requestId);
  }

  // 邮箱维度限流
  const emailLimited = await enforceKeyRateLimit(env, 'send-verify-email', `email:${email}`, 3, 600);
  if (emailLimited) return emailLimited;

  // 无论邮箱是否存在，都返回相同响应（防枚举）
  const genericOk = jsonResponse({ success: true, message: '若邮箱已注册，验证邮件已发送' }, 200, requestId);

  const user = await env.apex_db.prepare(
    'SELECT id, username, email_verified FROM users WHERE email = ? LIMIT 1'
  ).bind(email).first();
  if (!user) return genericOk;
  if (user.email_verified) {
    return jsonResponse({ success: true, message: '邮箱已验证' }, 200, requestId);
  }

  // 生成 token，只存 hash
  const token = generateToken();
  const tokenHash = await hashEmailVerifyToken(token);
  const expiresAt = new Date(Date.now() + config.emailVerifyTtlMs).toISOString();

  // 重发时旧 token 立即失效
  await env.apex_db.prepare(
    'DELETE FROM email_verifications WHERE user_id = ?'
  ).bind(user.id).run();
  await env.apex_db.prepare(
    'INSERT INTO email_verifications (user_id, token_hash, expires_at) VALUES (?, ?, ?)'
  ).bind(user.id, tokenHash, expiresAt).run();

  const verifyUrl = `${config.publicBaseUrl}/api/verify-email?token=${encodeURIComponent(token)}`;
  const html = emailTemplate(
    '请验证您的邮箱',
    `<a href="${verifyUrl}" style="display:inline-block;padding:12px 24px;background:#d4af37;color:#000;text-decoration:none;border-radius:8px;font-weight:bold;">点击验证邮箱</a><br><br>或者复制链接到浏览器：<br><span style="color:#4ade80;font-size:12px;word-break:break-all;">${verifyUrl}</span><br><br>此链接 24 小时内有效。`
  );

  const emailRes = await sendEmail(
    env,
    email,
    '【Apex】请验证您的邮箱',
    `请访问以下链接验证邮箱：${verifyUrl}`,
    html
  );

  await writeAudit(env, {
    action: 'verify_email_sent',
    targetType: 'email',
    metadata: { sent: emailRes.sent },
  }, request);

  if (!emailRes.sent) {
    // 生产环境绝不返回 token
    if (config.isDevelopment) {
      return jsonResponse({ success: true, message: '邮件发送失败（开发模式）', devToken: token }, 200, requestId);
    }
    return errorResponse('验证邮件发送失败，请稍后重试', 500, 'email_failed', requestId);
  }

  return genericOk;
}

export async function onRequestOptions(context) {
  const requestId = context.data && context.data.requestId ? context.data.requestId : '';
  return optionsResponse(requestId);
}
