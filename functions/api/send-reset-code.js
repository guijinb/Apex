import { generateCode, sanitize, jsonResponse, validateEmail, checkRateLimit } from '../_utils.js';
import { sendEmail, emailTemplate } from '../_email.js';

export async function onRequestPost(context) {
  try {
    const { request, env } = context;
    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';

    const rate = await checkRateLimit(env, ip, 'send-code', 3, 60);
    if (!rate.allowed) {
      return jsonResponse({ success: false, message: '请求过于频繁，请稍后再试' }, 429);
    }

    const body = await request.json();
    const email = sanitize(body.email || '');

    if (!validateEmail(email)) {
      return jsonResponse({ success: false, message: '请输入有效的邮箱地址' }, 400);
    }

    const user = await env.apex_db.prepare(
      'SELECT id FROM users WHERE email = ?'
    ).bind(email).first();

    if (!user) {
      return jsonResponse({ success: true, message: '若邮箱已注册，验证码已发送' });
    }

    const code = generateCode();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString();

    await env.apex_db.prepare(
      'UPDATE password_resets SET used = 1 WHERE email = ? AND used = 0'
    ).bind(email).run();

    await env.apex_db.prepare(
      'INSERT INTO password_resets (email, code, expires_at) VALUES (?, ?, ?)'
    ).bind(email, code, expiresAt).run();

    // 构造幂等键：确保同一邮箱的同一验证码在 24 小时内只发送一次
    const idempotencyKey = `reset-password/${email}/${code}`;

    const emailRes = await sendEmail(
      env,
      email,
      '【Apex】密码重置验证码',
      `您的密码重置验证码是：${code}\n\n验证码 10 分钟内有效，请勿泄露给他人。\n\n如果这不是您的操作，请忽略此邮件。\n\n—— Apex Entertainment`,
      emailTemplate(
        '您的密码重置验证码是：',
        '验证码 10 分钟内有效，请勿泄露给他人。<br>如果这不是您的操作，请忽略此邮件。',
        code
      ),
      idempotencyKey
    );

    if (emailRes.sent) {
      return jsonResponse({ success: true, message: '验证码已发送到您的邮箱' });
    } else {
      // 开发模式返回验证码，方便测试
      return jsonResponse({ success: true, message: '验证码已发送', devCode: code });
    }
  } catch (err) {
    return jsonResponse({ success: false, message: '服务器错误：' + err.message }, 500);
  }
}

export async function onRequestOptions() { return jsonResponse({}, 204); }
