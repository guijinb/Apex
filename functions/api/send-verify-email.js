import { jsonResponse, checkRateLimit, generateToken } from '../_utils.js';
import { sendEmail, emailTemplate } from '../_email.js';
import { hashSessionToken } from '../_session.js';

export async function onRequestPost(context) {
  try {
    const { request, env } = context;
    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';

    const rate = await checkRateLimit(env, ip, 'verify-email', 3, 60);
    if (!rate.allowed) return jsonResponse({ success: false, message: '请求过于频繁' }, 429);

    const body = await request.json();
    const email = String(body.email || '').trim();
    if (!email) return jsonResponse({ success: false, message: '缺少邮箱' }, 400);

    const user = await env.apex_db.prepare(
      'SELECT id, username FROM users WHERE email = ?'
    ).bind(email).first();
    if (!user) return jsonResponse({ success: true, message: '若邮箱已注册，验证邮件已发送' });
    if (user.email_verified) return jsonResponse({ success: true, message: '邮箱已验证' });

    // 生成 token，存 hash
    const token = generateToken();
    const tokenHash = await hashSessionToken(token);
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

    // 清理旧 token
    await env.apex_db.prepare('DELETE FROM email_verifications WHERE user_id = ?').bind(user.id).run();
    await env.apex_db.prepare(
      'INSERT INTO email_verifications (user_id, token_hash, expires_at) VALUES (?, ?, ?)'
    ).bind(user.id, tokenHash, expiresAt).run();

    // 发送邮件
    const verifyUrl = `https://apex-8rg.pages.dev/api/verify-email?token=${token}`;
    const html = emailTemplate(
      '请验证您的邮箱',
      `<a href="${verifyUrl}" style="display:inline-block;padding:12px 24px;background:#d4af37;color:#000;text-decoration:none;border-radius:8px;font-weight:bold;">点击验证邮箱</a><br><br>或者复制链接到浏览器：<br><span style="color:#4ade80;font-size:12px;word-break:break-all;">${verifyUrl}</span><br><br>此链接 24 小时内有效。`
    );
    const emailRes = await sendEmail(env, email, '【Apex】请验证您的邮箱', `请访问以下链接验证邮箱：${verifyUrl}`, html);

    if (emailRes.sent) {
      return jsonResponse({ success: true, message: '验证邮件已发送' });
    }
    return jsonResponse({ success: true, message: '验证邮件已发送', devToken: token });
  } catch (err) {
    return jsonResponse({ success: false, message: '服务器错误：' + err.message }, 500);
  }
}
export async function onRequestOptions() { return jsonResponse({}, 204); }
