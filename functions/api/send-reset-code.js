import { generateCode, sanitize, jsonResponse, validateEmail, checkRateLimit } from '../_utils.js';

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

    // 调用 AgentMail API 发送邮件
    const apiKey = env.AGENTMAIL_API_KEY;
    const inboxId = env.AGENTMAIL_INBOX_ID;
    let emailSent = false;

    if (apiKey && inboxId) {
      const emailRes = await fetch(
        `https://api.agentmail.to/v0/inboxes/${encodeURIComponent(inboxId)}/messages/send`,
        {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${apiKey}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            to: email,
            subject: '【Apex】密码重置验证码',
            text: `您的密码重置验证码是：${code}\n\n验证码 10 分钟内有效，请勿泄露给他人。\n\n如果这不是您的操作，请忽略此邮件。\n\n—— Apex Entertainment`,
            html: `<div style="font-family:-apple-system,sans-serif;max-width:600px;margin:0 auto;padding:24px;background:#0a0a0a;color:#fff;border-radius:12px;">
              <h2 style="color:#d4af37;margin:0 0 16px 0;letter-spacing:1px;">Apex Entertainment</h2>
              <p style="color:#ccc;margin:0 0 12px 0;">您的密码重置验证码是：</p>
              <div style="font-size:36px;font-weight:bold;letter-spacing:10px;color:#4ade80;padding:24px;background:#1a1a1a;border-radius:10px;text-align:center;margin:20px 0;font-family:'Courier New',monospace;">${code}</div>
              <p style="color:#888;font-size:13px;margin:12px 0;">验证码 10 分钟内有效，请勿泄露给他人。</p>
              <p style="color:#888;font-size:13px;margin:12px 0;">如果这不是您的操作，请忽略此邮件。</p>
              <hr style="border:none;border-top:1px solid #222;margin:20px 0;">
              <p style="color:#555;font-size:11px;text-align:center;margin:0;">© 2026 Apex Global Entertainment</p>
            </div>`
          })
        }
      );

      if (emailRes.ok) {
        emailSent = true;
        console.log('[AgentMail] 邮件已发送至：', email);
      } else {
        const errText = await emailRes.text();
        console.log('[AgentMail] 发送失败：', emailRes.status, errText);
      }
    } else {
      console.log('[AgentMail] 未配置环境变量，跳过真实发送');
    }

    if (emailSent) {
      return jsonResponse({ success: true, message: '验证码已发送到您的邮箱' });
    } else {
      // 环境变量未配置时返回 devCode 便于测试
      return jsonResponse({ success: true, message: '验证码已发送', devCode: code });
    }
  } catch (err) {
    return jsonResponse({ success: false, message: '服务器错误：' + err.message }, 500);
  }
}

export async function onRequestOptions() { return jsonResponse({}, 204); }
