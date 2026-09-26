// 通用邮件发送工具 - 带自动重试
export async function sendEmail(env, to, subject, text, html, idempotencyKey) {
  const apiKey = env.RESEND_API_KEY;
  if (!apiKey) {
    console.error('[Email] 缺少 RESEND_API_KEY');
    return { sent: false, reason: 'no_api_key' };
  }

  const maxRetries = 3;
  let lastError = '';

  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      const headers = {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json'
      };

      // 添加 Idempotency-Key 以保证重试安全
      if (idempotencyKey) {
        headers['Idempotency-Key'] = idempotencyKey;
      }

      const res = await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers,
        body: JSON.stringify({
          from: 'Apex Entertainment <onboarding@resend.dev>',
          to: [to],
          subject,
          text,
          html
        })
      });

      const data = await res.json();

      if (res.ok) {
        console.log(`[Email] 发送成功 (尝试 ${attempt}/${maxRetries}) -> ${to}`);
        return { sent: true, messageId: data.id };
      }

      // 4xx 错误通常是请求问题，重试无意义
      if (res.status >= 400 && res.status < 500) {
        console.error(`[Email] 永久失败 (${res.status}):`, data);
        return { sent: false, reason: 'permanent_error', status: res.status, error: data };
      }

      // 5xx 错误可以重试
      lastError = `HTTP ${res.status}: ${JSON.stringify(data)}`;
      console.warn(`[Email] 临时失败 (尝试 ${attempt}/${maxRetries}):`, lastError);

    } catch (err) {
      lastError = err.message;
      console.warn(`[Email] 网络错误 (尝试 ${attempt}/${maxRetries}):`, lastError);
    }

    // 指数退避：等待 1s, 2s, 4s
    if (attempt < maxRetries) {
      const delay = Math.pow(2, attempt - 1) * 1000;
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }

  console.error(`[Email] 重试 ${maxRetries} 次后仍失败:`, lastError);
  return { sent: false, reason: 'max_retries_exceeded', error: lastError };
}

// 邮件 HTML 模板
export function emailTemplate(title, content, code) {
  return `<div style="font-family:-apple-system,sans-serif;max-width:600px;margin:0 auto;padding:24px;background:#0a0a0a;color:#fff;border-radius:12px;">
    <h2 style="color:#d4af37;margin:0 0 16px 0;letter-spacing:1px;">Apex Entertainment</h2>
    <p style="color:#ccc;margin:0 0 12px 0;">${title}</p>
    ${code ? `<div style="font-size:36px;font-weight:bold;letter-spacing:10px;color:#4ade80;padding:24px;background:#1a1a1a;border-radius:10px;text-align:center;margin:20px 0;font-family:'Courier New',monospace;">${code}</div>` : ''}
    <p style="color:#888;font-size:13px;margin:12px 0;">${content}</p>
    <hr style="border:none;border-top:1px solid #222;margin:20px 0;">
    <p style="color:#555;font-size:11px;text-align:center;margin:0;">© 2026 Apex Global Entertainment</p>
  </div>`;
}
