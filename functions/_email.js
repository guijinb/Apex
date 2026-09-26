// 通用邮件发送（AgentMail）
export async function sendEmail(env, to, subject, text, html) {
  const apiKey = env.AGENTMAIL_API_KEY;
  const inboxId = env.AGENTMAIL_INBOX_ID;
  if (!apiKey || !inboxId) return { sent: false, reason: 'no_config' };

  const res = await fetch(
    `https://api.agentmail.to/v0/inboxes/${encodeURIComponent(inboxId)}/messages/send`,
    {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ to, subject, text, html })
    }
  );

  if (res.ok) return { sent: true };
  return { sent: false, reason: 'api_error', status: res.status };
}

// 通用邮件模板
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
