// Apex 邮件发送器
// - 主备 fallback：由 EMAIL_PROVIDER 控制顺序，默认 resend,agentmail
// - 每个 provider 有独立超时
// - Resend 支持 Idempotency-Key
// - AgentMail 使用 inbox_id 端点
// - 生产环境不返回敏感细节

import { getConfig } from './_config.js';

const PER_PROVIDER_TIMEOUT_MS = 8000;

async function fetchWithTimeout(url, options = {}, timeoutMs = PER_PROVIDER_TIMEOUT_MS) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timeout);
  }
}

async function sendViaResend(env, { to, subject, text, html, idempotencyKey }) {
  const config = getConfig(env);
  const apiKey = env.RESEND_API_KEY;
  if (!apiKey) return { ok: false, provider: 'resend', reason: 'no_api_key' };

  const headers = {
    Authorization: `Bearer ${apiKey}`,
    'Content-Type': 'application/json',
  };
  if (idempotencyKey) headers['Idempotency-Key'] = idempotencyKey;

  const payload = {
    from: config.emailFrom,
    to: [to],
    subject,
    text,
    html,
  };
  if (config.emailReplyTo) payload.reply_to = config.emailReplyTo;

  try {
    const res = await fetchWithTimeout('https://api.resend.com/emails', {
      method: 'POST',
      headers,
      body: JSON.stringify(payload),
    });
    let data = {};
    try { data = await res.json(); } catch {}

    if (res.ok) return { ok: true, provider: 'resend', messageId: data.id };

    if (res.status >= 400 && res.status < 500) {
      return { ok: false, provider: 'resend', reason: 'permanent_error', status: res.status };
    }
    return { ok: false, provider: 'resend', reason: 'server_error', status: res.status };
  } catch (error) {
    return {
      ok: false,
      provider: 'resend',
      reason: error.name === 'AbortError' ? 'timeout' : 'network_error',
    };
  }
}

async function sendViaAgentMail(env, { to, subject, text, html }) {
  const config = getConfig(env);
  const apiKey = env.AGENTMAIL_API_KEY;
  const inboxId = config.agentmailInboxId;
  if (!apiKey || !inboxId) return { ok: false, provider: 'agentmail', reason: 'no_config' };

  const url = `https://api.agentmail.to/v0/inboxes/${encodeURIComponent(inboxId)}/messages/send`;

  try {
    const res = await fetchWithTimeout(url, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ to, subject, text, html }),
    });
    let data = {};
    try { data = await res.json(); } catch {}

    if (res.ok) {
      return { ok: true, provider: 'agentmail', messageId: data.id || data.message_id };
    }
    if (res.status >= 400 && res.status < 500) {
      return { ok: false, provider: 'agentmail', reason: 'permanent_error', status: res.status };
    }
    return { ok: false, provider: 'agentmail', reason: 'server_error', status: res.status };
  } catch (error) {
    return {
      ok: false,
      provider: 'agentmail',
      reason: error.name === 'AbortError' ? 'timeout' : 'network_error',
    };
  }
}

function isRecoverable(reason) {
  return reason === 'timeout' || reason === 'network_error' || reason === 'server_error';
}

export async function sendEmail(env, to, subject, text, html, idempotencyKey) {
  const config = getConfig(env);
  const providers = config.emailProviders;
  const attemptsLog = [];
  let lastError = '';

  for (let i = 0; i < providers.length; i += 1) {
    const provider = providers[i];
    const isPrimary = i === 0;
    const maxAttempts = isPrimary ? 2 : 1;

    for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
      const result = provider === 'resend'
        ? await sendViaResend(env, { to, subject, text, html, idempotencyKey })
        : await sendViaAgentMail(env, { to, subject, text, html });

      attemptsLog.push({ provider, attempt, ok: result.ok, reason: result.reason || null });

      if (result.ok) {
        console.log(JSON.stringify({
          tag: 'email_sent',
          provider,
          attempt,
          to,
        }));
        return { sent: true, provider, messageId: result.messageId, attempts: attemptsLog };
      }

      lastError = `${provider}:${result.reason}`;

      if (!isRecoverable(result.reason)) {
        // permanent_error / no_api_key / no_config 直接切换下一个 provider
        break;
      }

      if (attempt < maxAttempts) {
        await new Promise((r) => setTimeout(r, Math.pow(2, attempt - 1) * 1000));
      }
    }
  }

  console.error(JSON.stringify({
    tag: 'email_all_failed',
    lastError,
    attempts: attemptsLog,
    to,
  }));
  return { sent: false, reason: 'all_providers_failed', error: lastError, attempts: attemptsLog };
}

export function emailTemplate(title, content, code) {
  const safeTitle = String(title || '');
  const safeContent = String(content || '');
  const safeCode = code ? String(code) : '';
  return '<div style="font-family:-apple-system,sans-serif;max-width:600px;margin:0 auto;padding:24px;background:#0a0a0a;color:#fff;border-radius:12px;">'
    + '<h2 style="color:#d4af37;margin:0 0 16px 0;letter-spacing:1px;">Apex Entertainment</h2>'
    + '<p style="color:#ccc;margin:0 0 12px 0;">' + safeTitle + '</p>'
    + (safeCode
        ? '<div style="font-size:36px;font-weight:bold;letter-spacing:10px;color:#4ade80;padding:24px;background:#1a1a1a;border-radius:10px;text-align:center;margin:20px 0;font-family:Courier New,monospace;">' + safeCode + '</div>'
        : '')
    + '<p style="color:#888;font-size:13px;margin:12px 0;">' + safeContent + '</p>'
    + '<hr style="border:none;border-top:1px solid #222;margin:20px 0;">'
    + '<p style="color:#555;font-size:11px;text-align:center;margin:0;">© 2026 Apex Global Entertainment</p>'
    + '</div>';
}
