import { hashEmailVerifyToken } from '../_emailVerify.js';
import { enforceIpRateLimit } from '../_rateLimit.js';

function htmlPage(title, heading, message, color) {
  return `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title}</title><style>body{background:#050505;color:#fff;font-family:system-ui,-apple-system,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;text-align:center;padding:20px;box-sizing:border-box;}h1{color:${color};margin:0 0 12px 0;}p{color:#888;margin:0 0 20px 0;}a{color:#d4af37;text-decoration:none;display:inline-block;padding:12px 24px;border:1px solid #d4af37;border-radius:8px;}</style></head><body><div><h1>${heading}</h1><p>${message}</p><a href="/">返回首页</a></div></body></html>`;
}

function renderSuccess() {
  return htmlPage('验证成功', '✅ 邮箱验证成功', '您的邮箱已激活，现在可以正常使用所有功能。', '#4ade80');
}

function renderError(message) {
  return htmlPage('验证失败', '验证失败', message, '#e63946');
}

function htmlResponse(body, status) {
  return new Response(body, {
    status,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
    },
  });
}

export async function onRequestGet(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const token = url.searchParams.get('token') || '';

  const limited = await enforceIpRateLimit(env, request, 'verify-email-ip', 30, 60);
  if (limited) return htmlResponse(renderError('请求过于频繁，请稍后再试'), 429);

  if (!token) return htmlResponse(renderError('缺少验证参数'), 400);

  const tokenHash = await hashEmailVerifyToken(token);
  const record = await env.apex_db.prepare(
    'SELECT id, user_id, expires_at, used_at FROM email_verifications WHERE token_hash = ? LIMIT 1'
  ).bind(tokenHash).first();

  if (!record) return htmlResponse(renderError('验证链接无效'), 400);
  if (record.used_at) return htmlResponse(renderError('该链接已被使用'), 400);
  if (new Date(record.expires_at) < new Date()) return htmlResponse(renderError('验证链接已过期'), 400);

  // 原子更新：user 标记 + verification 标记 used
  try {
    await env.apex_db.batch([
      env.apex_db.prepare(
        'UPDATE users SET email_verified = 1, email_verified_at = CURRENT_TIMESTAMP WHERE id = ?'
      ).bind(record.user_id),
      env.apex_db.prepare(
        'UPDATE email_verifications SET used_at = CURRENT_TIMESTAMP WHERE id = ?'
      ).bind(record.id),
    ]);
  } catch (err) {
    console.error('[verify-email] batch failed:', err && err.message ? err.message : err);
    return htmlResponse(renderError('服务器内部错误，请稍后重试'), 500);
  }

  return htmlResponse(renderSuccess(), 200);
}
