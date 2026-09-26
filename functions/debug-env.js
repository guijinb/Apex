// 临时诊断端点：显示运行时实际可见的环境变量
// 路径: /debug-env （非 /api 前缀，绕过 middleware 的 config 检查）
// ⚠️ 部署后必须删除
export async function onRequestGet(context) {
  const { env, request } = context;

  const check = {
    ENVIRONMENT: env.ENVIRONMENT || null,
    CAPTCHA_SECRET: Boolean(env.CAPTCHA_SECRET),
    CAPTCHA_SALT: Boolean(env.CAPTCHA_SALT),
    PUBLIC_BASE_URL: env.PUBLIC_BASE_URL || null,
    EMAIL_FROM: env.EMAIL_FROM ? '<set, len=' + String(env.EMAIL_FROM).length + '>' : null,
    EMAIL_REPLY_TO: Boolean(env.EMAIL_REPLY_TO),
    EMAIL_PROVIDER: env.EMAIL_PROVIDER || null,
    RESEND_API_KEY: Boolean(env.RESEND_API_KEY),
    AGENTMAIL_API_KEY: Boolean(env.AGENTMAIL_API_KEY),
    AGENTMAIL_INBOX_ID: Boolean(env.AGENTMAIL_INBOX_ID),
    AUDIT_SALT: Boolean(env.AUDIT_SALT),
    RATE_LIMIT_SALT: Boolean(env.RATE_LIMIT_SALT),
    SESSION_SALT: Boolean(env.SESSION_SALT),
    apex_db: Boolean(env.apex_db),
  };

  // 列出所有 env 的 key（只列名，不列值）
  const allKeys = Object.keys(env || {}).sort();

  // 手动复现 assertProductionConfig 的逻辑，看看到底缺什么
  const isProduction = (env.ENVIRONMENT || 'production') === 'production';
  const missing = [];
  if (isProduction) {
    if (!env.CAPTCHA_SECRET) missing.push('CAPTCHA_SECRET');
    if (!env.PUBLIC_BASE_URL) missing.push('PUBLIC_BASE_URL');
    if (!env.EMAIL_FROM) missing.push('EMAIL_FROM');
    const hasResend = Boolean(env.RESEND_API_KEY);
    const hasAgentmail = Boolean(env.AGENTMAIL_API_KEY && env.AGENTMAIL_INBOX_ID);
    if (!hasResend && !hasAgentmail) missing.push('RESEND_API_KEY_or_AGENTMAIL_API_KEY');
  }

  return new Response(JSON.stringify({
    check,
    allKeys,
    config_assert: {
      isProduction,
      missing,
      ok: missing.length === 0,
    },
  }, null, 2), {
    status: 200,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
    },
  });
}
