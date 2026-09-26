// 临时诊断端点：显示运行时实际可见的环境变量
// ⚠️ 部署后必须删除
export async function onRequestGet(context) {
  const { env } = context;

  // 只显示"是否存在"，不显示值
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

  return new Response(JSON.stringify({
    check,
    allKeys,
  }, null, 2), {
    status: 200,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
    },
  });
}
