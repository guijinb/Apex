export function getConfig(env = {}) {
  const environment = env.ENVIRONMENT || 'production';
  const isProduction = environment === 'production';
  const isDevelopment = environment === 'development';

  // 生产环境必须由 assertProductionConfig 强制要求 PUBLIC_BASE_URL；
  // 缺失时返回空字符串，由调用方负责判断，不再 fallback 到任何硬编码域名。
  const publicBaseUrl = String(env.PUBLIC_BASE_URL || '').replace(/\/+$/, '');

  const allowedOrigins = String(env.ALLOWED_ORIGINS || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);

  // EMAIL_PROVIDER 控制顺序，默认 resend 主 agentmail 备
  const emailProviders = String(env.EMAIL_PROVIDER || 'resend,agentmail')
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter((s) => s === 'resend' || s === 'agentmail');

  if (emailProviders.length === 0) emailProviders.push('resend');

  return {
    environment,
    isProduction,
    isDevelopment,
    publicBaseUrl,
    allowedOrigins,

    // Cookie 名称
    sessionCookie: '__Host-apex_session',
    legacySessionCookie: 'apex_session',
    adminCookie: '__Host-apex_admin_session',
    legacyAdminCookie: 'apex_admin_session',
    csrfCookie: 'apex_csrf',

    // Session TTL
    sessionMaxAge: 7 * 24 * 60 * 60,
    adminSessionMaxAge: 8 * 60 * 60,

    // Token TTL
    resetCodeTtlMs: 10 * 60 * 1000,
    emailVerifyTtlMs: 24 * 60 * 60 * 1000,
    captchaTokenTtlMs: 5 * 60 * 1000,
    captchaChallengeTtlMs: 2 * 60 * 1000,

    // 邮件
    emailProviders,
    emailFrom: env.EMAIL_FROM || 'Apex Entertainment <onboarding@resend.dev>',
    emailReplyTo: env.EMAIL_REPLY_TO || '',
    agentmailInboxId: env.AGENTMAIL_INBOX_ID || '',

    requireVerifiedEmailFrom: isProduction,
  };
}

export function assertProductionConfig(env = {}) {
  const config = getConfig(env);
  const missing = [];
  if (config.isProduction) {
    if (!env.CAPTCHA_SECRET) missing.push('CAPTCHA_SECRET');
    if (!env.PUBLIC_BASE_URL) missing.push('PUBLIC_BASE_URL');
    if (!env.EMAIL_FROM) missing.push('EMAIL_FROM');
    // 至少配置一个邮件服务商
    const hasResend = Boolean(env.RESEND_API_KEY);
    const hasAgentmail = Boolean(env.AGENTMAIL_API_KEY && env.AGENTMAIL_INBOX_ID);
    if (!hasResend && !hasAgentmail) missing.push('RESEND_API_KEY_or_AGENTMAIL_API_KEY');
  }
  return { ok: missing.length === 0, missing, config };
}
