// 系统状态探针
// - 不泄露 API Key / 数据库细节 / 内部 hostname
// - 只暴露每一项是否可用
// - Email 状态基于环境变量配置 + 至少一个 provider 可用

import { jsonResponse, optionsResponse } from '../_response.js';
import { getConfig } from '../_config.js';

function evaluateEmail(env) {
  const config = getConfig(env);
  const hasResend = Boolean(env.RESEND_API_KEY);
  const hasAgentmail = Boolean(env.AGENTMAIL_API_KEY && config.agentmailInboxId);

  const providers = [];
  if (hasResend) providers.push('resend');
  if (hasAgentmail) providers.push('agentmail');

  let state = 'error';
  if (providers.length >= 2) state = 'ok';
  else if (providers.length === 1) state = 'warn';
  else state = 'error';

  return {
    state,
    providers,
    primary: providers[0] || null,
  };
}

export async function onRequestGet(context) {
  const { env } = context;
  const requestId = context.data && context.data.requestId ? context.data.requestId : '';

  const checks = {
    api: { state: 'ok' },
    db: { state: 'unknown' },
    email: evaluateEmail(env),
    time: new Date().toISOString(),
    version: '2.0.0',
  };

  try {
    await env.apex_db.prepare('SELECT 1').first();
    checks.db.state = 'ok';
  } catch {
    checks.db.state = 'error';
  }

  const okStates = Object.values(checks)
    .filter((v) => v && typeof v === 'object' && 'state' in v)
    .map((v) => v.state);

  let overall = 'ok';
  if (okStates.includes('error')) overall = 'error';
  else if (okStates.includes('warn')) overall = 'warn';

  const status = overall === 'error' ? 503 : 200;

  return jsonResponse({
    success: overall === 'ok',
    overall,
    checks,
  }, status, requestId);
}

export async function onRequestOptions(context) {
  const requestId = context.data && context.data.requestId ? context.data.requestId : '';
  return optionsResponse(requestId);
}
