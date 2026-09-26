import { jsonResponse, errorResponse, optionsResponse } from '../_response.js';
import { parseJsonBody } from '../_validation.js';
import { getClientIP, hashIP, redactSensitive } from '../_security.js';
import { enforceIpRateLimit } from '../_rateLimit.js';

const TYPE_ALLOWLIST = new Set([
  'js_error',
  'promise_rejection',
  'perf_lcp',
  'perf_load',
  'client_info',
  'unknown',
]);

const MSG_MAX = 500;
const URL_MAX = 300;
const UA_MAX = 200;

export async function onRequestPost(context) {
  const { request, env } = context;
  const requestId = context.data && context.data.requestId ? context.data.requestId : '';

  // 客户端日志极易被滥用：每 IP 每分钟最多 60 次
  const limited = await enforceIpRateLimit(env, request, 'client-log', 60, 60);
  if (limited) return limited;

  const parsed = await parseJsonBody(request, 4096);
  if (!parsed.ok) return errorResponse(parsed.message, parsed.status, 'bad_request', requestId);

  const body = parsed.data || {};

  let type = String(body.type || 'unknown').trim().toLowerCase();
  if (!TYPE_ALLOWLIST.has(type)) type = 'unknown';

  const message = redactSensitive(String(body.message || '')).substring(0, MSG_MAX);
  const url = String(body.url || '').substring(0, URL_MAX);
  const ua = String(request.headers.get('User-Agent') || '').substring(0, UA_MAX);
  const ip = getClientIP(request);
  const ipHash = await hashIP(ip, env.AUDIT_SALT || env.CAPTCHA_SECRET || '');
  const environment = env.ENVIRONMENT || 'production';

  try {
    await env.apex_db.prepare(
      `INSERT INTO logs (type, message, url, user_agent, ip, request_id, environment)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    ).bind(type, message, url, ua, ipHash, requestId, environment).run();
  } catch (error) {
    console.error('[Log] insert failed:', error.message);
    return jsonResponse({ success: false }, 200, requestId);
  }

  return jsonResponse({ success: true }, 200, requestId);
}

export async function onRequestOptions(context) {
  const requestId = context.data && context.data.requestId ? context.data.requestId : '';
  return optionsResponse(requestId);
}
