import { generateChallenge, CAPTCHA_PURPOSES } from '../../_captcha.js';
import { jsonResponse, errorResponse, optionsResponse } from '../../_response.js';
import { enforceIpRateLimit } from '../../_rateLimit.js';
import { parseJsonBody } from '../../_validation.js';

export async function onRequestPost(context) {
  const { request, env } = context;
  const requestId = context.data && context.data.requestId ? context.data.requestId : '';
  const secret = env.CAPTCHA_SECRET;
  if (!secret) return errorResponse('服务器配置错误', 500, 'config_error', requestId);

  const limited = await enforceIpRateLimit(env, request, 'captcha-challenge', 60, 60);
  if (limited) return limited;

  const parsed = await parseJsonBody(request, 2048);
  if (!parsed.ok) return errorResponse(parsed.message, parsed.status, 'bad_request', requestId);

  const purpose = String(parsed.data && parsed.data.purpose || '').trim();
  if (!CAPTCHA_PURPOSES.has(purpose)) {
    return errorResponse('无效的验证用途', 400, 'invalid_purpose', requestId);
  }

  const result = await generateChallenge(secret);
  return jsonResponse({ success: true, purpose, ...result }, 200, requestId);
}

export async function onRequestOptions(context) {
  const requestId = context.data && context.data.requestId ? context.data.requestId : '';
  return optionsResponse(requestId);
}
