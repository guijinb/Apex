import {
  verifyChallenge,
  calculateScore,
  passesVerification,
  issueToken,
  hashIP,
  CAPTCHA_PURPOSES,
} from '../../_captcha.js';
import { jsonResponse, errorResponse, optionsResponse } from '../../_response.js';
import { enforceIpRateLimit } from '../../_rateLimit.js';
import { parseJsonBody } from '../../_validation.js';
import { getClientIP } from '../../_security.js';

export async function onRequestPost(context) {
  const { request, env } = context;
  const requestId = context.data && context.data.requestId ? context.data.requestId : '';
  const secret = env.CAPTCHA_SECRET;
  if (!secret) return errorResponse('服务器配置错误', 500, 'config_error', requestId);

  const limited = await enforceIpRateLimit(env, request, 'captcha-verify', 60, 60);
  if (limited) return limited;

  const parsed = await parseJsonBody(request, 8192);
  if (!parsed.ok) return errorResponse(parsed.message, parsed.status, 'bad_request', requestId);

  const body = parsed.data || {};
  const challenge = body.challenge;
  const signature = body.signature;
  const signals = body.signals;
  const purpose = String(body.purpose || '').trim();

  if (!CAPTCHA_PURPOSES.has(purpose)) {
    return errorResponse('无效的验证用途', 400, 'invalid_purpose', requestId);
  }
  if (!challenge || !signature) {
    return errorResponse('缺少验证参数', 400, 'missing_params', requestId);
  }

  const challengeOk = await verifyChallenge(challenge, signature, secret);
  if (!challengeOk) {
    return errorResponse('验证已过期，请刷新页面重试', 400, 'challenge_expired', requestId);
  }

  if (!signals || typeof signals !== 'object') {
    return errorResponse('缺少行为数据', 400, 'missing_signals', requestId);
  }

  const score = calculateScore(signals);

  if (!passesVerification(score)) {
    return jsonResponse(
      { success: false, message: '行为验证未通过，请稍后重试', score, code: 'verification_failed' },
      400,
      requestId
    );
  }

  const ip = getClientIP(request);
  const ipHash = await hashIP(ip, env.CAPTCHA_SALT || secret);
  const token = await issueToken(env, secret, { ipHash, purpose, score });

  return jsonResponse({ success: true, token, score, purpose }, 200, requestId);
}

export async function onRequestOptions(context) {
  const requestId = context.data && context.data.requestId ? context.data.requestId : '';
  return optionsResponse(requestId);
}
