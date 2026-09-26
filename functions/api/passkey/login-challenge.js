// POST /api/passkey/login-challenge
// 未登录也能调用。生成登录挑战（不绑定 user）
import { jsonResponse, errorResponse, optionsResponse } from '../../_response.js';
import { parseJsonBody, sanitize } from '../../_validation.js';
import { storeChallenge, getCredentialIdsForUser } from '../../_passkey.js';
import { getConfig } from '../../_config.js';
import { enforceIpRateLimit } from '../../_rateLimit.js';

export async function onRequestPost(context) {
  const { request, env } = context;
  const requestId = context.data && context.data.requestId ? context.data.requestId : '';

  const limited = await enforceIpRateLimit(env, request, 'passkey-login-challenge-ip', 20, 60);
  if (limited) return limited;

  const parsed = await parseJsonBody(request, 2048);
  if (!parsed.ok) return errorResponse(parsed.message, parsed.status, 'bad_request', requestId);

  const account = sanitize((parsed.data || {}).account, 200);

  const config = getConfig(env);
  const rpId = config.publicBaseUrl ? new URL(config.publicBaseUrl).hostname : '';
  if (!rpId) return errorResponse('服务器配置错误', 500, 'config_error', requestId);

  // 生成 challenge（不绑定 user——登录时用户未知）
  const { challengeId, challenge } = await storeChallenge(env, {
    type: 'authentication',
    userId: null,
  });

  // 若账号已填，返回该用户的 credentialIds（用于 allowCredentials）
  // 若未填，返回空数组（前端会用 resident key 或让用户填账号后重试）
  let allowCredentials = [];
  if (account) {
    const userRow = await env.apex_db.prepare(
      'SELECT id FROM users WHERE username = ? OR email = ? LIMIT 1'
    ).bind(account, account).first();
    if (userRow) {
      const ids = await getCredentialIdsForUser(env, userRow.id);
      allowCredentials = ids.map((id) => ({
        type: 'public-key',
        id,
        transports: ['internal', 'hybrid', 'usb', 'nfc', 'ble'],
      }));
    }
  }

  return jsonResponse({
    success: true,
    challengeId,
    publicKey: {
      challenge,
      rpId,
      timeout: 60000,
      userVerification: 'preferred',
      allowCredentials,
    },
  }, 200, requestId);
}

export async function onRequestOptions(context) {
  const requestId = context.data && context.data.requestId ? context.data.requestId : '';
  return optionsResponse(requestId);
}
