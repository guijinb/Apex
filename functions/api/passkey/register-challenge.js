// POST /api/passkey/register-challenge
// 需要登录。生成注册挑战，返回给前端用于 navigator.credentials.create()
import { jsonResponse, errorResponse, optionsResponse } from '../../_response.js';
import { getCurrentUser } from '../../_auth.js';
import { storeChallenge, getCredentialIdsForUser } from '../../_passkey.js';
import { getConfig } from '../../_config.js';
import { enforceIpRateLimit } from '../../_rateLimit.js';
import { writeAudit } from '../../_audit.js';

export async function onRequestPost(context) {
  const { request, env } = context;
  const requestId = context.data && context.data.requestId ? context.data.requestId : '';

  const limited = await enforceIpRateLimit(env, request, 'passkey-reg-challenge-ip', 20, 60);
  if (limited) return limited;

  const user = await getCurrentUser(env, request);
  if (!user) {
    return errorResponse('请先登录后再绑定 Passkey', 401, 'unauthenticated', requestId);
  }

  const config = getConfig(env);
  const rpId = config.publicBaseUrl ? new URL(config.publicBaseUrl).hostname : '';
  if (!rpId) {
    return errorResponse('服务器配置错误', 500, 'config_error', requestId);
  }

  const { challengeId, challenge } = await storeChallenge(env, {
    type: 'registration',
    userId: user.userId,
  });

  const excludeCredentials = (await getCredentialIdsForUser(env, user.userId)).map((id) => ({
    type: 'public-key',
    id,
    transports: ['internal', 'hybrid', 'usb', 'nfc', 'ble'],
  }));

  await writeAudit(env, {
    action: 'passkey_register_challenge',
    actorId: user.userId,
    actorType: 'user',
  }, request);

  return jsonResponse({
    success: true,
    challengeId,
    publicKey: {
      challenge,
      rp: { id: rpId, name: 'Apex Entertainment' },
      user: {
        id: String(user.userId),
        name: user.username,
        displayName: user.username,
      },
      pubKeyCredParams: [
        { type: 'public-key', alg: -7 },
      ],
      timeout: 60000,
      attestation: 'none',
      authenticatorSelection: {
        residentKey: 'preferred',
        userVerification: 'preferred',
      },
      excludeCredentials,
    },
  }, 200, requestId);
}

export async function onRequestOptions(context) {
  const requestId = context.data && context.data.requestId ? context.data.requestId : '';
  return optionsResponse(requestId);
}
