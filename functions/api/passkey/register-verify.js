// POST /api/passkey/register-verify
// 验证注册响应，保存凭证
import { jsonResponse, errorResponse, optionsResponse } from '../../_response.js';
import { parseJsonBody } from '../../_validation.js';
import { getCurrentUser } from '../../_auth.js';
import { consumeChallenge, savePasskey } from '../../_passkey.js';
import { getConfig } from '../../_config.js';
import { enforceIpRateLimit } from '../../_rateLimit.js';
import { writeAudit } from '../../_audit.js';
import {
  b64uDecode, b64uEncode,
  parseAuthenticatorData, coseKeyToJwk,
  verifyEs256Signature, verifyClientData,
  buildSignatureBase, sha256,
} from '../../_webauthn.js';
import { decodeCbor } from '../../_cbor.js';

export async function onRequestPost(context) {
  const { request, env } = context;
  const requestId = context.data && context.data.requestId ? context.data.requestId : '';

  const limited = await enforceIpRateLimit(env, request, 'passkey-reg-verify-ip', 20, 60);
  if (limited) return limited;

  const user = await getCurrentUser(env, request);
  if (!user) return errorResponse('请先登录', 401, 'unauthenticated', requestId);

  const parsed = await parseJsonBody(request, 16384);
  if (!parsed.ok) return errorResponse(parsed.message, parsed.status, 'bad_request', requestId);

  const body = parsed.data || {};
  const challengeId = String(body.challengeId || '');
  const rawId = String(body.rawId || '');
  const response = body.response || {};
  const clientDataJSON = String(response.clientDataJSON || '');
  const attestationObject = String(response.attestationObject || '');
  const transports = Array.isArray(body.transports) ? body.transports.join(',') : (body.transports || null);
  const deviceName = String(body.deviceName || '').substring(0, 80) || null;

  if (!challengeId || !rawId || !clientDataJSON || !attestationObject) {
    return errorResponse('缺少必要参数', 400, 'missing_params', requestId);
  }

  // 1) 消费 challenge
  const stored = await consumeChallenge(env, challengeId, 'registration');
  if (!stored || stored.userId !== user.userId) {
    return errorResponse('挑战已过期或无效', 400, 'invalid_challenge', requestId);
  }
  const expectedChallenge = stored.challenge;

  // 2) 验证 clientDataJSON
  const config = getConfig(env);
  const origin = config.publicBaseUrl || '';
  let clientData;
  try {
    const jsonStr = new TextDecoder().decode(b64uDecode(clientDataJSON));
    clientData = verifyClientData(jsonStr, {
      expectedType: 'webauthn.create',
      expectedChallenge,
      expectedOrigins: [origin],
    });
  } catch (e) {
    return errorResponse('客户端数据验证失败', 400, 'clientdata_invalid', requestId);
  }

  // 3) 解析 attestationObject
  let attestation;
  try {
    attestation = decodeCbor(b64uDecode(attestationObject));
  } catch (e) {
    return errorResponse('attestation 解析失败', 400, 'attestation_invalid', requestId);
  }

  const authDataBytes = attestation.authData;
  if (!(authDataBytes instanceof Uint8Array)) {
    return errorResponse('authData 格式错误', 400, 'authdata_invalid', requestId);
  }

  // 4) 解析 authData
  let authData;
  try {
    authData = parseAuthenticatorData(authDataBytes);
  } catch (e) {
    return errorResponse('authData 解析失败', 400, 'authdata_invalid', requestId);
  }

  if (!authData.attestedDataIncluded) {
    return errorResponse('缺少 attestedCredentialData', 400, 'no_credential_data', requestId);
  }

  // 5) 验证 rpIdHash
  const rpId = origin ? new URL(origin).hostname : '';
  const expectedRpIdHash = await sha256(new TextEncoder().encode(rpId));
  if (!bytesEqual(authData.rpIdHash, expectedRpIdHash)) {
    return errorResponse('rpId 不匹配', 400, 'rp_id_mismatch', requestId);
  }

  // 6) 提取凭证公钥
  let coseKey;
  try {
    coseKey = decodeCbor(authData.credentialPublicKey);
  } catch (e) {
    return errorResponse('公钥解析失败', 400, 'cose_key_invalid', requestId);
  }

  let jwk;
  try {
    jwk = coseKeyToJwk(coseKey);
  } catch (e) {
    return errorResponse('公钥不受支持: ' + e.message, 400, 'cose_key_unsupported', requestId);
  }

  // 7) credentialId 校验（应与 rawId 一致）
  const credIdFromAuthData = b64uEncode(authData.credentialId);
  if (credIdFromAuthData !== rawId) {
    return errorResponse('credentialId 不匹配', 400, 'credid_mismatch', requestId);
  }

  // 8) 保存凭证
  const publicKeyJwkEncoded = b64uEncode(new TextEncoder().encode(JSON.stringify(jwk)));
  const aaguidHex = authData.aaguid
    ? Array.from(authData.aaguid).map((b) => b.toString(16).padStart(2, '0')).join('')
    : null;

  try {
    await savePasskey(env, {
      userId: user.userId,
      credentialId: rawId,
      publicKey: publicKeyJwkEncoded,
      counter: authData.signCount,
      transports,
      deviceName,
      aaguid: aaguidHex,
    });
  } catch (e) {
    if (String(e.message || '').indexOf('UNIQUE') !== -1) {
      return errorResponse('该凭证已绑定', 409, 'credential_exists', requestId);
    }
    console.error('[Passkey] save failed:', e && e.message ? e.message : e);
    return errorResponse('保存凭证失败', 500, 'save_failed', requestId);
  }

  await writeAudit(env, {
    action: 'passkey_registered',
    actorId: user.userId,
    actorType: 'user',
    metadata: { deviceName, transports },
  }, request);

  return jsonResponse({
    success: true,
    message: 'Passkey 绑定成功',
  }, 200, requestId);
}

function bytesEqual(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a[i] ^ b[i];
  return diff === 0;
}

export async function onRequestOptions(context) {
  const requestId = context.data && context.data.requestId ? context.data.requestId : '';
  return optionsResponse(requestId);
}
