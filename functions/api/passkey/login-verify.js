// POST /api/passkey/login-verify
// 验证登录响应，创建 session
import { jsonResponse, errorResponse, optionsResponse } from '../../_response.js';
import { parseJsonBody } from '../../_validation.js';
import { consumeChallenge, getPasskeyByCredentialId, updatePasskeyCounter } from '../../_passkey.js';
import { buildSessionCookie, createUserSession } from '../../_auth.js';
import { getConfig } from '../../_config.js';
import { enforceIpRateLimit } from '../../_rateLimit.js';
import { writeAudit } from '../../_audit.js';
import {
  b64uDecode, parseAuthenticatorData,
  verifyEs256Signature, verifyClientData,
  buildSignatureBase, sha256,
} from '../../_webauthn.js';

export async function onRequestPost(context) {
  const { request, env } = context;
  const requestId = context.data && context.data.requestId ? context.data.requestId : '';

  const limited = await enforceIpRateLimit(env, request, 'passkey-login-verify-ip', 20, 60);
  if (limited) return limited;

  const parsed = await parseJsonBody(request, 16384);
  if (!parsed.ok) return errorResponse(parsed.message, parsed.status, 'bad_request', requestId);

  const body = parsed.data || {};
  const challengeId = String(body.challengeId || '');
  const rawId = String(body.rawId || '');
  const response = body.response || {};
  const clientDataJSON = String(response.clientDataJSON || '');
  const authenticatorData = String(response.authenticatorData || '');
  const signature = String(response.signature || '');
  const userHandle = response.userHandle ? String(response.userHandle) : null;

  if (!challengeId || !rawId || !clientDataJSON || !authenticatorData || !signature) {
    return errorResponse('缺少必要参数', 400, 'missing_params', requestId);
  }

  // 1) 消费 challenge
  const stored = await consumeChallenge(env, challengeId, 'authentication');
  if (!stored) {
    return errorResponse('挑战已过期或无效', 400, 'invalid_challenge', requestId);
  }
  const expectedChallenge = stored.challenge;

  // 2) 查凭证
  const cred = await getPasskeyByCredentialId(env, rawId);
  if (!cred) {
    return errorResponse('凭证未注册', 400, 'credential_not_found', requestId);
  }

  // 3) 验证 clientDataJSON
  const config = getConfig(env);
  const origin = config.publicBaseUrl || '';
  let clientData;
  try {
    const jsonStr = new TextDecoder().decode(b64uDecode(clientDataJSON));
    clientData = verifyClientData(jsonStr, {
      expectedType: 'webauthn.get',
      expectedChallenge,
      expectedOrigins: [origin],
    });
  } catch (e) {
    await writeAudit(env, {
      action: 'passkey_login_failed',
      actorId: cred.user_id,
      actorType: 'user',
      metadata: { reason: 'clientdata_invalid' },
    }, request);
    return errorResponse('客户端数据验证失败', 400, 'clientdata_invalid', requestId);
  }

  // 4) 解析 authData
  const authDataBytes = b64uDecode(authenticatorData);
  let authData;
  try {
    authData = parseAuthenticatorData(authDataBytes);
  } catch (e) {
    return errorResponse('authData 解析失败', 400, 'authdata_invalid', requestId);
  }

  // 5) 验证 rpIdHash
  const rpId = origin ? new URL(origin).hostname : '';
  const expectedRpIdHash = await sha256(new TextEncoder().encode(rpId));
  if (!bytesEqual(authData.rpIdHash, expectedRpIdHash)) {
    return errorResponse('rpId 不匹配', 400, 'rp_id_mismatch', requestId);
  }

  // 6) 检查 userPresent
  if (!authData.userPresent) {
    return errorResponse('用户在场验证失败', 400, 'user_not_present', requestId);
  }

  // 7) 提取公钥 JWK
  let jwk;
  try {
    const jwkJson = new TextDecoder().decode(b64uDecode(cred.public_key));
    jwk = JSON.parse(jwkJson);
  } catch (e) {
    console.error('[Passkey] stored public key parse failed:', e && e.message ? e.message : e);
    return errorResponse('凭证损坏', 500, 'credential_corrupt', requestId);
  }

  // 8) 验证签名
  const sigBytes = b64uDecode(signature);
  const signatureBase = await buildSignatureBase(authDataBytes, new TextDecoder().decode(b64uDecode(clientDataJSON)));

  let valid = false;
  try {
    valid = await verifyEs256Signature(jwk, sigBytes, signatureBase);
  } catch (e) {
    console.error('[Passkey] signature verify error:', e && e.message ? e.message : e);
  }

  if (!valid) {
    await writeAudit(env, {
      action: 'passkey_login_failed',
      actorId: cred.user_id,
      actorType: 'user',
      metadata: { reason: 'bad_signature' },
    }, request);
    return errorResponse('签名验证失败', 401, 'invalid_signature', requestId);
  }

  // 9) 签名计数器检查（防重放）
  const storedCounter = Number(cred.counter || 0);
  const newCounter = Number(authData.signCount || 0);

  // 若 storedCounter > 0 或 newCounter > 0，则要求 newCounter > storedCounter
  if (storedCounter > 0 || newCounter > 0) {
    if (newCounter <= storedCounter) {
      await writeAudit(env, {
        action: 'passkey_login_failed',
        actorId: cred.user_id,
        actorType: 'user',
        metadata: { reason: 'counter_regression', stored: storedCounter, incoming: newCounter },
      }, request);
      return errorResponse('凭证计数器异常，请重新绑定', 401, 'counter_regression', requestId);
    }
  }

  // 10) 查用户
  const user = await env.apex_db.prepare(
    'SELECT id, username, email, email_verified, status FROM users WHERE id = ?'
  ).bind(cred.user_id).first();

  if (!user) {
    return errorResponse('账号不存在', 404, 'user_not_found', requestId);
  }
  if (user.status && user.status !== 'active') {
    return errorResponse('账号已被禁用', 403, 'account_disabled', requestId);
  }

  // 11) 更新计数器
  await updatePasskeyCounter(env, rawId, newCounter);

  // 12) 创建 session
  const session = await createUserSession(env, user.id, request);
  const cfg = getConfig(env);

  await env.apex_db.prepare(
    'UPDATE users SET last_login_at = CURRENT_TIMESTAMP WHERE id = ?'
  ).bind(user.id).run();

  await writeAudit(env, {
    action: 'passkey_login_success',
    actorId: user.id,
    actorType: 'user',
  }, request);

  return jsonResponse({
    success: true,
    message: '登录成功',
    user: {
      id: user.id,
      username: user.username,
      email: user.email,
      emailVerified: Boolean(user.email_verified),
    },
  }, 200, requestId, {
    'Set-Cookie': buildSessionCookie(session.token, cfg.sessionMaxAge, env),
  });
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
