// Apex Passkey helper
// - challenge 存储与消费（一次性，5 分钟 TTL）
// - 凭证 CRUD
// - 签名计数器更新

import { generateChallenge } from './_webauthn.js';

const CHALLENGE_TTL_MS = 5 * 60 * 1000;

// 生成并存储 challenge，返回 { challengeId, challenge }
export async function storeChallenge(env, { type, userId = null }) {
  if (!['registration', 'authentication'].includes(type)) {
    throw new Error('invalid_challenge_type');
  }
  const challengeId = crypto.randomUUID();
  const challenge = generateChallenge();
  const expiresAt = new Date(Date.now() + CHALLENGE_TTL_MS).toISOString();

  await env.apex_db.prepare(
    'INSERT INTO passkey_challenges (id, challenge, type, user_id, expires_at) VALUES (?, ?, ?, ?, ?)'
  ).bind(challengeId, challenge, type, userId, expiresAt).run();

  return { challengeId, challenge, expiresAt };
}

// 消费 challenge（一次性），返回 { challenge, userId } 或 null
export async function consumeChallenge(env, challengeId, expectedType) {
  if (!challengeId) return null;
  const row = await env.apex_db.prepare(
    'SELECT id, challenge, type, user_id, expires_at FROM passkey_challenges WHERE id = ?'
  ).bind(challengeId).first();

  if (!row) return null;
  if (row.type !== expectedType) return null;
  if (new Date(row.expires_at) < new Date()) {
    await env.apex_db.prepare('DELETE FROM passkey_challenges WHERE id = ?').bind(challengeId).run();
    return null;
  }

  // 一次性消费：立即删除
  await env.apex_db.prepare('DELETE FROM passkey_challenges WHERE id = ?').bind(challengeId).run();

  return { challenge: row.challenge, userId: row.user_id };
}

// 列出某用户所有 passkey（脱敏）
export async function listPasskeysForUser(env, userId) {
  const result = await env.apex_db.prepare(
    'SELECT id, credential_id, device_name, transports, created_at, last_used_at FROM passkeys WHERE user_id = ? ORDER BY created_at DESC'
  ).bind(userId).all();
  return (result && result.results) || [];
}

// 按 credentialId 查找凭证
export async function getPasskeyByCredentialId(env, credentialId) {
  return env.apex_db.prepare(
    'SELECT id, user_id, credential_id, public_key, counter, transports FROM passkeys WHERE credential_id = ?'
  ).bind(credentialId).first();
}

// 列出某用户的 credential IDs（用于 excludeCredentials）
export async function getCredentialIdsForUser(env, userId) {
  const result = await env.apex_db.prepare(
    'SELECT credential_id FROM passkeys WHERE user_id = ?'
  ).bind(userId).all();
  return ((result && result.results) || []).map((r) => r.credential_id);
}

// 保存新凭证
export async function savePasskey(env, { userId, credentialId, publicKey, counter, transports, deviceName, aaguid }) {
  const result = await env.apex_db.prepare(
    `INSERT INTO passkeys (user_id, credential_id, public_key, counter, transports, device_name, aaguid)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).bind(
    userId,
    credentialId,
    publicKey,
    counter,
    transports || null,
    deviceName || null,
    aaguid || null
  ).run();
  return result.meta && result.meta.last_row_id;
}

// 删除凭证（只允许删自己的）
export async function deletePasskey(env, userId, credentialId) {
  const result = await env.apex_db.prepare(
    'DELETE FROM passkeys WHERE user_id = ? AND credential_id = ?'
  ).bind(userId, credentialId).run();
  return result.meta && result.meta.changes > 0;
}

// 更新计数器 + last_used_at
export async function updatePasskeyCounter(env, credentialId, newCounter) {
  await env.apex_db.prepare(
    'UPDATE passkeys SET counter = ?, last_used_at = CURRENT_TIMESTAMP WHERE credential_id = ?'
  ).bind(newCounter, credentialId).run();
}

// 清理过期 challenge
export async function cleanupExpiredChallenges(env) {
  try {
    await env.apex_db.prepare(
      "DELETE FROM passkey_challenges WHERE expires_at < datetime('now')"
    ).run();
  } catch (e) {
    console.error('[Passkey] cleanup challenges failed:', e && e.message ? e.message : e);
  }
}
