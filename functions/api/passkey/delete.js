// POST /api/passkey/delete
// 删除当前用户的某个 passkey
import { jsonResponse, errorResponse, optionsResponse } from '../../_response.js';
import { parseJsonBody } from '../../_validation.js';
import { getCurrentUser } from '../../_auth.js';
import { deletePasskey } from '../../_passkey.js';
import { enforceIpRateLimit } from '../../_rateLimit.js';
import { writeAudit } from '../../_audit.js';

export async function onRequestPost(context) {
  const { request, env } = context;
  const requestId = context.data && context.data.requestId ? context.data.requestId : '';

  const limited = await enforceIpRateLimit(env, request, 'passkey-delete-ip', 30, 60);
  if (limited) return limited;

  const user = await getCurrentUser(env, request);
  if (!user) return errorResponse('请先登录', 401, 'unauthenticated', requestId);

  const parsed = await parseJsonBody(request, 2048);
  if (!parsed.ok) return errorResponse(parsed.message, parsed.status, 'bad_request', requestId);

  const credentialId = String((parsed.data || {}).credentialId || '').trim();
  if (!credentialId) return errorResponse('缺少 credentialId', 400, 'missing_params', requestId);

  const removed = await deletePasskey(env, user.userId, credentialId);
  if (!removed) return errorResponse('凭证不存在或无权删除', 404, 'not_found', requestId);

  await writeAudit(env, {
    action: 'passkey_deleted',
    actorId: user.userId,
    actorType: 'user',
  }, request);

  return jsonResponse({ success: true, message: '已删除' }, 200, requestId);
}

export async function onRequestOptions(context) {
  const requestId = context.data && context.data.requestId ? context.data.requestId : '';
  return optionsResponse(requestId);
}
