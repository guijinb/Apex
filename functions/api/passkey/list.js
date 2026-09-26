// GET /api/passkey/list
// 列出当前用户绑定的所有 passkey
import { jsonResponse, errorResponse, optionsResponse } from '../../_response.js';
import { getCurrentUser } from '../../_auth.js';
import { listPasskeysForUser } from '../../_passkey.js';

export async function onRequestGet(context) {
  const { request, env } = context;
  const requestId = context.data && context.data.requestId ? context.data.requestId : '';

  const user = await getCurrentUser(env, request);
  if (!user) return errorResponse('请先登录', 401, 'unauthenticated', requestId);

  const rows = await listPasskeysForUser(env, user.userId);

  const passkeys = rows.map((r) => ({
    id: r.id,
    deviceName: r.device_name || '未命名设备',
    transports: r.transports ? r.transports.split(',') : [],
    createdAt: r.created_at,
    lastUsedAt: r.last_used_at,
  }));

  return jsonResponse({ success: true, passkeys }, 200, requestId);
}

export async function onRequestOptions(context) {
  const requestId = context.data && context.data.requestId ? context.data.requestId : '';
  return optionsResponse(requestId);
}
