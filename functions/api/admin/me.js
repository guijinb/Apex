import { jsonResponse, errorResponse, optionsResponse } from '../../_response.js';
import { PERMISSIONS } from '../../_admin.js';

export async function onRequestGet(context) {
  const requestId = context.data && context.data.requestId ? context.data.requestId : '';
  const admin = context.data && context.data.admin;
  if (!admin) return errorResponse('未登录', 401, 'unauthenticated', requestId);

  return jsonResponse({
    success: true,
    admin: {
      id: admin.id,
      username: admin.username,
      role: admin.role,
      permissions: PERMISSIONS[admin.role] || [],
    },
  }, 200, requestId);
}

export async function onRequestOptions(context) {
  const requestId = context.data && context.data.requestId ? context.data.requestId : '';
  return optionsResponse(requestId);
}
