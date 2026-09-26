import { jsonResponse } from '../../_utils.js';

export async function onRequestGet(context) {
  const admin = context.data && context.data.admin;
  if (!admin) return jsonResponse({ success: false, message: '未登录' }, 401);
  return jsonResponse({ success: true, admin });
}
