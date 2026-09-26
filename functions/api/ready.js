import { jsonResponse, optionsResponse } from '../_response.js';

export async function onRequestGet(context) {
  const requestId = context.data && context.data.requestId ? context.data.requestId : '';
  try {
    await context.env.apex_db.prepare('SELECT COUNT(*) FROM users').first();
    return jsonResponse({ success: true, ready: true }, 200, requestId);
  } catch {
    return jsonResponse({ success: false, ready: false }, 503, requestId);
  }
}

export async function onRequestOptions(context) {
  const requestId = context.data && context.data.requestId ? context.data.requestId : '';
  return optionsResponse(requestId);
}
