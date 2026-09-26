import { jsonResponse } from '../_utils.js';

export async function onRequestGet(context) {
  try {
    await context.env.apex_db.prepare('SELECT COUNT(*) FROM users').first();
    return jsonResponse({ success: true, ready: true });
  } catch (e) {
    return jsonResponse({ success: false, ready: false }, 503);
  }
}
