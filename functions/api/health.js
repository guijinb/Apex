import { jsonResponse } from '../_utils.js';

export async function onRequestGet(context) {
  const checks = {
    api: 'ok',
    db: 'unknown',
    time: new Date().toISOString(),
    version: '2.0.0',
  };

  try {
    await context.env.apex_db.prepare('SELECT 1').first();
    checks.db = 'ok';
  } catch (e) {
    checks.db = 'error';
  }

  const status = checks.db === 'ok' ? 200 : 503;
  return jsonResponse({ success: checks.db === 'ok', checks }, status);
}

export async function onRequestOptions() { return jsonResponse({}, 204); }
