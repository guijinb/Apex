import { jsonResponse, optionsResponse } from '../_response.js';
import { cleanupOldLogs } from '../_logs.js';

export async function onRequestGet(context) {
  const requestId = context.data && context.data.requestId ? context.data.requestId : '';
  const checks = {
    api: 'ok',
    db: 'unknown',
    time: new Date().toISOString(),
    version: '2.0.0',
  };

  try {
    await context.env.apex_db.prepare('SELECT 1').first();
    checks.db = 'ok';
  } catch {
    checks.db = 'error';
  }

  const status = checks.db === 'ok' ? 200 : 503;
  // 顺带清理过期日志（幂等，失败不影响主流程）
cleanupOldLogs(env).catch(() => {});


  return jsonResponse({ success: checks.db === 'ok', checks }, status, requestId);
}

export async function onRequestOptions(context) {
  const requestId = context.data && context.data.requestId ? context.data.requestId : '';
  return optionsResponse(requestId);
}
