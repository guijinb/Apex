import { jsonResponse, optionsResponse } from '../_response.js';
import { cleanupOldLogs } from '../_logs.js';

export async function onRequestGet(context) {
  const { env, data } = context;
  const requestId = data && data.requestId ? data.requestId : '';

  const checks = {
    api: 'ok',
    db: 'unknown',
    time: new Date().toISOString(),
    version: '2.0.0',
  };

  try {
    await env.apex_db.prepare('SELECT 1').first();
    checks.db = 'ok';
  } catch {
    checks.db = 'error';
  }

  // 顺带清理过期日志（幂等；任何异常都不影响主流程）
  // 必须用 try/catch + Promise.resolve 包裹，
  // 因为 cleanupOldLogs 若同步抛错，裸调用会导致整个 handler 500。
  try {
    Promise.resolve(cleanupOldLogs(env)).catch(() => {});
  } catch (_) {
    // 同步抛错也吞掉
  }

  const status = checks.db === 'ok' ? 200 : 503;
  return jsonResponse({ success: checks.db === 'ok', checks }, status, requestId);
}

export async function onRequestOptions(context) {
  const requestId = context.data && context.data.requestId ? context.data.requestId : '';
  return optionsResponse(requestId);
}
