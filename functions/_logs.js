// Apex 日志清理
// - logs 表（客户端错误日志）：保留 30 天
// - audit_logs 表（审计日志）：保留 90 天
// - 由 /api/health 定期触发（幂等，无副作用）
export async function cleanupOldLogs(env) {
  let total = 0;
  try {
    const r1 = await env.apex_db.prepare(
      "DELETE FROM logs WHERE created_at < datetime('now', '-30 days')"
    ).run();
    total += r1.meta && r1.meta.changes ? r1.meta.changes : 0;
  } catch (error) {
    console.error('[Logs] cleanup logs failed:', error && error.message ? error.message : error);
  }
  try {
    const r2 = await env.apex_db.prepare(
      "DELETE FROM audit_logs WHERE created_at < datetime('now', '-90 days')"
    ).run();
    total += r2.meta && r2.meta.changes ? r2.meta.changes : 0;
  } catch (error) {
    console.error('[Logs] cleanup audit_logs failed:', error && error.message ? error.message : error);
  }
  return total;
}
