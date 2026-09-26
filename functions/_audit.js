import { getClientIP, hashIP, redactSensitive } from './_security.js';

export async function writeAudit(env, entry = {}, request = null) {
  try {
    const ip = request ? getClientIP(request) : entry.ip || '';
    const ipHash = ip ? await hashIP(ip, env.AUDIT_SALT || env.CAPTCHA_SECRET || '') : null;
    const userAgent = request
      ? String(request.headers.get('User-Agent') || '').substring(0, 200)
      : String(entry.userAgent || '').substring(0, 200);

    const metadata = entry.metadata
      ? JSON.parse(redactSensitive(JSON.stringify(entry.metadata)))
      : null;

    await env.apex_db.prepare(
      `INSERT INTO audit_logs (actor_id, actor_type, action, target_type, target_id, request_id, ip_hash, user_agent, metadata, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`
    ).bind(
      entry.actorId || null,
      entry.actorType || 'system',
      entry.action || 'unknown',
      entry.targetType || null,
      entry.targetId || null,
      entry.requestId || null,
      ipHash,
      userAgent,
      metadata ? JSON.stringify(metadata) : null
    ).run();
  } catch (error) {
    console.error('[Audit] write failed:', error.message);
  }
}
