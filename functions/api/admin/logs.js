import { sanitize, jsonResponse } from '../../_utils.js';

// 简单管理员密码（生产环境建议改成 Cloudflare 环境变量里的强密码）
const ADMIN_PASSWORD = 'apex-admin-2026';

export async function onRequestGet(context) {
  try {
    const { request, env } = context;
    const url = new URL(request.url);
    const pwd = url.searchParams.get('pwd') || '';
    const type = sanitize(url.searchParams.get('type') || '');
    const limit = Math.min(parseInt(url.searchParams.get('limit') || '100'), 500);

    if (pwd !== ADMIN_PASSWORD) {
      return jsonResponse({ success: false, message: '未授权' }, 401);
    }

    let query = 'SELECT id, type, message, url, ip, created_at FROM logs';
    const params = [];
    if (type) {
      query += ' WHERE type = ?';
      params.push(type);
    }
    query += ' ORDER BY id DESC LIMIT ?';
    params.push(limit);

    const stmt = env.apex_db.prepare(query);
    const result = await (params.length > 0 ? stmt.bind(...params) : stmt).all();

    // 统计信息
    const stats = await env.apex_db.prepare(
      'SELECT type, COUNT(*) as count FROM logs GROUP BY type'
    ).all();

    const userCount = await env.apex_db.prepare('SELECT COUNT(*) as c FROM users').first();
    const sessionCount = await env.apex_db.prepare('SELECT COUNT(*) as c FROM sessions').first();

    return jsonResponse({
      success: true,
      total: result.results ? result.results.length : 0,
      stats: stats.results || [],
      userCount: userCount ? userCount.c : 0,
      sessionCount: sessionCount ? sessionCount.c : 0,
      logs: result.results || [],
    });
  } catch (err) {
    return jsonResponse({ success: false, message: '服务器错误：' + err.message }, 500);
  }
}

export async function onRequestOptions() { return jsonResponse({}, 204); }
