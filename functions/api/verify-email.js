import { jsonResponse } from '../_utils.js';
import { hashSessionToken } from '../_session.js';

export async function onRequestGet(context) {
  try {
    const { request, env } = context;
    const url = new URL(request.url);
    const token = url.searchParams.get('token');
    if (!token) return new Response('缺少验证参数', { status: 400 });

    const tokenHash = await hashSessionToken(token);
    const record = await env.apex_db.prepare(
      'SELECT id, user_id, expires_at, used_at FROM email_verifications WHERE token_hash = ?'
    ).bind(tokenHash).first();

    if (!record) return new Response('验证链接无效', { status: 400 });
    if (record.used_at) return new Response('该链接已被使用', { status: 400 });
    if (new Date(record.expires_at) < new Date()) return new Response('验证链接已过期', { status: 400 });

    // 更新用户
    await env.apex_db.prepare(
      'UPDATE users SET email_verified = 1, email_verified_at = CURRENT_TIMESTAMP WHERE id = ?'
    ).bind(record.user_id).run();
    await env.apex_db.prepare(
      'UPDATE email_verifications SET used_at = CURRENT_TIMESTAMP WHERE id = ?'
    ).bind(record.id).run();

    // 返回成功页面
    return new Response(`<!DOCTYPE html><html><head><meta charset="UTF-8"><title>验证成功</title><style>body{background:#050505;color:#fff;font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;text-align:center;}h1{color:#4ade80;}a{color:#d4af37;text-decoration:none;margin-top:20px;display:inline-block;padding:12px 24px;border:1px solid #d4af37;border-radius:8px;}</style></head><body><div><h1>✅ 邮箱验证成功</h1><p style="color:#888;">您的邮箱已激活，现在可以正常使用所有功能。</p><a href="/">返回首页</a></div></body></html>`, {
      status: 200,
      headers: { 'Content-Type': 'text/html; charset=utf-8' }
    });
  } catch (err) {
    return new Response('服务器错误', { status: 500 });
  }
}
