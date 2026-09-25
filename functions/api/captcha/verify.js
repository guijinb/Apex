import { generateToken, jsonResponse, checkRateLimit } from '../../_utils.js';

export async function onRequestPost(context) {
  try {
    const { request, env } = context;
    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
    const rate = await checkRateLimit(env, ip, 'captcha', 20, 60);
    if (!rate.allowed) return jsonResponse({ success: false, message: '请求过于频繁' }, 429);

    const token = generateToken();
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString();

    await env.apex_db.prepare(
      'INSERT INTO captcha_tokens (token, ip, expires_at) VALUES (?, ?, ?)'
    ).bind(token, ip, expiresAt).run();

    return jsonResponse({ success: true, token: token });
  } catch (err) {
    return jsonResponse({ success: false, message: '服务器错误：' + err.message }, 500);
  }
}

export async function onRequestOptions() { return jsonResponse({}, 204); }
