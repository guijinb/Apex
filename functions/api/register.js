import { hashPassword, sanitize, jsonResponse, validateEmail, validateUsername, validatePassword, checkRateLimit, verifyCaptchaToken } from '../_utils.js';

export async function onRequestPost(context) {
  try {
    const { request, env } = context;
    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
    const rate = await checkRateLimit(env, ip, 'register', 5, 3600);
    if (!rate.allowed) return jsonResponse({ success: false, message: '注册过于频繁，请稍后再试' }, 429);

    const body = await request.json();
    const username = sanitize(body.username || '');
    const email = sanitize(body.email || '');
    const password = body.password || '';
    const captchaToken = body.captchaToken || '';

    const captchaOk = await verifyCaptchaToken(env, captchaToken, ip);
    if (!captchaOk) return jsonResponse({ success: false, message: '人机验证无效或已过期，请重新验证' }, 400);

    if (!validateUsername(username)) return jsonResponse({ success: false, message: '账号需 6-20 位，仅限字母、数字、下划线' }, 400);
    if (!validateEmail(email)) return jsonResponse({ success: false, message: '请输入有效的邮箱地址' }, 400);
    if (!validatePassword(password)) return jsonResponse({ success: false, message: '密码强度不足' }, 400);

    const existing = await env.apex_db.prepare(
      'SELECT id FROM users WHERE username = ? OR email = ?'
    ).bind(username, email).first();
    if (existing) return jsonResponse({ success: false, message: '账号或邮箱已被注册' }, 409);

    const hash = await hashPassword(password);
    const result = await env.apex_db.prepare(
      'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)'
    ).bind(username, email, hash).run();

    return jsonResponse({ success: true, message: '注册成功', userId: result.meta.last_row_id });
  } catch (err) {
    return jsonResponse({ success: false, message: '服务器错误：' + err.message }, 500);
  }
}
export async function onRequestOptions() { return jsonResponse({}, 204); }
