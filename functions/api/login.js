import { verifyPassword, generateToken, sanitize, jsonResponse, checkRateLimit, verifyCaptchaToken } from '../_utils.js';

export async function onRequestPost(context) {
  try {
    const { request, env } = context;
    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
    const rate = await checkRateLimit(env, ip, 'login', 10, 60);
    if (!rate.allowed) return jsonResponse({ success: false, message: '请求过于频繁，请稍后再试' }, 429);

    const body = await request.json();
    const account = sanitize(body.account || '');
    const password = body.password || '';
    const captchaToken = body.captchaToken || '';

    const captchaOk = await verifyCaptchaToken(env, captchaToken, ip);
    if (!captchaOk) return jsonResponse({ success: false, message: '人机验证无效或已过期，请重新验证' }, 400);

    if (!account || !password) return jsonResponse({ success: false, message: '账号和密码不能为空' }, 400);

    const user = await env.apex_db.prepare(
      'SELECT id, username, email, password_hash FROM users WHERE username = ? OR email = ?'
    ).bind(account, account).first();
    if (!user || !(await verifyPassword(password, user.password_hash))) {
      return jsonResponse({ success: false, message: '账号或密码错误' }, 401);
    }

    const sessionToken = generateToken();
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
    await env.apex_db.prepare(
      'INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)'
    ).bind(sessionToken, user.id, expiresAt).run();

    return jsonResponse({ success: true, message: '登录成功', token: sessionToken, user: { id: user.id, username: user.username, email: user.email } });
  } catch (err) {
    return jsonResponse({ success: false, message: '服务器错误：' + err.message }, 500);
  }
}
export async function onRequestOptions() { return jsonResponse({}, 204); }
