import { verifyPassword, hashPassword, needsRehash, generateToken, sanitize, jsonResponse, checkRateLimit, verifyCaptchaToken, buildSessionCookie } from '../_utils.js';

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

    // 自动升级旧密码哈希（用户无感知）
    if (needsRehash(user.password_hash)) {
      try {
        const newHash = await hashPassword(password);
        await env.apex_db.prepare(
          'UPDATE users SET password_hash = ? WHERE id = ?'
        ).bind(newHash, user.id).run();
        console.log('[Apex] 密码哈希已升级：user_id=' + user.id);
      } catch (e) {
        console.error('[Apex] 哈希升级失败：', e.message);
      }
    }

    const sessionToken = generateToken();
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
    await env.apex_db.prepare(
      'INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)'
    ).bind(sessionToken, user.id, expiresAt).run();

    // 关键：通过 Set-Cookie 返回 Session，而不是放在 JSON 里
    return new Response(JSON.stringify({
      success: true,
      message: '登录成功',
      user: { id: user.id, username: user.username, email: user.email }
    }), {
      status: 200,
      headers: {
        'Content-Type': 'application/json; charset=utf-8',
        'Set-Cookie': buildSessionCookie(sessionToken),
      }
    });
  } catch (err) {
    return jsonResponse({ success: false, message: '服务器错误：' + err.message }, 500);
  }
}
export async function onRequestOptions() { return jsonResponse({}, 204); }
