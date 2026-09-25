import {
  verifyPassword, generateToken, sanitize, jsonResponse
} from '../_utils.js';

export async function onRequestPost(context) {
  try {
    const { request, env } = context;
    const body = await request.json();
    const account = sanitize(body.account || '');
    const password = body.password || '';

    if (!account || !password) {
      return jsonResponse({ success: false, message: '账号和密码不能为空' }, 400);
    }

    // 查询用户（支持账号或邮箱登录）
    const user = await env.apex_db.prepare(
      'SELECT id, username, email, password_hash FROM users WHERE username = ? OR email = ?'
    ).bind(account, account).first();

    if (!user) {
      return jsonResponse({ success: false, message: '账号或密码错误' }, 401);
    }

    // 校验密码
    const valid = await verifyPassword(password, user.password_hash);
    if (!valid) {
      return jsonResponse({ success: false, message: '账号或密码错误' }, 401);
    }

    // 创建会话
    const sessionToken = generateToken();
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
    await env.apex_db.prepare(
      'INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)'
    ).bind(sessionToken, user.id, expiresAt).run();

    return jsonResponse({
      success: true,
      message: '登录成功',
      token: sessionToken,
      user: { id: user.id, username: user.username, email: user.email },
    });
  } catch (err) {
    return jsonResponse({ success: false, message: '服务器错误：' + err.message }, 500);
  }
}

export async function onRequestOptions() {
  return jsonResponse({}, 204);
}
