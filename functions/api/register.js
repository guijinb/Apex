import {
  hashPassword, generateToken, sanitize, jsonResponse,
  validateEmail, validateUsername, validatePassword
} from '../_utils.js';

export async function onRequestPost(context) {
  try {
    const { request, env } = context;
    const body = await request.json();
    const username = sanitize(body.username || '');
    const email = sanitize(body.email || '');
    const password = body.password || '';

    // 参数校验
    if (!validateUsername(username)) {
      return jsonResponse({ success: false, message: '账号需 6-20 位，仅限字母、数字、下划线' }, 400);
    }
    if (!validateEmail(email)) {
      return jsonResponse({ success: false, message: '请输入有效的邮箱地址' }, 400);
    }
    if (!validatePassword(password)) {
      return jsonResponse({ success: false, message: '密码需至少 8 位，含大小写字母、数字和特殊字符' }, 400);
    }

    // 检查账号或邮箱是否已存在
    const existing = await env.apex_db.prepare(
      'SELECT id FROM users WHERE username = ? OR email = ?'
    ).bind(username, email).first();

    if (existing) {
      return jsonResponse({ success: false, message: '账号或邮箱已被注册' }, 409);
    }

    // 哈希密码并写入
    const hash = await hashPassword(password);
    const result = await env.apex_db.prepare(
      'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)'
    ).bind(username, email, hash).run();

    return jsonResponse({
      success: true,
      message: '注册成功',
      userId: result.meta.last_row_id,
    });
  } catch (err) {
    return jsonResponse({ success: false, message: '服务器错误：' + err.message }, 500);
  }
}

export async function onRequestOptions() {
  return jsonResponse({}, 204);
}
