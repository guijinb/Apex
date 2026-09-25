import { hashPassword, sanitize, jsonResponse, validatePassword } from '../_utils.js';

export async function onRequestPost(context) {
  try {
    const { request, env } = context;
    const body = await request.json();
    const email = sanitize(body.email || '');
    const code = sanitize(body.code || '');
    const newPassword = body.newPassword || '';

    if (!email || !code || !newPassword) {
      return jsonResponse({ success: false, message: '参数不完整' }, 400);
    }
    if (!validatePassword(newPassword)) {
      return jsonResponse({ success: false, message: '密码需至少 8 位，含大小写字母、数字和特殊字符' }, 400);
    }

    // 查找验证码
    const reset = await env.apex_db.prepare(
      `SELECT id, expires_at, used FROM password_resets
       WHERE email = ? AND code = ? ORDER BY id DESC LIMIT 1`
    ).bind(email, code).first();

    if (!reset) {
      return jsonResponse({ success: false, message: '验证码错误' }, 400);
    }
    if (reset.used) {
      return jsonResponse({ success: false, message: '验证码已被使用' }, 400);
    }
    if (new Date(reset.expires_at) < new Date()) {
      return jsonResponse({ success: false, message: '验证码已过期' }, 400);
    }

    // 更新密码
    const hash = await hashPassword(newPassword);
    await env.apex_db.prepare(
      'UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE email = ?'
    ).bind(hash, email).run();

    // 标记验证码已使用
    await env.apex_db.prepare(
      'UPDATE password_resets SET used = 1 WHERE id = ?'
    ).bind(reset.id).run();

    // 清除该用户所有会话（强制重新登录）
    await env.apex_db.prepare(
      'DELETE FROM sessions WHERE user_id = (SELECT id FROM users WHERE email = ?)'
    ).bind(email).run();

    return jsonResponse({ success: true, message: '密码重置成功' });
  } catch (err) {
    return jsonResponse({ success: false, message: '服务器错误：' + err.message }, 500);
  }
}

export async function onRequestOptions() {
  return jsonResponse({}, 204);
}
