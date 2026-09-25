import { generateCode, sanitize, jsonResponse, validateEmail } from '../_utils.js';

export async function onRequestPost(context) {
  try {
    const { request, env } = context;
    const body = await request.json();
    const email = sanitize(body.email || '');

    if (!validateEmail(email)) {
      return jsonResponse({ success: false, message: '请输入有效的邮箱地址' }, 400);
    }

    // 检查邮箱是否已注册
    const user = await env.apex_db.prepare(
      'SELECT id FROM users WHERE email = ?'
    ).bind(email).first();

    if (!user) {
      // 出于安全考虑，不直接告诉用户邮箱是否存在
      return jsonResponse({ success: true, message: '若邮箱已注册，验证码已发送' });
    }

    // 生成验证码（有效期10分钟），写入数据库
    const code = generateCode();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString();

    // 清除该邮箱之前的未使用验证码
    await env.apex_db.prepare(
      'UPDATE password_resets SET used = 1 WHERE email = ? AND used = 0'
    ).bind(email).run();

    await env.apex_db.prepare(
      'INSERT INTO password_resets (email, code, expires_at) VALUES (?, ?, ?)'
    ).bind(email, code, expiresAt).run();

    // ⚠️ 生产环境：这里应调用邮件服务 API 发送验证码
    // 现阶段为了演示，我们直接返回验证码到前端
    console.log(`[重置验证码] ${email} => ${code}`);

    return jsonResponse({
      success: true,
      message: '验证码已发送',
      // ⚠️ 生产环境请删除下面这行，避免泄露验证码
      devCode: code,
    });
  } catch (err) {
    return jsonResponse({ success: false, message: '服务器错误：' + err.message }, 500);
  }
}

export async function onRequestOptions() {
  return jsonResponse({}, 204);
}
