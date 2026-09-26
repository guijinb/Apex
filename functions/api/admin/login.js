import { jsonResponse, sanitize, checkRateLimit, verifyPassword } from '../../_utils.js';
import { generateToken } from '../../_utils.js';
import { hashSessionToken } from '../../_session.js';
import { buildAdminCookie, audit } from '../../_admin.js';

export async function onRequestPost(context) {
  try {
    const { request, env } = context;
    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
    const ua = request.headers.get('User-Agent') || '';

    const rate = await checkRateLimit(env, ip, 'admin-login', 5, 300);
    if (!rate.allowed) {
      await audit(env, { action: 'admin_login_rate_limited', ip, userAgent: ua });
      return jsonResponse({ success: false, message: '尝试过于频繁，请 5 分钟后再试' }, 429);
    }

    const body = await request.json();
    const username = sanitize(body.username || '');
    const password = body.password || '';
    const totpCode = sanitize(body.totpCode || '');

    if (!username || !password) {
      return jsonResponse({ success: false, message: '账号和密码不能为空' }, 400);
    }

    const admin = await env.apex_db.prepare(
      'SELECT id, username, password_hash, role, totp_secret, totp_enabled FROM admin_users WHERE username = ?'
    ).bind(username).first();

    if (!admin || !(await verifyPassword(password, admin.password_hash))) {
      await audit(env, { action: 'admin_login_failed', ip, userAgent: ua, metadata: { username } });
      return jsonResponse({ success: false, message: '账号或密码错误' }, 401);
    }

    // MFA 检查
    if (admin.totp_enabled) {
      if (!totpCode) {
        return jsonResponse({ success: false, message: '请输入 MFA 验证码', needMfa: true }, 401);
      }
      const { verifyTotp } = await import('../../_totp.js');
      const mfaOk = await verifyTotp(admin.totp_secret, totpCode);
      if (!mfaOk) {
        await audit(env, { actorId: admin.id, actorType: 'admin', action: 'admin_mfa_failed', ip, userAgent: ua });
        return jsonResponse({ success: false, message: 'MFA 验证码错误' }, 401);
      }
    }

    // 生成 session
    const token = generateToken();
    const tokenHash = await hashSessionToken(token);
    const expiresAt = new Date(Date.now() + 8 * 60 * 60 * 1000).toISOString();

    await env.apex_db.prepare(
      'INSERT INTO admin_sessions (id, admin_id, expires_at) VALUES (?, ?, ?)'
    ).bind(tokenHash, admin.id, expiresAt).run();

    await env.apex_db.prepare(
      'UPDATE admin_users SET last_login_at = CURRENT_TIMESTAMP WHERE id = ?'
    ).bind(admin.id).run();

    await audit(env, {
      actorId: admin.id, actorType: 'admin', action: 'admin_login_success',
      ip, userAgent: ua, metadata: { role: admin.role }
    });

    return new Response(JSON.stringify({
      success: true,
      message: '登录成功',
      admin: { id: admin.id, username: admin.username, role: admin.role }
    }), {
      status: 200,
      headers: {
        'Content-Type': 'application/json; charset=utf-8',
        'Set-Cookie': buildAdminCookie(token),
      }
    });
  } catch (err) {
    return jsonResponse({ success: false, message: '服务器错误：' + err.message }, 500);
  }
}

export async function onRequestOptions() { return jsonResponse({}, 204); }
