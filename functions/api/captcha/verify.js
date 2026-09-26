import { jsonResponse } from '../../_utils.js';
import { verifyChallenge, calculateScore, passesVerification, issueToken, hashIP } from '../../_captcha.js';

export async function onRequestPost(context) {
  try {
    const { request, env } = context;
    const secret = env.CAPTCHA_SECRET;
    if (!secret) {
      return jsonResponse({ success: false, message: '服务器配置错误' }, 500);
    }

    const body = await request.json();
    const { signals, challenge, signature } = body || {};

    // 1. 验证挑战签名（防止重放攻击）
    if (!challenge || !signature) {
      return jsonResponse({ success: false, message: '缺少验证参数' }, 400);
    }
    const challengeOk = await verifyChallenge(challenge, signature, secret);
    if (!challengeOk) {
      return jsonResponse({ success: false, message: '验证已过期，请刷新页面重试' }, 400);
    }

    // 2. 计算风控评分
    if (!signals || typeof signals !== 'object') {
      return jsonResponse({ success: false, message: '缺少行为数据' }, 400);
    }
    const score = calculateScore(signals);
    console.log('[Captcha] 评分：', score, '信号：', JSON.stringify(signals).substring(0, 200));

    // 3. 判断是否通过
    if (!passesVerification(score, 50)) {
      return jsonResponse({
        success: false,
        message: '行为验证未通过，请稍后重试',
        score,
      }, 400);
    }

    // 4. 签发一次性 Token（含 IP 绑定，有效期 5 分钟）
    const ip = request.headers.get('CF-Connecting-IP') || '';
    const ipHash = await hashIP(ip);
    const token = await issueToken(secret, ipHash, score);

    return jsonResponse({ success: true, token, score });
  } catch (err) {
    return jsonResponse({ success: false, message: '服务器错误：' + err.message }, 500);
  }
}

export async function onRequestOptions() { return jsonResponse({}, 204); }
