import { jsonResponse } from '../../_utils.js';
import { generateChallenge } from '../../_captcha.js';

export async function onRequestPost(context) {
  try {
    const { env } = context;
    const secret = env.CAPTCHA_SECRET;
    if (!secret) {
      return jsonResponse({ success: false, message: '服务器配置错误' }, 500);
    }
    const result = await generateChallenge(secret);
    return jsonResponse({ success: true, ...result });
  } catch (err) {
    return jsonResponse({ success: false, message: '服务器错误：' + err.message }, 500);
  }
}

export async function onRequestOptions() { return jsonResponse({}, 204); }
