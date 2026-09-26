import { jsonResponse } from '../_utils.js';

// 从 Cloudflare Pages 的静态资源中读取 i18n JSON
// 或者从代码内嵌（这里用简单方案：服务器返回支持的翻译）
export async function onRequestGet(context) {
  const { request } = context;
  const url = new URL(request.url);
  const lang = url.searchParams.get('lang') || 'zh-CN';

  // 支持的语言列表
  const supported = ['zh-CN', 'en', 'ja'];
  const target = supported.includes(lang) ? lang : 'en';

  return jsonResponse({ success: true, lang: target, supported });
}

export async function onRequestOptions() { return jsonResponse({}, 204); }
