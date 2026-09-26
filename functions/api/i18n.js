import { jsonResponse, optionsResponse } from '../_response.js';

const SUPPORTED = ['zh-CN', 'en', 'ja'];

export async function onRequestGet(context) {
  const { request } = context;
  const requestId = context.data && context.data.requestId ? context.data.requestId : '';
  const url = new URL(request.url);
  const lang = url.searchParams.get('lang') || 'zh-CN';
  const target = SUPPORTED.includes(lang) ? lang : 'en';

  return jsonResponse({ success: true, lang: target, supported: SUPPORTED }, 200, requestId);
}

export async function onRequestOptions(context) {
  const requestId = context.data && context.data.requestId ? context.data.requestId : '';
  return optionsResponse(requestId);
}
