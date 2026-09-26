import { getConfig } from './_config.js';

function baseHeaders(requestId = '') {
  const headers = new Headers({
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
  });
  if (requestId) headers.set('X-Request-ID', requestId);
  return headers;
}

export function jsonResponse(data, status = 200, requestId = '', extraHeaders = {}) {
  const headers = baseHeaders(requestId);
  for (const [key, value] of Object.entries(extraHeaders || {})) {
    if (value === undefined || value === null || value === '') continue;
    if (key.toLowerCase() === 'set-cookie' && Array.isArray(value)) {
      for (const v of value) headers.append('Set-Cookie', String(v));
      continue;
    }
    headers.set(key, String(value));
  }
  if (status === 204 || status === 304) return new Response(null, { status, headers });
  return new Response(JSON.stringify(data), { status, headers });
}

export function success(data = {}, requestId = '') {
  return jsonResponse({ success: true, ...data }, 200, requestId);
}

export function errorResponse(message = '服务器内部错误，请稍后重试。', status = 500, code = 'internal_error', requestId = '') {
  return jsonResponse({ success: false, message, code, request_id: requestId || undefined }, status, requestId);
}

export function noContent(requestId = '') {
  return jsonResponse({}, 204, requestId);
}

export function optionsResponse(requestId = '') {
  return jsonResponse({}, 204, requestId);
}

export function applyCors(request, headers, env = {}) {
  const config = getConfig(env);
  const origin = request.headers.get('Origin');
  if (!origin || config.allowedOrigins.length === 0) return headers;
  if (config.allowedOrigins.includes(origin)) {
    headers.set('Access-Control-Allow-Origin', origin);
    headers.set('Access-Control-Allow-Credentials', 'true');
    headers.set('Vary', 'Origin');
  }
  return headers;
}
