import { generateCsrfToken, buildCsrfCookie, verifyCsrf, getCsrfCookie } from './_csrf.js';
import { assertProductionConfig } from './_config.js';

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

// 统一 API 响应安全头（防御纵深：即使脱离 Cloudflare Pages 的 _headers 也生效）
const API_SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()',
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-origin',
};

function jsonError(status, message, requestId, extra) {
  return new Response(JSON.stringify({
    success: false,
    message,
    request_id: requestId,
    ...(extra || {}),
  }), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'X-Request-ID': requestId,
      'X-Content-Type-Options': 'nosniff',
    },
  });
}

export async function onRequest(context) {
  // requestId 用于日志关联，使用 CSPRNG 避免可预测序列被用于日志投毒
  const requestId = 'apx_' + Date.now().toString(36) + '_' +
    crypto.randomUUID().replace(/-/g, '').slice(0, 12);

  context.data = context.data || {};
  context.data.requestId = requestId;

  try {
    const url = new URL(context.request.url);
    const isApi = url.pathname.startsWith('/api/');

    // ---------- 生产环境配置断言（仅 API 路由） ----------
    if (isApi) {
      const check = assertProductionConfig(context.env);
      if (!check.ok) {
        console.error('[Apex][config] 生产环境缺少必需配置:', check.missing.join(', '));
        return jsonError(503, '服务暂时不可用，请稍后重试', requestId, {
          code: 'config_invalid',
        });
      }
    }

    // ---------- CSRF 校验 ----------
    if (!SAFE_METHODS.has(context.request.method.toUpperCase())) {
      const csrfOk = verifyCsrf(context.request);
      if (!csrfOk) {
        const headers = new Headers();
        headers.set('Content-Type', 'application/json; charset=utf-8');
        headers.set('X-Request-ID', requestId);
        headers.set('X-Content-Type-Options', 'nosniff');
        if (!getCsrfCookie(context.request)) {
          headers.append('Set-Cookie', buildCsrfCookie(generateCsrfToken()));
        }
        return new Response(JSON.stringify({
          success: false,
          message: 'CSRF 校验失败，请刷新页面后重试',
          code: 'csrf_invalid',
          request_id: requestId,
        }), {
          status: 403,
          headers,
        });
      }
    }

    const response = await context.next();
    const newHeaders = new Headers(response.headers);
    newHeaders.set('X-Request-ID', requestId);
    for (const [k, v] of Object.entries(API_SECURITY_HEADERS)) {
      newHeaders.set(k, v);
    }

    if (!getCsrfCookie(context.request)) {
      newHeaders.append('Set-Cookie', buildCsrfCookie(generateCsrfToken()));
    }

    if (response.status === 204 || response.status === 304) {
      return new Response(null, {
        status: response.status,
        statusText: response.statusText,
        headers: newHeaders,
      });
    }

    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: newHeaders,
    });
  } catch (err) {
    console.error('[Apex][middleware]', requestId, err && err.stack ? err.stack : err);
    return jsonError(500, '服务器内部错误', requestId);
  }
}
