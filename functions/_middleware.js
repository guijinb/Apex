import { generateCsrfToken, buildCsrfCookie } from './_csrf.js';

export async function onRequest(context) {
  const requestId = 'apx_' + Date.now().toString(36) + '_' +
    Math.random().toString(36).substring(2, 10);

  context.data = context.data || {};
  context.data.requestId = requestId;

  try {
    const response = await context.next();
    const newHeaders = new Headers(response.headers);
    newHeaders.set('X-Request-ID', requestId);
    newHeaders.set('X-Content-Type-Options', 'nosniff');

    // 如果没有 CSRF Cookie，下发一个
    const cookieHeader = context.request.headers.get('Cookie') || '';
    if (!cookieHeader.includes('apex_csrf=')) {
      newHeaders.append('Set-Cookie', buildCsrfCookie(generateCsrfToken()));
    }

    // 204/304 响应不能有 body
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
    return new Response(JSON.stringify({
      success: false,
      message: '服务器内部错误',
      request_id: requestId,
    }), {
      status: 500,
      headers: {
        'Content-Type': 'application/json; charset=utf-8',
        'X-Request-ID': requestId,
      },
    });
  }
}
