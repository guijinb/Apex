import { jsonResponse, errorResponse, optionsResponse } from '../_response.js';
import { getCurrentUser, buildClearAllSessionCookies } from '../_auth.js';

export async function onRequestGet(context) {
  const { request, env } = context;
  const requestId = context.data && context.data.requestId ? context.data.requestId : '';

  try {
    const user = await getCurrentUser(env, request);
    if (!user) {
      const headers = new Headers();
      headers.set('Content-Type', 'application/json; charset=utf-8');
      if (requestId) headers.set('X-Request-ID', requestId);
      for (const c of buildClearAllSessionCookies(env)) {
        headers.append('Set-Cookie', c);
      }
      return new Response(JSON.stringify({
        success: false,
        message: '未登录',
        code: 'unauthenticated',
      }), { status: 401, headers });
    }

    return jsonResponse({
      success: true,
      user: {
        id: user.userId,
        username: user.username,
        email: user.email,
        emailVerified: user.emailVerified,
      },
    }, 200, requestId);
  } catch (error) {
    console.error('[Me] failed:', error && error.message ? error.message : error);
    return errorResponse('服务器内部错误，请稍后重试。', 500, 'internal_error', requestId);
  }
}

export async function onRequestOptions(context) {
  const requestId = context.data && context.data.requestId ? context.data.requestId : '';
  return optionsResponse(requestId);
}
