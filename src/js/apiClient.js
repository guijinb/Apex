// Apex API Client - 统一请求处理
(function() {
  const getCookie = (name) => {
    const match = document.cookie.match(new RegExp('(^| )' + name + '=([^;]+)'));
    return match ? match[2] : null;
  };

  async function request(method, url, data, options = {}, _retryCount = 0) {
    const headers = {
      'Content-Type': 'application/json',
      ...options.headers,
    };

    // CSRF Token 自动附加
    const csrfToken = getCookie('apex_csrf');
    if (csrfToken) {
      headers['X-CSRF-Token'] = csrfToken;
    }

    // Captcha Token 自动注入（如果存在且是对象请求体）
    let body = data;
    if (data && typeof data === 'object' && !Array.isArray(data) && window.__captchaToken) {
      body = { ...data, captchaToken: window.__captchaToken };
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), options.timeout || 15000);

    try {
      const response = await fetch(url, {
        method,
        headers,
        credentials: 'include',
        body: body ? JSON.stringify(body) : undefined,
        signal: controller.signal,
        keepalive: options.keepalive === true,
      });
      clearTimeout(timeoutId);

      let json;
      try {
        json = await response.json();
      } catch (e) {
        json = { success: false, message: '无效的服务器响应' };
      }

      // CSRF 自愈：若首次请求因缺少 CSRF cookie 被 403 拒绝，
      // 服务端已在响应里 Set-Cookie 一个新 token（浏览器会自动保存），
      // 此处重试一次即可成功，无需用户手动刷新。
      if (
        response.status === 403 &&
        _retryCount < 1 &&
        json && typeof json === 'object' && json.code === 'csrf_invalid'
      ) {
        return request(method, url, data, options, _retryCount + 1);
      }

      if (!response.ok) {
        // 可触发全局事件供 UI 处理
        if (response.status === 401) {
          window.dispatchEvent(new CustomEvent('apex:unauthorized'));
        }
        if (response.status === 403) {
          window.dispatchEvent(new CustomEvent('apex:csrf-error'));
        }
      }

      return json;
    } catch (err) {
      clearTimeout(timeoutId);
      if (err.name === 'AbortError') {
        return { success: false, message: '请求超时，请检查网络' };
      }
      return { success: false, message: '网络错误：' + err.message };
    }
  }

  // 首屏预热：若首次访问没有 CSRF cookie，主动 GET 一次让 middleware 下发
  async function ensureCsrf() {
    if (getCookie('apex_csrf')) return;
    try {
      await fetch('/api/health', { credentials: 'include', cache: 'no-store' });
    } catch (e) { /* 静默失败，后续请求的重试逻辑会兜底 */ }
  }
  if (typeof document !== 'undefined') {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', ensureCsrf, { once: true });
    } else {
      ensureCsrf();
    }
  }

  window.apiClient = {
    get: (url, options) => request('GET', url, null, options),
    post: (url, data, options) => request('POST', url, data, options),
    put: (url, data, options) => request('PUT', url, data, options),
    patch: (url, data, options) => request('PATCH', url, data, options),
    delete: (url, data, options) => request('DELETE', url, data, options),
  };

  console.log('[Apex] apiClient 已加载');
})();
