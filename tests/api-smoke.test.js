// Apex API 冒烟测试
// 用法：BASE_URL=https://apex-8rg.pages.dev node tests/api-smoke.test.js
//
// 关键：所有 POST 请求必须先 GET 一次 /api/health 拿 CSRF cookie，
//       然后在 header 里带上 X-CSRF-Token。

const BASE_URL = process.env.BASE_URL || 'http://localhost:8788';
const FETCH_TIMEOUT_MS = Number(process.env.FETCH_TIMEOUT_MS || 8000);

let passed = 0;
let failed = 0;

// ---- 简易 cookie jar（Node 20 fetch 不会自动管理 cookie）----
const cookieJar = new Map();

function parseSetCookie(headerValue) {
  if (!headerValue) return;
  const parts = headerValue.split(/,\s*(?=[A-Za-z_]+=)/);
  for (const part of parts) {
    const m = part.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)=([^;]*)/);
    if (m) cookieJar.set(m[1], m[2]);
  }
}

function cookieHeader() {
  return Array.from(cookieJar.entries())
    .map(([k, v]) => `${k}=${v}`)
    .join('; ');
}

async function fetchWithTimeout(url, options = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

  // 自动带 cookie
  const opts = { ...options, signal: controller.signal };
  opts.headers = opts.headers || {};
  const ch = cookieHeader();
  if (ch) opts.headers['Cookie'] = ch;

  // 自动加 CSRF（除 GET/HEAD 外）
  const method = (opts.method || 'GET').toUpperCase();
  if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) {
    const csrf = cookieJar.get('apex_csrf');
    if (csrf) opts.headers['X-CSRF-Token'] = csrf;
  }

  try {
    const res = await fetch(url, opts);
    // 记录 Set-Cookie
    const setCookie = res.headers.get('set-cookie');
    parseSetCookie(setCookie);
    return res;
  } finally {
    clearTimeout(timer);
  }
}

async function test(name, fn) {
  try {
    await fn();
    console.log('  ✅ ' + name);
    passed++;
  } catch (e) {
    console.log('  ❌ ' + name + '：' + e.message);
    failed++;
  }
}

function assert(cond, msg) {
  if (!cond) throw new Error(msg || 'Assertion failed');
}

(async () => {
  console.log('\n🧪 API 冒烟测试：' + BASE_URL + '\n');

  // ---- 0. 预热：拿 CSRF cookie ----
  await test('GET /api/health 预热 CSRF cookie', async () => {
    const res = await fetchWithTimeout(BASE_URL + '/api/health');
    assert(res.status === 200, 'HTTP ' + res.status);
    assert(cookieJar.has('apex_csrf'), '未收到 apex_csrf cookie');
  });

  // ---- 1. Health ----
  await test('GET /api/health 返回 200 且 db 正常', async () => {
    const res = await fetchWithTimeout(BASE_URL + '/api/health');
    assert(res.status === 200, 'HTTP ' + res.status);
    const data = await res.json();
    assert(data.success === true, 'success 不为 true');
    assert(data.checks && data.checks.db === 'ok', 'db 状态非 ok');
  });

  // ---- 2. Ready ----
  await test('GET /api/ready 返回 200', async () => {
    const res = await fetchWithTimeout(BASE_URL + '/api/ready');
    assert(res.status === 200, 'HTTP ' + res.status);
  });

  // ---- 3. /api/me 未登录 ----
  await test('GET /api/me 未登录返回 401', async () => {
    const res = await fetchWithTimeout(BASE_URL + '/api/me');
    assert(res.status === 401, 'HTTP ' + res.status + '（预期 401）');
  });

  // ---- 4. CAPTCHA challenge ----
  await test('POST /api/captcha/challenge 返回 challenge', async () => {
    const res = await fetchWithTimeout(BASE_URL + '/api/captcha/challenge', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ purpose: 'login' }),
    });
    assert(res.status === 200, 'HTTP ' + res.status);
    const data = await res.json();
    assert(data.success === true, 'success 不为 true');
    assert(data.challenge, '缺 challenge');
  });

  // ---- 5. Register 空数据 ----
  await test('POST /api/register 空数据返回 400', async () => {
    const res = await fetchWithTimeout(BASE_URL + '/api/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });
    assert(res.status === 400, 'HTTP ' + res.status + '（预期 400）');
  });

  // ---- 6. Login 空数据 ----
  await test('POST /api/login 空数据返回 400', async () => {
    const res = await fetchWithTimeout(BASE_URL + '/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });
    assert(res.status === 400, 'HTTP ' + res.status + '（预期 400）');
  });

  // ---- 7. OPTIONS ----
  await test('OPTIONS /api/login 返回 204', async () => {
    const res = await fetchWithTimeout(BASE_URL + '/api/login', { method: 'OPTIONS' });
    assert(res.status === 204, 'HTTP ' + res.status + '（预期 204）');
  });

  // ---- 8. CSRF 缺失测试（用新 jar）----
  await test('POST /api/login 无 CSRF 应 403', async () => {
    // 用不带 cookie 的裸 fetch 验证
    const res = await fetch(BASE_URL + '/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });
    assert(res.status === 403, 'HTTP ' + res.status + '（预期 403 CSRF 拦截）');
  });

  // ---- 9. CORS 收紧 ----
  await test('GET /api/health 的 ACAO 不是 *', async () => {
    const res = await fetchWithTimeout(BASE_URL + '/api/health');
    const acao = res.headers.get('access-control-allow-origin');
    assert(acao !== '*', 'ACAO 是 *（应改为固定同源）');
  });

  console.log('\n📊 测试结果：' + passed + ' 通过，' + failed + ' 失败\n');
  process.exit(failed === 0 ? 0 : 1);
})();
