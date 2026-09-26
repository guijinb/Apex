// API 冒烟测试：验证所有核心 API 端点正常响应
// 可在 GitHub Actions 或本地运行：node tests/api-smoke.test.js
// 用法：BASE_URL=https://apex-8rg.pages.dev node tests/api-smoke.test.js

const BASE_URL = process.env.BASE_URL || 'http://localhost:8788';

const FETCH_TIMEOUT_MS = Number(process.env.FETCH_TIMEOUT_MS || 8000);

async function fetchWithTimeout(url, options = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    return await fetchWithTimeout(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

let passed = 0;
let failed = 0;

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

function assert(condition, message) {
  if (!condition) throw new Error(message || 'Assertion failed');
}

(async () => {
  console.log('\n🧪 API 冒烟测试：' + BASE_URL + '\n');

  // 1. Health Check
  await test('GET /api/health 返回 200 且 db 正常', async () => {
    const res = await fetchWithTimeout(BASE_URL + '/api/health');
    assert(res.status === 200, 'HTTP ' + res.status);
    const data = await res.json();
    assert(data.success === true, 'success 不为 true');
    assert(data.checks && data.checks.db === 'ok', 'db 检查失败');
  });

  // 2. Ready Check
  await test('GET /api/ready 返回 200', async () => {
    const res = await fetchWithTimeout(BASE_URL + '/api/ready');
    assert(res.status === 200, 'HTTP ' + res.status);
    const data = await res.json();
    assert(data.ready === true, 'ready 不为 true');
  });

  // 3. 未授权访问 /api/me
  await test('GET /api/me 未登录返回 401', async () => {
    const res = await fetchWithTimeout(BASE_URL + '/api/me');
    assert(res.status === 401, 'HTTP ' + res.status + '（预期 401）');
  });

  // 4. Captcha Challenge
  await test('POST /api/captcha/challenge 返回 challenge', async () => {
    const res = await fetchWithTimeout(BASE_URL + '/api/captcha/challenge', { method: 'POST' });
    assert(res.status === 200, 'HTTP ' + res.status);
    const data = await res.json();
    assert(data.success === true, 'success 不为 true');
    assert(data.challenge, '缺少 challenge');
    assert(data.signature, '缺少 signature');
  });

  // 5. 注册接口参数校验（不带数据应返回 400）
  await test('POST /api/register 空数据返回 400', async () => {
    const res = await fetchWithTimeout(BASE_URL + '/api/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{}'
    });
    assert(res.status === 400 || res.status === 401 || res.status === 429, 'HTTP ' + res.status);
  });

  // 6. 登录接口参数校验
  await test('POST /api/login 空数据返回 400', async () => {
    const res = await fetchWithTimeout(BASE_URL + '/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{}'
    });
    assert(res.status === 400 || res.status === 401 || res.status === 429, 'HTTP ' + res.status);
  });

  // 7. CORS 预检
  await test('OPTIONS /api/login 返回 204', async () => {
    const res = await fetchWithTimeout(BASE_URL + '/api/login', { method: 'OPTIONS' });
    assert(res.status === 204, 'HTTP ' + res.status + '（预期 204）');
  });

  console.log('\n📊 测试结果：' + passed + ' 通过，' + failed + ' 失败\n');
  process.exit(failed > 0 ? 1 : 0);
})();
