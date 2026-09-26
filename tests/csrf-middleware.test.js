// CSRF 中间件单元测试
// 使用纯 Node Web API（Request/Response/Headers/crypto）直接调用 onRequest
// 无需 dev server，CI 可跑
import { onRequest } from '../functions/_middleware.js';

let passed = 0;
let failed = 0;

function ok(cond, label) {
  if (cond) { passed++; console.log('  ✓ ' + label); }
  else { failed++; console.log('  ✗ ' + label); }
}

// 完整的 mock env（生产环境配置齐备）
const mockEnv = {
  ENVIRONMENT: 'development',  // 跳过 assertProductionConfig 严格检查
  CAPTCHA_SECRET: 'FAKE_FOR_TEST_ONLY_CAPTCHA_SECRET',
  PUBLIC_BASE_URL: 'https://example.com',
  EMAIL_FROM: 'noreply@example.invalid',
  RESEND_API_KEY: 'FAKE_FOR_TEST_ONLY_RESEND_KEY',
  apex_db: {
    prepare() {
      return { bind() { return this; }, first: async () => null, run: async () => ({}), all: async () => ({ results: [] }) };
    },
  },
};

async function runMiddleware(method, headers = {}) {
  const req = new Request('https://example.com/api/test', { method, headers });
  const ctx = {
    request: req,
    env: mockEnv,
    data: {},
    next: async () => new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    }),
  };
  return onRequest(ctx);
}

console.log('🧪 CSRF 中间件测试\n');

// 1) GET 无需 CSRF
{
  const res = await runMiddleware('GET');
  ok(res.status === 200, 'GET 请求放行（无需 CSRF）');
  ok(res.headers.get('X-Request-ID')?.startsWith('apx_'), 'GET 响应含 X-Request-ID');
  ok(res.headers.get('X-Frame-Options') === 'DENY', 'GET 响应含 X-Frame-Options');
  ok(res.headers.get('Strict-Transport-Security')?.includes('max-age=31536000'), 'GET 响应含 HSTS');
}

// 2) POST 无 CSRF → 403
{
  const res = await runMiddleware('POST');
  ok(res.status === 403, 'POST 无 CSRF token → 403');
  const body = await res.json();
  ok(body.code === 'csrf_invalid', 'POST 无 CSRF 返回 code=csrf_invalid');
}

// 3) POST cookie 与 header 一致 → 放行
{
  const token = 'a'.repeat(64);  // 64 个 a
  const res = await runMiddleware('POST', {
    'Cookie': `apex_csrf=${token}`,
    'X-CSRF-Token': token,
  });
  ok(res.status === 200, 'POST 带匹配 CSRF token → 放行');
}

// 4) POST cookie 与 header 不匹配 → 403
{
  const tokenA = 'a'.repeat(64);
  const tokenB = 'b'.repeat(64);
  const res = await runMiddleware('POST', {
    'Cookie': `apex_csrf=${tokenA}`,
    'X-CSRF-Token': tokenB,
  });
  ok(res.status === 403, 'POST 带不匹配 CSRF → 403');
}

// 5) 首次访问无 cookie → 403 但回 Set-Cookie 新 token
{
  const res = await runMiddleware('POST');
  ok(res.status === 403, '首次 POST 返回 403');
  const setCookie = res.headers.get('Set-Cookie');
  ok(Boolean(setCookie), '首次 POST 响应含 Set-Cookie（下发新 CSRF token）');
  ok(setCookie?.includes('apex_csrf='), 'Set-Cookie 含 apex_csrf');
}

// 6) DELETE 也需要 CSRF
{
  const res = await runMiddleware('DELETE');
  ok(res.status === 403, 'DELETE 无 CSRF → 403');
}

// 7) OPTIONS 放行（预检）
{
  const res = await runMiddleware('OPTIONS');
  ok(res.status === 200, 'OPTIONS 放行（无 CSRF）');
}

console.log(`\n[结果] 通过 ${passed} / 失败 ${failed}`);
if (failed === 0) { console.log('\n✅ CSRF 中间件测试全部通过\n'); process.exit(0); }
console.log(`\n❌ ${failed} 个失败\n`);
process.exit(1);
