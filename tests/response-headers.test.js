// 响应头安全测试：确保 API 响应头不泄露内部信息
import { jsonResponse, errorResponse } from '../functions/_response.js';

let passed = 0;
let failed = 0;

function ok(cond, label) {
  if (cond) { passed++; console.log('  ✓ ' + label); }
  else { failed++; console.log('  ✗ ' + label); }
}

console.log('🧪 响应头安全测试\n');

// 1) jsonResponse 基础头
{
  const res = jsonResponse({ hello: 'world' }, 200, 'req-123');
  ok(res.headers.get('Content-Type') === 'application/json; charset=utf-8', 'Content-Type 正确');
  ok(res.headers.get('Cache-Control') === 'no-store', 'Cache-Control: no-store');
  ok(res.headers.get('X-Content-Type-Options') === 'nosniff', 'X-Content-Type-Options: nosniff');
  ok(res.headers.get('X-Request-ID') === 'req-123', 'X-Request-ID 注入');
}

// 2) errorResponse 默认信息
{
  const res = errorResponse();
  ok(res.status === 500, '默认状态码 500');
  const body = await res.json();
  ok(body.success === false, 'success: false');
  ok(body.message === '服务器内部错误，请稍后重试。', '默认消息不泄露内部细节');
  ok(body.code === 'internal_error', '默认 code 正确');
}

// 3) errorResponse 不泄露 stack
{
  const res = errorResponse('参数错误', 400, 'bad_request', 'req-456');
  const body = await res.json();
  ok(!('stack' in body), '响应体不含 stack');
  ok(!('error' in body), '响应体不含 error 对象');
  ok(body.request_id === 'req-456', 'request_id 正确');
}

// 4) 204 无 body
{
  const res = jsonResponse({}, 204, 'req-789');
  ok(res.status === 204, '204 状态');
  const text = await res.text();
  ok(text === '', '204 无 body');
}

// 5) 响应 JSON 可解析
{
  const res = jsonResponse({ success: true, data: { a: 1 } });
  const body = await res.json();
  ok(body.success === true && body.data.a === 1, 'JSON 序列化/反序列化一致');
}

console.log(`\n[结果] 通过 ${passed} / 失败 ${failed}`);
if (failed === 0) { console.log('\n✅ 响应头安全测试全部通过\n'); process.exit(0); }
console.log(`\n❌ ${failed} 个失败\n`);
process.exit(1);
