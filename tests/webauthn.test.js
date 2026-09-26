// WebAuthn 核心单元测试
import {
  b64uEncode, b64uDecode, generateChallenge,
  parseAuthenticatorData, coseKeyToJwk, verifyEs256Signature,
  verifyClientData, sha256, buildSignatureBase,
  AUTH_FLAGS,
} from '../functions/_webauthn.js';
import { decodeCbor } from '../functions/_cbor.js';

let passed = 0, failed = 0;
function ok(cond, label) {
  if (cond) { passed++; console.log('  ✓ ' + label); }
  else { failed++; console.log('  ✗ ' + label); }
}
function eq(a, b, label) {
  const okv = JSON.stringify(a) === JSON.stringify(b);
  if (okv) { passed++; console.log('  ✓ ' + label); }
  else { failed++; console.log('  ✗ ' + label + '\n      得到: ' + JSON.stringify(a) + '\n      期望: ' + JSON.stringify(b)); }
}
function throws(fn, label) {
  try { fn(); failed++; console.log('  ✗ ' + label + ' (未抛错)'); }
  catch { passed++; console.log('  ✓ ' + label); }
}

console.log('🧪 WebAuthn 核心测试\n');

// ============ 1) base64url ============
console.log('【base64url】');
eq(b64uEncode(new Uint8Array([0x01, 0x02, 0x03])), 'AQID', 'encode [1,2,3]');
eq(b64uEncode(new Uint8Array([0xff, 0xfe, 0xfd])), '__79', 'encode [255,254,253]');
eq(Array.from(b64uDecode('AQID')), [1, 2, 3], 'decode AQID');
eq(Array.from(b64uDecode('__79')), [255, 254, 253], 'decode __79');
eq(Array.from(b64uDecode(b64uEncode(new Uint8Array([0, 1, 2, 250, 251, 252])))), [0, 1, 2, 250, 251, 252], 'roundtrip');

// ============ 2) generateChallenge ============
console.log('\n【generateChallenge】');
{
  const c1 = generateChallenge();
  const c2 = generateChallenge();
  ok(c1.length >= 40 && c1.length <= 48, 'challenge 长度 ~43 字符');
  ok(c1 !== c2, '两次生成不同');
  const bytes = b64uDecode(c1);
  eq(bytes.length, 32, '解码后 32 字节');
}

// ============ 3) parseAuthenticatorData ============
console.log('\n【parseAuthenticatorData】');
{
  // 最小 authData：32 + 1 + 4 = 37 字节，无 AT
  const minimal = new Uint8Array(37);
  minimal.fill(0xaa, 0, 32);   // rpIdHash
  minimal[32] = AUTH_FLAGS.UP; // flags: UP
  minimal[33] = 0; minimal[34] = 0; minimal[35] = 0; minimal[36] = 42; // signCount

  const parsed = parseAuthenticatorData(minimal);
  eq(parsed.signCount, 42, 'signCount = 42');
  eq(parsed.userPresent, true, 'userPresent = true');
  eq(parsed.userVerified, false, 'userVerified = false');
  eq(parsed.attestedDataIncluded, false, 'AT = false');
  eq(parsed.credentialId, null, 'credentialId = null');
}
{
  // 带 AT：37 + 16 (aaguid) + 2 (credIdLen) + 4 (credId) + COSE key bytes
  // 用一个假的 COSE key：[0xa0] (empty map, 1 byte)
  const withAt = new Uint8Array(37 + 16 + 2 + 4 + 1);
  withAt.fill(0xbb, 0, 32);
  withAt[32] = AUTH_FLAGS.UP | AUTH_FLAGS.UV | AUTH_FLAGS.AT;
  withAt[33] = 0; withAt[34] = 0; withAt[35] = 0; withAt[36] = 7;
  // aaguid 16 字节 0
  withAt[53] = 0; withAt[54] = 4; // credIdLen = 4
  withAt[55] = 0x01; withAt[56] = 0x02; withAt[57] = 0x03; withAt[58] = 0x04; // credId
  withAt[59] = 0xa0; // COSE: {}

  const parsed = parseAuthenticatorData(withAt);
  eq(parsed.signCount, 7, 'signCount = 7');
  eq(parsed.userPresent, true, 'UP');
  eq(parsed.userVerified, true, 'UV');
  eq(parsed.attestedDataIncluded, true, 'AT');
  eq(Array.from(parsed.credentialId), [1, 2, 3, 4], 'credentialId');
  eq(parsed.aaguid.length, 16, 'aaguid 16 bytes');
}
throws(() => parseAuthenticatorData(new Uint8Array(10)), '过短抛错');

// ============ 4) coseKeyToJwk ============
console.log('\n【coseKeyToJwk】');
{
  // 构造一个真实的 COSE key: {1: 2, 3: -7, -1: 1, -2: <32B>, -3: <32B>}
  const x = new Uint8Array(32); x.fill(0x01);
  const y = new Uint8Array(32); y.fill(0x02);
  const cose = { '1': 2, '3': -7, '-1': 1, '-2': x, '-3': y };
  const jwk = coseKeyToJwk(cose);
  eq(jwk.kty, 'EC', 'kty = EC');
  eq(jwk.crv, 'P-256', 'crv = P-256');
  ok(jwk.x.length > 0 && jwk.y.length > 0, 'x/y 存在');
}
throws(() => coseKeyToJwk({ '1': 3, '3': -7, '-1': 1 }), 'kty 非 EC 抛错');
throws(() => coseKeyToJwk({ '1': 2, '3': -8, '-1': 1 }), 'alg 非 ES256 抛错');
throws(() => coseKeyToJwk({ '1': 2, '3': -7, '-1': 2 }), 'crv 非 P-256 抛错');

// ============ 5) verifyEs256Signature（真实签名）============
console.log('\n【verifyEs256Signature】');
await (async () => {
  // 用 Node 生成一对 P-256 key，签一段数据，然后验证
  const keyPair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  );
  const jwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);

  const data = new TextEncoder().encode('hello webauthn apex');
  const sigBuf = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    keyPair.privateKey,
    data
  );
  const sig = new Uint8Array(sigBuf);

  // 用我们的函数验证
  const isValid = await verifyEs256Signature(jwk, sig, data);
  ok(isValid === true, '正确签名验证通过');

  // 篡改数据
  const tampered = new TextEncoder().encode('hello webauthn APEX');
  const isBad = await verifyEs256Signature(jwk, sig, tampered);
  ok(isBad === false, '篡改数据验证失败');
})();

// ============ 6) verifyClientData ============
console.log('\n【verifyClientData】');
{
  const cjson = JSON.stringify({
    type: 'webauthn.create',
    challenge: 'abc',
    origin: 'https://apex-8rg.pages.dev',
  });
  const r = verifyClientData(cjson, {
    expectedType: 'webauthn.create',
    expectedChallenge: 'abc',
    expectedOrigins: ['https://apex-8rg.pages.dev'],
  });
  eq(r.type, 'webauthn.create', '正确 clientData 通过');

  throws(() => verifyClientData(cjson, {
    expectedType: 'webauthn.get',
    expectedChallenge: 'abc',
    expectedOrigins: ['https://apex-8rg.pages.dev'],
  }), '错误 type 抛错');

  throws(() => verifyClientData(cjson, {
    expectedType: 'webauthn.create',
    expectedChallenge: 'XYZ',
    expectedOrigins: ['https://apex-8rg.pages.dev'],
  }), '错误 challenge 抛错');

  throws(() => verifyClientData(cjson, {
    expectedType: 'webauthn.create',
    expectedChallenge: 'abc',
    expectedOrigins: ['https://evil.com'],
  }), '错误 origin 抛错');

  throws(() => verifyClientData('not json', {
    expectedType: 'webauthn.create',
    expectedChallenge: 'abc',
    expectedOrigins: ['https://apex-8rg.pages.dev'],
  }), '非法 JSON 抛错');
}

// ============ 7) sha256 & buildSignatureBase ============
console.log('\n【sha256 / buildSignatureBase】');
await (async () => {
  const h = await sha256(new TextEncoder().encode('abc'));
  eq(h.length, 32, 'SHA-256 输出 32 字节');
  // 已知：SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
  const hex = Array.from(h).map((b) => b.toString(16).padStart(2, '0')).join('');
  eq(hex, 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad', 'SHA-256("abc") 已知向量');

  const authData = new Uint8Array([1, 2, 3]);
  const clientJson = '{"x":1}';
  const base = await buildSignatureBase(authData, clientJson);
  eq(base.length, 3 + 32, 'base 长度 = 3 + 32');
  eq(Array.from(base.slice(0, 3)), [1, 2, 3], 'base 前 3 字节 = authData');
})();

console.log(`\n[结果] 通过 ${passed} / 失败 ${failed}`);
if (failed === 0) { console.log('\n✅ WebAuthn 核心测试全部通过\n'); process.exit(0); }
console.log(`\n❌ ${failed} 个失败\n`); process.exit(1);
