// CBOR 解码器单元测试（WebAuthn 子集）
import { decodeCbor } from '../functions/_cbor.js';

let passed = 0, failed = 0;
// 深度规范化：Uint8Array → 普通数组，方便比较
function normalize(v) {
  if (v instanceof Uint8Array) return Array.from(v);
  if (Array.isArray(v)) return v.map(normalize);
  if (v && typeof v === 'object') {
    const out = {};
    for (const k of Object.keys(v)) out[k] = normalize(v[k]);
    return out;
  }
  return v;
}
function check(actual, expected, label) {
  const ok = JSON.stringify(normalize(actual)) === JSON.stringify(normalize(expected));
  if (ok) { passed++; console.log('  ✓ ' + label); }
  else { failed++; console.log('  ✗ ' + label + '\n      得到: ' + JSON.stringify(normalize(actual)) + '\n      期望: ' + JSON.stringify(normalize(expected))); }
}

console.log('🧪 CBOR 解码器测试\n');

// uint
check(decodeCbor(new Uint8Array([0x00])), 0, 'uint 0');
check(decodeCbor(new Uint8Array([0x0a])), 10, 'uint 10');
check(decodeCbor(new Uint8Array([0x17])), 23, 'uint 23');
check(decodeCbor(new Uint8Array([0x18, 0x18])), 24, 'uint 24 (1-byte)');
check(decodeCbor(new Uint8Array([0x18, 0xff])), 255, 'uint 255');
check(decodeCbor(new Uint8Array([0x19, 0x01, 0x00])), 256, 'uint 256 (2-byte)');

// negative
check(decodeCbor(new Uint8Array([0x20])), -1, 'neg -1');
check(decodeCbor(new Uint8Array([0x26])), -7, 'neg -7 (ES256 alg)');

// byte string
check(
  decodeCbor(new Uint8Array([0x43, 0x01, 0x02, 0x03])),
  [1, 2, 3],
  'bytes "010203" (Uint8Array → array on JSON.stringify)'
);

// text string
check(
  decodeCbor(new Uint8Array([0x64, 0x74, 0x65, 0x73, 0x74])),
  'test',
  'text "test"'
);

// array
check(
  decodeCbor(new Uint8Array([0x83, 0x01, 0x02, 0x03])),
  [1, 2, 3],
  'array [1,2,3]'
);

// map
check(
  decodeCbor(new Uint8Array([0xa2, 0x61, 0x61, 0x01, 0x61, 0x62, 0x02])),
  { a: 1, b: 2 },
  'map {a:1, b:2}'
);

// 嵌套：{"fmt":"none","authData":Uint8Array([1,2,3,4])}
const nested = new Uint8Array([
  0xa2,                            // map(2)
  0x63, 0x66, 0x6d, 0x74,          // text "fmt"
  0x64, 0x6e, 0x6f, 0x6e, 0x65,    // text "none"
  0x68, 0x61, 0x75, 0x74, 0x68, 0x44, 0x61, 0x74, 0x61,  // text "authData"
  0x44, 0x01, 0x02, 0x03, 0x04     // bytes(4) [1,2,3,4]
]);
check(
  decodeCbor(nested),
  { fmt: 'none', authData: [1, 2, 3, 4] },
  'nested map'
);

// 简单值
check(decodeCbor(new Uint8Array([0xf5])), true, 'true');
check(decodeCbor(new Uint8Array([0xf4])), false, 'false');
check(decodeCbor(new Uint8Array([0xf6])), null, 'null');

console.log(`\n[结果] 通过 ${passed} / 失败 ${failed}`);
if (failed === 0) { console.log('\n✅ CBOR 测试全部通过\n'); process.exit(0); }
console.log(`\n❌ ${failed} 个失败\n`); process.exit(1);
