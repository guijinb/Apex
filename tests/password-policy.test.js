// Apex 密码策略单元测试
// 覆盖：长度/字符类/黑名单/账号名/连续重复/字母序列/数字序列/键盘顺序
// 用法：node tests/password-policy.test.js
import { validatePassword } from '../functions/_validation.js';

let passed = 0;
let failed = 0;

function check(password, identifier, expected, label) {
  const r = validatePassword(password, identifier);
  const ok = r.valid === expected;
  if (ok) {
    passed++;
    console.log(`  ✓ ${label}`);
  } else {
    failed++;
    console.log(`  ✗ ${label}`);
    console.log(`      输入: "${password}" id="${identifier}"`);
    console.log(`      期望: valid=${expected}, 实际: valid=${r.valid} msg="${r.message}"`);
  }
}

console.log('🧪 密码策略测试开始...\n');

console.log('【基础规则】');
check('Ab1!',           '', false, '拒绝过短（4 位）');
check('Ab1!Xy9z',       '', true,  '通过 8 位最小长度');
check('Ab3!Kp9z',       '', true,  '通过基础 8 位');
check('Abcdefg1',       '', false, '拒绝缺少特殊字符');
check('abcdefg1!',      '', false, '拒绝缺少大写');
check('ABCDEFG1!',      '', false, '拒绝缺少小写');
check('Abcdefgh!',      '', false, '拒绝缺少数字');
check('A'.repeat(200) + 'b1!', '', false, '拒绝超长（>128）');

console.log('\n【常见弱密码黑名单】');
check('password',       '', false, '拒绝 password');
check('password123',    '', false, '拒绝 password123');
check('P@ssw0rd',       '', false, '拒绝 P@ssw0rd');
check('Qwerty123',      '', false, '拒绝 Qwerty123');
check('Admin123',       '', false, '拒绝 Admin123');
check('12345678',       '', false, '拒绝 12345678');
check('Letmein1!',      '', false, '拒绝 Letmein1!');

console.log('\n【密码包含账号名】');
check('MyAl1ce!a',      'alice',    false, '拒绝含账号名 alice');
check('MyALICE1!',      'alice',    false, '拒绝含账号名（大小写不敏感）');
check('Myalice1!x',     'alice',    false, '拒绝含账号名前缀');
check('safePass1!xY',   'alice',    true,  '账号名无关则通过');
check('User1!xyzAB',    'user@example.com', false, '拒绝含邮箱本地部分');
check('Examp1e!abc',    'user@example.com', false, '拒绝含邮箱域名头');
check('Uniq1!xyZab',    'user@example.com', true,  '邮箱无关则通过');

console.log('\n【连续重复字符】');
check('Abc1!aaaa',      '', false, '拒绝 4 连相同字符');
check('Abc1!AAA',       '', true,  '3 连相同字符允许');
check('Ab1!111111111',  '', false, '拒绝长串相同数字（同时命中数字序列）');

console.log('\n【字母 / 数字序列】');
check('Ab1!abcd',       '', false, '拒绝 abcd 正向字母序列');
check('Ab1!dcba',       '', false, '拒绝 dcba 反向字母序列');
check('Ab1!1234',       '', false, '拒绝 1234 正向数字序列');
check('Ab1!4321',       '', false, '拒绝 4321 反向数字序列');
check('Ab1!Zy9k',       '', true,  '无序列则通过');

console.log('\n【键盘顺序】');
check('Ab1!qwer',       '', false, '拒绝 qwer');
check('Ab1!rewq',       '', false, '拒绝 rewq（反向 qwer）');
check('Ab1!asdf',       '', false, '拒绝 asdf');
check('Ab1!zxcv',       '', false, '拒绝 zxcv');
check('Ab1!Mk7p',       '', true,  '无键盘顺序则通过');

console.log(`\n[结果] 通过 ${passed} / 失败 ${failed}`);

if (failed === 0) {
  console.log('\n✅ 密码策略测试全部通过\n');
  process.exit(0);
} else {
  console.log(`\n❌ ${failed} 个用例失败\n`);
  process.exit(1);
}
