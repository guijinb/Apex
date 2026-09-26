// Apex 密码策略单元测试（12 位起）
import { validatePassword } from '../functions/_validation.js';

let passed = 0, failed = 0;
function check(password, identifier, expected, label) {
  const r = validatePassword(password, identifier);
  const ok = r.valid === expected;
  if (ok) { passed++; console.log(`  ✓ ${label}`); }
  else {
    failed++;
    console.log(`  ✗ ${label}`);
    console.log(`      输入: "${password}" id="${identifier}"`);
    console.log(`      期望: valid=${expected}, 实际: valid=${r.valid} msg="${r.message}"`);
  }
}

console.log('🧪 密码策略测试（12 位起）\n');

console.log('【基础规则】');
check('Ab1!xy',          '', false, '拒绝 6 位');
check('Ab1!xyzwv',       '', false, '拒绝 9 位');
check('Ab1!xyzwvut',     '', false, '拒绝 11 位（差 1 位）');
check('Ab1!Zy9kM2pQ7w', '', true,  '通过 12 位最小长度');
check('Abcdefghijkl',    '', false, '拒绝缺少特殊字符');
check('abcdefghij1!x',   '', false, '拒绝缺少大写');
check('ABCDEFGHIJ1!X',   '', false, '拒绝缺少小写');
check('Abcdefghijk!x',   '', false, '拒绝缺少数字');
check('A'.repeat(200),   '', false, '拒绝超长（>128）');

console.log('\n【弱密码黑名单】');
check('password',        '', false, '拒绝 password');
check('password123',     '', false, '拒绝 password123');
check('P@ssw0rd',        '', false, '拒绝 P@ssw0rd');
check('P@ssw0rd123',     '', false, '拒绝 P@ssw0rd123（leet 归一化）');
check('Qwerty123456',    '', false, '拒绝 Qwerty123456');
check('Admin123456',     '', false, '拒绝 Admin123456');
check('Letmein1234',     '', false, '拒绝 Letmein1234');

console.log('\n【密码包含账号名】');
check('MyAl1ce!xyzQ9',   'alice',    false, '拒绝含账号名（leet 化 1）');
check('MyALICE1!xyz9',   'alice',    false, '拒绝含账号名（大小写不敏感）');
check('safePass1!xYz9',  'alice',    true,  '账号名无关则通过');
check('User1!xyzABc9p',  'user@example.com', false, '拒绝含邮箱本地部分 user');
check('Examp1e!abcXy9',  'user@example.com', false, '拒绝含邮箱域名头');
check('Uniq1!xyZab9Qw',  'user@example.com', true,  '邮箱无关则通过');

console.log('\n【连续重复字符】');
check('Abc1!aaaaXYZ9',   '', false, '拒绝 4 连相同字符');
check('Abc1!AAAxYz9Q',   '', true,  '3 连相同字符允许');

console.log('\n【字母 / 数字序列】');
check('Ab1!abcdXY9z',    '', false, '拒绝 abcd 正向字母序列');
check('Ab1!dcbaXY9z',    '', false, '拒绝 dcba 反向字母序列');
check('Ab1!1234Xy9z',    '', false, '拒绝 1234 正向数字序列');
check('Ab1!4321Xy9z',    '', false, '拒绝 4321 反向数字序列');
check('Ab1!Zy9kM2Qp',    '', true,  '无序列则通过');

console.log('\n【键盘顺序】');
check('Ab1!qwerXy9z',    '', false, '拒绝 qwer');
check('Ab1!rewqXy9z',    '', false, '拒绝 rewq（反向 qwer）');
check('Ab1!asdfXy9z',    '', false, '拒绝 asdf');
check('Ab1!zxcvXy9z',    '', false, '拒绝 zxcv');
check('Ab1!Mk7pQ9zW',    '', true,  '无键盘顺序则通过');

console.log(`\n[结果] 通过 ${passed} / 失败 ${failed}`);
if (failed === 0) { console.log('\n✅ 密码策略测试全部通过\n'); process.exit(0); }
console.log(`\n❌ ${failed} 个用例失败\n`); process.exit(1);
