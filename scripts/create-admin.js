// 用法：node scripts/create-admin.js <username> <password> <role>
// 例：node scripts/create-admin.js admin MyP@ssw0rd123! super_admin

const username = process.argv[2];
const password = process.argv[3];
const role = process.argv[4] || 'super_admin';

if (!username || !password) {
  console.error('❌ 用法：node scripts/create-admin.js <username> <password> [role]');
  console.error('   role 可选：super_admin / admin / support / analyst / viewer');
  process.exit(1);
}

// 与服务器一致的哈希算法（v1:600000:salt:hash）
async function hashPassword(password) {
  const ITERATIONS = 600000;
  const encoder = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey(
    'raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']
  );
  const hash = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: ITERATIONS, hash: 'SHA-256' },
    keyMaterial, 256
  );
  const saltHex = Array.from(salt).map(b => b.toString(16).padStart(2, '0')).join('');
  const hashHex = Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
  return `v1:${ITERATIONS}:${saltHex}:${hashHex}`;
}

(async () => {
  const hash = await hashPassword(password);
  // 输出可直接用于 wrangler 的 SQL
  console.log(`INSERT INTO admin_users (username, password_hash, role) VALUES ('${username}', '${hash}', '${role}');`);
})();
