// 逐语句应用 SQL 到 sqlite3，忽略 duplicate column name 错误
// 用法: node _sql_apply.js <sqlFile> <dbPath>
const fs = require('fs');
const { spawnSync } = require('child_process');

const [, , sqlFile, dbPath] = process.argv;
if (!sqlFile || !dbPath) {
  console.error('Usage: node _sql_apply.js <sqlFile> <dbPath>');
  process.exit(2);
}

let sql = fs.readFileSync(sqlFile, 'utf8');

// 去注释（保守：去掉整行 -- 注释和块注释）
sql = sql.replace(/\/\*[\s\S]*?\*\//g, '\n');
sql = sql.split('\n').map(line => {
  // 去掉行内 -- 后面内容（不处理字符串内，够用）
  const idx = line.indexOf('--');
  return idx >= 0 ? line.slice(0, idx) : line;
}).join('\n');

// 分句
const stmts = sql.split(';').map(s => s.trim()).filter(s => s.length > 0);

let ok = 0, skipped = 0, failed = 0;

for (const stmt of stmts) {
  const short = stmt.replace(/\s+/g, ' ').slice(0, 90);
  const r = spawnSync('sqlite3', [dbPath], { input: stmt + ';', encoding: 'utf8' });
  if (r.status === 0) {
    ok++;
    console.log('[OK] ' + short);
    continue;
  }
  const err = (r.stderr || '') + (r.stdout || '');
  if (/duplicate column name/i.test(err)) {
    skipped++;
    console.log('[SKIP-DUP] ' + short);
    continue;
  }
  failed++;
  console.error('[FAIL] ' + short);
  console.error(err.trim());
  process.exit(1);
}

console.log(`[STMT-SUMMARY] ok=${ok} skipped=${skipped} failed=${failed}`);
process.exit(0);
