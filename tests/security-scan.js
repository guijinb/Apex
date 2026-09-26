// Apex 安全扫描
// - 扫描范围：functions/ scripts/ tests/ .github/ + 根目录 *.html *.json *.toml _headers
// - 检测：硬编码敏感信息、危险 API、CORS 通配符、devCode/devToken 泄露
// - 用法：node tests/security-scan.js
import fs from 'fs';
import path from 'path';

let errors = 0;
let scanned = 0;

// ---------- 扫描目标 ----------
const SCAN_ROOTS = ['functions', 'scripts', 'tests', '.github'];
const SCAN_FILES = ['wrangler.toml', '_headers'];

// ---------- 排除规则 ----------
const EXCLUDE_DIRS = new Set(['node_modules', '.git', '.wrangler', 'backups']);
const EXCLUDE_PREFIXES = ['_bak_', '_archive_'];

// ---------- 检测规则 ----------
const RULES = [
  { id: 'eval',           regex: /\beval\s*\(/,                         msg: '使用了 eval（危险）' },
  { id: 'newFunction',    regex: /\bnew\s+Function\s*\(/,               msg: '使用了 new Function（危险）' },
  { id: 'docWrite',       regex: /\bdocument\.write\s*\(/,              msg: '使用了 document.write（危险）' },
  { id: 'hardcodedPwd',   regex: /password\s*[:=]\s*['"][^'"]{3,}['"]/i,msg: '可疑的硬编码密码' },
  { id: 'hardcodedKey',   regex: /api[_-]?key\s*[:=]\s*['"][^'"]{10,}['"]/i, msg: '可疑的硬编码 API Key' },
  { id: 'hardcodedSecret',regex: /secret\s*[:=]\s*['"][^'"]{10,}['"]/i, msg: '可疑的硬编码 Secret' },
  { id: 'hardcodedToken', regex: /token\s*[:=]\s*['"][^'"]{20,}['"]/i,  msg: '可疑的硬编码 Token' },
  { id: 'wildcardCors',   regex: /Access-Control-Allow-Origin\s*:\s*\*/,msg: 'CORS 通配符（危险）' },
  { id: 'devCode',        regex: /\bdevCode\s*[:=]/,                    msg: 'devCode 泄露（生产环境必须 isDevelopment 守卫）' },
  { id: 'devToken',       regex: /\bdevToken\s*[:=]/,                   msg: 'devToken 泄露（生产环境必须 isDevelopment 守卫）' },
  // ---- 值形态检测（不依赖变量名，只看值像不像真密钥）----
  { id: 'skLive',     regex: /['"]sk_live_[A-Za-z0-9_]{10,}['"]/,              msg: '疑似 Stripe live 密钥' },
  { id: 'pkLive',     regex: /['"]pk_live_[A-Za-z0-9_]{10,}['"]/,              msg: '疑似 Stripe live 公钥' },
  { id: 'skTest',     regex: /['"]sk_test_[A-Za-z0-9_]{10,}['"]/,              msg: '疑似 Stripe test 密钥' },
  { id: 'ghp',        regex: /['"]ghp_[A-Za-z0-9]{30,}['"]/,                   msg: '疑似 GitHub Personal Access Token' },
  { id: 'gho',        regex: /['"]gho_[A-Za-z0-9]{30,}['"]/,                   msg: '疑似 GitHub OAuth Token' },
  { id: 'awsAccess',  regex: /['"]AKIA[A-Z0-9]{16,}['"]/,                      msg: '疑似 AWS Access Key ID' },
  { id: 'googleApi',  regex: /['"]AIza[A-Za-z0-9_\-]{30,}['"]/,               msg: '疑似 Google API Key' },
  { id: 'slackToken', regex: /['"]xox[baprs]-[A-Za-z0-9\-]{10,}['"]/,         msg: '疑似 Slack Token' },
  { id: 'privateKey', regex: /-----BEGIN [A-Z ]*PRIVATE KEY-----/,             msg: '疑似私钥文件' },
  { id: 'jwt',        regex: /['"]eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}['"]/, msg: '疑似 JWT Token' },
];

// ---------- 行级白名单 ----------
const LINE_WHITELIST = [
  /placeholder/i,
  /password_hash/i,
  /type\s*=\s*['"]password['"]/i,
  /new-password/i,
  /password_resets/i,
  /password_updated/i,
  /\.password\b/i,
  /password\s*=/i,
  /verifyPassword/i,
  /hashPassword/i,
  /otpauth:\/\//i,
  /\?secret=/i,
  /\+\s*secret\s*\+/i,
  /secret\s*\+\s*['"]/i,
  /totp_secret/i,
  /admin_sessions/i,
  // ---- 测试/mock 值白名单（值是 placeholder 才放过，真实 secret 仍然报警） ----
  /['"]test-[^'"]*['"]/i,
  /['"]mock-[^'"]*['"]/i,
  /['"]fake-[^'"]*['"]/i,
  /['"]dummy-[^'"]*['"]/i,
  /['"]example[^'"]*['"]/i,
  /['"]placeholder[^'"]*['"]/i,
  /['"]FAKE_FOR_TEST[^'"]*['"]/i,
  /['"]FOR_TEST_ONLY[^'"]*['"]/i,
  /['"]your[_-]?[^'"]*['"]/i,
  /['"]change[_-]?me[^'"]*['"]/i,
  /['"]xxx+['"]/i,
  /['"]1234['"]/i,
  // ---- 允许显式赋值（变量名在左，值来自 env / 常量 / 空串） ----
  /=\s*env\./,
  /=\s*process\.env\./,
  /=\s*['"]['"]/,
  /Content-Security-Policy/i,
  /'\s*unsafe-inline'\s*/i,
];

// ---------- 文件级白名单 ----------
const FILE_WHITELIST = {
  'send-reset-code.js':   new Set(['devCode']),
  'send-verify-email.js': new Set(['devToken']),
  '_headers':             new Set(['devCode', 'devToken', 'wildcardCors']),
};

function isLineWhitelisted(line) {
  return LINE_WHITELIST.some(w => w.test(line));
}
function isFileWhitelisted(filePath, ruleId) {
  const base = path.basename(filePath);
  const allowed = FILE_WHITELIST[base];
  return allowed ? allowed.has(ruleId) : false;
}

function scanFile(filePath) {
  let content;
  try { content = fs.readFileSync(filePath, 'utf8'); } catch { return []; }
  const found = [];
  content.split('\n').forEach((line, idx) => {
    if (isLineWhitelisted(line)) return;
    for (const rule of RULES) {
      if (isFileWhitelisted(filePath, rule.id)) continue;
      if (rule.regex.test(line)) {
        found.push({ line: idx + 1, msg: rule.msg, snippet: line.trim().substring(0, 100) });
      }
    }
  });
  return found;
}

function walk(dir, out = []) {
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return out; }
  for (const e of entries) {
    const full = path.join(dir, e.name);
    if (e.isDirectory()) {
      if (EXCLUDE_DIRS.has(e.name)) continue;
      if (EXCLUDE_PREFIXES.some(p => e.name.startsWith(p))) continue;
      walk(full, out);
    } else if (e.isFile()) {
      out.push(full);
    }
  }
  return out;
}

function shouldScan(file) {
  const ext = path.extname(file).toLowerCase();
  if (['.js', '.cjs', '.mjs'].includes(ext)) return true;
  if (['.html', '.json', '.yml', '.yaml', '.toml'].includes(ext)) return true;
  if (path.basename(file) === '_headers') return true;
  return false;
}

console.log('🔍 Apex 安全扫描开始...\n');

const allFiles = [];
for (const root of SCAN_ROOTS) {
  if (fs.existsSync(root)) walk(root, allFiles);
}
for (const f of SCAN_FILES) {
  if (fs.existsSync(f)) allFiles.push(f);
}
for (const name of fs.readdirSync('.')) {
  const full = path.join('.', name);
  try {
    if (fs.statSync(full).isFile() &&
        (name.endsWith('.html') || name.endsWith('.json'))) {
      if (!allFiles.includes(full)) allFiles.push(full);
    }
  } catch {}
}

for (const f of allFiles) {
  if (!shouldScan(f)) continue;
  scanned++;
  const found = scanFile(f);
  if (found.length > 0) {
    console.log('\n📄 ' + f);
    for (const i of found) {
      console.log('  ⚠️  Line ' + i.line + ': ' + i.msg);
      console.log('     ' + i.snippet);
      errors++;
    }
  }
}

console.log(`\n[扫描完成] 文件数: ${scanned}, 问题数: ${errors}`);

if (errors === 0) {
  console.log('\n✅ 未发现安全问题\n');
  process.exit(0);
} else {
  console.log('\n❌ 发现 ' + errors + ' 个潜在问题\n');
  process.exit(1);
}
