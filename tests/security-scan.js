// 安全扫描：检查代码中是否有硬编码敏感信息、危险 API 等
// 用法：node tests/security-scan.js

const fs = require('fs');
const path = require('path');

let issues = 0;

function scanFile(filePath) {
  const content = fs.readFileSync(filePath, 'utf8');
  const lines = content.split('\n');
  const issues_ = [];

  const dangerousPatterns = [
    { regex: /password\s*[:=]\s*['"][^'"]{3,}['"]/i, msg: '可疑的硬编码密码' },
    { regex: /api[_-]?key\s*[:=]\s*['"][^'"]{10,}['"]/i, msg: '可疑的硬编码 API Key' },
    { regex: /secret\s*[:=]\s*['"][^'"]{10,}['"]/i, msg: '可疑的硬编码 Secret' },
    { regex: /token\s*[:=]\s*['"][^'"]{20,}['"]/i, msg: '可疑的硬编码 Token' },
    { regex: /eval\s*\(/, msg: '使用了 eval（危险）' },
    { regex: /new\s+Function\s*\(/, msg: '使用了 new Function（危险）' },
    { regex: /document\.write\s*\(/, msg: '使用了 document.write（危险）' },
  ];

  // 白名单：跳过合理的场景
  const whitelist = [
    /placeholder/i,
    /password_hash/i,
    /type\s*=\s*['"]password['"]/i,
    /new-password/i,
    /password_resets/i,
    /password_updated/i,
    /\.password\b/i,
    /password\s*=/i,  // 变量赋值
    /verifyPassword/i,
    /hashPassword/i,
  ];

  lines.forEach((line, idx) => {
    if (whitelist.some(w => w.test(line))) return;
    dangerousPatterns.forEach(p => {
      if (p.regex.test(line)) {
        issues_.push({
          line: idx + 1,
          msg: p.msg,
          snippet: line.trim().substring(0, 80)
        });
      }
    });
  });

  return issues_;
}

function scanDir(dir) {
  const files = fs.readdirSync(dir);
  files.forEach(file => {
    if (file === 'node_modules' || file === '.git' || file.startsWith('.')) return;
    const full = path.join(dir, file);
    const stat = fs.statSync(full);
    if (stat.isDirectory()) {
      scanDir(full);
    } else if (file.endsWith('.js')) {
      const found = scanFile(full);
      if (found.length > 0) {
        console.log('\n📄 ' + full);
        found.forEach(i => {
          console.log('  ⚠️  Line ' + i.line + ': ' + i.msg);
          console.log('     ' + i.snippet);
          issues++;
        });
      }
    }
  });
}

console.log('🔍 安全扫描开始...\n');
scanDir('./functions');

if (issues === 0) {
  console.log('\n✅ 未发现可疑的硬编码敏感信息\n');
  process.exit(0);
} else {
  console.log('\n❌ 发现 ' + issues + ' 个潜在问题\n');
  process.exit(1);
}
