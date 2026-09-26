// Apex 输入校验
// 规则：
//  - 密码校验为纯函数，返回 { valid, message }
//  - 前后端规则必须一致：前端镜像见 src/js/passwordPolicy.js，两者逻辑必须同步修改
//  - 后端为最终可信边界，前端校验仅为 UX 提示

export const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
export const USERNAME_RE = /^[a-zA-Z0-9_]{6,20}$/;
// 长度 8-128，至少含小写/大写/数字/特殊四类
export const STRONG_PASSWORD_RE = /^(?=.{12,128}$)(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]).*$/;

// 常见弱密码黑名单（小写比对）
const COMMON_PASSWORDS = new Set([
  // 基础
  'password', 'password1', 'password123', 'password1234', 'passw0rd', 'p@ssword', 'p@ssw0rd',
  'qwerty', 'qwerty123', 'qwerty1234', 'qwertyuiop', 'asdfghjkl', 'zxcvbnm', '1qaz2wsx', 'qazwsx',
  // 数字序列
  '12345678', '123456789', '1234567890', '87654321', '9876543210', '11111111', '00000000', '12121212',
  // 通用词
  'admin', 'admin123', 'administrator', 'root', 'toor', 'letmein', 'welcome', 'welcome1',
  'monkey', 'dragon', 'master', 'sunshine', 'princess', 'football', 'baseball', 'superman',
  'iloveyou', 'trustno1', 'abc12345', 'abc123456', 'abcd1234', 'a1b2c3d4', 'changeme',
  'secret', 'secret123', 'default', 'guest', 'test1234', 'testtest', 'temp1234',
  // 年份（易猜）
  '2024', '2025', '2026', 'password2024', 'password2025', 'password2026', 'admin2024', 'admin2025', 'admin2026',
]);

// 核心弱词：出现在归一化密码中即拒绝（子串匹配，长度 >= 6 避免误伤）
const CORE_WEAK_WORDS = ["password","qwerty","letmein","welcome","iloveyou","monkey","dragon","sunshine","princess","football","baseball","superman","trustno1","changeme","administrator","administrador","admin","guest","master","secret","root123","abc123"];

// 键盘行（用于检测键盘顺序）
const KEYBOARD_ROWS = [
  'qwertyuiop',
  'asdfghjkl',
  'zxcvbnm',
  '1234567890',
];

// 字母表与数字序列（正反）
const ALPHABET_FWD = 'abcdefghijklmnopqrstuvwxyz';
const ALPHABET_REV = 'zyxwvutsrqponmlkjihgfedcba';
const DIGITS_FWD   = '0123456789';
const DIGITS_REV   = '9876543210';

const ALPHABwET_FWD = 'abcdefghijklmnopqrstuvxyz';

function containsSequence(haystack, needles, minLen = 4) {
  const h = String(haystack || '').toLowerCase();
  for (const n of needles) {
    for (let i = 0; i + minLen <= n.length; i += 1) {
      if (h.includes(n.substring(i, i + minLen))) return true;
    }
  }
  return false;
}

function containsKeyboardRun(haystack, minLen = 4) {
  const h = String(haystack || '').toLowerCase();
  for (const row of KEYBOARD_ROWS) {
    const rev = row.split('').reverse().join('');
    for (const seq of [row, rev]) {
      for (let i = 0; i + minLen <= seq.length; i += 1) {
        if (h.includes(seq.substring(i, i + minLen))) return true;
      }
    }
  }
  return false;
}

// leet 归一化：把常见数字/符号替换映射回字母，用于"密码含账号名"检测时避免绕过
// 例如：@→a, 0→o, 1→i 或 l, 3→e, 4→a, 5→s, 7→t, 8→b, $→s, !→i
// 说明：数字 1 既可能是 i 也可能是 l，因此生成多个候选串进行匹配
function normalizeLeetCandidates(input) {
  const raw = String(input || '').toLowerCase();
  if (!raw) return [];
  const map1 = { '@': 'a', '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', '7': 't', '8': 'b', '$': 's', '!': 'i' };
  const map2 = { '1': 'l' };
  const candidates = new Set();
  let a = '';
  for (let i = 0; i < raw.length; i += 1) {
    const ch = raw[i];
    a += map1[ch] !== undefined ? map1[ch] : ch;
  }
  candidates.add(a);
  let b = '';
  for (let i = 0; i < raw.length; i += 1) {
    const ch = raw[i];
    b += map2[ch] !== undefined ? map2[ch] : (map1[ch] !== undefined ? map1[ch] : ch);
  }
  candidates.add(b);
  return Array.from(candidates);
}

// 提取 identifier 的有效 token（账号名或邮箱本地部分），用于「密码不能包含账号」检查
function identifierTokens(identifier) {
  const raw = String(identifier || '').trim().toLowerCase();
  if (!raw) return [];
  const tokens = new Set();
  tokens.add(raw);
  const at = raw.indexOf('@');
  if (at > 0) {
    tokens.add(raw.substring(0, at));
    const domain = raw.substring(at + 1);
    const domainHead = domain.split('.')[0];
    if (domainHead) tokens.add(domainHead);
  }
  // 过滤太短的 token（<3 位）避免误伤
  return Array.from(tokens).filter((t) => t.length >= 3);
}

export function sanitize(value, max = 200) {
  if (typeof value !== 'string') return '';
  return value.replace(/[<>"'`;\\]/g, '').trim().substring(0, max);
}

export function validateEmail(email) {
  return EMAIL_RE.test(String(email || '').trim());
}

export function validateUsername(username) {
  return USERNAME_RE.test(String(username || '').trim());
}

/**
 * 密码强度校验
 * @param {string} password
 * @param {string} identifier 账号名或邮箱（用于禁止密码包含账号）
 * @returns {{ valid: boolean, message: string }}
 */
export function validatePassword(password, identifier = '') {
  const value = String(password || '');

  // 1) 基础规则：长度 + 4 类字符
  if (!STRONG_PASSWORD_RE.test(value)) {
    return { valid: false, message: '密码需 12-128 位，含大小写字母、数字和特殊字符' };
  }

  // 2) 常见弱密码黑名单
  //    a) 精确匹配（含 leet 归一化候选）
  //    b) 子串匹配核心弱词（password、qwerty 等出现即拒）
  const commonCandidates = [value.toLowerCase()].concat(normalizeLeetCandidates(value));
  for (const cand of commonCandidates) {
    if (COMMON_PASSWORDS.has(cand)) {
      return { valid: false, message: '密码过于常见，请更换更安全的密码' };
    }
    for (const weak of CORE_WEAK_WORDS) {
      if (cand.includes(weak)) {
        return { valid: false, message: '密码包含常见弱词，请更换更安全的密码' };
      }
    }
  }

  // 3) 密码不能包含账号名 / 邮箱本地部分（含 leet 归一化候选）
  const tokens = identifierTokens(identifier);
  const normalizedPasswordCandidates = [value.toLowerCase()].concat(normalizeLeetCandidates(value));
  for (const t of tokens) {
    for (const cand of normalizedPasswordCandidates) {
      if (cand.includes(t)) {
        return { valid: false, message: '密码不能包含账号名或邮箱' };
      }
    }
  }

  // 4) 连续重复字符（4 个以上相同字符）
  if (/(.)\1{3,}/.test(value)) {
    return { valid: false, message: '密码不能包含 4 个以上连续重复字符' };
  }

  // 5) 连续字母 / 数字序列（如 abcd、1234、9876）
  if (containsSequence(value, [ALPHABET_FWD, ALPHABET_REV, DIGITS_FWD, DIGITS_REV], 4)) {
    return { valid: false, message: '密码不能包含连续字母或数字序列' };
  }

  // 6) 键盘顺序（qwer、asdf、1234 等）
  if (containsKeyboardRun(value, 4)) {
    return { valid: false, message: '密码不能包含键盘顺序（如 qwer、asdf）' };
  }

  return { valid: true, message: '' };
}

export async function parseJsonBody(request, maxBytes = 16384) {
  const contentLength = Number(request.headers.get('Content-Length') || 0);
  if (contentLength > maxBytes) {
    return { ok: false, status: 413, message: '请求体过大' };
  }
  try {
    const text = await request.text();
    if (text.length > maxBytes) return { ok: false, status: 413, message: '请求体过大' };
    const data = text ? JSON.parse(text) : {};
    return { ok: true, data };
  } catch {
    return { ok: false, status: 400, message: 'JSON 格式错误' };
  }
}
