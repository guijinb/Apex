// Apex 密码策略 —— 前端镜像
//
// ⚠️ 重要：本文件规则必须与 functions/_validation.js 严格一致。
// 修改任何一侧，必须同步另一侧，否则会出现「前端通过、后端拒绝」的 UX 断裂。
// 前端校验仅用于提升用户体验，后端才是可信边界。

(function () {
  'use strict';

  const STRONG_PASSWORD_RE = /^(?=.{12,128}$)(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]).*$/;

  const COMMON_PASSWORDS = new Set([
    'password', 'password1', 'password123', 'password1234', 'passw0rd', 'p@ssword', 'p@ssw0rd',
    'qwerty', 'qwerty123', 'qwerty1234', 'qwertyuiop', 'asdfghjkl', 'zxcvbnm', '1qaz2wsx', 'qazwsx',
    '12345678', '123456789', '1234567890', '87654321', '9876543210', '11111111', '00000000', '12121212',
    'admin', 'admin123', 'administrator', 'root', 'toor', 'letmein', 'welcome', 'welcome1',
    'monkey', 'dragon', 'master', 'sunshine', 'princess', 'football', 'baseball', 'superman',
    'iloveyou', 'trustno1', 'abc12345', 'abc123456', 'abcd1234', 'a1b2c3d4', 'changeme',
    'secret', 'secret123', 'default', 'guest', 'test1234', 'testtest', 'temp1234',
    '2024', '2025', '2026', 'password2024', 'password2025', 'password2026', 'admin2024', 'admin2025', 'admin2026',
  ]);

  // 核心弱词：出现在归一化密码中即拒绝（子串匹配，长度 >= 6 避免误伤）
  const CORE_WEAK_WORDS = ["password","qwerty","letmein","welcome","iloveyou","monkey","dragon","sunshine","princess","football","baseball","superman","trustno1","changeme","administrator","administrador","admin","guest","master","secret","root123","abc123"];

  const KEYBOARD_ROWS = [
    'qwertyuiop',
    'asdfghjkl',
    'zxcvbnm',
    '1234567890',
  ];

  const ALPHABET_FWD = 'abcdefghijklmnopqrstuvwxyz';
  const ALPHABET_REV = 'zyxwvutsrqponmlkjihgfedcba';
  const DIGITS_FWD   = '0123456789';
  const DIGITS_REV   = '9876543210';

  function containsSequence(haystack, needles, minLen) {
    const h = String(haystack || '').toLowerCase();
    for (let i = 0; i < needles.length; i += 1) {
      const n = needles[i];
      for (let j = 0; j + minLen <= n.length; j += 1) {
        if (h.indexOf(n.substring(j, j + minLen)) !== -1) return true;
      }
    }
    return false;
  }

  function containsKeyboardRun(haystack, minLen) {
    const h = String(haystack || '').toLowerCase();
    for (let i = 0; i < KEYBOARD_ROWS.length; i += 1) {
      const row = KEYBOARD_ROWS[i];
      const rev = row.split('').reverse().join('');
      const seqs = [row, rev];
      for (let k = 0; k < seqs.length; k += 1) {
        const seq = seqs[k];
        for (let j = 0; j + minLen <= seq.length; j += 1) {
          if (h.indexOf(seq.substring(j, j + minLen)) !== -1) return true;
        }
      }
    }
    return false;
  }

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

  function identifierTokens(identifier) {
    const raw = String(identifier || '').trim().toLowerCase();
    if (!raw) return [];
    const tokens = [raw];
    const at = raw.indexOf('@');
    if (at > 0) {
      tokens.push(raw.substring(0, at));
      const domain = raw.substring(at + 1);
      const head = domain.split('.')[0];
      if (head) tokens.push(head);
    }
    const seen = new Set();
    const out = [];
    for (let i = 0; i < tokens.length; i += 1) {
      const t = tokens[i];
      if (t.length >= 3 && !seen.has(t)) {
        seen.add(t);
        out.push(t);
      }
    }
    return out;
  }

  function validatePassword(password, identifier) {
    const value = String(password || '');

    if (!STRONG_PASSWORD_RE.test(value)) {
      return { valid: false, message: '密码需 12-128 位，含大小写字母、数字和特殊字符' };
    }
    const commonCandidates = [value.toLowerCase()].concat(normalizeLeetCandidates(value));
    for (let ci = 0; ci < commonCandidates.length; ci += 1) {
      const cand = commonCandidates[ci];
      if (COMMON_PASSWORDS.has(cand)) {
        return { valid: false, message: '密码过于常见，请更换更安全的密码' };
      }
      for (let wi = 0; wi < CORE_WEAK_WORDS.length; wi += 1) {
        if (cand.indexOf(CORE_WEAK_WORDS[wi]) !== -1) {
          return { valid: false, message: '密码包含常见弱词，请更换更安全的密码' };
        }
      }
    }
    const tokens = identifierTokens(identifier);
    const normalizedPasswordCandidates = [value.toLowerCase()].concat(normalizeLeetCandidates(value));
    for (let i = 0; i < tokens.length; i += 1) {
      for (let j = 0; j < normalizedPasswordCandidates.length; j += 1) {
        if (normalizedPasswordCandidates[j].indexOf(tokens[i]) !== -1) {
          return { valid: false, message: '密码不能包含账号名或邮箱' };
        }
      }
    }
    if (/(.)\1{3,}/.test(value)) {
      return { valid: false, message: '密码不能包含 4 个以上连续重复字符' };
    }
    if (containsSequence(value, [ALPHABET_FWD, ALPHABET_REV, DIGITS_FWD, DIGITS_REV], 4)) {
      return { valid: false, message: '密码不能包含连续字母或数字序列' };
    }
    if (containsKeyboardRun(value, 4)) {
      return { valid: false, message: '密码不能包含键盘顺序（如 qwer、asdf）' };
    }
    return { valid: true, message: '' };
  }

  // 强度评分：0-3（弱/中/强），用于 meter
  function scorePassword(password, identifier) {
    const r = validatePassword(password, identifier);
    if (r.valid) return { level: 3, message: r.message, valid: true };
    const v = String(password || '');
    if (!v) return { level: 0, message: '', valid: false };
    if (v.length >= 8) return { level: 2, message: r.message, valid: false };
    return { level: 1, message: r.message, valid: false };
  }

  window.ApexPasswordPolicy = {
    validatePassword: validatePassword,
    scorePassword: scorePassword,
    STRONG_PASSWORD_RE: STRONG_PASSWORD_RE,
  };
})();
