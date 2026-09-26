-- 修复 captcha_tokens 表结构，与 _captcha.js issueToken 实际使用列对齐
--
-- 原表 (0001_captcha_tokens.sql) 存在以下问题：
--   1. 缺少 purpose 列（_captcha.js 写入）
--   2. 缺少 score 列（_captcha.js 写入）
--   3. action 列 NOT NULL 但代码从不传值
--
-- captcha_tokens 属于临时数据（5 分钟 TTL），重建无副作用。

DROP TABLE IF EXISTS captcha_tokens;

CREATE TABLE captcha_tokens (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  token_hash TEXT NOT NULL UNIQUE,
  purpose TEXT NOT NULL,
  ip_hash TEXT,
  score INTEGER NOT NULL DEFAULT 0,
  used_at TEXT,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_captcha_tokens_hash ON captcha_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_captcha_tokens_expires ON captcha_tokens(expires_at);
