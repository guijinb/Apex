-- 0005_captcha_tokens.sql
-- 一次性 CAPTCHA Token 存储；与 IP hash + purpose 绑定，5 分钟过期

CREATE TABLE IF NOT EXISTS captcha_tokens (
  token_hash TEXT PRIMARY KEY,
  purpose TEXT NOT NULL,
  ip_hash TEXT NOT NULL,
  score INTEGER NOT NULL,
  expires_at TEXT NOT NULL,
  used_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_captcha_tokens_expires_at ON captcha_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_captcha_tokens_purpose ON captcha_tokens(purpose);
