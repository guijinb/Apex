-- CAPTCHA 一次性 Token 存储
CREATE TABLE IF NOT EXISTS captcha_tokens (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  token_hash TEXT NOT NULL UNIQUE,
  action TEXT NOT NULL,
  ip_hash TEXT,
  used_at TEXT,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_captcha_tokens_hash ON captcha_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_captcha_tokens_expires ON captcha_tokens(expires_at);
