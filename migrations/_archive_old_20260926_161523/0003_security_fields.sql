-- 0003_security_fields.sql
-- 增加 rate_limit_buckets 表，用于并发安全的限流

CREATE TABLE IF NOT EXISTS rate_limit_buckets (
  bucket_key TEXT NOT NULL,
  action TEXT NOT NULL,
  window_start INTEGER NOT NULL,
  count INTEGER NOT NULL DEFAULT 0,
  expires_at TEXT NOT NULL,
  PRIMARY KEY (bucket_key, action, window_start)
);

CREATE INDEX IF NOT EXISTS idx_rate_limit_buckets_expires_at ON rate_limit_buckets(expires_at);
