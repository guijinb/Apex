-- 为 sessions.revoked_at 增加索引
-- 目的：让 cleanupExpiredSessions() 的批量清理更快
CREATE INDEX IF NOT EXISTS idx_sessions_revoked_at ON sessions(revoked_at);
