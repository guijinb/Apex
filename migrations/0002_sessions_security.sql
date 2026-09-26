-- Session 安全字段（首次运行）
ALTER TABLE sessions ADD COLUMN last_seen_at TEXT;
