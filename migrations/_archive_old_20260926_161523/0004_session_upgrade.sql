-- 0004_session_upgrade.sql
-- logs.request_id / logs.environment 已包含在 0001_initial.sql。
-- 旧库兼容升级由 scripts/upgrade_legacy.sh 处理，此迁移保持 no-op。

SELECT 1;
