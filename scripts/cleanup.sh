#!/data/data/com.termux/files/usr/bin/bash
# 清理过期数据：rate_limit_buckets / captcha_tokens / logs
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MODE="${1:---local}"

LOG_RETENTION_DAYS=90

run_sql() {
  if [ "$MODE" = "--remote" ]; then
    wrangler d1 execute apex-db --remote --command="$1" --yes >/dev/null
  else
    DB_PATH="$PROJECT_ROOT/.wrangler/state/v3/d1/miniflare-D1DatabaseObject/local.sqlite"
    sqlite3 "$DB_PATH" "$1"
  fi
}

echo "[CLEANUP] mode=$MODE"
run_sql "DELETE FROM rate_limit_buckets WHERE expires_at < datetime('now', '-1 hour');"
run_sql "DELETE FROM captcha_tokens WHERE expires_at < datetime('now', '-1 hour');"
run_sql "DELETE FROM logs WHERE created_at < datetime('now', '-${LOG_RETENTION_DAYS} days');"
run_sql "DELETE FROM sessions WHERE expires_at < datetime('now', '-7 days');"
echo "[OK]"
