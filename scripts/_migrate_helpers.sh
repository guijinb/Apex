#!/data/data/com.termux/files/usr/bin/bash
# 迁移辅助函数（被 migrate.sh 引入）
# 关键：--local 模式优先使用 sqlite3 直连本地 D1 sqlite 文件，
# 绕开 Termux 下无法运行的 wrangler local。
set -uo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

detect_local_sqlite() {
  local d1dir="$PROJECT_ROOT/.wrangler/state/v3/d1"
  [ -d "$d1dir" ] || return 1
  local f
  f=$(find "$d1dir" -maxdepth 2 -type f -name "*.sqlite" 2>/dev/null | head -1)
  [ -n "$f" ] && echo "$f"
}

calc_checksum() {
  local file="$1"
  sha256sum "$file" | awk '{print substr($1,1,16)}'
}

list_migrations() {
  find "$PROJECT_ROOT/migrations" -maxdepth 1 -type f -name "*.sql" | sort
}

migration_version() {
  local file="$1"
  basename "$file" | sed -E 's/^([0-9]{4})_.*/\1/'
}

# 执行一条 SQL
run_sql_raw() {
  local mode="$1"
  local sql="$2"
  if [ "$mode" = "--remote" ]; then
    wrangler d1 execute apex-db --remote --command="$sql" --yes
    return $?
  fi
  local db
  db=$(detect_local_sqlite)
  if [ -n "$db" ] && command -v sqlite3 >/dev/null 2>&1; then
    sqlite3 "$db" "$sql"
    return $?
  fi
  wrangler d1 execute apex-db --local --command="$sql" --yes
}

# 执行一个 SQL 文件
run_sql_file() {
  local mode="$1"
  local file="$2"
  if [ "$mode" = "--remote" ]; then
    wrangler d1 execute apex-db --remote --file="$file" --yes
    return $?
  fi
  local db
  db=$(detect_local_sqlite)
  if [ -n "$db" ] && command -v sqlite3 >/dev/null 2>&1; then
    sqlite3 "$db" < "$file"
    return $?
  fi
  wrangler d1 execute apex-db --local --file="$file" --yes
}
