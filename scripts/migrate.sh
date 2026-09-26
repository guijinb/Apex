#!/data/data/com.termux/files/usr/bin/bash
# Apex 迁移系统
# 用法：bash scripts/migrate.sh [--local|--remote] [--dry-run]
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$PROJECT_ROOT/scripts/_migrate_helpers.sh"

MODE="--local"
DRY_RUN=0

for arg in "$@"; do
  case "$arg" in
    --remote) MODE="--remote" ;;
    --local)  MODE="--local" ;;
    --dry-run) DRY_RUN=1 ;;
    *) echo "[WARN] 未知参数: $arg" ;;
  esac
done

echo "[MIGRATE] mode=$MODE dry_run=$DRY_RUN"

# 1) 确保 _migrations 表存在
run_sql_raw "$MODE" "CREATE TABLE IF NOT EXISTS _migrations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  version TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  checksum TEXT NOT NULL,
  applied_at TEXT NOT NULL DEFAULT (datetime('now'))
);" >/dev/null 2>&1 || true
echo "[OK] _migrations 表已确认"

# 2) 载入已执行迁移
declare -A APPLIED
declare -A APPLIED_CHECKSUMS
while IFS='|' read -r v c; do
  v="$(echo "$v" | tr -d '[:space:]')"
  c="$(echo "$c" | tr -d '[:space:]')"
  if [ -n "$v" ]; then
    APPLIED["$v"]=1
    APPLIED_CHECKSUMS["$v"]="$c"
  fi
done < <(run_sql_raw "$MODE" "SELECT version || '|' || checksum FROM _migrations;" 2>/dev/null \
  | grep -E '^[0-9]{4}\|' || true)

APPLIED_COUNT=0
for _k in "${!APPLIED[@]}"; do APPLIED_COUNT=$((APPLIED_COUNT+1)); done
echo "[INFO] 已执行迁移数: $APPLIED_COUNT"

# 3) 遍历迁移
TOTAL=0
NEW_APPLIED=0
MISMATCH=0

apply_one() {
  local mode="$1"
  local f="$2"
  if [ "$mode" = "--remote" ]; then
    run_sql_file "$mode" "$f"
    return $?
  fi
  local db
  db=$(detect_local_sqlite)
  if [ -z "$db" ]; then
    echo "[ERROR] 本地 sqlite 未找到" >&2
    return 1
  fi
  if ! command -v node >/dev/null 2>&1; then
    echo "[ERROR] node 未安装" >&2
    return 1
  fi
  node "$PROJECT_ROOT/scripts/_sql_apply.cjs" "$f" "$db"
  return $?
}

for f in $(list_migrations); do
  TOTAL=$((TOTAL+1))
  v="$(migration_version "$f")"
  name="$(basename "$f")"
  ck="$(calc_checksum "$f")"

  if [ -n "${APPLIED[$v]:-}" ]; then
    prev="${APPLIED_CHECKSUMS[$v]:-}"
    if [ "$prev" != "$ck" ]; then
      echo "[MISMATCH] $name checksum 与已执行不一致 (db=$prev file=$ck)"
      MISMATCH=$((MISMATCH+1))
    else
      echo "[SKIP] $name 已执行"
    fi
    continue
  fi

  if [ "$DRY_RUN" -eq 1 ]; then
    echo "[DRY-RUN] 将执行 $name (checksum=$ck)"
    continue
  fi

  echo "[APPLY] $name"
  if ! apply_one "$MODE" "$f"; then
    echo "[ERROR] $name 执行失败"
    exit 1
  fi

  esc_name="${name//\'/\'\'}"
  run_sql_raw "$MODE" "INSERT INTO _migrations (version, name, checksum) VALUES ('$v', '$esc_name', '$ck');" >/dev/null 2>&1

  NEW_APPLIED=$((NEW_APPLIED+1))
  echo "[OK] $name applied"
done

echo ""
echo "[SUMMARY] total=$TOTAL applied=$NEW_APPLIED mismatch=$MISMATCH"

if [ "$MISMATCH" -gt 0 ]; then
  echo "[ERROR] 存在 checksum 不匹配，请人工排查"
  exit 2
fi
exit 0
