#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail
PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$PROJECT_ROOT/scripts/_migrate_helpers.sh"

MODE="--local"
[ "${1:-}" = "--remote" ] && MODE="--remote"

echo "[STATUS] mode=$MODE"
echo ""
echo "--- DB applied ---"
run_sql_raw "$MODE" "SELECT version || '  ' || name || '  ' || checksum || '  ' || applied_at FROM _migrations ORDER BY version;" 2>/dev/null || echo "(无记录)"
echo ""
echo "--- Files in migrations/ ---"
for f in $(list_migrations); do
  echo "$(basename "$f")  $(calc_checksum "$f")"
done
