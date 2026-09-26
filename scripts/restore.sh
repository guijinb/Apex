#!/data/data/com.termux/files/usr/bin/bash
# Apex D1 恢复脚本
# 用法：
#   bash scripts/restore.sh backups/apex-db-XXX.sql.gz --remote
#   bash scripts/restore.sh backups/apex-db-XXX.sql.gz --local
#
# 说明：
# - 会先校验 SHA256
# - 会先执行到临时数据库验证 SQL 可导入
# - 需手动加 --yes 才真正覆盖目标数据库

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GZ_FILE=""
MODE=""
CONFIRM=0

while [ $# -gt 0 ]; do
  case "$1" in
    --remote)
      MODE="--remote"; shift ;;
    --local)
      MODE="--local"; shift ;;
    --yes)
      CONFIRM=1; shift ;;
    *)
      GZ_FILE="$1"; shift ;;
  esac
done

if [ -z "$GZ_FILE" ] || [ ! -f "$GZ_FILE" ]; then
  echo "[ERROR] 请提供备份文件路径"
  exit 1
fi
if [ -z "$MODE" ]; then
  echo "[ERROR] 必须指定 --remote 或 --local"
  exit 1
fi

# 1) 校验 checksum
if [ -f "${GZ_FILE}.sha256" ]; then
  echo "[VERIFY] sha256"
  if ! sha256sum -c "${GZ_FILE}.sha256" >/dev/null 2>&1; then
    echo "[ERROR] SHA256 校验失败"
    exit 1
  fi
  echo "[OK] checksum"
fi

# 2) 解压到临时文件
TMP_SQL="$(mktemp)"
gunzip -c "$GZ_FILE" > "$TMP_SQL"
echo "[INFO] SQL 大小：$(wc -c < "$TMP_SQL") B"

# 3) 语法验证：导入临时 sqlite
if command -v sqlite3 >/dev/null 2>&1; then
  TMP_DB="$(mktemp)"
  if ! sqlite3 "$TMP_DB" < "$TMP_SQL"; then
    echo "[ERROR] SQL 无法导入临时数据库"
    rm -f "$TMP_DB" "$TMP_SQL"
    exit 1
  fi
  echo "[OK] SQL 语法验证通过"
  rm -f "$TMP_DB"
fi

if [ "$CONFIRM" -ne 1 ]; then
  echo "[WARN] 未指定 --yes，跳过真正导入"
  echo "       如需真正导入：bash scripts/restore.sh <file> $MODE --yes"
  rm -f "$TMP_SQL"
  exit 0
fi

# 4) 真正导入
echo "[RESTORE] $MODE"
if [ "$MODE" = "--remote" ]; then
  wrangler d1 execute apex-db --remote --file="$TMP_SQL" --yes
else
  wrangler d1 execute apex-db --local --file="$TMP_SQL" --yes
fi

rm -f "$TMP_SQL"
echo "[OK] 恢复完成"
