#!/data/data/com.termux/files/usr/bin/bash
# 校验最新备份是否可用
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BACKUP_DIR="${1:-$PROJECT_ROOT/backups}"

if [ ! -d "$BACKUP_DIR" ]; then
  echo "[ERROR] 备份目录不存在：$BACKUP_DIR"
  exit 1
fi

LATEST=$(ls -1t "$BACKUP_DIR"/apex-db-*.sql.gz 2>/dev/null | head -1)
if [ -z "$LATEST" ]; then
  echo "[ERROR] 未找到备份文件"
  exit 1
fi

echo "[LATEST] $LATEST"
echo "[SIZE] $(stat -c%s "$LATEST" 2>/dev/null || wc -c < "$LATEST") B"

if [ -f "${LATEST}.sha256" ]; then
  echo "[CHECKSUM]"
  if sha256sum -c "${LATEST}.sha256"; then
    echo "[OK] checksum 校验通过"
  else
    echo "[ERROR] checksum 校验失败"
    exit 1
  fi
fi

TMP_DB="$(mktemp)"
if gunzip -c "$LATEST" | sqlite3 "$TMP_DB" >/dev/null 2>&1; then
  echo "[OK] 备份可导入临时数据库"
else
  echo "[ERROR] 备份无法导入"
  rm -f "$TMP_DB"
  exit 1
fi

echo "[TABLES]"
sqlite3 "$TMP_DB" ".tables" | head -20

rm -f "$TMP_DB"
echo "[OK] 备份可用"
