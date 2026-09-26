#!/data/data/com.termux/files/usr/bin/bash
# Apex D1 备份脚本
# - 自动生成带时间戳的文件
# - 计算 SHA256
# - 可选 gzip 压缩
# - 支持 --remote / --local
# - 结果输出到 backups/

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MODE="--remote"
OUTPUT_DIR="$PROJECT_ROOT/backups"

while [ $# -gt 0 ]; do
  case "$1" in
    --remote)
      MODE="--remote"; shift ;;
    --local)
      MODE="--local"; shift ;;
    --output)
      OUTPUT_DIR="$2"; shift 2 ;;
    *)
      echo "[ERROR] 未知参数：$1"; exit 1 ;;
  esac
done

mkdir -p "$OUTPUT_DIR"

if ! command -v wrangler >/dev/null 2>&1; then
  echo "[ERROR] 未检测到 wrangler 命令"
  exit 1
fi

DATE=$(date +%Y%m%d_%H%M%S)
RAW_FILE="$OUTPUT_DIR/apex-db-${DATE}.sql"
GZ_FILE="${RAW_FILE}.gz"
SUM_FILE="${GZ_FILE}.sha256"

echo "[BACKUP] mode=$MODE output=$RAW_FILE"

if [ "$MODE" = "--remote" ]; then
  wrangler d1 export apex-db --remote --output="$RAW_FILE" --no-schema
else
  wrangler d1 export apex-db --local --output="$RAW_FILE" --no-schema
fi

if [ ! -f "$RAW_FILE" ]; then
  echo "[ERROR] 备份文件未生成：$RAW_FILE"
  exit 1
fi

SIZE=$(stat -c%s "$RAW_FILE" 2>/dev/null || wc -c < "$RAW_FILE")
if [ "$SIZE" -lt 100 ]; then
  echo "[ERROR] 备份文件过小（${SIZE}B），可能失败"
  rm -f "$RAW_FILE"
  exit 1
fi

gzip -f "$RAW_FILE"
sha256sum "$GZ_FILE" > "$SUM_FILE"

echo "[OK] $GZ_FILE ($SIZE B)"
echo "[OK] $SUM_FILE"

# 清理 30 天前的备份
find "$OUTPUT_DIR" -name "apex-db-*.sql.gz" -mtime +30 -delete 2>/dev/null || true
find "$OUTPUT_DIR" -name "apex-db-*.sql.gz.sha256" -mtime +30 -delete 2>/dev/null || true
