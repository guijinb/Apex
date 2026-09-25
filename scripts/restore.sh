#!/data/data/com.termux/files/usr/bin/bash
# Apex D1 数据库恢复脚本
# 用法：bash scripts/restore.sh backups/apex-db-20260101_120000.sql.gz

set -e

if [ -z "$1" ]; then
  echo "❌ 用法：bash scripts/restore.sh <备份文件.sql.gz>"
  echo ""
  echo "可用备份："
  ls -lh backups/*.sql.gz 2>/dev/null || echo "  （无备份文件）"
  exit 1
fi

BACKUP_FILE="$1"

if [ ! -f "$BACKUP_FILE" ]; then
  echo "❌ 文件不存在：${BACKUP_FILE}"
  exit 1
fi

# 1. 校验 SHA256（如果存在）
if [ -f "${BACKUP_FILE}.sha256" ]; then
  echo "🔐 校验文件完整性..."
  EXPECTED=$(cat "${BACKUP_FILE}.sha256" | awk '{print $1}')
  ACTUAL=$(sha256sum "${BACKUP_FILE}" | awk '{print $1}')
  if [ "$EXPECTED" != "$ACTUAL" ]; then
    echo "❌ 校验失败！备份文件已损坏"
    exit 1
  fi
  echo "✅ 校验通过"
fi

# 2. 解压到临时文件
TEMP_FILE="${BACKUP_FILE%.gz}"
echo "📂 解压中..."
gunzip -c "${BACKUP_FILE}" > "${TEMP_FILE}"

# 3. 恢复前二次确认
echo ""
echo "⚠️  即将恢复数据库，这会覆盖现有数据！"
echo "📁 备份文件：${BACKUP_FILE}"
read -p "确认恢复？(yes/no): " CONFIRM
if [ "$CONFIRM" != "yes" ]; then
  echo "❌ 已取消"
  rm -f "${TEMP_FILE}"
  exit 1
fi

# 4. 执行恢复
echo "🔄 恢复中..."
wrangler d1 execute apex-db --remote --file="${TEMP_FILE}"

# 5. 清理临时文件
rm -f "${TEMP_FILE}"

echo "✅ 恢复完成"
