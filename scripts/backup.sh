#!/data/data/com.termux/files/usr/bin/bash
# Apex D1 数据库备份脚本
# 用法：bash scripts/backup.sh

set -e

DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="backups"
BACKUP_FILE="${BACKUP_DIR}/apex-db-${DATE}.sql"

echo "🔄 开始备份 D1 数据库..."
echo "📅 时间：$(date)"

# 1. 导出数据库
wrangler d1 export apex-db --remote --output="${BACKUP_FILE}" --no-schema

# 2. 压缩
gzip "${BACKUP_FILE}"
COMPRESSED="${BACKUP_FILE}.gz"

# 3. 计算校验和
CHECKSUM=$(sha256sum "${COMPRESSED}" | awk '{print $1}')
echo "${CHECKSUM}  ${COMPRESSED}" > "${BACKUP_FILE}.sha256"

# 4. 记录元信息
SIZE=$(du -h "${COMPRESSED}" | awk '{print $1}')
echo "✅ 备份完成"
echo "📁 文件：${COMPRESSED}"
echo "📦 大小：${SIZE}"
echo "🔐 SHA256：${CHECKSUM}"

# 5. 清理 30 天前的备份
find "${BACKUP_DIR}" -name "*.sql.gz" -mtime +30 -delete
find "${BACKUP_DIR}" -name "*.sha256" -mtime +30 -delete

echo "🧹 已清理 30 天前的旧备份"
