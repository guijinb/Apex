#!/data/data/com.termux/files/usr/bin/bash
# Apex 数据库迁移工具
set -e

MIGRATIONS_DIR="migrations"
mkdir -p "$MIGRATIONS_DIR"

echo "🔄 数据库迁移检查"
echo "📁 迁移目录：$MIGRATIONS_DIR"
echo ""

if [ -z "$(ls -A $MIGRATIONS_DIR 2>/dev/null)" ]; then
  echo "⚠️  未找到迁移文件"
  exit 0
fi

echo "本地迁移文件："
ls -1 "$MIGRATIONS_DIR"/*.sql 2>/dev/null | while read f; do
  echo "  - $(basename $f)"
done

echo ""
echo "已应用："
wrangler d1 execute apex-db --remote --command "SELECT name, applied_at FROM migrations ORDER BY id;"
