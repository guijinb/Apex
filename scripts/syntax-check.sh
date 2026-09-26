#!/data/data/com.termux/files/usr/bin/bash
# Apex 全局 JS 语法检查
set -uo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_ROOT"

FAIL=0
COUNT=0

while IFS= read -r file; do
  COUNT=$((COUNT + 1))
  if node --check "$file" >/dev/null 2>&1; then
    echo "✅ $file"
  else
    echo "❌ $file"
    node --check "$file" || true
    FAIL=$((FAIL + 1))
  fi
done < <(find functions -type f -name "*.js" | sort)

echo ""
echo "[SUMMARY] checked=$COUNT failed=$FAIL"
[ "$FAIL" -eq 0 ]
