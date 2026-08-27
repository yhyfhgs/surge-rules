#!/bin/bash
# 一键更新规则集：提交 → 推送 → 清 jsDelivr 缓存 → 校验
# 用法: ./update.sh "提交说明"
set -e
cd "$(dirname "$0")"

echo "[pre-flight] 规则静态审计 + 全场景断言…"
python3 tests/audit.py --check all --fail-on P1 || { echo "审计未过，中止发布"; exit 1; }
python3 tests/runsuite.py || { echo "场景断言未过，中止发布"; exit 1; }

echo "[pre-flight] 重新生成 Clash 派生规则集 (clash/)…"
python3 surge2clash.py || { echo "Clash 转换失败，中止发布"; exit 1; }

git add -A
git diff --cached --quiet || git commit -m "${1:-update rules}"
git push origin main
echo "已推送: $(git rev-parse --short HEAD)"
files="$(ls *.list clash/*.list) clash/rule-providers.yaml"
fail=0
for f in $files; do
  curl -sS --max-time 30 "https://purge.jsdelivr.net/gh/yhyfhgs/surge-rules@main/$f" >/dev/null || fail=$((fail+1))
done
sleep 10
ok=0; n=0
for f in $files; do
  n=$((n+1))
  l=$(md5 -q "$f"); r=$(curl -sS --max-time 20 "https://cdn.jsdelivr.net/gh/yhyfhgs/surge-rules@main/$f" | md5 -q)
  [ "$l" = "$r" ] && ok=$((ok+1)) || echo "⚠ 未刷新: $f (CDN 边缘传播中, 稍后重跑本脚本或再等片刻)"
done
echo "CDN 一致性: $ok/$n — 完成后在 Surge「外部资源」/Clash Verge Rev「规则」页更新即可立即生效"
