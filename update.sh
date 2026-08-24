#!/bin/bash
# 一键更新规则集：提交 → 推送 → 清 jsDelivr 缓存 → 校验
# 用法: ./update.sh "提交说明"
set -e
cd "$(dirname "$0")"
git add -A
git diff --cached --quiet || git commit -m "${1:-update rules}"
git push origin main
echo "已推送: $(git rev-parse --short HEAD)"
fail=0
for f in *.list; do
  curl -sS --max-time 30 "https://purge.jsdelivr.net/gh/yhyfhgs/surge-rules@main/$f" >/dev/null || fail=$((fail+1))
done
sleep 10
ok=0
for f in *.list; do
  l=$(md5 -q "$f"); r=$(curl -sS --max-time 20 "https://cdn.jsdelivr.net/gh/yhyfhgs/surge-rules@main/$f" | md5 -q)
  [ "$l" = "$r" ] && ok=$((ok+1)) || echo "⚠ 未刷新: $f (CDN 边缘传播中, 稍后重跑本脚本或再等片刻)"
done
echo "CDN 一致性: $ok/$(ls *.list | wc -l | tr -d ' ') — 完成后在 Surge「外部资源」点全部更新即可立即生效"
