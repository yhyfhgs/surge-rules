#!/bin/bash
# 一键更新规则集：闸门 → 转换 → 提交推送 → 增量刷新 jsDelivr → 校验
# 用法: ./update.sh "提交说明"
#   重跑（无新提交）= 补刷模式：只对 CDN 上仍为旧版的文件发 purge，已一致的自动跳过。
#
# 刷新策略（2026-08-30 重写，防触发 jsDelivr 路径级限流——同一路径高频 purge 会被
# throttled，限流期内 purge 被受理但不执行，实测重置窗口约 1 小时）：
#   1) 增量：只处理本次 push 实际变更的分发文件（git diff 计算），不再无条件全量 purge；
#   2) 先验后清：purge 前先比对 CDN md5，已一致的直接跳过，重跑不重复消耗配额；
#   3) 限流感知：解析 purge API 响应，被 throttled 的文件如实报告剩余秒数，不盲目重发；
#   4) 单轮执行，不内置重试循环——被限流的文件等提示的时间后重跑本脚本补刷，
#      或等 @main 别名缓存 ≤12h 自然过期（届时 Surge「外部资源」/Clash 手动更新即可）。
#   注：md5 比对经本机代理出口访问 CDN，多边缘 POP 轮换可能出现"已一致又变旧"的抽样
#   漂移，属最终一致性的正常现象，勿因此反复重跑。
set -e
cd "$(dirname "$0")"

echo "[pre-flight] 规则静态审计 + 全场景断言…"
python3 tests/audit.py --check all --fail-on P1 || { echo "审计未过，中止发布"; exit 1; }
python3 tests/runsuite.py || { echo "场景断言未过，中止发布"; exit 1; }

echo "[pre-flight] 重新生成 Clash 派生规则集 (clash/)…"
python3 tools/surge2clash.py || { echo "Clash 转换失败，中止发布"; exit 1; }

git add -A
git diff --cached --quiet || git commit -m "${1:-update rules}"
old=$(git rev-parse origin/main 2>/dev/null || echo "")
git push origin main
new=$(git rev-parse HEAD)
echo "已推送: $(git rev-parse --short HEAD)"

# ── 计算 purge 候选：新提交 → 仅变更的分发文件；重跑 → 全量（随后仍先验后清）──
all_files="$(ls lists/*.list clash/*.list) clash/rule-providers.yaml"
if [ -n "$old" ] && [ "$old" != "$new" ]; then
  candidates=$(git diff --name-only "$old" "$new" | grep -E '^(lists/[^/]+\.list|clash/([^/]+\.list|rule-providers\.yaml))$' || true)
  echo "[publish] 本次变更分发文件 $(echo "$candidates" | grep -c .) 个"
else
  candidates=$all_files
  echo "[publish] 无新提交（补刷模式）：全量先验后清"
fi
[ -z "$candidates" ] && { echo "无分发文件变更，无需刷新 CDN，完成"; exit 0; }

# ── 先验后清 + 限流感知 ──
purged=""; purge_n=0; throttled=0; max_reset=0; already=0
for f in $candidates; do
  [ -f "$f" ] || continue   # diff 里的删除项无需 purge（CDN 上 404 属预期）
  l=$(md5 -q "$f")
  r=$(curl -sS --max-time 20 "https://cdn.jsdelivr.net/gh/yhyfhgs/surge-rules@main/$f" | md5 -q || true)
  if [ "$l" = "$r" ]; then already=$((already+1)); continue; fi
  resp=$(curl -sS --max-time 30 "https://purge.jsdelivr.net/gh/yhyfhgs/surge-rules@main/$f" || true)
  t=$(echo "$resp" | python3 -c "
import json,sys
try:
    d=json.load(sys.stdin); p=list(d.get('paths',{}).values())
    print(p[0].get('throttlingReset',0) if p and p[0].get('throttled') else 0)
except Exception:
    print(0)")
  if [ "${t:-0}" -gt 0 ] 2>/dev/null; then
    throttled=$((throttled+1)); [ "$t" -gt "$max_reset" ] && max_reset=$t
    echo "  ⚠ 限流中: $f (重置 ${t}s)"
  else
    purged="$purged $f"; purge_n=$((purge_n+1))
  fi
done
echo "[publish] 已一致跳过 $already ｜ 发出 purge $purge_n ｜ 被限流 $throttled"

# ── 复验（只验本轮真正发过 purge 的文件）──
if [ "$purge_n" -gt 0 ]; then
  sleep 20
  ok=0
  for f in $purged; do
    l=$(md5 -q "$f"); r=$(curl -sS --max-time 20 "https://cdn.jsdelivr.net/gh/yhyfhgs/surge-rules@main/$f" | md5 -q || true)
    [ "$l" = "$r" ] && ok=$((ok+1)) || echo "  ⚠ 边缘传播中: $f（几分钟内收敛，勿立即重跑）"
  done
  echo "CDN 一致性(本轮 purge 对象): $ok/$purge_n"
fi
if [ "$throttled" -gt 0 ]; then
  echo "⚠ $throttled 个文件因限流未刷新：约 $((max_reset/60+1)) 分钟后重跑 ./update.sh 补刷（自动跳过已一致项），或等 @main ≤12h 自然过期"
fi
echo "完成 — Surge「外部资源」/Clash Verge Rev「规则」页更新即可生效"
