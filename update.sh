#!/bin/bash
# 一键发布规则集：闸门 → 派生 clash/ → commit → push HEAD:main → 增量 purge jsDelivr → md5 复验
# 用法: ./update.sh "提交说明"（默认 "update rules"）
#
# 三态结果 —— 收尾必打印 STATUS 行，退出码即结论，不要只看"完成"字样：
#   VALIDATED_NOT_PUBLISHED   闸门通过、推送已校验，但本轮无分发文件需刷新        → exit 0
#   PUBLISHED_AND_VERIFIED    已推送且远端 SHA 校验通过；本轮所有对象 md5 一致、
#                             无限流、无失败                                      → exit 0
#   PUBLISHED_BUT_UNVERIFIED  已推送，但存在限流 / purge 失败 / 拉取失败 /
#                             复验不一致中的任一项                                → exit 1
#
# 关键约束：
#   1) 分支守卫 —— 只允许在 main 上发布。旧版在任意分支 commit 却固定 push origin main，
#      再拿当前 HEAD 算 purge diff，会造成"提交 A、推送 B、刷新 A"。非 main 立即退出，
#      不做任何提交。
#   2) 推送校验 —— 显式 push HEAD:main；push 后 fetch 并比对 origin/main == HEAD，
#      不相等即判定未发布并退出，绝不带着未确认的远端状态往下走。
#   3) 增量 —— 只处理 git diff old..new 命中的分发文件（lists/*.list、clash/*.list、
#      clash/rule-providers.yaml）；无新提交时退化为全量候选（随后仍先验后清）。
#   4) 先验后清 —— purge 前比对本地/CDN md5，一致即跳过，重跑不重复消耗配额。
#      CDN 拉取失败既不算"已一致"也不算"已刷新"：计入 fetch_fail 并照常 purge（宁多勿漏）。
#   5) 删除项 —— diff 中已从本地删除的分发文件同样发 purge（跳过先验、不做复验，
#      预期 404），防旧内容滞留边缘缓存；purge 请求本身的成败照常计入统计。
#   6) 限流感知 —— 解析 purge API 的 paths.*.throttled / throttlingReset，如实报告剩余
#      秒数，本轮不重发。单轮执行不内置重试循环；等窗口过去后重跑本脚本即补刷（幂等）。
#   7) 复验不一致未必等于故障 —— md5 比对经本机代理出口访问 CDN，jsDelivr 多边缘 POP
#      轮换存在最终一致性漂移。但状态判定仍如实归入 UNVERIFIED：文案区分"未验证"与
#      "明确失败"，退出码同为 1。兜底是 @main 别名缓存 ≤12h 自然过期。
set -euo pipefail
cd "$(dirname "$0")"

REPO="yhyfhgs/surge-rules"
REF="main"
CDN_BASE="https://cdn.jsdelivr.net/gh/$REPO@$REF"
PURGE_BASE="https://purge.jsdelivr.net/gh/$REPO@$REF"
DIST_RE='^(lists/[^/]+\.list|clash/([^/]+\.list|rule-providers\.yaml))$'
COMMIT_MSG="${1:-update rules}"

RUN_TMP="$(mktemp -d)"
cleanup() { rm -rf "$RUN_TMP"; }
trap cleanup EXIT

# ── 工具函数 ──────────────────────────────────────────────────────────────────

# 拉取 CDN 内容并输出其 md5；失败 return 1 且不输出（调用方必须区分这两种结局）。
# 写临时文件而非管道给 md5：命令替换会吃掉尾部换行，直接比对会假不一致。
cdn_md5() {
  local body="$RUN_TMP/cdn.bin"
  if curl -sS --fail --location --max-time 20 -o "$body" "$CDN_BASE/$1"; then
    md5 -q "$body"
    return 0
  fi
  return 1
}

# 解析 purge 响应文件 → ok | throttled:<剩余秒> | bad
purge_parse() {
  python3 - "$1" <<'PY'
import json, sys, time
out = 'bad'
try:
    with open(sys.argv[1], 'rb') as fh:
        data = json.load(fh)
    paths = data.get('paths')
    if isinstance(paths, dict) and paths:
        entry = list(paths.values())[0]
        if isinstance(entry, dict):
            if entry.get('throttled'):
                try:
                    sec = int(entry.get('throttlingReset') or 0)
                except (TypeError, ValueError):
                    sec = 0
                # 该字段在不同版本可能是时长或 Unix 时间戳，统一折算成剩余秒数
                if sec > 1000000000:
                    sec -= int(time.time())
                out = 'throttled:%d' % (sec if sec > 0 else 0)
            else:
                out = 'ok'
except Exception:
    out = 'bad'
print(out)
PY
}

# 对单个路径发 purge → ok | throttled:<秒> | bad:curl | bad:http<code>
# 这里刻意不加 --fail：jsDelivr 限流是 HTTP 200 + throttled 字段，但即便某天改用非 2xx
# 返回，也要先让解析器看一眼响应体，能读出 throttled 就按限流报，读不出才算 purge 失败。
purge_one() {
  local resp="$RUN_TMP/purge.json"
  local code="" parsed=""
  : > "$resp"
  if ! code=$(curl -sS --location --max-time 30 -o "$resp" -w '%{http_code}' "$PURGE_BASE/$1"); then
    echo "bad:curl"
    return 0
  fi
  parsed=$(purge_parse "$resp")
  if [ "$parsed" = "bad" ]; then
    echo "bad:http$code"
  else
    echo "$parsed"
  fi
}

# 打印一类问题的计数与文件名；$1=计数 $2=标题 $3=空格分隔的文件列表
report_group() {
  local n="$1" title="$2" files="$3" f
  if [ "$n" -gt 0 ]; then
    echo "  · $title（$n）"
    for f in $files; do echo "      $f"; done
  fi
}

# ── 0. 分支守卫（任何提交动作之前）────────────────────────────────────────────
branch=$(git rev-parse --abbrev-ref HEAD)
if [ "$branch" != "main" ]; then
  echo "✗ 当前分支为 '$branch'，本脚本只在 main 上发布。"
  echo "  原因：在别的分支提交却往 main 推，会出现「提交 A、推送 B、刷新 A」的错配。"
  echo "  处置：git switch main（或先把改动合入 main）后重跑，本次未做任何提交。"
  exit 1
fi

# ── 1. 三道闸门 ───────────────────────────────────────────────────────────────
echo "[pre-flight] ChinaIP 折叠漂移检查…"
if ! python3 tools/collapse_cidr.py lists/ChinaIP.list --check; then
  echo "✗ ChinaIP.list 未折叠（上游再生后须先跑 tools/collapse_cidr.py lists/ChinaIP.list），中止发布"; exit 1
fi

echo "[pre-flight] 规则静态审计 + 全场景断言…"
if ! python3 tests/audit.py --check all --fail-on P1; then echo "✗ 审计未过，中止发布"; exit 1; fi
if ! python3 tests/runsuite.py; then echo "✗ 场景断言未过，中止发布"; exit 1; fi

echo "[pre-flight] 重新生成 Clash 派生规则集 (clash/)…"
if ! python3 tools/surge2clash.py; then echo "✗ Clash 转换失败，中止发布"; exit 1; fi

# ── 2. 发布基线 ───────────────────────────────────────────────────────────────
# 先刷新远端引用，让增量 diff 以 CDN 实际服务的版本为准。
# 预取失败不致命：origin/main 偏旧只会让 diff 变大（多 purge，安全方向）；
# 真正的门是下面的 push + 远端 SHA 校验。
if ! git fetch origin main --quiet; then
  echo "  ⚠ 预取 origin/main 失败，改用本地远端引用计算增量（候选可能偏多）"
fi
old=""
if git rev-parse --verify --quiet origin/main >/dev/null; then
  old=$(git rev-parse origin/main)
fi

git add -A
if git diff --cached --quiet; then
  echo "[publish] 工作区无变更，未产生新提交"
else
  git commit -m "$COMMIT_MSG"
fi
new=$(git rev-parse HEAD)

# ── 3. 推送 + 远端 SHA 校验 ───────────────────────────────────────────────────
echo "[publish] 推送 HEAD → origin/main …"
if ! git push origin HEAD:main; then
  echo "✗ push 失败：本轮未发布。本地提交已生成，修好网络/权限后重跑即可。"
  exit 1
fi
if ! git fetch origin main --quiet; then
  echo "✗ push 后 fetch origin main 失败：无法确认远端状态，按未发布处理。"
  exit 1
fi
remote=$(git rev-parse origin/main)
if [ "$remote" != "$new" ]; then
  echo "✗ 推送校验失败：origin/main=$(git rev-parse --short origin/main) ≠ HEAD=$(git rev-parse --short HEAD)"
  echo "  远端 main 不是本地已验证的提交，停止刷新 CDN（否则会刷出未发布的内容）。"
  exit 1
fi
echo "[publish] 已推送并校验: $(git rev-parse --short HEAD)"

# ── 4. 计算 purge 候选 ────────────────────────────────────────────────────────
# 新提交 → 仅 diff 命中的分发文件；无新提交（补刷模式）→ 全量候选，随后仍先验后清。
live=""      # 本地存在：先验 md5 → 需要则 purge → 复验
gone=""      # 本地已删除：跳过先验，直接 purge，不复验（预期 404）
live_n=0
gone_n=0

if [ -n "$old" ] && [ "$old" != "$new" ]; then
  diff_out=$(git diff --name-only "$old" "$new")
  changed=""
  grep_rc=0
  changed=$(printf '%s\n' "$diff_out" | grep -E "$DIST_RE") || grep_rc=$?
  if [ "$grep_rc" -gt 1 ]; then
    echo "✗ 解析 git diff 输出失败（grep 退出码 $grep_rc），中止"
    exit 1
  fi
  for f in $changed; do
    if [ -f "$f" ]; then
      live="$live $f"; live_n=$((live_n+1))
    else
      gone="$gone $f"; gone_n=$((gone_n+1))
    fi
  done
  echo "[publish] 本次变更分发文件 $((live_n+gone_n)) 个（现存 $live_n ｜ 已删除 $gone_n）"
else
  for f in lists/*.list clash/*.list clash/rule-providers.yaml; do
    if [ -f "$f" ]; then live="$live $f"; live_n=$((live_n+1)); fi
  done
  echo "[publish] 无新提交（补刷模式）：全量 $live_n 个候选，先验后清"
fi

targets_n=$((live_n+gone_n))
if [ "$targets_n" -eq 0 ]; then
  echo
  echo "STATUS: VALIDATED_NOT_PUBLISHED — 闸门通过、推送已校验，但无分发文件变更，无需刷新 CDN"
  exit 0
fi

# ── 5. 先验后清 + 限流感知 ────────────────────────────────────────────────────
purge_sent=""       # 本轮真正发出 purge 且本地存在 → 需要复验
purge_n=0
already=0
deleted_ok=0
throttled_n=0;      throttled_files=""
purge_fail_n=0;     purge_fail_files=""
fetch_fail_pre_n=0; fetch_fail_pre_files=""
max_reset=0

for f in $live; do
  local_md5=$(md5 -q "$f")
  if remote_md5=$(cdn_md5 "$f"); then
    if [ "$local_md5" = "$remote_md5" ]; then
      already=$((already+1))
      continue
    fi
  else
    # 拉取失败（网络错/404/5xx）：不得当成"已一致"，也不得静默当成"不一致"。
    # 计入 fetch_fail，同时把该文件当作待 purge 处理——宁多 purge 不漏。
    fetch_fail_pre_n=$((fetch_fail_pre_n+1))
    fetch_fail_pre_files="$fetch_fail_pre_files $f"
    echo "  ⚠ 先验拉取失败: $f（按待刷新处理，照常 purge）"
  fi

  res=$(purge_one "$f")
  case "$res" in
    ok)
      purge_sent="$purge_sent $f"; purge_n=$((purge_n+1))
      ;;
    throttled:*)
      t=${res#throttled:}; t=${t:-0}
      throttled_n=$((throttled_n+1)); throttled_files="$throttled_files $f"
      if [ "$t" -gt "$max_reset" ]; then max_reset=$t; fi
      echo "  ⚠ 限流中: $f（重置 ${t}s，本轮未刷新）"
      ;;
    *)
      purge_fail_n=$((purge_fail_n+1)); purge_fail_files="$purge_fail_files $f"
      echo "  ✗ purge 未受理: $f（$res）"
      ;;
  esac
done

# 删除项：只发 purge，不复验（CDN 上 404 属预期），但请求成败照常计入统计。
for f in $gone; do
  res=$(purge_one "$f")
  case "$res" in
    ok)
      deleted_ok=$((deleted_ok+1))
      echo "  ✓ 删除项已发出 purge: $f"
      ;;
    throttled:*)
      t=${res#throttled:}; t=${t:-0}
      throttled_n=$((throttled_n+1)); throttled_files="$throttled_files $f"
      if [ "$t" -gt "$max_reset" ]; then max_reset=$t; fi
      echo "  ⚠ 限流中(删除项): $f（重置 ${t}s，本轮未刷新）"
      ;;
    *)
      purge_fail_n=$((purge_fail_n+1)); purge_fail_files="$purge_fail_files $f"
      echo "  ✗ purge 未受理(删除项): $f（$res）"
      ;;
  esac
done

echo "[publish] 已一致跳过 $already ｜ 发出 purge $purge_n ｜ 删除项 purge $deleted_ok ｜ 被限流 $throttled_n ｜ purge 失败 $purge_fail_n ｜ 先验拉取失败 $fetch_fail_pre_n"

# ── 6. 复验（只验本轮真正发过 purge 且本地存在的文件）─────────────────────────
verify_ok=0
mismatch_n=0;       mismatch_files=""
fetch_fail_ver_n=0; fetch_fail_ver_files=""

if [ "$purge_n" -gt 0 ]; then
  echo "[verify] 等待边缘传播 20s…"
  sleep 20
  for f in $purge_sent; do
    if [ ! -f "$f" ]; then continue; fi
    local_md5=$(md5 -q "$f")
    if remote_md5=$(cdn_md5 "$f"); then
      if [ "$local_md5" = "$remote_md5" ]; then
        verify_ok=$((verify_ok+1))
      else
        mismatch_n=$((mismatch_n+1)); mismatch_files="$mismatch_files $f"
        echo "  ⚠ 复验不一致: $f"
      fi
    else
      fetch_fail_ver_n=$((fetch_fail_ver_n+1)); fetch_fail_ver_files="$fetch_fail_ver_files $f"
      echo "  ✗ 复验拉取失败: $f"
    fi
  done
  echo "[verify] CDN 一致性（本轮 purge 对象）: $verify_ok/$purge_n"
fi

# ── 7. 三态收尾 ───────────────────────────────────────────────────────────────
fetch_fail_n=$((fetch_fail_pre_n+fetch_fail_ver_n))
problems=$((throttled_n+purge_fail_n+fetch_fail_n+mismatch_n))

echo
if [ "$problems" -eq 0 ]; then
  echo "STATUS: PUBLISHED_AND_VERIFIED — 已推送 $(git rev-parse --short HEAD)；候选 $targets_n（先验已一致 $already ｜ purge 后复验一致 $verify_ok ｜ 删除项 $deleted_ok）"
  echo "Surge「外部资源」/Clash Verge Rev「规则」页更新即可生效"
  exit 0
fi

wait_min=5
if [ "$max_reset" -gt 0 ]; then wait_min=$((max_reset/60+1)); fi

echo "STATUS: PUBLISHED_BUT_UNVERIFIED — 已推送 $(git rev-parse --short HEAD)，但本轮 CDN 刷新未获完整确认"
report_group "$mismatch_n"        "未验证 · 复验 md5 不一致（可能只是多 POP 最终一致性漂移）" "$mismatch_files"
report_group "$throttled_n"       "未验证 · 被 jsDelivr 限流，本轮未刷新"                     "$throttled_files"
report_group "$purge_fail_n"      "失败 · purge 请求未受理"                                   "$purge_fail_files"
report_group "$fetch_fail_pre_n"  "失败 · CDN 拉取失败（先验阶段，已按待刷新处理）"           "$fetch_fail_pre_files"
report_group "$fetch_fail_ver_n"  "失败 · CDN 拉取失败（复验阶段）"                           "$fetch_fail_ver_files"
echo "  处置：约 $wait_min 分钟后重跑 ./update.sh 补刷（幂等，先验后清会自动跳过已一致项）；"
echo "        或等 @main 别名缓存 ≤12h 自然过期，届时在 Surge「外部资源」/Clash Verge Rev「规则」页手动更新。"
exit 1
