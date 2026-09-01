#!/bin/bash
# Validate, derive Clash rules, push main, purge changed CDN paths, and verify md5.
# Status is one of VALIDATED_NOT_PUBLISHED, PUBLISHED_AND_VERIFIED, or
# PUBLISHED_BUT_UNVERIFIED. Only main may publish; every remote SHA is verified.
set -euo pipefail
cd "$(dirname "$0")"

REPO="yhyfhgs/surge-rules"
REF="main"
CDN_BASE="https://cdn.jsdelivr.net/gh/$REPO@$REF"
PURGE_BASE="https://purge.jsdelivr.net/gh/$REPO@$REF"
SURGE_APP_SUPPORT_ROOT="$(cd ../../.. && pwd)"
if grep -Eq '^[[:space:]]*geoip-maxmind-url[[:space:]]*=' ../Surge.conf; then
  SURGE_COUNTRY_DB_DEFAULT="$SURGE_APP_SUPPORT_ROOT/com.nssurge.surge-mac/GeoLite2-Country.mmdb"
else
  SURGE_COUNTRY_DB_DEFAULT="/Applications/Surge.app/Contents/Resources/GeoLite2-Country.mmdb"
fi
SURGE_COUNTRY_DB_PATH="${SURGE_COUNTRY_DB_PATH:-$SURGE_COUNTRY_DB_DEFAULT}"
SURGE_ASN_DB_PATH="${SURGE_ASN_DB_PATH:-/Applications/Surge.app/Contents/Resources/GeoLite2-ASN.mmdb}"
# Purge only published list/provider artifacts; modules and scripts are not
# production outputs and intentionally remain outside this candidate set.
DIST_RE='^(lists/[^/]+\.list|clash/([^/]+\.list|rule-providers\.yaml))$'
COMMIT_MSG="${1:-update rules}"

RUN_TMP="$(mktemp -d)"
cleanup() { rm -rf "$RUN_TMP"; }
trap cleanup EXIT

# ── 工具函数 ────────────────────────────────────────────────────────────────

# Fetch a CDN body and emit its md5; return 1 for transport/non-2xx failures.
# Keep the body on disk for an exact comparison and save the status in
# ``$RUN_TMP/cdn.code`` because callers invoke this function via substitution.
# A 404 means a new path is not published yet; other failures are actionable.
cdn_md5() {
  local body="$RUN_TMP/cdn.bin" code=""
  : > "$RUN_TMP/cdn.code"
  code=$(curl -sS --location --max-time 20 -o "$body" -w '%{http_code}' "$CDN_BASE/$1") || code=""
  printf '%s' "$code" > "$RUN_TMP/cdn.code"
  case "$code" in
    2??) md5 -q "$body"; return 0 ;;
  esac
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

# Purge one path → ok | throttled:<seconds> | bad:curl | bad:http<code>.
# Do not use --fail: parse the response body first so throttled remains visible.
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

# ── 0. 分支守卫（提交前）─────────────────────────────────────────────────────
branch=$(git rev-parse --abbrev-ref HEAD)
if [ "$branch" != "main" ]; then
  echo "✗ 当前分支为 '$branch'，本脚本只在 main 上发布。"
  echo "  原因：在别的分支提交却往 main 推，会出现「提交 A、推送 B、刷新 A」的错配。"
  echo "  处置：git switch main（或先把改动合入 main）后重跑，本次未做任何提交。"
  exit 1
fi

# ── 1. 发布闸门 ─────────────────────────────────────────────────────────────
echo "[pre-flight] ChinaIP 折叠漂移检查…"
if ! python3 tools/collapse_cidr.py lists/ChinaIP.list --check; then
  echo "✗ ChinaIP.list 未折叠（上游再生后须先跑 tools/collapse_cidr.py lists/ChinaIP.list），中止发布"; exit 1
fi

echo "[pre-flight] canonical routing manifest/profile check…"
if ! python3 tools/render_surge_rules.py --check ../Surge.conf; then
  echo "✗ Surge.conf [Rule] 与 config/routing.json 不一致，中止发布"; exit 1
fi

echo "[pre-flight] 规则静态审计 + 全场景断言…"
if ! python3 tests/analyze_rules_selftest.py; then
  echo "✗ 关系分析算法自检失败，中止发布"; exit 1
fi
if [ ! -r "$SURGE_COUNTRY_DB_PATH" ] || [ ! -r "$SURGE_ASN_DB_PATH" ]; then
  echo "✗ 缺少 Surge GeoLite2 Country/ASN 数据库，无法完成 IP 关系分析，中止发布"; exit 1
fi
if ! python3 tools/analyze_rules.py --out "$RUN_TMP/rule-analysis" --fail-on-shadow \
    --country-db "$SURGE_COUNTRY_DB_PATH" --asn-db "$SURGE_ASN_DB_PATH"; then
  echo "✗ 全量关系分析发现遮蔽或解析失败，中止发布"; exit 1
fi
if ! python3 tests/audit.py --check all --fail-on P1; then echo "✗ 审计未过，中止发布"; exit 1; fi
if ! python3 tests/runsuite.py; then echo "✗ 场景断言未过，中止发布"; exit 1; fi

echo "[pre-flight] 重新生成 Clash 派生规则集 (clash/)…"
if ! python3 tools/surge2clash.py; then echo "✗ Clash 转换失败，中止发布"; exit 1; fi

# ── 2. 发布基线 ─────────────────────────────────────────────────────────────
# Refresh origin/main for the incremental diff. A failed fetch only widens the
# candidate set; push plus the remote SHA check remains the publication gate.
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

# ── 3. 推送 + 远端 SHA 校验 ─────────────────────────────────────────────────
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

# ── 4. 计算 purge 候选 ───────────────────────────────────────────────────────
# New commit: diff-matched artifacts only. No new commit: full candidate set;
# both paths still verify before purging.
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

# ── 5. 先验后清 + 限流感知 ───────────────────────────────────────────────────
purge_sent=""       # 本轮真正发出 purge 且本地存在 → 需要复验
purge_n=0
already=0
deleted_ok=0
throttled_n=0;      throttled_files=""
purge_fail_n=0;     purge_fail_files=""
fetch_fail_pre_n=0; fetch_fail_pre_files=""
fetch_404_pre_files=""   # 先验失败中属"CDN 上尚无此路径"的子集（用于收尾文案分组）
resolved_pre_n=0;   resolved_pre_files=""   # 先验失败但复验一致 → 已从 problems 扣减
max_reset=0

for f in $live; do
  local_md5=$(md5 -q "$f")
  if remote_md5=$(cdn_md5 "$f"); then
    if [ "$local_md5" = "$remote_md5" ]; then
      already=$((already+1))
      continue
    fi
  else
    # Never treat a fetch failure as equality or silently ignore it: count it
    # and purge. A new path's expected 404 is cleared if post-purge md5 matches.
    fetch_fail_pre_n=$((fetch_fail_pre_n+1))
    fetch_fail_pre_files="$fetch_fail_pre_files $f"
    pre_code=$(cat "$RUN_TMP/cdn.code" 2>/dev/null || true)
    if [ "$pre_code" = "404" ]; then
      fetch_404_pre_files="$fetch_404_pre_files $f"
      echo "  ⚠ 先验 404: $f（CDN 尚无此路径，新增分发文件属预期；照常 purge，待复验裁决）"
    else
      echo "  ⚠ 先验拉取失败: $f（HTTP ${pre_code:-无响应}，按待刷新处理，照常 purge）"
    fi
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

# Deleted artifacts are purged without re-fetching; request failures still count.
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

# ── 6. 复验（只验本轮真正发过 purge 且本地存在的文件）───────────────────────
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
        # A preflight failure cleared by a matching post-purge md5 is success;
        # leave failures whose verification still fails in the final counts.
        case " $fetch_fail_pre_files " in
          *" $f "*)
            new_pre=""
            for g in $fetch_fail_pre_files; do
              if [ "$g" != "$f" ]; then new_pre="$new_pre $g"; fi
            done
            fetch_fail_pre_files="$new_pre"
            fetch_fail_pre_n=$((fetch_fail_pre_n-1))
            resolved_pre_n=$((resolved_pre_n+1))
            resolved_pre_files="$resolved_pre_files $f"
            ;;
        esac
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

# ── 7. 三态收尾 ─────────────────────────────────────────────────────────────
fetch_fail_n=$((fetch_fail_pre_n+fetch_fail_ver_n))
problems=$((throttled_n+purge_fail_n+fetch_fail_n+mismatch_n))

# Group unresolved preflight failures into expected 404s and network/5xx errors.
fetch_pre_404_n=0; fetch_pre_404_files=""
fetch_pre_net_n=0; fetch_pre_net_files=""
for f in $fetch_fail_pre_files; do
  case " $fetch_404_pre_files " in
    *" $f "*) fetch_pre_404_n=$((fetch_pre_404_n+1)); fetch_pre_404_files="$fetch_pre_404_files $f" ;;
    *)        fetch_pre_net_n=$((fetch_pre_net_n+1)); fetch_pre_net_files="$fetch_pre_net_files $f" ;;
  esac
done

echo
if [ "$problems" -eq 0 ]; then
  echo "STATUS: PUBLISHED_AND_VERIFIED — 已推送 $(git rev-parse --short HEAD)；候选 $targets_n（先验已一致 $already ｜ purge 后复验一致 $verify_ok ｜ 删除项 $deleted_ok）"
  if [ "$resolved_pre_n" -gt 0 ]; then
    echo "  · 其中 $resolved_pre_n 个文件先验拉取失败（新增分发文件的 404 属预期），purge 后复验一致，已按成功计："
    for f in $resolved_pre_files; do echo "      $f"; done
  fi
  echo "Surge「外部资源」/Clash Verge Rev「规则」页更新即可生效"
  exit 0
fi

wait_min=5
if [ "$max_reset" -gt 0 ]; then wait_min=$((max_reset/60+1)); fi

echo "STATUS: PUBLISHED_BUT_UNVERIFIED — 已推送 $(git rev-parse --short HEAD)，但本轮 CDN 刷新未获完整确认"
report_group "$mismatch_n"        "未验证 · 复验 md5 不一致（可能只是多 POP 最终一致性漂移）" "$mismatch_files"
report_group "$throttled_n"       "未验证 · 被 jsDelivr 限流，本轮未刷新"                     "$throttled_files"
report_group "$purge_fail_n"      "失败 · purge 请求未受理"                                   "$purge_fail_files"
report_group "$fetch_pre_404_n"   "未验证 · 先验 404（CDN 尚无此路径；新增文件属预期，但本轮未复验一致）" "$fetch_pre_404_files"
report_group "$fetch_pre_net_n"   "失败 · CDN 拉取失败（先验阶段，网络错/5xx，已按待刷新处理）" "$fetch_pre_net_files"
report_group "$fetch_fail_ver_n"  "失败 · CDN 拉取失败（复验阶段）"                           "$fetch_fail_ver_files"
echo "  处置：约 $wait_min 分钟后重跑 ./update.sh 补刷（幂等，先验后清会自动跳过已一致项）；"
echo "        或等 @main 别名缓存 ≤12h 自然过期，届时在 Surge「外部资源」/Clash Verge Rev「规则」页手动更新。"
exit 1
