#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Derive Clash/Mihomo classical rule sets from Surge lists.

``lists/*.list`` is the single editing layer; ``clash/`` is generated and
must not be hand-edited. Paths are resolved from this script, so it can be
invoked from the repository root or another working directory.

The generation is transactional:
1. Parse every manifest source and aggregate unknown types before touching
   ``clash/``.
2. Render every artifact in a temporary directory.
3. Atomically replace changed files (same-directory ``os.replace``), leave
   byte-identical files untouched, and remove stale generated lists.
4. ``--check`` performs steps 1–2 and reports drift without writing files.

Supported rule parameters, including ``no-resolve``, are passed through.
Trailing comments are removed only after ``" #"`` and with the same delimiter
as the semantic engine; leading comment lines are kept. ``USER-AGENT`` and
``URL-REGEX`` are omitted because Mihomo has no matching layer. Unknown types
fail with the complete list.

Outputs are one classical file per manifest source plus
``rule-providers.yaml`` in manifest order, including policy and ``no-resolve``
markers. Exit 0 means success (or no drift under ``--check``), 1 means drift,
and 2 means input/validation failure; failed validation never modifies
``clash/``.
"""
import argparse
import difflib
import io
import os
import shutil
import sys
import tempfile
import time

from routing_manifest import load_routing_manifest

# Resolve repository paths from this file; do not hard-code an absolute root.
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES_DIR = os.path.join(REPO_ROOT, "lists")
OUT_DIR = os.path.join(REPO_ROOT, "clash")
ROUTING_MANIFEST = os.path.join(REPO_ROOT, "config", "routing.json")
CDN_BASE = "https://cdn.jsdelivr.net/gh/yhyfhgs/surge-rules@main/clash"
PROVIDERS_NAME = "rule-providers.yaml"

PASSTHROUGH = {
    "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-WILDCARD",
    "IP-CIDR", "IP-CIDR6", "GEOIP", "IP-ASN", "PROCESS-NAME",
}
DROP = {"USER-AGENT", "URL-REGEX"}


def strip_trailing_comment(s):
    """Return stripped rule text after removing only a space-delimited comment.

    Keep this delimiter aligned with ``tests/engine.py``: bare ``#`` and tab
    delimiters remain rule text, and callers use this only for passthrough types.
    """
    idx = s.find(" #")
    if idx >= 0:
        s = s[:idx]
    return s.strip()

# ── 解析校验 ────────────────────────────────────────────────────────────────
def convert_file(name):
    """解析单个 .list，返回 (输出行列表, 有效规则数, {类型: 剔除数}, 未知类型清单)。

    未知类型不再就地退出：收集成 (name, lineno, rtype) 三元组交给调用方汇总，
    保证「一次运行报全所有问题」而不是修一条跑一次。
    """
    dropped = {}
    unknown = []
    kept = 0
    body = []
    src = os.path.join(RULES_DIR, name)
    with io.open(src, "r", encoding="utf-8") as f:
        for lineno, raw in enumerate(f, 1):
            line = raw.rstrip("\n")
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                body.append(line)
                continue
            rtype = stripped.split(",", 1)[0].strip().upper()
            if rtype in PASSTHROUGH:
                # 行尾注释（如 `,no-resolve  # note`）必须在这里
                # 剥掉：Mihomo 不识别行尾注释，会连注释一起当规则参数解析。
                body.append(strip_trailing_comment(stripped))
                kept += 1
            elif rtype in DROP:
                dropped[rtype] = dropped.get(rtype, 0) + 1
            else:
                unknown.append((name, lineno, rtype))
    return body, kept, dropped, unknown


# ── 渲染产物（纯函数，不落盘）───────────────────────────────────────────────
def render_list(name, body, dropped):
    header = [
        "# AUTO-GENERATED — Clash(Mihomo) classical 规则，由 ../lists/%s 派生" % name,
        "# 勿手工编辑；修改 Surge 源后运行 python3 tools/surge2clash.py 重新生成",
    ]
    if dropped:
        detail = ", ".join("%s x %d" % (k, v) for k, v in sorted(dropped.items()))
        header.append("# 已剔除 Clash 不支持的规则: %s" % detail)
    header.append("")
    return "\n".join(header + body).rstrip("\n") + "\n"


def render_providers(routing):
    extended_count = sum(bool(entry.get("extended_matching")) for entry in routing)
    lines = [
        "# AUTO-GENERATED — Clash Verge Rev 规则集配置（由 tools/surge2clash.py 生成，勿手工编辑）",
        "# 用法：在 Clash Verge Rev 中对订阅配置使用「Merge」扩展，粘贴本文件的",
        "# rule-providers 段；再参照文末注释的 rules 序列接入你自己的策略组。",
        "# 各 provider 与 Surge 同名 .list 一一对应，优先级语义见仓库 README。",
        "#",
        "# ─── sniffer 合同（消费端必须履约）───────────────────────────────────────",
        "# Surge 侧有 %d 张表在 conf 的 RULE-SET 行上开了 extended-matching（含 Payment /" % extended_count,
        "# AI / Telegram），让规则除域名外**同时匹配 SNI / Host 等扩展信息**，从而接住",
        "# 「客户端拿着字面量 IP 直连、但握手里带了域名」的连接。",
        "#",
        "# 这个开关**provider 携带不了**：它不是规则行上的参数，而是整张表的匹配语义，",
        "# rule-provider 只承载规则集本身，无处安放它。Clash / Mihomo 侧要取回等价行为，",
        "# **使用者必须在自己的 config 里显式开启 sniffer**，至少嗅探 TLS SNI 与 HTTP Host",
        "# （QUIC 亦建议开启，否则 HTTP/3 连接同样拿不到 hostname）。",
        "#",
        "# 不配 sniffer **不会报任何错**，只会在上述连接上静默漏匹配：hostname 丢失后，",
        "# 该连接会跳过全部域名规则，落到 IP 规则或最终的 MATCH 上 —— 这是本派生层最容易",
        "# 被忽略的一处能力差。",
        "#",
        "# 参考最小配置（放在你自己的 config 顶层，不属于本文件的 Merge 内容）：",
        "#   sniffer:",
        "#     enable: true",
        "#     sniff:",
        "#       HTTP:  { ports: [80, 8080-8880], override-destination: true }",
        "#       TLS:   { ports: [443, 8443] }",
        "#       QUIC:  { ports: [443, 8443] }",
        "#",
        "# 与它并列的已知能力差另有两条：Surge 内建 SYSTEM 集在 Clash 端无等价物；",
        "# 内建 LAN 集用 GEOIP,lan 近似。三条都是已知且刻意的取舍，不是 bug。",
        "# 合同的书面落点有两处：本注释与 docs/ARCHITECTURE.md 的 Clash derivation，改一处必须同步另一处。",
        "# ────────────────────────────────────────────────────────────────────────",
        "",
        "rule-providers:",
    ]
    for entry in routing:
        stem = entry["name"]
        name = stem + ".list"
        lines += [
            "  %s:" % stem,
            "    type: http",
            "    behavior: classical",
            "    format: text",
            "    url: %s/%s" % (CDN_BASE, name),
            "    path: ./rule-sets/surge-rules/%s" % name,
            "    interval: 86400",
        ]
    lines += [
        "",
        "# ─── rules 参考序列（与 Surge.conf [Rule] 区逐行同序；取消注释并替换为你的策略组名）───",
        "# Surge 内置 SYSTEM 集无 Clash 等价物（近似：本机常见系统域自行按需补充）；",
        "# LAN 集的近似前置规则（置于最前）：",
        "#  - GEOIP,lan,DIRECT,no-resolve",
        "# rules:",
    ]
    for entry in routing:
        suffix = ",no-resolve" if entry.get("no_resolve") else ""
        lines.append("#  - RULE-SET,%s,%s%s"
                     % (entry["name"], entry["policy"], suffix))
    lines += [
        "#  - GEOIP,CN,DIRECT,no-resolve",
        "#  - MATCH,Final",
    ]
    return "\n".join(lines) + "\n"


def build_all():
    """Parse and render all manifest sources without touching formal ``clash/``.

    Unknown types are aggregated and fail with exit 2 before any formal output.
    """
    try:
        routing = load_routing_manifest(ROUTING_MANIFEST, RULES_DIR)
    except ValueError as exc:
        sys.stderr.write("%s\n" % exc)
        raise SystemExit(2)
    names = [entry["name"] + ".list" for entry in routing]

    artifacts = {}
    unknown_all = []
    total_kept, total_dropped = 0, {}
    for name in names:
        body, kept, dropped, unknown = convert_file(name)
        unknown_all += unknown
        if unknown:
            continue  # 该表已判失败，无需渲染
        artifacts[name] = render_list(name, body, dropped)
        total_kept += kept
        for k, v in dropped.items():
            total_dropped[k] = total_dropped.get(k, 0) + v

    if unknown_all:
        sys.stderr.write("未知规则类型 %d 处 —— 请在 surge2clash.py 的 PASSTHROUGH/DROP 中"
                         "显式登记后再发布（正式 clash/ 未被修改）：\n" % len(unknown_all))
        for name, lineno, rtype in unknown_all:
            sys.stderr.write("  %s:%d  %s\n" % (name, lineno, rtype))
        types = sorted({t for _, _, t in unknown_all})
        sys.stderr.write("涉及类型：%s\n" % ", ".join(types))
        raise SystemExit(2)

    artifacts[PROVIDERS_NAME] = render_providers(routing)
    return artifacts, len(names), total_kept, total_dropped


def stage(artifacts):
    """Write all artifacts to a system temp directory; the caller removes it."""
    stage_dir = tempfile.mkdtemp(prefix="surge2clash-stage-")
    for name, text in artifacts.items():
        with io.open(os.path.join(stage_dir, name), "w", encoding="utf-8") as f:
            f.write(text)
    return stage_dir


# ── 比对与提交 ──────────────────────────────────────────────────────────────
def read_existing(name):
    """Read an existing artifact as bytes, or return ``None`` if absent."""
    path = os.path.join(OUT_DIR, name)
    if not os.path.isfile(path):
        return None
    with open(path, "rb") as f:
        return f.read()


def stale_files(artifacts):
    """Return generated lists left behind after a source was removed or renamed."""
    if not os.path.isdir(OUT_DIR):
        return []
    return sorted(f for f in os.listdir(OUT_DIR)
                  if f.endswith(".list") and f not in artifacts)


def line_delta(old_text, new_text):
    """返回 (新增行数, 删除行数)，用于漂移摘要。"""
    diff = difflib.unified_diff(old_text.splitlines(), new_text.splitlines(), n=0, lineterm="")
    added = removed = 0
    for line in diff:
        if line.startswith("+++") or line.startswith("---") or line.startswith("@@"):
            continue
        if line.startswith("+"):
            added += 1
        elif line.startswith("-"):
            removed += 1
    return added, removed


def compare(stage_dir, artifacts):
    """Compare staged bytes with formal output; return created, changed, and stale."""
    created, changed = [], []
    for name in sorted(artifacts):
        with open(os.path.join(stage_dir, name), "rb") as f:
            new = f.read()
        old = read_existing(name)
        if old is None:
            created.append(name)
        elif old != new:
            added, removed = line_delta(old.decode("utf-8", "replace"),
                                        new.decode("utf-8", "replace"))
            changed.append((name, added, removed))
    return created, changed, stale_files(artifacts)


def sweep_orphan_temps():
    """Remove same-directory temp files older than one hour, preserving live runs."""
    if not os.path.isdir(OUT_DIR):
        return
    cutoff = time.time() - 3600
    for f in os.listdir(OUT_DIR):
        if not (f.startswith(".") and f.endswith(".tmp")):
            continue
        path = os.path.join(OUT_DIR, f)
        try:
            if os.path.isfile(path) and os.path.getmtime(path) < cutoff:
                os.remove(path)
        except OSError:
            pass


def commit(stage_dir, artifacts):
    """Atomically install changed artifacts, skip identical files, and remove stale lists.

    Same-directory ``os.replace`` ensures readers see a complete old or new file.
    """
    created, changed, stale = compare(stage_dir, artifacts)
    if not os.path.isdir(OUT_DIR):
        os.makedirs(OUT_DIR)
    sweep_orphan_temps()
    for name in created + [c[0] for c in changed]:
        tmp = os.path.join(OUT_DIR, ".%s.%d.tmp" % (name, os.getpid()))
        try:
            shutil.copyfile(os.path.join(stage_dir, name), tmp)
            os.replace(tmp, os.path.join(OUT_DIR, name))
        finally:
            if os.path.exists(tmp):
                os.remove(tmp)
    for name in stale:
        os.remove(os.path.join(OUT_DIR, name))
    return created, changed, stale


def report_drift(created, changed, stale):
    """打印漂移摘要（--check 用），返回漂移文件总数。"""
    for name in created:
        print("  + %-24s 缺失，应新增" % name)
    for name, added, removed in changed:
        print("  ~ %-24s +%d -%d" % (name, added, removed))
    for name in stale:
        print("  - %-24s 陈旧，应删除" % name)
    return len(created) + len(changed) + len(stale)


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="从 lists/*.list 事务式派生 clash/ 规则集（无参数=重建；--check=只比对）")
    ap.add_argument("--check", action="store_true",
                    help="只比对「按当前 lists/ 应生成的产物」与现有 clash/，"
                         "打印漂移摘要；不写任何正式文件（0=一致，1=漂移）")
    args = ap.parse_args(argv)

    artifacts, n_lists, total_kept, total_dropped = build_all()
    drop_note = ("；剔除 " + ", ".join("%s x %d" % (k, v) for k, v in sorted(total_dropped.items()))
                 if total_dropped else "")

    if args.check:
        # Build the same staged bytes as a write, but never modify formal output.
        stage_dir = stage(artifacts)
        try:
            created, changed, stale = compare(stage_dir, artifacts)
        finally:
            shutil.rmtree(stage_dir, ignore_errors=True)
        if not (created or changed or stale):
            print("clash/ 与 lists/ 一致：%d 个列表，%d 条规则%s" % (n_lists, total_kept, drop_note))
            return 0
        print("clash/ 已漂移（需重新运行 python3 tools/surge2clash.py）：")
        n = report_drift(created, changed, stale)
        print("漂移文件 %d 个；正式目录未被修改。" % n)
        return 1

    stage_dir = stage(artifacts)
    try:
        created, changed, stale = commit(stage_dir, artifacts)
    finally:
        shutil.rmtree(stage_dir, ignore_errors=True)
    print("clash/ 重建完成：%d 个列表，%d 条规则%s" % (n_lists, total_kept, drop_note))
    print("原子替换：新增 %d，更新 %d，未变 %d，删除陈旧 %d"
          % (len(created), len(changed),
             len(artifacts) - len(created) - len(changed), len(stale)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
