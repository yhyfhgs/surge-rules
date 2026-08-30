#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""surge2clash.py — 从 Surge .list 派生 Clash(Mihomo) classical 规则集。

单一编辑源原则：只编辑 lists/ 下的 Surge .list；clash/ 整个目录为派生产物，
由本脚本全量重建（update.sh 发布前自动执行），勿手工编辑。

本脚本位于仓库的 tools/ 下，读写路径全部相对脚本自身位置推导：
  输入 <仓库根>/lists/*.list  →  输出 <仓库根>/clash/
在仓库根执行 `python3 tools/surge2clash.py` 即可，无需 cd。

事务式流水线（2026-08-31 起；此前是「边解析边覆盖正式目录」，中途报错会留下
「前半新、后半旧」的混合工作树）：
  1. 解析校验   全量读入 lists/，未知规则类型**汇总成清单**后一次性报错退出，
                此时正式 clash/ 一个字节都没被碰过
  2. 暂存生成   全部产物先在临时目录里完整生成，不碰正式目录
  3. 原子提交   逐文件与现有 clash/ 按字节比对：相同则跳过（不刷 mtime，
                避免整目录 mtime churn 触发无谓的 CDN purge），不同才经
                同目录临时文件 os.replace 原子换入；陈旧 .list 一并删除
  4. 只读校验   `--check` 只做 1+2，再与现有 clash/ 比对并打印漂移摘要，
                不写任何正式文件（供 CI / 发布前确认派生产物未过期）

转换规则：
  原样透传   DOMAIN / DOMAIN-SUFFIX / DOMAIN-KEYWORD / DOMAIN-WILDCARD / IP-CIDR
             / IP-CIDR6 / GEOIP / IP-ASN / PROCESS-NAME（含 no-resolve 等尾参；
             Mihomo ≥1.19 原生支持 DOMAIN-WILDCARD 且 */? 语义与 Surge 一致，
             2026-08-31 起不再改写为 DOMAIN-REGEX——正则方言差异与可审计性都更差）
  剔除       USER-AGENT / URL-REGEX（Clash/Mihomo 无 UA/URL 匹配层），文件头汇总计数
  未知类型   报全清单后中止 —— 防止上游出现新类型时被静默丢弃

产物：
  clash/<Name>.list          — classical text 规则（与 Surge 同名对应）
  clash/rule-providers.yaml  — Clash Verge Rev 可直接 Merge 的 rule-providers 段
                               + 按 Surge.conf 优先级排列的 rules 参考序列（注释态）

退出码：
  0  成功（--check 下为「clash/ 与 lists/ 一致」）
  1  --check 检出漂移
  2  输入校验失败（未知规则类型 / 找不到 lists/）——正式 clash/ 未被修改
"""
import argparse
import difflib
import io
import os
import shutil
import sys
import tempfile
import time

# 脚本在 <仓库根>/tools/ 下，上跳一级即仓库根；不写死绝对路径，便于整仓迁移。
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES_DIR = os.path.join(REPO_ROOT, "lists")
OUT_DIR = os.path.join(REPO_ROOT, "clash")
CDN_BASE = "https://cdn.jsdelivr.net/gh/yhyfhgs/surge-rules@main/clash"
PROVIDERS_NAME = "rule-providers.yaml"

PASSTHROUGH = {
    "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-WILDCARD",
    "IP-CIDR", "IP-CIDR6", "GEOIP", "IP-ASN", "PROCESS-NAME",
}
DROP = {"USER-AGENT", "URL-REGEX"}

# Surge.conf [Rule] 区的完整引用顺序（规则顺序即优先级），用于生成 rules 参考序列。
# (文件名, Surge 策略名)；SYSTEM/LAN 为 Surge 内置集，Clash 端以注释说明等价物。
# 必须与真实 Surge.conf 逐行同序 —— 2026-08-31 修正：Reject 补入 PKU 之后的真实位置
# （此前 Clash 参考把 Reject 排在 PrivateLAN/PKU 之前，与 Surge 顺序分叉）。
CONF_ORDER = [
    ("PrivateLAN", "DIRECT"),
    ("PKU", "DIRECT"),
    ("Reject", "REJECT"),
    ("GameDownloadCN", "DIRECT"),
    ("ModelDownloadCDN", "下载"),
    ("YouTube", "流媒体"),
    ("Google", "Google-X-Meta-MS"),
    ("Twitter", "Google-X-Meta-MS"),
    ("Meta", "Google-X-Meta-MS"),
    ("Microsoft", "Google-X-Meta-MS"),
    ("AI", "AI"),
    ("TikTok", "社交媒体"),
    ("SocialOthers", "社交媒体"),
    ("Telegram", "Telegram"),
    ("Streaming", "流媒体"),
    ("Games", "游戏"),
    ("DownloadCDN", "下载"),
    ("Payment", "Payment"),
    ("AppleCN", "DIRECT"),
    ("MicrosoftCN", "DIRECT"),
    ("ProxyGFW", "Final"),
    ("Japan", "🇯🇵日本节点"),
    ("UK", "🇬🇧英国节点"),
    ("Europe", "🇪🇺欧洲节点"),
    ("US", "🇺🇸美国节点"),
    ("Domestic", "DIRECT"),
    ("ChinaMedia", "DIRECT"),
    ("TencentCN", "DIRECT"),
    ("AlibabaCN", "DIRECT"),
    ("ByteDanceCN", "DIRECT"),
    ("BaiduCN", "DIRECT"),
    ("NetEaseCN", "DIRECT"),
    ("ChinaDomain", "DIRECT"),
    ("ChinaIP", "DIRECT"),
]


# ── 阶段 1：解析校验 ─────────────────────────────────────────────────────────
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
                body.append(stripped)
                kept += 1
            elif rtype in DROP:
                dropped[rtype] = dropped.get(rtype, 0) + 1
            else:
                unknown.append((name, lineno, rtype))
    return body, kept, dropped, unknown


# ── 阶段 2：渲染产物（纯函数，只产生文本，不落盘）─────────────────────────────
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


def render_providers(names):
    lines = [
        "# AUTO-GENERATED — Clash Verge Rev 规则集配置（由 tools/surge2clash.py 生成，勿手工编辑）",
        "# 用法：在 Clash Verge Rev 中对订阅配置使用「Merge」扩展，粘贴本文件的",
        "# rule-providers 段；再参照文末注释的 rules 序列接入你自己的策略组。",
        "# 各 provider 与 Surge 同名 .list 一一对应，优先级语义见仓库 README。",
        "",
        "rule-providers:",
    ]
    for name in names:
        stem = name[:-5]
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
    ordered = {n for n, _ in CONF_ORDER}
    for stem, policy in CONF_ORDER:
        if (stem + ".list") in set(names):
            suffix = ",no-resolve" if stem == "ChinaIP" else ""
            lines.append("#  - RULE-SET,%s,%s%s" % (stem, policy, suffix))
    for name in sorted(names):
        stem = name[:-5]
        if stem not in ordered:
            lines.append("#  - RULE-SET,%s,<策略组>   # 未在 Surge.conf 启用，按需接入" % stem)
    lines += [
        "#  - GEOIP,CN,DIRECT,no-resolve",
        "#  - MATCH,Final",
    ]
    return "\n".join(lines) + "\n"


def build_all():
    """阶段 1+2：全量解析校验并渲染。返回 (产物 {文件名: 文本}, 总规则数, 总剔除)。

    任何未知规则类型都会在这里汇总报错退出（退出码 2），此时正式 clash/ 未被触碰。
    """
    if not os.path.isdir(RULES_DIR):
        sys.stderr.write("找不到规则目录 %s\n" % RULES_DIR)
        raise SystemExit(2)
    names = sorted(f for f in os.listdir(RULES_DIR) if f.endswith(".list"))
    if not names:
        sys.stderr.write("未在 %s 找到任何 .list\n" % RULES_DIR)
        raise SystemExit(2)

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

    artifacts[PROVIDERS_NAME] = render_providers(names)
    return artifacts, len(names), total_kept, total_dropped


def stage(artifacts):
    """阶段 2 落盘：把全部产物完整写进系统临时目录，返回目录路径。

    刻意不落在仓库内：进程被硬杀时不会给 update.sh 的 `git add -A` 留下垃圾。
    跨文件系统由提交阶段的「同目录临时文件 + os.replace」兜底。调用方负责 rmtree。
    """
    stage_dir = tempfile.mkdtemp(prefix="surge2clash-stage-")
    for name, text in artifacts.items():
        with io.open(os.path.join(stage_dir, name), "w", encoding="utf-8") as f:
            f.write(text)
    return stage_dir


# ── 阶段 3/4：与正式目录比对、提交 ───────────────────────────────────────────
def read_existing(name):
    """读现有产物字节；不存在返回 None。按字节比对，避免非法编码残留读不出来。"""
    path = os.path.join(OUT_DIR, name)
    if not os.path.isfile(path):
        return None
    with open(path, "rb") as f:
        return f.read()


def stale_files(artifacts):
    """正式目录里已不该存在的派生文件（源表被删/改名后的残留）。"""
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
    """比对暂存产物与现有 clash/。返回 (新增, 变更[(名, +n, -n)], 陈旧)。

    刻意读暂存目录里的字节而不是内存文本：比对的就是提交阶段会换入的那份字节。
    """
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
    """清掉上次被硬杀留下的换入临时文件（超过 1 小时才算孤儿，免得踩并发实例）。"""
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
    """阶段 3：逐文件原子换入，内容相同的不重写（不刷 mtime），删除陈旧文件。

    换入用「与目标同目录的临时文件 + os.replace」：同文件系统保证 rename 原子，
    读者（Surge/CDN 发布脚本）永远看到完整的旧版或完整的新版，不会读到半截。
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
        # 只读路径：仍走完整暂存生成，比对的就是「真正会写出去的那份字节」。
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
