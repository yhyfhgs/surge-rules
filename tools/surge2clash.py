#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""surge2clash.py — 从 Surge .list 派生 Clash(Mihomo) classical 规则集。

单一编辑源原则：只编辑 lists/ 下的 Surge .list；clash/ 整个目录为派生产物，
由本脚本全量重建（update.sh 发布前自动执行），勿手工编辑。

本脚本位于仓库的 tools/ 下，读写路径全部相对脚本自身位置推导：
  输入 <仓库根>/lists/*.list  →  输出 <仓库根>/clash/
在仓库根执行 `python3 tools/surge2clash.py` 即可，无需 cd。

转换规则：
  原样透传   DOMAIN / DOMAIN-SUFFIX / DOMAIN-KEYWORD / IP-CIDR / IP-CIDR6
             / GEOIP / IP-ASN / PROCESS-NAME（含 no-resolve 等尾参）
  等价改写   DOMAIN-WILDCARD → DOMAIN-REGEX（* → .*，? → .，^$ 锚定，Surge 语义）
  剔除       USER-AGENT / URL-REGEX（Clash/Mihomo 无 UA/URL 匹配层），文件头汇总计数
  未知类型   直接报错中止 —— 防止上游出现新类型时被静默丢弃

产物：
  clash/<Name>.list          — classical text 规则（与 Surge 同名对应）
  clash/rule-providers.yaml  — Clash Verge Rev 可直接 Merge 的 rule-providers 段
                               + 按 Surge.conf 优先级排列的 rules 参考序列（注释态）
"""
import io
import os
import re
import sys

# 脚本在 <仓库根>/tools/ 下，上跳一级即仓库根；不写死绝对路径，便于整仓迁移。
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES_DIR = os.path.join(REPO_ROOT, "lists")
OUT_DIR = os.path.join(REPO_ROOT, "clash")
CDN_BASE = "https://cdn.jsdelivr.net/gh/yhyfhgs/surge-rules@main/clash"

PASSTHROUGH = {
    "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD",
    "IP-CIDR", "IP-CIDR6", "GEOIP", "IP-ASN", "PROCESS-NAME",
}
DROP = {"USER-AGENT", "URL-REGEX"}

# Surge.conf 第 8 区的引用顺序（规则顺序即优先级），用于生成 rules 参考序列。
# (文件名, Surge 策略名)；SYSTEM/LAN 为 Surge 内置集，Clash 端以注释说明等价物。
CONF_ORDER = [
    ("PrivateLAN", "DIRECT"),
    ("PKU", "DIRECT"),
    ("GameDownloadCN", "DIRECT"),
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


def wildcard_to_regex(pattern):
    """Surge DOMAIN-WILDCARD 语义：* 匹配任意串（可跨点），? 匹配单字符。"""
    out = []
    for ch in pattern:
        if ch == "*":
            out.append(".*")
        elif ch == "?":
            out.append(".")
        else:
            out.append(re.escape(ch))
    return "^" + "".join(out) + "$"


def convert_file(name):
    """转换单个 .list，返回 (输出行列表, 有效规则数, {类型: 剔除数})。"""
    dropped = {}
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
            elif rtype == "DOMAIN-WILDCARD":
                pattern = stripped.split(",", 2)[1].strip()
                body.append("DOMAIN-REGEX," + wildcard_to_regex(pattern))
                kept += 1
            elif rtype in DROP:
                dropped[rtype] = dropped.get(rtype, 0) + 1
            else:
                sys.exit("未知规则类型 %s（%s:%d）—— 请在 surge2clash.py 中显式登记后再发布"
                         % (rtype, name, lineno))
    return body, kept, dropped


def write_list(name, body, kept, dropped):
    header = [
        "# AUTO-GENERATED — Clash(Mihomo) classical 规则，由 ../lists/%s 派生" % name,
        "# 勿手工编辑；修改 Surge 源后运行 python3 tools/surge2clash.py 重新生成",
    ]
    if dropped:
        detail = ", ".join("%s x %d" % (k, v) for k, v in sorted(dropped.items()))
        header.append("# 已剔除 Clash 不支持的规则: %s" % detail)
    header.append("")
    out = os.path.join(OUT_DIR, name)
    with io.open(out, "w", encoding="utf-8") as f:
        f.write("\n".join(header + body).rstrip("\n") + "\n")


def write_providers(names):
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
        "# ─── rules 参考序列（按 Surge.conf 优先级；取消注释并替换为你的策略组名）───",
        "# Surge 内置 SYSTEM/LAN 集在 Clash 端的等价前置规则：",
        "#  - GEOIP,lan,DIRECT,no-resolve",
        "# rules:",
        "#  - RULE-SET,Reject,REJECT   # Surge.conf 已停用，Clash 端按需启用（须置于放行规则之前）",
    ]
    ordered = {n for n, _ in CONF_ORDER} | {"Reject"}
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
    out = os.path.join(OUT_DIR, "rule-providers.yaml")
    with io.open(out, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def main():
    names = sorted(f for f in os.listdir(RULES_DIR) if f.endswith(".list"))
    if not names:
        sys.exit("未在 %s 找到任何 .list" % RULES_DIR)
    # 全量重建：清掉 clash/ 里已不存在于源的陈旧 .list
    if os.path.isdir(OUT_DIR):
        for f in os.listdir(OUT_DIR):
            if f.endswith(".list") and f not in names:
                os.remove(os.path.join(OUT_DIR, f))
    else:
        os.makedirs(OUT_DIR)
    total_kept, total_dropped = 0, {}
    for name in names:
        body, kept, dropped = convert_file(name)
        write_list(name, body, kept, dropped)
        total_kept += kept
        for k, v in dropped.items():
            total_dropped[k] = total_dropped.get(k, 0) + v
    write_providers(names)
    drop_note = ("；剔除 " + ", ".join("%s x %d" % (k, v) for k, v in sorted(total_dropped.items()))
                 if total_dropped else "")
    print("clash/ 重建完成：%d 个列表，%d 条规则%s" % (len(names), total_kept, drop_note))


if __name__ == "__main__":
    main()
