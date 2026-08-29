#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
engine.py — Surge 规则语义引擎（分流测试套件 L0 层）

职责：
  1. 只读解析 Surge.conf（[Proxy] / [Proxy Group] / [Rule]）与 rules/lists/*.list；
  2. 把 RULE-SET 内联展开成一张「按 conf 顺序」的全局规则表（rule_index 即优先级）；
  3. 离线模拟一次请求的分流判定，返回 spec/testkit.md 约定的 JSON 结构；
  4. 供 audit.py / runsuite.py 以模块方式复用（`import engine`）。

设计约束：
  * python3 标准库 only（macOS 自带 3.9+ 可跑）；
  * 全程只读，绝不写入 Surge Profiles 目录；
  * 无法离线精确判定的语义（GEOIP 非 CN、IP-ASN、URL-REGEX、内置 SYSTEM/LAN 规则集）
    一律采用**显式标注的近似实现**，并在 Engine.warnings 中留痕。

CLI：
  engine.py match <host> [--process P] [--ip I] [--ua U] [--conf PATH] [--json]
  engine.py dump-index [--file NAME] [--json]
  engine.py --selftest [--json]
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import sys

# ---------------------------------------------------------------------------
# 常量与近似实现表
# ---------------------------------------------------------------------------

#: 域名类规则
DOMAIN_TYPES = frozenset((
    "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-WILDCARD",
))

#: IP 类规则（这些规则对「域名请求」若缺 no-resolve 会触发本地 DNS 解析）
IP_TYPES = frozenset((
    "IP-CIDR", "IP-CIDR6", "IP-ASN", "GEOIP", "IP-CIDR-SET", "IP-ASN6",
))

#: 逻辑组合规则
LOGICAL_TYPES = frozenset(("AND", "OR", "NOT"))

#: 其它已知可解析类型
OTHER_TYPES = frozenset((
    "PROCESS-NAME", "USER-AGENT", "URL-REGEX", "FINAL", "RULE-SET",
    "DOMAIN-SET", "SRC-IP", "SRC-PORT", "DEST-PORT", "PROTOCOL",
    "IN-PORT", "SCRIPT", "SUBNET", "CELLULAR-RADIO", "DEVICE-NAME",
    "RULE-SET-REMOTE",
))

KNOWN_TYPES = DOMAIN_TYPES | IP_TYPES | LOGICAL_TYPES | OTHER_TYPES

#: 已知修饰符（出现在规则行尾）
KNOWN_MODIFIERS = frozenset((
    "no-resolve", "extended-matching", "dns-failed", "force-remote-dns",
    "pre-matching", "update-interval", "hidden",
))

#: 出口画像映射（spec/testkit.md「共享 Schema」原文，不得私改）
EXIT_CLASS_MAP = {
    "🇺🇸美国家宽A": "US-HOME-A",
    "🇺🇸美国家宽B": "US-HOME-B",
    "🇺🇸美国落地": "US-DC",
    "🇯🇵日本家宽": "JP-HOME",
    "🇯🇵日本落地": "JP-DC",
    "🇪🇺欧洲": "EU",
    "🇬🇧英国": "EU",
    "🇳🇱荷兰": "EU",
    "🇩🇪德国": "EU",
    "DIRECT": "DIRECT",
    "REJECT": "REJECT",
}

#: 内置 SYSTEM 规则集的**近似**实现。
#: Surge 内置 SYSTEM 集合不公开，这里只收录 spec 点名的三个域 + 少量同类
#: 「设备激活/描述文件/门户探测」域，刻意取小集合以免掩盖真实分流路径。
#: 名单里带「实测」标注的，是 realworld.py --crosscheck 拿 surge-cli 逐条对账时
#: 发现「Surge 实际命中 RULE-SET SYSTEM 而本表没有」的域，按在线为准补录。
BUILTIN_SYSTEM_DOMAINS = (
    "captive.apple.com",
    "mesu.apple.com",
    "gdmf.apple.com",
    "albert.apple.com",
    "gs.apple.com",
    "ppq.apple.com",
    "static.ips.apple.com",
    "iprofiles.apple.com",
    "deviceenrollment.apple.com",
    "guzzoni.apple.com",        # 实测 2026-08-30: Surge 命中 DOMAIN guzzoni.apple.com(in SYSTEM)
)

#: 内置 LAN 规则集的**近似**实现：RFC1918 / loopback / link-local / 保留段。
BUILTIN_LAN_CIDRS = (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
    "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
    "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32",
)
BUILTIN_LAN_CIDRS6 = ("::1/128", "fc00::/7", "fe80::/10", "ff00::/8")
BUILTIN_LAN_DOMAINS = ("local", "localhost", "home.arpa", "lan")

#: IP-ASN **近似**映射：仅收录该 ASN 的少量代表性网段样本，用于离线冒烟。
#: 绝非完整 ASN 段表 —— 命中即视为「该 ASN 的典型段」，未命中不代表不属于该 ASN。
BUILTIN_ASN_SAMPLES = {
    # DigitalOcean（AI.list 收了整个 ASN，用户自有 DO VPS 会被拉进 AI 组）
    "14061": ["159.89.0.0/16", "165.227.0.0/16", "167.71.0.0/16", "167.99.0.0/16",
              "104.131.0.0/16", "134.209.0.0/16", "138.68.0.0/16", "142.93.0.0/16",
              "143.198.0.0/16", "146.190.0.0/16", "157.245.0.0/16", "161.35.0.0/16",
              "164.90.0.0/16", "165.22.0.0/16", "178.128.0.0/16", "188.166.0.0/16",
              "206.189.0.0/16", "68.183.0.0/16", "64.227.0.0/16", "45.55.0.0/16"],
    # Vultr / Choopa
    "20473": ["45.32.0.0/16", "45.63.0.0/16", "45.76.0.0/16", "45.77.0.0/16",
              "66.42.0.0/18", "104.156.224.0/19", "108.61.0.0/16", "149.28.0.0/16",
              "155.138.128.0/17", "207.246.64.0/18", "216.128.128.0/17"],
    # Anthropic（自有 /21）
    "399358": ["160.79.104.0/21"],
    "401518": ["160.79.104.0/21"],
    # Twitter / X
    "13414": ["104.244.40.0/21", "192.133.76.0/22", "199.16.156.0/22",
              "199.59.148.0/22", "199.96.56.0/21"],
    "35995": ["69.195.160.0/19"],
    "54888": ["209.237.192.0/19"],
    # Telegram
    "62014": ["149.154.160.0/20"], "62041": ["91.108.4.0/22"],
    "44907": ["91.108.56.0/22"], "59930": ["91.105.192.0/23"],
    "211157": ["95.161.64.0/20"],
    # CERNET / 北大
    "24355": ["162.105.0.0/16", "115.27.0.0/16", "222.29.0.0/16"],
    "4538":  ["202.112.0.0/16"],
}


# ---------------------------------------------------------------------------
# 基础工具
# ---------------------------------------------------------------------------

def host_suffixes(host):
    """生成 host 的全部后缀候选（含自身）：a.b.c → a.b.c / b.c / c"""
    parts = host.split(".")
    for i in range(len(parts)):
        yield ".".join(parts[i:])


def wildcard_to_regex(pattern):
    """把 Surge 通配（* 任意长度、? 单字符）转成正则。

    近似说明：Surge 的 DOMAIN-WILDCARD 未公开是否跨 `.` 匹配，这里 `*` 取
    「任意字符（含 .）」的宽松解释；`fnmatch` 的 [] 字符类语义被禁用。
    """
    out = ["^"]
    for ch in pattern:
        if ch == "*":
            out.append(".*")
        elif ch == "?":
            out.append(".")
        else:
            out.append(re.escape(ch))
    out.append("$")
    return re.compile("".join(out))


def is_ip_literal(text):
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def split_top_level(text, sep=","):
    """按顶层分隔符切分，忽略括号内的分隔符（用于 AND/OR/NOT）。"""
    out, depth, buf = [], 0, []
    for ch in text:
        if ch == "(":
            depth += 1
            buf.append(ch)
        elif ch == ")":
            depth -= 1
            buf.append(ch)
        elif ch == sep and depth == 0:
            out.append("".join(buf).strip())
            buf = []
        else:
            buf.append(ch)
    if buf:
        out.append("".join(buf).strip())
    return out


def strip_comment(line):
    """去掉 # 注释（行首或前置空白的 #）。URL-REGEX 行不处理以免破坏正则。"""
    s = line.rstrip("\n").rstrip("\r")
    if s.lstrip().startswith("#") or s.lstrip().startswith(";"):
        return ""
    if s.lstrip().startswith("//"):
        return ""
    if s.startswith("URL-REGEX"):
        return s.strip()
    idx = s.find(" #")
    if idx >= 0:
        s = s[:idx]
    return s.strip()


# ---------------------------------------------------------------------------
# 规则对象
# ---------------------------------------------------------------------------

class Rule(object):
    """展开后的一条规则。idx 即全局优先级（越小越先匹配）。"""

    __slots__ = ("idx", "type", "value", "policy", "modifiers", "source",
                 "line", "raw", "set_modifiers", "sub")

    def __init__(self, idx, rtype, value, policy, modifiers, source, line,
                 raw, set_modifiers=(), sub=None):
        self.idx = idx
        self.type = rtype
        self.value = value
        self.policy = policy
        self.modifiers = frozenset(modifiers)
        self.source = source          # 来源文件名 / "Surge.conf" / "SYSTEM" / "LAN"
        self.line = line              # 来源文件内行号（1 起）
        self.raw = raw
        self.set_modifiers = frozenset(set_modifiers)  # conf RULE-SET 行级修饰
        self.sub = sub                # AND/OR/NOT 的子条件列表

    # -- 修饰符 ------------------------------------------------------------
    @property
    def no_resolve(self):
        """有效 no-resolve = 规则自带 or conf RULE-SET 行级修饰。"""
        if "no-resolve" in self.modifiers or "no-resolve" in self.set_modifiers:
            return True
        if self.type in LOGICAL_TYPES and self.sub:
            ip_subs = [c for c in self.sub if c[0] in IP_TYPES]
            if ip_subs and all("no-resolve" in c[2] for c in ip_subs):
                return True
        return False

    @property
    def is_ip_class(self):
        if self.type in IP_TYPES:
            return True
        if self.type in LOGICAL_TYPES and self.sub:
            return any(c[0] in IP_TYPES for c in self.sub)
        return False

    def signature(self):
        """(type,value) 规范化签名，用于查重。PROCESS-NAME 大小写敏感。"""
        if self.type == "PROCESS-NAME":
            return (self.type, self.value)
        if self.type in DOMAIN_TYPES:
            return (self.type, (self.value or "").lower())
        return (self.type, self.value)

    def rule_str(self):
        """schema 中 matched_rule 的形式：TYPE,VALUE（不含 policy / 修饰符）。"""
        if self.type == "FINAL":
            return "FINAL"
        return "%s,%s" % (self.type, self.value)

    def __repr__(self):
        return "<Rule #%d %s -> %s @%s:%s>" % (
            self.idx, self.rule_str(), self.policy, self.source, self.line)


# ---------------------------------------------------------------------------
# 引擎
# ---------------------------------------------------------------------------

class Engine(object):

    def __init__(self, conf_path, rules_dir=None):
        self.conf_path = os.path.abspath(conf_path)
        base = os.path.dirname(self.conf_path)
        # 默认布局：<conf 同级>/rules/ 是规则仓库根，32 个 .list 收纳在其 lists/ 下。
        # 显式传入 rules_dir 时原样使用（自检的 tempdir fixture 走这一支）。
        self.rules_dir = os.path.abspath(
            rules_dir or os.path.join(base, "rules", "lists"))
        self.warnings = []
        self.proxies = {}          # 物理代理名 -> 原始定义
        self.groups = {}           # 策略组名 -> {"type":..., "members":[...]}
        self.general = {}
        self.rules = []            # 展开后的全局规则表
        self.ruleset_refs = []     # [(ref_raw, basename_or_builtin, policy, mods, conf_line)]
        self.missing_lists = []
        self._load()
        self._build_index()

    # -- 载入 --------------------------------------------------------------

    def _warn(self, msg):
        if msg not in self.warnings:
            self.warnings.append(msg)

    def _load(self):
        with open(self.conf_path, "r", encoding="utf-8", errors="replace") as fh:
            raw_lines = fh.readlines()

        section = None
        for lineno, raw in enumerate(raw_lines, 1):
            s = raw.strip()
            if not s:
                continue
            if s.startswith("[") and s.endswith("]"):
                section = s[1:-1].strip()
                continue
            if section == "General":
                if "=" in s and not s.startswith("#"):
                    k, v = s.split("=", 1)
                    self.general[k.strip()] = v.strip()
                continue
            if section == "Proxy":
                if s.startswith("#") or "=" not in s:
                    continue
                name, body = s.split("=", 1)
                self.proxies[name.strip()] = body.strip()
                continue
            if section == "Proxy Group":
                if s.startswith("#") or "=" not in s:
                    continue
                name, body = s.split("=", 1)
                toks = [t.strip() for t in body.split(",") if t.strip()]
                if not toks:
                    continue
                gtype, members = toks[0], []
                for t in toks[1:]:
                    if "=" in t:      # include-all-proxies=0 / policy-priority=… 等选项
                        continue
                    members.append(t)
                self.groups[name.strip()] = {"type": gtype, "members": members}
                continue
            if section == "Rule":
                text = strip_comment(raw)
                if not text:
                    continue
                self._add_conf_rule(text, lineno)
                continue

    def _add_conf_rule(self, text, conf_lineno):
        """把 conf [Rule] 里的一行加入规则表（RULE-SET 会内联展开）。"""
        head = text.split(",", 1)[0].strip().upper()
        if head in ("RULE-SET", "DOMAIN-SET"):
            toks = split_top_level(text)
            if len(toks) < 3:
                self._warn("conf:%d RULE-SET 行字段不足，跳过：%s" % (conf_lineno, text))
                return
            ref, policy = toks[1].strip(), toks[2].strip()
            mods = [m.strip().lower() for m in toks[3:] if m.strip()]
            self._expand_ruleset(ref, policy, mods, conf_lineno)
            return
        rule = self._parse_rule_line(text, with_policy=True,
                                     source=os.path.basename(self.conf_path),
                                     line=conf_lineno)
        if rule is not None:
            rule.idx = len(self.rules)
            self.rules.append(rule)

    def _expand_ruleset(self, ref, policy, mods, conf_lineno):
        upper = ref.strip().upper()
        if upper in ("SYSTEM", "LAN"):
            self.ruleset_refs.append((ref, upper, policy, mods, conf_lineno))
            self._append_builtin(upper, policy, mods, conf_lineno)
            return
        basename = ref.rstrip("/").split("/")[-1].split("?")[0]
        self.ruleset_refs.append((ref, basename, policy, mods, conf_lineno))
        path = os.path.join(self.rules_dir, basename)
        if not os.path.isfile(path):
            self.missing_lists.append((basename, ref, conf_lineno))
            self._warn("conf:%d 引用的规则集在本地不存在：%s" % (conf_lineno, basename))
            return
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for lineno, raw in enumerate(fh, 1):
                text = strip_comment(raw)
                if not text:
                    continue
                rule = self._parse_rule_line(text, with_policy=False,
                                             source=basename, line=lineno,
                                             policy=policy, set_modifiers=mods)
                if rule is not None:
                    rule.idx = len(self.rules)
                    self.rules.append(rule)

    def _append_builtin(self, which, policy, mods, conf_lineno):
        """内置 SYSTEM / LAN 规则集的近似展开。"""
        if which == "SYSTEM":
            self._warn("RULE-SET,SYSTEM 使用近似实现（%d 条系统域）"
                       % len(BUILTIN_SYSTEM_DOMAINS))
            for i, d in enumerate(BUILTIN_SYSTEM_DOMAINS, 1):
                r = Rule(len(self.rules), "DOMAIN", d, policy, (), "SYSTEM", i,
                         "DOMAIN,%s" % d, mods)
                self.rules.append(r)
        else:
            self._warn("RULE-SET,LAN 使用近似实现（RFC1918/loopback/link-local）")
            n = 0
            for d in BUILTIN_LAN_DOMAINS:
                n += 1
                self.rules.append(Rule(len(self.rules), "DOMAIN-SUFFIX", d, policy,
                                       (), "LAN", n, "DOMAIN-SUFFIX,%s" % d, mods))
            for c in BUILTIN_LAN_CIDRS:
                n += 1
                self.rules.append(Rule(len(self.rules), "IP-CIDR", c, policy,
                                       ("no-resolve",), "LAN", n,
                                       "IP-CIDR,%s,no-resolve" % c, mods))
            for c in BUILTIN_LAN_CIDRS6:
                n += 1
                self.rules.append(Rule(len(self.rules), "IP-CIDR6", c, policy,
                                       ("no-resolve",), "LAN", n,
                                       "IP-CIDR6,%s,no-resolve" % c, mods))

    def _parse_rule_line(self, text, with_policy, source, line,
                         policy=None, set_modifiers=()):
        """解析一行规则。with_policy=True 时第三段是策略（conf 内联规则）。"""
        toks = split_top_level(text)
        if not toks:
            return None
        rtype = toks[0].strip().upper()

        if rtype == "FINAL":
            pol = toks[1].strip() if len(toks) > 1 else policy
            mods = [m.strip().lower() for m in toks[2:]]
            return Rule(0, "FINAL", None, pol, mods, source, line, text, set_modifiers)

        if rtype not in KNOWN_TYPES:
            self._warn("%s:%d 未知规则类型 %s，已跳过：%s" % (source, line, rtype, text))
            return None

        if rtype in LOGICAL_TYPES:
            expr = toks[1] if len(toks) > 1 else ""
            pol, mods = None, []
            if with_policy and len(toks) > 2:
                pol = toks[2].strip()
                mods = [m.strip().lower() for m in toks[3:]]
            else:
                pol = policy
                mods = [m.strip().lower() for m in toks[2:]
                        if m.strip().lower() in KNOWN_MODIFIERS]
            sub = self._parse_logical(expr, source, line)
            return Rule(0, rtype, expr, pol, mods, source, line, text,
                        set_modifiers, sub)

        if rtype == "URL-REGEX":
            # value 可能含逗号；离线无 URL 上下文，恒不匹配（仅登记）
            rest = text.split(",", 1)[1] if "," in text else ""
            pol = policy
            if with_policy:
                sub_toks = split_top_level(rest)
                if len(sub_toks) >= 2:
                    pol = sub_toks[-1].strip()
                    rest = ",".join(sub_toks[:-1])
            self._warn("%s:%d URL-REGEX 离线无法判定（缺 URL 上下文），恒不匹配"
                       % (source, line))
            return Rule(0, rtype, rest.strip(), pol, (), source, line, text,
                        set_modifiers)

        if len(toks) < 2:
            self._warn("%s:%d 规则字段不足，跳过：%s" % (source, line, text))
            return None

        value = toks[1].strip()
        if with_policy:
            pol = toks[2].strip() if len(toks) > 2 else policy
            mods = [m.strip().lower() for m in toks[3:] if m.strip()]
        else:
            pol = policy
            mods = [m.strip().lower() for m in toks[2:] if m.strip()]
        for m in mods:
            if m not in KNOWN_MODIFIERS and "=" not in m:
                self._warn("%s:%d 未知修饰符 %s" % (source, line, m))
        return Rule(0, rtype, value, pol, mods, source, line, text, set_modifiers)

    def _parse_logical(self, expr, source, line):
        """解析 ((TYPE,VAL,mods),(TYPE,VAL)) → [(type, value, mods_frozenset)]"""
        expr = expr.strip()
        if expr.startswith("(") and expr.endswith(")"):
            expr = expr[1:-1]
        out = []
        for part in split_top_level(expr):
            p = part.strip()
            if p.startswith("(") and p.endswith(")"):
                p = p[1:-1]
            fields = [f.strip() for f in p.split(",")]
            if len(fields) < 2:
                self._warn("%s:%d 逻辑规则子条件解析失败：%s" % (source, line, part))
                continue
            t = fields[0].upper()
            v = fields[1]
            mods = frozenset(f.lower() for f in fields[2:])
            out.append((t, v, mods))
        return out

    # -- 索引 --------------------------------------------------------------

    def _build_index(self):
        self.by_domain = {}
        self.by_suffix = {}
        self.by_keyword = []       # [(kw, idx)]
        self.by_wildcard = []      # [(regex, idx)]
        self.by_process = {}
        self.by_process_pattern = []
        self.by_ua = []            # [(regex, idx, raw)]
        self.ip_nets = []          # [(version, net_int, mask_int, idx)]
        self.asn_rules = []        # [(asn, idx)]
        self.geoip_rules = []      # [(cc, idx)]
        self.logical_rules = []    # [Rule]
        self.final_rule = None
        self.rules_by_file = {}
        self._china_ip_cache = None

        for r in self.rules:
            self.rules_by_file.setdefault(r.source, []).append(r)
            t = r.type
            if t == "DOMAIN":
                self.by_domain.setdefault(r.value.lower(), []).append(r.idx)
            elif t == "DOMAIN-SUFFIX":
                self.by_suffix.setdefault(r.value.lower().lstrip("."), []).append(r.idx)
            elif t == "DOMAIN-KEYWORD":
                self.by_keyword.append((r.value.lower(), r.idx))
            elif t == "DOMAIN-WILDCARD":
                self.by_wildcard.append((wildcard_to_regex(r.value.lower()), r.idx))
            elif t == "PROCESS-NAME":
                if ("*" in r.value) or ("?" in r.value) or r.value.startswith("/"):
                    # 通配 / 全路径 / App Bundle 形态：无法哈希精确查找，走逐条匹配
                    self.by_process_pattern.append((r.value, r.idx))
                else:
                    self.by_process.setdefault(r.value, []).append(r.idx)
            elif t == "USER-AGENT":
                self.by_ua.append((wildcard_to_regex(r.value), r.idx, r.value))
            elif t in ("IP-CIDR", "IP-CIDR6"):
                parsed = self._parse_cidr(r.value)
                if parsed:
                    ver, net_int, mask = parsed
                    self.ip_nets.append((ver, net_int, mask, r.idx))
            elif t == "IP-ASN":
                self.asn_rules.append((r.value.strip(), r.idx))
            elif t == "GEOIP":
                self.geoip_rules.append((r.value.strip().upper(), r.idx))
            elif t in LOGICAL_TYPES:
                self.logical_rules.append(r)
            elif t == "FINAL":
                if self.final_rule is None:
                    self.final_rule = r

        # 会触发本地 DNS 解析的 IP 类规则（缺 no-resolve），按 idx 升序
        self.leaky_ip_rules = sorted(
            (r.idx, r) for r in self.rules if r.is_ip_class and not r.no_resolve)

    @staticmethod
    def _parse_cidr(text):
        try:
            net = ipaddress.ip_network(text.strip(), strict=False)
        except ValueError:
            return None
        ver = net.version
        return (ver, int(net.network_address), int(net.netmask))

    def _china_ip_nets(self):
        """GEOIP,CN 的近似实现：用 ChinaIP.list 的 CIDR 集合代替 MaxMind 库。"""
        if self._china_ip_cache is not None:
            return self._china_ip_cache
        nets = []
        path = os.path.join(self.rules_dir, "ChinaIP.list")
        if os.path.isfile(path):
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                for raw in fh:
                    text = strip_comment(raw)
                    if not text.startswith("IP-CIDR"):
                        continue
                    parts = text.split(",")
                    if len(parts) < 2:
                        continue
                    p = self._parse_cidr(parts[1])
                    if p:
                        nets.append(p)
            self._warn("GEOIP,CN 使用 ChinaIP.list 近似（%d 段）" % len(nets))
        else:
            self._warn("GEOIP,CN 无法近似：缺 ChinaIP.list")
        self._china_ip_cache = nets
        return nets

    # -- 策略组 → 物理出口 -------------------------------------------------

    def resolve_exit(self, policy):
        """递归取策略组首项，直到落到已知物理出口名或 [Proxy] 条目。

        spec 的 exit_class 表以「🇺🇸美国家宽A」这类**叶子出口组**为键，
        故递归遇到表内名字即停（此时它就是 physical_exit）；表外的组继续下钻
        到 [Proxy] 物理名。
        """
        seen, cur = set(), policy
        while True:
            if cur in EXIT_CLASS_MAP:
                return cur, EXIT_CLASS_MAP[cur]
            if cur in self.proxies:
                return cur, self._infer_exit_class(cur)
            if cur in self.groups and cur not in seen:
                seen.add(cur)
                members = self.groups[cur]["members"]
                if not members:
                    return cur, "UNKNOWN"
                cur = members[0]
                continue
            return cur, self._infer_exit_class(cur)

    @staticmethod
    def _infer_exit_class(name):
        if name in EXIT_CLASS_MAP:
            return EXIT_CLASS_MAP[name]
        for flag, cls in (("🇺🇸", "US-DC"), ("🇯🇵", "JP-DC"), ("🇪🇺", "EU"),
                          ("🇬🇧", "EU"), ("🇳🇱", "EU"), ("🇩🇪", "EU")):
            if name.startswith(flag):
                return cls
        return "UNKNOWN"

    # -- 匹配 --------------------------------------------------------------

    def match(self, host=None, ip=None, process=None, ua=None):
        """离线模拟一次请求的分流判定，返回 spec/testkit.md 的结果 JSON。"""
        q_host, q_ip = host, ip
        if host and is_ip_literal(host):
            q_ip, q_host = host, None
        if q_host:
            q_host = q_host.strip().rstrip(".").lower()

        best = None                      # (idx, Rule)
        is_domain_query = bool(q_host)

        def consider(idx):
            nonlocal best
            if best is None or idx < best:
                best = idx

        # --- 域名类 -------------------------------------------------------
        if q_host:
            hits = self.by_domain.get(q_host)
            if hits:
                consider(hits[0])
            for suf in host_suffixes(q_host):
                hits = self.by_suffix.get(suf)
                if hits:
                    consider(hits[0])
            for kw, idx in self.by_keyword:
                if best is not None and idx > best:
                    continue
                if kw in q_host:
                    consider(idx)
            for rx, idx in self.by_wildcard:
                if best is not None and idx > best:
                    continue
                if rx.match(q_host):
                    consider(idx)

        # --- 进程名 / UA --------------------------------------------------
        if process:
            # 精确名快查（查询为全路径时同时按 basename 查，对齐 Surge Filename Mode）
            hits = self.by_process.get(process)
            if hits:
                consider(hits[0])
            if "/" in process:
                base_hits = self.by_process.get(process.rsplit("/", 1)[-1])
                if base_hits:
                    consider(base_hits[0])
            for pv, idx in self.by_process_pattern:
                if best is not None and idx > best:
                    continue
                if self._proc_match(pv, process):
                    consider(idx)
        if ua:
            for rx, idx, _raw in self.by_ua:
                if best is not None and idx > best:
                    continue
                if rx.match(ua):
                    consider(idx)

        # --- IP 类 --------------------------------------------------------
        # 语义：域名请求 + 规则带 no-resolve → 跳过；域名请求 + 无 no-resolve →
        # 记 dns_leak 并跳过（离线不真解析）；显式给了 --ip 则视为「已解析」，
        # 允许非 no-resolve 的 IP 规则命中（同时仍记泄漏）。
        ip_obj = None
        if q_ip:
            try:
                ip_obj = ipaddress.ip_address(q_ip)
            except ValueError:
                self._warn("非法 IP：%s" % q_ip)
        if ip_obj is not None:
            ip_int, ver = int(ip_obj), ip_obj.version
            for r_ver, net_int, mask, idx in self.ip_nets:
                if r_ver != ver:
                    continue
                if best is not None and idx > best:
                    continue
                if not self._ip_rule_usable(idx, is_domain_query):
                    continue
                if (ip_int & mask) == net_int:
                    consider(idx)
            for asn, idx in self.asn_rules:
                if best is not None and idx > best:
                    continue
                if not self._ip_rule_usable(idx, is_domain_query):
                    continue
                if self._asn_match(asn, ip_obj):
                    consider(idx)
            for cc, idx in self.geoip_rules:
                if best is not None and idx > best:
                    continue
                if not self._ip_rule_usable(idx, is_domain_query):
                    continue
                if self._geoip_match(cc, ip_obj, ip_int, ver):
                    consider(idx)

        # --- 逻辑规则 ------------------------------------------------------
        for r in self.logical_rules:
            if best is not None and r.idx > best:
                continue
            if self._eval_logical(r, q_host, ip_obj, process, ua, is_domain_query):
                consider(r.idx)

        # --- 兜底 ----------------------------------------------------------
        matched = self.rules[best] if best is not None else self.final_rule
        if matched is None:
            return self._result(q_host, q_ip, process, ua, None, [], None)

        trace, leak_at = [], None
        if is_domain_query:
            for idx, r in self.leaky_ip_rules:
                if idx >= matched.idx:
                    break
                desc = "%s (%s:%s → %s) 缺 no-resolve，域名请求到此会触发本地 DNS 解析" % (
                    r.rule_str(), r.source, r.line, r.policy)
                trace.append(desc)
                if leak_at is None:
                    leak_at = r.rule_str()
        return self._result(q_host, q_ip, process, ua, matched, trace, leak_at)

    def _ip_rule_usable(self, idx, is_domain_query):
        """域名请求时：带 no-resolve 的 IP 规则一律跳过。"""
        if not is_domain_query:
            return True
        return not self.rules[idx].no_resolve

    def _asn_match(self, asn, ip_obj):
        sample = BUILTIN_ASN_SAMPLES.get(str(asn))
        if not sample:
            self._warn("IP-ASN,%s 无内置近似样本，离线判定为不匹配" % asn)
            return False
        for cidr in sample:
            p = self._parse_cidr(cidr)
            if not p:
                continue
            ver, net_int, mask = p
            if ver == ip_obj.version and (int(ip_obj) & mask) == net_int:
                return True
        return False

    def _geoip_match(self, cc, ip_obj, ip_int, ver):
        if cc == "CN":
            for r_ver, net_int, mask in self._china_ip_nets():
                if r_ver == ver and (ip_int & mask) == net_int:
                    return True
            return False
        self._warn("GEOIP,%s 离线无 MaxMind 库，判定为不匹配（近似）" % cc)
        return False

    def _eval_logical(self, rule, host, ip_obj, process, ua, is_domain_query):
        if not rule.sub:
            return False
        results = []
        for (t, v, mods) in rule.sub:
            results.append(self._eval_cond(t, v, mods, host, ip_obj, process,
                                           ua, is_domain_query))
        if rule.type == "AND":
            return all(r is True for r in results)
        if rule.type == "OR":
            return any(r is True for r in results)
        if rule.type == "NOT":
            return results and results[0] is False
        return False

    @staticmethod
    def _proc_match(v, process):
        """Surge PROCESS-NAME 三种形态（全部大小写敏感，surge-cli 6.9.0 实测语义）：
        Filename：可执行名，支持 */? 通配（Claude Helper* 命中全部括号变体）。
        Full Path（/ 开头）无通配：以 / 结尾为路径前缀匹配（App Bundle Mode），否则全路径精确。
        Full Path 含通配：整串 glob——* 一旦出现即失去前缀语义，须以 * 收尾才能匹配更深路径段。
        查询侧：process 含 / 视为全路径（Filename 规则对其 basename 匹配）；仅进程名时全路径规则不可判定。
        """
        if not process:
            return False
        has_glob = ("*" in v) or ("?" in v)
        if v.startswith("/"):
            if "/" not in process:
                return False
            if has_glob:
                return bool(wildcard_to_regex(v).match(process))
            if v.endswith("/"):
                return process.startswith(v)
            return process == v
        name = process.rsplit("/", 1)[-1] if "/" in process else process
        if has_glob:
            return bool(wildcard_to_regex(v).match(name))
        return name == v

    def _eval_cond(self, t, v, mods, host, ip_obj, process, ua, is_domain_query):
        if t in DOMAIN_TYPES:
            if not host:
                return False
            lv = v.lower()
            if t == "DOMAIN":
                return host == lv
            if t == "DOMAIN-SUFFIX":
                return host == lv or host.endswith("." + lv)
            if t == "DOMAIN-KEYWORD":
                return lv in host
            return bool(wildcard_to_regex(lv).match(host))
        if t == "PROCESS-NAME":
            return self._proc_match(v, process)
        if t == "USER-AGENT":
            return bool(ua and wildcard_to_regex(v).match(ua))
        if t in IP_TYPES:
            if is_domain_query and "no-resolve" in mods:
                return False
            if ip_obj is None:
                return False
            if t in ("IP-CIDR", "IP-CIDR6"):
                p = self._parse_cidr(v)
                if not p:
                    return False
                ver, net_int, mask = p
                return ver == ip_obj.version and (int(ip_obj) & mask) == net_int
            if t == "IP-ASN":
                return self._asn_match(v, ip_obj)
            if t == "GEOIP":
                return self._geoip_match(v.upper(), ip_obj, int(ip_obj), ip_obj.version)
        return False

    def _result(self, host, ip, process, ua, matched, trace, leak_at):
        if matched is None:
            return {
                "query": {"host": host, "ip": ip, "process": process, "ua": ua},
                "matched_rule": None, "rule_index": None, "source": None,
                "policy": None, "physical_exit": None, "exit_class": None,
                "dns_leak": False, "dns_leak_at": None, "trace": trace,
            }
        exit_name, exit_class = self.resolve_exit(matched.policy)
        return {
            "query": {"host": host, "ip": ip, "process": process, "ua": ua},
            "matched_rule": matched.rule_str(),
            "rule_index": matched.idx,
            "source": matched.source,
            "policy": matched.policy,
            "physical_exit": exit_name,
            "exit_class": exit_class,
            "dns_leak": bool(leak_at),
            "dns_leak_at": leak_at,
            "trace": trace,
        }


# ---------------------------------------------------------------------------
# 默认路径解析
# ---------------------------------------------------------------------------

_FALLBACK_CONF = "/Users/fhgs/Library/Application Support/Surge/Profiles/Surge.conf"


def default_conf_path():
    """安装到 rules/tests/ 后：<tests>/../../Surge.conf；开发期回落到已知绝对路径。"""
    env = os.environ.get("SURGE_CONF")
    if env and os.path.isfile(env):
        return env
    here = os.path.dirname(os.path.abspath(__file__))
    cand = os.path.abspath(os.path.join(here, "..", "..", "Surge.conf"))
    if os.path.isfile(cand):
        return cand
    if os.path.isfile(_FALLBACK_CONF):
        return _FALLBACK_CONF
    return cand


def build_engine(conf=None, rules=None):
    path = conf or default_conf_path()
    if not os.path.isfile(path):
        raise SystemExit("找不到 Surge 配置：%s（用 --conf 指定）" % path)
    return Engine(path, rules)


# ---------------------------------------------------------------------------
# 自检（≥20 条手工断言）
# ---------------------------------------------------------------------------

SELFTEST_CONF = u"""\
[General]
dns-server = 223.5.5.5

[Proxy]
PhysA = snell, 1.2.3.4, 63001
PhysB = snell, 5.6.7.8, 63002
PhysC = snell, 9.10.11.12, 63003

[Proxy Group]
\U0001F1FA\U0001F1F8美国家宽A = smart, PhysA, PhysB
\U0001F1FA\U0001F1F8美国家宽B = smart, PhysB, PhysA
\U0001F1FA\U0001F1F8美国落地 = smart, PhysC
\U0001F1EF\U0001F1F5日本家宽 = smart, PhysA
\U0001F1EC\U0001F1E7英国 = select, PhysB
AI = select, \U0001F1FA\U0001F1F8美国家宽A, \U0001F1FA\U0001F1F8美国家宽B
Social = select, \U0001F1FA\U0001F1F8美国落地, AI
UKNode = select, \U0001F1EC\U0001F1E7英国
Deep = select, UKNode
Final = select, \U0001F1FA\U0001F1F8美国家宽A, DIRECT

[Rule]
RULE-SET,SYSTEM,DIRECT,no-resolve
RULE-SET,https://cdn.jsdelivr.net/gh/x/y@main/First.list,AI
RULE-SET,https://cdn.jsdelivr.net/gh/x/y@main/Second.list,Social
RULE-SET,https://cdn.jsdelivr.net/gh/x/y@main/Leaky.list,Deep
RULE-SET,https://cdn.jsdelivr.net/gh/x/y@main/Third.list,DIRECT
RULE-SET,https://cdn.jsdelivr.net/gh/x/y@main/Safe.list,DIRECT,no-resolve
RULE-SET,LAN,DIRECT,no-resolve
GEOIP,CN,DIRECT,no-resolve
FINAL,Final,dns-failed
"""

SELFTEST_LISTS = {
    "First.list": u"""\
# 手工构造：覆盖各域名类规则 + 进程 + UA
DOMAIN,exact.example.com
DOMAIN-SUFFIX,suffix.example.com
DOMAIN-KEYWORD,kwtoken
DOMAIN-WILDCARD,wild-*.example.net
DOMAIN-WILDCARD,two-??.example.net
PROCESS-NAME,ClaudeApp
PROCESS-NAME,WildProc*
PROCESS-NAME,/Applications/BundleApp.app/
PROCESS-NAME,/Users/*/.hidden/*
USER-AGENT,MyApp*
IP-CIDR,203.0.113.0/24,no-resolve
IP-CIDR6,2001:db8:aa::/48,no-resolve
IP-ASN,399358,no-resolve
AND,((DOMAIN-KEYWORD,cdn),(DOMAIN-KEYWORD,-epic-))
""",
    "Second.list": u"""\
# 后位 list：这些条目会被 First.list 遮蔽（用于遮蔽断言）
DOMAIN,exact.example.com
DOMAIN-SUFFIX,deep.suffix.example.com
DOMAIN-SUFFIX,second-only.example.org
PROCESS-NAME,claudeapp
""",
    "Leaky.list": u"""\
# 缺 no-resolve 的 IP 规则：域名请求经过此处会触发本地 DNS 解析
IP-CIDR,198.51.100.0/24
""",
    "Third.list": u"""\
DOMAIN-SUFFIX,cn-direct.example.cn
DOMAIN-SUFFIX,suffix.example.com
""",
    "Safe.list": u"""\
# conf 行级 no-resolve 修饰：本文件内 IP 规则不带 no-resolve 也不算泄漏
IP-CIDR,192.0.2.0/24
""",
}


def _make_selftest_env(tmpdir):
    rules_dir = os.path.join(tmpdir, "rules")
    os.makedirs(rules_dir, exist_ok=True)
    conf = os.path.join(tmpdir, "Surge.conf")
    with open(conf, "w", encoding="utf-8") as fh:
        fh.write(SELFTEST_CONF)
    for name, body in SELFTEST_LISTS.items():
        with open(os.path.join(rules_dir, name), "w", encoding="utf-8") as fh:
            fh.write(body)
    return conf, rules_dir


def run_selftest(verbose=True):
    """内置自检：合成配置上跑手工断言 + 真实配置冒烟断言。"""
    import tempfile

    results = []

    def check(name, got, want):
        ok = (got == want)
        results.append({"name": name, "ok": ok, "got": got, "want": want})
        return ok

    tmpdir = tempfile.mkdtemp(prefix="surge-engine-selftest-")
    try:
        conf, rules_dir = _make_selftest_env(tmpdir)
        e = Engine(conf, rules_dir)

        def m(**kw):
            return e.match(**kw)

        # --- 1) 各规则类型 ---------------------------------------------
        check("T01 DOMAIN 精确匹配", m(host="exact.example.com")["policy"], "AI")
        check("T02 DOMAIN 不匹配子域",
              m(host="a.exact.example.com")["policy"], "Final")
        check("T03 DOMAIN-SUFFIX 匹配自身",
              m(host="suffix.example.com")["policy"], "AI")
        check("T04 DOMAIN-SUFFIX 匹配子域",
              m(host="a.b.suffix.example.com")["policy"], "AI")
        check("T05 DOMAIN-SUFFIX 不误匹配同尾串",
              m(host="notsuffix.example.com")["policy"], "Final")
        check("T06 DOMAIN-KEYWORD 子串匹配",
              m(host="foo-kwtoken-bar.test")["policy"], "AI")
        check("T07 DOMAIN-WILDCARD * 通配",
              m(host="wild-abc.example.net")["policy"], "AI")
        check("T08 DOMAIN-WILDCARD ? 单字符",
              m(host="two-12.example.net")["policy"], "AI")
        check("T09 DOMAIN-WILDCARD ? 长度不符不匹配",
              m(host="two-123.example.net")["policy"], "Final")
        check("T10 PROCESS-NAME 精确+大小写敏感",
              m(host="nomatch.invalid", process="ClaudeApp")["policy"], "AI")
        check("T11 PROCESS-NAME 大小写变体走后位 list",
              m(host="nomatch.invalid", process="claudeapp")["policy"], "Social")
        check("T12 USER-AGENT 通配",
              m(host="nomatch.invalid", ua="MyApp/1.0")["policy"], "AI")
        check("T13 AND 逻辑规则命中",
              m(host="cdn-epic-1.example.io")["policy"], "AI")
        check("T14 AND 逻辑规则半命中不算",
              m(host="cdn-only.example.io")["policy"], "Final")

        # --- 2) IP 类 ---------------------------------------------------
        check("T15 IP-CIDR 纯 IP 查询命中",
              m(host="203.0.113.9")["policy"], "AI")
        check("T16 IP-CIDR 边界外不命中",
              m(host="203.0.114.1")["policy"], "Final")
        check("T17 IP-CIDR6 命中",
              m(host="2001:db8:aa::1")["policy"], "AI")
        check("T18 IP-ASN 近似样本命中(Anthropic 160.79.104.0/21)",
              m(host="160.79.104.5")["policy"], "AI")
        check("T19 LAN 内置近似：私网 IP 直连",
              m(host="192.168.1.1")["policy"], "DIRECT")
        check("T20 LAN 内置近似：loopback 直连",
              m(host="127.0.0.1")["policy"], "DIRECT")
        check("T21 纯 IP 查询把 host 归一到 ip 字段",
              m(host="203.0.113.9")["query"]["ip"], "203.0.113.9")

        # --- 3) 遮蔽 -----------------------------------------------------
        r = m(host="exact.example.com")
        check("T22 遮蔽：前位 list 胜出（source）", r["source"], "First.list")
        check("T23 遮蔽：后位 list 更细后缀被吞",
              m(host="deep.suffix.example.com")["policy"], "AI")
        check("T24 后位 list 独有条目仍可命中",
              m(host="second-only.example.org")["policy"], "Social")
        check("T25 直连区条目被前位代理区遮蔽（P0 型）",
              m(host="x.suffix.example.com")["source"], "First.list")
        check("T26 直连区独有条目正常直连",
              m(host="www.cn-direct.example.cn")["policy"], "DIRECT")

        # --- 4) no-resolve / DNS 泄漏路径 --------------------------------
        leak = m(host="www.cn-direct.example.cn")
        check("T27 泄漏标记：路径经过缺 no-resolve 的 IP 规则",
              leak["dns_leak"], True)
        check("T28 泄漏定位到具体规则",
              leak["dns_leak_at"], "IP-CIDR,198.51.100.0/24")
        check("T29 泄漏 trace 非空", len(leak["trace"]) > 0, True)
        check("T30 命中点早于泄漏规则则不算泄漏",
              m(host="exact.example.com")["dns_leak"], False)
        check("T31 conf 行级 no-resolve 修饰生效（Safe.list 零泄漏条目）",
              [r.source for _i, r in e.leaky_ip_rules], ["Leaky.list"])
        check("T32 带 no-resolve 的 IP 规则对域名请求不参与匹配",
              m(host="some.unknown.invalid")["policy"], "Final")

        # --- 5) 策略组递归 / 出口画像 ------------------------------------
        check("T33 组递归：AI → 首项叶子出口组",
              m(host="exact.example.com")["physical_exit"], "🇺🇸美国家宽A")
        check("T34 exit_class 映射 US-HOME-A",
              m(host="exact.example.com")["exit_class"], "US-HOME-A")
        check("T35 组递归：Social 首项 → 美国落地/US-DC",
              m(host="second-only.example.org")["exit_class"], "US-DC")
        check("T36 多层组递归：Deep→UKNode→英国→EU",
              e.resolve_exit("Deep"), ("🇬🇧英国", "EU"))
        check("T37 DIRECT 原样透传", e.resolve_exit("DIRECT"), ("DIRECT", "DIRECT"))
        check("T38 REJECT 原样透传", e.resolve_exit("REJECT"), ("REJECT", "REJECT"))

        # --- 6) 内置 SYSTEM / FINAL --------------------------------------
        check("T39 内置 SYSTEM 近似：captive.apple.com 直连",
              m(host="captive.apple.com")["policy"], "DIRECT")
        check("T40 FINAL 兜底策略组",
              m(host="nothing-matches-here.invalid")["matched_rule"], "FINAL")
        check("T41 matched_rule 形如 TYPE,VALUE",
              m(host="suffix.example.com")["matched_rule"],
              "DOMAIN-SUFFIX,suffix.example.com")
        check("T42 结果 schema 键集合完整",
              sorted(m(host="exact.example.com").keys()),
              sorted(["query", "matched_rule", "rule_index", "source", "policy",
                      "physical_exit", "exit_class", "dns_leak", "dns_leak_at",
                      "trace"]))

        # --- 6.5) PROCESS-NAME 通配与全路径形态（2026-08-30 补，对齐 surge-cli 实测语义） --
        check("T43 PROCESS-NAME 通配命中括号变体",
              m(host="nomatch.invalid", process="WildProc (Renderer)")["policy"], "AI")
        check("T44 PROCESS-NAME 通配大小写敏感",
              m(host="nomatch.invalid", process="wildproc (Renderer)")["policy"], "Final")
        check("T45 App Bundle 路径前缀命中",
              m(host="nomatch.invalid",
                process="/Applications/BundleApp.app/Contents/MacOS/Sub Helper")["policy"], "AI")
        check("T46 Filename 规则对全路径查询取 basename",
              m(host="nomatch.invalid", process="/usr/local/bin/ClaudeApp")["policy"], "AI")
        check("T47 全路径含 * 为整串 glob（* 收尾达深层）",
              m(host="nomatch.invalid", process="/Users/alice/.hidden/tool")["policy"], "AI")
        check("T48 仅进程名查询不命中全路径规则",
              m(host="nomatch.invalid", process="BundleApp")["policy"], "Final")
    finally:
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)

    # --- 7) 真实配置冒烟（只断言与架构文档一致的稳定事实） ----------------
    real_ok = True
    real_conf = default_conf_path()
    if os.path.isfile(real_conf):
        try:
            re_engine = build_engine(real_conf)
            check("R01 真实配置可解析：规则数 > 100000",
                  len(re_engine.rules) > 100000, True)
            check("R02 FINAL 存在且指向 Final 组",
                  re_engine.final_rule.policy, "Final")
            check("R03 Final 组递归到 ISP-A 家宽",
                  re_engine.resolve_exit("Final"), ("🇺🇸美国家宽A", "US-HOME-A"))
            check("R04 AI 组递归到 ISP-A 家宽",
                  re_engine.resolve_exit("AI"), ("🇺🇸美国家宽A", "US-HOME-A"))
            check("R05 Google-X-Meta-MS 组递归到 WAVE 家宽",
                  re_engine.resolve_exit("Google-X-Meta-MS"),
                  ("🇺🇸美国家宽B", "US-HOME-B"))
            check("R06 社交媒体组递归到美国落地",
                  re_engine.resolve_exit("社交媒体"), ("🇺🇸美国落地", "US-DC"))
            check("R07 chatgpt.com → AI 组",
                  re_engine.match(host="chatgpt.com")["policy"], "AI")
            check("R08 www.youtube.com → 流媒体组（先于 Google）",
                  re_engine.match(host="www.youtube.com")["policy"], "流媒体")
            check("R09 x.com → Google-X-Meta-MS 组",
                  re_engine.match(host="x.com")["policy"], "Google-X-Meta-MS")
            check("R10 t.me → Telegram 组",
                  re_engine.match(host="t.me")["policy"], "Telegram")
            check("R11 www.taobao.com → DIRECT",
                  re_engine.match(host="www.taobao.com")["policy"], "DIRECT")
            check("R12 私网 IP 192.168.1.1 → DIRECT",
                  re_engine.match(host="192.168.1.1")["policy"], "DIRECT")
            check("R13 未知域名兜底 → Final 组",
                  re_engine.match(host="zzz-nonexistent-brand-77.tld")["policy"],
                  "Final")
            check("R13b RFC6761 特殊 TLD .invalid → PrivateLAN 直连",
                  re_engine.match(host="no-such-domain-zzz.invalid")["source"],
                  "PrivateLAN.list")
            check("R14 零本地解析约束：全表无缺 no-resolve 的 IP 类规则",
                  len(re_engine.leaky_ip_rules), 0)
            check("R15 任意代理域名判定 dns_leak=False",
                  re_engine.match(host="chatgpt.com")["dns_leak"], False)
        except Exception as exc:  # pragma: no cover
            real_ok = False
            results.append({"name": "R00 真实配置加载", "ok": False,
                            "got": repr(exc), "want": "no exception"})
    else:
        results.append({"name": "R00 真实配置加载", "ok": True,
                        "got": "skipped(未找到 Surge.conf)", "want": "skipped"})

    passed = sum(1 for r in results if r["ok"])
    failed = len(results) - passed
    if verbose:
        for r in results:
            flag = "PASS" if r["ok"] else "FAIL"
            line = "[%s] %s" % (flag, r["name"])
            if not r["ok"]:
                line += "\n       got : %r\n       want: %r" % (r["got"], r["want"])
            print(line)
        print("-" * 66)
        print("自检合计 %d 条：通过 %d，失败 %d" % (len(results), passed, failed))
    return {"total": len(results), "passed": passed, "failed": failed,
            "cases": results, "real_config_ok": real_ok}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _print_match_human(res, engine_obj):
    q = res["query"]
    print("查询       : host=%s ip=%s process=%s ua=%s" % (
        q["host"], q["ip"], q["process"], q["ua"]))
    print("命中规则   : %s" % res["matched_rule"])
    print("规则序号   : %s" % res["rule_index"])
    print("来源文件   : %s" % res["source"])
    print("策略组     : %s" % res["policy"])
    print("物理出口   : %s" % res["physical_exit"])
    print("出口画像   : %s" % res["exit_class"])
    print("DNS 泄漏   : %s%s" % (res["dns_leak"],
                                 ("  @ " + res["dns_leak_at"]) if res["dns_leak_at"] else ""))
    if res["trace"]:
        print("路径提示   :")
        for t in res["trace"]:
            print("  - %s" % t)
    if engine_obj.warnings:
        print("引擎告警   : %d 条（--json 可见）" % len(engine_obj.warnings))


def main(argv=None):
    # 公共选项：子命令前后都可写（engine.py --json match X / engine.py match X --json）
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--conf", help="Surge.conf 路径（默认自动定位）")
    common.add_argument("--rules", help=".list 所在目录（默认 conf 同级 rules/lists/）")
    common.add_argument("--json", action="store_true", help="JSON 输出")

    ap = argparse.ArgumentParser(
        prog="engine.py", parents=[common],
        description="Surge 规则语义引擎（离线分流模拟）")
    ap.add_argument("--selftest", action="store_true", help="运行内置自检")
    sub = ap.add_subparsers(dest="cmd")

    p_match = sub.add_parser("match", parents=[common], help="模拟一次请求判定")
    p_match.add_argument("host", help="域名或 IP")
    p_match.add_argument("--process", help="进程名")
    p_match.add_argument("--ip", help="已解析 IP（域名请求时视为已知解析结果）")
    p_match.add_argument("--ua", help="User-Agent")

    p_dump = sub.add_parser("dump-index", parents=[common],
                            help="导出展开后的全规则表")
    p_dump.add_argument("--file", help="只导出该来源文件的规则")

    args = ap.parse_args(argv)

    if args.selftest:
        rep = run_selftest(verbose=not args.json)
        if args.json:
            print(json.dumps(rep, ensure_ascii=False, indent=2))
        return 1 if rep["failed"] else 0

    if args.cmd is None:
        ap.print_help()
        return 0

    eng = build_engine(args.conf, args.rules)

    if args.cmd == "match":
        res = eng.match(host=args.host, ip=args.ip,
                        process=args.process, ua=args.ua)
        if args.json:
            out = dict(res)
            out["warnings"] = eng.warnings
            print(json.dumps(out, ensure_ascii=False, indent=2))
        else:
            _print_match_human(res, eng)
        return 0

    if args.cmd == "dump-index":
        rows = eng.rules
        if args.file:
            rows = [r for r in rows if r.source == args.file]
        if args.json:
            print(json.dumps([{
                "idx": r.idx, "type": r.type, "value": r.value,
                "policy": r.policy, "modifiers": sorted(r.modifiers),
                "set_modifiers": sorted(r.set_modifiers),
                "source": r.source, "line": r.line,
                "no_resolve": r.no_resolve,
            } for r in rows], ensure_ascii=False))
        else:
            print("#idx\ttype\tvalue\tpolicy\tmodifiers\tsource\tline")
            for r in rows:
                print("%d\t%s\t%s\t%s\t%s\t%s\t%s" % (
                    r.idx, r.type, r.value, r.policy,
                    "|".join(sorted(r.modifiers | r.set_modifiers)) or "-",
                    r.source, r.line))
        return 0

    ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
