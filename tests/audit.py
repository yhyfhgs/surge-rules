#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
audit.py — Surge 规则体系静态审计器（分流测试套件 L1 层）

复用 engine.py 的解析器（同一张按 conf 顺序展开的全局规则表），做 10 项可回归检查：

  A1  全 list IP 类规则 no-resolve 缺失（含 conf RULE-SET 行级修饰豁免逻辑）
  A2  跨 list 精确重复（(type,value) 相同出现多处 → 报后位死条目）
  A3  同 list 内部覆盖（DOMAIN ⊂ 同 list SUFFIX；SUFFIX ⊂ 更短 SUFFIX；KEYWORD 吞后缀）
  A4  跨 list 遮蔽（后位条目被前位更宽规则完全覆盖；直连区被代理区遮蔽标 P0）
  A5  conf 引用完整性（引用的 list 存在；存在的 list 被引用或在 allowlist）
  A6  DOMAIN-KEYWORD 审查表（列出供人工复核，不判错）
  A7  规则行格式 lint（无类型前缀的裸行 → P1；小写类型段 → P1/case）
  A8  禁止回流（allowlist.json `forbidden` 段登记的模式出现即 P0，不可豁免）
  A9  IP 跨表包含/遮蔽（**顺序感知**：只报「后位 CIDR 被前位 CIDR 完全包含」）
  A10 单标签后缀与 PSL 边界门禁（+ 同一逐行循环内的 arity / 严格 CIDR /
      modifier 白名单 / 类型段大小写归一）

输出（--out DIR）：
  findings.jsonl      —— 每行一个 finding（00-context.md 约定 schema + source/check）
  report.md           —— 中文审计报告
  keyword_review.tsv  —— A6 全量关键词表
  a2/a3/a4/a9_details.tsv —— 聚合前的逐条明细（findings 做了分组与截断，明细不截断）

退出码：存在严重度 ≥ --fail-on（默认 P1）的未豁免 finding 时返回 1。
python3 标准库 only；全程只读，不写 Surge Profiles 目录。
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import ipaddress
import json
import os
import re
import sys
from collections import OrderedDict, defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import engine as engine_mod  # noqa: E402

SEVERITY_ORDER = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}

#: 视为「直连意图」的策略
DIRECT_POLICIES = frozenset(("DIRECT",))
REJECT_POLICIES = frozenset(("REJECT", "REJECT-DROP", "REJECT-TINYGIF",
                             "REJECT-NO-DROP"))

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_ALLOWLIST = os.path.join(HERE, "allowlist.json")
#: A10 用的锁定快照目录（PSL + IANA TLD 表；哈希见 data/SNAPSHOTS.json）
DEFAULT_DATA_DIR = os.path.join(HERE, "data")

ALL_CHECKS = ("A1", "A2", "A3", "A4", "A5", "A6", "A7", "A8", "A9", "A10")

#: A10 modifier 白名单（本仓库行格式约定：list 内只允许 no-resolve）
ALLOWED_MODIFIERS = frozenset(("no-resolve",))
#: no-resolve 只对 IP 类规则有意义
IP_CLASS_TYPES = frozenset(("IP-CIDR", "IP-CIDR6", "IP-ASN", "GEOIP"))

#: RFC6761 / RFC6762 / RFC7686 / RFC8375 特殊用途名 + ICANN 保留的私用 TLD。
#: 这些不在 IANA 根区表里，但单标签形态是**正确**的（PrivateLAN.list 的 8 条）。
SPECIAL_USE_TLDS = frozenset((
    "example", "invalid", "local", "localhost", "test",        # RFC6761/6762
    "onion",                                                    # RFC7686
    "internal",                                                 # ICANN 保留私用
    "alt",                                                      # RFC9476
    "corp", "home", "intranet", "lan", "localdomain", "private",  # 事实私用
))


#: 形如 IPv4 前缀的关键词（A6 启发式提示用，例如 "101.91.69." / "1.2.3.4"）
IPV4_PREFIX_RX = re.compile(r"^\d{1,3}(\.\d{1,3}){1,3}\.?$")


def norm_suffix(rule):
    """后缀比较用值：仅 DOMAIN-SUFFIX 去掉可能的前导点。"""
    v = (rule.value or "").lower()
    return v.lstrip(".") if rule.type == "DOMAIN-SUFFIX" else v


def norm_raw(rule):
    """关键词包含判定用值：保留原样（前导点有语义，例如 `.tmall.com`）。"""
    return (rule.value or "").lower()


# ---------------------------------------------------------------------------
# 豁免表
# ---------------------------------------------------------------------------

class Allowlist(object):
    """按 (check_id, file, rule) 豁免。

    三元组之外提供三个**可选**限定键（不改变基础 schema，只是缩小豁免面）：
      by       —— 遮蔽/胜出方的规则串，如 "DOMAIN-SUFFIX,amazonaws.com"
      by_file  —— 遮蔽/胜出方所在 list，如 "YouTube.list"
      kind     —— finding 的 kind 字段，如 "psl-private"（A10 的子检查名）；
                  用于在同一 check 内只豁免某一类子检查，避免整表豁免把
                  arity / 严格 CIDR 这类真缺陷一并静音
    另有两个布尔键：
      preventive=true      —— 「防回归」前置豁免（当前配置本就不该命中），
                              未命中时不计入「未使用豁免」告警。
      pending_decision=true —— 「本轮未裁决、保留原状待用户决策」。与 preventive
                              不同：它**必须**每次运行都被单独打印出来，否则待裁决
                              事项会被伪装成永久豁免（W7-T09）。
    file / rule / by / by_file / kind 均支持 fnmatch 通配。

    与 exemptions 语义相反的顶层 `forbidden` 段：登记「按架构裁决必须持续不存在」
    的规则模式（如 D7 的 USER-AGENT/PROCESS-NAME、D11 上游合并排除表项）。
    由 A8 扫描源文件强制执行：命中即 P0，且不经过 exemptions 豁免。
    forbidden 条目支持两个**可选**作用域键（缺省 = 全库语义，向后兼容）：
      file      —— 只在匹配该 fnmatch 的 list 内视为禁令（「勿搬进 X.list」）
      not_file  —— 只在**不**匹配该 fnmatch 的 list 内视为禁令（「勿回 X.list 之外」，
                   即「必须只存在于 X.list」这类唯一归属守卫）
    """

    def __init__(self, path=None):
        self.path = path
        self.entries = []
        self.forbidden = []
        self.hits = defaultdict(int)
        if path and os.path.isfile(path):
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            self.entries = data.get("exemptions", [])
            self.forbidden = data.get("forbidden", [])

    @staticmethod
    def _check_match(entry, check):
        want = entry.get("check", "*")
        if want in (None, "*"):
            return True
        if isinstance(want, list):
            return check in want
        return want == check

    def match(self, check, file_name, rule_str, by=None, by_file=None, kind=None):
        for i, e in enumerate(self.entries):
            if not self._check_match(e, check):
                continue
            if not fnmatch.fnmatch(file_name or "", e.get("file", "*")):
                continue
            if not fnmatch.fnmatch(rule_str or "", e.get("rule", "*")):
                continue
            if "by" in e and (by is None or not fnmatch.fnmatch(by, e["by"])):
                continue
            if "by_file" in e and (by_file is None
                                   or not fnmatch.fnmatch(by_file, e["by_file"])):
                continue
            if "kind" in e and (kind is None
                                or not fnmatch.fnmatch(kind, e["kind"])):
                continue
            self.hits[i] += 1
            return e
        return None

    def forbidden_scope_ok(self, entry, file_name):
        """forbidden 条目的可选作用域：file（只在该表内禁）/ not_file（该表之外禁）。"""
        f = entry.get("file")
        if f is not None and not fnmatch.fnmatch(file_name or "", f):
            return False
        nf = entry.get("not_file")
        if nf is not None and fnmatch.fnmatch(file_name or "", nf):
            return False
        return True

    def unused(self, ran_checks=None):
        """未命中的豁免条目：排除 preventive 防回归条目与本次未执行的检查项。"""
        out = []
        for i, e in enumerate(self.entries):
            if self.hits[i] or e.get("preventive"):
                continue
            if ran_checks is not None:
                want = e.get("check", "*")
                names = ([want] if isinstance(want, str) else
                         (want or ["*"]))
                if "*" not in names and not (set(names) & set(ran_checks)):
                    continue
            out.append(e)
        return out

    def pending(self, ran_checks=None):
        """带 pending_decision 的豁免条目：待用户裁决，必须每次运行都单独提示。"""
        out = []
        for i, e in enumerate(self.entries):
            if not e.get("pending_decision"):
                continue
            if ran_checks is not None:
                want = e.get("check", "*")
                names = ([want] if isinstance(want, str) else (want or ["*"]))
                if "*" not in names and not (set(names) & set(ran_checks)):
                    continue
            out.append((e, self.hits[i]))
        return out


# ---------------------------------------------------------------------------
# A10 用的锁定快照：PSL + IANA 根区 TLD 表
# ---------------------------------------------------------------------------

def _idna_label(label):
    """把单个标签归一到 ASCII（punycode）小写形态；失败则原样小写返回。"""
    if all(ord(c) < 128 for c in label):
        return label.lower()
    try:
        return label.encode("idna").decode("ascii").lower()
    except Exception:
        return label.lower()


def idna_domain(dom):
    return ".".join(_idna_label(x) for x in
                    (dom or "").strip().strip(".").split("."))


class PublicSuffixList(object):
    """锁定 PSL 快照 + IANA 根区 TLD 表。

    `lookup(domain)` 实现 publicsuffix.org 的标准算法：
      · 规则按标签从右往左比对，`*` 匹配任意单个标签；
      · 任一 **exception**（`!foo.bar`）规则命中 → 该域是可注册域，**不是**公共后缀；
      · 否则取标签数最多的匹配规则；
      · 无规则命中时隐含规则为 `*`（即 TLD 本身是公共后缀）。
    IDN 条目在装载与查询两侧都做 IDNA 归一，故 `xn--fiqs8s` 与 `中国` 等价。

    `is_boundary(value)` 是 A10 真正用的判据，命中两种形态之一即算「注册边界」：
      (a) value 自身就是公共后缀（例：`ac.uk` / `claude.app`）；
      (b) PSL 里存在 `*.value` 通配规则（例：`*.oaiusercontent.com`）——此时
          value 的**每一个**子域都是公共后缀，`DOMAIN-SUFFIX,value` 等于把整个
          多租户命名空间一次性收进来，比 (a) 更宽。这就是规格里的「正确处理
          `*.parent`」。
    """

    def __init__(self, psl_path=None, tld_path=None):
        self.psl_path = psl_path
        self.tld_path = tld_path
        self.by_len = defaultdict(list)      # 标签数 -> [(labels, is_exception, section)]
        self.wild_parents = {}               # "oaiusercontent.com" -> section
        self.tlds = set()
        self.rule_count = 0
        self.sha256 = {}
        self.available = False
        if psl_path and os.path.isfile(psl_path):
            self._load_psl(psl_path)
        if tld_path and os.path.isfile(tld_path):
            self._load_tlds(tld_path)
        self.available = bool(self.by_len) and bool(self.tlds)

    @staticmethod
    def _sha256(path):
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 16), b""):
                h.update(chunk)
        return h.hexdigest()

    def _load_psl(self, path):
        self.sha256["psl"] = self._sha256(path)
        section = None
        with open(path, "r", encoding="utf-8") as fh:
            for raw in fh:
                s = raw.strip()
                if s.startswith("//"):
                    if "BEGIN ICANN DOMAINS" in s:
                        section = "icann"
                    elif "END ICANN DOMAINS" in s:
                        section = None
                    elif "BEGIN PRIVATE DOMAINS" in s:
                        section = "private"
                    elif "END PRIVATE DOMAINS" in s:
                        section = None
                    continue
                if not s:
                    continue
                exc = s.startswith("!")
                body = s[1:] if exc else s
                labels = tuple(_idna_label(x) for x in body.split("."))
                self.by_len[len(labels)].append((labels, exc, section or "icann"))
                self.rule_count += 1
                if not exc and labels[0] == "*":
                    self.wild_parents[".".join(labels[1:])] = section or "icann"

    def _load_tlds(self, path):
        self.sha256["tld"] = self._sha256(path)
        with open(path, "r", encoding="utf-8") as fh:
            for raw in fh:
                s = raw.strip()
                if not s or s.startswith("#"):
                    continue
                self.tlds.add(_idna_label(s))

    def lookup(self, domain):
        """返回 (is_public_suffix, section, prevailing_rule)。"""
        labels = idna_domain(domain).split(".")
        n = len(labels)
        matches = []
        for k in range(1, n + 1):
            tail = labels[n - k:]
            for rl, exc, sect in self.by_len.get(k, ()):
                ok = True
                for i, rlab in enumerate(rl):
                    if rlab != "*" and rlab != tail[i]:
                        ok = False
                        break
                if ok:
                    matches.append((k, rl, exc, sect))
        exceptions = [m for m in matches if m[2]]
        if exceptions:
            k, rl, _exc, sect = max(exceptions, key=lambda m: m[0])
            return (False, sect, "!" + ".".join(rl))
        if not matches:
            return (n == 1, None, "*（隐含规则）")
        k, rl, _exc, sect = max(matches, key=lambda m: m[0])
        return (k == n, sect, ".".join(rl))

    def is_boundary(self, value):
        """返回 (hit, section, prevailing_rule, how)；how ∈ {"self","wildcard-parent"}。"""
        is_ps, sect, rule = self.lookup(value)
        if is_ps:
            return (True, sect, rule, "self")
        norm = idna_domain(value)
        if norm in self.wild_parents:
            return (True, self.wild_parents[norm], "*." + norm, "wildcard-parent")
        return (False, sect, rule, None)

    def is_iana_tld(self, label):
        return _idna_label(label) in self.tlds


# ---------------------------------------------------------------------------
# 逐行源文件扫描（A7 / A8 / A10 共用同一遍解析）
# ---------------------------------------------------------------------------

class SourceLine(object):
    """一条 .list 里的非注释行的规范化视图。"""

    __slots__ = ("file", "line", "raw", "text", "body", "type_raw", "type",
                 "value", "mods", "norm", "head", "known")

    def __init__(self, file_name, lineno, raw, known_types):
        self.file = file_name
        self.line = lineno
        self.raw = raw
        self.text = raw.strip()
        # 行尾注释（" #" 之后）不属于规则本体；engine.strip_comment 同口径
        body = self.text
        if not body.startswith("URL-REGEX"):
            i = body.find(" #")
            if i >= 0:
                body = body[:i].strip()
        self.body = body
        parts = [p.strip() for p in body.split(",")]
        self.type_raw = parts[0]
        self.type = parts[0].upper()
        self.known = self.type in known_types
        self.value = parts[1] if len(parts) > 1 else None
        self.mods = [m for m in parts[2:]]
        norm_parts = [self.type] + parts[1:]
        self.norm = ",".join(norm_parts)
        self.head = ",".join(norm_parts[:2])


# ---------------------------------------------------------------------------
# 审计器
# ---------------------------------------------------------------------------

class Auditor(object):

    def __init__(self, eng, allowlist, max_findings=200, samples=6, psl=None):
        self.e = eng
        self.al = allowlist
        self.max_findings = max_findings
        self.samples = samples
        self.psl = psl
        self.findings = []
        self.details = {"A2": [], "A3": [], "A4": [], "A9": []}
        self.keywords = []
        self.exempted = []
        self._seq = 0
        self._lines = None
        # 只对「域名类」规则做覆盖/遮蔽分析
        self.domain_rules = [r for r in self.e.rules
                             if r.type in ("DOMAIN", "DOMAIN-SUFFIX",
                                           "DOMAIN-KEYWORD")]

    # -- 源文件逐行视图（A7 / A8 / A10 共用一遍解析）------------------------

    # KNOWN_TYPES 在类体后段由 A7_PREFIXES 派生（见 check_a7 上方）

    def source_lines(self):
        if self._lines is not None:
            return self._lines
        out = []
        for fname in sorted(os.listdir(self.e.rules_dir)):
            if not fname.endswith(".list"):
                continue
            path = os.path.join(self.e.rules_dir, fname)
            with open(path, "r", encoding="utf-8") as fh:
                for lineno, raw in enumerate(fh, 1):
                    t = raw.strip()
                    if not t or t.startswith("#"):
                        continue
                    out.append(SourceLine(fname, lineno, raw, self.KNOWN_TYPES))
        self._lines = out
        return out

    # -- finding 构造 ------------------------------------------------------

    def _add(self, check, severity, kind, file_name, rule_str, evidence,
             impact, fix, confidence="high", by=None, by_file=None,
             exemptable=True):
        if exemptable:
            ex = self.al.match(check, file_name, rule_str, by=by,
                               by_file=by_file, kind=kind)
            if ex is not None:
                self.exempted.append({"check": check, "file": file_name,
                                      "rule": rule_str,
                                      "reason": ex.get("reason", "")})
                return None
        self._seq += 1
        f = OrderedDict()
        f["id"] = "W6-%03d" % self._seq
        f["severity"] = severity
        f["kind"] = kind
        f["file"] = file_name
        f["rule"] = rule_str
        f["evidence"] = evidence
        f["impact"] = impact
        f["fix"] = fix
        f["confidence"] = confidence
        f["source"] = "audit"
        f["check"] = check
        self.findings.append(f)
        return f

    # -- A1 ---------------------------------------------------------------

    def check_a1(self):
        bad = [r for r in self.e.rules if r.is_ip_class and not r.no_resolve]
        for r in bad:
            self._add(
                "A1", "P1", "dns-leak", r.source, r.rule_str(),
                "%s:%d 的 IP 类规则未带 no-resolve，且 conf 中引用它的 RULE-SET 行"
                "也未加行级 no-resolve 修饰；原文：%s" % (r.source, r.line, r.raw),
                "域名请求匹配到此规则之前，Surge 会先用本地 dns-server（223.5.5.5/"
                "119.29.29.29）解析该域名，被墙域名会被污染并把解析行为泄漏给国内 DNS。",
                "在该行末尾追加 ,no-resolve；或在 Surge.conf 对应 RULE-SET 行末尾追加 "
                ",no-resolve 做行级修饰。")
        return len(bad)

    # -- A2 ---------------------------------------------------------------

    def check_a2(self):
        sig_map = OrderedDict()
        for r in self.e.rules:
            if r.type in ("FINAL", "URL-REGEX") or r.value is None:
                continue
            if r.source in ("SYSTEM", "LAN"):
                continue
            sig_map.setdefault(r.signature(), []).append(r)

        groups = []
        for sig, occ in sig_map.items():
            if len(occ) < 2:
                continue
            files = set(o.source for o in occ)
            if len(files) < 2:
                continue                      # 同 list 内重复归 A3
            groups.append((sig, occ))

        for sig, occ in groups:
            winner, dead = occ[0], occ[1:]
            for d in dead:
                self.details["A2"].append((
                    d.source, d.line, d.rule_str(), d.policy,
                    winner.source, winner.line, winner.policy))

        # 按 (胜出规则, 胜出文件, 死条目文件, 策略对) 聚合
        buckets = OrderedDict()
        for sig, occ in groups:
            winner, dead = occ[0], occ[1:]
            for d in dead:
                key = (winner.source, winner.policy, d.source, d.policy)
                buckets.setdefault(key, []).append((winner, d))

        items = sorted(buckets.items(), key=lambda kv: -len(kv[1]))
        emitted = 0
        skipped = 0
        for (wf, wpol, df, dpol), pairs in items:
            if wpol == dpol:
                sev, kind, conf = "P2", "redundant", "high"
                impact = ("同一条目在两个 list 中重复且策略相同，后位为死条目；"
                          "无功能影响，但增加规则表体积与维护歧义。")
            elif dpol in DIRECT_POLICIES and wpol not in DIRECT_POLICIES:
                sev, kind, conf = "P0", "misroute", "high"
                impact = ("国内直连意图被前位代理规则抢走：这些域名实际走 %s 组，"
                          "用户可感知为国内站点绕道海外、变慢或触发风控。" % wpol)
            elif wpol in DIRECT_POLICIES and dpol not in DIRECT_POLICIES:
                sev, kind, conf = "P1", "misroute", "medium"
                impact = ("代理意图被前位直连规则抢走：这些域名实际直连（%s），"
                          "若为被墙域名会连接失败；也可能是刻意的国内分流设计。" % wf)
            else:
                sev, kind, conf = "P1", "shadowed", "high"
                impact = ("同一域名在两个代理组间分裂：实际生效 %s，%s 的意图 %s 永不生效，"
                          "破坏「同会话同出口」的 IP 一致性。" % (wpol, df, dpol))
            if emitted >= self.max_findings:
                skipped += len(pairs)
                continue
            sample = pairs[:self.samples]
            ev = ("%s(%s) 与 %s(%s) 存在 %d 条 (type,value) 完全相同的规则，"
                  "按 conf 顺序前者胜出、后者为死条目。样例：%s%s"
                  % (wf, wpol, df, dpol, len(pairs),
                     "; ".join("%s [%s:%d 生效 / %s:%d 死]"
                               % (d.rule_str(), w.source, w.line, d.source, d.line)
                               for w, d in sample),
                     "" if len(pairs) <= self.samples else " …等"))
            fix = ("从 %s 删除这些重复条目（或反向：若 %s 的策略才是期望值，"
                   "需把该条目从 %s 移除并在 conf 中调整 list 顺序）。"
                   % (df, dpol, wf))
            if self._add("A2", sev, kind, df, pairs[0][1].rule_str(), ev,
                         impact, fix, conf, by=pairs[0][0].rule_str(),
                         by_file=wf) is not None:
                emitted += 1
        if skipped:
            self._add("A2", "P3", "structure", "-", "-",
                      "A2 聚合后仍有 %d 条重复未单列（超出 --max-findings=%d）。"
                      % (skipped, self.max_findings),
                      "仅影响报告篇幅，不影响判定。",
                      "查看 a2_details.tsv 获取全量明细。", "high")
        return sum(len(v) for v in buckets.values())

    # -- A3 ---------------------------------------------------------------

    def check_a3(self):
        by_file = defaultdict(list)
        for r in self.domain_rules:
            if r.source in ("SYSTEM", "LAN"):
                continue
            by_file[r.source].append(r)

        total = 0
        buckets = OrderedDict()
        for fname, rules in by_file.items():
            suffix_first, kws, seen_sig = {}, [], {}
            for r in rules:
                if r.type == "DOMAIN-SUFFIX":
                    suffix_first.setdefault(norm_suffix(r), r)
                elif r.type == "DOMAIN-KEYWORD":
                    kws.append((norm_raw(r), r))
            kw_rx = None
            if kws:
                # 长关键词优先，保证 m.group(0) 能在 kw_map 中命中
                kw_rx = re.compile("|".join(
                    re.escape(k) for k, _ in sorted(kws, key=lambda x: -len(x[0]))))
            kw_map = {}
            for k, r in kws:
                kw_map.setdefault(k, r)

            for r in rules:
                v = norm_suffix(r)
                vraw = norm_raw(r)
                sig = r.signature()
                # 同 list 内精确重复
                if sig in seen_sig:
                    first = seen_sig[sig]
                    buckets.setdefault((fname, first.rule_str(), "dup"), []) \
                            .append((first, r))
                    total += 1
                    continue
                seen_sig[sig] = r
                cover = None
                # KEYWORD 吞后缀/域名：K 是 S 的子串 ⟹ 所有匹配 S 的 host 必含 K
                if kw_rx is not None and r.type != "DOMAIN-KEYWORD":
                    m = kw_rx.search(vraw)
                    if m and m.group(0) in kw_map:
                        cover = (kw_map[m.group(0)], "keyword")
                # SUFFIX 覆盖：从最短（最宽）的祖先后缀开始找，归组更集中
                if cover is None and r.type in ("DOMAIN", "DOMAIN-SUFFIX"):
                    for s in reversed(list(engine_mod.host_suffixes(v))):
                        if r.type == "DOMAIN-SUFFIX" and s == v:
                            continue          # 自身不算
                        c = suffix_first.get(s)
                        if c is not None and c is not r:
                            cover = (c, "suffix")
                            break
                # DOMAIN 被同名 SUFFIX 覆盖已由上面的 s == v 分支处理
                if cover is None:
                    continue
                c, how = cover
                buckets.setdefault((fname, c.rule_str(), how), []).append((c, r))
                total += 1

        for (fname, cover_str, how), pairs in buckets.items():
            for c, r in pairs:
                self.details["A3"].append(
                    (fname, r.line, r.rule_str(), how, c.line, c.rule_str()))

        how_text = {"suffix": "被同 list 内更短的 DOMAIN-SUFFIX 完全覆盖",
                    "keyword": "被同 list 内的 DOMAIN-KEYWORD 完全吞掉",
                    "dup": "在同一 list 内重复出现"}
        items = sorted(buckets.items(), key=lambda kv: -len(kv[1]))
        emitted, skipped = 0, 0
        for (fname, cover_str, how), pairs in items:
            if emitted >= self.max_findings:
                skipped += len(pairs)
                continue
            sample = [r.rule_str() for _c, r in pairs[:self.samples]]
            ev = ("%s 内 %d 条规则%s（覆盖方：%s，行 %d）。样例：%s%s"
                  % (fname, len(pairs), how_text[how], cover_str,
                     pairs[0][0].line, ", ".join(sample),
                     "" if len(pairs) <= self.samples else " …等"))
            if self._add("A3", "P2", "redundant", fname,
                         pairs[0][1].rule_str(), ev,
                         "同 list 内策略一致，二者中靠前者生效、另一条永不单独生效，"
                         "属纯冗余；只增加规则表体积与合并冲突面，无分流影响。",
                         "删除这 %d 条被覆盖的条目，保留覆盖方 %s。"
                         % (len(pairs), cover_str),
                         "high", by=cover_str, by_file=fname) is not None:
                emitted += 1
        if skipped:
            self._add("A3", "P3", "structure", "-", "-",
                      "A3 聚合后仍有 %d 条冗余未单列（超出 --max-findings=%d）。"
                      % (skipped, self.max_findings),
                      "仅影响报告篇幅。", "查看 a3_details.tsv 获取全量明细。", "high")
        return total

    # -- A4 ---------------------------------------------------------------

    def check_a4(self):
        """按 conf 顺序增量扫描：后位条目是否被前位（不同 list 的）更宽规则完全覆盖。

        候选由「更短后缀 / 更早关键词」增量生成，再用 engine.match 对候选逐条**复核**：
        以引擎真实判定的命中规则为准（可能是比候选更早的规则），从而拿到该条目的
        真实生效策略，避免把「已被更早的同值规则正确解析」误判成错误分流。
        DOMAIN-WILDCARD 造成的覆盖不在本项判定范围（离线成本过高），见 README。
        """
        seen_suffix = {}          # suffix -> Rule（首次出现）
        seen_kw = OrderedDict()   # keyword -> Rule
        kw_rx = None
        buckets = OrderedDict()
        total = 0

        for r in self.domain_rules:
            v = norm_suffix(r)
            vraw = norm_raw(r)
            if r.type in ("DOMAIN", "DOMAIN-SUFFIX"):
                cands = []
                if kw_rx is not None:
                    m = kw_rx.search(vraw)
                    if m and m.group(0) in seen_kw:
                        cands.append(seen_kw[m.group(0)])
                for s in engine_mod.host_suffixes(v):
                    if r.type == "DOMAIN-SUFFIX" and s == v:
                        continue      # 与自身等值的后缀 = A2 精确重复，不在 A4 重复报
                    c = seen_suffix.get(s)
                    if c is not None:
                        cands.append(c)
                cands = [c for c in cands
                         if c.idx < r.idx and c.source != r.source]
                if cands:
                    cover = self._verify_cover(r, v)
                    if cover is not None:
                        key = (cover.source, cover.rule_str(), cover.policy,
                               r.source, r.policy)
                        buckets.setdefault(key, []).append((cover, r))
                        total += 1
            # 登记
            if r.type == "DOMAIN-SUFFIX":
                seen_suffix.setdefault(v, r)
            elif r.type == "DOMAIN-KEYWORD":
                if vraw not in seen_kw:
                    seen_kw[vraw] = r
                    # 长关键词优先，保证 m.group(0) 能在 seen_kw 中命中
                    kw_rx = re.compile("|".join(
                        re.escape(k) for k in sorted(seen_kw, key=len, reverse=True)))

        for key, pairs in buckets.items():
            for c, r in pairs:
                self.details["A4"].append(
                    (r.source, r.line, r.rule_str(), r.policy,
                     c.source, c.line, c.rule_str(), c.policy))

        items = sorted(buckets.items(), key=lambda kv: -len(kv[1]))
        emitted, skipped = 0, 0
        for (cf, cstr, cpol, rf, rpol), pairs in items:
            if cpol == rpol:
                sev, kind, conf = "P2", "redundant", "high"
                impact = ("前位 %s 的 %s 已覆盖这些域名且策略相同（%s），"
                          "后位条目永不生效，属纯冗余。" % (cf, cstr, cpol))
            elif rpol in DIRECT_POLICIES and cpol not in DIRECT_POLICIES:
                sev, kind, conf = "P0", "misroute", "high"
                impact = ("国内直连区条目被前位代理区遮蔽：这些域名实际走 %s 组而非直连，"
                          "用户可感知为国内站点绕道海外、延迟升高甚至触发风控/验证码。" % cpol)
            elif cpol in DIRECT_POLICIES and rpol not in DIRECT_POLICIES:
                sev, kind, conf = "P1", "misroute", "medium"
                impact = ("代理意图被前位直连规则遮蔽：这些域名实际直连；"
                          "若属被墙服务会连接失败，也可能是刻意的国内分流设计。")
            elif cpol in REJECT_POLICIES or rpol in REJECT_POLICIES:
                sev, kind, conf = "P1", "shadowed", "medium"
                impact = "拦截与放行意图冲突，实际以前位 %s 为准。" % cpol
            else:
                sev, kind, conf = "P1", "shadowed", "high"
                impact = ("跨策略组遮蔽：实际生效 %s，%s 期望的 %s 永不生效，"
                          "同一业务会话可能分裂到两个出口，破坏 IP 一致性。"
                          % (cpol, rf, rpol))
            if emitted >= self.max_findings:
                skipped += len(pairs)
                continue
            sample = [r.rule_str() for _c, r in pairs[:self.samples]]
            ev = ("%s(%s) 中 %d 条条目被前位 %s:%d 的 %s(%s) 完全覆盖。样例：%s%s"
                  % (rf, rpol, len(pairs), cf, pairs[0][0].line, cstr, cpol,
                     ", ".join(sample),
                     "" if len(pairs) <= self.samples else " …等"))
            if rpol in DIRECT_POLICIES and cpol not in DIRECT_POLICIES:
                fix = ("确认这些域名应直连后：把 %s 收窄（改成更具体的子域），"
                       "或把这些条目提前到 %s 之前的直连 list（如 Domestic.list 前移/"
                       "新增例外行）。" % (cstr, cf))
            elif cpol == rpol:
                fix = "删除 %s 中这 %d 条被覆盖的条目。" % (rf, len(pairs))
            else:
                fix = ("二选一：把 %s 收窄以放行这些域名，或删除 %s 中永不生效的条目"
                       "并确认 %s 才是期望策略。" % (cstr, rf, cpol))
            if self._add("A4", sev, kind, rf, pairs[0][1].rule_str(), ev,
                         impact, fix, conf, by=cstr, by_file=cf) is not None:
                emitted += 1
        if skipped:
            self._add("A4", "P3", "structure", "-", "-",
                      "A4 聚合后仍有 %d 条遮蔽未单列（超出 --max-findings=%d）。"
                      % (skipped, self.max_findings),
                      "仅影响报告篇幅。", "查看 a4_details.tsv 获取全量明细。", "high")
        return total

    def _verify_cover(self, rule, probe_host):
        """用引擎复核：probe_host 实际命中哪条规则。

        返回真正的「遮蔽方」Rule；若未被遮蔽、或遮蔽方与本条同文件（属 A3）、
        或遮蔽方与本条 (type,value) 完全相同（属 A2），返回 None。
        """
        res = self.e.match(host=probe_host)
        idx = res.get("rule_index")
        if idx is None or idx >= rule.idx:
            return None
        cover = self.e.rules[idx]
        if cover.source == rule.source:
            return None
        if cover.signature() == rule.signature():
            return None
        return cover

    # -- A5 ---------------------------------------------------------------

    def check_a5(self):
        referenced, ref_lines = OrderedDict(), {}
        for ref, base, policy, mods, line in self.e.ruleset_refs:
            if base in ("SYSTEM", "LAN"):
                continue
            referenced[base] = policy
            ref_lines[base] = line

        # conf 中被注释掉的 RULE-SET 行（用于解释「文件存在但未引用」）
        commented = {}
        with open(self.e.conf_path, "r", encoding="utf-8", errors="replace") as fh:
            for i, raw in enumerate(fh, 1):
                s = raw.strip()
                if s.startswith("#") and "RULE-SET" in s:
                    base = s.rstrip("/").split("/")[-1].split(",")[0].strip()
                    if base.endswith(".list"):
                        commented[base] = i

        n = 0
        for base, ref, line in self.e.missing_lists:
            n += 1
            self._add("A5", "P0", "stale", base, "RULE-SET,%s" % ref,
                      "Surge.conf:%d 引用了 %s，但本地 lists/ 目录中不存在该文件。"
                      % (line, base),
                      "该 RULE-SET 在本地/CDN 缺失时 Surge 会跳过整段规则，"
                      "这一层分流直接失效，流量落到后面的兜底规则。",
                      "补齐 lists/%s，或从 Surge.conf 删除该 RULE-SET 行。" % base)

        existing = sorted(f for f in os.listdir(self.e.rules_dir)
                          if f.endswith(".list"))
        for f in existing:
            if f in referenced:
                continue
            note = ("（Surge.conf:%d 存在被注释掉的引用行）" % commented[f]
                    if f in commented else "（conf 中完全没有引用行）")
            n += 1
            self._add("A5", "P3", "stale", f, "-",
                      "lists/%s 存在于仓库但未被 Surge.conf 的任何 RULE-SET 引用%s。"
                      % (f, note),
                      "文件仍随 git/CDN 分发但对分流无任何作用；长期不更新会与上游脱节，"
                      "误以为生效会导致排障方向错误。",
                      "确认是刻意停用则加入 allowlist.json 豁免并在 docs/MAINTENANCE.md"
                      " 裁决登记中说明；否则在 conf 中恢复引用或从仓库移除。", "high")
        return n

    # -- A6 ---------------------------------------------------------------

    def check_a6(self):
        by_file = defaultdict(list)
        for r in self.e.rules:
            if r.type != "DOMAIN-KEYWORD" or r.source in ("SYSTEM", "LAN"):
                continue
            by_file[r.source].append(r)
            self.keywords.append((r.idx, r.source, r.line, r.value, r.policy))

        order = [ref[1] for ref in self.e.ruleset_refs]
        for fname in order:
            rules = by_file.get(fname)
            if not rules:
                continue
            kws = [r.value for r in rules]
            shown = kws[:40]
            # 启发式提示（仍不判错）：形如 IPv4 前缀的关键词
            ipish = [k for k in kws if IPV4_PREFIX_RX.match(k)]
            note = ""
            if ipish:
                note = ("｜提示：其中 %d 条形如 IPv4 前缀（如 %s），而 DOMAIN-KEYWORD "
                        "只对**域名**做子串匹配，纯 IP 请求没有 hostname、不会命中；"
                        "若原意是匹配 IP 段应改用 IP-CIDR,…,no-resolve。"
                        % (len(ipish), ", ".join(ipish[:3])))
            self._add("A6", "P3", "structure", fname,
                      "DOMAIN-KEYWORD ×%d" % len(kws),
                      "%s 含 %d 条 DOMAIN-KEYWORD（策略 %s）：%s%s —— "
                      "关键词是子串匹配，命中面无上界，本项只列出供人工复核，不判错。%s"
                      % (fname, len(kws), rules[0].policy, ", ".join(shown),
                         " …等" if len(kws) > 40 else "", note),
                      "过宽关键词会把同名第三方域名一并抓走（例如自建 sentry.*/"
                      "datadog.* 遥测域、含品牌名的无关站点），造成误分流与 IP 分裂；"
                      "形如 IP 前缀的关键词则通常是彻底不生效的死规则。",
                      "逐条确认：能收窄成 DOMAIN-SUFFIX 的收窄；形如 IP 前缀的改写为 "
                      "IP-CIDR 或删除；确属必要的在 allowlist.json 登记 reason。"
                      "完整表见 keyword_review.tsv。",
                      "low")
        return len(self.keywords)

    # -- A7 ---------------------------------------------------------------

    A7_PREFIXES = ("DOMAIN,", "DOMAIN-SUFFIX,", "DOMAIN-KEYWORD,", "DOMAIN-WILDCARD,",
                   "USER-AGENT,", "PROCESS-NAME,", "URL-REGEX,",
                   "IP-CIDR,", "IP-CIDR6,", "IP-ASN,", "GEOIP,",
                   "AND,", "OR,", "NOT,")
    #: A7/A8/A10 共用的已知类型集合（与 A7_PREFIXES 同源，保证三者口径一致）
    KNOWN_TYPES = frozenset(p.rstrip(",") for p in A7_PREFIXES)

    def check_a7(self):
        """A7：规则行格式 lint。两类：

        · **真·裸行**（无任何已知类型前缀）—— Surge 与本套引擎都会静默忽略：
          表面上已收录、实际不存在，且任何落点测试都不会替它报错
          （2026-08-30 迁移脚本踩坑后固化为发布闸门）。判 P1/format。
        · **小写类型段**（`user-agent,X` / `process-name,Y`）—— engine.py:510 与
          surge2clash.py:124 都做 `.upper()` 后当作真规则解析/剔除，而旧版 A7 把它
          误判成「裸行」、A8 完全看不见它（W7-T03）。现在归一后 A8 能抓到它并判
          P0/forbidden，A7 只保留一条 P1/case 的行格式告警。
        """
        n = 0
        for sl in self.source_lines():
            if sl.type in self.KNOWN_TYPES:
                if sl.type_raw == sl.type:
                    continue
                n += 1
                self._add("A7", "P1", "case", sl.file, sl.text[:80],
                          "%s:%d 规则类型段非全大写：`%s` —— engine.py 与 "
                          "surge2clash.py 都会 .upper() 后当作 %s 解析，"
                          "而本仓库的行格式约定是类型段全大写。"
                          % (sl.file, sl.line, sl.type_raw, sl.type),
                          "类型段大小写不一致会让「按字面 grep 找规则」「按行首前缀分区」"
                          "这类维护动作全部失效；历史上还导致 A8 禁令门禁被绕过"
                          "（本轮已在 A8/A10 侧做归一，此处只保留格式告警）。",
                          "把类型段改成全大写（%s,…）。" % sl.type,
                          "high")
                continue
            n += 1
            self._add("A7", "P1", "format", sl.file, sl.text[:80],
                      "%s:%d 无已知规则类型前缀：%s —— Surge 与离线引擎都会静默忽略此行。"
                      % (sl.file, sl.line, sl.text[:80]),
                      "规则看似已收录、实际不生效：目标域/进程落到后位表或 FINAL，"
                      "且所有测试都不会替它报错，属于最隐蔽的一类失效。",
                      "补上正确的类型前缀（如 DOMAIN-SUFFIX,），或删除该行。",
                      "high")
        return n

    # -- A8 ---------------------------------------------------------------

    def check_a8(self):
        """A8：禁止回流（forbidden / expected-absent）。

        allowlist.json 顶层 `forbidden` 段登记「按架构裁决必须持续不存在」的
        规则模式（fnmatch 全串匹配，对整行、去行尾注释的本体、以及去修饰符的
        `TYPE,VALUE` 头两段各试一次，且类型段统一大写后再试一遍）。与 exemptions
        相反：命中即 P0，且**不经过豁免**——把 D7（全库零 USER-AGENT/PROCESS-NAME）、
        D11（上游合并排除表）等自然语言裁决升级为机器门禁，防止上游再生/误合并
        把已删规则静默带回。
        直接扫源文件文本而非 engine 规则表，确保 engine 不解析的类型也逃不掉。

        作用域（R2-4）：条目可带 `file`（只在该表内禁）或 `not_file`（该表之外禁，
        即「必须只存在于该表」的唯一归属守卫）。缺省 = 全库语义，向后兼容。"""
        n = 0
        forb = [e for e in getattr(self.al, "forbidden", [])
                if e.get("pattern")]
        if not forb:
            return 0
        # 性能：无通配符的模式进 dict 做 O(1) 精确查，含通配符的才逐条 fnmatch。
        # 同一 pattern 可能有多条不同作用域的登记，故 exact 存列表。
        exact = defaultdict(list)
        globs = []
        for entry in forb:
            pat = entry["pattern"]
            if any(ch in pat for ch in "*?["):
                globs.append(entry)
            else:
                exact[pat].append(entry)
        for sl in self.source_lines():
            # 四种候选串：原始整行 / 去行尾注释的本体 / 类型段归一后的整条 / 归一后的头两段
            cands = []
            for c in (sl.text, sl.body, sl.norm, sl.head):
                if c and c not in cands:
                    cands.append(c)
            entry = None
            for c in cands:
                for e in exact.get(c, ()):
                    if self.al.forbidden_scope_ok(e, sl.file):
                        entry = e
                        break
                if entry is not None:
                    break
            if entry is None:
                for e in globs:
                    pat = e["pattern"]
                    if not any(fnmatch.fnmatch(c, pat) for c in cands):
                        continue
                    if not self.al.forbidden_scope_ok(e, sl.file):
                        continue
                    entry = e
                    break
            if entry is None:
                continue
            pat = entry["pattern"]
            scope = ""
            if entry.get("file"):
                scope = "（作用域 file=%s）" % entry["file"]
            elif entry.get("not_file"):
                scope = "（作用域 not_file=%s，即该模式只允许存在于 %s）" % (
                    entry["not_file"], entry["not_file"])
            n += 1
            self._add(
                "A8", "P0", "forbidden", sl.file, sl.text[:80],
                "%s:%d 命中 forbidden 模式 `%s`%s：%s —— 登记理由：%s"
                % (sl.file, sl.line, pat, scope, sl.text[:80],
                   entry.get("reason", "（未写 reason）")),
                "该规则按架构裁决必须持续不存在（已删除/已排除/只允许存在于别的表），"
                "此次出现说明上游再生或人工合并把它带了回来；"
                "带回即恢复当初删除它所要消除的危害。",
                "删除该行本身（若是 not_file 作用域，则把它搬回被指定的那张表）。"
                "禁止改为豁免——forbidden 模式不接受 exemption；若裁决确已变更，"
                "先更新 allowlist.json 的 forbidden 段与 docs/MAINTENANCE.md 裁决登记。",
                "high", exemptable=False)
        return n

    # -- A9 ---------------------------------------------------------------

    def check_a9(self):
        """A9：IP 跨表包含/遮蔽审计（**顺序感知**）。

        判据：按 conf 真实序扫描全部 IP-CIDR / IP-CIDR6，只报「后位 CIDR 被**前位**
        更宽的 CIDR 完全包含」——即后位那条是死条目。反向（narrow 在前、broad 在后）
        是**正确**的精确覆盖，不报。若按无序包含计数，当前仓库会报 31 条跨策略，
        其中 30 条行为正确，会把唯一真信号淹掉（advisor 裁决 8 / WB 交付 §3.5）。

        分级：
          · 同策略        → P3（不阻断，纯冗余）
          · 跨策略        → P1（同一段分裂到两个出口）
          · 被包含方 DIRECT 且包含方是代理 → P0（沿用 A2/A4 的直连被抢跑惯例）

        与 A2 的分界：完全相同的 (type,value) 归 A2，本项只报**真包含**。
        与 A3/A4 的分界：本项只看 IP 面，域名面归 A3/A4。

        **已知盲区（离线不可判）**：`IP-ASN` 与 `GEOIP` 无法在离线侧展开成前缀集合，
        因此「某条 CIDR 是否被前位的 IP-ASN/GEOIP 抢跑」判不了。本项会把这个盲区
        的规模（前位 ASN/GEOIP 条数 × 后位 CIDR 条数）单独报成一条 P3，便于跟踪，
        判定本身仍只基于 CIDR×CIDR。
        """
        nets = []
        for r in self.e.rules:
            if r.type not in ("IP-CIDR", "IP-CIDR6"):
                continue
            if r.source in ("SYSTEM", "LAN"):
                continue
            try:
                net = ipaddress.ip_network(r.value, strict=False)
            except ValueError:
                continue          # 非法 CIDR 由 A10 的严格解析报
            nets.append((net, r))

        seen = {}                 # (version, prefixlen, netaddr) -> Rule（首次出现）
        buckets = OrderedDict()
        total = 0
        for net, r in nets:
            best = None
            for plen in range(0, net.prefixlen + 1):
                sup = net.supernet(new_prefix=plen)
                got = seen.get((net.version, plen, int(sup.network_address)))
                if got is None or got.idx >= r.idx:
                    continue
                if plen == net.prefixlen and got.value == r.value:
                    continue      # (type,value) 完全相同 = A2 的地盘
                if best is None or got.idx < best.idx:
                    best = got
            key = (net.version, net.prefixlen, int(net.network_address))
            if key not in seen:
                seen[key] = r
            if best is None:
                continue
            total += 1
            self.details["A9"].append(
                (r.source, r.line, r.rule_str(), r.policy,
                 best.source, best.line, best.rule_str(), best.policy))
            bkey = (best.source, best.rule_str(), best.policy, r.source, r.policy)
            buckets.setdefault(bkey, []).append((best, r))

        items = sorted(buckets.items(), key=lambda kv: -len(kv[1]))
        emitted, skipped = 0, 0
        for (cf, cstr, cpol, rf, rpol), pairs in items:
            if cpol == rpol:
                sev, kind, conf = "P3", "redundant", "high"
                impact = ("前位 %s 的 %s 已完全包含这些网段且策略相同（%s），"
                          "后位条目永不生效，属纯冗余；不影响分流。" % (cf, cstr, cpol))
                fix = ("可删除 %s 中这 %d 条被包含的网段；若该表是机器生成层"
                       "（ChinaIP/ChinaDomain，约定零手改），在 allowlist.json 登记 "
                       "A9 豁免即可。" % (rf, len(pairs)))
            elif rpol in DIRECT_POLICIES and cpol not in DIRECT_POLICIES:
                sev, kind, conf = "P0", "misroute", "high"
                impact = ("直连意图的网段被**前位**代理段完全包含：这些 IP 实际走 %s 组"
                          "而非直连，用户可感知为国内地址绕道海外、延迟升高甚至触发风控。"
                          % cpol)
                fix = ("确认这些网段应直连后：把 %s 收窄，或把这些网段提前到 %s 之前的"
                       "直连表。若落点本就是期望值（如国内 IDC 里的境外厂商自有段），"
                       "在 allowlist.json 登记 A9 豁免并写清判据。" % (cstr, cf))
            elif cpol in DIRECT_POLICIES and rpol not in DIRECT_POLICIES:
                sev, kind, conf = "P1", "misroute", "medium"
                impact = ("代理意图的网段被前位直连段完全包含：这些 IP 实际直连；"
                          "若属被墙服务会连接失败，也可能是刻意的国内分流设计。")
                fix = ("二选一：把 %s 收窄，或删除 %s 中永不生效的网段并确认 %s "
                       "才是期望策略。" % (cstr, rf, cpol))
            else:
                sev, kind, conf = "P1", "shadowed", "high"
                impact = ("跨策略组的 IP 包含：实际生效 %s，%s 期望的 %s 永不生效，"
                          "同一业务的 IP 面可能分裂到两个出口。" % (cpol, rf, rpol))
                fix = ("二选一：把 %s 收窄以放行这些网段，或删除 %s 中永不生效的条目。"
                       % (cstr, rf))
            if emitted >= self.max_findings:
                skipped += len(pairs)
                continue
            sample = [r.rule_str() for _c, r in pairs[:self.samples]]
            ev = ("%s(%s) 中 %d 条 CIDR 被**前位** %s:%d 的 %s(%s) 完全包含"
                  "（按 conf 真实序，只报后位被前位吞掉的方向）。样例：%s%s"
                  % (rf, rpol, len(pairs), cf, pairs[0][0].line, cstr, cpol,
                     ", ".join(sample),
                     "" if len(pairs) <= self.samples else " …等"))
            if self._add("A9", sev, kind, rf, pairs[0][1].rule_str(), ev,
                         impact, fix, conf, by=cstr, by_file=cf) is not None:
                emitted += 1
        if skipped:
            self._add("A9", "P3", "structure", "-", "-",
                      "A9 聚合后仍有 %d 条包含关系未单列（超出 --max-findings=%d）。"
                      % (skipped, self.max_findings),
                      "仅影响报告篇幅。", "查看 a9_details.tsv 获取全量明细。", "high")

        # 盲区登记：IP-ASN / GEOIP 无法离线展开成前缀集合
        asn_geo = [r for r in self.e.rules
                   if r.type in ("IP-ASN", "GEOIP") and r.source not in ("SYSTEM", "LAN")]
        if asn_geo and nets:
            first = min(r.idx for r in asn_geo)
            after = sum(1 for _n, r in nets if r.idx > first)
            self._add("A9", "P3", "blindspot", "-", "IP-ASN/GEOIP × IP-CIDR",
                      "本项只做 CIDR×CIDR 的包含判定。全库另有 %d 条 IP-ASN/GEOIP"
                      "（%s），它们无法在离线侧展开成前缀集合；位于其后的 %d 条 CIDR "
                      "是否会被它们抢跑，A9 判不了。"
                      % (len(asn_geo),
                         ", ".join(sorted(set("%s:%s" % (r.source, r.rule_str())
                                              for r in asn_geo))[:6]) +
                         (" …等" if len(set(r.rule_str() for r in asn_geo)) > 6 else ""),
                         after),
                      "真实 Surge 会用 MaxMind/ASN 库判定，可能把某些 CIDR 提前抢走，"
                      "造成离线断言与真机落点不一致（scenarios 里已用 policy_in 双态"
                      "表达这类盲区）。",
                      "需要真机验证的用 realworld.py --crosscheck；场景断言一律用 "
                      "policy_in 双态而非硬断言。本条为登记项，不代表存在缺陷。",
                      "high")
        return total

    # -- A10 --------------------------------------------------------------

    def check_a10(self):
        """A10：单标签后缀与 PSL 边界门禁（+ 同一逐行循环内的行格式硬校验）。

        六个子检查，各自一个 kind（allowlist 可用 `kind` 键分别豁免，避免整表豁免
        把真缺陷一并静音）：

          single-label-tld      单标签 DOMAIN-SUFFIX，且在锁定的 IANA 根区表内
                                （= 认领整个 TLD，必须显式登记）
          single-label-special  单标签，且属 RFC6761/6762/7686/8375 特殊用途名
          single-label-unknown  单标签，两张表都不在 —— 通常是拼写错误或已撤销的 TLD
          psl-icann / psl-private
                                DOMAIN-SUFFIX 命中 PSL 注册边界（含 `*.parent` 与
                                `!exception` 的正确处理）= 把整个多租户命名空间收进来
          arity                 `TYPE,VALUE` 缺 VALUE
          strict-cidr           IP-CIDR/IP-CIDR6 带主机位（ip_network(strict=True) 失败）
          modifier              修饰符不在白名单内，或 no-resolve 挂在非 IP 类规则上

        判据数据源是**锁定快照**（tests/data/，哈希记录在 data/SNAPSHOTS.json）：
        门禁不联网，快照更新是一次有意的、可 review 的提交。
        """
        n = 0
        psl = self.psl
        if psl is None or not psl.available:
            self._add("A10", "P1", "stale", "-", "tests/data/",
                      "A10 需要锁定的 PSL 快照与 IANA TLD 表，但 %s 下缺少 "
                      "public_suffix_list.dat / tlds-alpha-by-domain.txt。"
                      % DEFAULT_DATA_DIR,
                      "单标签后缀与 PSL 边界门禁整体失效——这正是 R1-13 那批"
                      "多租户宽后缀能进库的原因。",
                      "按 tests/data/SNAPSHOTS.json 记录的 URL 重新下载快照，"
                      "校验 sha256 后放回 tests/data/。",
                      "high", exemptable=False)
            return 1

        for sl in self.source_lines():
            if not sl.known:
                continue          # 真·裸行归 A7
            # --- arity ---
            if not sl.value:
                n += 1
                self._add("A10", "P1", "arity", sl.file, sl.text[:80],
                          "%s:%d 只有类型段、没有值：%s"
                          % (sl.file, sl.line, sl.text[:80]),
                          "无值规则会被引擎与 Surge 静默丢弃或匹配空串，"
                          "属于「看似收录、实际不存在」的一类。",
                          "补上值，或删除该行。", "high")
                continue
            # --- modifier 白名单 ---
            for m in sl.mods:
                if not m:
                    continue
                low = m.lower()
                if low not in ALLOWED_MODIFIERS:
                    n += 1
                    self._add("A10", "P1", "modifier", sl.file, sl.text[:80],
                              "%s:%d 的修饰符 `%s` 不在白名单 %s 内。"
                              % (sl.file, sl.line, m, sorted(ALLOWED_MODIFIERS)),
                              "未知修饰符在 Surge 侧行为未定义；在 Clash 派生层"
                              "（classical provider 按逗号切分）会让整条规则或整个 "
                              "provider 加载失败。",
                              "删除该修饰符，或先确认 Surge 支持后再把它加进 "
                              "audit.py 的 ALLOWED_MODIFIERS 并在 DEVELOPMENT.md "
                              "登记行格式约定。", "high")
                elif low == "no-resolve" and sl.type not in IP_CLASS_TYPES:
                    n += 1
                    self._add("A10", "P1", "modifier", sl.file, sl.text[:80],
                              "%s:%d 在非 IP 类规则（%s）上挂了 no-resolve：%s"
                              % (sl.file, sl.line, sl.type, sl.text[:80]),
                              "no-resolve 只对 IP 类规则有意义；挂在域名类规则上"
                              "说明这一行的类型或意图写错了。",
                              "删掉 no-resolve，或把类型改成 IP-CIDR/IP-CIDR6/"
                              "IP-ASN/GEOIP。", "high")
            # --- 严格 CIDR ---
            if sl.type in ("IP-CIDR", "IP-CIDR6"):
                try:
                    ipaddress.ip_network(sl.value, strict=True)
                except ValueError as exc:
                    n += 1
                    self._add("A10", "P1", "strict-cidr", sl.file, sl.text[:80],
                              "%s:%d 的 CIDR 非规范形（严格解析失败）：%s —— %s"
                              % (sl.file, sl.line, sl.value, exc),
                              "带主机位的 CIDR（如 1.2.3.4/24）在不同实现里可能被"
                              "静默取整、也可能被整条丢弃；两种行为差一个 /24 的覆盖面。",
                              "改写成网络地址形（把主机位清零），或改用 /32、/128 "
                              "表达单个地址。", "high")
                continue
            # --- 单标签后缀 / PSL 边界 ---
            if sl.type != "DOMAIN-SUFFIX":
                continue
            v = sl.value.strip(".").lower()
            if not v:
                continue
            if "." not in v:
                if psl.is_iana_tld(v):
                    kind = "single-label-tld"
                    ev = ("%s:%d 的 `DOMAIN-SUFFIX,%s` 是**单标签后缀**，认领整个 TLD"
                          "（该串在锁定的 IANA 根区表中确实存在）。"
                          % (sl.file, sl.line, v))
                    impact = ("整个 TLD 下的任何域名都会被这一条接走。品牌 gTLD"
                              "（如 .google）通常正确，通用 gTLD（如 .wang）则会把"
                              "无关注册人的域名一并带走。")
                elif v in SPECIAL_USE_TLDS:
                    kind = "single-label-special"
                    ev = ("%s:%d 的 `DOMAIN-SUFFIX,%s` 是**单标签后缀**，属 "
                          "RFC6761/6762/7686/8375 特殊用途名或 ICANN 保留私用名。"
                          % (sl.file, sl.line, v))
                    impact = ("特殊用途名不进入公共 DNS；把它们钉在直连/内网表是"
                              "正确做法，但仍须显式登记以防被误当成真 TLD 处理。")
                else:
                    kind = "single-label-unknown"
                    ev = ("%s:%d 的 `DOMAIN-SUFFIX,%s` 是**单标签后缀**，但它"
                          "**既不在**锁定的 IANA 根区表里，**也不是**已知特殊用途名。"
                          % (sl.file, sl.line, v))
                    impact = ("多半是拼写错误、被撤销的 gTLD，或把二级域误写成了"
                              "单标签；这条规则永远不会命中任何真实请求。")
                n += 1
                self._add("A10", "P1", kind, sl.file, sl.norm, ev, impact,
                          "确属刻意认领整个 TLD 的，在 allowlist.json 用 "
                          "{\"check\":\"A10\",\"kind\":\"%s\",…} 登记并写清判据；"
                          "否则收窄成具体注册域或删除。" % kind,
                          "high")
                continue
            hit, sect, rule, how = psl.is_boundary(v)
            if not hit:
                continue
            kind = "psl-private" if sect == "private" else "psl-icann"
            if how == "wildcard-parent":
                why = ("PSL 里存在通配规则 `%s` —— 即 `%s` 的**每一个**子域都是"
                       "独立的公共后缀，本条等于把整个多租户命名空间一次收进来"
                       "（比后缀自身命中更宽）。" % (rule, v))
            else:
                why = "PSL 判定 `%s` 自身就是公共后缀（生效规则 `%s`）。" % (v, rule)
            n += 1
            self._add("A10", "P1", kind, sl.file, sl.norm,
                      "%s:%d 的 `DOMAIN-SUFFIX,%s` 命中 PSL **%s** 段：%s"
                      % (sl.file, sl.line, v, sect.upper() if sect else "?", why),
                      "公共后缀 = 注册边界：该后缀之下的每个标签属于**不同注册人**。"
                      "用 DOMAIN-SUFFIX 收录它，等于把该平台所有租户的流量一并"
                      "绑到同一个出口（R1-13 删掉的 40+ 条就是这一类）。",
                      "收窄成具体的注册域（`<tenant>.%s` 用 DOMAIN 精确形），"
                      "或——若这是第一方自持命名空间/刻意的兜底分层——在 "
                      "allowlist.json 用 {\"check\":\"A10\",\"kind\":\"%s\",…} "
                      "登记并写清判据。" % (v, kind),
                      "high")
        return n

    # -- 运行 --------------------------------------------------------------

    def run(self, checks):
        stats = OrderedDict()
        if "A1" in checks:
            stats["A1"] = self.check_a1()
        if "A2" in checks:
            stats["A2"] = self.check_a2()
        if "A3" in checks:
            stats["A3"] = self.check_a3()
        if "A4" in checks:
            stats["A4"] = self.check_a4()
        if "A5" in checks:
            stats["A5"] = self.check_a5()
        if "A6" in checks:
            stats["A6"] = self.check_a6()
        if "A7" in checks:
            stats["A7"] = self.check_a7()
        if "A8" in checks:
            stats["A8"] = self.check_a8()
        if "A9" in checks:
            stats["A9"] = self.check_a9()
        if "A10" in checks:
            stats["A10"] = self.check_a10()
        self.findings.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]],
                                          f["check"], f["id"]))
        return stats


# ---------------------------------------------------------------------------
# 输出
# ---------------------------------------------------------------------------

CHECK_TITLE = {
    "A1": "A1 IP 类规则 no-resolve 缺失",
    "A2": "A2 跨 list 精确重复",
    "A3": "A3 同 list 内部覆盖",
    "A4": "A4 跨 list 遮蔽",
    "A5": "A5 conf 引用完整性",
    "A6": "A6 DOMAIN-KEYWORD 审查表（不判错）",
    "A7": "A7 规则行格式 lint（裸行/未知前缀 → P1；小写类型段 → P1/case）",
    "A8": "A8 禁止回流（forbidden 模式出现 → P0，不可豁免；支持 file/not_file 作用域）",
    "A9": "A9 IP 跨表包含/遮蔽（顺序感知：只报后位被前位吞掉）",
    "A10": "A10 单标签后缀与 PSL 边界门禁（+ arity / 严格 CIDR / modifier 白名单）",
}

SEV_TITLE = {
    "P0": "P0 — 功能损坏或明确错误分流（用户可感知）",
    "P1": "P1 — IP 一致性 / DNS 泄漏风险",
    "P2": "P2 — 冗余 / 遮蔽 / 过宽但无直接伤害",
    "P3": "P3 — 风格 / 优化建议",
}


def write_report(path, aud, stats, checks, args):
    e = aud.e
    sev_count = defaultdict(int)
    check_count = defaultdict(int)
    for f in aud.findings:
        sev_count[f["severity"]] += 1
        check_count[f["check"]] += 1

    L = []
    a = L.append
    a("# Surge 规则体系静态审计报告（W6 / audit.py）\n")
    a("## 概述\n")
    a("- 配置：`%s`" % e.conf_path)
    a("- 规则目录：`%s`" % e.rules_dir)
    a("- 展开后全局规则数：**%d** 条，来自 %d 个来源（含内置 SYSTEM/LAN 近似）"
      % (len(e.rules), len(e.rules_by_file)))
    a("- 执行检查项：%s" % ", ".join(checks))
    a("- 豁免表：`%s`（%d 条规则，命中 %d 次，未命中 %d 条）"
      % (aud.al.path, len(aud.al.entries), sum(aud.al.hits.values()),
         len(aud.al.unused(checks))))
    a("- 未豁免 finding：**%d** 条（P0=%d, P1=%d, P2=%d, P3=%d）；被豁免 %d 条"
      % (len(aud.findings), sev_count["P0"], sev_count["P1"],
         sev_count["P2"], sev_count["P3"], len(aud.exempted)))
    if aud.psl is not None and aud.psl.available:
        a("- A10 锁定快照：`%s`（PSL %d 条规则，sha256 `%s…`）、`%s`（IANA TLD %d 条，"
          "sha256 `%s…`）\n"
          % (os.path.basename(aud.psl.psl_path), aud.psl.rule_count,
             aud.psl.sha256.get("psl", "")[:16],
             os.path.basename(aud.psl.tld_path or "-"), len(aud.psl.tlds),
             aud.psl.sha256.get("tld", "")[:16]))
    else:
        a("")

    a("### 各检查项原始命中量（聚合前）\n")
    a("| 检查项 | 说明 | 原始命中 | 输出 finding |")
    a("| --- | --- | ---: | ---: |")
    for c in checks:
        a("| %s | %s | %d | %d |"
          % (c, CHECK_TITLE[c].split(" ", 1)[1], stats.get(c, 0), check_count[c]))
    a("")

    a("### 引擎近似项声明（判定时须知）\n")
    for w in e.warnings[:40]:
        a("- %s" % w)
    if len(e.warnings) > 40:
        a("- …另有 %d 条同类告警" % (len(e.warnings) - 40))
    a("")

    a("## 发现明细（按严重度分组）\n")
    any_f = False
    for sev in ("P0", "P1", "P2", "P3"):
        group = [f for f in aud.findings if f["severity"] == sev]
        if not group:
            continue
        any_f = True
        a("### %s — 共 %d 条\n" % (SEV_TITLE[sev], len(group)))
        for f in group:
            a("#### %s [%s/%s] `%s` — `%s`\n"
              % (f["id"], f["check"], f["kind"], f["file"], f["rule"]))
            a("- **证据**：%s" % f["evidence"])
            a("- **影响**：%s" % f["impact"])
            a("- **修复**：%s" % f["fix"])
            a("- **置信度**：%s\n" % f["confidence"])
    if not any_f:
        a("（本次运行未产生未豁免 finding。）\n")

    if aud.exempted:
        a("## 已豁免条目（allowlist.json）\n")
        agg = defaultdict(int)
        reason = {}
        for x in aud.exempted:
            k = (x["check"], x["file"], x["reason"])
            agg[k] += 1
            reason[k] = x["reason"]
        a("| 检查项 | 文件 | 条数 | 豁免理由 |")
        a("| --- | --- | ---: | --- |")
        for (c, fl, rs), n in sorted(agg.items(), key=lambda kv: -kv[1]):
            a("| %s | %s | %d | %s |" % (c, fl, n, rs))
        a("")
        unused = aud.al.unused(checks)
        if unused:
            a("> 未命中的豁免条目（可能已随规则演进失效，建议复核后清理）：")
            for u in unused:
                a("> - check=%s file=%s rule=%s — %s"
                  % (u.get("check"), u.get("file", "*"), u.get("rule", "*"),
                     u.get("reason", "")))
            a("")

    pending = aud.al.pending(checks)
    if pending:
        a("## 待用户裁决的豁免（`pending_decision: true`）\n")
        a("这些条目的 reason 明写「本轮未裁决、保留原状待用户决策」。它们**不影响退出码**，"
          "但每次运行都单独列出——否则待裁决事项会被 `preventive` 伪装成永久豁免"
          "（审计 W7-T09）。逐条结案后请删除该键。\n")
        a("| 检查项 | 文件 | 规则 | 本次命中 | 待裁决内容 |")
        a("| --- | --- | --- | ---: | --- |")
        for e, hits in pending:
            want = e.get("check", "*")
            a("| %s | %s | `%s` | %d | %s |"
              % (want if isinstance(want, str) else ",".join(want),
                 e.get("file", "*"), e.get("rule", "*"), hits,
                 e.get("reason", "")))
        a("")

    if "A6" in checks and aud.keywords:
        a("## A6 DOMAIN-KEYWORD 审查表（不判错，供人工复核）\n")
        a("全量 %d 条见 `keyword_review.tsv`；下表按 conf 生效顺序列出前 120 条。\n"
          % len(aud.keywords))
        a("| # | 关键词 | 来源 list | 行 | 策略 |")
        a("| ---: | --- | --- | ---: | --- |")
        for i, (idx, src, line, val, pol) in enumerate(aud.keywords[:120], 1):
            a("| %d | `%s` | %s | %d | %s |" % (i, val, src, line, pol))
        a("")

    a("## 统计\n")
    a("| 严重度 | 条数 |")
    a("| --- | ---: |")
    for sev in ("P0", "P1", "P2", "P3"):
        a("| %s | %d |" % (sev, sev_count[sev]))
    a("| **合计** | **%d** |" % len(aud.findings))
    a("")
    a("退出码策略：存在严重度 ≥ %s 的未豁免 finding 时 `audit.py` 返回 1。"
      % args.fail_on)

    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(L) + "\n")


def write_details(outdir, aud):
    headers = {
        "A2": ["dead_file", "dead_line", "rule", "dead_policy",
               "winner_file", "winner_line", "winner_policy"],
        "A3": ["file", "line", "rule", "how", "cover_line", "cover_rule"],
        "A4": ["file", "line", "rule", "policy",
               "cover_file", "cover_line", "cover_rule", "cover_policy"],
        "A9": ["file", "line", "rule", "policy",
               "cover_file", "cover_line", "cover_rule", "cover_policy"],
    }
    for key, rows in aud.details.items():
        if not rows:
            continue
        path = os.path.join(outdir, "%s_details.tsv" % key.lower())
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\t".join(headers[key]) + "\n")
            for row in rows:
                fh.write("\t".join(str(x) for x in row) + "\n")
    if aud.keywords:
        with open(os.path.join(outdir, "keyword_review.tsv"), "w",
                  encoding="utf-8") as fh:
            fh.write("rule_index\tsource\tline\tkeyword\tpolicy\n")
            for row in aud.keywords:
                fh.write("\t".join(str(x) for x in row) + "\n")


# ---------------------------------------------------------------------------
# 自检：合成一份「植入了已知缺陷」的配置，验证 A1–A8 确实会触发
# ---------------------------------------------------------------------------

SELFTEST_CONF = u"""\
[Proxy]
PhysA = snell, 1.2.3.4, 63001

[Proxy Group]
Proxy = select, PhysA
Final = select, PhysA, DIRECT

[Rule]
RULE-SET,https://cdn.example/gh/x/y@main/Front.list,Proxy
RULE-SET,https://cdn.example/gh/x/y@main/Leak.list,Proxy
RULE-SET,https://cdn.example/gh/x/y@main/Safe.list,Proxy,no-resolve
RULE-SET,https://cdn.example/gh/x/y@main/Direct.list,DIRECT
RULE-SET,https://cdn.example/gh/x/y@main/Missing.list,DIRECT
FINAL,Final
"""

SELFTEST_LISTS = {
    "Front.list": u"""\
DOMAIN,repeat.example.com
DOMAIN,repeat.example.com
DOMAIN-SUFFIX,shadow.example.com
DOMAIN-SUFFIX,dup.example.org
DOMAIN-SUFFIX,inner.example.net
DOMAIN-SUFFIX,a.inner.example.net
DOMAIN-SUFFIX,x-swallowme-y.example.io
DOMAIN-KEYWORD,swallowme
PROCESS-NAME,Claude
bare-line-without-type.example.invalid
""",
    "Leak.list": u"""\
IP-CIDR,198.51.100.0/24
""",
    "Safe.list": u"""\
IP-CIDR,192.0.2.0/24
""",
    "Direct.list": u"""\
DOMAIN-SUFFIX,sub.shadow.example.com
DOMAIN-SUFFIX,dup.example.org
DOMAIN-SUFFIX,clean.example.cn
PROCESS-NAME,claude
""",
    "Unused.list": u"""\
DOMAIN-SUFFIX,never-referenced.example
""",
}


# --- 第二份合成配置：A9 / A10 / A8 作用域与大小写归一（S34–S46）--------------
# 独立于第一份，避免新样本扰动 S01–S33 的精确计数。
SELFTEST2_CONF = u"""\
[Proxy]
PhysA = snell, 1.2.3.4, 63001

[Proxy Group]
Proxy = select, PhysA
Final = select, PhysA, DIRECT

[Rule]
RULE-SET,https://cdn.example/gh/x/y@main/Broad.list,Proxy
RULE-SET,https://cdn.example/gh/x/y@main/Narrow.list,DIRECT
RULE-SET,https://cdn.example/gh/x/y@main/Same.list,Proxy
RULE-SET,https://cdn.example/gh/x/y@main/Lint.list,Proxy
RULE-SET,https://cdn.example/gh/x/y@main/Scope.list,Proxy
RULE-SET,https://cdn.example/gh/x/y@main/Other.list,Proxy
FINAL,Final
"""

SELFTEST2_LISTS = {
    # 前位的三条「宽」网段（策略 Proxy）
    "Broad.list": u"""\
IP-CIDR,203.0.113.0/24,no-resolve
IP-CIDR,198.18.0.0/15,no-resolve
IP-CIDR6,2001:db8:aaaa::/48,no-resolve
""",
    # 后位、DIRECT：203.0.113.128/25 被前位代理段吞掉 → A9 P0
    # 192.0.2.0/24 是「顺序感知」哨兵：它在前，Same.list 的 /16 在后，必须**不报**
    "Narrow.list": u"""\
IP-CIDR,203.0.113.128/25,no-resolve
IP-CIDR,192.0.2.0/24,no-resolve
""",
    # 后位、同策略：两条被前位同策略段吞掉 → A9 P3；192.0.0.0/16 是反向哨兵
    "Same.list": u"""\
IP-CIDR,198.18.32.0/20,no-resolve
IP-CIDR6,2001:db8:aaaa:1::/64,no-resolve
IP-CIDR,192.0.0.0/16,no-resolve
""",
    # A10 的正负样本 + A7/A8 大小写归一样本
    "Lint.list": u"""\
DOMAIN-SUFFIX,museum
DOMAIN-SUFFIX,localhost
DOMAIN-SUFFIX,zzznotatld
DOMAIN-SUFFIX,ac.uk
DOMAIN-SUFFIX,blogspot.com
DOMAIN-SUFFIX,oaiusercontent.com
DOMAIN-SUFFIX,xn--gmqw5a.xn--j6w193g
DOMAIN-SUFFIX,city.kobe.jp
DOMAIN-SUFFIX,plain.example.com
IP-CIDR,100.64.0.1/26,no-resolve
IP-CIDR,100.65.0.0/16,no-resolve,force-remote-dns
DOMAIN-SUFFIX,
user-agent,LowerCaseUA*
""",
    "Scope.list": u"""\
DOMAIN-SUFFIX,scoped.example
DOMAIN-SUFFIX,only-here.example
""",
    "Other.list": u"""\
DOMAIN-SUFFIX,scoped.example
DOMAIN-SUFFIX,only-here.example
""",
}

SELFTEST2_ALLOW = {
    "version": 1,
    "exemptions": [],
    "forbidden": [
        {"pattern": "DOMAIN-SUFFIX,scoped.example", "file": "Scope.list",
         "reason": "自检用：file 作用域 —— 只在 Scope.list 内是禁令"},
        {"pattern": "DOMAIN-SUFFIX,only-here.example", "not_file": "Scope.list",
         "reason": "自检用：not_file 作用域 —— 只允许存在于 Scope.list"},
        {"pattern": "USER-AGENT,*",
         "reason": "自检用：D7 全库零 UA（小写行必须也被抓到）"},
    ],
}


def run_audit_selftest(verbose=True):
    import tempfile
    import shutil

    results = []

    def check(name, got, want):
        results.append({"name": name, "ok": got == want, "got": got, "want": want})

    tmpdir = tempfile.mkdtemp(prefix="surge-audit-selftest-")
    try:
        rules_dir = os.path.join(tmpdir, "rules")
        os.makedirs(rules_dir)
        conf = os.path.join(tmpdir, "Surge.conf")
        with open(conf, "w", encoding="utf-8") as fh:
            fh.write(SELFTEST_CONF)
        for name, body in SELFTEST_LISTS.items():
            with open(os.path.join(rules_dir, name), "w", encoding="utf-8") as fh:
                fh.write(body)
        empty = os.path.join(tmpdir, "empty.json")
        with open(empty, "w", encoding="utf-8") as fh:
            fh.write('{"version":1,"exemptions":[]}')

        eng = engine_mod.Engine(conf, rules_dir)
        aud = Auditor(eng, Allowlist(empty))
        stats = aud.run(list(ALL_CHECKS))
        F = aud.findings

        def pick(check_id, **kw):
            out = []
            for f in F:
                if f["check"] != check_id:
                    continue
                if all(f.get(k) == v for k, v in kw.items()):
                    out.append(f)
            return out

        # A1：Leak.list 缺 no-resolve，Safe.list 靠 conf 行级修饰豁免
        check("S01 A1 命中缺 no-resolve 的 IP 规则", stats["A1"], 1)
        check("S02 A1 定位到 Leak.list",
              [f["file"] for f in pick("A1")], ["Leak.list"])
        check("S03 A1 严重度 P1", [f["severity"] for f in pick("A1")], ["P1"])
        check("S04 A1 不误报 conf 行级 no-resolve 的 Safe.list",
              [f for f in pick("A1") if f["file"] == "Safe.list"], [])

        # A2：跨 list 精确重复且策略冲突 → P0 misroute
        a2 = pick("A2")
        check("S05 A2 命中 1 组跨 list 重复", len(a2), 1)
        check("S06 A2 死条目在 Direct.list", a2[0]["file"], "Direct.list")
        check("S07 A2 直连意图被代理抢走 → P0", a2[0]["severity"], "P0")
        check("S08 A2 kind=misroute", a2[0]["kind"], "misroute")
        check("S09 A2 PROCESS-NAME 大小写变体不算重复",
              [f for f in a2 if "PROCESS-NAME" in f["rule"]], [])

        # A3：同 list 内 后缀覆盖 / 关键词吞并 / 精确重复
        a3rules = sorted(f["rule"] for f in pick("A3"))
        check("S10 A3 命中 3 条同 list 冗余", stats["A3"], 3)
        check("S11 A3 覆盖后缀/关键词/重复三种形态", a3rules,
              sorted(["DOMAIN-SUFFIX,a.inner.example.net",
                      "DOMAIN-SUFFIX,x-swallowme-y.example.io",
                      "DOMAIN,repeat.example.com"]))
        check("S12 A3 全部为 P2",
              sorted(set(f["severity"] for f in pick("A3"))), ["P2"])

        # A4：直连区条目被前位代理区遮蔽 → P0
        a4 = pick("A4")
        check("S13 A4 命中 1 组跨 list 遮蔽", len(a4), 1)
        check("S14 A4 被遮蔽方是 Direct.list 的条目",
              (a4[0]["file"], a4[0]["rule"]),
              ("Direct.list", "DOMAIN-SUFFIX,sub.shadow.example.com"))
        check("S15 A4 直连被代理遮蔽 → P0/misroute",
              (a4[0]["severity"], a4[0]["kind"]), ("P0", "misroute"))
        check("S16 A4 不重复报 A2 已覆盖的精确重复",
              [f for f in a4 if "dup.example.org" in f["rule"]], [])

        # A5：引用缺失（P0）+ 存在但未被引用（P3）
        a5 = pick("A5")
        check("S17 A5 命中 2 条", len(a5), 2)
        check("S18 A5 缺失的被引用 list 判 P0",
              sorted((f["file"], f["severity"]) for f in a5),
              sorted([("Missing.list", "P0"), ("Unused.list", "P3")]))

        # A6：关键词审查表
        check("S19 A6 收集到全部关键词", stats["A6"], 1)
        check("S20 A6 输出 P3 且不判错",
              [(f["severity"], f["kind"]) for f in pick("A6")],
              [("P3", "structure")])

        # A7：无类型前缀的裸行必须被捕获（正向 fixture）
        a7 = pick("A7")
        check("S28 A7 命中 1 条裸行", stats["A7"], 1)
        check("S29 A7 定位到 Front.list 的裸行且判 P1",
              [(f["file"], f["severity"],
                f["rule"].startswith("bare-line-without-type")) for f in a7],
              [("Front.list", "P1", True)])

        # A8：无 forbidden 段时不产生任何 finding
        check("S30 A8 无 forbidden 段时为 0", stats["A8"], 0)

        # 豁免表生效
        al_path = os.path.join(tmpdir, "allow.json")
        with open(al_path, "w", encoding="utf-8") as fh:
            json.dump({"version": 1, "exemptions": [
                {"check": "A4", "file": "Direct.list",
                 "rule": "DOMAIN-SUFFIX,sub.shadow.example.com",
                 "by": "DOMAIN-SUFFIX,shadow.example.com", "reason": "自检用"},
                {"check": ["A5"], "file": "Unused.list", "reason": "自检用"},
                {"check": "A8", "file": "*", "rule": "PROCESS-NAME,*",
                 "reason": "自检用：试图豁免 forbidden，必须无效"},
            ], "forbidden": [
                {"pattern": "PROCESS-NAME,*",
                 "reason": "自检用：D7 全库零进程规则"},
            ]}, fh)
        aud2 = Auditor(engine_mod.Engine(conf, rules_dir), Allowlist(al_path))
        aud2.run(list(ALL_CHECKS))
        check("S21 allowlist 按 (check,file,rule,by) 豁免 A4",
              [f for f in aud2.findings if f["check"] == "A4"], [])
        check("S22 allowlist check 支持数组写法（A5/Unused 被豁免）",
              [f["file"] for f in aud2.findings if f["check"] == "A5"],
              ["Missing.list"])
        check("S23 豁免计数正确", len(aud2.exempted), 2)
        check("S24 未被豁免的 P0 仍然保留",
              sorted(set(f["check"] for f in aud2.findings
                         if f["severity"] == "P0")), ["A2", "A5", "A8"])

        # A8：forbidden 命中 P0，且 exemptions 无法豁免
        a8 = [f for f in aud2.findings if f["check"] == "A8"]
        check("S31 A8 抓到全部 PROCESS-NAME 回流行", len(a8), 2)
        check("S32 A8 判 P0/forbidden 且无视同名 exemption",
              sorted(set((f["severity"], f["kind"]) for f in a8)),
              [("P0", "forbidden")])
        check("S33 A8 命中的文件集合正确",
              sorted(f["file"] for f in a8), ["Direct.list", "Front.list"])

        # findings schema 完整性（00-context.md 约定）
        need = ["id", "severity", "kind", "file", "rule", "evidence",
                "impact", "fix", "confidence"]
        check("S25 findings 含 00-context 全部必需字段",
              all(all(k in f for k in need) for f in F), True)
        check("S26 findings 附带 source=audit",
              sorted(set(f["source"] for f in F)), ["audit"])
        check("S27 severity 取值合法",
              sorted(set(f["severity"] for f in F)) ==
              sorted(set(f["severity"] for f in F) & set(SEVERITY_ORDER)), True)

        # ------------------------------------------------------------------
        # 第二份合成配置：A9 / A10 / A8 作用域与大小写归一（S34–S46）
        # ------------------------------------------------------------------
        rules2 = os.path.join(tmpdir, "rules2")
        os.makedirs(rules2)
        conf2 = os.path.join(tmpdir, "Surge2.conf")
        with open(conf2, "w", encoding="utf-8") as fh:
            fh.write(SELFTEST2_CONF)
        for name, body in SELFTEST2_LISTS.items():
            with open(os.path.join(rules2, name), "w", encoding="utf-8") as fh:
                fh.write(body)
        al2_path = os.path.join(tmpdir, "allow2.json")
        with open(al2_path, "w", encoding="utf-8") as fh:
            json.dump(SELFTEST2_ALLOW, fh, ensure_ascii=False)

        psl = PublicSuffixList(
            os.path.join(DEFAULT_DATA_DIR, "public_suffix_list.dat"),
            os.path.join(DEFAULT_DATA_DIR, "tlds-alpha-by-domain.txt"))
        check("S36 A10 锁定快照可用（PSL + IANA TLD 表已入库）", psl.available, True)

        aud3 = Auditor(engine_mod.Engine(conf2, rules2), Allowlist(al2_path),
                       psl=psl)
        aud3.run(list(ALL_CHECKS))
        G = aud3.findings

        def pick3(check_id, **kw):
            return [f for f in G if f["check"] == check_id
                    and all(f.get(k) == v for k, v in kw.items())]

        # --- A8 作用域 ---
        a8 = pick3("A8")
        check("S34 A8 file 作用域：同一 pattern 只在指定表内命中",
              sorted((f["file"], f["rule"]) for f in a8
                     if "scoped.example" in f["rule"]),
              [("Scope.list", "DOMAIN-SUFFIX,scoped.example")])
        check("S35 A8 not_file 作用域：只在指定表**之外**命中",
              sorted((f["file"], f["rule"]) for f in a8
                     if "only-here.example" in f["rule"]),
              [("Other.list", "DOMAIN-SUFFIX,only-here.example")])
        check("S37 A8 抓到小写类型段的 UA 行并判 P0（W7-T03 大小写绕过已封）",
              sorted((f["severity"], f["file"]) for f in a8
                     if f["rule"].lower().startswith("user-agent")),
              [("P0", "Lint.list")])
        check("S38 A8 合计 3 条（file 1 + not_file 1 + 小写 UA 1）", len(a8), 3)

        # --- A7 大小写分流 ---
        a7 = pick3("A7")
        check("S39 A7 把小写已知类型判 case 而非 format",
              sorted((f["kind"], f["severity"], f["file"]) for f in a7),
              [("case", "P1", "Lint.list")])

        # --- A9 顺序感知 ---
        a9 = pick3("A9")
        check("S40 A9 原始命中 3 条（跨策略 1 + 同策略 2）",
              len(aud3.details["A9"]), 3)
        check("S41 A9 跨策略且被包含方 DIRECT → P0/misroute",
              sorted((f["severity"], f["kind"], f["file"], f["rule"])
                     for f in a9 if f["file"] == "Narrow.list"),
              [("P0", "misroute", "Narrow.list", "IP-CIDR,203.0.113.128/25")])
        check("S42 A9 同策略 → P3/redundant（v4 与 v6 各一条）",
              sorted((f["severity"], f["rule"]) for f in a9
                     if f["file"] == "Same.list"),
              [("P3", "IP-CIDR,198.18.32.0/20"),
               ("P3", "IP-CIDR6,2001:db8:aaaa:1::/64")])
        check("S43 A9 顺序感知：narrow 在前、broad 在后**不报**"
              "（192.0.0.0/16 ⊃ 192.0.2.0/24）",
              [f for f in a9 if "192.0" in f["rule"]], [])

        # --- A10 ---
        a10 = pick3("A10")
        a10_map = dict((f["rule"], f["kind"]) for f in a10)
        check("S44 A10 单标签三分类正确（IANA TLD / 特殊用途名 / 未知串）",
              [a10_map.get("DOMAIN-SUFFIX,museum"),
               a10_map.get("DOMAIN-SUFFIX,localhost"),
               a10_map.get("DOMAIN-SUFFIX,zzznotatld")],
              ["single-label-tld", "single-label-special", "single-label-unknown"])
        check("S45 A10 PSL：ICANN / PRIVATE / *.parent / IDNA 四种形态全部命中",
              [a10_map.get("DOMAIN-SUFFIX,ac.uk"),
               a10_map.get("DOMAIN-SUFFIX,blogspot.com"),
               a10_map.get("DOMAIN-SUFFIX,oaiusercontent.com"),
               a10_map.get("DOMAIN-SUFFIX,xn--gmqw5a.xn--j6w193g")],
              ["psl-icann", "psl-private", "psl-private", "psl-icann"])
        check("S46 A10 零误报：PSL !exception（city.kobe.jp）与普通注册域不报",
              sorted(r for r in a10_map
                     if "kobe" in r or "plain.example.com" in r), [])
        check("S47 A10 arity / strict-cidr / modifier 各命中 1",
              sorted(f["kind"] for f in a10
                     if f["kind"] in ("arity", "strict-cidr", "modifier")),
              ["arity", "modifier", "strict-cidr"])
        check("S48 A10 全部判 P1",
              sorted(set(f["severity"] for f in a10)), ["P1"])

        # --- A10 的 kind 作用域豁免：只静音一类子检查 ---
        al4_path = os.path.join(tmpdir, "allow4.json")
        with open(al4_path, "w", encoding="utf-8") as fh:
            json.dump({"version": 1, "forbidden": SELFTEST2_ALLOW["forbidden"],
                       "exemptions": [
                           {"check": "A10", "file": "Lint.list",
                            "kind": "psl-private", "rule": "*",
                            "reason": "自检用：只豁免 psl-private 子检查"}]}, fh,
                      ensure_ascii=False)
        aud4 = Auditor(engine_mod.Engine(conf2, rules2), Allowlist(al4_path),
                       psl=psl)
        aud4.run(list(ALL_CHECKS))
        k4 = sorted(set(f["kind"] for f in aud4.findings if f["check"] == "A10"))
        check("S49 exemptions 的 kind 键只静音指定子检查，其余照报",
              k4, ["arity", "modifier", "psl-icann", "single-label-special",
                   "single-label-tld", "single-label-unknown", "strict-cidr"])

        # --- pending_decision ---
        al5_path = os.path.join(tmpdir, "allow5.json")
        with open(al5_path, "w", encoding="utf-8") as fh:
            json.dump({"version": 1, "forbidden": [], "exemptions": [
                {"check": "A10", "file": "Lint.list", "kind": "psl-private",
                 "rule": "*", "preventive": True, "pending_decision": True,
                 "reason": "自检用：待裁决"}]}, fh, ensure_ascii=False)
        al5 = Allowlist(al5_path)
        aud5 = Auditor(engine_mod.Engine(conf2, rules2), al5, psl=psl)
        aud5.run(list(ALL_CHECKS))
        check("S50 pending_decision 条目即使 preventive 也必须被单独列出",
              [(e.get("file"), h) for e, h in al5.pending(list(ALL_CHECKS))],
              [("Lint.list", 2)])
        check("S51 pending_decision 不改变 unused 语义（preventive 仍免告警）",
              al5.unused(list(ALL_CHECKS)), [])
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    passed = sum(1 for r in results if r["ok"])
    failed = len(results) - passed
    if verbose:
        for r in results:
            line = "[%s] %s" % ("PASS" if r["ok"] else "FAIL", r["name"])
            if not r["ok"]:
                line += "\n       got : %r\n       want: %r" % (r["got"], r["want"])
            print(line)
        print("-" * 66)
        print("audit 自检合计 %d 条：通过 %d，失败 %d" % (len(results), passed, failed))
    return {"total": len(results), "passed": passed, "failed": failed,
            "cases": results}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="audit.py", description="Surge 规则体系静态审计器（A1–A8）")
    ap.add_argument("--conf", help="Surge.conf 路径（默认自动定位）")
    ap.add_argument("--rules", help=".list 所在目录（默认 conf 同级 rules/lists/）")
    ap.add_argument("--allowlist", default=DEFAULT_ALLOWLIST,
                    help="豁免表路径（默认同目录 allowlist.json）")
    ap.add_argument("--data-dir", default=DEFAULT_DATA_DIR,
                    help="A10 锁定快照目录（PSL + IANA TLD 表；默认 tests/data/）")
    ap.add_argument("--check", default="all",
                    help="逗号分隔的检查项，如 A1,A4；默认 all")
    ap.add_argument("--out", help="输出目录（写 findings.jsonl / report.md / *.tsv）")
    ap.add_argument("--json", action="store_true", help="stdout 输出 JSON 摘要")
    ap.add_argument("--max-findings", type=int, default=200,
                    help="每个检查项最多输出多少条聚合 finding（默认 200）")
    ap.add_argument("--samples", type=int, default=6,
                    help="每条聚合 finding 中展示的样例条数（默认 6）")
    ap.add_argument("--fail-on", default="P1", choices=["P0", "P1", "P2", "P3"],
                    help="严重度达到该级别即以退出码 1 失败（默认 P1）")
    ap.add_argument("--selftest", action="store_true",
                    help="用植入已知缺陷的合成配置验证 A1–A8 与豁免表")
    args = ap.parse_args(argv)

    if args.selftest:
        rep = run_audit_selftest(verbose=not args.json)
        if args.json:
            print(json.dumps(rep, ensure_ascii=False, indent=2))
        return 1 if rep["failed"] else 0

    checks = (list(ALL_CHECKS) if args.check.strip().lower() == "all"
              else [c.strip().upper() for c in args.check.split(",") if c.strip()])
    for c in checks:
        if c not in ALL_CHECKS:
            ap.error("未知检查项 %s（可选：%s）" % (c, ",".join(ALL_CHECKS)))

    eng = engine_mod.build_engine(args.conf, args.rules)
    al = Allowlist(args.allowlist)
    psl = PublicSuffixList(
        os.path.join(args.data_dir, "public_suffix_list.dat"),
        os.path.join(args.data_dir, "tlds-alpha-by-domain.txt"))
    aud = Auditor(eng, al, max_findings=args.max_findings,
                  samples=args.samples, psl=psl)
    stats = aud.run(checks)

    sev_count = defaultdict(int)
    for f in aud.findings:
        sev_count[f["severity"]] += 1
    threshold = SEVERITY_ORDER[args.fail_on]
    failing = sum(1 for f in aud.findings
                  if SEVERITY_ORDER[f["severity"]] <= threshold)

    if args.out:
        os.makedirs(args.out, exist_ok=True)
        with open(os.path.join(args.out, "findings.jsonl"), "w",
                  encoding="utf-8") as fh:
            for f in aud.findings:
                fh.write(json.dumps(f, ensure_ascii=False) + "\n")
        write_report(os.path.join(args.out, "report.md"), aud, stats, checks, args)
        write_details(args.out, aud)

    summary = OrderedDict()
    summary["conf"] = eng.conf_path
    summary["rules_dir"] = eng.rules_dir
    summary["total_rules"] = len(eng.rules)
    summary["checks"] = checks
    summary["raw_hits"] = stats
    summary["findings"] = len(aud.findings)
    summary["by_severity"] = {s: sev_count[s] for s in ("P0", "P1", "P2", "P3")}
    summary["by_check"] = {c: sum(1 for f in aud.findings if f["check"] == c)
                           for c in checks}
    summary["exempted"] = len(aud.exempted)
    summary["allowlist_unused"] = len(al.unused(checks))
    summary["allowlist_pending"] = [
        {"check": e.get("check"), "file": e.get("file", "*"),
         "rule": e.get("rule", "*"), "hits": h, "reason": e.get("reason", "")}
        for e, h in al.pending(checks)]
    summary["exemptions_total"] = len(al.entries)
    summary["forbidden_total"] = len(al.forbidden)
    if psl.available:
        summary["snapshots"] = {"psl_sha256": psl.sha256.get("psl"),
                                "psl_rules": psl.rule_count,
                                "tld_sha256": psl.sha256.get("tld"),
                                "tlds": len(psl.tlds)}
    summary["fail_on"] = args.fail_on
    summary["failing"] = failing
    summary["out"] = args.out

    if args.json:
        print(json.dumps(summary, ensure_ascii=False, indent=2))
    else:
        print("配置        : %s" % eng.conf_path)
        print("规则总数    : %d 条" % len(eng.rules))
        print("检查项      : %s" % ", ".join(checks))
        print("原始命中    : %s" % ", ".join("%s=%d" % kv for kv in stats.items()))
        print("未豁免发现  : %d 条（P0=%d P1=%d P2=%d P3=%d）"
              % (len(aud.findings), sev_count["P0"], sev_count["P1"],
                 sev_count["P2"], sev_count["P3"]))
        print("已豁免      : %d 条；豁免表未命中 %d 条"
              % (len(aud.exempted), len(al.unused(checks))))
        pending = al.pending(checks)
        if pending:
            print("待裁决豁免  : %d 条（不影响退出码，但每次运行都提示）" % len(pending))
            for e, h in pending:
                reason = e.get("reason", "")
                print("  · %-16s %-34s 命中 %d —— %s"
                      % (e.get("file", "*"), e.get("rule", "*"), h,
                         reason[:88] + ("…" if len(reason) > 88 else "")))
        if args.out:
            print("输出目录    : %s" % args.out)
        print("退出判定    : fail-on=%s → 失败 %d 条" % (args.fail_on, failing))
        if aud.findings:
            print("-" * 66)
            for f in aud.findings[:15]:
                print("[%s] %s %-3s %-16s %s"
                      % (f["severity"], f["id"], f["check"], f["file"], f["rule"]))
            if len(aud.findings) > 15:
                print("… 另有 %d 条，见 report.md / findings.jsonl"
                      % (len(aud.findings) - 15))

    return 1 if failing else 0


if __name__ == "__main__":
    sys.exit(main())
