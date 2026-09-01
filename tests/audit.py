#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""audit.py — 分流测试套件 L1：规则体系静态审计（发布闸门）。

复用 engine.py 的解析器（同一张按 conf 顺序展开的全局规则表），做 10 项检查：

  A1  IP 类规则缺 no-resolve（含 conf RULE-SET 行级修饰豁免）—— DNS 泄漏红线
  A2  跨 list 精确重复（后位是死条目；直连被代理抢走 = P0）
  A3  同 list 内部覆盖（DOMAIN ⊂ SUFFIX / SUFFIX ⊂ 更短 SUFFIX / KEYWORD 吞并 / 重复）
  A4  跨 list 遮蔽（后位被前位更宽规则覆盖，engine 复核真实命中；直连被遮 = P0）
  A5  conf 引用完整性（引用的表必须存在；存在的表必须被引用或豁免）
  A6  DOMAIN-KEYWORD 审查表（P3，只列出供人工复核，不判错）
  A7  行格式 lint（无类型前缀的裸行 = 静默死规则 P1；小写类型段 P1/case）
  A8  禁止回流（allowlist `forbidden` 段命中即 P0，不可豁免；支持 file/not_file 作用域）
  A9  IP 跨表包含（顺序感知：只报「后位 CIDR 被前位完全包含」；ASN/GEOIP 盲区单列 P3）
  A10 单标签后缀与 PSL 注册边界门禁 + arity / 严格 CIDR / modifier 白名单
      （判据是锁定快照 tests/data/，门禁不联网）

豁免表 allowlist.json：`exemptions` 按 (check, file, rule) 匹配，可选 by / by_file /
kind 收窄豁免面，`preventive: true` 为防回归条目（未命中不算无用豁免）；每条必须写
reason。顶层 `forbidden` 段由 A8 强制，不吃豁免。

用法：audit.py [--conf C] [--rules D] [--check A1,A4|all] [--fail-on P1] [--out DIR] [--selftest]
--out 只写 findings.jsonl。退出码：存在严重度 ≥ --fail-on 的未豁免 finding 时返回 1。
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
DIRECT_POLICIES = frozenset(("DIRECT",))
REJECT_POLICIES = frozenset(("REJECT", "REJECT-DROP", "REJECT-TINYGIF",
                             "REJECT-NO-DROP"))

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_ALLOWLIST = os.path.join(HERE, "allowlist.json")
DEFAULT_DATA_DIR = os.path.join(HERE, "data")

ALL_CHECKS = ("A1", "A2", "A3", "A4", "A5", "A6", "A7", "A8", "A9", "A10")

#: 本仓库行格式约定：list 内只允许 no-resolve 修饰符，且只对 IP 类有意义。
ALLOWED_MODIFIERS = frozenset(("no-resolve",))
IP_CLASS_TYPES = frozenset(("IP-CIDR", "IP-CIDR6", "IP-ASN", "GEOIP"))

#: RFC6761/6762/7686/9476 特殊用途名 + 事实私用 TLD：单标签形态是正确的。
SPECIAL_USE_TLDS = frozenset((
    "example", "invalid", "local", "localhost", "test", "onion", "internal",
    "alt", "corp", "home", "intranet", "lan", "localdomain", "private",
))

IPV4_PREFIX_RX = re.compile(r"^\d{1,3}(\.\d{1,3}){1,3}\.?$")


def norm_suffix(rule):
    """后缀比较用值：仅 DOMAIN-SUFFIX 去掉可能的前导点。"""
    v = (rule.value or "").lower()
    return v.lstrip(".") if rule.type == "DOMAIN-SUFFIX" else v


def norm_raw(rule):
    """关键词包含判定用值：保留原样（前导点有语义，如 `.tmall.com`）。"""
    return (rule.value or "").lower()


# ---------------------------------------------------------------------------
# 豁免表
# ---------------------------------------------------------------------------

class Allowlist(object):
    """exemptions 按 (check, file, rule) 豁免，可选 by / by_file / kind 收窄；
    preventive=true 的条目未命中不计入「无用豁免」。forbidden 段由 A8 强制，
    命中即 P0 且不经过豁免；条目可带 file（只在该表内禁）或 not_file
    （该表之外禁，即「必须只存在于该表」）。所有键支持 fnmatch 通配。"""

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
        f = entry.get("file")
        if f is not None and not fnmatch.fnmatch(file_name or "", f):
            return False
        nf = entry.get("not_file")
        if nf is not None and fnmatch.fnmatch(file_name or "", nf):
            return False
        return True

    def unused(self, ran_checks=None):
        """未命中且非 preventive 的豁免条目（排除本次未执行的检查项）。"""
        out = []
        for i, e in enumerate(self.entries):
            if self.hits[i] or e.get("preventive"):
                continue
            if ran_checks is not None:
                want = e.get("check", "*")
                names = [want] if isinstance(want, str) else (want or ["*"])
                if "*" not in names and not (set(names) & set(ran_checks)):
                    continue
            out.append(e)
        return out


# ---------------------------------------------------------------------------
# A10 判据：锁定的 PSL + IANA 根区 TLD 快照
# ---------------------------------------------------------------------------

def _idna_label(label):
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
    """锁定 PSL 快照 + IANA 根区 TLD 表。lookup() 实现 publicsuffix.org 标准算法
    （`*` 通配单标签、`!exception` 优先）；is_boundary() 判「注册边界」——值自身是
    公共后缀，或 PSL 存在 `*.value` 通配（此时该后缀等于把整个多租户命名空间收进来）。"""

    def __init__(self, psl_path=None, tld_path=None):
        self.psl_path = psl_path
        self.tld_path = tld_path
        self.by_len = defaultdict(list)      # 标签数 -> [(labels, is_exception, section)]
        self.wild_parents = {}
        self.tlds = set()
        self.rule_count = 0
        self.sha256 = {}
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
                    elif "BEGIN PRIVATE DOMAINS" in s:
                        section = "private"
                    elif "END" in s and "DOMAINS" in s:
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
                if s and not s.startswith("#"):
                    self.tlds.add(_idna_label(s))

    def lookup(self, domain):
        """返回 (is_public_suffix, section, prevailing_rule)。"""
        labels = idna_domain(domain).split(".")
        n = len(labels)
        matches = []
        for k in range(1, n + 1):
            tail = labels[n - k:]
            for rl, exc, sect in self.by_len.get(k, ()):
                if all(rlab == "*" or rlab == tail[i] for i, rlab in enumerate(rl)):
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
    """一条 .list 非注释行的规范化视图。"""

    __slots__ = ("file", "line", "text", "body", "type_raw", "type",
                 "value", "mods", "norm", "head", "known")

    def __init__(self, file_name, lineno, raw, known_types):
        self.file = file_name
        self.line = lineno
        self.text = raw.strip()
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
        self.mods = parts[2:]
        norm_parts = [self.type] + parts[1:]
        self.norm = ",".join(norm_parts)
        self.head = ",".join(norm_parts[:2])


# ---------------------------------------------------------------------------
# 审计器
# ---------------------------------------------------------------------------

def classify_shadow(cover_policy, dead_policy, cover_file):
    """A2/A4/A9 共用的遮蔽分级：返回 (severity, kind, 一句话影响)。"""
    if cover_policy == dead_policy:
        return ("P2", "redundant", "前位已覆盖且策略相同，后位是纯冗余死条目")
    if dead_policy in DIRECT_POLICIES and cover_policy not in DIRECT_POLICIES:
        return ("P0", "misroute",
                "直连意图被前位 %s 抢走：国内目标绕道海外、变慢或触发风控" % cover_policy)
    if cover_policy in DIRECT_POLICIES and dead_policy not in DIRECT_POLICIES:
        return ("P1", "misroute",
                "代理意图被前位直连（%s）抢走：被墙目标会连接失败" % cover_file)
    if cover_policy in REJECT_POLICIES or dead_policy in REJECT_POLICIES:
        return ("P1", "shadowed", "拦截与放行意图冲突，实际以前位 %s 为准" % cover_policy)
    return ("P1", "shadowed",
            "跨组遮蔽：实际生效 %s，%s 永不生效，会话可能分裂到两个出口"
            % (cover_policy, dead_policy))


class Auditor(object):

    #: A7/A8/A10 共用的已知类型集合（含 A8 禁用类型，保证源扫描口径一致）。
    A7_PREFIXES = ("DOMAIN,", "DOMAIN-SUFFIX,", "DOMAIN-KEYWORD,", "DOMAIN-WILDCARD,",
                   "USER-AGENT,", "PROCESS-NAME,", "URL-REGEX,",
                   "IP-CIDR,", "IP-CIDR6,", "IP-ASN,", "GEOIP,",
                   "AND,", "OR,", "NOT,")
    KNOWN_TYPES = frozenset(p.rstrip(",") for p in A7_PREFIXES)

    def __init__(self, eng, allowlist, max_findings=200, samples=6, psl=None):
        self.e = eng
        self.al = allowlist
        self.max_findings = max_findings
        self.samples = samples
        self.psl = psl
        self.findings = []
        self.exempted = []
        self.keywords = 0
        self._seq = 0
        self._lines = None
        self.domain_rules = [r for r in self.e.rules
                             if r.type in ("DOMAIN", "DOMAIN-SUFFIX",
                                           "DOMAIN-KEYWORD")]

    def source_lines(self):
        if self._lines is None:
            out = []
            for fname in sorted(os.listdir(self.e.rules_dir)):
                if not fname.endswith(".list"):
                    continue
                with open(os.path.join(self.e.rules_dir, fname),
                          "r", encoding="utf-8") as fh:
                    for lineno, raw in enumerate(fh, 1):
                        t = raw.strip()
                        if t and not t.startswith("#"):
                            out.append(SourceLine(fname, lineno, raw, self.KNOWN_TYPES))
            self._lines = out
        return self._lines

    def _add(self, check, severity, kind, file_name, rule_str, evidence,
             fix="", by=None, by_file=None, exemptable=True):
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
        f["check"] = check
        f["kind"] = kind
        f["severity"] = severity
        f["file"] = file_name
        f["rule"] = rule_str
        f["evidence"] = evidence
        f["fix"] = fix
        self.findings.append(f)
        return f

    def _overflow(self, check, skipped):
        if skipped:
            self._add(check, "P3", "structure", "-", "-",
                      "%s 聚合后仍有 %d 条未单列（超出 --max-findings=%d）"
                      % (check, skipped, self.max_findings))

    # -- A1 ---------------------------------------------------------------

    def check_a1(self):
        bad = [r for r in self.e.rules if r.is_ip_class and not r.no_resolve]
        for r in bad:
            self._add("A1", "P1", "dns-leak", r.source, r.rule_str(),
                      "%s:%d IP 类规则未带 no-resolve（conf RULE-SET 行也无行级修饰）"
                      "——域名请求到此会先被本地 DNS 解析，泄漏访问意图" % (r.source, r.line),
                      "在该行末尾追加 ,no-resolve，或在 conf 对应 RULE-SET 行加行级修饰")
        return len(bad)

    # -- A2 ---------------------------------------------------------------

    def check_a2(self):
        sig_map = OrderedDict()
        for r in self.e.rules:
            if r.type == "FINAL" or r.value is None or r.source in ("SYSTEM", "LAN"):
                continue
            sig_map.setdefault(r.signature(), []).append(r)

        buckets = OrderedDict()
        total = 0
        for sig, occ in sig_map.items():
            if len(occ) < 2 or len(set(o.source for o in occ)) < 2:
                continue          # 同 list 内重复归 A3
            winner, dead = occ[0], occ[1:]
            for d in dead:
                total += 1
                key = (winner.source, winner.policy, d.source, d.policy)
                buckets.setdefault(key, []).append((winner, d))

        emitted, skipped = 0, 0
        for (wf, wpol, df, dpol), pairs in sorted(buckets.items(),
                                                  key=lambda kv: -len(kv[1])):
            if emitted >= self.max_findings:
                skipped += len(pairs)
                continue
            sev, kind, impact = classify_shadow(wpol, dpol, wf)
            sample = "; ".join("%s [%s:%d 生效 / %s:%d 死]"
                               % (d.rule_str(), w.source, w.line, d.source, d.line)
                               for w, d in pairs[:self.samples])
            if self._add("A2", sev, kind, df, pairs[0][1].rule_str(),
                         "%s(%s) 与 %s(%s) 有 %d 条完全相同的规则，前者胜出。%s。样例：%s%s"
                         % (wf, wpol, df, dpol, len(pairs), impact, sample,
                            "" if len(pairs) <= self.samples else " …等"),
                         "从 %s 删除重复条目（或确认 %s 才是期望策略后反向处理）" % (df, dpol),
                         by=pairs[0][0].rule_str(), by_file=wf) is not None:
                emitted += 1
        self._overflow("A2", skipped)
        return total

    # -- A3 ---------------------------------------------------------------

    def check_a3(self):
        by_file = defaultdict(list)
        for r in self.domain_rules:
            if r.source not in ("SYSTEM", "LAN"):
                by_file[r.source].append(r)

        how_text = {"suffix": "被同 list 更短的 DOMAIN-SUFFIX 完全覆盖",
                    "keyword": "被同 list 的 DOMAIN-KEYWORD 完全吞掉",
                    "dup": "在同一 list 内重复出现"}
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
                v, vraw, sig = norm_suffix(r), norm_raw(r), r.signature()
                if sig in seen_sig:
                    buckets.setdefault((fname, seen_sig[sig].rule_str(), "dup"),
                                       []).append((seen_sig[sig], r))
                    total += 1
                    continue
                seen_sig[sig] = r
                cover = None
                if kw_rx is not None and r.type != "DOMAIN-KEYWORD":
                    m = kw_rx.search(vraw)
                    if m and m.group(0) in kw_map:
                        cover = (kw_map[m.group(0)], "keyword")
                if cover is None and r.type in ("DOMAIN", "DOMAIN-SUFFIX"):
                    # 从最短（最宽）的祖先后缀开始找，归组更集中；自身不算
                    for s in reversed(list(engine_mod.host_suffixes(v))):
                        if r.type == "DOMAIN-SUFFIX" and s == v:
                            continue
                        c = suffix_first.get(s)
                        if c is not None and c is not r:
                            cover = (c, "suffix")
                            break
                if cover is None:
                    continue
                c, how = cover
                buckets.setdefault((fname, c.rule_str(), how), []).append((c, r))
                total += 1

        emitted, skipped = 0, 0
        for (fname, cover_str, how), pairs in sorted(buckets.items(),
                                                     key=lambda kv: -len(kv[1])):
            if emitted >= self.max_findings:
                skipped += len(pairs)
                continue
            sample = ", ".join(r.rule_str() for _c, r in pairs[:self.samples])
            if self._add("A3", "P2", "redundant", fname, pairs[0][1].rule_str(),
                         "%s 内 %d 条规则%s（覆盖方 %s 行 %d，同策略纯冗余）。样例：%s%s"
                         % (fname, len(pairs), how_text[how], cover_str,
                            pairs[0][0].line, sample,
                            "" if len(pairs) <= self.samples else " …等"),
                         "删除被覆盖的条目，保留 %s" % cover_str,
                         by=cover_str, by_file=fname) is not None:
                emitted += 1
        self._overflow("A3", skipped)
        return total

    # -- A4 ---------------------------------------------------------------

    def check_a4(self):
        """按 conf 顺序增量扫描跨 list 遮蔽；候选由更短后缀/更早关键词生成，
        再用 engine.match 复核真实命中，避免把「已被更早同值规则正确解析」误判。"""
        seen_suffix, seen_kw = {}, OrderedDict()
        kw_rx = None
        buckets = OrderedDict()
        total = 0

        for r in self.domain_rules:
            v, vraw = norm_suffix(r), norm_raw(r)
            if r.type in ("DOMAIN", "DOMAIN-SUFFIX"):
                cands = []
                if kw_rx is not None:
                    m = kw_rx.search(vraw)
                    if m and m.group(0) in seen_kw:
                        cands.append(seen_kw[m.group(0)])
                for s in engine_mod.host_suffixes(v):
                    if r.type == "DOMAIN-SUFFIX" and s == v:
                        continue      # 等值后缀 = A2 的地盘
                    c = seen_suffix.get(s)
                    if c is not None:
                        cands.append(c)
                if any(c.idx < r.idx and c.source != r.source for c in cands):
                    cover = self._verify_cover(r, v)
                    if cover is not None:
                        key = (cover.source, cover.rule_str(), cover.policy,
                               r.source, r.policy)
                        buckets.setdefault(key, []).append((cover, r))
                        total += 1
            if r.type == "DOMAIN-SUFFIX":
                seen_suffix.setdefault(v, r)
            elif r.type == "DOMAIN-KEYWORD" and vraw not in seen_kw:
                seen_kw[vraw] = r
                kw_rx = re.compile("|".join(
                    re.escape(k) for k in sorted(seen_kw, key=len, reverse=True)))

        emitted, skipped = 0, 0
        for (cf, cstr, cpol, rf, rpol), pairs in sorted(buckets.items(),
                                                        key=lambda kv: -len(kv[1])):
            if emitted >= self.max_findings:
                skipped += len(pairs)
                continue
            sev, kind, impact = classify_shadow(cpol, rpol, cf)
            sample = ", ".join(r.rule_str() for _c, r in pairs[:self.samples])
            if self._add("A4", sev, kind, rf, pairs[0][1].rule_str(),
                         "%s(%s) 中 %d 条被前位 %s:%d 的 %s(%s) 完全覆盖。%s。样例：%s%s"
                         % (rf, rpol, len(pairs), cf, pairs[0][0].line, cstr, cpol,
                            impact, sample,
                            "" if len(pairs) <= self.samples else " …等"),
                         "收窄 %s，或删除 %s 中永不生效的条目" % (cstr, rf),
                         by=cstr, by_file=cf) is not None:
                emitted += 1
        self._overflow("A4", skipped)
        return total

    def _verify_cover(self, rule, probe_host):
        """engine 复核 probe_host 的真实命中；同文件归 A3、同签名归 A2，返回 None。"""
        res = self.e.match(host=probe_host)
        idx = res.get("rule_index")
        if idx is None or idx >= rule.idx:
            return None
        cover = self.e.rules[idx]
        if cover.source == rule.source or cover.signature() == rule.signature():
            return None
        return cover

    # -- A5 ---------------------------------------------------------------

    def check_a5(self):
        referenced = {base for _ref, base, _p, _m, _l in self.e.ruleset_refs
                      if base not in ("SYSTEM", "LAN")}
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
                      "Surge.conf:%d 引用了 %s，但 lists/ 中不存在——该层分流直接失效"
                      % (line, base),
                      "补齐 lists/%s，或从 conf 删除该 RULE-SET 行" % base)
        for f in sorted(f for f in os.listdir(self.e.rules_dir)
                        if f.endswith(".list")):
            if f in referenced:
                continue
            note = ("（conf:%d 有被注释掉的引用行）" % commented[f]
                    if f in commented else "（conf 中无引用行）")
            n += 1
            self._add("A5", "P3", "stale", f, "-",
                      "lists/%s 存在但未被 conf 引用%s——仍随 CDN 分发但对分流无作用"
                      % (f, note),
                      "刻意停用则登记 allowlist 豁免；否则恢复引用或移除文件")
        return n

    # -- A6 ---------------------------------------------------------------

    def check_a6(self):
        by_file = OrderedDict()
        for r in self.e.rules:
            if r.type == "DOMAIN-KEYWORD" and r.source not in ("SYSTEM", "LAN"):
                by_file.setdefault(r.source, []).append(r)
                self.keywords += 1
        for fname, rules in by_file.items():
            kws = [r.value for r in rules]
            ipish = [k for k in kws if IPV4_PREFIX_RX.match(k)]
            note = ("｜其中 %d 条形如 IPv4 前缀（如 %s）——DOMAIN-KEYWORD 只匹配域名，"
                    "纯 IP 请求不会命中，应改用 IP-CIDR,…,no-resolve"
                    % (len(ipish), ", ".join(ipish[:3]))) if ipish else ""
            self._add("A6", "P3", "structure", fname,
                      "DOMAIN-KEYWORD ×%d" % len(kws),
                      "%s 含 %d 条 DOMAIN-KEYWORD（策略 %s）：%s%s——关键词命中面无上界，"
                      "只列出供人工复核，不判错%s"
                      % (fname, len(kws), rules[0].policy, ", ".join(kws[:40]),
                         " …等" if len(kws) > 40 else "", note),
                      "能收窄成 DOMAIN-SUFFIX 的收窄；确属必要的在 allowlist 登记 reason")
        return self.keywords

    # -- A7 ---------------------------------------------------------------

    def check_a7(self):
        """裸行（无已知类型前缀）会被 Surge 与引擎静默忽略 = 最隐蔽的死规则，P1；
        小写类型段会被解析层 .upper() 吞掉、历史上绕过过 A8 门禁，P1/case。"""
        n = 0
        for sl in self.source_lines():
            if sl.known:
                if sl.type_raw != sl.type:
                    n += 1
                    self._add("A7", "P1", "case", sl.file, sl.text[:80],
                              "%s:%d 类型段非全大写：`%s`——本仓库行格式约定类型段全大写"
                              % (sl.file, sl.line, sl.type_raw),
                              "改成 %s,…" % sl.type)
                continue
            n += 1
            self._add("A7", "P1", "format", sl.file, sl.text[:80],
                      "%s:%d 无已知规则类型前缀——Surge 与离线引擎都会静默忽略此行"
                      % (sl.file, sl.line),
                      "补上正确的类型前缀，或删除该行")
        return n

    # -- A8 ---------------------------------------------------------------

    def check_a8(self):
        """forbidden 模式命中即 P0 且不可豁免。直接扫源文件文本（含类型段大写归一
        后的四种候选串），确保 engine 不解析的类型也逃不掉。"""
        forb = [e for e in self.al.forbidden if e.get("pattern")]
        if not forb:
            return 0
        exact, globs = defaultdict(list), []
        for entry in forb:
            if any(ch in entry["pattern"] for ch in "*?["):
                globs.append(entry)
            else:
                exact[entry["pattern"]].append(entry)

        n = 0
        for sl in self.source_lines():
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
                if entry:
                    break
            if entry is None:
                for e in globs:
                    if (any(fnmatch.fnmatch(c, e["pattern"]) for c in cands)
                            and self.al.forbidden_scope_ok(e, sl.file)):
                        entry = e
                        break
            if entry is None:
                continue
            scope = ""
            if entry.get("file"):
                scope = "（作用域 file=%s）" % entry["file"]
            elif entry.get("not_file"):
                scope = "（作用域 not_file=%s，只允许存在于该表）" % entry["not_file"]
            n += 1
            self._add("A8", "P0", "forbidden", sl.file, sl.text[:80],
                      "%s:%d 命中 forbidden 模式 `%s`%s——登记理由：%s"
                      % (sl.file, sl.line, entry["pattern"], scope,
                         entry.get("reason", "（未写 reason）")),
                      "删除该行（not_file 作用域则搬回指定表）；forbidden 不接受豁免，"
                      "裁决变更须先改 allowlist 的 forbidden 段",
                      exemptable=False)
        return n

    # -- A9 ---------------------------------------------------------------

    def check_a9(self):
        """顺序感知：只报「后位 CIDR 被前位更宽 CIDR 完全包含」（后位是死条目）；
        narrow 在前、broad 在后是正确的精确覆盖，不报。IP-ASN/GEOIP 离线不可展开，
        其抢跑盲区单列一条 P3 登记。"""
        nets = []
        for r in self.e.rules:
            if r.type not in ("IP-CIDR", "IP-CIDR6") or r.source in ("SYSTEM", "LAN"):
                continue
            try:
                nets.append((ipaddress.ip_network(r.value, strict=False), r))
            except ValueError:
                continue          # 非法 CIDR 由 A10 报

        seen = {}                 # (version, prefixlen, netaddr) -> 首次出现的 Rule
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
                    continue      # 完全相同 = A2 的地盘
                if best is None or got.idx < best.idx:
                    best = got
            seen.setdefault((net.version, net.prefixlen, int(net.network_address)), r)
            if best is None:
                continue
            total += 1
            key = (best.source, best.rule_str(), best.policy, r.source, r.policy)
            buckets.setdefault(key, []).append((best, r))

        emitted, skipped = 0, 0
        for (cf, cstr, cpol, rf, rpol), pairs in sorted(buckets.items(),
                                                        key=lambda kv: -len(kv[1])):
            if emitted >= self.max_findings:
                skipped += len(pairs)
                continue
            if cpol == rpol:
                sev, kind, impact = "P3", "redundant", "同策略纯冗余，不影响分流"
            else:
                sev, kind, impact = classify_shadow(cpol, rpol, cf)
            sample = ", ".join(r.rule_str() for _c, r in pairs[:self.samples])
            if self._add("A9", sev, kind, rf, pairs[0][1].rule_str(),
                         "%s(%s) 中 %d 条 CIDR 被前位 %s:%d 的 %s(%s) 完全包含"
                         "（顺序感知，只报后位被吞）。%s。样例：%s%s"
                         % (rf, rpol, len(pairs), cf, pairs[0][0].line, cstr, cpol,
                            impact, sample,
                            "" if len(pairs) <= self.samples else " …等"),
                         "收窄 %s，或删除 %s 中被包含的网段（机器生成层用 allowlist 豁免）"
                         % (cstr, rf),
                         by=cstr, by_file=cf) is not None:
                emitted += 1
        self._overflow("A9", skipped)

        asn_geo = [r for r in self.e.rules
                   if r.type in ("IP-ASN", "GEOIP") and r.source not in ("SYSTEM", "LAN")]
        if asn_geo and nets:
            first = min(r.idx for r in asn_geo)
            after = sum(1 for _n, r in nets if r.idx > first)
            self._add("A9", "P3", "blindspot", "-", "IP-ASN/GEOIP × IP-CIDR",
                      "本项只判 CIDR×CIDR。另有 %d 条 IP-ASN/GEOIP 离线无法展开，"
                      "其后的 %d 条 CIDR 是否被抢跑判不了；真机验证用 realworld.py "
                      "--crosscheck，场景断言用 policy_in 双态。本条为登记项，不代表缺陷"
                      % (len(asn_geo), after))
        return total

    # -- A10 --------------------------------------------------------------

    def check_a10(self):
        """单标签后缀与 PSL 注册边界门禁 + 同一循环内的行格式硬校验。
        kind：single-label-tld / single-label-special / single-label-unknown /
        psl-icann / psl-private / arity / strict-cidr / modifier（allowlist 可按
        kind 分别豁免）。判据是锁定快照，门禁不联网。"""
        psl = self.psl
        if psl is None or not psl.available:
            self._add("A10", "P1", "stale", "-", "tests/data/",
                      "缺少锁定的 PSL / IANA TLD 快照（%s），单标签与 PSL 边界门禁"
                      "整体失效" % DEFAULT_DATA_DIR,
                      "按 tests/data/SNAPSHOTS.json 记录的 URL 重新下载并校验 sha256",
                      exemptable=False)
            return 1

        n = 0
        for sl in self.source_lines():
            if not sl.known:
                continue          # 裸行归 A7
            if not sl.value:
                n += 1
                self._add("A10", "P1", "arity", sl.file, sl.text[:80],
                          "%s:%d 只有类型段、没有值——会被静默丢弃或匹配空串"
                          % (sl.file, sl.line),
                          "补上值，或删除该行")
                continue
            for m in sl.mods:
                if not m:
                    continue
                low = m.lower()
                if low not in ALLOWED_MODIFIERS:
                    n += 1
                    self._add("A10", "P1", "modifier", sl.file, sl.text[:80],
                              "%s:%d 修饰符 `%s` 不在白名单 %s 内——Clash 派生层会"
                              "把它当规则参数解析失败"
                              % (sl.file, sl.line, m, sorted(ALLOWED_MODIFIERS)),
                              "删除该修饰符，或确认支持后加入 ALLOWED_MODIFIERS")
                elif low == "no-resolve" and sl.type not in IP_CLASS_TYPES:
                    n += 1
                    self._add("A10", "P1", "modifier", sl.file, sl.text[:80],
                              "%s:%d 在非 IP 类规则（%s）上挂了 no-resolve——类型或"
                              "意图写错了" % (sl.file, sl.line, sl.type),
                              "删掉 no-resolve，或改成 IP 类规则")
            if sl.type in ("IP-CIDR", "IP-CIDR6"):
                try:
                    ipaddress.ip_network(sl.value, strict=True)
                except ValueError as exc:
                    n += 1
                    self._add("A10", "P1", "strict-cidr", sl.file, sl.text[:80],
                              "%s:%d CIDR 非规范形（严格解析失败：%s）——带主机位的 "
                              "CIDR 在不同实现里可能被取整或丢弃"
                              % (sl.file, sl.line, exc),
                              "清零主机位，或用 /32、/128 表达单个地址")
                continue
            if sl.type != "DOMAIN-SUFFIX":
                continue
            v = sl.value.strip(".").lower()
            if not v:
                continue
            if "." not in v:
                if psl.is_iana_tld(v):
                    kind, why = "single-label-tld", "该串在锁定的 IANA 根区表中存在，认领整个 TLD"
                elif v in SPECIAL_USE_TLDS:
                    kind, why = "single-label-special", "属 RFC 特殊用途名/事实私用名，钉在直连表是正确做法但须显式登记"
                else:
                    kind, why = "single-label-unknown", "既不在 IANA 根区表也非特殊用途名——多半是拼写错误或已撤销 TLD，永不命中"
                n += 1
                self._add("A10", "P1", kind, sl.file, sl.norm,
                          "%s:%d `DOMAIN-SUFFIX,%s` 是单标签后缀：%s"
                          % (sl.file, sl.line, v, why),
                          "确属刻意的在 allowlist 用 kind=%s 登记；否则收窄或删除" % kind)
                continue
            hit, sect, rule, how = psl.is_boundary(v)
            if not hit:
                continue
            kind = "psl-private" if sect == "private" else "psl-icann"
            why = ("PSL 存在通配规则 `%s`——每个子域都是独立公共后缀，本条等于把整个"
                   "多租户命名空间一次收进来" % rule) if how == "wildcard-parent" else \
                  ("PSL 判定其自身就是公共后缀（生效规则 `%s`）" % rule)
            n += 1
            self._add("A10", "P1", kind, sl.file, sl.norm,
                      "%s:%d `DOMAIN-SUFFIX,%s` 命中 PSL %s 段：%s——后缀之下每个标签"
                      "属于不同注册人" % (sl.file, sl.line, v,
                                          (sect or "?").upper(), why),
                      "收窄成具体注册域，或（第一方自持/刻意兜底）在 allowlist 用 "
                      "kind=%s 登记" % kind)
        return n

    # -- 运行 --------------------------------------------------------------

    def run(self, checks):
        stats = OrderedDict()
        for c in ALL_CHECKS:
            if c in checks:
                stats[c] = getattr(self, "check_%s" % c.lower())()
        self.findings.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]],
                                          f["check"], f["id"]))
        return stats


# ---------------------------------------------------------------------------
# 自检：植入已知缺陷的合成配置，验证各检查项与豁免表语义
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
    "Leak.list": u"IP-CIDR,198.51.100.0/24\n",
    "Safe.list": u"IP-CIDR,192.0.2.0/24\n",
    "Direct.list": u"""\
DOMAIN-SUFFIX,sub.shadow.example.com
DOMAIN-SUFFIX,dup.example.org
DOMAIN-SUFFIX,clean.example.cn
PROCESS-NAME,claude
""",
    "Unused.list": u"DOMAIN-SUFFIX,never-referenced.example\n",
}

# 第二份合成配置：A9 顺序感知 / A10 / A8 作用域与大小写归一
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
    "Broad.list": u"""\
IP-CIDR,203.0.113.0/24,no-resolve
IP-CIDR,198.18.0.0/15,no-resolve
IP-CIDR6,2001:db8:aaaa::/48,no-resolve
""",
    # 203.0.113.128/25 被前位代理段吞 → P0；192.0.2.0/24 是顺序哨兵（在前，不报）
    "Narrow.list": u"""\
IP-CIDR,203.0.113.128/25,no-resolve
IP-CIDR,192.0.2.0/24,no-resolve
""",
    # 同策略被吞 ×2 → P3；192.0.0.0/16 是反向哨兵（broad 在后，不报）
    "Same.list": u"""\
IP-CIDR,198.18.32.0/20,no-resolve
IP-CIDR6,2001:db8:aaaa:1::/64,no-resolve
IP-CIDR,192.0.0.0/16,no-resolve
""",
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
         "reason": "自检：file 作用域"},
        {"pattern": "DOMAIN-SUFFIX,only-here.example", "not_file": "Scope.list",
         "reason": "自检：not_file 作用域"},
        {"pattern": "USER-AGENT,*", "reason": "自检：小写行必须也被抓到"},
    ],
}


def run_audit_selftest(verbose=True):
    import shutil
    import tempfile

    results = []

    def check(name, got, want):
        results.append({"name": name, "ok": got == want, "got": got, "want": want})

    def pick(findings, check_id, **kw):
        return [f for f in findings if f["check"] == check_id
                and all(f.get(k) == v for k, v in kw.items())]

    tmpdir = tempfile.mkdtemp(prefix="surge-audit-selftest-")
    try:
        def make_env(subdir, conf_text, lists):
            rules_dir = os.path.join(tmpdir, subdir)
            os.makedirs(rules_dir)
            conf = os.path.join(tmpdir, subdir + ".conf")
            with open(conf, "w", encoding="utf-8") as fh:
                fh.write(conf_text)
            for name, body in lists.items():
                with open(os.path.join(rules_dir, name), "w", encoding="utf-8") as fh:
                    fh.write(body)
            return conf, rules_dir

        def make_allow(name, data):
            path = os.path.join(tmpdir, name)
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(data, fh, ensure_ascii=False)
            return path

        # ---- 第一份配置：A1–A8 基础语义 ----------------------------------
        conf, rules_dir = make_env("rules", SELFTEST_CONF, SELFTEST_LISTS)
        empty = make_allow("empty.json", {"version": 1, "exemptions": []})
        aud = Auditor(engine_mod.Engine(conf, rules_dir), Allowlist(empty))
        stats = aud.run(list(ALL_CHECKS))
        F = aud.findings

        check("S01 A1 命中缺 no-resolve 的 IP 规则", stats["A1"], 1)
        check("S02 A1 定位到 Leak.list 且判 P1",
              [(f["file"], f["severity"]) for f in pick(F, "A1")],
              [("Leak.list", "P1")])
        check("S03 A1 不误报 conf 行级 no-resolve 的 Safe.list",
              [f for f in pick(F, "A1") if f["file"] == "Safe.list"], [])

        a2 = pick(F, "A2")
        check("S04 A2 命中 1 组跨 list 重复", len(a2), 1)
        check("S05 A2 直连意图被代理抢走 → P0/misroute 于 Direct.list",
              (a2[0]["file"], a2[0]["severity"], a2[0]["kind"]),
              ("Direct.list", "P0", "misroute"))

        check("S06 A3 命中 3 条同 list 冗余（后缀/关键词/重复）且全 P2",
              (stats["A3"], sorted(set(f["severity"] for f in pick(F, "A3")))),
              (3, ["P2"]))
        check("S07 A3 形态齐全",
              sorted(f["rule"] for f in pick(F, "A3")),
              sorted(["DOMAIN-SUFFIX,a.inner.example.net",
                      "DOMAIN-SUFFIX,x-swallowme-y.example.io",
                      "DOMAIN,repeat.example.com"]))

        a4 = pick(F, "A4")
        check("S08 A4 命中 1 组遮蔽：Direct.list 被前位代理区遮蔽 → P0",
              [(f["file"], f["rule"], f["severity"]) for f in a4],
              [("Direct.list", "DOMAIN-SUFFIX,sub.shadow.example.com", "P0")])
        check("S09 A4 不重复报 A2 已覆盖的精确重复",
              [f for f in a4 if "dup.example.org" in f["rule"]], [])

        check("S10 A5 缺失引用 P0 + 未引用文件 P3",
              sorted((f["file"], f["severity"]) for f in pick(F, "A5")),
              sorted([("Missing.list", "P0"), ("Unused.list", "P3")]))
        check("S11 A6 输出 P3 审查表且不判错",
              [(f["severity"], f["kind"]) for f in pick(F, "A6")],
              [("P3", "structure")])
        check("S12 A7 捕获裸行并判 P1",
              [(f["file"], f["severity"],
                f["rule"].startswith("bare-line-without-type"))
               for f in pick(F, "A7")],
              [("Front.list", "P1", True)])
        check("S13 A8 无 forbidden 段时为 0", stats["A8"], 0)
        check("S14 findings schema 键完整",
              all(all(k in f for k in ("id", "check", "kind", "severity",
                                       "file", "rule", "evidence", "fix"))
                  for f in F), True)

        # ---- 豁免表语义 --------------------------------------------------
        al_path = make_allow("allow.json", {"version": 1, "exemptions": [
            {"check": "A4", "file": "Direct.list",
             "rule": "DOMAIN-SUFFIX,sub.shadow.example.com",
             "by": "DOMAIN-SUFFIX,shadow.example.com", "reason": "自检"},
            {"check": ["A5"], "file": "Unused.list", "reason": "自检"},
            {"check": "A8", "file": "*", "rule": "PROCESS-NAME,*",
             "reason": "自检：试图豁免 forbidden，必须无效"},
            {"check": "A1", "file": "NeverMatches.list", "preventive": True,
             "reason": "自检：preventive 未命中不算无用"},
        ], "forbidden": [
            {"pattern": "PROCESS-NAME,*", "reason": "自检：全库零进程规则"},
        ]})
        al2 = Allowlist(al_path)
        aud2 = Auditor(engine_mod.Engine(conf, rules_dir), al2)
        aud2.run(list(ALL_CHECKS))
        check("S15 allowlist 按 (check,file,rule,by) 豁免 A4",
              [f for f in aud2.findings if f["check"] == "A4"], [])
        check("S16 check 数组写法生效（A5/Unused 被豁免）",
              [f["file"] for f in aud2.findings if f["check"] == "A5"],
              ["Missing.list"])
        check("S17 A8 抓到全部 PROCESS-NAME 回流且无视同名 exemption",
              sorted((f["severity"], f["file"]) for f in aud2.findings
                     if f["check"] == "A8"),
              [("P0", "Direct.list"), ("P0", "Front.list")])
        check("S18 无用豁免只含 A8 那条尝试（preventive 未命中不算无用）",
              [e.get("check") for e in al2.unused(list(ALL_CHECKS))], ["A8"])

        # ---- 第二份配置：A9 / A10 / A8 作用域 ----------------------------
        conf2, rules2 = make_env("rules2", SELFTEST2_CONF, SELFTEST2_LISTS)
        psl = PublicSuffixList(
            os.path.join(DEFAULT_DATA_DIR, "public_suffix_list.dat"),
            os.path.join(DEFAULT_DATA_DIR, "tlds-alpha-by-domain.txt"))
        check("S19 A10 锁定快照可用", psl.available, True)

        aud3 = Auditor(engine_mod.Engine(conf2, rules2),
                       Allowlist(make_allow("allow2.json", SELFTEST2_ALLOW)),
                       psl=psl)
        stats3 = aud3.run(list(ALL_CHECKS))
        G = aud3.findings

        a8 = pick(G, "A8")
        check("S20 A8 file 作用域只在指定表内命中",
              sorted((f["file"], f["rule"]) for f in a8
                     if "scoped.example" in f["rule"]),
              [("Scope.list", "DOMAIN-SUFFIX,scoped.example")])
        check("S21 A8 not_file 作用域只在指定表之外命中",
              sorted((f["file"], f["rule"]) for f in a8
                     if "only-here.example" in f["rule"]),
              [("Other.list", "DOMAIN-SUFFIX,only-here.example")])
        check("S22 A8 抓到小写类型段的 UA 行并判 P0",
              sorted((f["severity"], f["file"]) for f in a8
                     if f["rule"].lower().startswith("user-agent")),
              [("P0", "Lint.list")])
        check("S23 A7 小写已知类型判 case 而非 format",
              sorted((f["kind"], f["severity"]) for f in pick(G, "A7")),
              [("case", "P1")])

        a9 = pick(G, "A9")
        check("S24 A9 原始命中 3 条（跨策略 1 + 同策略 2）", stats3["A9"], 3)
        check("S25 A9 直连被前位代理段吞 → P0/misroute",
              sorted((f["severity"], f["kind"], f["rule"]) for f in a9
                     if f["file"] == "Narrow.list"),
              [("P0", "misroute", "IP-CIDR,203.0.113.128/25")])
        check("S26 A9 同策略 → P3/redundant（v4 与 v6 各一条）",
              sorted((f["severity"], f["rule"]) for f in a9
                     if f["file"] == "Same.list"),
              [("P3", "IP-CIDR,198.18.32.0/20"),
               ("P3", "IP-CIDR6,2001:db8:aaaa:1::/64")])
        check("S27 A9 顺序感知：narrow 在前、broad 在后不报",
              [f for f in a9 if "192.0" in f["rule"]], [])

        a10_map = {f["rule"]: f["kind"] for f in pick(G, "A10")}
        check("S28 A10 单标签三分类正确",
              [a10_map.get("DOMAIN-SUFFIX,museum"),
               a10_map.get("DOMAIN-SUFFIX,localhost"),
               a10_map.get("DOMAIN-SUFFIX,zzznotatld")],
              ["single-label-tld", "single-label-special", "single-label-unknown"])
        check("S29 A10 PSL：ICANN / PRIVATE / *.parent / IDNA 全部命中",
              [a10_map.get("DOMAIN-SUFFIX,ac.uk"),
               a10_map.get("DOMAIN-SUFFIX,blogspot.com"),
               a10_map.get("DOMAIN-SUFFIX,oaiusercontent.com"),
               a10_map.get("DOMAIN-SUFFIX,xn--gmqw5a.xn--j6w193g")],
              ["psl-icann", "psl-private", "psl-private", "psl-icann"])
        check("S30 A10 零误报：!exception 与普通注册域不报",
              sorted(r for r in a10_map
                     if "kobe" in r or "plain.example.com" in r), [])
        check("S31 A10 arity / strict-cidr / modifier 各命中 1",
              sorted(f["kind"] for f in pick(G, "A10")
                     if f["kind"] in ("arity", "strict-cidr", "modifier")),
              ["arity", "modifier", "strict-cidr"])

        # ---- kind 作用域豁免：只静音一类子检查 ---------------------------
        al4 = make_allow("allow4.json", {
            "version": 1, "forbidden": SELFTEST2_ALLOW["forbidden"],
            "exemptions": [{"check": "A10", "file": "Lint.list",
                            "kind": "psl-private", "rule": "*",
                            "reason": "自检：只豁免 psl-private"}]})
        aud4 = Auditor(engine_mod.Engine(conf2, rules2), Allowlist(al4), psl=psl)
        aud4.run(list(ALL_CHECKS))
        check("S32 kind 键只静音指定子检查，其余照报",
              sorted(set(f["kind"] for f in aud4.findings if f["check"] == "A10")),
              ["arity", "modifier", "psl-icann", "single-label-special",
               "single-label-tld", "single-label-unknown", "strict-cidr"])
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
        prog="audit.py", description="Surge 规则体系静态审计器（A1–A10）")
    ap.add_argument("--conf", help="Surge.conf 路径（默认自动定位）")
    ap.add_argument("--rules", help=".list 所在目录（默认 conf 同级 rules/lists/）")
    ap.add_argument("--allowlist", default=DEFAULT_ALLOWLIST, help="豁免表路径")
    ap.add_argument("--data-dir", default=DEFAULT_DATA_DIR,
                    help="A10 锁定快照目录（默认 tests/data/）")
    ap.add_argument("--check", default="all", help="逗号分隔的检查项，如 A1,A4；默认 all")
    ap.add_argument("--out", help="输出目录（写 findings.jsonl）")
    ap.add_argument("--json", action="store_true", help="stdout 输出 JSON 摘要")
    ap.add_argument("--max-findings", type=int, default=200,
                    help="每个检查项最多输出多少条聚合 finding")
    ap.add_argument("--samples", type=int, default=6,
                    help="每条聚合 finding 展示的样例条数")
    ap.add_argument("--fail-on", default="P1", choices=["P0", "P1", "P2", "P3"],
                    help="严重度达到该级别即退出码 1（默认 P1）")
    ap.add_argument("--selftest", action="store_true", help="运行内置自检")
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

    summary = OrderedDict()
    summary["conf"] = eng.conf_path
    summary["rules_dir"] = eng.rules_dir
    summary["total_rules"] = len(eng.rules)
    summary["checks"] = checks
    summary["raw_hits"] = stats
    summary["findings"] = len(aud.findings)
    summary["by_severity"] = {s: sev_count[s] for s in ("P0", "P1", "P2", "P3")}
    summary["exempted"] = len(aud.exempted)
    summary["allowlist_unused"] = len(al.unused(checks))
    summary["exemptions_total"] = len(al.entries)
    summary["forbidden_total"] = len(al.forbidden)
    if psl.available:
        summary["snapshots"] = {"psl_sha256": psl.sha256.get("psl"),
                                "psl_rules": psl.rule_count,
                                "tld_sha256": psl.sha256.get("tld"),
                                "tlds": len(psl.tlds)}
    summary["fail_on"] = args.fail_on
    summary["failing"] = failing

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
        if args.out:
            print("输出目录    : %s" % args.out)
        print("退出判定    : fail-on=%s → 失败 %d 条" % (args.fail_on, failing))
        if aud.findings:
            print("-" * 66)
            for f in aud.findings[:15]:
                print("[%s] %s %-3s %-16s %s"
                      % (f["severity"], f["id"], f["check"], f["file"], f["rule"]))
            if len(aud.findings) > 15:
                print("… 另有 %d 条，见 --out 的 findings.jsonl"
                      % (len(aud.findings) - 15))

    return 1 if failing else 0


if __name__ == "__main__":
    sys.exit(main())
