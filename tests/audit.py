#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
audit.py — Surge 规则体系静态审计器（分流测试套件 L1 层）

复用 engine.py 的解析器（同一张按 conf 顺序展开的全局规则表），做 6 项可回归检查：

  A1  全 list IP 类规则 no-resolve 缺失（含 conf RULE-SET 行级修饰豁免逻辑）
  A2  跨 list 精确重复（(type,value) 相同出现多处 → 报后位死条目）
  A3  同 list 内部覆盖（DOMAIN ⊂ 同 list SUFFIX；SUFFIX ⊂ 更短 SUFFIX；KEYWORD 吞后缀）
  A4  跨 list 遮蔽（后位条目被前位更宽规则完全覆盖；直连区被代理区遮蔽标 P0）
  A5  conf 引用完整性（引用的 list 存在；存在的 list 被引用或在 allowlist）
  A6  DOMAIN-KEYWORD 审查表（列出供人工复核，不判错）

输出（--out DIR）：
  findings.jsonl      —— 每行一个 finding（00-context.md 约定 schema + source/check）
  report.md           —— 中文审计报告
  keyword_review.tsv  —— A6 全量关键词表
  a2/a3/a4_details.tsv—— 聚合前的逐条明细（findings 做了分组与截断，明细不截断）

退出码：存在严重度 ≥ --fail-on（默认 P1）的未豁免 finding 时返回 1。
python3 标准库 only；全程只读，不写 Surge Profiles 目录。
"""

from __future__ import annotations

import argparse
import fnmatch
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

DEFAULT_ALLOWLIST = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                 "allowlist.json")

ALL_CHECKS = ("A1", "A2", "A3", "A4", "A5", "A6")


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

    三元组之外提供两个**可选**限定键（不改变基础 schema，只是缩小豁免面）：
      by       —— 遮蔽/胜出方的规则串，如 "DOMAIN-SUFFIX,amazonaws.com"
      by_file  —— 遮蔽/胜出方所在 list，如 "YouTube.list"
    另有 preventive=true：表示这是「防回归」的前置豁免（当前配置本就不该命中），
    未命中时不计入「未使用豁免」告警。file / rule / by / by_file 均支持 fnmatch 通配。
    """

    def __init__(self, path=None):
        self.path = path
        self.entries = []
        self.hits = defaultdict(int)
        if path and os.path.isfile(path):
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            self.entries = data.get("exemptions", [])

    @staticmethod
    def _check_match(entry, check):
        want = entry.get("check", "*")
        if want in (None, "*"):
            return True
        if isinstance(want, list):
            return check in want
        return want == check

    def match(self, check, file_name, rule_str, by=None, by_file=None):
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
            self.hits[i] += 1
            return e
        return None

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


# ---------------------------------------------------------------------------
# 审计器
# ---------------------------------------------------------------------------

class Auditor(object):

    def __init__(self, eng, allowlist, max_findings=200, samples=6):
        self.e = eng
        self.al = allowlist
        self.max_findings = max_findings
        self.samples = samples
        self.findings = []
        self.details = {"A2": [], "A3": [], "A4": []}
        self.keywords = []
        self.exempted = []
        self._seq = 0
        # 只对「域名类」规则做覆盖/遮蔽分析
        self.domain_rules = [r for r in self.e.rules
                             if r.type in ("DOMAIN", "DOMAIN-SUFFIX",
                                           "DOMAIN-KEYWORD")]

    # -- finding 构造 ------------------------------------------------------

    def _add(self, check, severity, kind, file_name, rule_str, evidence,
             impact, fix, confidence="high", by=None, by_file=None):
        ex = self.al.match(check, file_name, rule_str, by=by, by_file=by_file)
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
                      "Surge.conf:%d 引用了 %s，但本地 rules/ 目录中不存在该文件。"
                      % (line, base),
                      "该 RULE-SET 在本地/CDN 缺失时 Surge 会跳过整段规则，"
                      "这一层分流直接失效，流量落到后面的兜底规则。",
                      "补齐 rules/%s，或从 Surge.conf 删除该 RULE-SET 行。" % base)

        existing = sorted(f for f in os.listdir(self.e.rules_dir)
                          if f.endswith(".list"))
        for f in existing:
            if f in referenced:
                continue
            note = ("（Surge.conf:%d 存在被注释掉的引用行）" % commented[f]
                    if f in commented else "（conf 中完全没有引用行）")
            n += 1
            self._add("A5", "P3", "stale", f, "-",
                      "rules/%s 存在于仓库但未被 Surge.conf 的任何 RULE-SET 引用%s。"
                      % (f, note),
                      "文件仍随 git/CDN 分发但对分流无任何作用；长期不更新会与上游脱节，"
                      "误以为生效会导致排障方向错误。",
                      "确认是刻意停用则加入 allowlist.json 豁免并在文件头注明停用日期；"
                      "否则在 conf 中恢复引用或从仓库移除。", "high")
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
    a("- 未豁免 finding：**%d** 条（P0=%d, P1=%d, P2=%d, P3=%d）；被豁免 %d 条\n"
      % (len(aud.findings), sev_count["P0"], sev_count["P1"],
         sev_count["P2"], sev_count["P3"], len(aud.exempted)))

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
# 自检：合成一份「植入了已知缺陷」的配置，验证 A1–A6 确实会触发
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

        # 豁免表生效
        al_path = os.path.join(tmpdir, "allow.json")
        with open(al_path, "w", encoding="utf-8") as fh:
            json.dump({"version": 1, "exemptions": [
                {"check": "A4", "file": "Direct.list",
                 "rule": "DOMAIN-SUFFIX,sub.shadow.example.com",
                 "by": "DOMAIN-SUFFIX,shadow.example.com", "reason": "自检用"},
                {"check": ["A5"], "file": "Unused.list", "reason": "自检用"},
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
                         if f["severity"] == "P0")), ["A2", "A5"])

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
        prog="audit.py", description="Surge 规则体系静态审计器（A1–A6）")
    ap.add_argument("--conf", help="Surge.conf 路径（默认自动定位）")
    ap.add_argument("--rules", help="rules/ 目录（默认 conf 同级 rules/）")
    ap.add_argument("--allowlist", default=DEFAULT_ALLOWLIST,
                    help="豁免表路径（默认同目录 allowlist.json）")
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
                    help="用植入已知缺陷的合成配置验证 A1–A6 与豁免表")
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
    aud = Auditor(eng, al, max_findings=args.max_findings, samples=args.samples)
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
