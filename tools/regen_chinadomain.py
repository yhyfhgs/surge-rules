#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Guarded generator for the machine-owned ``ChinaDomain.list`` layer.

Run this low-frequency pipeline manually, outside ``update.sh``, after a
locked upstream fetch. ``--shadow`` records decisions without replacing the
output; ``--apply`` writes only entries that pass the persistence gate. The
output and per-rule report are the auditable artifacts; individual entries
must not be hand-edited.

Pipeline: type and forbidden filters → ownership de-duplication against the
earlier routing lists (including broad parents of split-routed children) →
multi-resolver classification → P1–P10 protections → output checks.
Built-in poison, keyword, type, and carrier-pin decisions remain independently
reproducible. Quarantine is only exported here; active reachability must be
tested without Surge.

Protection invariants:
* Any CN answer or AAAA answer, approved CDN CNAME, non-overlapping resolver
  answers, grace ASN, Greater-China result, or pin keeps/quarantines the entry.
* Three foreign verdicts at least seven days apart are required before a drop.
* A drop batch over the configured threshold exits 1; resolver success below
  70% exits 2; a deletion that would route outside ``Final``/``Proxy`` (or a
  compatibility alias) exits 1. Unresolved entries are retained. Meta parked
  signatures are report-only.

Usage::

    python3 tools/regen_chinadomain.py --shadow --upstream PATH --state PATH --report PATH
    python3 tools/regen_chinadomain.py --apply --upstream PATH --state PATH \\
        --out lists/ChinaDomain.list --report PATH

Exit codes: 0 success; 1 input/guard or P8/P9 failure; 2 insufficient
resolver success.
"""
import argparse
import fnmatch
import ipaddress
import json
import os
import re
import subprocess
import sys
import time
from bisect import bisect_right
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

from routing_manifest import load_routing_manifest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROUTING_MANIFEST = os.path.join(REPO_ROOT, "config", "routing.json")

# ---------------------------------------------------------------- 配置常量

CN_RESOLVERS = ["223.5.5.5", "119.29.29.29", "180.76.76.76"]   # AliDNS / DNSPod / BaiduDNS
INTL_RESOLVERS = ["8.8.8.8", "1.1.1.1"]                        # 参照侧（用于识别投毒）
DIG_TIMEOUT = 4

# ── 内置投毒 / 境外托管域 ────────────────────────────────────────────────────
# Keep these decisions in the filter so output remains independently reproducible
# instead of depending on ProxyGFW list order.
DELETED_POISON_DOMAINS = {
    # 已转 ProxyGFW（14）
    "123du.cc", "23us.so", "biyuwu.cc", "emsec.hk", "hanfan.cc", "hostloc.me",
    "locvps.com", "mht.la", "mojie.app", "mojie.co", "nt.app", "xs7.la",
    "yiruan.la", "zzzzzz.me",
    # 仅删除，落 FINAL（3）
    "mojie.kim", "mojieai.com", "springerlink.com",
}

# ── 内置品牌关键词 ──────────────────────────────────────────────────────────
# ChinaDomain accepts suffixes, not unbounded keywords; keep this pre-filter
# independent from the allowlist's post-run audit.
BANNED_BRAND_KEYWORDS = {
    ".tmall.com", "alicdn", "alipay", "aliyun", "baidu",
    "hnagroup", "officecdn", "taobao", "weibo",
}

# ── D11 上游合并排除项 ─────────────────────────────────────────────────────
# Keep these keyword names separate so reports distinguish them from the
# general DOMAIN-KEYWORD type filter.
D11_EXCLUDED_KEYWORDS = {"stripe", "beplay"}

# ── 承载集豁免（P10 机器侧种子）────────────────────────────────────────────
# A carrier entry protects a host that would otherwise fall through a later,
# broader rule to DIRECT. These pins cover proxy carriers and Reject HTTPDNS;
# recompute them whenever the routing lists change.
CARRIER_SET_PINS = {
    # a) ProxyGFW 18 条承载集
    "cloud.oracle.com",           # ← ChinaDomain:68167 oracle.com
    "666pool.cn", "bloomberg.cn", "daxa.cn", "lightnovel.cn",
    "uupool.cn", "zhijianfengyi.cn", "zmw.cn",   # ← ChinaDomain DOMAIN-SUFFIX,cn
    "hasi.wang",                  # ← ChinaDomain DOMAIN-SUFFIX,wang
    "bbs.tuitui.info",            # ← ChinaDomain:86329
    "cg.play-analytics.com",      # ← ChinaDomain:69825
    "bx.in.th",                   # ← TencentCN:624 in.th
    "shortconn.im.qcloud.com",    # ← TencentCN:857 qcloud.com
    "c.mi.com",                   # ← Domestic:369 mi.com
    "openapi.longbridge.cn", "openapi-quote.longbridge.cn",
    "openapi-trade.longbridge.cn",               # ← Domestic:347
    "schwab.com.cn",              # ← Domestic:153 com.cn
    # b) Reject 3 条 HTTPDNS（advisor 裁决 1）
    "dnspod.meituan.httpdns.start.qcloud.com",
    "httpdns-v6.gslb.yy.com",
    "httpdns.qcloud.com",
}

# P3 国内 CDN / GSLB 的 CNAME 骨架 —— 命中即无条件保留（CDN 双栈域保护）
CN_CDN_CNAME_SUFFIX = {
    # 阿里
    "alicdn.com", "kunlungr.com", "kunlunar.com", "kunlunca.com", "kunlunsl.com",
    "kunlunso.com", "kunlunta.com", "kunlunvi.com", "kunlunwe.com", "kunlunle.com",
    "kunlunpi.com", "kunlunhuf.com", "kunlunaq.com", "cdngslb.com", "aliyuncs.com",
    # 腾讯
    "dnsv1.com", "dnsv1.com.cn", "tcdn.qq.com", "cdntip.com", "cdntips.com",
    "qcloudcdn.cn", "myqcloud.com", "tencent-cloud.net",
    # 百度
    "bsgslb.cn", "bsclink.cn", "a.bdydns.com", "jomodns.com",
    # 网宿 / 帝联 / 蓝汛 / 白山
    "wscdns.com", "wsdvs.com", "wsglb0.com", "wswebcdn.com", "wswebpic.com",
    "lxdns.com", "chinanetcenter.com", "ourwebcdn.net", "cdn20.com",
    "cdnhwc1.com", "cdnhwc2.com", "cdnhwc3.com", "cdnhwc4.com",   # 华为云
    "ksyuncdn.com", "ksyungslb.com",                              # 金山云
    "volcgslb.com", "volcvod.com", "bytefcdn-oversea.com",        # 火山/字节
    "qtlcdn.com", "qtlgslb.com", "qtlglb.com",                    # 七牛
    "upcdn.net", "ucloud.cn",                                     # UCloud
    "cdncenter.cn", "sinajs.cn", "sinaimg.cn",
}

# P4 全球 anycast / 大厂云：不自动丢，进隔离区等 P5 实测
GRACE_ASN = {
    "13335",   # Cloudflare（含中国大陆 JD Cloud PoP）
    "20940", "16625", "21342", "35994", "12222",  # Akamai
    "54113",   # Fastly
    "16509", "14618",                             # AWS
    "8075", "8068",                               # Microsoft / Azure
    "15169", "396982",                            # Google / GCP
    "45102", "37963",                             # Alibaba intl / Alibaba CN
    "132203", "45090",                            # Tencent intl / CN
    "55990", "136907",                            # Huawei Cloud
    "24429",                                      # Alibaba (Taobao)
}

# 经典投毒靶 AS：CN 侧答案落进这些网段且与境外侧完全不相交 ⇒ 判投毒
POISON_TARGET_ASN = {"32934", "13414", "19679", "36351"}   # FB / Twitter / Dropbox 等

# 大中华但非大陆：单列一档，默认不丢（HK/MO/TW 直连通常可用）
GREATER_CHINA_CC = {"HK", "MO", "TW"}

# Meta 停放签名（审计裁决 10）：57.144.0.0/14 内、host 以 .141 结尾。
# 只用于报告标注，不作为自动删除依据 —— 停放 ≠ 境外托管，处置口径不同。
META_PARKED_NET = ipaddress.ip_network("57.144.0.0/14")

DOMAIN_TYPES = {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-WILDCARD", "DOMAIN-KEYWORD"}
BANNED_TYPES = {"USER-AGENT", "PROCESS-NAME", "URL-REGEX"}

IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

# ---------------------------------------------------------------- 工具

def parse_rules(path):
    out = []
    with open(path, encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            idx = s.find(" #")          # 行尾注释：与 engine.py / surge2clash.py 同口径
            if idx >= 0:
                s = s[:idx].strip()
            if not s:
                continue
            p = [x.strip() for x in s.split(",")]
            out.append({"line": i, "type": p[0], "value": p[1].lower() if len(p) > 1 else "",
                        "params": p[2:], "raw": s})
    return out


class CNSet:
    """CN 地址集合：ChinaIP.list ∪ 上游 ChinaIPs ∪ Loyalsoldier cn.txt（取并集，
    使「境外」判定保守 —— 只有三边都不认才算境外）。"""

    def __init__(self, paths):
        v4, v6 = [], []
        for p in paths:
            if not p or not os.path.exists(p):
                continue
            for line in open(p, encoding="utf-8"):
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                idx = s.find(" #")
                if idx >= 0:
                    s = s[:idx].strip()
                tok = s.split(",")[1] if s.startswith("IP-CIDR") else s
                try:
                    n = ipaddress.ip_network(tok.strip(), strict=False)
                except ValueError:
                    continue
                (v4 if n.version == 4 else v6).append(n)
        self.n4 = sorted(ipaddress.collapse_addresses(v4), key=lambda n: int(n.network_address))
        self.n6 = sorted(ipaddress.collapse_addresses(v6), key=lambda n: int(n.network_address))
        self.s4 = [int(n.network_address) for n in self.n4]
        self.s6 = [int(n.network_address) for n in self.n6]

    def __contains__(self, ipstr):
        try:
            ip = ipaddress.ip_address(ipstr)
        except ValueError:
            return False
        arr, st = (self.n4, self.s4) if ip.version == 4 else (self.n6, self.s6)
        i = bisect_right(st, int(ip)) - 1
        return i >= 0 and ip in arr[i]


def dig(host, server, rrtype="A"):
    try:
        p = subprocess.run(["dig", "+tcp", "+short", "+time=3", "+tries=1",
                            "@%s" % server, host, rrtype],
                           capture_output=True, text=True, timeout=DIG_TIMEOUT)
    except (subprocess.TimeoutExpired, OSError):
        return None, []
    if p.returncode != 0:
        return None, []
    ips, cn = [], []
    for l in p.stdout.split("\n"):
        l = l.strip()
        if not l:
            continue
        if IPV4_RE.match(l) or (rrtype == "AAAA" and ":" in l):
            ips.append(l)
        else:
            cn.append(l.rstrip(".").lower())
    return ips, cn


def is_meta_parked(ips):
    """审计裁决 10 的停放签名：57.144.0.0/14 内且 host 以 .141 结尾。"""
    for ip in ips:
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if a.version == 4 and a in META_PARKED_NET and ip.endswith(".141"):
            return True
    return False


# ---------------------------------------------------------------- F0/F1/F2

def f0_type_filter(rules):
    """D7/D11 类型级禁收：USER-AGENT / PROCESS-NAME / URL-REGEX 一律丢。"""
    keep, drop = [], []
    for r in rules:
        if r["type"] in BANNED_TYPES:
            r["reason"] = "D11-banned-type:%s" % r["type"]
            drop.append(r)
        else:
            keep.append(r)
    return keep, drop


def f1_forbidden(rules, allowlist_path):
    """allowlist forbidden 段 + 内置 17 域 + 9 品牌关键词 + D11 排除项 + 类型级硬规则。"""
    pats = []
    if allowlist_path and os.path.exists(allowlist_path):
        with open(allowlist_path, encoding="utf-8") as f:
            al = json.load(f)
        pats = [e["pattern"] for e in al.get("forbidden", [])]

    keep, drop = [], []
    for r in rules:
        v, t = r["value"], r["type"]
        sig = "%s,%s" % (t, v)
        reason = None

        # (1) 内置 17 条已删投毒/境外托管域：域本身或其任一子域都不得回流。
        #     A9 要求这条结果可独立复现，所以放在最前、不依赖任何外部文件。
        for d in DELETED_POISON_DOMAINS:
            if v == d or v.endswith("." + d):
                reason = "builtin-deleted-poison:%s" % d
                break

        # (2) 尾部 9 条品牌关键词 + D11 排除项（只对 DOMAIN-KEYWORD 生效：
        #     它们是「关键词裁决」，误伤同名精确后缀不是本条的本意）
        if reason is None and t == "DOMAIN-KEYWORD":
            if v in BANNED_BRAND_KEYWORDS:
                reason = "builtin-banned-brand-keyword:%s" % v
            elif v in D11_EXCLUDED_KEYWORDS:
                reason = "D11-excluded-keyword:%s" % v

        # (3) allowlist forbidden 段（A8 的同一份签名）
        if reason is None:
            hit = next((p for p in pats if fnmatch.fnmatch(sig, p) or sig == p), None)
            if hit:
                reason = "forbidden:%s" % hit

        # (4) 类型级硬规则：机器管理层不接受任何 DOMAIN-KEYWORD（无标签边界）。
        #     比逐个登记关键词更抗上游变化 —— 上游新加一个关键词也拦得住。
        if reason is None and t == "DOMAIN-KEYWORD":
            reason = "keyword-not-allowed-in-machine-layer"
        if reason is None and t == "DOMAIN-SUFFIX" and "." not in v:
            reason = "single-label-public-suffix"

        if reason:
            r["reason"] = reason
            drop.append(r)
        else:
            keep.append(r)
    return keep, drop


def f2_ownership(rules, lists_dir, order, policies=None):
    """丢弃前位已认领的规则及包含前位分流子域的宽父后缀。"""
    suf, exact, kw, split_parents = {}, {}, [], {}
    for t in order:
        p = os.path.join(lists_dir, t + ".list")
        if not os.path.isfile(p):
            raise FileNotFoundError("routing list disappeared after manifest validation: %s" % p)
        for r in parse_rules(p):
            if r["type"] == "DOMAIN-SUFFIX":
                suf.setdefault(r["value"], (t, r["line"]))
                if t not in ("PrivateLAN", "Reject") and (
                        policies is None or policies.get(t) != "DIRECT"):
                    labels = r["value"].split(".")
                    for i in range(1, len(labels)):
                        split_parents.setdefault(".".join(labels[i:]),
                                                 (r["value"], t, r["line"]))
            elif r["type"] == "DOMAIN":
                exact.setdefault(r["value"], (t, r["line"]))
                if t not in ("PrivateLAN", "Reject") and (
                        policies is None or policies.get(t) != "DIRECT"):
                    labels = r["value"].split(".")
                    for i in range(len(labels)):
                        split_parents.setdefault(".".join(labels[i:]),
                                                 (r["value"], t, r["line"]))
            elif r["type"] == "DOMAIN-WILDCARD" and t not in ("PrivateLAN", "Reject") and (
                    policies is None or policies.get(t) != "DIRECT"):
                last_meta = max(r["value"].rfind("*"), r["value"].rfind("?"))
                tail = r["value"][last_meta + 1:]
                if tail.startswith(".") and len(tail) > 1:
                    labels = tail[1:].split(".")
                    for i in range(len(labels)):
                        split_parents.setdefault(".".join(labels[i:]),
                                                 (r["value"], t, r["line"]))
            elif r["type"] == "DOMAIN-KEYWORD":
                kw.append((r["value"], t, r["line"]))
    keep, drop = [], []
    for r in rules:
        v = r["value"]
        owner = None
        if r["type"] == "DOMAIN" and v in exact:
            owner = ("exact",) + exact[v]
        if owner is None:
            parts = v.split(".")
            for i in range(len(parts)):
                c = ".".join(parts[i:])
                if c in suf:
                    owner = ("suffix:" + c,) + suf[c]
                    break
        if owner is None:
            for k, t, ln in kw:
                if k in v:
                    owner = ("keyword:" + k, t, ln)
                    break
        if owner is None and r["type"] == "DOMAIN-SUFFIX" and "." in v:
            child = split_parents.get(v)
            if child:
                owner = ("split-child:" + child[0], child[1], child[2])
        if owner:
            r["reason"] = "owned-by %s:%s via %s" % (owner[1], owner[2], owner[0])
            drop.append(r)
        else:
            keep.append(r)
    return keep, drop


# ---------------------------------------------------------------- F3 解析

def resolve_one(name, is_exact):
    """返回 CN 侧多解析器结果 + 境外参照结果。"""
    rec = {"name": name, "cn": {}, "cname": set(), "aaaa": [], "intl": []}
    host = name
    ips, cn = dig(host, CN_RESOLVERS[0], "A")
    if not ips and not is_exact:
        h2 = "www." + name
        ips2, cn2 = dig(h2, CN_RESOLVERS[0], "A")
        if ips2:
            host, ips, cn = h2, ips2, cn2
    rec["probe_host"] = host
    rec["cn"][CN_RESOLVERS[0]] = ips or []
    rec["cname"] |= set(cn or [])
    if not ips:
        rec["status"] = "NO_A"
        rec["cname"] = sorted(rec["cname"])
        return rec
    for s in CN_RESOLVERS[1:]:
        i2, c2 = dig(host, s, "A")
        rec["cn"][s] = i2 or []
        rec["cname"] |= set(c2 or [])
    a6, c6 = dig(host, CN_RESOLVERS[0], "AAAA")
    rec["aaaa"] = a6 or []
    rec["cname"] |= set(c6 or [])
    gi, _ = dig(host, INTL_RESOLVERS[0], "A")
    rec["intl"] = gi or []
    rec["status"] = "OK"
    rec["cname"] = sorted(rec["cname"])
    return rec


def cymru_bulk(ips):
    """Team Cymru 批量 ASN/CC 查询（whois 43 端口）。失败即返回已拿到的部分。"""
    import socket
    out = {}
    ips = sorted(set(ips))
    for i in range(0, len(ips), 200):
        chunk = ips[i:i + 200]
        try:
            s = socket.create_connection(("whois.cymru.com", 43), timeout=40)
            s.sendall(("begin\nverbose\n" + "\n".join(chunk) + "\nend\n").encode())
            buf = b""
            s.settimeout(40)
            try:
                while True:
                    d = s.recv(65536)
                    if not d:
                        break
                    buf += d
            except socket.timeout:
                pass
            s.close()
        except Exception:                                       # noqa: BLE001
            continue
        for line in buf.decode(errors="replace").split("\n"):
            if "|" not in line or line.startswith("Bulk mode"):
                continue
            f = [x.strip() for x in line.split("|")]
            if len(f) >= 7 and f[1] and f[1][0].isdigit():
                out[f[1]] = {"asn": f[0], "cc": f[3], "asname": f[6]}
    return out


# ---------------------------------------------------------------- F4 误删保护

def verdict(rec, cnset, asninfo, pinned):
    """返回 (verdict, protections_triggered)。

    verdict ∈ KEEP_CN / KEEP_PROTECTED / QUARANTINE / DROP_OFFSHORE /
              DROP_POISON / NO_A
    """
    prot = []
    name = rec["name"]

    # P10 pin list（含内置承载集豁免）：机器强制永不丢
    for p in pinned:
        if name == p or name.endswith("." + p) or p.endswith("." + name):
            return "KEEP_PROTECTED", ["P10-pinned:%s" % p]

    if rec["status"] == "NO_A":
        # 解析不出来不等于境外；单独归档，默认**保留**（丢它只省行数不改行为）
        return "NO_A", ["P-noans-keep-by-default"]

    all_cn_ips = [ip for lst in rec["cn"].values() for ip in lst]
    if not all_cn_ips:
        return "NO_A", ["P-noans-keep-by-default"]

    # P1 多解析器 quorum：任一 CN 解析器给出 CN 落点即保留
    if any(ip in cnset for ip in all_cn_ips):
        return "KEEP_CN", ["P1-quorum-cn-hit"]

    # P2 双栈救援：v6 落 CN 即保留
    if any(ip in cnset for ip in rec["aaaa"]):
        return "KEEP_PROTECTED", ["P2-aaaa-cn"]

    # P3 CN CDN CNAME 骨架
    for c in rec["cname"]:
        for suf in CN_CDN_CNAME_SUFFIX:
            if c == suf or c.endswith("." + suf):
                prot.append("P3-cdn-cname:%s" % c)
                return "KEEP_PROTECTED", prot

    # P6 registrable-domain quorum：解析器之间互相矛盾 → 证据不足，隔离
    sets = [frozenset(v) for v in rec["cn"].values() if v]
    if len(set(sets)) > 1 and not set.intersection(*[set(s) for s in sets]):
        return "QUARANTINE", ["P6-resolver-disagreement"]

    ccs = {asninfo.get(ip, {}).get("cc", "?") for ip in all_cn_ips}
    asns = {asninfo.get(ip, {}).get("asn", "?") for ip in all_cn_ips}

    # 停放标注（裁决 10）：只标不删 —— 停放域的处置口径与境外托管不同。
    if is_meta_parked(all_cn_ips):
        prot.append("meta-parked-signature(57.144.0.0/14 + .141)")

    # 投毒识别：CN 侧与境外侧答案完全不相交，且 CN 侧落在无关大厂网段
    if rec["intl"] and not (set(all_cn_ips) & set(rec["intl"])):
        if asns & POISON_TARGET_ASN:
            return "DROP_POISON", prot + ["poison: cn-answer in unrelated AS, disjoint from intl"]

    # P4 全球 anycast / 大厂云 —— 不自动丢，进隔离等实测
    if asns & GRACE_ASN:
        return "QUARANTINE", prot + ["P4-grace-asn:%s" % sorted(asns & GRACE_ASN)]

    # 大中华非大陆：单列一档，默认保留（直连通常可用）
    if ccs and ccs <= GREATER_CHINA_CC:
        return "KEEP_PROTECTED", prot + ["P-greater-china-direct-ok"]

    return "DROP_OFFSHORE", prot + ["cc=%s asn=%s" % (sorted(ccs), sorted(asns))]


# ---------------------------------------------------------------- P9 落点复核

def p9_recheck(names, engine_path, conf, rules_dir):
    """Recheck each pending deletion with ``engine.py``; allowed policies are Final or Proxy.

    The result is ``{name: (policy, source)}``; legacy policy aliases may also
    be returned by the engine. An empty result means the engine was unavailable
    and must remain a failed gate, never an implicit pass.
    """
    if not os.path.exists(engine_path):
        return {}
    out = {}
    for n in names:
        cmd = [sys.executable, engine_path, "match", n, "--json"]
        if conf:
            cmd += ["--conf", conf]
        if rules_dir:
            cmd += ["--rules", rules_dir]
        try:
            res = json.loads(subprocess.check_output(cmd, stderr=subprocess.DEVNULL))
        except Exception:                                       # noqa: BLE001
            continue
        out[n] = (res.get("policy"), res.get("source"))
    return out


# ---------------------------------------------------------------- main

def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="regen_chinadomain.py",
        description="ChinaDomain 再生管线过滤器（护栏版）；低频有人值守操作，不进 update.sh")
    ap.add_argument("--upstream", required=True, help="上游 ChinaMaxNoIP_All.list（建议先过 fetch_locked.py）")
    ap.add_argument("--lists-dir", default=os.path.join(REPO_ROOT, "lists"))
    ap.add_argument("--allowlist", default=os.path.join(REPO_ROOT, "tests", "allowlist.json"))
    ap.add_argument("--engine", default=os.path.join(REPO_ROOT, "tests", "engine.py"),
                    help="P9 落点复核用的 engine.py")
    ap.add_argument("--conf", default=None, help="透传给 engine.py 的 Surge.conf")
    ap.add_argument("--cn-set", nargs="*", default=[],
                    help="CN 地址集合来源（ChinaIP.list / 上游 ChinaIPs / cn.txt，取并集）")
    ap.add_argument("--pin", default=None,
                    help="额外 pin list（一行一个域，永不删）；内置承载集豁免总是生效")
    ap.add_argument("--state", default=os.path.join(REPO_ROOT, "tools", "state", "chinadomain.json"),
                    help="P7 迟滞状态文件")
    ap.add_argument("--out", default=None, help="候选表输出路径（仅 --apply 写）")
    ap.add_argument("--report", default=None, help="逐条裁决报告 JSON")
    ap.add_argument("--quarantine-out", default=None, help="隔离区清单（交 P5 实测流程）")
    ap.add_argument("--sample", type=int, default=0, help="只对系统抽样跑（评估用）")
    ap.add_argument("--workers", type=int, default=48)
    ap.add_argument("--max-drop-pct", type=float, default=20.0, help="P8 爆炸半径闸门")
    ap.add_argument("--min-resolve-rate", type=float, default=70.0)
    ap.add_argument("--hysteresis", type=int, default=3, help="P7 连续判定次数")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--shadow", action="store_true",
                   help="影子运行：算出会丢什么但一条都不丢，只写 state 与报告（第 1、2 轮）")
    g.add_argument("--apply", action="store_true",
                   help="正式：P7 迟滞满足的才真删并写表（第 3 轮起）")
    a = ap.parse_args(argv)

    try:
        routing = load_routing_manifest(ROUTING_MANIFEST, a.lists_dir)
    except ValueError as exc:
        print("!! %s" % exc)
        return 1
    names = [entry["name"] for entry in routing]
    try:
        china_domain_index = names.index("ChinaDomain")
    except ValueError:
        print("!! routing manifest is missing required ruleset 'ChinaDomain'")
        return 1
    ownership_order = names[:china_domain_index]
    policies = {entry["name"]: entry["policy"] for entry in routing}

    rules = parse_rules(a.upstream)
    n0 = len(rules)
    rules, d0 = f0_type_filter(rules)
    rules, d1 = f1_forbidden(rules, a.allowlist)
    rules, d2 = f2_ownership(rules, a.lists_dir, ownership_order, policies)
    print("F0 type      : -%d   %s" % (len(d0), Counter(r["type"] for r in d0)))
    print("F1 forbidden : -%d   %s" % (len(d1), Counter(r["reason"].split(":")[0] for r in d1)))
    print("F2 ownership : -%d" % len(d2))
    print("survivors    : %d / %d" % (len(rules), n0))

    # A3/A9 的产出前自检：这三条必须恒为 0，否则后面白跑
    assert not [r for r in rules if r["type"] in BANNED_TYPES], "F0 漏网：仍有禁收类型"
    assert not [r for r in rules if r["type"] == "DOMAIN-KEYWORD"], "F1 漏网：仍有 DOMAIN-KEYWORD"
    leaked = [r["value"] for r in rules
              if any(r["value"] == d or r["value"].endswith("." + d)
                     for d in DELETED_POISON_DOMAINS)]
    assert not leaked, "F1 漏网：17 条已删域回流 %s" % leaked

    todo = rules
    if a.sample:
        step = max(1, len(rules) // a.sample)
        todo = rules[::step][:a.sample]
        print("[sample] probing %d of %d" % (len(todo), len(rules)))

    cnset = CNSet(a.cn_set or [os.path.join(a.lists_dir, "ChinaIP.list")])
    print("CN set: v4=%d v6=%d" % (len(cnset.n4), len(cnset.n6)))

    t0 = time.time()
    with ThreadPoolExecutor(max_workers=a.workers) as ex:
        recs = list(ex.map(lambda r: resolve_one(r["value"], r["type"] == "DOMAIN"), todo))
    ok = sum(1 for r in recs if r["status"] == "OK")
    rate = ok / max(len(recs), 1) * 100
    print("resolved %d/%d = %.1f%% in %.0fs" % (ok, len(recs), rate, time.time() - t0))
    if rate < a.min_resolve_rate:
        print("!! 解析成功率 %.1f%% < %.1f%% —— 判定不可信，中止" % (rate, a.min_resolve_rate))
        return 2

    offshore_ips = {ip for r in recs for ip in
                    [x for lst in r["cn"].values() for x in lst] + r["intl"]
                    if ip not in cnset}
    asninfo = cymru_bulk(offshore_ips) if offshore_ips else {}
    print("cymru: %d/%d" % (len(asninfo), len(offshore_ips)))

    pinned = set(CARRIER_SET_PINS)
    if a.pin and os.path.exists(a.pin):
        with open(a.pin, encoding="utf-8") as f:
            pinned |= {l.strip().lower() for l in f if l.strip() and not l.startswith("#")}
    print("P10 pin: %d 条（内置承载集 %d + 外部 %d）"
          % (len(pinned), len(CARRIER_SET_PINS), len(pinned) - len(CARRIER_SET_PINS)))

    state = {}
    if a.state and os.path.exists(a.state):
        with open(a.state, encoding="utf-8") as f:
            state = json.load(f)

    out_rows, counts = [], Counter()
    for rule, rec in zip(todo, recs):
        v, prot = verdict(rec, cnset, asninfo, pinned)
        counts[v] += 1
        streak = state.get(rec["name"], {}).get("streak", 0)
        streak = streak + 1 if v.startswith("DROP") else 0
        state[rec["name"]] = {"streak": streak, "last": v, "ts": time.strftime("%Y-%m-%d")}
        out_rows.append({"rule": rule["raw"], "name": rec["name"], "verdict": v,
                         "protections": prot, "streak": streak,
                         "probe_host": rec.get("probe_host"),
                         "cn": rec["cn"], "aaaa": rec["aaaa"], "intl": rec["intl"],
                         "cname": rec["cname"],
                         "asn": {ip: asninfo.get(ip) for lst in rec["cn"].values()
                                 for ip in lst if ip in asninfo}})

    print("\n=== verdicts ===")
    for k, v in counts.most_common():
        print("   %-20s %6d  %5.2f%%" % (k, v, v / len(recs) * 100))

    # P7 迟滞 + P8 爆炸半径
    eff_drop = [r for r in out_rows
                if r["verdict"].startswith("DROP") and r["streak"] >= a.hysteresis]
    pct = len(eff_drop) / max(len(recs), 1) * 100
    print("\nP7 迟滞后实际丢弃: %d (%.2f%%)  [阈值 %.1f%%]" % (len(eff_drop), pct, a.max_drop_pct))
    if pct > a.max_drop_pct:
        print("!! P8 爆炸半径闸门拦截：本轮丢弃比例超阈值，需人工复核后再跑")
        return 1

    # A7：0 条删除项可以触发过 P3 或 P10 —— 触发了说明护栏逻辑有洞
    bad = [r for r in eff_drop
           if any(p.startswith("P3-") or p.startswith("P10-") for p in r["protections"])]
    if bad:
        print("!! A7 违规：%d 条待删项曾触发 P3/P10 护栏，中止" % len(bad))
        for r in bad[:10]:
            print("   %s  %s" % (r["name"], r["protections"]))
        return 1

    # P9 落点复核：待删域删除后必须落 Final 或 Proxy；兼容旧策略别名。
    if eff_drop:
        checked = p9_recheck([r["name"] for r in eff_drop], a.engine, a.conf, a.lists_dir)
        if not checked:
            print("!! P9 未能复核（engine.py 不可用）—— 这是一道硬门禁，不允许静默跳过")
            return 1
        stray = {n: pol for n, (pol, _src) in checked.items()
                 if pol not in ("Final", "Proxy", "ProxyGFW", "FINAL")}
        for r in out_rows:
            if r["name"] in checked:
                r["p9_policy"] = checked[r["name"]][0]
                r["p9_source"] = checked[r["name"]][1]
        if stray:
            print("!! P9 违规：%d 条待删项删除后不落 Final/Proxy，中止" % len(stray))
            for n, pol in list(stray.items())[:10]:
                print("   %-40s → %s" % (n, pol))
            return 1
        print("P9 落点复核: %d/%d 条落 Final/Proxy ✓" % (len(checked), len(eff_drop)))

    if a.report:
        with open(a.report, "w", encoding="utf-8") as f:
            json.dump({"mode": "apply" if a.apply else "shadow",
                       "upstream": a.upstream, "n_upstream": n0,
                       "dropped_f0": [r["raw"] for r in d0],
                       "dropped_f1": [{"rule": r["raw"], "reason": r["reason"]} for r in d1],
                       "dropped_f2_count": len(d2),
                       "counts": dict(counts),
                       "effective_drops": len(eff_drop),
                       "rows": out_rows}, f, ensure_ascii=False, indent=1)
        print("report -> %s" % a.report)

    if a.quarantine_out:
        q = [r["name"] for r in out_rows if r["verdict"] == "QUARANTINE"]
        with open(a.quarantine_out, "w", encoding="utf-8") as f:
            f.write("# 隔离区：交 P5 主动可达性实测；**必须在没有 Surge 的环境跑**\n")
            f.write("\n".join(q) + "\n")
        print("quarantine -> %s (%d 条)" % (a.quarantine_out, len(q)))

    if a.state:
        d = os.path.dirname(a.state)
        if d and not os.path.isdir(d):
            os.makedirs(d)
        with open(a.state, "w", encoding="utf-8") as f:
            json.dump(state, f, ensure_ascii=False)
        print("state -> %s" % a.state)

    if a.apply and a.out:
        drop_names = {r["name"] for r in eff_drop}
        kept = [r for r in rules if r["value"] not in drop_names]
        with open(a.out, "w", encoding="utf-8") as f:
            f.write("# ChinaDomain — 整表机器刷新层，由 tools/regen_chinadomain.py 再生；勿手改单条\n")
            f.write("# 数据源与 pin 见 sources.lock.json；再生回路见 docs/MAINTENANCE.md\n")
            f.write("# 排序：规则类型分区，区内字母序\n\n")
            for r in sorted(kept, key=lambda x: (x["type"] != "DOMAIN", x["value"])):
                f.write(r["raw"] + "\n")
        print("wrote %s (%d 条)" % (a.out, len(kept)))
    elif a.shadow:
        print("(--shadow：一条都没丢，未写表)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
