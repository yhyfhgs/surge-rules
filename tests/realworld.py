#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
realworld.py — 分流测试套件 L4「真实客户端 / 网络栈实测层」(surge-cli, 不需要 http-api)。

用真实客户端画像发请求、用系统命令看网络栈、用 surge-cli 问 Surge 本人:
    --tun         接管状态: utun / 默认路由 / 系统 DNS / hijack 落地
    --dns         DNS 深测: hijack / fake-IP / canary / SVCB / DoH / 泄漏抽样
    --webrtc      STUN 取 srflx 公网 IP, 与 HTTP 出口交叉比对
    --clients     真实客户端画像 × 各组代表域: 归属 / 连通性 / 出口落点
    --crosscheck  surge-cli 实测语义 vs engine.py 离线推演, 逐条对账
    --ua-routing  MITM/auto-quic-block 红线 + 零 USER-AGENT 规则的负向验证

原则(与 L3 一致): 纯只读, surge-cli 只用 status / rule explain / http probe /
dump dns / dns lookup; 只访问数据配置登记的端点, 默认限速 3 req/s; 在线为准;
环境缺失给指引而非崩溃; 标准库 + 系统自带命令(curl/dig/netstat/scutil/ifconfig/lsof)。

退出码: 0 通过 / 1 有硬失败 / 2 环境不可用 / 3 用法错误或中断。
"""

import argparse
import base64
import ipaddress
import json
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime

VERSION = "1.0.0"
SELF_DIR = os.path.dirname(os.path.abspath(__file__))

DEFAULT_SURGE_CLI = "/Applications/Surge.app/Contents/Applications/surge-cli"
DEFAULT_TARGETS = os.path.join(SELF_DIR, "realworld_targets.json")
DEFAULT_SCEN_DIR = os.path.join(SELF_DIR, "scenarios")

#: macOS 上 Surge 虚拟网卡的 DNS 响应器地址(见 surge-docs/dns/advanced.md)。
#: 发往 198.18.0.2–198.18.0.9 的查询都视为发给 Surge 自己的响应器。
SURGE_DNS_RESPONDER_V4 = ("198.18.0.2", "198.18.0.9")
SURGE_DNS_RESPONDER_V6 = "fd00:6152::2"
#: fake-IP 池(同上): 198.18.0.0/15, 实际分配区间 198.18.1.1–198.19.255.254。
FAKE_IP_NET = ipaddress.ip_network("198.18.0.0/15")

ENV_GUIDE = """\
────────────────────────────────────────────────────────────────────────
L4 实测层需要一个「正在跑规则模式的 Surge」+ surge-cli, 现在拿不到。

检查顺序:
  1. Surge 在跑吗?            pgrep -fl 'Surge.app/Contents/MacOS/Surge'
  2. surge-cli 在吗?          ls /Applications/Surge.app/Contents/Applications/surge-cli
     不在默认位置就用  --surge-cli <路径>  指过去。
  3. 出站模式是 rule 吗?      surge-cli status | grep Mode
     全局直连/全局代理下所有分流断言都不成立, 请先在 Surge 里切回「规则模式」。

L4 不需要 http-api —— surge-cli 走的是本机控制通道, 不用改配置。
离线三层(engine.py / audit.py / runsuite.py)不依赖本层, 任何时候都能跑。
────────────────────────────────────────────────────────────────────────"""


# ---------------------------------------------------------------------------
# 与 live_check.py 共享的小工具(同仓库兄弟模块, 加载失败就大声失败)
# ---------------------------------------------------------------------------

sys.path.insert(0, SELF_DIR)

import live_check as _LC  # noqa: E402

dwidth = _LC.dwidth
pad = _LC.pad
render_table = _LC.render_table
Log = _LC.Log
RateLimiter = _LC.RateLimiter
exit_class_of = _LC.exit_class_of
parse_probe_ip = _LC.parse_probe_ip
is_private_ip = _LC.is_private_ip


# ---------------------------------------------------------------------------
# 断言收集器
# ---------------------------------------------------------------------------

class Checks(object):
    """统一收集断言。ok=True 通过 / False 不通过 / None 仅报告不断言。

    level="FAIL" 的不通过项才计入退出码; level="WARN" 只提示。
    """

    LEVELS = ("FAIL", "WARN")

    def __init__(self):
        self.items = []

    def add(self, section, name, ok, expect, actual, level="FAIL", note=""):
        assert level in self.LEVELS
        self.items.append({
            "section": section, "name": name, "ok": ok, "level": level,
            "expect": expect, "actual": actual, "note": note,
        })
        return ok

    # -- 统计 --------------------------------------------------------------
    def failures(self):
        return [i for i in self.items if i["ok"] is False and i["level"] == "FAIL"]

    def warnings(self):
        return [i for i in self.items if i["ok"] is False and i["level"] == "WARN"]

    def stats(self):
        s = {"total": len(self.items), "pass": 0, "fail": 0, "warn": 0, "report": 0}
        for i in self.items:
            if i["ok"] is None:
                s["report"] += 1
            elif i["ok"]:
                s["pass"] += 1
            elif i["level"] == "FAIL":
                s["fail"] += 1
            else:
                s["warn"] += 1
        return s

    def mark(self, ok):
        return "✓" if ok else ("✗" if ok is False else "·")


# ---------------------------------------------------------------------------
# 只读外部命令封装
# ---------------------------------------------------------------------------

def run_cmd(argv, timeout=15.0, stdin_text=None):
    """跑一个只读外部命令。返回 dict(ok, rc, out, err)。命令不存在也不抛。"""
    try:
        p = subprocess.run(argv, capture_output=True, timeout=timeout,
                           input=(stdin_text.encode() if stdin_text else None))
    except FileNotFoundError:
        return {"ok": False, "rc": -1, "out": "", "err": "命令不存在: %s" % argv[0]}
    except subprocess.TimeoutExpired:
        return {"ok": False, "rc": -1, "out": "", "err": "超时(%.0fs): %s" % (timeout, argv[0])}
    except Exception as e:                                     # noqa: BLE001
        return {"ok": False, "rc": -1, "out": "", "err": "%s: %s" % (type(e).__name__, e)}
    return {"ok": p.returncode == 0, "rc": p.returncode,
            "out": p.stdout.decode("utf-8", "replace"),
            "err": p.stderr.decode("utf-8", "replace")}


# surge-cli 的 notes 有两种写法:
#   'Sub-rule matched: DOMAIN-SUFFIX x.com(in Twitter.list)'   域名类, 表名在括号里
#   'Sub-rule matched: IP-ASN,15169' + 'Rule matched: RULE-SET Google.list'
#                                                   IP 类, 表名要去下一条 note 里取
SUBRULE_RE = re.compile(r"Sub-rule matched:\s*(?P<rule>.+?)\(in (?P<list>[^)]+)\)\s*$")
SUBRULE_BARE_RE = re.compile(r"Sub-rule matched:\s*(?P<rule>.+?)\s*$")
RULESET_RE = re.compile(r"Rule matched:\s*RULE-SET\s+(?P<list>\S+)\s*$")


class SurgeCLI(object):
    """surge-cli 只读封装。只用 status / rule explain|match / http probe /
    dump dns / dns lookup 这几个不改状态的命令。"""

    def __init__(self, path=None, timeout=15.0, redact=False):
        self.path = path or DEFAULT_SURGE_CLI
        self.timeout = timeout
        self.redact = redact
        self.available = False
        self.reason = ""
        self.status = {}
        self.features = {}
        self._explain_cache = {}
        self._probe()

    # -- 基础 --------------------------------------------------------------
    def _probe(self):
        if not os.path.isfile(self.path):
            self.reason = "找不到 surge-cli: %s" % self.path
            return
        r = run_cmd([self.path, "status"], self.timeout)
        if not r["ok"]:
            self.reason = (r["err"] or r["out"] or "surge-cli status 失败").strip().splitlines()[0]
            return
        cur = None
        lines = [l for l in r["out"].splitlines() if l.strip()]
        if lines:
            # 首行形如 "Surge 6.9.0 (12230)", 没有冒号, 单独收下
            self.status["Version"] = lines[0].strip()
        for line in r["out"].splitlines():
            if re.match(r"^\s{2,}\S+:", line) and cur == "features":
                k, _, v = line.strip().partition(":")
                self.features[k.strip()] = v.strip()
                continue
            if line.strip().lower().startswith("features"):
                cur = "features"
                continue
            if ":" in line:
                k, _, v = line.partition(":")
                self.status[k.strip()] = v.strip()
                cur = None
        self.available = True

    def node(self, name):
        """物理节点名。--redact 下只保留国旗与 exit_class, 便于把报告贴到公开处。"""
        if not name:
            return ""
        if not self.redact:
            return name
        cls, _ = exit_class_of(name)
        flag = name[:2] if name[:1] in ("\U0001F1E6",) or ord(name[:1]) >= 0x1F1E6 else ""
        return "%s<节点:%s>" % (flag, cls)

    def raw(self, args, timeout=None):
        """跑 `surge-cli --raw <args>` 并解析 JSON; 失败返回 dict(_error=...)"""
        r = run_cmd([self.path, "--raw"] + list(args), timeout or self.timeout)
        if not r["ok"] and not r["out"].strip():
            return {"_error": (r["err"] or "rc=%s" % r["rc"]).strip()}
        try:
            return json.loads(r["out"] or "{}")
        except ValueError:
            return {"_error": "输出不是合法 JSON: %s" % r["out"][:120]}

    # -- rule explain ------------------------------------------------------
    def explain(self, target, **overrides):
        """返回 dict(policy, source, sub_rule, rule, final, exit_class, error)。

        overrides 直接透传成 surge-cli 的 key=value(user-agent / process-path /
        dest-port / protocol / url / sni ...)。
        """
        key = (target, tuple(sorted(overrides.items())))
        if key in self._explain_cache:
            return self._explain_cache[key]
        args = ["rule", "explain", target]
        for k, v in overrides.items():
            if v is None:
                continue
            args.append("%s=%s" % (k.replace("_", "-"), v))
        d = self.raw(args)
        if "_error" in d:
            res = {"policy": None, "source": None, "sub_rule": None, "rule": None,
                   "final": None, "exit_class": None, "error": d["_error"]}
        else:
            source, sub, ruleset = None, None, None
            for n in d.get("notes") or []:
                m = SUBRULE_RE.search(n)
                if m:
                    sub, source = m.group("rule").strip(), m.group("list").strip()
                    continue
                m = SUBRULE_BARE_RE.search(n)
                if m and sub is None:
                    sub = m.group("rule").strip()
                    continue
                m = RULESET_RE.search(n)
                if m:
                    ruleset = m.group("list").strip()
            if source is None:
                source = ruleset
            rule = d.get("rule") or ""
            if source is None and rule.upper().startswith("FINAL"):
                source, sub = "<FINAL>", rule
            final = d.get("final")
            res = {"policy": d.get("rule-policy"), "source": source, "sub_rule": sub,
                   "rule": rule, "final": final,
                   "exit_class": exit_class_of(final)[0] if final else None,
                   "steps": d.get("steps") or [], "error": None}
        self._explain_cache[key] = res
        return res

    # -- http probe (真实 HEAD, 由 Surge 自己发起) --------------------------
    def http_probe(self, url, policy=None):
        args = ["http", "probe", url] + ([policy] if policy else [])
        d = self.raw(args, timeout=max(self.timeout, 20.0))
        if "_error" in d:
            return {"ok": False, "error": d["_error"]}
        headers = {}
        for h in d.get("headers") or []:
            headers[str(h.get("name", "")).lower()] = h.get("value")
        return {"ok": True, "status": d.get("status"), "policy": d.get("policy"),
                "rule": d.get("rule"), "ms": d.get("duration-ms"),
                "headers": headers, "error": None}

    # -- dump dns (Surge 内部 DNS 缓存快照) --------------------------------
    def dns_cache_domains(self):
        d = self.raw(["dump", "dns"], timeout=max(self.timeout, 20.0))
        if "_error" in d:
            return None
        return set(str(e.get("domain", "")).lower().rstrip(".")
                   for e in (d.get("dnsCache") or []) if e.get("domain"))

    # -- dns lookup (触发一次真实解析, 只对直连域用) ------------------------
    def dns_lookup(self, domain):
        r = run_cmd([self.path, "dns", "lookup", domain], max(self.timeout, 20.0))
        out = r["out"]
        m = re.search(r"^Server:\s*(.+)$", out, re.M)
        a = re.search(r"^A:\s*(.+)$", out, re.M)
        return {"ok": r["ok"], "server": m.group(1).strip() if m else None,
                "a": a.group(1).strip() if a else None, "raw": out}


class Curl(object):
    """用系统 curl 模拟真实客户端。body 与统计量用哨兵串分隔, 不落任何临时文件。"""

    # 哨兵串开头不能是 '@' —— curl 的 -w 把 @开头的值当成「从文件读格式」。
    MARK = "\n<<RW-CURL-META>>"
    WFMT = (MARK + "%{http_code}\t%{http_version}\t%{time_total}\t"
            "%{remote_ip}\t%{num_connects}\t%{size_download}")

    def __init__(self, timeout=10.0, rate=3.0, proxy_port=None):
        self.timeout = timeout
        self.limiter = RateLimiter(rate)
        self.proxy_port = proxy_port
        self.path = shutil.which("curl") or "/usr/bin/curl"
        self.available = os.path.isfile(self.path)

    def fetch(self, url, client=None, via="auto", method="GET", max_body=8192):
        """via: auto=沿用环境(真实 App 的行为) / proxy=显式走 Surge HTTP 代理 /
        tun=绕开代理走 TUN。返回 dict(ok, status, http_version, ms, remote_ip, body, error)。"""
        client = client or {}
        argv = [self.path, "-sS", "--max-time", "%.1f" % self.timeout,
                "-w", self.WFMT, "-o", "-"]
        if method == "HEAD":
            argv.append("-I")
        ua = client.get("ua")
        if ua:
            argv += ["-A", ua]
        for k, v in (client.get("headers") or {}).items():
            if k.lower() == "accept-encoding":
                # 画像里的 Accept-Encoding 常含 br/zstd, 而 macOS 自带的 libcurl 只会解
                # gzip/deflate —— 原样发出去会拿到一坨没法解析的压缩正文(回显 IP 就读不到了)。
                # 内容编码不参与任何分流判定, 所以这里交给 --compressed 自己协商。
                argv.append("--compressed")
                continue
            argv += ["-H", "%s: %s" % (k, v)]
        http = str(client.get("http") or "").strip()
        if http == "2":
            argv.append("--http2")
        elif http == "1.1":
            argv.append("--http1.1")
        if via == "proxy" and self.proxy_port:
            argv += ["-x", "http://127.0.0.1:%d" % self.proxy_port]
        elif via == "tun":
            argv += ["--noproxy", "*"]
        argv.append(url)

        self.limiter.wait()
        r = run_cmd(argv, timeout=self.timeout + 5.0)
        out = r["out"]
        body, _, meta = out.rpartition(self.MARK)
        if not meta:
            lines = [l for l in (r["err"] or "").splitlines() if l.strip()]
            return {"ok": False, "status": None, "http_version": None, "ms": None,
                    "remote_ip": None, "body": "",
                    "error": (lines[0].strip() if lines else "curl 无输出")}
        f = (meta.strip().split("\t") + [""] * 6)[:6]
        code = f[0]
        try:
            code_i = int(code)
        except ValueError:
            code_i = 0
        return {"ok": code_i > 0, "status": code_i, "http_version": f[1] or None,
                "ms": int(float(f[2] or 0) * 1000), "remote_ip": f[3] or None,
                "connects": f[4], "body": body[:max_body],
                "error": None if code_i > 0 else (r["err"].strip() or "无响应")}


# ---------------------------------------------------------------------------
# 最小 STUN 客户端(RFC 5389 Binding Request over UDP)
# ---------------------------------------------------------------------------

STUN_BINDING_REQUEST = 0x0001
STUN_BINDING_SUCCESS = 0x0101
STUN_MAGIC = 0x2112A442
ATTR_MAPPED_ADDRESS = 0x0001
ATTR_XOR_MAPPED_ADDRESS = 0x0020
ATTR_ERROR_CODE = 0x0009


def stun_binding(host, port, timeout=3.0, source_ip=None):
    """向 STUN 服务器发一个 Binding Request, 取回 server-reflexive 地址。

    返回 dict(ok, ip, port, peer, ms, error)。peer 是 UDP 应答的来源地址 ——
    TUN 接管时它应该是 198.18.0.0/15 里的 fake IP, 直接看到真实 IP 说明这条
    UDP 流没经过 Surge。
    """
    txid = os.urandom(12)
    req = struct.pack("!HHI12s", STUN_BINDING_REQUEST, 0, STUN_MAGIC, txid)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    t0 = time.monotonic()
    try:
        if source_ip:
            s.bind((source_ip, 0))
        s.sendto(req, (host, port))
        data, peer = s.recvfrom(2048)
    except Exception as e:                                     # noqa: BLE001
        return {"ok": False, "ip": None, "port": None, "peer": None,
                "ms": int((time.monotonic() - t0) * 1000),
                "error": "%s: %s" % (type(e).__name__, e)}
    finally:
        s.close()
    ms = int((time.monotonic() - t0) * 1000)

    if len(data) < 20:
        return {"ok": False, "ip": None, "port": None, "peer": peer[0], "ms": ms,
                "error": "应答长度 %d < 20, 不是 STUN 报文" % len(data)}
    mtype, mlen, magic, rtx = struct.unpack("!HHI12s", data[:20])
    if magic != STUN_MAGIC or rtx != txid:
        return {"ok": False, "ip": None, "port": None, "peer": peer[0], "ms": ms,
                "error": "magic/transaction-id 不匹配, 应答可能被中间设备伪造"}
    if mtype != STUN_BINDING_SUCCESS:
        return {"ok": False, "ip": None, "port": None, "peer": peer[0], "ms": ms,
                "error": "STUN 消息类型 0x%04X(非 Binding Success)" % mtype}

    body = data[20:20 + mlen]
    ip = rport = None
    i = 0
    while i + 4 <= len(body):
        atype, alen = struct.unpack("!HH", body[i:i + 4])
        val = body[i + 4:i + 4 + alen]
        i += 4 + alen + ((4 - alen % 4) % 4)
        if atype not in (ATTR_XOR_MAPPED_ADDRESS, ATTR_MAPPED_ADDRESS) or len(val) < 8:
            continue
        family = val[1]
        p = struct.unpack("!H", val[2:4])[0]
        addr = val[4:]
        if atype == ATTR_XOR_MAPPED_ADDRESS:
            p ^= (STUN_MAGIC >> 16) & 0xFFFF
            mask = struct.pack("!I", STUN_MAGIC) + txid
            addr = bytes(b ^ m for b, m in zip(addr, mask))
        try:
            if family == 0x01 and len(addr) >= 4:
                ip, rport = socket.inet_ntop(socket.AF_INET, addr[:4]), p
            elif family == 0x02 and len(addr) >= 16:
                ip, rport = socket.inet_ntop(socket.AF_INET6, addr[:16]), p
        except OSError:
            continue
        if atype == ATTR_XOR_MAPPED_ADDRESS:
            break                                    # XOR 属性优先, 拿到就停
    if not ip:
        return {"ok": False, "ip": None, "port": None, "peer": peer[0], "ms": ms,
                "error": "应答里没有 (XOR-)MAPPED-ADDRESS"}
    return {"ok": True, "ip": ip, "port": rport, "peer": peer[0], "ms": ms, "error": None}


# ---------------------------------------------------------------------------
# DNS 线格式(给 DoH 用; 只做最小实现, 够判可用性即可)
# ---------------------------------------------------------------------------

DNS_RCODE = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
             4: "NOTIMP", 5: "REFUSED"}


def dns_wire_query(name, qtype=1):
    """构造一个 RFC 1035 线格式查询(id=0, 便于 DoH 缓存)。"""
    parts = [bytes([len(l)]) + l.encode("idna" if any(ord(c) > 127 for c in l) else "ascii")
             for l in name.strip(".").split(".")]
    qname = b"".join(parts) + b"\x00"
    return struct.pack("!HHHHHH", 0, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", qtype, 1)


def dns_wire_summary(data):
    """从应答报文里取 (rcode 名, ANCOUNT)。"""
    if not data or len(data) < 12:
        return ("(短报文)", 0)
    _, flags, _, ancount, _, _ = struct.unpack("!HHHHHH", data[:12])
    rcode = flags & 0x000F
    return (DNS_RCODE.get(rcode, "RCODE%d" % rcode), ancount)


def doh_query(url, name, timeout=8.0):
    """RFC 8484 GET 方式查一次 DoH。全程不经 http_proxy 环境变量。"""
    q = base64.urlsafe_b64encode(dns_wire_query(name)).rstrip(b"=").decode()
    full = url + ("&" if "?" in url else "?") + "dns=" + q
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    req = urllib.request.Request(full, headers={
        "Accept": "application/dns-message",
        "User-Agent": "surge-realworld/%s" % VERSION,
    })
    t0 = time.monotonic()
    try:
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read(4096)
            rcode, an = dns_wire_summary(body)
            return {"ok": True, "status": resp.status, "rcode": rcode, "answers": an,
                    "ms": int((time.monotonic() - t0) * 1000), "error": None}
    except urllib.error.HTTPError as e:
        return {"ok": False, "status": e.code, "rcode": None, "answers": 0,
                "ms": int((time.monotonic() - t0) * 1000), "error": "HTTP %s" % e.code}
    except Exception as e:                                     # noqa: BLE001
        return {"ok": False, "status": None, "rcode": None, "answers": 0,
                "ms": int((time.monotonic() - t0) * 1000),
                "error": "%s: %s" % (type(e).__name__, e)}


# ---------------------------------------------------------------------------
# 配置文本与系统状态解析(全部只读)
# ---------------------------------------------------------------------------

def default_conf_path():
    env = os.environ.get("SURGE_CONF")
    if env and os.path.isfile(env):
        return env
    cand = os.path.abspath(os.path.join(SELF_DIR, "..", "..", "Surge.conf"))
    return cand


def read_conf(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def conf_general(text, key):
    """取 [General] 里某个键的值(只认未被注释的行)。"""
    m = re.search(r"^\s*%s\s*=\s*(.+?)\s*$" % re.escape(key), text, re.M)
    return m.group(1).strip() if m else None


def conf_mitm_hostname(text):
    """返回 (启用与否, hostname 值, auto-quic-block 值)。注释掉的模板不算启用。"""
    sec = re.search(r"^\[MITM\]\s*$(.*?)(?=^\[|\Z)", text, re.M | re.S)
    body = sec.group(1) if sec else ""
    host = None
    for line in body.splitlines():
        s = line.strip()
        if s.startswith("#") or not s.lower().startswith("hostname"):
            continue
        _, _, v = s.partition("=")
        host = v.strip()
        break
    quic = None
    m = re.search(r"^\s*auto-quic-block\s*=\s*(\S+)", body, re.M)
    if m:
        quic = m.group(1).strip()
    return (bool(host), host, quic)


def parse_ifconfig_utun():
    r = run_cmd(["ifconfig", "-a"], 10.0)
    if not r["ok"]:
        return []
    out = []
    cur = None
    for line in r["out"].splitlines():
        m = re.match(r"^(utun\d+):\s*flags=\S+<([^>]*)>\s*mtu\s*(\d+)", line)
        if m:
            cur = {"name": m.group(1), "flags": m.group(2), "mtu": int(m.group(3)),
                   "inet": [], "inet6": []}
            out.append(cur)
            continue
        if re.match(r"^\S", line):
            cur = None
            continue
        if cur is None:
            continue
        m = re.match(r"^\s+inet\s+(\S+)", line)
        if m:
            cur["inet"].append(m.group(1))
        m = re.match(r"^\s+inet6\s+(\S+)", line)
        if m:
            cur["inet6"].append(m.group(1).split("%")[0])
    return out


def parse_default_routes(family="inet"):
    """返回 [(destination, gateway, flags, netif)]，按 netstat 输出顺序(首条即当前优先)。"""
    r = run_cmd(["netstat", "-rn", "-f", family], 10.0)
    if not r["ok"]:
        return []
    rows = []
    for line in r["out"].splitlines():
        f = line.split()
        if len(f) >= 4 and f[0] == "default":
            rows.append((f[0], f[1], f[2], f[-1]))
    return rows


def parse_route_hosts(prefixes):
    """挑出指向某些目的地址的主机路由(用来看 hijack-dns 有没有在路由层落地)。"""
    r = run_cmd(["netstat", "-rn", "-f", "inet"], 10.0)
    if not r["ok"]:
        return {}
    want = set(prefixes)
    found = {}
    for line in r["out"].splitlines():
        f = line.split()
        if len(f) >= 4 and f[0] in want:
            found[f[0]] = f[-1]
    return found


def parse_scutil_dns():
    """返回 (resolver#1 的 nameserver 列表, 该 resolver 绑定的接口)。"""
    r = run_cmd(["scutil", "--dns"], 10.0)
    if not r["ok"]:
        return ([], "", r["out"])
    block = re.search(r"resolver #1\b(.*?)(?=\nresolver #|\Z)", r["out"], re.S)
    if not block:
        return ([], "", r["out"])
    ns = re.findall(r"nameserver\[\d+\]\s*:\s*(\S+)", block.group(1))
    ifm = re.search(r"if_index\s*:\s*\d+\s*\(([^)]+)\)", block.group(1))
    return (ns, ifm.group(1) if ifm else "", r["out"])


def parse_scutil_proxy():
    r = run_cmd(["scutil", "--proxy"], 10.0)
    if not r["ok"]:
        return {}
    d = {}
    for m in re.finditer(r"^\s*(\w+)\s*:\s*(\S+)\s*$", r["out"], re.M):
        d[m.group(1)] = m.group(2)
    return d


def detect_proxy_port(conf_text):
    """Surge HTTP 代理端口: 配置 http-listen > 系统代理设置 > 常规端口探测。"""
    m = re.search(r"^\s*http-listen\s*=\s*(?:([0-9.]+):)?(\d+)", conf_text or "", re.M)
    if m:
        return int(m.group(2)), "配置 http-listen"
    px = parse_scutil_proxy()
    if px.get("HTTPSEnable") == "1" and px.get("HTTPSPort", "").isdigit():
        return int(px["HTTPSPort"]), "系统代理设置(scutil --proxy)"
    for port in (6152, 8888, 8080, 1087):
        s = socket.socket()
        s.settimeout(0.4)
        try:
            s.connect(("127.0.0.1", port))
            return port, "端口探测"
        except OSError:
            continue
        finally:
            s.close()
    return 6152, "回退默认值"


def is_fake_ip(text):
    try:
        return ipaddress.ip_address(str(text).strip()) in FAKE_IP_NET
    except ValueError:
        return False


def in_responder_range(addr):
    try:
        ip = ipaddress.ip_address(str(addr).strip())
    except ValueError:
        return False
    if ip.version == 6:
        return str(ip) == SURGE_DNS_RESPONDER_V6
    lo = ipaddress.ip_address(SURGE_DNS_RESPONDER_V4[0])
    hi = ipaddress.ip_address(SURGE_DNS_RESPONDER_V4[1])
    return lo <= ip <= hi


# ---------------------------------------------------------------------------
# 数据配置
# ---------------------------------------------------------------------------

def load_targets(path, log):
    if not os.path.isfile(path):
        raise SystemExit("找不到数据配置 %s(用 --targets 指定)" % path)
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except ValueError as e:
        raise SystemExit("数据配置解析失败 %s: %s" % (path, e))
    data.setdefault("clients", [])
    data.setdefault("groups", [])
    data["_clients_by_id"] = {c["id"]: c for c in data["clients"] if c.get("id")}
    return data


def client_of(targets, cid):
    return targets["_clients_by_id"].get(cid) or {"id": cid, "ua": None, "headers": {}}


# ---------------------------------------------------------------------------
# 子命令 1: --tun  接管状态
# ---------------------------------------------------------------------------

def cmd_tun(ctx):
    log, chk, cli = ctx["log"], ctx["checks"], ctx["cli"]
    S = "tun"
    log.section("TUN / 接管状态检测")

    # 1. Surge 与出站模式
    if cli.available:
        mode = cli.status.get("Mode", "")
        log("  Surge      : %s   Profile: %s" % (cli.status.get("Version", "?"),
                                                 os.path.basename(cli.status.get("Profile Path", "?"))))
        log("  出站模式   : %s" % (mode or "?"))
        chk.add(S, "出站模式为 rule", mode == "rule", "rule", mode or "?",
                note="全局直连/全局代理下所有分流断言都不成立")
        feats = ", ".join("%s=%s" % (k, v) for k, v in sorted(cli.features.items())) or "(未解析到)"
        log("  Features   : %s" % feats)
        em = cli.features.get("enhanced-mode", "")
        chk.add(S, "enhanced-mode 已开(TUN 接管前提)", em.lower() == "on", "On", em or "?",
                level="WARN")
    else:
        chk.add(S, "surge-cli 可用", False, "可用", cli.reason)

    # 2. utun 接口
    utuns = parse_ifconfig_utun()
    rows = [[u["name"], u["mtu"], ",".join(u["inet"]) or "-",
             (u["inet6"][0] if u["inet6"] else "-"), u["flags"][:28]] for u in utuns]
    log("")
    log("  utun 接口枚举(ifconfig, 只读):")
    log(render_table(["接口", "MTU", "inet", "inet6", "flags"], rows))
    chk.add(S, "存在 utun 接口", bool(utuns), ">=1 个", "%d 个" % len(utuns))

    # 3. 默认路由
    v4 = parse_default_routes("inet")
    v6 = parse_default_routes("inet6")
    log("")
    log("  默认路由(netstat -rn):")
    log(render_table(["族", "目的", "网关", "flags", "出接口"],
                     [["inet"] + list(r) for r in v4] + [["inet6"] + list(r) for r in v6]))
    top4 = v4[0][3] if v4 else ""
    ok4 = top4.startswith("utun")
    chk.add(S, "IPv4 默认路由指向 utun", ok4, "utun*", top4 or "(无默认路由)",
            note="不指向 utun 说明 TUN 没接管, 本层测的就不是 Surge 的分流结果")
    surge_if = top4 if ok4 else ""
    if surge_if:
        me = [u for u in utuns if u["name"] == surge_if]
        addr = (me[0]["inet"][0] if me and me[0]["inet"] else "")
        chk.add(S, "Surge 虚拟网卡地址落在 fake-IP 段", bool(addr and is_fake_ip(addr)),
                "属于 %s" % FAKE_IP_NET, "%s = %s" % (surge_if, addr or "(无 inet 地址)"),
                level="WARN", note="macOS 上 Surge VIF 用 198.18.0.1, 响应器在 198.18.0.2")
    if v6:
        top6 = v6[0][3]
        chk.add(S, "IPv6 默认路由指向 utun", top6.startswith("utun"), "utun*", top6,
                level="WARN", note="conf 里 ipv6 = true 时才有意义")

    # 4. 系统 DNS 指向
    ns, ifname, _ = parse_scutil_dns()
    log("")
    log("  系统 DNS(scutil --dns, resolver #1): %s   绑定接口: %s"
        % (", ".join(ns) or "(空)", ifname or "-"))
    hit = [n for n in ns if in_responder_range(n)]
    chk.add(S, "系统 DNS 指向 Surge 响应器", bool(hit),
            "%s–%s 或 %s" % (SURGE_DNS_RESPONDER_V4[0], SURGE_DNS_RESPONDER_V4[1],
                             SURGE_DNS_RESPONDER_V6),
            ", ".join(ns) or "(空)",
            note="见 surge-docs/dns/advanced.md: macOS 响应器地址 198.18.0.2")
    if surge_if and ifname and ifname != surge_if:
        chk.add(S, "DNS resolver 与默认路由同接口", False, surge_if, ifname, level="WARN")

    # 5. hijack-dns 在路由层的落地
    conf = ctx["conf_text"]
    hijack = conf_general(conf, "hijack-dns")
    log("")
    log("  配置 hijack-dns = %s" % (hijack or "(未配置)"))
    probes = [s.strip() for s in (ctx["targets"].get("dns", {}).get("hijack_servers") or [])]
    routes = parse_route_hosts(probes)
    if routes:
        log(render_table(["被劫持的 DNS 服务器", "主机路由出接口"],
                         [[k, v] for k, v in sorted(routes.items())]))
    hijacked_via_utun = [k for k, v in routes.items() if v.startswith("utun")]
    # 主机路由是 Surge 收到查询后按需下发、且会过期的临时项, 拿不到不算问题 ——
    # hijack 的功能面判定以 --dns 里的 dig 结果为准, 这里只做「看到了就记一笔」。
    chk.add(S, "hijack-dns 目标已被路由进 utun",
            True if hijacked_via_utun else None,
            "探测 DNS 的主机路由指向 utun",
            ", ".join(hijacked_via_utun) or "(路由表里暂无; 主机路由按需下发且会过期, 功能面看 --dns)",
            level="WARN",
            note="配置 hijack-dns = %s" % (hijack or "(未配置)"))

    # 6. 本机监听端口(只看 Surge 自己的)
    port, how = ctx["proxy_port"], ctx["proxy_port_how"]
    r = run_cmd(["lsof", "-nP", "-iTCP:%d" % port, "-sTCP:LISTEN"], 10.0)
    listeners = [l.split()[0] for l in r["out"].splitlines()[1:] if l.strip()]
    log("")
    log("  HTTP 代理端口 : %d (%s)   监听进程: %s"
        % (port, how, ", ".join(sorted(set(listeners))) or "(未探测到)"))
    px = parse_scutil_proxy()
    log("  系统代理设置  : HTTPEnable=%s HTTPSEnable=%s Port=%s"
        % (px.get("HTTPEnable", "?"), px.get("HTTPSEnable", "?"), px.get("HTTPSPort", "?")))
    chk.add(S, "Surge HTTP 代理端口在监听", bool(listeners), "有进程 LISTEN",
            ", ".join(sorted(set(listeners))) or "无", level="WARN")

    ctx["result"]["tun"] = {
        "mode": cli.status.get("Mode") if cli.available else None,
        "features": cli.features, "utun": utuns,
        "default_route_v4": v4, "default_route_v6": v6,
        "system_dns": ns, "system_dns_if": ifname,
        "hijack_dns": hijack, "hijack_routes": routes,
        "proxy_port": port, "proxy_port_source": how, "listeners": listeners,
    }
    return 0


# ---------------------------------------------------------------------------
# 子命令 2: --dns  DNS 深测
# ---------------------------------------------------------------------------

def dig(server, name, qtype="A", timeout=3):
    argv = ["dig", "+time=%d" % timeout, "+tries=1", "@%s" % server, name, qtype]
    r = run_cmd(argv, timeout + 5.0)
    out = r["out"]
    m = re.search(r"status:\s*(\w+)", out)
    ans = re.findall(r"^\S+\s+\d+\s+IN\s+(?:A|AAAA)\s+(\S+)\s*$", out, re.M)
    return {"ok": r["ok"], "status": m.group(1) if m else None,
            "answers": ans, "raw": out, "err": r["err"]}


def cmd_dns(ctx):
    log, chk, cli = ctx["log"], ctx["checks"], ctx["cli"]
    S = "dns"
    tg = ctx["targets"].get("dns", {}) or {}
    conf = ctx["conf_text"]
    log.section("DNS 深测(hijack / fake-IP / canary / SVCB / DoH / 泄漏抽样)")

    have_dig = shutil.which("dig") is not None

    # --- 1. hijack-dns 生效性 --------------------------------------------
    log("")
    log("  1) hijack-dns 生效性 —— 向任意公共 DNS 发查询, 应被 Surge 就地应答 fake IP")
    log("     配置: hijack-dns = %s   fake-IP 池 = %s"
        % (conf_general(conf, "hijack-dns") or "(未配置)", FAKE_IP_NET))
    rows, hijack_ok, hijack_tot = [], 0, 0
    if not have_dig:
        log("     [跳过] 系统里没有 dig, 无法做这项测试。")
        chk.add(S, "hijack-dns 生效", None, "fake IP", "dig 不可用", level="WARN")
    else:
        for srv in (tg.get("hijack_servers") or []):
            for name in (tg.get("hijack_probe_domains") or []):
                d = dig(srv, name)
                a = d["answers"]
                fake = [x for x in a if is_fake_ip(x)]
                hijack_tot += 1
                if fake:
                    hijack_ok += 1
                rows.append(["@%s" % srv, name, d["status"] or "-",
                             ", ".join(a[:2]) or "(无 A 记录)",
                             "fake ✓" if fake else ("真实 IP ✗" if a else "?")])
        log(render_table(["DNS 服务器", "查询", "status", "应答", "判定"], rows))
        chk.add(S, "所有探测查询都被劫持为 fake IP", hijack_tot > 0 and hijack_ok == hijack_tot,
                "%d/%d" % (hijack_tot, hijack_tot), "%d/%d" % (hijack_ok, hijack_tot),
                note="真实 IP 说明该 DNS 查询绕过了 Surge, 域名对 Surge 不可见")

    # --- 2. canary / SVCB ------------------------------------------------
    log("")
    log("  2) 响应器行为(surge-docs/dns/advanced.md)")
    first_srv = (tg.get("hijack_servers") or ["8.8.8.8"])[0]
    if have_dig:
        canary = tg.get("canary_domain") or "use-application-dns.net"
        d = dig(first_srv, canary)
        log("     canary %s → status=%s" % (canary, d["status"]))
        chk.add(S, "canary 域被答成 NXDOMAIN(关掉浏览器自带 DoH)",
                d["status"] == "NXDOMAIN", "NXDOMAIN", d["status"] or "?",
                note="Firefox 靠它决定是否禁用内置 DoH; 不是 NXDOMAIN 则浏览器可能绕过 Surge")

        svcb_dom = tg.get("svcb_probe_domain") or "cloudflare.com"
        d = dig(first_srv, svcb_dom, "TYPE65")
        raw_svcb = conf_general(conf, "allow-dns-svcb")
        allow_svcb = (raw_svcb or "false").lower() in ("true", "1", "yes")
        log("     SVCB/HTTPS(TYPE65) %s → status=%s   (配置 allow-dns-svcb = %s)"
            % (svcb_dom, d["status"], raw_svcb or "未设置, 默认 false"))
        if allow_svcb:
            chk.add(S, "SVCB 查询按配置放行", d["status"] != "NOTIMP", "非 NOTIMP",
                    d["status"] or "?", level="WARN",
                    note="放行后 HTTPS 记录里的 IP hints 可能绕过 fake-IP 机制")
        else:
            chk.add(S, "SVCB 查询被拒(默认 allow-dns-svcb=false)",
                    d["status"] == "NOTIMP", "NOTIMP", d["status"] or "?",
                    note="不是 NOTIMP 说明客户端可能拿到 IP hints 从而绕过 fake-IP")

    # --- 3. DoH 可用性 ----------------------------------------------------
    log("")
    log("  3) DoH 可用性")
    edns = conf_general(conf, "encrypted-dns-server") or ""
    doh_urls = [u.strip() for u in edns.split(",") if u.strip().startswith("http")]
    log("     配置 encrypted-dns-server = %s" % (edns or "(未配置)"))
    rows = []
    for u in doh_urls:
        res = doh_query(u, "www.example.com")
        rows.append([u, res["status"] or "-", res["rcode"] or "-", res["answers"],
                     "%d ms" % res["ms"], res["error"] or "OK"])
        chk.add(S, "DoH 端点可用: %s" % u,
                bool(res["ok"] and res["rcode"] == "NOERROR" and res["answers"] > 0),
                "HTTP 200 + NOERROR + 有记录",
                "%s / %s / %d 条" % (res["status"], res["rcode"], res["answers"]),
                level="WARN", note=res["error"] or "")
    if rows:
        log(render_table(["DoH 端点", "HTTP", "rcode", "记录数", "耗时", "备注"], rows))
    else:
        log("     (配置里没有 encrypted-dns-server, 跳过)")

    # Surge 自己在用哪个上游 —— 用一个本来就该本地解析的直连域探测
    probe_direct = ((tg.get("leak_sample") or {}).get("direct") or ["www.qq.com"])[0]
    if cli.available:
        lk = cli.dns_lookup(probe_direct)
        log("     Surge 内部解析器实际使用: %s   (探测域 %s, 直连域, 本地解析本就是期望行为)"
            % (lk["server"] or "?", probe_direct))
        chk.add(S, "Surge 内部解析器走的是加密 DNS",
                bool(lk["server"] and lk["server"].startswith("http")),
                "https://... (DoH)", lk["server"] or "?", level="WARN",
                note="回落到明文 UDP 53 说明 DoH 不可用, 上游会看到全部直连域名")

    # --- 4. 本地 DNS 泄漏 live 抽样 ---------------------------------------
    log("")
    log("  4) 本地 DNS 泄漏 live 抽样 —— 代理域名不该出现在 Surge 的本地解析记录里")
    log("     手法: dump dns 取快照 → 真实访问样本域 → 再取快照 → 只看「新增」条目。")
    log("     只看新增就不用 flush, 全程零写操作; 快照前就有的条目单列「无法判定」。")
    sample = tg.get("leak_sample") or {}
    leak_rows = []
    if not cli.available:
        chk.add(S, "本地 DNS 泄漏抽样", None, "-", "surge-cli 不可用", level="WARN")
    else:
        before = cli.dns_cache_domains()
        if before is None:
            chk.add(S, "本地 DNS 泄漏抽样", None, "-", "dump dns 读取失败", level="WARN")
        else:
            curl = ctx["curl"]
            touched = []
            for host in (sample.get("proxy") or []) + (sample.get("direct") or []):
                curl.fetch("https://%s/" % host, method="HEAD", via=ctx["via"])
                touched.append(host)
            time.sleep(1.0)
            after = cli.dns_cache_domains() or set()
            new = after - before
            leaked = []
            for host in (sample.get("proxy") or []):
                h = host.lower()
                ex = cli.explain(host)
                ip_class = bool(ex["sub_rule"] and re.match(r"^(IP-CIDR|IP-ASN|GEOIP)", ex["sub_rule"]))
                if h in new:
                    verdict, leaked = "✗ 新增本地解析 = 泄漏", leaked + [host]
                elif h in before:
                    verdict = "? 快照前已存在, 无法判定"
                else:
                    verdict = "✓ 未产生本地解析"
                leak_rows.append([host, ex["policy"] or "?", ex["source"] or "?",
                                  "IP 类" if ip_class else "域名类", verdict])
            for host in (sample.get("direct") or []):
                h = host.lower()
                ex = cli.explain(host)
                verdict = ("✓ 有本地解析(直连域, 符合预期)"
                           if (h in new or h in before) else "· 本次未触发解析")
                leak_rows.append([host, ex["policy"] or "?", ex["source"] or "?",
                                  "域名类", verdict])
            log(render_table(["样本域", "策略组", "命中表", "规则类别", "判定"], leak_rows))
            log("     本轮 dump dns 新增 %d 条。" % len(new))
            chk.add(S, "代理域名未触发本地 DNS 解析", not leaked,
                    "0 条泄漏", "%d 条: %s" % (len(leaked), ", ".join(leaked) or "-"),
                    note="全链路零本地解析是本规则体系的头号红线(所有 IP 类规则都带 no-resolve)")

    ctx["result"]["dns"] = {
        "hijack": {"ok": hijack_ok, "total": hijack_tot},
        "doh": doh_urls, "leak_rows": leak_rows,
    }
    return 0


# ---------------------------------------------------------------------------
# 子命令 3: --webrtc  STUN 泄漏检测
# ---------------------------------------------------------------------------

def cmd_webrtc(ctx):
    log, chk, cli = ctx["log"], ctx["checks"], ctx["cli"]
    S = "webrtc"
    stun_cfg = (ctx["targets"].get("stun") or {})
    servers = stun_cfg.get("servers") or []
    conf = ctx["conf_text"]
    udp_beh = conf_general(conf, "udp-policy-not-supported-behaviour") or "(未配置, 默认 DIRECT)"
    log.section("WebRTC / STUN 泄漏检测")
    log("")
    log("  原理: WebRTC 靠 STUN(UDP)向公网服务器问「你看到的我是谁」, 拿到的 server-reflexive")
    log("        地址就是浏览器会写进 ICE candidate、对端能看到的公网 IP。它如果等于本机真实")
    log("        出口, 就是经典的 WebRTC 泄漏 —— 网页拿到的 IP 与你的 HTTP 出口对不上。")
    log("  配置: udp-policy-not-supported-behaviour = %s" % udp_beh)
    if str(udp_beh).upper().startswith("REJECT"):
        log("        = REJECT: 策略不支持 UDP 时直接拒绝, 不回落直连。")
        log("        因此「STUN 超时无应答」是**符合预期的零泄漏**, 不算失败;")
        log("        真正的失败是拿到了应答、而且那个应答等于本机真实出口 IP。")
    else:
        log("        ⚠ 非 REJECT: 策略不支持 UDP 时会回落直连, STUN 会直接暴露本机真实出口 IP。")

    # 基准: 走 DIRECT 的那台 STUN 服务器给出的 srflx = 本机真实出口 IP
    baseline_ip, rows, records = None, [], []
    for s in servers:
        host, port = s.get("host"), int(s.get("port") or 3478)
        ex = cli.explain(host) if cli.available else {"policy": None, "source": None,
                                                     "final": None, "exit_class": None}
        res = stun_binding(host, port, timeout=ctx["timeout"])
        rec = dict(s, group=ex["policy"], source=ex["source"], stun=res,
                   exit_class=ex["exit_class"])
        records.append(rec)
        if s.get("baseline") and res["ok"]:
            baseline_ip = res["ip"]
        if s.get("expect_group") and ex["policy"]:
            chk.add(S, "STUN 服务器 %s 落在预期组" % host, ex["policy"] == s["expect_group"],
                    s["expect_group"], ex["policy"], level="WARN",
                    note="归属变了的话下面的泄漏判定基准也就变了, 需要更新 realworld_targets.json")

    if baseline_ip is None:
        log("")
        log("  ⚠ 基准 STUN(应走 DIRECT 的那台)没拿到应答, 无法建立「本机真实出口」基准值。")
        chk.add(S, "取得本机真实出口基准值", None, "baseline STUN 有应答", "无应答", level="WARN")
    else:
        log("")
        log("  本机真实出口基准(走 DIRECT 的 STUN 回显): %s" % ctx["mask_ip"](baseline_ip))

    # 各代理组的 HTTP 出口, 用来和 UDP 出口对账
    http_exit = ctx["group_http_exit"]
    for rec in records:
        res = rec["stun"]
        srflx = res["ip"]
        grp = rec["group"] or "?"
        peer_note = ""
        if res["peer"]:
            peer_note = "fake" if is_fake_ip(res["peer"]) else "真实"
        if not res["ok"]:
            verdict = "无应答/失败"
            if str(udp_beh).upper().startswith("REJECT"):
                verdict = "无应答(REJECT 语义下= 零泄漏)"
            rows.append([rec["host"], grp, "-", peer_note or "-",
                         (res["error"] or "")[:34], verdict])
            chk.add(S, "STUN %s 无泄漏" % rec["host"], True,
                    "不得回显本机真实出口", "无应答", level="WARN", note=res["error"] or "")
            continue

        leaked = bool(baseline_ip and srflx == baseline_ip and grp not in ("DIRECT", None))
        if rec.get("baseline"):
            verdict = "基准值(DIRECT 组, 本就应是真实出口)"
            ok = None
        elif leaked:
            verdict = "✗ 泄漏: UDP 出口 = 本机真实出口"
            ok = False
        else:
            hx = http_exit.get(grp)
            if hx and hx == srflx:
                verdict = "✓ 与该组 HTTP 出口同 IP"
            elif hx:
                verdict = "✓ 非本机出口(但与 HTTP 出口不同 IP: %s)" % ctx["mask_ip"](hx)
            else:
                verdict = "✓ 非本机出口"
            ok = True
        rows.append([rec["host"], grp, ctx["mask_ip"](srflx), peer_note or "-",
                     "%d ms" % res["ms"], verdict])
        if ok is not None:
            chk.add(S, "STUN %s 无泄漏" % rec["host"], ok,
                    "srflx ≠ 本机真实出口", ctx["mask_ip"](srflx),
                    note="srflx 等于本机真实出口 = WebRTC 会把真实 IP 暴露给对端")
        if res["peer"] and not is_fake_ip(res["peer"]) and grp not in ("DIRECT", None):
            chk.add(S, "STUN %s 的 UDP 流经过 Surge" % rec["host"], False,
                    "应答来自 fake IP(198.18.0.0/15)", res["peer"], level="WARN",
                    note="应答直接来自真实 IP, 说明这条 UDP 流没被 TUN 接管")

    log("")
    log(render_table(["STUN 服务器", "策略组", "srflx 公网 IP", "应答来源",
                      "耗时/错误", "判定"], rows))
    log("")
    log("  说明: 「应答来源=fake」指 UDP 应答来自 198.18.0.0/15 的 fake IP, 即这条流确实")
    log("        被 Surge 的虚拟网卡接管了; 直接看到真实 IP 才是绕过。")

    ctx["result"]["webrtc"] = {
        "udp_policy_not_supported_behaviour": udp_beh,
        "baseline_present": baseline_ip is not None,
        "servers": [{"host": r["host"], "group": r["group"],
                     "ok": r["stun"]["ok"], "ms": r["stun"]["ms"],
                     "error": r["stun"]["error"],
                     "peer_is_fake": is_fake_ip(r["stun"]["peer"]) if r["stun"]["peer"] else None,
                     "same_as_baseline": bool(baseline_ip and r["stun"]["ip"] == baseline_ip)}
                    for r in records],
    }
    return 0


# ---------------------------------------------------------------------------
# 子命令 4: --clients  真实客户端模拟
# ---------------------------------------------------------------------------

def cmd_clients(ctx):
    log, chk, cli, curl = ctx["log"], ctx["checks"], ctx["cli"], ctx["curl"]
    S = "clients"
    targets = ctx["targets"]
    groups = targets.get("groups") or []
    if ctx["filter"]:
        groups = [g for g in groups if ctx["filter"] in g.get("group", "")]
    log.section("真实客户端模拟(UA / HTTP 版本 / Accept 组合 × 各组代表域)")
    log("")
    log("  通道: %s   限速: %.1f req/s   超时: %.0fs"
        % (ctx["via_desc"], ctx["rate"], ctx["timeout"]))

    # --- 1. UA 端到端到达矩阵 --------------------------------------------
    ua_url = targets.get("ua_matrix_url")
    if ua_url:
        log("")
        log("  1) UA 端到端到达矩阵 —— 用 %s 的回显核对源站真正收到的 UA" % ua_url)
        rows = []
        for c in targets.get("clients") or []:
            r = curl.fetch(ua_url, client=c, via=ctx["via"])
            uag = ""
            m = re.search(r"^uag=(.*)$", r["body"] or "", re.M)
            if m:
                uag = m.group(1).strip()
            ip, _ = parse_probe_ip("cf_trace", r["body"] or "")
            ok = (uag == (c.get("ua") or "")) if uag else None   # 没回显 = 判不了, 不是失败
            rows.append([c["id"], r["status"] or "-", "HTTP/%s" % (r["http_version"] or "?"),
                         "%s ms" % (r["ms"] if r["ms"] is not None else "-"),
                         ctx["mask_ip"](ip) if ip else "-",
                         "✓ 原样到达" if ok else
                         ("· 正文无 uag 回显, 无法判定" if ok is None
                          else "✗ 被改写: %s" % uag[:30])])
            if r["ok"]:
                chk.add(S, "UA 原样到达源站: %s" % c["id"], ok, (c.get("ua") or "")[:40],
                        uag[:40] or "(正文里没有 uag 回显)", level="WARN",
                        note="被改写通常意味着有 Header Rewrite 模块或中间设备在动请求")
            else:
                chk.add(S, "UA 矩阵探测可达: %s" % c["id"], None, "可达",
                        r["error"] or "UNREACHABLE", level="WARN")
        log(render_table(["画像", "状态", "协商版本", "耗时", "出口 IP", "UA 核对"], rows))

    # --- 2. 逐组: 归属 / 连通性 / 出口落点 --------------------------------
    log("")
    log("  2) 逐组代表域: 归属复核 → 真实客户端连通性 → 出口落点")
    baseline_exit = None
    group_exit = {}
    all_rows = []
    # 基准值(本机真实出口)是后面所有「有没有真的走代理」判定的锚点, 被 --filter 滤掉
    # 也得单独补一次, 否则整节退化成「只报告」。
    if ctx["filter"]:
        for g in targets.get("groups") or []:
            for h in g.get("hosts") or []:
                if not h.get("baseline"):
                    continue
                r = curl.fetch(h.get("url") or ("https://%s/" % h["host"]), via=ctx["via"])
                ip, _ = parse_probe_ip(h.get("echo") or "plain_ip", r["body"] or "")
                if ip:
                    baseline_exit = ip
                    group_exit.setdefault(g["group"], ip)
    for g in groups:
        gname = g.get("group")
        hosts = g.get("hosts") or []
        clients = [client_of(targets, cid) for cid in (g.get("clients") or ["curl_baseline"])]
        # 2a. 归属复核(不需要外网)
        for h in hosts:
            if not cli.available:
                break
            ex = cli.explain(h["host"])
            chk.add(S, "代表域归属: %s" % h["host"], ex["policy"] == gname,
                    gname, ex["policy"] or "?",
                    note="归属变了就得更新 realworld_targets.json, 否则这一组量到的不是它的出口")
        # 2b. 权威落点回读: 每组只发一次 http probe, 由 Surge 自己发起真实 HEAD
        probe_note = ""
        if cli.available and hosts:
            p = cli.http_probe(hosts[0].get("url") or ("https://%s/" % hosts[0]["host"]))
            if p["ok"]:
                probe_note = "%s → %s" % (p["status"], cli.node(p["policy"]))
                ray = (p["headers"] or {}).get("cf-ray") or ""
                if "-" in ray:
                    probe_note += " [CF colo %s]" % ray.rsplit("-", 1)[1]
            else:
                probe_note = "probe 失败: %s" % (p.get("error") or "")[:28]
        # 2c. 真实客户端请求
        for hi, h in enumerate(hosts):
            url = h.get("url") or ("https://%s/" % h["host"])
            use = clients if (hi == 0 or h.get("echo")) else clients[:1]
            for c in use:
                r = curl.fetch(url, client=c, via=ctx["via"])
                ip = None
                if h.get("echo") and r["body"]:
                    ip, _ = parse_probe_ip(h["echo"], r["body"])
                if ip:
                    group_exit.setdefault(gname, ip)
                    if h.get("baseline"):
                        baseline_exit = ip
                all_rows.append([gname, h["host"], c["id"],
                                 r["status"] if r["ok"] else "×",
                                 "HTTP/%s" % (r["http_version"] or "?") if r["ok"] else "-",
                                 "%s ms" % (r["ms"] if r["ms"] is not None else "-"),
                                 ctx["mask_ip"](ip) if ip else "-",
                                 probe_note if (hi == 0 and c is use[0]) else ""])
                chk.add(S, "连通性 %s [%s]" % (h["host"], c["id"]),
                        True if r["ok"] else None, "可达",
                        (str(r["status"]) if r["ok"] else (r["error"] or "UNREACHABLE"))[:44],
                        level="WARN",
                        note="UNREACHABLE 是网络层没打通(被墙/拒绝 HEAD/挡爬虫), 不算分流错误")
                if c.get("http") == "2" and r["ok"] and r["http_version"]:
                    chk.add(S, "HTTP/2 协商 %s [%s]" % (h["host"], c["id"]),
                            None, "2", r["http_version"], level="WARN")

    log(render_table(["策略组", "代表域", "客户端画像", "状态", "协商版本", "耗时",
                      "出口 IP", "Surge 回读落点"], all_rows))

    # --- 3. 出口落点判定 --------------------------------------------------
    log("")
    log("  3) 出口落点判定(以 DIRECT 组回显的本机真实出口为基准)")
    if baseline_exit:
        log("     本机真实出口: %s" % ctx["mask_ip"](baseline_exit))
    rows = []
    for gname, ip in sorted(group_exit.items()):
        if gname == "DIRECT":
            ok = bool(baseline_exit and ip == baseline_exit)
            verdict = "✓ 直连组, 即本机出口" if ok else "? 与基准不一致"
            rows.append([gname, ctx["mask_ip"](ip), verdict])
            continue
        if not baseline_exit:
            rows.append([gname, ctx["mask_ip"](ip), "? 无基准值, 只报告"])
            chk.add(S, "出口落点 %s" % gname, None, "≠ 本机真实出口",
                    ctx["mask_ip"](ip), level="WARN")
            continue
        ok = ip != baseline_exit and not is_private_ip(ip)
        rows.append([gname, ctx["mask_ip"](ip),
                     "✓ 已走代理出口" if ok else "✗ 与本机真实出口相同 = 没走代理"])
        chk.add(S, "出口落点 %s 确实走了代理" % gname, ok, "≠ 本机真实出口",
                ctx["mask_ip"](ip),
                note="等于本机出口说明该组当前实际是直连, 与规则期望不符")
    if rows:
        log(render_table(["策略组", "出口 IP", "判定"], rows))
    else:
        log("     (本轮没有任何一组拿到 IP 回显; 没有回显端点的组只做归属与连通性验证)")

    ctx["group_http_exit"].update(group_exit)
    ctx["result"]["clients"] = {"group_exit": {k: bool(v) for k, v in group_exit.items()},
                                "baseline_exit_present": bool(baseline_exit),
                                "rows": len(all_rows)}
    return 0


# ---------------------------------------------------------------------------
# 子命令 5: --crosscheck  分流落点交叉验证
# ---------------------------------------------------------------------------

def _engine_bridge():
    """加载 engine.py 实例; 失败返回 (None, 原因)。"""
    try:
        import engine
        return (engine.build_engine(), "")
    except BaseException as e:                                 # noqa: BLE001
        return (None, "engine.build_engine() 失败: %s" % e)


def _collect_queries(scen_dir, flt=None):
    """把 scenarios/*.json 里的请求摊平成去重后的查询列表。"""
    import runsuite as rs
    files = rs.load_scenarios(scen_dir)
    seen, out = set(), []
    for fname, arr in files:
        for scn in arr:
            name = scn.get("name", "")
            if flt and flt not in name and flt not in fname:
                continue
            for q in scn.get("requests", []) or []:
                key = (q.get("host"), q.get("ip"))
                if key in seen:
                    continue
                seen.add(key)
                out.append({"file": fname, "scenario": name,
                            "host": q.get("host"), "ip": q.get("ip")})
    return out


def _norm_source(source, rule):
    """把两边对「命中来源」的不同叫法归一, 避免纯标注差异被算成不一致。

    engine.py 把 FINAL 记成 source='Surge.conf'(规则写在 conf 里), surge-cli 则
    根本不给 list 名 —— 两者说的是同一件事。命中不到来源时统一记 None。
    """
    if rule and str(rule).upper().startswith("FINAL"):
        return "<FINAL>"
    if not source:
        return None
    s = str(source).strip()
    if s in ("<FINAL>", "Surge.conf"):
        return "<FINAL>"
    return s


def cmd_crosscheck(ctx):
    log, chk, cli = ctx["log"], ctx["checks"], ctx["cli"]
    S = "crosscheck"
    log.section("分流落点交叉验证(surge-cli 实测语义 vs engine.py 离线推演)")
    log("")
    log("  这是抓「离线引擎与真实 Surge 语义差异」的关键测试: 同一条查询, 一边问 Surge")
    log("  自己(rule explain, 不建立连接), 一边跑离线引擎, 两边的策略组与命中表逐条对账。")
    log("  判定原则同 L3: **在线为准** —— 不一致时该改的是 engine.py 或规则, 不是反过来。")

    if not cli.available:
        chk.add(S, "surge-cli 可用", False, "可用", cli.reason)
        return 2
    eng, why = _engine_bridge()
    if eng is None:
        chk.add(S, "engine.py 可用", False, "可用", why)
        return 2

    queries = _collect_queries(ctx["scen_dir"], ctx["filter"])
    if ctx["limit"]:
        queries = queries[:ctx["limit"]]
    log("")
    log("  场景目录: %s   去重后查询数: %d" % (ctx["scen_dir"], len(queries)))

    before = cli.dns_cache_domains()
    mismatch_policy, mismatch_source, errors = [], [], []
    n_domain = n_ip = 0
    t0 = time.monotonic()
    for q in queries:
        host, ip = q["host"], q["ip"]
        target = host or ip
        ex = cli.explain(target)
        if ex["error"]:
            errors.append((q, ex["error"]))
            continue
        try:
            off = eng.match(host=host, ip=ip)
        except Exception as e:                                 # noqa: BLE001
            errors.append((q, "engine: %s" % e))
            continue
        if ip and not host:
            n_ip += 1
        else:
            n_domain += 1
        label = " ".join(filter(None, [host or "", ("ip=" + ip) if ip else ""]))
        if (off.get("policy") or "") != (ex["policy"] or ""):
            mismatch_policy.append({
                "query": label, "kind": "ip" if (ip and not host) else "domain",
                "surge": ex["policy"], "engine": off.get("policy"),
                "surge_rule": "%s @ %s" % (ex["sub_rule"] or "-", ex["source"] or "-"),
                "engine_rule": "%s @ %s" % (off.get("matched_rule") or "-",
                                            off.get("source") or "-"),
                "scenario": q["scenario"]})
        elif _norm_source(ex["source"], ex["sub_rule"]) != \
                _norm_source(off.get("source"), off.get("matched_rule")):
            mismatch_source.append({
                "query": label, "policy": ex["policy"],
                "surge_source": ex["source"], "engine_source": off.get("source"),
                "surge_rule": ex["sub_rule"], "engine_rule": off.get("matched_rule"),
                "scenario": q["scenario"]})
    dur = time.monotonic() - t0

    log("  比对完成: %d 条(域名 %d / 纯 IP %d), 用时 %.1fs, 平均 %.0f ms/条"
        % (len(queries), n_domain, n_ip, dur, dur * 1000 / max(1, len(queries))))

    # rule explain 本身不该触发任何解析(所有 IP 类规则都带 no-resolve)
    if before is not None:
        after = cli.dns_cache_domains() or set()
        new = after - before
        log("  规则评估期间 Surge 本地 DNS 缓存新增: %d 条" % len(new))
        chk.add(S, "规则评估不触发本地 DNS 解析", len(new) == 0, "0 条新增",
                "%d 条: %s" % (len(new), ", ".join(sorted(new)[:5])),
                level="WARN",
                note="rule explain 不建连接; 有新增说明某条 IP 类规则缺 no-resolve 或来自并发的其它流量")

    # 策略组不一致
    log("")
    if mismatch_policy:
        log("  【策略组不一致】(在线为准)")
        log(render_table(["查询", "类别", "Surge 实测", "engine 推演", "Surge 命中", "engine 命中"],
                         [[m["query"], m["kind"], m["surge"], m["engine"],
                           m["surge_rule"], m["engine_rule"]] for m in mismatch_policy]))
    else:
        log("  【策略组不一致】无 ✓")
    dom_mis = [m for m in mismatch_policy if m["kind"] == "domain"]
    ip_mis = [m for m in mismatch_policy if m["kind"] == "ip"]
    chk.add(S, "域名查询的策略组与 Surge 一致", not dom_mis, "0 条不一致",
            "%d 条" % len(dom_mis),
            note="域名类语义两边都能精确实现, 不一致就是引擎 bug 或规则理解偏差")
    chk.add(S, "纯 IP 查询的策略组与 Surge 一致", not ip_mis, "0 条不一致",
            "%d 条" % len(ip_mis),
            level=("FAIL" if ctx["strict"] else "WARN"),
            note="engine.py 的 GEOIP/IP-ASN 是显式声明的离线近似, 这里默认只提示; --strict 可升为硬失败")

    # 命中表不一致(策略组相同, 但命中的是另一张表)
    log("")
    if mismatch_source:
        log("  【命中表不一致 —— 策略组相同, 但命中的 list 不同】")
        log("  多数是级联去重的自然结果(同一域在细分表与兜底表都在), 但也可能暴露遮蔽关系判错。")
        log(render_table(["查询", "策略组", "Surge 命中表", "engine 命中表"],
                         [[m["query"], m["policy"], m["surge_source"], m["engine_source"]]
                          for m in mismatch_source[:40]]))
        if len(mismatch_source) > 40:
            log("  ... 另有 %d 条, 见 --json / 报告" % (len(mismatch_source) - 40))
    else:
        log("  【命中表不一致】无 ✓")
    chk.add(S, "命中表与 Surge 一致", not mismatch_source, "0 条", "%d 条" % len(mismatch_source),
            level="WARN", note="仅提示: 命中表不同但策略组相同时不影响实际分流")

    if errors:
        log("")
        log("  【查询失败】%d 条" % len(errors))
        for q, e in errors[:10]:
            log("    · %s → %s" % (q.get("host") or q.get("ip"), e))
        chk.add(S, "所有查询都拿到了判定", False, "0 条失败", "%d 条" % len(errors),
                level="WARN")

    ctx["result"]["crosscheck"] = {
        "queries": len(queries), "domain": n_domain, "ip": n_ip,
        "mismatch_policy": mismatch_policy, "mismatch_source": mismatch_source,
        "errors": [{"query": q.get("host") or q.get("ip"), "error": e} for q, e in errors],
    }
    return 0


# ---------------------------------------------------------------------------
# 子命令 6: --ua-routing  MITM 红线 + UA 中性验证
# ---------------------------------------------------------------------------

def cmd_ua_routing(ctx):
    """MITM/auto-quic-block 红线 + 「全库零 USER-AGENT 规则」的负向验证。

    2026-08-30 裁决后全库移除了全部 USER-AGENT 规则(静态面由 A8 把守), 本节在
    真实 Surge 上复核同一事实: 每个用例带 UA 与不带 UA 的落点必须完全相同,
    落点变化 = 有 UA 规则回流, 应删规则本身。
    """
    log, chk, cli = ctx["log"], ctx["checks"], ctx["cli"]
    S = "ua-routing"
    cases = (ctx["targets"].get("ua_routing") or {}).get("cases") or []
    conf = ctx["conf_text"]
    mitm_on, mitm_host, quic = conf_mitm_hostname(conf)
    log.section("UA 中性验证 + MITM 红线")
    log("")
    log("  [MITM] hostname = %s" % (mitm_host if mitm_on else "(留空/注释, 未启用)"))
    log("         auto-quic-block = %s" % (quic or "(未设置)"))
    if mitm_on:
        chk.add(S, "启用 MITM hostname 时 auto-quic-block 必须为 true",
                str(quic).lower() == "true", "true", quic or "(未设置)",
                note="否则命中域的 HTTP/3 会绕过 MITM 形成半解密(profile 红线)")

    if not cli.available:
        chk.add(S, "surge-cli 可用", False, "可用", cli.reason)
        return 2

    rows = []
    for case in cases:
        cid = case.get("id") or case.get("host")
        host = case["host"]
        ua, base_ua = case.get("ua"), case.get("baseline_ua") or "curl/8.7.1"
        got = cli.explain(host, user_agent=ua)
        base = cli.explain(host, user_agent=base_ua)
        same = got["policy"] == base["policy"]
        rows.append([cid, (ua or "")[:32], base["policy"] or "?",
                     got["policy"] or "?", got["source"] or "-",
                     "✓ UA 不改变落点" if same else "✗ UA 改变了落点"])
        chk.add(S, "UA 中性 %s" % cid, same, base["policy"] or "?",
                got["policy"] or "?",
                note="落点随 UA 变化 = 有 USER-AGENT 规则回流(命中 %s), 应删规则本身"
                     % (got["source"] or "?"))
        if case.get("baseline_policy"):
            chk.add(S, "基线落点 %s" % cid, base["policy"] == case["baseline_policy"],
                    case["baseline_policy"], base["policy"] or "?", level="WARN",
                    note="基线变了说明宿主域自身归属变了, 用例需要更新")

    log("")
    log("  规则层(surge-cli rule explain, 不建连接, 随时可跑):")
    log(render_table(["用例", "UA(截断)", "基线落点", "带 UA 落点", "命中表", "判定"], rows))

    ctx["result"]["ua_routing"] = {
        "mitm_enabled": mitm_on, "auto_quic_block": quic, "cases": rows,
    }
    return 0


# ---------------------------------------------------------------------------
# 报告输出
# ---------------------------------------------------------------------------

def write_report(path, log, result, checks):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    s = checks.stats()
    body = ["# Surge 真实客户端 / 网络栈实测报告 (realworld.py v%s)" % VERSION, "",
            "- 生成时间: %s" % ts,
            "- 生成方式: `python3 realworld.py --full`",
            "- 断言统计: 通过 %d / 失败 %d / 提示 %d / 仅报告 %d"
            % (s["pass"], s["fail"], s["warn"], s["report"]),
            "- 判定原则: **在线为准**。与离线引擎冲突时改 engine.py 或规则, 不是反过来。",
            "", "## 控制台输出", "", "```"]
    body.extend(log.lines)
    body += ["```", "", "## 断言明细", "",
             render_table(["区块", "断言", "结果", "期望", "实际"],
                          [[i["section"], i["name"], checks.mark(i["ok"]),
                            i["expect"], i["actual"]] for i in checks.items]),
             "", "## 机器可读结果", "", "```json",
             json.dumps({"stats": s, "checks": checks.items, "detail": result},
                        ensure_ascii=False, indent=2), "```"]
    try:
        d = os.path.dirname(os.path.abspath(path))
        if d:
            os.makedirs(d, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(body) + "\n")
        return True
    except OSError as e:
        sys.stderr.write("写报告失败: %s\n" % e)
        return False


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(
        prog="realworld.py",
        description="Surge 分流测试套件 L4: 真实客户端与网络栈实测(用 surge-cli + 系统命令, 不需要 http-api)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""示例:
  python3 realworld.py --tun                 # 接管状态(离线可跑)
  python3 realworld.py --crosscheck          # 与离线引擎对账(离线可跑)
  python3 realworld.py --ua-routing          # MITM 红线 + UA 中性验证
  python3 realworld.py --dns                 # DNS 深测
  python3 realworld.py --webrtc              # STUN / WebRTC 泄漏
  python3 realworld.py --clients             # 真实客户端画像 × 各组代表域
  python3 realworld.py --offline             # 只跑不需要外网的部分
  python3 realworld.py --full --report ~/Desktop/surge-audit/realworld.md

退出码: 0 通过 / 1 有失败 / 2 环境不可用 / 3 用法或中断""")
    p.add_argument("--tun", action="store_true", help="TUN / 接管状态检测")
    p.add_argument("--dns", action="store_true", help="DNS 深测")
    p.add_argument("--webrtc", action="store_true", help="WebRTC / STUN 泄漏检测")
    p.add_argument("--clients", action="store_true", help="真实客户端模拟")
    p.add_argument("--crosscheck", action="store_true", help="分流落点交叉验证")
    p.add_argument("--ua-routing", action="store_true", dest="ua_routing",
                   help="UA 分流生效性(四格通道矩阵)")
    p.add_argument("--full", action="store_true", help="全部子命令按序跑一遍并写报告")
    p.add_argument("--offline", action="store_true",
                   help="只跑不需要外网的部分(--tun --crosscheck --ua-routing 的规则层)")
    p.add_argument("--list-targets", action="store_true",
                   help="打印数据配置摘要并复核每个代表域的归属, 不发任何外部请求")

    p.add_argument("--targets", default=DEFAULT_TARGETS, help="数据配置路径")
    p.add_argument("--conf", default=None, help="Surge.conf 路径")
    p.add_argument("--scenarios-dir", default=DEFAULT_SCEN_DIR, dest="scen_dir",
                   help="交叉验证用的场景目录")
    p.add_argument("--surge-cli", default=DEFAULT_SURGE_CLI, dest="surge_cli",
                   help="surge-cli 路径")
    p.add_argument("--via", choices=("auto", "proxy", "tun"), default="auto",
                   help="真实请求走哪条通道: auto=沿用环境(真实 App 的行为, 默认) / "
                        "proxy=显式走 Surge HTTP 代理 / tun=绕开代理走 TUN")
    p.add_argument("--proxy-port", type=int, default=None, help="Surge HTTP 代理端口")
    p.add_argument("--timeout", type=float, default=10.0, help="单请求超时秒数(默认 10)")
    p.add_argument("--rate", type=float, default=3.0, help="每秒请求数上限(默认 3)")
    p.add_argument("--filter", default=None, help="只跑名字含该子串的组/场景")
    p.add_argument("--limit", type=int, default=None, help="交叉验证最多跑多少条查询")
    p.add_argument("--strict", action="store_true",
                   help="把纯 IP 查询的离线/在线差异也升级为硬失败(默认只提示)")
    p.add_argument("--redact", action="store_true",
                   help="输出里遮蔽节点名与出口 IP 尾段, 方便把报告贴到公开处")
    p.add_argument("--report", default=None, help="报告输出路径(markdown)")
    p.add_argument("--json", action="store_true", dest="as_json",
                   help="stdout 只输出 JSON(人读信息全部静音)")
    return p


def make_mask_ip(redact):
    def mask(ip):
        if not ip:
            return ip
        if not redact:
            return ip
        try:
            a = ipaddress.ip_address(str(ip))
        except ValueError:
            return ip
        if a.version == 4:
            return ".".join(str(ip).split(".")[:3] + ["x"])
        return str(ip).rsplit(":", 2)[0] + "::x"
    return mask


def main(argv=None):
    args = build_parser().parse_args(argv)
    picks = [args.tun, args.dns, args.webrtc, args.clients, args.crosscheck,
             args.ua_routing, args.full, args.offline, args.list_targets]
    if not any(picks):
        build_parser().print_help()
        return 3

    log = Log(quiet=args.as_json)
    checks = Checks()
    conf_path = args.conf or default_conf_path()
    conf_text = read_conf(conf_path)
    if not conf_text:
        sys.stderr.write("读不到 Surge 配置: %s(用 --conf 指定)\n" % conf_path)
        return 3
    targets = load_targets(args.targets, log)
    cli = SurgeCLI(args.surge_cli, timeout=max(args.timeout, 15.0), redact=args.redact)
    port, how = (args.proxy_port, "命令行 --proxy-port") if args.proxy_port \
        else detect_proxy_port(conf_text)
    curl = Curl(timeout=args.timeout, rate=args.rate, proxy_port=port)

    via_desc = {"auto": "auto(沿用环境变量/系统代理, 即真实 App 的行为)",
                "proxy": "proxy(显式 -x http://127.0.0.1:%d)" % port,
                "tun": "tun(--noproxy '*', 绕开代理走 TUN)"}[args.via]

    ctx = {
        "log": log, "checks": checks, "cli": cli, "curl": curl,
        "targets": targets, "conf_text": conf_text, "conf_path": conf_path,
        "scen_dir": args.scen_dir, "proxy_port": port, "proxy_port_how": how,
        "via": args.via, "via_desc": via_desc, "timeout": args.timeout,
        "rate": args.rate, "filter": args.filter, "limit": args.limit,
        "strict": args.strict, "mask_ip": make_mask_ip(args.redact),
        "offline": bool(args.offline), "group_http_exit": {}, "result": {},
    }

    log("Surge 真实客户端 / 网络栈实测 (realworld.py v%s)" % VERSION)
    log("配置      : %s" % conf_path)
    log("数据配置  : %s" % args.targets)
    log("surge-cli : %s" % (cli.path if cli.available else "不可用 —— " + cli.reason))
    log("curl      : %s" % (curl.path if curl.available else "不可用"))
    log("通道      : %s" % via_desc)

    if args.list_targets:
        return cmd_list_targets(ctx)

    if not cli.available:
        log("")
        log(ENV_GUIDE)
        return 2
    if cli.status.get("Mode") and cli.status["Mode"] != "rule":
        log("")
        log("  ⚠ 出站模式是 %s 而不是 rule —— 分流断言全部不成立, 先切回规则模式。"
            % cli.status["Mode"])
        log(ENV_GUIDE)
        return 2

    order = []
    if args.full:
        order = [cmd_tun, cmd_dns, cmd_clients, cmd_webrtc, cmd_ua_routing, cmd_crosscheck]
    elif args.offline:
        order = [cmd_tun, cmd_crosscheck, cmd_ua_routing]
    else:
        if args.tun:
            order.append(cmd_tun)
        if args.dns:
            order.append(cmd_dns)
        if args.clients:
            order.append(cmd_clients)
        if args.webrtc:
            order.append(cmd_webrtc)
        if args.ua_routing:
            order.append(cmd_ua_routing)
        if args.crosscheck:
            order.append(cmd_crosscheck)

    env_fail = 0
    for fn in order:
        rc = fn(ctx)
        if rc == 2:
            env_fail = 2

    # --- 汇总 ------------------------------------------------------------
    s = checks.stats()
    log.section("汇总")
    per_section = {}
    for i in checks.items:
        d = per_section.setdefault(i["section"], {"pass": 0, "fail": 0, "warn": 0, "report": 0})
        if i["ok"] is None:
            d["report"] += 1
        elif i["ok"]:
            d["pass"] += 1
        elif i["level"] == "FAIL":
            d["fail"] += 1
        else:
            d["warn"] += 1
    log(render_table(["区块", "通过", "失败", "提示", "仅报告"],
                     [[k, v["pass"], v["fail"], v["warn"], v["report"]]
                      for k, v in per_section.items()]))
    fails = checks.failures()
    if fails:
        log("")
        log("【失败明细】")
        for i in fails:
            log("  ✗ [%s] %s" % (i["section"], i["name"]))
            log("      期望: %s" % i["expect"])
            log("      实际: %s" % i["actual"])
            if i["note"]:
                log("      说明: %s" % i["note"])
    warns = checks.warnings()
    if warns:
        log("")
        log("【提示(不计失败)】%d 条" % len(warns))
        for i in warns[:20]:
            log("  ! [%s] %s —— 期望 %s, 实际 %s" % (i["section"], i["name"],
                                                     i["expect"], i["actual"]))
        if len(warns) > 20:
            log("  ... 另有 %d 条, 见报告 / --json" % (len(warns) - 20))
    log("")
    log("结果: %s(通过 %d / 失败 %d / 提示 %d / 仅报告 %d)"
        % ("FAIL" if s["fail"] else "PASS", s["pass"], s["fail"], s["warn"], s["report"]))

    if args.report:
        if write_report(args.report, log, ctx["result"], checks):
            log("报告已写入: %s" % args.report)

    if args.as_json:
        print(json.dumps({"version": VERSION, "stats": s, "checks": checks.items,
                          "detail": ctx["result"]}, ensure_ascii=False, indent=2))
    return 1 if s["fail"] else (env_fail or 0)


def cmd_list_targets(ctx):
    """打印数据配置摘要并复核归属。不发任何外部请求。"""
    log, cli, targets = ctx["log"], ctx["cli"], ctx["targets"]
    log.section("数据配置摘要与归属复核(不发外部请求)")
    rows = []
    for g in targets.get("groups") or []:
        for h in g.get("hosts") or []:
            ex = cli.explain(h["host"]) if cli.available else {"policy": "?", "source": "?"}
            ok = (ex["policy"] == g["group"])
            rows.append([g["group"], h["host"], h.get("echo") or "-",
                         ex["policy"] or "?", ex["source"] or "-",
                         "✓" if ok else "✗ 归属已变"])
    log(render_table(["声明策略组", "代表域", "回显方式", "Surge 实测组", "命中表", "复核"], rows))
    log("")
    log(render_table(["画像", "说明", "HTTP", "UA"],
                     [[c["id"], c.get("desc", ""), c.get("http", ""),
                       (c.get("ua") or "")[:60]] for c in targets.get("clients") or []]))
    bad = [r for r in rows if r[-1] != "✓"]
    log("")
    log("代表域 %d 个, 归属复核不通过 %d 个。" % (len(rows), len(bad)))
    return 1 if bad else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.stderr.write("\n已中断。\n")
        sys.exit(3)
