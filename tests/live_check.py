#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
live_check.py — 分流测试套件 L3「在线实测层」(需要 Surge HTTP API)。

做离线层做不到的三件事: 用 HTTP API 读「Surge 认为发生了什么」; 用真实 HTTPS
请求量各策略组的真实出口 IP 并查 RDAP 判住宅/机房; 用 DNS 缓存实锤泄漏。

原则: 只读(唯一写操作是 POST /v1/dns/flush, --no-flush 可关), 绝不改配置;
在线为准, 与离线引擎冲突时输出偏差表; API 未开启时给指引而非崩溃; 标准库 only。

退出码: 0 通过 / 1 有失败 / 2 HTTP API 不可用 / 3 用法或环境错误。
"""

import argparse
import json
import os
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime

VERSION = "1.0.0"
SELF_DIR = os.path.dirname(os.path.abspath(__file__))

# ---------------------------------------------------------------------------
# 本地私有覆盖档(不入库; 与 engine.py 共用同一 schema 与查找顺序)
# ---------------------------------------------------------------------------
#
# tests/ 随公开仓库分发, 代码里只放中性占位默认值; 真实策略组名 / 节点关键字 /
# ASN / RDAP 归属关键字外置到覆盖档: 环境变量 LIVE_CHECK_LOCAL 指定的路径, 或
# tests/live_check_local.json(已 gitignore)。schema 键: exit_class_exact /
# exit_class_keywords / asn_map / residential_hints / datacenter_hints。
# 缺失时全部走中性默认值, 不报错(启发式归类退化到国旗兜底)。

_LOCAL_KEYS = ("exit_class_exact", "exit_class_keywords", "asn_map",
               "residential_hints", "datacenter_hints")


def local_profile_candidates(self_dir=SELF_DIR):
    out = []
    env = os.environ.get("LIVE_CHECK_LOCAL")
    if env:
        out.append(env)
    out.append(os.path.join(self_dir, "live_check_local.json"))
    return out


def load_local_profile(self_dir=SELF_DIR):
    """读第一个存在的覆盖档, 返回 (dict, 路径 or None); 缺失不报错。"""
    for path in local_profile_candidates(self_dir):
        try:
            with open(path, encoding="utf-8") as fh:
                raw = json.load(fh)
        except (OSError, ValueError):
            continue
        if isinstance(raw, dict):
            return {k: raw[k] for k in _LOCAL_KEYS if k in raw}, path
    return {}, None


LOCAL_PROFILE, LOCAL_PROFILE_PATH = load_local_profile()

# ---------------------------------------------------------------------------
# 常量: 出口分类映射(exit_class 取值集合与 spec/testkit.md「共享 Schema」一致;
#       键/关键字是本机 conf 的私有名字, 由本地覆盖档提供)
# ---------------------------------------------------------------------------

# 策略组/物理节点名 → exit_class 精确映射。
# 这里只登记中性占位组名; 真实组名由覆盖档的 exit_class_exact 覆盖合并进来。
EXIT_CLASS_EXACT_DEFAULT = {
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
EXIT_CLASS_EXACT = dict(EXIT_CLASS_EXACT_DEFAULT)
_lc_exact = LOCAL_PROFILE.get("exit_class_exact") or {}
if isinstance(_lc_exact, dict):
    EXIT_CLASS_EXACT.update({str(k): str(v) for k, v in _lc_exact.items()})

# 物理节点名(如 🇺🇸<ISP>-<机房>-LAX)的启发式归类。
# 在线拿到的 policyName 往往是链路末端的物理节点而不是策略组名, 用关键字回推 exit_class。
# 注意: 这是启发式, 输出中会标 "~" 前缀提示。
# 节点名里的 ISP / 机房关键字是私有信息, 内置表只留一条中性示例说明格式,
# 真实关键字放本地覆盖档的 exit_class_keywords, 形如:
#   [["KW-A", "US-HOME-A"], ["KW-B", "US-HOME-B"]]
EXIT_CLASS_KEYWORDS_DEFAULT = [
    ("KW-A", "US-HOME-A"),
]
# 覆盖档的关键字排在内置示例之前 —— 首个子串命中即返回, 覆盖档优先。
EXIT_CLASS_KEYWORDS = [tuple(x) for x in
                       (LOCAL_PROFILE.get("exit_class_keywords") or [])
                       if isinstance(x, (list, tuple)) and len(x) == 2]
EXIT_CLASS_KEYWORDS += list(EXIT_CLASS_KEYWORDS_DEFAULT)
EXIT_CLASS_FLAGS = [
    ("🇺🇸", "US-DC"),
    ("🇯🇵", "JP-DC"),
    ("🇬🇧", "EU"),
    ("🇪🇺", "EU"),
    ("🇳🇱", "EU"),
    ("🇩🇪", "EU"),
]

# --exit-map 的出口画像探针。
#
# 关键约束: 探针 URL 必须本身就命中目标策略组的规则, 否则量到的不是这个组的出口。
# 下方每条都注明了它靠哪条规则落到该组(依据当前 rules/ 实际内容), 并且都在 2026-08 实测可用。
#   route_probe: 没有 IP 回显端点的组, 用它发一次普通请求, 好让 recent 里留下记录做归属交叉验证。
#
# 端点会失效(站点换 CDN / 关掉 trace), 失效时本节退化为「配置推导 + 交叉验证」而不是报错,
# 想换端点只改这张表即可 —— 选取标准见 README「exit-map 探针为什么是这几个域名」。
EXIT_PROBES = [
    {
        "group": "AI",
        "urls": [
            "https://chatgpt.com/cdn-cgi/trace",   # AI.list: DOMAIN-SUFFIX,chatgpt.com
            "https://claude.ai/cdn-cgi/trace",     # AI.list: DOMAIN-SUFFIX,claude.ai
        ],
        "parser": "cf_trace",
    },
    {
        "group": "Google-X-Meta-MS",
        # x.com 已迁到 Cloudflare, /cdn-cgi/trace 可用; 命中 Twitter.list: DOMAIN-SUFFIX,x.com
        # (旧的 domains.google.com/checkip 已 301 到 domains.google, 不再回显 IP, 勿用)
        "urls": ["https://x.com/cdn-cgi/trace"],
        "parser": "cf_trace",
    },
    {
        "group": "社交媒体",
        # SocialOthers.list 里的站点目前都没有可用的 IP 回显端点:
        #   discord.com/cdn-cgi/trace → 403, reddit/tumblr/bsky/pinterest → 返回 HTML。
        # 因此本组只做归属交叉验证, 出口 IP 走「配置推导」列。
        "urls": [],
        "route_probe": "https://discord.com/",
        "parser": "cf_trace",
    },
    {
        "group": "流媒体",
        "urls": [
            # Streaming.list: DOMAIN-SUFFIX,fast.com → api.fast.com 命中同一条; v2 端点回显 client.ip + client.asn
            "https://api.fast.com/netflix/speedtest/v2"
            "?https=true&token=YXNkZmFzZGxmbnNkYWZoYXNkZmhrYWxm&urlCount=1",
        ],
        "parser": "fast_json",
    },
    {
        "group": "🇯🇵日本节点",
        # Japan.list: DOMAIN-SUFFIX,pixiv.net, 且 pixiv 在 Cloudflare 后面
        "urls": ["https://www.pixiv.net/cdn-cgi/trace"],
        "parser": "cf_trace",
    },
    {
        "group": "DIRECT",
        "urls": [
            "https://myip.ipip.net/",                        # Domestic.list: DOMAIN-SUFFIX,ipip.net
            "http://connect.rom.miui.com/generate_204",      # Domestic.list: DOMAIN-SUFFIX,miui.com(仅测连通)
        ],
        "parser": "ipip",
    },
    {
        "group": "Final",
        "urls": [
            "https://icanhazip.com/",  # 不在任何 list 中 → FINAL,Final
        ],
        "parser": "plain_ip",
    },
]

# 仅用于给 RDAP 结果加注释的内置 ASN 表(不参与断言)。
# 只收录与本机线路无关的公共云 ASN; 自己上游线路的 ASN 是私有信息,
# 放本地覆盖档的 asn_map。
KNOWN_ASN_DEFAULT = {
    "20473": "The Constant Company / Vultr (机房)",
    "14061": "DigitalOcean (机房)",
    "399358": "Anthropic (机房)",
    "401518": "Anthropic (机房)",
}
KNOWN_ASN = dict(KNOWN_ASN_DEFAULT)
_lc_asn = LOCAL_PROFILE.get("asn_map") or {}
if isinstance(_lc_asn, dict):
    KNOWN_ASN.update({str(k): str(v) for k, v in _lc_asn.items()})

# RDAP 机构名/网段名 → 住宅 or 机房 的关键字启发式。
# 内置表只放行业通名; 自己实际用的线路商 / 机房品牌放本地覆盖档的
# residential_hints / datacenter_hints。
RESIDENTIAL_HINTS_DEFAULT = ("COMCAST", "CHARTER", "SPECTRUM",
                             "VERIZON", "COX", "FRONTIER", "CENTURYLINK", "BIGLOBE",
                             "NTT", "KDDI", "SOFTBANK", "OCN", "BROADBAND", "CABLE",
                             "TELECOM", "RESIDENTIAL", "FTTH")
DATACENTER_HINTS_DEFAULT = ("HOSTING", "CLOUD", "DATACENTER", "DATA CENTER", "SERVER",
                            "VPS", "VULTR", "DIGITALOCEAN", "LINODE", "AMAZON",
                            "GOOGLE LLC", "OVH", "HETZNER", "CHOOPA", "COLO", "IDC",
                            "LEASEWEB", "M247")


def _merge_hints(default, key):
    extra = LOCAL_PROFILE.get(key) or []
    if not isinstance(extra, (list, tuple)):
        extra = []
    return tuple(default) + tuple(str(x).upper() for x in extra
                                  if str(x).upper() not in default)


RESIDENTIAL_HINTS = _merge_hints(RESIDENTIAL_HINTS_DEFAULT, "residential_hints")
DATACENTER_HINTS = _merge_hints(DATACENTER_HINTS_DEFAULT, "datacenter_hints")

# --dns-leak 在 scenarios/dns_leak.json 缺失时使用的内置兜底样本。
FALLBACK_PROXY_HOSTS = [
    "chatgpt.com", "claude.ai", "x.com", "discord.com", "reddit.com",
    "netflix.com", "github.com", "wikipedia.org", "spotify.com", "medium.com",
]
FALLBACK_DIRECT_HOSTS = [
    "www.baidu.com", "www.taobao.com", "www.qq.com", "www.bilibili.com",
]

API_GUIDE = """\
────────────────────────────────────────────────────────────────────────
Surge HTTP API 不可用 —— 这不是本程序的 bug, 需要你手工开启一次。

开启步骤(约 1 分钟):
  1. 用编辑器打开你的主配置:
       /Users/<你>/Library/Application Support/Surge/Profiles/Surge.conf
  2. 在 [General] 段任意位置加入一行(key 自取, 只在本机使用):
       http-api = surgetest@127.0.0.1:6171
     格式为  http-api = <Key>@<监听地址>:<端口>
     ▸ 监听地址务必写 127.0.0.1, 不要写 0.0.0.0, 否则局域网内任何人都能控制你的 Surge。
     ▸ 不需要 http-api-tls / http-api-web-dashboard, 本套件用不到。
  3. Surge Dashboard → 右上角「重载配置」(或菜单栏图标 → Reload Profile)。
  4. 把 Key 交给本程序(二选一):
       export SURGE_API_KEY=surgetest        # 推荐, 避免 Key 出现在命令行历史里
       python3 live_check.py --check-api --key surgetest
  5. 复跑:  python3 live_check.py --check-api

排查:
  ▸ 报「连接被拒绝」 → 配置没生效, 确认已重载, 并用 `lsof -nP -iTCP:6171 -sTCP:LISTEN` 看端口。
  ▸ 报「401/403 鉴权失败」 → Key 与配置里的不一致(区分大小写)。
  ▸ 端口被占用 → 换个端口(如 6172), 同时用 --api http://127.0.0.1:6172 告诉本程序。

本程序不会替你修改任何配置文件。离线三层(engine.py / audit.py / runsuite.py)
无需 HTTP API 也能完整运行, 在线层只是给离线结论加一道实网证据。
────────────────────────────────────────────────────────────────────────"""


# ---------------------------------------------------------------------------
# 小工具: 终端表格 / 宽度 / 日志
# ---------------------------------------------------------------------------

def dwidth(s):
    """估算字符串在等宽终端里的显示宽度(CJK/emoji 记 2 列, 国旗的两个 RI 码位各记 1)。"""
    w = 0
    for ch in str(s):
        o = ord(ch)
        if 0x1F1E6 <= o <= 0x1F1FF:      # Regional Indicator, 成对渲染为 2 列
            w += 1
        elif 0x0300 <= o <= 0x036F:      # 组合附加符号
            w += 0
        elif (0x1100 <= o <= 0x115F or 0x2E80 <= o <= 0xA4CF or 0xAC00 <= o <= 0xD7A3
              or 0xF900 <= o <= 0xFAFF or 0xFE30 <= o <= 0xFE6F or 0xFF00 <= o <= 0xFF60
              or 0xFFE0 <= o <= 0xFFE6 or 0x1F300 <= o <= 0x1FAFF or 0x2600 <= o <= 0x27BF):
            w += 2
        else:
            w += 1
    return w


def pad(s, width):
    s = "" if s is None else str(s)
    return s + " " * max(0, width - dwidth(s))


def render_table(headers, rows):
    """返回 markdown 风格但等宽对齐的表格文本(同时用于终端与 live_report.md)。"""
    if not rows:
        return "  (无数据)"
    cols = len(headers)
    widths = [dwidth(h) for h in headers]
    norm = []
    for r in rows:
        cells = [("" if c is None else str(c)) for c in list(r)[:cols]]
        cells += [""] * (cols - len(cells))
        norm.append(cells)
        for i, c in enumerate(cells):
            widths[i] = max(widths[i], dwidth(c))
    out = ["| " + " | ".join(pad(h, widths[i]) for i, h in enumerate(headers)) + " |",
           "|" + "|".join("-" * (widths[i] + 2) for i in range(cols)) + "|"]
    for cells in norm:
        out.append("| " + " | ".join(pad(c, widths[i]) for i, c in enumerate(cells)) + " |")
    return "\n".join(out)


class Log(object):
    """人读输出通道。--json 模式下全部静音, 保证 stdout 是纯 JSON。"""

    def __init__(self, quiet=False):
        self.quiet = quiet
        self.lines = []

    def __call__(self, msg=""):
        self.lines.append(str(msg))
        if not self.quiet:
            print(msg)

    def section(self, title):
        self("")
        self("=" * 72)
        self("  " + title)
        self("=" * 72)


# ---------------------------------------------------------------------------
# Surge HTTP API 客户端
# ---------------------------------------------------------------------------

class ApiError(Exception):
    def __init__(self, kind, detail):
        Exception.__init__(self, "%s: %s" % (kind, detail))
        self.kind = kind        # refused / timeout / auth / http / decode / other
        self.detail = detail


class SurgeAPI(object):
    def __init__(self, base, key, timeout=8.0, dump_dir=None):
        self.base = base.rstrip("/")
        self.key = key or ""
        self.timeout = timeout
        self.dump_dir = dump_dir
        # 显式关闭代理: API 是本机回环, 绝不能被 http_proxy 环境变量或 Surge 自己劫持。
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def request(self, path, method="GET", payload=None):
        url = self.base + path
        data = None
        headers = {"X-Key": self.key, "Accept": "application/json"}
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with self.opener.open(req, timeout=self.timeout) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as e:
            body = ""
            try:
                body = e.read().decode("utf-8", "replace")[:200]
            except Exception:
                pass
            if e.code in (401, 403):
                raise ApiError("auth", "HTTP %s 鉴权失败(X-Key 与配置不一致?) %s" % (e.code, body))
            raise ApiError("http", "HTTP %s %s %s" % (e.code, path, body))
        except urllib.error.URLError as e:
            reason = getattr(e, "reason", e)
            if isinstance(reason, socket.timeout):
                raise ApiError("timeout", "请求 %s 超时(%ss)" % (path, self.timeout))
            if isinstance(reason, ConnectionRefusedError) or "refused" in str(reason).lower():
                raise ApiError("refused", "连接被拒绝: %s" % self.base)
            raise ApiError("other", "%s (%s)" % (reason, path))
        except socket.timeout:
            raise ApiError("timeout", "请求 %s 超时(%ss)" % (path, self.timeout))
        except Exception as e:                       # noqa: BLE001 - 兜底不让在线层拖垮整个跑批
            raise ApiError("other", "%s: %s" % (type(e).__name__, e))

        self._dump(path, raw)
        if not raw:
            return {}
        try:
            return json.loads(raw.decode("utf-8", "replace"))
        except ValueError:
            raise ApiError("decode", "响应不是合法 JSON(%s): %s" % (path, raw[:120]))

    def _dump(self, path, raw):
        if not self.dump_dir:
            return
        try:
            os.makedirs(self.dump_dir, exist_ok=True)
            name = re.sub(r"[^A-Za-z0-9]+", "_", path).strip("_") or "root"
            with open(os.path.join(self.dump_dir, name + ".json"), "wb") as f:
                f.write(raw)
        except OSError:
            pass

    # --- 具体端点(全部只读, 除 flush_dns) -------------------------------
    def outbound(self):
        return self.request("/v1/outbound")

    def policy_groups(self):
        return self.request("/v1/policy_groups")

    def group_selected(self, group):
        return self.request("/v1/policy_groups/select?group_name=" + urllib.parse.quote(group))

    def recent_requests(self):
        return self.request("/v1/requests/recent")

    def dns_records(self):
        return self.request("/v1/dns")

    def flush_dns(self):
        return self.request("/v1/dns/flush", method="POST", payload={})

    def profile_text(self):
        data = self.request("/v1/profiles/current?sensitive=0")
        if isinstance(data, dict):
            for k in ("profile", "content", "text"):
                if isinstance(data.get(k), str):
                    return data[k]
        return ""


# ---------------------------------------------------------------------------
# 通过 Surge 本地代理发真实请求
# ---------------------------------------------------------------------------

class RateLimiter(object):
    def __init__(self, per_second):
        self.interval = 1.0 / float(per_second) if per_second > 0 else 0.0
        self._last = 0.0

    def wait(self):
        if self.interval <= 0:
            return
        gap = self.interval - (time.monotonic() - self._last)
        if gap > 0:
            time.sleep(gap)
        self._last = time.monotonic()


class ProxyClient(object):
    """经 Surge HTTP 代理端口发起真实请求; 失败一律降级为 UNREACHABLE, 不视为断言失败。"""

    def __init__(self, port, timeout=8.0, rate=3.0, insecure=False):
        self.port = port
        self.timeout = timeout
        self.limiter = RateLimiter(rate)
        proxy = "http://127.0.0.1:%d" % port
        ctx = ssl.create_default_context()
        if insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": proxy, "https": proxy}),
            urllib.request.HTTPSHandler(context=ctx),
        )

    def fetch(self, url, method="GET", max_bytes=65536):
        """返回 dict(ok, status, body, error)。ok=False 表示网络层没打通。"""
        self.limiter.wait()
        req = urllib.request.Request(url, method=method, headers={
            "User-Agent": "surge-live-check/%s" % VERSION,
            "Accept": "*/*",
            "Connection": "close",
        })
        t0 = time.monotonic()
        try:
            with self.opener.open(req, timeout=self.timeout) as resp:
                body = b"" if method == "HEAD" else resp.read(max_bytes)
                return {"ok": True, "status": resp.status, "error": None,
                        "body": body.decode("utf-8", "replace"),
                        "ms": int((time.monotonic() - t0) * 1000)}
        except urllib.error.HTTPError as e:
            # HTTP 4xx/5xx 说明链路是通的(TCP+TLS 已建立), 对分流判定而言算成功。
            try:
                body = e.read(max_bytes).decode("utf-8", "replace")
            except Exception:
                body = ""
            return {"ok": True, "status": e.code, "error": "HTTP %s" % e.code,
                    "body": body, "ms": int((time.monotonic() - t0) * 1000)}
        except Exception as e:                        # noqa: BLE001
            return {"ok": False, "status": None, "body": "",
                    "error": "%s: %s" % (type(e).__name__, e),
                    "ms": int((time.monotonic() - t0) * 1000)}

    def touch(self, host):
        """轻量触发一次到 host 的连接, 让 Surge 产生一条请求记录 / DNS 记录。"""
        url = "https://%s/" % host
        r = self.fetch(url, method="HEAD", max_bytes=1024)
        if not r["ok"]:
            # 部分站点拒绝 HEAD 或 TLS 指纹敏感, 退回 GET 再试一次。
            r = self.fetch(url, method="GET", max_bytes=2048)
        return r


def detect_proxy_port(api, explicit=None, log=None):
    """确定 Surge 的 HTTP 代理端口: 显式指定 > 配置文本 http-listen > 常规端口探测。"""
    if explicit:
        return explicit, "命令行 --proxy-port"
    # 1) 从 API 读配置文本(只读)
    if api is not None:
        try:
            text = api.profile_text()
            m = re.search(r"^\s*http-listen\s*=\s*(?:([0-9.]+):)?(\d+)", text, re.M)
            if m:
                return int(m.group(2)), "配置 http-listen"
        except ApiError:
            pass
    # 2) 常规端口探测(Surge Mac 默认 6152 HTTP / 6153 SOCKS5)
    for port in (6152, 8888, 8080, 1087):
        s = socket.socket()
        s.settimeout(0.4)
        try:
            s.connect(("127.0.0.1", port))
            return port, "端口探测(默认值)"
        except OSError:
            continue
        finally:
            s.close()
    if log:
        log("  [警告] 未探测到可用的 Surge HTTP 代理端口, 回退到 6152。")
    return 6152, "回退默认值"


# ---------------------------------------------------------------------------
# 离线引擎桥接(engine.py 可能尚未安装 → 全程可降级)
# ---------------------------------------------------------------------------

class EngineBridge(object):
    """同目录 engine.py 的进程内桥接; 加载失败时降级为「仅在线结论」。"""

    def __init__(self, tests_dir, conf=None):
        self.conf = conf
        self.available = False
        self.reason = ""
        self.mode = "in-process"
        self._cache = {}
        self._eng = None
        try:
            if tests_dir not in sys.path:
                sys.path.insert(0, tests_dir)
            import engine
            self._eng = engine.build_engine(conf)
            self.available = True
        except BaseException as e:                              # noqa: BLE001
            self.reason = "engine.py 加载失败: %s" % e

    def match(self, host, ip=None):
        if not self.available:
            return None
        key = (host, ip)
        if key not in self._cache:
            try:
                self._cache[key] = self._eng.match(host=host, ip=ip)
            except Exception:                                   # noqa: BLE001
                self._cache[key] = None
        return self._cache[key]


# ---------------------------------------------------------------------------
# 解析辅助
# ---------------------------------------------------------------------------

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6_RE = re.compile(r"\b(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}\b")


def exit_class_of(name):
    """策略/节点名 → exit_class。返回 (class, is_heuristic)。"""
    if not name:
        return ("UNKNOWN", False)
    n = name.strip()
    if n in EXIT_CLASS_EXACT:
        return (EXIT_CLASS_EXACT[n], False)
    up = n.upper()
    for kw, cls in EXIT_CLASS_KEYWORDS:
        if kw.upper() in up:
            return (cls, True)
    for flag, cls in EXIT_CLASS_FLAGS:
        if flag in n:
            return (cls, True)
    return ("UNKNOWN", False)


def host_of_url(url):
    if not url:
        return ""
    u = str(url).strip()
    if "://" not in u:
        # Surge 有时记成 "host:443"
        u = u.split("/")[0]
        return u.rsplit(":", 1)[0] if u.count(":") == 1 else u
    try:
        parsed = urllib.parse.urlsplit(u)
        return (parsed.hostname or "").lower()
    except ValueError:
        return ""


def parse_policy_chain(req):
    """
    从一条 recent request 记录里抽出 (顶层策略组, 末端物理策略, 命中规则文本)。

    Surge 不同版本字段名不一致, 这里全部做兜底:
      * policyName / policy         → 通常是末端物理节点名
      * rule / ruleName             → 命中的规则(如 "RULE-SET(AI.list)")
      * notes[]                     → 可能含 "Policy: AI(🇺🇸美国家宽A → 🇺🇸<末端节点>)"
    """
    policy = ""
    for k in ("policyName", "policy", "policy_name"):
        v = req.get(k)
        if isinstance(v, str) and v:
            policy = v
            break
    rule = ""
    for k in ("rule", "ruleName", "rule_name", "matchedRule"):
        v = req.get(k)
        if isinstance(v, str) and v:
            rule = v
            break

    chain_text = policy
    notes = req.get("notes")
    if isinstance(notes, list):
        for note in notes:
            if not isinstance(note, str):
                continue
            if note.lower().startswith("policy:"):
                chain_text = note.split(":", 1)[1].strip()
            elif not rule and note.lower().startswith("rule:"):
                rule = note.split(":", 1)[1].strip()

    # 拆 "AI(A → B)" / "AI → B" / "AI > B" 这类链式表示
    flat = chain_text.replace("(", " → ").replace(")", "").replace("->", "→").replace(" > ", " → ")
    parts = [p.strip() for p in flat.split("→") if p.strip()]
    group = parts[0] if parts else policy
    leaf = parts[-1] if parts else policy
    return group, leaf, rule


def collect_recent(api, since_epoch=None):
    """拉取 recent requests, 归一化为 host → 最近一条记录。"""
    data = api.recent_requests()
    items = []
    if isinstance(data, dict):
        for k in ("requests", "recentRequests", "items"):
            if isinstance(data.get(k), list):
                items = data[k]
                break
    elif isinstance(data, list):
        items = data
    by_host = {}
    for req in items:
        if not isinstance(req, dict):
            continue
        url = req.get("URL") or req.get("url") or req.get("host") or ""
        host = host_of_url(url)
        if not host:
            continue
        ts = None
        for k in ("startDate", "timestamp", "startTime", "date"):
            v = req.get(k)
            if isinstance(v, (int, float)):
                ts = float(v)
                break
        if since_epoch is not None and ts is not None and ts < since_epoch - 5:
            continue
        prev = by_host.get(host)
        if prev is None or (ts or 0) >= (prev.get("_ts") or 0):
            rec = dict(req)
            rec["_ts"] = ts
            by_host[host] = rec
    return by_host


def load_scenarios(target, scen_dir, log):
    """
    加载场景。target 可以是 'all' / 目录 / 单个 json 文件。
    返回 (scenarios, errors)。文件不存在不抛异常, 交上层降级。
    """
    files = []
    if target in (None, "", "all"):
        if os.path.isdir(scen_dir):
            files = sorted(os.path.join(scen_dir, f)
                           for f in os.listdir(scen_dir) if f.endswith(".json"))
    elif os.path.isdir(target):
        files = sorted(os.path.join(target, f)
                       for f in os.listdir(target) if f.endswith(".json"))
    elif os.path.isfile(target):
        files = [target]
    else:
        cand = os.path.join(scen_dir, target)
        if os.path.isfile(cand):
            files = [cand]
        elif os.path.isfile(cand + ".json"):
            files = [cand + ".json"]

    scenarios, errors = [], []
    for path in files:
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError) as e:
            errors.append("%s 解析失败: %s" % (os.path.basename(path), e))
            continue
        if isinstance(data, dict):
            data = data.get("scenarios", [])
        if not isinstance(data, list):
            errors.append("%s 顶层不是 JSON 数组" % os.path.basename(path))
            continue
        for sc in data:
            if isinstance(sc, dict):
                sc = dict(sc)
                sc["_file"] = os.path.basename(path)
                scenarios.append(sc)
    return scenarios, errors


# ---------------------------------------------------------------------------
# 子命令 2: --policies
# ---------------------------------------------------------------------------

def parse_group_types(profile_text):
    """从配置文本里取每个策略组的类型(select / smart / url-test / fallback ...)。"""
    types = {}
    in_group = False
    for line in profile_text.splitlines():
        s = line.strip()
        if s.startswith("["):
            in_group = s.lower().startswith("[proxy group]")
            continue
        if not in_group or not s or s.startswith("#") or s.startswith(";"):
            continue
        if "=" not in s:
            continue
        name, rest = s.split("=", 1)
        first = rest.strip().split(",")[0].strip().lower()
        types[name.strip()] = first
    return types


def fetch_group_members(api):
    """/v1/policy_groups → {组名: [成员名, ...]}。成员首项即离线引擎的假设出口。"""
    groups = api.policy_groups()
    members = {}
    if isinstance(groups, dict):
        src = groups.get("policy-groups") if isinstance(groups.get("policy-groups"), dict) else groups
        for gname, opts in src.items():
            if not isinstance(opts, list):
                continue
            names = []
            for o in opts:
                if isinstance(o, dict):
                    n = o.get("name") or o.get("policy") or o.get("policyName")
                    if n:
                        names.append(n)
                elif isinstance(o, str):
                    names.append(o)
            members[gname] = names
    return members


def cmd_policies(api, log, result):
    log.section("2. 策略组选中项 vs 引擎假设(默认首项)")
    try:
        members = fetch_group_members(api)
    except ApiError as e:
        log("  [错误] 读取策略组失败: %s" % e.detail)
        result["policies"] = {"error": e.detail}
        return 1

    types = {}
    try:
        types = parse_group_types(api.profile_text())
    except ApiError:
        pass

    rows, entries, warn = [], [], 0
    for gname in sorted(members.keys()):
        opts = members[gname]
        assumed = opts[0] if opts else ""
        gtype = types.get(gname, "?")
        try:
            sel = api.group_selected(gname)
            current = ""
            if isinstance(sel, dict):
                current = sel.get("policy") or sel.get("policyName") or sel.get("name") or ""
        except ApiError as e:
            current = "<读取失败: %s>" % e.kind
        auto = gtype in ("smart", "url-test", "fallback", "load-balance")
        if not current or current.startswith("<"):
            status = "未知"
        elif current == assumed:
            status = "一致"
        elif auto:
            status = "自动选路(非问题)"
        else:
            status = "★ 用户手选与测试假设不一致"
            warn += 1
        cls_cur = exit_class_of(current)[0]
        cls_asm = exit_class_of(assumed)[0]
        same_exit = "是" if cls_cur == cls_asm and cls_cur != "UNKNOWN" else "否"
        rows.append([gname, gtype, current, assumed, same_exit, status])
        entries.append({"group": gname, "type": gtype, "current": current,
                        "engine_assumption": assumed, "same_exit_class": same_exit == "是",
                        "status": status})

    log(render_table(["策略组", "类型", "当前选中", "引擎假设(首项)", "出口同类", "结论"], rows))
    log("")
    if warn:
        log("  ⚠ 有 %d 个 select 组的当前选中项与离线引擎假设(成员首项)不同。" % warn)
        log("    离线层永远按「首项」推演, 所以这些组的 runsuite 结论只在你切回首项时才成立。")
        log("    这通常是你自己手动切换过节点, 不是配置错误。")
    else:
        log("  ✓ 所有 select 组的当前选中项与引擎假设一致(或差异来自 smart 自动选路)。")
    log("  说明: smart / url-test / fallback 组由 Surge 动态择优, 选中项漂移属预期, 不计为失败。")
    result["policies"] = {"groups": entries, "mismatch_select_groups": warn}
    return 0


# ---------------------------------------------------------------------------
# 子命令 3: --scenario
# ---------------------------------------------------------------------------

def cmd_scenario(api, proxy, engine, scenarios, log, result, limit_hosts=None):
    log.section("3. 场景实测 (在线为准, 与离线引擎对比)")
    if not scenarios:
        log("  [跳过] 没有可用场景。scenarios/*.json 由 W7 提供; 也可用 --hosts a.com,b.com 临时指定。")
        result["scenario"] = {"skipped": "no scenarios"}
        return 0

    # 收集去重后的 host 清单(保留每个 host 归属的场景, 用于断言)
    host_ctx = {}
    order = []
    for sc in scenarios:
        name = sc.get("name", "?")
        asserts = sc.get("assert", {}) if isinstance(sc.get("assert"), dict) else {}
        per_req = {}
        for pr in (asserts.get("per_request") or []):
            # 请求可以用 host, 也可以是纯 IP 场景里的 ip —— 两种键都要认
            key = pr.get("host") or pr.get("ip") if isinstance(pr, dict) else None
            if key:
                per_req[key] = pr
        for r in sc.get("requests", []):
            if isinstance(r, dict):
                host = r.get("host") or r.get("ip")
            else:
                host = r
            if not host:
                continue
            if limit_hosts and host not in limit_hosts:
                continue
            if host not in host_ctx:
                host_ctx[host] = []
                order.append(host)
            expect = per_req.get(host, {}).get("policy") or asserts.get("policy")
            policy_in = per_req.get(host, {}).get("policy_in") or asserts.get("policy_in")
            host_ctx[host].append({
                "scenario": name, "file": sc.get("_file", ""),
                "expect_policy": expect, "policy_in": policy_in,
            })

    if not order:
        log("  [跳过] %d 个场景里没有可测域名(--hosts 过滤后为空?)。" % len(scenarios))
        result["scenario"] = {"skipped": "no hosts after filtering"}
        return 0

    log("  场景数 %d, 去重后待测域名 %d 个 (限速 ≤3 req/s, 超时 %ss)" %
        (len(scenarios), len(order), int(proxy.timeout)))
    log("  提示: 首次运行耗时约 %d 秒, 请勿中断。" % max(1, int(len(order) / 3) + 5))

    started = time.time()
    reach, skipped = {}, []
    for i, host in enumerate(order, 1):
        if is_private_ip(host):
            skipped.append(host)
            continue
        r = proxy.touch(host)
        reach[host] = r
        if not log.quiet and (i % 20 == 0 or i == len(order)):
            print("    …已发起 %d/%d" % (i, len(order)))

    time.sleep(1.0)  # 给 Surge 一点时间把请求写进 recent 列表
    try:
        recent = collect_recent(api, since_epoch=started)
    except ApiError as e:
        log("  [错误] 读取 /v1/requests/recent 失败: %s" % e.detail)
        result["scenario"] = {"error": e.detail}
        return 1

    rows, details = [], []
    stat = {"pass": 0, "fail": 0, "unreachable": 0,
            "not_found": 0, "engine_diff": 0, "no_expect": 0, "skipped": len(skipped)}

    for host in order:
        ctx = host_ctx[host][0]
        if host in skipped:
            rows.append([host, ctx["expect_policy"] or "-", "-", "-", "SKIPPED",
                         "内网/回环地址, 在线不实测(离线层已覆盖)"])
            details.append({"host": host, "state": "SKIPPED",
                            "scenario": ctx["scenario"], "file": ctx["file"]})
            continue
        net = reach.get(host, {})
        rec = recent.get(host)
        if rec is None:
            # 有些请求会被合并/复用连接, 或站点直接被墙没建立连接
            state = "UNREACHABLE" if not net.get("ok") else "NOT_FOUND"
            stat["unreachable" if state == "UNREACHABLE" else "not_found"] += 1
            note = net.get("error") or ""
            note = ("recent 中无记录 (%s)" % note) if (state == "NOT_FOUND" and note) else \
                   (note or "recent 中无记录")
            rows.append([host, ctx["expect_policy"] or "-", "-", "-", state, note[:44]])
            details.append({"host": host, "state": state, "net_error": net.get("error"),
                            "scenario": ctx["scenario"], "file": ctx["file"]})
            continue

        group, leaf, rule = parse_policy_chain(rec)
        remote = rec.get("remoteAddress") or rec.get("remoteAddr") or ""
        online_cls = exit_class_of(group if group in EXIT_CLASS_EXACT else leaf)[0]

        # 离线引擎判定
        eng = engine.match(host) if engine.available else None
        eng_policy = (eng or {}).get("policy")
        eng_cls = (eng or {}).get("exit_class")

        expect = ctx["expect_policy"]
        allowed = ctx["policy_in"] if isinstance(ctx["policy_in"], list) else None

        if expect or allowed:
            ok = (group == expect) or (leaf == expect) or (allowed and (group in allowed or leaf in allowed))
            if not ok and expect and eng_policy == expect and group == leaf:
                # 在线只报了末端物理节点名, 无法直接比组名 → 退一步比 exit_class
                ok = exit_class_of(expect)[0] == online_cls and online_cls != "UNKNOWN"
            if ok:
                state = "PASS"
                stat["pass"] += 1
            else:
                state = "FAIL"
                stat["fail"] += 1
        else:
            state = "REPORT"
            stat["no_expect"] += 1

        diff = ""
        if eng_policy and eng_policy != group and eng_policy != leaf:
            if eng_cls and eng_cls == online_cls:
                diff = "组名不同/出口同类"
            else:
                diff = "离线=%s" % eng_policy
                stat["engine_diff"] += 1

        rows.append([host, expect or (",".join(allowed) if allowed else "-"),
                     group if group == leaf else "%s→%s" % (group, leaf),
                     online_cls, state, diff or (rule or "")[:36]])
        details.append({"host": host, "state": state, "expect": expect,
                        "online_group": group, "online_leaf": leaf,
                        "online_rule": rule, "online_exit_class": online_cls,
                        "remote_address": remote, "engine_policy": eng_policy,
                        "engine_exit_class": eng_cls, "engine_diff": diff,
                        "scenario": ctx["scenario"], "file": ctx["file"]})

    log("")
    log(render_table(["域名", "期望组", "在线策略", "出口类", "结果", "备注/命中规则"], rows))
    log("")
    log("  统计: PASS %d | FAIL %d | UNREACHABLE %d | NOT_FOUND %d | "
        "仅报告 %d | 跳过 %d"
        % (stat["pass"], stat["fail"], stat["unreachable"],
           stat["not_found"], stat["no_expect"], stat["skipped"]))
    if not engine.available:
        log("  注: 离线引擎不可用(%s), 本次只有在线结论, 无偏差对比。" % engine.reason)
    elif stat["engine_diff"]:
        log("  注: %d 个域名的离线判定与在线不一致 —— 以在线为准, 这是 engine.py 的待修点。"
            % stat["engine_diff"])
    log("  注: UNREACHABLE 表示网络层没打通(被墙/证书/站点拒绝 HEAD), 不算分流错误。")

    # 一次什么都没量到的运行不能报「全部通过」—— 那是最坑人的假绿灯
    decided = stat["pass"] + stat["fail"] + stat["no_expect"]
    blind = stat["unreachable"] + stat["not_found"]
    testable = len(order) - len(skipped)
    inconclusive = False
    if testable > 0 and decided == 0:
        inconclusive = True
        log("")
        log("  ✗ 本次没有任何可判定结果(%d 个域名全部 UNREACHABLE/NOT_FOUND)。" % testable)
        log("    先查: Surge 是否在规则模式、代理端口 %d 对不对、/v1/requests/recent 有没有内容。"
            % proxy.port)
    elif testable and blind >= max(1, testable // 2):
        log("  ⚠ %d/%d 个域名没量到结果, 本次覆盖率偏低, 结论仅供参考。" % (blind, testable))

    # 会话级 same_policy 断言
    sess_rows = []
    for sc in scenarios:
        asserts = sc.get("assert", {}) if isinstance(sc.get("assert"), dict) else {}
        if not asserts.get("same_policy"):
            continue
        hosts = []
        for r in sc.get("requests", []):
            h = (r.get("host") or r.get("ip")) if isinstance(r, dict) else r
            # 只认这次真的测了、且在 recent 里找得到的请求
            if h and h in host_ctx and h in recent:
                hosts.append(h)
        if len(hosts) < 2:
            continue   # 只剩一个请求就谈不上「会话内是否分裂」, 不计入统计
        classes, groups = set(), set()
        for h in hosts:
            g, lf, _ = parse_policy_chain(recent[h])
            groups.add(g)
            classes.add(exit_class_of(g if g in EXIT_CLASS_EXACT else lf)[0])
        if len(classes) <= 1:
            sess_state = "PASS"
            stat["pass"] += 1
        else:
            sess_state = "FAIL(会话内出口分裂)"
            stat["fail"] += 1
        sess_rows.append([sc.get("name", "?"), len(hosts), " / ".join(sorted(groups))[:44],
                          " / ".join(sorted(classes)), sess_state])
    if sess_rows:
        log("")
        log("  会话内一致性 (same_policy):")
        log(render_table(["场景", "可判定请求数", "在线策略集合", "出口类集合", "结果"], sess_rows))

    result["scenario"] = {"stat": stat, "details": details,
                          "session_consistency": sess_rows,
                          "inconclusive": inconclusive}
    return 1 if (stat["fail"] or inconclusive) else 0


# ---------------------------------------------------------------------------
# 子命令 4: --exit-map
# ---------------------------------------------------------------------------

def parse_probe_ip(kind, body):
    """返回 (ip, asn)。asn 只有个别端点(fast.com v2)给得出, 拿不到就是空串。"""
    if not body:
        return (None, "")
    if kind == "cf_trace":
        m = re.search(r"^ip=(.+)$", body, re.M)
        return ((m.group(1).strip(), "") if m else (None, ""))
    if kind == "fast_json":
        try:
            data = json.loads(body)
        except ValueError:
            return (None, "")
        client = data.get("client") if isinstance(data, dict) else None
        if isinstance(client, dict):
            asn = str(client.get("asn") or "").lstrip("Aa Ss").strip()
            return (client.get("ip"), asn)
        return (None, "")
    # plain_ip / ipip: 抓第一个 IP 字面量
    m = IPV4_RE.search(body) or IPV6_RE.search(body)
    return ((m.group(0), "") if m else (None, ""))


def parse_proxy_servers(profile_text):
    """
    从配置文本的 [Proxy] 段取 {节点名: 服务器地址}。

    为什么有用: 本配置是 snell 级联(家宽节点用 underlying-proxy 指向落地机房中转),
    真正面向互联网的那一跳就是**该节点自己的 server 地址**。已用多组节点对照
    chatgpt.com / x.com 的 cdn-cgi/trace 与 api.fast.com 回显实测核对一致。
    所以对没有 IP 回显端点的策略组, 可以用「配置推导」补上出口 IP。
    (勿在本文件写入任何真实节点地址/名称举例 —— tests/ 随公开仓库发布。)
    注意这里只读服务器地址, 绝不读取/打印 psk 等敏感字段。
    """
    servers = {}
    in_proxy = False
    for line in profile_text.splitlines():
        s = line.strip()
        if s.startswith("["):
            in_proxy = s.lower().startswith("[proxy]")
            continue
        if not in_proxy or not s or s.startswith("#") or s.startswith(";") or "=" not in s:
            continue
        name, rest = s.split("=", 1)
        parts = [p.strip() for p in rest.split(",")]
        # 形如: <type>, <server>, <port>, ... → 第 2 个字段是服务器地址
        if len(parts) >= 2 and parts[1]:
            servers[name.strip()] = parts[1]
    return servers


def resolve_selected_chain(api, group, members, cache, depth=0):
    """按「当前选中项」递归展开 组 → … → 物理节点, 返回名字链。"""
    if group in cache:
        return cache[group]
    chain = [group]
    cur = group
    seen = {group}
    while depth < 8 and cur in members:
        try:
            sel = api.group_selected(cur)
            nxt = ""
            if isinstance(sel, dict):
                nxt = sel.get("policy") or sel.get("policyName") or sel.get("name") or ""
        except ApiError:
            nxt = ""
        if not nxt:
            nxt = members[cur][0] if members.get(cur) else ""
        if not nxt or nxt in seen:
            break
        chain.append(nxt)
        seen.add(nxt)
        cur = nxt
        depth += 1
    cache[group] = chain
    return chain


def rdap_lookup(proxy, ip, cache):
    """走 Surge(Final 组)查 RDAP, 拿 ASN/机构/网段名。失败不阻断。"""
    if ip in cache:
        return cache[ip]
    info = {"ip": ip, "asn": "", "org": "", "netname": "", "type": "", "error": ""}
    r = proxy.fetch("https://rdap.arin.net/registry/ip/%s" % urllib.parse.quote(ip),
                    method="GET", max_bytes=131072)
    if not r["ok"]:
        info["error"] = r["error"]
        cache[ip] = info
        return info
    try:
        data = json.loads(r["body"])
    except ValueError:
        info["error"] = "RDAP 响应非 JSON(HTTP %s)" % r["status"]
        cache[ip] = info
        return info

    info["netname"] = data.get("name", "") or ""
    info["type"] = data.get("type", "") or ""
    # ARIN RDAP 扩展: 起源 AS
    for key in ("arin_originas0_originautnums", "originautnums", "origin_autnums"):
        v = data.get(key)
        if isinstance(v, list) and v:
            info["asn"] = str(v[0])
            break
    # 机构名: entities → vcardArray → fn
    def walk_entities(ents):
        for ent in ents or []:
            if not isinstance(ent, dict):
                continue
            vcard = ent.get("vcardArray")
            if isinstance(vcard, list) and len(vcard) > 1 and isinstance(vcard[1], list):
                for item in vcard[1]:
                    if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
                        return str(item[3])
            sub = walk_entities(ent.get("entities"))
            if sub:
                return sub
        return ""
    info["org"] = walk_entities(data.get("entities")) or data.get("handle", "") or ""
    cache[ip] = info
    return info


def classify_exit(info, expected_map, group):
    """返回 (类型判断, 断言结论)。expected_asn.json 缺省时只报告不断言。"""
    blob = (" ".join([info.get("org", ""), info.get("netname", "")])).upper()
    guess = "未知"
    if any(h in blob for h in DATACENTER_HINTS):
        guess = "机房(疑似)"
    if any(h in blob for h in RESIDENTIAL_HINTS):
        guess = "住宅(疑似)"
    asn = str(info.get("asn") or "")
    if asn in KNOWN_ASN:
        note = KNOWN_ASN[asn]
        guess = ("住宅" if "住宅" in note else "机房") + "(ASN %s)" % asn
    verdict = "仅报告"
    exp = (expected_map or {}).get(group)
    if exp:
        allowed = [str(a) for a in (exp if isinstance(exp, list) else exp.get("asn", []))]
        if not asn:
            verdict = "无法断言(RDAP 未给出 ASN)"
        elif asn in allowed:
            verdict = "✓ 符合期望"
        else:
            verdict = "✗ 期望 ASN ∈ {%s}, 实际 %s" % (",".join(allowed), asn)
    return guess, verdict


def cmd_exit_map(api, proxy, log, result, expected_map):
    log.section("4. 出口画像 (组 → 出口 IP → ASN → 住宅/机房)")
    started = time.time()
    rows, entries, cache = [], [], {}
    fail = 0

    # 先从配置推导每个组的出口 IP(见 parse_proxy_servers 的说明), 用于:
    #   a) 补上没有 IP 回显端点的组;  b) 与实测值互相印证。
    servers, members, chain_cache = {}, {}, {}
    try:
        servers = parse_proxy_servers(api.profile_text())
        members = fetch_group_members(api)
    except ApiError as e:
        log("  (配置推导不可用: %s)" % e.detail)

    def derive(group):
        if not members:
            return "", ""
        chain = resolve_selected_chain(api, group, members, chain_cache)
        leaf = chain[-1] if chain else group
        if leaf in ("DIRECT", "REJECT"):
            return leaf, " → ".join(chain[1:]) or leaf
        return servers.get(leaf, ""), " → ".join(chain[1:]) or leaf

    for probe in EXIT_PROBES:
        group = probe["group"]
        ip, used_url, err, probe_asn = None, "", "", ""
        for url in probe["urls"]:
            r = proxy.fetch(url, method="GET", max_bytes=32768)
            if not r["ok"]:
                err = r["error"]
                continue
            got, got_asn = parse_probe_ip(probe["parser"], r["body"])
            if got:
                ip, used_url, err, probe_asn = got, url, "", got_asn
                break
            err = "HTTP %s 但未解析出 IP" % r["status"]
        if not ip and probe.get("route_probe"):
            proxy.fetch(probe["route_probe"], method="HEAD", max_bytes=512)  # 只为留下 recent 记录

        derived_ip, chain_txt = derive(group)
        target_ip = ip or (derived_ip if IPV4_RE.match(derived_ip or "") else None)

        if not target_ip:
            note = "无回显端点, 配置也推导不出 IP" if not probe["urls"] else \
                   ("UNREACHABLE: %s" % (err or "无响应"))
            rows.append([group, chain_txt or "-", "-", derived_ip or "-", "-", "-", "-", note[:34]])
            entries.append({"group": group, "chain": chain_txt, "derived_ip": derived_ip,
                            "measured_ip": None, "error": err or "no echo endpoint"})
            continue

        if group == "DIRECT":
            info = {"ip": target_ip, "asn": "", "org": "(本地出口, 未查 RDAP)",
                    "netname": "", "error": ""}
        else:
            # dict(...) 复制一份: rdap_lookup 返回的是缓存里的对象, 就地改会污染同 IP 的其它组
            info = dict(rdap_lookup(proxy, target_ip, cache))
        if not info.get("asn") and probe_asn:
            info["asn"] = probe_asn          # fast.com v2 自带 ASN, 补 RDAP 的空
        guess, verdict = classify_exit(info, expected_map, group)
        if verdict.startswith("✗"):
            fail += 1

        asn_txt = info.get("asn") or "-"
        if asn_txt in KNOWN_ASN:
            asn_txt = "%s(%s)" % (asn_txt, KNOWN_ASN[asn_txt].split("(")[0].strip())
        org_txt = info.get("org") or ""
        net_txt = info.get("netname") or ""
        # 机构名常是 "Private Customer" 这类占位, 此时网段名(如 EXAMPLE-NET-…)才是有效信息
        who = net_txt if (not org_txt or org_txt.lower().startswith("private")) and net_txt else org_txt
        # 只有「两边都是 IP 字面量」才谈得上一致性; DIRECT 的推导值是 "DIRECT" 不参与比较
        comparable = bool(ip) and bool(IPV4_RE.match(derived_ip or "") or IPV6_RE.match(derived_ip or ""))
        if comparable and ip != derived_ip:
            match = "✗ 实测≠推导"
        elif comparable:
            match = "✓ 一致"
        elif ip:
            match = "仅实测"
        else:
            match = "仅推导"

        rows.append([group, chain_txt or "-", ip or "-", derived_ip or "-",
                     asn_txt, (who or "-")[:26], guess, "%s / %s" % (match, verdict)])
        entries.append({"group": group, "chain": chain_txt, "measured_ip": ip,
                        "derived_ip": derived_ip, "probe_url": used_url,
                        "asn": info.get("asn"), "org": org_txt, "netname": net_txt,
                        "guess": guess, "consistency": match, "verdict": verdict,
                        "rdap_error": info.get("error")})

    log(render_table(["策略组", "选中链路", "实测出口 IP", "推导出口 IP", "ASN", "机构/网段",
                      "类型判断", "一致性 / 断言"], rows))
    log("")

    # 用 recent requests 反查这些探针实际走了哪个策略, 交叉验证「探针确实落在目标组」
    try:
        recent = collect_recent(api, since_epoch=started)
        xrows = []
        for probe in EXIT_PROBES:
            urls = list(probe["urls"])
            if probe.get("route_probe"):
                urls.append(probe["route_probe"])
            for url in urls:
                h = host_of_url(url)
                rec = recent.get(h)
                if rec is None:
                    continue
                g, leaf, rule = parse_policy_chain(rec)
                mark = "✓" if (g == probe["group"] or leaf == probe["group"]
                               or exit_class_of(probe["group"])[0] ==
                               exit_class_of(g if g in EXIT_CLASS_EXACT else leaf)[0]) else "⚠ 探针未落在目标组"
                xrows.append([probe["group"], h, "%s→%s" % (g, leaf) if g != leaf else g,
                              (rule or "")[:30], mark])
        if xrows:
            log("  探针归属交叉验证 (确认量到的确实是该组的出口):")
            log(render_table(["目标组", "探针域名", "实际策略", "命中规则", "结论"], xrows))
            log("")
    except ApiError as e:
        log("  (交叉验证跳过: %s)" % e.detail)

    if not expected_map:
        log("  说明: 未找到 expected_asn.json, 本节只报告不断言。")
        log("        如需断言, 在 tests/ 下创建 expected_asn.json, 形如:")
        log('        {"AI": ["64500"], "Google-X-Meta-MS": ["64501"], "社交媒体": ["64502"]}')
    log("  说明: 出口链路是 snell 级联(家宽节点用 underlying-proxy 经落地机房中转),")
    log("        真正面向互联网的是家宽节点自身的 server 地址, 所以「推导出口 IP」取的就是它;")
    log("        实测与推导一致 = 链路正常; 不一致 = 链路降级/被中转商改写, 需要人工看一眼。")
    log("  说明: ARIN RDAP 对家宽客户网段常常不返回 ASN(originAS 为空)、机构写成 Private Customer,")
    log("        此时以「网段名」(如 <ISP>-NET-<段号>)判断归属, ASN 列为空不代表异常。")
    result["exit_map"] = {"entries": entries, "assert_failures": fail}
    return 1 if fail else 0


# ---------------------------------------------------------------------------
# 子命令 5: --dns-leak
# ---------------------------------------------------------------------------

def extract_dns_domains(data):
    """从 /v1/dns 响应里抽出本地已解析的域名集合(兼容多种字段命名)。"""
    domains = set()

    def eat(items):
        for it in items or []:
            if isinstance(it, dict):
                for k in ("domain", "domainName", "host", "name"):
                    v = it.get(k)
                    if isinstance(v, str) and v:
                        domains.add(v.lower().rstrip("."))
                        break
            elif isinstance(it, str):
                domains.add(it.lower().rstrip("."))

    if isinstance(data, dict):
        for k in ("dnsCache", "local", "records", "entries", "dns"):
            v = data.get(k)
            if isinstance(v, list):
                eat(v)
            elif isinstance(v, dict):
                for sub in v.values():
                    if isinstance(sub, list):
                        eat(sub)
    elif isinstance(data, list):
        eat(data)
    return domains


def is_private_ip(text):
    """内网/回环/链路本地地址 —— 在线层不实测它们(没有意义, 离线层已覆盖)。"""
    if not text or not IPV4_RE.match(text):
        return False
    try:
        a, b = [int(x) for x in text.split(".")[:2]]
    except ValueError:
        return False
    return (a == 10 or a == 127 or (a == 172 and 16 <= b <= 31)
            or (a == 192 and b == 168) or (a == 169 and b == 254) or a == 0)


def host_covered(host, resolved):
    """host 或其上级域出现在本地 DNS 缓存里都算被本地解析过。"""
    h = host.lower().rstrip(".")
    if h in resolved:
        return h
    for d in resolved:
        if h == d or h.endswith("." + d) or d.endswith("." + h):
            return d
    return None


def cmd_dns_leak(api, proxy, scen_dir, log, result, do_flush=True):
    log.section("5. DNS 泄漏实测 (本地 DNS 缓存实锤)")

    proxy_hosts, direct_hosts, src = [], [], ""
    scenarios, _ = load_scenarios(os.path.join(scen_dir, "dns_leak.json"), scen_dir, log)
    if scenarios:
        src = "scenarios/dns_leak.json"
        for sc in scenarios:
            asserts = sc.get("assert", {}) if isinstance(sc.get("assert"), dict) else {}
            want_no_leak = asserts.get("no_dns_leak")
            pol = asserts.get("policy")
            for r in sc.get("requests", []):
                h = r.get("host") if isinstance(r, dict) else r
                if not h:
                    continue
                if pol == "DIRECT" or want_no_leak is False:
                    direct_hosts.append(h)
                else:
                    proxy_hosts.append(h)
    if not proxy_hosts:
        src = "内置兜底样本(scenarios/dns_leak.json 不存在)"
        proxy_hosts = list(FALLBACK_PROXY_HOSTS)
        direct_hosts = list(FALLBACK_DIRECT_HOSTS)

    proxy_hosts = list(dict.fromkeys(proxy_hosts))
    direct_hosts = list(dict.fromkeys(direct_hosts))
    log("  样本来源: %s" % src)
    log("  代理域名 %d 个(断言不得出现在本地 DNS) / 直连域名 %d 个(断言应出现)"
        % (len(proxy_hosts), len(direct_hosts)))

    if do_flush:
        try:
            api.flush_dns()
            log("  ✓ 已 POST /v1/dns/flush 清空本地 DNS 缓存(本程序唯一的写操作)。")
        except ApiError as e:
            log("  ⚠ flush 失败(%s), 继续测试, 但历史缓存可能造成误报。" % e.detail)
    else:
        log("  (--no-flush: 跳过清缓存, 历史记录可能造成误报)")

    baseline = set()
    try:
        baseline = extract_dns_domains(api.dns_records())
    except ApiError as e:
        log("  ⚠ flush 后读取基线失败: %s" % e.detail)
    if baseline:
        log("  flush 后残留 %d 条本地 DNS 记录, 已作为基线排除。" % len(baseline))

    for h in proxy_hosts + direct_hosts:
        proxy.touch(h)
    time.sleep(1.0)

    try:
        resolved = extract_dns_domains(api.dns_records())
    except ApiError as e:
        log("  [错误] 读取 /v1/dns 失败: %s" % e.detail)
        result["dns_leak"] = {"error": e.detail}
        return 1

    new_resolved = set(resolved) - set(baseline)
    rows, leaks, suspect, entries = [], 0, 0, []
    for h in proxy_hosts:
        hit = host_covered(h, new_resolved)
        if hit:
            rows.append([h, "代理", "★ 本地已解析(%s)" % hit, "P1 泄漏"])
            leaks += 1
            entries.append({"host": h, "kind": "proxy", "leaked": True, "matched": hit})
            continue
        # flush 没清干净时不能简单判「干净」, 否则是静默漏报 —— 单列出来让人复核
        old = host_covered(h, set(baseline))
        if old:
            rows.append([h, "代理", "flush 前既有记录(%s)" % old, "? 无法判定"])
            suspect += 1
            entries.append({"host": h, "kind": "proxy", "leaked": None, "matched": old,
                            "note": "pre-existing cache entry"})
        else:
            rows.append([h, "代理", "未本地解析", "✓"])
            entries.append({"host": h, "kind": "proxy", "leaked": False})
    missing = 0
    for h in direct_hosts:
        hit = host_covered(h, new_resolved)
        if hit:
            rows.append([h, "直连", "本地已解析(%s)" % hit, "✓ 预期"])
            entries.append({"host": h, "kind": "direct", "resolved": True})
        else:
            rows.append([h, "直连", "未出现在本地 DNS", "? 待查"])
            missing += 1
            entries.append({"host": h, "kind": "direct", "resolved": False})

    log("")
    log(render_table(["域名", "期望路径", "本地 DNS 状态", "结论"], rows))
    log("")
    if leaks:
        log("  ✗ 检出 %d 个代理域名被本地 DNS 解析 —— 对应 audit A1(no-resolve 缺失)的实锤证据。" % leaks)
        log("    复核步骤: 用 engine.py match <域名> 看 dns_leak_at 指向哪条 IP 规则。")
    else:
        log("  ✓ 未检出代理域名的本地 DNS 解析。")
    if suspect:
        log("  ? %d 个代理域名在 flush 之前就有本地 DNS 记录, 本次无法判定(既不算通过也不算泄漏)。"
            % suspect)
        log("    多半是 flush 没生效或别的进程抢先解析了; 隔一会儿重跑一次即可。")
    if missing:
        log("  注: %d 个直连域名没出现在本地 DNS —— 常见原因是系统/浏览器缓存命中或走了 DoH,"
            % missing)
        log("      不等于分流错误。")
    log("  注意: 本地 DNS 缓存是全机共享的, 其它 App(浏览器 DoH 旁路、Spotlight、后台服务)")
    log("        也会往里写记录, 所以本项必须在 flush 之后立即跑, 否则易误报。")

    result["dns_leak"] = {"source": src, "leaks": leaks, "undecidable": suspect,
                          "direct_missing": missing, "entries": entries}
    return 1 if leaks else 0


# ---------------------------------------------------------------------------
# 子命令 1: --check-api
# ---------------------------------------------------------------------------

def cmd_check_api(api, log, result):
    log.section("1. Surge HTTP API 可用性探测")
    log("  目标: %s   X-Key: %s" % (api.base, "(已提供)" if api.key else "(空!)"))
    try:
        outbound = api.outbound()
    except ApiError as e:
        log("  ✗ 探测失败 [%s] %s" % (e.kind, e.detail))
        log("")
        log(API_GUIDE)
        result["check_api"] = {"ok": False, "kind": e.kind, "detail": e.detail}
        return 2

    mode = ""
    if isinstance(outbound, dict):
        mode = outbound.get("mode") or outbound.get("outbound") or json.dumps(outbound, ensure_ascii=False)[:40]
    log("  ✓ /v1/outbound 可用, 当前出站模式: %s" % mode)

    checks = [("/v1/policy_groups", api.policy_groups),
              ("/v1/requests/recent", api.recent_requests),
              ("/v1/dns", api.dns_records)]
    rows = [["/v1/outbound", "OK", str(mode)[:40]]]
    ok_all = True
    for path, fn in checks:
        try:
            data = fn()
            size = len(data) if isinstance(data, (list, dict)) else 0
            rows.append([path, "OK", "%d 个顶层字段/条目" % size])
        except ApiError as e:
            ok_all = False
            rows.append([path, "FAIL", "[%s] %s" % (e.kind, e.detail[:44])])
    log("")
    log(render_table(["端点", "状态", "备注"], rows))
    if mode and mode != "rule":
        log("")
        log("  ⚠ 出站模式不是 rule(当前 %s) —— 全局直连/全局代理下所有分流断言都不成立," % mode)
        log("    请在 Surge 里切回「规则模式」再跑其它子命令。")
    result["check_api"] = {"ok": ok_all, "mode": mode,
                           "endpoints": [{"path": r[0], "status": r[1]} for r in rows]}
    return 0 if ok_all else 1


# ---------------------------------------------------------------------------
# 报告输出
# ---------------------------------------------------------------------------

def write_report(path, log, result):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    body = ["# Surge 分流在线实测报告 (live_check.py v%s)" % VERSION,
            "",
            "- 生成时间: %s" % ts,
            "- 生成方式: `python3 live_check.py --full`",
            "- 判定原则: **在线为准**。与离线引擎冲突处按在线结论修 engine.py 或规则。",
            "",
            "## 控制台输出",
            "",
            "```"]
    body.extend(log.lines)
    body.append("```")
    body.append("")
    body.append("## 机器可读结果")
    body.append("")
    body.append("```json")
    body.append(json.dumps(result, ensure_ascii=False, indent=2))
    body.append("```")
    try:
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
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
        prog="live_check.py",
        description="Surge 分流测试套件 L3 在线实测层(需要 Surge HTTP API)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""示例:
  python3 live_check.py --check-api                 # 先确认 API 通不通
  python3 live_check.py --policies                  # 策略组选中项 vs 引擎假设
  python3 live_check.py --scenario all              # 全场景在线实测
  python3 live_check.py --scenario ai_overseas.json # 只跑一个场景文件
  python3 live_check.py --exit-map                  # 出口 IP / ASN 画像
  python3 live_check.py --dns-leak                  # DNS 泄漏实锤
  python3 live_check.py --full --report live_report.md

退出码: 0 通过 / 1 有失败 / 2 API 不可用 / 3 用法或环境错误""")
    p.add_argument("--check-api", action="store_true", help="探测 HTTP API 可用性, 不可用时打印开启指引并退出 2")
    p.add_argument("--policies", action="store_true", help="列出各策略组当前选中项并与引擎假设(成员首项)对比")
    p.add_argument("--scenario", metavar="FILE|all", nargs="?", const="all",
                   help="对场景中的域名发真实请求并与在线记录/离线引擎对比")
    p.add_argument("--exit-map", action="store_true", help="出口画像: 组 → 出口 IP → ASN → 住宅/机房")
    p.add_argument("--dns-leak", action="store_true", help="flush 本地 DNS 后实测代理域名是否被本地解析")
    p.add_argument("--full", action="store_true", help="顺序执行 policies → scenario all → exit-map → dns-leak 并生成报告")

    p.add_argument("--api", default=os.environ.get("SURGE_API", "http://127.0.0.1:6171"),
                   help="Surge HTTP API 地址 (默认 http://127.0.0.1:6171, 或环境变量 SURGE_API)")
    p.add_argument("--key", default=os.environ.get("SURGE_API_KEY", ""),
                   help="API Key (优先取环境变量 SURGE_API_KEY, 避免写进命令行历史)")
    p.add_argument("--proxy-port", type=int, default=None, help="Surge HTTP 代理端口 (默认自动探测, 常见 6152)")
    p.add_argument("--tests-dir", default=SELF_DIR, help="tests/ 目录 (用于定位 engine.py / scenarios / expected_asn.json)")
    p.add_argument("--scenarios-dir", default=None, help="场景目录 (默认 <tests-dir>/scenarios)")
    p.add_argument("--conf", default=None, help="传给 engine.py 的 Surge.conf 路径")
    p.add_argument("--hosts", default=None, help="逗号分隔的临时域名清单, 无场景文件时也能跑 --scenario")
    p.add_argument("--timeout", type=float, default=8.0, help="单请求超时秒数 (默认 8)")
    p.add_argument("--rate", type=float, default=3.0, help="每秒最大请求数 (默认 3)")
    p.add_argument("--no-flush", action="store_true", help="--dns-leak 时不清 DNS 缓存(全程零写操作)")
    p.add_argument("--insecure", action="store_true", help="跳过 TLS 证书校验(仅排障用, 会掩盖 MITM 问题)")
    p.add_argument("--report", default=None, help="报告输出路径 (默认 ./live_report.md, 仅 --full)")
    p.add_argument("--dump-raw", default=None, help="把 API 原始响应存到该目录, 用于排查字段名差异")
    p.add_argument("--json", action="store_true", help="stdout 只输出机器可读 JSON")
    p.add_argument("--version", action="version", version="live_check.py " + VERSION)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    want_any = any([args.check_api, args.policies, args.scenario, args.exit_map,
                    args.dns_leak, args.full])
    if not want_any:
        build_parser().print_help()
        sys.stderr.write("\n错误: 至少指定一个动作 (--check-api / --policies / --scenario / "
                         "--exit-map / --dns-leak / --full)\n")
        return 3

    log = Log(quiet=args.json)
    result = {"version": VERSION, "time": datetime.now().isoformat(timespec="seconds"),
              "api": args.api}

    log("Surge 分流在线实测 live_check.py v%s" % VERSION)
    log("时间: %s" % result["time"])

    api = SurgeAPI(args.api, args.key, timeout=args.timeout, dump_dir=args.dump_raw)

    # 任何动作都先做一次 API 探测: API 不通就没有「在线为准」可言。
    rc = cmd_check_api(api, log, result)
    if rc == 2:
        if args.json:
            print(json.dumps(result, ensure_ascii=False, indent=2))
        return 2
    exit_code = 0 if rc == 0 else 1
    if args.check_api and not (args.policies or args.scenario or args.exit_map
                               or args.dns_leak or args.full):
        if args.json:
            print(json.dumps(result, ensure_ascii=False, indent=2))
        return exit_code

    if not args.key:
        log("")
        log("  ⚠ 未提供 API Key(SURGE_API_KEY / --key)。若 API 配了 Key, 后续调用会 401。")

    scen_dir = args.scenarios_dir or os.path.join(args.tests_dir, "scenarios")
    port, how = detect_proxy_port(api, args.proxy_port, log)
    log("")
    log("  Surge HTTP 代理端口: %d (来源: %s)" % (port, how))
    proxy = ProxyClient(port, timeout=args.timeout, rate=args.rate, insecure=args.insecure)
    result["proxy_port"] = port

    engine = EngineBridge(args.tests_dir, conf=args.conf)
    log("  离线引擎: %s" % ("engine.py 可用 [%s]" % engine.mode if engine.available
                        else "不可用(%s) → 仅在线结论" % engine.reason))

    expected_map = None
    exp_path = os.path.join(args.tests_dir, "expected_asn.json")
    if os.path.isfile(exp_path):
        try:
            with open(exp_path, "r", encoding="utf-8") as f:
                expected_map = json.load(f)
            log("  出口断言表: expected_asn.json (%d 组)" % len(expected_map))
        except (OSError, ValueError) as e:
            log("  ⚠ expected_asn.json 解析失败, 忽略: %s" % e)

    run_policies = args.policies or args.full
    run_scenario = bool(args.scenario) or args.full
    run_exit = args.exit_map or args.full
    run_dns = args.dns_leak or args.full

    if run_policies:
        exit_code |= cmd_policies(api, log, result)

    if run_scenario:
        target = args.scenario if args.scenario else "all"
        scenarios, errs = load_scenarios(target, scen_dir, log)
        for e in errs:
            log("  ⚠ %s" % e)
        limit_hosts = None
        if args.hosts:
            hosts = [h.strip() for h in args.hosts.split(",") if h.strip()]
            if scenarios:
                limit_hosts = set(hosts)
            else:
                scenarios = [{"name": "ad-hoc(--hosts)", "_file": "-",
                              "requests": [{"host": h} for h in hosts], "assert": {}}]
        if not scenarios and not os.path.isdir(scen_dir):
            log("")
            log("  [提示] 场景目录不存在: %s" % scen_dir)
            log("         scenarios/*.json 由 runsuite 层(W7)提供; 也可用 --hosts 临时指定域名。")
        exit_code |= cmd_scenario(api, proxy, engine, scenarios, log, result, limit_hosts)

    if run_exit:
        exit_code |= cmd_exit_map(api, proxy, log, result, expected_map)

    if run_dns:
        exit_code |= cmd_dns_leak(api, proxy, scen_dir, log, result, do_flush=not args.no_flush)

    log.section("总结")
    log("  退出码: %d (%s)" % (exit_code, "全部通过" if exit_code == 0 else "存在失败项, 详见上表"))
    result["exit_code"] = exit_code

    if args.full or args.report:
        path = args.report or os.path.join(os.getcwd(), "live_report.md")
        if write_report(path, log, result):
            msg = "  报告已写入: %s" % path
            log.lines.append(msg)
            if not args.json:
                print(msg)

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    return exit_code


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.stderr.write("\n已中断。\n")
        sys.exit(3)
