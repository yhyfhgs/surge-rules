#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
runsuite.py — L2 场景断言运行器（Surge 分流测试套件 / W7）

加载 scenarios/*.json 全量场景，逐条请求调用 L0 引擎 engine.py 判定，
按文件分组输出 pass / fail / known_broken 统计表与失败明细。

依赖：python3 标准库 only；同目录的 engine.py（W6 交付）。

用法：
    python3 runsuite.py                       # 跑全部场景，人读输出
    python3 runsuite.py --filter openai       # 只跑名字/文件名含 openai 的场景
    python3 runsuite.py --json                # 机器可读输出
    python3 runsuite.py --conf /path/Surge.conf --dir scenarios --engine ./engine.py
    python3 runsuite.py --conf tests/fixtures/Surge.test.conf --rules lists/
                                              # 脱敏 fixture + 显式 .list 目录（CI 用）
    python3 runsuite.py --list-known-broken   # 只列当前的待修清单
    python3 runsuite.py --allow-known-broken  # 放行 known_broken（默认严格：>0 即退出码 1）

退出码：0=无失败且无 known_broken；1=有失败断言，或存在 known_broken 而未加
       --allow-known-broken；2=引擎不可用/场景文件损坏/schema 校验不通过。

--------------------------------------------------------------------------
场景 JSON schema（与 spec/testkit.md 一致，known_broken 为其定义的机制）
--------------------------------------------------------------------------
[
  {
    "name": "openai_chatgpt_web",
    "desc": "一句话说明这是哪个真实用户行为",
    "requests": [
      {"host": "chatgpt.com"},                     # 域名查询
      {"host": "api.openai.com", "process": "ChatGPT"},   # 带进程
      {"ip": "8.8.8.8"},                           # 纯 IP 查询
      {"ua": "YouTube/17.38.10"},                  # 纯 UA 查询
      {"host": "x.com", "note": "任意人读注释，不参与断言"}
    ],
    "assert": {
      "same_policy": true,        # 会话内（未被 per_request 覆盖的）请求同一策略组
      "policy": "AI",             # 期望策略组名
      "policy_in": ["AI","Final"],# 或：允许多组之一（与 policy 二选一）
      "no_dns_leak": true,        # 匹配路径上不得有缺 no-resolve 的 IP 类规则
      "per_request": [            # 个别请求单独期望；按完整查询元组精确匹配
        {"host": "discord.com", "policy": "社交媒体"},
        {"host": "sentry.io", "policy": "Final",
         "known_broken": true, "reason": "现状 AI，KEYWORD 误伤"}
      ]
    },
    "known_broken": true,         # 整场景的策略类断言记为「已知待修」，不计失败
    "reason": "为什么现在是坏的 + 怎么修"
  }
]

约定：
* per_request 条目按 (host, ip, process, ua) 完整元组精确匹配请求，因此同一
  host 的不同 process 变体可以各自给期望，互不误伤。
* 被 per_request 覆盖的请求不参与 same_policy 分组判定（它们本来就被声明为不同）。
* 场景级 known_broken 只作用于「策略类」断言（policy / policy_in /
  same_policy / per_request 策略），不作用于 no_dns_leak——DNS 泄漏是独立的
  安全轴，任何时候泄漏都必须是硬失败。
* no_dns_leak 字段缺省即不断言（如国内直连域名，本地解析是期望行为）。
* 数据集自检：写了却匹配不到任何请求的 per_request 条目会报 per_request.orphan
  失败（防止 host 拼错或漏写 process 导致断言静默失效）。

--------------------------------------------------------------------------
加载期 schema 严格校验（审计 P1-10 / §12.2）
--------------------------------------------------------------------------
场景不是「静默跳过」而是「加载失败并指名道姓」。任一场景违规 → 整个套件拒绝
运行、退出码 2。规则：

  1. name 全局唯一（跨文件），且为非空字符串；
  2. requests 非空，每项含合法 host 或 ip（host 至少两级标签、无 scheme/端口/
     路径/通配符；ip 必须能被 ipaddress 解析且不能是 CIDR）；
  3. assert 至少有一项有效断言（policy / policy_in / same_policy:true /
     no_dns_leak:true / 非空 per_request）——注意 same_policy:false 是说明性
     字段，本身不构成断言；
  4. policy 与 policy_in 互斥（assert 级与 per_request 条目级都查）；
  5. per_request 的 (host,ip,process,ua) 键唯一，且每条都必须对上 requests 里
     的某个请求（撞键会静默覆盖、孤儿条目会静默失效，两者都拒绝）；
  6. 场景级 / request 级 / assert 级 / per_request 级出现白名单外的键即报错，
     报错信息里列出该层的完整白名单；
  7. same_policy:true 时，未被 per_request 覆盖的请求必须 ≥ 2 个——空集合或单
     请求的「同组」断言没有信息量，是典型假绿。

历史遗留：LEGACY_EMPTY_REQUESTS 里登记的场景暂免第 2 条的「非空」检查，运行时
打印醒目告警而非报错（详见该常量注释）。豁免登记若失效会提示删除。
"""

import argparse
import ipaddress
import json
import os
import subprocess
import sys
import unicodedata

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_SCEN_DIR = os.path.join(HERE, "scenarios")
DEFAULT_ENGINE = os.path.join(HERE, "engine.py")

QUERY_KEYS = ("host", "ip", "process", "ua")

# -- schema 白名单：出现白名单外的键 = 加载失败（打错字不再被静默忽略）--------
SCENARIO_KEYS = ("assert", "desc", "known_broken", "name", "note", "reason", "requests")
REQUEST_KEYS = ("host", "ip", "note", "process", "ua")
ASSERT_KEYS = ("no_dns_leak", "per_request", "policy", "policy_in", "same_policy")
PERREQ_KEYS = ("host", "ip", "known_broken", "note", "policy", "policy_in",
               "process", "reason", "ua")

# -- 历史遗留豁免（仅豁免「requests 非空」一条，且只对这些具名场景生效）------
# 这两个场景原本完全建立在 PROCESS-NAME 请求上；commit 0fa4a24「全库移除 96 条
# PROCESS-NAME 与 155 条 USER-AGENT」把它们的 requests 掏空成 []，留下产出 0 条
# 断言却照样「通过」的空壳——正是 P1-10 点名的假绿空洞本体。
# runsuite 不拥有 scenarios/ 下的文件，故此处以具名豁免让闸门保持可跑，同时每次
# 运行都打印告警。正确的了结方式是补齐请求或整条删除，然后删掉这里的登记。
LEGACY_EMPTY_REQUESTS = {}  # 2026-08-31 两个空场景已重建为域名版，豁免清空；加回时按 {场景名: 成因说明} 登记


# --------------------------------------------------------------------------
# 引擎适配层：只依赖 spec/testkit.md 定义的 engine 接口
#   1) 模块级函数     engine.match(host=..., ip=..., process=..., ua=...)
#   2) 引擎实例       engine.build_engine(conf).match(...) / engine.Engine(conf).match(...)
#   3) 退化到 CLI     engine.py match <host> [--ip I] [--process P] [--ua U] --json
# 三者返回同一份 spec 定义的结果 JSON，runsuite 只读其中的
# policy / matched_rule / source / physical_exit / exit_class / dns_leak(_at)。
# --------------------------------------------------------------------------
class EngineError(Exception):
    pass


class Engine(object):
    def __init__(self, path, conf=None, rules=None):
        self.path = path
        self.conf = conf
        self.rules = rules        # .list 目录；None = 让引擎按 conf 位置自行推导
        self.mode = None          # "module" | "instance" | "cli"
        self._mod = None
        self._inst = None
        self._cache = {}
        self._load()

    def _load(self):
        if not os.path.exists(self.path):
            raise EngineError("找不到引擎文件：%s\n"
                              "runsuite 依赖 W6 交付的 engine.py（同目录），"
                              "或用 --engine 指定路径。" % self.path)
        try:
            import importlib.util
            spec = importlib.util.spec_from_file_location("surge_engine", self.path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            self._mod = mod
        except Exception as e:                                  # noqa: BLE001
            sys.stderr.write("[warn] 以 Python 模块导入 engine.py 失败（%s），"
                             "退化为 CLI 调用。\n" % e)
            self._mod = None
        m = self._mod
        if m is not None and callable(getattr(m, "match", None)):
            self.mode = "module"
            return
        # 引擎实例形态：build_engine(conf) 或 Engine(conf)
        for maker in ("build_engine", "Engine"):
            fn = getattr(m, maker, None) if m is not None else None
            if fn is None:
                continue
            # 给了 --rules 就只试「带 rules 的构造」：宁可退化成 CLI 模式（那条路
            # 一定会传 --rules），也不能静默丢掉它去读默认 lists/ —— 那会让整套断言
            # 跑在错误的规则目录上却全绿。
            if self.rules:
                cands = ((lambda: fn(self.conf, self.rules)),)
            else:
                cands = (((lambda: fn(self.conf)) if self.conf else (lambda: fn())),
                         (lambda: fn()))
            for call in cands:
                try:
                    inst = call()
                except Exception:                               # noqa: BLE001
                    continue
                if callable(getattr(inst, "match", None)):
                    self._inst = inst
                    self.mode = "instance"
                    return
        self.mode = "cli"

    # -- 统一入口 ---------------------------------------------------------
    def query(self, q):
        key = tuple(q.get(k) for k in QUERY_KEYS)
        if key in self._cache:
            return self._cache[key]
        if self.mode == "module":
            res = self._query_python(q)
        elif self.mode == "instance":
            res = self._query_instance(q)
        else:
            res = self._query_cli(q)
        res = self._normalize(res)
        self._cache[key] = res
        return res

    def _query_instance(self, q):
        try:
            return self._inst.match(**{k: q.get(k) for k in QUERY_KEYS})
        except TypeError:
            return self._inst.match(q.get("host") or q.get("ip"))
        except Exception as e:                                  # noqa: BLE001
            raise EngineError("调用 engine 实例 match 失败（query=%r）：%s" % (q, e))

    def _query_python(self, q):
        kw = {k: q.get(k) for k in QUERY_KEYS}
        if self.conf:
            for name in ("conf", "conf_path"):
                try:
                    return self._mod.match(**dict(kw, **{name: self.conf}))
                except TypeError:
                    continue
        try:
            return self._mod.match(**kw)
        except TypeError:
            pass
        # 引擎可能只接受位置参数 match(host, ...)
        try:
            return self._mod.match(q.get("host") or q.get("ip"))
        except Exception as e:                                  # noqa: BLE001
            raise EngineError("调用 engine.match 失败（query=%r）：%s" % (q, e))

    def _query_cli(self, q):
        target = q.get("host") or q.get("ip") or ""
        cmd = [sys.executable, self.path, "match", target, "--json"]
        if q.get("ip") and not q.get("host"):
            pass                       # 纯 IP 直接作为位置参数传入
        elif q.get("ip"):
            cmd += ["--ip", q["ip"]]
        if q.get("process"):
            cmd += ["--process", q["process"]]
        if q.get("ua"):
            cmd += ["--ua", q["ua"]]
        if self.conf:
            cmd += ["--conf", self.conf]
        if self.rules:
            cmd += ["--rules", self.rules]
        try:
            out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL)
        except Exception as e:                                  # noqa: BLE001
            raise EngineError("调用 engine.py CLI 失败（query=%r）：%s" % (q, e))
        try:
            return json.loads(out.decode("utf-8"))
        except Exception as e:                                  # noqa: BLE001
            raise EngineError("engine.py --json 输出不是合法 JSON：%s" % e)

    @staticmethod
    def _normalize(res):
        if not isinstance(res, dict):
            raise EngineError("engine 返回值不是 dict：%r" % (res,))
        return {
            "policy": res.get("policy"),
            "matched_rule": res.get("matched_rule"),
            "rule_index": res.get("rule_index"),
            "source": res.get("source"),
            "physical_exit": res.get("physical_exit"),
            "exit_class": res.get("exit_class"),
            "dns_leak": bool(res.get("dns_leak")),
            "dns_leak_at": res.get("dns_leak_at"),
        }


# --------------------------------------------------------------------------
# 断言执行
# --------------------------------------------------------------------------
def qkey(d):
    return tuple(d.get(k) for k in QUERY_KEYS)


def qlabel(q):
    bits = []
    if q.get("host"):
        bits.append(q["host"])
    if q.get("ip"):
        bits.append("ip=" + q["ip"])
    if q.get("process"):
        bits.append("proc=" + q["process"])
    if q.get("ua"):
        bits.append("ua=" + q["ua"])
    return " ".join(bits) or "<空查询>"


# --------------------------------------------------------------------------
# 加载期 schema 严格校验（P1-10 / §12.2）
# 违规 = 加载失败并指名道姓（文件[下标] «场景名» 层级[下标]：原因），不静默跳过。
# --------------------------------------------------------------------------
# host 里不该出现的东西：空白、scheme/路径分隔、端口冒号、查询串、通配符、引号等。
_HOST_BAD_CHARS = set(" \t\r\n\f\v/\\:?#@*%&=+,;'\"()[]{}<>|^`~!$")


def check_host(h):
    """合法返回 None，否则返回中文错误说明。IP 字面量作 host 合法（HTTPDNS 场景）。"""
    if not isinstance(h, str) or not h:
        return "host 必须是非空字符串"
    if len(h) > 253:
        return "host 长度 %d 超过 253 字符上限" % len(h)
    bad = sorted(set(c for c in h if c in _HOST_BAD_CHARS or ord(c) < 33))
    if bad:
        return ("host %r 含非法字符 %r——只写主机名，不要带 scheme、端口、路径或通配符"
                % (h, "".join(bad)))
    labels = (h[:-1] if h.endswith(".") else h).split(".")
    if len(labels) < 2:
        return "host %r 只有一级标签，至少要两级（形如 example.com）" % h
    for lb in labels:
        if not lb:
            return "host %r 含空标签（连续点或以点开头）" % h
        if len(lb) > 63:
            return "host %r 的标签 %r 超过 63 字符" % (h, lb)
        if lb.startswith("-") or lb.endswith("-"):
            return "host %r 的标签 %r 不能以连字符开头或结尾" % (h, lb)
    return None


def check_ip(v):
    """合法返回 None，否则返回中文错误说明。"""
    if not isinstance(v, str) or not v:
        return "ip 必须是非空字符串"
    if "/" in v:
        return "ip %r 是 CIDR；此处只能写单个地址（网段断言请用规则层）" % v
    try:
        ipaddress.ip_address(v)
    except ValueError:
        return "ip %r 不是合法的 IPv4/IPv6 地址" % v
    return None


def _unknown_keys(obj, allowed, layer, tag, errors):
    extra = sorted(k for k in obj if k not in allowed)
    if extra:
        errors.append("%s：%s 出现未知键 %s；本层允许的键为 {%s}"
                      % (tag, layer, ", ".join(repr(k) for k in extra),
                         ", ".join(allowed)))


def _check_target(d, tag, errors):
    """校验一个「查询目标」（request 或 per_request 条目）的 host/ip/process/ua。"""
    n0 = len(errors)
    ok = False
    for key, fn in (("host", check_host), ("ip", check_ip)):
        if key in d:
            e = fn(d[key])
            if e:
                errors.append("%s：%s" % (tag, e))
            else:
                ok = True
    if not ok and len(errors) == n0:
        errors.append("%s：必须含合法的 host 或 ip，当前一个都没有（键：%s）"
                      % (tag, ", ".join(sorted(d)) or "<空对象>"))
    for k in ("process", "ua", "note", "reason"):
        if k in d and (not isinstance(d[k], str) or not d[k]):
            errors.append("%s：%s 必须是非空字符串" % (tag, k))


def validate_scenarios(files):
    """加载期严格校验。返回 (errors, warnings)，两者都是可读中文字符串列表。"""
    errors, warnings = [], []
    seen_names = {}
    quarantined = set()

    for fname, arr in files:
        for idx, scn in enumerate(arr):
            where = "%s[%d]" % (fname, idx)
            if not isinstance(scn, dict):
                errors.append("%s：场景必须是 JSON 对象，实际为 %s"
                              % (where, type(scn).__name__))
                continue
            name = scn.get("name")
            tag = "%s «%s»" % (where, name if isinstance(name, str) and name
                               else "<未命名>")

            # --- 场景级键 / name 全局唯一 ---
            _unknown_keys(scn, SCENARIO_KEYS, "场景级", tag, errors)
            if not isinstance(name, str) or not name.strip():
                errors.append("%s：name 缺失或不是非空字符串" % tag)
                name = None
            elif name in seen_names:
                errors.append("%s：name 重复——已在 %s 用过；name 必须全局唯一，"
                              "否则报告里两条场景无法区分" % (tag, seen_names[name]))
            else:
                seen_names[name] = where
            for k, typ, tname in (("desc", str, "字符串"), ("note", str, "字符串"),
                                  ("reason", str, "字符串"),
                                  ("known_broken", bool, "布尔值")):
                if k in scn and not isinstance(scn[k], typ):
                    errors.append("%s：%s 必须是%s" % (tag, k, tname))

            # --- requests 非空 + 每项合法 ---
            reqs = scn.get("requests")
            req_keys, reqs_usable = [], False
            if not isinstance(reqs, list):
                errors.append("%s：requests 缺失或不是数组" % tag)
            elif not reqs:
                if name in LEGACY_EMPTY_REQUESTS:
                    quarantined.add(name)
                    warnings.append(
                        "%s：requests 为空——历史遗留具名豁免（%s）。该场景产出 0 条断言，"
                        "是 P1-10 点名的假绿空壳；请补齐请求或整条删除，然后删掉 runsuite.py "
                        "里 LEGACY_EMPTY_REQUESTS 的对应登记。"
                        % (tag, LEGACY_EMPTY_REQUESTS[name]))
                else:
                    errors.append("%s：requests 为空——空场景产不出任何断言，"
                                  "却会在报告里显示为通过，属假绿空洞" % tag)
            else:
                reqs_usable = True
                for ri, r in enumerate(reqs):
                    rtag = "%s request[%d]" % (tag, ri)
                    if not isinstance(r, dict):
                        errors.append("%s：请求必须是 JSON 对象，实际为 %s"
                                      % (rtag, type(r).__name__))
                        continue
                    _unknown_keys(r, REQUEST_KEYS, "request", rtag, errors)
                    _check_target(r, rtag, errors)
                    req_keys.append(qkey(r))

            # --- assert ---
            asrt = scn.get("assert")
            if not isinstance(asrt, dict):
                errors.append("%s：assert 缺失或不是 JSON 对象" % tag)
                continue
            _unknown_keys(asrt, ASSERT_KEYS, "assert", tag, errors)
            if "policy" in asrt and "policy_in" in asrt:
                errors.append("%s：assert 的 policy 与 policy_in 互斥，不能同时出现"
                              "（policy_in 会被 policy 挡住，静默失效）" % tag)
            if "policy" in asrt and (not isinstance(asrt["policy"], str)
                                     or not asrt["policy"]):
                errors.append("%s：assert.policy 必须是非空字符串" % tag)
            if "policy_in" in asrt:
                pin = asrt["policy_in"]
                if (not isinstance(pin, list) or not pin
                        or not all(isinstance(x, str) and x for x in pin)):
                    errors.append("%s：assert.policy_in 必须是非空的字符串数组" % tag)
            for k in ("same_policy", "no_dns_leak"):
                if k in asrt and not isinstance(asrt[k], bool):
                    errors.append("%s：assert.%s 必须是布尔值" % (tag, k))

            # --- per_request：键唯一 + 全部对得上 requests ---
            per = asrt.get("per_request", [])
            if "per_request" in asrt and not isinstance(per, list):
                errors.append("%s：assert.per_request 必须是数组" % tag)
                per = []
            per_keys = {}
            for pi, p in enumerate(per):
                ptag = "%s per_request[%d]" % (tag, pi)
                if not isinstance(p, dict):
                    errors.append("%s：条目必须是 JSON 对象，实际为 %s"
                                  % (ptag, type(p).__name__))
                    continue
                _unknown_keys(p, PERREQ_KEYS, "per_request", ptag, errors)
                _check_target(p, ptag, errors)
                has_p, has_pin = "policy" in p, "policy_in" in p
                if has_p and has_pin:
                    errors.append("%s：policy 与 policy_in 互斥，不能同时出现" % ptag)
                elif not has_p and not has_pin:
                    errors.append("%s：条目必须给出 policy 或 policy_in，"
                                  "否则它只是把请求排除出 same_policy 分组、不产生任何断言"
                                  % ptag)
                if has_p and (not isinstance(p["policy"], str) or not p["policy"]):
                    errors.append("%s：policy 必须是非空字符串" % ptag)
                if has_pin:
                    pin = p["policy_in"]
                    if (not isinstance(pin, list) or not pin
                            or not all(isinstance(x, str) and x for x in pin)):
                        errors.append("%s：policy_in 必须是非空的字符串数组" % ptag)
                if "known_broken" in p and not isinstance(p["known_broken"], bool):
                    errors.append("%s：known_broken 必须是布尔值" % ptag)
                k = qkey(p)
                if k in per_keys:
                    errors.append("%s：与 per_request[%d] 撞键（%s）——后项会覆盖前项，"
                                  "前一条断言静默丢失" % (ptag, per_keys[k], qlabel(p)))
                else:
                    per_keys[k] = pi
                if reqs_usable and k not in req_keys:
                    errors.append("%s：条目 %s 对不上 requests 里的任何请求——"
                                  "按 (host, ip, process, ua) 四元组精确匹配，"
                                  "检查是否拼错或漏写 process/ua" % (ptag, qlabel(p)))

            # --- assert 至少一项有效断言 ---
            if not (("policy" in asrt) or ("policy_in" in asrt)
                    or asrt.get("same_policy") is True
                    or asrt.get("no_dns_leak") is True
                    or bool(per)):
                errors.append("%s：assert 里没有任何有效断言。至少要有一项："
                              "policy / policy_in / same_policy:true / no_dns_leak:true / "
                              "非空 per_request（same_policy:false 只是说明性字段，"
                              "本身不构成断言）" % tag)

            # --- same_policy:true 不得对空/单请求集合通过 ---
            if asrt.get("same_policy") is True and name not in quarantined:
                uncovered = [k for k in req_keys if k not in per_keys]
                if len(uncovered) < 2:
                    errors.append("%s：same_policy:true，但未被 per_request 覆盖的请求只有 "
                                  "%d 个——空集合或单请求的「同组」断言没有信息量、必然通过，"
                                  "是假绿；请补到至少 2 个请求，或去掉 same_policy"
                                  % (tag, len(uncovered)))

    for stale in sorted(set(LEGACY_EMPTY_REQUESTS) - quarantined):
        warnings.append("runsuite.py 的 LEGACY_EMPTY_REQUESTS 仍登记着 «%s»，但该场景"
                        "已不存在或已不再违规——请删掉这条豁免登记。" % stale)

    return errors, warnings


def run_scenario(scn, engine):
    """返回 (assertions, error)；assertion = dict(kind,query,expect,actual,ok,xfail,...)"""
    out = []
    asrt = scn.get("assert", {}) or {}
    scn_broken = bool(scn.get("known_broken"))
    scn_reason = scn.get("reason", "")
    per = asrt.get("per_request", []) or []
    per_map = {qkey(p): p for p in per}

    results = []
    for q in scn.get("requests", []):
        try:
            r = engine.query(q)
        except EngineError as e:
            return out, str(e)
        results.append((q, r))

    def add(kind, q, expect, actual, ok, broken, reason, scope=None):
        # scope: "entry" = per_request 条目上的细粒度标记（通过即为「意外通过」信号）
        #        "scenario" = 场景级粗粒度标记（通过就算正常通过，不制造噪声）
        out.append({
            "scenario": scn.get("name"),
            "kind": kind,
            "query": qlabel(q) if q else "<场景级>",
            "expect": expect,
            "actual": actual,
            "ok": ok,
            "known_broken": bool(broken),
            "broken_scope": scope if broken else None,
            "reason": reason or "",
        })

    # --- 逐请求：策略断言 ---
    uncovered = []
    for q, r in results:
        k = qkey(q)
        entry = per_map.get(k)
        detail = "%s [%s @ %s]" % (r["policy"], r["matched_rule"], r["source"])
        if entry is not None:
            if entry.get("known_broken"):
                broken, scope, reason = True, "entry", entry.get("reason", "")
            elif scn_broken:
                broken, scope, reason = True, "scenario", scn_reason
            else:
                broken, scope, reason = False, None, ""
            if "policy_in" in entry:
                exp = entry["policy_in"]
                add("per_request.policy_in", q, exp, detail,
                    r["policy"] in exp, broken, reason, scope)
            elif "policy" in entry:
                exp = entry["policy"]
                add("per_request.policy", q, exp, detail,
                    r["policy"] == exp, broken, reason, scope)
        else:
            uncovered.append((q, r))
            if "policy" in asrt:
                add("policy", q, asrt["policy"], detail,
                    r["policy"] == asrt["policy"], scn_broken, scn_reason, "scenario")
            elif "policy_in" in asrt:
                add("policy_in", q, asrt["policy_in"], detail,
                    r["policy"] in asrt["policy_in"], scn_broken, scn_reason, "scenario")

    # --- 场景级：same_policy ---
    if asrt.get("same_policy"):
        pols = []
        for q, r in uncovered:
            if r["policy"] not in pols:
                pols.append(r["policy"])
        add("same_policy", None, "所有请求同一策略组",
            " / ".join(str(p) for p in pols) if pols else "<无请求>",
            len(pols) <= 1, scn_broken, scn_reason, "scenario")

    # --- 数据集自身的健康检查：per_request 条目写了却没匹配上任何请求 ---
    seen_keys = set(qkey(q) for q, _ in results)
    for k, entry in per_map.items():
        if k not in seen_keys:
            add("per_request.orphan", entry, "该条目应能匹配到 requests 里的某个请求",
                "无匹配（host/ip/process/ua 元组需与请求完全一致，检查是否拼错或漏写 process）",
                False, False, "")

    # --- 逐请求：no_dns_leak（独立安全轴，不受场景级 known_broken 豁免）---
    if asrt.get("no_dns_leak"):
        for q, r in results:
            add("no_dns_leak", q, "无本地解析",
                ("泄漏于 " + str(r["dns_leak_at"])) if r["dns_leak"] else "无泄漏",
                not r["dns_leak"], False, "")

    return out, None


# --------------------------------------------------------------------------
# 输出
# --------------------------------------------------------------------------
def dwidth(s):
    return sum(2 if unicodedata.east_asian_width(c) in "WF" else 1 for c in str(s))


def pad(s, n):
    s = str(s)
    return s + " " * max(0, n - dwidth(s))


def load_scenarios(scen_dir):
    if not os.path.isdir(scen_dir):
        raise EngineError("场景目录不存在：%s（用 --dir 指定）" % scen_dir)
    files = sorted(f for f in os.listdir(scen_dir) if f.endswith(".json"))
    if not files:
        raise EngineError("场景目录里没有 .json 文件：%s" % scen_dir)
    data = []
    for f in files:
        p = os.path.join(scen_dir, f)
        try:
            with open(p, encoding="utf-8") as fh:
                arr = json.load(fh)
        except Exception as e:                                  # noqa: BLE001
            raise EngineError("场景文件解析失败 %s：%s" % (p, e))
        if not isinstance(arr, list):
            raise EngineError("场景文件顶层必须是数组：%s" % p)
        data.append((f, arr))
    return data


def main():
    ap = argparse.ArgumentParser(
        description="Surge 分流场景断言运行器（L2）",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dir", default=DEFAULT_SCEN_DIR, help="场景目录（默认 ./scenarios）")
    ap.add_argument("--engine", default=DEFAULT_ENGINE, help="engine.py 路径（默认同目录）")
    ap.add_argument("--conf", default=None, help="Surge.conf 路径（透传给引擎）")
    ap.add_argument("--rules", default=None,
                    help=".list 所在目录（透传给引擎的 rules_dir；"
                         "默认让引擎按 conf 位置推导。配公共脱敏 conf 用）")
    ap.add_argument("--filter", default=None, help="只跑名字或文件名含该子串的场景")
    ap.add_argument("--json", action="store_true", dest="as_json", help="机器可读输出")
    ap.add_argument("--list-known-broken", action="store_true",
                    help="只列出标记为 known_broken 的场景/条目清单")
    ap.add_argument("--allow-known-broken", action="store_true",
                    help="放行 known_broken 断言（默认严格：known_broken > 0 即退出码 1）")
    args = ap.parse_args()

    try:
        files = load_scenarios(args.dir)
    except EngineError as e:
        sys.stderr.write("错误：%s\n" % e)
        return 2

    schema_errors, schema_warnings = validate_scenarios(files)
    if schema_errors:
        sys.stderr.write("=" * 78 + "\n")
        sys.stderr.write("场景 schema 校验失败：%d 项。套件拒绝加载（未跑任何断言）。\n"
                         % len(schema_errors))
        sys.stderr.write("=" * 78 + "\n")
        for e in schema_errors:
            sys.stderr.write("  ✗ %s\n" % e)
        sys.stderr.write("\n场景 schema 规则见 runsuite.py 头部注释「加载期 schema 严格校验」。\n")
        return 2
    for w in schema_warnings:
        sys.stderr.write("[schema 告警] %s\n" % w)

    if args.list_known_broken:
        return list_known_broken(files, args)

    try:
        engine = Engine(args.engine, args.conf, args.rules)
    except EngineError as e:
        sys.stderr.write("错误：%s\n" % e)
        return 2

    per_file = []
    all_asserts = []
    hard_error = None
    for fname, arr in files:
        rows = []
        nscn = nreq = 0
        for scn in arr:
            name = scn.get("name", "")
            if args.filter and args.filter not in name and args.filter not in fname:
                continue
            a, err = run_scenario(scn, engine)
            if err:
                hard_error = err
                break
            rows.extend(a)
            nscn += 1
            nreq += len(scn.get("requests", []))
        if hard_error:
            break
        per_file.append((fname, nscn, nreq, rows))
        all_asserts.extend(rows)

    if hard_error:
        sys.stderr.write("错误：%s\n" % hard_error)
        return 2

    stats = summarize(all_asserts)
    if args.as_json:
        print(json.dumps({
            "engine": {"path": args.engine, "mode": engine.mode, "conf": args.conf,
                       "rules": args.rules},
            "schema_warnings": schema_warnings,
            "allow_known_broken": args.allow_known_broken,
            "totals": stats,
            "files": [{"file": f, "scenarios": ns, "requests": nr,
                       "stats": summarize(rows)} for f, ns, nr, rows in per_file],
            "assertions": all_asserts,
        }, ensure_ascii=False, indent=2))
    else:
        report(per_file, all_asserts, stats, engine, args)

    if stats["fail"] > 0:
        return 1
    if stats["known_broken"] > 0 and not args.allow_known_broken:
        sys.stderr.write("错误：known_broken 断言 %d 条 > 0，发布闸门判为不通过。\n"
                         "        用 --list-known-broken 看清单；确需临时放行加 "
                         "--allow-known-broken。\n" % stats["known_broken"])
        return 1
    return 0


def summarize(rows):
    """统计口径：
    * 断言失败且被标记 known_broken → 计入「待修」，不算失败；
    * 断言通过且标记来自 per_request 条目（细粒度、明确断言「这一条现在是错的」）
      → 计入「意外通过」，提示可以摘标记；
    * 断言通过且标记来自场景级（粗粒度，只表示该场景至少有一条已知坏断言）
      → 计入正常通过，避免整场景每条请求都刷「意外通过」噪声。
    """
    s = {"total": len(rows), "pass": 0, "fail": 0, "known_broken": 0, "unexpected_pass": 0}
    for r in rows:
        if r["known_broken"] and not r["ok"]:
            s["known_broken"] += 1
        elif r["known_broken"] and r["ok"] and r.get("broken_scope") == "entry":
            s["unexpected_pass"] += 1
        elif r["ok"]:
            s["pass"] += 1
        else:
            s["fail"] += 1
    return s


def fixed_scenarios(rows):
    """标了 known_broken 但一条都没失败的场景 → 标记可以摘掉了。"""
    marked, failed = set(), set()
    for r in rows:
        if r["known_broken"]:
            marked.add(r["scenario"])
            if not r["ok"]:
                failed.add(r["scenario"])
    return sorted(marked - failed)


def report(per_file, all_asserts, stats, engine, args):
    print("=" * 78)
    print("Surge 分流场景回归（L2 runsuite）")
    print("=" * 78)
    print("引擎     : %s  [%s 模式]" % (args.engine, engine.mode))
    print("配置     : %s" % (args.conf or "<引擎默认>"))
    print("场景目录 : %s" % args.dir)
    if args.filter:
        print("过滤     : %s" % args.filter)
    print("")

    cols = [("文件", 24), ("场景", 6), ("请求", 6), ("断言", 6),
            ("通过", 6), ("失败", 6), ("待修", 6), ("意外通过", 10)]
    print("".join(pad(c, w) for c, w in cols))
    print("-" * 78)
    for fname, nscn, nreq, rows in per_file:
        if nscn == 0:                     # --filter 未命中的文件不占版面
            continue
        s = summarize(rows)
        print("".join(pad(v, w) for v, (_, w) in zip(
            [fname, nscn, nreq, s["total"], s["pass"], s["fail"],
             s["known_broken"], s["unexpected_pass"]], cols)))
    print("-" * 78)
    tot_scn = sum(x[1] for x in per_file)
    tot_req = sum(x[2] for x in per_file)
    print("".join(pad(v, w) for v, (_, w) in zip(
        ["合计", tot_scn, tot_req, stats["total"], stats["pass"], stats["fail"],
         stats["known_broken"], stats["unexpected_pass"]], cols)))
    print("")

    fails = [r for r in all_asserts if not r["ok"] and not r["known_broken"]]
    if fails:
        print("【失败明细】")
        for r in fails:
            print("  ✗ %s / %s" % (r["scenario"], r["kind"]))
            print("      查询: %s" % r["query"])
            print("      期望: %s" % r["expect"])
            print("      实际: %s" % r["actual"])
        print("")

    xpass = [r for r in all_asserts
             if r["ok"] and r["known_broken"] and r.get("broken_scope") == "entry"]
    if xpass:
        print("【意外通过 — per_request 上的 known_broken 标记可以摘掉了】")
        for r in xpass:
            print("  ! %s / %s  查询: %s  期望: %s  实际: %s"
                  % (r["scenario"], r["kind"], r["query"], r["expect"], r["actual"]))
        print("")

    fixed = fixed_scenarios(all_asserts)
    if fixed:
        print("【已修复场景 — 整场景已全绿，可移除 known_broken 字段】")
        for name in fixed:
            print("  ✓ %s" % name)
        print("")

    broken = [r for r in all_asserts if r["known_broken"] and not r["ok"]]
    if broken:
        print("【已知待修（known_broken，不计失败）】")
        seen = set()
        for r in broken:
            if r["scenario"] in seen:
                continue
            seen.add(r["scenario"])
            print("  · %s" % r["scenario"])
            if r["reason"]:
                print("      %s" % r["reason"])
        print("")

    leaks = [r for r in all_asserts if r["kind"] == "no_dns_leak" and not r["ok"]]
    print("DNS 泄漏断言: %d 条，失败 %d 条%s"
          % (len([r for r in all_asserts if r["kind"] == "no_dns_leak"]),
             len(leaks), "（P1 实锤，需立即修）" if leaks else " ✓"))
    kb_blocks = stats["known_broken"] > 0 and not args.allow_known_broken
    print("结果: %s（失败 %d / 待修 %d / 通过 %d）"
          % ("FAIL" if (stats["fail"] or kb_blocks) else "PASS",
             stats["fail"], stats["known_broken"], stats["pass"]))
    if kb_blocks:
        print("      ↑ 无失败断言，但 known_broken %d 条 > 0，按 §12.2「main 分支 "
              "known-broken 必须为 0」判为不通过；临时放行加 --allow-known-broken。"
              % stats["known_broken"])


def list_known_broken(files, args):
    n = 0
    for fname, arr in files:
        head = False
        for scn in arr:
            name = scn.get("name", "")
            if args.filter and args.filter not in name and args.filter not in fname:
                continue
            items = []
            if scn.get("known_broken"):
                items.append(("场景", scn.get("reason", "")))
            for p in (scn.get("assert", {}) or {}).get("per_request", []) or []:
                if p.get("known_broken"):
                    items.append((qlabel(p), p.get("reason", "")))
            if not items:
                continue
            if not head:
                print("\n== %s ==" % fname)
                head = True
            print("  · %s — %s" % (name, scn.get("desc", "")))
            for scope, reason in items:
                n += 1
                print("      [%s] %s" % (scope, reason))
    print("\n合计 known_broken 条目：%d" % n)
    return 0


if __name__ == "__main__":
    sys.exit(main())
