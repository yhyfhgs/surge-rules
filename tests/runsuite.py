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
    python3 runsuite.py --list-known-broken   # 只列当前的待修清单

退出码：0=无失败；1=有失败断言；2=引擎不可用/场景文件损坏。

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
"""

import argparse
import json
import os
import subprocess
import sys
import unicodedata

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_SCEN_DIR = os.path.join(HERE, "scenarios")
DEFAULT_ENGINE = os.path.join(HERE, "engine.py")

QUERY_KEYS = ("host", "ip", "process", "ua")


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
    def __init__(self, path, conf=None):
        self.path = path
        self.conf = conf
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
            for call in ((lambda: fn(self.conf)) if self.conf else (lambda: fn()),
                         (lambda: fn())):
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
    ap.add_argument("--filter", default=None, help="只跑名字或文件名含该子串的场景")
    ap.add_argument("--json", action="store_true", dest="as_json", help="机器可读输出")
    ap.add_argument("--list-known-broken", action="store_true",
                    help="只列出标记为 known_broken 的场景/条目清单")
    args = ap.parse_args()

    try:
        files = load_scenarios(args.dir)
    except EngineError as e:
        sys.stderr.write("错误：%s\n" % e)
        return 2

    if args.list_known_broken:
        return list_known_broken(files, args)

    try:
        engine = Engine(args.engine, args.conf)
    except EngineError as e:
        sys.stderr.write("错误：%s\n" % e)
        return 2

    per_file = []
    all_asserts = []
    hard_error = None
    for fname, arr in files:
        rows = []
        for scn in arr:
            name = scn.get("name", "")
            if args.filter and args.filter not in name and args.filter not in fname:
                continue
            a, err = run_scenario(scn, engine)
            if err:
                hard_error = err
                break
            rows.extend(a)
            scn["_nreq"] = len(scn.get("requests", []))
        if hard_error:
            break
        nscn = len([s for s in arr
                    if not args.filter or args.filter in s.get("name", "") or args.filter in fname])
        nreq = sum(s.get("_nreq", 0) for s in arr if "_nreq" in s)
        per_file.append((fname, nscn, nreq, rows))
        all_asserts.extend(rows)

    if hard_error:
        sys.stderr.write("错误：%s\n" % hard_error)
        return 2

    stats = summarize(all_asserts)
    if args.as_json:
        print(json.dumps({
            "engine": {"path": args.engine, "mode": engine.mode, "conf": args.conf},
            "totals": stats,
            "files": [{"file": f, "scenarios": ns, "requests": nr,
                       "stats": summarize(rows)} for f, ns, nr, rows in per_file],
            "assertions": all_asserts,
        }, ensure_ascii=False, indent=2))
    else:
        report(per_file, all_asserts, stats, engine, args)

    return 1 if stats["fail"] > 0 else 0


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
    print("结果: %s（失败 %d / 待修 %d / 通过 %d）"
          % ("FAIL" if stats["fail"] else "PASS",
             stats["fail"], stats["known_broken"], stats["pass"]))


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
