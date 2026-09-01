#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""rebuild.py — 从 sources.lock.json 的 pin 重建机器管理层的表，并与本地文件比对。

这是「可重建性」的**执行证明**：不是声称某张表来自某个上游，而是当场从那个
revision 的字节把它算出来，再逐条比对。审计 V2 §3.7 把「ChinaDomain 不可从声明的
pin 重建（534 条差异无法解释）」列为 P1，而 ChinaIP 是全库唯一今天就能证明的表 ——
本脚本先把这一半做实。

流水线（每一步都由 lock 的 transform 数组显式声明，脚本不藏任何隐式处理）：
    fetch_locked.py 取到已校验的上游原文
        → require_types   出现声明外的规则类型即失败（上游加新类型不会被静默吞掉）
        → require_param   每条必须带该尾参（ChinaIP 的 no-resolve 是硬语义，
                           丢了会让 IP 规则触发 DNS 解析，等于泄漏）
        → collapse_cidr   用 tools/collapse_cidr.py 的同一套折叠 + 集合指纹
        → 比对 expect      rules / per_type / set_sha256
        → 比对本地表        地址集合逐条 diff

「diff = 0」的含义：重建结果与 lists/<target> 覆盖的**地址集合逐位相同**。
比对的是集合而不是文件文本 —— 表头注释、分区空行属于仓库格式约定，不是上游数据。

用法
----
  python3 tools/rebuild.py                      # 重建全部 pinned 条目并比对
  python3 tools/rebuild.py --id blackmatrix7_china_ip
  python3 tools/rebuild.py --network            # 上游原文走网络取
  python3 tools/rebuild.py --diff-out build/rebuild-diff.txt
  python3 tools/rebuild.py --write              # 差异不为 0 时把重建结果写回 lists/
                                                # （上游同步专用；默认只读）

退出码：0 = 全部条目 diff=0 且 expect 吻合；1 = 有差异 / expect 不符;
       2 = lock 或上游不可用（此时未做任何比对，不要把它读成「一致」）。
"""
import argparse
import io
import ipaddress
import json
import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLS_DIR = os.path.join(REPO_ROOT, "tools")
LISTS_DIR = os.path.join(REPO_ROOT, "lists")
sys.path.insert(0, TOOLS_DIR)

import collapse_cidr as cc                                       # noqa: E402
import fetch_locked as fl                                        # noqa: E402

IP_TYPES = ("IP-CIDR", "IP-CIDR6")


class RebuildError(Exception):
    pass


# ── 解析：上游原文 / 本地表，统一成 {类型: [网段]} ───────────────────────────
def parse_rules(text, label):
    """返回 (by_type, params_by_type)。只认 IP 类；其余类型原样记录以便 require_types 报错。"""
    by_type, params, other = {}, {}, {}
    for lineno, raw in enumerate(text.splitlines(), 1):
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        idx = s.find(" #")                    # 行尾注释：与 engine.py / surge2clash.py 同口径
        if idx >= 0:
            s = s[:idx].strip()
        if not s:
            continue
        parts = [p.strip() for p in s.split(",")]
        rtype = parts[0].upper()
        if rtype not in IP_TYPES:
            other.setdefault(rtype, []).append(lineno)
            continue
        try:
            net = ipaddress.ip_network(parts[1], strict=False)
        except ValueError as e:
            raise RebuildError("%s:%d 网段非法：%s（%s）" % (label, lineno, parts[1], e))
        by_type.setdefault(rtype, []).append(net)
        params.setdefault(rtype, set()).add(tuple(parts[2:]))
    return by_type, params, other


def read_text(path):
    with io.open(path, "r", encoding="utf-8") as f:
        return f.read()


# ── transform 各 op ─────────────────────────────────────────────────────────
def op_require_types(step, by_type, params, other, log):
    want = set(step.get("types", []))
    stray = {t: v for t, v in other.items() if t not in want}
    if stray:
        raise RebuildError(
            "上游出现声明外的规则类型 %s —— transform 的 require_types 只声明了 %s。\n"
            "  这是上游格式变更的信号，必须先人工判读并显式登记，不能静默丢弃。"
            % (", ".join(sorted(stray)), ", ".join(sorted(want))))
    missing = want - set(by_type)
    if missing:
        raise RebuildError("上游缺少声明的规则类型：%s" % ", ".join(sorted(missing)))
    log.append("require_types  %s ✓（%s）"
               % (", ".join(sorted(want)),
                  "，".join("%s %d 条" % (t, len(by_type[t])) for t in sorted(by_type))))


def op_require_param(step, by_type, params, other, log):
    want = step.get("param")
    bad = []
    for t, groups in sorted(params.items()):
        for g in groups:
            if want not in g:
                bad.append("%s 存在缺 %s 的条目（尾参=%r）" % (t, want, g))
    if bad:
        raise RebuildError("；".join(bad))
    log.append("require_param  每条均带 ,%s ✓" % want)


def op_collapse_cidr(step, by_type, params, other, log):
    """用 collapse_cidr.py 的同一实现折叠；返回折叠后的 by_type。"""
    out = {}
    for t in sorted(by_type):
        out[t] = list(ipaddress.collapse_addresses(by_type[t]))
        log.append("collapse_cidr  %-9s %5d → %5d 条" % (t, len(by_type[t]), len(out[t])))
    return out


def op_exclude_cidr(step, by_type, params, other, log):
    excludes = [ipaddress.ip_network(value, strict=True)
                for value in step.get("values", [])]
    out = {}
    for rule_type, networks in by_type.items():
        current = list(networks)
        for excluded in excludes:
            if excluded.version != (4 if rule_type == "IP-CIDR" else 6):
                continue
            next_set = []
            for network in current:
                if not network.overlaps(excluded):
                    next_set.append(network)
                elif network.subnet_of(excluded):
                    continue
                elif excluded.subnet_of(network):
                    next_set.extend(network.address_exclude(excluded))
                else:
                    raise RebuildError("非 CIDR 嵌套交叉：%s × %s" % (network, excluded))
            current = next_set
        out[rule_type] = list(ipaddress.collapse_addresses(current))
    log.append("exclude_cidr  %s" % ", ".join(str(value) for value in excludes))
    return out


OPS = {
    "require_types": op_require_types,
    "require_param": op_require_param,
    "collapse_cidr": op_collapse_cidr,
    "exclude_cidr": op_exclude_cidr,
}


def run_transform(src, text, log):
    by_type, params, other = parse_rules(text, "上游 " + src.get("path", "?"))
    for step in src.get("transform", []):
        op = step.get("op")
        fn = OPS.get(op)
        if fn is None:
            raise RebuildError(
                "transform 里有本脚本未实现的 op：%r。\n"
                "  未实现的变换绝不能被跳过 —— 那样『重建成功』就成了假证明。" % op)
        res = fn(step, by_type, params, other, log)
        if res is not None:
            by_type = res
    return by_type


# ── 比对 ────────────────────────────────────────────────────────────────────
def check_expect(src, by_type, problems, log):
    exp = src.get("expect", {})
    total = sum(len(v) for v in by_type.values())
    if "rules" in exp and total != exp["rules"]:
        problems.append("规则总数 %d ≠ expect.rules %d" % (total, exp["rules"]))
    else:
        log.append("expect.rules   %d ✓" % total)
    for t, want in sorted(exp.get("per_type", {}).items()):
        got = len(by_type.get(t, []))
        if got != want:
            problems.append("%s 条数 %d ≠ expect %d" % (t, got, want))
        else:
            log.append("expect.per_type %-9s %d ✓" % (t, got))
    for t, want in sorted(exp.get("set_sha256", {}).items()):
        got = cc.set_digest(by_type.get(t, []))
        if got != want:
            problems.append("%s set_sha256 不符\n      实得 %s\n      期望 %s" % (t, got, want))
        else:
            log.append("expect.set_sha256 %-9s %s… ✓" % (t, got[:16]))


def diff_against_local(src, by_type, problems, diff_lines):
    """与 lists/<target> 逐条比对地址集合。返回 (目标名, 新增, 缺失) 列表。"""
    results = []
    for target in src.get("targets", []):
        path = os.path.join(LISTS_DIR, target)
        if not os.path.isfile(path):
            problems.append("目标表不存在：lists/%s" % target)
            continue
        local_by_type, _, _ = parse_rules(read_text(path), "lists/" + target)
        added = removed = 0
        for t in sorted(set(by_type) | set(local_by_type)):
            rebuilt = set(ipaddress.collapse_addresses(by_type.get(t, [])))
            current = set(ipaddress.collapse_addresses(local_by_type.get(t, [])))
            only_rebuilt = sorted(rebuilt - current, key=lambda n: (n.version, n))
            only_local = sorted(current - rebuilt, key=lambda n: (n.version, n))
            added += len(only_rebuilt)
            removed += len(only_local)
            for n in only_rebuilt:
                diff_lines.append("+ %s,%s   (重建有，lists/%s 无)" % (t, n, target))
            for n in only_local:
                diff_lines.append("- %s,%s   (lists/%s 有，重建无)" % (t, n, target))
        results.append((target, added, removed))
        if added or removed:
            problems.append("lists/%s 与重建结果不一致：重建独有 %d 条 / 本地独有 %d 条"
                            % (target, added, removed))
    return results


def render_target(src, by_type, target):
    """按仓库格式约定渲染重建结果：沿用本地表头注释 + 折叠后的分区。"""
    path = os.path.join(LISTS_DIR, target)
    header = []
    if os.path.isfile(path):
        for line in read_text(path).splitlines():
            if line.startswith("#"):
                header.append(line)
            else:
                break
    param = ""
    for step in src.get("transform", []):
        if step.get("op") == "require_param":
            param = "," + step["param"]
    blocks = []
    for t in IP_TYPES:
        if t not in by_type:
            continue
        blocks.append("\n".join("%s,%s%s" % (t, n, param) for n in sorted(by_type[t])))
    return "\n".join(header) + "\n\n" + "\n\n".join(blocks) + "\n"


# ── 主流程 ──────────────────────────────────────────────────────────────────
def rebuild_one(src, prefer_network, write, diff_lines):
    sid = src.get("id", "<无 id>")
    print("─" * 74)
    print("条目 %s  ←  %s @ %s" % (sid, src.get("path"),
                                   src.get("revision_short") or src.get("revision", "")[:7]))
    data, where, err = fl.fetch_one(src, prefer_network=prefer_network)
    if data is None:
        sys.stderr.write("✗ %s 取源失败：%s\n" % (sid, err))
        return 2
    ok, got, _ = fl.verify(src, data)
    if not ok:
        sys.stderr.write("✗ %s 上游 sha256 不匹配（实得 %s / lock %s）——"
                         " 拒绝在未校验的字节上重建。\n" % (sid, got, src.get("sha256")))
        return 2
    print("  上游   : %s  sha256 %s… ✓" % (where, got[:16]))

    log, problems = [], []
    try:
        by_type = run_transform(src, data.decode("utf-8"), log)
    except RebuildError as e:
        sys.stderr.write("✗ %s transform 失败：%s\n" % (sid, e))
        return 2
    check_expect(src, by_type, problems, log)
    results = diff_against_local(src, by_type, problems, diff_lines)

    for line in log:
        print("  %s" % line)
    for target, added, removed in results:
        mark = "✓ diff = 0" if not (added or removed) else "✗ +%d / -%d" % (added, removed)
        print("  比对   : lists/%-16s %s" % (target, mark))

    if problems:
        for p in problems:
            sys.stderr.write("  ✗ %s\n" % p)
        if write:
            for target, _, _ in results:
                dest = os.path.join(LISTS_DIR, target)
                with io.open(dest, "w", encoding="utf-8") as f:
                    f.write(render_target(src, by_type, target))
                print("  已写回 : lists/%s（--write）" % target)
            return 0
        return 1
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="rebuild.py",
        description="从 sources.lock.json 的 pin 重建机器管理层的表并与 lists/ 比对")
    ap.add_argument("--lock", default=fl.LOCK_PATH, help="lock 文件路径")
    ap.add_argument("--id", default=None, help="只重建该 id 的条目")
    ap.add_argument("--network", action="store_true", help="上游原文走网络取（跳过 local_mirror）")
    ap.add_argument("--diff-out", default=None, help="把逐条差异写到该文件（默认只在终端出摘要）")
    ap.add_argument("--write", action="store_true",
                    help="差异不为 0 时把重建结果写回 lists/（上游同步专用；默认只读）")
    args = ap.parse_args(argv)

    lock = fl.load_lock(args.lock)
    srcs = fl.pinned_sources(lock, args.id)
    if not srcs:
        sys.stderr.write("lock 中没有 provenance=pinned 的条目%s。\n"
                         % ("（id=%s）" % args.id if args.id else ""))
        return 2

    diff_lines = []
    worst = 0
    for src in srcs:
        worst = max(worst, rebuild_one(src, args.network, args.write, diff_lines))

    if args.diff_out:
        path = args.diff_out if os.path.isabs(args.diff_out) \
            else os.path.join(REPO_ROOT, args.diff_out)
        d = os.path.dirname(path)
        if d and not os.path.isdir(d):
            os.makedirs(d)
        with io.open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(diff_lines) + ("\n" if diff_lines else "（无差异）\n"))
        print("差异明细 → %s（%d 行）" % (os.path.relpath(path, REPO_ROOT), len(diff_lines)))

    print("─" * 74)
    if worst == 0:
        print("结论：%d 个 pinned 条目全部可从 pin 重建，diff = 0 ✓" % len(srcs))
    elif worst == 1:
        print("结论：重建成功但与 lists/ 存在差异 —— 见上方明细。")
    else:
        print("结论：未能完成重建（取源或 transform 失败），**不要**读成「一致」。")
    return worst


if __name__ == "__main__":
    sys.exit(main())
