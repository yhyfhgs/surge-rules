#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""collapse_cidr.py — Surge .list 里 IP-CIDR / IP-CIDR6 的等价折叠器。

用途：机器管理层的 IP 表（ChinaIP 等）由上游整表拷贝而来，普遍含大量
「被同表更宽前缀完整包含」的子网与「可合并成一条超网」的相邻对。用
`ipaddress.collapse_addresses` 折叠成规范最小形式，条数可减半，而**地址集合
与策略语义完全不变**（Surge 的 IP 规则是纯集合归属判定，只要集合不变，落点
就不变；ChinaIP 还兼作离线引擎 GEOIP,CN 的近似源，同理不变）。

等价性依据：`collapse_addresses` 的输出是一个地址集合的**规范最小表示**
（不重叠、不相邻、按网络地址升序，唯一确定）。因此
    collapse(A) == collapse(B)  ⟺  A 与 B 覆盖的地址集合逐位相同。
`--verify` 就是把折叠前后两侧都规范化后逐条比对，并输出各自的集合 SHA-256。

只依赖 python3 标准库（ipaddress / hashlib / argparse）。

用法
----
  # 就地折叠并写回（写回前先做一次内部等价自检，不等价则拒绝写）
  python3 tools/collapse_cidr.py lists/ChinaIP.list

  # 只看会折叠成什么样，不写文件
  python3 tools/collapse_cidr.py lists/ChinaIP.list --dry-run

  # 等价校验：把本文件折叠一遍，与自身原始集合逐条比对并打印 SHA-256
  python3 tools/collapse_cidr.py lists/ChinaIP.list --verify

  # 等价校验（对基线）：证明写回后的文件与折叠前的快照集合相同
  git show HEAD:lists/ChinaIP.list > /tmp/ChinaIP.pre.list
  python3 tools/collapse_cidr.py lists/ChinaIP.list --verify --against /tmp/ChinaIP.pre.list

  # 写到别处而不覆盖原文件
  python3 tools/collapse_cidr.py lists/ChinaIP.list -o /tmp/ChinaIP.new.list

退出码：0 = 成功 / 集合等价；1 = 不等价或输入非法。
（`--dry-run` 在「文件尚未折叠」时也返回 0；要把「已折叠」当闸门用
  `--check`，漂移时返回 1。）

格式约定（与仓库 docs/MAINTENANCE 的表格式一致）
------------------------------------------------
* 文件头注释（首行起连续的 `#` 行）原样保留，本脚本不改一个字；
* 规则按类型分区、区间空一行，分区顺序沿用原文件里各类型首次出现的顺序；
* IP-CIDR / IP-CIDR6 区内按**网络地址**升序（`ipaddress` 的自然序，即
  网络地址在前、前缀长度在后），非 IP 区的行原样保序不动；
* `,no-resolve` 等尾参逐条保留；尾参不同的行分组折叠，绝不跨组合并
  （避免把 no-resolve 与非 no-resolve 语义混在一条超网里）；
* 默认强制「IP 类规则必须带 no-resolve」，缺失即报错退出；`--add-no-resolve`
  可在再生管线里自动补齐。
"""
import argparse
import hashlib
import ipaddress
import os
import sys
from bisect import bisect_right

IP_TYPES = {"IP-CIDR": 4, "IP-CIDR6": 6}
# 逻辑规则整行保留，不参与按逗号的类型/值拆分。
LOGICAL_TYPES = {"AND", "OR", "NOT"}


# --------------------------------------------------------------------------
# 解析
# --------------------------------------------------------------------------

class Section(object):
    """一个规则类型分区：区首注释 + 该类型的全部条目。"""

    def __init__(self, rtype):
        self.rtype = rtype
        self.comments = []      # 区首注释行（原文，含 '#'）
        self.raw = []           # 非 IP 类型：原样行
        self.nets = []          # IP 类型：(network, params_tuple, 原始文本)


def _fail(msg):
    sys.stderr.write("collapse_cidr: %s\n" % msg)
    raise SystemExit(1)


def parse_list(path):
    """读一个 Surge .list，返回 (header_lines, [Section, ...])。"""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            lines = fh.read().splitlines()
    except OSError as exc:
        _fail("无法读取 %s：%s" % (path, exc))
    return parse_lines(lines, path)


def parse_lines(lines, path):
    """按同一条路径解析行序列；path 仅用于报错定位。"""
    # 文件头：首行起连续的注释/空行，遇到第一条规则为止。
    i = 0
    header = []
    while i < len(lines) and (lines[i].lstrip().startswith("#")
                              or not lines[i].strip()):
        header.append(lines[i])
        i += 1
    while header and not header[-1].strip():
        header.pop()

    sections = {}
    order = []
    pending = []            # 尚未归属的正文注释，挂到下一条规则所在的分区
    errors = []

    for lineno, raw in enumerate(lines[i:], start=i + 1):
        text = raw.strip()
        if not text:
            continue
        if text.startswith("#"):
            pending.append(raw.rstrip())
            continue
        if "," not in text:
            errors.append("%s:%d 无类型前缀的裸行：%s" % (path, lineno, text))
            continue

        rtype = text.split(",", 1)[0].strip().upper()
        if rtype not in sections:
            sections[rtype] = Section(rtype)
            order.append(rtype)
        sec = sections[rtype]
        if pending:
            sec.comments.extend(pending)
            pending = []

        if rtype not in IP_TYPES or rtype in LOGICAL_TYPES:
            sec.raw.append(text)
            continue

        fields = [f.strip() for f in text.split(",")]
        value, params = fields[1], tuple(p for p in fields[2:] if p)
        try:
            net = ipaddress.ip_network(value, strict=True)
        except ValueError as exc:
            errors.append("%s:%d 非法 CIDR：%s（%s）" % (path, lineno, text, exc))
            continue
        if net.version != IP_TYPES[rtype]:
            errors.append("%s:%d 类型与地址族不符：%s 声明为 %s"
                          % (path, lineno, text, rtype))
            continue
        sec.nets.append((net, params, text))

    if pending:
        # 文件尾部的孤立注释：挂到最后一个分区末尾也会被重排，索性直接拒绝，
        # 避免静默丢失。
        errors.append("%s 末尾存在不属于任何分区的注释行：%s"
                      % (path, " / ".join(pending)))
    if errors:
        for e in errors:
            sys.stderr.write("collapse_cidr: %s\n" % e)
        _fail("输入存在 %d 处问题，已中止（未写任何文件）" % len(errors))

    return header, [sections[t] for t in order]


# --------------------------------------------------------------------------
# 折叠
# --------------------------------------------------------------------------

def group_by_params(entries):
    """按尾参分组：{params_tuple: [network, ...]}，绝不跨组折叠。"""
    groups = {}
    for net, params, _ in entries:
        groups.setdefault(params, []).append(net)
    return groups


def collapse_group(nets):
    return list(ipaddress.collapse_addresses(nets))


def set_digest(nets):
    """一组网段的规范集合指纹：先规范化，再对逐行文本取 SHA-256。"""
    canon = "\n".join(str(n) for n in ipaddress.collapse_addresses(nets))
    return hashlib.sha256((canon + "\n").encode("utf-8")).hexdigest()


def covered_by(net, canon_sorted):
    """canon_sorted 为已排序的规范网段列表；判断 net 是否被其中某条完整包含。"""
    idx = bisect_right(canon_sorted, net) - 1
    if idx < 0:
        return False
    return net.subnet_of(canon_sorted[idx])


def check_no_resolve(sections, add_missing):
    """约束：所有 IP 类规则必须带 no-resolve。"""
    missing = []
    for sec in sections:
        if sec.rtype not in IP_TYPES:
            continue
        fixed = []
        for net, params, text in sec.nets:
            if "no-resolve" not in params:
                if add_missing:
                    params = params + ("no-resolve",)
                else:
                    missing.append(text)
            fixed.append((net, params, text))
        sec.nets = fixed
    return missing


# --------------------------------------------------------------------------
# 渲染
# --------------------------------------------------------------------------

def render(header, sections):
    out = list(header)
    for sec in sections:
        out.append("")
        out.extend(sec.comments)
        if sec.rtype in IP_TYPES:
            rows = []
            for params, nets in group_by_params(sec.nets).items():
                for net in collapse_group(nets):
                    rows.append((net, params))
            rows.sort(key=lambda r: r[0])
            for net, params in rows:
                out.append(",".join((sec.rtype, str(net)) + params))
        else:
            out.extend(sec.raw)
    return "\n".join(out) + "\n"


# --------------------------------------------------------------------------
# 校验
# --------------------------------------------------------------------------

def ip_groups(sections):
    """{(rtype, params): [network, ...]}"""
    out = {}
    for sec in sections:
        if sec.rtype not in IP_TYPES:
            continue
        for params, nets in group_by_params(sec.nets).items():
            out.setdefault((sec.rtype, params), []).extend(nets)
    return out


def count_rules(sections):
    return sum(len(s.nets) if s.rtype in IP_TYPES else len(s.raw)
               for s in sections)


def fmt_params(params):
    return ",".join(params) if params else "（无尾参）"


def verify(before_sections, after_sections, label_before, label_after,
           quiet=False):
    """逐组做规范化后逐条比对，打印 SHA-256 与覆盖数；返回 True/False。"""
    def say(fmt, *a):
        if not quiet:
            print(fmt % a if a else fmt)

    gb, ga = ip_groups(before_sections), ip_groups(after_sections)
    ok = True

    for key in sorted(set(gb) - set(ga)):
        ok = False
        say("  ✗ %s,%s 只存在于 %s", key[0], fmt_params(key[1]), label_before)
    for key in sorted(set(ga) - set(gb)):
        ok = False
        say("  ✗ %s,%s 只存在于 %s", key[0], fmt_params(key[1]), label_after)

    for key in sorted(set(gb) & set(ga)):
        rtype, params = key
        cb, ca = collapse_group(gb[key]), collapse_group(ga[key])
        hb, ha = set_digest(gb[key]), set_digest(ga[key])
        nb = sum(n.num_addresses for n in cb)
        na = sum(n.num_addresses for n in ca)
        same = (cb == ca)
        if not same:
            ok = False
        say("  [%s,%s] 规范化后 %d ↔ %d 条；覆盖地址数 %d ↔ %d",
            rtype, fmt_params(params), len(cb), len(ca), nb, na)
        say("      SHA-256(%s) = %s", label_before, hb)
        say("      SHA-256(%s) = %s", label_after, ha)
        if same:
            say("      → 逐条比对 %d/%d 完全一致 ✓", len(cb), len(ca))
        else:
            sb, sa = set(cb), set(ca)
            diff_b = [str(n) for n in cb if n not in sa][:5]
            diff_a = [str(n) for n in ca if n not in sb][:5]
            say("      → 不一致 ✗ 仅在 %s：%s；仅在 %s：%s",
                label_before, diff_b or "-", label_after, diff_a or "-")

        # 独立交叉校验：原始每条网段都必须被对侧规范集合完整包含。
        miss = [str(n) for n in gb[key] if not covered_by(n, ca)][:5]
        if miss:
            ok = False
            say("      → 反向包含校验失败 ✗ 未被覆盖示例：%s", ", ".join(miss))
        else:
            say("      → 反向包含校验：%s 侧 %d 条网段全部被 %s 覆盖 ✓",
                label_before, len(gb[key]), label_after)
    return ok


# --------------------------------------------------------------------------
# 主流程
# --------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="collapse_cidr.py",
        description="Surge .list 的 IP-CIDR/IP-CIDR6 等价折叠与集合校验")
    ap.add_argument("path", help="待处理的 .list 文件")
    ap.add_argument("-o", "--output", help="写到指定文件（默认就地覆盖）")
    ap.add_argument("--dry-run", action="store_true",
                    help="只报告折叠效果，不写任何文件")
    ap.add_argument("--check", action="store_true",
                    help="闸门模式：文件已是折叠后形态则退出 0，否则 1；不写文件")
    ap.add_argument("--verify", action="store_true",
                    help="等价校验模式：打印集合 SHA-256 与逐条比对结果，不写文件")
    ap.add_argument("--against", metavar="BASELINE",
                    help="与 --verify 合用：拿 BASELINE 文件的地址集合作对照"
                         "（默认与 path 自身折叠前的集合对照）")
    ap.add_argument("--add-no-resolve", action="store_true",
                    help="自动为缺失 no-resolve 的 IP 规则补上（默认缺失即报错）")
    args = ap.parse_args(argv)

    header, sections = parse_list(args.path)
    missing = check_no_resolve(sections, args.add_no_resolve)
    if missing:
        for m in missing[:20]:
            sys.stderr.write("collapse_cidr: 缺 no-resolve：%s\n" % m)
        _fail("%d 条 IP 规则缺 ,no-resolve（用 --add-no-resolve 自动补齐）"
              % len(missing))

    before_n = count_rules(sections)
    text = render(header, sections)
    # 折叠结果再走一遍同一条解析路径，杜绝渲染期笔误。
    _, after_sections = parse_lines(text.splitlines(), args.path + "（折叠后）")
    after_n = count_rules(after_sections)

    # ---- --verify ----
    if args.verify:
        if args.against:
            base_header, base_sections = parse_list(args.against)
            check_no_resolve(base_sections, True)
            lb, la = os.path.basename(args.against), os.path.basename(args.path)
            src_sections, dst_sections = base_sections, sections
            print("等价校验：%s（基线） ↔ %s（当前）" % (lb, la))
            print("规则条数：%d → %d" % (count_rules(base_sections), before_n))
        else:
            lb, la = "折叠前", "折叠后"
            src_sections, dst_sections = sections, after_sections
            print("等价校验：%s 折叠前 ↔ 折叠后" % os.path.basename(args.path))
            print("规则条数：%d → %d（减少 %d 条，%.1f%%）"
                  % (before_n, after_n, before_n - after_n,
                     100.0 * (before_n - after_n) / before_n if before_n else 0.0))
        ok = verify(src_sections, dst_sections, lb, la)
        print("结论：%s" % ("地址集合逐位等价 ✓" if ok else "地址集合不等价 ✗"))
        return 0 if ok else 1

    # ---- 折叠效果摘要 ----
    per_type = []
    for sec, sec2 in zip(sections, after_sections):
        if sec.rtype in IP_TYPES:
            per_type.append("%s %d→%d" % (sec.rtype, len(sec.nets), len(sec2.nets)))
    print("%s：%s；总计 %d → %d 条（减少 %d，%.1f%%）"
          % (os.path.basename(args.path), "，".join(per_type) or "无 IP 规则",
             before_n, after_n, before_n - after_n,
             100.0 * (before_n - after_n) / before_n if before_n else 0.0))

    # ---- 写前自检：折叠结果必须与输入地址集合等价 ----
    if not verify(sections, after_sections, "折叠前", "折叠后",
                  quiet=args.check):
        _fail("等价自检失败，未写任何文件")

    if args.check:
        with open(args.path, "r", encoding="utf-8") as fh:
            current = fh.read()
        if current == text:
            print("结论：已是折叠后形态，无漂移 ✓")
            return 0
        print("结论：与折叠后形态存在差异（尚未折叠或有手工改动）✗")
        return 1

    if args.dry_run:
        print("结论：--dry-run，未写文件")
        return 0

    out_path = args.output or args.path
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(text)
    print("已写入：%s" % out_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
