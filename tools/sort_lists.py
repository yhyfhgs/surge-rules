#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""sort_lists.py — Surge .list 的表内规则重排器（类型分组 + 区内定序）。

用途：单张 .list 里 DOMAIN / DOMAIN-SUFFIX / IP-CIDR 等类型历史上是交错的
（例如 ProxyGFW 按注册域族聚合、Reject 按来源批次追加），人读时要在同一屏里
跳着分辨类型。本脚本把每张表重排成「类型分区 + 区内确定序」的规范形态。

**语义无变化**：Surge 的表内匹配不依赖行序——同一张 rule-set 内不存在
「先命中者胜」的策略分歧（整表只有一个策略，由 config/routing.json 指定），
落点只取决于「该表是否包含匹配项」。行序影响的只有 `config/routing.json` 里
**表与表之间**的顺序，本脚本一个字节都不碰那里。因此重排前后每张表的
**规则行多重集完全相同**，这也是验收口径（见 docs/MAINTENANCE「排序约定」）。

规范形态
--------
* 文件头注释块（首条规则之前的连续 `#` 行）原样保留在顶部，随后空一行；
* 规则按固定的类型桶顺序分区：
      DOMAIN → DOMAIN-SUFFIX → DOMAIN-WILDCARD → DOMAIN-KEYWORD
      → IP-CIDR → IP-CIDR6 → IP-ASN → GEOIP
  出现此列表之外的类型：**报错退出**，绝不静默放行（新类型必须先在这里
  和 docs/MAINTENANCE 里定好位置）；
* 桶内定序：域名类按规则值的字典序（`casefold` 归一大小写），
  IP-CIDR / IP-CIDR6 按网络地址数值序（`ipaddress`，网络地址在前、
  前缀长度在后），IP-ASN 按 ASN 数值序，GEOIP 按国家码字典序；
* 行尾注释（如 Telegram 的 ` # last_verified=…`）与 `,no-resolve` 等尾参
  随规则行整体移动，**逐字节保留**；
* 桶与桶之间恰好一个空行，桶内无空行，文件尾恰好一个换行。

排序稳定：完全相同的两行保持原相对次序，因此 `--write` 之后立即 `--check`
必然通过（幂等）。

用法
----
  # 闸门：检查全部 lists/*.list 是否已是规范形态（不写任何文件）
  python3 tools/sort_lists.py --check

  # 就地重排全部表
  python3 tools/sort_lists.py --write

  # 只处理指定文件
  python3 tools/sort_lists.py --check lists/ProxyGFW.list
  python3 tools/sort_lists.py --write lists/ProxyGFW.list

  # 内置自检（构造小样例验证桶序 / 注释保留 / 幂等 / 未知类型报错）
  python3 tools/sort_lists.py --selftest

退出码：0 = 已规范 / 已写回；1 = `--check` 发现偏差，或输入非法。
只依赖 python3 标准库（argparse / ipaddress / os / sys）。
"""
import argparse
import ipaddress
import os
import sys

# 类型桶顺序即分区顺序；此表之外的类型一律报错。
BUCKET_ORDER = (
    "DOMAIN",
    "DOMAIN-SUFFIX",
    "DOMAIN-WILDCARD",
    "DOMAIN-KEYWORD",
    "IP-CIDR",
    "IP-CIDR6",
    "IP-ASN",
    "GEOIP",
)
BUCKET_INDEX = {name: index for index, name in enumerate(BUCKET_ORDER)}
DOMAIN_TYPES = {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-WILDCARD", "DOMAIN-KEYWORD"}
CIDR_TYPES = {"IP-CIDR": 4, "IP-CIDR6": 6}


class SortError(Exception):
    """输入不满足规范形态的前提（未知类型、行内注释、非法值等）。"""


def _strip_comment(line):
    head = line.split("#", 1)[0]
    return head.strip()


def parse_rule(path, lineno, line):
    """返回 (类型, 值)；类型不在 BUCKET_ORDER 内或行畸形则抛 SortError。"""
    text = _strip_comment(line)
    parts = [part.strip() for part in text.split(",")]
    if len(parts) < 2 or not parts[0] or not parts[1]:
        raise SortError("%s:%d: 规则行畸形: %r" % (path, lineno, line))
    rule_type = parts[0].upper()
    if rule_type not in BUCKET_INDEX:
        raise SortError(
            "%s:%d: 未知规则类型 %r —— 请先在 tools/sort_lists.py 的 BUCKET_ORDER "
            "与 docs/MAINTENANCE 里为它定好分区位置" % (path, lineno, rule_type))
    return rule_type, parts[1]


def sort_key(path, lineno, rule_type, value):
    """桶内排序键；同桶内类型一致，因此各分支的键类型互相不比较。"""
    if rule_type in DOMAIN_TYPES or rule_type == "GEOIP":
        return (value.casefold(), value)
    if rule_type in CIDR_TYPES:
        try:
            net = ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise SortError("%s:%d: 非法 %s 值 %r: %s"
                            % (path, lineno, rule_type, value, exc)) from exc
        if net.version != CIDR_TYPES[rule_type]:
            raise SortError("%s:%d: %s 的值 %r 是 IPv%d"
                            % (path, lineno, rule_type, value, net.version))
        return (int(net.network_address), net.prefixlen)
    if rule_type == "IP-ASN":
        try:
            return (int(value),)
        except ValueError as exc:
            raise SortError("%s:%d: 非法 IP-ASN 值 %r" % (path, lineno, value)) from exc
    raise SortError("%s:%d: 类型 %r 没有排序规则" % (path, lineno, rule_type))


def split_file(path, text):
    """拆成 (头注释行, 各桶的规则行)；桶按 BUCKET_ORDER 索引。"""
    if "\r" in text:
        raise SortError("%s: 含 CR，本仓库的 .list 一律 LF 行尾" % path)
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()

    header, start = [], 0
    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            start = index
            break
        header.append(line)
    else:
        start = len(lines)
    while header and not header[-1].strip():
        header.pop()

    buckets = [[] for _ in BUCKET_ORDER]
    for offset, line in enumerate(lines[start:]):
        lineno = start + offset + 1
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            raise SortError(
                "%s:%d: 首条规则之后出现注释行 %r —— 分区注释由本脚本生成，"
                "行间注释请改成行尾注释或并入文件头" % (path, lineno, stripped))
        rule_type, value = parse_rule(path, lineno, line)
        buckets[BUCKET_INDEX[rule_type]].append(
            (sort_key(path, lineno, rule_type, value), line))
    return header, buckets


def render(header, buckets):
    """把头注释与各桶渲染成规范文本（桶内已排序）。"""
    out = list(header)
    if header:
        out.append("")
    first = True
    for bucket in buckets:
        if not bucket:
            continue
        if not first:
            out.append("")
        out.extend(line for _, line in bucket)
        first = False
    if not out:
        return ""
    return "\n".join(out) + "\n"


def canonical_text(path, text):
    header, buckets = split_file(path, text)
    for bucket in buckets:
        bucket.sort(key=lambda item: item[0])
    return render(header, buckets)


def first_deviation(actual, expected):
    """返回 (行号, 实际行, 期望行)；两侧完全一致时返回 None。"""
    left = actual.split("\n")
    right = expected.split("\n")
    for index in range(max(len(left), len(right))):
        got = left[index] if index < len(left) else None
        want = right[index] if index < len(right) else None
        if got != want:
            return (index + 1, got, want)
    return None


def process(path, write):
    """返回 (是否已规范, 提示行)。write=True 时不一致就写回。"""
    with open(path, encoding="utf-8") as handle:
        text = handle.read()
    expected = canonical_text(path, text)
    if text == expected:
        return True, "%-24s ✓ 已是分区规范形态" % os.path.basename(path)
    if write:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(expected)
        again = canonical_text(path, expected)
        if again != expected:
            raise SortError("%s: 重排非幂等，已中止" % path)
        return False, "%-24s → 已重排" % os.path.basename(path)
    lineno, got, want = first_deviation(text, expected)
    return False, ("%-24s ✗ 首个偏差在第 %d 行\n    实际: %s\n    期望: %s"
                   % (os.path.basename(path), lineno,
                      "<文件已结束>" if got is None else repr(got),
                      "<文件应结束>" if want is None else repr(want)))


# ---------------------------------------------------------------- selftest

_SELFTEST_MIXED = """\
# Sample — 头注释第一行
# 头注释第二行

IP-CIDR6,2001:db8:2::/48,no-resolve
DOMAIN-SUFFIX,beta.example.com
GEOIP,NL,no-resolve
IP-ASN,64500,no-resolve
DOMAIN,zeta.example.org
IP-CIDR,10.2.0.0/16,no-resolve  # last_verified=2026-09-01
DOMAIN-KEYWORD,tracking
IP-CIDR,10.1.0.0/16,no-resolve

DOMAIN-WILDCARD,*.wild.example.net
GEOIP,CH,no-resolve
IP-ASN,4538,no-resolve
DOMAIN-SUFFIX,Alpha.Example.com
IP-CIDR6,2001:db8:1::/48,no-resolve
DOMAIN,ada.example.org
IP-CIDR,10.1.0.0/24,no-resolve
"""

_SELFTEST_EXPECTED = """\
# Sample — 头注释第一行
# 头注释第二行

DOMAIN,ada.example.org
DOMAIN,zeta.example.org

DOMAIN-SUFFIX,Alpha.Example.com
DOMAIN-SUFFIX,beta.example.com

DOMAIN-WILDCARD,*.wild.example.net

DOMAIN-KEYWORD,tracking

IP-CIDR,10.1.0.0/16,no-resolve
IP-CIDR,10.1.0.0/24,no-resolve
IP-CIDR,10.2.0.0/16,no-resolve  # last_verified=2026-09-01

IP-CIDR6,2001:db8:1::/48,no-resolve
IP-CIDR6,2001:db8:2::/48,no-resolve

IP-ASN,4538,no-resolve
IP-ASN,64500,no-resolve

GEOIP,CH,no-resolve
GEOIP,NL,no-resolve
"""


def _check(name, condition, detail=""):
    status = "PASS" if condition else "FAIL"
    print("  [%s] %s%s" % (status, name, ("  " + detail) if detail and not condition else ""))
    return bool(condition)


def selftest():
    print("sort_lists 自检")
    ok = True
    got = canonical_text("<selftest>", _SELFTEST_MIXED)
    ok &= _check("桶序 / 区内定序 / 头注释 / 行尾注释", got == _SELFTEST_EXPECTED,
                 "\n实际:\n%s" % got)
    ok &= _check("幂等：canonical(canonical(x)) == canonical(x)",
                 canonical_text("<selftest>", got) == got)
    ok &= _check("多重集守恒：重排不增删任何规则行",
                 sorted(l for l in _SELFTEST_MIXED.split("\n") if l.strip()
                        and not l.startswith("#"))
                 == sorted(l for l in got.split("\n") if l.strip()
                           and not l.startswith("#")))

    try:
        canonical_text("<selftest>", "DOMAIN,a.example\nUSER-AGENT,Foo*\n")
    except SortError as exc:
        ok &= _check("未知类型报错", "未知规则类型" in str(exc))
    else:
        ok &= _check("未知类型报错", False, "USER-AGENT 被静默放行")

    try:
        canonical_text("<selftest>", "DOMAIN,a.example\n# 行间注释\nDOMAIN,b.example\n")
    except SortError as exc:
        ok &= _check("行间注释报错", "注释行" in str(exc))
    else:
        ok &= _check("行间注释报错", False, "行间注释被吞掉")

    try:
        canonical_text("<selftest>", "IP-CIDR,10.0.0.0/8,no-resolve\nIP-CIDR,not-an-ip\n")
    except SortError as exc:
        ok &= _check("非法 CIDR 报错", "非法" in str(exc))
    else:
        ok &= _check("非法 CIDR 报错", False)

    ok &= _check("无头注释文件不产生前导空行",
                 canonical_text("<selftest>", "DOMAIN-SUFFIX,b.example\n"
                                              "DOMAIN-SUFFIX,a.example\n")
                 == "DOMAIN-SUFFIX,a.example\nDOMAIN-SUFFIX,b.example\n")
    ok &= _check("重复行保序保量",
                 canonical_text("<selftest>", "DOMAIN,a.example\nDOMAIN,a.example\n")
                 == "DOMAIN,a.example\nDOMAIN,a.example\n")
    print("结论：%s" % ("全部通过 ✓" if ok else "存在失败 ✗"))
    return 0 if ok else 1


# -------------------------------------------------------------------- main

def main():
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(here)
    parser = argparse.ArgumentParser(
        description="Surge .list 的表内规则重排器（类型分组 + 区内定序）")
    parser.add_argument("paths", nargs="*",
                        help="待处理的 .list（默认 lists/ 下全部）")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true",
                      help="闸门模式：已是规范形态退出 0，否则 1 并打印首个偏差；不写文件")
    mode.add_argument("--write", action="store_true", help="就地重排并写回")
    mode.add_argument("--selftest", action="store_true", help="只跑内置自检")
    parser.add_argument("--rules-dir", default=os.path.join(root, "lists"),
                        help="默认表目录")
    args = parser.parse_args()

    if args.selftest:
        return selftest()
    if not args.check and not args.write:
        parser.error("必须指定 --check、--write 或 --selftest 之一")

    paths = args.paths
    if not paths:
        if not os.path.isdir(args.rules_dir):
            sys.stderr.write("表目录不存在: %s\n" % args.rules_dir)
            return 1
        paths = [os.path.join(args.rules_dir, name)
                 for name in sorted(os.listdir(args.rules_dir))
                 if name.endswith(".list")
                 and os.path.isfile(os.path.join(args.rules_dir, name))]
    if not paths:
        sys.stderr.write("没有待处理的 .list\n")
        return 1

    clean, dirty = 0, []
    for path in paths:
        try:
            ok, message = process(path, args.write)
        except SortError as exc:
            sys.stderr.write("%s\n" % exc)
            return 1
        if ok:
            clean += 1
        else:
            dirty.append(os.path.basename(path))
        print(message)

    if args.write:
        print("结论：%d 张表已重排，%d 张本就规范 ✓" % (len(dirty), clean))
        return 0
    if dirty:
        print("结论：%d 张表未达分区规范形态 ✗（%s）" % (len(dirty), ", ".join(dirty)))
        return 1
    print("结论：%d 张表均为分区规范形态 ✓" % clean)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
