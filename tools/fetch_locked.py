#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fetch_locked.py — 按 sources.lock.json 取上游原文并逐字节校验。

存在的理由（审计 V2 R3-1）：机器管理层的表此前是「git pull 后直接覆盖」进来的，
没有任何环节证明「覆盖进来的字节 == 表头声明的那个 revision」。ChinaDomain 相对
声明的 pin 有 534 条无法解释的缺失，就是这条无证据链路的直接产物。

本脚本只做一件事，且只有两种结局：
  拿到的字节 sha256 == lock 声明   → 落 build/upstream/<id>/<basename>，退出 0
  不等（或取不到）                  → 一个字节都不落盘，退出 1

**禁止绕过**：任何「先 pull 下来再说」的流程都等于把这条证据链剪断。要换上游版本，
先改 lock 的 revision + sha256（并说明依据），再跑本脚本 —— 顺序反过来就没有意义了。

取源顺序（两个后端产出的字节必须完全相同，校验对二者一视同仁）：
  1. 本地镜像 local_mirror（git repo）：`git cat-file -p <revision>:<path>`
     —— 可选加速/离线路径。2026-09-01 起 lock 里没有任何条目声明它（本地上游克隆
     已随仓库精简删除），要用就自己 clone 一份再把 local_mirror 指过去。
  2. 网络 url 模板（{revision} / {path} 占位）—— 镜像缺失或 --network 时走这条。
     没有镜像时这是唯一取源路径；sha256 校验对它一视同仁，所以证据链不受影响。

用法
----
  python3 tools/fetch_locked.py                 # 取全部 provenance=pinned 条目
  python3 tools/fetch_locked.py --id blackmatrix7_china_ip
  python3 tools/fetch_locked.py --network       # 强制走网络（验证 lock 对公网仍成立）
  python3 tools/fetch_locked.py --check         # 只校验、不落盘
  python3 tools/fetch_locked.py --out /tmp/up   # 换输出目录

退出码：0 = 全部条目校验通过；1 = 有条目校验失败或取不到源；2 = lock 文件不可用。
"""
import argparse
import hashlib
import io
import json
import os
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOCK_PATH = os.path.join(REPO_ROOT, "sources.lock.json")
DEFAULT_OUT = os.path.join(REPO_ROOT, "build", "upstream")
NET_TIMEOUT = 60


def load_lock(path=LOCK_PATH):
    if not os.path.isfile(path):
        sys.stderr.write("找不到 lock 文件：%s\n" % path)
        raise SystemExit(2)
    try:
        with io.open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except ValueError as e:
        sys.stderr.write("lock 文件不是合法 JSON：%s\n" % e)
        raise SystemExit(2)


def pinned_sources(lock, only_id=None):
    """只返回 provenance=pinned 的条目 —— observed/unpinned 没有可校验的上游。"""
    out = []
    for src in lock.get("sources", []):
        if src.get("provenance") != "pinned":
            continue
        if only_id and src.get("id") != only_id:
            continue
        out.append(src)
    return out


# ── 后端 1：本地 git 镜像 ────────────────────────────────────────────────────
def fetch_from_mirror(src):
    """从 local_mirror 的 git 对象库按 revision 取原文；取不到返回 None（不报错，交给网络后端）。"""
    mirror = src.get("local_mirror")
    if not mirror:
        return None
    repo = mirror if os.path.isabs(mirror) else os.path.join(REPO_ROOT, mirror)
    if not os.path.isdir(os.path.join(repo, ".git")):
        return None
    spec = "%s:%s" % (src["revision"], src["path"])
    try:
        # 走 git 对象库而不是工作树：工作树可能已 checkout 到别的 revision，
        # 或被本地改动污染；对象库里的 blob 是不可变的。
        return subprocess.check_output(["git", "-C", repo, "cat-file", "-p", spec],
                                       stderr=subprocess.DEVNULL)
    except (subprocess.CalledProcessError, OSError):
        return None


# ── 后端 2：网络 ─────────────────────────────────────────────────────────────
def fetch_from_network(src):
    import urllib.request
    tmpl = src.get("url")
    if not tmpl:
        return None, "lock 未给 url 模板"
    url = tmpl.replace("{revision}", src["revision"]).replace("{path}", src["path"])
    try:
        with urllib.request.urlopen(url, timeout=NET_TIMEOUT) as r:
            return r.read(), url
    except Exception as e:                                      # noqa: BLE001
        return None, "%s（%s: %s）" % (url, type(e).__name__, e)


def fetch_one(src, prefer_network=False):
    """返回 (data, 来源描述, 错误)。任一后端成功即返回。"""
    if not prefer_network:
        data = fetch_from_mirror(src)
        if data is not None:
            return data, "local_mirror %s@%s" % (src.get("local_mirror"),
                                                 src.get("revision_short") or src["revision"][:7]), None
    data, where = fetch_from_network(src)
    if data is not None:
        return data, where, None
    if prefer_network:
        return None, None, "网络取源失败：%s" % where
    return None, None, ("本地镜像不可用且网络取源失败：%s" % where)


def verify(src, data):
    """逐字节校验 sha256（与可选的 size）。返回 (ok, 实际摘要, 说明列表)。"""
    got = hashlib.sha256(data).hexdigest()
    want = src.get("sha256", "")
    notes = []
    if src.get("size") is not None and len(data) != src["size"]:
        notes.append("字节数 %d ≠ lock 声明 %d" % (len(data), src["size"]))
    return got == want, got, notes


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="fetch_locked.py",
        description="按 sources.lock.json 取上游并校验 sha256（不匹配即 exit 1，一个字节都不落盘）")
    ap.add_argument("--lock", default=LOCK_PATH, help="lock 文件路径")
    ap.add_argument("--id", default=None, help="只处理该 id 的条目")
    ap.add_argument("--out", default=DEFAULT_OUT, help="落盘目录（默认 build/upstream/）")
    ap.add_argument("--network", action="store_true",
                    help="强制走网络后端（跳过 local_mirror），用于验证 lock 对公网仍成立")
    ap.add_argument("--check", action="store_true", help="只校验，不落盘")
    args = ap.parse_args(argv)

    lock = load_lock(args.lock)
    srcs = pinned_sources(lock, args.id)
    if not srcs:
        sys.stderr.write("lock 中没有 provenance=pinned 的条目%s；无事可做。\n"
                         % ("（id=%s）" % args.id if args.id else ""))
        return 1 if args.id else 0

    failed = 0
    for src in srcs:
        sid = src.get("id", "<无 id>")
        data, where, err = fetch_one(src, prefer_network=args.network)
        if data is None:
            sys.stderr.write("✗ %s：%s\n" % (sid, err))
            failed += 1
            continue
        ok, got, notes = verify(src, data)
        for n in notes:
            sys.stderr.write("  ! %s：%s\n" % (sid, n))
        if not ok:
            sys.stderr.write(
                "✗ %s sha256 不匹配 —— 拒绝落盘。\n"
                "    来源   : %s\n"
                "    实得   : %s\n"
                "    lock   : %s\n"
                "  上游内容与 lock 声明不符。**不要**改 lock 去迁就它：先查清上游是否改写了历史，\n"
                "  确认无误后再显式更新 revision + sha256 并说明依据。\n"
                % (sid, where, got, src.get("sha256", "<缺失>")))
            failed += 1
            continue
        print("✓ %s  sha256 %s…  (%d 字节)  ← %s" % (sid, got[:16], len(data), where))
        if args.check:
            continue
        dest_dir = os.path.join(args.out, sid)
        if not os.path.isdir(dest_dir):
            os.makedirs(dest_dir)
        dest = os.path.join(dest_dir, os.path.basename(src["path"]))
        # 先写同目录临时文件再 replace：中途被杀不会留下半截的「已校验」产物。
        tmp = dest + ".%d.tmp" % os.getpid()
        try:
            with open(tmp, "wb") as f:
                f.write(data)
            os.replace(tmp, dest)
        finally:
            if os.path.exists(tmp):
                os.remove(tmp)
        print("    → %s" % os.path.relpath(dest, REPO_ROOT))

    if failed:
        sys.stderr.write("\n%d/%d 个条目校验失败。\n" % (failed, len(srcs)))
        return 1
    print("\n%d/%d 个 pinned 条目全部校验通过。" % (len(srcs), len(srcs)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
