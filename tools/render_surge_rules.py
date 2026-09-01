#!/usr/bin/env python3
"""Render the canonical routing manifest into an existing Surge profile."""

import argparse
import difflib
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

from routing_manifest import load_routing_manifest  # noqa: E402


BASE_URL = "https://cdn.jsdelivr.net/gh/yhyfhgs/surge-rules@main/lists"


def render_rules(entries):
    """Render the [Rule] block, one ``# <index> <section>`` header per section.

    Sections are the manifest's own grouping (validated contiguous there); the
    index is derived from the order of first appearance so the numbers can never
    drift out of sync with the manifest. The headers are comments, so they change
    nothing about matching: Surge, the analyzer, the audit engine, and the
    scenario engine all drop ``#`` lines before parsing.
    """
    lines = ["[Rule]", "RULE-SET,SYSTEM,DIRECT"]
    section, index = None, -1
    for entry in entries:
        if entry["section"] != section:
            section = entry["section"]
            index += 1
            lines.append("# %d %s" % (index, section))
        parts = ["RULE-SET", "%s/%s.list" % (BASE_URL, entry["name"]), entry["policy"]]
        if entry.get("extended_matching"):
            parts.append("extended-matching")
        if entry.get("no_resolve"):
            parts.append("no-resolve")
        lines.append(",".join(parts))
    lines += [
        "RULE-SET,LAN,DIRECT,no-resolve",
        "GEOIP,CN,DIRECT,no-resolve",
        "FINAL,Final,dns-failed",
    ]
    return "\n".join(lines)


def _rule_section_bounds(profile):
    lines = profile.splitlines()
    starts = [i for i, line in enumerate(lines) if line.strip().casefold() == "[rule]"]
    if len(starts) != 1:
        raise ValueError("profile must contain exactly one [Rule] section")
    start = starts[0]
    end = next((i for i in range(start + 1, len(lines))
                if lines[i].strip().startswith("[") and lines[i].strip().endswith("]")),
               len(lines))
    return lines, start, end


def replace_rule_section(profile, block):
    lines, start, end = _rule_section_bounds(profile)
    new_lines = lines[:start] + block.splitlines() + [""] + lines[end:]
    return "\n".join(new_lines).rstrip() + "\n"


def extract_rule_section(profile):
    """Return the normalized [Rule] section from a Surge profile."""
    lines, start, end = _rule_section_bounds(profile)
    section = lines[start:end]
    while section and not section[-1].strip():
        section.pop()
    return "\n".join(section)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("profile")
    parser.add_argument("output", nargs="?")
    parser.add_argument("--check", action="store_true",
                        help="check the profile [Rule] section without writing a file")
    parser.add_argument("--manifest", default=os.path.join(ROOT, "config", "routing.json"))
    parser.add_argument("--rules-dir", default=os.path.join(ROOT, "lists"))
    args = parser.parse_args()
    if args.check and args.output is not None:
        parser.error("--check accepts only the profile path")
    if not args.check and args.output is None:
        parser.error("the output path is required unless --check is used")
    entries = load_routing_manifest(args.manifest, args.rules_dir)
    with open(args.profile, encoding="utf-8") as handle:
        profile = handle.read()
    block = render_rules(entries)
    if args.check:
        actual = extract_rule_section(profile)
        if actual != block:
            diff = difflib.unified_diff(
                actual.splitlines(True), block.splitlines(True),
                fromfile=args.profile, tofile="config/routing.json [Rule]")
            sys.stderr.write("profile [Rule] differs from config/routing.json:\n")
            sys.stderr.writelines(diff)
            return 1
        print("profile [Rule] matches config/routing.json")
        return 0

    rendered = replace_rule_section(profile, block)
    with open(args.output, "w", encoding="utf-8") as handle:
        handle.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
