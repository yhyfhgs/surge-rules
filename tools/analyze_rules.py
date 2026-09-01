#!/usr/bin/env python3
"""Extract all rules and derive containment, overlap, and order constraints."""

from __future__ import annotations

import argparse
import bisect
import hashlib
import ipaddress
import json
import re
from collections import Counter, defaultdict, deque
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.parse import urlparse


DOMAIN_TYPES = {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-WILDCARD"}
CIDR_TYPES = {"IP-CIDR", "IP-CIDR6"}
SELECTOR_TYPES = {"IP-ASN", "IP-ASN6", "GEOIP", "IP-CIDR-SET"}
OTHER_TYPES = {
    "AND", "OR", "NOT", "PROCESS-NAME", "USER-AGENT", "URL-REGEX",
    "SRC-IP", "SRC-PORT", "DEST-PORT", "PROTOCOL", "IN-PORT", "SCRIPT",
    "SUBNET", "CELLULAR-RADIO", "DEVICE-NAME",
}


@dataclass(frozen=True)
class Ref:
    name: str
    policy: str
    rank: int
    line: int


@dataclass(frozen=True)
class Rule:
    id: str
    source: str
    line: int
    type: str
    value: str
    norm: str
    modifiers: tuple[str, ...]
    family: str
    policy: str | None
    list_rank: int | None
    global_rank: int | None
    registrable: str | None


class PSL:
    def __init__(self, path: Path):
        self.exact, self.wild, self.exceptions = set(), set(), set()
        for raw in path.read_text(encoding="utf-8").splitlines():
            value = raw.strip()
            if not value or value.startswith("//"):
                continue
            if value.startswith("!"):
                self.exceptions.add(self.labels(value[1:]))
            elif value.startswith("*."):
                self.wild.add(self.labels(value[2:]))
            else:
                self.exact.add(self.labels(value))
        self.boundary_ancestors = set()
        for labels in self.exact:
            for start in range(1, len(labels)):
                self.boundary_ancestors.add(".".join(labels[start:]))
        for labels in self.wild:
            for start in range(len(labels)):
                self.boundary_ancestors.add(".".join(labels[start:]))

    @staticmethod
    def labels(value: str) -> tuple[str, ...]:
        return tuple(part.encode("idna").decode("ascii")
                     for part in value.lower().strip(".").split("."))

    def registrable(self, value: str) -> str | None:
        labels = self.labels(value)
        matches, exceptions = [1], []
        for start in range(len(labels)):
            tail = labels[start:]
            if tail in self.exceptions:
                exceptions.append(len(tail) - 1)
            if tail in self.exact:
                matches.append(len(tail))
            if start + 1 < len(labels) and labels[start + 1:] in self.wild:
                matches.append(len(tail))
        suffix_len = max(exceptions) if exceptions else max(matches)
        if len(labels) <= suffix_len:
            return None
        return ".".join(labels[-suffix_len - 1:])


def strip_comment(raw: str) -> str:
    text = raw.strip()
    if not text or text.startswith(("#", ";", "//")):
        return ""
    if text.upper().startswith("URL-REGEX,"):
        return text
    index = text.find(" #")
    return text[:index].strip() if index >= 0 else text


def parse_refs(conf: Path) -> list[Ref]:
    refs, in_rules = [], False
    for lineno, raw in enumerate(conf.read_text(encoding="utf-8").splitlines(), 1):
        text = raw.strip()
        if text.startswith("[") and text.endswith("]"):
            in_rules = text.casefold() == "[rule]"
            continue
        if not in_rules:
            continue
        text = strip_comment(raw)
        if not text:
            continue
        parts = [part.strip() for part in text.split(",")]
        if parts[0].upper() != "RULE-SET" or len(parts) < 3:
            continue
        parsed = urlparse(parts[1])
        name = Path(parsed.path).name
        if parsed.scheme in ("http", "https") and name.endswith(".list"):
            refs.append(Ref(name, parts[2], len(refs), lineno))
    duplicates = [name for name, count in Counter(r.name for r in refs).items()
                  if count > 1]
    if duplicates:
        raise ValueError("duplicate RULE-SET references: " + ", ".join(duplicates))
    return refs


def family(rule_type: str) -> str:
    if rule_type in DOMAIN_TYPES:
        return "domain"
    if rule_type in CIDR_TYPES | SELECTOR_TYPES:
        return "ip"
    if rule_type in OTHER_TYPES:
        return "other"
    raise ValueError(f"unsupported rule type {rule_type}")


def normalize(rule_type: str, value: str) -> str:
    if rule_type in DOMAIN_TYPES:
        value = value.lower().rstrip(".")
        return value.lstrip(".") if rule_type == "DOMAIN-SUFFIX" else value
    if rule_type in CIDR_TYPES:
        return str(ipaddress.ip_network(value, strict=True))
    if rule_type in ("IP-ASN", "IP-ASN6"):
        return value.lower().removeprefix("as")
    return value.upper() if rule_type == "GEOIP" else value


def extract(rules_dir: Path, refs: list[Ref], psl: PSL) -> list[Rule]:
    by_name = {ref.name: ref for ref in refs}
    files = sorted(rules_dir.glob("*.list"))
    present = {path.name for path in files}
    missing = sorted(set(by_name) - present)
    if missing:
        raise FileNotFoundError("missing referenced lists: " + ", ".join(missing))
    ordered = [rules_dir / ref.name for ref in refs]
    ordered += [path for path in files if path.name not in by_name]
    rules, global_rank = [], 0
    for path in ordered:
        ref = by_name.get(path.name)
        for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            text = strip_comment(raw)
            if not text:
                continue
            parts = [part.strip() for part in text.split(",")]
            if len(parts) < 2 or not parts[1]:
                raise ValueError(f"{path}:{lineno}: malformed rule")
            rule_type, value = parts[0].upper(), parts[1]
            norm = normalize(rule_type, value)
            if rule_type in {"DOMAIN", "DOMAIN-SUFFIX"}:
                reg = psl.registrable(norm)
            elif rule_type == "DOMAIN-WILDCARD":
                tail = wildcard_fixed_suffix(norm)
                reg = psl.registrable(tail) if tail else None
            else:
                reg = None
            rules.append(Rule(
                f"{path.name}:{lineno}", path.name, lineno, rule_type, value, norm,
                tuple(part.lower() for part in parts[2:]), family(rule_type),
                ref.policy if ref else None, ref.rank if ref else None,
                global_rank if ref else None, reg,
            ))
            if ref:
                global_rank += 1
    return rules


def wildcard_regex(pattern: str) -> re.Pattern[str]:
    body = "".join(".*" if char == "*" else "." if char == "?"
                   else re.escape(char) for char in pattern)
    return re.compile("^" + body + "$")


def wildcard_fixed_suffix(pattern: str) -> str | None:
    last_meta = max(pattern.rfind("*"), pattern.rfind("?"))
    tail = pattern[last_meta + 1:]
    return tail[1:] if tail.startswith(".") and len(tail) > 1 else None


def glob_alphabet(*patterns: str) -> tuple[str, ...]:
    literals = {char for pattern in patterns for char in pattern if char not in "*?"}
    alphabet = set(literals)
    other = next((char for char in "abcdefghijklmnopqrstuvwxyz0123456789-._"
                  if char not in literals), None)
    if other is not None:
        alphabet.add(other)
    return tuple(sorted(alphabet))


def glob_epsilon_closure(pattern: str, states) -> frozenset[int]:
    closure, pending = set(states), list(states)
    while pending:
        state = pending.pop()
        if state < len(pattern) and pattern[state] == "*" and state + 1 not in closure:
            closure.add(state + 1)
            pending.append(state + 1)
    return frozenset(closure)


def glob_step(pattern: str, states: frozenset[int], char: str) -> frozenset[int]:
    target = set()
    for state in states:
        if state == len(pattern):
            continue
        token = pattern[state]
        if token == "*":
            target.add(state)
        elif token == "?" or token == char:
            target.add(state + 1)
    return glob_epsilon_closure(pattern, target)


def glob_overlap_witness(left: str, right: str) -> str | None:
    alphabet = glob_alphabet(left, right)
    initial = (glob_epsilon_closure(left, {0}), glob_epsilon_closure(right, {0}))
    pending, previous = deque([initial]), {initial: None}
    while pending:
        state = pending.popleft()
        if len(left) in state[0] and len(right) in state[1]:
            chars = []
            while previous[state] is not None:
                state, char = previous[state]
                chars.append(char)
            return "".join(reversed(chars))
        for char in alphabet:
            next_left = glob_step(left, state[0], char)
            next_right = glob_step(right, state[1], char)
            if not next_left or not next_right:
                continue
            target = next_left, next_right
            if target not in previous:
                previous[target] = state, char
                pending.append(target)
    return None


def glob_covers(cover: str, target: str) -> bool:
    alphabet = glob_alphabet(cover, target)
    initial = (glob_epsilon_closure(target, {0}), glob_epsilon_closure(cover, {0}))
    pending, visited = deque([initial]), {initial}
    while pending:
        target_states, cover_states = pending.popleft()
        if len(target) in target_states and len(cover) not in cover_states:
            return False
        for char in alphabet:
            next_target = glob_step(target, target_states, char)
            if not next_target:
                continue
            state = next_target, glob_step(cover, cover_states, char)
            if state not in visited:
                visited.add(state)
                pending.append(state)
    return True


class Relations:
    def __init__(self, rules: list[Rule], expansions=None):
        self.rules = rules
        self.by_id = {rule.id: rule for rule in rules}
        self.expansions = expansions or {}
        self.rows, self.keys = [], set()
        self.keyword_intersections = defaultdict(int)
        self.wildcard_intersections = defaultdict(int)
        self.suffix_keyword_intersections = defaultdict(int)
        self.suffix_wildcard_intersections = defaultdict(int)
        self.aggregate_rows = []

    def add(self, kind: str, left: Rule, right: Rule, proof: str):
        if left.id == right.id:
            return
        if kind == "equivalent" and left.id > right.id:
            left, right = right, left
        key = kind, left.id, right.id
        if key in self.keys:
            return
        self.keys.add(key)
        self.rows.append({
            "relation": kind, "family": left.family,
            "left": left.id, "right": right.id, "proof": proof,
        })

    def build_domains(self):
        rules = [rule for rule in self.rules if rule.family == "domain"]
        suffixes, exact = defaultdict(list), defaultdict(list)
        keywords, wildcards = [], []
        for rule in rules:
            if rule.type == "DOMAIN-SUFFIX":
                suffixes[rule.norm].append(rule)
            elif rule.type == "DOMAIN":
                exact[rule.norm].append(rule)
            elif rule.type == "DOMAIN-KEYWORD":
                keywords.append(rule)
            else:
                wildcards.append(rule)
        for group in exact.values():
            self.equivalent_group(group, "same exact host")
        literals = [rule for rule in rules if rule.type in {"DOMAIN", "DOMAIN-SUFFIX"}]
        for target in literals:
            labels = target.norm.split(".")
            for start in range(len(labels)):
                candidate = ".".join(labels[start:])
                for coverer in suffixes.get(candidate, ()):
                    if target.type == "DOMAIN-SUFFIX" and candidate == target.norm:
                        self.add("equivalent", coverer, target, "same suffix language")
                    else:
                        self.add("covers", coverer, target, "suffix containment")
        for keyword in keywords:
            for target in literals:
                if keyword.norm in target.norm:
                    self.add("covers", keyword, target, "keyword in literal value")
        keyword_groups = defaultdict(list)
        for keyword in keywords:
            keyword_groups[keyword.norm].append(keyword)
        for group in keyword_groups.values():
            self.equivalent_group(group, "same keyword language")
        for index, left in enumerate(keywords):
            for right in keywords[index + 1:]:
                if left.norm == right.norm:
                    continue
                if left.norm in right.norm:
                    self.add("covers", left, right, "keyword containment")
                elif right.norm in left.norm:
                    self.add("covers", right, left, "keyword containment")
                else:
                    self.add("overlaps", left, right,
                             f"shared witness {left.norm + right.norm}")
        for wildcard in wildcards:
            regex = wildcard_regex(wildcard.norm)
            covered_by = set()
            fixed_suffix = wildcard_fixed_suffix(wildcard.norm)
            if fixed_suffix:
                labels = fixed_suffix.split(".")
                for start in range(len(labels)):
                    for suffix in suffixes.get(".".join(labels[start:]), ()):
                        self.add("covers", suffix, wildcard, "fixed wildcard suffix")
                        covered_by.add(suffix.id)
            for target in literals:
                if regex.fullmatch(target.norm):
                    kind = "covers" if target.type == "DOMAIN" else "overlaps"
                    self.add(kind, wildcard, target, f"shared witness {target.norm}")
        for keyword in keywords:
            keyword_glob = f"*{keyword.norm}*"
            for wildcard in wildcards:
                witness = glob_overlap_witness(keyword_glob, wildcard.norm)
                if witness is None:
                    continue
                keyword_covers = glob_covers(keyword_glob, wildcard.norm)
                wildcard_covers = glob_covers(wildcard.norm, keyword_glob)
                if keyword_covers and wildcard_covers:
                    self.add("equivalent", keyword, wildcard, "same glob language")
                elif keyword_covers:
                    self.add("covers", keyword, wildcard, "glob-language containment")
                elif wildcard_covers:
                    self.add("covers", wildcard, keyword, "glob-language containment")
                else:
                    self.add("overlaps", keyword, wildcard, f"generated witness {witness}")
        for index, left in enumerate(wildcards):
            for right in wildcards[index + 1:]:
                witness = glob_overlap_witness(left.norm, right.norm)
                if witness is None:
                    continue
                left_covers = glob_covers(left.norm, right.norm)
                right_covers = glob_covers(right.norm, left.norm)
                if left_covers and right_covers:
                    self.add("equivalent", left, right, "same glob language")
                elif left_covers:
                    self.add("covers", left, right, "glob-language containment")
                elif right_covers:
                    self.add("covers", right, left, "glob-language containment")
                else:
                    self.add("overlaps", left, right, f"generated witness {witness}")
        self.build_suffix_aggregates(suffixes, keywords, wildcards)

    def build_suffix_aggregates(self, suffixes, keywords, wildcards):
        suffix_groups = sorted((value[::-1], group) for value, group in suffixes.items())
        suffix_rule_count = sum(len(group) for _, group in suffix_groups)
        all_suffix_buckets = Counter(
            (suffix.source, suffix.policy, suffix.list_rank)
            for _, group in suffix_groups for suffix in group
        )
        for keyword in keywords:
            self.keyword_intersections[keyword.id] = suffix_rule_count
            self.add_suffix_aggregate(
                keyword, all_suffix_buckets,
                "every suffix language admits a subdomain containing the keyword")
        for _, group in suffix_groups:
            for suffix in group:
                self.suffix_keyword_intersections[suffix.id] = len(keywords)

        for wildcard in wildcards:
            pattern = wildcard.norm[::-1]
            transition_cache = {}

            def step(states, char):
                key = states, char
                if key not in transition_cache:
                    transition_cache[key] = glob_step(pattern, states, char)
                return transition_cache[key]

            previous = ""
            states = [glob_epsilon_closure(pattern, {0})]
            pair_count = 0
            buckets = Counter()
            for reversed_suffix, group in suffix_groups:
                limit = min(len(previous), len(reversed_suffix))
                common = 0
                while common < limit and previous[common] == reversed_suffix[common]:
                    common += 1
                states = states[:common + 1]
                current = states[-1]
                for char in reversed_suffix[common:]:
                    current = step(current, char)
                    states.append(current)
                after_separator = step(current, ".")
                intersects = (len(pattern) in current
                              or any(state < len(pattern) for state in after_separator))
                if intersects:
                    pair_count += len(group)
                    for suffix in group:
                        self.suffix_wildcard_intersections[suffix.id] += 1
                        buckets[(suffix.source, suffix.policy, suffix.list_rank)] += 1
                previous = reversed_suffix
            self.wildcard_intersections[wildcard.id] = pair_count
            self.add_suffix_aggregate(
                wildcard, buckets, "exact reversed-glob/suffix-language automaton")

    def add_suffix_aggregate(self, left, buckets, proof):
        for (source, policy, rank), pair_count in sorted(
                buckets.items(), key=lambda item: (item[0][0], item[0][1] or "")):
            same_policy = left.policy == policy
            if left.list_rank is None or rank is None:
                precedence = "unreferenced"
            elif left.source == source:
                precedence = "same-list"
            elif left.list_rank < rank:
                precedence = "left-before-right"
            else:
                precedence = "right-before-left"
            self.aggregate_rows.append({
                "relation": "intersects", "family": "domain",
                "left": left.id, "left_source": left.source,
                "left_policy": left.policy, "right_type": "DOMAIN-SUFFIX",
                "right_source": source, "right_policy": policy,
                "pair_count": pair_count, "precedence": precedence,
                "routing_effect": ("same-policy-intersection" if same_policy
                                   else "split-policy-intersection"),
                "proof": proof,
            })

    def build_ips(self):
        cidrs = [rule for rule in self.rules if rule.type in CIDR_TYPES]
        network_rules, parsed = defaultdict(list), {}
        for rule in cidrs:
            network = ipaddress.ip_network(rule.norm, strict=True)
            parsed[rule.id] = network
            network_rules[(network.version, network.prefixlen,
                           int(network.network_address))].append(rule)
        for target in cidrs:
            network = parsed[target.id]
            for prefix in range(network.prefixlen + 1):
                parent = network.supernet(new_prefix=prefix)
                group = network_rules.get((network.version, prefix,
                                           int(parent.network_address)), ())
                for coverer in group:
                    kind = "equivalent" if prefix == network.prefixlen else "covers"
                    self.add(kind, coverer, target, "CIDR containment")
        selectors = [rule for rule in self.rules if rule.type in SELECTOR_TYPES]
        signatures = defaultdict(list)
        for rule in selectors:
            signatures[(rule.type, rule.norm)].append(rule)
        for group in signatures.values():
            self.equivalent_group(group, "same selector")
        expanded = [rule for rule in selectors if rule.id in self.expansions]
        for selector in expanded:
            intervals = self.expansions[selector.id]
            for cidr in cidrs:
                relation = selector_cidr_relation(intervals, parsed[cidr.id])
                if relation == "left-covers":
                    self.add("covers", selector, cidr, "MMDB selector contains CIDR")
                elif relation == "right-covers":
                    self.add("covers", cidr, selector, "CIDR contains MMDB selector")
                elif relation == "equivalent":
                    self.add("equivalent", selector, cidr, "same MMDB address set")
                elif relation == "overlaps":
                    self.add("overlaps", selector, cidr, "MMDB/CIDR intersection")
        for index, left in enumerate(expanded):
            for right in expanded[index + 1:]:
                if left.type == right.type and left.norm != right.norm:
                    continue
                relation = interval_relation(self.expansions[left.id], self.expansions[right.id])
                if relation == "left-covers":
                    self.add("covers", left, right, "MMDB set containment")
                elif relation == "right-covers":
                    self.add("covers", right, left, "MMDB set containment")
                elif relation == "equivalent":
                    self.add("equivalent", left, right, "same MMDB address set")
                elif relation == "overlaps":
                    self.add("overlaps", left, right, "MMDB set intersection")

    def equivalent_group(self, group, proof):
        for index, left in enumerate(group):
            for right in group[index + 1:]:
                self.add("equivalent", left, right, proof)


def merge_networks(networks) -> dict[int, list[tuple[int, int]]]:
    values = defaultdict(list)
    for network in networks:
        values[network.version].append((int(network.network_address),
                                        int(network.broadcast_address)))
    result = {}
    for version, items in values.items():
        merged = []
        for start, end in sorted(items):
            if merged and start <= merged[-1][1] + 1:
                merged[-1] = merged[-1][0], max(merged[-1][1], end)
            else:
                merged.append((start, end))
        result[version] = merged
    return result


def intervals_contain(left, right) -> bool:
    for version, wanted in right.items():
        available = left.get(version, [])
        ceiling = (1 << (32 if version == 4 else 128)) - 1
        for start, end in wanted:
            index = bisect.bisect_right(available, (start, ceiling)) - 1
            if index < 0 or available[index][1] < end:
                return False
    return True


def intervals_intersect(left, right) -> bool:
    for version in set(left) & set(right):
        a, b = left[version], right[version]
        small, large = (a, b) if len(a) <= len(b) else (b, a)
        ceiling = (1 << (32 if version == 4 else 128)) - 1
        for start, end in small:
            index = bisect.bisect_right(large, (end, ceiling)) - 1
            if index >= 0 and large[index][1] >= start:
                return True
    return False


def interval_relation(left, right) -> str:
    left_covers, right_covers = intervals_contain(left, right), intervals_contain(right, left)
    if left_covers and right_covers:
        return "equivalent"
    if left_covers:
        return "left-covers"
    if right_covers:
        return "right-covers"
    return "overlaps" if intervals_intersect(left, right) else "disjoint"


def selector_cidr_relation(selector, network) -> str:
    intervals = selector.get(network.version, [])
    if not intervals:
        return "disjoint"
    start, end = int(network.network_address), int(network.broadcast_address)
    ceiling = (1 << network.max_prefixlen) - 1
    index = bisect.bisect_right(intervals, (start, ceiling)) - 1
    selector_covers = index >= 0 and intervals[index][1] >= end
    versions = [version for version, values in selector.items() if values]
    cidr_covers = (versions == [network.version]
                   and start <= intervals[0][0] and end >= intervals[-1][1])
    if selector_covers and cidr_covers:
        return "equivalent"
    if selector_covers:
        return "left-covers"
    if cidr_covers:
        return "right-covers"
    next_index = bisect.bisect_left(intervals, (start, -1))
    if next_index < len(intervals) and intervals[next_index][0] <= end:
        return "overlaps"
    if next_index and intervals[next_index - 1][1] >= start:
        return "overlaps"
    return "disjoint"


def load_mmdb(rules: list[Rule], country_db: Path | None, asn_db: Path | None):
    if not country_db and not asn_db:
        return {}, {}
    try:
        import maxminddb
    except ImportError as exc:
        raise RuntimeError("install maxminddb to use --country-db/--asn-db") from exc
    wanted_countries = {r.norm for r in rules if r.type == "GEOIP"}
    wanted_asns = {int(r.norm) for r in rules if r.type in {"IP-ASN", "IP-ASN6"}}
    countries, asns, metadata = defaultdict(list), defaultdict(list), {}
    if country_db:
        with maxminddb.open_database(str(country_db), mode=maxminddb.MODE_MMAP_EXT) as reader:
            meta = reader.metadata()
            metadata["country"] = db_meta(country_db, meta.build_epoch)
            for network, record in reader:
                country = record.get("country") or record.get("registered_country") or {}
                code = country.get("iso_code")
                if code in wanted_countries:
                    countries[code].append(network)
    if asn_db:
        with maxminddb.open_database(str(asn_db), mode=maxminddb.MODE_MMAP_EXT) as reader:
            meta = reader.metadata()
            metadata["asn"] = db_meta(asn_db, meta.build_epoch)
            for network, record in reader:
                number = record.get("autonomous_system_number")
                if number in wanted_asns:
                    asns[number].append(network)
    expansions = {}
    for rule in rules:
        if rule.type == "GEOIP" and country_db:
            expansions[rule.id] = merge_networks(countries[rule.norm])
        elif rule.type in {"IP-ASN", "IP-ASN6"} and asn_db:
            expansions[rule.id] = merge_networks(asns[int(rule.norm)])
    return expansions, metadata


def db_meta(path: Path, epoch: int) -> dict:
    return {"path": str(path.resolve()), "build_epoch": epoch,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def effect(row, by_id) -> str:
    left, right = by_id[row["left"]], by_id[row["right"]]
    if left.policy is None or right.policy is None:
        return "unreferenced"
    if row["relation"] == "overlaps":
        return "same-policy-overlap" if left.policy == right.policy else "split-overlap"
    if row["relation"] == "equivalent":
        return "redundant-equivalent" if left.policy == right.policy else "conflicting-equivalent"
    if left.policy == right.policy:
        return "redundant-coverage"
    return "active-shadow" if left.global_rank < right.global_rank else "order-dependent-exception"


def tarjan(nodes, graph):
    serial, stack, indices, low, active, result = 0, [], {}, {}, set(), []

    def visit(node):
        nonlocal serial
        indices[node] = low[node] = serial
        serial += 1
        stack.append(node)
        active.add(node)
        for target in graph.get(node, ()):
            if target not in indices:
                visit(target)
                low[node] = min(low[node], low[target])
            elif target in active:
                low[node] = min(low[node], indices[target])
        if low[node] == indices[node]:
            component = []
            while True:
                item = stack.pop()
                active.remove(item)
                component.append(item)
                if item == node:
                    break
            if len(component) > 1:
                result.append(sorted(component))

    for node in sorted(nodes):
        if node not in indices:
            visit(node)
    return sorted(result, key=lambda group: (-len(group), group))


def diagnose(rules: list[Rule], relation_rows: list[dict]):
    by_id = {rule.id: rule for rule in rules}
    counts, effects, shadowed = defaultdict(Counter), Counter(), defaultdict(list)
    constraints, graph = defaultdict(Counter), defaultdict(set)
    split_apex, split_parent = defaultdict(list), defaultdict(list)
    for row in relation_rows:
        left, right = by_id[row["left"]], by_id[row["right"]]
        counts[left.id][row["relation"]] += 1
        counts[right.id]["covered_by" if row["relation"] == "covers" else row["relation"]] += 1
        row["left_policy"], row["right_policy"] = left.policy, right.policy
        row["routing_effect"] = current = effect(row, by_id)
        effects[current] += 1
        if current in {"active-shadow", "conflicting-equivalent"}:
            shadowed[right.id].append(left.id)
        if (row["relation"] == "covers" and left.policy != right.policy
                and left.policy is not None and right.policy is not None
                and left.source != right.source):
            constraints[(right.source, left.source)][row["family"]] += 1
            graph[right.source].add(left.source)
        if (row["relation"] == "covers" and left.type == "DOMAIN-SUFFIX"
                and left.registrable == left.norm == right.registrable
                and left.norm != right.norm and left.policy != right.policy):
            split_apex[left.id].append(right.id)
        if (row["relation"] == "covers"
                and left.type in {"DOMAIN-SUFFIX", "DOMAIN-WILDCARD", "DOMAIN-KEYWORD"}
                and left.norm != right.norm and left.policy != right.policy
                and left.policy is not None and right.policy is not None
                and right.policy != "REJECT"):
            split_parent[left.id].append(right.id)
    fragmented = defaultdict(list)
    for rule in rules:
        if rule.registrable:
            fragmented[rule.registrable].append(rule)
    fragmented = {name: group for name, group in fragmented.items()
                  if len({rule.policy for rule in group}) > 1}
    cycles = tarjan({rule.source for rule in rules}, graph)
    return (by_id, counts, effects, shadowed, constraints, cycles,
            split_apex, split_parent, fragmented)


def write_jsonl(path: Path, rows):
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def main() -> int:
    repo = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--conf", type=Path, default=repo.parent / "Surge.conf")
    parser.add_argument("--rules", type=Path, default=repo / "lists")
    parser.add_argument("--psl", type=Path, default=repo / "tests/data/public_suffix_list.dat")
    parser.add_argument("--expired", type=Path, default=repo / "config/proxygfw-expired.txt")
    parser.add_argument("--country-db", type=Path)
    parser.add_argument("--asn-db", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--fail-on-shadow", action="store_true")
    args = parser.parse_args()

    refs = parse_refs(args.conf)
    psl = PSL(args.psl)
    rules = extract(args.rules, refs, psl)
    expansions, mmdb_meta = load_mmdb(rules, args.country_db, args.asn_db)
    empty_selectors = [
        rule.id for rule in rules
        if rule.id in expansions and not any(expansions[rule.id].values())
    ]
    relations = Relations(rules, expansions)
    relations.build_domains()
    relations.build_ips()
    (by_id, counts, effects, shadowed, constraints, cycles,
     split_apex, split_parent, fragmented) = diagnose(rules, relations.rows)
    non_security_splits = {
        rule_id: children for rule_id, children in split_apex.items()
        if any(by_id[child].policy != "REJECT" for child in children)
    }

    def ordered_safe(rule_id, children):
        """True when every different-policy child wins by first match.

        A broad parent that sits behind all of its different-policy children is
        an ordered-safe split: the children keep their own policy and the parent
        only restores the fallback for the rest of the subtree. Only a parent
        that precedes a child actually kills it, and that case is already an
        `active-shadow` in `shadowed`.
        """
        parent = by_id[rule_id].global_rank
        return all(by_id[child].global_rank < parent for child in children)

    unsafe_splits = {rule_id: children
                     for rule_id, children in non_security_splits.items()
                     if not ordered_safe(rule_id, children)}
    unsafe_parents = {rule_id: children
                      for rule_id, children in split_parent.items()
                      if not ordered_safe(rule_id, children)}
    expired = {line.strip().lower() for line in args.expired.read_text(encoding="utf-8").splitlines()
               if line.strip() and not line.lstrip().startswith("#")}
    expired_reentries = [rule.id for rule in rules
                         if rule.source == "ProxyGFW.list"
                         and rule.norm.lower() in expired]
    proxygfw_ip = [rule.id for rule in rules
                   if rule.source == "ProxyGFW.list" and rule.family == "ip"]
    proxygfw_psl = [rule.id for rule in rules
                    if rule.source == "ProxyGFW.list"
                    and rule.type == "DOMAIN-SUFFIX"
                    and (psl.registrable(rule.norm) is None
                         or rule.norm in psl.boundary_ancestors)]
    out = args.out
    out.mkdir(parents=True, exist_ok=True)

    rule_rows = []
    for rule in rules:
        row = asdict(rule)
        row["modifiers"] = list(rule.modifiers)
        row["relation_counts"] = dict(sorted(counts[rule.id].items()))
        row["shadowed_by"] = shadowed.get(rule.id, [])
        if rule.type == "DOMAIN-KEYWORD":
            row["aggregate_suffix_intersections"] = relations.keyword_intersections[rule.id]
        elif rule.type == "DOMAIN-WILDCARD":
            row["aggregate_suffix_intersections"] = relations.wildcard_intersections[rule.id]
        elif rule.type == "DOMAIN-SUFFIX":
            row["aggregate_keyword_intersections"] = relations.suffix_keyword_intersections[rule.id]
            row["aggregate_wildcard_intersections"] = relations.suffix_wildcard_intersections[rule.id]
        if rule.type in SELECTOR_TYPES:
            if rule.id in empty_selectors:
                row["selector_analysis"] = "pinned-mmdb-empty"
            else:
                row["selector_analysis"] = ("pinned-mmdb" if rule.id in expansions
                                            else "opaque-no-dataset")
        rule_rows.append(row)
    write_jsonl(out / "rules.jsonl", rule_rows)
    write_jsonl(out / "relationships.jsonl", relations.rows)
    write_jsonl(out / "relationship_aggregates.jsonl", relations.aggregate_rows)
    write_jsonl(out / "split_apex.jsonl", (
        {"broad_rule": rule_id, "registrable_domain": by_id[rule_id].norm,
         "broad_policy": by_id[rule_id].policy, "contained_rules": sorted(children)}
        for rule_id, children in sorted(split_apex.items())
    ))
    write_jsonl(out / "split_parent.jsonl", (
        {"broad_rule": rule_id, "broad_domain": by_id[rule_id].norm,
         "broad_policy": by_id[rule_id].policy, "contained_rules": sorted(children)}
        for rule_id, children in sorted(split_parent.items())
    ))
    write_jsonl(out / "fragmented_domains.jsonl", (
        {"registrable_domain": name,
         "policies": sorted({rule.policy for rule in group if rule.policy is not None}),
         "rules": sorted(rule.id for rule in group)}
        for name, group in sorted(fragmented.items())
    ))
    topology = {
        "constraints": [
            {"before": before, "after": after, "reason_counts": dict(sorted(reason.items()))}
            for (before, after), reason in sorted(constraints.items())
        ],
        "cycles": cycles,
    }
    (out / "topology.json").write_text(
        json.dumps(topology, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8")
    type_counts, family_counts = Counter(r.type for r in rules), Counter(r.family for r in rules)
    summary = {
        "inputs": {
            "conf": str(args.conf.resolve()),
            "conf_sha256": hashlib.sha256(args.conf.read_bytes()).hexdigest(),
            "rules_dir": str(args.rules.resolve()), "mmdb": mmdb_meta,
        },
        "list_order": [asdict(ref) for ref in refs],
        "rules": {"total": len(rules), "by_type": dict(sorted(type_counts.items())),
                  "by_family": dict(sorted(family_counts.items())),
                  "accounted": len(rule_rows)},
        "relations": {"total": len(relations.rows),
                      "by_type": dict(sorted(Counter(r["relation"] for r in relations.rows).items())),
                      "routing_effects": dict(sorted(effects.items())),
                      "aggregate_records": len(relations.aggregate_rows),
                      "aggregate_pairs": sum(row["pair_count"]
                                             for row in relations.aggregate_rows),
                      "aggregate_routing_effects": {
                          current: sum(row["pair_count"] for row in relations.aggregate_rows
                                       if row["routing_effect"] == current)
                          for current in sorted({row["routing_effect"]
                                                 for row in relations.aggregate_rows})
                      }},
        "diagnostics": {"shadowed_or_conflicting_rules": len(shadowed),
                        "expired_proxygfw_reentries": expired_reentries,
                        "proxygfw_ip_rules": proxygfw_ip,
                        "proxygfw_psl_boundaries": proxygfw_psl,
                        "empty_mmdb_selectors": empty_selectors,
                        "split_apex_rules": len(split_apex),
                        "non_security_split_apex": sorted(non_security_splits),
                        "non_security_split_parents": sorted(split_parent),
                        "ordered_safe_split_apex": sorted(
                            set(non_security_splits) - set(unsafe_splits)),
                        "ordered_safe_split_parents": sorted(
                            set(split_parent) - set(unsafe_parents)),
                        "order_unsafe_split_apex": sorted(unsafe_splits),
                        "order_unsafe_split_parents": sorted(unsafe_parents),
                        "fragmented_registrable_domains": len(fragmented),
                        "topology_constraints": len(constraints), "topology_cycles": cycles},
    }
    (out / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    if len(rule_rows) != len(rules):
        return 2
    if args.fail_on_shadow and (shadowed or expired_reentries
                                or proxygfw_ip or proxygfw_psl
                                or empty_selectors or unsafe_splits or unsafe_parents):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
