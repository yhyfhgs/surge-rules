"""Load and validate the canonical routing manifest."""

import json
import os
import re


_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9]*$")
_ROOT_FIELDS = {"version", "rulesets", "system", "final"}
_RULESET_FIELDS = {"name", "policy", "extended_matching", "no_resolve", "section", "kind", "exclude_rulesets"}
_REQUIRED_RULESET_FIELDS = {"name", "policy", "section"}


class Routing(list):
    def __init__(self, version=1, system=None, final=None):
        super().__init__()
        self.version = version
        self.system = system
        self.final = final


def _reject_duplicate_keys(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError("duplicate JSON key %r" % key)
        obj[key] = value
    return obj


def _read_json(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f, object_pairs_hook=_reject_duplicate_keys)
    except (OSError, ValueError) as exc:
        raise ValueError("invalid routing manifest %s: %s" % (path, exc)) from exc


def load_routing_manifest(path, rules_dir=None):
    """Return validated ruleset entries, optionally checking lists/*.list bijection."""
    data = _read_json(path)
    if not isinstance(data, dict):
        raise ValueError("routing manifest root must be an object")
    unknown_root = sorted(set(data) - _ROOT_FIELDS)
    missing_root = sorted({"version", "rulesets"} - set(data))
    if unknown_root or missing_root:
        raise ValueError("routing manifest root fields invalid: missing=%s unknown=%s"
                         % (missing_root, unknown_root))
    if type(data["version"]) is not int or data["version"] not in (1, 2):
        raise ValueError("unsupported routing manifest version %r" % data["version"])
    if not isinstance(data["rulesets"], list) or not data["rulesets"]:
        raise ValueError("routing manifest rulesets must be a non-empty list")

    entries = Routing(version=data["version"], system=data.get("system"), final=data.get("final"))
    seen = {}
    for position, raw in enumerate(data["rulesets"], 1):
        if not isinstance(raw, dict):
            raise ValueError("routing manifest rulesets[%d] must be an object" % (position - 1))
        unknown = sorted(set(raw) - _RULESET_FIELDS)
        missing = sorted(_REQUIRED_RULESET_FIELDS - set(raw))
        if unknown or missing:
            raise ValueError("routing manifest rulesets[%d] fields invalid: missing=%s unknown=%s"
                             % (position - 1, missing, unknown))

        name = raw["name"]
        policy = raw["policy"]
        section = raw["section"]
        if not isinstance(name, str) or not _NAME_RE.fullmatch(name):
            raise ValueError("routing manifest rulesets[%d].name is invalid: %r"
                             % (position - 1, name))
        if name in seen:
            raise ValueError("duplicate routing ruleset %r at positions %d and %d"
                             % (name, seen[name], position))
        if (not isinstance(policy, str) or not policy or policy != policy.strip()
                or any(char in policy for char in ",\r\n")):
            raise ValueError("routing manifest policy for %s is invalid: %r" % (name, policy))
        if (not isinstance(section, str) or not section or section != section.strip()
                or any(char in section for char in "\r\n")):
            raise ValueError("routing manifest section for %s is invalid: %r" % (name, section))
        for flag in ("extended_matching", "no_resolve"):
            if flag in raw and not isinstance(raw[flag], bool):
                raise ValueError("routing manifest %s.%s must be boolean" % (name, flag))
        if data["version"] == 2:
            if raw.get("kind") not in ("domain", "ip"):
                raise ValueError("v2 rulesets require domain/ip kind: " + name)
            exclusions = raw.get("exclude_rulesets", [])
            if (not isinstance(exclusions, list) or
                    any(not isinstance(n, str) for n in exclusions) or
                    len(set(exclusions)) != len(exclusions) or name in exclusions):
                raise ValueError("invalid exclusions: " + name)
            if exclusions and raw["kind"] != "ip":
                raise ValueError("only IP rulesets may have exclusions")
        seen[name] = position
        entries.append(dict(raw))

    # Sections are rendered as one comment per switch, so a section must occupy a
    # single contiguous run; a reappearing name would emit two headers for it.
    runs = []
    for entry in entries:
        if not runs or runs[-1] != entry["section"]:
            runs.append(entry["section"])
    repeated = sorted({name for name in runs if runs.count(name) > 1})
    if repeated:
        raise ValueError("routing manifest sections must be contiguous: %s" % repeated)

    if data["version"] == 2:
        by_name = {e["name"]: e for e in entries}
        reached_ip = False
        for entry in entries:
            if entry["kind"] == "ip":
                reached_ip = True
            elif reached_ip:
                raise ValueError("domain ruleset after IP boundary: " + entry["name"])
            for excluded in entry.get("exclude_rulesets", []):
                target = by_name.get(excluded)
                if (not target or target["kind"] != "ip" or target["policy"] != "DIRECT"
                        or target.get("exclude_rulesets")):
                    raise ValueError("exclusions require an unfiltered DIRECT IP owner: " + excluded)
        if entries.system is not None:
            if (set(entries.system) != {"before", "policy"} or
                    entries.system["before"] not in by_name or
                    by_name[entries.system["before"]]["kind"] != "domain" or
                    entries.system["policy"] != "DIRECT"):
                raise ValueError("invalid SYSTEM placement")
        if (not isinstance(entries.final, dict) or
                set(entries.final) != {"policy", "dns_failed"} or
                not isinstance(entries.final["policy"], str) or not entries.final["policy"].strip() or
                any(c in entries.final["policy"] for c in ",\r\n") or
                type(entries.final["dns_failed"]) is not bool):
            raise ValueError("invalid FINAL metadata")

    if rules_dir is not None:
        if not os.path.isdir(rules_dir):
            raise ValueError("rules directory does not exist: %s" % rules_dir)
        file_names = {
            name[:-5]
            for name in os.listdir(rules_dir)
            if name.endswith(".list") and os.path.isfile(os.path.join(rules_dir, name))
        }
        manifest_names = set(seen)
        missing_files = sorted(manifest_names - file_names)
        missing_entries = sorted(file_names - manifest_names)
        if missing_files or missing_entries:
            raise ValueError("routing manifest/list mismatch: missing files=%s missing entries=%s"
                             % (missing_files, missing_entries))

        if data["version"] == 2:
            domain_types = {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-WILDCARD", "DOMAIN-KEYWORD"}
            ip_types = {"IP-CIDR", "IP-CIDR6", "IP-ASN", "GEOIP"}
            types_by_name = {}
            for entry in entries:
                observed_types = set()
                allowed = domain_types if entry["kind"] == "domain" else ip_types
                with open(os.path.join(rules_dir, entry["name"] + ".list"), encoding="utf-8") as handle:
                    count = 0
                    for line in handle:
                        text = line.strip()
                        if not text or text.startswith(("#", ";", "//")):
                            continue
                        if text.split(",", 1)[0] not in allowed:
                            raise ValueError("wrong rule kind in " + entry["name"])
                        observed_types.add(text.split(",", 1)[0])
                        count += 1
                    types_by_name[entry["name"]] = observed_types
                    if not count:
                        raise ValueError("empty ruleset: " + entry["name"])
            for entry in entries:
                for target in entry.get("exclude_rulesets", []):
                    if types_by_name[target] - {"IP-CIDR", "IP-CIDR6"}:
                        raise ValueError("exclusion targets must contain only CIDRs: " + target)
    return entries
