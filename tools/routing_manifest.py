"""Load and validate the canonical routing manifest."""

import json
import os
import re


_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9]*$")
_ROOT_FIELDS = {"version", "rulesets"}
_RULESET_FIELDS = {"name", "policy", "extended_matching", "no_resolve"}


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
    missing_root = sorted(_ROOT_FIELDS - set(data))
    if unknown_root or missing_root:
        raise ValueError("routing manifest root fields invalid: missing=%s unknown=%s"
                         % (missing_root, unknown_root))
    if type(data["version"]) is not int or data["version"] != 1:
        raise ValueError("unsupported routing manifest version %r" % data["version"])
    if not isinstance(data["rulesets"], list) or not data["rulesets"]:
        raise ValueError("routing manifest rulesets must be a non-empty list")

    entries = []
    seen = {}
    for position, raw in enumerate(data["rulesets"], 1):
        if not isinstance(raw, dict):
            raise ValueError("routing manifest rulesets[%d] must be an object" % (position - 1))
        unknown = sorted(set(raw) - _RULESET_FIELDS)
        missing = sorted({"name", "policy"} - set(raw))
        if unknown or missing:
            raise ValueError("routing manifest rulesets[%d] fields invalid: missing=%s unknown=%s"
                             % (position - 1, missing, unknown))

        name = raw["name"]
        policy = raw["policy"]
        if not isinstance(name, str) or not _NAME_RE.fullmatch(name):
            raise ValueError("routing manifest rulesets[%d].name is invalid: %r"
                             % (position - 1, name))
        if name in seen:
            raise ValueError("duplicate routing ruleset %r at positions %d and %d"
                             % (name, seen[name], position))
        if (not isinstance(policy, str) or not policy or policy != policy.strip()
                or any(char in policy for char in ",\r\n")):
            raise ValueError("routing manifest policy for %s is invalid: %r" % (name, policy))
        for flag in ("extended_matching", "no_resolve"):
            if flag in raw and not isinstance(raw[flag], bool):
                raise ValueError("routing manifest %s.%s must be boolean" % (name, flag))
        seen[name] = position
        entries.append(dict(raw))

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

    return entries
