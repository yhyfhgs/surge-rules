"""Strict parser for the rule-set calls emitted by the routing manifest.

The supported logical form is a positive RULE-SET minus named RULE-SETs.
Reject any other logical expression instead of silently dropping its policy.
"""
from pathlib import Path
from urllib.parse import urlparse


def split_fields(text):
    fields, start, depth, quote = [], 0, 0, None
    for i, char in enumerate(text):
        if quote:
            if char == quote:
                quote = None
        elif char in "\"'":
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth < 0:
                raise ValueError("unbalanced logical rule")
        elif char == "," and depth == 0:
            fields.append(text[start:i].strip())
            start = i + 1
    if depth or quote:
        raise ValueError("unbalanced logical rule or quote")
    fields.append(text[start:].strip())
    return fields


def unwrap(text):
    if not (text.startswith("(") and text.endswith(")")):
        raise ValueError("logical operand requires parentheses")
    return text[1:-1]


def list_name(ref):
    return Path(urlparse(ref).path).name


def parse_ruleset_call(text):
    """Return (ref, policy, modifiers, exclusions), or None for a leaf rule."""
    parts = split_fields(text)
    kind = parts[0].upper()
    if kind == "RULE-SET":
        if len(parts) < 3 or not all(parts[:3]):
            raise ValueError("RULE-SET requires a reference and policy")
        return parts[1], parts[2], tuple(parts[3:]), ()
    if kind not in {"AND", "OR", "NOT"}:
        return None
    if kind != "AND" or len(parts) not in (3, 4):
        raise ValueError("unsupported logical call; expected RULE-SET with exclusions")
    operands = split_fields(unwrap(parts[1]))
    positive = split_fields(unwrap(operands[0]))
    if len(positive) < 2 or positive[0] != "RULE-SET":
        raise ValueError("logical positive operand must be RULE-SET")
    exclusions = []
    for operand in operands[1:]:
        negative = split_fields(unwrap(operand))
        if len(negative) != 2 or negative[0] != "NOT":
            raise ValueError("logical exclusions must use NOT")
        leaf = split_fields(unwrap(unwrap(negative[1])))
        if len(leaf) != 2 or leaf[0] != "RULE-SET":
            raise ValueError("logical exclusion must be a plain RULE-SET")
        exclusions.append(leaf[1])
    if not exclusions or len(set(exclusions)) != len(exclusions):
        raise ValueError("logical exclusions must be nonempty and unique")
    if positive[1] in exclusions:
        raise ValueError("a rule-set cannot exclude itself")
    modifiers = tuple(positive[2:]) + tuple(parts[3:])
    return positive[1], parts[2], modifiers, tuple(exclusions)


def render_call(entry, reference, clash=False):
    mods = ["no-resolve"] if entry.get("no_resolve") else []
    if not clash and entry.get("extended_matching"):
        mods.append("extended-matching")
    ref = reference(entry["name"])
    if not entry.get("exclude_rulesets"):
        return ",".join(["RULE-SET", ref, entry["policy"]] + mods)
    positive = ",".join(["RULE-SET", ref] + mods)
    operands = ["(" + positive + ")"] + [
        "(NOT,((RULE-SET," + reference(name) + ")))"
        for name in entry["exclude_rulesets"]
    ]
    return "AND,(" + ",".join(operands) + ")," + entry["policy"]
