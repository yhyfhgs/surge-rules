#!/usr/bin/env python3
"""Small regression checks for topology and ChinaDomain ownership helpers."""

from pathlib import Path
import contextlib
import io
import json
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import analyze_rules  # noqa: E402
from regen_chinadomain import f2_ownership  # noqa: E402


class AnalyzeRulesSelfTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.psl = analyze_rules.PSL(ROOT / "tests/data/public_suffix_list.dat")

    def test_wildcard_intersection_has_exact_witness(self):
        witness = analyze_rules.glob_overlap_witness("*nowtv100.*", "*-adnow.com")
        self.assertEqual(witness, "nowtv100.-adnow.com")
        self.assertTrue(analyze_rules.wildcard_regex("*nowtv100.*").fullmatch(witness))
        self.assertTrue(analyze_rules.wildcard_regex("*-adnow.com").fullmatch(witness))

    def test_glob_inclusion_positive_and_negative(self):
        cover = "assets.*.example.com"
        self.assertTrue(analyze_rules.glob_covers(cover, "assets.cdn.example.com"))
        self.assertFalse(analyze_rules.glob_covers(cover, "cdn.assets.example.com"))

    def test_wildcard_fixed_suffix_and_psl_parent(self):
        self.assertEqual(analyze_rules.wildcard_fixed_suffix("*.kawasaki.jp"),
                         "kawasaki.jp")
        self.assertIn("kawasaki.jp", self.psl.boundary_ancestors)
        self.assertIsNone(self.psl.registrable("foo.kawasaki.jp"))

        with tempfile.TemporaryDirectory(prefix="analyze-rules-selftest-") as tmp:
            rules_dir = Path(tmp)
            (rules_dir / "Owner.list").write_text(
                "DOMAIN-SUFFIX,kawasaki.jp\n", encoding="utf-8")
            (rules_dir / "Wildcard.list").write_text(
                "DOMAIN-WILDCARD,*.kawasaki.jp\n", encoding="utf-8")
            refs = [
                analyze_rules.Ref("Owner.list", "Proxy", 0, 1),
                analyze_rules.Ref("Wildcard.list", "Proxy", 1, 2),
            ]
            rules = analyze_rules.extract(rules_dir, refs, self.psl)
            self.assertEqual(rules[1].registrable, "kawasaki.jp")
            relations = analyze_rules.Relations(rules)
            relations.build_domains()
            self.assertIn(
                {
                    "relation": "covers",
                    "family": "domain",
                    "left": "Owner.list:1",
                    "right": "Wildcard.list:1",
                    "proof": "fixed wildcard suffix",
                },
                relations.rows,
            )

    def test_non_apex_broad_parent_is_reported(self):
        with tempfile.TemporaryDirectory(prefix="split-parent-selftest-") as tmp:
            rules_dir = Path(tmp)
            (rules_dir / "Child.list").write_text(
                "DOMAIN,versioncheck.addons.mozilla.org\n"
                "DOMAIN,cdn.example.net\n"
                "DOMAIN,tracking.example.org\n",
                encoding="utf-8")
            (rules_dir / "Parent.list").write_text(
                "DOMAIN-SUFFIX,addons.mozilla.org\n"
                "DOMAIN-WILDCARD,*.example.net\n"
                "DOMAIN-KEYWORD,tracking\n",
                encoding="utf-8")
            refs = [
                analyze_rules.Ref("Child.list", "Download", 0, 1),
                analyze_rules.Ref("Parent.list", "Proxy", 1, 2),
            ]
            rules = analyze_rules.extract(rules_dir, refs, self.psl)
            relations = analyze_rules.Relations(rules)
            relations.build_domains()
            result = analyze_rules.diagnose(rules, relations.rows)
            self.assertEqual(result[6], {})
            self.assertEqual(
                result[7],
                {
                    "Parent.list:1": ["Child.list:1"],
                    "Parent.list:2": ["Child.list:2"],
                    "Parent.list:3": ["Child.list:3"],
                },
            )

    # A broad parent plus a different-policy child is safe or fatal purely by
    # list order, so both cases use the same two files and differ only in the
    # order the profile references them.
    SPLIT_CHILD = ("Child.list", "Download", "DOMAIN,versioncheck.addons.mozilla.org\n")
    SPLIT_PARENT = ("Parent.list", "Proxy", "DOMAIN-SUFFIX,addons.mozilla.org\n")

    def run_shadow_gate(self, tmp, listing):
        """Run the full --fail-on-shadow gate over a temp profile.

        `listing` is [(list name, policy, body)] in profile order. Returns the
        analyzer exit code and the summary diagnostics.
        """
        root = Path(tmp)
        rules_dir = root / "lists"
        rules_dir.mkdir()
        for name, _policy, body in listing:
            (rules_dir / name).write_text(body, encoding="utf-8")
        conf = root / "Surge.conf"
        conf.write_text(
            "[Rule]\n"
            + "".join("RULE-SET,https://rules.example/%s,%s\n" % (name, policy)
                      for name, policy, _body in listing)
            + "FINAL,Final\n",
            encoding="utf-8")
        expired = root / "expired.txt"
        expired.write_text("", encoding="utf-8")
        out = root / "out"
        argv = ["analyze_rules.py", "--conf", str(conf), "--rules", str(rules_dir),
                "--psl", str(ROOT / "tests/data/public_suffix_list.dat"),
                "--expired", str(expired), "--out", str(out), "--fail-on-shadow"]
        saved = sys.argv
        sys.argv = argv
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                code = analyze_rules.main()
        finally:
            sys.argv = saved
        summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
        return code, summary["diagnostics"]

    def test_ordered_safe_split_passes_shadow_gate(self):
        with tempfile.TemporaryDirectory(prefix="ordered-safe-selftest-") as tmp:
            code, diagnostics = self.run_shadow_gate(
                tmp, [self.SPLIT_CHILD, self.SPLIT_PARENT])
            self.assertEqual(code, 0)
            self.assertEqual(diagnostics["ordered_safe_split_parents"], ["Parent.list:1"])
            self.assertEqual(diagnostics["order_unsafe_split_parents"], [])
            self.assertEqual(diagnostics["shadowed_or_conflicting_rules"], 0)

    def test_order_unsafe_split_fails_shadow_gate(self):
        with tempfile.TemporaryDirectory(prefix="order-unsafe-selftest-") as tmp:
            code, diagnostics = self.run_shadow_gate(
                tmp, [self.SPLIT_PARENT, self.SPLIT_CHILD])
            self.assertEqual(code, 1)
            self.assertEqual(diagnostics["order_unsafe_split_parents"], ["Parent.list:1"])
            self.assertEqual(diagnostics["ordered_safe_split_parents"], [])
            self.assertEqual(diagnostics["shadowed_or_conflicting_rules"], 1)

    def test_f2_rejects_broad_suffixes_owned_by_non_direct_rules(self):
        with tempfile.TemporaryDirectory(prefix="regen-ownership-selftest-") as tmp:
            rules_dir = Path(tmp)
            (rules_dir / "ExactProxy.list").write_text(
                "DOMAIN,api.example.net\n", encoding="utf-8")
            (rules_dir / "WildcardProxy.list").write_text(
                "DOMAIN-WILDCARD,*.assets.example.org\n", encoding="utf-8")
            (rules_dir / "Direct.list").write_text(
                "DOMAIN,api.direct.example\n", encoding="utf-8")
            candidates = [
                {"type": "DOMAIN-SUFFIX", "value": "example.net", "line": 1},
                {"type": "DOMAIN-SUFFIX", "value": "assets.example.org", "line": 2},
                {"type": "DOMAIN-SUFFIX", "value": "direct.example", "line": 3},
                {"type": "DOMAIN-SUFFIX", "value": "unrelated.example", "line": 4},
            ]
            keep, drop = f2_ownership(
                candidates,
                str(rules_dir),
                ["ExactProxy", "WildcardProxy", "Direct"],
                {"ExactProxy": "Proxy", "WildcardProxy": "Proxy", "Direct": "DIRECT"},
            )
            self.assertEqual(
                {rule["value"] for rule in drop},
                {"example.net", "assets.example.org"},
            )
            self.assertEqual(
                [rule["value"] for rule in keep],
                ["direct.example", "unrelated.example"],
            )
            self.assertTrue(all("split-child:" in rule["reason"] for rule in drop))


if __name__ == "__main__":
    unittest.main()
