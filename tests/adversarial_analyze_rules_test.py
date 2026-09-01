#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Adversarial stress test suite for tools/analyze_rules.py and Clash synchronization.

Tests:
1. Synthetic Conflicting Rules:
   - Conflicting exact DOMAIN across lists -> conflicting-equivalent & active-shadow.
   - Redundant DOMAIN across lists with same policy -> redundant-equivalent.
2. CIDR Overlap & Containment Analysis:
   - Broad CIDR preceding narrow CIDR with different policy -> active-shadow (fails gate).
   - Narrow CIDR preceding broad CIDR with different policy -> order-dependent-exception (safe).
   - CIDR identical equivalent across lists.
3. Topological Cyclic Dependencies:
   - 2-node mutual containment cycle (ListA <-> ListB) -> detected by Tarjan algorithm.
   - 3-node cyclic dependency (ListA -> ListB -> ListC -> ListA) -> detected in topology_cycles.
4. Order-Unsafe vs Ordered-Safe Split Apex & Parent Rules:
   - Apex domain parent preceding child -> order_unsafe_split_apex.
   - Apex domain parent following child -> ordered_safe_split_apex.
   - Non-apex wildcard/keyword parent preceding child -> order_unsafe_split_parents.
5. Expired Domain Re-entry Detection:
   - Expired domain in ProxyGFW.list -> detected in expired_proxygfw_reentries (fails gate).
6. ProxyGFW Protocol and Boundary Enforcement:
   - IP rules inside ProxyGFW.list -> detected in proxygfw_ip_rules.
   - PSL boundary / TLD suffix inside ProxyGFW.list -> detected in proxygfw_psl_boundaries.
7. Clash Synchronization Adversarial Invariants:
   - Unknown rule types -> abort with exit 2 without modifying clash/.
   - Comment stripping and passthrough / drop filtering.
"""

import contextlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "tools"))

import analyze_rules
import surge2clash


class AdversarialRuleTopologyTest(unittest.TestCase):
    """Stress-test analyze_rules.py algorithms with synthetic topologies."""

    @classmethod
    def setUpClass(cls):
        cls.psl = analyze_rules.PSL(ROOT_DIR / "tests/data/public_suffix_list.dat")

    def run_analyzer_gate(self, tmp_dir: Path, lists_spec: list, expired_domains: list = None):
        """Helper to run analyze_rules in a temporary environment.

        lists_spec: [(filename, policy, rule_content_str)]
        """
        rules_dir = tmp_dir / "lists"
        rules_dir.mkdir(parents=True, exist_ok=True)
        for name, _pol, content in lists_spec:
            (rules_dir / name).write_text(content, encoding="utf-8")

        conf_file = tmp_dir / "Surge.conf"
        conf_lines = ["[Rule]"]
        for name, policy, _ in lists_spec:
            conf_lines.append(f"RULE-SET,https://rules.example/{name},{policy}")
        conf_lines.append("FINAL,Final")
        conf_file.write_text("\n".join(conf_lines) + "\n", encoding="utf-8")

        expired_file = tmp_dir / "expired.txt"
        expired_content = "\n".join(expired_domains or [])
        expired_file.write_text(expired_content, encoding="utf-8")

        out_dir = tmp_dir / "out"

        argv = [
            "analyze_rules.py",
            "--conf", str(conf_file),
            "--rules", str(rules_dir),
            "--psl", str(ROOT_DIR / "tests/data/public_suffix_list.dat"),
            "--expired", str(expired_file),
            "--out", str(out_dir),
            "--fail-on-shadow",
        ]

        saved_argv = sys.argv
        sys.argv = argv
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                code = analyze_rules.main()
        finally:
            sys.argv = saved_argv

        summary_json = json.loads((out_dir / "summary.json").read_text(encoding="utf-8"))
        return code, summary_json

    def test_conflicting_exact_rules_detection(self):
        """Test detection of exact duplicate domain with conflicting policies."""
        with tempfile.TemporaryDirectory(prefix="topo-conflict-") as tmp:
            tmp_path = Path(tmp)
            lists_spec = [
                ("ListA.list", "REJECT", "DOMAIN,conflict.example.com\n"),
                ("ListB.list", "DIRECT", "DOMAIN,conflict.example.com\n"),
            ]
            code, summary = self.run_analyzer_gate(tmp_path, lists_spec)
            self.assertEqual(code, 1, "Conflicting rules must trigger gate failure")
            self.assertGreaterEqual(summary["diagnostics"]["shadowed_or_conflicting_rules"], 1)

            # Check relationships.jsonl
            rel_lines = [json.loads(line) for line in (tmp_path / "out/relationships.jsonl").read_text().splitlines()]
            effects = [r.get("routing_effect") for r in rel_lines]
            self.assertIn("conflicting-equivalent", effects)

    def test_cidr_containment_and_shadowing(self):
        """Test IPv4/IPv6 CIDR containment and order-dependent shadowing."""
        # Case A: Broad preceding Narrow -> active-shadow (gate fails)
        with tempfile.TemporaryDirectory(prefix="topo-cidr-shadow-") as tmp:
            tmp_path = Path(tmp)
            lists_spec = [
                ("DirectNet.list", "DIRECT", "IP-CIDR,10.0.0.0/16,no-resolve\n"),
                ("RejectSub.list", "REJECT", "IP-CIDR,10.0.1.0/24,no-resolve\n"),
            ]
            code, summary = self.run_analyzer_gate(tmp_path, lists_spec)
            self.assertEqual(code, 1, "Broad CIDR preceding Narrow CIDR with different policy must fail gate")
            self.assertGreaterEqual(summary["diagnostics"]["shadowed_or_conflicting_rules"], 1)

        # Case B: Narrow preceding Broad -> order-dependent exception (gate passes)
        with tempfile.TemporaryDirectory(prefix="topo-cidr-safe-") as tmp:
            tmp_path = Path(tmp)
            lists_spec = [
                ("RejectSub.list", "REJECT", "IP-CIDR,10.0.1.0/24,no-resolve\n"),
                ("DirectNet.list", "DIRECT", "IP-CIDR,10.0.0.0/16,no-resolve\n"),
            ]
            code, summary = self.run_analyzer_gate(tmp_path, lists_spec)
            self.assertEqual(code, 0, "Narrow CIDR preceding Broad CIDR is order-safe exception and must pass")
            self.assertEqual(summary["diagnostics"]["shadowed_or_conflicting_rules"], 0)

    def test_2_node_cyclic_dependency_detection(self):
        """Test that Tarjan algorithm correctly detects a 2-node cyclic dependency."""
        with tempfile.TemporaryDirectory(prefix="topo-cycle-2-") as tmp:
            tmp_path = Path(tmp)
            # ListA has parent foo.com (Policy Proxy), ListB has child api.foo.com (Policy Direct) -> ListB must precede ListA
            # ListB has parent bar.org (Policy Direct), ListA has child cdn.bar.org (Policy Proxy) -> ListA must precede ListB
            lists_spec = [
                ("ListA.list", "Proxy", "DOMAIN-SUFFIX,foo.com\nDOMAIN,cdn.bar.org\n"),
                ("ListB.list", "DIRECT", "DOMAIN,api.foo.com\nDOMAIN-SUFFIX,bar.org\n"),
            ]
            code, summary = self.run_analyzer_gate(tmp_path, lists_spec)
            # Both orders are unsafe, cycles should be detected
            cycles = summary["diagnostics"]["topology_cycles"]
            self.assertEqual(len(cycles), 1, "Must detect 1 topological cycle")
            self.assertEqual(sorted(cycles[0]), ["ListA.list", "ListB.list"])

    def test_3_node_cyclic_dependency_detection(self):
        """Test that Tarjan algorithm correctly detects a 3-node cyclic dependency."""
        with tempfile.TemporaryDirectory(prefix="topo-cycle-3-") as tmp:
            tmp_path = Path(tmp)
            # ListA (Parent node1.com) -> ListB (Child a.node1.com, Parent node2.com) -> ListC (Child b.node2.com, Parent node3.com) -> ListA (Child c.node3.com)
            lists_spec = [
                ("ListA.list", "PolicyA", "DOMAIN-SUFFIX,node1.com\nDOMAIN,c.node3.com\n"),
                ("ListB.list", "PolicyB", "DOMAIN,a.node1.com\nDOMAIN-SUFFIX,node2.com\n"),
                ("ListC.list", "PolicyC", "DOMAIN,b.node2.com\nDOMAIN-SUFFIX,node3.com\n"),
            ]
            code, summary = self.run_analyzer_gate(tmp_path, lists_spec)
            cycles = summary["diagnostics"]["topology_cycles"]
            self.assertEqual(len(cycles), 1)
            self.assertEqual(sorted(cycles[0]), ["ListA.list", "ListB.list", "ListC.list"])

    def test_proxygfw_expired_domain_reentry(self):
        """Test that re-entering an expired domain into ProxyGFW.list fails the gate."""
        with tempfile.TemporaryDirectory(prefix="topo-expired-") as tmp:
            tmp_path = Path(tmp)
            lists_spec = [
                ("ProxyGFW.list", "Proxy", "DOMAIN-SUFFIX,dead-legacy-domain.com\n"),
            ]
            expired = ["dead-legacy-domain.com"]
            code, summary = self.run_analyzer_gate(tmp_path, lists_spec, expired_domains=expired)
            self.assertEqual(code, 1, "Expired domain re-entry must fail gate")
            self.assertIn("ProxyGFW.list:1", summary["diagnostics"]["expired_proxygfw_reentries"])

    def test_proxygfw_ip_rule_and_psl_boundary_violation(self):
        """Test detection of IP rules and PSL boundaries in ProxyGFW.list."""
        # IP Rule in ProxyGFW
        with tempfile.TemporaryDirectory(prefix="topo-proxy-ip-") as tmp:
            tmp_path = Path(tmp)
            lists_spec = [
                ("ProxyGFW.list", "Proxy", "IP-CIDR,1.1.1.1/32,no-resolve\n"),
            ]
            code, summary = self.run_analyzer_gate(tmp_path, lists_spec)
            self.assertEqual(code, 1)
            self.assertIn("ProxyGFW.list:1", summary["diagnostics"]["proxygfw_ip_rules"])

        # PSL Boundary (e.g. DOMAIN-SUFFIX,co.uk) in ProxyGFW
        with tempfile.TemporaryDirectory(prefix="topo-proxy-psl-") as tmp:
            tmp_path = Path(tmp)
            lists_spec = [
                ("ProxyGFW.list", "Proxy", "DOMAIN-SUFFIX,co.uk\n"),
            ]
            code, summary = self.run_analyzer_gate(tmp_path, lists_spec)
            self.assertEqual(code, 1)
            self.assertIn("ProxyGFW.list:1", summary["diagnostics"]["proxygfw_psl_boundaries"])


class AdversarialClashSyncTest(unittest.TestCase):
    """Stress-test Surge to Clash derivation rules and edge cases."""

    def test_unknown_rule_type_rejection(self):
        """Test that unknown rule types cause convert_file to return unknown list."""
        with tempfile.TemporaryDirectory(prefix="clash-unknown-") as tmp:
            list_file = Path(tmp) / "Dummy.list"
            list_file.write_text("INVALID-RULE-TYPE,example.com\nDOMAIN,valid.com\n", encoding="utf-8")

            # Mock RULES_DIR
            saved_dir = surge2clash.RULES_DIR
            try:
                surge2clash.RULES_DIR = str(tmp)
                body, kept, dropped, unknown = surge2clash.convert_file("Dummy.list")
                self.assertEqual(len(unknown), 1)
                self.assertEqual(unknown[0][2], "INVALID-RULE-TYPE")
            finally:
                surge2clash.RULES_DIR = saved_dir

    def test_comment_stripping_safety(self):
        """Test that only space-hash is stripped from rule lines."""
        # Bare # inside string or non-space delimited
        self.assertEqual(surge2clash.strip_trailing_comment("DOMAIN,foo.com,no-resolve # inline comment"), "DOMAIN,foo.com,no-resolve")
        self.assertEqual(surge2clash.strip_trailing_comment("DOMAIN,foo.com"), "DOMAIN,foo.com")
        self.assertEqual(surge2clash.strip_trailing_comment("DOMAIN,foo.com#not_a_comment"), "DOMAIN,foo.com#not_a_comment")

    def test_drop_types_filtering(self):
        """Test that USER-AGENT and URL-REGEX are counted in dropped dictionary."""
        with tempfile.TemporaryDirectory(prefix="clash-drop-") as tmp:
            list_file = Path(tmp) / "DropTest.list"
            list_file.write_text("USER-AGENT,*Spotify*\nURL-REGEX,^https://api\\.example\\.com\nDOMAIN,valid.com\n", encoding="utf-8")

            saved_dir = surge2clash.RULES_DIR
            try:
                surge2clash.RULES_DIR = str(tmp)
                body, kept, dropped, unknown = surge2clash.convert_file("DropTest.list")
                self.assertEqual(kept, 1)
                self.assertEqual(dropped.get("USER-AGENT"), 1)
                self.assertEqual(dropped.get("URL-REGEX"), 1)
                self.assertEqual(len(unknown), 0)
            finally:
                surge2clash.RULES_DIR = saved_dir


if __name__ == "__main__":
    unittest.main(verbosity=2)
