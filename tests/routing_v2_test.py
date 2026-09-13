#!/usr/bin/env python3
"""Regression tests for domain-first routing, DNS state and filtered IP sets."""
import ipaddress
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'tools'))
sys.path.insert(0, str(ROOT / 'tests'))
from engine import Engine
from rule_syntax import parse_ruleset_call, render_call
from routing_manifest import load_routing_manifest
from analyze_rules import merge_networks, subtract_intervals
from rebuild import op_include_cidr, RebuildError
import collapse_cidr


class RoutingStateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        for name, body in {
            'Service': 'DOMAIN-SUFFIX,service.example\n',
            'Domestic': 'DOMAIN-SUFFIX,domestic.example\n',
            'Early': 'IP-CIDR,198.51.100.0/25,no-resolve\n',
            'Resolve': 'IP-CIDR,203.0.113.0/24\n',
            'Late': 'IP-CIDR,198.51.100.128/25,no-resolve\n',
            'Region': 'GEOIP,US\n',
            'Protected': 'IP-CIDR,192.0.2.0/25\nIP-CIDR6,2001:db8:1::/48\n',
        }.items():
            (self.root / (name + '.list')).write_text(body)
        ref = lambda n: str(self.root / (n + '.list'))
        filtered = render_call({'name':'Region', 'policy':'Region',
                                'exclude_rulesets':['Protected']}, ref)
        self.conf = self.root / 'test.conf'
        self.conf.write_text('[General]\nencrypted-dns-server = https://1.1.1.1/dns-query\n[Rule]\n' +
            '\n'.join([
                'RULE-SET,' + ref('Service') + ',Proxy,extended-matching',
                'RULE-SET,' + ref('Domestic') + ',DIRECT,extended-matching',
                'RULE-SET,' + ref('Early') + ',Early',
                'RULE-SET,' + ref('Resolve') + ',Resolve',
                'RULE-SET,' + ref('Late') + ',Late', filtered,
                'RULE-SET,' + ref('Protected') + ',DIRECT',
                'FINAL,Final,dns-failed']) + '\n')
        self.e = Engine(str(self.conf), str(self.root))
        self.e._db_lookup = lambda kind, ip: {'country': {'iso_code':'US'}} if kind == 'country' else {}

    def tearDown(self):
        self.tmp.cleanup()

    def test_domain_precedes_lookup(self):
        r = self.e.match(host='api.service.example', dns_status='failed')
        self.assertEqual(r['policy'], 'Proxy')
        self.assertEqual(r['dns_resolution_count'], 0)

    def test_missing_answer_is_not_a_fabricated_final(self):
        r = self.e.match(host='unknown.example')
        self.assertIsNone(r['policy'])
        self.assertTrue(r['resolution_required'])
        self.assertFalse(r['routing_complete'])

    def test_explicit_domain_stage(self):
        r = self.e.match(host='unknown.example', stage='domain')
        self.assertEqual(r['policy'], 'Final')
        self.assertFalse(r['routing_complete'])
        self.assertEqual(r['dns_resolution_count'], 0)

    def test_resolved_address_matches_no_resolve(self):
        self.assertEqual(self.e.match(host='unknown.example', ip='198.51.100.1')['policy'], 'Early')

    def test_no_resolve_before_lookup_is_not_revisited(self):
        r = self.e.match(host='unknown.example', dns_status='success', resolved_ips=['198.51.100.1'])
        self.assertEqual(r['policy'], 'Region')
        self.assertEqual(r['dns_resolution_count'], 1)

    def test_no_resolve_after_lookup_still_matches(self):
        r = self.e.match(host='unknown.example', dns_status='success', resolved_ips=['198.51.100.200'])
        self.assertEqual(r['policy'], 'Late')
        self.assertFalse(r['dns_leak'])

    def test_dns_failure_option_is_required(self):
        self.assertEqual(self.e.match(host='unknown.example', dns_status='failed')['policy'], 'Final')
        self.e.final_rule.modifiers = frozenset()
        self.assertIsNone(self.e.match(host='unknown.example', dns_status='failed')['policy'])

    def test_sni_preserves_first_match_order(self):
        self.assertEqual(self.e.match(host='domestic.example', sni='api.service.example')['policy'], 'Proxy')
        self.assertEqual(self.e.match(host='192.0.2.5', sni='api.service.example')['policy'], 'Proxy')

    def test_regions_exclude_direct_sets(self):
        self.assertEqual(self.e.match(ip='192.0.2.10')['policy'], 'DIRECT')
        self.assertEqual(self.e.match(ip='192.0.2.200')['policy'], 'Region')

    def test_mixed_family_exclusion_tests_both_answers(self):
        r = self.e.match(host='unknown.example', dns_status='success',
                         resolved_ips=['192.0.2.200', '2001:db8:1::1'])
        self.assertEqual(r['policy'], 'DIRECT')

    def test_first_record_per_family(self):
        r = self.e.match(host='unknown.example', dns_status='success',
                         resolved_ips=['198.51.100.200', '203.0.113.1'])
        self.assertEqual(r['policy'], 'Late')

    def test_plaintext_resolver_detected(self):
        self.e.general['encrypted-dns-server'] = 'tcp://1.1.1.1'
        self.assertTrue(self.e.match(host='unknown.example')['dns_leak'])


class RoutingFormatTests(unittest.TestCase):
    def test_exclusion_parser_and_flags(self):
        text = 'AND,((RULE-SET,/tmp/Region.list,no-resolve),(NOT,((RULE-SET,/tmp/ChinaIP.list)))),Proxy'
        self.assertEqual(parse_ruleset_call(text), ('/tmp/Region.list','Proxy',('no-resolve',),('/tmp/ChinaIP.list',)))
        for invalid in ['OR,((RULE-SET,A),(RULE-SET,B)),P',
                        'AND,((RULE-SET,A),(NOT,((RULE-SET,A)))),P',
                        'AND,((RULE-SET,A),(GEOIP,CN)),P']:
            with self.assertRaises(ValueError):
                parse_ruleset_call(invalid)

    def test_manifest_rejects_wrong_kind_and_exclusions(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/'Domestic.list').write_text('DOMAIN-SUFFIX,domestic.example\n')
            doc = {'version':2, 'rulesets':[{'name':'Domestic','kind':'ip','policy':'DIRECT','section':'IP'}],
                   'system':None,'final':{'policy':'Final','dns_failed':True}}
            file = root/'routing.json'
            file.write_text(json.dumps(doc))
            with self.assertRaises(ValueError):
                load_routing_manifest(str(file), str(root))
            doc['rulesets'][0]['kind']='domain'
            doc['rulesets'][0]['exclude_rulesets']=['Missing']
            file.write_text(json.dumps(doc))
            with self.assertRaises(ValueError):
                load_routing_manifest(str(file), str(root))

    def test_interval_difference_matches_independent_address_membership(self):
        raw = [ipaddress.ip_network('192.0.2.0/24')]
        cuts = [ipaddress.ip_network('192.0.2.64/26'), ipaddress.ip_network('192.0.2.192/27')]
        actual = subtract_intervals(merge_networks(raw), merge_networks(cuts))
        for value in range(int(raw[0].network_address), int(raw[0].broadcast_address)+1):
            expected = not any(ipaddress.ip_address(value) in net for net in cuts)
            self.assertEqual(any(lo <= value <= hi for lo,hi in actual[4]), expected)

    def test_retention_cannot_bypass_hard_exclusion(self):
        with self.assertRaises(RebuildError):
            op_include_cidr({'values':['192.0.2.0/24'],'guard_values':['192.0.2.64/26']}, {}, {}, [], [])

    def test_cidr_check_preserves_resolving_and_no_resolve_groups(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'Mixed.list'
            text = ('# mixed lookup semantics\n\n'
                    'IP-CIDR,192.0.2.0/25\n'
                    'IP-CIDR,192.0.2.128/25,no-resolve\n')
            path.write_text(text)
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(collapse_cidr.main([str(path),'--check']), 0)
            self.assertEqual(path.read_text(), text)

    def test_cidr_equivalence_rejects_changed_lookup_semantics(self):
        with tempfile.TemporaryDirectory() as tmp:
            before,after = Path(tmp)/'Before.list',Path(tmp)/'After.list'
            before.write_text('IP-CIDR,192.0.2.0/24\n')
            after.write_text('IP-CIDR,192.0.2.0/24,no-resolve\n')
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(collapse_cidr.main([str(after),'--verify','--against',str(before)]), 1)

    def test_cidr_check_still_rejects_uncollapsed_shape(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'Uncollapsed.list'
            text = '\nIP-CIDR,192.0.2.0/25\nIP-CIDR,192.0.2.128/25\n'
            path.write_text(text)
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(collapse_cidr.main([str(path),'--check']), 1)
            self.assertEqual(path.read_text(), text)


if __name__ == '__main__':
    unittest.main()
