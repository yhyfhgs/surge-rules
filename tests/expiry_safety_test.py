#!/usr/bin/env python3
"""Network failures must never become evidence for deleting live rules."""
import asyncio
import datetime
from pathlib import Path
import sys
import unittest
from unittest.mock import AsyncMock, patch
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'tools'))
import probe_dead_domains as p


class ExpirySafety(unittest.TestCase):
    def test_doh_error_does_not_consult_delegation_for_death(self):
        async def run():
            with patch.object(p,'probe_tier1_cn_dns',AsyncMock(return_value=p.Tier1Result(status='CN_TIMEOUT'))), \
                 patch.object(p,'probe_tier2_clean_doh',AsyncMock(return_value=p.Tier2Result(status='DOH_ERROR'))), \
                 patch.object(p,'probe_tier3_authoritative_tld',AsyncMock(return_value=p.Tier3Result(status='NOT_DELEGATED'))) as authority:
                value=await p.triangulate_domain('service.example')
                self.assertFalse(value.is_dead)
                authority.assert_not_awaited()
        asyncio.run(run())

    def test_one_resolver_nxdomain_is_not_quorum(self):
        async def run():
            async def fetch(provider,domain,timeout):
                return provider['name'], {'Status':3} if provider is p.DOH_ENDPOINTS[0] else None
            with patch.object(p,'query_doh_provider',fetch):
                result=await p.probe_tier2_clean_doh('unknown.example')
                self.assertNotEqual(result.status,'DOH_NXDOMAIN')
        asyncio.run(run())

    def test_parent_soa_is_not_unregistration(self):
        async def run():
            response=p.DnsResponse(txid=1,rcode=0,flags=0x8400,authorities=[p.DnsRecord(name='com',rtype=p.TYPE_SOA,rclass=1,ttl=60,data='parent')])
            with patch.object(p,'udp_dns_query',AsyncMock(return_value=response)):
                result=await p.probe_tier3_authoritative_tld('registered.com')
                self.assertNotEqual(result.status,'NOT_DELEGATED')
        asyncio.run(run())

    def test_fake_ip_is_not_censorship_evidence(self):
        async def run():
            response=p.DnsResponse(txid=1,rcode=0,flags=0x8180,answers=[p.DnsRecord(name='service.example',rtype=p.TYPE_A,rclass=1,ttl=60,data='198.18.0.5')])
            with patch.object(p,'udp_dns_query',AsyncMock(return_value=response)):
                result=await p.probe_tier1_cn_dns('service.example')
                self.assertEqual(result.status,'CN_INTERCEPTED')
                self.assertFalse(result.is_poisoned)
        asyncio.run(run())

    def test_same_timestamp_cannot_confirm_expiry(self):
        verdict=p.TriangulationVerdict(domain='old.example',tier1=p.Tier1Result(status='CN_NXDOMAIN'),
            tier2=p.Tier2Result(status='DOH_NXDOMAIN'),tier3=p.Tier3Result(status='NOT_DELEGATED'),
            tier4=p.Tier4Result(status='SKIPPED'),verdict='DEAD_UNREGISTERED',is_dead=True,reason='fixture')
        manager=p.HysteresisManager(required_sweeps=3)
        for _ in range(10):record=manager.update(verdict)
        self.assertEqual(record.consecutive_dead_sweeps,1)
        self.assertEqual(record.status,'CANDIDATE_DEAD')
        verdict.timestamp=(datetime.datetime.fromisoformat(verdict.timestamp)+datetime.timedelta(days=1)).isoformat()
        self.assertEqual(manager.update(verdict).consecutive_dead_sweeps,2)


if __name__=='__main__':unittest.main()
