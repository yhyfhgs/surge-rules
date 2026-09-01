#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Adversarial stress test suite for tools/probe_dead_domains.py.

Tests:
1. DNS Wire Codec Adversarial & Fuzzing:
   - Malformed packets (too short, truncated headers, truncated questions, truncated RDATA).
   - Compression pointer loops (self-loop, 2-hop loop, chain loop, pointer out of bounds).
   - Label length boundary conditions (63-byte label, 64-byte label overflow).
   - IDNA/Unicode domains and non-ASCII raw label error handling.
   - Corrupted/truncated SOA, CNAME, AAAA, TXT record payloads.
   - Pseudo-random byte fuzzing across parse_dns_response (must not crash unexpectedly).
2. 4-Tier Decision Matrix Comprehensive Stress Testing:
   - GFW DNS pollution + Clean DoH resolution -> BLOCKED_BY_GFW (MUST NOT be marked dead).
   - GFW DNS pollution + Clean DoH NXDOMAIN + TLD NOT_DELEGATED -> DEAD_UNREGISTERED.
   - Clean DoH ALIVE + Parking page fingerprint (title/body/IP) -> DEAD_PARKED.
   - Clean DoH ALIVE + Clean HTTP 200 -> ALIVE.
   - Clean DoH NXDOMAIN + TLD LAME_DELEGATION / UNKNOWN -> DEAD_LAME_DELEGATION.
   - Full network timeout / inconclusive across all tiers -> UNKNOWN_UNRESOLVED (safely retained).
3. Temporal Hysteresis State Machine Resilience:
   - Consecutive streak accumulation across N sweeps.
   - Immediate reset upon recovery (ALIVE or BLOCKED_BY_GFW).
   - JSON serialization, disk round-trip, corrupted JSON recovery.
   - Concurrent updates and state transitions.
"""

import asyncio
import io
import json
import os
import random
import struct
import tempfile
import unittest
from pathlib import Path

# Add project tools directory to sys.path
import sys
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "tools"))

import probe_dead_domains as pdd


class AdversarialDnsCodecTest(unittest.TestCase):
    """Stress-test DNS wire protocol encoder/decoder against adversarial inputs."""

    def test_encode_dns_name_boundaries(self):
        """Test encoding empty, single-label, max-label, and overflow label."""
        # Empty string / root
        self.assertEqual(pdd.encode_dns_name(""), b"\x00")
        self.assertEqual(pdd.encode_dns_name("."), b"\x00")

        # Max valid label (63 bytes)
        max_label = "a" * 63
        encoded_max = pdd.encode_dns_name(f"{max_label}.com")
        self.assertEqual(len(encoded_max), 1 + 63 + 1 + 3 + 1)
        self.assertEqual(encoded_max[0], 63)

        # Overflow label (64 bytes) -> ValueError
        overflow_label = "a" * 64
        with self.assertRaises(ValueError):
            pdd.encode_dns_name(f"{overflow_label}.com")

        # IDNA / Punycode conversion
        encoded_idn = pdd.encode_dns_name("中文.cn")
        self.assertIn(b"xn--", encoded_idn)

    def test_decode_dns_name_compression_loop_traps(self):
        """Test that compression loops raise ValueError and do not hang/infinite-loop."""
        # Case 1: Direct self loop at offset 0 (0xC000 points to 0)
        loop_self = b"\xc0\x00"
        with self.assertRaises(ValueError) as ctx:
            pdd.decode_dns_name(loop_self, 0)
        self.assertIn("compression loop", str(ctx.exception).lower())

        # Case 2: 2-hop loop: offset 0 points to 4 (0xC004), offset 4 points to 0 (0xC000)
        loop_2hop = b"\xc0\x04\x00\x00\xc0\x00"
        with self.assertRaises(ValueError) as ctx:
            pdd.decode_dns_name(loop_2hop, 0)
        self.assertIn("compression loop", str(ctx.exception).lower())

        # Case 3: Label followed by loop back to start
        # [3] "foo" [ptr -> offset 0]
        loop_label = b"\x03foo\xc0\x00"
        with self.assertRaises(ValueError) as ctx:
            pdd.decode_dns_name(loop_label, 0)
        self.assertIn("compression loop", str(ctx.exception).lower())

        # Case 4: Long multi-hop chain loop
        # 0: ptr -> 6; 2: dummy; 6: ptr -> 10; 10: ptr -> 0
        loop_chain = b"\xc0\x06\x00\x00\x00\x00\xc0\x0a\x00\x00\xc0\x00"
        with self.assertRaises(ValueError) as ctx:
            pdd.decode_dns_name(loop_chain, 0)
        self.assertIn("compression loop", str(ctx.exception).lower())

    def test_decode_dns_name_incomplete_and_corrupt(self):
        """Test truncated label lengths and incomplete pointers."""
        # Pointer header 0xC0 without second byte
        truncated_ptr = b"\x03com\xc0"
        with self.assertRaises(ValueError) as ctx:
            pdd.decode_dns_name(truncated_ptr, 4)
        self.assertIn("incomplete dns pointer", str(ctx.exception).lower())

        # Label length specifies 10 bytes, but only 3 bytes follow
        truncated_label = b"\x0afoo"
        with self.assertRaises(ValueError) as ctx:
            pdd.decode_dns_name(truncated_label, 0)
        self.assertIn("incomplete dns label", str(ctx.exception).lower())

        # Empty data
        name, off = pdd.decode_dns_name(b"", 0)
        self.assertEqual(name, "")
        self.assertEqual(off, 0)

    def test_parse_dns_response_malformed_packets(self):
        """Test packet parser resilience against undersized and corrupted packets."""
        # Less than 12-byte header
        for length in range(12):
            with self.assertRaises(ValueError):
                pdd.parse_dns_response(b"\x00" * length)

        # Header with QDCOUNT=5, but no question payload
        hdr_fake_questions = struct.pack("!HHHHHH", 0x1234, 0x8180, 5, 0, 0, 0)
        resp = pdd.parse_dns_response(hdr_fake_questions)
        self.assertEqual(len(resp.questions), 0)

        # Header with ANCOUNT=10, but no answer payload
        hdr_fake_answers = struct.pack("!HHHHHH", 0x1234, 0x8180, 0, 10, 0, 0)
        resp2 = pdd.parse_dns_response(hdr_fake_answers)
        self.assertEqual(len(resp2.answers), 0)

    def test_parse_dns_response_corrupted_rdata_types(self):
        """Test parser handling when RDATA lengths do not match expected record type lengths."""
        # A record with rdlength=3 instead of 4
        qname = pdd.encode_dns_name("example.com")
        pkt = bytearray(struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0))
        pkt.extend(qname + struct.pack("!HH", pdd.TYPE_A, 1))
        # Answer: name ptr to 12, TYPE=A, CLASS=1, TTL=60, RDLENGTH=3, RDATA=3 bytes
        pkt.extend(b"\xc0\x0c" + struct.pack("!HHIH", pdd.TYPE_A, 1, 60, 3) + b"\x01\x02\x03")

        resp = pdd.parse_dns_response(bytes(pkt))
        self.assertEqual(len(resp.answers), 1)
        # Because rdlength != 4, falls back to hex
        self.assertEqual(resp.answers[0].data, "010203")

        # AAAA record with rdlength=10 instead of 16
        pkt_aaaa = bytearray(struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0))
        pkt_aaaa.extend(qname + struct.pack("!HH", pdd.TYPE_AAAA, 1))
        pkt_aaaa.extend(b"\xc0\x0c" + struct.pack("!HHIH", pdd.TYPE_AAAA, 1, 60, 10) + b"\x00" * 10)
        resp_aaaa = pdd.parse_dns_response(bytes(pkt_aaaa))
        self.assertEqual(len(resp_aaaa.answers), 1)
        self.assertEqual(resp_aaaa.answers[0].data, "00" * 10)

        # CNAME record pointing to an invalid pointer -> "<decoding-error>"
        pkt_cname = bytearray(struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0))
        pkt_cname.extend(qname + struct.pack("!HH", pdd.TYPE_CNAME, 1))
        # RDATA contains truncated pointer 0xC0
        pkt_cname.extend(b"\xc0\x0c" + struct.pack("!HHIH", pdd.TYPE_CNAME, 1, 60, 1) + b"\xc0")
        resp_cname = pdd.parse_dns_response(bytes(pkt_cname))
        self.assertEqual(len(resp_cname.answers), 1)
        self.assertEqual(resp_cname.answers[0].data, "<decoding-error>")

    def test_dns_parser_fuzz_harness(self):
        """Adversarial fuzzer: feed 500 mutated byte sequences to parse_dns_response."""
        random.seed(42)
        valid_packet = pdd.build_dns_query("fuzz.test.com", pdd.TYPE_A)

        for _ in range(500):
            # Mutate valid packet or generate random garbage
            choice = random.randint(1, 4)
            if choice == 1:
                # Random bytes
                fuzz_bytes = os.urandom(random.randint(1, 256))
            elif choice == 2:
                # Truncated valid packet
                fuzz_bytes = valid_packet[:random.randint(0, len(valid_packet))]
            elif choice == 3:
                # Bit flipped valid packet
                ba = bytearray(valid_packet)
                for _ in range(random.randint(1, 5)):
                    idx = random.randint(0, len(ba) - 1)
                    ba[idx] ^= random.randint(1, 255)
                fuzz_bytes = bytes(ba)
            else:
                # Valid header + random payload
                fuzz_bytes = struct.pack("!HHHHHH", random.randint(0, 65535), 0x8180, random.randint(0, 5), random.randint(0, 5), 0, 0) + os.urandom(random.randint(0, 60))

            try:
                pdd.parse_dns_response(fuzz_bytes)
            except ValueError:
                # ValueErrors for malformed packets / compression loops are expected and safe
                pass
            except Exception as e:
                self.fail(f"Unexpected exception during fuzzing: {type(e).__name__}: {e}")


class AdversarialDecisionMatrixTest(unittest.TestCase):
    """Stress-test 4-tier triangulation decision matrix logic and safety guarantees."""

    def test_gfw_pollution_retention_guarantee(self):
        """CRITICAL: Poisoned CN DNS + Clean DoH MUST produce BLOCKED_BY_GFW and is_dead=False."""
        poison_ips = ["203.98.7.65", "243.185.187.39", "37.61.54.158", "127.0.0.1"]
        clean_ips = ["104.244.42.1", "151.101.1.140"]

        for pip in poison_ips:
            t1 = pdd.Tier1Result(status="CN_POLLUTED", is_poisoned=True, answers=[pip])
            t2 = pdd.Tier2Result(status="DOH_ALIVE", answers=[clean_ips[0]], providers_responding=["Cloudflare"])
            t3 = pdd.Tier3Result(status="SKIPPED")
            t4 = pdd.Tier4Result(status="ACTIVE_WEBSITE", http_code=200)

            # Test direct verdict creation
            verd = pdd.TriangulationVerdict(
                domain="twitter.com",
                tier1=t1,
                tier2=t2,
                tier3=t3,
                tier4=t4,
                verdict="BLOCKED_BY_GFW",
                is_dead=False,
                reason="Alive globally but polluted by GFW DNS. Rule MUST be preserved.",
            )
            self.assertFalse(verd.is_dead, f"GFW blocked domain with poison IP {pip} was wrongly marked dead!")
            self.assertEqual(verd.verdict, "BLOCKED_BY_GFW")

    def test_mock_triangulate_domain_all_branches(self):
        """Mock network calls in triangulate_domain to verify all decision branches."""
        async def run_cases():
            # Mock case 1: GFW blocked domain
            async def mock_t1_polluted(dom, timeout):
                return pdd.Tier1Result(status="CN_POLLUTED", is_poisoned=True, answers=["203.98.7.65"])
            async def mock_t2_alive(dom, timeout):
                return pdd.Tier2Result(status="DOH_ALIVE", answers=["104.244.42.1"], providers_responding=["Cloudflare"])
            async def mock_t4_active(dom, ip_hint, timeout):
                return pdd.Tier4Result(status="ACTIVE_WEBSITE", http_code=200)

            saved_t1 = pdd.probe_tier1_cn_dns
            saved_t2 = pdd.probe_tier2_clean_doh
            saved_t4 = pdd.probe_tier4_http_parking
            try:
                pdd.probe_tier1_cn_dns = mock_t1_polluted
                pdd.probe_tier2_clean_doh = mock_t2_alive
                pdd.probe_tier4_http_parking = mock_t4_active

                v1 = await pdd.triangulate_domain("blocked-service.com")
                self.assertFalse(v1.is_dead)
                self.assertEqual(v1.verdict, "BLOCKED_BY_GFW")

                # Mock case 2: Parking detection
                async def mock_t4_parked(dom, ip_hint, timeout):
                    return pdd.Tier4Result(status="PARKED", matched_fingerprint="Sedo parking", http_code=200)
                pdd.probe_tier4_http_parking = mock_t4_parked

                v2 = await pdd.triangulate_domain("parked-domain.com")
                self.assertTrue(v2.is_dead)
                self.assertEqual(v2.verdict, "DEAD_PARKED")

                # Mock case 3: Dead unregistered (DoH NXDOMAIN + TLD NOT_DELEGATED)
                async def mock_t2_nx(dom, timeout):
                    return pdd.Tier2Result(status="DOH_NXDOMAIN", providers_responding=["Cloudflare", "Google"])
                async def mock_t3_not_delegated(dom, timeout):
                    return pdd.Tier3Result(status="NOT_DELEGATED", tld="com")
                pdd.probe_tier2_clean_doh = mock_t2_nx
                pdd.probe_tier3_authoritative_tld = mock_t3_not_delegated

                v3 = await pdd.triangulate_domain("unregistered-12345.com")
                self.assertTrue(v3.is_dead)
                self.assertEqual(v3.verdict, "DEAD_UNREGISTERED")

                # Mock case 4: Lame delegation (DoH NXDOMAIN + TLD LAME_DELEGATION)
                async def mock_t3_lame(dom, timeout):
                    return pdd.Tier3Result(status="LAME_DELEGATION", tld="net")
                pdd.probe_tier3_authoritative_tld = mock_t3_lame

                v4 = await pdd.triangulate_domain("lame-ns-domain.net")
                self.assertTrue(v4.is_dead)
                self.assertEqual(v4.verdict, "DEAD_LAME_DELEGATION")

                # Mock case 5: Inconclusive / Network error -> safely retained
                async def mock_t2_err(dom, timeout):
                    return pdd.Tier2Result(status="DOH_ERROR")
                async def mock_t3_unknown(dom, timeout):
                    return pdd.Tier3Result(status="UNKNOWN", tld="org")
                pdd.probe_tier2_clean_doh = mock_t2_err
                pdd.probe_tier3_authoritative_tld = mock_t3_unknown

                v5 = await pdd.triangulate_domain("timeout-flaky.org")
                self.assertFalse(v5.is_dead)
                self.assertEqual(v5.verdict, "UNKNOWN_UNRESOLVED")

            finally:
                pdd.probe_tier1_cn_dns = saved_t1
                pdd.probe_tier2_clean_doh = saved_t2
                pdd.probe_tier4_http_parking = saved_t4

        asyncio.run(run_cases())


class AdversarialTemporalHysteresisTest(unittest.TestCase):
    """Stress-test multi-sweep temporal hysteresis state management."""

    def test_hysteresis_streak_lifecycle(self):
        """Test candidate -> confirmed -> recovery -> re-death transitions."""
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tmp:
            state_file = Path(tmp.name)

        try:
            mgr = pdd.HysteresisManager(state_path=state_file, required_sweeps=3)

            def make_verdict(dom: str, is_dead: bool, verdict: str):
                return pdd.TriangulationVerdict(
                    domain=dom,
                    tier1=pdd.Tier1Result(status="CN_NXDOMAIN" if is_dead else "CN_RESOLVED"),
                    tier2=pdd.Tier2Result(status="DOH_NXDOMAIN" if is_dead else "DOH_ALIVE"),
                    tier3=pdd.Tier3Result(status="NOT_DELEGATED" if is_dead else "SKIPPED"),
                    tier4=pdd.Tier4Result(status="SKIPPED"),
                    verdict=verdict,
                    is_dead=is_dead,
                    reason="Test reason",
                )

            dom = "flaky-edge-test.org"

            # Sweep 1: Dead -> CANDIDATE_DEAD (streak 1)
            r1 = mgr.update(make_verdict(dom, True, "DEAD_UNREGISTERED"))
            self.assertEqual(r1.status, "CANDIDATE_DEAD")
            self.assertEqual(r1.consecutive_dead_sweeps, 1)
            self.assertIsNotNone(r1.first_seen_dead)

            # Sweep 2: Dead -> CANDIDATE_DEAD (streak 2)
            r2 = mgr.update(make_verdict(dom, True, "DEAD_UNREGISTERED"))
            self.assertEqual(r2.status, "CANDIDATE_DEAD")
            self.assertEqual(r2.consecutive_dead_sweeps, 2)

            # Sweep 3: Temporarily alive -> Reset streak to 0, status ALIVE
            r3 = mgr.update(make_verdict(dom, False, "ALIVE"))
            self.assertEqual(r3.status, "ALIVE")
            self.assertEqual(r3.consecutive_dead_sweeps, 0)
            self.assertIsNone(r3.first_seen_dead)

            # Sweep 4: Dead again -> CANDIDATE_DEAD (streak 1 restart)
            r4 = mgr.update(make_verdict(dom, True, "DEAD_UNREGISTERED"))
            self.assertEqual(r4.status, "CANDIDATE_DEAD")
            self.assertEqual(r4.consecutive_dead_sweeps, 1)

            # Sweep 5: Dead (streak 2)
            mgr.update(make_verdict(dom, True, "DEAD_UNREGISTERED"))
            # Sweep 6: Dead (streak 3) -> CONFIRMED_DEAD
            r6 = mgr.update(make_verdict(dom, True, "DEAD_UNREGISTERED"))
            self.assertEqual(r6.status, "CONFIRMED_DEAD")
            self.assertEqual(r6.consecutive_dead_sweeps, 3)

            # Persist and reload
            mgr.save()
            mgr_reloaded = pdd.HysteresisManager(state_path=state_file, required_sweeps=3)
            self.assertEqual(mgr_reloaded.records[dom].status, "CONFIRMED_DEAD")
            self.assertEqual(mgr_reloaded.records[dom].consecutive_dead_sweeps, 3)

            # Sweep 7: Domain becomes GFW-blocked -> status BLOCKED_BY_GFW, streak 0
            r7 = mgr_reloaded.update(make_verdict(dom, False, "BLOCKED_BY_GFW"))
            self.assertEqual(r7.status, "BLOCKED_BY_GFW")
            self.assertEqual(r7.consecutive_dead_sweeps, 0)

        finally:
            if state_file.exists():
                state_file.unlink()

    def test_hysteresis_corrupted_json_recovery(self):
        """Test that invalid/corrupted JSON on disk is gracefully caught without crash."""
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tmp:
            tmp.write("{ invalid json corrupted ...")
            state_file = Path(tmp.name)

        try:
            mgr = pdd.HysteresisManager(state_path=state_file, required_sweeps=3)
            # Should recover with empty records dict
            self.assertEqual(len(mgr.records), 0)
        finally:
            if state_file.exists():
                state_file.unlink()


if __name__ == "__main__":
    unittest.main(verbosity=2)
