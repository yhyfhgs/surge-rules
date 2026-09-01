# Maintenance

## Ownership decision

Assign each rule to one owner:

1. Local/system or campus traffic → `PrivateLAN` / `PKU`.
2. Confirmed blocking target → `Reject`.
3. CN game/model bulk download exception → `GameDownloadCN` /
   `ModelDownloadCDN`.
4. Specific ecosystem/service → its owner list (`Google`, `Microsoft`, `AI`,
   `Streaming`, `Games`, and so on).
5. Verified Apple/Microsoft CN endpoint → `AppleCN` / `MicrosoftCN`.
6. Region-bound domain → `Japan`, `UK`, `Europe`, or `US`.
7. Curated domestic domain → `Domestic` or the corresponding CN vendor list.
8. Confirmed proxy-required domain with no owner → `ProxyGFW`.
9. Domestic long tail → generated `ChinaDomain`; never hand-add a rule there.

`config/routing.json` is the canonical order. Do not copy the order into another
script or document.

## Rule invariants

- Move a rule; do not duplicate it in the destination.
- Do not retain a broad suffix, wildcard, or keyword parent when a child
  intentionally uses another routing policy. Use exact hosts/subtrees or
  consolidate the family.
- `Reject` children are the explicit security exception to that rule.
- Never classify a whole shared-cloud CIDR, DDNS namespace, public suffix, or
  private tenant boundary as one service.
- `ProxyGFW` is domain-only. It may not contain IP rules, PSL-boundary suffixes,
  expired domains, or domains with a specific owner.
- Every IP rule has `no-resolve`.
- `USER-AGENT`, `PROCESS-NAME`, and `URL-REGEX` are forbidden in this repository.
- Prefer `DOMAIN`/`DOMAIN-SUFFIX`; use wildcard/keyword rules only with positive
  and negative witnesses.

Before adding `example.com`:

```bash
rg -n 'example\.com' lists
```

If the service has redirects, login, API, media, and CDN endpoints, treat them as
one session family first. Split only source-IP-independent bulk data or a proven
region-specific surface.

## Generated machine layers

### ChinaDomain

`tools/regen_chinadomain.py` loads the routing manifest and removes:

- forbidden types/values;
- rules already owned by earlier lists;
- broad generated parents containing an earlier different-policy child.

Run its shadow/hysteresis workflow described by `--help`; do not bypass its DNS,
blast-radius, pin, or post-removal routing gates.

### ChinaIP

Keep CIDRs canonical:

```bash
python3 tools/collapse_cidr.py lists/ChinaIP.list --check
python3 tools/rebuild.py --id blackmatrix7_china_ip
```

Explicit service ranges may precede ChinaIP. ChinaIP itself precedes regional
GeoIP fallback because pinned GeoLite regional selectors intersect ChinaIP-owned
ranges.

### ProxyGFW expiry

`config/proxygfw-expired.txt` records 766 domains removed after a dual-resolver
NXDOMAIN/authority-failure sweep. The analyzer rejects their re-entry. A domain
may be removed from that denylist only with new DNS and ownership evidence.

## Validate a change

Render a candidate profile so verification uses the new manifest without touching
the active profile:

```bash
python3 tools/render_surge_rules.py ../Surge.conf /tmp/Surge.candidate.conf
surge-cli --check /tmp/Surge.candidate.conf
```

Run all offline gates:

```bash
python3 tools/analyze_rules.py \
  --conf /tmp/Surge.candidate.conf --rules lists \
  --out /tmp/rule-analysis --fail-on-shadow

python3 tests/audit.py \
  --conf /tmp/Surge.candidate.conf --rules lists \
  --check all --fail-on P1

python3 tests/runsuite.py \
  --conf /tmp/Surge.candidate.conf --rules lists
```

Expected behavioral baseline: 208 scenarios, 1,418 requests, 2,639 assertions,
and 1,100 DNS-leak assertions, all passing.

For IP relationship changes, also run MMDB expansion:

```bash
python3 -m pip install -r requirements-analysis.txt

PYTHONPATH=/path/to/maxminddb python3 tools/analyze_rules.py \
  --conf /tmp/Surge.candidate.conf --rules lists \
  --country-db "/Users/fhgs/Library/Application Support/com.nssurge.surge-mac/GeoLite2-Country.mmdb" \
  --asn-db /Applications/Surge.app/Contents/Resources/GeoLite2-ASN.mmdb \
  --out /tmp/rule-analysis-mmdb --fail-on-shadow
```

Inspect `relationships.jsonl`, `relationship_aggregates.jsonl`,
`split_apex.jsonl`, `split_parent.jsonl`, and `topology.json`. Aggregate weights
are exact syntactic intersection counts, not traffic measurements; review their
list/policy buckets rather than judging a change from one total. Any non-security
suffix, wildcard, or keyword record in `split_parent.jsonl` must be narrowed or
assigned one owner.

## Update the active profile

After the candidate passes:

```bash
python3 tools/render_surge_rules.py ../Surge.conf /tmp/Surge.candidate.conf
surge-cli --check /tmp/Surge.candidate.conf
```

Replace the active profile only after reviewing the `[Rule]` diff. The renderer
changes only that section; proxy groups, nodes, MITM, and other private settings
are preserved.

## Derive and publish

```bash
python3 tools/surge2clash.py
python3 tools/surge2clash.py --check
./update.sh "describe the routing change"
```

`update.sh` requires `requirements-analysis.txt` to be installed and readable
Country/ASN databases. `SURGE_COUNTRY_DB_PATH` / `SURGE_ASN_DB_PATH` override
discovery. Otherwise a profile with `geoip-maxmind-url` uses the downloaded Country
database in Surge's app-support directory, while ASN uses the bundled database.
Missing dependencies or databases abort publication; the gate always runs full
MMDB-expanded relationship analysis before static audit, scenarios, transactional
Clash generation, branch/SHA verification, purge, and md5 verification.

Final status meanings:

- `VALIDATED_NOT_PUBLISHED`: gates passed; no distribution change.
- `PUBLISHED_AND_VERIFIED`: push and CDN md5 verification passed.
- `PUBLISHED_BUT_UNVERIFIED`: remote/CDN verification is incomplete; exit is
  nonzero and the publish must not be reported as complete.

## Debugging

For an unexpected route:

```bash
python3 tests/engine.py match example.com --conf /tmp/Surge.candidate.conf --json
surge-cli rule explain example.com
```

- Expected owner loses to an earlier rule → remove/narrow the earlier coverer.
- Expected owner is absent and request reaches `Final` → add an explicit rule to
  the correct owner; do not restore a broad parent.
- Literal IP reaches the wrong region → compare service IP, ChinaIP, and MMDB
  interval edges in the analyzer output.
- DNS assertion fails → locate an IP rule without `no-resolve`; do not add a
  downstream DNS workaround.

The running Surge result is authoritative for runtime semantics; the analyzer
records the exact MMDB bytes needed to reproduce GeoIP/ASN conclusions.
