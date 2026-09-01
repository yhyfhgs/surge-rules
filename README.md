# surge-rules

Surge rules with a generated Mihomo/Clash mirror. `lists/*.list` are the rule
sources; [`config/routing.json`](config/routing.json) is the only source of list
order, policies, `extended-matching`, and `no-resolve` metadata.

Current verified baseline:

- 38 lists and 141,651 source rules.
- 1,711 materialized syntax relations: 448 `covers` and 1,263 `overlaps`.
- 3,575,213 exact keyword/wildcard↔suffix intersection pairs represented compactly
  in 960 weighted records: 21,406 same-policy and 3,553,807 split-policy.
- Syntax topology: 159 order-dependent exceptions, 59 split apexes (46
  Reject/security, 13 ordered-safe), 118 fragmented domains, and 24 constraints.
- Runtime MMDB: 3,385 relations (1,831 `covers` / 1,554 `overlaps`), 1,493
  order-dependent exceptions, 118 fragmented domains, and 41 constraints.
- Both analyses have zero active shadows, conflicting equivalents, cycles, or
  order-unsafe splits, and runtime selectors are all non-empty. Non-security
  splits are permitted only in ordered-safe form — every different-policy child
  placed in an earlier list — and 14 are registered.
- 227 scenarios, 1,644 requests, 3,099 assertions, and 1,326 DNS-leak assertions.

## Routing model

Surge is first-match-wins. The manifest groups the 34 lists into six sections:

| Section | Lists | Purpose |
|---|---|---|
| 局域直连 | PrivateLAN, PKU | Local and campus traffic |
| 广告/恶意拦截 | Reject | Global reject overrides |
| 下载 | GameDownloadCN, ModelDownloadCDN, DownloadCDN | Bulk-download planes whose narrow rules must beat broader service owners |
| 代理 | YouTube, Google, Twitter, Meta, Microsoft, AI, TikTok, SocialOthers, Telegram, Streaming, Games, Payment, ProxyGFW | Service/session ownership, closed by the domain-only proxy residual |
| 国内直连 | AppleCN, MicrosoftCN, Domestic, ChinaMedia, TencentCN, AlibabaCN, ByteDanceCN, BaiduCN, NetEaseCN, ChinaDomain, ChinaIP | One contiguous DIRECT run: vendor CN endpoints, curated domestic, generated long tail, authoritative CN ranges |
| 地区分流 | Japan, US, UK, Europe | Region-bound domains plus each region's IP fallback in one hybrid list; sits after ChinaIP so GeoLite selectors cannot pull CN ranges abroad, with Japan first so `GEOIP,US` cannot capture the LINE/LY CIDRs |
| Terminal | LAN, GEOIP CN, FINAL | Built-in safety and unmatched traffic |

`ProxyGFW` uses `Proxy`; terminal `FINAL` uses `Final`. They are deliberately
different policies. Shared cloud CIDRs, public-suffix tenant spaces, dead domains,
and domains with a specific service owner do not belong in `ProxyGFW`.

## Repository

```text
config/routing.json             canonical topology
config/proxygfw-expired.txt     dead-domain re-entry denylist
lists/*.list                    Surge sources
clash/*.list                    generated Mihomo sources
tools/analyze_rules.py          exhaustive relationship analyzer
tools/sort_lists.py             in-list type-bucket sorter and its gate
tools/render_surge_rules.py     render manifest order into a Surge profile
tools/surge2clash.py            regenerate Clash outputs
tests/audit.py                  structural checks
tests/runsuite.py               behavioral regression suite
docs/ARCHITECTURE.md            invariants and algorithms
docs/MAINTENANCE.md             edit/verify/publish workflow
tests/README.md                 test suite operation
```

Per-batch evidence and decisions live in `CHANGELOG.md`; superseded diagnostic
reports are recoverable from git history, cited from the entry that replaced them.

## Verify

```bash
# Every list is in canonical type-bucket order.
python3 tools/sort_lists.py --check

# Render and validate a candidate profile without touching the active profile.
python3 tools/render_surge_rules.py ../Surge.conf /tmp/Surge.candidate.conf
surge-cli --check /tmp/Surge.candidate.conf

# Every source rule is emitted to rules.jsonl and analyzed.
python3 tools/analyze_rules.py \
  --conf /tmp/Surge.candidate.conf --rules lists \
  --out /tmp/rule-analysis --fail-on-shadow

python3 tests/audit.py \
  --conf /tmp/Surge.candidate.conf --rules lists \
  --check all --fail-on P1
python3 tests/runsuite.py \
  --conf /tmp/Surge.candidate.conf --rules lists

# Derived layer must match the sources and manifest.
python3 tools/surge2clash.py --check
```

For a complete ASN/GEOIP cross-match, pass Surge's pinned MMDB files and make
`maxminddb` available:

```bash
python3 -m pip install -r requirements-analysis.txt

python3 tools/analyze_rules.py \
  --conf /tmp/Surge.candidate.conf --rules lists \
  --country-db "/Users/fhgs/Library/Application Support/com.nssurge.surge-mac/GeoLite2-Country.mmdb" \
  --asn-db /Applications/Surge.app/Contents/Resources/GeoLite2-ASN.mmdb \
  --out /tmp/rule-analysis-mmdb --fail-on-shadow
```

The active profile sets `geoip-maxmind-url`, so Surge stores the runtime Country
database in its app-support directory; the ASN database remains bundled with the
application. Analyze the same pair the running profile uses.

## Edit and publish

1. Move a rule from its old owner to its new owner; never duplicate it.
2. Do not add a broad suffix, wildcard, or keyword parent when narrower rules use
   another policy. Use explicit hosts/subtrees or unify the service family.
3. Every IP rule must include `no-resolve`.
4. Run the verification commands above.
5. Run `python3 tools/surge2clash.py` to refresh `clash/`.
6. Publish with `./update.sh "message"`.

`update.sh` requires the analysis dependency and readable Country/ASN MMDB files.
`SURGE_COUNTRY_DB_PATH` / `SURGE_ASN_DB_PATH` override discovery; otherwise the
Country path follows `geoip-maxmind-url` and the ASN path uses Surge's bundled
database. It runs the full MMDB-expanded analysis before static audit, scenarios,
Clash generation, push verification, jsDelivr purge, and CDN md5 verification.

## Consumers

Surge URL:

```text
https://cdn.jsdelivr.net/gh/yhyfhgs/surge-rules@main/lists/<Name>.list
```

Mihomo URL:

```text
https://cdn.jsdelivr.net/gh/yhyfhgs/surge-rules@main/clash/<Name>.list
```

Use the generated reference order in
[`clash/rule-providers.yaml`](clash/rule-providers.yaml). Do not hand-edit files
under `clash/`.

Upstream provenance is in [SOURCES.md](SOURCES.md). Historical changes are in
[CHANGELOG.md](CHANGELOG.md).
