# Architecture

## Sources of truth

- `lists/*.list`: rule content.
- `config/routing.json`: complete list order, policy, `extended_matching`,
  list-level `no_resolve` metadata, and the contiguous `section` grouping the
  renderer prints as `[Rule]` partition comments.
- `clash/`: generated output; never edit it directly.
- The active Surge profile: local proxy-group definitions and the rendered
  `[Rule]` section.

`tools/routing_manifest.py` validates a strict bijection between the manifest and
all source lists. Duplicate JSON keys/names, missing lists, unknown fields, and
invalid metadata fail immediately.

## First-match state machine

For a request key $x$ and ordered rules $r_1,\ldots,r_n$, routing is

$$
P(x)=\operatorname{policy}(r_k),\qquad
k=\min\{i\mid r_i\text{ matches }x\}.
$$

Consequences:

1. An exact duplicate in a later list is dead.
2. If a broad rule precedes a narrower different-policy rule, the narrow rule is
   dead.
3. If a narrow exception precedes a broad owner, list order is a semantic
   dependency.
4. A broad registrable-domain suffix must not be used as an accidental default
   when children are intentionally split *and the parent wins*. A broad parent
   that sits behind every different-policy child is an ordered-safe split: each
   child keeps its own policy by first match and the parent only restores the
   fallback for the rest of the subtree. Enumerate the intended subtrees,
   consolidate the service family, or prove the ordered-safe placement.

The only general exception is the immutable security ordering: local/system rules
and `Reject` precede ordinary routing owners.

## Domain and IP phases

Mixed regional lists caused regional domains to sit behind `ProxyGFW` merely to
protect earlier exact IP rules. The topology now separates those concerns.

### Domain phase

```text
local/security
→ precise download/media exceptions
→ service owners
→ domestic direct
   (verified Apple/Microsoft CN endpoints, then curated domestic lists)
→ regional domains
→ residual ProxyGFW
→ generated ChinaDomain
```

The nine domestic-direct lists form one contiguous run. The vendor CN endpoints
and the curated domestic lists share a policy and had no ordering constraint
against the regional lists that once sat between them, so the split was
decorative; clustering them keeps the phase boundary where a policy actually
changes. Order within each run is unchanged.

Regional domains therefore win before generic GFW routing. `ProxyGFW` is
domain-only and contains no PSL-boundary suffixes and no generic cloud CIDRs. It
does hold whole multi-tenant namespaces whose platforms are blocked outright;
see the contract below.

### IP phase

```text
service-owned IP/ASN rules
→ ChinaIP
→ regional ASN/GEOIP fallbacks
→ built-in LAN/GEOIP CN
→ FINAL
```

The ChinaIP-before-GeoIP order is deliberate. The pinned Surge GeoLite databases
contain regional selectors that intersect ChinaIP-owned ranges; placing regional
GeoIP first would send those CN ranges abroad. The LINE/LY ranges are kept as
explicit CIDRs inside `JapanIP` — ahead of that list's own ASN/GEOIP fallback, so
a GeoIP-database drift cannot lose them — and they have zero intersection with
ChinaIP, a property the A9 cross-policy gate keeps guarded.

All IP-class rules use `no-resolve`. A domain request therefore skips the IP
phase without local DNS resolution.

## `ProxyGFW` contract

`ProxyGFW` selects `Proxy`; unmatched traffic selects `Final`. A rule in
`ProxyGFW` must satisfy all of the following:

- no specific ecosystem, service, regional, or domestic owner exists;
- current evidence says proxying is required;
- it is not a shared-cloud CIDR;
- it is not in `config/proxygfw-expired.txt`;
- if children route elsewhere, the GFW rule is exact or explicitly narrowed, not
  a broad registrable-domain suffix.

The multi-tenant clause is directional. A multi-tenant or public-suffix
namespace must never be filed under a *single-service* owner list, because the
tenants are unrelated parties. Keeping a blocked multi-tenant platform's whole
namespace in `ProxyGFW` is the correct outcome, not a violation: `ProxyGFW` is
the residual layer, not a service-ownership table. The registered namespaces
held there are `wordpress.com`, `medium.com`, `substack.com`, `fc2.com`,
`typepad.com`, `over-blog.com`, `weebly.com`, `squarespace.com`,
`strikingly.com`, `angelfire.com`, `geocities.jp`, `geocities.co.jp`,
`narod.ru`, `no-ip.com`, the `dynamicdns` family, `mixpanel.com`,
`bitbucket.org`, and `imgur.com` — 18 entries.

The relationship analyzer makes violations of the first-match contract visible;
the release gate rejects active full shadows, conflicting equivalents, expired
GFW re-entry, GFW IP rules, GFW PSL-boundary suffixes, and order-unsafe splits.

## Exhaustive analyzer

`tools/analyze_rules.py` emits:

- `rules.jsonl`: one record for every non-comment source rule;
- `relationships.jsonl`: provable `covers`, `equivalent`, and `overlaps` edges;
- `relationship_aggregates.jsonl`: exact high-cardinality intersection counts,
  weighted by list and policy bucket;
- `split_apex.jsonl`: broad registrable-domain parents with different-policy
  descendants;
- `split_parent.jsonl`: every suffix, wildcard, or keyword parent with
  different-policy children, including non-registrable parent cases;
- `fragmented_domains.jsonl`: registrable domains spanning policies;
- `topology.json`: list-order constraints and strongly connected components;
- `summary.json`: counts, input hashes, policies, and diagnostics.

### Domain algorithms

- Reversed-label suffix aggregation proves `DOMAIN-SUFFIX` containment and groups
  suffix families without expanding every pair.
- Exact maps prove equivalent `DOMAIN`/suffix sets.
- Keywords and wildcards compile to exact glob automata. Matching those automata
  against reversed suffix families computes every possible intersection exactly.
- Materializable witnesses remain in `relationships.jsonl`; high-cardinality
  keyword/wildcard↔suffix products are emitted compactly to
  `relationship_aggregates.jsonl` as weighted list/policy records with precedence
  metadata.
- The locked Public Suffix List computes registrable-domain boundaries and
  tenant/public-suffix violations.

### IP algorithms

- CIDR blocks use canonical prefix ancestry. Two CIDRs are either disjoint,
  equal, or nested.
- Optional MMDB expansion converts every `GEOIP` and `IP-ASN` selector to merged
  IPv4/IPv6 intervals. Binary-search interval containment then cross-matches all
  selectors with every CIDR and with each other.
- MMDB path, SHA-256, and build epoch are written to `summary.json`; the result is
  reproducible against the same database bytes.

The pre-refactor and post-refactor measurements are recorded in
[RULE_ANALYSIS_2026-09-01.md](RULE_ANALYSIS_2026-09-01.md).

Final syntax verification accounts for 141,679 rules and 1,739 materialized
relations (476 covers / 1,263 overlaps). The compact aggregate represents
3,575,469 exact possible pairs in 960 records: 21,406 same-policy and 3,554,063
split-policy. These are syntactically possible matches, not observed traffic.

Syntax topology has 159 order-dependent exceptions, 118 fragmented domains, and
24 constraints with no cycles. Of its 59 split apexes, 46 are Reject/security
exceptions and 13 are registered ordered-safe splits; `split_parent.jsonl` adds
one non-apex ordered-safe parent, for 14. Order-unsafe splits, active shadows,
and conflicting equivalents are zero. `split_parent.jsonl` is the general
broad-parent gate for suffix, wildcard, and keyword rules; `split_apex.jsonl` is
its registrable-domain view. The final relation classes include 317 redundant
coverage relations, 256 same-policy overlaps, and 1,007 split-policy overlaps.

The 13 registered ordered-safe split apexes restore the FINAL funnel for
`apple.com` (AppleCN), `aliyuncs.com` (AlibabaCN), `myqcloud.com`,
`smtcdns.com`, `wechat.com` (TencentCN), `byteimg.com` (ByteDanceCN),
`bilivideo.com`, `iqiyi.com`, `smtcdns.net` (ChinaMedia), `hf.co` (AI),
`blizzard.com` (Games), and `1drv.com`, `office.net` (MicrosoftCN); the extra
parent is `officeapps.live.com` (MicrosoftCN). Every different-policy child of
each one is placed in an earlier list, so the topology constraints in
`topology.json` are what keeps the split safe. Reordering those lists breaks it.

The runtime MMDB expansion reports 3,413 relations (1,859 covers / 1,554
overlaps), 1,493 order-dependent exceptions, 366 redundant coverage relations,
293 same-policy overlaps, 1,261 split-policy overlaps, 118 fragmented domains,
and 41 constraints. It has no cycles, active shadows, conflicting equivalents, or
empty selectors.

Database selection must match the running profile. When `geoip-maxmind-url` is
set, Surge's downloaded Country database is under its app-support directory; the
ASN database remains bundled. `summary.json` records both paths, hashes, and build
epochs so the result is reproducible. The frozen run used Country
`/Users/fhgs/Library/Application Support/com.nssurge.surge-mac/GeoLite2-Country.mmdb`
(SHA-256 `e1067e503cde899e2f4f584bc6c5fd7bbd3f49a374ea3eb4e3b17dda5a654f32`,
epoch `1787184868`) and bundled ASN
`/Applications/Surge.app/Contents/Resources/GeoLite2-ASN.mmdb` (SHA-256
`b320d77e002b7454b03d18fca803728a57cfd12428ca39e21bc31fab1b0a5f32`,
epoch `1787904925`).

## Zero-local-DNS invariant

The routing closure is:

1. Domain rules inspect the original host.
2. Every IP rule has `no-resolve`; it only sees literal-IP traffic.
3. An unmatched domain reaches `FINAL,Final,dns-failed` and is resolved by the
   selected remote path.
4. `use-local-host-item-for-proxy` remains false and HTTPS/SVCB hints must not be
   allowed to bypass the hostname rule path.

The scenario suite carries 1,326 explicit DNS-leak assertions.

## Clash derivation

`tools/surge2clash.py` loads the canonical manifest, validates all source files,
renders into a temporary directory, and atomically replaces generated outputs.
Unknown rule types abort the transaction. The reference rule sequence in
`clash/rule-providers.yaml` comes from the same manifest as Surge rendering.

Surge `extended-matching` has no provider-level Mihomo equivalent. Mihomo users
must enable HTTP/TLS sniffing when they need SNI/Host matching for literal-IP
connections.

## Verification layers

| Layer | Command | Purpose |
|---|---|---|
| Shape | `tools/sort_lists.py --check` | Canonical in-list type buckets and ordering |
| Relationship | `tools/analyze_rules.py ... --fail-on-shadow` | Exhaustive inventory and topology |
| Static | `tests/audit.py --check all --fail-on P1` | Formatting, DNS, duplicates, PSL, forbidden rules |
| Behavioral | `tests/runsuite.py` | 227 scenarios / 3,099 assertions |
| Native syntax | `surge-cli --check <profile>` | Surge profile acceptance |
| Derived | `tools/surge2clash.py --check` | Source/Clash equality and manifest order |
| Live | `tests/realworld.py --crosscheck` | Running Surge semantics and GeoIP/ASN behavior |

No gate substitutes synthetic fallback data for an unexpected error; parsing,
missing files, unknown types, and invalid topology fail loudly.

Release analysis is never syntax-only: `update.sh` requires `maxminddb`, readable
Country/ASN MMDB files, and a successful full MMDB-expanded analyzer run.
