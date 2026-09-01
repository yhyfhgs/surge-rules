# Rule topology analysis — 2026-09-01

Status: verified diagnostic baseline for the rule refactor. This document records analysis evidence; it is not a generated rule source. The two dated audit reports in this directory are historical and superseded.

## Scope and reproducibility

The baseline analyzer read 34 lists; the refactored manifest references 39. Each run accounts for every parsed rule. It extracts domain rules (`DOMAIN`, `DOMAIN-SUFFIX`, `DOMAIN-KEYWORD`, `DOMAIN-WILDCARD`) and IP rules (`IP-CIDR`, `IP-CIDR6`, `IP-ASN`, `GEOIP`). It normalizes IDNA/domain case and IP networks, then matches:

- suffix, keyword, wildcard, and exact-domain containment;
- IPv4/IPv6 CIDR containment;
- exact selector equivalence;
- intersections with a generated witness where applicable;
- cross-list policy effects and order constraints;
- registrable-domain fragmentation and apex/subdomain splits.

Each input rule is emitted to `rules.jsonl`; relations retain both source list and line ID. The analyzer fails on malformed or unsupported rule syntax rather than silently dropping it. Its output is written outside the repository so diagnostics do not mutate rule inputs.

Historical plain-syntax run (from the repository root):

```sh
python3 tools/analyze_rules.py \
  --conf "../Surge.conf" \
  --rules lists \
  --psl tests/data/public_suffix_list.dat \
  --out /private/tmp/surge-rule-analysis-baseline
```

Current outputs are `summary.json`, `rules.jsonl`, `relationships.jsonl`,
`relationship_aggregates.jsonl`, `split_apex.jsonl`, `split_parent.jsonl`,
`fragmented_domains.jsonl`, and `topology.json`. Historical runs below predate the
compact aggregate and generalized split-parent artifacts; their recorded metrics
are preserved exactly.

## Historical pre-refactor plain-syntax baseline

The plain run accounts for `142707` rules: `129421` domain-family rules and `13286` IP-family rules. It found `2134` syntax relationships:

| Relation | Count | Meaning |
|---|---:|---|
| `covers` | 2074 | The left match language contains the right language/address set. |
| `equivalent` | 3 | Both rules match the same language/address set. |
| `overlaps` | 57 | The languages/address sets intersect but neither contains the other. |

The verified routing consequences and topology diagnostics are:

| Finding | Count | Interpretation |
|---|---:|---|
| Order-dependent exceptions | **741** | Opposite-policy containment whose winner depends on list order; an ordering constraint, not an automatic deletion list. |
| Split apex rules | **200** | An apex/suffix rule spans subdomains that are assigned different policies. The broad rule must be removed or narrowed when the split is intentional. |
| Fragmented registrable domains | **228** | One registrable domain is represented across multiple policies/lists. These are session-consistency review units. |
| Conflicting equivalent domain duplicates | **2** | `AI.list:212`/`ChinaDomain.list:58740` and `AI.list:323`/`ChinaDomain.list:79635` (`lingyiwanwu.com` and `skywork.ai`). |
| Active CIDR shadow | **1** | `Google.list:672` (`74.125.0.0/16`) covers `ChinaIP.list:1346` (`74.125.16.64/26`) with an earlier, different policy. |
| Topology cycles | **0** | The policy-order constraint graph is topologically sortable for this run. |

These results confirm that the hierarchy problem is real: broad rules and narrower exceptions are not merely co-located; 741 cross-policy outcomes can change when list order changes. The 200 split-apex findings directly implement the refactor rule that an apex cannot remain as a broad fallback when its subdomains require separate routing.

## Historical pre-refactor MMDB-expanded verification

The second run uses the same 142707 source rules and adds address-set evidence for `IP-ASN` and `GEOIP` selectors. It was run as:

```sh
python3 tools/analyze_rules.py \
  --conf "../Surge.conf" \
  --rules lists \
  --psl tests/data/public_suffix_list.dat \
  --country-db "/Applications/Surge.app/Contents/Resources/GeoLite2-Country.mmdb" \
  --asn-db "/Applications/Surge.app/Contents/Resources/GeoLite2-ASN.mmdb" \
  --out /private/tmp/surge-rule-analysis-mmdb2
```

The result is `4143` relationships: `3650` covers, `4` equivalent, and `489` overlaps. The increase is selector/address-set evidence, not additional source rules. The expanded run reports `1838` order-dependent exceptions, `442` active shadows, `2` conflicting equivalents, `1370` redundant coverage relations, `2` redundant equivalents, `91` same-policy overlaps, and `398` split-policy overlaps.

Input provenance recorded in `/private/tmp/surge-rule-analysis-mmdb2/summary.json`.
Both historical MMDB paths were under
`/Applications/Surge.app/Contents/Resources/`:

| Input | SHA-256 | Build/data timestamp |
|---|---|---|
| `../Surge.conf` | `38a50dd50df21e4ce187ccf3380b5634aa6f4f558329eaa7907d6aafa59d05b8` | profile snapshot used by both runs |
| `GeoLite2-ASN.mmdb` | `b320d77e002b7454b03d18fca803728a57cfd12428ca39e21bc31fab1b0a5f32` | epoch `1787904925` = 2026-08-28 08:15:25 UTC (16:15:25 Asia/Shanghai) |
| `GeoLite2-Country.mmdb` | `7e5e06e029f44384ea9a6f086b20b6a09614922b9161de69b90a2598cf14225b` | epoch `1787931904` = 2026-08-28 15:45:04 UTC (23:45:04 Asia/Shanghai) |

The MMDB is evidence for selector containment/intersection only. It does not prove that a cloud address belongs to a particular product, and it must not be used as a substitute for first-party ownership evidence.

## Post-refactor verification

The frozen syntax run was reproduced with the shadow gate enabled:

```sh
python3 tools/analyze_rules.py \
  --conf "../Surge.conf" \
  --rules lists \
  --psl tests/data/public_suffix_list.dat \
  --out /private/tmp/surge-rule-analysis-final \
  --fail-on-shadow
```

It accounts for **141,829** rules across 39 lists and materializes **1,630**
relations: **367 covers** and **1,263 overlaps**. The classified results include
**287 redundant coverage relations**, **256 same-policy overlaps**, and **1,007
split-policy overlaps**.

Keyword/wildcard↔suffix analysis additionally finds **3,579,582 exact possible
intersection pairs**. These are stored compactly in
`relationship_aggregates.jsonl` as **960 weighted records** keyed by list/policy
with precedence metadata, not expanded into millions of `relationships.jsonl`
rows:

| Aggregate dimension | Weighted pairs |
|---|---:|
| Same policy | 21,554 |
| Split policy | 3,558,028 |

The weights are exact syntactic match-language intersections computed by glob
automata against reversed suffix aggregates. They are not DNS observations,
request counts, or production traffic.

| Diagnostic | Before | After |
|---|---:|---:|
| Active shadows / conflicting equivalents | 3 | **0** |
| Order-dependent exceptions | 741 | **80** |
| Split registrable-domain apexes | 200 | **46** |
| Non-security split apexes | not separately classified | **0** (superseded, see below) |
| Non-security broad parents | not separately classified | **0** (superseded, see below) |
| Fragmented registrable domains | 228 | **119** |
| List topology constraints | 60 | **13** |
| Topology cycles | 0 | **0** |

All remaining 46 split apexes are `Reject`/security exceptions. The generalized
`split_parent.jsonl` gate covers suffix, wildcard, and keyword parents;
`split_apex.jsonl` is its registrable-domain projection.

**The "zero non-security split apexes" target is superseded.** Driving that
number to zero meant demoting apex suffixes to exact `DOMAIN` rules, which cut
the FINAL funnel for whole subtrees — `appleid.apple.com`,
`oss-cn-beijing.aliyuncs.com`, `cos.ap-guangzhou.myqcloud.com`, `api.iqiyi.com`
and many more stopped matching any rule at all. The invariant is now stated in
terms of order, not shape: a non-security split is permitted when the broad
parent sits behind every different-policy child, so first match still gives each
child its own policy. See the follow-up section.

Install the pinned analysis dependency before reproducing the final MMDB run:

```sh
python3 -m pip install -r requirements-analysis.txt

python3 tools/analyze_rules.py \
  --conf "../Surge.conf" \
  --rules lists \
  --psl tests/data/public_suffix_list.dat \
  --country-db "/Users/fhgs/Library/Application Support/com.nssurge.surge-mac/GeoLite2-Country.mmdb" \
  --asn-db "/Applications/Surge.app/Contents/Resources/GeoLite2-ASN.mmdb" \
  --out /private/tmp/surge-rule-analysis-final-mmdb \
  --fail-on-shadow
```

The final expanded run reports **3,304 relations** (**1,750 covers / 1,554
overlaps**), **1,414 order-dependent exceptions**, **336 redundant coverage
relations**, **293 same-policy overlaps**, **1,261 split-policy overlaps**, **119
fragmented domains**, and **30 topology constraints**. It has zero active shadows,
conflicting equivalents, empty selectors, or cycles.
The verified order is service-owned IP → ChinaIP → regional ASN/GEOIP
fallback.

The active profile sets `geoip-maxmind-url`, so the runtime Country database is
the downloaded app-support copy rather than the historical bundled Country file.
ASN remains bundled:

| Runtime input | SHA-256 | Build/data epoch |
|---|---|---:|
| `/Users/fhgs/Library/Application Support/com.nssurge.surge-mac/GeoLite2-Country.mmdb` | `e1067e503cde899e2f4f584bc6c5fd7bbd3f49a374ea3eb4e3b17dda5a654f32` | `1787184868` |
| `/Applications/Surge.app/Contents/Resources/GeoLite2-ASN.mmdb` | `b320d77e002b7454b03d18fca803728a57cfd12428ca39e21bc31fab1b0a5f32` | `1787904925` |

Additional enforced results:

- `ProxyGFW` has zero IP rules, PSL-boundary suffixes, or expired-domain re-entry.
- The two ChinaDomain/AI duplicate domains and the two ChinaIP ownership
  duplicates are removed at their generation source.
- `ProxyGFW` is a domain-only residual after dead domains, tenant/public-suffix
  rules, shared-cloud CIDRs, and classifiable service assets were deleted or
  migrated.
- All scenarios pass; the count grew to 227 scenarios / 1,644 requests / 3,099
  assertions, including 1,326 DNS-leak assertions, after the follow-up below.

## Follow-up: 2026-09-01 ordered-safe correction

Post-refactor verification found that the apex demotions above had removed the
fallback for entire service subtrees. Sixteen exact apexes were re-promoted to
`DOMAIN-SUFFIX` after proving, one at a time, that every different-policy rule
under the registrable domain lives in an earlier list; the same criterion
rejected `qcloud.com`, `mi.com`, `naver.com`, and `azure.com`, which each keep a
later different-policy child.

The release gate was re-scoped to match: `tools/analyze_rules.py` still reports
every non-security split, but `--fail-on-shadow` now fails only on
`order_unsafe_split_apex` / `order_unsafe_split_parents`, alongside the existing
active-shadow, expired-re-entry, GFW-IP, and PSL-boundary checks. The
ordered-safe entries are listed separately in `summary.json`.

| Diagnostic | 09-01 refactor | After correction |
|---|---:|---:|
| Source rules | 141,829 | **141,679** |
| Materialized relations | 1,630 (367 covers) | **1,739 (476 covers)** |
| Order-dependent exceptions | 80 | **159** |
| Split registrable-domain apexes | 46 | **59** (46 security + 13 ordered-safe) |
| Order-unsafe splits | not classified | **0** |
| Fragmented registrable domains | 119 | **118** |
| List topology constraints | 13 | **24** |
| Active shadows / conflicting equivalents | 0 | **0** |
| MMDB relations | 3,304 (1,750 covers) | **3,413 (1,859 covers)** |
| MMDB order-dependent exceptions | 1,414 | **1,493** |
| MMDB topology constraints | 30 | **41** |
| Scenario assertions | 2,639 | **3,099** |

Order-dependent exceptions roughly doubled by construction: each ordered-safe
apex turns its pre-placed children into recorded order dependencies. That is the
mechanism working, not drift — but it does mean `topology.json` constraints are
now load-bearing, and reordering a constrained list pair would silently kill the
children it protects.

The same batch migrated 49 rules out of `ProxyGFW` (Longbridge OpenAPI to
`Domestic`, Google `.new` shortcuts to `Google`, the Aylo family to `Streaming`,
and regional media/commerce to `Japan`/`UK`/`Europe`/`US`) and removed 169 more:
167 DNS-dead domains registered in `config/proxygfw-expired.txt` (766 → 933),
plus `clipfish.de` (301 to `watchbox.de`) and `prosiben.de` (a misspelling whose
correct form was already in `Europe`).

## Policy separation and target topology

The canonical manifest and rendered profile route `ProxyGFW` to `Proxy` and the
terminal `FINAL` rule to `Final`. `ProxyGFW` is therefore a live residual proxy
policy, not a synonym for the unknown-traffic fallback. Any earlier conclusion
based on `ProxyGFW == Final` is superseded.

The target topology is a deterministic first-match flow. Broad rules must never precede a narrower rule that needs a different policy:

```text
local / LAN / campus exceptions
        ↓
reject and security block layer
        ↓
exact service exceptions and separable data-plane downloads
        ↓
service-owned domain/control/session layers
        ↓
regional domains
        ↓
vendor-specific CN direct layers
        ↓
ProxyGFW: only uncategorized, definitively proxy-required residuals
        ↓
ChinaDomain long-tail fallback
        ↓
verified service IP → ChinaIP → regional ASN/GEOIP fallback
        ↓
FINAL: unknown traffic only
```

Domain and IP branches must be analyzed separately: a domain rule expresses ownership/host semantics, while an IP rule expresses an address-set fallback. A shared cloud ASN, CDN, or hosting suffix is not a product identity. Region rules belong before the broad proxy residual whenever a region-specific outcome is intended; otherwise the residual can preempt them and make the regional layer appear redundant.

## Applied refactoring criteria and review boundaries

The analyzer identifies candidates; it does not infer business ownership from syntax alone. The following categories have sufficient structural or existing evidence to prioritize, with each concrete move still checked against its source/provenance and expected post-migration winner:

| Category | Refactoring rule | Examples/evidence to verify |
|---|---|---|
| Intentional apex splits | Remove a broad apex/suffix only from a layer that *precedes* the narrower split; a parent placed behind all of its different-policy children may stay. | The pre-refactor 200 records are reduced to 46 Reject/security exceptions plus 13 registered ordered-safe splits. |
| Public multi-tenant download suffixes | Remove generic `cloudfront.net`, `s3.amazonaws.com`, `github.io`, `vercel.app`, `workers.dev`, and similar platform-wide suffixes from download policy; retain only exact, proven data endpoints. | DownloadCDN’s shared-platform matches and the cross-policy containment records. |
| Download/session companions | Move authentication, API, account, payment, telemetry, and site-control hosts out of a generic download/data-plane list into their owning service or Payment/shared layer. | Final fragmented-domain review units: 119. |
| Region-locked service families | Keep login/control/playback hosts that require a country together in the region list; split only an independently verified, session-independent byte-delivery endpoint. | BBC/UK playback hosts, DLsite, Telegraph, Cygames, and Niconico/Dwango are high-confidence review families from the prior evidence set. |
| CN vs international vendor surfaces | Use exact host or vendor-CN rules for proven direct endpoints; do not let a broad CN apex capture known international subdomains. | Microsoft `live.com`/OneDrive boundary and Google `-cn` mirror vs `.cn` endpoint evidence. |
| Payment and anti-fraud chain | Keep checkout, authentication, 3DS, and fraud-decision dependencies on the same stable policy. | ThreatMetrix/`h.online-metrix.net` is a Payment candidate; generic analytics remains separate unless the session evidence says otherwise. |
| Shared cloud IP/ASN selectors | Remove or quarantine shared-provider ranges unless first-party ownership is proven; use expiry metadata for dynamic single-IP rules. | Google Cloud, AWS, Tencent Cloud, and other provider-wide ranges in IP relation output. |
| ProxyGFW reclassification | Move a rule to a dedicated owner/region/CN/Payment list when evidence supports that category. Keep it in ProxyGFW only when no narrower category applies and proxying is definite. | Final contract: zero GFW IP, PSL-boundary, or expired rules; zero active/conflicting relationships. |

Every migration must be checked in the actual sequential flow: the old winner, new winner, all narrower descendants, and the deletion fallback must be recorded. A syntactically equivalent move is not sufficient if it changes a login/payment/session exit.

## Comment and documentation debt

The comment-debt finding is confirmed primarily at the documentation/history layer. The two dated audit files contained `1483 + 1102 = 2585` lines of overlapping narrative, stale counts, and completed-action history. The lists themselves were not broadly comment-heavy; the long headers concentrated most of the debt. Mutable history does not belong beside generated rules.

The maintenance rule is therefore: keep a short purpose statement and non-obvious invariant beside a list; keep evidence, counts, and dated decisions in this analysis/reference tree; do not use comments as a second audit log. The two old reports are reduced to archival stubs below, while their full text remains recoverable from git history and the supporting artifacts under `reference/audit-v2-20260831/`.

## Evidence locations and limits

- Historical pre-refactor plain artifacts: `/private/tmp/surge-rule-analysis-baseline/`.
- Historical pre-refactor MMDB artifacts: `/private/tmp/surge-rule-analysis-mmdb2/`.
- Final artifacts are reproducible with the post-refactor commands above; each
  `summary.json` records input hashes and MMDB provenance.
- Prior network and per-worker evidence: `reference/audit-v2-20260831/`.
- Full historical audit text: git history at `e03c530` and `5dcd5ec`.

Static matching proves syntax, containment, intersection, and order effects. It does not prove current traffic volume, service ownership of a shared platform, or that every endpoint in a fragmented registrable domain must share an exit. Such changes remain evidence-gated and must be validated by the rule engine and scenario suite after implementation.
