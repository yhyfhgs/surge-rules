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
4. A broad parent behind every different-policy child is an **ordered-safe
   split**: each child keeps its own policy by first match and the parent only
   restores the fallback for the rest of the subtree. A parent that precedes any
   different-policy child is an active shadow and the gate rejects it.

The only general exception is the immutable security ordering: local/system rules
and `Reject` precede ordinary routing owners.

## Section topology

The manifest groups the lists into six sections (see README for the table):
局域直连 → 广告/恶意拦截 → 下载 → 代理 → 国内直连 → 地区分流 → built-in
LAN / GEOIP,CN / FINAL.

- Download-plane lists precede the service owners because their narrow rules
  must beat broader service suffixes (`GameDownloadCN` < `Games`,
  `ModelDownloadCDN` < `AI`).
- `ProxyGFW` closes the proxy section: domain-only, no PSL-boundary suffixes, no
  cloud CIDRs, no cross-policy intersection with the domestic or regional lists
  that follow it, and it still precedes `ChinaDomain` — which is what the
  poisoned-domain protection actually requires.
- Each regional list carries its domains and its IP fallback (explicit CIDRs,
  then ASN, then GEOIP — every IP line with `no-resolve`). The regional section
  sits after `ChinaIP` because the pinned GeoLite databases contain regional
  selectors that intersect ChinaIP-owned ranges. `Japan` leads the section
  because MaxMind marks part of the verified LINE/LY CIDRs as US; those ranges
  stay as explicit CIDRs inside `Japan`, disjoint from ChinaIP — a property the
  A9 gate keeps guarded.

All IP-class rules use `no-resolve`; a domain request skips every IP rule
without local DNS resolution.

## `ProxyGFW` contract

`ProxyGFW` selects `Proxy`; unmatched traffic selects `Final`. A rule in
`ProxyGFW` must satisfy all of the following:

- no specific ecosystem, service, regional, or domestic owner exists;
- current evidence says proxying is required;
- it is not a shared-cloud CIDR;
- it is not in `config/proxygfw-expired.txt`;
- if children route elsewhere, the GFW rule is exact or explicitly narrowed, not
  a broad registrable-domain suffix.

The multi-tenant clause is directional: a multi-tenant or public-suffix
namespace must never be filed under a *single-service* owner list, but keeping a
blocked platform's whole namespace in `ProxyGFW` is the correct outcome —
`ProxyGFW` is the residual layer, not a service-ownership table. Registered
namespaces held there: `wordpress.com`, `medium.com`, `substack.com`, `fc2.com`,
`typepad.com`, `over-blog.com`, `weebly.com`, `squarespace.com`,
`strikingly.com`, `angelfire.com`, `geocities.jp`, `geocities.co.jp`,
`narod.ru`, `no-ip.com`, the `dynamicdns` family, `mixpanel.com`,
`bitbucket.org`, and `imgur.com`.

## Exhaustive analyzer

`tools/analyze_rules.py` emits, under `--out`:

- `rules.jsonl` — one record per non-comment source rule;
- `relationships.jsonl` — provable `covers` / `equivalent` / `overlaps` edges;
- `relationship_aggregates.jsonl` — exact high-cardinality intersection counts,
  weighted by list and policy bucket (syntactically possible pairs, not traffic);
- `split_apex.jsonl` / `split_parent.jsonl` — broad parents with
  different-policy descendants (registrable-domain view / general view);
- `fragmented_domains.jsonl` — registrable domains spanning policies;
- `topology.json` — list-order constraints and strongly connected components;
- `summary.json` — counts, input hashes, MMDB paths/hashes/epochs, diagnostics.

Domain algorithms: reversed-label suffix aggregation proves containment; exact
maps prove equivalents; keywords and wildcards compile to glob automata whose
products compute every possible intersection exactly; the locked Public Suffix
List computes registrable-domain boundaries. IP algorithms: canonical prefix
ancestry for CIDRs; optional MMDB expansion converts every `GEOIP` / `IP-ASN`
selector to merged intervals for exact cross-matching, with database path,
SHA-256, and build epoch recorded so results are reproducible.

With `--fail-on-shadow` the gate rejects: active shadows, conflicting
equivalents, expired-GFW re-entry, GFW IP rules, GFW PSL-boundary suffixes,
empty MMDB selectors, and order-unsafe splits (`order_unsafe_split_apex` /
`order_unsafe_split_parents` in `summary.json`).

**Ordered-safe split registry.** Non-security splits are permitted only in
ordered-safe form — every different-policy child placed in an earlier list. The
authoritative registry is the analyzer's `ordered_safe_split_apex` /
`ordered_safe_split_parents` output; current members restore the FINAL funnel
for `apple.com` (AppleCN), `aliyuncs.com` (AlibabaCN), `myqcloud.com`,
`smtcdns.com`, `wechat.com` (TencentCN), `byteimg.com` (ByteDanceCN),
`bilivideo.com`, `iqiyi.com`, `smtcdns.net` (ChinaMedia), `hf.co` (AI),
`blizzard.com` (Games), `1drv.com`, `office.net` (MicrosoftCN), plus the
non-apex parent `officeapps.live.com` (MicrosoftCN). Because every child sits in
an earlier list, the `topology.json` constraints are load-bearing: reordering a
constrained pair silently kills the child.

## Zero-local-DNS invariant

1. Domain rules inspect the original host.
2. Every IP rule has `no-resolve`; it only sees literal-IP traffic.
3. An unmatched domain reaches `FINAL,Final,dns-failed` and is resolved by the
   selected remote path.
4. `use-local-host-item-for-proxy` remains false and HTTPS/SVCB hints must not
   bypass the hostname rule path.

The scenario suite carries dedicated DNS-leak assertions for this invariant.

## Clash derivation

`tools/surge2clash.py` loads the canonical manifest, validates all source files,
renders into a temporary directory, and atomically replaces generated outputs.
Unknown rule types abort the transaction. The reference rule sequence in
`clash/rule-providers.yaml` comes from the same manifest as Surge rendering.

Surge `extended-matching` has no provider-level Mihomo equivalent; Mihomo users
must enable HTTP/TLS sniffing to get SNI/Host matching for literal-IP
connections (the contract is spelled out in `clash/rule-providers.yaml`).

## Verification layers

| Layer | Command | Purpose |
|---|---|---|
| Shape | `tools/sort_lists.py --check` | Canonical in-list type buckets and ordering |
| Relationship | `tools/analyze_rules.py … --fail-on-shadow` | Exhaustive inventory and topology |
| Static | `tests/audit.py --check all --fail-on P1` | A1–A10: DNS, duplicates, shadows, PSL, forbidden rules |
| Behavioral | `tests/runsuite.py` | Scenario assertions (counts per CHANGELOG) |
| Native syntax | `surge-cli --check <profile>` | Surge profile acceptance |
| Derived | `tools/surge2clash.py --check` | Source/Clash equality and manifest order |
| Live | `tests/live_check.py` / `tests/realworld.py` | Running-Surge semantics, exits, DNS behavior |

No gate substitutes synthetic fallback data for an unexpected error; parsing,
missing files, unknown types, and invalid topology fail loudly. Release analysis
is never syntax-only: `update.sh` requires `maxminddb`, readable Country/ASN
MMDB files, and a successful full MMDB-expanded analyzer run.
