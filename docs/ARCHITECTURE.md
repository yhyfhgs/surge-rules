# Architecture

## Sources of truth

| Path | Responsibility |
|---|---|
| `lists/*.list` | Rule content |
| `config/routing.json` | Complete list order, policies, modifiers and contiguous section labels |
| `config/mihomo-runtime.yaml` | DNS, TUN and sniffing settings for the generated Mihomo merge file |
| `clash/` | Generated distribution files |
| `../Surge.conf` | Private local settings and the rendered `[Rule]` section |

`tools/routing_manifest.py` enforces a bijection between manifest entries and
source lists. Duplicate keys/names, missing lists, unknown fields and invalid
metadata fail immediately. Never maintain a second list-order table.

## First-match routing

The earliest matching rule selects the policy. An exact duplicate or a narrow
rule behind its broad coverer adds no coverage. A broad parent may follow
narrower different-policy children: this **ordered-safe split** preserves their
routes and supplies the remaining subtree's fallback. Putting the parent ahead
of any such child creates an active shadow and fails validation.

The v2 manifest separates non-IP and IP stages. Each stage runs Reject, service
proxy, region, then DIRECT lists. YouTube/Streaming are adjacent; Telegram
precedes the other social lists. SYSTEM sits in the DIRECT non-IP block; FINAL
is the only terminal rule. No mixed LAN or unconditional GEOIP,CN tail is emitted.

- Before moving MicrosoftCN behind Microsoft, Microsoft's four broad parents
  are narrowed to explicit service scopes. OneDrive storage/authentication and
  the approved DIRECT exceptions remain protected by independent witnesses.
- Download exceptions precede service owners. Games uses explicit Blizzard
  scopes so the later DIRECT download.blizzard.com remains effective.
- ProxyGFW precedes domestic and regional domain owners. ChinaTLD closes the
  domain stage, preserving prior proxy/Reject/regional .cn exceptions.
- Regional IP calls use AND/NOT to subtract PrivateLANIP, PKUIP, AppleCNIP and
  ChinaIP. This is a boolean exclusion, not an early DIRECT rule. Japan's
  verified LINE/LY prefixes still precede the other regions.

Within a list, all rules share a policy. `tools/sort_lists.py` canonicalizes type
buckets and ordering without changing routing. Cross-list order is semantic;
manifest sections only control rendered comments.

## ProxyGFW contract

ProxyGFW selects `Proxy`; unmatched traffic selects `Final`. Its rules require
current evidence of blocking and no specific ecosystem, service, domestic or
regional owner. It accepts no IP rules, PSL-boundary suffixes, or domains listed
in `config/proxygfw-expired.txt`. Different-policy descendants require narrowing
the GFW rule; shared-cloud CIDRs never establish service ownership.

Registered blocked multitenant platforms may remain whole in this residual
layer. This differs from assigning a tenant namespace to one service. Preserve
`wordpress.com`, `medium.com`, `substack.com`, `fc2.com`, `typepad.com`,
`over-blog.com`, `weebly.com`, `squarespace.com`, `strikingly.com`, `angelfire.com`,
`geocities.jp`, `geocities.co.jp`, `narod.ru`, `no-ip.com`, the `dynamicdns`
family, `mixpanel.com`, `bitbucket.org` and `imgur.com`.

## DNS and observation states

Domain entries match the requested host and, with extended matching, available
TLS SNI/HTTP Host. The IP stage may resolve an unmatched domain through verified
encrypted DNS. `no-resolve` prevents initiating a lookup; it does not disable a
rule after an address is available. Per-list modifiers belong to the manifest.

The engine distinguishes pre-resolved addresses, a successful/failed lookup,
and missing observations. It uses actual Country/ASN MMDB records and never
substitutes small sample networks for release conclusions. A missing DNS answer
returns an incomplete result. `stage=domain` explicitly tests domain ownership;
its Final fallback is not an end-to-end routing claim. Multi-address/family
behavior is checked separately from single-address interval proofs.

Private candidates use global DoH over proxy paths for unmatched classification,
ordered per-list resolver mappings for known domains, and domestic DoH for
DIRECT services. PrivateLAN uses system resolution. Proxy servers on the DNS
paths are verified as IP literals to avoid bootstrap recursion. Keep
`use-local-host-item-for-proxy` false and certificate verification enabled.

## Evidence-controlled IP content

`config/ip-review-exclusions.json` prevents quarantined historical IP rules from
reappearing unchanged. Its readmission records cite fresh registered ownership;
a missing ASN mapping alone is not proof of reassignment. Streaming retains
verified Netflix network scope, Telegram uses the exact published CIDR set,
and stale/shared game probe addresses do not become broad service owners.
ChinaIP remains locked and rebuilt with explicit exclusion/retention guards.

## Relationship analyzer

`tools/analyze_rules.py` writes the following under `--out`:

| Output | Meaning |
|---|---|
| `rules.jsonl` | Every non-comment source rule |
| `relationships.jsonl` | Proven covers, equivalent and overlapping pairs |
| `relationship_aggregates.jsonl` | Exact high-cardinality intersection counts by list/policy |
| `split_apex.jsonl`, `split_parent.jsonl` | Broad parents with different-policy descendants |
| `fragmented_domains.jsonl` | Registrable domains spanning policies |
| `topology.json` | Required list-order edges and strongly connected components |
| `summary.json` | Counts, input hashes, MMDB metadata and diagnostics |

Reversed-label aggregation and exact maps prove domain containment/equality;
glob-automaton products compute keyword/wildcard intersections. The locked PSL
identifies registration boundaries. CIDR prefix ancestry and optional MMDB
interval expansion compare IP selectors. Logical exclusions subtract the
protected address intervals before coverage/intersection analysis. Country/ASN database paths, hashes and
build epochs make MMDB conclusions reproducible. Aggregate counts describe
syntactic intersections, not traffic.

`--fail-on-shadow` rejects active shadows, conflicting equivalents, unsafe
splits, expired-GFW re-entry, GFW IP/PSL-boundary rules and empty MMDB selectors.
The `ordered_safe_split_apex` / `ordered_safe_split_parents` outputs are the
current split registry; `order_unsafe_*` entries require correction. Do not copy
that changing registry into documentation or reorder a constrained pair.

## Derived output and verification

`tools/surge2clash.py` validates sources, renders to a temporary directory and
atomically replaces generated outputs. Unknown rule types abort conversion.
Provider order comes from the same manifest as Surge. Global sniffing
approximates `extended-matching`; SYSTEM is unavailable and the explicit
PrivateLAN/PrivateLANIP lists replace the mixed LAN tail. See the [Clash contract](CLASH.md) for resolver and platform limits.

The [maintenance workflow](MAINTENANCE.md#validate-a-change) combines shape,
relationship, static, behavioral, native syntax and derived-output checks.
Release analysis requires readable Country/ASN MMDB files and `maxminddb`.
Live tests establish runtime behavior; even exact static address-set proofs
cannot replace authenticated application testing. Current service decisions and unresolved traffic questions live in
[Maintenance](MAINTENANCE.md#current-decisions), with dated evidence links.
