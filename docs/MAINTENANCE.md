# Maintenance

## Ownership decision

Assign each rule to one owner:

1. Local/system or campus traffic → `PrivateLAN` / `PKU`.
2. Confirmed blocking target → `Reject`.
3. CN game/model bulk download exception → `GameDownloadCN` / `ModelDownloadCDN`.
4. Specific ecosystem/service → its owner list (`Google`, `Microsoft`, `AI`,
   `Streaming`, `Games`, …).
5. Verified Apple/Microsoft CN endpoint → `AppleCN` / `MicrosoftCN`.
6. Curated domestic domain → `Domestic` or the corresponding CN vendor list.
7. Region-bound domain → `Japan`, `UK`, `Europe`, or `US`.
8. Confirmed proxy-required domain with no owner → `ProxyGFW`.
9. Domestic long tail → generated `ChinaDomain`; never hand-add a rule there.
10. `.cn` / CNNIC IDN host with no owner above → nothing to add: the terminal
    `ChinaTLD` catch-all already routes it DIRECT. Add an explicit `.cn` entry
    to `Domestic` only when it must precede a broader different-policy rule.

Steps 5–7 are mutually exclusive by construction: no host matched by the
domestic-direct lists is matched by any regional list, so the tree reads
top-down without backtracking. `config/routing.json` is the canonical order —
do not copy it into another script or document.

Before adding `example.com`, find its current owner first:

```bash
rg -n 'example\.com' lists
```

If the service has redirects, login, API, media, and CDN endpoints, treat them
as one session family; split only source-IP-independent bulk data or a proven
region-specific surface.

## Rule invariants

- Move a rule; do not duplicate it in the destination.
- A broad suffix/wildcard/keyword parent may keep a different-policy child only
  **ordered-safe**: every such child must sit in an earlier list, proven by list
  indices in `config/routing.json` before promoting an apex. One failing child
  means the apex is not promoted. `Reject` children are the explicit security
  exception (Reject precedes every routing owner).
- Never classify a whole shared-cloud CIDR, DDNS namespace, public suffix, or
  private tenant boundary as one service. (Blocked multi-tenant platforms
  staying whole in `ProxyGFW` is not such a classification — it is the residual
  layer.)
- `ProxyGFW` is domain-only: no IP rules, no PSL-boundary suffixes, no expired
  domains, no domains with a specific owner.
- Every IP rule has `no-resolve`.
- `USER-AGENT`, `PROCESS-NAME`, and `URL-REGEX` are forbidden repo-wide (A8, no
  exemptions).
- Prefer `DOMAIN`/`DOMAIN-SUFFIX`; use wildcard/keyword rules only with positive
  and negative witnesses.

## List sort order

Every `lists/*.list` is stored in one canonical shape, produced and enforced by
`tools/sort_lists.py`: rules grouped into fixed type buckets (`DOMAIN` →
`DOMAIN-SUFFIX` → `DOMAIN-WILDCARD` → `DOMAIN-KEYWORD` → `IP-CIDR` →
`IP-CIDR6` → `IP-ASN` → `GEOIP`; any other type is an error), deterministic
order inside each bucket, trailing comments and `,no-resolve` traveling with
their rule byte for byte, buckets separated by one blank line.

Order inside a list carries no routing meaning — a rule-set has a single policy.
Only the list order in `config/routing.json` is load-bearing. Do not hand-sort:
run `python3 tools/sort_lists.py --write` and let `--check` gate it.

The manifest also groups rulesets into contiguous named `section`s;
`tools/render_surge_rules.py` prints one `# <index> <section>` comment per
switch. Sections are presentation only.

## Generated machine layers

### ChinaDomain

`tools/regen_chinadomain.py` loads the routing manifest and removes forbidden
types/values, rules already owned by earlier lists, and broad generated parents
containing an earlier different-policy child. Run its shadow/hysteresis workflow
described by `--help`; do not bypass its DNS, blast-radius, pin, or post-removal
routing gates.

### ChinaIP

```bash
python3 tools/collapse_cidr.py lists/ChinaIP.list --check
python3 tools/rebuild.py --id blackmatrix7_china_ip
```

The upstream is a geolocation-database export, not an RIR feed, and it carries
foreign allocations. `config/chinaip-exclusions.txt` holds every range the
ownership audit proved non-CN under the RIR/RDAP tier; the `exclude_cidr`
transform in `sources.lock.json` subtracts it during every rebuild, so an
upstream refresh cannot silently re-import them. Re-admitting a range requires
fresh RDAP evidence recorded next to its line. Evidence-conflicted segments stay
in ChinaIP deliberately — conservative direct.

ChinaIP precedes regional GeoIP fallback because pinned GeoLite regional
selectors intersect ChinaIP-owned ranges. A verified service range only needs
its own list ahead of ChinaIP when the two actually intersect; when disjoint it
belongs in the regional list it shares a policy with (the LINE/LY CIDRs in
`Japan` are the worked example). Recompute that disjointness before moving any
CIDR across the ChinaIP boundary; A9 rejects a regression.

### ProxyGFW expiry

`config/proxygfw-expired.txt` records domains removed after dual-resolver
NXDOMAIN/authority-failure sweeps; the analyzer rejects their re-entry. A domain
may be removed from the denylist only with new DNS and ownership evidence.
Domains dropped for a non-DNS reason (migration, misspelling) are removed from
`ProxyGFW` without being registered here — the denylist means "resolves
nowhere", not "should not be proxied".

## Validate a change

```bash
python3 tools/sort_lists.py --check

python3 tools/render_surge_rules.py ../Surge.conf /tmp/Surge.candidate.conf
surge-cli --check /tmp/Surge.candidate.conf

python3 tools/analyze_rules.py --conf /tmp/Surge.candidate.conf --rules lists \
  --out /tmp/rule-analysis --fail-on-shadow

python3 tests/audit.py --conf /tmp/Surge.candidate.conf --rules lists \
  --check all --fail-on P1
python3 tests/runsuite.py --conf /tmp/Surge.candidate.conf --rules lists
```

For IP relationship changes, run the MMDB expansion too (command in README).
Inspect `relationships.jsonl`, `relationship_aggregates.jsonl`,
`split_apex.jsonl`, `split_parent.jsonl`, and `topology.json`. Aggregate weights
are exact syntactic intersection counts, not traffic. A non-security record in
`split_parent.jsonl` must either be ordered-safe (listed under
`ordered_safe_split_parents`) or be narrowed or assigned one owner; anything
under `order_unsafe_*` fails the gate.

## Update the active profile

After the candidate passes, replace the active profile only after reviewing the
`[Rule]` diff. The renderer changes only that section; proxy groups, nodes,
MITM, and other private settings are preserved.

Re-render whenever `config/routing.json` changes, not only when a list changes.
The active profile has silently fallen a batch behind before;
`render_surge_rules.py --check ../Surge.conf` is the gate that catches it — run
it as part of every batch.

### Profile red lines

These constrain the active profile, which lives outside this repository:

- Certificate material — the CA `.p12` and its passphrase — must never enter
  this repository (public, permanent history).
- Do not write an `enable` key into `[MITM]`; Surge strips it on normalization
  and the switch lives in the GUI runtime.
- While `[MITM] hostname` is non-empty, `auto-quic-block` must be `true`,
  otherwise HTTP/3 to a decrypted host bypasses MITM. `tests/realworld.py
  --ua-routing` asserts the pair.

## Derive and publish

```bash
python3 tools/surge2clash.py
python3 tools/surge2clash.py --check
./update.sh "describe the routing change"
```

`update.sh` requires `requirements-analysis.txt` installed and readable
Country/ASN databases (`SURGE_COUNTRY_DB_PATH` / `SURGE_ASN_DB_PATH` override
discovery). It runs the full MMDB-expanded analysis, static audit, scenarios,
transactional Clash generation, branch/SHA verification, then purges exactly the
published distribution surface (`lists/*.list`, `clash/*.list`,
`clash/rule-providers.yaml`) and verifies CDN md5.

Final status: `VALIDATED_NOT_PUBLISHED` (gates passed, no distribution change) /
`PUBLISHED_AND_VERIFIED` / `PUBLISHED_BUT_UNVERIFIED` (nonzero — rerun later to
re-purge; never report an unverified publish as complete).

## Debugging

```bash
python3 tests/engine.py match example.com --conf /tmp/Surge.candidate.conf --json
surge-cli rule explain example.com
```

- Expected owner loses to an earlier rule → remove/narrow the earlier coverer.
- Expected owner absent, request reaches `Final` → add an explicit rule to the
  correct owner, or restore the apex suffix once ordered-safe placement is
  proved for every different-policy child.
- Literal IP reaches the wrong region → compare service IP, ChinaIP, and MMDB
  interval edges in the analyzer output.
- DNS assertion fails → locate an IP rule without `no-resolve`; do not add a
  downstream DNS workaround.

The running Surge result is authoritative for runtime semantics; the analyzer
records the exact MMDB bytes needed to reproduce GeoIP/ASN conclusions.

## Open decisions

These cannot be settled by static analysis; neither is a defect, and neither may
be "resolved" by a syntax-only change.

| Item | What is unresolved | What would settle it |
|---|---|---|
| `Streaming` IP surface | Whether every CIDR still belongs to a streaming provider, and whether any range should move to a regional or service owner | Real traffic capture plus a shadow-routing comparison against the live profile |
| OneDrive data plane | How deep `1drv.com` / `livefilestore.com` / `microsoftpersonalcontent.com` should be owned by `MicrosoftCN` versus `Microsoft`, given the poisoning stopgap | Connectivity measurement from a CN vantage point on both exits |

Microsoft session-face normalization is a third open item: `microsoft.com`,
`live.com`, `msn.com`, and `office.com` keep their mixed exact/suffix shape
because the `ms_boundary_*` scenarios in `tests/scenarios/services.json` lock
the current boundary. Changing it needs new connectivity evidence.
