# Maintenance

Commands run from the repository root. The [architecture](ARCHITECTURE.md)
defines ordering and DNS invariants; `config/routing.json` alone defines list
order and policy. Keep private profiles, credentials and diagnostic output
outside this public repository. Never touch `../Backup/`.

## Edit rules

1. Find the current owner with `rg -n 'example\.com' lists`.
2. Use local/campus or Reject ownership first, then evidenced bulk-download
   exceptions, service owners, domestic owners, regions, or residual ProxyGFW.
   Google/Microsoft/Meta/X AI stays with its ecosystem. Independent international
   AI uses AI; domestic products use Domestic or their CN vendor owner.
3. Move rules instead of duplicating them. Keep redirects, login, API and CDN
   endpoints in one session family; split only evidenced download/regional
   surfaces. A broad parent must follow every different-policy child.
4. Prefer DOMAIN/DOMAIN-SUFFIX. Wildcards and keywords need positive and negative
   witnesses. Never use a shared-cloud CIDR, public suffix or tenant boundary as
   a single-service owner. Registered blocked platforms may remain in ProxyGFW.
5. Keep domain and IP sets separate. The manifest controls `no_resolve` and
   extended matching; reviewed IP sets may initiate encrypted resolution only
   after the domain stage. USER-AGENT, PROCESS-NAME and URL-REGEX source rules
   remain forbidden. Every allowlist exemption needs a reason.
6. Add behavioral assertions and run `python3 tools/sort_lists.py --write`.
   The sorter preserves rule modifiers and trailing comments.

Never hand-add to ChinaDomain. Unowned `.cn` / CNNIC IDN hosts already match
terminal ChinaTLD; an explicit Domestic entry is needed only for earlier
priority. ProxyGFW must remain domain-only with no PSL-boundary suffix, expired
domain or specifically owned service.

## Generated layers and upstreams

- **ChinaDomain:** use `tools/regen_chinadomain.py --help` and its shadow workflow.
  Preserve DNS, blast-radius, pin, post-removal routing and hysteresis gates;
  retain probe state between runs. `--additions-only` probes new candidates and
  admits only KEEP results while retaining the existing layer. Same-day retries
  cannot advance deletion hysteresis. A failed resolution-rate gate leaves the
  source unchanged; never lower the gate just to obtain output.
- **ChinaIP:** run `python3 tools/collapse_cidr.py lists/ChinaIP.list --check` and
  locked `python3 tools/rebuild.py --id blackmatrix7_china_ip`. The source is a
  geolocation export, not an RIR feed. Its `exclude_cidr` transform subtracts
  `config/chinaip-exclusions.txt`; re-admission requires fresh RDAP evidence
  beside the entry. Evidence-conflicted ranges deliberately remain DIRECT.
  Recompute intersections before moving CIDRs across ChinaIP or regional lists;
  preserve collapse/address-set verification on refresh. Explicit `include_cidr`
  retention must name exclusion guards; `--write` cannot bypass locked expected
  counts/hashes. `output_params` separates verified upstream parameters from
  the manifest-controlled output matching policy. The CIDR collapser preserves
  modifiers and compares each modifier group separately; it never adds
  `no-resolve` unless explicitly requested for a legacy profile.
- **ProxyGFW expiry:** `config/proxygfw-expired.txt` guards confirmed DNS failures
  against re-entry. Removal from this denylist needs fresh DNS and ownership
  evidence. Migration or misspelling removals do not belong in it. The liveness
  prober requires at least two clean NXDOMAIN responses plus authoritative
  confirmation. Timeout/NODATA/parking hints are not death evidence; confirmed
  expiry needs observations at least 24 hours apart. Under a running proxy,
  domestic DNS anomaly labels do not independently establish blocking.
- **Clash:** edit sources and `config/mihomo-runtime.yaml`, then regenerate with
  `python3 tools/surge2clash.py`. Follow [CLASH.md](CLASH.md) for deployment.

Record upstream provenance in [SOURCES.md](../SOURCES.md) and `sources.lock.json`.
Apply upstream changes through the locked fetch/rebuild tools. AI review inputs
are pinned evidence, not policies or promises to rebuild curated lists. Verify
those inputs before using them:

```bash
python3 - <<'PYLOCK'
import json
with open('sources.lock.json') as f:
    inputs = json.load(f)['ai_review']['inputs']
with open('/tmp/ai-review.lock.json', 'w') as f:
    json.dump({'schema_version': 1, 'sources': inputs}, f)
PYLOCK
python3 tools/fetch_locked.py --lock /tmp/ai-review.lock.json --network --out /tmp/ai-review-inputs
```

Keep accepted moves, omissions, regional evidence and actual validation in a
dated evidence record. Do not classify endpoints from vendor nationality,
`.com`/`.ai`, or an upstream `scope: cn` flag alone.

## Validate a change

```bash
python3 tools/sort_lists.py --check
python3 tools/render_surge_rules.py ../Surge.conf /tmp/Surge.candidate.conf
surge-cli --check /tmp/Surge.candidate.conf
python3 tools/analyze_rules.py --conf /tmp/Surge.candidate.conf --rules lists \
  --country-db "$HOME/Library/Application Support/com.nssurge.surge-mac/GeoLite2-Country.mmdb" \
  --asn-db /Applications/Surge.app/Contents/Resources/GeoLite2-ASN.mmdb \
  --out /tmp/rule-analysis --fail-on-shadow
python3 tests/audit.py --conf /tmp/Surge.candidate.conf --rules lists \
  --check all --fail-on P1
python3 tests/runsuite.py --conf /tmp/Surge.candidate.conf --rules lists
python3 tools/surge2clash.py --check
```

Regenerate Clash before its check if sources changed. Filtered regional selectors
require MMDB expansion; a syntax-only run cannot evaluate their address sets. For IP/GEOIP/ASN changes,
install `requirements-analysis.txt` and also expand against the Country/ASN
MMDB files used by the active profile. A profile with `geoip-maxmind-url` uses
Surge's downloaded Country database; otherwise use its bundled Country file:

```bash
python3 tools/analyze_rules.py --conf /tmp/Surge.candidate.conf --rules lists \
  --country-db "$HOME/Library/Application Support/com.nssurge.surge-mac/GeoLite2-Country.mmdb" \
  --asn-db /Applications/Surge.app/Contents/Resources/GeoLite2-ASN.mmdb \
  --out /tmp/rule-analysis-mmdb --fail-on-shadow
```

Review relationships, split records and topology before accepting broad parents
or list reordering. Every non-security split must be ordered-safe; all
`order_unsafe_*` findings require correction. See [Tests](../tests/README.md) for
tool self-tests and live diagnostics. Documentation-only edits need link, path
and diff checks; run affected existing tests for tool changes.

## Active profile and publication

For rule-only changes, review and replace the generated `[Rule]` section. For
this v2 migration, prepare both clients with `tools/prepare_profiles.py`: it
updates generated routing and ordered DNS mappings, removes DIRECT from proxy
policy groups, and checks proxy definitions and MITM material remain intact.
Candidates must pass validation before installation. Re-render managed DNS
mappings whenever domain-list order or ownership changes.

Production Surge and Clash profiles use the official CDN `@main` URLs under
`https://cdn.jsdelivr.net/gh/yhyfhgs/surge-rules@main/`. Immutable revision URLs
are useful for verification; do not leave production profiles pinned unless
the user explicitly requests a fixed version. Surge's managed Host DNS list
references must use the same official base as its Rule section.

```bash
python3 tools/prepare_profiles.py \
  --surge-in ../Surge.conf --surge-out /tmp/Surge.candidate.conf \
  --clash-in ../Clash/Clash.yaml --clash-out /tmp/Clash.candidate.yaml \
  --rules-base "$PWD/lists" --clash-provider-dir "$PWD/clash"
```

The renderer's check recognizes one canonical CDN main/immutable base or the
source directory. Check the installed sequence with:

```bash
python3 tools/render_surge_rules.py --check ../Surge.conf
```

Never publish profile contents, certificates or credentials. Never write an
`enable` key in `[MITM]`; its switch belongs to the GUI runtime. A nonempty MITM
hostname requires `auto-quic-block = true` to prevent HTTP/3 bypass.

For an inspected routing release on main:

```bash
python3 tools/surge2clash.py
python3 tests/clash_contract.py --conf /tmp/Surge.candidate.conf  # PyYAML required
SURGE_RELEASE_PROFILE=/tmp/Surge.candidate.conf ./update.sh "describe the routing change"
```

`SURGE_RELEASE_PROFILE` selects the validated candidate, so a migration can be
published before replacing the live profile. Without it, update.sh uses the
active profile. The release checks native Surge syntax, CIDR collapse, engine
and v2/expiry safety self-tests, full MMDB
relationships, static audit, scenarios and Clash generation. It requires
`requirements-analysis.txt` plus readable databases; override discovery with
`SURGE_COUNTRY_DB_PATH` / `SURGE_ASN_DB_PATH` when needed. It then runs
`git add -A`, commits, pushes main, verifies the remote SHA, purges changed
`lists/*.list` / `clash/*.list` / `clash/rule-providers.yaml`, and checks CDN md5.
Inspect the entire working tree first. Commit documentation-only work by exact
paths instead of using this release script.

Report the actual state: `VALIDATED_NOT_PUBLISHED`, `PUBLISHED_AND_VERIFIED`, or
`PUBLISHED_BUT_UNVERIFIED`. The last is nonzero and awaits CDN verification;
a successful push alone does not establish publication. Rerunning a release
without new distribution changes performs the full CDN recheck.

## Debugging

```bash
python3 tests/engine.py match example.com --conf /tmp/Surge.candidate.conf --json
surge-cli rule explain example.com
```

Missing address observations return `routing_complete=false`; use `--stage domain`
for a domain-only boundary check, or supply `--dns-status` and `--resolved-ip`
for a controlled full-routing witness. An explicit `--ip` is already resolved.

If an earlier rule steals ownership, narrow/remove that coverer. If the owner is
missing, add it or restore a parent only after proving safe placement. For IP
misrouting, inspect service/ChinaIP/MMDB interval edges. For DNS assertion
failures, inspect the resolution boundary, encrypted resolver configuration and
actual request state rather than blindly restoring `no-resolve`. Running Surge is authoritative
for runtime semantics. L3/L4 need a relevant live-testing task and must not
change configuration or policy selections.

## Current decisions

- **Microsoft / OneDrive:** v2 places Microsoft before the later DIRECT block.
  Its `microsoft.com`, `live.com`, `office.com`, `msn.com` parents are narrowed
  to service scopes so MicrosoftCN exceptions remain effective. The 2026-09-12 decision routes OneDrive sync/storage/shared sign-in
  and `office.live.com` through Microsoft after direct access failed. This also
  supersedes the former DIRECT exception for `files.1drv.com`. Other approved
  MicrosoftCN update/CDN/preview endpoints retain DIRECT. Do not reintroduce
  OneDrive direct exceptions on refresh. See [proxy restoration](evidence/2026-09-12-onedrive-proxy.md)
  and the superseded [direct trial](evidence/2026-09-12-onedrive-direct.md).
- **Google:** Google owns `google.com`, `googleapis.com`, `googleusercontent.com`
  and `ggpht.com` after YouTube/download exceptions. The user explicitly included
  Google API tenant traffic; see [the decision](evidence/2026-09-07-clash-routing.md).
- **Regional AI:** International DashScope/Coding Plan and documented overseas
  `<region>.maas.aliyuncs.com` precede AlibabaCN; Beijing APIs, account/login and
  consoles retain AlibabaCN. TRAE's observed `trae-api-cn.mchost.guru` belongs to
  ByteDanceCN and `trae-api-sg.mchost.guru` to AI. Do not restore blanket
  `mchost.guru`, `aliyuncs.com` or shared ByteDance CDN ownership in AI.
  See [reviewed endpoints and omissions](evidence/2026-09-07-ai-upstream.md).

The v2 evidence record distinguishes IP readmission, quarantine and native
connection witnesses. Unknown historical Streaming ranges remain quarantined;
expanding that set requires real capture and a shadow-routing comparison.
OneDrive synchronization still needs a real authenticated client sync. Rule matches and unauthenticated HTTP responses
establish neither. Broad compatibility entries in vendor documentation do not
make shared cloud namespaces OneDrive owners.


## Coordinated v2 rollout

Old clients expect mixed lists and must not consume the split files with their
old rule sequence. Keep the active old profile on its prior immutable revision
while publishing the new distribution. After all new files are verified, prepare
both private profiles with the same new immutable `--rules-base` URL. The helper
uses that revision for Clash URLs and cache paths too. Validate and install the
candidates, then verify native matching. Do not claim an isolated Mihomo test
means the user's separate Clash client has reloaded.

Keep rollback material outside the repository and outside `../Backup/`: original
Rule/DNS/group values and the old revision are sufficient; never export the
certificate into public artifacts. The publish script's push/CDN statuses and
local activation are separate results.
