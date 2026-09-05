# Surge rules development

This directory is the public `surge-rules` repository. Commands below run here. The active profile `../Surge.conf` and `../Backup/` are outside the repository: never publish the profile, regenerate it wholesale, or touch backups. Read `docs/ARCHITECTURE.md`, `docs/MAINTENANCE.md`, and the affected source before nontrivial routing work.

## Source and privacy boundaries

- Routing is first-match-wins. `config/routing.json` alone defines list order, policies, modifiers and sections. Edit it and/or `lists/*.list`, render a candidate, verify it, then review the diff before replacing only the profile's `[Rule]` section. Never hand-edit that generated section.
- Cross-list order is semantic; ordered-safe broad parents must remain behind every different-policy child (Reject exceptions follow the documented contract). Use `tools/sort_lists.py --write` for canonical within-list shape, not manual sorting.
- Never hand-edit generated `clash/`, `lists/ChinaDomain.list`, or `lists/ChinaIP.list`. Their workflows are `tools/surge2clash.py`, `tools/regen_chinadomain.py`, and locked `tools/rebuild.py --id blackmatrix7_china_ip`. Preserve ChinaIP exclusions and collapse checks; re-admission needs fresh documented RDAP evidence.
- Keep node names, exit IP/ASN/ISP mappings, policy internals, certificates and credentials out of public files. Use neutral test placeholders. `tests/live_check_local.json` is private/ignored: verify `git check-ignore` before committing. Put diagnostic artifacts outside the repository. Do not dump private profile contents into logs or reports.
- Upstream provenance belongs in `SOURCES.md` and `sources.lock.json`; use locked fetch/rebuild tools, not upstream overwrite. Preserve existing uncommitted work and unrelated files.

## Routing invariants

- Move rules between owners instead of duplicating them. All IP-class rules carry `no-resolve`.
- `ProxyGFW` is a domain-only residual: no IP, PSL-boundary suffix, specifically owned domain or denylisted expired domain. Preserve registered multitenant namespaces; removing an expired-domain denial needs fresh DNS evidence.
- `USER-AGENT`, `PROCESS-NAME`, and `URL-REGEX` are forbidden repository-wide without exemptions. Every allowlist exemption needs a reason.
- Treat redirect/login/API/CDN endpoints as one session family; split only evidenced download or regional surfaces. Live-traffic decisions in `docs/MAINTENANCE.md` cannot be resolved by syntax-only edits.
- Never write an `[MITM] enable` key. Nonempty MITM hostname requires `auto-quic-block = true`; certificate material stays private. Live tests must not change configuration or policy selections.

## Verification and release

For rule changes, follow the full workflow in `docs/MAINTENANCE.md`:

```bash
python3 tools/sort_lists.py --check
python3 tools/render_surge_rules.py ../Surge.conf /tmp/Surge.candidate.conf
surge-cli --check /tmp/Surge.candidate.conf
python3 tools/analyze_rules.py --conf /tmp/Surge.candidate.conf --rules lists --out /tmp/rule-analysis --fail-on-shadow
python3 tests/audit.py --conf /tmp/Surge.candidate.conf --rules lists --check all --fail-on P1
python3 tests/runsuite.py --conf /tmp/Surge.candidate.conf --rules lists
python3 tools/surge2clash.py --check
```

IP/GEOIP/ASN changes also need the documented MMDB analysis. Diagnose domains with `python3 tests/engine.py match example.com --json` and the runtime `surge-cli rule explain example.com`; offline success is not proof of all live semantics. L3/L4 require running Surge and explicit relevant task scope. Instructions-only edits need link/path/diff checks, not live routing tests.

`./update.sh "description"` validates, runs `git add -A`, pushes main and verifies CDN state. Inspect/stage scope before any commit; never use this broad staging release script for unrelated documentation cleanup or a dirty tree. Distinguish Git push from CDN publication and `VALIDATED_NOT_PUBLISHED`, `PUBLISHED_AND_VERIFIED`, `PUBLISHED_BUT_UNVERIFIED`; never report the last as complete.

Use focused edits and explicit errors, never fabricated successful checks or speculative routing fixes. Run affected existing checks without new scaffolding. Match English README/docs and Chinese test docs/commit messages/CHANGELOG; routing batches record motivation and actual validation in CHANGELOG. Counts and unresolved decisions come from current command output and evidence, not copied snapshots.
