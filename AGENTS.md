# Surge rules development

This is the public `surge-rules` repository; commands run here. The active
`../Surge.conf` and `../Backup/` are private: never publish the profile,
regenerate it wholesale, or touch backups. Before nontrivial routing work read
[Architecture](docs/ARCHITECTURE.md), [Maintenance](docs/MAINTENANCE.md),
[Current decisions](docs/DECISIONS.md) and the affected source.

## Tools and source boundaries

- Load `~/.agents/skills/surge/SKILL.md`, falling back to
  `/Applications/Surge.app/Contents/Resources/Skills/surge/SKILL.md`.
  [Surge CLI setup](docs/SURGE-CLI.md) covers installation and upgrades;
  `CLAUDE.md` imports this file.
- Resolve `surge-cli` from PATH, then
  `/Applications/Surge.app/Contents/Applications/surge-cli`. Read command-specific
  help before unfamiliar syntax; prefer rendered output, using `--raw` only for
  a documented missing field. Use the CLI for supported runtime operations.
  `rule match` / `rule explain` inspect active rules; `--check <path>` validates
  file syntax only. Installing tools or diagnosing does not authorize runtime
  mutations such as temporary rules, group/mode/feature changes or reloads.
- `config/routing.json` alone defines list order, policies, modifiers and
  sections. Edit it and/or `lists/*.list`, render and validate a candidate, then
  review the diff before replacing only the generated `[Rule]` section.
  `tools/prepare_profiles.py` handles explicitly scoped DNS/group migrations
  while preserving private nodes and certificates.
- Regenerate Clash with `tools/surge2clash.py`, ChinaDomain with its guarded
  `tools/regen_chinadomain.py` workflow, and ChinaIP with locked
  `tools/rebuild.py --id blackmatrix7_china_ip`. Preserve ChinaIP exclusions,
  retention and collapse checks; re-admission needs fresh recorded RDAP evidence.
- Keep node names, exit IP/ASN/ISP mappings, policy internals, certificates and
  credentials out of public files. Use neutral test placeholders and keep
  diagnostics outside the repository. Verify `git check-ignore
  tests/live_check_local.json` before committing. Never dump private profiles
  into logs. Preserve existing uncommitted work and unrelated files.
- Upstream provenance belongs in `SOURCES.md` and `sources.lock.json`; use locked
  fetch/rebuild tools. Keep one current document per subject; superseded detail
  belongs in Git history, with immutable links from the current decision record.

## Routing invariants

- First match wins. Keep one owner per rule and domain/IP sets separate. Reviewed
  IP sets may resolve only after the domain stage; matching modifiers come from
  the v2 manifest. Canonicalize within-list shape with `tools/sort_lists.py --write`.
- Cross-list order is semantic. Every ordered-safe broad parent stays behind
  different-policy children; Reject exceptions follow the documented contract.
- ProxyGFW is a domain-only residual: no IP, PSL-boundary suffix, specifically
  owned domain or denylisted expired domain. Preserve registered multitenant
  namespaces; removing an expiry denial requires fresh DNS evidence.
- USER-AGENT, PROCESS-NAME and URL-REGEX are forbidden repository-wide without
  exemptions. Every allowlist exemption needs a reason.
- Redirect/login/API/CDN endpoints form one session family; split only evidenced
  download/regional surfaces. Follow the traffic evidence required by
  [Current decisions](docs/DECISIONS.md) and Maintenance.
- Never write an `[MITM] enable` key. Nonempty MITM hostname requires
  `auto-quic-block = true`; certificates remain private. Live tests must not
  change configuration or policy selections.

## Verification and release

- Rule changes must complete the full [maintenance validation workflow](docs/MAINTENANCE.md#validate-a-change):
  source sorting, candidate rendering, native syntax, relationship analysis,
  static audit, scenarios and generated Clash checks. IP/GEOIP/ASN changes also
  require the documented actual-MMDB analysis. Run affected existing checks.
- Diagnose candidates with `python3 tests/engine.py match example.com --json`
  and explicit `--conf` when needed; verify active semantics with
  `surge-cli rule explain example.com` and runtime evidence. L3/L4 require a
  running Surge and relevant live-testing task scope. Documentation-only edits
  use link/path/diff checks.
- `./update.sh "description"` validates, runs `git add -A`, pushes main and
  verifies CDN state. Use it only for an inspected routing release with a clean,
  appropriately scoped tree. Stage/commit documentation-only changes by exact
  paths. Report `VALIDATED_NOT_PUBLISHED`, `PUBLISHED_AND_VERIFIED`, or
  `PUBLISHED_BUT_UNVERIFIED`; the last awaits CDN verification.
- Use focused edits, explicit errors and observed evidence. README/docs are
  English; test docs, commit messages and CHANGELOG are Chinese. Routing batches
  record motivation and actual validation in CHANGELOG. Current counts and
  unresolved decisions must come from command output and evidence.
