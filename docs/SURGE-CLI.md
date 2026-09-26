# Surge skill and CLI

Use the local Surge bundle for matching skill/CLI versions. This guide covers
user-level setup and repository boundaries; command details live in the skill,
and routing changes follow [Maintenance](MAINTENANCE.md).

## Installation and discovery

| Component | Location |
|---|---|
| Vendor skill | `/Applications/Surge.app/Contents/Resources/Skills/surge/` |
| Shared user skill | `~/.agents/skills/surge/` |
| Claude compatibility link | `~/.claude/skills/surge` → `~/.agents/skills/surge` |
| Vendor CLI | `/Applications/Surge.app/Contents/Applications/surge-cli` |
| User PATH link | `~/.local/bin/surge-cli` → vendor CLI |

For a first installation, inspect all destinations and preserve existing local
changes. Run these commands only when each destination is absent:

```bash
mkdir -p "$HOME/.agents/skills" "$HOME/.local/bin"
cp -R /Applications/Surge.app/Contents/Resources/Skills/surge "$HOME/.agents/skills/surge"
ln -s /Applications/Surge.app/Contents/Applications/surge-cli "$HOME/.local/bin/surge-cli"
mkdir -p "$HOME/.claude/skills"
ln -s "$HOME/.agents/skills/surge" "$HOME/.claude/skills/surge"
```

Keep `~/.local/bin` in the agent process's PATH; otherwise use the bundled
executable directly. Avoid duplicate copies under other scanned skill roots.
Invoke `$surge explain how example.com is routed` to select the skill explicitly.
Refresh skill discovery or restart the client if needed. Other agent clients
must discover the shared directory or link their supported skill root to it.

Read `SKILL.md` first; use `references/command-reference.md` for command details
and `references/plugin-authoring.md` for Surge plugins. The Claude link shares
these files. The local 6.9.1 installation preserves the vendor instructions,
references and icon, with only `agents/openai.yaml` corrected: its original UI
prompt recommended `--raw`, conflicting with `SKILL.md`. Retain this behavior
when reviewing an update, only if upstream still has that inconsistency:

```yaml
default_prompt: "Use $surge to operate Surge with surge-cli safely, prefer default rendered output, inspect baseline state, make minimal authorized changes, and verify the result."
```

## CLI entry points

Resolve the CLI from PATH, then the vendor path above. Read help before using
unfamiliar syntax; prefer rendered output. Use `--raw` only for a documented
field missing from that output; it also bypasses client-side command validation.

```bash
command -v surge-cli
surge-cli -h
surge-cli help rule match
surge-cli help rule explain
surge-cli version
surge-cli --check /tmp/Surge.candidate.conf
```

Most commands require the running controller. Help, `--check <path>`,
`plugin validate` and `plugin pack` work offline. `version` reports the running
core/controller protocol; the app's `Info.plist` holds its bundle version.
`--check` validates file syntax without installation/reload. The distinct
`profile check <name>` checks a named profile through the running macOS app.
Inspect exit codes; invalid configurations must fail.

For remote control use `--remote host:port` (IPv6: `[address]:port`) and
`--password-stdin`, `SURGE_CLI_PASSWORD` or the secure prompt. Never place
passwords in command arguments or public files.

## Diagnostic workflow

1. Start passively with `status` and `dump summary`; cached summary indicators
   are not fresh connectivity measurements.
2. `rule match example.com 443` and `rule explain https://example.com` inspect
   active rules and policy hops. They do not evaluate a Python-engine candidate
   or establish a successful connection. IP-dependent matching uses resolver state.
3. Use `dns lookup`, `dns trace` and `geoip` for resolution/address questions;
   DNS commands can send queries. Within a relevant connectivity task, use
   `test-policy` or `http probe`, keeping authenticated application success separate.
4. For tunnels, get the `lineHash` from `dump policy` and inspect
   `proxy-runtime-status` before logs. Narrow traffic/log evidence with the skill's
   relevant commands; keep private output outside this public repository.

Streaming commands require incremental reading. A finite command's first frame
is not completion; stop ongoing watches when sufficient evidence is collected.
The skill documents timeout and controller-version gates. [Tests](../tests/README.md)
sets the scope and redaction rules for L3/L4 diagnostics.

## State changes and plugins

Prefer dedicated mode/group/feature/profile/module commands for authorized
changes, inspecting state before and after. Installing tools and validating
files do not authorize reloads, DNS flushes, connection termination or temporary
rules. Temporary rules take effect immediately, precede profile rules and vanish
when Surge stops; never use them to substitute for the candidate workflow.
Live validation must not change configuration or policy selections.

Surge plugins are distinct from agent skills. Offline validation/packing differs
from `plugin load-unpacked`, `plugin configure` and `plugin enable`, which alter
the running app. Read plugin help and the skill's authoring reference first;
`plugin install` was listed but unavailable in the recorded 6.9.1 CLI.

## Upgrades and verification

The CLI symlink follows app updates; the copied skill needs a reviewed refresh:

1. Compare the vendor/shared directories with `diff -ru`, preserving local
   metadata corrections only where still necessary.
2. Verify the executable with
   `codesign --verify --strict /Applications/Surge.app/Contents/Applications/surge-cli`.
3. Check general and command-specific help, and runtime `version` when Surge is
   running. Test `--check` with neutral valid/invalid temporary profiles and inspect
   both exit statuses; recheck protocol gates before using new commands.
4. Confirm one discovered skill in another local session, with working reference,
   icon and compatibility links. This is separate from a routing release.

Installation evidence recorded on 2026-09-13: Surge 6.9.1/build 12290,
Core 6009001/Protocol 25; signature and links passed. One skill/five files were
installed, four vendor-identical and one UI metadata correction. Discovery found
one enabled USER skill in the repository and a separate temporary directory;
11 help calls passed and valid/invalid file checks returned 0/1. These are dated
installation results, not an ongoing runtime health claim.
