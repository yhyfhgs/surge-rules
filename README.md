# surge-rules

Surge rule lists with a generated Mihomo/Clash mirror. Edit [lists/](lists/) for
rule content and [config/routing.json](config/routing.json) for list order,
policies and modifiers. Routing is first-match-wins.

## Use

```text
Surge:  https://cdn.jsdelivr.net/gh/yhyfhgs/surge-rules@main/lists/<Name>.list
Mihomo: https://cdn.jsdelivr.net/gh/yhyfhgs/surge-rules@main/clash/<Name>.list
```

This is the domain/IP-separated v2 layout. Upgrade the rule sequence and list
files together; old mixed-list configurations should remain on their previous
commit. Use immutable commit URLs for a coherent rollout.

Mihomo users can merge [clash/rule-providers.yaml](clash/rule-providers.yaml)
and supply their own policy groups. Follow the [Clash deployment contract](docs/CLASH.md)
for DNS, TUN and runtime limits. Files under `clash/` are generated.

## Maintain

Assign each rule to one owner, keep domain rules before the encrypted-resolution
IP stage, and preserve list-order dependencies. Regional IP selectors subtract
the DIRECT protection sets; matching modifiers live in the v2 manifest. The local `../Surge.conf` contains private settings;
the renderer replaces only `[Rule]`. `tools/prepare_profiles.py` additionally
prepares reviewed DNS/group changes and verifies private proxy/certificate
sections remain intact. It never activates a candidate.

The [maintenance guide](docs/MAINTENANCE.md#validate-a-change) is the single
command reference for candidate validation, MMDB analysis and publication.
For a quick source/mirror check:

```bash
python3 tools/sort_lists.py --check
python3 tools/surge2clash.py --check
```

| Reference | Contents |
|---|---|
| [Architecture](docs/ARCHITECTURE.md) | Ownership, ordering, DNS invariants and analyzer output |
| [Maintenance](docs/MAINTENANCE.md) | Edit, regenerate, validate, debug and release |
| [Tests](tests/README.md) | Offline and live test entry points, data and limits |
| [Sources](SOURCES.md) / [lock](sources.lock.json) | Upstream provenance and reproducible inputs |
| [Changelog](CHANGELOG.md) | Batch decisions, validation and historical records |

Current rule and test counts come from tool output. Dated evidence is linked
from the changelog and source register; obsolete reports remain in Git history.
