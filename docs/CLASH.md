# Mihomo configuration and DNS contract

`clash/rule-providers.yaml` is a generated merge configuration, including active
`rules`, DNS, TUN and sniffing settings. Supply the policy groups referenced by
`config/routing.json` and a `Proxy` group selecting a real remote proxy. Replace
these top-level sections when merging; appending subscription DNS or rules can
restore leaks or change the first match. Edit `config/mihomo-runtime.yaml`, then
run `python3 tools/surge2clash.py`; never edit generated files.

Each manifest list has exactly one classical provider. All non-comment source
rules are preserved, in order, with their modifiers. Unsupported types abort
conversion instead of silently dropping rules. Provider order and policies
come from the manifest. Every `RULE-SET` reference carries `no-resolve`, so mixed
classical providers cannot resolve a hostname just to test an IP selector.

This is rule-content parity, not an assertion that the two runtimes are
identical. Surge SYSTEM has no portable equivalent; the LAN approximation is
`GEOIP,lan` at the same terminal position as Surge LAN. Global HTTP/TLS/QUIC
sniffing approximates per-list `extended-matching`; encrypted or absent hostname
metadata cannot be recovered reliably by either a suffix list or sniffing.

## DNS paths

| Query purpose | Resolver path |
|---|---|
| Ordinary A/AAAA in fake-IP mode | Synthetic IPv4/IPv6 answer; no real lookup needed |
| Other application queries / required proxy resolution | IP-literal DoH servers through `Proxy` |
| A connection already selected as DIRECT | Explicit direct DoH |
| Resolve a proxy server hostname | Separate direct DoH bootstrap |
| Resolve a DNS server hostname | Encrypted default resolver; configured resolvers already use IP literals |

No plaintext/system resolver, domestic `nameserver-policy`, or parallel fallback
is configured for ordinary proxied domain queries. Failure of the selected
proxy must fail resolution; never put DIRECT in that group's fallback chain.
Direct service queries and proxy hostname bootstrap remain visible to their
selected resolver. To avoid proxy-hostname bootstrap entirely, use IP-literal
proxy servers with the protocol's separate TLS server name where applicable.
DoH encryption alone does not make a direct lookup remote.

TUN captures UDP and TCP port 53; fake-IP has both IPv4 and IPv6 ranges. Sniffing
is active for HTTP, TLS and QUIC. OS routing still matters: Mihomo documents that
macOS/Windows cannot automatically hijack DNS addressed to a LAN resolver.
Point the OS/client at Mihomo's DNS listener or a captured public resolver, and
verify physical-interface traffic. Application-owned DoH/DoT, excluded routes,
other VPNs and a disabled TUN require separate runtime verification. The merge
file cannot prove that an arbitrary machine has no DNS leaks.

Do not start this TUN alongside another active VPN/TUN merely to validate the
file. Use `mihomo -t` for syntax. An isolated instance with TUN disabled can
verify provider loading, fake-IP replies and the proxy resolver's failure path;
this does not certify OS-wide DNS interception.

## Validation and deployment

```bash
python3 tools/surge2clash.py --check
# Install PyYAML into your chosen test environment first.
python3 tests/clash_contract.py --conf /tmp/Surge.candidate.conf
mihomo -t -d /path/to/private/mihomo/data -f /path/to/private/config.yaml
```

For native tests, copy generated providers into a temporary data directory and
replace their HTTP definitions with local `type: file`, `behavior: classical`,
`format: text` definitions. Use neutral proxy placeholders. The contract test
compares every source rule independently and checks first-match ownership,
including nested subdomains, lookalike negative cases and existing exceptions.

The public merge file refers to CDN `main`. A local validation does not publish
those bytes. Release the inspected routing batch before deploying HTTP providers
that reference a newly added list; otherwise use the validated local provider
files. A saved migration file is not evidence that a running client loaded it.

## References

- [Mihomo DNS configuration](https://wiki.metacubex.one/config/dns/): resolver roles and proxy suffixes.
- [Mihomo TUN](https://wiki.metacubex.one/config/inbound/tun/): DNS interception and platform limits.
- [Mihomo sniffing](https://wiki.metacubex.one/config/sniff/): Host/SNI inference.
