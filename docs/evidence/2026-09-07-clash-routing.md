# 2026-09-07 routing and Clash verification

Scope: source-list suffix coverage, generated Mihomo configuration, and the
user-confirmed private local migration file. No policy selection or live TUN change was performed. The follow-up request
authorizes Git remote publication and jsDelivr refresh.

The user confirmed retaining the shared ecosystem policy and existing verified
YouTube/download/domestic exceptions, and explicitly approved routing all
`googleapis.com` traffic, including tenant endpoints, by Google's network.

## Routing changes

- Google: replace 112 exact/narrow rules under `google.com`, `googleapis.com`,
  `googleusercontent.com`, `ggpht.com` with four suffix parents. Net -108 rules.
  Earlier YouTube and download rules remain authoritative.
- Microsoft: replace two exact `cloud.microsoft` hosts with the unified suffix;
  add `usercontent.microsoft`. Net zero rules. Existing `static.microsoft` is
  already in DownloadCDN and stays there.
- MicrosoftFallback: four suffixes (`microsoft.com`, `live.com`, `office.com`,
  `msn.com`) after all domestic owners, before regional fallback. The earlier
  Microsoft/MicrosoftCN ordering remains intact for OneDrive/Office carve-outs.
- Meta/Twitter: primary service/CDN parents already use suffixes; unchanged.
  Nested-domain and lookalike tests check the actual owner list, not just the
  common policy label.
- No IP rules or cloud-ASN ownership changed.

## Observed checks

| Check | Result |
|---|---|
| Initial generated mirror | 35 lists / 142,320 rules, no drift |
| Final exact source/provider comparison | 36 lists / 142,216 rules, no dropped rules |
| Canonical sorting | 36 lists pass |
| Surge native candidate syntax | OK |
| Exhaustive analyzer | 0 active shadow/conflict; 0 unsafe splits; 0 topology cycles |
| Static A1–A10 audit | 0 P0/P1/P2; 3 existing P3 notices (keywords and unexpanded IP selectors) |
| Scenarios | 336 scenarios / 2,241 requests / 4,375 assertions pass |
| DNS scenario assertions | 1,912 pass, 0 failures |
| Independent Clash contract | 44 owner/negative witnesses pass; provider contents/order/DNS contract pass |
| Converter regression tests | 3 pass, including unsupported-type rejection |
| Mihomo 1.19.30 native syntax | Generated neutral fixture and private candidate pass |
| Isolated native provider loading | All 36 providers, 142,216 rules actually loaded |
| Isolated fake-IP DNS | UDP/TCP A and AAAA: synthetic IPv4/IPv6 replies, no upstream proxy call |
| Isolated real-query failure | TXT query attempts both configured DoH IPs through the mock proxy; returns SERVFAIL when proxy fails |

The first isolated startup exposed a missing ASN database: syntax-only checking
had passed while runtime providers were not fully loaded. After downloading the
real GeoLite2-ASN database from Mihomo's configured upstream, all native counts
matched. No synthetic GeoIP/ASN data was substituted. Consumers must install the
real Country/ASN assets before treating native provider initialization as ready.

Diagnostics and private candidates remain outside the public repository.
The private migration configuration uses the generated HTTP providers and CDN
URLs, following the user's follow-up request. It contains no inline provider
snapshots. The same manifest supplies its rules; SYSTEM has no portable equivalent
and LAN uses the documented terminal GEOIP approximation. Node/group definitions
and the previously chosen DNS proxy exit remain unchanged.

## Limits and state

Source and generated artifacts are validated locally. The follow-up release
uses `update.sh` for the full MMDB gate, Git push and CDN byte verification;
report publication complete only after that verification succeeds.
The isolated test disables TUN and uses only a neutral loopback proxy. It proves
resolver behavior in that process, not OS-wide interception on the user's
machine. The private migration file passing native syntax does not establish
that a running client has imported it. See [DNS deployment conditions](../CLASH.md).

## Decision sources

- [Google Android network requirements](https://support.google.com/work/android/answer/10513641?hl=en): Google service hosts, FCM and static assets.
- [Google Workspace firewall guidance](https://knowledge.workspace.google.com/admin/security/firewall-and-proxy-settings): Drive user-content and API endpoints.
- [Microsoft unified domains](https://learn.microsoft.com/en-us/microsoft-365/enterprise/cloud-microsoft-domain?view=o365-worldwide): unified Microsoft 365 domain.
- [Microsoft 365 endpoints](https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges?view=o365-worldwide): cloud/static/user-content endpoint families.
- [Mihomo DNS](https://wiki.metacubex.one/config/dns/) and [TUN](https://wiki.metacubex.one/config/inbound/tun/): resolver roles, proxy binding, TCP/UDP interception and OS limits.

The private file is updated after syntax, provider parity and unchanged
node/group checks. No running Clash client is reloaded by this workflow.
