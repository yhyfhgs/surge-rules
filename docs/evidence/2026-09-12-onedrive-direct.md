# OneDrive direct routing — 2026-09-12

The user requested DIRECT for OneDrive synchronization and explicitly included
shared Microsoft sign-in endpoints, accepting the effect on other Microsoft
applications that use the same hosts.

## Observed baseline

Surge 6.9.1 was running in rule mode. Native `rule explain` returned the Microsoft
proxy policy for `onedrive.live.com`, `skyapi.onedrive.live.com`,
`d.docs.live.net`, `login.live.com` and `login.microsoftonline.com`.
`api.onedrive.com` and `files.1drv.com` already returned DIRECT.

The active profile had Microsoft ahead of MicrosoftCN, despite the opposite
order in the manifest. Its regional group labels also differed from the
manifest: only the shorter existing aliases were defined. The manifest now
uses those existing aliases, and the reviewed generated Rule section restores
canonical list order. Regional routing destinations are unchanged; scenario
expectations and Clash output use the same labels. Private group definitions
and other profile sections are preserved.

No running OneDrive process was found. The observed active (138 records) and
recent (200 records) connection snapshots contained no OneDrive matches. These
snapshots cannot establish the behavior of an authenticated synchronization job.

## Direct connectivity evidence

Read-only native HEAD probes used an explicit DIRECT policy without changing
the selected groups or active configuration. `login.live.com` returned HTTP
404 and `login.microsoftonline.com` returned HTTP 200, each in approximately
one second. A 404 at an unauthenticated root establishes TCP/TLS/HTTP reachability,
not successful sign-in.

Direct probes to `onedrive.live.com` and `skyapi.onedrive.live.com` timed out.
For both names, Surge's local DNS returned addresses covered by Meta.list,
whereas encrypted Google DNS returned a disjoint set of Microsoft service
answers. This supports the existing DNS-poisoning diagnosis; the user-selected
DIRECT route does not repair the resolver. Probes through the original proxy,
and probes to `d.docs.live.net` and `api.onedrive.com`, hit the native HEAD
client's HTTP/2 bodyless-response error. They are inconclusive, not successes.

Raw request, DNS, probe and candidate-profile artifacts remain outside the
public repository. No account URLs, tenant identifiers, node names, credentials
or exit mappings are published here.

## Routing scope and sources

The [consumer OneDrive reference](https://learn.microsoft.com/en-us/sharepoint/required-urls-and-ports)
identifies OneDrive API, file, storage, legacy Live/SkyDrive and sign-in endpoints.
The [Microsoft 365 reference](https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges?view=o365-worldwide)
adds SharePoint/OneDrive for Business dependencies and shared identity, CDN and
MFA namespaces. Retrieval hashes are recorded as **observed** documentation
inputs in `sources.lock.json:onedrive_review`; neither document is imported as
a routing list.

MicrosoftCN adds 35 new endpoint rules and broadens two existing rules:
`storage.live.com` now includes subdomains, and the WNS notification namespace
now covers the documented business dependency. Five existing rules move with
one owner each: `p.sfx.ms`, `login.windows.net`, `msauth.net`, `msftauth.net`
from Microsoft, and `msftauthimages.net` from DownloadCDN. MicrosoftCN grows
from 85 to 125 rules; the repository grows by 35 rules overall.

The broad `microsoft.com`, `live.com`, `live.net`, `microsoftonline.com` and
`gfx.ms` owners remain in Microsoft behind their direct exceptions. Copilot,
Teams and Graph service requests retain the Microsoft proxy policy; their
shared sign-in hosts now use DIRECT. Shared cloud parents, generic analytics
platforms, test-only hosts and broad compatibility entries in Microsoft's
documentation are not adopted as OneDrive rules.

## Validation

- Source shape: 35 canonical lists; native candidate profile syntax accepted.
- Relationship analyzer, including Country/ASN MMDB expansion: 142,240 rules;
  no active shadows or unsafe ordered splits.
- Static A1–A10 audit: no P0/P1/P2 findings; three existing P3 information items.
- Scenario suite: 346 scenarios, 2,409 requests, 4,721 assertions passed;
  2,080 DNS assertions passed. The OneDrive additions cover 67 direct endpoint
  witnesses and 14 boundary witnesses.
- Clash: 35 providers and all 142,240 source rules match exactly; manifest
  order, DNS contract and 82 ownership witnesses passed.

The release additionally runs the full MMDB-expanded analyzer, static audit
and standard publication gates. Git push and CDN hash verification are reported
by `update.sh` as separate steps. After publication, the local client must
refresh the three changed remote lists and use the canonical Rule section.

DIRECT matching and successful CDN publication are distinct from end-to-end
OneDrive availability. Correct DNS and a real authenticated synchronization
remain necessary to close the connectivity issue.
