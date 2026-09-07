# 2026-09-07 Microsoft list simplification

The user requested removing the newly introduced fallback list and retaining
simple conf/YAML references to existing owner lists. The user then explicitly
approved MicrosoftCN taking priority, including four formerly proxied exceptions.

## Final ownership

- `MicrosoftCN` precedes `Microsoft` within the service section.
- `Microsoft.list` owns `microsoft.com`, `live.com`, `office.com`, `msn.com`.
- `files.1drv.com`, `content.office.net`, `cdn.designerapp.osi.office.net`
  (including their subdomains), and `odc.officeapps.live.com` now match the
  existing MicrosoftCN parents and use DIRECT.
- Existing download exceptions remain ahead of both lists.
- Remove the newly added MicrosoftFallback source and derived list. No new lists
  or inline exceptions are introduced. The manifest again has 35 source lists.
- Remove 24 redundant Microsoft narrow rules plus the four superseded proxy
  rules. Total source/provider rule count: 142,188.

## Validation boundary

The 336 existing scenarios / 2,241 requests / 4,375 assertions pass, including
1,912 DNS assertions. Independently comparing every distinct baseline scenario
query found only five policy changes: the four approved endpoints plus the
existing `support.content.office.net` descendant. No other scenario query changes
policy. The contract test checks 50 owner/negative witnesses and independently
compares actual Surge conf order/policies with the generated YAML and manifest.

The release workflow runs full Country/ASN-expanded relationship analysis,
static audit, scenarios and CDN verification. The private Clash file keeps HTTP
providers and existing DNS/node/group settings. Surge changes are limited to its
generated Rule section. Running clients are not manually reloaded.

CDN verification must check all 71 remaining distribution files and purge both
removed fallback paths. Report success only after those checks complete; a Git
push alone does not prove CDN publication.
