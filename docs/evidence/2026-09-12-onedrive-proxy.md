# OneDrive proxy restoration — 2026-09-12

The user reported that direct routing could not open OneDrive and requested
proxy routing. This supersedes the earlier same-day direct trial, including its
shared sign-in scope. The change also updates Clash and the published rule lists.

## Evidence and scope

Before this change, native Surge matching still returned DIRECT/MicrosoftCN
for the OneDrive web entry, sync API, file hosts and shared login endpoints.
The [direct-trial record](2026-09-12-onedrive-direct.md) documents local DNS
answers in Meta-owned ranges and direct timeouts for two personal OneDrive
hosts. The user's observed access failure supports reversing the routing
decision without adding DNS overrides or fixed IP addresses.

All 67 endpoints in the existing OneDrive session scenario now expect the
Microsoft proxy policy. This covers personal and SharePoint-backed file
storage, legacy APIs, nested storage names, login, authentication assets,
MFA and client resources. Shared `office.live.com` web traffic and `g.live.com`
redirects also follow that session. Generic Office preview endpoints, Microsoft
update/download surfaces and unrelated service owners keep their existing rules.

The change removes 53 OneDrive/session clauses from MicrosoftCN. Twenty-five
move to Microsoft; the other 28 are already covered by Microsoft's existing
`live.com`, `live.net`, `microsoft.com`, `microsoftonline.com`, `gfx.ms` or
`msn.com` parents. Keeping those duplicate children would add no coverage.
MicrosoftCN changes from 125 to 72 rules, Microsoft from 53 to 78; the repository
has 142,212 source rules, 28 fewer than the direct trial.

No new list, policy group or manifest ordering is required. Generated Clash
output changes only Microsoft.list and MicrosoftCN.list; the existing provider
order and URLs remain valid. During final client refresh, a stale local Rule
section reappeared and was restored from the validated manifest, preserving all
other current profile bytes. Shared authentication stays with Microsoft rather
than returning its images to the earlier DownloadCDN policy.

The official endpoint references and observed document hashes in
`sources.lock.json:onedrive_review` are unchanged. Only the user-selected routing
decision changes; no upstream rule or IP allocation data is refreshed.

## Validation

- 35 source lists and native candidate profile syntax validated.
- Relationship analyzer: 142,212 rules, zero active shadows, unsafe splits or
  topology cycles. Existing MicrosoftCN exceptions remain ordered safely.
- Static A1–A10 audit: no P0/P1/P2 findings; three existing P3 information items.
- The release's full Country/ASN MMDB analyzer and algorithm self-tests passed.
- 346 scenarios, 2,409 requests and 4,720 assertions pass, including 2,080 DNS
  assertions. The 67 OneDrive witnesses now require the proxy policy, and the
  14 boundary witnesses retain their individual expectations.
- One former same-policy assertion is no longer applicable because the shared
  Office web entry and the generic Office preview now deliberately have different
  routes. Each of its three requests retains an explicit policy assertion.
- All 35 Clash providers and 142,212 rules match their source exactly; the DNS
  contract, manifest order and 82 ownership witnesses pass.

The standard release also runs the static audit and full Country/ASN MMDB
analysis before pushing, then purges and verifies the changed CDN files. The
local Surge resources are refreshed after publication, followed by native
matching and connection checks. Raw diagnostic artifacts stay outside the
repository; node names, credentials and account/tenant URLs are not published.

Routing checks and unauthenticated HTTP responses cannot certify a completed
OneDrive file synchronization. No authenticated sync job is claimed here.

## Publication and runtime result

Rule commit `9010f67` was pushed and verified against origin/main. The standard
release initially verified all four changed distribution files. A second check
through the host's own network then found an edge still serving the previous
`@main` bodies, despite a correct immutable commit URL. All four changed paths
were purged again, and host-side verification confirmed the four lists plus
the unchanged Clash provider configuration match the published source.

The two stale public Surge resource-cache files were updated only after their
replacement bytes matched both Git HEAD and the immutable CDN revision. A
subsequent normal external-resource refresh and profile reload loaded the
current lists. Final native matching passed all 81 witnesses, including all
67 OneDrive session endpoints using Microsoft and a proxy exit. Five additional
MicrosoftCN update/preview/CDN controls still returned DIRECT after restoring
the canonical Rule section.

Browser navigation from `onedrive.live.com` now reached the public Microsoft
OneDrive website. The document entry redirected to `login.live.com` with HTTP
200. Unauthenticated command-line requests returned HTTP 403 for the OneDrive
root and HTTP 400 for the Sky API, so those responses are not presented as
authenticated application success. No proxy selections, DNS overrides, fixed
service IPs, certificates or engine restart were needed.
