# Current routing decisions

Consolidated on 2026-09-13 against the v2 sources and updated for the
2026-09-26 upstream refresh. This document retains the
decisions and unresolved evidence that still affect maintenance. List content,
order and modifiers remain in `lists/` and `config/routing.json`; operating
procedures belong in [Maintenance](MAINTENANCE.md). Historical measurements below
describe their recorded batch, not a new runtime check.

## Microsoft and OneDrive

OneDrive storage, synchronization, SharePoint-backed files, shared sign-in,
authentication assets, MFA, `office.live.com` and `g.live.com` use Microsoft.
The user reversed the DIRECT trial on 2026-09-12 after OneDrive failed to open.
At that time, direct probes to `onedrive.live.com` and `skyapi.onedrive.live.com`
timed out; local DNS returned Meta-owned addresses while encrypted DNS returned
different Microsoft service answers. No fixed IP or DNS override was adopted.

The v2 manifest places Microsoft before the later DIRECT block. Its four broad
parents (`microsoft.com`, `live.com`, `office.com`, `msn.com`) were narrowed to
service scopes to preserve MicrosoftCN update/CDN/preview exceptions. The former
DIRECT choice for `files.1drv.com` is superseded. Do not restore OneDrive DIRECT
exceptions, the old MicrosoftCN-first ordering, or MicrosoftFallback on refresh.

The existing OneDrive scenario protects 67 session endpoints and separate
boundary witnesses. Seven proposed Office resource DIRECT changes were withheld
because a broad vendor parent did not establish an authenticated resource's
independence. Existing DownloadCDN decisions remain. Shared cloud namespaces and
compatibility entries in vendor documentation are not blanket OneDrive owners.

Official consumer and Microsoft 365 documentation is recorded as observed HTML
in `sources.lock.json:onedrive_review`, not as imported rule lists. Native
matching and unauthenticated HTTP responses do not establish successful account
sign-in or file synchronization; a real authenticated sync remains unverified.

## Google and session ownership

Google owns `google.com`, `googleapis.com`, `googleusercontent.com` and
`ggpht.com` after the earlier YouTube/download exceptions. The user explicitly
included Google API tenant traffic in that decision. This does not authorize
generalizing unrelated shared-cloud namespaces into service rules.

Box's `boxcloud.com` file namespace follows its existing account/session owner.
1Password account content stays with its proxy family; F1 consent follows
Streaming. Explicit firmware/model-transfer downloads may retain independent
download ownership. Redirects, login, API and authenticated resources otherwise
remain one session family.

When a regional owner holds a site, its static asset hosts follow that owner
instead of DownloadCDN. `note.com` and its asset domain `st-note.com` therefore
use Japan; ProxyGFW does not take a site that has a regional owner. Trip.com's
`tripcdn.com` uses Domestic with `ctrip.com`, because its GSLB returns mainland
addresses to domestic resolvers. DownloadCDN excludes embeddable SaaS widgets
such as accessibility, support or identity components.

## AI ownership and regional exceptions

Independent international AI uses AI. Google/Microsoft/Meta/X products retain
their ecosystem owner; domestic products use Domestic or the appropriate CN
vendor. Nationality, a `.com`/`.ai` suffix or an upstream `scope: cn` flag alone
does not establish an endpoint's region.

| Surface | Retained decision |
|---|---|
| DashScope international/US, Hong Kong DashScope and international Coding Plan | Exact AI endpoints precede AlibabaCN's parent; Beijing APIs, account/login and consoles retain AlibabaCN. |
| `maas.aliyuncs.com` regions `ap-southeast-1`, `us-east-1`, `eu-central-1`, `ap-northeast-1`, `cn-hongkong` | The five documented serving suffixes use AI; do not infer additional regions. |
| `traeapi.us`, `trae-api-sg.mchost.guru` | AI. The observed `trae-api-cn.mchost.guru` exact host belongs to ByteDanceCN. |
| Other `mchost.guru` hosts | No blanket AI or DIRECT suffix; only evidenced regional endpoints receive those owners. |
| `modelscope.cn`, `qianwen.com`, `qoder.cn`, `tongyi.com`; domestic Coze family | AlibabaCN and ByteDanceCN respectively. Their international products retain separate AI ownership. |
| `lingyiwanwu.com` | Domestic; its Chinese website is distinct from the international `01.ai` entry. |
| OpenAI Azure Blob / Cloudflare asset hosts | Exact owned hosts only; no shared tenant-parent expansion. |
| Hugging Face browsing/API and bulk transfers | Browsing/API uses AI; Xet/LFS and evidenced bulk model/dataset delivery use the earlier ModelDownloadCDN owner. |
| Meta Llama API and weight downloads | The API stays with Meta. `llamameta.net`, which `meta-llama/llama-models` names as the weight download host, uses ModelDownloadCDN. |

The 18 review inputs are pinned in `sources.lock.json:ai_review.inputs`; full
accepted endpoint details and original official references remain in the
[AI review](https://github.com/yhyfhgs/surge-rules/blob/caf887f791185f46c371d482788af690677c4573/docs/evidence/2026-09-07-ai-upstream.md).
These pins reproduce review evidence, not every curated destination list.

Keep these omissions and limits when refreshing:

- Do not import process rules, URL regexes, broad brand/telemetry keywords,
  shared cloud/CDN parents or DigitalOcean's ASN merely from an AI aggregate.
- `hf.space`, `repl.co`, `replit.app`, `replit.dev` and `windsurf.build` are
  tenant-hosting boundaries, not whole-service model API rules.
- `anthropic.com.cn` and `chatbotclaude.com` lacked sufficient first-party active
  service evidence in the review; they were neither admitted nor declared dead.
  An unauthenticated Auth0 redirect did not justify changing `anthropic.auth0.com`.
- `mcbaas.work`, `mcdemo.show`, `tcwqqdy.guru` and `trae.guru` retain their existing
  AI ownership pending endpoint/traffic evidence; their complete regional scope
  was not established. Generic Alibaba accounts and ByteDance telemetry/CDNs
  retain their existing owners.

## IP ownership and guarded admission

The v2 review kept 35 existing list names and split out 17 IP lists. Domain
ownership completes before reviewed IP sets may initiate encrypted resolution.
Regional IP calls subtract PrivateLANIP, PKUIP, AppleCNIP and ChinaIP; actual
Country/ASN MMDB intervals establish the effective sets.

- StreamingIP retains verified or narrowly bounded Netflix scope. Official
  network guidance identifies AS2906/40027/55095; fresh RDAP responses support
  only their returned ranges. Unknown historical cloud/ISP cache ranges remain
  quarantined. Expansion needs real traffic capture and a shadow comparison.
- Fresh registered ownership supported AI/Meta/X readmissions where the ASN
  database alone was incomplete. A missing ASN record does not prove reassignment.
- TelegramIP follows the exact official CIDR set with equivalent collapse,
  plus `95.161.64.0/20`, readmitted on 2026-09-26 from observed client traffic
  and its RIPE registration (see [FINAL review](#final-monitor-review)). GamesIP keeps directly allocated Blizzard addresses; old cloud/ISP probes
  without a dedicated binding remain excluded. JapanIP retains reviewed LINE/LY
  ranges and JP fallback, without the five removed whole-operator ASNs.
- `config/ip-review-exclusions.json` is the anti-reentry registry. Quarantine
  does not mean an address is dead. ChinaIP's lock entry preserves exclusion,
  retention and address-set guards; uncertain ranges require fresh evidence.
- The 2026-09-26 ChinaIP refresh accepted four upstream removals whose RDAP
  registrations are foreign (Cloud Innovation US ranges and China Telecom South
  Africa). It held back the new `64.96.5.0/24` and `2620:57:4004::/47` ranges,
  registered to Uniregistry/Tucows (US/CA), in the lock's review holdback.

The 2026-09-13 ChinaDomain additions-only review failed the 70% resolution gate
twice and admitted nothing. On 2026-09-26 the same gate passed at 78.3%, and 371
positive KEEP rows were admitted without lowering the threshold. P10 carrier pins
only protect existing rows from deletion; they never justify a new row, so the
public suffix `in.th` was withheld.
The corrected 21,906-value manual-domain sweep established no confirmed expiry:
timeouts, NODATA, parking hints and isolated NXDOMAIN answers were insufficient.
Use the current [expiry workflow](MAINTENANCE.md#generated-layers-and-upstreams).

The synthetic `battle.blizzard.com` candidate was rejected after NXDOMAIN and
replaced with verified service scope; it was not added to the expiry denylist.
Figma/Obsidian/Cloudflare control-plane additions to ProxyGFW were withheld:
first-party ownership alone did not establish blocking. Figma and Obsidian
unauthenticated roots responded through both tested paths. The 2026-09-26 user
decision below superseded this for Obsidian; Figma and the Cloudflare control
plane remain unowned.

## FINAL monitor review

The private FINAL monitor recorded 6,766 connections to 287 destinations from
2026-09-15 to 2026-09-26 (16 controlled probe connections excluded). Every
destination still reached FINAL under the rules published before this batch.
The 2026-09-26 batch assigned 99 of them, which carried 5,354 connections
(79.1%). Classification uses observed hosts and processes plus RDAP, registry,
application metadata or page-title checks. Per-host usage stays in the private
monitor. The accepted user decisions are:

- **ProxyGFW:** identified overseas first-party services that lack a specific
  owner may enter without blocking evidence. This covers applications and sites
  used directly, such as Obsidian, Zotero, Tailscale, Typora, NodeSeek and
  finance/data sites. The Overleaf compile host joins `overleaf.com`, like the
  1Password content domains. Hosting and proxy-provider sites were withheld from
  the public lists because they would disclose private infrastructure.
- **Academic:** a new DIRECT list after PKU holds the academic sites seen in
  FINAL, so campus IP access reaches institutional subscriptions. A second user
  decision on the same day moved the academic publishers and search sites out
  of ProxyGFW: arXiv, OpenReview, Semantic Scholar, Elsevier/ScienceDirect,
  Springer, Nature, IEEE, ACM and Science. Elsevier's content CDNs
  (`sciencedirectassets.com`, `els-cdn.com`) left DownloadCDN, and
  `springernature.com` was added for Springer Nature's shared assets.
  Before the move, every host answered a DIRECT request through Surge. A
  direct connection that bypassed Surge also succeeded for each domestic-DoH
  answer with a valid certificate. For `link.springer.com` and
  `www.nature.com`, domestic DoH returns a Google Cloud entry that presents a
  valid `*.nature.com` certificate. `paperswithcode.com` was reset on every
  direct attempt and stays in ProxyGFW. Publishers already in ChinaDomain
  (Wiley, Taylor & Francis, SAGE, OUP, Cambridge, JSTOR, APS, ACS, IOP, PNAS,
  Scopus and others) route DIRECT and were not duplicated. Universities keep
  their regional owners. Institutional access applies only on the campus
  network; elsewhere DIRECT uses the local ISP address.
- **Reject:** only ad delivery and bidding endpoints were added (DSP/SSP,
  cookie sync, native/video ads, the Freestar bidding stack, Naver ads). Under
  the existing "block ads, not analytics" rule, measurement (Comscore, Nielsen,
  DoubleVerify, IAS), identity graphs, ABM intent/visitor identification and
  attribution pixels are not rejected.
- **Ecosystem and service owners:** the Gemini API docs MCP and Colab runtimes
  join Google; Microsoft Clarity joins Microsoft, as Google Analytics joins
  Google. Cloudflare's MCP server and STUN host, observed from AI clients, join
  AI as exact hosts. Writefull and AI-detection services join AI. A Tencent
  Cloud IM login endpoint failed repeatedly through the proxy, so TencentCN now
  owns `qcloud.com` as a suffix. The earlier-listed ProxyGFW exception
  `shortconn.im.qcloud.com` is an ordered-safe child in v2.
- **TelegramIP:** Telegram client traffic to `95.161.76.100` (ports 80, 443
  and 5222) was observed on seven days. RIPE registers `95.161.64.0/20` as TM-SUBNETS, with Telegram
  Messenger Inc as abuse contact and MNT-TELEGRAM as maintainer. The range left
  the quarantine registry with that evidence.

The remaining FINAL traffic is intentional:

- Third-party SaaS components stay on the neutral exit under the 2026-08-31
  audit ruling. This includes Customer.io/Gist, Segment, HubSpot, Hotjar,
  Optimizely, consent managers, support widgets and site builders.
- Bot-defense, CAPTCHA, fingerprinting and IP-geolocation components share the
  calling page's exit. This includes AWS WAF, PerimeterX, DataDome,
  FingerprintJS and ipapi.co.
- The rest are tenant boundaries (`github.io`, `cloudfront.net`,
  `supabase.co`), raw IPs, unidentified domains and personal sites.
- Raw IPs include Tencent Cloud and Azure addresses contacted without a
  hostname. Shared-cloud CIDRs cannot own a service, and process rules are
  forbidden.

## Latest recorded release and open verification

Routing commit `6cbd13c6a86ffefa4000d4e47e491cbb64ce1fc7` (FINAL monitor review)
was recorded as **PUBLISHED_AND_VERIFIED** on 2026-09-26. It contained 53 lists
and 140,748 source rules. The 5,058 scenario assertions passed, including 2,216
DNS assertions, as did 84 adversarial assertions. The full MMDB/static gates
reported no P0/P1/P2 findings and three existing P3 notices. `update.sh` matched
all 25 changed distribution files on the CDN. The private Surge profile gained
only the Academic rule and its DNS mapping. After it reloaded, all 53 rule sets
refreshed, including the upstream-refresh lists below, and 47 native routing
witnesses matched their new owners. The private Clash file gained the Academic
provider and rule; no production Clash process was running.

The previous routing release, `4632936d8ff6dab58f9b1f86279ab799d3ccba23`
(2026-09-26 upstream refresh, 52 lists, 140,674 rules), passed 4,852 scenario
assertions and matched 105/105 distribution files at both `@main` and its
immutable commit. The release before it, `8c92cbbd70dd082df48f696751c5a30e120183f2`
(2026-09-13, 140,282 rules), also passed 84 adversarial assertions.

After the coordinated immutable-revision rollout, the user's final choice was
official production `@main` URLs for both private clients, including Surge Host
DNS mappings and Clash's v2 provider cache. The recorded follow-up verified
105/105 CDN files, 52/52 ready Surge resources and 90/90 native routing witnesses
(including 67/67 OneDrive endpoints). This is the retained deployment convention.

No production Clash process was running during that release. An isolated
TUN-disabled Mihomo instance loaded all 52 CDN providers and passed dual-stack
DNS plus 8/8 connection-policy witnesses, then stopped. It did not establish
production-client reload or OS-wide DNS interception. Real authenticated
login/sync/payment/playback and a daily FINAL-rate improvement remain outside
those observations. See the [Clash contract](CLASH.md).

## Historical evidence

Superseded designs and full batch measurements remain at this immutable Git
revision; they are evidence, not current routing instructions.

| Record | Retained purpose |
|---|---|
| [Domain/IP v2](https://github.com/yhyfhgs/surge-rules/blob/caf887f791185f46c371d482788af690677c4573/docs/evidence/2026-09-13-domain-ip-v2.md) | Source review, readmissions, per-list deltas, publication and final `@main` activation. |
| [OneDrive proxy restoration](https://github.com/yhyfhgs/surge-rules/blob/caf887f791185f46c371d482788af690677c4573/docs/evidence/2026-09-12-onedrive-proxy.md) | Current proxy decision and its connectivity limits. |
| [OneDrive DIRECT trial](https://github.com/yhyfhgs/surge-rules/blob/caf887f791185f46c371d482788af690677c4573/docs/evidence/2026-09-12-onedrive-direct.md) | Failed trial and DNS observations; routing superseded. |
| [AI review](https://github.com/yhyfhgs/surge-rules/blob/caf887f791185f46c371d482788af690677c4573/docs/evidence/2026-09-07-ai-upstream.md) | Pinned inputs, exact accepted endpoints, omissions and source links. |
| [Google/Microsoft suffix review](https://github.com/yhyfhgs/surge-rules/blob/caf887f791185f46c371d482788af690677c4573/docs/evidence/2026-09-07-clash-routing.md) | Google tenant scope; old MicrosoftFallback design superseded. |
| [Microsoft list merge](https://github.com/yhyfhgs/surge-rules/blob/caf887f791185f46c371d482788af690677c4573/docs/evidence/2026-09-07-microsoft-merge.md) | Retired fallback list; old ordering/DIRECT choices superseded. |
