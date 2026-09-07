# 2026-09-07 AI upstream review

The batch keeps independent international AI in `AI`, major ecosystem AI in its
existing Google/Microsoft/Meta/X owner, and domestic products in their CN owner.
It adds regional API coverage without importing upstream process rules, broad
cloud providers, or public tenant namespaces. Surge and Clash derive from the
same 35-list manifest.

## Input snapshots

| Upstream | Revision | Reviewed rules |
|---|---|---|
| VPSDance/ai-proxy-rules | `cc1d596a6b645986d293bd93f43a3e9ab114f3e8` (2026-09-07) | `rules/surge/all.list`: 392 rules; ten provider YAML files for ownership decisions |
| SukkaW/Surge | `81632ebcfaa6a2469721d63e7be16639db319f63` (2026-09-05) | `Source/non_ip/ai.conf`: 51 rules |
| blackmatrix7/ios_rule_script | `5f06cacdb752a951bba8511b25eadde77ebc683c` (2026-09-05) | OpenAI 35, Copilot 51, Gemini 13, BardAI 10, Anthropic 3, Claude 3 |

All 18 input files were downloaded by immutable revision, SHA-256/size recorded
in `sources.lock.json:ai_review.inputs`, and fetched again through
`tools/fetch_locked.py --network`. Verification: 18/18 passed, including a replay
from the checked-in lock metadata. The pins reproduce review inputs; manually
curated destination lists remain outside the whole-list rebuild promise.

## Changes from the initial working tree

- Add 18 domain rules and remove the blanket `mchost.guru` rule: net +17,
  142,188 → 142,205 source/provider rules. IP/CIDR/ASN bytes are unchanged.
- Move 14 existing domain rules between owners, without duplicate ownership.
  Thirteen retain DIRECT: four Alibaba products and nine Coze domains move from
  Domestic to AlibabaCN/ByteDanceCN. `lingyiwanwu.com` moves AI → Domestic.
- The pre-existing Microsoft simplification is preserved and released with this
  batch; see [its separate record](2026-09-07-microsoft-merge.md).

| Surface | Final ownership | Evidence and boundary |
|---|---|---|
| `claudemcpclient.com` | AI | VPSDance Anthropic core input; use its own service suffix. Apex DNS returned NOERROR with no A answer and HTTPS failed, so this is upstream coverage, not a claim that the apex serves a website. |
| `lcicat.org`, `lcicollections.org`, `muthos.com` | AI | VPSDance Anthropic input plus current public DNS answers within the already-owned Anthropic `160.79.104.0/21`; no new IP rule. HTTPS handshake failure at the apex is not interpreted as domain expiry. |
| `openaiassets.blob.core.windows.net`, `openai.com.cdn.cloudflare.net` | AI, exact hosts | VPSDance OpenAI assets. The Blob host returned HTTP 400 to an unauthenticated root request. Do not widen to Azure Blob or Cloudflare tenant parents. |
| `dashscope-intl.aliyuncs.com`, `dashscope-us.aliyuncs.com`, `cn-hongkong.dashscope.aliyuncs.com`, `coding-intl.dashscope.aliyuncs.com` | AI, exact hosts | Official region/plan endpoints. API-key-authenticated regional APIs are independent of the cloud console cookie session. AI precedes the AlibabaCN `aliyuncs.com` parent. |
| `ap-southeast-1`, `us-east-1`, `eu-central-1`, `ap-northeast-1`, `cn-hongkong` under `maas.aliyuncs.com` | AI, five regional suffixes | Official Model Studio workspace/trial serving domains. These are AI serving namespaces, not generic OSS/cloud hosting parents. Beijing and unlisted regions retain the vendor rule. |
| `traeapi.us`, `trae-api-sg.mchost.guru` | AI | TRAE staff international allowlist plus VPSDance Singapore endpoint; the API ping returned HTTP 200. |
| `trae-api-cn.mchost.guru` | ByteDanceCN, exact host | Public TRAE CN startup configuration and support reports identify this model endpoint; API ping returned HTTP 200. |
| Other `mchost.guru` hosts | Existing fallback, ordinarily Final | The former AI suffix captured the proven domestic endpoint. Keep the two evidenced regional hosts; no inferred region wildcard or whole-namespace migration. |
| `modelscope.cn`, `qianwen.com`, `qoder.cn`, `tongyi.com` | AlibabaCN | Existing DIRECT rules moved to their ecosystem owner. Their international products remain AI. |
| `coze.cn`, `cozeapp.net`, `cozebaas.cn`, `cozebuild.com`, `cozecdn.com`, `cozedeploy.com`, `cozefn.cn`, `cozeide.cn`, `cozesdk.com` | ByteDanceCN | Existing DIRECT rules; upstream explicitly identifies the domestic Coze family. |
| `lingyiwanwu.com` | Domestic | Current official Chinese site identifies the Beijing company and ICP registration; it is not inferred international from `.com` or from the company's separate `01.ai` entry. |

The blanket `mchost.guru` contraction also removes AI routing from unknown hosts
under that parent. This is deliberate: neither a global AI suffix nor a global
DIRECT suffix can represent its evidenced CN/SG split. No additional hosts are
invented from a country-name pattern.

## Existing coverage and deliberate omissions

- Google Gemini, AI Studio, NotebookLM, Antigravity and Google API families;
  Microsoft Copilot/GitHub; Meta AI/Llama; and X/Grok remain with their ecosystem
  owners. Narrow upstream entries already covered by those parents are not
  duplicated in AI.
- DeepSeek, Kimi `.com`/Moonshot `.cn`, MiniMax `.com`, Zhipu/BigModel and domestic
  ByteDance/Alibaba/Tencent/Baidu services retain DIRECT. International
  Qwen/Qoder, Kimi `.ai`/Moonshot `.ai`, MiniMax `.io`/Hailuo `.video`, Z.ai,
  SiliconFlow `.com`, StepFun `.ai`, Coze `.com`, and ModelScope `.com` retain AI.
  In particular, upstream `scope: cn` on Moonshot or Zhipu does not override an
  international product decision. `www.kimi.ai` and `www.kimi.com` both returned
  HTTP 200 without redirecting into each other in this check.
- Alibaba cloud accounts, login and consoles retain the existing AlibabaCN
  family. Retrieved console HTML references shared Alibaba assets and domestic
  console services. International model API endpoints are explicitly regional;
  their coverage does not move all cloud account traffic into AI.
- Hugging Face browsing/API remains AI. Its Xet/LFS/`aws.cdn.hf.co` bulk model
  and dataset delivery remains the earlier ModelDownloadCDN owner.
- Do not import the 23 VPSDance PROCESS-NAME entries, Sukka URL-REGEX, broad
  brand/telemetry keywords, DigitalOcean ASN 14061, or shared cloud/CDN parents.
  Existing rules and exemptions remain subject to A1–A10, not upstream labels.
- `hf.space`, `repl.co`, `replit.app`, `replit.dev`, and `windsurf.build` remain
  excluded tenant hosting namespaces. Windsurf's own deployment documentation
  identifies `<SUBDOMAIN_NAME>.windsurf.build` as a user's public deployment;
  this is not a missing model API rule.
- `anthropic.com.cn` and `chatbotclaude.com` are not newly imported: current
  apex queries had no A answer and the review did not establish a first-party
  active service. They are not declared expired or added to the expiry denylist.
- `anthropic.auth0.com` retains the existing Proxy owner: its unauthenticated
  redirect led to the generic Auth0 site. That observation does not establish
  an active Claude login dependency or justify changing the shared Auth0 owner.
- `awsapps.com`, `awsstatic.com`, `sso.amazonaws.com`, `api.cloudflare.com`,
  general analytics/payment infrastructure, and generic ByteDance telemetry/CDN
  hosts retain their existing owners. AI upstream membership alone is not
  exclusive service ownership.
- The upstream CN grouping of `mcbaas.work`, `mcdemo.show`, `tcwqqdy.guru` and
  `trae.guru` does not establish each namespace's full regional behavior. Their
  existing AI routing is preserved pending actual endpoint/traffic evidence;
  this review does not certify them as exclusively domestic or international.

## Evidence

- [VPSDance pinned aggregate](https://github.com/VPSDance/ai-proxy-rules/blob/cc1d596a6b645986d293bd93f43a3e9ab114f3e8/rules/surge/all.list)
- [Sukka pinned AI source](https://github.com/SukkaW/Surge/blob/81632ebcfaa6a2469721d63e7be16639db319f63/Source/non_ip/ai.conf)
- [blackmatrix7 pinned OpenAI rules](https://github.com/blackmatrix7/ios_rule_script/blob/5f06cacdb752a951bba8511b25eadde77ebc683c/rule/Surge/OpenAI/OpenAI.list)
- [Alibaba region and access domains](https://www.alibabacloud.com/help/en/model-studio/regions/), [Base URLs](https://www.alibabacloud.com/help/en/model-studio/base-url), [Coding Plan](https://www.alibabacloud.com/help/en/model-studio/coding-plan-faq), [US workspace endpoint](https://www.alibabacloud.com/help/en/model-studio/text-to-video-api-reference)
- [TRAE staff allowlist](https://forum.trae.cn/t/topic/12725/3), [CN public startup configuration](https://forum.trae.cn/t/topic/7102), [international staff allowlist](https://forum.trae.cn/t/topic/3492/4)
- [Zero One official Chinese site](https://www.lingyiwanwu.com/)
- [Windsurf user deployments](https://docs.windsurf.com/windsurf/cascade/app-deploys)

Public endpoint probes used unauthenticated HTTPS only; no paid inference,
account changes or client policy changes. Root 400/401 responses show a server
responded, not that authenticated service use succeeded. The CN/SG TRAE ping
paths returned 200. DashScope CN/international model discovery returned 401,
and Coding Plan international discovery returned 200. These observations do not
compare domestic and overseas exit quality. Raw diagnostics remain outside the
repository.

## Validation

- 344 scenarios / 2,328 requests / 4,557 assertions passed; 1,999 DNS assertions
  passed. Eight added AI cases cover regional pairs, ecosystems, exact assets,
  shared-host negatives and model downloads. The earlier Zero One assertion was
  updated to distinguish its domestic website from the separate international
  entry rather than force every company domain into one policy.
- Source/Clash contract: 35 providers, 142,205 exact source/provider rules,
  identical manifest order/policies, DNS contract and 73 ownership witnesses.
- Surge native syntax accepted the candidate. A post-publication check detected
  the saved profile had reverted MicrosoftCN behind Microsoft. Restored only the
  reviewed generated Rule section and reloaded it; all other profile sections
  were verified unchanged. The final saved profile again matches the manifest.
- Mihomo native syntax passed with local provider files and neutral proxy
  placeholders. An isolated TUN-disabled instance loaded 35 providers and all
  142,205 rules, returned fake IPv4/IPv6 via UDP and TCP, and returned SERVFAIL
  when its proxy failed instead of falling back to direct DNS.
- Shape and diff checks passed. The final release passed A1–A10: 142,241 rules
  including profile/built-in entries, no P0/P1/P2, and the same three P3
  information items. Full Country/ASN-expanded analysis accounted for all
  142,205 source rules with no unsafe splits or expired-domain re-entry.

## Publication and runtime result

Routing release `0fffcbe` was pushed and origin/main SHA verified. Its two
changed distribution files were purged and both CDN hashes matched. The earlier
Microsoft release `d0adde3` had already included the first part of this AI batch
from the shared working tree; this final release completes it without rewriting
history.

A subsequent full check matched all 71 current distribution files against the
validated local MD5s. The retired `lists/MicrosoftFallback.list` still returned
old cached bytes initially; both removed fallback paths were purged again,
accepted by both jsDelivr providers without throttling, and both then returned
HTTP 404. Result: **PUBLISHED_AND_VERIFIED**.

All 35 canonical Surge resources were refreshed and reported ready with none
still updating. Native `surge-cli rule explain` passed 12/12 public policy
witnesses: CN/international DashScope, Coding Plan, CN/SG TRAE, Zero One, Claude,
Gemini, HF downloads and three Microsoft DIRECT priority examples. The saved
private Clash rule order and HTTP provider definitions match the public merge
file; no running Clash application was available for a client refresh. Native
Mihomo behavior was verified using the isolated instance described above.
