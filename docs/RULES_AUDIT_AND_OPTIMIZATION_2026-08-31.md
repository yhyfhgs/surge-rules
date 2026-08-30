# Surge 规则全量审计与精准分流迭代方案

> 审计日期：2026-08-31（Asia/Shanghai）<br>
> 审计基线：`a1c3efc9e02b2f930cc07007a76253f932967081`<br>
> 实测运行时：Surge Mac 6.9.0（Core 6009000）、Mihomo 1.19.20<br>
> 审计对象：仓库全部跟踪文件、34 个 `lists/*.list`、34 个 Clash 派生 list、真实 `Surge.conf` 的有效规则序、测试/发布/回滚链路及本地参考库<br>
> 本文只给出审计结论和迭代设计；本轮没有修改任何现行分流规则、策略组或 Surge 配置。

## 1. 结论先行

当前项目不是“规则不可用”，而是“基础工程已经不错，但精准度与可证明性尚未闭环”。必须把三类结论分开：

1. **当前运行健康**：Surge 原生 profile 校验通过；34 个远程规则集全部 ready；离线 1,044 条断言全绿；完整只读实网矩阵未发现 DNS/WebRTC 泄漏或代表域连通性失败。
2. **规则分类仍有确定误差**：`DownloadCDN`、共享云平台/ASN、104 条无边界关键词、共享遥测/认证域、地区表与流媒体表的会话拆分，均存在可证明的过捕获或分类歧义。
3. **工程发布闭环不可靠**：`update.sh` 存在“purge/校验失败仍返回 0”的假成功路径；`preventive` 同时承载“允许重叠”和“必须不存在”两种相反语义，后者会被当前实现静默豁免；真实顺序、Clash 顺序、文档、测试和上游来源没有统一事实源。

最需要优先处理的不是继续增加域名，而是：

- 把多租户公共后缀、共享云 ASN/IP、共享第三方组件从业务专属表中剥离；
- 将 `DOMAIN-KEYWORD` 从默认工具降级为严格例外；
- 让规则拓扑、上游版本、排除/移动裁决和生成结果可机器重建；
- 建立 Surge 与 Mihomo 的双端差分测试；
- 让任何“已发布但未验证”的状态明确失败，而不是打印“完成”。

## 2. 审计范围、方法与边界

### 2.1 已执行的检查

本次不是抽样看几个域名，而是对全部源规则逐行解析后再做分层审查：

- 盘点 99 个 Git 跟踪文件、34 个 Surge 源 list、35 个 Clash 派生产物、10 个场景文件和所有维护文档；
- 对 **154,681 条源规则**逐行做类型、字段、大小写、空白、域名字符、CIDR 严格解析、IPv4/IPv6 类型、修饰符和 `no-resolve` 检查；
- 按真实 `Surge.conf` 顺序展开 SYSTEM/LAN 近似及 FINAL，共检查 **154,717 条有效规则**；
- 执行项目内置 A1–A7 审计、engine/audit 自检、103 个场景、625 个请求、1,044 条断言；
- 额外实现域名包含、CIDR 基数树/集合折叠、跨文件 CIDR 遮蔽、单标签后缀和多租户公共后缀检查；
- 用当前 Public Suffix List（SHA-256 `24b79d731bb0d296171c513aed2e89c3163cb74a177b14d2b27f006e8ce00936`）核对所有 `DOMAIN-SUFFIX`；按 exact/wildcard/exception 正确语义并统一 IDNA A-label，识别落在 ICANN/PRIVATE 有效公共后缀边界上的规则；
- 用 Surge 原生 `--check`、`rule match`、`rule explain`、`dump performance`、`dump rule-usage`、`benchmark rule-matching` 和 external-resource 状态交叉验证；
- 完整执行 L4：TUN、DNS、客户端画像、WebRTC/STUN、UA 通道矩阵、563 个唯一查询的 Surge/离线差分；
- 用 Mihomo 实际加载全部 34 个 classical provider，确认 **154,681 条派生规则全部被解析**；
- 对照 2026-08-31 的 Surge 与 Mihomo 官方文档核验规则语义。

### 2.2 不能伪装成“已证明”的部分

静态分析可以证明语法、包含、顺序和确定误匹配，但不能凭规则名字证明 12.9 万个域名当前仍属于某家公司、仍在使用或仍应走某个出口。当前仓库又没有逐条 provenance、命中历史和可重建上游，所以本文将结论分为：

- **确定**：由规则语义、顺序、官方文档或真机结果直接证明；
- **高置信**：所有权/多租户性质明确，但实际用户流量影响仍需日志确认；
- **观察候选**：必须先收集命中、CNAME、RDAP/ASN 或完整会话链，不能直接删除。

这一区分很重要。对 154,681 条规则声称“逐条人工确认业务所有权”是不真实的；正确做法是让每一条都通过严格机器检查，并把需要业务证据的少数规则自动提升到人工队列。

## 3. 当前基线

### 3.1 资产与规则类型

| 项目 | 当前值 |
|---|---:|
| Git 跟踪文件 | 99 |
| Surge 源规则集 | 34 |
| Clash list / provider YAML | 34 / 1 |
| Surge 源规则 | 154,681 |
| 展开后有效规则 | 154,717 |
| `DOMAIN` | 519 |
| `DOMAIN-SUFFIX` | 129,341 |
| `DOMAIN-KEYWORD` | 104 |
| `DOMAIN-WILDCARD` | 54 |
| `IP-CIDR` | 19,449 |
| `IP-CIDR6` | 5,175 |
| `IP-ASN` | 32 |
| `GEOIP` | 7 |
| allowlist 条目 | 39 |
| 场景 / 唯一查询 / 断言 | 103 / 563 / 1,044 |
| DNS 泄漏断言 | 333 |

### 3.2 当前验证结果

| 层 | 结果 | 结论边界 |
|---|---|---|
| Surge `--check` | `OK` | profile 可加载；不证明未知参数一定有效，也不证明分类正确 |
| 外部规则资源 | 34/34 ready | 当前 Surge 已取得全部规则集 |
| `audit.py` | P0/P1/P2 未豁免项均为 0；17 组 P3 关键词报告 | allowlist 会隐藏既定重叠；且存在 `preventive` 语义缺陷 |
| `runsuite.py` | 1,044/1,044，known-broken=0 | 只证明既定 563 个唯一查询符合既定期望 |
| engine 自检 | 65/65 | 离线规则语义实现的合成/冒烟样例通过 |
| audit 自检 | 27/27 | 已植入并验证 A1–A6；A7 尚无“非法规则行必须被捕获”的正向自检，也不包含本文新增盲区 |
| L4 完整实网 | 123 pass / 0 fail / 2 warning / 36 report-only | DNS、客户端、WebRTC 均通过；2 个纯 IP 的 DE/US GEOIP 只能由 Surge 真引擎判定 |
| Surge/Mihomo 派生 | Mihomo 解析 34 provider、154,681 条 | 证明当前文件可加载；不证明 SNI、DNS、UDP 和 FINAL 语义等价 |
| 随机未命中规则基准 | 平均 574.5 µs | 当前机器/当前运行态基线，不是跨版本 SLO |
| Surge 引擎内存 | 约 197 MB | 含完整运行态，不等于规则集独占内存 |
| 临时规则 | 0 | 本次真机结论未受临时规则覆盖 |

### 3.3 测试的语义覆盖率

625 个场景请求去重后为 563 个查询，只触达 34 张表中的约 **324 条不同子规则**，约占 154,681 条源规则的 **0.21%**。这不是说其余规则都错误，而是说明：

- 场景测试对高频核心服务有效；
- 大型上游表的业务语义主要依赖“信任上游”，不是由回归测试证明；
- `Europe`、`Japan`、`NetEaseCN`、`UK`、`US` 在 L2 场景中没有任何胜出规则；地区代表域只存在于非发布闸门的 L4 数据中；
- `cloudfront.net`、`blob.core.windows.net`、`github.io`、`vercel.app`、`pages.dev`、`workers.dev`、AS396982、`35.192.0.0/12`、PayPal 关键词负例、`api.snapkit.com` 和 `cocacola.co.jp` 均没有 L2 直接覆盖。

因此当前的“全绿”应解释为**回归稳定**，不能解释为**全量分类正确**。

## 4. 精准分流的形式化目标

设有序规则为 $R=(r_1,\ldots,r_n)$，规则 $r_i$ 的匹配谓词为 $m_i(x)$、策略为 $p_i$。Surge/Mihomo 的核心行为是首次命中：

$$
j(x)=\min\{i\mid m_i(x)=1\},\qquad P(x)=p_{j(x)}
$$

对一次业务会话 $S=(x_1,\ldots,x_k)$，只验证单个域名不够。应同时最小化：

$$
\mathcal{L}=
w_m\Pr[P(x)\neq P^*(x)]
+w_s\Pr[|\{P(x_i):x_i\in S_{critical}\}|>1]
+w_r\Pr[\text{false reject}]
+w_d\Pr[\text{proxy target local DNS}]
+\lambda C(R)
$$

其中：

- $P^*$ 是经证据确认的目标策略；
- $S_{critical}$ 是登录、鉴权、支付、API、上传等要求出口一致的关键子链；
- $C(R)$ 是规则规模、线性关键词/正则成本、维护成本和跨端差异的组合；
- 对支付、登录和 REJECT，$w_s$、$w_r$ 应显著高于“下载是否走便宜线路”的带宽权重。

由此得到六条核心不变量：

1. **精确例外先于宽兜底**，并由机器验证包含关系；
2. **业务所有权不等于云平台所有权**，共享 ASN、对象存储和托管后缀不能直接代表调用者；
3. **身份关键链同出口**，大文件例外只能切割已证明与登录态无关的数据面；
4. **所有 IP 规则保持 `no-resolve`**，但不能把它误写成“Clash 全链 DNS 自动安全”；
5. **Surge 与 Mihomo 必须跑同一语料的差分测试**，不能只验证文件能解析；
6. **所有豁免必须是预期存在的例外；预期不存在的规则必须是 deny assertion，不能放进 exemption。**

## 5. 严重度定义

| 级别 | 定义 |
|---|---|
| P0 | 可导致发布假成功、禁止规则静默回流、错误分支发布或无法可信回滚的控制面缺陷 |
| P1 | 已能证明会过捕获、错分流、跨端行为不一致，或直接破坏会话/DNS/策略不变量 |
| P2 | 当前行为通常相同，但存在大规模冗余、测试盲区、所有权错误或维护漂移 |
| P3 | 文档、命名、格式、可移植性和低风险清理项 |

## 6. 最高优先级发现

### P0-01：`update.sh` 会在发布未验证时返回成功

确定证据位于 `update.sh:48-80`：

- CDN 拉取和 purge 请求都以 `|| true` 吞掉失败；
- purge 返回非 JSON 时被转换为 `t=0`，随后当作“未限流且已发 purge”；
- 复验 hash 不一致只打印“边缘传播中”；
- throttled 只告警；
- 最终仍打印“完成”并返回 0。

这与 `docs/ARCHITECTURE.md:48` 和 `README.md:159` 所声称的“MD5 一致才算成功/不会发半成品”直接矛盾。

必须改为三态结果：

```text
VALIDATED_NOT_PUBLISHED
PUBLISHED_AND_VERIFIED
PUBLISHED_BUT_UNVERIFIED   # 必须非零退出
```

并采用 `set -euo pipefail`、`curl --fail-with-body --location`、明确 HTTP/JSON 字段校验、SHA-256、限流/不一致非零退出。

### P0-02：非 `main` 分支可造成“提交 A、推送 B、刷新 A”

`update.sh:25-29` 在当前分支 `git add -A`/commit，却固定 `git push origin main`，随后又把当前 `HEAD` 当成新版本计算 purge diff。若在 feature 分支执行，脚本可能刷新没有进入远端 main 的内容。

发布前必须验证当前分支、远端基线和推送后的远端 SHA；推送应显式使用 `HEAD:main`，且远端 `refs/heads/main` 必须等于本地已验证 SHA。

### P0-03：`preventive` 字段混合了两种相反语义

39 个 allowlist 条目中有 35 个 `preventive=true`。其中一部分是当前允许存在的分层重叠，例如 `amazonaws.com` 具体子域与宽兜底；另一部分则明确写着“当前不应命中、命中即删”。但 `tests/audit.py:98-127,154-161` 对两者都在命中时直接返回 exemption；其唯一特殊行为只是“未命中时不报告 unused”。

实际语义变成：

> 当前没有时不提示；未来真的回流时也不报错。

这会让 D7/D11 已禁止的 `USER-AGENT`、`PROCESS-NAME` 和若干危险宽关键词绕过发布门禁。其中 `USER-AGENT` 会在 Clash 派生时被剔除，造成 Surge/Clash 分叉；`PROCESS-NAME` 与危险 `DOMAIN-KEYWORD` 会原样进入两端，虽然不是同一种分叉，仍违反 D7/D11 和精准度约束。

不能把所有 `preventive` 整体反转成“命中即失败”，否则当前合法的 AWS 分层也会被阻断。必须逐条迁移成四种机器语义：

- `expected_overlap`：预期存在的精确 winner/dead 关系；
- `exemptions`：确实允许存在的 finding；
- `forbidden_rules`：出现即 P0/P1；
- `expected_absent`：必须持续不存在的类型/模式。

### P1-01：`DownloadCDN.list` 是当前最大误分流源

该表声称只承载“大流量批量下载”，实际有 5,623 条，并包含整个多租户平台、账号/API、论坛、支付、遥测和浏览静态资源。

确定的公共平台例子：

| 行 | 规则 | 为什么不能代表“下载” |
|---:|---|---|
| 538 | `blob.core.windows.net` | 任意 Azure Blob 租户 |
| 1298 | `cloudfront.net` | 任意 CloudFront distribution |
| 1588 | `digitaloceanspaces.com` | 任意 DigitalOcean Spaces 租户 |
| 2219 / 2222 | `github.io` / `gitlab.io` | 任意 Pages 站点 |
| 3705 / 3737 / 3772 | `netlify.app` / `now.sh` / `onrender.com` | 任意应用、API、OAuth 回调 |
| 3840 / 5357 / 5482 | `pages.dev` / `vercel.app` / `workers.dev` | 任意 Cloudflare/Vercel 租户 |
| 4426 | `s3.amazonaws.com` | 任意 S3 bucket |
| 5023 | `supabase.co` | 任意 Supabase 项目 |
| 5290 | `unpkg.com` | 包内容 CDN，不等于所有请求都是可分离的大文件 |

Public Suffix List 核对发现，全库有 462 条 `DOMAIN-SUFFIX` 落在有效公共后缀边界，其中 **327 条在 DownloadCDN**。这意味着它们按定义会覆盖多个互不相关的注册者/租户，而不是一个业务所有者。另有 `digitaloceanspaces.com` 等不直接等于 PSL 边界、但业务上仍属多租户平台的宽后缀；两类风险需分别统计。

该表还包含 `account-api.bandainamcoid.com`、`account.bandainamcoid.com`、OneNote sync/API、FiveM crash/docs/forum、Trustpilot、Algolia、Zendesk、Datadog、Freshdesk、Gigya、Braze 等非下载面。词法启发式至少找出 21 条 account/login/auth、86 条 API、75 条 analytics/APM/tracking、9 条 payment/checkout 候选；这些计数是人工复核队列，不应直接当删除列表。

正确重构方式是**从空白 allowlist 重建**：只收可证明为包仓库、OS/软件发行、镜像、模型权重、游戏补丁的精确 host/bucket。禁止以整个公共云/托管平台后缀作为下载信号。

### P1-02：云 ASN/IP 被错误当成业务身份

`Google.list:634` 的 `IP-ASN,396982` 会把任意 Google Cloud 客户工作负载归到 Google-X-Meta-MS。Google 官方文档明确把 AS396982描述为 Google Cloud 通告公开前缀所用 ASN，而不是“Google 第一方产品专网”。

`Games.list:510` 的 `35.192.0.0/12` 覆盖 **1,048,576 个 IPv4 地址**。它是一个过宽 supernet，包含大量 Google Cloud 当前公布的客户可用区域前缀，因而至少会覆盖大量无关 GCP 租户，不能作为 Games 身份。真机对样本地址执行规则匹配时，前位 AS396982 已让 Google 表胜出；ASN 数据缺失或双端数据库不一致时，这个 `/12` 又会成为错误后备规则。

同一问题还包括：

- Google 表的 `appspot.com`、`cloudfunctions.net`、`firebaseapp.com`、`run.app`、`web.app`；
- TencentCN 的 14 个腾讯云海外 `/24`；
- Streaming 的通用 AWS API Gateway/云 IP；
- Telegram/Games 等表中可被重新分配的第三方云 `/32`。

规则必须区分：

- `first_party_network=true`：业务方稳定专网，可作为 IP fallback；
- `cloud_provider_shared=true`：只代表云厂商，不代表租户，默认回 Final/SharedHosting；
- `dynamic_single_ip=true`：必须有 `last_verified` 和自动过期。

### P1-03：`Streaming.list` 过宽且把共享依赖绑定到流媒体出口

Streaming 共 3,070 条，其中有 1,980 条 CIDR（1,975 IPv4 + 5 IPv6）和 3 条 IP-ASN，按项目定义共 **1,983 条 IP 类规则**；IPv4 CIDR 的并集覆盖约 **6,038,120 个地址**。与 AWS 官方 `ip-ranges.json` snapshot（`createDate=2026-08-30-17-17-05`）对照，有 1,089 条 Streaming IPv4 CIDR 完整落入 AWS 公共云范围，合计 5,619,709 个地址；这些范围同时承载 AWS 客户工作负载，并非流媒体专网。域名区还包含 Adobe DTM、Braze、Optimizely、Kochava、CookieLaw 和通用 AWS API Gateway 区域后缀。

应拆为：

1. 流媒体控制面（登录、目录、播放授权）；
2. 精确内容面 CDN；
3. 经证明确属服务方的 ASN/IP fallback；
4. SharedTelemetry/SharedConsent/SharedAPI，默认不绑定到任何单一流媒体服务。

### P1-04：104 条 `DOMAIN-KEYWORD` 的误捕获不是理论风险

关键词按 hostname 任意子串匹配，无标签边界。当前 104 条分布在 17 张表，且 Reject、YouTube、Google、Payment、MicrosoftCN、ChinaDomain 等关键位置均有宽关键词。

将当前关键词与未合并的上游 Direct/ChinaMax 候选对撞后，已得到具体冲突：

- `DOMAIN-KEYWORD,gmail` 会抓到 `qingmail.com`、`suningmail.com`；
- `DOMAIN-KEYWORD,avtb` 会抓到快手上游域 `eqoavtbu.com`，当前落 Final；
- `DOMAIN-KEYWORD,github` 会抓到 `githubim.com`、`githubshare.com`、`hellogithub.com`、`kkgithub.com`；
- TikTok 的 `DOMAIN-KEYWORD,ttcdn-tos.` 会抓到上游明确 DIRECT 的 `ttcdn-tos.kkimg.cc`；
- `youtube`、`twitter`、`telegram`、`whatsapp`、`paypal` 等会抓到任何含品牌串的第三方/仿冒域；
- ChinaDomain 尾部 9 个品牌关键词会把任意包含 `baidu`、`alipay`、`aliyun`、`taobao`、`weibo` 等子串的未收录域强制 DIRECT；
- Reject 的 `dnserror`、`hostingcloud`、`adsyndication` 等没有命名边界，误杀代价最高。

应设新规则：`DOMAIN-KEYWORD` 默认禁止；例外必须同时具备 owner、完整理由、至少两个负向邻域样例、真实命中证据和复核日期。结构固定的 CNAME 片段改 `DOMAIN-WILDCARD`，品牌域改精确 `DOMAIN`/`DOMAIN-SUFFIX`。

### P1-05：共享依赖无法按“调用它的主站”分类

AI 表刻意收录 `static.cloudflareinsights.com`、`challenges.cloudflare.com`、Datadog、Statsig、Sentry、Intercom、GrowthBook、Arkose、Replit 多租户后缀。域名规则看不到 referrer，也不知道这是 ChatGPT 触发还是普通网站触发，因此会把**所有站点**使用这些共享服务的连接送到 AI 出口。

Streaming、DownloadCDN、ProxyGFW 和 Google 中存在同构问题。更准确的抽象是：

- SharedAuth；
- SharedChallenge；
- SharedTelemetry；
- SharedHosting；
- SharedObjectStorage；
- SharedConsent/Experiment。

如果某个共享域必须与 AI 同出口，应在策略层显式让 SharedChallenge 选择同一个底层出口，而不是伪造“它属于 AI”。这样至少所有权、风险和命中统计仍是独立的。

一个现有裁决应直接更正：`static.cloudflareinsights.com` 是 Cloudflare Web Analytics 性能 beacon，不是 Turnstile challenge。它应归 SharedTelemetry/Final；以“可降低验证码率”为理由绑到 AI 没有技术依据。

### P2-02：共享托管规则使 Payment 覆盖无法证明

`Payment.list` 位于 DownloadCDN 之后，而 DownloadCDN 覆盖大量 CloudFront/Blob/Pages/S3 租户域。但根因不只是顺序：若支付组件使用 `merchant-x.cloudfront.net`，Payment 中又没有这个精确租户 host，即使单纯前移 Payment 也仍不会命中。

正确顺序是先识别并收录经验证的支付租户精确 host，再让 Payment 位于 GenericDownload 之前。当前 `downloads.lemonsqueezy.com`、`public-files.gumroad.com` 只证明文件交付面被前位拆分，并不能证明 checkout/3DS 已经失败；是否要求同出口必须由真实支付链验证。

建议顺序改成：

```text
VerifiedLargeObjectExceptions  # 仅极少数已证明可拆的大文件 host
Payment                        # 登录/3DS/checkout 关键链
GenericDownload                # 严格收缩后的通用下载
```

同时将 `DOMAIN-KEYWORD,paypal` 替换为 PayPal 官方精确后缀，并加入仿冒/商户自建 callback 的负向样例。

### P1-07：Domestic 不是通用直连例外层

真实顺序是 AppleCN/MicrosoftCN → ProxyGFW → 地区表 → Domestic。因此，任何落在 `amazonaws.com`、`azureedge.net`、`microsoft.com`、`akamai.net`、`fastly.net` 等 GFW 宽后缀下的直连特例，即使写进 Domestic 也永远不会生效。

应拆出 `DirectExceptionsPreGFW.list`，只允许精确 DOMAIN 或经审查的小后缀；Domestic 保持为 GFW 后的国内长尾层。

### P1-08：Surge 与 Clash 当前并不行为等价

确定差异包括：

- Surge 实际顺序为 SYSTEM → PrivateLAN → PKU → Reject；生成的 Clash 参考是 Reject → PrivateLAN → PKU；
- Surge 有 SYSTEM，Clash 示例只有一条 `GEOIP,lan` 注释；
- 11 张 Surge 表使用 `extended-matching`，provider 无法携带这一修饰；Mihomo 必须另行配置 HTTP/TLS/QUIC sniffer；
- Surge 的 `FINAL,Final,dns-failed` 被简化为 `MATCH,Final`；
- Surge 的零本地 DNS 还依赖 VIF/fake-IP/远端解析，Mihomo 的实际行为取决于完整 `dns:`、nameserver、respect-rules、TUN 和 sniffer 配置；
- Mihomo 对“不支持 UDP 的节点”可继续向后匹配，Surge 当前配置是 REJECT，不做 DIRECT 回退；
- GEOIP/ASN 数据库来源、日期和更新路径并不相同。

所以 `clash/rule-providers.yaml` 只能叫“规则内容片段”，不能声称自动继承 Surge 的完整 DNS、安全和顺序语义。

### P1-09：上游同步与拓扑不可重复

除了 ChinaIP 表头记录了具体 commit，其他“机器管理”表没有：

- 逐表精确 URL/commit/checksum/license；
- 仓库内同步脚本；
- 可机器执行的过滤、移动和排除清单；
- 生成当前 34 张表的确定步骤；
- 统一的顺序、策略、启停和 modifiers manifest。

目前规则内容在 `lists/`，顺序在私有 `Surge.conf`，Clash 顺序在转换器，文档又有两份表，场景断言和 allowlist 再复制一遍业务裁决。这就是 32→34、90→103、Reject 停用→启用后文档全面漂移的根因。

### P1-10：测试器本身存在可制造假绿的空洞

`runsuite.py` 没有严格 schema：空 requests + `same_policy` 可通过、无 assert 可产生 0 断言、`policy`/`policy_in` 可冲突、未知字段被忽略、重复 `per_request` key 后项覆盖前项，新增 known-broken 也不阻断发布。

离线引擎对非 CN GEOIP 和大多数 ASN 只是近似；L4 已证明 159.89.0.1/45.32.0.1 在真 Surge 中命中 DE/US，而 engine 落 FINAL。在线结果正确，但发布闸门只跑离线层。

### P2-01：当前已启用 IPv6，但服务 IP fallback 高度不对称

真实配置为 `ipv6=true`、`ipv6-vif=auto`。ChinaIP 有完整 IPv4/IPv6 数据，但多个业务表只有 IPv4 或覆盖极不对称：Games 42/0、Meta 42/0、ProxyGFW 40/0、Twitter 8/0、Streaming 1,975/5（IPv4/IPv6 CIDR）。

正常域名/SNI 流量可由域名规则承接，但 literal IPv6、hostname 丢失、sniffer 失败和数据库缺失时会与 IPv4 落到不同策略。不能把 IPv4 云段机械映射为 IPv6；应先删除共享云段，再只为第一方稳定网络补双栈数据，并加入仅 A、仅 AAAA、A+AAAA、IPv6 literal、有/无 SNI 的差分矩阵。

## 7. 确定的结构重复与审计盲区

### 7.1 现有 A2/A3/A4 的原始发现

- 18 条跨文件精确重复：AI↔ChinaDomain 2 条、PKU↔ChinaIP 2 条、TencentCN↔ChinaIP 14 条；
- ProxyGFW 的 `amazonaws.com` 覆盖同表 `sso.amazonaws.com`；
- AppleCN 的 `digicert.com` 覆盖 Domestic 的 `cacerts/crl3/ocsp.digicert.com` 3 条。

这些当前均被 allowlist 聚合豁免。策略结果大多相同，但“CA 基础设施被登记在 Apple 表”仍是所有权错误。

### 7.2 ChinaIP 可等价减半

ChinaIP 的 22,417 条 CIDR 中：

- 11,228 条被同表更宽前缀完整包含；
- `collapse_addresses` 后只需 11,090 条；
- 可减少 **11,327 条（50.5%）**，地址集合与策略语义不变。

跨文件还有 189 条落在 AppleCN 宽段、19 条落在 Domestic 宽段、14 条落在 TencentCN、2 条落在 PKU；`74.125.16.64/26` 被前位 Google `74.125.0.0/16` 覆盖。

现有审计只覆盖域名包含和精确 CIDR 重复，没有 CIDR 子网/超网、IP-ASN/GEOIP 与 CIDR 的交叉检查。

### 7.3 公共后缀边界

使用上述锁定 PSL snapshot、正确处理 wildcard/exception 和 IDNA 后，当前有 462 条规则落在有效公共后缀边界：

| 文件 | 数量 | 含义 |
|---|---:|---|
| DownloadCDN | 327 | 全部为 PRIVATE；绝大多数是 AWS/托管/对象存储多租户边界 |
| ProxyGFW | 37 | 多个动态 DNS、PaaS、政府公共后缀 |
| ChinaDomain | 55 | 44 个 ICANN TLD（含 33 个 IDN A-label）+ 11 个私有托管边界 |
| Google | 11 | 2 个品牌 gTLD + 9 个 Google Cloud 多租户边界 |
| AI | 8 | Replit/HF/OpenAI/Claude 等私有后缀；需区分平台内容与业务所有权 |
| 其他 9 张表 | 24 | 政府/教育/品牌/平台边界混合 |

合计 ICANN 66、PRIVATE 396。不能把 PSL 的 `*.parent` 简化成 `parent`，也不能把 `!exception` 本身计为公共后缀；后续应把这段算法固化为 A11 测试。

此外 ChinaDomain 有 44 条单标签后缀，其中除 `.cn` 和品牌 gTLD 外，还包括 `.wang`、`.shouji`、`.xihuan` 及“集团、在线、公司、网站、网络、手机、健康、招聘、游戏”等 IDN gTLD。中文名称不等于服务器位于中国；整 TLD DIRECT 是高召回、低精度启发式，应移入单独的 `ChinaTLDHeuristics` 层并基于命中/可达性决定保留。

## 8. 逐文件审计

表中“L2 命中”为 563 个唯一查询中命中该表的查询数/不同子规则数，不代表生产命中率。

| list | 规则结构 | L2 命中 | 结论与动作 |
|---|---:|---:|---|
| AI | D20/DS350/DK2/V4 4/V6 2/ASN5 = 383 | 94/56 | P1。核心 AI 域覆盖较强；SharedChallenge/Telemetry/Experiment/Support/Hosting 被整体绑到 AI。拆 `AIService` 与 Shared*，但保留明确产品专属的 Cognito/AWS Q 等控制面。 |
| AlibabaCN | DS1256 | 16/7 | P3。格式干净；缺精确上游锁和语义覆盖。4 个品牌 gTLD 可显式白名单。 |
| AppleCN | D8/DS1507/DK6/V4 10/V6 3 = 1534 | 10/3 | P2。6 个关键词应收窄；17/8 等稳定专网可保留；`digicert.com` 应迁共享 CA 层；Apple 媒体与 PCC 取舍需以会话场景固化。 |
| BaiduCN | DS232 | 10/2 | P3。格式干净；补来源锁和更多负向边界即可。 |
| ByteDanceCN | DS356 | 13/10 | P3。国内表相对清楚；需持续对撞 TikTok/Lark/CapCut 国际域。 |
| ChinaDomain | D171/DS106293/DK9 = 106473 | 12/5 | P1。机器层不可重建；9 个关键词、44 个整 TLD、若干境外托管 exact 需要分层。不得继续人工单条修补。 |
| ChinaIP | V4 17264/V6 5153 = 22417 | 3/3 | P2。`no-resolve` 全部正确；发布前自动 collapse 至约 11,090 条并输出集合 hash。 |
| ChinaMedia | D65/DS909/DK2 = 976 | 19/8 | P2。`bilibili`/`qiyi` 关键词应收窄；实际是中国媒体生态而非纯播放面，名称与 metadata 应一致。 |
| Domestic | D14/DS595/DW2/V4 2 = 613 | 60/32 | P1。内容混合国内 AI、银行、NTP、captive、CA；拆 NetworkInfra/CA/ManualDomestic，并新增 PreGFW direct exceptions。 |
| DownloadCDN | D66/DS5491/DK17/DW49 = 5623 | 22/16 | **P1 最高**。327 条 PSL 边界、大量 API/auth/APM/共享平台；从精确下载 allowlist 重建。 |
| Europe | DS68/GEOIP4 = 72 | 0/0 | P2。GEOIP 仅覆盖 CH/DE/FR/NL；域名层另含泛欧/跨国实体。名称和范围需明确，并加入 L2 正/负场景。 |
| GameDownloadCN | D7/DS59 = 66 | 5/5 | P1。精确国服 CDN 合理；`steambroadcast.com`、`steamusercontent.com` 和全球 content 域会把 UGC/直播也 DIRECT，应拆下载与社区内容。 |
| Games | D6/DS478/DK4/V4 42 = 530 | 7/5 | P1。删除/隔离 GCP `/12`；云 `/32` 建生命周期；4 个品牌关键词改精确域。 |
| Google | DS612/DK3/V4 4/V6 2/ASN5 = 626 | 26/11 | P1，高。AS396982 与 GCP 私有公共后缀代表租户平台，不代表 Google 产品；关键词也有 qingmail/suningmail 实证碰撞。 |
| Japan | DS78/ASN5/GEOIP1 = 84 | 0/0 | P2。域名、银行、媒体、ISP ASN/GEOIP 混合；L4 有代表域但发布闸门无覆盖。 |
| Meta | DS501/DK3/V4 42/ASN3 = 549 | 7/5 | P1。大量品牌防御/拼写域不属于运行关键面；更严重的是共享 AWS `/15` 会过捕获无关租户。拆 operational/brand archive，删除共享云段并收窄关键词。 |
| Microsoft | D11/DS28 = 39 | 23/12 | P1。表小且边界有意收窄；GitHub 主链较强，但共享 Pages 不应交 Download，也不应简单视为 Microsoft 第一方会话。 |
| MicrosoftCN | D5/DS62/DK3 = 70 | 1/1 | P1。`1drv/onedrive/skydrive` 无边界；OneDrive/Office/MSN 与 Microsoft/Download 跨策略。改官方端点表，并以 service bundle 场景裁决 `live.com/office.com/msn.com` 的宽 DIRECT。 |
| ModelDownloadCDN | DS4 | 2/2 | P2。当前是“窄、可解释、先于生态”的好模板；需验证签名重定向链和其他模型源，而不是直接扩成平台后缀。 |
| NetEaseCN | DS112 | 0/0 | P2。格式干净，但 L2 无胜出规则；增加非媒体网易服务场景或证明该表可合并。 |
| PKU | DS10/V4 10/V6 1/ASN1 = 22 | 6/4 | P3。早期直连合理；2 条与 ChinaIP 重复，可作为显式校园网 fallback 并在 manifest 说明。 |
| Payment | DS60/DK1 = 61 | 5/2 | P1。真实配置当前确为固定 `select`，这一点正确；PayPal 关键词仍需移除，Payment 应前置于 generic download，并补真实 checkout/3DS/auth/CDN 全链。 |
| PrivateLAN | DS130/V4 14/V6 4 = 148 | 2/2 | P3。保留地址和本地域合理；与内建 LAN 的重复可接受但需统一 Clash 顺序。 |
| ProxyGFW | D3/DS6403/DK9/V4 40 = 6455 | 22/11 | P1。共享 AWS/Azure/Akamai/Fastly 宽兜底会挡住后位直连例外；9 个关键词逐项收窄；删除 `sso.amazonaws.com` 死规则。 |
| Reject | D73/DS256/DW3/DK16/V4 8 = 356 | 83/78 | P1。启用状态与负向测试是优点；16 个关键词全部必须改精确/通配或删除，避免第一优先级误杀。 |
| SocialOthers | DS24 | 13/7 | P3。小而清楚；补服务完整链和 Midjourney/Discord 跨组裁决说明。 |
| Streaming | D48/DS1021/DK18/V4 1975/V6 5/ASN3 = 3070 | 19/9 | **P1 最高**。共享依赖、区域 API Gateway、巨大 IP 面；按服务拆 control/content/first-party network。 |
| Telegram | D1/DS20/DK2/V4 10/V6 4/ASN5 = 42 | 7/5 | P2。核心专网合理；关键词收窄；第三方 `/32` 增加 RDAP/last-seen/expiry。 |
| TencentCN | D1/DS2250/V4 14 = 2265 | 14/3 | P1。域名面干净；14 个腾讯云海外段可能承载客户租户，应从“腾讯第一方”剥离或提供证据。 |
| TikTok | D18/DS58/DK7/ASN2 = 85 | 11/9 | P1。`api.snapkit.com` 属 Snap，`cocacola.co.jp` 非 TikTok；删除/复核。7 个伪后缀关键词改 wildcard 并加 `ttcdn-tos.kkimg.cc` 负例。 |
| Twitter | DS25/DK1/V4 8/ASN3 = 37 | 14/10 | P1。Cursor/Anysphere 是独立 DevAI 所有权，不应命名为 Twitter；即使策略相同也应独立统计。`twitter` 改精确域。 |
| UK | DS36/GEOIP1 = 37 | 0/0 | P2。BBC/Sky/NowTV 与 Streaming 的内容面可能双出口；按服务 bundle 决定整体走 UK 还是 streaming。 |
| US | DS52/GEOIP1 = 53 | 0/0 | P2。CBS/Tubi/Fubo 等主站与播放面可能分到 US/Streaming；银行/券商则应保持稳定地区出口，建议拆 MediaUS 与 FinanceUS。 |
| YouTube | D2/DS5/DK1/V4 2/V6 1 = 11 | 1/1 | P1。表过度依赖 `youtube` 关键词和 extended matching；补官方后缀、负例及 hostname 丢失/SNI/IPv6 场景。 |

## 9. 104 条关键词的逐组处置

下面完整列出全部关键词；建议目标不是机械清零，而是让每一条都有边界和证据。

| 文件 | 数量 | 当前关键词 | 建议 |
|---|---:|---|---|
| Reject | 16 | `-ad.a.yximgs.com`, `-ad.ixigua.com`, `-ad.sm.cn`, `-ad.video.yximgs.com`, `-ad.wtzw.com`, `-adnow.com`, `-ads.realmemobile.com`, `-rtb.gravite.net`, `adsyndication`, `adtarget.`, `advertmarket`, `dnserror`, `hostingcloud`, `nimiqpool`, `packetsdk`, `pangolin-sdk-toutiao` | 前 8/结构化片段改 label-aware wildcard；其余改精确 suffix 或隔离观察。Reject 不允许保留无边界品牌词。 |
| YouTube | 1 | `youtube` | 用 `youtube.com`、`youtube-nocookie.com` 等官方后缀替代，并加 `youtube-dubbing.com`/`youtubeeducation.com` 负例。 |
| Google | 3 | `blogspot`, `gmail`, `recaptcha` | 改官方 suffix/wildcard；`gmail` 已误抓 `qingmail.com`/`suningmail.com`。 |
| Twitter | 1 | `twitter` | 改官方后缀；第三方含品牌域默认不属于 X。 |
| Meta | 3 | `fbcdn`, `instagram`, `whatsapp` | 现有 suffix 已覆盖核心域；移除或补确切遗漏后缀，禁止品牌子串。 |
| AI | 2 | `chatgpt-async-webps-prod`, `openaicom-api` | 若为固定云主机命名结构，改精确 wildcard 并记录样本；否则观察后删除。 |
| TikTok | 7 | `bytedance.map.`, `musical.ly.`, `tiktokcdn-`, `tiktokcdn.com.`, `tiktokv.com.`, `ttcdn-tos.`, `ttlivecdn.com.` | 改带标签边界的 wildcard；加入 kkimg.cc 等 DIRECT 负例。 |
| Telegram | 2 | `nicegram`, `telegram` | 改官方/客户端精确后缀；第三方包含品牌词不自动归 Telegram。 |
| Streaming | 18 | `apiproxy-device-prod-nlb-`, `avoddashs`, `bbcfmt`, `dualstack.apiproxy-`, `dualstack.ichnaea-web-`, `hbogoasia`, `japonx`, `japronx`, `jooxweb-api`, `netflixdnstest`, `nivod`, `nowtv100`, `rthklive`, `spotify`, `ttvnw`, `tvbanywhere`, `uk-live`, `voddazn` | ELB/CNAME 结构改 wildcard；品牌词改 suffix；没有当前命中证据的先观察。 |
| Games | 4 | `epicgames`, `steambroadcast`, `steamstore`, `steamuserimages` | 改官方 suffix；不以品牌子串捕获第三方社区/镜像。 |
| DownloadCDN | 17 | `-assets.worldsex.com`, `-cdn.eporner.com`, `-files.gitbook.io`, `-res.cloudinary.com`, `-thumbs.pornhost.com`, `-thumbs.worldsex.com`, `99avcdn`, `assets.trustpilot.net`, `cdn.adultempire.com`, `cdn.trustpilot.net`, `dsn.algolia.net`, `images.trustpilot.com`, `images.trustpilot.net`, `scripts.trustpilot.com`, `static.trustpilot.com`, `vod-adaptive.akamaized.net`, `web-assets.zendesk` | 结构化 host 改 DOMAIN/WILDCARD；Trustpilot/Algolia/Zendesk 从下载表移出；成人视频资源应归 Streaming 或独立内容组。 |
| Payment | 1 | `paypal` | 必须替换为官方精确后缀和负向仿冒集。 |
| AppleCN | 6 | `apple-support.akadns.net`, `apple.com.akadns.net`, `apple.com.edgekey.net`, `icloud.com.akadns.net`, `smp-device`, `testflight` | CNAME 结构改 wildcard，`testflight` 改官方后缀；`smp-device` 先收命中样本。 |
| MicrosoftCN | 3 | `1drv`, `onedrive`, `skydrive` | 替换为已验证的 Microsoft/OneDrive 精确后缀。 |
| ProxyGFW | 9 | `1e100`, `abema`, `appledaily`, `avtb`, `beetalk`, `dlercloud`, `dropbox`, `github`, `sci-hub` | 仅 `sci-hub` 可在严格品牌镜像语义下暂留；其他改 suffix/删除。`avtb`/`github` 已有上游 Direct 碰撞。 |
| ChinaMedia | 2 | `bilibili`, `qiyi` | 由现有官方后缀替代，不以品牌子串强制 DIRECT。 |
| ChinaDomain | 9 | `.tmall.com`, `alicdn`, `alipay`, `aliyun`, `baidu`, `hnagroup`, `officecdn`, `taobao`, `weibo` | 机器层全部删除；厂商表与精确 suffix 已承担职责。任何残留都应由生成器 forbidden check 阻断。 |

关键词逐条分类后的建议规模是：暂留 1、改精确 DOMAIN/SUFFIX 54、改有右侧可信边界的 WILDCARD 23、删除/隔离 15、先观测 11。唯一可暂留候选是 `sci-hub`；它仍必须有负例与命中统计。

需要注意，删除宽关键词前必须恢复曾被级联去重删掉的精确后缀。例如当前 YouTube 只剩少量规则，是因为约 170 个含 `youtube` 的精确资产被宽关键词覆盖后裁掉；Bilibili、iQIYI、Blogspot、Spotify、Dropbox 等也有同样问题。正确迁移顺序是：**恢复精确资产 → 加负例 → 删除关键词 → 全链差分**。

## 10. 会话边界与确定归属问题

### 10.1 OneDrive/Office 被拆成三条策略链

微软官方 OneDrive Consumer 必需端点把登录、配置、数据和 Office 依赖视为同一产品链。当前项目却分为：

| 角色 | 当前文件/策略 | 代表域 |
|---|---|---|
| 登录/海外控制面 | Microsoft / Google-X-Meta-MS | `login.live.com`, `login.microsoftonline.com`, `odc.officeapps.live.com` |
| 国内 Office/OneDrive 宽面 | MicrosoftCN / DIRECT | `live.com`, `livefilestore.com`, `office.com`, `oneclient.sfx.ms` |
| 数据/同步面 | DownloadCDN / 下载 | `contentsync.onenote.com`, `d.docs.live.net`, `hierarchyapi.onenote.com`, `files.1drv.com` |

这不是“看到文件域就归下载”可以解释的分类。应先把这些端点归入同一 `OneDriveOffice` service_id/canonical owner，禁止未经证明的任意拆分；是否必须使用同一公网出口，再由登录、上传、下载、同步和风控实测决定。只有经实测证明签名 URL 与源 IP/cookie 无关的数据面才允许前置拆出。同 owner 不应机械等于“所有字节同线路”，但任何例外都必须有证据。

MSN 也有同构分裂：`api.msn.com`/`assets.msn.com`/视频域在 Microsoft，而 `msn.com` 宽后缀在 MicrosoftCN。页面、API、素材和地区内容可能看到不同出口；应优先整链统一，若保留 API/素材例外，必须用地区内容一致性场景证明。

官方依据：[Microsoft — Required URLs and ports for OneDrive consumer](https://learn.microsoft.com/en-us/sharepoint/required-urls-and-ports)。

### 10.2 Cursor 不属于 Twitter/X

Twitter 表把 `anysphere.co`、`cursor.com`、`cursor.sh`、`cursorapi.com`、`cursorvm.com`、`cursor-cdn.com` 全部归入 X/Twitter。Cursor 官方服务条款明确其主体是 Anysphere, Inc.，不能由“Grok 某条后端曾使用 Cursor 基建”推导出“Cursor 全生态属于 X”。

建议：

- Cursor/Anysphere 迁入 AI/DevAI 或独立 `DeveloperAI`；
- `grok.com`、`x.ai` 留在 X/xAI；
- 若 Grok 确实依赖某个精确 Cursor host，只登记该 host 为 Grok 依赖，不反向吞并供应商全部资产。

官方依据：[Cursor Terms of Service](https://cursor.com/en-US/terms-of-service)。

### 10.3 TikTok 有两个确定异业域

- `TikTok.list:4` 的 `api.snapkit.com` CNAME/官方文档均指向 Snapchat Snap Kit，不属于 TikTok 所有。TikTok 可能作为调用方使用分享集成，但这不能把所有 Snap Kit 客户都归 TikTok；应归 SharedSocialIntegration/Snapchat，若无实际调用证据再删除。
- `TikTok.list:5` 的 `cocacola.co.jp` 是日本可口可乐公司域；应删除，若需要地区分流则归 Japan。
- `courses.snapsolve.com` 是字节历史教育产品痕迹，当前无命中证据时应进入观察/过期队列，不因历史收购永久保留。

官方依据：[Snap for Developers — Snap Kit](https://developers.snap.com/snap-kit/home)。

### 10.4 `qwenlm.ai` 与 `qwen.ai` 是同一国际入口却被拆分

`Domestic.list:467` 将 `qwenlm.ai` 直连，而 `AI.list` 将 `qwen.ai` 代理。当前 `qwenlm.ai` 会跳转到 `chat.qwen.ai`，因此确定违反“国内厂商国际站统一代理”的所有权原则，并制造首跳出口变化；首跳通常发生在登录前，是否造成实际登录/风控故障仍需场景验证。

应将 `qwenlm.ai` 迁入 AI，并以首跳、登录、API、静态、上传组成完整 Qwen 国际场景。直接证据：[qwenlm.ai](https://qwenlm.ai/)。

### 10.5 Meta 运行域与防御注册库存混在一起

Meta 的 501 个 suffix 中有大量看起来属于品牌错拼、防御注册、旧活动和占位库存的域。即使其中一些仍由 Meta 防御性持有，也不代表产品运行时会访问；当前仓库没有逐条证明其现时所有权和活跃状态。`facebook-login.com`、`facebook-support.org`、`facebookporn.org`、`oculuscasino.net` 等应先核对当前注册、DNS、证书和命中，再决定是否迁入资产库存而不是运行分流表。

建议拆分：

- `MetaOperational.list`：实际 Facebook/Instagram/WhatsApp/Threads/Messenger/Oculus/Meta AI 运行域；
- `inventory/MetaDefensive.txt`：不被 RULE-SET 引用的所有权/防御库存；
- 证书、HTTP 行为、DNS 和生产命中均为空的防御域不进入分流；
- `Meta.list:512` 的 AWS `18.194.0.0/15` 覆盖 131,072 个地址，不是 Meta 专网，应移除；其余云 `/32` 设到期复核。

### 10.6 Streaming 混入大量公司资产域，不能把整表视为播放会话清单

表内含 Amazon 招聘/大学、Disney 招聘/邮轮/商店/会议、CBS Store、Netflix Investor、Fox careers/corporate/shop 等。公司拥有一个域并不意味着它是播放会话依赖。

Streaming 应从实际播放器链正向生成：

```text
StreamingAuth
StreamingCatalogAPI
StreamingPlaybackManifest
StreamingContentCDN
StreamingFirstPartyNetwork
```

招聘、商店、投资者关系、乐园、品牌防御和通用 A/B/归因域默认不收。

### 10.7 业务分类与地区分类发生所有权竞争

当前同一品牌被“业务类型”和“地区”同时分类，没有 canonical owner。下表能确定的是**结构性跨策略**；其中 Chase、Tubi、Booth/Niconico 的页面/明确资产子域属于高置信同链，BBC/Fubo/CBS/Fox/NBC/ESPN 等是否在同一次真实会话同时触发仍需抓包证明：

| 服务 | 地区表 | Streaming/Games/Download 表 | 风险 |
|---|---|---|---|
| BBC | UK：`bbc.com`, `bbcmedia.co.uk` | Streaming：`bbc.co.uk`, `bbci.co.uk`, BBC CDN | 结构性双策略；真实页面/播放是否同时触发需抓包 |
| CBS | US：`cbs.com`, `cbsinteractive.com` | Streaming：`cbsi.com`, `cbsimg.net`, `cbsivideo.com` 等 | 主站与播放资产跨策略，真实产品链需验证 |
| Tubi | US：`tubi.io` | Streaming：`tubi.tv`, `production-public.tubi.io` | 同注册域只有部分子域被前位摘走 |
| Fubo | US：`fubo.tv` | Streaming：`fubotv.com` | 高疑似同服务跨策略，需登录/播放链验证 |
| Fandango | US：`fandango.com` | Streaming：`athome.fandango.com` | 同品牌下可能是不同产品；先观测再决定是否统一 |
| Fox/NBC/ESPN | US 有主站/品牌域 | Streaming 有大量体育/视频域 | 结构性跨策略；不同法人/频道/产品需逐场景建模 |
| Cygames | Japan：`cygames.jp` | Games：部分游戏 API 子域 | 存在未枚举 API 回落 Japan 的结构可能，需实际游戏流量验证 |
| Booth/Niconico | Japan 有主域 | Download 有 `asset.booth.pm`, `cdn.nimg.jp` | 页面与素材/内容分裂 |
| Chase | US：`chase.com` | Download：`asset.chase.com`, `sites.chase.com`, `chasecdn.com` | 银行页面静态链走下载出口 |

目标架构默认必须选定唯一 canonical owner。本文推荐：**服务 owner 决定规则归属，region 是 policy 属性，不再是第二套域名所有权。** 银行、政府等非媒体地区服务可保留地区 owner。只有经完整会话测试证明与身份/风控无关的精确数据面 host，才允许作为有 reason、负例、expiry 的 VerifiedLargeObjectException；禁止未经证明的逐域混用。

两个共享生态边界应单独进入观测：

- YouTube 页面/视频在 Streaming，但 `accounts.google.com` 等共享身份域在 Google。域名引擎无法判断本次 Google 登录由 YouTube、Gmail 还是其他产品触发；解决方法是接受 SharedAuth 独立策略，或让相关策略在登录场景共享同一底层固定出口，不能把 Google IdP 整体搬进 YouTube。
- `music.apple.com`、`tv.apple.com`、`podcasts.apple.com` 在 Streaming，而 `apple.com`、`itunes.com`、`mzstatic.com`、`icloud.com` 在 AppleCN/DIRECT。这是典型的“产品前门与共享生态依赖”边界，应以真实播放、登录、购买和资料库同步场景裁决，不能仅凭域名名称宣布错误。

### 10.8 游戏下载和游戏会话也需分开

GameDownloadCN 的精确国服 CDN 前置是正确模式，但 `steambroadcast.com`、`steamusercontent.com` 和部分全球 Steam content 域同时承载直播/UGC/社区内容，并不等于“国服游戏下载”。Games 中 `sony.com` 又会把 Sony 相机、电子、影视和企业站整体送进游戏策略。

建议：

- GameDownloadCN 只保留下载/补丁/国服发行 host；
- Steam UGC/Broadcast 回 Games 或独立 SteamSession；
- `sony.com` 移除，仅保留 PlayStation/SIE 业务域；
- 云游戏 `/32` 必须有 last-seen 和 expiry。

## 11. Surge 与 Mihomo 兼容性审计

### 11.1 当前可加载，但只证明语法

34 个 Clash list 与转换器当前输出逐字一致；Mihomo 1.19.20 实际加载得到 34 个 classical provider、154,681 条规则。54 条转换后的 DOMAIN-REGEX 当前均可编译。

### 11.2 顺序必须由同一个 manifest 生成

真实 Surge 开头：

```text
SYSTEM → PrivateLAN → PKU → Reject
```

Clash 参考开头：

```text
GEOIP,lan（注释） → Reject → PrivateLAN → PKU
```

当前未发现确定交集不代表可以接受分叉。Reject、PrivateLAN、PKU 必须进入统一 `config/rulesets.yaml` 顺序，Surge/Clash/README/测试均由它生成。

### 11.3 原样透传 `DOMAIN-WILDCARD`

当前 Mihomo 已原生支持 `DOMAIN-WILDCARD`，`*` 为零或多字符、`?` 为单字符。现行 wildcard→regex 对 54 条 ASCII 规则基本等价，但：

- 引入 Python `re.escape` 与 Mihomo 正则方言的未来差异；
- 正则比原生 wildcard 更难审计；
- 转换器只取第二字段，未来 wildcard 行若带修饰符会被丢弃。

应把 `DOMAIN-WILDCARD` 加入 passthrough，转换器先解析所有字段再输出。

### 11.4 `extended-matching` 需要 Mihomo sniffer 合同

Surge 对 YouTube、Google、Twitter、Meta、Microsoft、AI、TikTok、SocialOthers、Telegram、Streaming、Payment 共 11 表启用 `extended-matching`，会额外检查 TLS SNI、HTTP Host 和 `:authority`。

Mihomo provider 本身无法携带这个外层语义。使用者必须明确启用 HTTP/TLS/QUIC sniffing，并验证透明代理、fake-IP、pure IP 与 DNS mapping；否则 hostname 丢失时会落入 IP-ASN/GEOIP/MATCH，YouTube 可能被 Google ASN 接走，Payment/AI 也会偏离。

### 11.5 `no-resolve` 不等于全链 DNS 安全

两端的 `no-resolve` 都只是阻止目标 IP 规则为了匹配而主动解析；若前位已解析，仍可使用已有结果。Mihomo 的实际 DNS 去向还取决于 enhanced-mode、nameserver/fallback、nameserver-policy、direct/proxy nameserver、respect-rules、TUN hijack 和 sniffer。

因此仓库可以承诺：

- “派生规则保留所有 `no-resolve`”；

但不能仅凭 provider 片段承诺：

- “Clash 全链零本地 DNS”。

应发布一个经过验证的完整 Mihomo DNS/sniffer 示例和对应泄漏测试，或把承诺限定为 Surge。

### 11.6 SYSTEM、`dns-failed`、UDP 和数据库无一比一对应

- `GEOIP,lan` 不是 Surge SYSTEM 的完整等价；
- `MATCH,Final` 没有 `FINAL,Final,dns-failed` 的补偿语义；
- Mihomo 在 UDP 节点不支持时可继续匹配后位，Surge 当前是 REJECT；
- 两端 GEOIP/ASN 数据库来源和更新时间不同。

双端测试必须覆盖：DOMAIN、resolved IP、literal IPv4/IPv6、有/无 SNI、有/无 ASN 数据、TCP/UDP/QUIC、DNS 冷/热缓存。

官方依据：[Mihomo Routing Rules](https://wiki.metacubex.one/en/config/rules/)、[Mihomo Rule Providers](https://wiki.metacubex.one/en/config/rule-providers/)、[Mihomo DNS](https://wiki.metacubex.one/en/config/dns/)。

## 12. 测试与审计器需要补的检查

### 12.1 把当前 A1–A7 扩展为可证明的门禁

建议新增：

| 检查 | 算法 | 失败级别 |
|---|---|---|
| A8 严格语法/修饰符 | 类型、arity、域名、IDNA、严格 CIDR、modifier 白名单；未知参数 fail-fast | P1 |
| A9 forbidden/expected-absent | UA/process、D11、ChinaDomain 关键词、已排除域 | P0/P1 |
| A10 CIDR 包含/折叠 | IPv4/IPv6 Patricia trie + exact union collapse | 同策略 P2；跨策略 P0/P1 |
| A11 public suffix/shared hosting | 锁定 PSL；命中 ICANN/PRIVATE 边界必须显式 `shared=true` | P1/P2 |
| A12 wildcard/keyword 覆盖 | anchored automata/regex + 负向生成；禁止开放右侧 | P1 |
| A13 raw-upstream conflict | 在级联去重前输出每个 loser/winner，禁止静默丢掉精确规则 | P1 |
| A14 service owner/session split | 同一 service 的 auth/api/data/static/payment 跨 policy 必须显式批准 | P1 |
| A15 cloud ownership | ASN/RDAP/官方 cloud range；shared cloud 不能标 first-party | P1 |
| A16 Surge/Mihomo differential | 两端对相同语料输出 policy/source 等价矩阵 | P1 |
| A17 generated drift | 所有生成物、文档片段、count、hash 与 manifest 一致 | P1 |

实现复杂度可以保持线性或近线性：

- 精确重复：hash，$O(N)$；
- suffix 包含：反向域标签 trie，$O(\sum labels)$；
- CIDR：Patricia trie，$O(N\cdot 32)$ / $O(N\cdot 128)$；
- keyword 多模式碰撞：Aho–Corasick，$O(total\ characters+matches)$；
- wildcard：只对 54 条模式编译并对候选集验证，不需要全量两两比较；
- 场景 owner：按 `service_id` 分组，$O(N)$。

所有网络集合运算使用整数网段和精确集合，不使用浮点数；IDNA 统一成 A-label 后比较，避免 Unicode/大小写/根点形成重复。

### 12.2 场景 schema 必须严格

每个场景必须满足：

- name 全局唯一；
- requests 非空；
- 每个 request 至少有合法 host/ip；
- assert 至少包含一项有效断言；
- `policy` 与 `policy_in` 互斥；
- `per_request` key 唯一且全部能对上 requests；
- unknown key 失败；
- `same_policy` 不可对空集合通过；
- main 分支 known-broken 必须为 0；
- 每个启用 list 至少有正向和负向边界，地区/GEOIP 需真机或固定测试数据库。

### 12.3 负向测试比继续堆正向域更重要

每个宽规则至少生成四类反例：

```text
<token>-unrelated.example
<official-domain>.attacker.example
tenant.<shared-public-suffix>
literal-IP-without-hostname
```

每个 service 场景至少包括 apex、子域、auth、API、static、upload/data、telemetry、IPv4、IPv6、SNI、QUIC 和邻近不应命中的域。

### 12.4 L4 应分成发布阻断与周期观测

- 每次发布阻断：Surge `--check`、rule match/explain 差分、DNS cache 增量、关键 20–50 场景；
- 每日/每周：完整 L4、ASN/RDAP、CNAME 漂移、真实 checkout、地区媒体和多客户端；
- 只有网络波动的连通性测试不能直接阻断；确定的 policy/source/DNS 差分必须阻断。

## 13. 项目工程链路审计

### 13.1 只有“内容单一源”，没有“拓扑单一源”

`lists/*.list` 作为规则文本源是成立的，但以下事实存在多份手工副本：

- 真实顺序、策略、启停、modifiers：仓库外 `Surge.conf`；
- Clash 顺序：`tools/surge2clash.py` 的 `CONF_ORDER` + Reject 特殊分支；
- 当前规则表：README；
- 架构顺序：ARCHITECTURE；
- 期望策略：scenarios；
- winner/loser：allowlist；
- 业务裁决：MAINTENANCE。

直接结果是当前文档仍写：

- 32 张表，实际 34；
- 90 场景/931 或 930 断言/351 DNS，实际 103/1,044/333；
- 65 个发布文件，实际 69；
- A1–A6，实际 A1–A7；
- Reject 注释停用，实际已启用；
- 规则序漏掉 ModelDownloadCDN 和 Payment；
- Mihomo 守恒 138,185，实际 154,681。

CHANGELOG 中的历史数字不应回改；README/ARCHITECTURE/tests README 的“当前状态”必须由 manifest 自动生成。

### 13.2 “机器管理层”不能由当前仓库重建

ChinaDomain、ChinaIP、厂商表和 GFW 表的上游同步没有完整供应链。除 ChinaIP 的单个 commit 外，缺少逐表 source URL、revision、原始 SHA-256、license、转换器、排除/移动表和重建命令。

更危险的是，D11 和“17 个排除域”存在于自然语言文档；宽关键词覆盖精确条目后，级联去重会把 loser 从最终表删除，使当前 A4 再也看不到上游冲突。`eqoavtbu.com`、`ttcdn-tos.kkimg.cc` 就是例子。

正式构建不能依赖可变的 `reference/` 浅克隆。reference 适合作人工资料库，不适合作供应链输入。

### 13.3 Clash 生成器不是事务式

`surge2clash.py` 先删陈旧文件，再逐文件覆盖正式 `clash/`；如果后部文件出现未知类型，中途退出会留下“前半新、后半旧”的混合工作树。

应改成：

1. 全部输入先解析和校验；
2. 临时目录完整生成；
3. Mihomo 实载/计数/差分；
4. 成功后原子替换；
5. 提供 `--check`，CI 只比较而不修改正式目录。

### 13.4 没有仓库 CI，发布只依赖本机私有配置

仓库没有 GitHub Actions、公共脱敏测试 profile、schema lint、生成漂移检查或 source lock 检查。`engine.py` 还包含本机绝对路径 fallback，新的 clone 无法独立复现真实 audit/runsuite。

`docs/MAINTENANCE.md` 声称 audit/runsuite 可用 `--rules`，但 runsuite 实际没有该参数。应生成 `tests/fixtures/Surge.test.conf`，把逻辑 policy 和顺序公开，节点/证书/出口映射继续留在仓库外。

### 13.5 发布脚本还有四个次级缺口

- 删除/重命名的 list 因本地文件不存在被直接跳过，不 purge 旧 CDN 路径；
- modules/scripts 已设计为 CDN 资源，却不在发布候选集合；
- `git add -A` 会把所有未忽略文件一起提交；`live_check.py` 默认把报告写到 `$PWD/live_report.md`，而 `.gitignore` 没同时覆盖仓库根和 `tests/` 两种运行位置；
- 没有远端 CI、不可变 release tag、分发 SHA 清单和真实回滚演练。

### 13.6 回滚文档引用了不存在的备份点

MAINTENANCE 记载的两个 pre-merge/pre-audit 备份目录当前不存在；Git 只有 `pre-restructure-20260829` 一个旧标签，落后当前 HEAD 多个提交。回滚不应只 checkout `lists/`，因为 topology、converter、tests 和 docs 也可能随版本变化。

每次成功发布应创建不可变 `rules-YYYYMMDD.N` tag，并附：

- commit SHA；
- source lock 摘要；
- 规则数/类型数；
- 全部分发文件 SHA-256；
- 场景/断言结果；
- Surge/Mihomo 版本与差分摘要。

### 13.7 来源与许可证信息不完整

根目录没有 LICENSE/SOURCES 清单。项目公开再分发多个上游的重组规则，应为自有脚本/文档声明许可，并记录每个上游 URL、license、revision、使用范围和变换方式。

## 14. 推荐目标架构

### 14.1 两类事实源，而不是五份手写顺序

第一阶段保留 `lists/` 为内容源，同时新增 topology manifest；供应链完成后，`lists/` 也应变为确定生成物。

```text
sources/sources.lock.json       # 上游 revision/path/hash/license
overrides/
  include.yaml                  # 人工精确补充 + reason/owner/expiry
  exclude.yaml                  # forbidden/expected-absent
  moves.yaml                    # 从上游类别迁移到 canonical service owner
config/rulesets.yaml            # 顺序、策略、启停、modifiers、平台能力
config/services.yaml            # service → auth/api/data/static/shared/region
            │
            ▼
tools/build_rules.py            # 严格解析、规范化、冲突报告、生成
            │
            ├── lists/*.list
            ├── clash/*.list
            ├── clash/rule-providers.yaml
            ├── tests/fixtures/Surge.test.conf
            ├── docs/generated/*.md
            └── dist/manifest.json + SHA256SUMS
```

### 14.2 `rulesets.yaml` 最小 schema

```yaml
schema_version: 1
rulesets:
  - id: private_lan
    file: PrivateLAN.list
    order: 10
    enabled: true
    logical_policy: DIRECT
    surge_modifiers: []
    mihomo_requirements: []
    role: system_exception

  - id: ai
    file: AI.list
    order: 100
    enabled: true
    logical_policy: AI
    surge_modifiers: [extended-matching]
    mihomo_requirements: [sniffer_http, sniffer_tls, sniffer_quic]
    role: service_owner
```

私有策略组名可以在本机 overlay 映射；公共 manifest 只保存逻辑 policy。这一个文件生成 Surge 测试顺序、Clash 参考、文档表、provider 数量和发布清单。

### 14.3 `services.yaml` 解决会话拆分

```yaml
services:
  onedrive_office:
    owner: microsoft_session
    expected_policy: MICROSOFT
    region: global
    endpoints:
      auth:
        - DOMAIN,login.live.com
        - DOMAIN,login.microsoftonline.com
      api:
        - DOMAIN,odc.officeapps.live.com
        - DOMAIN,contentsync.onenote.com
        - DOMAIN,hierarchyapi.onenote.com
      data:
        - DOMAIN,d.docs.live.net
        - DOMAIN-SUFFIX,files.1drv.com

  cloudflare_turnstile:
    owner: shared_challenge
    shared: true
    expected_policy: FINAL
    endpoints:
      challenge:
        - DOMAIN-SUFFIX,challenges.cloudflare.com
```

构建时强制：

- 一个 service 只有一个 canonical owner；
- auth/api/payment/data 跨 policy 必须显式 exception；
- `shared=true` 的域禁止迁入单一业务 owner；
- 同一 registrable domain 的子域跨 policy 必须有 reason、负例和 expiry；
- 公共后缀规则必须声明 `platform_scope=true`，不能伪装成 service scope。

### 14.4 `sources.lock.json` 最小 schema

```json
{
  "schema_version": 1,
  "sources": [
    {
      "id": "blackmatrix7_china_ip",
      "repository": "https://github.com/blackmatrix7/ios_rule_script",
      "revision": "<full commit sha>",
      "path": "rule/Surge/ChinaIPs/ChinaIPs.list",
      "sha256": "<raw file hash>",
      "license": "<SPDX or reviewed text>",
      "targets": ["ChinaIP.list"],
      "transformer": "surge_rules_v1"
    }
  ]
}
```

同步流程必须按 revision 下载并校验原始 hash，不允许“pull 最新后直接覆盖”。

### 14.5 目标规则序

建议将“安全/身份/流量/地区”分层，且只允许窄例外越级：

| 层 | 内容 | 不变量 |
|---|---|---|
| 0 | SYSTEM / PrivateLAN / PKU | 内网与系统先于拦截和代理 |
| 1 | RejectExact | 无宽品牌关键词；每条有正/负例 |
| 2 | Verified narrow exceptions | GameDownloadCN、ModelDownload、已验证大文件；只允许精确 host/小后缀 |
| 3 | Identity/service owners | YouTube、Google、X/xAI、Meta、Microsoft、AI、社交、Telegram、Streaming、Games |
| 4 | Payment | 固定出口；在 generic download/shared hosting 之前 |
| 5 | Shared infrastructure | Auth/Challenge/Telemetry/Hosting/ObjectStorage；独立统计，默认 Final |
| 6 | GenericDownload | 收缩后的包/镜像/发行端点 |
| 7 | AppleCN/MicrosoftCN + DirectExceptionsPreGFW | 精确国内/CA/系统例外 |
| 8 | ProxyGFW | 宽代理兜底，不再吞掉可表达的精确例外 |
| 9 | Region-owned non-media services | 银行、政府、仅地区可用服务；媒体已归 service owner |
| 10 | Domestic manual/ecosystem/ChinaDomain | 手工层→厂商层→机器长尾；关键词为 0 |
| 11 | ChinaIP/LAN/GEOIP/FINAL | 全 IP no-resolve；未知域由 Final 处理 |

## 15. 数据驱动迭代闭环

### 15.1 观测字段

生产观测至少记录：

```text
timestamp
hostname / SNI
matched ruleset + sub-rule
logical service_id
policy group
physical exit class（脱敏）
destination IP / ASN / country
protocol (TCP/UDP/QUIC)
DNS path / local-cache delta
success / timeout / TLS / HTTP status class
process（仅诊断标签，不重新引入 PROCESS-NAME 分流）
```

不采集 URL path、cookie、token 或正文。公开报告只保留聚合和脱敏出口类别。

### 15.2 两类核心报告

1. `session_split`：同一 service 在 5–15 分钟窗口内，auth/api/data/payment 使用多个出口；
2. `orphan_or_overcapture`：30/60/90 天零命中规则、共享后缀的非目标租户命中、ASN/RDAP 归属变化。

还应记录 `FINAL` 热点。高频 FINAL 不自动等于漏规则：先判断它是未知通用站、共享平台还是确实缺少的服务端点。

### 15.3 规则生命周期

| 规则来源 | 复核周期 | 默认处理 |
|---|---|---|
| 第一方稳定注册域 | 90–180 天 | 所有权/DNS/证书变化时复核 |
| 共享 SaaS/公共后缀 | 每次变更 | 默认 Shared/Final，业务表需强证据 |
| 第一方 ASN/网段 | 30–90 天 | RPKI/RDAP/官方清单核对 |
| 公有云 `/32`/短期 CNAME | 7–30 天 | 自动到期；有持续命中才续期 |
| Reject 恶意域 | 7–30 天 | 来源、证据、失效/重新注册检查 |
| 关键词/通配符 | 7–14 天 | 必须有正负例和命中样本 |

## 16. 量化目标与验收指标

下面是建议 SLO，不是对当前数据的伪精确估计：

| 指标 | 目标 |
|---|---|
| 代理目标本地 DNS 泄漏 | 0 |
| false REJECT（已知语料） | 0 |
| 关键 service auth/api/payment/data 跨出口 | 0 |
| Surge/Mihomo 支持语义差分 | 0；不可等价项必须明确列出 |
| P0/P1 未豁免 finding | 0 |
| forbidden/expected-absent 命中 | 0 |
| 上游 provenance 覆盖 | 100% |
| 生成物可重复 | clean checkout 全量重建后 git diff=0 |
| `DOMAIN-KEYWORD` | Reject/Payment/DIRECT=0；全库 104→≤10，最终以观测决定是否清零 |
| ChinaIP | 22,417→约 11,090，地址集合 hash 不变 |
| 每张启用表场景覆盖 | 至少 1 正向 + 1 负向；关键表覆盖完整 service roles |
| main known-broken | 0 |
| 发布结果 | 远端 SHA、HTTP 状态、SHA-256 全部可验证；否则非零退出 |
| 性能回归 | 相同机器/冷暖缓存下 p50/p95 不劣化 >10%，并记录内存变化 |

不要用“规则行命中率”单独衡量大长尾表；应以流量加权覆盖、误捕获率、会话完整性和可证明来源为主。

## 17. 分阶段实施路线

### Phase 0：先修控制面，不改变分流行为

1. 修复 update 假成功、分支/远端 SHA、删除项、modules/scripts、SHA-256；
2. 逐条拆分 `preventive`：合法分层迁 expected-overlap，禁止回流迁 forbidden/expected-absent；
3. 给 A7 增加非法裸行正向 fixture，再把 engine/audit selftest、schema lint、生成 `--check` 加入闸门；
4. 新增公共脱敏测试 profile 和 GitHub Actions；
5. 建 `config/rulesets.yaml`，由它生成当前顺序和文档数字；
6. 修正 README/ARCHITECTURE/tests README 当前事实；历史 CHANGELOG 不改。

验收：任意网络失败/限流/远端不一致均非零退出；clean clone 可离线跑完整 L0–L2；文档生成无漂移。

### Phase 1：先加负例，再修确定错误

按“测试先于行为变更”的顺序：

1. 加 `eqoavtbu.com`、`ttcdn-tos.kkimg.cc`、qingmail/suningmail、PayPal 仿冒、共享租户负例；
2. Cursor→AI/DevAI；SnapKit 移出 TikTok；Coca-Cola 移 Japan/删除；`qwenlm.ai`→AI；
3. OneDrive/OneNote 数据面移出 Download，统一 OneDriveOffice；
4. `sony.com` 移出 Games；Meta AWS `/15` 移出；Games GCP `/12` 移出；
5. 清理 P0/P1 关键词，并恢复被宽关键词消掉的精确规则；
6. 修正 Clash Private/PKU/Reject 顺序和 wildcard passthrough。

验收：新增正/负语料双端差分为 0；关键服务完整场景同出口；无新的 known-broken。

### Phase 2：重建三张最高风险表

顺序：

1. DownloadCDN：从精确大文件 allowlist 重建；
2. Streaming：从播放会话重建，移除 AWS 共享云段与公司资产库存；
3. Meta：Operational 与 Defensive inventory 分离。

所有大范围删除先做 7–14 天 shadow：候选规则只记录“若删除会落哪里”，不直接改策略。对实际命中逐条补 service owner 后再切换。

验收：Download 公共后缀边界只剩显式批准项；Streaming 只保留第一方 ASN/IP；生产 session_split 不上升；性能基准不退化。

### Phase 3：上游供应链与机器层重建

1. `sources.lock.json` 从 ChinaDomain/ChinaIP/ProxyGFW 开始；
2. 把自然语言 exclude/move 迁入机器清单；
3. 在去重前生成完整冲突报告；
4. ChinaIP 自动 collapse；
5. 逐步覆盖厂商表和剩余聚合表；
6. 增加 LICENSE/SOURCES。

验收：固定 revision 能逐字节重建全部分发文件；任何上游变更都有结构化 diff、冲突、规则数和场景影响报告。

### Phase 4：长期观测、版本化与回滚演练

1. `stable`/`next` 双轨或不可变 release tag；
2. 规则 hit、FINAL hotspot、session_split、RDAP/ASN/CNAME 漂移日报；
3. 30/60/90 天零命中清理；
4. 每次 Surge/Mihomo 大版本重跑官方语义与双端矩阵；
5. 每季度真实回滚演练。

## 18. 优先级 backlog

| ID | 优先级 | 动作 | 风险控制/验证 |
|---|---|---|---|
| C-01 | P0 | update 三态、非零失败、分支/SHA 守卫 | 模拟断网、429、非 JSON、hash mismatch、feature branch |
| C-02 | P0 | preventive 逐条迁 expected-overlap / forbidden / expected-absent | 合法 AWS 分层继续通过；植入 USER-AGENT/D11 必须阻断 |
| C-03 | P1 | rulesets manifest + 公共 fixture + CI | clean clone 全绿，文档/Clash 顺序自动生成 |
| R-01 | P1 | DownloadCDN 多租户/非下载清理 | PSL gate + shadow + FiveM/OneDrive/银行负例 |
| R-02 | P1 | AS396982、Games GCP `/12`、Meta AWS `/15`、Streaming AWS 段处理 | literal IP/SNI/ASN on/off 双端矩阵 |
| R-03 | P1 | 104 keywords 分批收窄 | 精确资产恢复 + 邻域负例 + 7–14 天观察 |
| R-04 | P1 | OneDriveOffice canonical owner | 官方 endpoint 全链 + 上传/同步/下载/登录实测 |
| R-05 | P1 | Cursor/SnapKit/Coca-Cola/Qwen/Sony 归属修复 | 一手来源 + 主站/API/静态会话场景 |
| R-06 | P1 | Shared* 中性层 | AI/非 AI 同用 Turnstile/Sentry/Intercom A/B |
| R-07 | P2 | 补支付租户精确 host，再将 Payment 前置于 generic download | 真实 3DS/checkout/支付下载签名验证 |
| X-01 | P1 | Clash 顺序、sniffer/DNS 合同、wildcard passthrough | Mihomo 实载 + Surge/Mihomo differential |
| A-01 | P1 | A8–A17 审计扩展 | 合成 fixture 覆盖每种缺陷 |
| D-01 | P2 | ChinaIP collapse | 地址集合 SHA/成员抽样/双端 ruleCount |
| S-01 | P1 | source lock + build pipeline | 固定 revision 重建无 diff |
| O-01 | P2 | 观测与过期 | 公开聚合不含隐私，零命中可回溯删除 |
| DOC-01 | P2 | 当前状态文档自动生成 | CI 禁止生成片段漂移 |
| REL-01 | P2 | immutable tag/checksum/回滚 | 一次完整发布和一次回滚演练 |

## 19. 核心项目测试与真机检查命令

以下命令不修改现行 Surge 配置；但 Python 可能写字节码，转换器会重写/删除 `clash/` 派生文件，L4 会发送真实请求并改变短期 DNS/request 运行态。严格复核时应设置 `PYTHONDONTWRITEBYTECODE=1`，在临时目录运行转换并做 comparator；涉及真机的命令需 Surge 正在运行：

```bash
python3 tests/audit.py --check all --fail-on P1
python3 tests/audit.py --selftest
python3 tests/engine.py --selftest
python3 tests/runsuite.py
python3 tests/realworld.py --offline --redact
python3 tests/realworld.py --full --redact --report /tmp/surge-realworld.md
python3 tools/surge2clash.py

/Applications/Surge.app/Contents/Applications/surge-cli --check ../Surge.conf
/Applications/Surge.app/Contents/Applications/surge-cli external-resource list
/Applications/Surge.app/Contents/Applications/surge-cli dump performance
/Applications/Surge.app/Contents/Applications/surge-cli dump rule-usage
/Applications/Surge.app/Contents/Applications/surge-cli benchmark rule-matching
/Applications/Surge.app/Contents/Applications/surge-cli dump temp-rule

mihomo -v
# 本次另以临时最小配置实际加载全部 34 个本地 classical provider，
# 并从 controller API 汇总得到 ruleCount=154681。
```

注意：直接运行 `python3 tools/surge2clash.py` 会重写派生目录；本次重写后 `git diff` 为 0，证明当前派生干净。未来应改用无写入的 `--check`。

这些命令只能复现项目内置测试和主要真机检查，**尚不能独立复现本文全部一次性分析数字**，例如 PSL 462/327、AWS CIDR 交集、ChinaIP collapse、0.21% 子规则覆盖和 raw-upstream 关键词碰撞。本轮使用的分析脚本与外部数据快照尚未入库；Phase 2 应将 A8–A17、PSL/AWS snapshot revision/hash、Mihomo 临时加载配置和结构化结果正式纳入仓库，届时这些数字才能从 clean clone 一键重建。

## 20. 官方语义与外部证据

访问日期均为 2026-08-31：

### Surge

- [Rules Overview / 首次命中与参数行为](https://manual.nssurge.com/rules/overview.html)
- [Domain Rules / DOMAIN、SUFFIX、KEYWORD、extended-matching](https://manual.nssurge.com/rules/domain.html)
- [IP Rules / no-resolve、IPv4/IPv6、首个地址语义](https://manual.nssurge.com/rules/ip.html)
- [Rule Sets](https://manual.nssurge.com/rules/ruleset.html)
- [FINAL / dns-failed](https://manual.nssurge.com/rules/final.html)
- [REJECT / pre-matching](https://manual.nssurge.com/policies/reject.html)
- [DNS Overview](https://manual.nssurge.com/dns/overview.html)
- [General / IPv6、VIF、hijack-dns、block-quic](https://manual.nssurge.com/profile/general.html)
- [Surge CLI](https://manual.nssurge.com/tools/cli.html)

### Mihomo

- [Routing Rules / 顺序、wildcard、no-resolve、UDP 行为](https://wiki.metacubex.one/en/config/rules/)
- [Rule Providers](https://wiki.metacubex.one/en/config/rule-providers/)
- [Provider Content / classical](https://wiki.metacubex.one/en/config/rule-providers/content/)
- [DNS Configuration](https://wiki.metacubex.one/en/config/dns/)

### 共享平台、ASN 与业务归属

- [Public Suffix List](https://publicsuffix.org/list/)
- [Google Cloud 公开通告前缀与 AS396982](https://docs.cloud.google.com/vpc/docs/create-pap)
- [Google Compute Engine FAQ / Cloud IP ranges](https://docs.cloud.google.com/compute/docs/faq)
- [AWS IP address ranges](https://docs.aws.amazon.com/vpc/latest/userguide/aws-ip-ranges.html)
- [Cursor Terms of Service / Anysphere](https://cursor.com/en-US/terms-of-service)
- [Snap for Developers / Snap Kit](https://developers.snap.com/snap-kit/home)
- [Microsoft OneDrive required endpoints](https://learn.microsoft.com/en-us/sharepoint/required-urls-and-ports)
- [Cloudflare Web Analytics data collection](https://developers.cloudflare.com/web-analytics/data-metrics/data-origin-and-collection/)
- [Statsig platform overview](https://docs.statsig.com/welcome)
- [Intercom](https://www.intercom.com/)

## 21. 最终判断

项目目前最强的部分是格式纪律、`no-resolve` 约束、Surge 真机验证、Clash 派生可加载和核心服务场景。最弱的部分不是“缺更多域”，而是四个抽象错误：

1. 把云平台/公共后缀当成业务所有者；
2. 把公司拥有的域名库存当成运行时服务依赖；
3. 同时用业务类别和地区争夺同一会话所有权；
4. 用 allowlist 和绿色回归掩盖无法重建的上游与未覆盖的负向边界。

下一轮应以“减少不确定匹配面”为主，而不是以“规则条数增长”为目标。优先完成控制面 P0、Download/共享云/关键词止血和 service owner 建模，再做上游自动同步。这样得到的规则会更少、解释性更强、双端更一致，也更容易用真实数据证明它确实更精准。
