# 更新记录

本文件遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 风格,倒序排列。

---

## [2026-08-31·三轮] V2 审计整改:24 项确定级修复 + A9/A10 门禁上线 + 供应链锁层开工

依据 `docs/RULES_AUDIT_V2_2026-08-31.md`,分 R0(保险丝)/ R1(确定级)/ R2(门禁)/ R3(供应链)三波并行执行。**守恒基线 143,640 → 142,708 条(净 −932)**,表数 34 不变。删除面集中在多租户注册边界、S3 兼容对象存储族、死条目与信任面缺陷;迁移面在总数上互相抵消。实测得到的口径更正统一登记在审计文档的「执行勘误」节(E-1 … E-8),正文数字以该节为准。

仍未处理(需 shadow / 真实流量):Streaming 的 AWS IP 段、OneDrive 数据面归属、`azureedge.net` 共享 CDN 逐条判定、`TencentCN:in.th` 泰国注册边界 —— 四项已作为「待裁决豁免」在每次 audit 运行时提示。

### Fixed
- **OneDrive 投毒止血**:`Microsoft.list` 补 `DOMAIN-SUFFIX,onedrive.live.com` —— 这是对 `MicrosoftCN` 宽后缀 `live.com` 的**刻意窄豁免**(CN 侧解析投毒导致个人版 OneDrive 直连不可用)。`office.live.com` / `view.officeapps.live.com` / `g.live.com` 仍 DIRECT,以负例断言锁死;**禁止扩宽为 `live.com`,禁止删除**。
- **信任面清理**:`GameDownloadCN` 删 `steambroadcast.com`(2026-04-27 注册 / Registrar.eu / Cloudflare NS,真 Valve 域一律 MarkMonitor,301 跳 faceit.com —— 留在 DIRECT 白名单区等于给易主域一条绕过 Reject 的通道)与停放页死规则 `steamcontent.net`;`Twitter` 删已被第三方注册/停放的 `twimg.org` / `twimg.co` / `tellapart.com` / `twitteroauth.com`;**`PKU.list` 的 5 条非校园域清零**(`bdwm.net` 等改由常规链路判定)。
- **幽灵规则 11 条**:`ChinaMedia` 的 `domesticmedia` / `domesticmediagame` / `domesticmediapay` 三族 —— 上游从未存在过对应实体,双侧 NXDOMAIN。已入 forbidden **全局作用域**防再生带回。
- **死条目 / 死段清理**:`TencentCN` 删 14 条腾讯云海外 IP 段(承接方均为 `ChinaIP`,代表 IP 逐个复算落点不变),表头「海外段以 IP-CIDR 登记」这句**虚假保障**同步改写为「纯域名表,不设 IP 区」;`Google` 删 `IP-ASN,19527` / `43515` 与 10 条死条目;`Domestic` 删 `googleapis.cn`(双侧均无 A 记录)与 2 条被 ChinaIP 覆盖的 `/32`;`Japan` 删 `paravi.jp`(并入 U-NEXT,承接域已在同表);`Reject` A 组实删 38 条(原判 41 条,其中 3 条 HTTPDNS 删后落 DIRECT 不落 FINAL,按「承载集同构」保留,见勘误 E-2)。
- **`tools/surge2clash.py` 行尾注释透传**:`convert_file()` 只跳过行首 `#`,`IP-CIDR,…,no-resolve  # last_verified=…` 会被原样带进派生文件,Mihomo 把注释当规则参数解析 —— 轻则该条失效,重则整个 provider 加载失败。新增 `strip_trailing_comment()`,剥离逻辑与 `tests/engine.py:strip_comment()` **逐字符对齐**(同为 `s.find(" #")`);刻意不放宽到制表符或裸 `#`,否则 `clash/` 与 Surge 会对同一行给出不同规则,比原 bug 更难查。
- **`update.sh` 先验 404 误报**:首次发布(远端尚无该文件)的先验探测被当成网络失败,导致本应 `PUBLISHED_AND_VERIFIED` 的路径退出 1。桩测覆盖 11 个状态路径,修后仅目标路径由 exit 1 → exit 0,其余状态一条未变。
- **公开文档残留**:`docs/MAINTENANCE.md` 与 `tests/live_check.py` 各 1 处未脱敏残留已打码,脱敏扫描真命中归零。

### Changed
- **Meta 防御性域名分档(520 → 92)**:域名区按 X(易主/停放)/ N(无效)/ D(防御性注册)三档处置 —— X 3 条 + N 14 条删除,**D 档 411 条迁出存档**至 `reference/`(gitignore,不入库不分发)。IP 区 41 → 15 条:删 27 条非 Meta 段(含误收的 GCP `108.177.8.0/21` 与 LINE 3 段),`129.134.0.0/17` 与 `157.240.0.0/17` 各合并为 `/16`,补 `57.144.0.0/14`。合并依据改引 ARIN 整段 NetName `THEFA-3`(原引的 AS32934 通告实测为 0 条,见勘误 E-5)。D 档挑 3 条最典型的入 forbidden 做**绊线**,上游整表回灌时立刻报警。
- **S3 与多租户对象存储族(共 289 + 3 条)**:删 280 条 `s3[.-]*.amazonaws.com` 区域端点后缀(区域端点与已禁收的 `<bucket>.s3.amazonaws.com` 是同一 bucket 的两种寻址形式,PSL PRIVATE 段全部收录 = 官方认定为注册边界)+ 9 条同构的 Scaleway / SAKURA 端点。**审计原文的「321 条」是纯前缀 grep 的计数方法学错误**,差额 41 条中 32 条是第一方 `s3.<brand>` host(Figma / Brave / Producthunt / Envato…),删掉属过度删除 —— forbidden 签名一律锚定厂商域,**不得写成 `s3*`**(见勘误 E-1)。收尾波补删 3 条同构的 `DOMAIN-WILDCARD`(`s3.*.backblazeb2.com` / `*.s3.*.backblazeb2.com` / `s3.*.wasabisys.com`),闭合此前只兑现 6/10 的家族缺口;`f00X.backblazeb2.com` 与 `s3.brave.com` / `s3-*.figma.com` 等单租户第一方端点刻意保留。
- **`ModelDownloadCDN` 整表重写(4 → 5 条)**:2026-08-31 `curl -sI` 复核,HF 已整体切 Xet 后端,模型 / LFS / 数据集三条 resolve 路径的 302 Location 统一落 `us.aws.cdn.hf.co`,而**旧表无任何条目覆盖它**,大文件被 `AI.list` 的 `hf.co` 接走、占用 AI 组家宽中转;`cdn-lfs.huggingface.co` 已死。补 `aws.cdn.hf.co` + `cdn-lfs.hf.co` 后权重下载回到区 3「下载」组,站点浏览与 API 仍归 AI.list。
- **`DownloadCDN` 二次收窄(5,559 → 5,177 条)**:除 S3 族外,删 40 条多租户 / PSL 边界后缀(`vercel.dev` / `r2.dev` / `file.core.windows.net` / `bitbucket.io` / `linodeobjects.com` / IPFS 公共网关等)、19 条通用 SaaS 组件(Freshdesk 8 / Split.io 6 / **SAP CIAM 身份组件 Gigya 3** / Segment 1 / Braze EU 1 —— Gigya 尤其危险,把身份认证绑到下载出口意味着任意使用 SAP CIAM 的站点登录都走「下载」组)、23 条站点静态子域(归还各地区表,**地区表零新增行**)、以及 3 条与「大流量批量下载」定位直接冲突的认证 / 同意管理 / 资产面(`secure.telegraph.co.uk` 等)。Intercom 四个注册域此前劈成两表两出口,统一归 AI。
- **BBC 播放面按「该 host 是否 BBC 专属」重划**:判据从「注册域是否多租户」改掉 —— 多租户的是注册域不是主机名,把 BBC 独占的主机名留在没有英国出口的策略组里,iPlayer 属地锁照样过不去。9 条 `*-uk-live.akamaized.net` + `bbc.mp-pxcdn.com` 迁 `UK.list` 取回英国出口;`*-ww-live` 与多租户承载的 `bbcfmt.s.llnwi.net` 留 `Streaming`。
- **Google `-cn` 族按可达性矩阵处置(−20 / Domestic +18)**:18 条迁 `Domestic` 直连(证书层证实与 `.cn` 镜像族同基础设施),`googleadservices-cn.com`(www 侧 CN 权威置空)与 `qiao-cn.com`(双侧 NODATA)删除,`gstatic-cn.com` 留观察项。
- **ThreatMetrix 入 `Payment`**:只收 `DOMAIN-SUFFIX,online-metrix.net` 这一个注册域(`.com` 与其他 TLD 归属未验证,刻意不收)。设备指纹上报必须与收单授权同出口,否则 3DS 挑战率与拒付率上升;新场景 `payment_chain.json` 用 `same_policy` 把该不变量固化。
- **Datadog 遥测面归 AI**:补 `DOMAIN-WILDCARD,browser-intake-*-datadoghq.com` 与 `DOMAIN-SUFFIX,browser-intake-datadoghq.eu`,收回 us3 / ap1 / eu 三个此前落 Final 的现网端点;通配前缀锚定,`browser-intake-evil.example.com` 不误伤。
- **Steam 国服 CDN**:删整族双侧 NXDOMAIN 的 `dl.steam.ksyna.com`,`dl.steam.clngaa.com` 放宽为父后缀 `steam.clngaa.com`,收回对 ChinaDomain 兜底的依赖。
- 其它归属:`YouTube` 补 `yt3/yt4.googleusercontent.com` 与 `jnn-pa.googleapis.com`,接收 `IP-ASN,36040`;`US` 删 `espnplus.com` / `tubi.io`,`Streaming` 的 `tubi.tv` 由 `DOMAIN` 升 `DOMAIN-SUFFIX`(修同一注册域上 DOMAIN 与 SUFFIX 混用的结构缺陷);`AppleCN` 删 `DOMAIN-KEYWORD,smp-device`(该表已无 DOMAIN-KEYWORD);国内厂商国际站 `01.ai` / `siliconflow.com` 迁 AI,对应 `.cn` 保持直连;`Domestic` 补 3 条 CA 域、`MicrosoftCN` 补 `msocsp.com`。

### Added
- **audit A9 · IP 跨表包含 / 遮蔽审计**:按 conf 真实序建前缀模型,报「后位 CIDR 被前位完全包含」与「跨策略部分交叠」;同策略 P3 不阻断,**跨策略 P1**。基线实测 **145 条(144 同策略 + 1 跨策略)**,整体登记 exemption,门禁只对**新增**跨策略交叠报警。审计原文的「154 + 28」是把「完全包含」与「部分交叠」分两次计数,与实装的顺序感知口径不同 —— 已重标,见勘误 E-8。
- **audit A10 · 单标签后缀与 PSL 注册边界**:用**入库的锁定快照**(`tests/data/public_suffix_list.dat` + `tlds-alpha-by-domain.txt`,逐字节固定 sha256)判「这条后缀是不是别人的注册边界」,ICANN 与 PRIVATE 两段均参与,`*.parent` 通配与 `!exception` 按标准算法处理,IDN 两侧做 IDNA 归一。**门禁不联网**:判据必须可复现可 review,快照更新是一次有意的提交而不是运行时下载。基线 143 条全部预登记,**首次上线 0 误报 0 漏报**;唯一真信号 `TencentCN:in.th`(认领了整个泰国 `in.th` 二级注册边界)列为待裁决。两份快照已登记进 `SOURCES.md`。
- **A8 加作用域**:forbidden 条目支持 `file` / `not_file`,可表达「这条模式在 A 表禁收、在 B 表是承接机制」。forbidden **130 → 244 条**,exemptions **30 → 54 条**(撤销 1 / 收窄 1 / 标记 3 / 新增 25)。audit 自检 **33 → 51 条**。
- **供应链锁层开工**:`sources.lock.json` + `tools/fetch_locked.py` + `tools/rebuild.py`。**ChinaIP 已做实** —— pinned 到 `blackmatrix7/ios_rule_script@65e8adf`,折叠后与本地文件地址集合逐位相同(`rebuild.py` diff = 0),本地镜像与公网两条取源路径 sha256 一致;其余表按 provenance 如实标为 `observed`(未锁)。`tools/regen_chinadomain.py`:ChinaDomain 再生管线过滤器(六级流水线 + P1–P10 护栏,内置 17 删域 / 9 品牌关键词 / D11 排除项 / 21 条承载集豁免),**低频有人值守操作,刻意不进 `update.sh`**。
- **场景基线 147 → 189 场景 / 1,233 请求 / 2,269 断言 / 915 条 DNS 泄漏断言**,失败 0、已知待修 0。新增 6 个场景文件:`fix_download_v2` / `fix_domestic_v2` / `fix_ecosystem_v2` / `fix_regions_v2`(四波修复的正负例)、`ipv6_parity`(IPv4/IPv6 双栈落点一致性,每条带 `no_dns_leak`)、`payment_chain`(支付全链同出口)。`runsuite.py` 新增 `--rules` 参数,配公共脱敏 conf 使用。
- `clash/rule-providers.yaml` 补 sniffer 合同说明(Surge 的 `extended-matching` 在 Clash 侧**无 provider 等价物**,使用者必须自行开 `sniffer`,不配不报错、只静默漏匹配)。
- `MAINTENANCE §8` 裁决登记 **+49 条**;`§6` 红线 **7 → 9 条**。`.gitignore` 补 `build/`(`fetch_locked.py` 的默认输出目录,不排除会被 `update.sh` 的 `git add -A` 收进仓库)。

> **发布前注意**:本轮守恒基线 142,708 取自 `surge2clash --check` 的转换器计数,**未做 mihomo 实载复验**(上一版 143,640 是 controller API 的 `ruleCount` 实测值)。实载复验留待下次发布前补做,补做后若不等以实载值为准。

---

## [2026-08-31·二轮] 审计整改完成:关键词全量迁移(104→8) + DownloadCDN 止血 + ChinaIP 折叠减半 + 测试链加固

同日第二轮,承接首轮(见下节)未尽的「无需真实流量验证即可安全完成」项;9 个并行子任务执行,advisor 统一裁决收口。仍未处理(需 shadow/实测):Streaming 的 1,089 条 AWS IP 段、Meta 防御域拆分、OneDrive 数据面归属、TencentCN 海外段、地区表 canonical owner。

### Changed
- **关键词全量迁移(84→8,含首轮共 104→8)**:六个生态表/四个直连侧表/两媒体表/Games 的 47 条宽品牌与结构关键词,全部按「上游对撞恢复精确资产 → 删除/锚定 → 正负断言」迁移——恢复精确后缀约 400 条(YouTube 167、Google 76、Spotify 21、bilibili/iQIYI 20、dropbox 14 等),消除报告实证的全部误捕获(qingmail/suningmail、`univod.cn`→DIRECT、`ttcdn-tos.kkimg.cc`、`sf1-ttcdn-tos.pstatp.com`→字节国内直连、iqiyi 系仿冒 buzz 域等)。存留 8 条均为登记观察项(Reject 6 + `smp-device` + `sci-hub`)。全部已删关键词入 forbidden 段(A8,共 126 条模式)。
- **DownloadCDN 确定级止血(5,622→5,559 条)**:删 13 条多租户平台宽后缀(github.io/vercel.app/pages.dev/cloudfront.net/blob.core.windows.net/s3.amazonaws.com 等,任意租户流量不再被吸入下载出口)与 14 条通用 SaaS 组件规则(Trustpilot/Algolia/Zendesk/Optimizely);`unpkg.com` 经裁决保留(单一注册者包 CDN,与 jsDelivr/cdnjs 同类);本表 DOMAIN-KEYWORD 17→0。FiveM/Cfx 34 条与万代账号域整族迁 Games(`fivem.net`/`cfx.re`/`bandainamcoid.com`)。
- **Streaming 共享组件清理**:删 AdobeDTM/Braze/Optimizely/Kochava/CookieLaw/OneTrust 与 AWS 区域通用后缀(`execute-api.*`/`us-west-2.amazonaws.com`/`amazonaws.co.uk`)共 11 条,第一方网关只留实证精确 host;补 Abema 4 条缺失资产。**IP-CIDR/IP-ASN 面逐字节未动**(Phase 2 shadow 范畴)。
- **ChinaIP 等价折叠(22,417→11,090 条,-50.5%)**:新增 `tools/collapse_cidr.py`(写前等价自检,不等价拒绝写);地址集合逐位不变(SHA-256 相同 + 方法独立的 49 万探测点成员判定 0 分歧)。发布链新增折叠漂移闸门(update.sh 步 0.5),上游再生后未折叠会被拦下。
- **归属收口**:YouTube 专属 googleapis 三子域(`youtubei` 等)归 YouTube.list(App API 面与视频面同会话);AppleCN 4 条 CNAME 调度域改 DOMAIN-SUFFIX 点边界。

### Fixed
- **runsuite 加载期 schema 严格校验**(报告 P1-10 全部假绿空洞):name 唯一、requests 非空、断言有效性、policy×policy_in 互斥、per_request 键唯一且可对应、未知键报错、known-broken>0 非零退出(`--allow-known-broken` 逃生口)。顺带挖出并重建了两个被 PROCESS-NAME 移除掏空的存量空场景(0 断言却显示通过——正是 P1-10 所指问题的活体)。
- **surge2clash 事务式**(报告 §13.3):全量解析校验(未知类型一次报全清单)→ 临时目录生成 → 逐文件原子换入,正式 `clash/` 全有或全无;新增 `--check` 漂移门(0/1/2 退出码);内容相同零重写,消除 mtime churn。
- audit A8 大模式量优化(精确模式 O(1) 查表,126 条模式全库扫描 0.6s)。

### Added
- `SOURCES.md`:19 个上游/参考来源的 URL、本地快照 revision、许可证(逐个取证,含「未声明」的如实登记)与使用方式;LICENSE 选型(涉 GPL/AGPL 传染性)留待用户裁决。
- 场景 5 个新文件 + 重建 2 场景:`kw_ecosystem`/`kw_direct`/`kw_media`/`download_cleanup`/`region_coverage`(地区表与 NetEaseCN 首获 L2 正负覆盖)。回归基线 113→**147 场景 / 1,731 断言 / 674 条 DNS 泄漏断言**;Surge 源与 Mihomo 1.19.20 实载守恒 **143,640 条**。
- MAINTENANCE 裁决登记追加 12 行(二轮批次):多租户平台永久禁收、SaaS 组件解耦、FiveM/Epic/Steam、YouTube googleapis、ChinaDomain 再生回收清单等。

---

## [2026-08-31] 外部审计整改:发布链三态化 + forbidden 门禁 + 归属修正 + 关键词边界化

依据外部审计报告(docs/RULES_AUDIT_AND_OPTIMIZATION_2026-08-31.md)逐条核实后修复其中「确定级」发现;需真实流量验证或整表重建的项(DownloadCDN/Streaming 重构、地区表 canonical owner、上游供应链)未在本轮处理,见报告 Phase 2-4。

### Fixed
- **update.sh 发布假成功(P0)**:重写为三态结果——`VALIDATED_NOT_PUBLISHED` / `PUBLISHED_AND_VERIFIED`(exit 0)/ `PUBLISHED_BUT_UNVERIFIED`(exit 1)。CDN 拉取失败、purge 未受理、非 JSON 响应、复验 md5 不一致、限流,全部如实计数并以非零退出;不再有任何网络失败路径通向"完成"。`set -euo pipefail`。
- **update.sh 分支错配(P0)**:只允许 main 分支发布(非 main 立即退出、不产生提交);push 改为显式 `HEAD:main`,push 后 fetch 并校验 `origin/main == HEAD` 才继续刷 CDN——消除「提交 A、推送 B、刷新 A」路径。diff 中的**删除项**也发 purge,防旧内容滞留边缘缓存。
- **allowlist preventive 双语义(P0)**:「防回归豁免」此前同时承载「允许重叠」与「命中即删」两种相反语义,后者会被静默豁免放行。拆分为:允许存在的仍留 exemptions(39→30 条);「必须持续不存在」迁入顶层 **forbidden 段**(18 条:全类型 USER-AGENT/PROCESS-NAME/URL-REGEX、D11 上游排除项、已删品牌关键词),由新增 **audit A8** 扫源文件强制——命中即 P0 且不可被 exemptions 豁免。
- **audit 自检盲区**:补 A7 正向 fixture(裸行必须被捕获)与 A8 正向 fixture(植入 PROCESS-NAME 必须被抓、豁免必须无效),自检 27→33 条。
- **Surge/Clash 顺序分叉**:rule-providers.yaml 的 rules 参考序列此前把 Reject 排在 PrivateLAN/PKU 之前,与 Surge 真实顺序(PrivateLAN→PKU→Reject)相反;Reject 已补入 CONF_ORDER 真实位置,参考序列与 Surge.conf 逐行同序。
- **文档漂移**:README/ARCHITECTURE/tests README 的表数(32→34)、场景与断言数、A1–A6→A1–A8、Mihomo 守恒数(138,185→154,666)、Reject 停用表述、发布文件数(65→69)全面对齐现状;MAINTENANCE 修正 runsuite「--rules」参数误载(实为 --conf)与已不存在的两个备份目录登记(实际回滚依赖 git 历史与 tag `pre-restructure-20260829`)。

### Changed
- **归属修正(确定级,共 7 项)**:Cursor/Anysphere 全家(6 域)Twitter→AI(独立公司,更正 08-30 裁决);`qwenlm.ai` Domestic→AI(跳转 chat.qwen.ai,国际站统一代理);`static.cloudflareinsights.com` 移出 AI 落 FINAL(Web Analytics beacon 非 Turnstile,更正 08-30 B2 裁决);`api.snapkit.com` / `sdk.snapkit.com`(Snap 资产)移出 TikTok/DownloadCDN,`cocacola.co.jp`(日本可口可乐)移出 TikTok 迁 Japan.list;`sony.com` 移出 Games(集团总域,PlayStation/SIE 域保留);`digicert.com` AppleCN→Domestic CA 段(CA 所有权归位,直连行为不变,Domestic 内 3 条子域并入宽后缀)。
- **共享云段清理(3 条)**:Games 删 GCP `35.192.0.0/12`(约 105 万地址客户段)、Meta 删 AWS `18.194.0.0/15`、Google 删 `IP-ASN,396982`(GCP 客户前缀 ASN)——云平台所有权≠业务所有权,云客户 IP 回落 FINAL;第一方专网段(Meta AS32934 等)不受影响。
- **关键词边界化(104→84 条)**:Reject 10 条改 DOMAIN-WILDCARD 锚定(8 条右锚定片段 + `dnserror.*` + `hostingcloud.*`,拦截意图保持、标签外子串不再有第一优先级误杀面);Payment 的 `paypal` 关键词改为 5 条官方精确后缀(paypal.com/paypal.me/paypalobjects.com/paypal.cn/paypalcorp.com,原表无任何 PayPal 精确规则);ChinaDomain 删尾部 9 条品牌关键词(核心域由厂商表承接,`hnagroup.com` 补入 Domestic 承接)——防含品牌子串的投毒/仿冒域被强制 DIRECT。Reject 剩余 6 条特异词与 MicrosoftCN 3 条产品词列观察项(见 MAINTENANCE 裁决登记)。
- **Clash 派生 DOMAIN-WILDCARD 原样透传**:Mihomo ≥1.19 原生支持且 `*`/`?` 语义与 Surge 一致,不再转写 DOMAIN-REGEX(消除正则方言差异);Mihomo 1.19.20 实载 34 provider 验证 ruleCount=154,666 与源守恒。
- **死条目清理**:ProxyGFW 删 `sso.amazonaws.com`(被同表 `amazonaws.com` 覆盖,行为由宽兜底承接不变)。

### Added
- `tests/scenarios/ownership_fix.json`:10 场景/44 请求/87 断言,锁定本轮全部归属修正与关键词边界化的正/负例(PayPal 仿冒域、品牌子串仿冒域、dnserror/hostingcloud 误杀负例、共享云 IP 落点、Qwen 国际链同出口等)。回归基线 103→113 场景、1044→1131 断言、DNS 泄漏断言 333→374 条。
- MAINTENANCE「裁决登记」追加 12 行:forbidden 段机制、Cursor/CF Insights 两项裁决更正、SnapKit/可口可乐、Qwen、PayPal 后缀集、ChinaDomain 再生过滤、sony.com、共享云段三禁、Reject 关键词边界红线、MicrosoftCN 观察项。

---

## [2026-08-30] Reject 启用 + DIRECT 过度覆盖修复 + 全库注释精简 + 公开仓库脱敏

### Added
- **Reject.list 重构启用**(1152 → 364 行):定位收敛为「广告投放/网盟/流氓变现 SDK + HTTPDNS 私有 DoH + 恶意与假冒站」。新增恶意层 183 条(源:blackmatrix7 Hijacking,长期在册的假冒官网下载站/返利劫持链/私服垃圾站/住宅代理 SDK);HTTPDNS 上游差集补 4 条。**埋点/统计/归因/推送/APM/个性化推荐域一律放行**并以负向断言锁死;795 条无注解 IP 沉洞不再回收。Surge.conf 第 1 区已启用为 REJECT。
- `tests/scenarios/reject_layer.json` 扩为 14 场景/151 断言(正向拦截 + 负向防误杀)。
- `docs/MAINTENANCE.md` 新增「裁决登记」:20 条操作性红线自各表头注释集中迁入。

### Changed
- **DIRECT 过度覆盖修复 48 条**:`linux.do`/`linuxdo.org` 等 17 域经 DNS 投毒与直连超时双实证自直连层移入 ProxyGFW;13 条境外托管不可达域自 Domestic/ChinaDomain/NetEaseCN 删除落 FINAL;`biliintl.co` 移交 Streaming。回归对照 11 个国内域保持 DIRECT。
- **全库注释精简**:34 张表头注释 143 → 83 行(字节 −65%),统一「定位/排序/红线」≤3 行;日期叙事与重复裁决段落删除,仍有效约束迁入 MAINTENANCE 裁决登记;Surge.conf 注释同步重写并把分区重编号为 0–10 连续序列;本文件内 commit hash 引用全部改为「日期+标题」(历史重写会更换全部 hash,hash 引用不再可靠)。
- **公开仓库脱敏(外置 + 中性默认)**:tests 内策略组名/线路关键词/ASN 映射下沉到仓库外覆盖档(三级查找:`LIVE_CHECK_LOCAL` → `rules-local/live_check_local.json` 真源 → `tests/live_check_local.json` 兜底;schema:`exit_class_exact`/`exit_class_keywords`/`asn_map`/`residential_hints`/`datacenter_hints`),公开代码仅含中性占位;缺档时相关断言自动 skipped。`lists/Europe.list` 移除一条服务商官网域。

### Security
- 本 commit 之后执行 `git filter-repo` 全历史重写:清除历史 blob 与 commit message 中残留的线路商/机房标识、ASN 与含标识的组名(真实节点地址与密钥经复核在全历史零存在)。旧 commit hash 全部失效。

### Removed
- `ChinaDomain.list`/`AlibabaCN.list` 各删 1 条被 Reject 前位抢占的死条目(adsame.com/yukhj.com)。

## [2026-08-29] 布局重构 v2 —— 待发布

> 状态:本地重构完成、audit/runsuite 全绿、已本地 commit。**push 与 CDN 切换由用户执行**,步骤见本节末尾「发布切换顺序」。

**动机**:仓库根目录同时堆放 32 个 `.list`、转换脚本、发布脚本、测试目录与文档,规则文件与工程文件混杂;同时要为下一阶段的 Surge module / script 能力预留位置。本次把仓库分层成「数据(lists)/ 派生(clash)/ 工具(tools)/ 验证(tests)/ 扩展(modules+scripts)/ 文档(docs)/ 参考(reference)」七个明确区域。

### Added

- `lists/` —— 32 个 Surge `.list` 全部收纳于此,成为**唯一编辑源**。所有移动均用 `git mv`,历史完整保留。
- `tools/` —— `surge2clash.py` 从仓库根移入,内部路径随之适配(原先假设 `.list` 与脚本同目录,现指向 `../lists`)。
- `modules/` —— 新建 Surge 模块目录,本次仅交付 `_template.sgmodule` 起手模板与 `README.md` 目录约定。
- `scripts/` —— 新建 JS 脚本目录,本次仅交付 `_template.js` 起手模板与 `README.md` 目录约定。
- `docs/` —— 新建文档体系:`ARCHITECTURE.md`(架构、规则序、设计裁决、测试体系)、`MAINTENANCE.md`(维护与发布手册)、`DEVELOPMENT.md`(module/script 开发指南)。
- `CHANGELOG.md` —— 即本文件,此前仓库无更新记录,历史只能靠 `git log` 还原。
- `reference/` —— 本地参考库(上游参考项目 + Surge 官方文档抓取),**gitignored,不入库**,仅供本地查阅。

### Changed

- **CDN 路径契约**:Surge 侧引用路径由根目录改为 `lists/` 子目录 ——
  - 旧:`https://cdn.jsdelivr.net/gh/yhyfhgs/surge-rules@main/<Name>.list`
  - 新:`https://cdn.jsdelivr.net/gh/yhyfhgs/surge-rules@main/lists/<Name>.list`
  - **Clash 侧路径不变**(`clash/<Name>.list`、`clash/rule-providers.yaml`),这是本次刻意保持 `clash/` 位置不动的原因 —— 已在用的 Clash 端零改动。
- `update.sh` 留在仓库根作为发布入口,内部路径适配新布局;purge / md5 集合仍为 **65 个文件**。
- `tests/` 位置不动,`engine.py` 的 `rules_dir` 推导改为指向 `rules/lists/`;`audit.py` 与 `engine.py` 底部的内嵌 self-test(tempdir fixtures)不依赖真实布局,不受影响(自检基线 58/58 与 27/27 保持全绿)。
- `.gitignore` 追加 `reference/`。
- 仓库根 `README.md` 重写:补上架构图、目录结构树、按 0–8 九区组织的 32 表总览、Surge/Clash 双端引用示例与文档导航。

### Security

- **全部 git 历史已执行脱敏重写**(`git filter-repo`):清除 `tests/` 历史版本中曾出现的真实节点地址与私有线路标识(替换为 `<REDACTED-*>` 占位);测试工具的私有节点映射外置到仓库外,公开代码只保留通用 ISP 关键词。
- **私有映射的三级查找**(`live_check.py`,取第一个存在的文件,不叠加):① 环境变量 `LIVE_CHECK_LOCAL` 指定的路径;② `<repo>/../rules-local/live_check_local.json` —— **真源**,整个目录都在仓库外;③ `<repo>/tests/live_check_local.json` —— 旧路径兜底,靠 `.gitignore` 守着。schema 含 `exit_class_exact` / `exit_class_keywords` / `asn_map` / `residential_hints` / `datacenter_hints`(并兼容早期键名);文件全缺时走中性默认值,不报错,只是出口归类退化到国旗兜底。
- **影响**:自 2026-08-25「Audit overhaul: AI/CDN routing fixes, region GEOIP reorder, dead-rule cleanup, add tests/」起的 commit hash 与旧历史不同,旧 clone / fork 需要重新拉取。
- **本文件不写 commit hash**,一律用「日期 + commit 标题」引用 —— 历史重写会让所有 hash 永久失效,标题可用 `git log --grep` 稳定定位。

### 影响面

- **Surge 用户需换 URL**:conf 中 32 处 RULE-SET 引用要从 `@main/<Name>.list` 改为 `@main/lists/<Name>.list`(其中 Reject 一处为注释停用态)。
- **Clash 用户无感**:引用路径未变。
- **规则内容零变化**:本次只搬位置,不动任何规则条目,因此不涉及分流行为变更。

### 发布切换顺序

1. 本地重构 + audit/runsuite 全绿 + 本地 commit(已完成)。
2. 用户运行 `./update.sh "<msg>"` → push + purge 新路径 + md5 校验。
3. 用 `Backup/` 中备好的新版 `Surge.conf`(32 处 URL 已改为 `@main/lists/<Name>.list`)替换现行 conf,Surge GUI 重载。
4. **缓冲窗口**:jsDelivr `@main` 的旧根路径文件在缓存过期前(最长约 12h)仍可命中,为切换留出余量;尽快完成第 3 步即可,期间新旧路径并存不影响使用。

---

## [2026-08-27] Clash (Mihomo) 派生层上线

**动机**:同一套规则此前只服务 Surge。要在 Clash Verge Rev / Mihomo 上复用,又不愿维护两份会漂移的规则源,于是确立「单一编辑源 + 机器派生」原则。

### Added

- `surge2clash.py` —— Surge → Clash classical 规则集转换器,全量再生 `clash/` 下 32 个同名 `.list`。
- `clash/rule-providers.yaml` —— 全部 rule-providers 定义 + 按优先级排好序的 `rules` 参考序列,可在 Clash Verge Rev 的「Merge」扩展中直接取用。
- 转换器接入发布链:`update.sh` 在双闸门通过后自动再生 `clash/`,purge / md5 集合扩展到 **65 个文件**(32 Surge + 32 Clash + 1 YAML)。

### 转换约定

- `DOMAIN-WILDCARD` → `DOMAIN-REGEX`,按 Surge 语义转写(`*` → `.*`、`?` → `.`,并加 `^$` 锚定)。
- `USER-AGENT` / `URL-REGEX` 为 Surge 专有匹配层,Clash 无对应能力 —— 剔除,并在各文件头标注被剔除的数量。
- 其余类型(含 `no-resolve` 标志)原样透传。
- 遇到未知规则类型 **fail-fast 中止发布**,不做静默降级。

### 验证基线

- **138,185 条**经 mihomo 1.19.20 实载核对守恒。
- 核对方法要点:`mihomo -t` 是懒加载,不验证 provider 内容,必须启动后查 API 的 `ruleCount`;provider 异步初始化需等约 10s 再读数。

### 影响面

- `clash/` 自此为**纯派生产物,禁止手工编辑** —— 任何手改都会在下次发布被覆盖。
- Clash 端因缺少 UA / URL 匹配层,分流精度略低于 Surge 端,差额已在文件头计数体现。

---

## [2026-08-25] 审计整改与测试体系固化

**动机**:blackmatrix7 大合并把规模推到十万条量级后,靠肉眼已无法保证「唯一归属 + 零 DNS 泄漏 + 无遮蔽」三条不变量。本轮做了一次系统性审计整改,并把所有结论固化成可回归的断言,防止后续被"好心修复"回退。

### Added

- `tests/` 测试四件套:
  - `engine.py` —— 离线规则引擎,只读解析 `Surge.conf` 与本仓库 `.list`,复现 Surge 的匹配顺序;GEOIP,CN 用 `ChinaIP.list` 做近似。
  - `audit.py` —— 静态审计 A1–A6。
  - `runsuite.py` —— **90 个真实场景 / 931 条断言**,其中 **351 条为 DNS 泄漏断言**。
  - `live_check.py` —— 对着运行中的 Surge HTTP API 做在线核对。
  - 配套 `allowlist.json`(既定裁决的落点)与 `scenarios/*.json`。
- `update.sh` 接入 pre-flight 闸门:audit + runsuite 全绿才允许发布。

### Changed

- **AI 与生态边界重划**:AI.list 收窄 KEYWORD(sentry / datadog / sift / openai),移除 DO / Vultr ASN;国内厂商的国际站(coze / qwen.ai / z.ai / minimax.io / moonshot.ai 等)移入 AI.list 走代理,对应 `.cn` 域移出走直连;GitHub 全生态统一到 AI 策略。
- **Microsoft.list 独立成表**(2026-08-25 commit「Restructure: Microsoft.list (Google-X-Meta), region lists self-contained IP rules moved after Apple/MS/GFW, LINE to Japan, drop conf pins」)—— Copilot / Bing / MSN / 国际登录面共 25 条从 AI 组拆出,与 Google / Twitter / Meta 同走一组。
- **策略组更名** Google-X-Meta → **Google-X-Meta-MS**(2026-08-25 commit「Rename policy group to Google-X-Meta-MS across test assertions and tooling」),测试断言与工具链同步改名。
- **CDN 配对整理**:国内媒体 CDN(bilibili / iqiyi)归还 DIRECT;NTP 与 captive portal 归 DIRECT;stripe / docker / npm 归属统一;bstar → Streaming;pximg → Japan。DownloadCDN 定位收窄为「大流量批量下载域」,剥离 **533 个**站点静态资源域。
- **地区表自包含并后置**:Japan / UK / Europe / US 的 GEOIP / IP-ASN 规则收进各自表内,整体移到 Apple / 微软 / GFW 之后、国内区之前 —— 修掉了 Apple 17/8 与 ProxyGFW 的 IP 规则被 `GEOIP,US` / `GEOIP,JP` / `GEOIP,DE` 抢先遮蔽的问题。
- LINE 归入 Japan 表。
- 移除 conf 侧的若干 pin 条目,规则归属回到 list 内自洽。

### Removed

- 死规则与冗余清理合计 **-855 条**,其中 TencentCN 的 233 条伪 KEYWORD 规则、以及各处重复 / 被遮蔽 / 过期条目。
- 停止跟踪 `__pycache__`,并加入 `.gitignore`(2026-08-25 commit「Drop tracked __pycache__」与「Ignore __pycache__」)。

### 影响面

- 本轮结论均已固化进 `tests/` 断言与 `allowlist.json`。**逆向"修复"会直接打红断言** —— 见 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) 的设计裁决记录。

---

## [2026-08-25] blackmatrix7 大合并与发布链建立

**动机**:自建规则覆盖不了国内长尾域名,漏网流量落到 FINAL 走代理,既慢又浪费带宽。引入 blackmatrix7 上游补齐长尾,同时把发布从"手动 push + 等 CDN"变成一条可复现的命令。

### Added

- **国内直连三层格局成形**(2026-08-25 commit「merge blackmatrix7: 6 CN sub-lists + ChinaDomain fallback」):在既有 Domestic 手工层之上,补入 6 个厂商细分表(ChinaMedia / TencentCN / AlibabaCN / ByteDanceCN / BaiduCN / NetEaseCN),再以 ChinaDomain(**约 10.6 万条**)做长尾兜底。
- `update.sh`(2026-08-25 commit「Add update.sh: one-command push + jsDelivr purge + verify」)—— 一条命令完成 push + 逐文件 purge jsDelivr + md5 校验,解决了 CDN 缓存导致"改了但没生效"的老问题。

### 影响面

- 规模从千条级跃到十万条级,肉眼审阅失效 —— 直接催生了同日的审计整改与测试体系。
- ChinaDomain 自此为**机器管理层**,手工条目一律不加(要加就加进 Domestic 或对应厂商细分表)。

---

## [2026-08-25] 初始发布

### Added

- 首次发布 **23 个**去重后的 Surge 规则集(2026-08-25 commit「Initial release: 23 deduplicated Surge rulesets」),确立「每个域名/IP 全链唯一归属」的核心原则。

### Changed

- 国内 AI 厂商域名(Kimi / Qwen / Zhipu / MiniMax / Kling / Coze 国际站等)移入 Domestic 走直连(2026-08-25 commit「Move domestic AI vendors (Kimi/Qwen/Zhipu/MiniMax/Kling/Coze intl etc.) to Domestic DIRECT」)—— 该归属在后续审计中被重新裁决:国际站改走代理、`.cn` 域保持直连。
- 生态绑定的 CDN 归还各自服务表(2026-08-25 commit「Move ecosystem-bound CDNs to their service lists (Angular/googlezip->Google, SteamOS/Epic/Blizzard CDN->Games)」):Angular / googlezip → Google,SteamOS / Epic / Blizzard CDN → Games。

### Removed

- ProxyGFW 中失效的 `googlezip.net` 条目(2026-08-25 commit「Remove dead googlezip.net entry from ProxyGFW (owned by Google list)」),归属权已属 Google 表 —— 唯一归属原则的第一次落地执行。
