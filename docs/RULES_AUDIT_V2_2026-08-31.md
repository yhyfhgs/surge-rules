# Surge 规则体系第二轮全量审计与迭代路线

> 审计日期:2026-08-31(Asia/Shanghai)<br>
> 审计基线:commit `e03c530`(`origin/main == HEAD`,工作区干净,分支 `main`)<br>
> 审计方法:8 个并行领域 worker 全量只读审计 + advisor 交叉抽查 **6/6 通过**、独立证实 12 项关键发现<br>
> 审计对象:34 张 `lists/*.list` 共 **143,640** 条源规则、`Surge.conf` 的 `[General]`/`[Proxy Group]`/`[Rule]`/`[MITM]` 结构、`clash/` 派生层、`update.sh` / `tools/` / `tests/` 全链路、`SOURCES.md` 与 6 份文档的数字断言<br>
> **本轮未修改任何规则文件、配置文件或测试文件。** 本文只给审计结论与迭代路线;所有改动动作均登记为路线图待执行项。

---

## 0. 结论先行

### 0.1 三句话定性

1. **结构面已经很干净,问题从「结构」转移到了「内容真实性」。** 域名层前位遮蔽 0 条、同表精确重复 0 条、`DOMAIN` 被 `DOMAIN-SUFFIX` 覆盖 0 条、IP 类规则 100% 带 `no-resolve`、`USER-AGENT`/`PROCESS-NAME`/`URL-REGEX` 全库为 0、策略引用与组成员闭包 100% 闭合。两轮级联去重在域名层的效果是**彻底的**。
2. **本轮最高优先级是一个上轮没有的新类别 —— 信任面缺陷。** 未注册域、停放域、易主域、拼写错误域出现在**最高优先级的 DIRECT 层**:`pkuiot.com` 未注册却坐在区 0、`bdwm.net` 已是 GoDaddy 停放页且免疫全库拦截层、`steambroadcast.com` 已非 Valve 资产却在区 2 拿 DIRECT。这类条目一旦被抢注,攻击者直接获得一条绕过 Reject 的白名单。
3. **上轮的方法论缺陷被本轮实证:按名单删除,而不是按判据删除。** 上轮删掉 13 条具名多租户宽后缀,同族兄弟原样留在表里(S3 区域端点、`vercel.dev`、`r2.dev`、`file.core.windows.net`、`repl.co`/`hf.space`…);删掉 AWS 一个 `/15`,同判据的 27 条杂段没动;删掉 `IP-ASN,396982`,同判据的 AS19527/AS43515 没动。**解法不是再列一次名单,而是把判据变成门禁**(A9–A13)。

### 0.2 本轮最重要的八件事

| # | 主题 | 一句话 | 级别 | 详见 |
|---|---|---|---|---|
| 1 | 信任面缺陷 | 区 0 有 1 条**未注册域** + 1 条停放域;区 2 有 1 条易主域;代理侧另有 3 条停放/易主域 | P1–P2 | §3.1 |
| 2 | 家族闭合失败 | 321 条 S3 区域后缀、27 条非 Meta IP 段、2 个同判据 ASN、8 类 SaaS 组件残留 | P1 | §3.2 |
| 3 | 裁决-机器脱节 | `MAINTENANCE §8` 的 **34 条禁收裁决在 forbidden 门禁覆盖率 = 0%**;`kw_direct.json` 6 条断言是定时炸弹 | P2 | §3.3 |
| 4 | DIRECT 侧投毒故障 | `onedrive.live.com` 4 个 host 被投毒 + 强制 DIRECT ⇒ **OneDrive 个人版实测完全不可用**;674 条 DNS 断言守不住这一类 | P1 | §3.4 |
| 5 | 失效与惰性 | ModelDownloadCDN **4 条全失效**(区 3 设计目的被架空);ProxyGFW 6,427 条中 **99.7% 惰性**;TencentCN 14 段全是死条目 | P1–P2 | §3.5 |
| 6 | 会话与归属精化 | 29 个注册域跨策略分裂,其中 8 个是**真实同会话跨出口**(BBC / Prime Video JP / DLsite / Cygames / Niconico / ESPN+ / Tubi / Telegraph) | P1 | §3.6 |
| 7 | 机器层再生管线 | ChinaDomain **不可从声明的 pin 重建**(534 条差异无法解释);境外托管噪声约 1.6 万条;**仓库根本没有再生脚本** | P1 | §3.7 |
| 8 | conf 与工程侧 | DNS 两 DoH 单点无明文兜底;`[Proxy]` 段 1 条孤儿节点;`persistent` 9 处全惰性;`update.sh` 新表必然误报失败 | P2 | §3.8 |

### 0.3 发现分级统计

统计口径:对 8 份 worker 报告中**每一条带 `[P级|置信度]` 标注的编号发现**逐条计数(可用 `grep -E '^### \S+ \[P[0-3]'` 复现),标 `[✅ 核验通过]` 的条目不计入。

| 级别 | 条数 | 说明 |
|---|---:|---|
| **P0** | **0** | 无控制面失守、无发布假成功、无禁止规则回流 |
| **P1** | **26** | 可证明的误分流 / 过捕获 / 会话破坏 / 信任面敞口 |
| **P2** | **66** | 冗余 / 盲区 / 所有权错误 / 门禁缺口 / 漂移 |
| **P3** | **49** | 文档 / 格式 / 低风险 / 观察候选 |
| **合计** | **141** | 另有 5 条 `[✅ 核验通过]` 结论(W8)与各报告 §1 的 72 条落实核验不计入 |

分领域:

| 报告 | 范围 | 规则数 | P1 | P2 | P3 | 小计 |
|---|---|---:|---:|---:|---:|---:|
| W1 | 8 张生态代理表 | 1,682 | 3 | 9 | 3 | 15 |
| W2 | 流媒体 / 下载 / 游戏 / AI 6 表 | 9,668 | 10 | 9 | 3 | 22 |
| W3 | Reject / Payment / PrivateLAN / PKU / ProxyGFW | 7,060 | 2 | 9 | 7 | 18 |
| W4 | Japan / UK / Europe / US | 247 | 8 | 7 | 5 | 20 |
| W5 | 国内侧 9 表 | 7,429 | 1 | 8 | 6 | 15 |
| W6 | ChinaDomain / ChinaIP | 117,554 | 2 | 7 | 1 | 10 |
| W7 | 工程链路(update.sh / tools / tests) | — | 0 | 7 | 7 | 14 |
| W8 | 主配置与全局横切 | 143,640(交叉) | 0 | 10 | 17 | 27 |
| | **合计** | **143,640** | **26** | **66** | **49** | **141** |

> 口径说明:W8 报告的执行摘要自述「P2 共 9 项、P3 共 12 项、✅ 7 项」,与其正文的 32 条编号条目(27 条 P 级 + 5 条 ✅)不符 —— 本表以**正文逐条标注**为准(可机器复现),该差异已回报 advisor。

> 覆盖完整性自证:六个**规则表**领域的条数之和 1,682 + 9,668 + 7,060 + 247 + 7,429 + 117,554 = **143,640**,与 `ARCHITECTURE §5.3` 的守恒基线逐位相符 ⇒ 34 张表**无一遗漏、无一重复**分配。W7/W8 是横切领域,不参与该求和。

### 0.4 路线图一览

| 批次 | 定位 | 行动项 | 阻塞关系 |
|---|---|---:|---|
| **R0** | 保险丝 —— 发布前必做,防打红 | 3 | 无依赖,可立刻做 |
| **R1** | 立即修复 —— 全部「确定」级,一个发布批次 | 24 | 依赖 R0 |
| **R2** | 门禁升级 —— A9/A10/A12 实装 + 34 条禁收入表 | 11 | 依赖 R1(避免门禁上线即报存量) |
| **R3** | 机器层与供应链 —— 再生管线 + sources.lock | 8 | 依赖 R2 的 A10;部分依赖用户待决 6 |
| **R4** | 观测与周期 —— A11/A13 周期化 + 观察项结案 | 8 | 依赖命中统计采集能力 |

执行模式沿用既有约定:**Fable 写批次 spec → Opus 并行执行 → audit + runsuite 双闸门 → 单次发布**。

---

## 1. 方法与覆盖

### 1.1 分工与覆盖矩阵

本轮把 34 张表按语义边界切成 6 个规则领域 + 2 个横切领域,8 个 worker 并行只读审计,互不共享中间结论(防止串供),最后由 advisor 做交叉抽查与仲裁。

| Worker | 覆盖对象 | 主要方法 |
|---|---|---|
| **W1** | Google / YouTube / Twitter / Meta / Microsoft / Telegram / TikTok / SocialOthers | 1,682 条全量结构化检查;**1,583 条域名规则逐条实时 DNS(NS/SOA/A)探测**;Meta 520 条另加 HTTPS+HTTP 双端口活性探测;72 条 CIDR + 17 条 IP-ASN 逐条对照 RIR whois/RDAP 与 RIPEstat 通告前缀集 |
| **W2** | AI / Streaming / Games / DownloadCDN / GameDownloadCN / ModelDownloadCDN | 全量脚本检查 + AWS `ip-ranges.json`(`syncToken=1788119825`)/ GCP `cloud.json` / Azure ServiceTags(`changeNumber=415`)三云快照包含判定;Team Cymru 批量 ASN;PSL 快照;curl/openssl 一手复现 |
| **W3** | Reject / Payment / PrivateLAN / PKU / ProxyGFW | Reject 329 域 + **ProxyGFW 6,427 域全量(非抽样)双侧 DNS 存活扫描**;按 conf 真实序做承载力比对;8 条 Reject IP 逐条 whois |
| **W4** | Japan / UK / Europe / US | 247 条**逐条人工核对**;全库 143,676 条做注册域(eTLD+1)与品牌 token 双维对撞;`tests/engine.py` 逐 host 复算真实落点与当前物理出口;PSL 快照(16,424 行)核公共后缀边界 |
| **W5** | Domestic / TencentCN / AlibabaCN / ByteDanceCN / BaiduCN / NetEaseCN / ChinaMedia / AppleCN / MicrosoftCN | 用 conf 真实序重建全库 143,640 条匹配模型,对 9 表 **7,400 条域名规则逐条**做前位抢跑 / 后位覆盖判定;双侧 `dig +tcp` + `curl --resolve` 绕代理复现 |
| **W6** | ChinaDomain / ChinaIP | 全量结构化检查 + **系统抽样 n=2000(Wilson 95%CI)**+ 2,827 域双解析器实测 + 上游/GEOIP 全量集合比对;交付可运行再生过滤器原型 |
| **W7** | `update.sh` / `tools/` / `tests/` / `modules/` / `scripts/` / `SOURCES.md` / 派生一致性 | 6 条基线命令 + **38 组故障注入探针**(scratchpad 内合成 fixture,仓库零改动) |
| **W8** | `Surge.conf` 全 146 行 / 22 个策略组拓扑闭包 / 34 表四类跨表关系 / 11 处 `extended-matching` / 6 份文档 30 余处数字断言 | 按 conf 真实序拼单一有序规则流,做精确重复 / 后缀遮蔽 / IPv4+IPv6 前缀树 CIDR 包含 / 关键词-通配捕获四类全量分析;官方手册本机快照逐条核语义 |

### 1.2 证据强度分级(沿用上轮体系)

- **确定**:规则语义 + 规则序 + 一手证据(whois/RDAP/BGP/双侧 DNS/curl 复现/官方文档原文)直接证明。
- **高置信**:所有权或语义明确,但实际流量影响未经命中数据确认。
- **观察候选**:必须先取得命中统计、CNAME 链、抓包或完整会话链才能裁决,**不得直接删除**。

本文每条重要发现均标注 `[P级|置信度]`,`file:line` 引用来自对应 worker 报告。

### 1.3 advisor 交叉抽查

advisor 对 8 份报告中**跨报告收敛**与**高风险**的结论做了独立抽查,**6 组全部通过**,并在此基础上独立证实了 12 项关键发现。下列 12 项在本文中可用「**确定,advisor 复核通过**」表述:

| # | 结论 | 对应 worker 发现 |
|---|---|---|
| 1 | `steambroadcast.com` 非 Valve(2026-04-27 注册 / Registrar.eu / Cloudflare NS;真 Valve 域一律 MarkMonitor),现在 `GameDownloadCN.list:53` 拿 DIRECT | W2 G-01 |
| 2 | ModelDownloadCDN **全部 4 条失效**;HF 大文件实测 302 → `us.aws.cdn.hf.co`,落 `AI.list` 的 `hf.co` → AI 组 | W2 M-01 |
| 3 | DownloadCDN 残留 **321 条** `s3[.-]*.amazonaws.com` 区域后缀(家族闭合失败的直接实证) | W2 D-01 |
| 4 | `§8` 的 **34 条「明确禁收」裁决在 forbidden 门禁覆盖 = 0**(`bolt.com`/`revolut`/`sony.com`/`cloudflareinsights` 等 8 个代表项逐一验证 NOT-in-forbidden;forbidden 实际 130 条) | W7-T02 |
| 5 | `update.sh` 新增分发表时先验必然 404 → 计入 `fetch_fail_pre_n` → **成功发布必报 `PUBLISHED_BUT_UNVERIFIED`**(`update.sh:228-234`、`:304-305` 代码路径确认) | W7-T01 |
| 6 | `ChinaDomain.list:22497` 存在整条 `DOMAIN-SUFFIX,cn`(上游已折叠 .cn 子项,表内无其他 .cn 条目)⇒「删 .cn 死域会落 DIRECT」陷阱成立 | W3-07 |
| 7 | `kw_direct.json` 6 条断言硬编码 `policy=Final`,且 reason 自述「待再生回收为 DIRECT」⇒ 下次 ChinaDomain 再生必打红 runsuite,与 `§8`「再生回收属预期勿当回归」裁决**直接矛盾** | W6 F-06 |
| 8 | `live.streamingfast.net` 投毒实证(国内 `108.160.170.43` 污染池 vs 境外 `211.21.19.128`);`origin-a.akamaihd.ne`(上游拼写错误)在 `ChinaDomain.list:119` | W6 F-01 / F-02 |
| 9 | `onedrive.live.com` 投毒实证(国内 `103.252.115.53` vs 境外 CNAME→`13.107.139.11`),`MicrosoftCN.list:35` 的 `live.com` 打 DIRECT ⇒ **OneDrive 网页版直连必挂** | W5-01 |
| 10 | `ChinaMedia.list:339-349` 共 **11 条 `domesticmedia*` 幽灵规则** = bilibili 域家族一次字符串替换事故的**平行副本**(真 bilibili 后缀在 `:261-270` 完好,`bilibili.tv` 在 Streaming 正确)。处置 = 删 11 条,**无级联损失** | W5-02 |
| 11 | `[Proxy]` 段一条**英国方向链式条目为孤儿**(无组引用、非任何条目的 `underlying-proxy` 目标) | W8-09 |
| 12 | **双独立收敛**:ProxyGFW 策略与 FINAL 同为 `Final` 组 ⇒ 域名侧 **99.7% 惰性**,仅 **18 条**做功(抢占后位 DIRECT)。**裁决:不删表**,重定位为「FINAL 策略保险层 + 防后位误直连层」 | W3-01 / W8-18 |

> 第 10、12 两项特别提示表述边界:**不得**写成「bilibili 资产丢失」(真域完好);**不得**写成「.cn 子条目都是死条目」(上游已折叠);ProxyGFW 的维护/再生验收改按 **18 条做功集**判定,**不按行数**判定。

### 1.4 本轮不能证明的部分

静态分析 + 一手网络证据可以证明语法、包含关系、规则序、确定误匹配与域名当前的注册/托管状态,但**不能**证明:

- 12.9 万条 `DOMAIN-SUFFIX` 当前是否仍属于某家公司、是否仍在使用;
- 任何一条规则的**实际命中量**(仓库当前没有把 Surge 命中日志回流成可分析数据的机制,这是本轮所有「删除类」建议的**共同缺口**);
- 非 CN 的 `GEOIP` 判定(离线引擎无 MaxMind 库,7 条非 CN GEOIP 一律判不匹配 —— 这是已登记的离线近似盲区,本轮实测触发 56 次);
- 任何需要「无 Surge 的大陆出口主机」才能做的直连可达性实测(本机增强模式 TUN 捕获一切,实测 `curl --noproxy '*' --resolve` 仍返回经代理结果)。

上述四项已全部转成 §7 的用户待决项或 §6 的 R4 观测项,**不以推断代替证据**。

### 1.5 基线快照(commit `e03c530`)

| 项目 | 值 | 来源 |
|---|---:|---|
| Git 分支 / 远端一致性 | `main`,`origin/main == HEAD`,工作区干净 | W7 |
| Surge 源规则 | **143,640** | W7 / W8 |
| 展开后有效规则(含 conf 内建) | **143,676** | W7 / W8 |
| 差值 36 的构成 | SYSTEM 20 + LAN 14 + `GEOIP,CN` + `FINAL` | W8-1.7 |
| `lists/` / `clash/` / 分发候选 | 34 / 34 / **69** | W7 / W8 |
| `DOMAIN-SUFFIX` | 129,706 | W8 |
| `IP-CIDR` / `IP-CIDR6` | 9,348 / 3,947 | W8 |
| `DOMAIN` / `DOMAIN-WILDCARD` | 503 / 90 | W8 |
| `IP-ASN` / `GEOIP` | 31 / 7 | W8 |
| `DOMAIN-KEYWORD` | **8** | W8 |
| `USER-AGENT` / `PROCESS-NAME` / `URL-REGEX` | **0 / 0 / 0** | W1–W8 一致 |
| `no-resolve` 修饰符 | 13,333 = IP 类总数 ⇒ **100% 覆盖** | W8 |
| `extended-matching` | conf RULE-SET 行 11 处;`lists/` 行级 **0** | W8 |
| audit 原始命中 | A1=0 A2=11 A3=0 A4=0 A5=0 A6=8 A7=0 A8=0 | W7 |
| audit 未豁免发现 | 3 条,**全 P3**(A6 关键词清单) | W7 |
| runsuite | 16 文件 / 147 场景 / 969 请求 / **1731 断言 / 失败 0 / 待修 0** | W7 |
| DNS 泄漏断言 | 674,失败 0 | W7 |
| audit selftest / engine selftest | 33/33 / 65/65 | W7 |
| `surge2clash --check` | 一致,34 表 / 143,640 条 | W7 |
| `collapse_cidr --check` | 11,090 → 11,090,无漂移 | W7 |
| allowlist | `exemptions` 30(其中 `preventive` 27)/ `forbidden` 130 | W7 / W8 |
| 跨表精确重复 | 11 条,**全部命中既有豁免,增量 0** | W8 |
| 前位后缀遮蔽(真·死条目) | **0** | W8 |
| 跨表 CIDR 包含 | 154 条,**跨策略仅 1 条**(结论正确但未登记) | W6 / W7 / W8 |
| 脱敏扫描 | 108 个跟踪文件;conf `[Proxy]` 节点名 **0 命中**、节点 IP/主机名 **0 命中** | W7 |

---

## 2. 上轮整改落实度汇总

上轮报告 `docs/RULES_AUDIT_AND_OPTIMIZATION_2026-08-31.md` 的整改项,本轮逐项核验结果:

### 2.1 总表

| 领域 | 核验项 | ✅ 完全落实 | ⚠️ 部分落实 | ❌ 未落实 |
|---|---:|---:|---:|---:|
| W1 生态代理表 | 8 | 7 | 1 | 0 |
| W2 流媒体/下载/游戏/AI | 9 | 7 | 2 | 0 |
| W3 Reject/Payment/区0/GFW | 9 | 7 | 2 | 0 |
| W4 地区表 | 8 | 5 | 0 | 3 |
| W5 国内侧 | 10 | 6 | 2 | 2 |
| W6 机器层 | 13 | 7 | 2 | 4 |
| W7 工程链路 | 23 | 19 | 1 | 3 |
| W8 conf 与横切 | 18 | 14 | 1 | 3 |
| **合计** | **98** | **72** | **11** | **15** |

**落实率 73.5%(72/98)**。未落实的 15 项**全部**是上轮标记为「属实但未做」的遗留大项,本轮的职责是把它们具体化为可执行方案,而不是重新发现一遍。

### 2.2 ✅ 完全落实(代表项,共 72 项)

| 类别 | 代表项 | 证据 |
|---|---|---|
| 关键词治理 | 104 → **8** 条(Reject 6 + `smp-device` + `sci-hub`);被删关键词全部入 forbidden 段 | W8 实测逐条吻合 |
| 三类型禁令 | 全库 `USER-AGENT`/`PROCESS-NAME`/`URL-REGEX` = **0**;A8 门禁经 22 条合成禁令样本注入验证真实有效 | W7 故障注入 |
| `no-resolve` | 13,333 条 IP 类规则 **100% 覆盖** | W8 |
| ChinaIP 折叠 | 22,417 → **11,090**,`--check` 0 漂移、`--verify` SHA 逐位等价;折叠漂移已进 `update.sh` pre-flight 闸门 | W6 |
| 控制面三态 | `VALIDATED_NOT_PUBLISHED` / `PUBLISHED_AND_VERIFIED` 退 0、`PUBLISHED_BUT_UNVERIFIED` 退 1;7 场景桩实测 | W7 |
| main 分支守卫 | 位于 `git add -A` 之前;临时 git 仓库实测 `feature/x` 分支正确中止 | W7 |
| purge 严格校验 | 12 组单元测试覆盖 12 种响应形态,非 JSON 不再降级成 `t=0` | W7 |
| 事务式派生 | `surge2clash.py` 全量校验→暂存→原子换入;未知类型出现在字母序最后一张表时,`clash/` 目录 md5 快照**逐字节未变** | W7 |
| runsuite schema | 上轮点名的 6 个假绿空洞 + 额外注入的 5 个,**11/11 全部堵死** | W7 |
| Clash 顺序 | `CONF_ORDER` 与 `Surge.conf` 的 34 条 RULE-SET **逐条同序、策略名逐字相同** | W3 / W7 / W8 |
| 归属迁移 | Cursor/Anysphere 全家 → AI;`cocacola.co.jp` → Japan;`snapkit.com` 全库归零;`digicert` → Domestic CA 段;`qwenlm.ai` → AI | W1 / W4 / W5 |
| 死条目清理 | ProxyGFW `sso.amazonaws.com` 已删;同表自遮蔽扫描 0 条(脚本已用该形态做正向对照) | W3 |
| 地区表覆盖 | 新增 `region_coverage.json`,4 个地区场景各 6 条请求(含负例);**34/34 表全部被至少 2 条请求触达** | W4 / W7 |
| 文档计数 | 34 表 / 69 文件 / 147 场景 / 1731 断言 / 674 DNS / 143,640 守恒在 README、ARCHITECTURE、MAINTENANCE、tests/README 全部一致 | W8 |
| 脱敏架构 | 三级查找机制存在、schema 五键完整、`live_check_local.json` 未被 git 跟踪;conf 节点名与节点 IP 全库 0 命中 | W7 |

### 2.3 ⚠️ 部分落实(11 项)—— 全部是同一个病

**11 项里有 8 项是同一个根因:按名单删除而不是按判据删除。** 上轮的整改动作精确执行了「删掉被点名的那几条」,但同判据的兄弟条目原样留在表里。

| 上轮项 | 做了什么 | 漏了什么 | 数量 |
|---|---|---|---:|
| 删 13 条多租户宽后缀 | 13 条具名项逐条 grep 验证 ABSENT ✅ | S3 区域端点族、`vercel.dev`/`vusercontent.net`、`r2.dev`、`file.core.windows.net`、`bitbucket.io`/`codeberg.page`、`repl.co`/`replit.app`/`replit.dev`/`hf.space`… | **321 + 40** |
| 删 14 条 SaaS 组件 | Trustpilot/Algolia/Optimizely/AdobeDTM/Kochava/OneTrust/CookieLaw/Conductrics 全库归零 ✅ | Freshdesk 8、Split.io 6、Gigya 3、Segment 1、Braze EU 1 | **19** |
| 删 Meta AWS `18.194.0.0/15` | 该行已删 ✅ | 同判据的 27 条杂段(SoftLayer 15 含一条 `/17`、AWS 动态 EC2 `/32` 8、LY Corporation 3、Google 1) | **27** |
| 删 Google `IP-ASN,396982` | 全库无 396982 ✅ | 同判据的 `IP-ASN,19527`(98.4% GCP 客户段)与 `IP-ASN,43515`(98.6%) | **2** |
| Reject 关键词 → 锚定通配 | 16 条改精确/通配 ✅ | `dnserror.*` / `hostingcloud.*` 是**前缀锚定**,静默丢失全部子域覆盖,而现有断言两种语义下都通过、测不出回退 | **2** |
| `sci-hub` 观察项 | 按裁决暂留 ✅ | 未设「零命中 N 天可删」的到期条件,每轮审计都要重新讨论 | 6 条关键词共性 |
| PKU↔ChinaIP 2 条重复登记豁免 | 已在 exemptions 以 F1 登记 ✅ | 豁免理由只写「同为 DIRECT 无功能影响」,**没覆盖新发现的归属错误**(`202.127.16.0/20` 属中科院 CSTNET,非北大) | 1 |
| 文档计数漂移修复 | 大面积修正 ✅ | `tests/README.md:216` 仍写「forbidden 18 条」(实 130,差 7 倍);`docs/DEVELOPMENT.md:205` 仍写「65 个文件」(实 69) | 2 |
| ChinaIP 跨表 CIDR 遮蔽 | 折叠后从 189+19+14+2 降到 154 ⚠️ | `audit.py` 的 `check_a4()` 只遍历 `domain_rules`,**完全不做 IP 段包含判定** ⇒ 154 条现有审计报不出来 | 154 |

> **结论**:再列一次名单只会在下一轮产生第三份名单。R2 的 A9/A10 就是为了把这 8 项变成**数据源保证的家族闭合**(PSL、云厂商 IP 快照、IANA TLD 表、前缀树)。

### 2.4 ❌ 未落实(15 项)—— 全部转入路线图

| # | 上轮项 | 本轮判定 | 去向 |
|---|---|---|---|
| 1 | Meta 运行域 / 防御注册库存拆分 | 属实,已给出 520 条逐条分档(R1 32 / R2 32 / O 28 / X 3 / N 14 / **D 411**) | R3 |
| 2 | DownloadCDN 从精确 allowlist 重建 | 属实,已给出 R1–R6 保留类 + X1–X5 禁收类蓝图 | R1(止血)+ 长期 |
| 3 | Streaming IP 面清理 | 属实,已给出 1,975 条逐条处置 CSV(D1–D6) | R4(shadow 7–14 天) |
| 4 | canonical owner 跨表竞争 | 属实且比上轮描述更严重:29 注册域 + 11 品牌,**8 个真实跨出口** | R1(档1/档3)+ R2(属地锁) |
| 5 | US 拆 MediaUS / FinanceUS | 不采纳拆表,改为「迁移到既有 Streaming」 | R2(依赖用户待决 1) |
| 6 | Europe GEOIP 范围口径 | 属实,已给出三方案(A 表头声明 / B 收窄到有出口的国家 / C 扩 EU 全集) | R2(方案 A) |
| 7 | ChinaDomain 44 条整 TLD 分层 | 属实,已按 IANA 注册局分 T0/T1/T2/T3 四档 | R3 |
| 8 | ChinaDomain 境外托管过滤 | 属实,已交付可运行原型 + 十道护栏 + 量化验收区间 | R3 |
| 9 | `sources.lock.json` | 属实,ChinaIP **今天就能锁**(SHA 逐位可重建),ChinaDomain 需先过两轮影子运行 | R3 |
| 10 | 跨表 CIDR 子网/超网检查纳入审计 | 属实,盲区已实证有内容 | R2(A9) |
| 11 | CI / 公共脱敏 fixture | 属实,唯一硬阻塞是 `runsuite.py` 缺 `--rules`(5 行) | R3(S1–S5) |
| 12 | `modules/` `scripts/` 不在发布候选集 | 属实但**当前无生产文件**,是潜伏项 | R2(加注释锚点,不扩 `DIST_RE`) |
| 13 | extended-matching 的 Mihomo sniffer 合同 | 属实,`clash/rule-providers.yaml` 与 `ARCHITECTURE §5.2` 均只字未提 | R2 |
| 14 | MicrosoftCN OneDrive/Office 归属裁决 | 属实,且**现已产生实际故障** | R1(止血)+ R2(裁决登记) |
| 15 | Domestic 拆 NetworkInfra/CA/ManualDomestic + PreGFW | **不采纳**(见 §5 反向澄清) | 改为门禁 + 场景断言 |

---

## 3. 系统性发现

本章按**机制**而非按表组织。八个主题各自给出:机制 / 证据 / 清单指针 / 修复方向。大清单不内嵌全文,只给统计 + 判定签名 + ≤20 条代表样本 + 完整清单所在 worker 报告文件名。

---

### 3.1 主题一 · 信任面缺陷(本轮最高优先级新类别)

#### 机制

规则表的每一条 `DOMAIN-SUFFIX` 都是一张**长期有效的白名单**,但域名的所有权是**会过期的**。当一个域被注销、被停放商接管、被第三方重注册,或者本来就是上游的拼写错误时,规则仍然生效 —— 而它此刻指向的是**别人的资产**。

危害与所在层直接相关:

| 所在层 | 危害 |
|---|---|
| 区 0(PrivateLAN / PKU,DIRECT) | 优先级高于 Reject ⇒ 抢注者获得一条**免疫全库拦截层**的直连白名单 |
| 区 1(Reject) | 死域删除后落 DIRECT(受 `DOMAIN-SUFFIX,cn` 兜底约束)⇒ 比不删更危险 |
| 区 2(GameDownloadCN,DIRECT) | 易主域被无条件直连 |
| 区 5–8(代理侧) | 停放页/变现页被送进代理组,浪费出口且是钓鱼落点 |

#### 证据

| 条目 | 位置 | 判定签名 | 级别 |
|---|---|---|---|
| `pkuiot.com` | `PKU.list:10`,**区 0 / DIRECT** | `whois` → **`No match`**;双侧 `dig` → NXDOMAIN。全库唯一「未注册域 + 最高优先级 + DIRECT」组合 | **P2 \| 确定** |
| `bdwm.net` | `PKU.list:4`,**区 0 / DIRECT** | GoDaddy 注册商 + `Domains By Proxy` 隐私注册人 + `*.DOMAINCONTROL.COM` NS + `/lander` 跳转 + AWS 停放 anycast。北大未名 BBS 现役入口是 `bbs.pku.edu.cn`,已被同表 `pku.edu.cn` 覆盖 | **P2 \| 确定** |
| `steambroadcast.com` | `GameDownloadCN.list:53`,**区 2 / DIRECT** | 2026-04-27 注册 / Registrar.eu / 注册人组织 Dynadot / Cloudflare NS;**真 Valve 域一律 MarkMonitor**;`curl -sI` → 301 → `https://faceit.com/`;不在任何上游源表内 | **P1 \| 确定,advisor 复核通过** |
| `origin-a.akamaihd.ne` | `ChinaDomain.list:119`,区 10 / DIRECT | 上游**拼写错误**(应为 `.net`),`.ne` 是尼日尔 ccTLD,当前无 NS ⇒ **任何人注册即可拿到一条 DIRECT 白名单** | **P1 \| 确定,advisor 复核通过** |
| `twimg.org` / `twimg.co` / `tellapart.com` | `Twitter.list:16 / :14 / :12`,区 5 / 代理 | 三者分别停在 NameCheap(2025-12-11 新注册)、ParkingCrew、Network Solutions;对照真 X 资产 SOA 一律 `a.uNN.twtrdns.net` 或 CSC Corporate Domains | **P2 \| 确定** |
| `telegramdownload.com` | `Telegram.list:30` | `ns1.abovedomains.com` + Trellian/DSParking `103.224.212.210`,HTTPS 200 但 `<title>` 就是域名本身 | **P2 \| 确定** |
| `courses.snapsolve.com` | `TikTok.list:5` | SOA = `ns1.sedoparking.com`,A = `64.190.63.222`(Sedo 停放服务器)。`§8` 登记的观察项**现在有硬证据** | **P2 \| 确定** |
| `zimuzu.tv` | `ChinaMedia.list:982` | `103.224.182.253` 属 Trellian/above.com 停放集群 | **P2 \| 确定** |
| `domesticmedia.com` | `ChinaMedia.list:342` | 2005-08-01 注册 / Wild West Domains,与 B 站**无关的第三方在册域**,被强制 DIRECT | **P2 \| 确定,advisor 复核通过** |
| `musespark.ai` | `Meta.list:457`,区 5 / 代理 | 2025-09-18 由自然人经 GNAME 注册;TLS issuer = Google Trust Services;NS 在 Cloudflare(非 AS32934)。是**当前在线的第三方 AI 产品**,被 Meta 表抢在 AI 表之前吞掉 | **P1 \| 确定** |
| `crowdtangle.com` / `fbf8.com` | `Meta.list:34 / :305` | **悬空的 Route53 委派** —— 任何人创建同名托管区并抽中相同 NS 组即可接管解析 | **P3 \| 确定** |

规模型证据(需按判据批处理,不逐条列):

| 集合 | 条数 | 判定签名 | 完整清单 |
|---|---:|---|---|
| Meta 自持防御/库存停放域 | **411** | NS ∈ {`a-d.ns.facebook.com`, `ns.instagram.com`, `ns.whatsapp.net`} 或 Registrar = `RegistrarSEC LLC`;A = `57.144.220.141` / `57.144.221.141`;**HTTPS 无可用证书**;HTTP 301 回自身 https 后断链 | `reference/audit-v2-20260831/reports/W1-ecosystem.md` §3.8 |
| Meta 无委派 / 死区 | 14 | SERVFAIL / NXDOMAIN / 悬空委派 | `reference/audit-v2-20260831/reports/W1-ecosystem.md` §3.6 |
| Reject 已死域 | **61**(62 减去须保留的 `ad.xiaomi.com`) | 双侧(`@8.8.8.8` + `@1.1.1.1`)一致 NXDOMAIN,且子域同样不存在 | `reference/audit-v2-20260831/reports/W3-reject-special.md` W3-07 |
| ProxyGFW 已死域 | **769**(642 NXDOMAIN + 127 权威失效) | 全量扫描(非抽样)双侧一致;TLD 分布 `com 224 / org 114 / net 86 / info 23 / hk 17 / me 15 / tw 12`;**`.cn` 0 条** | `reference/audit-v2-20260831/w3/gfw_nx.txt`(642)+ `gfw_servfail.txt`(127) |
| ChinaDomain 死域(无 A 记录) | 约 **14,184**(13.35%,95%CI 11.93–14.91%) | 系统抽样 n=2000 外推 | `reference/audit-v2-20260831/reports/W6-machine-tables.md` §3.2 |
| 各生态表死条目 | 25 | NXDOMAIN / SERVFAIL / 委派失效,双侧一致 | `reference/audit-v2-20260831/reports/W1-ecosystem.md` W1-012 |

代表样本(Reject A 组 41 条中的前 20 条,**删除后落 FINAL,可安全清理**):

```
dnspod.meituan.httpdns.start.qcloud.com   httpdns-v6.gslb.yy.com   httpdns.qcloud.com
186078.com   189key.com   285680.com   51chumoping.com   5vl58stm.com   91veg.com
baiwanchuangyi.com   beilamusi.com   benshiw.net   brdtest.co   cishantao.com
daitdai.com   dsaeerf.com   fkku194.com   goupaoerdai.com   gzxnlk.com   ichaosheng.com
```

完整 41 条 + 必留 20 条 `.cn` 清单见 `reference/audit-v2-20260831/reports/W3-reject-special.md` W3-07。

#### 关键约束:`DOMAIN-SUFFIX,cn` 陷阱

**确定,advisor 复核通过**:`ChinaDomain.list:22497` 是整条 `DOMAIN-SUFFIX,cn`(上游已折叠 .cn 子项,表内无其他 .cn 条目)。因此:

```
删掉一条已死的 .cn Reject 条目
  → 该域被重新注册后,落点从 REJECT 直接变成 DIRECT
  → 比不删更危险
```

实测验证:`python3 tests/engine.py match sifuXX.cn` → `DIRECT | ChinaDomain.list | DOMAIN-SUFFIX,cn`;`match notinlist.com` → `Final | Surge.conf | FINAL`。

同构形态还有三处 —— ProxyGFW 的 18 条承载集与 769 条死域清单的交集恰好是 `666pool.cn`(SERVFAIL)、`hasi.wang`(NXDOMAIN)、`bbs.tuitui.info`(NXDOMAIN)。**「承载」与「删了会掉进 DIRECT」是同一件事**:它们之所以承载,正是因为后位 ChinaDomain 有更宽的兜底(`cn` / `wang` / `tuitui.info`)会接住它们。**存活过滤器必须加承载集豁免。**

> 表述边界:**不得**写成「.cn 子条目都是死条目」。上游已把 .cn 子项折叠进整条 `DOMAIN-SUFFIX,cn`,表内不存在其他 .cn 条目。

#### 修复

| 动作 | 批次 |
|---|---|
| 删除 `pkuiot.com` / `bdwm.net` / `pkuecon.cn` / `IP-ASN,24355` / `202.127.16.0/20`(区 0 清理,同批收窄 F1 豁免) | R1 |
| 删除 `steambroadcast.com` 并入 forbidden 防回流 | R1 |
| 删除 `twimg.org` / `twimg.co` / `tellapart.com` / `twitteroauth.com` / `telegramdownload.com` / `courses.snapsolve.com` / `bytedance.net` / `musespark.ai` / `zimuzu.tv` / `domesticmedia*` 11 条 | R1 |
| Reject A 组 41 条安全死域清理 + 同步改 `reject_layer.json` 3 条断言 | R1 |
| Meta 411 条 D 档迁 `reference/` 本地库存档;X 3 + N 14 直接删 | R3 |
| ProxyGFW 769 条死域分批(承载集交集 3 条除外)并入再生过滤器 | R3 |
| **A13 信任面检查**周期化:NXDOMAIN / 未注册 / 停放签名 / 易主检测,对 DIRECT 侧与 Reject 例外域优先 | R4 |
| `§8` 新增裁决:「区 0 表(PrivateLAN/PKU)禁收未注册域」 | R2 |

---

### 3.2 主题二 · 家族闭合失败(上轮方法论缺陷)

#### 机制

上轮的整改动作是**枚举式**的:「删掉这 13 条宽后缀」「删掉这 14 条 SaaS 组件」「删掉这条 AWS `/15`」「删掉 `IP-ASN,396982`」。每一条都精确执行了 ✅,但**判据本身没有被固化**,所以同判据的兄弟条目原样留在表里。

```
上轮:判据 → 人工枚举出 N 条 → 删 N 条 → 判据丢失
本轮:判据 → 数据源(PSL / 云 IP 快照 / IANA TLD / RIR RDAP)→ 门禁持续强制
```

#### 证据 —— 六个家族

**① AWS S3 区域端点族(P1 | 确定,advisor 复核通过)**

- **advisor 复现口径:`DownloadCDN.list` 残留 321 条 `s3[.-]*.amazonaws.com` 区域后缀。**
- worker 侧分形态计数(`reference/audit-v2-20260831/reports/W2-media-download.md` D-01):

| 形态 | 条数 | 覆盖对象 |
|---|---:|---|
| `s3.<region>.amazonaws.com` | 86 | 该 region **任意** bucket |
| `s3-website.<region>.amazonaws.com` | 67 | 任意租户的 S3 静态站(等同 `github.io` 类) |
| `s3-accesspoint.<region>.amazonaws.com` | 62 | 任意 Access Point |
| `s3-object-lambda.<region>.amazonaws.com` | 31 | 任意 Object Lambda |
| `s3-fips.<region>` / `s3-accesspoint-fips.<region>` | 30 | 同上 FIPS 变体 |
| `s3-deprecated.<region>` | 4 | 同上 |
| 小计(S3 区域端点族) | **280** | |

- **口径差异**:worker 的 280(仅 S3 区域端点族)/ 278(PSL 命中子集)/ 318(PSL 边界后缀合计,含其他平台 40 条)与 advisor 的 321(`s3[.-]*.amazonaws.com` 全形态正则)不同。**以 321 为准**;执行时以脚本重算并把判定签名写进 forbidden,不以任何一份人工计数为最终依据。
- **语义等价证明**:`<bucket>.s3.us-east-1.amazonaws.com` 与 `<bucket>.s3.amazonaws.com` 是同一 bucket 的两种寻址形式。后者已在 forbidden 段(命中即 P0),前者仍在表中生效。且 PSL 的 **PRIVATE 段**收录了全部 `s3*.<region>.amazonaws.com` 形式 —— 即官方认定它们是**注册边界**,后缀之下是互不相关的租户。
- **正面样板**:`AI.list:21 ppl-ai-file-upload.s3.amazonaws.com` —— 平台上的第一方资产用**精确 host** 收进对应生态表,正是 `§8` 要求的写法。

**② 其他多租户平台后缀(P1 | 确定)—— 40 条**

代表样本(≤20 条,完整清单见 `reference/audit-v2-20260831/reports/W2-media-download.md` D-02):

| 文件:行 | 规则 | 已禁收的同族兄弟 |
|---|---|---|
| `DownloadCDN.list:5306` | `vercel.dev` | `vercel.app` |
| `DownloadCDN.list:5350` | `vusercontent.net` | 同族(Vercel v0 用户内容) |
| `DownloadCDN.list:3990` | `r2.dev` | `pages.dev` / `workers.dev` |
| `DownloadCDN.list:1854` | `file.core.windows.net` | `blob.core.windows.net` |
| `DownloadCDN.list:494` | `bitbucket.io` | `github.io` / `gitlab.io` |
| `DownloadCDN.list:1292` | `codeberg.page` | 同上 |
| `DownloadCDN.list:201` | `app.render.com` | `onrender.com` |
| `DownloadCDN.list:452` | `azurestaticapps.net` | `netlify.app` 等 |
| `DownloadCDN.list:1391` | `csb.app`(CodeSandbox) | 同类多租户应用托管 |
| `DownloadCDN.list:5354/5355` | `w-corp-staticblitz.com` / `w-credentialless-staticblitz.com` | 同上 |
| `DownloadCDN.list:2844/5349/4939` | `linodeobjects.com` / `vultrobjects.com` / `storage.yandexcloud.net` | `digitaloceanspaces.com` |
| `DownloadCDN.list:2755` | `js.org` | 多租户子域托管 |
| `DownloadCDN.list:4012` | `readthedocs.io` | 多租户文档托管 |
| `DownloadCDN.list:1218/1251/1715` | `cf-ipfs.com` / `cloudflare-ipfs.com` / `dweb.link` | 公共 IPFS 网关(任意 CID) |
| `AI.list:297/303/305` | `repl.co` / `replit.app` / `replit.dev` | `vercel.app`(结构完全同构) |
| `AI.list:173` | `hf.space` | 同上(任意用户 Space) |
| `AI.list:370` | `windsurf.build` | 同上 |

**明确保留、不属此类**(注册人唯一,须写进 exemptions 防误删):`AI.list:81 claude.app`、`:88 claudeusercontent.com`、`:254 oaiusercontent.com`(第一方用户内容域)、`Streaming.list:160 bbc`(品牌 gTLD,与 `.google`/`.goog` 裁决同理)、`UK.list:4/12/23 ac.uk`/`gov.uk`/`nhs.uk`(**注册人按政策限定为英国机构,属地归属充分**,与多租户禁收不同源;`co.uk` 刻意不整体收录)、`Japan.list:7 au.com`(实测 KDDI 自有、**不在 PSL**,勿按 `uk.com`/`eu.com` 类比删除)。

**③ 通用 SaaS 组件残留(P2 | 确定)—— 19 条**

| 服务 | 行 | 规则 |
|---|---|---|
| Freshdesk(客服) | 411, 414, 416, 420, 423, 426, 810, 5524 | `assets{10,2,3,5,7,9}.freshdesk.com`、`cdn.freshdesk.com`、`DOMAIN-WILDCARD,assets*.freshdesk.com` |
| Split.io(特性开关) | 433, 1023, 1801, 4510, 4957, 5016 | `auth.` / `cdn.` / `events.` / `sdk.` / `streaming.` / `telemetry.split.io` |
| **Gigya(SAP CIAM 身份)** | 823, 1193, 5539 | `cdn.gigya.com`、`cdns.gigya.com`、`DOMAIN-WILDCARD,cdns.*.gigya.com` |
| Segment(CDP) | 1000 | `cdn.segment.com` |
| Braze EU | 5557 | `DOMAIN-WILDCARD,sdk.*.braze.eu`(而 `braze.com` **已入 forbidden**,漏了 `.eu` 变体) |

Gigya 尤其值得注意 —— 它是**身份认证**组件,绑到下载出口意味着任意使用 SAP CIAM 的站点登录走「下载」组。

**④ Meta IP 区非 Meta 空间(P1 | 确定)—— 27 条 / 36,176 个地址**

`Meta.list:526-566` 共 41 条 IPv4,其中 27 条不属于 Meta。交叉验证方式:RIPEstat 取 AS32934+54115+63293 的 344 条 v4 / 426 条 v6 通告前缀,这 27 条**无一落在其中**,其余 14 条全部命中。

| 组 | 条数 | 实际所有者 | 地址数 |
|---|---:|---|---:|
| IBM SoftLayer(含 `184.173.128.0/17`) | 15 | NETBLK-THEPLANET / SOFTLAYER-* | 33,088 |
| AWS 动态 EC2 `/32` | 8 | Amazon Technologies Inc. | 8 |
| **LY Corporation(Yahoo Japan / LINE)** | 3 | `119.235.224.0/24`、`119.235.232.0/24`、`119.235.236.0/23` | 1,024 |
| **Google** | 1 | `108.177.8.0/21`(ARIN `108.177.0.0/17` = GOOGLE) | 2,048 |
| 合计 | **27** | | **36,176** |

`108.177.8.0/21` 还是**确定的死条目**:`Google.list:702 IP-ASN,15169` 位次在前且 AS15169 通告 `108.177.0.0/17` ⊇ 该 `/21`。

LINE 三段由 **W1-002 与 W3-15 双独立收敛**(W3 在做 ProxyGFW IP 区分析时,发现 ProxyGFW 的 `119.235.224.0/21` 被前位 Meta 的 `/24` 局部截胡才暴露)。**裁决:删除**。

同批还有两条**覆盖不足**:`Meta.list:553 129.134.0.0/17` 与 `:554 157.240.0.0/17` 只覆盖各自 `/16` 的前一半,而 ARIN 两个 `/16` 整段 netname 均为 THEFA-3(Facebook)⇒ 合并为 `/16`,条数不增、覆盖翻倍、无过捕获。另需补录 Meta 现役主力段 `57.144.0.0/14`(`facebook.com` 当前落点 `57.144.220.1`,RIPE netname `FB-BLOCK` / org Meta Platforms Ireland Limited)。

**⑤ 同判据 ASN(P2 | 高置信)—— 2 条**

`§8` 裁决「Google | `IP-ASN,396982` 勿收(GCP 通告**客户**前缀所用 ASN)」。用同一把尺子(Google 公布的 `34.0.0.0/8`、`35.184–35.247`、`104.196/14`、`130.211/16`、`146.148/17` 等 GCP 段):

```
AS15169 GOOGLE      : 1233 v4 前缀 / 4,198,656 地址,GCP 段 239 条 = 3,080,960 (73.4%)  ← 既有裁决接受的代价，不动
AS19527 GOOGLE-2    :  258 v4 前缀 / 2,734,080 地址,GCP 段 191 条 = 2,689,536 (98.4%)  ← Google.list:703,应删
AS43515 YOUTUBE(IE) :  189 v4 前缀 / 2,671,872 地址,GCP 段 155 条 = 2,633,216 (98.6%)  ← Google.list:705,应删
AS36040 YOUTUBE     :   85 v4 前缀 /    22,016 地址,GCP 段   0 条 =         0 ( 0.0%)  ← 全是 ISP 内嵌 GGC 缓存,应迁 YouTube.list
```

**本条不与裁决冲突,是把同一裁决补齐到漏掉的两个 ASN。**

**⑥ Streaming IP 面(P1 | 确定)—— 1,975 条中仅 19 条经得起所有权检验**

| 处置 | 条数 | 覆盖地址 | 判据 |
|---|---:|---:|---|
| **D1 DELETE-CLOUD** | 1,090 | 5,619,710 | 完整落入 AWS/GCP/Azure **已发布服务地址段**(独立复现上轮 1,089 条 AWS 交集,地址数逐位一致;另发现上轮遗漏的 GCP 1 条) |
| **D2 KEEP-FIRSTPARTY** | **19** | 132,352 | 起源 ASN 或 RIR NetName 属流媒体服务本体(Netflix AS2906/40027、Hulu AS23286、DAZN AS199710) |
| **D3 DELETE-SHAREDCDN** | 12 | 132,102 | 共享 CDN/云(Akamai AS20940 ×11 含 `23.78.0.0/16`;Amazon `54.0.0.0/16`) |
| **D4 DELETE-THIRDPARTY-BLOCK** | 12 | 147,712 | ≥`/24` 且落在他人网内(StarHub `203.116.0.0/16`、HKT 四段合计 47,104 地址、iboss `/17`…) |
| **D5 OBSERVE-EMBEDDED-CACHE** | 836 | 868 | `/30`–`/32`,分布在 **149 个第三方 ISP** 内的异构嵌入式缓存(反查证明混杂 Netflix OCA、Google GGC、Akamai AANP,乃至 Virgin Media **未分配住宅地址池** `host62-252-213-84.not-set-yet.virginmedia.com`) |
| **D6 MOVE-WRONG-OWNER** | 6 | 5,376 | 第一方但非流媒体主体(Kakao,APNIC netname `DAUMKAKAO`;其中 4 条 `/22` 当前**未在全球 BGP 通告**) |
| 合计 | **1,975** | **6,038,120** | |

清理后 Streaming IPv4 面从 1,975 条 / 603.8 万地址降到 **19 条 / 13.2 万地址**。逐条 CSV:`reference/audit-v2-20260831/w2/streaming_ip_disposition.csv`(1,975 行);可重跑脚本 `cidr_classify.py` → `noncloud_analyze.py` → `streaming_disposition.py`。

#### 统一判别式(建议写入 `ARCHITECTURE.md`)

> 云上 IP 段**可收**,当且仅当:(a) 该前缀**不在**云厂商公开的服务地址快照内(AWS `ip-ranges.json` / GCP `cloud.json` / Azure ServiceTags);**且** (b) RIR whois / RDAP 显示为业务方的**专属再分配或直接分配**。
> 「由云厂商 ASN 通告」**不构成**收录依据。

反例已双向验证:`AI.list` 的 `216.73.216.0/22` 同样由 AS16509 通告,但**不在** `ip-ranges.json` 内、RDAP `name=AWS-ANTHROPIC / Anthropic, PBC` ⇒ BYOIP 专属再分配,**正确保留**;而 1,089 条 Streaming CIDR 同样由 AS16509 通告但落在服务快照内 ⇒ **不可收**。

`AI.list` 的 5 条 IP-ASN + 4 条 CIDR **全部经 RDAP 验证为第一方**,是全库 IP 规则的**正面样板**(AS399358/400243/401551 = Anthropic 三个 ASN、AS401518/401864 = OpenAI;`153.61.0.0/16` ARIN AP-2440 Anthropic 新分配未通告;`160.79.104.0/21` 整 `/21` 分配给 Anthropic 后由三家云 BYOIP 通告)。

#### 修复

| 动作 | 批次 |
|---|---|
| 删 321 条 S3 家族 + 40 条其他 PSL 边界后缀 + 19 条 SaaS 组件;同批把族模式写进 forbidden | R1 |
| 删 Meta IP 区 27 条(含 LINE 3 段)+ 合并两条 `/17` → `/16` + 补录 `57.144.0.0/14` | R1 |
| 删 `IP-ASN,19527` / `IP-ASN,43515`;`IP-ASN,36040` 迁 YouTube.list | R1 |
| **A10 · 单标签后缀与 PSL 边界门禁**上线:PSL 快照哈希入库,`DOMAIN-SUFFIX` 命中 PSL(ICANN 或 PRIVATE)即报,例外走 exemptions 逐条登记 | R2 |
| Streaming IP 面 D1/D3/D4 删除 + D5 观察 + D6 迁 Kakao,CSV 驱动、shadow 7–14 天 | R4 |

---

### 3.3 主题三 · 裁决-机器脱节

#### 机制

`docs/MAINTENANCE.md §8` 是本项目的**裁决登记**,记录了「这个域为什么不收」「这条为什么刻意保留」。但**裁决是自然语言,机器读不到**。当前只有两条通路能把裁决变成强制:`tests/allowlist.json` 的 `forbidden` 段(A8 门禁)和 `tests/scenarios/` 的断言。

本轮实测这两条通路的覆盖率:

```
§8 + D11 的「明确禁收 / 已删勿收回 / 勿单列」裁决:  34 条
其中已进入 forbidden 段:                           0 条   ← 覆盖率 0%
```

**确定,advisor 复核通过**:advisor 用 `bolt.com` / `revolut` / `sony.com` / `cloudflareinsights` 等 8 个代表项逐一验证 NOT-in-forbidden。现有 130 条 forbidden 覆盖的是「三类型全禁 + 已删关键词 + 多租户/SaaS 宽后缀」,与 `§8` 的裁决清单是两个不相交的集合。

#### 证据 —— 四个具体脱节点

**① 34 条禁收裁决 0 入表(P2 | 确定,advisor 复核通过)**

| 登记出处 | 规则模式 | 需要 file 作用域? |
|---|---|---|
| D11 排除表 | `DOMAIN-KEYWORD,stripe` | 否 |
| §8 AI | `bolt.com`、`static.cloudflareinsights.com`、`sso.amazonaws.com` | 否 |
| §8 Games | `sony.com`、`IP-CIDR,35.192.0.0/12` | 否 |
| §8 Meta | `llama-api.com`、`metaquest.com`、`horizonworlds.com`、`IP-CIDR,18.194.0.0/15` | 否 |
| §8 Google | `IP-ASN,396982` | 否 |
| §8 Payment ×7 | `revolut.com`、`remitly.com`、`westernunion.com`、`moneygram.com`、`worldline.com`、`shop.app`、`checkout.shopify.com` | 否 |
| §8 Domestic 已删域 ×7 | `id6.com`、`mi-idc.com`、`jstarkan.com`、`mrw.so`、`sifou.com`、`lancdn.com`、`oneplus.net` | **`not_file`**(已转 ProxyGFW) |
| §8 ChinaDomain 17 删域 | `mojie.kim`、`mojieai.com`、`springerlink.com`(另 14 条已转 ProxyGFW) | **`not_file`** |
| §8 Microsoft | `DOMAIN-SUFFIX,microsoft.com` | **`file`**(ProxyGFW 内合法) |
| §8 TikTok | `cocacola.co.jp` | **`file`**(Japan.list 内合法) |
| §8 Streaming | `akamaized.net` / `akamaihd.net` | **`file`**(见 ④) |

**根因之二**:`check_a8` 只按 `pattern` 做 fnmatch 全库匹配,**无 `file` 作用域** ⇒「勿搬进 Microsoft.list」「勿回 Domestic」「勿单列(但宽兜底是对的)」这类**表内禁令根本无法表达**,写进去会误伤当前正确的条目。修法是给 forbidden 加两个可选键(向后兼容,缺省保持全库语义),`check_a8` 改动 ≤ 8 行:

```json
{"pattern": "DOMAIN-SUFFIX,microsoft.com", "file": "Microsoft.list",
 "reason": "§8 Microsoft:整条搬进 Microsoft.list 会一次性遮蔽 MicrosoftCN 45 条国内直连域"}
{"pattern": "DOMAIN-SUFFIX,linux.do", "not_file": "ProxyGFW.list",
 "reason": "§8 Domestic:已转 ProxyGFW,回流到直连层即恢复投毒域直连必超时"}
```

**② `kw_direct.json` 定时炸弹(P2 | 确定,advisor 复核通过)**

`§8` 登记「约 26 域再生时自然回收为 DIRECT,**属预期,勿当回归**」,但 `tests/scenarios/kw_direct.json:69,95,96,125,188-191,209` 有 9 条断言把这些 host 写死为 `Final`。实测其中 **6 条会真回收**:

| host | 在当前上游 | 在 pin `65e8adf` | `@223.5.5.5` A 记录 | 再生后落点 |
|---|---|---|---|---|
| `51drv.com` | 有 | 有 | 无 A | **DIRECT(断言翻转)** |
| `eqoavtbu.com` | 有 | 有 | 无 A | **DIRECT(翻转)** |
| `githubim.com` | 有 | 有 | `62.234.8.38`(腾讯云 CN) | **DIRECT(翻转)** |
| `githubshare.com` | 有 | 有 | `82.157.34.245`(腾讯云 CN) | **DIRECT(翻转)** |
| `hellogithub.com` | 有 | 有 | `117.50.220.24`(UCloud CN) | **DIRECT(翻转)** |
| `kkgithub.com` | 有 | 有 | `43.161.236.178`(腾讯云 CN) | **DIRECT(翻转)** |
| `bilibilihelper.com` / `blbilibili.com` / `qiyikeji.com` | 无 | 无 | — | Final(断言仍成立) |

后果是一个死结:**按文档做正确的事(再生)就会打红 runsuite,`update.sh` 闸门 B 中止发布**。这也是唯一一条**必须在下一次发布之前修掉**的项(见 R0)。

修法:6 条断言从「期望 `Final`」改成 `policy_in` 双态可接受,reason 引 `§8`。**不要**为了让断言变绿把这 6 域手工钉进 ProxyGFW —— 它们实测都在国内云上,DIRECT 才是对的。

**③ `check_a8` 大小写敏感(P2 | 确定)**

`audit.py` 的 A7/A8 对规则类型**大小写敏感**,而 `engine.py:510` 与 `surge2clash.py:124` 都做 `.upper()`。合成注入 `user-agent,LowerCaseUA*` 与 `process-name,LowerCaseProc`:A7 报 2 条(判为「无类型前缀的裸行」)、**A8 = 0 命中**。后果:本应是 P0/forbidden 回流,实际报成 P1/format;`--fail-on P1` 仍能拦住,但任何一次把闸门放宽到 `--fail-on P0` 就变成真正的 P0 绕过。且 A7 的 evidence 文案写「离线引擎会**静默忽略**此行」,**对本仓库自己的引擎就是假的**。

**④ `§8` akamai 措辞自相矛盾(P3 | 高置信)**

`MAINTENANCE.md:308`(Streaming 行)明写「`akamaized.net`/`akamaihd.net` 宽后缀**仍禁收**」,而 `ProxyGFW.list:242-244` 有三条 `akamai.net` / `akamaihd.net` / `akamaistream.net` 活着,且无任何 allowlist 条目或 `ARCHITECTURE` 裁决背书(铁律里「刻意分层兜底」只列了 `amazonaws.com` / `microsoft.com` / `azureedge.net`)。

**裁决:按 D6 同构处理** —— 补登记为「刻意分层兜底」,**不删**;`§8` 措辞收敛为「`akamaized.net`/`akamaihd.net` 宽后缀禁止**新增**收录,存量 GFW 兜底条目按 D6 登记」。当前无实际误分流(区 9/10 的 Akamai 条目全是 `akamaized.net`,不被这 3 条覆盖;引擎逐条裁定 9 个候选域全部落 DIRECT);风险是前瞻性的 —— 下次 ChinaDomain 上游再生若引入任意 `*.akamaihd.net` 的 CN host,会被区 8 抢跑成 `Final`。好消息是 A4 会把「直连区被代理区遮蔽」判 P0,闸门能拦住。

**⑤ 文档打码(P3 | 确定)**

`MAINTENANCE.md:244` 在**公开仓库**里逐字写出了带厂商标识的备份 conf 文件名,而 `ARCHITECTURE D9` 明写「文件名带厂商标识故不入库」—— 文件本身确实没入库,但**文件名承载的正是 D9 要保护的那条信息**。同批 `tests/live_check.py:1358` 的注释以某线路商网段名作为示例。

W7 从本地覆盖档提取 28 个线路商/机房/组名 token 对 108 个跟踪文件全量扫描,16 个 token 有命中,逐条判读后 **14 个是第三方域名里的巧合子串、2 个是真命中**(即上述两处)。conf `[Proxy]` 段的 22 个节点名与 15 个节点 IP/主机名 → **0 命中**。

#### 修复 —— 一条流程红线

> **`§8` 裁决登记必须伴随 `forbidden` / 断言落地。** 一条裁决如果只写进文档而没有对应的机器强制(forbidden 条目、场景断言、或 audit 判据),视为**未完成**。

| 动作 | 批次 |
|---|---|
| `kw_direct.json` 6 条断言改 `policy_in` 双态 | **R0** |
| `MAINTENANCE.md:244` 与 `live_check.py:1358` 打码 | **R0** |
| forbidden 加 `file` / `not_file` 两个可选键 + `check_a8` ≤8 行改动 + 补 selftest S34/S35 | R2 |
| 34 条禁收模式入 forbidden(带作用域) | R2 |
| A7/A8 类型段统一大写归一 | R2 |
| `§8` 补登记本轮全部裁决(见 §5 与 §8.4) | R2 |

---

### 3.4 主题四 · DIRECT 侧投毒故障(用户可感,674 断言盲区)

#### 机制

现有的 674 条 DNS 泄漏断言守的是「**IP 类规则必须带 `no-resolve`**」,防的是「代理目标被本地解析」。但存在**第二条盲区路径**:

```
域名被强制 DIRECT
  → DIRECT 连接由本机 DNS 解析
  → 国内递归返回被投毒的 IP
  → 连接必失败
```

这条路径上,`no-resolve` 是无关的、674 条断言是看不见的。**这不是「IP 规则缺 no-resolve」问题,而是「强制 DIRECT ⇒ 本地解析」这条路径上的盲区。**

#### 证据 —— OneDrive 个人版实测不可用(P1 | 确定,advisor 复核通过)

`MicrosoftCN.list:35 DOMAIN-SUFFIX,live.com` 位于区 7(先于 ProxyGFW 区 8),把被投毒的 `*.onedrive.live.com` 打成 DIRECT。

```
# 双侧解析对比（+tcp，绕开本机 fake-IP）
dig +tcp @223.5.5.5 onedrive.live.com          → 108.160.167.159 / 108.160.170.33 / 103.252.115.53  （Dropbox 段/毒 IP）
dig +tcp @114.114.114.114 onedrive.live.com    → 202.160.130.117                                     （毒 IP）
dig +tcp @8.8.8.8  onedrive.live.com           → 13.107.139.11                                        （真 Microsoft）
dig +tcp @223.5.5.5 skyapi.onedrive.live.com   → 157.240.20.18 / 88.191.249.182                       （Meta 段/毒 IP）
dig +tcp @223.5.5.5 photos.onedrive.live.com   → 157.240.12.35                                        （Meta 段）
dig +tcp @223.5.5.5 snapshot.onedrive.live.com → 108.160.169.54                                        （Dropbox 段）

# 当前规则下实测（经 Surge）
curl https://onedrive.live.com/          → code=000  t=10.0s （超时）
curl https://skyapi.onedrive.live.com/   → code=000  t=10.0s （超时）
curl https://login.live.com/             → code=200  （Microsoft.list → 代理组，正常）

# 绕过代理、指定真实 IP 直连（证明「IP 可达、只是 DNS 被毒」）
curl --noproxy '*' --resolve onedrive.live.com:443:13.107.139.11  → code=403 t=0.65s ✅
curl --noproxy '*' --resolve onedrive.live.com:443:108.160.167.159 → code=000 t=0.18s ❌
```

同批扫描的 23 个 `live.com` / `office.com` / `msn.com` / `onedrive.com` host 中,**只有这 4 个被毒**;其余(`office.live.com` / `view.officeapps.live.com` / `mail.live.com` / `c.live.com` / `al.msn.com` / `support.office.com` …)CN 与 INTL 解析一致,DIRECT 正确。

**修法**:在 `Microsoft.list`(区 5,先于 MicrosoftCN 区 7)加一条 `DOMAIN-SUFFIX,onedrive.live.com`,归 Google-X-Meta-MS —— 与已在同表的 `login.live.com` 同出口,顺带把 OneDrive Consumer 的「登录 + 前门 + API」收进同一会话。

- **不要**改 MicrosoftCN 的 `live.com`(会连带把 20+ 条正常直连域推去代理);
- **不要**放 ProxyGFW(位次在 MicrosoftCN 之后,写了不生效)。

#### 证据 —— ChinaDomain 侧的同类

**① 4 条 `DOMAIN` 精确条目 CN 侧被投毒(P1 | 确定,advisor 复核通过)**

CN 侧返回与业务无关的大厂网段,`@8.8.8.8` 侧完全不同:

```
live.streamingfast.net      → 国内 108.160.170.43 污染池   vs  境外 211.21.19.128
hls-1.wamu.org              → 192.133.77.59  (AS13414 Twitter)
wowza-stream.wbur.org       → 199.59.149.232 (Twitter)
1-fss24-s0.streamhoster.com → 202.160.129.37 (Twitter)
```

**② 沉默失败实例**:`chinacourt.org` 在 `223.5.5.5` 返回 `11.11.11.11`(AS749 DoD);`4abb.com` 返回 `127.0.0.1`。这类 bogon 答案 DIRECT 之后是**无声超时**。

**③ 171 条 `DOMAIN` 精确条目全量普查(P1 | 确定)**

`ChinaDomain.list:5-175` 是上游 ChinaMax 的境外 IPTV/流媒体源站清单,不是国内域名:

| 判定 | 条数 | 占比 |
|---|---:|---:|
| OFFSHORE(境外托管) | 77 | 45.0% |
| NO_A(域已死) | 56 | 32.7% |
| CN_HOSTED + MIXED(**真国内**) | **22** | **12.9%** |
| OFFSHORE(港台) | 12 | 7.0% |
| POISON_SUSPECT | 4 | 2.3% |

代表样本(境外托管 77 条中的前 20 条,完整清单见 `reference/audit-v2-20260831/reports/W6-machine-tables.md` F-02(b)):

```
14033.live.streamtheworld.com   19183.live.streamtheworld.com   22283.live.streamtheworld.com
aljazeera-eng-hd-live.hls.adaptive.level3.net   amdlive-ch03-ctnd-com.akamaized.net
analytics.strava.com   as-hls-ww-live.akamaized.net   cdn-videos.akamaized.net
hls.kqed.org   hls.wlrn.mobi   ip.istatmenus.app   jpts.sinovision.net
ksn-cinfo.geoksn.kaspersky.com   ksn-verdict.geoksn.kaspersky.com   livecdn.fptplay.net
movie.mcas.jp   origin-a.akamaihd.ne   stream.houstonpublicmedia.org
stream.wbez.org   www.filmon.com
```

**明确保留的 22 条**:卡巴斯基 KSN 中国节点(`*.geoksn.kaspersky.com` 落 `119.255.133/24`)、`activation-v2.kaspersky.com`、高通授时(`qcomgeo2.com` / `xtracloud.net`)等,确实是国内落地面。

#### 修复

| 动作 | 批次 |
|---|---|
| `Microsoft.list` 加 `DOMAIN-SUFFIX,onedrive.live.com` + 4 条正例 + 3 条负例断言 | R1 |
| ChinaDomain 4 条投毒 `DOMAIN` 并入再生过滤器 seed(语义等同已删的 17 条,建议同样转 ProxyGFW) | R1 / R3 |
| **`live_check.py` 增「DIRECT 域双侧解析分歧」检测**:对所有落 DIRECT 的宽后缀展开代表 host 清单,双侧 `dig +tcp` 比对;CN 侧落入已知投毒段即告警 | R2 |
| **A13 信任面检查**周期化(与 §3.1 同一检查) | R4 |
| `§8` 增裁决:OneDrive/Office canonical owner = `Microsoft.list`(国际控制面)+ `MicrosoftCN.list`(国内 CDN/更新面);唯一允许前置拆出的是「已证明与源 IP/cookie 无关的签名 URL 数据面」,当前仅 4 条 | R2 |

**关于 `live.com` / `office.com` / `msn.com` 宽 DIRECT 的裁决意见**:

- `office.com`、`msn.com`:**保留宽 DIRECT**。实测 23 个代表 host 无投毒;`api.msn.com`/`assets.msn.com` 的代理例外由 `Microsoft.list` 前位承接,是刻意分层。
- `live.com`:**保留,但必须挖掉 `onedrive.live.com` 这一个子树**。
- `sharepoint.com` / `office365.com`:**列观察项**(见 §7)。当前形态是「商业版数据面直连 + 登录面代理」,若使用条件访问按 IP 判定则有会话破坏风险,但无实测样本,不凭推断改动。

---

### 3.5 主题五 · 失效与惰性

#### 机制

三种不同的「不做功」,危害完全不同,必须分开处理:

| 类型 | 定义 | 危害 | 处置原则 |
|---|---|---|---|
| **失效** | 规则写了,但目标已不存在或已改形态 ⇒ 设计目的落空 | **高** —— 用户以为有保护,实际没有 | 修规则,不是删规则 |
| **死条目** | 规则被前位同策略规则完全覆盖 ⇒ 删留行为一致 | 低 —— 但是**虚假保障** | 删,并撤销对应豁免 |
| **惰性** | 规则命中与不命中落点相同 ⇒ 只影响日志字段 | 无 —— 但会被误判为「无用可删」 | **重定位 + 改验收标准**,不删 |

#### 证据 —— 失效

**① ModelDownloadCDN 4 条全失效(P1 | 确定,advisor 复核通过)**

区 3 存在的唯一理由是「大模型权重走下载组不占 AI 组家宽」。实测 HF 的模型权重与数据集下载**当前一律重定向到 `us.aws.cdn.hf.co`**,该 host 不被表内任何一条覆盖 ⇒ 落 `AI.list:172 DOMAIN-SUFFIX,hf.co` → **AI 组**。**区 3 的设计目的被完全架空。**

```
curl -sI "https://huggingface.co/openai/whisper-tiny/resolve/main/model.safetensors"
  → 302  location: https://us.aws.cdn.hf.co/xet-bridge-us/63314bb6.../...
curl -sI "https://huggingface.co/bert-base-uncased/resolve/main/pytorch_model.bin"
  → 302  location: https://us.aws.cdn.hf.co/xet-bridge-us/621ffdc0.../...
curl -sI ".../datasets/stanfordnlp/imdb/resolve/main/plain_text/train-00000-of-00001.parquet"
  → 302  location: https://us.aws.cdn.hf.co/xet-bridge-us/621ffdd2.../...
```

三条路径(Xet 模型 / 经典 LFS 模型 / 数据集)全部指向同一 host。另两处缺陷:`ModelDownloadCDN.list:7 cdn-lfs.huggingface.co` 是**死规则**(`@8.8.8.8` NXDOMAIN;`@223.5.5.5` 返回 `208.101.60.87` = 典型投毒应答);而**实际存在的** `cdn-lfs.hf.co`(无区域后缀,`65.8.54.x` CloudFront)未收录。

修法(整表重写为 5 条):

```
DOMAIN-SUFFIX,aws.cdn.hf.co        # 覆盖 us./eu. 等区域前缀（当前 us. 已验证）
DOMAIN-SUFFIX,cdn-lfs.hf.co        # 无区域变体，已验证存在
DOMAIN-SUFFIX,cdn-lfs-eu-1.hf.co   # 保留
DOMAIN-SUFFIX,cdn-lfs-us-1.hf.co   # 保留
DOMAIN-SUFFIX,xethub.hf.co         # 保留（覆盖 transfer./cas-server./cas-bridge. 已验证）
# 删除：cdn-lfs.huggingface.co（死域 + 国内投毒）
```

**② Reject wildcard 静默覆盖收窄(P2 | 确定)**

`Reject.list:347 DOMAIN-WILDCARD,dnserror.*` 与 `:348 DOMAIN-WILDCARD,hostingcloud.*` 是**前缀锚定**。Surge 的 `DOMAIN-WILDCARD` 从**主机名开头**整体匹配,因此它们只覆盖 `hostingcloud.<…>` 形态,**不覆盖任何带前缀的子域** —— 而旧的 `DOMAIN-KEYWORD,hostingcloud` 是覆盖的。这是一次静默的覆盖收窄,且现有断言(`reject_layer.json:116` 只测 apex 形态)**在两种语义下都通过,测不出这个回退**。

```
hostingcloud.racing      → REJECT | Reject.list | DOMAIN-WILDCARD,hostingcloud.*
www.hostingcloud.racing  → Final  | Surge.conf  | FINAL      ← 回退
a.hostingcloud.download  → Final  | Surge.conf  | FINAL      ← 回退
dnserror.example.com     → REJECT | Reject.list | DOMAIN-WILDCARD,dnserror.*
www.dnserror.com         → Final  | Surge.conf  | FINAL      ← 回退
# 对照：正确锚定的通配无此问题
ads-partner.tiktok.com   → REJECT | DOMAIN-WILDCARD,ads-*.tiktok.com
ads-x.y.tiktok.com       → REJECT | DOMAIN-WILDCARD,ads-*.tiktok.com
```

修法:各补一条子域形态 `DOMAIN-WILDCARD,*.dnserror.*` / `*.hostingcloud.*`(仍保持标签边界,不回退成无边界关键词),或恢复等价覆盖;**同批必须补 `www.` 形态断言**,否则这次修复同样测不出来。`*.hostingcloud.*` 因 `*` 跨点,不会误伤 `myhostingcloud.com`(该串前无点)—— 需加负例断言证明。

> 备注:ProxyGFW 的 `DOMAIN-WILDCARD,avtb*`(`:6434`)有同样的前缀锚定问题,但因该表策略 = FINAL 策略**无功能差异**,不建议单独修。

**③ Google 死条目**:`Google.list` 10 条 NXDOMAIN/SERVFAIL(含 `app-measurement.net`、`certificate-transparency.dev`、3 条 `xn--*` IDN、`blogspot.td`);`Microsoft.list:8 gateway.bingviz.microsoft.net` NXDOMAIN。低优先级批量清理。

#### 证据 —— 死条目

**① TencentCN 14 个腾讯云海外 `/24` 全部是行为死条目(P2 | 确定)**

`TencentCN.list:2257-2270`。所有权已逐段查清(RDAP + Team Cymru BGP + 实时 DNS 三源交叉):5 段属腾讯自有 portable 分配(TENCENT-NET-AP),9 段属腾讯云国际主体的 IaaS 池。但**比所有权更强的结论**是:

```
段                 现落                          删除后落
43.156.86.0/24     TencentCN:2257 DIRECT         ChinaIP:578  43.156.0.0/16   DIRECT   ← 同策略
101.32.104.0/24    TencentCN:2259 DIRECT         ChinaIP:1387 101.32.104.0/24 DIRECT   ← 同策略
203.205.232.0/24   TencentCN:2266 DIRECT         ChinaIP:6958 203.205.128.0/17 DIRECT  ← 同策略
… 14/14 全部如此
```

TencentCN 与 ChinaIP 之间只隔着五张**纯域名**表,不存在会插队的 IP 规则。

**且覆盖面严重不完整**:对 15 个微信/QQ 海外入口域做 6 轮解析共取到 27 个第一方 IP,其中 **16 个落在这 14 段之外**;其中 `43.129.*` / `43.130.*` / `43.154.240.*` / `43.155.124.*` / `124.156.190.*` **连 ChinaIP 都没覆盖**。表头写「腾讯云海外段以 IP-CIDR + no-resolve 登记」给出的是**虚假保障**。

**裁决:删除 14 条,同步撤销 `tests/allowlist.json` 里那条 A2 豁免(豁免的对象消失了),并修正表头注释。** 不扩充成「完整腾讯海外段」—— 那等于把 AS132203 的租户池整体直连,与「共享云客户段勿收」裁决冲突。

**② Domestic 2 条 IP-CIDR 同样是死条目(P2 | 确定)**:`Domestic.list:617 140.205.1.0/24`(被 `ChinaIP:4758 140.205.0.0/16` 覆盖)、`:618 162.14.0.0/18`(被 `ChinaIP:5148 162.14.0.0/16` 覆盖)。且按层次规则,阿里/腾讯的 IP 段归属应在厂商表。

**③ ChinaIP 154 条被前位表 CIDR 完全覆盖(P2 | 确定)**

| 覆盖者 | 前位表 | 被覆盖条数 | 策略关系 |
|---|---|---:|---|
| `17.0.0.0/8` | AppleCN | **142** | 同为 DIRECT |
| `144.178.0.0/19` + `2403:300::/32` | AppleCN | 2 | 同为 DIRECT |
| 6 条腾讯云 `/24` | TencentCN | 6 | 同为 DIRECT |
| `162.105.0.0/16`、`202.127.16.0/20` | PKU | 2 | 同为 DIRECT |
| **`74.125.0.0/16`** | **Google** | **1** | **策略不同** |
| 合计 | | **154** | |

唯一的跨策略包含 `Google.list:696 74.125.0.0/16` [Google-X-Meta-MS] ⊇ `ChinaIP.list:1346 74.125.16.64/26` [DIRECT] —— **结论上是正确的**(APNIC 委派给 CN 的一小段 Google 自有地址,Google 在墙内不可用,走 Google 组比直连正确),但**没有任何登记,纯靠巧合正确**。另有 28 条部分交叠(PKU 8、TencentCN 7、Reject 7 条 HTTPDNS IP、Domestic 2、Streaming 2、其他 2)。

**规则本身不动**(机器层零手改),补的是审计:见 R2 的 **A9**。

**④ 其他死条目**:`Meta.list:549 108.177.8.0/21`(见 §3.2);`GameDownloadCN.list:56 steamcontent.net`(apex → `217.19.248.132` = AS60819 SafeNames 停放页);`ProxyGFW.list:6440 14.102.250.18/31`(Cymru 返回 `NA | NA | NA`,无 BGP 起源、无注册记录);`Japan.list:48 paravi.jp`(Paravi 2023 并入 U-NEXT,`curl -I` → 000 无响应);Japan 的 5 条 `IP-ASN`(下一行就是 `GEOIP,JP`,边际贡献 = 这些 ASN 中不被判为 JP 的前缀;RDAP 实测持有者 IIJ / KDDI / OCN / NTT PC / OPTAGE **五家全是接入型 eyeball ISP,不是内容托管网络**)。

#### 证据 —— 惰性(重定位,不删)

**ProxyGFW 6,427 条域名规则中 6,409 条(99.7%)与「不写这条规则」结果逐位等价(P1 | 确定,advisor 复核通过 —— W3-01 / W8-18 双独立收敛)**

机制:ProxyGFW 的策略是 `Final`,conf 收尾 `FINAL,Final,dns-failed` 的策略**也是 `Final`**(同一个 select 组);全库 IP 类规则一律 `no-resolve`,因此域名请求在整条规则链上不触发任何本地 DNS。命中 ProxyGFW 与一路落到 `FINAL` 的差别只剩「命中了哪条规则」这个日志字段。

```
ProxyGFW 域名条目 6427
  [承载] 与后位表重叠（不存在则会被后位表判为 DIRECT）:   18
  [惰性] 后位表无覆盖（删掉也会落 FINAL→Final，同策略）: 6409  = 99.7%
  承载条目的后位表分布: {'ChinaDomain': 11, 'TencentCN': 2, 'Domestic': 5}
```

**18 条承载集全清单**(这是本表新的验收基准):

```
:7    cloud.oracle.com            ← ChinaDomain:68167 oracle.com
:126  666pool.cn      :698  bloomberg.cn     :1313 daxa.cn      :3155 lightnovel.cn
:5715 uupool.cn       :6379 zhijianfengyi.cn :6401 zmw.cn       ← ChinaDomain:22497 DOMAIN-SUFFIX,cn
:2360 hasi.wang                   ← ChinaDomain:89141 DOMAIN-SUFFIX,wang
:543  bbs.tuitui.info             ← ChinaDomain:86329
:944  cg.play-analytics.com       ← ChinaDomain:69825
:818  bx.in.th                    ← TencentCN:624 in.th
:4701 shortconn.im.qcloud.com     ← TencentCN:857 qcloud.com
:827  c.mi.com                    ← Domestic:369 mi.com
:3960-3962 openapi{,-quote,-trade}.longbridge.cn ← Domestic:347
:4578 schwab.com.cn               ← Domestic:153 com.cn
```

**裁决:不删表。** 重定位为「**FINAL 策略保险层 + 防后位误直连层**」:

1. `ARCHITECTURE.md §2` 区 8 的「为什么在这个位置」一栏补写:策略同 FINAL,本表的作用是「抢在区 9/10 之前认领,防被墙域落进 DIRECT 层」;
2. **再生验收标准改为「18 条承载集是否完整」,不再按行数或与上游对齐判定**;惰性部分的增减不作为回归;
3. 「只有在裁决把 `FINAL` 改成 `DIRECT` 之后,全表 6,427 条才同时变成承载条目」应作为**本表存在理由**写进裁决登记,避免后人以「99.7% 无用」为由删表。

同批需登记的还有 conf 注释:`Surge.conf:115-116` 区 8 注释未点明策略同 FINAL(W8-18)。

#### 修复

| 动作 | 批次 |
|---|---|
| ModelDownloadCDN 整表重写(5 条)+ 3 条断言(`us.aws.cdn.hf.co` → 下载 / `huggingface.co` → AI) | R1 |
| Reject wildcard 语义回归修复 + `www.` 形态正例 + `myhostingcloud.com` 负例 | R1 |
| 删 TencentCN 14 段 + 撤销 A2 豁免 + 改表头;删 Domestic 2 条 IP | R1 |
| 删 `steamcontent.net`、`14.102.250.18/31`、`paravi.jp`、Google/Microsoft 死条目 | R1 |
| **A9 · IP 跨表包含/遮蔽审计**上线,154+28 条整体登记 exemption,门禁只对**新增跨策略交叠**报警 | R2 |
| ProxyGFW 重定位 + 验收标准改写 + `ARCHITECTURE §2` / conf 注释同步 | R2 |
| Japan 5 条 IP-ASN:保留但登记「边际 = GEOIP 数据缺口兜底」或删,执行时按 W4 方案 | R2 |
| ProxyGFW 769 条死域并入再生过滤器(承载集豁免) | R3 |

---

### 3.6 主题六 · 会话与归属精化

#### 机制

「唯一归属」这条铁律在**结构**上已经守住了(跨表精确重复 11 条全部已豁免、前位遮蔽 0 条)。但它守不住另一类问题:

```
前位表持有 更深的子域    （如 DownloadCDN 的 static.telegraph.co.uk）
后位表持有 顶域后缀      （如 UK.list 的 telegraph.co.uk）
  → 两条规则都活着、都在命中
  → 但把一个服务劈成两个出口
```

这**不是遮蔽**,`audit.py` 的 A4 按定义查不出来(A4 查的是「后表条目被前表遮蔽 = 死条目」)。实测 `raw_hits.A4 = 0`,而独立脚本在同一份数据上找出 **29 个分裂注册域 + 11 个分裂品牌**,其中 **8 个是真实同会话跨出口**。发布闸门对这一整类问题**结构性失明**。

#### 属地锁归属原则(advisor 仲裁)

W4 提请裁决:上轮的「服务 owner 决定归属、region 只是 policy 属性」在本配置下无法落地 —— 策略层**没有「本服务需要某国出口」的表达能力**(`流媒体`/`游戏`/`下载` 都是全局单选组)。

**裁定:上轮原则在无 manifest / 无服务模型的现状下不采纳为通用原则。属地锁内容的 owner = 能提供正确出口的表。**

| 属地锁类型 | 归属 | 理由 |
|---|---|---|
| 英国锁(BBC iPlayer / NOW / UKTV) | **UK.list** | `流媒体` 组的六个候选里没有独立英国出口;经 🇪🇺欧洲 smart 组存在伦敦节点通路但**不可控**(该组是跨 DE/NL/GB 三国的 smart 组,选到英国是概率事件) |
| 日本锁(Niconico / Cygames 日区 / DLsite / Prime Video JP) | **Japan.list** | 同上;且 `游戏` 组首选是机房出口,对日区限定手游是负优化 |
| 美国锁(Fox / CBS / NBC / Tubi / Fubo) | **留 Streaming** | 该组首选 = 美国家宽,与属地一致,归服务表可行 |

> **表述边界**:**不得**写成「流媒体组无任何英国出口成员」。正确表述是「无独立英国出口成员,经欧洲 smart 组存在伦敦节点通路但不可控」。

BBC 反向(`bbc.co.uk` ↔ `bbc.com`)按此原则修正,并**同步改 `tests/scenarios/region_coverage.json` 的 `region_uk_node` 断言**(该场景把 `bbc.co.uk → 流媒体` 写成期望值 —— 这是测试断言而非 `§8` 裁决,不构成裁决冲突,但不同步改会打红 runsuite)。

#### 证据 —— 8 个真实跨出口

> 出口组名按仓库脱敏惯例改写为中性代号:🇺🇸美国家宽A / 🇺🇸美国家宽B / 🇯🇵日本家宽 / 🇺🇸美国落地 / 🇯🇵日本落地 / 🇪🇺欧洲。

| # | 服务 | 分裂形态 | 后果 | 级别 |
|---|---|---|---|---|
| 1 | **BBC** | `bbc.com` + `bbcmedia.co.uk` 在 UK.list → 🇬🇧英国;`bbc.co.uk` / `bbci.co.uk` + 8 条在 `Streaming.list:160-169` → 流媒体 → 🇺🇸家宽;`gn-web-assets.api.bbc.com` 在 DownloadCDN → 下载 | **需要英国 IP 的 iPlayer 全链走美国出口,不需要的国际新闻站走英国出口 —— 方向完全倒置** | **P1 \| 确定** |
| 2 | **Prime Video JP** | `Japan.list:5 amazon.co.jp` → 🇯🇵;`Streaming.list:148 atv-ps-fe.amazon.co.jp` → 流媒体 → 🇺🇸家宽 | 账号/购买/首页在日本,**播放授权(playback-service)在美国** ⇒ 日区属地校验必按美国出口判定 | **P1 \| 确定** |
| 3 | **DLsite** | `Japan.list:16 dlsite.com` → 🇯🇵;`DownloadCDN.list:34/1572/1648/2940`(`trial.` / `dl.` / `download.` / `media.`)→ 下载 → 🇺🇸落地 | DLsite 下载令牌**按会话来源签发**:结算在日本、取件在美国;部分作品有属地限制且判定发生在下载面 | **P1 \| 高置信** |
| 4 | **Telegraph** | `UK.list:31 telegraph.co.uk` → 🇬🇧;`DownloadCDN.list:4523 secure.telegraph.co.uk` → 下载 → 🇺🇸落地 | `secure.` 是**认证/订阅面**,不是静态资源面;登录请求从美国发出而主站会话在英国 ⇒ 付费墙/订阅校验跨出口。与 D4「大流量批量下载域」定位直接冲突 | **P1 \| 高置信** |
| 5 | **Cygames** | `Japan.list:15 cygames.jp` 等 5 域 → 🇯🇵;`Games.list:17 api-priconne-redive.cygames.jp` / `:296 omotenashi.cygames.jp` → 游戏 → 🇺🇸落地 | 同一款日区限定手游的**客户端 API 在美国、官网在日本** ⇒ 属地风险 + RTT 惩罚 | **P1 \| 高置信** |
| 6 | **Niconico / Dwango** | `Streaming.list:851/853`(`niconico.com` / `nicovideo.jp`)→ 流媒体;`Japan.list:18/46/67`(`dwango.jp` / `nimg.jp` / `simg.jp`)→ 🇯🇵;`DownloadCDN.list:921/1300/4081` → 下载 | 5 个注册域劈成 3 张表 3 个出口。whois 实证 `nimg.jp` / `simg.jp` 持有者均为 Dwango;`common-header.nimg.jp` 是全站公共头、`resource.video.nimg.jp` 是视频资源面 | **P1 \| 高置信** |
| 7 | **ESPN+** | `US.list:23 espnplus.com` → 🇺🇸美国节点;`Streaming.list:379 espn.com` 吃掉跳转目标 `plus.espn.com` → 流媒体 | `curl -sI` 实测 302 跳转,**一次用户导航中途换出口**。本轮唯一「删就完事、零副作用」的条目 | **P1 \| 确定** |
| 8 | **Tubi** | `US.list:47 tubi.io` → 🇺🇸;`Streaming.list:59/72`(`DOMAIN,tubi.tv` + `DOMAIN,www.tubi.tv`)/ `:909` / `:1022` → 流媒体;`DownloadCDN.list:5132 tubi.video` → 下载 | 三重问题:① 用 `DOMAIN` 精确匹配 ⇒ **`api.tubi.tv` 落 FINAL(覆盖空洞)**;② `tubi.io` 顶域无 A 记录(`@223.5.5.5` 返回 Facebook 段 = 典型投毒),唯一活体子域已被 Streaming 认领 ⇒ **近死条目 + 分裂源**;③ `tubi.video` 又被 DownloadCDN 拿走 | **P1 \| 确定** |

#### 证据 —— 批量归位(23 条,P2 | 确定)

统一模式:地区表持有注册域,DownloadCDN 持有其 `static.` / `cdn.` / `assets.` / `i.` / `images.` / `ftp.` / `mirror.` 子域。功能性影响多数是**加载延迟与 TLS 会话不共享**。

统一动作:**从 `lists/DownloadCDN.list` 删除,由地区表既有顶域后缀承接 —— 地区表零新增行。**

```
# → Japan.list
DownloadCDN:235   asset.booth.pm                 → Japan:10  booth.pm
DownloadCDN:978   cdn.rex.contents.rakuten.co.jp → Japan:62  rakuten.co.jp
DownloadCDN:1777  error.rakuten.co.jp            → Japan:62  rakuten.co.jp
DownloadCDN:1853  file.chobit.cc                 → Japan:12  chobit.cc
# → UK.list
DownloadCDN:400   assets.vodafone.co.uk          → UK:38     vodafone.co.uk
DownloadCDN:1220  cf.eip.telegraph.co.uk         → UK:31     telegraph.co.uk
DownloadCDN:2284  i.dailymail.co.uk              → UK:9      dailymail.co.uk
DownloadCDN:4493  scripts.dailymail.co.uk        → UK:9      dailymail.co.uk
DownloadCDN:4747  static.giffgaff.com            → UK:11     giffgaff.com
DownloadCDN:4764  static.independent.co.uk       → UK:15     independent.co.uk
DownloadCDN:4854  static.telegraph.co.uk         → UK:31     telegraph.co.uk
DownloadCDN:4858  static.theguardian.com         → UK:32     theguardian.com
DownloadCDN:5322  video.dailymail.co.uk          → UK:9      dailymail.co.uk
# → Europe.list
DownloadCDN:365   assets.scaleway.com            → Europe:54 scaleway.com
DownloadCDN:853   cdn.ionos.de                   → Europe:32 ionos.de
DownloadCDN:964   cdn.prod.www.spiegel.de        → Europe:56 spiegel.de
DownloadCDN:4610  sp-spiegel-de.spiegel.de       → Europe:56 spiegel.de
# → US.list
DownloadCDN:565   c1.newegg.com                  → US:37     newegg.com
DownloadCDN:2295  i.iheart.com                   → US:31     iheart.com
DownloadCDN:2422  images.fandango.com            → US:25     fandango.com
DownloadCDN:2477  images10.newegg.com            → US:37     newegg.com
DownloadCDN:4765  static.inferno.iheart.com      → US:31     iheart.com
DownloadCDN:5376  web-static.pages.iheart.com    → US:31     iheart.com
```

**明确「保留分裂、勿动」的条目**(理由充分,须同步登记进 `§8` 防下轮误删):

| 条目 | 理由 |
|---|---|
| `DownloadCDN:2853 linuxsoft.cern.ch`、`:4103 rsync-linuxsoft.cern.ch` | CERN 的 Linux 发行版镜像,真·大流量下载 |
| `DownloadCDN:1997 ftp.free.fr` | Free.fr 公开 FTP 镜像 |
| `DownloadCDN:2089 ftp.tudelft.nl`、`:2126 ftpserv.tudelft.nl` | 代尔夫特理工公开镜像 |
| `DownloadCDN:3461/3467 mirror1/2.infomaniak.com`、`:3200 mirror.infomaniak.ch` | Infomaniak 公开镜像 |
| `DownloadCDN:118 anorien.csc.warwick.ac.uk`、`:3309 mirror.ox.ac.uk` | 英国大学镜像,先于 `UK.list:4 ac.uk` 是**刻意分层** |
| `Japan:28 happyon.jp` / `Europe:64 tvnow.de` / `Europe:41 npostart.nl` | **纯跳转域**,目标域已在同表,跳转本身也须走对出口。勿当死条目删 |
| Hulu JP vs Hulu US | 不同法人(HJ Holdings vs Disney)、不同服务,**分裂正确** |
| `Japan:19/21 e-hentai.org` / `exhentai.org` | 按**出口偏好**而非属地所有权收录(实测 Cloudflare anycast),勿以「不是日本实体」为由删 |
| `Japan:67 simg.jp` | 顶域无 A 但 SOA 活、NS 在 AWS,**子域型域**,保留 |

#### 证据 —— 其他归属精化

| 项 | 内容 | 级别 |
|---|---|---|
| **YouTube 三分裂** | ① 频道头像:表里钉死旧形态 `yt3/yt4.ggpht.com`(流媒体),而现网同时在用 `yt3/yt4.googleusercontent.com` → 被 `Google.list:514` 接走;② `jnn-pa.googleapis.com`(播放完整性/attestation)未收 → 落 Google 组;③ `IP-ASN,36040`(0% GCP,全是 ISP 内嵌 GGC 缓存段 —— 正是承载 YouTube 视频的那批)放在 `Google.list:704`。**与裁决 306 同源,属其自然延伸** | P2 \| 确定 |
| **Google 21 条 `-cn` 镜像域** | `Google.list` 的 21 条 `-cn` 中国镜像域,**20 条解析进中国移动 CMNET** 且落在 `ChinaIP` 的 `120.192.0.0/10` 内,却走代理;而语义完全平行的 `.cn` 镜像族(`google.cn`/`googleapis.cn`/`gstatic.cn`/`googlecnapps.cn`/`gkecnapps.cn`,`Domestic.list:249-255`)是 DIRECT。同一用途、同一落点、**相反策略**,且代理侧的往返是「境外出口 → 回中国移动」的发卡弯。注意 `googleadservices-cn.com` 的 `www` 在 CN 侧返回 `0.0.0.0`、境外侧返回真实 IP ⇒ **迁移前需逐端点实测,不可整族一次性改** | P2 \| 高置信 |
| **ThreatMetrix 入 Payment** | `h.online-metrix.net`(LexisNexis ThreatMetrix)当前落 FINAL,与 Payment 组不是同一策略。**advisor 仲裁:收入 Payment。** 理由:通用 SaaS 裁决针对的是**与会话风控无关**的组件;ThreatMetrix 是 3DS 风控决策链**本体**,出口漂移正是它的检测信号。`§8` 补边界:**参与支付风控决策链的指纹/反欺诈组件归 Payment** | P2 \| 高置信 |
| **`01.ai` / `siliconflow.com`** | 当前在 `Domestic.list:20 / :486` 直连,而同公司的 `lingyiwanwu.com` 已判给 AI.list。**advisor 裁定:按 D3 + `qwenlm.ai` 先例迁 AI.list;对应 `.cn`/中文主域保持直连。** 执行时若 W5 报告中有相反可达性证据则复核 | P2 \| 高置信 |
| **CA 成对断裂** | Domestic 的 CA 段声明「兼作 CA 吊销/AIA 端点集中直连位」,但同一 CA 的三件套被拆开:Sectigo 缺 `crl.sectigo.com`、GlobalSign 缺 `secure.globalsign.com`(AIA)、VeriSign 缺 `ocsp.verisign.com`、Amazon Trust 缺 `crt.rootca1.amazontrust.com`、Microsoft 缺 `ocsp.msocsp.com`。另有 `godaddy.com` / `comodoca.com` 被 ProxyGFW 前位后缀吃掉但**未登记**(`usertrust.com` / `entrust.net` 已登记) | P2 \| 高置信 |
| **`musespark.ai` 移出 Meta** | 见 §3.1 | P1 \| 确定 |
| **GameDownloadCN 定位冲突** | 表的**声明定位**是「国服游戏下载 CDN 直连」,**实际内容**是「Steam 全球下载 + 国服游戏发行 + 一批会话/UGC/社区域」。上游两张源表加起来 33 条,本表 66 条。核心冲突:`:20 cm.steampowered.com`(Steam Connection Manager = 登录/好友/库控制通道)在区 2 DIRECT,而 `steampowered.com` 在 `Games.list:411` → 游戏组 ⇒ **同一会话跨两出口**;`:61/:62` 创意工坊用户内容、`:37 lpl.com.cn` 赛事站同理;`:68 xboxlive.cn` 与 `:12 battlenet.com.cn` 比上游宽 | P1 \| 确定 |
| **G-03 双写** | `GameDownloadCN:4/26` 与 `Domestic:509/510` 的 Steam 国服 CDN 双写(父后缀在 Domestic 已覆盖子域)。同为 DIRECT 无功能影响,但违反唯一归属 | P2 \| 确定 |

#### 修复

| 动作 | 批次 |
|---|---|
| 档 1 六条零副作用动作(删 `espnplus.com` / `tubi.io` / `paravi.jp` / `secure.telegraph.co.uk` / `sourcepoint.theguardian.com`;`tubi.tv` 两条 `DOMAIN` 合并为 `DOMAIN-SUFFIX`) | R1 |
| 档 3 批量归位 23 条 | R1 |
| YouTube 三分裂归位;Google `-cn` 族(先做可达性矩阵);ThreatMetrix 入 Payment;`01.ai`/`siliconflow` 迁 AI;CA 断裂补 4 条 | R1 |
| BBC 全族 → UK;Niconico → Japan;Cygames API → Japan;Prime Video JP → Japan(先抓包) | R2(依赖用户待决 1) |
| Fox / CBS / NBC / Fubo → Streaming | R2(依赖用户待决 1) |
| GameDownloadCN 三段拆分 + 收窄到上游口径 + G-03 双写消解(**必须实测下载带宽**) | R2 |
| **A11 · 注册域跨策略分裂报告**上线,黄金基线 = 当前 29 项 | R2 / R4 |

---

### 3.7 主题七 · 机器层再生管线(最大工程)

#### 机制

`ChinaDomain`(106,464 条)与 `ChinaIP`(11,090 条)合计占全库 **81.8%**。铁律规定它们是「整表机器刷新层,禁止手工改单条」。但**仓库根本没有再生脚本** —— `tools/` 只有 `collapse_cidr.py` 与 `surge2clash.py`,`update.sh` 也不拉上游。`MAINTENANCE §8` 里所有「整表再生后须重新过滤 …」的约束**目前全靠人记**。

供应链因此两极分化:

| 表 | 可重建性 | 证据 |
|---|---|---|
| **ChinaIP** | ✅ **可从声明的 pin 逐位重建** | 从 `reference/…/ChinaIPs.list @65e8adf`(22,425 行)折叠后,v4 7,165 条 SHA `88e05292…`、v6 3,925 条 SHA `9ae07b0f…`,与本地文件**逐位相同** |
| **ChinaDomain** | ❌ **不可重建** | pin 有本地无 5,237 条 → 4,686 条可由归属去重解释、12 条由已删宽关键词解释、**539 条无任何已登记规则可解释**(其中 534 条在当前上游仍然存在);另有 1 处未登记的类型改写(上游 `DOMAIN-SUFFIX,api.blipsandchitz.me` 在本地变成 `DOMAIN,…`) |

且 `SOURCES.md` 自述 `rule/` 目录是 **2026-08-30 才追加检出**的,而表是 08-25/08-29 建的 ⇒ **声明的 revision 是事后补登,不是构建输入**。

#### 证据 —— ChinaDomain 境外托管噪声量化

系统抽样 n=2000(step=53.12,随机起点 seed 20260831;文件按字母序排列 ⇒ 等距抽样天然按字母/长度/TLD 分层,自加权,对全表无偏),Wilson 95% CI:

| 判定 | k | p | 95% CI | 外推全表 |
|---|---:|---:|---|---:|
| CN_HOSTED | 1428 | 71.40% | 69.38–73.34% | 75,861 |
| NO_A(死域/停放) | 267 | 13.35% | 11.93–14.91% | 14,184 |
| OFFSHORE | 266 | 13.30% | 11.88–14.86% | 14,131 |
| OFFSHORE(港澳台) | 35 | 1.75% | 1.26–2.42% | 1,859 |
| POISON_SUSPECT | 2 | 0.10% | 0.03–0.36% | 106 |
| **境外合计** | **303** | **15.15%** | **13.65–16.79%** | **16,096 [14,498–17,837]** |
| **噪声合计** | **570** | **28.50%** | **26.56–30.52%** | **30,280 [28,224–32,425]** |

判定极其保守:只有当该域**全部** A/AAAA 记录都不落在 `ChinaIP.list ∪ 上游 ChinaIPs ∪ Loyalsoldier cn.txt` **三者并集**时才判境外。且境外判定域中 84.7% 的 CN 侧答案与 `@8.8.8.8` 答案有交集 ⇒ 是真的托管在境外,不是被污染。

> **口径说明**:`MAINTENANCE` 登记的「约 2 万条」偏高但同量级。本文以 15.15%(≈1.6 万)为**裸估计上界**(三项已知偏差方向一致,真实境外比例 ≤ 15.15%),以**加护栏后的 5.50%** 为实际删除面。两个数字不可混用。

#### 证据 —— 过滤器原型与十道护栏

**已交付可运行原型**:`reference/audit-v2-20260831/w6/chinadomain_regen_filter.py`,在真实上游数据上跑通。

```
上游 ChinaMaxNoIP_All.list (111,258)
   F0 类型过滤 ── 丢 USER-AGENT / PROCESS-NAME / URL-REGEX（D7/D11，类型级）        实测 -77
   F1 forbidden ─ 丢命中 allowlist.forbidden 的规则 + 硬规则「机器层 DOMAIN-KEYWORD 恒为 0」 实测 -14
   F2 归属去重 ── 丢已被 conf 前位表认领的域（exact/suffix/keyword）                实测 -4,783
   F3 解析分类 ── 3×CN 解析器 quorum + 1×境外参照 + A/AAAA
   F4 误删保护 ── P1..P10，任一触发 → KEEP 或 QUARANTINE
   F5 产出闸门 ── 迟滞(P7) → 爆炸半径(P8) → 落点复核(P9) → 写表
```

| # | 护栏 | 针对的误删场景 |
|---|---|---|
| P1 | **多解析器 quorum**:3 个 CN 公共解析器任一返回 CN 落点即保留 | GSLB 就近调度、单解析器故障、区域性 CDN 分域 |
| P2 | **双栈救援**:任一 AAAA 落 CN v6 即保留 | v4 走境外 CDN、v6 走国内的双栈站 |
| P3 | **CN CDN CNAME 骨架白名单**(60+ 后缀)命中即**无条件保留** | **CDN 双栈域核心保护** —— 调度节点可能临时给境外 IP,但域本身由国内 CDN 承载 |
| P4 | **全球 anycast / 大厂云宽限**:落点 ASN ∈ {Cloudflare / Akamai / Fastly / AWS / Azure / Google / Alibaba / Tencent / Huawei} → 进隔离区,不自动丢 | **「大厂境外 POP 但国内可达」核心保护** |
| P5 | **主动可达性实测**(隔离区出口):`curl --resolve` 两次间隔 ≥5 min 均失败才允许丢 | 唯一的决定性证据 |
| P6 | **解析器互斥即隔离**:3 个答案两两无交集 → 证据不足 | 投毒 / GSLB 抖动 |
| P7 | **迟滞**:同一域需**连续 3 次**再生(间隔 ≥7 天)判为境外才真删 | 上游 DNS 抖动、临时迁移 |
| P8 | **爆炸半径闸门**:单轮丢弃 >20% 直接 `exit 1` | 解析器整体故障导致清表 |
| P9 | **落点复核**:每条待删域用 `engine.py` 算删除后落点,必须 ∈ {Final, ProxyGFW} | 删了反而被某张中间表接管 |
| P10 | **pin list**(`keep.txt`):人工钉住,机器强制永不删 | 合规/业务硬需求 |
| — | 解析成功率 <70% → `exit 2`;**NO_A 默认保留**(单独归档) | 网络异常 / 临时 NXDOMAIN |

**护栏效果实测**(过完 F0–F2 后的 106,384 条中系统抽 n=1200,解析成功率 88.2%):

| 判定 | k | p | 95% CI | 外推 |
|---|---:|---:|---|---:|
| KEEP_CN(P1 命中) | 895 | 74.58% | 72.04–76.97% | 79,344 |
| KEEP_PROTECTED(P2/P3/港澳台) | 29 | 2.42% | 1.69–3.45% | 2,570 |
| NO_A(默认保留) | 141 | 11.75% | 10.05–13.70% | 12,500 |
| **QUARANTINE**(P4 宽限 / P6 互斥) | 69 | 5.75% | 4.57–7.21% | **6,117** |
| DROP_OFFSHORE | 64 | 5.33% | 4.20–6.75% | 5,673 |
| DROP_POISON | 2 | 0.17% | 0.05–0.61% | 177 |
| **自动丢弃合计** | **66** | **5.50%** | **4.35–6.94%** | **5,851 [4,623–7,380]** |

> **护栏把删除面压到裸过滤器的 1/3**(15.15% → 5.50%),另有 5.75% 进隔离区等 P5 实测。这就是误删保护的量化代价与价值。

#### 证据 —— 其他机器层缺口

| 项 | 内容 | 级别 |
|---|---|---|
| **11 条 PSL PRIVATE 后缀在直连层** | `1kapp.com` / `appchizi.com` / `applinzi.com` / `vipsinaapp.com`(新浪 SAE)、`vicp.fun` / `zicp.fun`(花生壳 DDNS)、`nyat.app`(NAT 穿透,**apex 落 GitHub Pages `185.199.109.153`**)、`mycloudnas.com` / `nett.to` / `heiyu.space` / `zone.id`(印尼二级托管后缀)。语义与已禁收的 13 条国际多租户后缀完全同构 | P2 \| 确定 |
| **44 条整 TLD 无分层、无退出机制** | `DOMAIN-SUFFIX,cn` 一条的覆盖面就与 **1,066 条前位具体域**相交,横跨 DIRECT / Final / Payment / REJECT / 流媒体 **五种策略**。分档(IANA root DB 核验):**T0 必留** `cn`;**T1 品牌 gTLD 8 条**(`citic`/`icbc`/`sina`/`sohu`/`unicom` + 3 条 IDN,注册局 = 单一中国主体,精度天然 100%);**T2 CN 注册局开放注册 ~28 条**;**T3 境外注册局运营 7 条**(`wang` 注册局在 HK;`xn--6frz82g`(移动)注册局 Identity Digital;`xn--czrs0t`/`xn--fjq720a`/`xn--unup4y`/`xn--vhquv` 注册局均为 Binky Moon, LLC(美国))。`.wang` 已有实证反例:26 条 `.wang` 域散落在其他表,其中 5 条在**非直连区** | P2 \| 高置信 |
| **3 条可疑二级形态** | `com.fi`(:23624)/ `com.mp`(:23625)/ `com.tv`(:23626) —— `.fi` / `.tv` 的注册局**并不使用 `com.` 二级层级**,把 `com.fi` 当后缀会把任何 `*.com.fi` 打成 DIRECT。**须用 PSL 快照立即核查** | P2 \| 确定 |
| **上游 2 条关键词无门禁** | 当前上游带 13 条 `DOMAIN-KEYWORD`,11 条已登记,**`stripe`(D11 明文点名的排除项)与 `beplay` 未登记** ⇒ 文档说了、机器不管。更彻底的修法是类型级断言「`ChinaDomain.list` 的 `DOMAIN-KEYWORD` 计数恒为 0」,比逐个登记关键词更抗上游变化 | P2 \| 确定 |
| **`.beer` 653 条域名农场** | 形如 `0006fc9541020.beer` 的十六进制随机串,抽样 36 条全部解析到少数几个阿里云/移动 IP。CN 托管、判定无错,但整批会在下次上游刷新时轮换。分 TLD 噪声率:`.biz` 82.1% / `.shop` 81.5% / `.la` 81.5% / `.xin` 76.7% / `.hk` 75.9% vs `.com` 26.1% | P3 \| 观察候选 |

#### 双兜底(`ChinaIP` + `GEOIP,CN`)—— 保留

全量集合差(非抽样):

| 对比 | v4 段数 | v4 地址数 | v4 占比 | v6 段数 | v6 占比 |
|---|---:|---:|---:|---:|---:|
| ChinaIP.list | 7,165 | 359,024,114 | — | 3,925 | — |
| Loyalsoldier CN | 6,223 | 344,332,800 | — | 3,428 | — |
| **ChinaIP 独有** | **2,576** | **14,752,242** | **4.109%** | 2,107 | 0.188% |
| **GEOIP 独有** | 58 | 60,928 | 0.018% | **540** | **6.152%** |

**关键观察**:GEOIP 独有的 58 个 v4 段 / 540 个 v6 段,与「本地快照落后上游两天」的差集**几乎完全重合** ⇒ 同步一次上游后,GEOIP 的边际贡献 ≈ 0。

**裁决:保留双层。** 两层各补一个盲区:ChinaIP 补 mmdb 的大块粒度盲区(4.1%,含大厂 anycast 的大陆 PoP 碎片 —— mmdb 通常把整个 `104.16.0.0/12` 标成 US,恰恰漏掉它们),GEOIP 补 ChinaIP 的同步滞后盲区。且 `tests/engine.py` 的 `GEOIP,CN` 判定**硬引用 ChinaIP.list 做近似**,删表等于让离线引擎失去 CN 判定能力,674 条 DNS 泄漏断言基线一起塌掉。成本只有一行规则。

配套:①同步 ChinaIP 到上游最新(纳入例行,本地落后 2 天:v4 缺 59 段、v6 缺 540 段 = 6.15% 地址空间);②把「GEOIP 独有段数」纳入定期体检,**v4 独有 >300 段即告警**(该数字持续增长 = ChinaIP 同步已停摆的早期信号)。

#### 修复

| 动作 | 批次 |
|---|---|
| 171 条 `DOMAIN` 逐条清单:必删投毒 4 + 建议删境外 77;保留港台 12 + 国内 22;死域 56 交 NO_A 桶 | R1 / R3 |
| `sources.lock.json` **从 ChinaIP 先行**(唯一今天就能锁的表:`expect.set_sha256` + `tools/fetch_locked.py` + `tools/rebuild.py` + A12 lock 一致性)。ChinaDomain 的 lock 等过滤器过完两轮影子运行再写 | R3 |
| `tools/regen_chinadomain.py` 入库(护栏版):`--shadow` 2 轮 → `--apply`;含 17 删域 + 9 关键词 + D11 既有过滤 | R3 |
| ChinaDomain 534 条不可解释差异:短期在 `SOURCES.md` 注明「pin 为事后补登,不可据以重建」;长期由 `rebuild.py` 自动收敛 | R3 |
| `ChinaTLDHeuristics.list` 拆出(位次紧贴 ChinaDomain 之后 ⇒ **行为完全等价**),T1 上移厂商表、T3 挂 90 天观察期 | R3 |
| forbidden 补 `DOMAIN-KEYWORD,stripe` / `beplay` + 类型级断言 | R2 |
| **硬性缺口**:P5 主动可达性实测需要**无 Surge 的大陆出口主机**(本机 TUN 捕获一切,实测 `--noproxy '*' --resolve` 仍返回经代理结果)⇒ 列入用户待决 6 | — |

---

### 3.8 主题八 · conf 与工程侧

#### 证据 —— DNS 单点(P2 | 确定)

`Surge.conf:20-21` 读起来像「DoH 优先、明文兜底」,**实际不是**。官方手册原文:配了 `encrypted-dns-server` 后,传统 DNS 服务器**只用于连通性测试和解析加密 DNS URL 里的主机名**。而本配置的两个 DoH 端点都写成 **IP 字面量**,没有主机名需要 bootstrap ⇒ `dns-server` 一行在正常路径上**完全不参与解析**。

后果:若所在网络阻断到这两个 IP 的 443(酒店/机场 captive portal、企业网、运营商临时封锁),Surge 内部 DNS 客户端**没有任何降级路径**;此时只有 `FINAL,Final,dns-failed` 兜住「解析失败」的连接,而所有**需要本地解析的 DIRECT 连接**(国内直连区 ≈ 全库 92% 的域)会直接失败。

**正面结论(任务的正面回答)**:国内 DoH 的**选型是正确的**,且与架构自洽 ——

1. **代理连接不使用本地 DNS**(`use-local-host-item-for-proxy` 默认 false ⇒ 代理策略下 DNS 永远在远端做)⇒ 「用国内 DoH 会污染代理域解析」这个担心**不成立**;
2. 国内 DoH 服务的是 DIRECT 侧,而 DIRECT 侧几乎全是国内域 ⇒ 给出最优的国内 CDN 就近解析,**是正确的方向选择而非妥协**;
3. DoH 连接本身**不进规则链**(`encrypted-dns-follow-outbound-mode` 默认 false ⇒ 加密 DNS 连接始终用 DIRECT 并绕过规则系统)。交叉核验:`Reject.list:357-364` 的 8 条 HTTPDNS IP 段**都不包含**本 conf 的两个 DoH 端点 IP ⇒ 即便将来打开该键也不会自锁;
4. 无解析循环(IP 字面量);
5. `hijack-dns = *:53` 让客户端查询在 53 端口就被 fake-IP 应答器接住,**根本走不到上游 DoH** ⇒ 国内 DoH 的查询量远小于直觉,隐私暴露面也更低。

⇒ **唯一代价就是「无明文回退」**,这应当被显式记档为一次取舍,而不是当成配置遗漏(见用户待决 5)。

#### 证据 —— 零本地解析闭环的第三根支柱(P2 | 高置信)

`ARCHITECTURE §4` 把「全链路零本地 DNS 解析」定义为最重要且最易被好心修复破坏的约束,并用 674 条断言守住 IP 规则的 `no-resolve`。但这条约束还有**第二根支柱没被任何断言守住**:

> `use-local-host-item-for-proxy`,default **false**。启用后,若目标域存在本地 DNS mapping,Surge 会**用 IP 而不是域名**建立代理连接。

而 `read-etc-hosts = true` 恰好保证 `/etc/hosts` 条目会成为 local DNS mapping。**两者叠加 = 精确地制造出该架构禁止的行为**,且 674 条断言看不见(它们只检 IP 规则的 `no-resolve`,不解析 conf 的这个键)。全库搜索:该键在 conf、文档、测试、裁决登记里**一次都没出现过**。

第三根支柱同理:`allow-dns-svcb` 缺失(默认 false)⇒ 拒绝 SVCB/HTTPS(type 65)查询,**恰好堵住「HTTPS RR 的 ipv4hint 绕过 fake-IP」这条路**。这是零本地解析闭环的一部分,但 `§4` 只讲了 `no-resolve` 与 `FINAL,dns-failed` 两根。

#### 证据 —— 策略组与节点

| 项 | 内容 | 级别 |
|---|---|---|
| **孤儿节点** | `[Proxy]` 段一条**英国方向链式条目**(名称从略)既不是任何组的显式成员,也不是任何条目的 `underlying-proxy` 目标;而全部 22 个组都写了 `include-all-proxies=0` ⇒ **永远无法被选中的死策略**。核验:22 个条目中 16 条是组成员、5 条仅作中转目标、**1 条不可达**。这类问题现有四件套完全看不见(audit 只扫 `lists/`,engine 只解析 `[Rule]`) | **P2 \| 确定,advisor 复核通过** |
| **`persistent` 9 处全惰性** | 官方文档中 `persistent` **只在 `load-balance` 组下定义**;`select` 的选择本来就会持久化,`smart` 没有粘性出口语义。危害不是行为错误而是**认知错误**:`persistent=1` 的字面含义(按目标站点粘住出口)恰好是 Payment 这类需求最想要的语义,一旦有人以为它生效,就会以为「粘性出口」这个能力已经有了。**要按目标站点粘出口只有 `load-balance` + `persistent=true` 一条路,而 Payment 已裁决必须 `select`** | P2 \| 确定 |
| **`Final` 组默认成员是家宽** | `select` 组默认选择是第一个成员 ⇒ 开箱即用状态下,`ProxyGFW.list` 6,469 条 + **全部未命中域名**这两个最大的长尾桶都跑在家宽线上。与区 3 注释「大文件走下载组不占家宽」及 `下载` 组把机房组放首位的做法**方向相反** | P2 \| 高置信 → 用户待决 2 |
| **AI / Google-X-Meta-MS 无组内逃生门** | 9 个业务组里 7 个含至少一个机房组或 `DIRECT`,只有这两个的成员**全部是家宽组**。这是刻意的(家宽出口对 AI 服务与大厂风控更友好),但 `select` 组**不会自动故障转移** ⇒ 三条家宽链同时降级时组内没有任何备选,必须改 conf 才能应急 | P2 \| 高置信 |
| **`policy-priority` 未加引号** | 当前每组只有一对且值内无逗号/分号 ⇒ **今天可解析、生效、方向正确**;隐患是加第二对时若用逗号分隔会被组解析器切成两个参数而静默丢弃。官方示例是带引号的 quoted list | P3 \| 确定 |
| **`Payment` 组裁决核验通过 ✅** | 组类型 `select` ✅;二级出口**不漂移** —— Payment 的三个代理候选都是 smart 组,但各组成员是**同一落地出口的多条中转路径**,3DS/风控看到的落地出口 IP 在组内恒定 ⇒ smart 的自适应只切换中转跳。**裁决在两级都成立。** 附带风险:第 4 个成员是 `DIRECT`,误切过去会从家宽变成本机国内出口 —— 最典型的 3DS 触发场景,建议在裁决登记补半句 | ✅ |
| **smart 组构成合法 ✅** | 6 个 smart 组的 16 个成员位全部是 `[Proxy]` 条目,无 `DIRECT`、无嵌套组;smart 组只出现在 `select` 成员位(`select` 不在受限清单内)⇒ 合法 | ✅ |
| **三个单成员 select 组** | 命名壳,**不是错误** —— 给上层四个组提供稳定的「按国家」命名层,换节点只改一行。若采纳孤儿节点方案 1,其中一个自然变成 2 成员 | P3 |

#### 证据 —— `update.sh` 与测试

| 项 | 内容 | 级别 |
|---|---|---|
| **新增分发表必然误报失败** | 先验阶段 `cdn_md5` 对**本次新增**的分发文件必然 404(CDN 上尚不存在),被计入 `fetch_fail_pre_n`;该计数**无条件**汇入 `problems`,即使随后 purge 成功、复验 md5 一致也不会撤销 ⇒ 一次**完全成功**的发布被判定为 `PUBLISHED_BUT_UNVERIFIED` 并 `exit 1`,且在收尾里被归入「**失败**·CDN 拉取失败」。本仓库近期 32→34 表,该路径**已被触发过两次**。这会训练维护者忽略退出码,直接侵蚀「退出码即结论」这条契约 | **P2 \| 确定,advisor 复核通过** |
| **IPv6 断言零覆盖** | `grep -c '"ip": *"[0-9a-f]*:"' tests/scenarios/` = **0**;20 条裸 IP 请求全部是 IPv4。而 conf 实配 `ipv6=true`,库内有 **3,947 条 `IP-CIDR6`** | P2 \| 确定 |
| **宽规则覆盖率** | 98 条宽规则(8 KEYWORD + 90 WILDCARD)中 **67 条无正向场景(68%)、79 条无负向样本(81%)**;场景里负例样式 host 仅 13 条 / 969。8 条 `DOMAIN-KEYWORD` 中 5 条**正 0 负 0**。`§8` 已裁决这 8 条「凭命中/误杀证据裁决」—— **但一条负例都没有,无法产生「误杀证据」** | P2 \| 确定 |
| **非 CN GEOIP 盲区被当成事实** | `ownership_fix.json` 的 `shared_cloud_ip_removed` 对 `35.192.0.1` / `18.194.0.1` 用了硬断言 `policy: "Final"`,而这**只在离线引擎里成立**(引擎无 MaxMind,7 条非 CN GEOIP 一律判不匹配,本轮触发 56 次)。RDAP 实证 `35.192.0.1` = US(GOOGLE-CLOUD)、`18.194.0.1` = DE(AMAZO-ZFRA)⇒ 真实 Surge 会在区 9 命中 `GEOIP,US`@US.list / `GEOIP,DE`@Europe.list。同文件的 `1.1.1.1 → Final` 断言**是正确的**(全库 GEOIP 只有 CH/DE/FR/GB/JP/NL/US 七国,无 AU)。对照组 `edge_cases.json` 的 `user_vps_ip_asn` 用 `policy_in` + 明确说明,是**教科书级正确做法** | P2 \| 确定 |
| **3 条待裁决被 `preventive` 永久静音** | exemptions[21]/[22]/[23] 的 reason 明写「本轮 fix_spec 未裁决,保留原状待用户决策」,却都带 `preventive: true` ⇒ `unused()` 对 preventive 条目**永不报告未使用** ⇒ **待裁决事项被伪装成永久豁免**。统计口径上更糟:30 条 exemptions 里 27 条是 preventive,真正参与「无用豁免」卫生检查的只有 3 条(10%) | P3 \| 确定 |
| **`runsuite.py` 无 `--rules`** | `engine.py` 与 `audit.py` 都有,只有 runsuite 没有。而 `engine.py:371` 的 rules_dir 推导硬编码为 `<conf 同级>/rules/lists/` ⇒ 任何放在 `tests/fixtures/` 的公共脱敏 conf 都会解析到不存在的目录。**这是公共 fixture 与 CI 的唯一硬阻塞**,改动 5 行 | P3 \| 确定 |
| **`modules/` `scripts/` 不在 `DIST_RE`** | 文档把它们定义为 jsDelivr CDN 资源,但发布正则不含这两个目录 ⇒ 永远不会被 purge。**当前不构成实际故障**(两目录只有 README + `_template`),是潜伏项。**现在不要扩 `DIST_RE`**(会把模板文件纳入 purge 候选白耗配额),改为加注释锚点 | P3 \| 确定 |

#### 证据 —— extended-matching 判定标准(P3 | 确定)

现状 11 开 / 23 不开,任务预设的「Games / GFW / 地区表漏配」经核验**恰恰有充分理由不开**。反推出的自洽判据:

> **判据 R**:当「本表策略」与「本表不命中后该请求最终会落到的策略」**不同**,且该表的流量存在**可能携带 SNI/Host 的字面量 IP 连接**时,才值得开 `extended-matching`。

按 R 复核 34 张表,**32 张一致**:国内直连各表兜底是 `ChinaIP`+`GEOIP,CN` ⇒ 同为 DIRECT,不开;`ProxyGFW` 策略就是 `Final`、与 FINAL 同组,不开(且代价是 6,424 条后缀 × 每连接 2 个额外匹配键);地区表自带 GEOIP/IP-ASN 在**同一位次**接住字面量 IP,不开;`Games` 的硬编码 IP 流量是**裸 TCP/UDP,没有 SNI 可取**,不开。

**真正的两个缺口**:

- **`Reject`**:策略与兜底差最远(REJECT ≠ 任何兜底),且广告/HTTPDNS SDK 是硬编码 IP 的高发区 ⇒ **按 R 应该是最该开的一张表**,现在却是唯一「差最远却完全不做扩展匹配」的表;
- **`DownloadCDN`**:存在**明文 HTTP + Host 头的按 IP 下载**(部分软件分发客户端的经典形态)。

但这个判据在 `ARCHITECTURE.md` / `MAINTENANCE.md` / conf 注释里**一个字都没有** ⇒ 下一个维护者要么误以为漏配而全表铺开,要么误以为是随意的。

**同批必须补的红线**:官方语义 —— 只要 set 文件里**任意一行**域名规则带 `extended-matching`,**整张表**的域名规则都会被打开。当前 `lists/` 行级为 0,conf 是唯一开关面;但上游合并很容易带进来,一行就能把最大 106,464 条的表的匹配语义改掉,而 audit 现在不检这个。

#### 证据 —— Clash 派生层的能力差额账本(P2 | 确定)

`ARCHITECTURE §5.2` 的转换约定表列了 `DOMAIN-WILDCARD` / `USER-AGENT` / `URL-REGEX` / 其余类型 / 未知类型五行,**唯独没有 `extended-matching`**;§5.2 末尾说「因为 UA / URL 两层被剔除,Clash 端精度必然略低,文件头的计数就是这份差额的账本」—— 但 **UA/URL 现在都是 0,那本账已经空了**,真正的差额已经全部转移到 `extended-matching` 上,而它**没有任何账本、且不可计数**。

11 张表(含 Payment、AI、Telegram)在 Surge 侧会用 SNI/Host 兜底,Clash rule-provider 无法携带该语义,必须由使用者显式配 `sniffer`。当前产物的注释块只说了 SYSTEM 无等价物、LAN 用 `GEOIP,lan` 近似,对 sniffer 只字未提。

#### 修复

| 动作 | 批次 |
|---|---|
| `update.sh` 404 一行修(复验 `verify_ok` 分支扣减先验失败计数) | **R0** |
| conf 显式写死 `use-local-host-item-for-proxy = false` + `MAINTENANCE §6` 红线第 8 条;`allow-dns-svcb` 默认值作用补进 `ARCHITECTURE §4` | R2 |
| 孤儿节点:加进英国组或从 `[Proxy]` 删除(用户裁决);删 9 处 `persistent`;`policy-priority` 加引号;`all-hybrid` 删或加注释 | R2 |
| `MITM` 重启用检查单补第三条(`block-quic` 从 `always-allow` 改回 `per-policy`);hostname 模板补正向项(现模板**全是排除项,照抄即空转**) | R2 |
| `shared_cloud_ip_removed` 两条断言改 `policy_in`;3 条 `preventive` 加 `pending_decision` 键;文档漂移 4 处;`runsuite --rules` 5 行 | R2 |
| IPv6 测试语料(8 条请求覆盖全部语义分支)+ 采集 IPv6 字面量连接占比 | R2 |
| `extended-matching` 判据 R 写进 `ARCHITECTURE §2`;`sniffer` 合同写进 `rule-providers.yaml` 头部与 `§5.2`;`lists/` 行级 `extended-matching` 判 P1 | R2 |
| Reject `pre-matching` 启用(**前置条件已核验通过**:Reject 被区 0 抢先命中 0 条、区 0 被 pre-matching 后的 Reject 抢跑 0 条)| R4 |
| `extended-matching` 补 Reject + DownloadCDN(需命中数据) | R4 / 观察 |
| 供应链 S1–S5(`--rules` → `rulesets.yaml` → 公共 fixture → CI → `sources.lock`,总计约 10 人时) | R3 |
| LICENSE 三方案 | 用户待决 4 |

---

## 4. 逐表状态总表

健康度口径:**优** = 无发现或仅 P3 备案;**良** = 有 P2/P3,不影响功能;**需整改** = 有 P1 或影响用户可感行为;**待重建** = 表的内容基础需要按判据重做。
条数取自各 worker 报告;标 † 者为**行数**(含表头注释与空行),未标者为**规则数**。

| # | 表 | 区 | 策略 | 条数 | 健康度 | 发现 | 本轮动作 | 批次 | 来源 |
|---:|---|---:|---|---:|---|---:|---|---|---|
| 1 | PrivateLAN | 0 | DIRECT | 148 | 优 | 1 | 与内建 LAN 的重叠**是必要的**(`198.18.0.0/15` fake-IP 段必须在区 0 判 DIRECT),写进裁决登记防被当冗余删;`p.to` 列零命中候选 | R2 | W3 |
| 2 | PKU | 0 | DIRECT | 22 | **需整改** | 5 | 删 `pkuiot.com`(未注册)/ `bdwm.net`(停放)/ `pkuecon.cn`(非北大主体、境外托管、证书过期)/ `IP-ASN,24355`(电子科大 CERNET2 IX,非北大)/ `202.127.16.0/20`(中科院 CSTNET);收窄 F1 豁免 | R1 | W3 |
| 3 | Reject | 1 | REJECT | 356 | 良 | 5 | 删 A 组 41 条死域(**B 组 20 条 `.cn` 必留**);修 2 条 wildcard 前缀锚定;5 处过期注释;`pre-matching` 前置条件已核验 | R1/R4 | W3 |
| 4 | GameDownloadCN | 2 | DIRECT | 66 | **需整改** | 3 | 删 `steambroadcast.com`(易主)+ `steamcontent.net`(停放);三段拆分(会话/UGC → Games);收窄 `xboxlive.cn`/`battlenet.com.cn` 到上游口径;消解与 Domestic 的双写 | R1/R2 | W2 |
| 5 | ModelDownloadCDN | 3 | 下载 | 4 | **需整改** | 1 | **4 条全失效** ⇒ 整表重写为 5 条 | R1 | W2 |
| 6 | YouTube | 4 | 流媒体 | 188† | 优 | 1 | 收 `yt3/yt4.googleusercontent.com` + `jnn-pa.googleapis.com`;接收 `IP-ASN,36040` | R1 | W1 |
| 7 | Google | 5 | Google-X-Meta-MS | 705† | 良 | 5 | 删 `IP-ASN,19527`/`43515` + 10 条死条目;21 条 `-cn` 族归属统一(先做可达性矩阵);11 条 GCP 多租户后缀待裁决 | R1/R2 | W1 |
| 8 | Twitter | 5 | Google-X-Meta-MS | 45† | 良 | 1 | 删 4 条(3 停放/易主 + 1 第三方开源库站) | R1 | W1 |
| 9 | Meta | 5 | Google-X-Meta-MS | 570† | **需整改** | 6 | 删 IP 区 27 条 + 合并 2 条 `/17`→`/16` + 补 `57.144.0.0/14`;删 X 3 + N 14;411 条 D 档迁 `reference/` | R1/R3 | W1/W3 |
| 10 | Microsoft | 5 | Google-X-Meta-MS | 39 | 优 | 1 | **加 `onedrive.live.com`(P1 止血)**;删 1 条死域 | R1 | W1/W5 |
| 11 | AI | 5 | AI | 389 | 良 | 5 | 删 4 条 PSL 边界后缀;收 `01.ai`/`siliconflow.com`;`sift.com`/`cdn.usefathom.com`/`cp4.cloudflare.com` 待裁决;**IP/ASN 区是全库正面样板** | R1/R2 | W2 |
| 12 | TikTok | 5 | 社交媒体 | 96† | 良 | 2 | 删 `courses.snapsolve.com`(Sedo 停放,观察期可结案)+ `bytedance.net`(解析 RFC1918);10 条 wildcard 不自洽,整组待裁决 | R1/R4 | W1 |
| 13 | SocialOthers | 5 | 社交媒体 | 24 | **优** | 0 | 无动作。所有权 100% 正确,无停放域、无云共享段、无 IP 区 | — | W1 |
| 14 | Telegram | 5 | Telegram | 57† | 良 | 1 | 删 `telegramdownload.com` + `194.221.250.50/32`;2 条 `/32` 加 `last_verified`。**IP 区质量全库最好,v4/v6 最对称(10/4)** | R1/R4 | W1 |
| 15 | Streaming | 5 | 流媒体 | 3,118 | **待重建**(IP 面) | 8 | IP 面 1,975 → 19(D1/D3/D4 删 1,114、D5 观察 836、D6 迁 6);22 条公司资产域移出;4 条无右锚 wildcard 备案;BBC 全族 → UK | R2/R4 | W2/W4 |
| 16 | Games | 5 | 游戏 | 532 | 良 | 1 | 18 条 AWS EC2 弹性 `/32` 加 `last_verified` 或删(Blizzard 10 条保留);接收 GameDownloadCN 的会话/UGC 面;Cygames 2 条交回 Japan | R1/R4 | W2/W4 |
| 17 | DownloadCDN | 5 | 下载 | 5,559 | **需整改** | 6 | 删 321 条 S3 家族 + 40 条其他 PSL 边界 + 19 条 SaaS 组件;23 条批量归位;114 条非下载面进人工复核队列;Datadog/Intercom/Mixpanel 跨表分裂 4 条 | R1/R2 | W2/W4 |
| 18 | Payment | 6 | Payment | 65 | 良 | 2 | 收 `online-metrix.net`(ThreatMetrix);建 `payment_chain.json` 把 4 条 `§8` 裁决固化成断言。**被前位遮蔽 0、抢占后位 0,14 个真实 checkout/3DS host 全部落 Payment** | R1/R2 | W3 |
| 19 | AppleCN | 7 | DIRECT | 1,539† | 良 | 4 | 删 `DOMAIN-KEYWORD,smp-device`(观察期结案,已退化为纯过捕获);13 条 IP 规则**全部唯一生效**;`17.0.0.0/8` 与 `skip-proxy` 是**互补路径,均需保留** | R1 | W5 |
| 20 | MicrosoftCN | 7 | DIRECT | 77† | **需整改** | 1 | 表本身不改(改在 `Microsoft.list` 侧);补 `msocsp.com`;`office.com`/`msn.com` 保留宽 DIRECT | R1 | W5 |
| 21 | ProxyGFW | 8 | Final | 6,469 | 重定位 | 5 | **不删表**,重定位 + 验收标准改按 18 条承载集;IP 区 JP/KR 12 条迁 Japan、AWS/SoftLayer 共享云段删、`14.102.250.18/31` 删;3 条 Akamai 宽后缀按 D6 登记;769 条死域并入再生过滤器 | R1/R2/R3 | W3/W7 |
| 22 | Japan | 9 | 🇯🇵日本节点 | 85 | **需整改** | 8 | 删 `paravi.jp`;接收 Prime Video JP / Niconico / Cygames / DLsite 属地锁面;5 条 IP-ASN 登记为观察项;`au.com`/`e-hentai` 保留理由入 `§8` | R1/R2 | W4 |
| 23 | UK | 9 | 🇬🇧英国节点 | 37 | **需整改** | 3 | **接收 BBC 全族 10 条 + 删 DownloadCDN 1 条**;接收 `secure./static./cf.eip.telegraph.co.uk`;`ac.uk`/`gov.uk`/`nhs.uk` 保留理由入 `§8` | R1/R2 | W4 |
| 24 | Europe | 9 | 🇪🇺欧洲节点 | 72 | 良 | 1 | GEOIP 四条口径写进表头 + `§8`(方案 A);接收 4 条静态子域。**改 GEOIP 前须先开 http-api** | R2 | W4 |
| 25 | US | 9 | 🇺🇸美国节点 | 53 | **需整改** | 4 | 删 `espnplus.com` + `tubi.io`;Fox/CBS/NBC/Fubo 7 域 → Streaming(依赖用户待决 1);接收 6 条静态子域 | R1/R2 | W4 |
| 26 | Domestic | 10 | DIRECT | 611 | 良 | 6 | 删 2 条 IP 死条目;补 3 条 CA 端点;`01.ai`/`siliconflow.com` 迁出;`zimuzu.tv` 类停放域;141 条被 ChinaDomain 覆盖 → 只做 P3 报告项**不批量删** | R1/R2 | W5 |
| 27 | ChinaMedia | 10 | DIRECT | 994 | **需整改** | 5 | **删 11 条 `domesticmedia*` 幽灵规则**;删 `zimuzu.tv`;38 条被厂商表覆盖 → 表头加说明不大改 | R1/R2 | W5 |
| 28 | TencentCN | 10 | DIRECT | 2,270† | **需整改** | 2 | **删 14 条海外 `/24`**(全是死条目 + 虚假保障)+ 撤销 A2 豁免 + 改表头 | R1 | W5 |
| 29 | AlibabaCN | 10 | DIRECT | 1,260† | 良 | 1 | 观察项(`ics.design`/`doctoryou.ai` 疑似易主) | R4 | W5 |
| 30 | ByteDanceCN | 10 | DIRECT | 359† | **优** | 0 | 无动作 | — | W5 |
| 31 | BaiduCN | 10 | DIRECT | 235† | **优** | 0 | 无动作 | — | W5 |
| 32 | NetEaseCN | 10 | DIRECT | 115† | **优** | 0 | 无动作 | — | W5 |
| 33 | ChinaDomain | 10 | DIRECT | 106,464 | **待重建** | 8 | 171 条 `DOMAIN` 逐条处置;再生过滤器护栏版落地(shadow 2 轮);44 条整 TLD 拆 `ChinaTLDHeuristics`;11 条 PSL PRIVATE 后缀;3 条可疑二级形态立即核查;`stripe`/`beplay` 入 forbidden | R1/R2/R3 | W6 |
| 34 | ChinaIP | 10 | DIRECT | 11,090 | 良 | 2 | 同步上游(v4 缺 59 段 / v6 缺 540 段);154+28 条跨表包含登记 exemption;**`sources.lock` 首个落地对象** | R2/R3 | W6 |

**汇总**:优 **7** / 良 **13** / 需整改 **11** / 待重建 **2**(Streaming 仅 IP 面、ChinaDomain 整表)/ 重定位 **1** = **34**。

---

## 5. 反向澄清 —— 对上轮报告的修正

本章存在的唯一目的:**防止照单全收上轮 backlog**。下列 8 项在上轮被列为待办或问题,本轮实测后判定为「不做」或「方向需要修正」。每一项都应写进 `§8` 裁决登记,否则下一轮会被重新「发现」一遍。

| # | 上轮结论 | 本轮判定 | 证据 |
|---|---|---|---|
| 1 | 拆 `DirectExceptionsPreGFW` 表 | **不建** | 用真实规则序对 9 张国内表 **7,400 条域名规则逐条**判定,**被前位表抢跑 = 0 条**(含 keyword / wildcard 口径)⇒ 该表的**初始载荷为空**。为一张空表新开一个 conf 区是纯成本(分发候选 69→71、多 2–4 次 purge 调用、放大 jsDelivr 路径级限流风险、5 份手抄顺序全要改)。**采纳替代**:抢跑门禁(A4 扩展)+ DIRECT 解析分歧检测入 `live_check` + CA 完整性场景 |
| 2 | Payment 前移到 DownloadCDN 之前 | **不动** | 全量扫描:Payment 65 条**被前位表遮蔽 0 条、抢占后位 0 条**;逐条实测 14 个真实 checkout/3DS host 全部落 Payment 组。上轮担心的「支付组件用多租户 CDN 后缀而 Payment 无该精确租户 host」在实测中**未复现** —— 主流 PSP(Stripe/Adyen/Braintree/Checkout.com/Klarna/PayPal)的 checkout 与 3DS 端点都在自有域下。**唯一动作 = 补 ThreatMetrix + CA 断裂中涉支付的部分** |
| 3 | AppleCN 的品牌防御域组是 Meta 式过捕获 | **非问题** | 按品牌词表筛出 335 条不含 Apple 品牌词的条目,40 条抽样核验:**27 条(67.5%)解析进 Apple 自有 `17.0.0.0/8`**(该段本就由 `AppleCN.list:1526` 直连)、11 条(27.5%)无 A 记录,仅 2 条落在 Apple 段外。**不构成 Meta 式风险,不建议按 Meta 方案拆 operational/brand-archive** |
| 4 | Apple 媒体域拆分是缺陷 | **刻意取舍** | 核验:Streaming(区 5)先于 AppleCN(区 7),34 条 apple/itunes/mzstatic/icloud 相关条目**全部有效,无一被遮蔽**;反向 AppleCN 也无条目被抢跑。会话确实是拆的(目录与授权面走代理、媒体字节与封面走直连),但这与 D4「大流量不占代理」取向一致,且 **Apple 的区域判定绑 Apple ID 而非出口 IP** ⇒ 不判为缺陷,登记为观察项 |
| 5 | IPv6 服务 IP fallback 不对称需补段 | **缓,先补测试语料** | 采纳降级意见:全库 13,333 条 IP 类规则**全部带 `no-resolve`**,只对已携带字面量 IP 的连接生效;而 `hijack-dns = *:53` + fake-IP 应答器把绝大多数连接还原成域名(**规则始终看到原始域名,即便客户端自行解析**),`allow-dns-svcb=false` 又堵掉 HTTPS-RR 的 IP hint 绕过路径 ⇒ 真正会走到 IP 规则的只剩**硬编码 IPv6 字面量**的连接。**行动 = 先补 IPv6 literal 测试语料(当前 3,947 条 `IP-CIDR6` 对 0 条测试)+ 采集 IPv6 字面量连接占比,有数据再决定补段;不机械映射 v4 云段** |
| 6 | region 只是 policy 属性、服务 owner 决定归属 | **不照搬** | 见 §3.6。本配置的策略层**无法表达「本服务需要某国出口」**。裁定:属地锁内容的 owner = **能提供正确出口的表** |
| 7 | `ChinaIP` 与 `GEOIP,CN` 双兜底冗余 | **保留双层** | 见 §3.7。ChinaIP 独有 4.109% v4 地址(含 mmdb 标不出来的大厂 anycast 大陆 PoP 碎片),GEOIP 独有 0.018% v4 且与「本地落后两天」完全重合;且 `engine.py` 的 `GEOIP,CN` 判定**硬引用 ChinaIP.list 做近似** |
| 8 | 拆 Domestic 为 NetworkInfra / CA / ManualDomestic | **不做** | 拆完之后落点不变、优先级不变、可读性提升有限(表内已按类型分区 + 字母序,表头已声明 CA 用途),而成本可量化:conf 每张新表 +1 行(与「conf 保持简洁」既定裁决冲突)、分发候选 69→73、`surge2clash.py`/`rule-providers.yaml`/README 34 表清单/`ARCHITECTURE §3`/`MAINTENANCE` 决策树全要改、mihomo 守恒基线需重标定。**CA 覆盖是「清单完整性」问题,不是「表结构」问题 —— 拆表不会让清单变全,断言会** |

**另两条需登记的「勿当缺陷」结论**:

- **`PrivateLAN` 与内建 `LAN` 的重叠是必要的**:①位次决定一切(PrivateLAN 在区 0 第 2 条,内建 `LAN` 在 ChinaIP 之后);②`198.18.0.0/15` 是 Surge 自己的 fake-IP 段,必须在区 0 判 DIRECT,否则 fake-IP 回环会被后续规则接管;③覆盖面更广(`0.0.0.0/8`、`100.64.0.0/10` CGNAT、TEST-NET、多播、6to4 relay,内建集不含)。
- **区 9 地区表的 GEOIP 对裸 IP 会话构成「第二个 FINAL」,但 D8 没有被违反**:向前看,所有更早的 IP 规则(AppleCN 17/8、ProxyGFW 40 条、Streaming 1,975 条、Games 42 条、四张生态表的 IP+ASN)都在区 9**之前,没有被遮蔽**;真正的效应是把原本落 `Final` 的裸 IP 流量按目的国提前分走(受影响的具体类别:未枚举的游戏服务器裸 IP、BT/P2P 对端、NTP/STUN/DoH-by-IP)。**不建议改位次**(改位次直接违反 D8);要保留「裸 IP 游戏流量走游戏组」只能在 `Games.list` 补精确游戏服务器段。

---

## 6. 迭代路线 R0–R4

执行模式沿用既有约定:**Fable 写批次 spec → Opus 并行执行 → `audit --fail-on P1` + `runsuite` 双闸门 → 单次发布**。
每个批次的**通用验收**(下表不再重复):`python3 tests/audit.py --check all --fail-on P1` exit 0;`python3 tests/runsuite.py` 全绿;`python3 tools/surge2clash.py --check` exit 0;规则守恒基线随条数变化**重新登记**并写进 `CHANGELOG.md`。
回滚:变更前打 tag;出问题按 `MAINTENANCE §7.2` 走 `git checkout <good> -- lists/` + 重跑 `update.sh`(**必须重 purge**)。

### R0 · 保险丝(发布前必做,防打红)

> 这三项的共同特征:**不做就会在下一次正常操作中产生假失败或泄漏**,且都是一次性小改动。

| # | 动作 | 涉及文件 | 验收标准 | 依赖 |
|---|---|---|---|---|
| R0-1 | `kw_direct.json` 6 条断言从硬 `policy: "Final"` 改为 `policy_in` 双态可接受(或拆 `pre-regen`/`post-regen` 两场景),reason 引 `§8`「再生回收属预期」 | `tests/scenarios/kw_direct.json:69,95,96,125,188-191,209` | 现状 `runsuite` 仍 1731/1731 全绿;**模拟再生后(把 6 域临时移出 ProxyGFW)仍全绿** | 无 |
| R0-2 | `update.sh` 先验 404 一行修:复验 `verify_ok` 分支扣减 `fetch_fail_pre_n`;`report_group` 文案区分 404 与网络错 | `update.sh:228-234, 304-305` | 用 W7 的桩脚本跑 S1–S7 七场景:**S3(先验 404 + purge ok + 复验一致)从 exit 1 变 exit 0,其余六个状态不变** | 无 |
| R0-3 | 文档打码:带厂商标识的备份 conf 文件名改中性描述;`live_check.py` 注释示例改占位符 | `docs/MAINTENANCE.md:244`、`tests/live_check.py:1358` | 用本地覆盖档 token 集重跑脱敏扫描,**真命中降为 0**(14 处巧合子串入白名单并注明) | 无 |

### R1 · 立即修复(全部「确定」级,一个发布批次)

> 纳入条件:证据为**确定**级、动作为删除或精确新增、**不依赖用户裁决、不依赖抓包**。共 24 项。

| # | 动作 | 涉及文件 | 验收标准 | 依赖 |
|---|---|---|---|---|
| R1-01 | **加 `DOMAIN-SUFFIX,onedrive.live.com`**(P1 止血) | `lists/Microsoft.list` | 4 条正例(`onedrive.` / `skyapi.` / `photos.` / `snapshot.onedrive.live.com` → Google-X-Meta-MS)+ **3 条负例**(`office.live.com` / `view.officeapps.live.com` / `g.live.com` 仍 DIRECT,防误伤);上线后 `curl -s -o /dev/null -w '%{http_code}' https://onedrive.live.com/` **期望非 000** | R0 |
| R1-02 | **ModelDownloadCDN 整表重写为 5 条** | `lists/ModelDownloadCDN.list` | `curl -sI` 取一次 302 的 Location,确认该 host 被区 3 命中;`hf.co` 主站仍落 AI;新增断言 `us.aws.cdn.hf.co → 下载`、`huggingface.co → AI` | R0 |
| R1-03 | **删 11 条 `domesticmedia*` 幽灵规则** | `lists/ChinaMedia.list:339-349` | `grep -rn domesticmedia lists/ clash/` 为空;`runsuite` 无变化;forbidden 登记 `DOMAIN-SUFFIX,domesticmedia*` 防再生带回 | R0 |
| R1-04 | 删 `steambroadcast.com` + `steamcontent.net` | `lists/GameDownloadCN.list:53,56` | `grep -rn "steambroadcast.com\|steamcontent.net" lists/` = 0;A8 新增模式命中 0;新增断言 `steambroadcast.com → Final` | R0 |
| R1-05 | 区 0 清理 5 条(`pkuiot.com` / `bdwm.net` / `pkuecon.cn` / `IP-ASN,24355` / `202.127.16.0/20`) | `lists/PKU.list:4,8,10,24,29`、`tests/allowlist.json` F1 豁免 | `engine.py match bdwm.net` 从 `DIRECT\|PKU.list` 变 `Final\|Surge.conf`;`bbs.pku.edu.cn` 仍 `DIRECT\|PKU.list`;A2 原始命中从 11 降为 10 且豁免表无「未命中」告警 | R0 |
| R1-06 | **Meta IP 区:删 27 条 + 合并 2 条 `/17`→`/16` + 补 `57.144.0.0/14`** | `lists/Meta.list:526-566` | 正例 `157.240.200.1` literal → Google-X-Meta-MS;**负例 `184.173.128.1` / `108.177.8.1` / `119.235.224.1` / `54.235.23.242` literal 不得落 Google-X-Meta-MS**;674 条 DNS 泄漏断言全绿 | R0 |
| R1-07 | 删 LINE 3 段(随 R1-06 同批,W1/W3 交叉印证) | `lists/Meta.list:550,551,552` | `engine.py match 119.235.224.5` 不再落 Google-X-Meta-MS | R1-06 |
| R1-08 | 删 `twimg.org` / `twimg.co` / `tellapart.com` / `twitteroauth.com` | `lists/Twitter.list:12,14,16,24` | `grep` 为空;`runsuite` 全绿 | R0 |
| R1-09 | 删 `musespark.ai` / `facebookquotes4u.com` / `ip6.static.sl-reverse.com` | `lists/Meta.list:208,436,457` | 负例 `musespark.ai` **不得**落 Google-X-Meta-MS | R0 |
| R1-10 | 删 `telegramdownload.com` + `194.221.250.50/32`;2 条 `/32` 加 `last_verified` | `lists/Telegram.list:30,42,45,46` | `runsuite` 全绿 | R0 |
| R1-11 | 删 `courses.snapsolve.com` + `bytedance.net` | `lists/TikTok.list:5` 等 | `runsuite` 全绿;观察记录补「apex 已被 ByteDance 置空」 | R0 |
| R1-12 | **删 321 条 S3 家族**(以脚本重算为准,不以人工计数为依据) | `lists/DownloadCDN.list` | ①`grep -cE '^DOMAIN-SUFFIX,s3' lists/DownloadCDN.list` = **0**;②forbidden 新增族模式命中 0;③负例「任意 `<random>.s3.us-east-1.amazonaws.com` 不得落下载组」 | R0 |
| R1-13 | 删 40 条其他 PSL 边界后缀(**保留** `claude.app` / `claudeusercontent.com` / `oaiusercontent.com` / `.bbc` / `ac.uk` 族 / `au.com`) | `lists/DownloadCDN.list`、`lists/AI.list` | A10 上线后 PSL 命中数 == 已登记豁免数 | R0 |
| R1-14 | 删 19 条通用 SaaS 组件 + 4 条跨表分裂(Datadog 1 / Intercom 2 / Mixpanel 1) | `lists/DownloadCDN.list` | `grep -rn datadoghq lists/` 只出现在 AI.list;Intercom 四域统一归 AI;Mixpanel 两条统一归 ProxyGFW | R0 |
| R1-15 | 删 `IP-ASN,19527` / `IP-ASN,43515`;`IP-ASN,36040` 迁 YouTube.list | `lists/Google.list:703,704,705`、`lists/YouTube.list` | 负例「literal IP 34.x/35.x(非 Google 产品)不得落 Google-X-Meta-MS」;确认 exemptions[2](YouTube 相关条目被前位遮蔽属预期)仍覆盖 | R0 |
| R1-16 | YouTube 三分裂归位:新增 `DOMAIN,yt3/yt4.googleusercontent.com` + `DOMAIN,jnn-pa.googleapis.com` | `lists/YouTube.list` | 断言 `yt3.googleusercontent.com → 流媒体`;不动 `Google.list` 宽后缀(保持唯一归属) | R1-15 |
| R1-17 | **删 TencentCN 14 条海外 `/24` + 撤销 A2 豁免 + 改表头** | `lists/TencentCN.list:2257-2270`、`tests/allowlist.json` | `w5_ip.py` 复算 14 段落点不变(仍 DIRECT);674 条 DNS 断言不变;A2 命中数由 11 降至 4 可作为**上游漂移信号** | R0 |
| R1-18 | 删 Domestic 2 条 IP 死条目 | `lists/Domestic.list:617,618` | 落点不变 | R0 |
| R1-19 | 删 `smp-device` 关键词 + 从 `§8` 观察项清单划掉(8→7) | `lists/AppleCN.list:1524` | 所有 Apple 场景不变;**负例 `smp-device.example.com` 不落 DIRECT** | R0 |
| R1-20 | 删 `zimuzu.tv`、`qcly.xyz`(解析回环)、`trpc.tech`(内网地址) | `lists/ChinaMedia.list:982`、`lists/TencentCN.list:893,1888` | `runsuite` 全绿 | R0 |
| R1-21 | **Reject A 组 41 条死域清理 + wildcard 语义回归修复** | `lists/Reject.list`、`tests/scenarios/reject_layer.json` | ①先取基线 `runsuite --filter reject_layer` = 151/151;②删 A 组后仍全通(同步改用到 `mindmanager.cc`/`smgru.net`/`pinzhitmall.com` 的 3 条断言);③**新增正例 `www.hostingcloud.racing`、`a.hostingcloud.download`;新增负例 `myhostingcloud.com` 落 Final**;④**B 组 20 条 `.cn` 保留理由写进 `§8`** | R0 |
| R1-22 | 归属精化五组:`espnplus.com` 删 / `tubi.io` 删 + `tubi.tv` 两条 `DOMAIN` 合并为 `DOMAIN-SUFFIX` / `paravi.jp` 删 / `secure.telegraph.co.uk` 删 / `sourcepoint.theguardian.com` 删 | `lists/US.list:23,47`、`lists/Streaming.list:59,72`、`lists/Japan.list:48`、`lists/DownloadCDN.list:4523,4609` | `plus.espn.com` 仍落流媒体、`espnplus.com` 落 Final;**`api.tubi.tv` 空洞消失**;`secure.telegraph.co.uk` 落 🇬🇧英国节点 | R0 |
| R1-23 | 档 3 批量归位 23 条(一次 diff、一次 runsuite) | `lists/DownloadCDN.list`(23 处删除) | 对每个已处置注册域枚举其全库 host,`engine.match()` 复算后 **policy 集合 size == 1**;地区表**零新增行** | R0 |
| R1-24 | 归属统一四项:ThreatMetrix 入 Payment / `01.ai` + `siliconflow.com` 迁 AI / CA 补 4 条(`crl.sectigo.com`、`secure.globalsign.com`、`ocsp.verisign.com`、MicrosoftCN 的 `msocsp.com`)/ Google 21 条 `-cn` 族归属统一 | `lists/Payment.list`、`lists/AI.list`、`lists/Domestic.list`、`lists/MicrosoftCN.list`、`lists/Google.list` | ①`engine match h.online-metrix.net` → Payment,新建 `payment_chain.json` 的 `payment_full_chain_same_exit` 场景(`same_policy: true`)通过;②新 CA 条目不被前位遮蔽(`w5_shadow.py` 复算仍为 0);③**`-cn` 族先做逐端点可达性矩阵再迁,不可整族一次改**(`googleadservices-cn.com` 的 `www` 对来源有区分) | R0 |

**R1 收尾**:`ARCHITECTURE §5.3` 守恒基线由 143,640 重新标定;`CHANGELOG.md` 记录每类删除的条数与原因分类。

### R2 · 门禁升级

> 目标:把 R1 用到的每一条**判据**变成机器强制,使同类问题不会在下一轮重新出现。

| # | 动作 | 涉及文件 | 验收标准 | 依赖 |
|---|---|---|---|---|
| R2-1 | **A9 · IP 跨表包含/遮蔽审计**实装(Patricia trie 或按前缀长度分桶;同策略 → P3 不阻断,**跨策略 → P1**) | `tests/audit.py` | 对当前仓库输出 **154 条同策略 + 1 条跨策略**;把 `74.125.16.64/26` 那条写进 exemptions;门禁只对**新增跨策略交叠**报警 | R1 |
| R2-2 | **A10 · 单标签后缀与 PSL 边界门禁**实装(IANA TLD 表 + PSL 快照锁定并入 `SOURCES.md`;正确处理 `*.parent` 与 `!exception`);同一逐行循环内顺带做 arity / 严格 CIDR(`strict=True`)/ modifier 白名单 / 大小写归一 | `tests/audit.py`、`tests/allowlist.json` | ①60 条现存单标签后缀(52 真实 gTLD + 8 条 RFC6761 特殊用途名)一次性入 allowlist ⇒ **首次上线 0 误报**;②PSL 命中数 == 已登记豁免数;③同时修掉 A7/A8 大小写敏感 —— 注入 `user-agent,X` 应改判 **A8/P0** | R1 |
| R2-3 | **A12 · 文档-实现漂移检查**实装(首批:forbidden 18→130、CHANGELOG 126→130、`DEVELOPMENT.md` 65→69、`tests/README`) | `tests/audit.py`、6 份文档 | 可断言量:`lists=34` `clash=34` `dist=69` `ext_matching=11` `scenarios=147` `assertions=1731` `dns_assertions=674` `clash_rules=143640` `exemptions` `forbidden`;`grep -rn "forbidden 1[0-9] 条\|65 个" tests/README.md docs/` 为空 | R2-6(拓扑 manifest) |
| R2-4 | forbidden 加 `file` / `not_file` 作用域 + **34 条禁收模式入表** + 补 selftest S34/S35 | `tests/allowlist.json`、`tests/audit.py:625-685` | ①补表后 `audit --check A8 --fail-on P0` 仍 **0 命中**;②逐条验收:合成含该行的 `.list` 确认判 P0,放到「允许存在」的表确认不误报;③`audit --selftest` ≥35/35 | R1 |
| R2-5 | `shared_cloud_ip_removed` 两条断言改 `policy_in`;3 条 `preventive` 加 `pending_decision` 键并在摘要独立打印 | `tests/scenarios/ownership_fix.json`、`tests/allowlist.json`、`tests/audit.py` | `runsuite` 仍 1731/1731;`audit --selftest` 33/33;退出码不变 | 无 |
| R2-6 | IPv6 测试语料(8 条请求覆盖全部语义分支)+ A/AAAA 差分场景 | `tests/scenarios/ipv6_parity.json` | 先用 `engine.py match <v6> --json` 取现状写成 `policy_in` 的一项、期望写成另一项;**新场景打红是目的而非 bug**;每条带 `no_dns_leak: true` | 无 |
| R2-7 | 文档与注释登记(一批):`§8` 补登记本轮全部裁决;`ARCHITECTURE §2` 补 ProxyGFW 重定位 + `extended-matching` 判据 R;`§4` 补零本地解析第三根支柱;`§5.2` 补 sniffer 合同;conf 区 1/区 8 注释修正;`rule-providers.yaml` 头部 sniffer 合同;`MAINTENANCE §6` 红线 +2 条(`use-local-host-item-for-proxy` / 行级 `extended-matching`) | `docs/*`、`Surge.conf` 注释、`tools/surge2clash.py` 模板 | `surge2clash --check` 因头部注释变化报漂移(**预期**),同批再生后回到 exit 0;A12 的文档断言全绿 | R2-3 |
| R2-8 | conf 侧修正:显式写 `use-local-host-item-for-proxy = false`;删 9 处 `persistent`;`policy-priority` 加引号;孤儿节点入组或删;MITM 检查单补第三条 + hostname 模板补正向项;`modules/`/`scripts/` 加 `DIST_RE` 待办注释锚点;`.gitignore` 补 `findings.jsonl` / `report.md` / `*.tsv` | `Surge.conf`、`update.sh:36`、`.gitignore` | Surge profile `--check` 通过;组详情里 priority 仍显示生效;`git status` 干净 | 用户待决 3、7 |
| R2-9 | 属地锁归位(依赖用户待决 1):BBC 全族 → UK + 同步改 `region_coverage.json`;Niconico → Japan;Cygames API → Japan;Fox/CBS/NBC/Fubo → Streaming | `lists/UK.list`、`lists/Japan.list`、`lists/Streaming.list`、`lists/US.list`、`lists/Games.list`、`lists/DownloadCDN.list`、`tests/scenarios/region_coverage.json` | ①`bbc.co.uk` / `www.bbc.co.uk` / `bbci.co.uk` / `open.live.bbc.co.uk` 四个 host 全部落 🇬🇧英国节点;②真机打开 iPlayer 播放页确认不出属地拒绝页;③六个 Niconico host 全落 🇯🇵日本节点;④`api-priconne-redive.cygames.jp` 落 🇯🇵日本节点 + 真机启动游戏不出「地域外」提示 | **用户待决 1**;Prime Video JP / DLsite 需先抓包 |
| R2-10 | GameDownloadCN 三段拆分 + 收窄上游口径 + 消解 G-03 双写 | `lists/GameDownloadCN.list`、`lists/Games.list`、`lists/Domestic.list:509,510` | ①断言 `cm.steampowered.com → 游戏`(与 `store.steampowered.com` 同组)、`<x>.steamcontent.com → DIRECT`;②**带宽实测(必做)**:改动前后各跑一次 Steam 大作下载记录峰值速率,若 `cm.steampowered.com` 改代理后出现登录/好友异常或下载协商变慢则回滚该条并登记裁决 | R1 |
| R2-11 | Europe GEOIP 口径(方案 A):表头 + `§8` 写明「GEOIP 层只对裸 IP 生效,当前覆盖 CH/DE/FR/NL;域名层按实体枚举,含 BE/LU/跨国实体,**两层刻意不对齐**」 | `lists/Europe.list` 表头、`docs/MAINTENANCE.md §8` | 纯注释;**若改 GEOIP 本身则须先开 http-api**(离线引擎无法验证非 CN 的 GEOIP) | 用户待决 1 |

### R3 · 机器层与供应链

| # | 动作 | 涉及文件 | 验收标准 | 依赖 |
|---|---|---|---|---|
| R3-1 | **`sources.lock.json` 从 ChinaIP 先行**:`provenance: pinned` + `upstream_sha256` + `transform` 链 + `expect.set_sha256`;配 `tools/fetch_locked.py`(校验不匹配即 exit 1,**禁止 `git pull` 后直接覆盖**)+ `tools/rebuild.py` | 新增 `sources.lock.json`、`tools/`、`tests/audit.py`(lock 一致性并入 A12) | `rebuild.py` 对 ChinaIP **diff = 0**(今天就应成立);ChinaIP 同步上游后 v4 补 59 段 / v6 补 540 段,`collapse_cidr --verify --against` 证明**只增不减** | R2-2 |
| R3-2 | **`tools/regen_chinadomain.py` 入库(护栏版)**:六级流水线 + P1–P10;`update.sh` **不**自动调用(再生是低频、有人值守操作),在 `MAINTENANCE §0` 旁加一条再生回路 | 新增 `tools/regen_chinadomain.py`、`tools/state/chinadomain.json`、`docs/MAINTENANCE.md` | 12 项硬门禁全过:产出表 `DOMAIN-KEYWORD` == 0、三类型 == 0、A8 0 命中、**单轮删除比例 ≤20% 且落在预测区间 [4,623, 7,380]**、每条删除项报告齐全(3×resolver 答案 / AAAA / intl 答案 / CNAME 链 / ASN·CC / streak)、**0 条删除项触发过 P3 或 P10**、每条经 `engine.py` 复核落点 ∈ {Final, ProxyGFW}、17 条投毒域在产出表中不存在(须能**独立复现**而非靠 ProxyGFW 抢跑)、6 条再生回收域正确回收为 DIRECT 且 R0-1 已同步 | R0-1、R2 |
| R3-3 | 逐次运行:第 1、2 次 `--shadow`(只写 `state.json` 与报告,人工抽查 30 DROP + 30 KEEP);第 3 次起 `--apply`(P7 迟滞满足才真删);QUARANTINE 单独出 `quarantine.txt` 交 P5 实测 | 同上 | 影子两轮的判定与本轮抽样外推**同量级**;P5 实测通道就绪 | **用户待决 6** |
| R3-4 | ChinaDomain 171 条 `DOMAIN` 处置:必删投毒 4(转 ProxyGFW)+ 建议删境外 77;保留港台 12 + 国内 22;死域 56 交 NO_A 桶 | `lists/ChinaDomain.list:5-175`(经再生管线) | 负例断言 `analytics.strava.com` / `hls.kqed.org` / `live.streamingfast.net` 落 **Final 而非 DIRECT**;正例 `ksn-dc1.geoksn.kaspersky.com` 锁住 DIRECT | R3-2 |
| R3-5 | 拆 `ChinaTLDHeuristics.list`(位次紧贴 ChinaDomain 之后 ⇒ **行为完全等价**);T1 品牌 gTLD 8 条上移厂商表;T3 境外注册局 7 条挂 90 天观察期;3 条可疑二级形态用 PSL 快照立即核查 | 新增 `lists/ChinaTLDHeuristics.list`、`Surge.conf` +1 行、README/ARCHITECTURE/MAINTENANCE/tests README 表数 34→35、分发候选 69→71 | ①`runsuite` 147 场景 1731 断言**全绿且逐条落点不变**(等价性证明);②`ChinaDomain + ChinaTLDHeuristics` 规则数之和 == 改造前 ChinaDomain 规则数(守恒);③`region_coverage.json:241` 的「由 `DOMAIN-SUFFIX,cn` 承接」断言同步改指向新表;④T1 每个 TLD 各加 1 条正例断言 | R3-2、R2-2 |
| R3-6 | Meta 411 条 D 档迁 `reference/` 本地库存档(**不入库、不分发**;不建 `inventory/` 新目录 —— 与「conf 简洁、仓库只放生效物」的既有偏好一致);同批删 X 3 + N 14 | `lists/Meta.list`(520 → 92 或 64)、`reference/` | ①正例 `facebook.com` / `scontent.cdninstagram.com` / `web.whatsapp.com` / `www.threads.com` / `graph.oculus.com` / `www.meta.com` → Google-X-Meta-MS;②负例 `acebook.com` / `facebookporn.org` → **不得**落 Google-X-Meta-MS;③`surge2clash --check` exit 0,`ruleCount` 守恒基线按新条数重新登记 | R1-06 |
| R3-7 | ProxyGFW 死域分批(766 条,**承载集交集 3 条必留**)并入再生管线的存活过滤器 | `lists/ProxyGFW.list`、再生管线 | **硬性**:18 条承载集不丢失(重跑 `dedup.py` 后位比对段);`runsuite` 全量 0 回归;剔除原因分类计数写进 `CHANGELOG` | R2-7 |
| R3-8 | 供应链 S1–S5:S1 `runsuite --rules`(5 行,**所有后续阶段的前置**)→ S2 `config/rulesets.yaml` + `tools/gen_topology.py --check`(杀掉 5 份手抄顺序)→ S3 `tests/fixtures/Surge.test.conf`(公共脱敏 conf)→ S4 `.github/workflows/gate.yml` → S5 `sources.lock`(诚实版,带 `provenance` 枚举允许「锁不住」被如实表达) | `tests/runsuite.py`、新增 `config/`、`tools/gen_topology.py`、`tests/fixtures/`、`.github/` | S1:不带参数仍 1731/1731,`--conf <fixture> --rules lists/` 场景与断言数一致;S2:三向比对(顺序 / 文件集合 / `ext_matching`)任一不符 exit 1;S3:`gen_topology --check` 必须验证 fixture 的 `[Rule]` 顺序与真实 conf 一致(否则 CI 变成自欺);S4:push 即跑全部闸门 + `scan_secrets.py`;S5:只对 `pinned` 条目做实事 | R3-1 |

> **明确不做**(与上轮宏大方案的差异):❌ `services.yaml`(单人维护下会立刻腐烂成第 6 份手抄副本;其核心价值已被 scenarios 的 `same_policy` 断言覆盖);❌ 完整再生管线的全部机器化(`sources.lock` + forbidden 已拿到 80% 收益);❌ 不可变 release tag + 分发 SHA 清单(本机发布 + git 历史完整 + CDN 有 `@<commit>` 固定路径可回溯,收益/成本比低)。

### R4 · 观测与周期

| # | 动作 | 涉及文件 | 验收标准 | 依赖 |
|---|---|---|---|---|
| R4-1 | **A11 · 注册域跨策略分裂报告**周期化(报告型不阻断;白名单显式登记刻意分裂) | `tests/audit.py`、`tests/allowlist.json` | **黄金基线 = 当前 29 项**;处置完 R1 档1+档3 后应降到 **14 项**(4 项刻意保留 + 10 项待裁决/抓包);这 14 项全部写进 exemptions 后 A11 应报 **0**。首次上线判 P2 且默认不 fail,先跑 30 天 | R1-22/23 |
| R4-2 | **A13 · 信任面检查**周期化(NXDOMAIN / 未注册 / 停放签名 / 易主;停放签名 = 停放商 NS + 无证书 + 301 断链)。对 **DIRECT 侧与 Reject 例外域优先**;**不进发布闸门** | `tests/live_check.py` 或独立周期脚本 | 对 `PrivateLAN` + `PKU` 的真实域(排除 RFC 特殊用途名):whois `No match` 报 **P0**;注册人不含预期机构关键字或起源 ASN 不在 CERNET(AS4538/AS23910)/CN 范围报 **P1**。周期沿用「Reject 恶意域 7–30 天」节奏 | R1-05 |
| R4-3 | **DIRECT 域双侧解析分歧检测**入 `live_check`:对落 DIRECT 的宽后缀(`live.com`/`office.com`/`msn.com`/`apple.com`/`icloud.com`/`qq.com` 等 top-N)展开代表 host,双侧 `dig +tcp` 比对,CN 侧落入已知投毒段即告警 | `tests/live_check.py` | 能独立复现 W5-01 的 OneDrive 结论(该缺陷就是它的第一个战果) | R1-01 |
| R4-4 | Streaming IP 面执行:D1 1,090 + D3 12 + D4 12 删除;D5 836 观察;D6 6 迁 Kakao。**CSV 驱动,shadow 7–14 天** | `lists/Streaming.list`、`reference/audit-v2-20260831/w2/streaming_ip_disposition.csv` | ①重跑 `cidr_classify.py`,`D1` 计数 = 0;②`runsuite` 全绿(**已验证现有 147 场景无任何字面 IP 落在待删的 1,956 条内**);③补 3 条负例/正例场景(AWS EC2 字面 IP 不得落流媒体、Akamai 不得落流媒体、Netflix `45.57.x.x` 必须落流媒体);④对 D2 的 19 条各取一个字面 IP 用 `live_check.py` 真机复核 | R2-1 |
| R4-5 | 命中统计驱动的观察项结案:`smp-device` **已可结案**(R1-19);Reject 6 条特异词补「零命中 90 天 → 删」的到期条件;Streaming 4 条无右锚 wildcard 备案 | `docs/MAINTENANCE.md §8`、`tests/scenarios/` | 8 条 `DOMAIN-KEYWORD` **各补 1 正 1 负**(负例按模板 `<token>-unrelated.example`);Reject 13 条 wildcard 各补 1 负例;TikTok 5 条尾点 wildcard 补正向样本以**启动 90 天计时** | 命中统计采集能力 |
| R4-6 | Reject 启用 `pre-matching`(前置条件已核验:双向冲突各 0 条) | `Surge.conf:84`、`docs/ARCHITECTURE.md §2`、`tests/audit.py` | ①`reject_layer.json`(14 场景 / 151 断言,含负向防误杀)必须全绿;②`dns_leak.json` 全绿;③**新增不变量检查:Reject.list 与 SYSTEM/PrivateLAN/PKU 的域集合必须不相交**(该不变量一旦被破坏就是静默的内网/系统流量被拦);④规则序表标注「pre-matching:实际优先级高于区 0」;⑤改动前后各测一次「随机未命中规则基准」把收益量化进 CHANGELOG | R2-7 |
| R4-7 | `extended-matching` 补 Reject + DownloadCDN(**先测再加**) | `Surge.conf:84`、DownloadCDN 的 RULE-SET 行 | Reject 的前置条件是**先把 6 条无边界特异词清掉**(否则扩展匹配会让它们在 SNI 上也做子串匹配 —— 这是最大风险点);DownloadCDN 需先确认存在「按 IP + Host 头」的下载流量,零命中则不加 | R4-5 |
| R4-8 | **90 天零命中清理制度**:Games 18 条 EC2 `/32`、Telegram 2 条 `/32`、AI 4 条 volc-dns 域、TikTok 10 条 wildcard、`PrivateLAN:119 p.to`、ChinaIP 独有段的 US/JP/SG 部分、`.beer` 653 条留存率 | `docs/MAINTENANCE.md §8` | 每类明确写出「取数方式 + 到期动作」;`§8` 现有的「零命中 90 天可删」补上**可执行的取证路径**(Surge Dashboard 按规则筛选,或 `live_check.py` 增「按规则统计命中」模式),否则这句话没有落地手段 | 命中统计采集能力 |

---

## 7. 用户待决项

本章**只给决策材料,不替用户作答**。每项列出:决定什么、阻塞谁、正反面事实。

### 7.1 流媒体组的日常出口国

- **决定什么**:`流媒体` 是**全局单选组**,一次选择作用于组内所有服务。日常选哪个出口国,决定了美国属地锁服务与 `bbc.com` 方向的微调。
- **阻塞**:R2-9(Fox/CBS/NBC/Fubo 是否迁 Streaming)、Niconico 迁移方向的最终确认。
- **事实**:`流媒体` 组的六个候选为 🇺🇸美国家宽A / 🇺🇸美国家宽B / 🇺🇸美国落地 / 🇯🇵日本家宽 / 🇯🇵日本落地 / 🇪🇺欧洲。**没有独立英国出口**;唯一可能落到英国的是「欧洲」组,而它是跨 DE/NL/GB 三国的 smart 组,选到英国是概率事件。若用户常年把流媒体切到日本,则「Niconico 迁 Japan」是负优化;若常年在美国,则「Fox/CBS/NBC 迁 Streaming」成立而「BBC 迁 Streaming」不成立。
- **注**:BBC 迁 UK(R2-9)**不依赖本项** —— 它是绕开该限制的方案。

### 7.2 `Final` 组的默认成员顺序

- **决定什么**:`Final` 组第一个成员即默认出口。当前是家宽组。
- **事实**:`Final` 承接两类流量 —— `ProxyGFW.list` 的 6,469 条 + **全部未命中域名**(`FINAL,Final,dns-failed`)。开箱即用状态下,全库最大的两个长尾桶都跑在家宽线上,与区 3 注释「大文件走下载组不占家宽」及 `下载` 组把机房组放首位的做法**方向相反**。
- **代价**:仅改默认首成员;若此前已在 GUI 手选过,选择会持久化、不受影响。`runsuite` 断言检的是**策略组名**不是组内成员,不会打红。
- **数据缺口**:`Final` 组的实际流量占比无数据(需 Surge Dashboard 的策略流量视图)。若占比很低,本项可降为 P3。

### 7.3 `always-real-ip`(仅当接入网关模式下游)

- **判断条件**:本机是否作为**网关**给主机/掌机/其他设备供网。
- **是** → 立即补 `always-real-ip = *.srv.nintendo.net, *.stun.playstation.net, xbox.*.microsoft.com, *.xboxlive.com`,并在 `Games.list` 表头交叉引用,本项升 P2。
- **否** → 影响仅限本机上的游戏客户端,保持 P3,只在 `MAINTENANCE` 记一条「若出现 NAT 类型检测异常,先加 `always-real-ip`」。
- **机制**:`hijack-dns = *:53` 把所有 DNS 查询纳入 fake-IP 应答面。对浏览器/App 无碍(连接走回 VIF 还原成域名),但 STUN / NAT 类型探测**依赖真实可路由地址**,fake IP 会导致判定失败或 P2P 打洞不成。`always-real-ip` 的条目仍按域名匹配规则,不影响分流。

### 7.4 LICENSE 三方案拍板

- **现状**:仓库根目录**无 LICENSE**;`SOURCES.md` 如实记录「待裁决」。默认「保留所有权利」与「这是公开仓库、供他人订阅」的实际用途**直接矛盾**,且未履行 GPL/AGPL 的再分发义务。
- **约束**:主力上游 blackmatrix7 是 **GPL-2.0**(ChinaDomain / ChinaIP 整表引用 + 14 张表取材);SukkaW 是 **AGPL-3.0**(7 张表取材 + Reject 广告层逐行裁剪);Loyalsoldier / VirgilClyne 是 GPL-3.0;另有 MIT 与 2 个未声明来源。
- **枢纽问题(无确定答案)**:规则内容是否构成受 copyleft 约束的「作品」?事实性数据在多数法域不受著作权保护,但**选择与编排**可能构成汇编作品 —— 本库对上游做的「裁剪、重组、去重与归属重裁」恰恰是编排层的创造性劳动,**同时也意味着上游的编排被继承了**。
- **三方案**:**A 双轨(推荐)** —— 根 `LICENSE` 用 MIT 只覆盖自有代码与文档,新增 `LICENSE-RULES.md` 声明 `lists/`+`clash/` 为上游规则的重组衍生物、整体按最严格者(AGPL-3.0)对待再分发;**B 整仓 AGPL-3.0** —— 最简单最保守,但把约 5,600 行与上游规则无衍生关系的自有工具不必要地绑上 AGPL;**C 维持现状** —— 零工作量,法律上任何人都不能复制/修改/再分发。
- **AGPL §13 判断**:本库分发形态是**静态文件经 CDN 分发**,不是运行中的程序 ⇒ 主流理解是 §13 不触发;但 §4/§5 的**再分发义务确实触发**(必须传递许可证与源码获取途径)。`SOURCES.md` 已完成「标明来源与修改方式」这一半,缺的是「传递许可证声明」。
- **必须拍板的三点**:(i) 自有工具单列 MIT 还是整仓 AGPL;(ii) 是否在 `LICENSE-RULES.md` 公开承认整表来源(`SOURCES.md` 已公开,实质已承认);(iii) blackmatrix7 的 README 另有一条**非许可证的附加限制**(禁止公众号/自媒体转载发布),与 GPL-2.0 的「不得附加额外限制」条款存在张力 —— 建议**如实转述而不解释其效力**。

### 7.5 DNS 单点的取舍

- **决定什么**:接受「无明文回退」这个取舍,还是加冗余。
- **正面**:国内 DoH 选型正确且与架构自洽(见 §3.8 五点论证)。
- **代价**:两个 DoH 端点都是 IP 字面量 ⇒ `dns-server` 一行**近乎惰性**。若网络阻断到这两个 IP 的 443,Surge 内部 DNS **没有任何降级路径**,所有需要本地解析的 DIRECT 连接(≈全库 92% 的域)会失败。
- **三条路**:①**最小改动** —— 再加 1–2 个**异网**加密端点做冗余(不同 AS、不同端口栈,如 `h3://` / `quic://`),降低单一 443 封锁的相关性;②**显式接受** —— 在 `ARCHITECTURE §4` 补一句「加密 DNS 无明文回退是刻意选择(防明文污染)」,并写进 `MAINTENANCE §5` 排障表(症状:**大量 DIRECT 域 DNS 失败而代理域正常**);③**保留明文兜底** —— 唯一方式是去掉 `encrypted-dns-server`,**不能靠留着 `dns-server` 实现**(这是本项最容易误解的一点)。

### 7.6 大陆出口无代理主机(环境依赖)

- **阻塞**:R3-3 —— ChinaDomain 再生过滤器的 **P5 主动可达性实测**是隔离区(约 6,117 条)放行的**唯一决定性证据来源**。
- **事实**:本机 Surge 增强模式 TUN + fake-IP 捕获全部流量。实测:即使 `curl --noproxy '*' --resolve www.google.com:443:142.251.153.119` 也返回 200(经代理);`--noproxy` 裸访问返回 `remote_ip=198.18.3.21`(fake-IP)⇒ **本机无法测真实直连可达性**。
- **需要**:一台无 Surge 的大陆出口主机 / 容器网络命名空间;或 Surge 侧临时把候选域强制 DIRECT 后读 `/v1/requests/recent`(**需先开 http-api**)。
- **连带**:`live_check.py` 依赖 http-api,而 conf 当前未开(`grep -c '^http-api' Surge.conf` = 0)⇒ **所有 GEOIP 相关结论、真机落点复核、命中统计采集都被同一个开关阻塞**。这是本轮**单点阻塞面最大**的一项。

### 7.7 MITM 若复启:检查单

- **当前零现网风险**:`[MITM]` 的 `hostname` 是**键缺席**(不是空值),`auto-quic-block = false` 在无 hostname 命中时是**空操作**。
- **待证**:conf 注释给出的重启用检查单只提到把 `auto-quic-block` 改回 `true`,**没提 `block-quic`**。而 `[General] block-quic = always-allow` 的官方定义是「globally override … allowing everything」,与 MITM 层的 `auto-quic-block` 分属不同层,**官方未记载其优先关系** ⇒「照注释只改 `auto-quic-block` 就够」是**未经验证的假设**;若 `always-allow` 同样压过 MITM 层,注释所警告的「HTTP/3 绕过 MITM 成半解密」恰好会发生。
- **需要**:给 1 个测试域启用 MITM 后用 `curl --http3` 观察是否落 HTTP/3(需 GUI 启用 MITM,属手动验证,不进闸门)。
- **同批**:`hostname` 模板**全是排除项、没有正向项**,照抄解注释后 MITM 仍然一个域都不解密(官方示例末尾的 `*` 才是正向捕获项)。

---

## 8. 附录

### 8.1 新增审计检查 A9–A13 规格

当前已实现 A1–A8(A8 = forbidden 回流)。**本轮统一编号如下,worker 报告中各自提出的 A9/A10/A11 等编号一律以本表为准。**

| 编号 | 名称 | 合并自 | 判据与分级 | 首批已知命中 | 优先级 |
|---|---|---|---|---|---|
| **A9** | **IP 跨表包含/遮蔽审计** | W6 F-07、W7 推荐、W8 独立要求(同一检查) | 用 `ipaddress` 按 conf 顺序建前缀树(或按前缀长度分桶),报「后位 CIDR 被前位 CIDR 完全包含」与「跨策略部分交叠」。**同策略 → P2/P3 不阻断;跨策略 → P1**(被包含方是 DIRECT、包含方是代理时按 A4 惯例升 P0)。同时补上 `IP-ASN`/`GEOIP` 与 CIDR 的交叉盲区 | **154 条**被前位覆盖(142 条在 AppleCN `17.0.0.0/8` 下)+ 28 条部分交叠;**跨策略仅 1 条**(`Google 74.125.0.0/16` ⊃ `ChinaIP 74.125.16.64/26`,结论正确但未登记) | **★ 1** |
| **A10** | **单标签后缀与 PSL 边界门禁** | W7 的 A9-lite + W2 的 PSL 驱动检查(合并) | 锁定 IANA TLD 表 + PSL 快照(哈希入 `SOURCES.md`,正确处理 `*.parent` 与 `!exception`):①任何单标签 `DOMAIN-SUFFIX` 必须在显式 allowlist 内;②`DOMAIN-SUFFIX` 命中 PSL(ICANN 或 PRIVATE)即报,例外走 exemptions。**同一逐行循环内顺带做** arity(`len(parts)>=2`)、严格 CIDR(`ip_network(strict=True)`)、modifier 白名单、大小写归一 | 全库 **60 条**单标签后缀(52 真实 gTLD + 8 条 RFC6761 特殊用途名),ChinaDomain 占 44 条;DownloadCDN S3 家族 + 40 条其他平台后缀;ChinaDomain **11 条 PSL PRIVATE 直连层**后缀 | **★ 2** |
| **A11** | **注册域跨策略分裂报告** | W4 算法 | 用锁定的 PSL snapshot 把每条域名规则映射到 eTLD+1 → 收集所有认领它的 `(list, rule)` → 用 conf 规则序映射到目标 policy → 同一 eTLD+1 映射到 >1 policy 即报。分级:涉「认证/支付/登录」语义 host(`secure.`/`auth.`/`login.`/`sso.`/`id.`/`account.`)或涉地区表 + 属地锁清单 → **P1**;其余 → P2。**报告型不阻断**,豁免走 exemptions(表达「允许存在」),**不得**写进 forbidden(语义不符) | **黄金基线 = 当前 29 项**;处置完 R1 后应降到 14 项;全部登记后应报 0 | 周期任务 |
| **A12** | **文档-实现漂移检查** | W7 A17-lite | grep 出文档里的断言数字,与 manifest / `runsuite --json` / `surge2clash --check` / `allowlist.json` 对比。可断言量:`lists` `clash` `dist` `ext_matching` `scenarios` `assertions` `dns_assertions` `clash_rules` `exemptions` `forbidden`。**依赖 S2 的 `gen_topology.py --emit counts`**;`sources.lock` 一致性并入本项 | `tests/README.md` forbidden **18→130**(差 7 倍);`docs/DEVELOPMENT.md` **65→69**;`CHANGELOG` 126→130 | **★ 3** |
| **A13** | **信任面检查(新类别)** | 本轮新增(W1/W2/W3/W5/W6 交叉暴露) | NXDOMAIN / 未注册 / 停放签名 / 易主检测。**停放签名 = 停放商 NS + 无可用证书 + 301 断链**;易主检测 = 注册商/NS 与该品牌的既知签名不符(如 Meta 的 `RegistrarSEC LLC` + `*.ns.facebook.com`、Valve 的 MarkMonitor、X 的 `a.uNN.twtrdns.net`)。**对 DIRECT 侧与 Reject 例外域优先**。周期任务,**不进发布闸门** | 见 §3.1 的 11 条逐条 + 6 组规模型证据 | 周期任务 |

**首批实施推荐顺序:A9 → A10 → A12**(与论证一致);**A11 / A13 为周期任务**。

**两项未编号的候选检查**(本轮未纳入 A9–A13,须由 advisor 后续定编号):

1. **直连层前位抢跑门禁**(W5 提出):对 Domestic + 6 张厂商表 + AppleCN/MicrosoftCN 的每条域名规则,按 conf 真实序 + **策略差异**维度计算是否被更前位规则完全覆盖,命中判 P1。当前实测**抢跑 = 0**,是防未来回归的门禁。`A4` 已有跨 list 遮蔽框架,**建议作为 A4 的扩展维度实现,而非新开编号**。
2. **conf 不变量检查**(W8 提出):断言 `use-local-host-item-for-proxy` 不为 true、全部 IP 类 RULE-SET 行带 `no-resolve`、`FINAL` 带 `dns-failed`、**每个 `[Proxy]` 条目必须是某组成员或某条目的 `underlying-proxy` 目标**(除非有组开 `include-all-proxies=1`)。纯静态、零外部依赖、可进发布闸门。现有四件套对此完全失明(audit 只扫 `lists/`,engine 只解析 `[Rule]`)。

### 8.2 大清单指针与再生方法

本文按约定**不内嵌大清单全文**。下表给出每份大清单的统计、判定签名与获取方式。

| 清单 | 条数 | 判定签名 | 所在文件 / 再生命令 |
|---|---:|---|---|
| Meta 防御/库存停放域 | **411** | NS ∈ {`a-d.ns.facebook.com`, `ns.instagram.com`, `ns.whatsapp.net`} 或 Registrar = `RegistrarSEC LLC`;A = `57.144.220.141` / `.221.141`;HTTPS 无可用证书;HTTP 301 回自身 https 后断链 | `reference/audit-v2-20260831/reports/W1-ecosystem.md` §3.8;`reference/audit-v2-20260831/meta_tiers.txt`;`python3 reference/audit-v2-20260831/w1_meta_final.py` |
| Streaming IP 逐条处置 | **1,975**(D1 1,090 / D2 19 / D3 12 / D4 12 / D5 836 / D6 6) | 见 §3.2 的六类判据 | `reference/audit-v2-20260831/w2/streaming_ip_disposition.csv`;`python3 reference/audit-v2-20260831/w2/cidr_classify.py` → `noncloud_analyze.py` → `streaming_disposition.py` |
| ProxyGFW 死域 | **769**(642 NXDOMAIN + 127 权威失效) | 双侧(`@8.8.8.8` A + `@1.1.1.1` NS,2 tries)一致 NXDOMAIN 或一致 SERVFAIL | `reference/audit-v2-20260831/w3/gfw_nx.txt` + `gfw_servfail.txt`;`reference/audit-v2-20260831/w3/gfw_sweep.sh` + `gfw_recheck.sh` |
| ProxyGFW 承载集(**必留**) | **18** | 与区 9/10 后位表重叠(不存在则会被后位判 DIRECT)。**已在 §3.5 逐条列出** | `reference/audit-v2-20260831/w3/dedup.py` 后位比对段 |
| Reject 死域 | **61**(A 组 41 可删 / B 组 20 `.cn` 必留) | 同上双侧;B 组受 `DOMAIN-SUFFIX,cn` 兜底约束 | `reference/audit-v2-20260831/reports/W3-reject-special.md` W3-07(**全文列出**);`reference/audit-v2-20260831/w3/nx.txt` |
| DownloadCDN 非下载面复核队列 | **114**(166 中完全无下载语义 token 的) | 词法分类:api/control 57、support/CRM 35、telemetry 29、payment 13、consent/AB 12、account/auth 10。**含约 4 条 `.ad.jp` 词法误报,是人工复核队列不是删除清单** | `reference/audit-v2-20260831/w2/dlcdn_flagged.csv`;`python3 reference/audit-v2-20260831/w2/dlcdn.py` |
| ChinaDomain 171 条 `DOMAIN` 全量普查 | **171**(投毒 4 / 境外 77 / 死域 56 / 港台 12 / 国内 22) | 见 §3.4;全量普查非抽样 | `reference/audit-v2-20260831/reports/W6-machine-tables.md` F-02(**全文列出**);`reference/audit-v2-20260831/w6/classified.json` |
| ChinaDomain 境外托管噪声 | 裸估 **≈16,096**;护栏后自动丢弃 **≈5,851 [4,623–7,380]**;隔离区 **≈6,117** | 三并集 CN 判定 + 3×resolver quorum + P1–P10 护栏 | `reference/audit-v2-20260831/w6/chinadomain_regen_filter.py`(**可运行原型**)、`filter_report.json`、`probe.jsonl`、`classified.json` |
| ChinaDomain 不可解释差异 | **539**(其中 534 条在当前上游仍存在) | pin 有本地无,且不能由归属去重(4,686)或已删宽关键词(12)解释 | `reference/audit-v2-20260831/w6/unexplained.json`;`python3 reference/audit-v2-20260831/w6/cd_upstream_diff.py` |
| ChinaDomain 44 条整 TLD | **44**(11 ASCII + 33 IDN)+ 3 条可疑二级形态 | `^DOMAIN-SUFFIX,[a-z0-9-]+$` 单标签,按 IANA root DB 注册局分 T0/T1/T2/T3 | `reference/audit-v2-20260831/reports/W6-machine-tables.md` F-04 与 `reference/audit-v2-20260831/reports/W8-conf-global.md` §3.1(**均全文列出**);`reference/audit-v2-20260831/w6/tld_iana.txt` |
| ChinaIP 跨表包含 | **154 + 28** | 前缀树按 conf 真实序比对 | `reference/audit-v2-20260831/w6/ip_cross.json`;`python3 reference/audit-v2-20260831/w6/ipcross.py` |
| 注册域跨策略分裂矩阵 | **29 注册域 + 11 品牌** | eTLD+1 归并后被 ≥2 张表认领且其中至少一张是地区表 | `reference/audit-v2-20260831/reports/W4-regions.md` §3.1 / §3.1b(**均全文列出**);`reference/audit-v2-20260831/w4_collide.py` |
| 34 条禁收裁决缺口 | **34**(其中 3 条须 file-scoped) | `§8` + D11 的「明确禁收/勿收回/勿单列」逐条 vs forbidden 130 条 | `reference/audit-v2-20260831/reports/W7-toolchain.md` W7-T02(**全文列出**) |
| 宽后缀反向分层视图 | **2,196 条**被 283 条宽后缀承接 | 后位宽后缀覆盖前位具体域 = 刻意分层兜底(top:`cn` 1,066 / `amazonaws.com` 296 / `microsoft.com` 85 / `akamaihd.net` 49) | `reference/audit-v2-20260831/w8_out/rev_layering.txt`;`python3 reference/audit-v2-20260831/w8_scan2.py` |

### 8.3 worker 报告索引

| 报告 | 文件名 | 行数 | 核心交付 |
|---|---|---:|---|
| W1 | `reference/audit-v2-20260831/reports/W1-ecosystem.md` | 683 | Meta 520 条**逐条分档**(R1/R2/O/X/N/D)+ 27 条非 Meta IP 段逐条 RIR 核验 + ASN 判据补齐 |
| W2 | `reference/audit-v2-20260831/reports/W2-media-download.md` | 547 | Streaming 1,975 条 IP **逐条处置 CSV** + DownloadCDN 重建蓝图 + 云 IP 收录**统一判别式** |
| W3 | `reference/audit-v2-20260831/reports/W3-reject-special.md` | 483 | ProxyGFW **99.7% 惰性 + 18 条承载集**证明 + 再生管线四道过滤器 + 区 0 存活巡检 |
| W4 | `reference/audit-v2-20260831/reports/W4-regions.md` | 571 | 29 注册域 + 11 品牌**完整冲突矩阵** + 三档迁移方案 + A11 算法与黄金测试集 |
| W5 | `reference/audit-v2-20260831/reports/W5-domestic.md` | 464 | OneDrive 投毒**实测复现** + Domestic 618 行**逐条打标签** + 「不拆表改门禁」的成本论证 |
| W6 | `reference/audit-v2-20260831/reports/W6-machine-tables.md` | 500 | 再生过滤器**可运行原型** + 十道护栏量化效果 + `sources.lock` 最小实现 + 双兜底三方案论证 |
| W7 | `reference/audit-v2-20260831/reports/W7-toolchain.md` | 633 | **38 组故障注入探针** + 34 条禁收缺口 + 供应链 5 阶段裁剪 + LICENSE 决策材料 |
| W8 | `reference/audit-v2-20260831/reports/W8-conf-global.md` | 775 | conf 逐键审计 + 22 组拓扑闭包 + 四类跨表全量扫描 + `extended-matching` **判据 R** |

### 8.4 编号与冲突取舍记录

本文在 8 份报告之间做过如下取舍,一律**以 advisor 裁决为准**;记录在此以便追溯。

| # | 冲突点 | 各方口径 | 本文采用 |
|---|---|---|---|
| 1 | S3 家族条数 | W2:280(S3 区域端点族)/ 278(PSL 子集)/ 318(PSL 边界合计) vs advisor:**321** | **321**;执行时以脚本重算并把**判定签名**(而非计数)写进 forbidden |
| 2 | 新审计检查编号 | 6 份报告各自提出 A9/A10/A11/A17-lite,互相冲突 | **§8.1 的 A9–A13 统一编号**;W5 的抢跑门禁并入 A4 扩展维度,W8 的 conf 不变量列为待编号候选 |
| 3 | 属地锁归属原则 | W4 提请裁决;上轮主张「服务 owner 决定归属」 | **owner = 能提供正确出口的表**;英国锁→UK、日本锁→Japan、美国锁→留 Streaming |
| 4 | 「流媒体组无英国出口」表述 | W4 原文「没有任何英国出口成员」 | 修正为「**无独立英国出口成员**,经欧洲 smart 组存在伦敦节点通路但不可控」 |
| 5 | ThreatMetrix | W3 标 ⚖️ 与「通用 SaaS 组件」裁决冲突,提请终审 | **收入 Payment**;`§8` 补边界「参与支付风控决策链的指纹/反欺诈组件归 Payment」 |
| 6 | `01.ai` / `siliconflow.com` | W5 标 ⚖️,给两种自洽写法 | 按 **D3 + `qwenlm.ai` 先例迁 AI.list**,`.cn`/中文主域保持直连 |
| 7 | ProxyGFW 3 条 Akamai 宽后缀 | W7 二选一,倾向「承认为刻意分层」 | 按 **D6 同构处理,不删**;`§8` 措辞收敛为「禁止**新增**收录,存量按 D6 登记」 |
| 8 | TencentCN 14 段 | W5 倾向删;allowlist 已登记 A2 豁免、W6/W8 视作「预期分层」 | **删除**,并同步撤销 A2 豁免、修正表头 |
| 9 | Meta 411 条去处 | W1 建议新建 `inventory/MetaDefensive.txt` | 改为 **`reference/` 本地库存档**(不入库、不分发),不建 `inventory/` 新目录 |
| 10 | IPv6 不对称优先级 | W1/W7 主张补段;W8 主张下调 | **采纳降级**:先补测试语料 + 采集占比,有数据再决定;不机械映射 v4 云段 |
| 11 | Meta 中的 LINE 段条数 | W3-15 点了 2 条;W1-002 列了 3 条 | **3 段**(`119.235.224.0/24`、`119.235.232.0/24`、`119.235.236.0/23`) |
| 12 | ChinaDomain 噪声量 | W6 裸估 15.15%(≈1.6 万) vs `MAINTENANCE` 登记「约 2 万条」vs 护栏后 5.50% | 三者**不可混用**:裸估是上界,护栏后 5.50% 是实际删除面,「约 2 万」偏高但同量级 |
| 13 | 策略组名脱敏 | W4 直接使用带线路商标识的组名;W8 已改写为中性代号 | **沿用 W8 的中性代号**(🇺🇸美国家宽A/B、🇯🇵日本家宽、🇺🇸美国落地、🇯🇵日本落地、🇪🇺欧洲) |
| 14 | 孤儿节点标识 | 上游材料带有具体节点名 | **改写为「某英国方向链式节点」**;`[Proxy]` 段行号可引用,名称不引用 |

---

## 附:本文的脱敏边界

本文档为进入公开仓库而写,遵守以下红线:

- **不出现**任何节点 IP、psk、`ca-p12`、`ca-passphrase` 内容;
- **不出现**线路商 / 机房标识;带此类标识的策略组名一律改写为中性代号,备份 conf 文件名与网段名示例一律打码;
- **不出现**具体节点名称;涉及节点时用「某英国方向链式节点」一类占位;
- 引用 `Surge.conf` 限于 `[Rule]` / `[General]` / `[MITM]` 结构与策略组**拓扑**,不引用 `[Proxy]` 段条目内容。

W7 已对 108 个跟踪文件做过全量脱敏扫描:conf `[Proxy]` 的 22 个节点名与 15 个节点 IP/主机名 **0 命中**;本地覆盖档 28 个 token 中 16 个有命中,逐条判读后 14 个是第三方域名里的巧合子串、2 个是真命中(已列入 R0-3)。建议把该扫描脚本固化为 `tools/scan_secrets.py` 并进 CI(R3-8 的 S4)。

---

*本文档是审计与迭代路线。**本轮未修改任何规则文件、配置文件或测试文件**,未执行 `update.sh`,未做任何 git 写操作。所有改动动作均登记为 §6 的路线图待执行项,按「Fable 写批次 spec → Opus 并行执行 → 双闸门 → 单次发布」的既定模式推进。*

---

## 执行勘误(2026-08-31 修复批次)

本节由**执行方**追加,不改动上文任何原文。以下各条是执行 §6 路线图时**实测得到的更正**;正文对应结论仍成立时会注明「结论不变」,只是**依据 / 口径**须以本节为准。裁决登记同步落在 [`MAINTENANCE.md §8`](MAINTENANCE.md)。

| # | 原文口径 | 实测更正 |
|---|---|---|
| E-1 | R1-12 / §3.2 的 S3 族「**321 条**」,验收写 `grep -cE '^DOMAIN-SUFFIX,s3' = 0` | **实测更正**:321 是**纯前缀** grep 的计数方法学错误;按 D-01 自己给的锚定签名 `grep -cE '^DOMAIN-SUFFIX,s3[.-].*amazonaws\.com$'` 实得 **280 条**,差额 41 条中约 32 条是第一方 `s3.<brand>` host(Figma / Brave / Producthunt / Envato…),删掉属无依据的过度删除。**验收改用判定签名,不用计数**;forbidden 签名必须锚定 `amazonaws.com`,不得写成 `s3*` |
| E-2 | W3-07 把 Reject A 组定义为「**41 条**非 `.cn`、删除后落 FINAL、可清理」 | **实测更正**:逐条 `engine.match` 复核,其中 3 条 HTTPDNS(`dnspod.meituan.httpdns.start.qcloud.com` / `httpdns.qcloud.com` / `httpdns-v6.gslb.yy.com`)删除后落 **DIRECT** 而非 FINAL(被 `TencentCN qcloud.com` / `Domestic yy.com` 宽后缀接住),不满足 A 组定义前提。**A 组实删 38 条,3 条按「承载集同构」保留**;`reject_layer.json::httpdns_private_doh_reject` 因此无需改动 |
| E-3 | §3.6 与 W4-15:`Japan:48 paravi.jp` 判为死条目(`curl -I` → 000 无响应,规则永不命中) | **实测更正**:`paravi.jp` **301** → `www.paravi.jp` **200**(Vercel 托管的 `/internal-redirect` 壳页),双侧 DNS 均正常解析(`@8.8.8.8` 65.8.180.x / `@223.5.5.5` 3.175.214.x,均属 AWS)。**域名活着,不是死域**。删除结论不变,但依据须改为 W4-03 的**跳转域口径**:Paravi 2023 并入 U-NEXT,承接域 `unext.jp` / `nxtv.jp` 已在同表,壳本身无属地锁。与「勿当死条目删」的 `happyon.jp` 一类的边界是**服务是否仍在运营**,不是「是否有 HTTP 响应」 |
| E-4 | §3.2:`108.177.8.0/21` 可能同时存在于 `Google.list` 与 `Meta.list` | **实测更正**:**仅存于 `Meta.list`**(`Google.list` 全表无此条),系上游 Facebook IP 表历史夹带;已随 R1-06 删除,并按 `file: Meta.list` 登记防再合并带回。ARIN 实证 `108.177.0.0/17` = GOOGLE |
| E-5 | R1-06:`129.134.0.0/17` 合并为 `/16` 的依据是「AS32934 在 `129.134.128.0/17` 内有约 66 条 `/24` 通告」 | **实测更正**:今日 RIPEstat 实测该区间内 AS32934 通告 **0 条**。合并结论不变,但正当性依据改引 **ARIN 整段 NetName `THEFA-3`(Facebook, Inc.)**;`157.240.0.0/16` 同此依据 |
| E-6 | §3.1 / A13:Meta 停放签名写作 A 记录 = `57.144.220.141` **或** `57.144.221.141` 两个定值 | **实测更正**:CN 侧另见 `57.144.64.141` / `57.144.216.141`,属同一停放池的不同主机。**签名须放宽为「`57.144.0.0/14` 内、主机号以 `.141` 结尾」**,否则再生过滤器会漏掉约一半停放域 |
| E-7 | —(新发现,原文无) | **实测更正 · 新增死条目**:`Domestic.list` 的 `googleapis.cn` 在 CN 与国际侧**均无 A 记录**(原文 W1-007 记录的 `120.253.253.107` 已不复现)⇒ 该 DIRECT 条目当前是死端点,并入 `-cn` 族批次一并删除。同族的 `google.cn` / `gstatic.cn` 仍活,不受影响 |
| E-8 | §6 / §7 / R2-1 / W6 F-07 反复引用的 A9 基线「**154 + 28**」(154 条被前位完全包含 + 28 条部分交叠,跨策略仅 1 条) | **实测重标为 145**(**144 条同策略 + 1 条跨策略**)。差额不是漏报:①`154 + 28` 出自 `reference/audit-v2-20260831/w6/ipcross.py`,该脚本把「完全包含」与「部分交叠」**分两次计数**,而实装的 A9 是**顺序感知**口径 —— 只对「后位被**其前位**覆盖」记一次,同一条 CIDR 被多个前位覆盖不重复计;②R1-06 的 Meta IP 整理(删 `108.177.8.0/21`、`129.134.0.0/17`→`/16` 合并)本身消掉了若干条重叠。**跨策略 1 条的结论不变**(`Google 74.125.0.0/16` ⊃ `ChinaIP 74.125.16.64/26`,已入 exemptions)。`tests/allowlist.json` 按 145 的实测口径整体登记,门禁仍只对**新增跨策略交叠**报 P1;上文所有出现「154」「154+28」的段落一律以本条为准 |

> 另有两条口径提醒,不构成对原文的更正,但影响下轮取数:①`api.tubi.tv` 当前双侧均无 A 记录,`tubi.tv` 由 `DOMAIN` 升 `DOMAIN-SUFFIX` 修的是**结构缺陷**(同一注册域上 DOMAIN 与 SUFFIX 混用),覆盖空洞是潜在的而非活跃的;②W4-01 方案 A 的 12 条枚举本身不自洽(挑出 `bbcfmt` 却漏掉同属播放面的 9 条 `*-uk-live` + 2 条 `*-ww-live` + `bbc.mp-pxcdn.com`),处置方式是**整体迁移或整体保留** —— **本批次已改按「该 host 是否 BBC 专属」重划并执行整体迁移**:9 条 `*-uk-live` + `bbc.mp-pxcdn.com` 迁 `UK.list` 取回英国出口,`*-ww-live` 与多租户承载的 `bbcfmt.s.llnwi.net` 留 `Streaming.list`,详见 `MAINTENANCE §8`。
