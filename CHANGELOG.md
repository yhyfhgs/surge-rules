# 更新记录

## [2026-09-13·域名/IP 分区重构] 52 表、加密解析兜底与证据驱动清理

- 实施用户审阅后的 v6：35 个原表名称保留，拆出 17 个 IP 表；域名先于 IP，各区代理/地区/直连连续。Microsoft 与 Games 收窄父域，保留 OneDrive 67 项既有会话正例和国内下载例外。
- 规则 **142,212 → 140,282**（域名 129,062 / IP 11,220）。StreamingIP **1,983 → 21**；TelegramIP 改为官方集合的 11 条等价折叠；GamesIP **41 → 8**；JapanIP 移除五个全运营商 ASN。对 ASN 缺项使用新 RDAP 证据，避免误删 AI/Meta/X 的真实范围。
- ChinaIP 锁定重建为 **11,067** 条；保留受控 HK 范围及硬排除。ChinaDomain 新增候选未达解析可信度门槛，原 106,962 条保持，未降低门槛强行导入。
- 补模型传输/AI 与既有服务族；移走账户资源、收窄流媒体/TikTok/微软 CDN 通配。删除由合成示例引入的 battle.blizzard.com 候选，补真实 api.blizzard.com；未将可直连的 Figma/Obsidian 主机冒充 GFW 缺口。
- 重写匹配/审计/渲染契约：真实 MMDB、已解析状态、逻辑集合减法、SNI/Host、私网 DNS 例外、双端同源。修复过期探测器把超时当死亡及同日重复累积的风险；复核 21,906 个手工域名值，未对缺证据的候选作删除。
- CIDR 折叠发布门禁改为保留并分别校验尾参，修复旧工具强制 `no-resolve` 与分区解析的冲突；跨尾参集合差异仍拒绝通过。
- **4,750 条场景断言、84 条对抗断言通过**；静态无 P0/P1/P2，3 个既有 P3；52 个 Mihomo provider 实际加载计数一致，双栈 DNS 和故障 SERVFAIL 验证通过。真实登录/同步/支付/播放及日常 Final 降幅不以匿名探针代替。
- 发布与生效状态在执行后单独记录；[完整证据与逐表数量](docs/evidence/2026-09-13-domain-ip-v2.md)。

保留最近批次的动机、结果与验证；旧日志中的命令实录、重复统计和已替代设计
统一从 [精简前的完整记录](https://github.com/yhyfhgs/surge-rules/blob/9ebce49d8644dbe982fdcddfc62eb46296a7b277/CHANGELOG.md)
查阅。历史数字只代表对应批次，当前值以检查输出为准。

## [2026-09-13·仓库精简] 归并文档与清理历史产物

- 删除过时的审计总报告；README、架构、维护、测试与来源文档各保留明确职责，移除重复流程、失效统计和已退役脚本参考。近期决策保留，旧日志改为 Git 历史索引。
- 127 个旧诊断文件（约 321 MiB）移至仓库外私有暂存目录；清除 Python 缓存和 Finder 元数据，补全本地设置、探测状态的忽略规则。
- 压力测试改用 `--conf` / `--rules` 和共用默认配置解析，解除历史临时配置依赖；删除个人绝对路径回退及 11 个未使用的导入。
- 本批清理不改规则、顺序、上游锁、场景数据或活动 profile。仅叠加本批改动的隔离快照通过 4,720 条场景断言、84 条压力测试、35 个 Clash provider 的逐条一致性与 82 个归属见证；原生语法、静态审计和受影响自检通过，审计仅有 3 条既有 P3 信息项。

## [2026-09-12·OneDrive 恢复代理] 同步、文件与共享登录统一代理

- 用户反馈直连打不开 OneDrive，修正上一轮要求，改为整条会话接入现有 Microsoft 代理策略；个人版、SharePoint 文件、同步 API、共享登录/认证资源及 Office 网页入口一并覆盖。
- 从 MicrosoftCN 移除 53 条会话规则：25 条迁入 Microsoft，28 条由 Microsoft 既有父后缀直接承接，避免重复。MicrosoftCN 125 → 72，Microsoft 53 → 78，全库 142,212 条。其他更新/CDN/预览端点与列表顺序保持原样，无新增列表或 profile 改写。
- 35 张 Surge/Clash 列表逐条一致；346 场景、2,409 请求、4,720 断言通过，含 2,080 条 DNS 断言；82 个 Clash 归属见证、原生候选语法和关系分析通过。A1–A10 无 P0/P1/P2，3 条既有 P3 信息项。发布继续执行标准门禁、完整 MMDB 和 CDN 哈希核验。
- 直连试验保留为历史证据并明确标记已被替代；当前范围与验证见 [代理恢复记录](docs/evidence/2026-09-12-onedrive-proxy.md)。不将路由匹配或未登录探测写成文件同步成功。
- `9010f67` 已推送。发现本机出口的 CDN 边缘仍返回旧别名后，补刷四份 Surge/Clash 分发文件，复验四表及 provider 均一致；校正两份公开资源缓存并恢复客户端写回的旧 `[Rule]` 顺序。最终 81/81 原生匹配通过（OneDrive 67/67 代理），另 5 项更新/预览/CDN 保持 DIRECT。浏览器已能打开 OneDrive 官网，文档入口跳转登录页返回 HTTP 200；发布状态 `PUBLISHED_AND_VERIFIED`。

## [2026-09-12·OneDrive 直连，已被替代] 同步、文件与共享登录端点统一直连

- 用户要求 OneDrive 同步直连，并明确同意共享微软登录端点也直连。运行中的 Surge 原先将个人版入口、同步 API、文档数据面和登录面交给 Microsoft 代理策略；补齐 MicrosoftCN 的同步/身份端点，迁入 Microsoft 的 4 条和 DownloadCDN 的 1 条认证/客户端资源规则，保持唯一 owner。MicrosoftCN 85 → 125 条，全库净增 35 条。
- 修复活动 profile 落后的列表顺序，恢复 MicrosoftCN 在 Microsoft 之前；manifest 的 4 个地区策略标签与当前已存在的组别名对齐，地区去向不变。Clash 与场景期望同步更新，不修改私有组定义。
- 35 表 / 142,240 条规则；346 场景、2,409 请求、4,721 断言通过，含 2,080 条 DNS 断言。Clash 逐条一致，82 个归属见证通过；原生候选语法、关系分析及完整 MMDB 展开通过。A1–A10 无 P0/P1/P2，3 条既有 P3 信息项。发布继续执行标准门禁及 CDN 哈希核验。
- **连通性限制**：两个个人版入口的本机 DNS 仍返回 Meta 地址，DIRECT 探测超时；微软两个登录端点直连得到 HTTP 响应。当前未捕获到 OneDrive 客户端同步流量，不将分流通过写成同步成功。官方来源、实测与边界见 [证据记录](docs/evidence/2026-09-12-onedrive-direct.md)。

## [2026-09-07·AI 上游维护] 固定来源复核与国内外入口归属

- 核对 VPSDance `cc1d596`、blackmatrix7 `5f06cac`、Sukka `81632eb` 的 AI 来源；18 份 revision/SHA-256 输入经 locked fetch 全数验证，登记 `sources.lock.json:ai_review`。裁决与未采用项见 [证据记录](docs/evidence/2026-09-07-ai-upstream.md)。
- 新增 18 条域名规则、移除跨国内外模型 API 的 `mchost.guru` 宽后缀，净增 17；Claude/OpenAI 专属资产、阿里国际 DashScope/Coding Plan 与 5 个境外 MaaS 区域、TRAE 国际域补齐。国内 TRAE 模型端点归 ByteDanceCN，已实测新加坡端点归 AI。
- 14 条既有规则迁移 owner：通义/Qoder/ModelScope 与 Coze 国内域回归厂商 CN 表（13 条 DIRECT 不变），零一万物中文官网 `lingyiwanwu.com` 改归 Domestic。大厂 AI 继续原生态策略，国内模型与国际产品入口分别断言；HF 模型下载仍优先「下载」。不导入共享云/托管父域、进程或宽关键词规则。
- Surge/Clash 共 35 表、142,205 条源规则逐条一致；344 场景 / 2,328 请求 / 4,557 断言全部通过，含 1,999 条 DNS 断言。Clash contract 73 个归属见证通过；Surge/Mihomo 原生语法及隔离 Mihomo 全 provider 加载、双栈 fake-IP、代理失败 DNS 不直连均通过。最终发布门禁全数通过（无 P0/P1/P2；3 条既有 P3 信息项）。`0fffcbe` 已推送；全量 CDN 71/71 文件哈希一致，补 purge 后两个旧 Fallback 地址均 404。Surge 35 份资源刷新就绪、12/12 原生分流见证通过，状态 `PUBLISHED_AND_VERIFIED`。

## [2026-09-07·微软列表合并] 移除新增 Fallback，MicrosoftCN 优先

- 用户要求不增设厂商 Fallback 表，尽量调整现有列表；进一步明确 MicrosoftCN 全部优先，4 处原代理例外也改为直连。
- 将 microsoft.com / live.com / office.com / msn.com 合回 Microsoft.list，移除 24 条被宽后缀覆盖的窄规则与 4 条已改为直连的例外；撤销上批新增的 MicrosoftFallback 源表及 Clash 派生表。
- 现有 MicrosoftCN 前移至 Microsoft 之前，下载仍优先于两者；无新增列表、无内联例外。Surge conf 与 Clash YAML 同源生成 35 个 CDN 列表引用，保持同序同策略。
- 4,375 条场景断言全部通过（含 1,912 条 DNS 断言），50 个独立归属正负例通过。对既有测试请求逐个比较，只有获准的 4 个端点族产生策略变化；规则总数 142,188。发布完整检查和 CDN 核验结果见执行记录；[变更边界](docs/evidence/2026-09-07-microsoft-merge.md)。

## [2026-09-07·厂商 suffix 与 Clash DNS] 补齐厂商兜底、Clash 生效配置与无损镜像验证

- 用户确认保留共用策略组及已验证的 YouTube / 下载 / 国内例外，另明确同意整个 googleapis.com（含租户端点）归 Google 网络。
- Google 112 条窄规则归并为 google.com / googleapis.com / googleusercontent.com / ggpht.com 四个 suffix；Microsoft 补 cloud.microsoft / usercontent.microsoft；新增后置 MicrosoftFallback 四个 suffix，避免遮蔽 MicrosoftCN。Meta / Twitter 主域已是 suffix，新增归属反例验证。
- Clash 生成器输出生效的 DNS / TUN / sniffer / rules；每个 RULE-SET 带 no-resolve；普通查询 DoH 绑定代理，bootstrap / DIRECT 使用独立加密 DNS；UDP/TCP 53 劫持与双栈 fake-IP。禁止静默丢弃不支持的源规则。
- 一一对应 **36 表 / 142,216 条**，analyzer 0 遮蔽/顺序冲突；A1–A10 无 P0/P1/P2（3 条现有 P3 提示）；**336 场景 / 4,375 断言**全通过，含 **1,912 条 DNS 断言**；44 个独立归属正负例、3 个转换器回归检查通过。Surge 与 Mihomo 原生语法通过；Mihomo 隔离实例实际加载全部规则，验证 UDP/TCP A/AAAA fake-IP 和代理故障 SERVFAIL。
- 用户要求本地迁移配置使用 CDN provider，统一引用本仓库分发列表，节点与策略组定义保持原样。未切换运行中的网络配置；系统级防泄漏仍需客户端加载后的抓包证明。详见 [证据与适用范围](docs/evidence/2026-09-07-clash-routing.md)、[Clash 部署约束](docs/CLASH.md)。本批次通过 `update.sh` 执行远端发布和 CDN 核验，实际完成状态见发布结果。

## 历史索引

以下批次的细节和实际验证见上述完整记录。旧审计报告已过时，可用
`git show 9ebce49:docs/AUDIT_AND_GOVERNANCE_REPORT.md` 查阅当时版本。

| 批次 | 变更 |
|---|---|
| 2026-09-02·全表复核与覆盖补录 | .cn 直连兜底表 + 上游同步（ChinaIP / ChinaDomain 增量）+ 14 张手工表覆盖补录与属地归位 |
| 2026-09-02·网络仿真与全量治理 | 网络请求仿真测试体系全面升级 (4,043 断言) + 34 表拓扑重叠与失效资产深度审计 |
| 2026-09-01·仓库精简 | 测试/检测层瘦身 44%、场景 27 文件并 9、目录归一,行为逐数不变 |
| 2026-09-01·ChinaIP 归属审计 | 剔除 432 个 RIR 口径下确属外国的上游错误收录条目 |
| 2026-09-01·用户排法 | 六分区聚类 + 地区表域名/IP 合并(34 表),吸收用户手写 conf 排法 |
| 2026-09-01·仓库精简 | 删历史诊断文档与 module/script 脚手架,tests/README 减 70% |
| 2026-09-01·日本 IP 合并 | `JapanServiceIP` 并入 `JapanIP`:表数 39 → 38 |
| 2026-09-01·聚类重排 | 表间聚类:9 张国内直连表连成一段,地区域名整体后移 |
| 2026-09-01·冗余清理 | 同表冗余收尾:删 28 条被同表宽父完全覆盖的窄条目 |
| 2026-09-01·重排 | 表内类型分组 + conf 分区呈现 |
| 2026-09-01·复验 | FINAL 漏斗回归纠正 + ProxyGFW 迁移清理 |
| 2026-09-01 | Deterministic topology and residual-GFW refactor |
| 2026-08-31·三轮 | V2 审计整改:24 项确定级修复 + A9/A10 门禁上线 + 供应链锁层开工 |
| 2026-08-31·二轮 | 审计整改完成:关键词全量迁移(104→8) + DownloadCDN 止血 + ChinaIP 折叠减半 + 测试链加固 |
| 2026-08-31 | 外部审计整改:发布链三态化 + forbidden 门禁 + 归属修正 + 关键词边界化 |
| 2026-08-30 | Reject 启用 + DIRECT 过度覆盖修复 + 全库注释精简 + 公开仓库脱敏 |
| 2026-08-29 | 布局重构 v2 —— 待发布 |
| 2026-08-27 | Clash (Mihomo) 派生层上线 |
| 2026-08-25 | 审计整改与测试体系固化 |
| 2026-08-25 | blackmatrix7 大合并与发布链建立 |
| 2026-08-25 | 初始发布 |
