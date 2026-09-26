# 更新记录

当前约定见 [现行决策](docs/DECISIONS.md)，操作流程见 [维护手册](docs/MAINTENANCE.md)。
历史数字只代表对应批次，当前数量以检查输出为准。

## [2026-09-26·学术出版商直连] ProxyGFW 与 DownloadCDN 的学术出版/检索域迁入 Academic

- 用户裁决：学术出版商统一走 Academic 直连。自 ProxyGFW 迁入 11 个：arXiv、OpenReview、Semantic Scholar、Elsevier、ScienceDirect、Springer、Nature、IEEE、ACM、Science 与 sciencemag.org；自 DownloadCDN 迁入 Elsevier 内容 CDN 2 个（sciencedirectassets.com、els-cdn.com）；新增 Springer Nature 资源域 springernature.com。
- 迁前实测：18 个代表主机经 Surge 的 DIRECT 策略全部可达。用国内 DoH（迁移后的解析路径）的结果绕过 Surge 直连，TLS 校验全部通过；link.springer.com 与 www.nature.com 的国内解析为 Google Cloud 入口，证书为 `*.nature.com`，不是污染。paperswithcode.com 直连 4 次均被对端关闭，保留在 ProxyGFW。
- ChinaDomain 中的出版商（Wiley、T&F、SAGE、OUP、Cambridge、JSTOR、APS、ACS、IOP、PNAS、Scopus 等）本就直连，不重复收录；地区表中的高校保持原归属。机构订阅只在校园网内生效，校外直连使用本地运营商地址。
- 验证：规则 140,748 → 140,749（+14/−13）；真实 MMDB 关系分析无遮蔽和顺序不安全拆分；静态审计无 P0/P1/P2（3 个既有 P3）；场景 5,090 条（新增 32 条）和其中 2,232 条 DNS 断言全过；对抗测试 84/84；Clash 53 表 140,749 条，合同检查通过。学术场景放到迁移前的规则上有 15 条失败，说明断言覆盖了本次迁移。
- 同批按用户要求发布仓库指令文件统一：删除只含 `@AGENTS.md` 一行的 CLAUDE.md，AGENTS.md 去掉对它的引用。
- 发布：`f48f68a` **PUBLISHED_AND_VERIFIED**。update.sh 预检发现 6 个变更文件已是新内容，没有发出刷新，但 Surge 自己下载到的仍是旧的 ProxyGFW、Academic 和 DownloadCDN。补发这 6 个文件的 jsDelivr purge 后，Surge 缓存与发布文件逐字节一致；20 条原生见证全部通过，arXiv、OpenReview、Semantic Scholar、IEEE Xplore、Springer 和 Elsevier 在当前规则下都经 DIRECT 返回 200。

## [2026-09-26·FINAL 监控归类] 按 12 天 FINAL 实测归属 99 个目的地

- 私有 FINAL 监控在 2026-09-15～26 记录 6,766 次连接、287 个目的地（已排除 16 次受控探测），在本批之前已发布的规则下（含同日上游复核）全部仍落 FINAL。本批归属其中 99 个，覆盖 5,354 次（79.1%）。Obsidian 同步、Cloudflare MCP、Writefull 和 Gemini API 文档 MCP 等高频项都有了明确归属；逐主机用量只留在私有监控里。
- 用户裁决三项：①境外、未证实被墙、没有专属归属的第一方服务并入 ProxyGFW（15 条，含 Obsidian、Overleaf 编译产物、Zotero、Tailscale、Typora、NodeSeek 和资讯站；主机商与代理服务商站点会暴露私有基础设施，未写入公开列表）；②新建 Academic 直连表（21 条，位于 PKU 之后），用校园网 IP 访问机构订阅；③Reject 只收投放与竞价面（12 条）。测量、身份图谱、ABM 与归因类按「拦广告不拦统计」继续放行。
- 服务归属：Google +3（Gemini 文档 MCP、Colab 运行时、安全浏览 OHTTP 中继）；Microsoft +1（Clarity）；AI +13（Writefull、GPTZero 等，以及 Cloudflare MCP 与 STUN 两个精确主机）；Payment +3、SocialOthers +2、Streaming +1；DownloadCDN +2（Tectonic 宏包、Surge 更新源）。TencentCN 把 `qcloud.com` 从精确顶点升级为后缀，依据是腾讯云 IM 登录端点经代理反复失败。TelegramIP 依据客户端流量和 RIPE 登记再准入 `95.161.64.0/20`。
- 约 1,412 次连接留在 FINAL，依据既有裁决或上述隐私考虑：通用 SaaS 组件；反爬、验证码、指纹与 IP 定位组件；租户边界；裸 IP；未识别域。
- 规则 140,674 → 140,748（+75/−1），表 52 → 53，有序安全拆分父域 28 → 33（均为子项在前）。
- 验证全部通过：原生语法、渲染一致性、引擎自检 54/54；真实 MMDB 关系分析无遮蔽和顺序不安全拆分；静态审计无 P0/P1/P2（3 个既有 P3）；场景 5,058 条（新增 212 条，qcloud 的 6 条断言迁入新场景）和其中 2,216 条 DNS 断言；对抗测试 84/84；Clash 53 表 140,748 条，合同检查通过。新增场景放到旧规则上有 83 条失败，说明断言确实覆盖了本批改动。
- 发布：`6cbd13c` **PUBLISHED_AND_VERIFIED**，25 个分发文件中 2 个原本一致、23 个刷新后复验一致；另抽查 5 个关键文件的 CDN SHA-256 一致。私有 Surge 配置只新增 Academic 规则与 DNS 映射 2 行，自动重载后 53 个规则集全部刷新就绪（同时生效了同日上游复核的列表），47 条原生匹配见证落到新归属；未被任何域名表认领的 `api.segment.io` 解析后按既有美国地区 IP 规则分流。Clash 配置新增 Academic provider 与规则 8 行，生产 Clash 进程未运行。

## [2026-09-26·上游复核] 固定输入重锁、ChinaIP/ChinaDomain 刷新与厂商补录

- 检查 11 个上游仓库 13 个分支头。原 412 份固定输入中 339 份字节未变、66 份有变化、7 份版本未动；9/13 无法访问的 41 份 SukkaLab 分发文件现已可取。连同 Sukka 新增的 `domestic_cdn` 3 份，共 415 份复核输入重锁到当前版本，经 `fetch_locked.py` 逐份 SHA-256 校验通过。
- ChinaIP 按 blackmatrix7 `9ff3629c` 锁定重建：接受上游删除的 4 段（Cloud Innovation 的 US 段、China Telecom South Africa 的 ZA 段）；上游新增的 `64.96.5.0/24`、`2620:57:4004::/47` 经 ARIN RDAP 为 Uniregistry/Tucows（US/CA），列入复核暂扣。11,067 → 11,063，重建 diff 为 0。
- ChinaDomain 按同一版本只增不删：761 个新候选解析成功率 78.3%（门槛 70% 未调整），写入 371 条正向 KEEP，106,962 → 107,333。修正生成器：P10 承载集保护只防删除，不能作为新增依据；PSL 公共后缀不得新增，因此拦下 `DOMAIN-SUFFIX,in.th`；同时保留现有表头。新增 1 条回归测试。
- 厂商与服务补录（均有注册或 NS 证据）：Meta 收 `tfbnw.net`；Payment 收 `stripe.dev/.events/.global`；Google 收 `firebase.dev`；AI 收 `freebuff.com`（Codebuff 更名）；Meta 的 Llama 权重下载域 `llamameta.net` 归 ModelDownloadCDN。
- 地区与直连：gfwlist 新增的 `note.com` 属日本内容平台，连同其静态资源域 `st-note.com` 归 Japan，DownloadCDN 交还 `assets./cdn.st-note.com`；`chineseposters.net`、`quakemachinex.com` 进 ProxyGFW。Sukka 已从全局 CDN 移除 `tripcdn.com`，国内解析返回中国移动地址，改归 Domestic；Firefox 新门户探测域进 Domestic。
- DownloadCDN 收 Sukka 新增的 15 条 CDN/镜像主机，已有具体归属的主机保持原 owner；嵌入式无障碍组件 `cdn.eye-able.com` 不入下载组。手工表净增 25 条，全库 140,282 → 140,674。
- 未采用：Loyalsoldier/hagezi/Sukka 聚合拒绝列表的增量、`rs.lovable.dev`（缺用途证据）、v2fly/MetaCubeX 的 geolocation-cn 增量、作业帮从百度拆分（两者都直连，blackmatrix7 仍列在百度）、gfwlist 9/26 新增（镜像尚未同步）。TelegramIP 与官方 CIDR 完全一致，无需改动。
- 验证：52 张表形态规范；原生语法通过；真实 MMDB 全量关系分析无遮蔽、无顺序不安全拆分；静态审计无 P0/P1/P2，仅 3 个既有 P3，豁免无失效；364 场景 / 2,464 请求 / 4,852 断言通过，其中 DNS 断言 2,135 条；Clash 52 个 provider 与 140,674 条规则逐条一致，86 个归属见证通过；引擎自检 55/55、v2 回归 20/20、过期安全自检通过。
- `4632936` 已推送，状态 **PUBLISHED_AND_VERIFIED**：22 个变更分发文件经先验/刷新核验一致，另对 `@main` 与固定提交各验 105/105 个文件的 SHA-256。双端私有配置已使用 `@main`，无需改动；客户端下次更新外部资源时生效，本批未重载 Surge，也未检查生产 Clash 客户端。

## [2026-09-13·文档与目录清理] 保留现行说明，归档重复资料

- 六份分散的历史证据归并为一份现行决策，保留 OneDrive、Google、AI 和 IP 归属及未完成的实测边界；完整旧记录使用固定 Git 版本链接。
- 精简 AGENTS、CLI 指南、维护流程和旧日志；修正来源文档的旧 ChinaIP pin 说明与 MMDB 行为描述，统一正式 `@main` 使用约定。
- Profiles 的旧路由计划、Clash 历史草稿、失配验证报告和缓存移至仓库外可恢复暂存；保留当前双端配置、节点/SSH 说明、部署记录和 Backup。
- 排除 Backup 后，Markdown 27 → 15 份，79 个旧文件可恢复移出；63 个本地链接/锚点、11 个固定 Git 历史引用（9 个对象）、36 个文件/通配路径检查通过，差异与私有忽略检查通过。161 个规则/代码/锁等运行相关文件、Clash 配置及保留的节点/SSH 资料与清理前逐字节一致；双端配置未由本次清理写入，未执行规则发布。

## [2026-09-13·全局工具] 安装 Surge skill 与 CLI，补充使用文档

- 从 Surge 6.9.1（12290）应用内安装 1 个 skill、5 个文件至用户级 `~/.agents/skills/surge`，Claude 通过链接共享；4 个文件与原包逐字节一致，仅修正 UI 提示中与正文冲突的 `--raw` 建议，并补显式 `$surge` 调用。
- 将 `~/.local/bin/surge-cli` 链接到应用内官方可执行文件；签名校验通过，运行中 Core 6009001 / Controller Protocol 25。11 项帮助入口通过，有效/无效临时配置分别返回 0/1。
- Codex 在仓库和独立临时目录均发现唯一、已启用的 USER skill。新增 [安装、诊断与升级指南](docs/SURGE-CLI.md)，更新 AGENTS、README、维护和测试入口；CLAUDE 继续导入 AGENTS。文档链接、路径和差异检查通过。本批仅安装工具和更新文档，未执行规则发布。

## [2026-09-13·域名/IP 分区重构] 52 表与加密解析兜底

- 35 个原表名称保留，拆出 17 个 IP 表；域名先于 IP，各区代理/地区/直连连续。Microsoft/Games 收窄父域，保留 67 个 OneDrive 会话正例和下载例外。
- 规则 142,212 → 140,282；StreamingIP 1,983 → 21，TelegramIP 按官方集合折叠为 11 条，GamesIP 41 → 8，JapanIP 移除五个全运营商 ASN。AI/Meta/X 再准入使用新 RDAP 证据。
- ChinaIP 锁定重建为 11,067 条，保留排除和受控范围；ChinaDomain 未通过新增候选可信度门槛，原 106,962 条保持。修复过期探测的超时误判与同日重复计数；21,906 个域名值复核未产生确认死亡结论。
- 匹配、分析和双端生成使用真实 MMDB、明确 DNS 状态与逻辑集合减法；CIDR 折叠保留尾参。模型下载/服务族归属补齐，缺乏证据的共享资源和 ProxyGFW 扩张未采用。
- 当批 4,750 条场景断言、84 条对抗断言通过；静态无 P0/P1/P2，3 个既有 P3。`8c92cbb` 发布状态 **PUBLISHED_AND_VERIFIED**。
- 最终按用户要求恢复正式 `@main` 地址：CDN 105/105 文件一致，Surge 52/52 资源就绪、90/90 原生见证通过；隔离 Mihomo 加载 52 表，双栈 DNS 与 8/8 连接策略验证通过。未据此宣称生产 Clash 已加载、账户同步成功或日常 FINAL 下降。[当批完整证据](https://github.com/yhyfhgs/surge-rules/blob/caf887f791185f46c371d482788af690677c4573/docs/evidence/2026-09-13-domain-ip-v2.md)。

## 历史索引

- [本次精简前的日志](https://github.com/yhyfhgs/surge-rules/blob/caf887f791185f46c371d482788af690677c4573/CHANGELOG.md)：2026-09-13 首轮仓库精简、OneDrive 恢复代理及失败直连试验、AI 上游维护、微软合并和旧 Clash 方案。
- [更早的完整日志](https://github.com/yhyfhgs/surge-rules/blob/9ebce49d8644dbe982fdcddfc62eb46296a7b277/CHANGELOG.md)：2026-09-02 及之前的治理、验证和发布批次。
- [历史审计报告](https://github.com/yhyfhgs/surge-rules/blob/9ebce49d8644dbe982fdcddfc62eb46296a7b277/docs/AUDIT_AND_GOVERNANCE_REPORT.md)：仅用于追溯，不作为现行设计或统计。
