# 上游来源登记

`lists/` 下的 34 张表不是从零手写的:国内长尾、IP 段、各厂商与服务表的底料来自若干上游开源规则集,再经本仓库裁剪、重组、全局唯一化去重后成形。本文件逐条登记这些上游 —— 上游 URL、能取到的本地快照 revision、许可证、以及本仓库的使用方式,供再分发溯源与合规核对。

使用方式分三类:**整表引用**(上游一张表基本整体进入本库某张表)、**取材/裁剪**(按行筛选后并入)、**对撞参考**(不直接引入,只在做关键词迁移、精确集恢复、归属裁决时对照)。

「本地快照 revision」列记的是**取材当时那一份的 revision**,是溯源坐标而不是现存文件:曾经落在 `reference/` 下的这些克隆(始终 `.gitignore`、从不分发)已于 2026-09-01 随仓库精简删除。需要复核某条取材时,按该列的上游 URL + revision 重新浅克隆即可 —— 都是公开仓库,重新取得的字节与当时一致。

| 来源 | 类别 | 上游 URL | 本地快照 revision | 许可证 | 本仓库使用方式 |
|---|---|---|---|---|---|
| blackmatrix7/ios_rule_script | 规则上游 | https://github.com/blackmatrix7/ios_rule_script | `reference/ios_rule_script` @ `65e8adf`(上游提交 2026-08-28;sparse-checkout `rewrite` + `script` + `rule/Surge`,`rule/` 于 2026-08-30 追加检出) | GPL-2.0(仓库 LICENSE);README 另声明「禁止公众号 / 自媒体转载发布」 | 主力上游。整表引用:ChinaDomain ← `ChinaMaxNoIP`、ChinaIP ← `ChinaIPs`(须 IPv4 + IPv6 全量源)。取材/裁剪:PrivateLAN ← `Lan`、AppleCN ← `Apple`、Games ← `Game`、GameDownloadCN ← `Game/GameDownloadCN` + `SteamCN`、ProxyGFW ← `Proxy`、Telegram ← `Telegram`、TikTok ← `TikTok`、ChinaMedia ← `ChinaMedia` 系、AlibabaCN ← `Alibaba` + `AliPay`、TencentCN ← `Tencent` + `WeChat`、BaiduCN ← `Baidu`、ByteDanceCN ← `ByteDance`、NetEaseCN ← `NetEase`、Reject 恶意层 ← `Hijacking` + `BlockHttpDNS`。对撞参考:`rule/Surge/<Service>/` 下各服务表(YouTube / Google / Twitter / Facebook / Instagram / WhatsApp / OneDrive / Bilibili / iQIYI / GitHub / Dropbox / AbemaTV / Spotify / OpenAI 等),用于关键词迁移时恢复精确后缀集 |
| SukkaW/Surge(ruleset.skk.moe) | 规则上游 | https://github.com/SukkaW/Surge ;产物 https://ruleset.skk.moe/ | 无本地快照 —— 早期按 URL 直取,未记录 revision | AGPL-3.0 | 2026-08-25 初版本地化的取材源之一:旧 profile 曾直引 `List/{non_ip,ip,domainset}/*.conf` 共 14 条(domestic / cdn / download / stream / ai / apple_cn / apple_services / apple_intelligence / apple_cdn / microsoft_cdn / china_ip / china_ip_ipv6 等),现已拆并入 Domestic / DownloadCDN / Streaming / AI / AppleCN / MicrosoftCN / ChinaIP 等表。Reject.list 的广告投放层由其 reject 规则集**逐行裁剪**而来 |
| Repcz/Tool | 规则上游 | https://github.com/Repcz/Tool (分支 `X`) | 无本地快照 —— 早期按 URL 直取,未记录 revision | MIT | 初版本地化取材源:曾直引 `Surge/Rules/*.list` 13 条(YouTube / Twitter / TikTok / Spotify / PrimeVideo / OneDrive / Netflix / HBO / Facebook / Disney / Bahamut / AppleMedia / DownloadCDN_Global),现已并入 YouTube / Twitter / TikTok / Streaming / MicrosoftCN / DownloadCDN 等表 |
| Loyalsoldier/surge-rules | 规则上游 | https://github.com/Loyalsoldier/surge-rules (分支 `release`) | 无本地快照 —— 早期按 URL 直取,未记录 revision | GPL-3.0 | 初版本地化取材源:曾以 `DOMAIN-SET` 直引 `private.txt`(内网/私有域)与 `icloud.txt`(iCloud 域),对应今 PrivateLAN.list 与 AppleCN.list 的部分覆盖面 |
| Loyalsoldier/geoip | 运行时依赖 | https://github.com/Loyalsoldier/geoip (分支 `release`,`Country.mmdb`) | 无本地快照 —— 由客户端按 URL 拉取,随 release 滚动 | CC-BY-SA-4.0 | 不入本仓库。消费端 Surge 配置的 `geoip-maxmind-url` 指向它,是全链 `GEOIP,*` 判定(地区表 GEOIP 与收尾 `GEOIP,CN`)的实际数据源;离线引擎 `tests/engine.py` 不用它,而以 ChinaIP.list 近似 `GEOIP,CN` |
| VPSDance/ai-proxy-rules | 规则上游 | https://github.com/VPSDance/ai-proxy-rules | 无本地快照 —— 早期按 URL 直取,未记录 revision | MIT | 初版 AI.list 的取材源之一(曾直引 `rules/surge/all.list`);现 AI.list 已按分档裁决重建,见 docs/MAINTENANCE.md §8 |
| VirgilClyne/GetSomeFries | 规则上游 + 开发参考 | https://github.com/VirgilClyne/GetSomeFries | `reference/GetSomeFries` @ `b4aa767`(2026-08-29 浅克隆) | GPL-3.0 | 取材:Reject.list 的 HTTPDNS / 私有 DoH 层取自 `ruleset/HTTPDNS.Block.list` 的差集补充。参考:sgmodule 工程化与 `pre-matching` / `extended-matching` / `no-resolve` 修饰符用法 |
| NobyDa/Script | 开发参考 | https://github.com/NobyDa/Script | `reference/NobyDa-Script` @ `0b8d083`(2026-08-29 浅克隆) | GPL-3.0 | 脚本参考:签到/面板类 sgmodule 与 JS 写法,不参与规则分发 |
| chavyleung/scripts | 开发参考 | https://github.com/chavyleung/scripts | `reference/chavyleung-scripts` @ `3278838`(2026-08-29 浅克隆) | GPL-3.0 | 脚本参考:`Env.js` 框架(环境判定/持久化/通知),不参与规则分发 |
| VirgilClyne/iRingo | 开发参考 | https://github.com/VirgilClyne/iRingo | `reference/iRingo` @ `838d8d2`(2026-08-29 浅克隆,含 NSRingo 9 个 submodule) | Apache-2.0 | 脚本参考:Apple 服务增强(Weather/Maps/Siri/TestFlight)的重写与 Map Local 实战,不参与规则分发 |
| Semporia/TikTok-Unlock | 开发参考 | https://github.com/Semporia/TikTok-Unlock | `reference/TikTok-Unlock` @ `557dc2b`(2026-08-29 浅克隆) | 未声明(仓库无 LICENSE,README 亦未声明) | 模块参考:TikTok 解锁 sgmodule 结构;其 `Surge/TikTok.list` 仅作对照,未整表引入 |
| app2smile/rules | 开发参考 | https://github.com/app2smile/rules | `reference/app2smile-rules` @ `df6366a`(2026-08-29 浅克隆) | MIT | 模块参考:JSON / Protobuf 两条去广告改写路线,不参与规则分发 |
| yichahucha/surge | 开发参考 | https://github.com/yichahucha/surge | `reference/yichahucha-surge` @ `06d6e36`(2026-08-29 浅克隆) | GPL-3.0 | 脚本参考:MitM 改写范式,不参与规则分发 |
| zmqcherish/proxy-script | 开发参考 | https://github.com/zmqcherish/proxy-script | `reference/proxy-script` @ `1d9f51b`(2026-08-29 浅克隆) | 未声明(仓库无 LICENSE,README 亦未声明) | 脚本参考:配置化去广告与抓包分析笔记,不参与规则分发 |
| Script-Hub-Org/Script-Hub | 开发参考 | https://github.com/Script-Hub-Org/Script-Hub | `reference/Script-Hub` @ `6b4fb62`(2026-08-29 浅克隆) | GPL-3.0 | 脚本参考:QX / Loon / Stash → Surge 的重写与脚本格式转换器,不参与规则分发 |
| sub-store-org/Sub-Store | 开发参考 | https://github.com/sub-store-org/Sub-Store | `reference/Sub-Store` @ `99941ee`(2026-08-29 浅克隆) | AGPL-3.0 | 工程参考:大型 script + module 工程与 HTTP API 设计,不参与规则分发 |
| fmz200/wool_scripts | 开发参考 | https://github.com/fmz200/wool_scripts | `reference/wool_scripts` @ `2d95818`(2026-08-29 浅克隆) | GPL-3.0 | 模块参考:巨型去广告 module 的分片维护方式,不参与规则分发 |
| xream/scripts | 开发参考 | https://github.com/xream/scripts | `reference/xream-scripts` @ `f902afd`(2026-08-29 浅克隆) | GPL-3.0 | 脚本参考:logger / panel / 诊断类模块,不参与规则分发 |
| Surge 官方手册 | 文档参考 | https://manual.nssurge.com/ | 非 git;`reference/surge-docs` 曾是 2026-08-29 抓取的 87 页 Markdown 副本(随抓取脚本一并于 2026-09-01 删除;需要时直接看在线手册) | 未声明(版权归 Surge Networks,仅本地离线阅读,勿再分发) | 语义核对:`no-resolve` / `extended-matching` / `pre-matching` / RULE-SET 加载等官方定义,是本库两条不变量的规范依据 |
| Public Suffix List | 门禁快照(入库) | https://publicsuffix.org/list/public_suffix_list.dat | `tests/data/public_suffix_list.dat` @ `VERSION 2026-08-29_12-33-06_UTC`;sha256 `24b79d731bb0d296171c513aed2e89c3163cb74a177b14d2b27f006e8ce00936`;333,164 B;取得 2026-08-31 | MPL-2.0(见文件头部) | **不进 `lists/`,只作判据**:`tests/audit.py` A10 的注册边界依据(ICANN + PRIVATE 两段,`*.parent` 通配与 `!exception` 按标准算法处理)。门禁不联网,快照更新是一次有意的提交。与 `reference/audit-v2-20260831/w6/` 的 W2/W6 用件**逐字节一致**,判据可直接对账;刷新步骤见 `tests/data/SNAPSHOTS.json` 的 `_readme` |
| IANA 根区 TLD 表 | 门禁快照(入库) | https://data.iana.org/TLD/tlds-alpha-by-domain.txt | `tests/data/tlds-alpha-by-domain.txt` @ `Version 2026083100`(Last Updated Mon Aug 31 07:07:01 2026 UTC);sha256 `09b9f7dc145257b803853ce3f72a1785744c3789d9f0494dead52c048f9435f4`;9,536 B;取得 2026-08-31 | IANA 公开数据 | **不进 `lists/`,只作判据**:A10 区分「单标签后缀是真 TLD」与「拼写错误 / 已撤销 TLD」。IDN TLD 在表中为 punycode(`xn--`)形态,与 `lists/` 写法一致。刷新与 PSL 同一流程 |

**关于本文件的效力范围**

- 这是**现状登记**,不是构建锁。除 `ios_rule_script@65e8adf` 外,规则上游多为「按 URL 直取后人工重组」,既没有逐表原始 SHA-256,也没有可复现的转换命令与排除清单;曾用作本地对照的那批浅克隆本身也是可变的,不适合直接充当供应链输入。
- **逐表 revision 锁定、原始 checksum 与可一键重建的再生管线仍属 Phase 3 供应链工程**(依据见 `git show e03c530:docs/RULES_AUDIT_AND_OPTIMIZATION_2026-08-31.md` §13.2 / §13.7 / §14.4 与其 Phase 3 路线;该报告已于 2026-09-01 从 `docs/` 移除,结论见 CHANGELOG 2026-08-31 条目)。**2026-08-31 起已开工但未完工**:仓库根 `sources.lock.json` + `tools/fetch_locked.py` + `tools/rebuild.py` 落地了机器可读的锁层,其中 **ChinaIP 已做实**(pinned 到 `blackmatrix7/ios_rule_script@65e8adf`,折叠后与本地文件地址集合逐位相同,`rebuild.py` diff = 0);其余表按 provenance 如实标为 `observed`(未锁)。**在全部表转为 pinned 之前,不要把本文件或该 lock 当作「固定 revision 可逐字节重建全部分发物」的依据。**
- 上表末两行的 PSL / IANA 快照**不是规则上游**,不参与 `lists/` 的任何内容,只作 `tests/audit.py` A10 的离线判据;它们是本仓库唯一逐字节锁定并入库的外部数据。
- 各上游版权归原作者,遵循其各自仓库的 LICENSE。本仓库对上游内容做了裁剪、重组、去重与归属重裁,**不保证与任一上游语义等同**;上游的收录裁决与本库的偏离逐条登记在 docs/MAINTENANCE.md §8「裁决登记」。
- 本仓库自身尚未声明 LICENSE(同一报告 §13.7 同批建议,待裁决)。
