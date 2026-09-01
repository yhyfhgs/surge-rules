# 更新记录

本文件遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 风格,倒序排列。

---

## [2026-09-01·用户排法] 六分区聚类 + 地区表域名/IP 合并(34 表),吸收用户手写 conf 排法

**来源与事故披露**:用户曾直接手改活动 `Surge.conf` 的 `[Rule]` 段(六个自命名分区、
按国家配对地区表、下载聚合、ProxyGFW 收进代理区尾),该版本在上一批次被误判为
「渲染滞后」而覆盖 —— 备份存于 `Profiles/Backup/Surge.conf.user-edit-20260901.bak`。
经用户裁决,本批次把该排法**正式吸收进 `config/routing.json`**(manifest 是 `[Rule]`
的唯一真源,手改 conf 无法存续,这也是事故根源)。

### Changed
- **manifest 重排为用户六分区**:局域直连 → 广告/恶意拦截 → 下载(GameDownloadCN,
  ModelDownloadCDN,**DownloadCDN 提前**) → 代理(服务生态 13 张,**ProxyGFW 收尾**) →
  国内直连(AppleCN…NetEaseCN,ChinaDomain,ChinaIP 共 11 张连续 DIRECT) →
  地区分流(Japan,US,UK,Europe)。72 个翻转表对经关系检索:仅 6 组有跨策略记录,
  其中 4 组(270 条)为 wildcard×wildcard 的纯语法假想交集,零现实风险。
- **地区表合并为域名+IP 混合表**(用户指示):JapanIP(18 条,含 LINE/LY 12 CIDR)、
  USIP、UKIP、EuropeIP 并入对应地区表的 IP 桶后删除,**39→34 表**;行级
  `no-resolve` 原样保留(A1 红线),manifest 不再需要表级 `no_resolve`(Streaming
  混合表先例)。**区内 Japan 居首**:MaxMind 把部分 LINE CIDR 判为 US,若 US 在前
  `GEOIP,US` 会抢走属地锁段;Japan 居首同时让日本运营商 ASN 的全球段维持既有落点,
  本批次地区 IP 行为零变化。
- **删除 2 条多租户 wildcard(翻转冲突的真实来源)**:`DownloadCDN` 的
  `*-res.cloudinary.com`(翻转后会抢走 AI 的 `pplx-res.cloudinary.com`,且与 S3
  租户边界判例同构)与 `cdn.*.office.net`(会抢走 Microsoft 的
  `cdn.designerapp.osi.office.net`;office CDN 长尾由 MicrosoftCN 的 `office.net`
  承接,落点从「下载(可切)」收敛为恒 DIRECT,与 res*.cdn 锁死判例一致)。
  **随动断言**:`download_cleanup` 中该 wildcard 的正例一对
  (`image-res.cloudinary.com`)随规则删除而移除 —— 正例的存在意义就是验证该规则;
  防伪造负例(`image-res.cloudinary.com.thief.net`→Final)保留。
- conf 重渲染落盘(mtime 实证)+ `render --check` 通过;clash/ 再生(34 表,删 4 个
  陈旧派生)。

### Verified
- analyzer plain+MMDB `--fail-on-shadow` 双 exit 0:141,649 条(141,651−2)全 accounted,
  **order_unsafe 全零**(翻转安全性的机器兜底),shadow/cycles/GFW 三闸门全空,
  约束 24/41,ordered-safe 顶点仍为同一组(13/14);runsuite 227 场景/1,643 请求/
  **3,097 断言全绿**(3,099−2,即随动删除的一对),DNS 泄漏 1,325 条 0 失败;
  audit 未豁免仍 3 条 P3;sort_lists 34/34;surge2clash 守恒;surge-cli OK。
- 落点抽测 16/16:翻转修复生效(pplx-res→AI、designerapp→Microsoft)、
  护栏保持(music.apple.com→流媒体、odc.officeapps→Google-X-Meta-MS、
  storage.googleapis.com→Final)、地区表后置仍做功(welt.de/mixi.jp/standard.co.uk)、
  LINE IP `103.2.28.1`→日本节点、既有修复零回退。

## [2026-09-01·仓库精简] 删历史诊断文档与 module/script 脚手架,tests/README 减 70%

**动机**:仓库里堆着三类没有消费者的东西 —— 结论已经进 `ARCHITECTURE`/`CHANGELOG` 的
历史诊断报告、一个从未产出过生产件的 module/script 脚手架、以及一份把叙事和操作混在
一起的 770 行测试文档。留着它们的代价不是磁盘,是**每次改动都要判断一遍「这份还算不算
数」**;`RULE_ANALYSIS` 那份甚至还在被 `README`/`ARCHITECTURE` 当作现行依据引用,而它的
基线早已被后两个批次改掉。本批次**只删文档与脚手架,不动任何规则、测试代码、场景、
allowlist、快照**。

### Removed(入库面,git 可完整恢复)
| 文件 | 行数 | 处置依据 |
|---|---|---|
| `docs/RULE_ANALYSIS_2026-09-01.md` | 293 | 诊断证据,结论已在 `ARCHITECTURE` + `CHANGELOG`;其 141,829 条基线已被后续批次改掉,继续被引用只会误导。`git show 311f7cd:` 可取全文 |
| `docs/RULES_AUDIT_V2_2026-08-31.md` | 12 | 2026-08-31 起就只是指向 `RULE_ANALYSIS` 的桩;全文见 `git show 5dcd5ec:` |
| `docs/RULES_AUDIT_AND_OPTIMIZATION_2026-08-31.md` | 12 | 同上;全文见 `git show e03c530:` |
| `docs/DEVELOPMENT.md` | 273 | module/script 开发指南。它描述的三件交付物(`modules/`、`scripts/`、`reference/`)本批次全部删除,全文随之失去对象 —— 见下方「并入 MAINTENANCE 的部分」 |
| `modules/README.md` + `modules/_template.sgmodule` | 38 + 217 | 脚手架。全库零 `PROCESS-NAME`/`USER-AGENT`、零模块分发,`update.sh` 的 `DIST_RE` 也不包含这两个目录 —— 模板不该占 CDN purge 额度,更不该占「这仓库是干什么的」的认知带宽 |
| `scripts/README.md` + `scripts/_template.js` | 38 + 456 | 同上 |

合计删除 **1,339 行 / 8 个文件**。`tests/README.md` **770 → 233 行(−70%)**:保留各工具
用途、全部调用式、断言与 allowlist schema、退出码、已知观察项与限制;删除历史叙事、
过时基线数字(208 场景 / 1418 请求 / 2639 断言 / 39 表等,真值改为指向 `CHANGELOG` 与
命令自身输出)与重复段落。**测试代码、`scenarios/`、`allowlist.json`、`tests/data/`
一个字节未动。**

**并入 `MAINTENANCE` 的部分**:`DEVELOPMENT.md` 里只有三条仍然作用于**现存对象**(活动
profile)的约束,已移入 `MAINTENANCE` 新增的「Profile red lines」:CA 证书材料与口令永不
入库(公开仓库,git 历史不可逆);`[MITM]` 不写 `enable` 键(Surge 规范化会移除,开关在
GUI 运行态,conf 只留 `h2 = true`);`hostname` 非空时 `auto-quic-block` 必须为 `true`
(否则被解密域的 HTTP/3 绕过 MITM 形成半解密)。另把 `update.sh` 的 `DIST_RE` 分发面
(`lists/*.list` + `clash/*.list` + `rule-providers.yaml`)写进「Derive and publish」,
并新增一条「manifest 改了就重渲染 profile」——本批次 5a 刚踩到活动 profile 落后一个批次
的坑。其余(sgmodule 段语义、脚本 API 全表、MitM 原理、调试流程、参考项目导读)随对象
一并删除。

### Removed(本地未入库面,不可从 git 恢复)
- `reference/` 整个目录:**434 MB / 9,716 个文件**。含 14 个上游浅克隆(`ios_rule_script`
  136MB、`wool_scripts` 117MB、`chavyleung-scripts` 78MB、`iRingo` 36MB、`xream-scripts`
  16MB 等)——全部是公开仓库,`SOURCES.md` 逐条记着 URL + revision,随时可重新克隆;
  以及 `audit-v2-20260831/`(19MB 工作归档)与 `meta-defensive-inventory-20260831.txt`,
  两者结论均已提炼入库,且含出口判定类信息,本地不留。
- `tests/__pycache__`(464KB)、`tools/__pycache__`(208KB),运行时自动再生。

删除前 `rg --no-ignore --hidden 'reference/'` 全库排查,唯一的**程序性**引用是
`sources.lock.json` 的 `"local_mirror": "reference/ios_rule_script"`,已删除该键 ——
它只是 `fetch_locked.py` 的可选离线后端(取不到就静默回落网络后端),sha256 校验对两个
后端一视同仁,**证据链强度不变**;`fetch_locked.py` 的取源顺序注释同步说明。其余引用
全是散文:`SOURCES.md` 的快照 revision 列(已加一句说明它是溯源坐标而非现存文件)、
`CHANGELOG` 历史条目、以及 `tests/` 数据面里三处 `reason`/`desc`/`note` 说明文本
(**按不动测试面的约束原样保留**,它们不是会被打开的路径)。`.gitignore` 的
`reference/` 条目**保留并补注释**:目录没了,但条目仍是防线,防止将来重新克隆时被
`git add -A` 整仓提交进来。

### Changed
- `docs/ARCHITECTURE.md` / `README.md` / `SOURCES.md` 中指向被删文档的引用,改为
  `git show <commit>:<path>` + 对应 `CHANGELOG` 条目。
- `docs/ARCHITECTURE.md` 的最终验证数字同步校正到实测(与 5a 校正 `README` 同源的既有
  漂移):141,679 → **141,651** 条、1,739(476 covers)→ **1,711(448)**、
  3,575,469 → **3,575,213** 对、3,554,063 → **3,553,807** split-policy、
  redundant coverage 317 → **289**。

### Verified
全套闸门在删除后重跑,**8 项全部退出 0**:`analyze_rules --fail-on-shadow` plain 与
MMDB(141,651 条 / 38 表,与 5a 后逐项相同)、`audit.py`(A9=144、未豁免 3 条全 P3、
`allowlist_unused` 0)、`runsuite.py`(227 场景 / 1,644 请求 / 3,099 断言全绿,
DNS 泄漏断言 1,326 条 0 失败)、`render_surge_rules --check`、`sort_lists --check`、
`surge2clash --check`、`surge-cli --check`。删除面全在文档与本地归档,闸门数字与 5a 后
完全一致本身就是「没碰到承重面」的证据。

未跑 `update.sh`,未推送,未触发 CDN purge。

## [2026-09-01·日本 IP 合并] `JapanServiceIP` 并入 `JapanIP`:表数 39 → 38

**动机**:`JapanServiceIP` 与 `JapanIP` 是同一个策略(`🇯🇵日本节点`)、同一个修饰符
(`no-resolve`)、同一个语义面(日本 IP)的两张表,拆开只为了让 12 条 LINE/LY 实测
网段排在 `ChinaIP` 之前。但这个「之前」是空的:**这 12 条 CIDR 与 `ChinaIP` 的全部
11,088 段地址空间交集为 0**,`ChinaIP` 根本没有机会抢跑,所以把它们挪到 `ChinaIP`
之后不改变任何一条落点。一张只为不存在的冲突而存在的表,是分发链上多出来的一个
`RULE-SET` 往返、一份 CDN 产物和一条要维护的 manifest 条目。

**唯一语义改动**:12 条 `IP-CIDR` 从 `JapanServiceIP` 移入 `JapanIP` 的 `IP-CIDR`
桶(桶序由 `sort_lists.py` 决定,CIDR 在 `IP-ASN`/`GEOIP` 之前),`JapanServiceIP`
整表删除。**规则内容一条未增未删未改写**;12 条 CIDR **保留显式网段、不折叠成
ASN/GEOIP**——GeoIP 库是上游漂移面,把实测网段化进 `GEOIP,JP` 等于把 LINE 段的
命中权交给一个会变的第三方数据库。

### Changed
- **`lists/JapanIP.list`**:12 条 LINE/LY `IP-CIDR` 并入(`103.2.28.0/22`、
  `119.235.224.0/21`、`119.235.232.0/23`、`119.235.235.0/24`、`125.6.146.0/24`、
  `125.6.149.0/24`、`125.6.190.0/24`、`147.92.128.0/17`、`203.104.103.0/24`、
  `203.104.128.0/19`、`203.174.66.64/26`、`203.174.77.0/24`),头注释改为
  「JapanIP — 日本服务网段与 ASN/GEOIP fallback」。`lists/JapanServiceIP.list` 删除。
- **`config/routing.json`**:删 `JapanServiceIP` 条目,分区 8 只剩 `ChinaIP`,
  `section` 由「服务与国内 IP」更名为「国内 IP」。其余 37 条条目的
  `name`/`policy`/`extended_matching`/`no_resolve`/`section` 逐条比对全等,顺序未动。
- **`Surge.conf` `[Rule]` 段重渲染**:少 1 行 `RULE-SET`、分区 8 注释更名。
  顺带修正一处**发布链遗留漂移**:磁盘上的活动 profile 停留在 c5cebe9 之前的
  11 段旧序(`render_surge_rules --check` 在 HEAD 上本就退出 1),本次重渲染把
  c5cebe9 的聚类重排与本批次一并落到 profile,`--check` 恢复退出 0。
- **`clash/` 随 manifest 再生**:`JapanIP.list` 更新、`JapanServiceIP.list` 与
  `rule-providers.yaml` 对应 provider 块删除,事务式替换报告「更新 2、未变 37、
  删除陈旧 1」,`--check` 报 38 表 141,651 条一致。
- **文档同步**:`docs/ARCHITECTURE.md` 的 IP phase 图删去 `JapanServiceIP` 层,
  「Verified LINE/LY ranges remain ahead of ChinaIP」改写为 LINE/LY 段以显式 CIDR
  留在 `JapanIP`、与 `ChinaIP` 零交集且由 A9 跨策略门禁看守;`docs/MAINTENANCE.md`
  的 ChinaIP 节把「显式服务网段可以排在 ChinaIP 之前」改写为**判据**:只有真的
  与 ChinaIP 相交才需要独立前置表,不交就并入同策略地区表,并要求跨 ChinaIP 边界
  移动 CIDR 前先复算交集;`README.md` 路由模型表删 Service IP 行。

### Verified
证据落盘 `verify-20260901/J-merge-slim/`:
- **零交集证明(执行前复算)**:12 条 CIDR × `ChinaIP` 11,088 段(7,163 条 IPv4 +
  3,925 条 IPv6)= **133,056 对穷尽两两判定,相交 0 对**;另做一次不依赖该结果的
  地址空间核算——用 `collapse_addresses` 折叠 `ChinaIP` 后逐条 `address_exclude`,
  12 条 CIDR 的**每一个地址都不被 `ChinaIP` 覆盖**(残余 = 全量)。见
  `intersection_proof.json`。
- **关系集恒等**:plain analyzer 的 `topology.json`、`relationships.jsonl`、
  `relationship_aggregates.jsonl`、`split_apex.jsonl`、`split_parent.jsonl`、
  `fragmented_domains.jsonl` **6 份合并前后逐字节相同**。MMDB analyzer 6 份中
  5 份逐字节相同,`relationships.jsonl` 的差异经**按规则内容而非 file:line 位次
  归一化后比对**,3,385 条关系的多重集**完全相同**——差异只是
  `JapanServiceIP.list:N` → `JapanIP.list:M` 的重编号。
- **合并后全闸门**:`analyze_rules --fail-on-shadow` plain 与 MMDB 均退出 0,
  规则 **141,651 条不变**、表数 39 → 38,plain 1,711 条关系(448 covers /
  1,263 overlaps)、MMDB 3,385 条(1,831 / 1,554)、拓扑约束 24 / 41、
  `shadowed_or_conflicting_rules` 0、`order_unsafe_split_*` 均空、无环。
  `audit.py` 退出 0,输出**除 conf 路径外与合并前逐字节相同**:141,687 条、
  A3=1 / A6=7 / **A9=144** / A10=59,未豁免 3 条全 P3、已豁免 63、
  `allowlist_unused` 0 —— **A9 零漂移,allowlist 一条未改**。
  `runsuite.py` 退出 0:227 场景 / 1,644 请求 / **3,099 断言全绿**,
  DNS 泄漏断言 1,326 条 0 失败;**`tests/scenarios/` 无一条断言引用
  `JapanServiceIP` 表名,故本批次零改动、零机械重命名**。
  `render_surge_rules --check`、`sort_lists --check`(38/38)、
  `surge2clash --check`、`surge-cli --check` 均退出 0。
- **落点抽测**:对 12 条 CIDR **逐条**取代表 IP(含 `103.2.28.1`、`147.92.128.1`)
  跑 `tests/engine.py match`,合并前后策略与物理出口同为
  `🇯🇵日本节点` / `🇯🇵日本GLBB家宽`,命中规则同为原 CIDR,只有 `source` 由
  `JapanServiceIP.list` 变为 `JapanIP.list`——**12/12 落点不变**。
- **残留清零**:`rg --no-ignore --hidden JapanServiceIP` 在 `lists/`、`clash/`、
  `config/`、`tools/`、`tests/`(含 `scenarios/`、`allowlist.json`)、`docs/`、
  `README.md`、`Surge.conf` 全部无命中。

**顺带修正的既有文档漂移**(非本次合并所致):`README.md`「Current verified
baseline」块自 311f7cd 起未随 41c07af、c5cebe9 更新,3 项数字与实测不符,本次一并
校正到实测值——源规则数 141,679 → **141,651**,plain 关系 1,739(476 covers)→
**1,711(448)**,MMDB 关系 3,413(1,859 covers)→ **3,385(1,831)**;交集对数
3,575,469 → 3,575,213、split-policy 3,554,063 → 3,553,807。同块其余数字
(159 序依赖例外、59 split apex、118 碎片域、24 / 41 约束、227 场景 / 3,099 断言)
实测一致,未动。

未跑 `update.sh`,未推送,未触发 CDN purge。

## [2026-09-01·聚类重排] 表间聚类:9 张国内直连表连成一段,地区域名整体后移

**动机**:`config/routing.json` 里 DIRECT 表被地区表劈成两半——`AppleCN`/`MicrosoftCN`
在地区域名之前,`Domestic` 起的 7 张在地区域名之后。这个交错不承重:它不来自任何一条
拓扑约束,只是历史上分两批加进来的顺序残留。代价是 `[Rule]` 段读起来策略在
DIRECT→代理→DIRECT 之间来回跳,归属决策树也要在第 5、6、7 步之间折返。本批次按约束
驱动聚类把 9 张 DIRECT 表连成一段、地区域名整体挪到其后,**只改表间顺序,不增删、
不改写任何一条规则,不动任何一张表内的行**。

**唯一语义改动**:`rulesets` 数组重排 + `section` 值同步(「厂商 CN 端点」并入
「国内直连」,分区由 11 段收敛为 10 段,序号重编 0-9)。其余分区与每个分区内部的
相对顺序一律未动。

### Changed
- **`config/routing.json`**:`AppleCN, MicrosoftCN, Domestic, ChinaMedia, TencentCN,
  AlibabaCN, ByteDanceCN, BaiduCN, NetEaseCN` 连续 9 张构成「国内直连」段,
  `Japan, UK, Europe, US` 四张「地区域名」段整体移到其后。`AppleCN`/`MicrosoftCN`
  的 `section` 由「厂商 CN 端点」改为「国内直连」;39 个条目的 `name`/`policy`/
  `extended_matching`/`no_resolve` 字段**逐条比对全等**,section 之外零变化。
- **`Surge.conf` `[Rule]` 段重渲染**:4 行 `RULE-SET` 位置调整、1 行分区注释消失
  (55 → 54 行)、分区号 4-9 顺延。分段 sha256 比对断言:`[General]`/`[Proxy]`/
  `[Proxy Group]`/`[MITM]` 与前言**逐字节相同**,只有 `[Rule]` 段变化。
- **`clash/rule-providers.yaml` 随 manifest 再生**:4 个 provider 块与参考序列尾注
  的 4 行随之移位,内容零改动;39 张 `clash/*.list` 一个字节未变,
  仍为 **141,651 条**。
- **文档同步**:`docs/ARCHITECTURE.md` 的 Domain phase 图把厂商 CN 端点并入
  domestic direct 块、地区域名移到其后并说明聚类依据;`docs/MAINTENANCE.md`
  归属决策树第 6、7 步对调并注明两组互斥;`README.md` 路由模型表的
  「Verified direct」「Domestic domains」两行合并为一行「Domestic direct」。

### Verified
行为等价四重证明,均落盘 `verify-20260901/I-reorder/`:
- **约束满足**:重排前 `topology.json` 的每条 `{before,after}` 断言在新序下逐条复核,
  plain 24 条 + MMDB 41 条 = **65 条全部满足,违反 0 条**(旧序同样 65/65,故本次
  重排既未破坏也未依赖任何一条约束)。
- **翻转对零冲突**:相对序真正翻转的是 `Domestic`/`ChinaMedia`/`TencentCN`/
  `AlibabaCN`/`ByteDanceCN`/`BaiduCN`/`NetEaseCN` 7 张 × `Japan`/`UK`/`Europe`/`US`
  4 张 = **28 对**(`AppleCN`/`MicrosoftCN` 本就在地区表之前,序未翻转,一并作旁证)。
  在重排前 plain 与 MMDB 两份 `relationships.jsonl` 中检索这 28 对的跨策略
  `covers`/`equivalent`/`overlaps`:**0 条**;`relationship_aggregates.jsonl` 的
  split-policy 聚合权重:**0**。事实上这些表对之间**没有任何一条关系记录**。
  另做一次不依赖 analyzer 产物的独立复核:这 11 张表全为域名类规则(无关键词、
  无 IP),直接穷尽 **1,694,202 个规则对**做语言相交判定,**相交 0 处**——
  28 对表的匹配语言两两不交,故先后顺序在语义上自由。
- **重排后全闸门**:`analyze_rules --fail-on-shadow` plain 与 MMDB 均退出 0,
  规则 **141,651 条不变**,`shadowed_or_conflicting_rules` 0、
  `order_unsafe_split_apex` / `order_unsafe_split_parents` 均空、拓扑约束仍为
  24 / 41、无环。产物比对更强:`topology.json`、`relationships.jsonl`、
  `relationship_aggregates.jsonl`、`split_apex.jsonl`、`split_parent.jsonl`、
  `fragmented_domains.jsonl` **两侧各 6 份全部逐字节相同**;`summary.json` 的差异
  只有 `inputs.conf_sha256` 与 `list_order` 两项,全部诊断计数逐项相等。
  `rules.jsonl` 因表位次平移而下标变化,属定义性后果。
  `audit.py` 退出 0:141,687 条、A1-A10 原始命中与清理批次完全一致
  (A3=1、A6=7、**A9=144**、A10=59),未豁免 3 条全 P3、已豁免 63、
  `allowlist_unused` 0;`findings.jsonl`/`report.md`/`a3_details.tsv`/
  **`a9_details.tsv`**/`keyword_review.tsv` 五份产物逐字节相同——A9 是 IP 序敏感审计,
  而 IP 面四段(服务与国内 IP、地区 IP 兜底)相对序一行未动,故不变符合预期,
  无需逐条解释。`runsuite.py` 退出 0:227 场景 / 1,644 请求 /
  **3,099 断言全绿**,DNS 泄漏断言 1,326 条 0 失败,输出与重排前逐字节相同。
  `render_surge_rules --check`、`surge2clash --check`(39 表 141,651 条一致)、
  `sort_lists --check` 39/39 均退出 0;`surge-cli profile check Surge` 报
  `Valid` 退出 0。
- **落点抽测**:从 `D-boundary/landing.csv` 与 `tests/scenarios/fix_final_funnel.json`
  取 **60 个代表域名**,覆盖全部 13 张涉及表(7 张移动的 DIRECT 表 + 4 张地区表 +
  `AppleCN`/`MicrosoftCN`),其中 4 张地区表的候选**全量取尽**(21 个)因为翻转的
  风险面正在于此。`tests/engine.py` match 重排前后逐一对照,
  落点(表 / 策略 / 命中规则 / 物理出口 / 出口类别 / DNS 泄漏)**60/60 相同**;
  52 个域名的 `rule_index` 因表位次平移而变化,不计入落点判据。

`tests/scenarios/` 既有断言一条未改未删;`lists/` 一个字节未动;未跑 `update.sh`,
未触发 CDN purge。

## [2026-09-01·冗余清理] 同表冗余收尾:删 28 条被同表宽父完全覆盖的窄条目

**来源**:同日「FINAL 漏斗回归纠正」把 13 个注册域顶点升回 `DOMAIN-SUFFIX` 后,
这些表里原有的窄枚举条目就被**同一张表内**的宽父完全吞掉了——两条同策略、同表,
靠前者生效、另一条永不单独生效。audit 的 A3 因此报出 11 组 P2 同表冗余(共 29 条)。
行为上无害,但它们白占规则表体积、扩大合并冲突面,本批次一次性清掉。

**口径**:被删域名的落点由同表宽父原样承接,分流结果零变化;行为锚点历来由
`tests/scenarios/` 的场景断言承担,不由冗余行承担,故断言一条未改未删,
3,099 条全绿且输出与清理前逐字节相同。

### Removed
- **28 条同表冗余条目**,逐表分布:`AppleCN` 10 条(`beta`/`gs-loc`/`init.itunes`/
  `ocsp`/`ocsp2`/`smp-device`/`testflight`/`time`/`www.apple.com` 九条 `DOMAIN`
  与 `DOMAIN-SUFFIX,smoot.apple.com`,均由 `DOMAIN-SUFFIX,apple.com` 覆盖);
  `MicrosoftCN` 11 条(`office.net` 覆盖 7 条、`windowsupdate.com` 覆盖 2 条、
  `1drv.com` / `delivery.mp.microsoft.com` 各覆盖 1 条);`ChinaMedia` 4 条
  (`iqiyi.com` 覆盖 3 条、`bilivideo.com` 覆盖 1 条);`AI` 1 条
  (`api.hf.co` ⊂ `hf.co`);`Games` 1 条(`www.blizzard.com` ⊂ `blizzard.com`);
  `AlibabaCN` 1 条(`dashscope.aliyuncs.com` ⊂ `aliyuncs.com`)。
  按类型计:`DOMAIN` −19、`DOMAIN-SUFFIX` −9,IP 面一条未动。
- **`clash/` 6 张表随 `lists/` 再生**,39 表 **141,679 → 141,651 条**。

### Kept
- **`MicrosoftCN.list` 的 `DOMAIN,view.officeapps.live.com` 保留**,是 11 组里唯一的
  例外。依据 2026-08-31「OneDrive 投毒止血」裁决明文「**禁止扩宽为 `live.com`,
  禁止删除**」:该条与 `Microsoft.list` 的窄豁免 `onedrive.live.com` 互为对照,
  显式记录「office 系 `live.com` 子树仍 DIRECT」这条边界,删掉就只剩隐式表达。
  行为由 `ms_boundary` 断言锁定。
- 为它在 `tests/allowlist.json` 新增 A3 豁免一条(exemptions 43 → 44),
  匹配三元组 `A3 / MicrosoftCN.list / DOMAIN,view.officeapps.live.com`,
  并以 `by: DOMAIN-SUFFIX,officeapps.live.com` 收窄豁免面,理由里写明裁决锚点。
  非 `preventive`——它每次运行都应命中,`allowlist_unused` 仍为 0。

### Verified
- `audit.py` 退出 0:A3 原始命中 29 → 1(即保留的那条),经豁免后 **A3 未豁免归零**;
  全库未豁免 14 → **3 条,且全部为 P3**(A6 两条、A9 一条,与清理前同一组),
  P0/P1/P2 均为 0;已豁免 62 → 63,`allowlist_unused` 0、`allowlist_pending` 空。
- `runsuite.py` 退出 0:227 场景 / 1,644 请求 / **3,099 断言全绿**,
  DNS 泄漏断言 1,326 条 0 失败,输出与清理前逐字节相同(仅 conf 路径行不同)。
- `analyze_rules --fail-on-shadow` plain 与 MMDB 两侧均退出 0。规则 141,679 → 141,651
  (−28,与实际删除数吻合)。拓扑面变化只有三处,且都是删冗余的定义性后果:
  `covers` 关系 476 → 448(plain)/ 1,859 → 1,831(MMDB),
  `redundant-coverage` 317 → 289(plain)/ 366 → 338(MMDB),各减 28——
  每条被删规则原本恰好贡献一条「被同表宽父覆盖」关系;
  聚合权重 `aggregate_pairs` 3,575,469 → 3,575,213(−256)是 Reject / TikTok(各 10 条
  关键词与通配规则)、Streaming(6 条)、DownloadCDN、ProxyGFW 与被删的 9 条
  `DOMAIN-SUFFIX` 之间的句法交集逐条消失,拆解后恰好 90+90+54+13+9=256,
  属计数面而非拓扑面。
  其余逐项相等:`shadowed_or_conflicting_rules` 0、`split_apex_rules` 59、
  拓扑约束 24(plain)/ 41(MMDB)、无环、碎片注册域 118、
  `order_unsafe_split_apex` / `order_unsafe_split_parents` 均空,
  ordered-safe 顶点仍是同一组 13 / 14 条(行号引用随删行上移,规则原文逐条比对全等)。
- `sort_lists --check` 39/39 绿——只删行,类型桶结构与桶间空行未受影响;
  `surge2clash --check` 一致、`render_surge_rules --check` 一致。

## [2026-09-01·重排] 表内类型分组 + conf 分区呈现

**动机**:单张 `.list` 里 `DOMAIN` 与 `DOMAIN-SUFFIX` 历来交错书写(ProxyGFW 按注册域族
聚合、Reject 按来源批次追加),人读时要在同一屏里跳着分辨类型;`Surge.conf` 的 `[Rule]`
段则是 39 行同构的 `RULE-SET`,看不出分流的层次。本批次只改**书写顺序与呈现**,
不增删、不改写任何一条规则。

**无损口径**:Surge 的表内匹配不看行序——同一张 rule-set 只有一个策略,落点只取决于
「该表是否包含匹配项」;行序只在 `config/routing.json` 的**表间顺序**上有意义,而那里
一条未动。证明有二:重排前后每张表的「规则行多重集 sha256」逐表相同(39/39);
analyzer 的 relationships / aggregates / split_apex / split_parent / fragmented_domains /
topology 在把行号引用换回规则原文、剥掉 `line`/`global_rank` 等位置标签后**集合完全
相同**(plain 与 MMDB 两侧各验一次)。

### Added
- **`tools/sort_lists.py`**:表内重排器。类型桶固定为 `DOMAIN → DOMAIN-SUFFIX →
  DOMAIN-WILDCARD → DOMAIN-KEYWORD → IP-CIDR → IP-CIDR6 → IP-ASN → GEOIP`,
  此列表之外的类型**报错退出**,不静默放行;桶内域名类按规则值字典序(大小写归一)、
  IP-CIDR/IP-CIDR6 按网络地址数值序、IP-ASN 按 ASN 数值序、GEOIP 按国家码字典序;
  行尾注释(如 Telegram 的 `# last_verified=…`)与 `,no-resolve` 尾参随行逐字节保留,
  文件头注释块原样留在顶部,桶间恰好一个空行。`--check` 作闸门并打印首个偏差、
  `--write` 就地重排、`--selftest` 内置 8 项自检(桶序、注释保留、幂等、多重集守恒、
  未知类型/行间注释/非法 CIDR 报错等)。排序稳定,写后即查必然通过。
- **`tests/analyze_rules_selftest.py` 增两个用例(5 → 7)**:同样两张表、只调换 conf 里的
  引用顺序——ordered-safe(宽父排在异策略窄子之后)跑完整 `--fail-on-shadow` 退出 0,
  该父规则落进 `ordered_safe_split_parents`,`shadowed` 为空;order-unsafe(宽父在前)
  退出 1,落进 `order_unsafe_split_parents`。把「分裂的危害取决于顺序而非形态」
  这条口径钉成回归护栏。既有 5 个用例一字未动。

### Changed
- **37 张手工表按新形态重排**,其中 22 张实际改动:AI、AlibabaCN、AppleCN、ChinaMedia、
  Domestic、DownloadCDN、Europe、GameDownloadCN、Games、Google、Japan、JapanIP、
  Microsoft、MicrosoftCN、PKU、Payment、ProxyGFW、SocialOthers、Streaming、TencentCN、
  UK、US;其余 15 张本就规范。文本层面净减 13 行,全部是多余空行(PKU 的双空行、
  按服务分组留下的段间空行)被归一;注释行一字未改,规则行一条未增删。
- **机器管理层零改动**:`ChinaIP`(IP-CIDR 段 → IP-CIDR6 段)与 `ChinaDomain`
  (DOMAIN 171 条 → DOMAIN-SUFFIX 106,206 条)本就是分组形态,`sort_lists.py --check`
  直接通过,两个文件未被写入。
- **`config/routing.json` 每条 ruleset 增加 `section` 字段**,共 11 个分区:
  0 局域与校园、1 拒绝层、2 下载与数据面例外、3 服务生态、4 厂商 CN 端点、5 地区域名、
  6 国内直连、7 代理残差、8 国内长尾、9 服务与国内 IP、10 地区 IP 兜底。
  rulesets 的相对顺序一条未变——那是上一批次逐条验证过的拓扑序。
- **`tools/routing_manifest.py`**:`section` 进入允许字段并成为必填,校验为去空白后非空、
  不含换行的字符串;另校验分区必须**连续**——同名分区分成两段会让渲染为它输出两行
  分区注释,直接拒。
- **`tools/render_surge_rules.py`**:分区切换处输出一行 `# <序号> <分区名>`,序号由首次
  出现顺序推导而不写进 manifest,因此不会与之漂移。`--check` 逐行比对时注释行同样参与。
  分区注释是注释:Surge、analyzer、audit 引擎、场景引擎在解析前都会丢弃 `#` 行,
  匹配语义为零变化。
- **`../Surge.conf` 重渲染**:`[Rule]` 段净增 11 行分区注释、删 0 行,
  `[General]`/`[Proxy]`/`[Proxy Group]`/`[MITM]` 四段逐字节未动。
- **`clash/` 22 张表随 `lists/` 再生**,39 表 141,679 条规则守恒。

### Verified
- `sort_lists --check` 39/39 绿(写后即查,幂等);`sort_lists --selftest` 8/8 通过。
- 每表规则行多重集 sha256 逐表比对:39 张表全等,总数 141,679 不变。
- analyzer plain:141,679 规则 / 1,739 关系 / 159 order-dependent / 59 split apex /
  118 碎片注册域 / 24 拓扑约束、无环;MMDB 展开:3,413 关系 / 1,493 order-dependent /
  41 约束。两侧逐项与重排前相等,`--fail-on-shadow` 退出 0;输出差异只有行号引用与
  conf sha256。
- `tests/audit.py` 退出 0,输出与重排前逐字节相同(A1=0 A2=0 A3=29 A4=0 A5=0 A6=7
  A7=0 A8=0 A9=144 A10=59;未豁免 14 条 P0=0/P1=0/P2=11/P3=3,已豁免 62 条)。
  A9 顺序感知口径无漂移。
- `tests/runsuite.py` 227 场景 / 1,644 请求 / **3,099 断言全绿**,DNS 泄漏断言 1,326 条
  0 失败,输出与重排前逐字节相同。
- `rebuild.py --diff-out` diff=0、`collapse_cidr --check` 无漂移、`surge2clash --check`
  一致、`render_surge_rules --check` 一致、`surge-cli --check` OK。

## [2026-09-01·复验] FINAL 漏斗回归纠正 + ProxyGFW 迁移清理

**回归来源**:同日「Deterministic topology」重构把「非安全分裂顶点归零」当成硬指标,
做法是把一批注册域顶点从 `DOMAIN-SUFFIX` 降级为精确 `DOMAIN`。指标确实归零了,
代价是整片子树失去兜底——`appleid.apple.com`、`itunes.apple.com`、
`oss-cn-beijing.aliyuncs.com`、`cos.ap-guangzhou.myqcloud.com`、`api.iqiyi.com`、
`p3-pc.byteimg.com` 等主机不再命中任何规则,直接掉进 FINAL。

**纠正口径**:分裂的危害取决于**顺序**而非**形态**。宽父规则排在**所有**异策略窄子
之后时,首次匹配仍然让每个窄子拿到自己的策略,父规则只为子树其余部分恢复兜底——
这是 ordered-safe split,不是遮蔽。真正要拒的是「宽父在前吃掉窄子」(active shadow)。

### Fixed
- **13 个精确顶点恢复为 `DOMAIN-SUFFIX`**:`apple.com`、`edge.apple`(AppleCN)、
  `aliyuncs.com`(AlibabaCN)、`myqcloud.com`/`smtcdns.com`/`wechat.com`(TencentCN)、
  `byteimg.com`(ByteDanceCN)、`bilivideo.com`/`iqiyi.com`/`smtcdns.net`(ChinaMedia)、
  `hf.co`(AI)、`blizzard.com`(Games)、`1drv.com`(MicrosoftCN)。每一条都逐条核过
  `config/routing.json` 表序:该注册域下全部异策略规则的表序号必须小于目标表,
  一条不满足即不升级。
- **判据未通过、按原样保留的顶点**:`qcloud.com`(ProxyGFW 持后置
  `shortconn.im.qcloud.com`)、`mi.com`(后置 `c.mi.com`)、`naver.com`(Streaming 持后置
  `tv.naver.com`)、`azure.com`(Streaming/DownloadCDN 共 5 条后置异策略子项)。
  这四条连同 `longbridge.cn`、`microsoft.com`、`live.com`、`msn.com`、`office.com`
  由新场景 `funnel_deferred_apexes_unchanged` 锁成回归护栏。
- **`googleapis.com` 整段后缀仍然禁收**:`tests/allowlist.json` 的 forbidden 段把它
  锁死为共享 API/租户命名空间(A8 判 P0 且不可豁免)。改以显式服务端点承接长尾:
  新增 `android` / `fcm` / `play` / `safebrowsing.googleapis.com` 四条;
  `storage.googleapis.com` 因 `ai_ecosystem` 与 `fix_ecosystem_v2` 已锁成 Final,
  本批次不动。
- **`googleusercontent.com` / `ggpht.com` / `steampowered.com` 三个顶点不升级**:
  `google_steam_secondary` 已把 `unknown.*` 子域锁成 Final,升级即推翻已锁裁决。
- **缺失归属补录**:`clients1`–`clients5.google.com`(与在册 `clients6` 同侧)、
  Domestic 的 `googleapis.cn`(Google CN 镜像域,与 `google.cn` 同侧)与
  `sina.com.cn`(注册域而非 PSL 边界,与 `sina.cn`/`sina.com` 同段)。
- **Microsoft FINAL 漏斗补录 9 条**:MicrosoftCN 收 `officeapps.live.com`、
  `office.net`、`outlook.com`、`outlook.office.com`、`windowsupdate.com`、
  `delivery.mp.microsoft.com`;Microsoft 收 `graph`/`teams`/`login.microsoft.com`。
  既有混合形态一条未动——需代理的子域全部已在前置的 Microsoft(10) 或 DownloadCDN(17)
  占位,`odc.officeapps.live.com`、`content.office.net`、`files.1drv.com`、
  `attachments.office.net` 等负例逐条断言。

### Changed
- **ProxyGFW 迁移 47 条**(移动而非复制,目标表不留双份):Longbridge 三条 openapi
  子域经 DNS 实测落境内阿里云 ALB → Domestic;13 个 Google 文档快捷域
  (`deck`/`doc`/`docs`/`form`/`forms`/`presentation`/`sheet`/`sheets`/`site`/`sites`/
  `slides`/`spreadsheet`/`website.new`)302 实测全落 docs/sites.google.com,按
  `meet.new` 先例 → Google(`repo.new`、`whats.new` 非 Google 资产不迁);Aylo 集团
  10 域加 `virtualrealporn.com` → Streaming;德/俄、英、日、美地区面共 20 条 →
  对应地区表(`dw.de`/`dw-world.de`/`deutsche-welle.de` 是国际广播非本地面,保留;
  `amazon.com`/`www.amazon.com` 因 `vendor_family_unification` 已锁 Proxy,保留)。
- **ProxyGFW 清理 170 条**:167 条死域按 A/B/C 三档证据删除并登记
  `config/proxygfw-expired.txt`(766 → 933)——A 档 12 条无 NS、B 档 10 条停放在注册商
  停放 NS、C 档 145 条顶点/`www`/21 个常见子域均无 A 记录;执行前另抽 5 条经
  `dns.google` DoH 复核确认,防探测窗口期误判。另删 `clipfish.de`(301 迁
  `watchbox.de`)与 `prosiben.de`(拼写残留,正确拼写早在 Europe),这两条属服务迁移
  与拼写问题而非 DNS 死亡,**不**登记进 expired 名单。删 `pg2dhpc3p5ec22g3.jkforum.net`
  (抓包生成的一次性 hash 子域),父域 `jkforum.net` 与 `www` 归属不变。
  `avtb` 三条按族聚合排序移到 `avoision.com` 之后。
- **发布闸门口径同步**:`tools/analyze_rules.py` 仍然报告全部非安全分裂,但
  `--fail-on-shadow` 改为只对 `order_unsafe_split_apex` / `order_unsafe_split_parents`
  失败,与 active shadow、expired 回流、GFW IP、PSL 边界四项并列。ordered-safe 条目
  单独列在 `summary.json`,不再一刀切拒。**这使 `topology.json` 的表序约束变成承重
  结构:重排受约束的表对会静默杀死它保护的窄子。**
- **ProxyGFW 契约措辞精化**:多租户条款是**有方向**的——多租户/公共后缀命名空间
  不得归入**单一服务专表**,但被墙平台的整命名空间留在 ProxyGFW 属正确行为
  (残差表不是服务归属表)。当前登记 18 条:`wordpress.com`、`medium.com`、
  `substack.com`、`fc2.com`、`typepad.com`、`over-blog.com`、`weebly.com`、
  `squarespace.com`、`strikingly.com`、`angelfire.com`、`geocities.jp`、
  `geocities.co.jp`、`narod.ru`、`no-ip.com`、`dynamicdns` 族、`mixpanel.com`、
  `bitbucket.org`、`imgur.com`。
- **未决项恢复可见性**:08-31 的 pending_decision 豁免被清除后,Streaming 的 1,983 条
  IP 面与 OneDrive 数据面深归属失去了显式跟踪。两项连同 Microsoft 会话面归一登记进
  `docs/MAINTENANCE.md` 的「Open decisions」节,各自写明「需要什么证据才能重裁」。

### Verified
- 规则总数 141,829 → **141,679**(−150:迁移互相抵消,净减来自 170 条清理与 20 条补录)。
- 语法关系 1,630 → **1,739**(covers 367 → 476,overlaps 1,263 不变);
  顺序依赖例外 80 → **159**;分裂顶点 46 → **59**(46 条安全例外 + 13 条 ordered-safe);
  order-unsafe **0**;碎片注册域 119 → **118**;表序约束 13 → **24**,无环。
- 运行时 MMDB 展开:关系 3,304 → **3,413**(covers 1,750 → 1,859),顺序依赖例外
  1,414 → **1,493**,表序约束 30 → **41**,无环、无 active shadow、无空选择器。
- 场景断言 2,639 → **3,099**(新增 `tests/scenarios/fix_final_funnel.json`,19 个场景
  460 条断言:每条修复一组正例,每个升级顶点一组前置占位负例);DNS 泄漏断言
  1,100 → **1,326**;**既有断言一条未改未删,全部仍通过**。
- 静态审计 A1–A10 exit 0(A4 跨表遮蔽 0 条、A8 禁止回流 0 条;新增的 A3 同表冗余
  均为同策略同族窄条,P2,不达发布阈值);`render_surge_rules.py --check` 确认
  `[Rule]` 段与 manifest 一致、Surge.conf 未改动;`collapse_cidr --check` 无漂移;
  Clash 派生 `--check` 通过。
- 影子复验:49 个目标域名落点全部达成,68 条护栏域名落点逐条不变,回归 0 条。

## [2026-09-01] Deterministic topology and residual-GFW refactor

- Added exhaustive domain/CIDR/ASN/GEOIP relationship analysis with runtime-MMDB
  expansion. Every one of 141,829 source rules is accounted for.
- Final syntax analysis materializes 1,630 relations (367 covers / 1,263
  overlaps) and compactly records 3,579,582 exact keyword/wildcard↔suffix pairs
  in 960 weighted records (21,554 same-policy / 3,558,028 split-policy).
- Final syntax topology has 80 order-dependent exceptions, 119 fragmented domains,
  and 13 constraints. All 46 split apexes are Reject/security exceptions;
  non-security split apexes and general broad parents are zero.
- The final syntax relation classes include 287 redundant coverage relations,
  256 same-policy overlaps, and 1,007 split-policy overlaps.
- The runtime MMDB run reports 3,304 relations (1,750 covers / 1,554 overlaps),
  1,414 order-dependent exceptions, 336 redundant coverage relations, 293
  same-policy overlaps, 1,261 split-policy overlaps, 119 fragmented domains, and
  30 constraints, with no cycles, active conflicts, or empty selectors.
- Added `config/routing.json` as the canonical 39-list topology; Surge rendering,
  ChinaDomain ownership filtering, and Clash generation now consume it.
- Split regional domain, verified service-IP, ChinaIP, and regional GeoIP phases.
  Pinned MMDB verification reduced active shadows/conflicting equivalents to zero.
- Reduced `ProxyGFW` to a domain-only residual: removed 766 expired domains, 37
  public/private-suffix tenant boundaries, shared cloud CIDRs, and service-owned
  rules; added re-entry and structural gates.
- Reclassified Microsoft, LINE/LY, BBC, Pinterest/Discord/social, streaming,
  gaming, and regional service families. Broad mixed-policy parents were removed
  or narrowed; split apexes fell from 200 to 46 Reject/security exceptions, with
  zero non-security split apexes.
- Updated ChinaDomain and ChinaIP regeneration to filter earlier ownership rather
  than allowlisting downstream duplicates. The generalized `split_parent` gate
  covers suffix, wildcard, and keyword parents; 42 residual single-label public
  suffix rules were removed from generated ChinaDomain.
- Pruned obsolete audit narratives and oversized source/list comments; the full
  historical reports remain recoverable from git history.
- `update.sh` now requires the analysis dependency plus readable pinned Country/ASN
  MMDB files, selects the downloaded Country DB when `geoip-maxmind-url` is active,
  and blocks publication unless the full expanded analysis passes.
- Verified 208 scenarios / 1,418 requests / 2,639 assertions / 1,100 DNS-leak
  assertions, static audit, engine/audit self-tests, Surge syntax, pinned rebuild,
  and Clash parity.

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
- **audit A10 · 单标签后缀与 PSL 注册边界**:用**入库的锁定快照**(`tests/data/public_suffix_list.dat` + `tlds-alpha-by-domain.txt`,逐字节固定 sha256)判「这条后缀是不是别人的注册边界」,ICANN 与 PRIVATE 两段均参与,`*.parent` 通配与 `!exception` 按标准算法处理,IDN 两侧做 IDNA 归一。**门禁不联网**:判据必须可复现可 review,快照更新是一次有意的提交而不是运行时下载。该版本的历史基线为 143 条预登记,`TencentCN:in.th` 当时列为待裁决;当前状态以 2026-09-01 的无豁免广父规则门禁为准。两份快照已登记进 `SOURCES.md`。
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
