# 更新记录

本文件遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 风格,倒序排列。

---

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
- **Microsoft.list 独立成表**(commit `39c4025`)—— Copilot / Bing / MSN / 国际登录面共 25 条从 AI 组拆出,与 Google / Twitter / Meta 同走一组。
- **策略组更名** Google-X-Meta → **Google-X-Meta-MS**(commit `d7bd596`),测试断言与工具链同步改名。
- **CDN 配对整理**:国内媒体 CDN(bilibili / iqiyi)归还 DIRECT;NTP 与 captive portal 归 DIRECT;stripe / docker / npm 归属统一;bstar → Streaming;pximg → Japan。DownloadCDN 定位收窄为「大流量批量下载域」,剥离 **533 个**站点静态资源域。
- **地区表自包含并后置**:Japan / UK / Europe / US 的 GEOIP / IP-ASN 规则收进各自表内,整体移到 Apple / 微软 / GFW 之后、国内区之前 —— 修掉了 Apple 17/8 与 ProxyGFW 的 IP 规则被 `GEOIP,US` / `GEOIP,JP` / `GEOIP,DE` 抢先遮蔽的问题。
- LINE 归入 Japan 表。
- 移除 conf 侧的若干 pin 条目,规则归属回到 list 内自洽。

### Removed

- 死规则与冗余清理合计 **-855 条**,其中 TencentCN 的 233 条伪 KEYWORD 规则、以及各处重复 / 被遮蔽 / 过期条目。
- 停止跟踪 `__pycache__`,并加入 `.gitignore`(commits `76c20c7`、`6c6d378`)。

### 影响面

- 本轮结论均已固化进 `tests/` 断言与 `allowlist.json`。**逆向"修复"会直接打红断言** —— 见 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) 的设计裁决记录。

---

## [2026-08-25] blackmatrix7 大合并与发布链建立

**动机**:自建规则覆盖不了国内长尾域名,漏网流量落到 FINAL 走代理,既慢又浪费带宽。引入 blackmatrix7 上游补齐长尾,同时把发布从"手动 push + 等 CDN"变成一条可复现的命令。

### Added

- **国内直连三层格局成形**(commit `9b928b1`):在既有 Domestic 手工层之上,补入 6 个厂商细分表(ChinaMedia / TencentCN / AlibabaCN / ByteDanceCN / BaiduCN / NetEaseCN),再以 ChinaDomain(**约 10.6 万条**)做长尾兜底。
- `update.sh`(commit `70a6ee2`)—— 一条命令完成 push + 逐文件 purge jsDelivr + md5 校验,解决了 CDN 缓存导致"改了但没生效"的老问题。

### 影响面

- 规模从千条级跃到十万条级,肉眼审阅失效 —— 直接催生了同日的审计整改与测试体系。
- ChinaDomain 自此为**机器管理层**,手工条目一律不加(要加就加进 Domestic 或对应厂商细分表)。

---

## [2026-08-25] 初始发布

### Added

- 首次发布 **23 个**去重后的 Surge 规则集(commit `f3d85ea`),确立「每个域名/IP 全链唯一归属」的核心原则。

### Changed

- 国内 AI 厂商域名(Kimi / Qwen / Zhipu / MiniMax / Kling / Coze 国际站等)移入 Domestic 走直连(commit `c853f2c`)—— 该归属在后续审计中被重新裁决:国际站改走代理、`.cn` 域保持直连。
- 生态绑定的 CDN 归还各自服务表(commit `981f0d3`):Angular / googlezip → Google,SteamOS / Epic / Blizzard CDN → Games。

### Removed

- ProxyGFW 中失效的 `googlezip.net` 条目(commit `15df72a`),归属权已属 Google 表 —— 唯一归属原则的第一次落地执行。
