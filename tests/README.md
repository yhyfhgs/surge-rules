# Surge 分流测试套件

给这套规则体系做「仿真实网络环境」的回归测试：改完规则先跑一遍，别等到用着不对劲了才发现。

五个入口，从纯离线到真实客户端，逐层加码：

| 层  | 入口             | 要不要联网 | 回答的问题                                            | 单次耗时 |
| --- | ---------------- | ---------- | ----------------------------------------------------- | -------- |
| L0  | `engine.py`      | 否         | 这个域名会命中哪条规则、走哪个组、从哪个出口出去？    | < 1 秒   |
| L1  | `audit.py`       | 否         | 规则表本身有没有毛病（DNS 泄漏面、重复、遮蔽、失联）？| ~5 秒    |
| L2  | `runsuite.py`    | 否         | 208 个真实使用场景的 1418 条请求，分流结果符合预期吗？ | ~10 秒   |
| L3  | `live_check.py`  | **是**     | 真实网络里实际发生的，跟离线推演的一样吗？出口 IP 对吗？| 1–5 分钟 |
| L4  | `realworld.py`   | 部分       | 真实浏览器/App 发出去会怎样？DNS、WebRTC、TUN、UA 分流真的生效吗？| 3–5 分钟 |

全部 python3 标准库实现，无第三方依赖，macOS 自带的 python3 直接能跑。
L4 额外用到系统自带的 `curl / dig / netstat / scutil / ifconfig / lsof` 与
Surge 自带的 `surge-cli`，同样零第三方依赖。

L3 和 L4 是**两个不同的观测面**，不是替代关系：

- L3 靠 Surge HTTP API 回读「Surge 认为发生了什么」——需要你手工开一次 `http-api`；
- L4 靠真实客户端 + 系统命令 + `surge-cli` 看「机器上实际发生了什么」——**不用改配置**。

---

## 30 秒上手

```bash
cd "/Users/<你>/Library/Application Support/Surge/Profiles/rules/tests"

python3 engine.py match chatgpt.com      # 查单个域名怎么走
python3 audit.py                         # 体检规则表
python3 runsuite.py                      # 跑全部场景断言
python3 realworld.py --offline           # 接管状态 + 与真实 Surge 对账（不发外网请求）
```

前三条不碰网络、不改任何文件，随便跑。`realworld.py --offline` 也不发外网请求，
但需要 Surge 正在跑（它要问 surge-cli）。`live_check.py` 需要先开一次
Surge HTTP API，见下方[开启 Surge HTTP API](#开启-surge-http-api)。

---

## 目录结构

```
rules/tests/
├── engine.py            L0 规则语义引擎（解析 conf + 39 个 list，离线模拟匹配）
├── audit.py             L1 静态审计器（A1–A10 十项检查）
├── runsuite.py          L2 场景断言运行器
├── live_check.py        L3 在线实测（Surge HTTP API + 真实请求）
├── realworld.py         L4 真实客户端 / 网络栈实测（surge-cli + curl + 系统命令）
├── realworld_targets.json  L4 的数据驱动配置（各组代表域 / 客户端画像 / STUN / UA 用例）
├── live_check_local.json   私有出口映射覆盖档（**已 gitignore**，勿入库；见下）
├── allowlist.json       审计豁免表（把「刻意设计」标出来，免得每次都报）
├── scenarios/           场景数据集，26 个 .json，共 208 场景 / 1418 请求
│   ├── ai_overseas.json      海外独立 AI（OpenAI / Anthropic / Perplexity …）
│   ├── ai_ecosystem.json     大厂 AI 生态一致性（Gemini / Copilot / Grok …）
│   ├── ai_domestic.json      国内 AI 直连（DeepSeek / Kimi / 通义 …）
│   ├── cn_intl.json          国内厂商国际站（Coze / Trae / TikTok …）
│   ├── cn_ecosystem.json     国内大厂全家桶（微信 / 淘宝 / B站 …）
│   ├── intl_services.json    国际非 AI（GitHub / Netflix / Steam …）
│   ├── cdn_pairing.json      主站与 CDN 配对一致性
│   ├── edge_cases.json       边界（OCSP / NTP / captive / 纯 IP / 遥测域）
│   ├── reject_layer.json     Reject 拦截层（广告投放 / HTTPDNS / 钓鱼恶意，及刻意放行的埋点域）
│   ├── ownership_fix.json    2026-08-31 审计整改：归属修正与关键词边界化的正/负例断言
│   ├── download_cleanup.json DownloadCDN 收窄：剥离的站点静态域落回主站所在组
│   ├── region_coverage.json  地区表（Japan / UK / Europe / US）与 NetEaseCN 的正负覆盖
│   ├── kw_direct.json        关键词边界化后的直连面回归
│   ├── kw_ecosystem.json     关键词边界化后的生态归属回归
│   ├── kw_media.json         关键词边界化后的媒体面回归（含 BBC 播放面归属边界）
│   ├── payment_chain.json    支付链路同出口（风控 / 3DS / 拒付）
│   ├── ipv6_parity.json      IPv4 / IPv6 双栈落点一致性，每条带 no_dns_leak
│   ├── fix_download_v2.json  2026-08-31 修复批次：下载面（HF / S3 族 / 多租户后缀）正负例
│   ├── fix_domestic_v2.json  同批次：国内直连面
│   ├── fix_ecosystem_v2.json 同批次：生态归属面
│   ├── fix_regions_v2.json   同批次：地区表面
│   └── dns_leak.json         DNS 泄漏专项
├── expected_asn.json     可选，给 live_check --exit-map 做 ASN 断言（默认没有 = 只报告）
└── README.md             本文件
```

`rules/` 目录是 git 仓库并且会被 jsDelivr 分发，**测试产出的报告不要写进 `rules/`**，
用 `--out` 指到别处，例如 `~/Desktop/surge-audit/`。

`live_check.py` 会 import `engine.py`（比起每个域名开一个子进程，快得多），
所以运行后会在 `tests/` 下留一个 `__pycache__/`。建议在仓库的 `.gitignore` 里加上：

```gitignore
tests/__pycache__/
tests/live_report.md
tests/live_check_local.json
```

**私有节点信息一律外置。** `tests/` 会随公开仓库分发，所以真实策略组名、节点名、
出口 IP、线路商与机房标识、自家线路的 ASN 都不许写进任何会入库的文件。代码里只留
**中性占位默认值**（`美国家宽A` / `US-HOME-A` / `ISP-A` / `DC-X` / 私有段 ASN `64500`…），
真实映射放本地私有覆盖档，运行时覆盖合并。报告要贴给别人看就加 `realworld.py --redact`
（节点名折叠成 `🇺🇸<节点:US-HOME-A>`，IP 尾段打码）。

覆盖档 `engine.py` 与 `live_check.py` 共用，schema 与查找顺序一致：

```json
{
  "exit_class_exact":    {"<策略组或叶子出口组名>": "<exit_class>"},
  "exit_class_keywords": [["<物理节点名关键字>", "<exit_class>"]],
  "asn_map":             {"<ASN>": "<注释>"},
  "residential_hints":   ["<RDAP 机构/网段名关键字>"],
  "datacenter_hints":    ["<RDAP 机构/网段名关键字>"]
}
```

查找顺序取**第一个存在的文件**（不叠加）：

1. 环境变量 `LIVE_CHECK_LOCAL` 指定的路径；
2. `<repo>/../rules-local/live_check_local.json` —— 推荐，整个目录都在仓库外；
3. `<repo>/tests/live_check_local.json` —— 旧路径，靠 `.gitignore` 兜底。

文件缺失不报错，全部走中性默认值：`engine.py` 自检里针对真实 conf 的出口画像断言
（R03–R05）会自动标记为 skipped，`live_check.py` 的启发式归类退化到国旗兜底。

---

## L0 `engine.py` —— 规则语义引擎

离线复刻 Surge 的匹配语义：读 `Surge.conf` 的 `[Rule]`，把每条 `RULE-SET` 的远程 URL
按文件名映射回本地 `rules/lists/*.list` 内联展开，然后按顺序做首次命中匹配。
（默认规则目录 = `Surge.conf` 同级的 `rules/lists/`；用 `--rules` 可指到别处。）

```bash
python3 engine.py match chatgpt.com                  # 人读输出
python3 engine.py match chatgpt.com --json           # 机器可读
python3 engine.py match claude.ai --process Claude   # 带进程名
python3 engine.py match 1.1.1.1                      # 纯 IP 查询
python3 engine.py dump-index                         # 导出展开后的全规则表
python3 engine.py --selftest                         # 内置自检（65 条手工断言）
```

输出字段：

| 字段              | 含义                                                        |
| ----------------- | ----------------------------------------------------------- |
| `matched_rule`    | 命中的那条规则原文                                          |
| `rule_index`      | 它在展开后全表里的位置（数字越小优先级越高）                |
| `source`          | 来自哪个 .list                                              |
| `policy`          | 命中的策略组（`DIRECT` / `REJECT` 也算）                    |
| `physical_exit`   | 递归解析策略组默认首项后的物理节点                          |
| `exit_class`      | 出口归类，用来判断「两个请求是不是同一个出口」              |
| `dns_leak`        | 命中之前是否途经过**不带 no-resolve 的 IP 类规则**          |
| `dns_leak_at`     | 是哪一条                                                    |

`exit_class` 取值：`US-HOME-A` / `US-HOME-B` / `US-DC` / `JP-HOME` / `JP-DC` /
`EU` / `DIRECT` / `REJECT`（取值集合是共享契约；哪个策略组算哪一类，由本地私有
覆盖档的 `exit_class_exact` 提供，见上文「私有节点信息一律外置」）。

**注意引擎的两个前提**，看结果时要记着：

1. 策略组一律按**成员首项**推演。你在 Surge 里手动切过节点的话，离线结论跟实际会不一样
   —— 用 `live_check.py --policies` 一眼看出哪些组被切过。
2. `IP-ASN` / `GEOIP` 是离线近似（`GEOIP,CN` 用 `ChinaIP.list` 近似，ASN 用一张内置小表），
   代码里已注明。纯 IP 查询的结论要以在线为准。

---

## L1 `audit.py` —— 静态审计器

不看场景，只审规则表本身。

```bash
python3 audit.py                                  # 终端摘要
python3 audit.py --out ~/Desktop/surge-audit      # 同时写 report.md / findings.jsonl / *.tsv
python3 audit.py --check A1,A4                    # 只跑指定检查项
python3 audit.py --fail-on P0                     # 只有 P0 才算失败（默认 P1）
python3 audit.py --selftest                       # 用植入已知缺陷的合成配置自检（51 条）
```

十项检查：

| 编号 | 查什么                                   | 为什么重要                                       |
| ---- | ---------------------------------------- | ------------------------------------------------ |
| A1   | IP 类规则缺 `no-resolve`                 | 直接对应 DNS 泄漏，本体系的头号红线              |
| A2   | 跨 list 精确重复                         | 后出现的那条是死条目                             |
| A3   | 同 list 内部覆盖                         | `DOMAIN` 被同表 `SUFFIX` 吃掉之类                |
| A4   | 跨 list 遮蔽                             | 尤其「直连区条目被代理区抢跑」= P0               |
| A5   | conf 引用完整性                          | 引用了不存在的 list，或有 list 没人引用          |
| A6   | `DOMAIN-KEYWORD` 清单                    | 只列出来给人复核，不判对错                       |
| A7   | 规则行格式 lint                          | 无类型前缀的裸行会被静默忽略 = 死规则，判 P1     |
| A8   | 禁止回流                                 | `forbidden` 段登记的模式一出现即 P0，**不可豁免** |
| A9   | IP 跨表包含 / 遮蔽                       | 按 conf 真实序判「后位 CIDR 被前位覆盖」；同策略 P3，**跨策略 P1** |
| A10  | 单标签后缀与 PSL 注册边界                | 用入库的 PSL + IANA 快照判「这条后缀是不是别人的注册边界」，离线不联网 |

严重度：P0 功能损坏或明确错误分流 / P1 IP 一致性与 DNS 泄漏风险 / P2 冗余遮蔽但无直接伤害 /
P3 风格建议。

### `allowlist.json`

两段结构：`exemptions` 登记「允许存在的刻意设计」，按 `(check, file, rule)` 三元组匹配；
`forbidden` 登记「必须持续不存在的规则模式」，由 A8 扫源文件强制。两段每条都**必须**写 `reason`：

```json
{
  "version": 1,
  "exemptions": [
    {
      "check": ["A2", "A3", "A4"],
      "file": "Google.list",
      "by_file": "YouTube.list",
      "preventive": true,
      "reason": "YouTube 专属资产由前位 YouTube.list 认领"
    }
  ],
  "forbidden": [
    {
      "pattern": "USER-AGENT,*",
      "reason": "D7 裁决：全库零 USER-AGENT——全域生效会跨境错分流，且 Clash 派生剔除该类型造成双端分叉"
    }
  ]
}
```

- `check` 可以是字符串或数组，省略表示所有检查项。
- `file` / `rule` 支持 `*` `?` 通配；还可以用 `by` / `by_file` 指定「遮蔽方」来缩小豁免面。
- `preventive: true` 表示这是防回归条目 —— 当前配置本来就不该命中它，没命中不会被算成
  「无用豁免」。
- `forbidden` 段**不吃豁免**：命中即 P0，`exemptions` 里写什么都盖不住它。

`exemptions` 只登记仍然允许存在的精确裁决，例如大厂自有 AI 归各自生态、
已验证的下载/组件分界与上游回流降噪。ProxyGFW 的宽云后缀与 PSL 边界
不再整表豁免；它们必须保持不存在。

`forbidden` 覆盖四类：
① `USER-AGENT` / `PROCESS-NAME` / `URL-REGEX` 三类**全类型**禁令（D7）；
② D11 上游合并排除项（`DOMAIN-KEYWORD,google`、`akadns.net`、`ms` ccTLD 等）；
③ 历次审计删掉的品牌关键词（paypal、ChinaDomain 尾部 9 条、OneDrive 精确后缀恢复后的
   `1drv` / `onedrive` / `skydrive` 等）；
④ 多租户托管 / 对象存储平台的宽后缀签名（github.io / vercel.app / pages.dev /
   cloudfront.net / `s3.*.amazonaws.com` 等）——**签名必须锚定注册域**，例如 S3 族写成
   `s3.*.amazonaws.com` / `s3-*.amazonaws.com` 而不是 `s3*`，否则会误伤 32 条第一方
   `s3.<brand>` host。

> **两段的条数刻意不写进正文。** 它们是每轮审计都会增长的量，写死就是下一处文档漂移
> ——历史教训：本段一度把 `forbidden` 写成两位数，而实际已是三位数，差了近 7 倍。
> 当轮数字见 `CHANGELOG.md`，真值以 `tests/allowlist.json` 为准，由 audit 的文档漂移
> 检查直接读取比对。

---

## L2 `runsuite.py` —— 场景断言运行器

场景 = 一次自然的用户行为所触发的整组域名（主站 + API + CDN 静态资源 + 登录风控 + 遥测）。
判的不是「单个域名走哪」，而是「这一整套操作会不会被拆到不同出口上」。

```bash
python3 runsuite.py                          # 跑全部
python3 runsuite.py --filter openai          # 只跑名字/文件名含 openai 的
python3 runsuite.py --json                   # 机器可读
python3 runsuite.py --list-known-broken      # 只列当前的待修清单
```

场景格式：

```json
{
  "name": "openai_chatgpt_web",
  "desc": "网页版 ChatGPT 登录并对话+上传图片",
  "requests": [
    {"host": "chatgpt.com"}, {"host": "auth.openai.com"},
    {"host": "cdn.oaistatic.com"}, {"host": "files.oaiusercontent.com"}
  ],
  "assert": {"same_policy": true, "policy": "AI", "no_dns_leak": true}
}
```

断言字段：

- `same_policy` —— 会话内所有请求必须落在同一策略组
- `policy` —— 期望的组名
- `policy_in` —— 允许是其中之一
- `per_request` —— 给个别请求单独定期望
- `no_dns_leak` —— 匹配路径上不得触发本地 DNS 解析

### `known_broken` 是什么

标了 `"known_broken": true` 的场景，是**当前规则下确实过不了、但已经知道原因**的。
runsuite 会把它们单独统计成「待修清单」而不是测试失败——这样 CI 才有绿灯可言，
同时待办也不会被忘掉。修好一条就把标记删掉。

当前基线：208 场景 / 1418 请求 / 2639 断言，失败 0，已知待修 0 条；
1100 条 DNS 泄漏断言全通过。
（L4 的 `realworld.py --dns` 已用实网抽样二次确认，见下文）。

---

## L3 `live_check.py` —— 在线实测

前面三层都是「按规则文本推演」。这一层去看**真实网络里实际发生了什么**：通过 Surge
本地代理发真请求，再从 Surge HTTP API 把这些请求的实际策略、实际命中规则、实际出口读回来。

> **判定原则：在线为准。** 在线跟离线打架时，是离线引擎或规则需要改，不是反过来。

```bash
export SURGE_API_KEY=surgetest          # 先把 Key 给它，见下一节

python3 live_check.py --check-api       # 1. API 通不通
python3 live_check.py --policies        # 2. 策略组当前选中项 vs 引擎假设
python3 live_check.py --scenario all    # 3. 场景实测（真发请求）
python3 live_check.py --exit-map        # 4. 出口画像：组 → 出口 IP → ASN → 住宅/机房
python3 live_check.py --dns-leak        # 5. DNS 泄漏实锤
python3 live_check.py --full            # 2→5 全跑并生成 live_report.md
```

### 各子命令在做什么

**`--check-api`** 探测 `/v1/outbound` 等只读端点。不通就打印开启指引并以退出码 2 结束
（连接被拒 / Key 不对 / 超时会分别给不同提示）。**任何其它子命令都会先做这一步**，
因为 API 不通就无所谓「在线为准」了。

**`--policies`** 列出每个策略组当前实际选中的成员，和离线引擎的假设（成员首项）对比。
关键在于它会区分两种不一致：

- `select` 组不一致 → 标 ★ 告警，说明**你手动切过节点**，离线结论此刻不适用；
- `smart` / `url-test` / `fallback` 组不一致 → 标「自动选路(非问题)」，Surge 动态择优而已。

**`--scenario <file|all>`** 对场景里每个域名发一次真实 HEAD（失败退回 GET），限速每秒 ≤3、
超时 8 秒；然后拉 `/v1/requests/recent` 找回这些请求，取出实际 `policyName`、命中规则、
远端地址，跟场景期望和离线引擎三方对照。也可以不用场景文件临时点名：

```bash
python3 live_check.py --scenario --hosts chatgpt.com,claude.ai,api.anthropic.com
```

结果状态：`PASS` / `FAIL` / `KNOWN_BROKEN` / `UNREACHABLE`（网络层没打通，不算断言失败）/
`NOT_FOUND`（请求发出去了但 recent 里没找到记录）/ `SKIPPED`（内网、回环地址，在线不实测，
离线层已经覆盖）。如果一次跑下来**一条都没判定成**，会直接报错退出 1 —— 什么都没量到
却显示「全部通过」是最坑人的假绿灯。

场景里用 `{"ip": "8.8.8.8"}` 写的纯 IP 请求同样支持，`per_request` 里也可以用 `ip` 作键。

**`--exit-map`** 给每个策略组画出口像。每组用一个**本身就命中该组规则**的探针域名
（否则量的就不是这个组），拿回显 IP 后走 Surge 查 RDAP 标注机构与网段：

| 组            | 探针                                        | 靠哪条规则落到该组                    |
| ------------- | ------------------------------------------- | ------------------------------------- |
| AI            | `chatgpt.com` / `claude.ai` 的 `/cdn-cgi/trace` | AI.list                            |
| Google-X-Meta | `x.com/cdn-cgi/trace`                       | Twitter.list（x.com 已在 Cloudflare 后）|
| 社交媒体      | 无可用回显端点，只做归属验证                | SocialOthers.list                     |
| 流媒体        | `api.fast.com`（v2 端点自带 ASN）           | Streaming.list: `fast.com`            |
| 🇯🇵日本节点    | `www.pixiv.net/cdn-cgi/trace`               | Japan.list: `pixiv.net`               |
| DIRECT        | `myip.ipip.net`、`connect.rom.miui.com`     | Domestic.list                         |
| Final         | `icanhazip.com`                             | 不在任何 list → FINAL                 |

除了实测，它还会从配置**推导**一遍出口 IP：本配置是 snell 级联（家宽节点用
`underlying-proxy` 经落地机房中转），真正面向互联网的那一跳就是家宽节点自己的 server 地址。
实测已验证三条链路的推导值与回显值完全一致。两列并排，就能一眼看出链路有没有降级；
没有回显端点的组（比如社交媒体）也能靠推导补上出口 IP。

要断言 ASN 就建 `expected_asn.json`（没有这个文件时只报告不断言）：

```json
{
  "AI":            ["64500"],
  "Google-X-Meta": ["64501"],
  "社交媒体":       ["64502"]
}
```

（示例里用的是 RFC 5398 私有段 ASN 占位：`64500` = 家宽线路商 ISP-A，`64501` = ISP-B，
`64502` = 落地机房 DC-X。填自己真实的 ASN 即可 —— 真实 ASN 能反查线路商，
所以 `expected_asn.json` 建议一并加进 `.gitignore`。）

**`--dns-leak`** 先 `POST /v1/dns/flush` 清本地 DNS 缓存，再依次访问 `dns_leak.json` 里的
代理域名，然后读 `/v1/dns`：这些域名**不该**出现在本地解析记录里，出现了就是 P1 实锤；
同时直连域名**应该**出现。不想让它清缓存就加 `--no-flush`（代价是历史记录容易造成误报）。

**`--full`** 按 2→5 顺序跑完并写出 `live_report.md`（控制台全文 + 机器可读 JSON）。

### 常用参数

| 参数                    | 说明                                                       |
| ----------------------- | ---------------------------------------------------------- |
| `--key` / `SURGE_API_KEY` | API Key。建议走环境变量，别写进命令行历史                |
| `--api`                 | API 地址，默认 `http://127.0.0.1:6171`                     |
| `--proxy-port`          | Surge HTTP 代理端口。默认先读配置的 `http-listen`，再探测 6152 |
| `--scenarios-dir`       | 换一个场景目录                                             |
| `--timeout` / `--rate`  | 单请求超时（默认 8 秒）/ 每秒请求数上限（默认 3）          |
| `--report`              | 报告输出路径                                               |
| `--json`                | stdout 只输出 JSON（人读信息全部静音）                     |
| `--dump-raw DIR`        | 把 API 原始响应存下来，Surge 换版本改字段名时用来排查      |
| `--no-flush`            | 不清 DNS 缓存，全程零写操作                                |

### 安全边界

- 除了 `POST /v1/dns/flush`（清本地 DNS 缓存，可用 `--no-flush` 关掉），**只读 API**，
  不切策略、不改配置、不重载 profile。
- 从不读取或打印 psk、ca-p12 等敏感字段；解析配置文本时只取节点的服务器地址。
- 对外只发普通 HTTPS GET/HEAD。
- 不会修改 `Surge.conf` 或 `rules/` 下任何文件。

---

## L4 `realworld.py` —— 真实客户端与网络栈实测

L3 问的是「Surge 认为发生了什么」。L4 换一个观测面：**用真实客户端画像发请求、用系统
自带命令看网络栈、用 `surge-cli` 直接问 Surge 本人**，回答 L0–L3 都回答不了的六类问题。

它**不需要 `http-api`** —— `surge-cli` 走的是本机控制通道，不用改任何配置。

```bash
python3 realworld.py --tun          # 接管状态：utun / 默认路由 / 系统 DNS / hijack
python3 realworld.py --dns          # DNS 深测：hijack 生效性 / fake-IP / canary / SVCB / DoH / 泄漏抽样
python3 realworld.py --webrtc       # WebRTC：最小 STUN 客户端取 srflx 公网 IP 比对
python3 realworld.py --clients      # 真实客户端画像 × 各策略组代表域
python3 realworld.py --crosscheck   # surge-cli 实测语义 vs engine.py 离线推演，逐条对账
python3 realworld.py --ua-routing   # UA 分流生效性（四格通道矩阵）
python3 realworld.py --offline      # 只跑不需要外网的部分（--tun --crosscheck --ua-routing）
python3 realworld.py --full --report ~/Desktop/surge-audit/realworld.md
python3 realworld.py --list-targets # 只打印数据配置并复核归属，一个外部请求都不发
```

### 各子命令在做什么

**`--tun` 接管状态。** `ifconfig` 枚举 utun 接口、`netstat -rn` 看 v4/v6 默认路由指向、
`scutil --dns` 看系统 DNS 指到哪、`scutil --proxy` + `lsof` 看系统代理与监听端口、
`surge-cli status` 看出站模式与 features。硬断言三条：**出站模式必须是 `rule`**、
**IPv4 默认路由必须指向 utun**、**系统 DNS 必须指向 Surge 的响应器**
（macOS 是 `198.18.0.2`，见 `reference/surge-docs/dns/advanced.md`）。任何一条不成立，
后面所有分流结论都不作数 —— 所以这一节应该第一个跑。

**`--dns` DNS 深测。** 四件事：

1. **hijack-dns 生效性**：`dig @8.8.8.8 / @1.1.1.1 / @9.9.9.9` 查普通域名，
   应答必须落在 fake-IP 池 `198.18.0.0/15` 里。返回真实 IP 就说明那条 DNS 查询绕过了
   Surge，对应的域名对 Surge 不可见（分流从源头就失效）。
2. **响应器行为**：canary 域 `use-application-dns.net` 必须被答成 `NXDOMAIN`
   （Firefox 靠它关掉内置 DoH）；SVCB/HTTPS（TYPE65）在 `allow-dns-svcb` 默认关闭时
   必须是 `NOTIMP`（放行的话 HTTPS 记录里的 IP hints 会绕过 fake-IP 机制）。
3. **DoH 可用性**：对 conf 里每个 `encrypted-dns-server` 发一次 RFC 8484 GET
   （标准库自己拼线格式 DNS 报文，不经代理），核 HTTP 状态 + rcode + 记录数；
   再用 `surge-cli dns lookup` 看 **Surge 自己实际用的是哪个上游**，回落到明文 UDP 53
   会被标出来。
4. **本地 DNS 泄漏 live 抽样**：`surge-cli dump dns` 取快照 → 真实访问样本域 → 再取快照，
   **只看新增条目**。代理域名新增 = P1 实锤泄漏；直连域名新增 = 符合预期。
   只看增量就不用 flush，**全程零写操作**；快照前就存在的条目单列「无法判定」，
   既不算通过也不算泄漏。

**`--webrtc` WebRTC 泄漏。** 标准库实现的最小 STUN 客户端（RFC 5389 Binding Request /
XOR-MAPPED-ADDRESS，UDP），向数据配置里的公共 STUN 服务器取 server-reflexive 地址 ——
那正是 WebRTC 会写进 ICE candidate、对端能看到的公网 IP。判定基准不写死任何 IP：
配置里 `baseline: true` 的那台 STUN **必须落 DIRECT**，它回显的就是本机真实出口，
其余各组的 srflx 与它比。

- srflx == 本机真实出口，而该域命中的是代理组 → **泄漏（硬失败）**；
- srflx ≠ 本机真实出口 → 通过，并顺带和该组的 HTTP 出口 IP 对账（同 IP / 不同 IP 都会标出来）；
- **超时无应答**：结合 conf 的 `udp-policy-not-supported-behaviour` 解释 ——
  取值是 `REJECT` 时，策略不支持 UDP 就直接拒绝、不回落直连，所以**无应答等于零泄漏**，
  不算失败；如果这个值不是 REJECT，程序会警告：UDP 会回落直连，STUN 将直接暴露真实出口。
- 还会看 UDP 应答的来源地址：应该是 `198.18.0.0/15` 的 fake IP（说明这条流被 TUN 接管了），
  直接看到真实 IP 就是绕过。

**`--clients` 真实客户端模拟。** 用 `curl` 拼真实 UA / HTTP 版本 / Accept 头组合，模拟
Safari、Chrome、iOS 网页、iOS 原生 App、ChatGPT 客户端、Claude 桌面端、Telegram 等画像，
访问每个策略组的 2–3 个代表域。四类判定：

| 判定       | 怎么做                                                     | 级别 |
| ---------- | ---------------------------------------------------------- | ---- |
| UA 副作用  | 画像 UA 不能意外命中 `USER-AGENT` 规则，否则量到的落点是假的 | 提示 |
| 归属复核   | `surge-cli rule explain` 复核代表域确实落在声明的组里       | 硬失败 |
| 连通性     | 真实请求能不能打通（UNREACHABLE 不算分流错误）             | 仅报告 |
| 出口落点   | 有回显端点的组取出口 IP；代理组的出口**必须不等于**本机真实出口 | 硬失败 |

另外每组会用 `surge-cli http probe` 发一次真实 HEAD，把 Surge 自己回读的落点
（物理节点 + Cloudflare colo 代码）并排放在表里；再用一张「UA 端到端到达矩阵」
（`chatgpt.com/cdn-cgi/trace` 会回显 `uag=`）确认每个画像的 UA 原样到了源站没被改写。

> 画像里的 `Accept-Encoding` 会被换成 `curl --compressed` 自行协商 —— macOS 自带的
> libcurl 不会解 brotli，原样发出去只能拿到一坨没法解析的压缩正文。内容编码不参与
> 任何分流判定，所以这个替换是安全的。

**`--crosscheck` 分流落点交叉验证。** 这是**抓离线引擎与真实 Surge 语义差异的关键测试**：
把 `scenarios/*.json` 的请求摊平去重，逐条同时问 `surge-cli rule explain`（不建立连接）
和离线 `engine.py`，对账两件事 —— 策略组、命中的 list。

- 域名类查询不一致 → **硬失败**（域名语义两边都能精确实现，不一致就是引擎 bug）；
- 纯 IP 查询不一致 → 默认只提示（`GEOIP` 非 CN / `IP-ASN` 在离线层是**显式声明的近似**），
  `--strict` 可以把它升成硬失败；
- 命中表不一致（策略组相同、命中的 list 不同）→ 提示，多数是级联去重的自然结果。

顺带还做一件事：比对期间对 Surge 的 DNS 缓存取前后快照，**规则评估本身不应触发任何本地
解析**（全表 IP 类规则都带 `no-resolve`），有新增就说明哪里漏了 `no-resolve`。

**`--ua-routing` UA 分流生效性。** `USER-AGENT` 规则只在「Surge 的 HTTP 引擎能读到 UA」
时生效（`reference/surge-docs/rules/http.md`）。能不能读到取决于请求走哪条通道，
所以本节按**四格矩阵**逐格实测：

| 通道          | 路径          | 协议  | Surge 能否读到 UA | 为什么                                    |
| ------------- | ------------- | ----- | ----------------- | ----------------------------------------- |
| `proxy_https` | Surge HTTP 代理 | HTTPS | **可以**          | UA 出现在 `CONNECT` 请求头里，不解密也可见 |
| `proxy_http`  | Surge HTTP 代理 | HTTP  | **可以**          | HTTP 引擎直接读到                          |
| `tun_http`    | 绕开代理走 TUN  | HTTP  | **可以**          | 明文 HTTP 仍由 HTTP 引擎处理               |
| `tun_https`   | 绕开代理走 TUN  | HTTPS | 需 MITM           | 只有 SNI，UA 不可见 —— **未启用时自动跳过** |

每条用例跑两层：

- **规则层**：`surge-cli rule explain <域> user-agent=<UA>` 与不带 UA 的基线对比，
  断言策略组/命中表符合预期。不建立连接、不需要外网，**随时可跑**。
- **线路层**：真的发两次请求（带 UA / 基线 UA），比对回显的出口 IP。
  只有当两个落点的**物理出口本来就不同**时才做 IP 层断言，否则标「区分不出」——
  避免拿一个证明不了任何事的断言充数。

`tun_https` 这一格是**给 MITM 预留的骨架**：程序读 conf 的 `[MITM] hostname`，
未启用或没覆盖该域就打 SKIP 并说明原因；一旦把该域加进 `hostname`，这一格会自动开始断言。
同时会检查 conf 自己写下的那条红线：**启用 `hostname` 时 `auto-quic-block` 必须是 `true`**，
否则命中域的 HTTP/3 会绕过 MITM 形成半解密。

### 数据驱动配置 `realworld_targets.json`

改测什么不用改代码，全在这个文件里：

| 段            | 内容                                                             |
| ------------- | ---------------------------------------------------------------- |
| `clients`     | 客户端画像：`ua` / `http`（1.1 或 2）/ `headers`                  |
| `groups`      | 每个策略组的 2–3 个代表域 + 该组要用哪些画像                       |
| `stun`        | STUN 服务器；`baseline: true` 的那台必须落 DIRECT                  |
| `dns`         | hijack 探测用的 DNS 服务器与域名、canary、SVCB 探测域、泄漏抽样样本 |
| `ua_routing`  | UA 用例：宿主域 + UA + 期望落点 + 基线落点 + 对应的规则出处        |

`groups[].hosts` 的选取标准只有一条：**这个域名本身必须命中该策略组的规则**，否则量到的
不是这个组的出口。程序每轮都会用 `surge-cli` 复核归属，域名换了组会直接报失败 ——
所以这张表是**自校验**的，不用担心它悄悄过期。`echo` 字段声明 IP 回显端点的解析方式
（`cf_trace` / `fast_json` / `ipip` / `plain_ip` / `null`），取值与 `live_check.py` 通用。

### 常用参数

| 参数              | 说明                                                                 |
| ----------------- | -------------------------------------------------------------------- |
| `--via`           | 真实请求走哪条通道：`auto`（沿用环境变量/系统代理，即真实 App 的行为，默认）/ `proxy` / `tun` |
| `--redact`        | 遮蔽节点名与出口 IP 尾段，方便把报告贴到公开处                        |
| `--strict`        | 把纯 IP 查询的离线/在线差异也升级为硬失败                             |
| `--filter`        | 只跑名字含该子串的策略组 / 场景                                       |
| `--limit`         | `--crosscheck` 最多跑多少条查询                                       |
| `--targets`       | 换一个数据配置文件                                                    |
| `--surge-cli`     | surge-cli 不在默认路径时指过去                                        |
| `--timeout` / `--rate` | 单请求超时（默认 10 秒）/ 每秒请求数上限（默认 3）               |
| `--report`        | 报告输出路径（markdown，含控制台全文 + 断言明细 + 机器可读 JSON）     |
| `--json`          | stdout 只输出 JSON                                                    |

### 安全边界

- **纯只读**：不改任何系统状态、不 reload Surge、不 flush DNS、不切策略、不写配置。
  `surge-cli` 只用 `status` / `rule explain` / `http probe` / `dump dns` / `dns lookup`
  这几个不改状态的读命令。
- **外发最小化**：只访问 `realworld_targets.json` 里登记的公共探测端点与被测域，
  普通 GET/HEAD，不携带任何本机标识，默认限速 3 req/s。
  `--offline` / `--list-targets` 一个外部请求都不发。
- **不打印敏感字段**：从不读取或输出 psk、ca-p12；`--redact` 还能把节点名与出口 IP 一起打码。
- **`--dns` 里唯一一次主动解析**用的是直连域（本地解析对它本就是期望行为），不会污染判定面。

---

## 开启 Surge HTTP API

只有 L3 需要。**程序不会替你改配置，请手工加这一行。**

1. 编辑 `Surge.conf`，在 `[General]` 段加：

   ```ini
   http-api = surgetest@127.0.0.1:6171
   ```

   格式是 `http-api = <Key>@<监听地址>:<端口>`。Key 自己取，只在本机用。

   > 监听地址务必写 `127.0.0.1`。写成 `0.0.0.0` 等于把 Surge 的控制权交给整个局域网。
   > `http-api-tls` 和 `http-api-web-dashboard` 本套件都用不到，不用开。

2. Surge Dashboard 右上角「重载配置」（或菜单栏图标 → Reload Profile）。

3. 把 Key 交给程序：

   ```bash
   export SURGE_API_KEY=surgetest
   python3 live_check.py --check-api
   ```

排查：

- **连接被拒绝** → 配置没生效。确认已重载，然后 `lsof -nP -iTCP:6171 -sTCP:LISTEN` 看端口。
- **401 / 403** → Key 跟配置里的对不上（区分大小写）。
- **端口被占用** → 换一个（如 6172），同时 `--api http://127.0.0.1:6172`。
- **出站模式不是 rule** → 全局直连/全局代理下所有分流断言都不成立，先切回规则模式。

---

## 常见误报 —— 这些不是 bug

按被误会的频率排序。

**1. 「策略组当前选中项与测试假设不一致」**
你自己在 Surge 里切过节点而已。离线三层永远按成员首项推演，所以想让离线结论完全对得上，
要么把组切回首项，要么以 `live_check --policies` 的输出为准。`smart` 组的漂移更是常态，
程序已经区分开了。

**2. 在线策略显示的是节点名而不是组名**
`/v1/requests/recent` 里的 `policyName` 通常是链路末端的物理节点（如 `🇺🇸<ISP>-<机房>-LAX`），
不是 `AI`。程序会从 notes 里还原完整链路，还原不出来时退一步比 `exit_class`。
表里写成 `AI→🇺🇸<末端节点名>` 就是还原成功了。

**3. `UNREACHABLE` / `NOT_FOUND` 不等于分流错了**
`UNREACHABLE` 是 TCP/TLS 没打通：站点被墙、证书问题、拒绝 HEAD、CDN 挡爬虫都算。
`NOT_FOUND` 是请求发出去了但 recent 里没找到——连接复用、请求合并都会这样。
两者都不计为断言失败。但如果**大面积**出现，程序会警告：这次跑的覆盖率不够，结论别当真。

**4. DNS 泄漏结果需要 flush 之后立刻看**
本地 DNS 缓存是全机共享的，浏览器 DoH 旁路、Spotlight、后台服务都会往里写。
所以 `--dns-leak` 必须紧跟 flush 跑。程序对「flush 之前就已经存在的记录」单列成
「? 无法判定」，既不当通过也不当泄漏——隔一会儿重跑一次通常就清楚了。

**5. 直连域名没出现在本地 DNS**
标成「? 待查」不是错误。系统缓存命中、走了 DoH、或者这次压根没触发解析，都会这样。
真正要盯的是反过来的情况：代理域名出现在本地 DNS 里。

**6. `--exit-map` 的 ASN 列是空的**
ARIN 的 RDAP 对家宽客户网段经常不返回 ASN（`originAS` 为空），机构名写成 `Private Customer`。
这时候看**网段名**：形如 `<ISP>-NET-<段号>` 的网段名一样能确认归属。空 ASN 不代表异常。

**7. 「实测≠推导」**
两种可能：链路降级了（家宽那一跳没走通，退回落地机房出口），或者中转商改写了出口。
值得人工看一眼，但不是程序的问题。另外 CDN 出口 IP 本身会随时间漂，两次跑结果不同很正常。

**8. `known_broken` 的场景「失败」了**
那是待修清单，不是测试失败。`runsuite.py --list-known-broken` 能单独列出来。
反过来，如果一个 `known_broken` 场景突然通过了，说明问题已经修好，把标记删掉。

**9. 主站与资源面分属不同组**
这不再是默认架构取舍。只有已证明与源 IP / cookie 无关的大文件端点才能脱离
服务 owner；其余登录、API、静态与 CDN 伴生面应先保持同会话归属。

**10. 这些是刻意设计，审计和场景都别报**

- YouTube 全量归流媒体组、且排在 Google 之前 —— 与 Google 组分离是刻意的。
- 大厂自有 AI 归各自生态：Gemini → Google.list，Grok/x.ai → Twitter.list，
  Meta AI → Meta.list。conf 里 Google/Twitter/Meta 都排在 AI.list 之前。
- 全库零 `USER-AGENT` / `PROCESS-NAME` / `URL-REGEX`（D7 裁决）：这三类已登记在
  `allowlist.json` 的 `forbidden` 段，由 A8 把守，出现即 P0 回流。
- `ProxyGFW` 只保留无专属 owner 且已验证需要代理的精确域名；宽云/多租户后缀禁收。
- `Reject.list` 已在 conf 区 1 启用（REJECT，全链最前的拦截层）。

**11. `AI.list` 那行带 `extended-matching`**
意味着它对 SNI 和 HTTP Host 都会匹配，比其它 RULE-SET 更「贪」一点。看到 AI 组抓到了
预期之外的域名时，先想想是不是这个原因。

**12. audit 报的 P2 大多不用急**
A2/A3 那些 P2 条目大部分是分层设计的自然产物（同一厂商在细分表和长尾兜底表里都出现）。
先处理 P0/P1，P2 攒着一起清。

**13. `realworld.py --webrtc` 里 STUN 超时**
conf 里 `udp-policy-not-supported-behaviour = REJECT` 的语义就是「策略不支持 UDP 就直接拒绝、
不回落直连」。所以**超时 = 那条 UDP 被挡住了 = 零泄漏**，是好事不是坏事。真正要盯的是
反过来：拿到了应答、而且那个应答等于本机真实出口 IP。

**14. `realworld.py --clients` 里两个组的出口 IP 相同**
不同策略组的成员首项可能指向同一个物理节点（比如 `Final` 与 `流媒体` 当前都落到同一台
日本家宽），此时 IP 层就是区分不出来的。要看它们确实是**不同的组**，看
`surge-cli http probe` 回读的那一列，或者跑 `--crosscheck`。

**15. `--ua-routing` 里一堆 SKIP**
三种原因，表格最后一列都写着：`tun_https` 是 MITM 未启用（**这就是它该有的样子**）；
「没有 IP 回显端点」是那条用例的宿主域拿不到出口 IP；「两个落点物理出口相同」是
IP 层区分不出来 —— 这三种都只影响线路层，规则层的断言照常跑。

**16. `--crosscheck` 报纯 IP 不一致**
`GEOIP` 非 CN 在离线层判不出来，这是已登记的近似盲区（见「已知限制」）。默认只提示，
要当硬失败用 `--strict`。域名类不一致才是真问题。

---

## 典型工作流

**改规则之前**，先存一份基线：

```bash
python3 audit.py --out ~/Desktop/surge-audit/before
python3 runsuite.py --json > ~/Desktop/surge-audit/before.json
```

**改完之后**，比对：

```bash
python3 audit.py --out ~/Desktop/surge-audit/after
python3 runsuite.py                       # 失败数应为 0，known_broken 应该只减不增
python3 engine.py match <你改动涉及的域名>  # 逐个确认命中了预期的规则
python3 realworld.py --crosscheck         # 离线推演与真实 Surge 有没有对不上的
```

**推送之前**（联网确认一次）：

```bash
python3 live_check.py --full --report ~/Desktop/surge-audit/live_report.md
python3 realworld.py --full --redact --report ~/Desktop/surge-audit/realworld.md
```

**只想快速确认「Surge 现在真的在正常接管」**（10 秒，不发外网请求）：

```bash
python3 realworld.py --tun
```

**挂进 `update.sh` 当前置钩子**（可选）：

```bash
python3 "$(dirname "$0")/tests/audit.py" --fail-on P1 || {
    echo "审计未通过，先修 P0/P1 再推送"; exit 1;
}
python3 "$(dirname "$0")/tests/runsuite.py" || exit 1
```

L3/L4 刻意不进闸门 —— 理由见[退出码约定](#退出码约定)最后一段。

---

## 退出码约定

`0` 通过、`1` 有失败项，这两条五个入口都一样；`2` 以上各家含义略有差别：

| 入口            | 0        | 1                             | 2                          | 3                        |
| --------------- | -------- | ----------------------------- | -------------------------- | ------------------------ |
| `engine.py`     | 正常     | `--selftest` 有断言失败       | —                          | —                        |
| `audit.py`      | 无发现   | 命中 `--fail-on` 级别（默认 P1）| —                        | —                        |
| `runsuite.py`   | 断言全过 | 有断言失败                    | 场景目录或引擎不可用       | —                        |
| `live_check.py` | 通过     | 有失败项 / DNS 泄漏 / 无可判定结果 | Surge HTTP API 不可用 | 用法错误或被 Ctrl-C 打断 |
| `realworld.py`  | 通过     | 有硬失败（FAIL）项            | Surge 未运行 / surge-cli 缺失 / 出站模式不是 rule | 用法错误或被 Ctrl-C 打断 |

`known_broken`、`realworld.py` 里标 `WARN` 的提示项、以及「仅报告不断言」的项目，
一律不计为失败。所有入口都支持 `--json`，配合退出码方便接 CI。

**`update.sh` 的发布闸门只有 `audit.py` 与 `runsuite.py` 两个**（纯离线、无外部依赖、
结果可复现）。`live_check.py` 与 `realworld.py` 依赖真实网络和运行中的 Surge，
结果会随节点状态、站点可达性波动，**刻意不挂进闸门** —— 它们是推送前手工跑一遍的确认步骤。

---

## 已知限制

- **离线层的 IP 判定是近似的。** `GEOIP,CN` 用 `ChinaIP.list` 近似，`IP-ASN` 用内置小表，
  `URL-REGEX` 因为离线没有 URL 上下文而恒不匹配。纯 IP 和 URL 相关的结论以在线为准。
  具体盲区已由 `realworld.py --crosscheck` 量化（2026-08-30 实测）：**426 条域名查询与真实
  Surge 逐条一致，全部差异都集中在纯 IP 上**，且都是 `GEOIP` 非 CN 判不出来
  —— 区域表 `US.list` / `UK.list` / `Europe.list` / `Japan.list` 里的 `GEOIP,XX` 规则，
  离线层一律判不匹配、落 Final，真实 Surge 会把这些 IP 收进对应的区域组。
  补齐它需要 MaxMind 库（第三方依赖 + 上百 MB 数据），与「标准库 only」的设计冲突，
  因此**刻意不补**：这类结论一律以 `--crosscheck` 的在线结果为准。
- **`RULE-SET,SYSTEM` 和 `RULE-SET,LAN` 是近似实现**（系统域集合 / RFC1918 段），
  Surge 内置表的确切内容不公开。`BUILTIN_SYSTEM_DOMAINS` 采用「实测补录」策略：
  `--crosscheck` 发现某域真实命中 `RULE-SET SYSTEM` 而表里没有时，按在线为准补进去
  （已补录 `guzzoni.apple.com`）。
- **`USER-AGENT` 规则的生效面取决于通道，不取决于 MITM 开关。** 实测四格矩阵：
  经 Surge HTTP 代理时 UA 在 `CONNECT` 头里，**HTTPS 未解密也能匹配**；走 TUN 时
  明文 HTTP 能匹配、HTTPS 不能。所以「hostname 留空 ⇒ UA 规则只对明文 HTTP 生效」
  是个常见误解 —— 详见 `--ua-routing`。
- **离线层按策略组首项推演**，跟你手选的节点可能不一致，先跑 `--policies` 确认。
- **在线层依赖 recent requests 匹配**，连接复用或请求合并时会拿不到记录（`NOT_FOUND`）。
- **exit-map 的探针域名会失效**（站点换 CDN、关掉 trace 端点）。失效时该组退化为
  「配置推导 + 归属验证」，不会报错。换端点只需改 `live_check.py` 顶部的 `EXIT_PROBES` 表，
  选取标准就一条：**这个域名本身必须命中目标组的规则**。
- **场景数据集是手工维护的。** 厂商换域名、加 CDN，场景就会过时；请求失败先怀疑域名过期，
  再怀疑规则。`realworld.py --list-targets` 能一眼看出 L4 的代表域有没有换组。
- **L4 的出口 IP 只在有回显端点的组量得到。** 没有回显端点的组（社交媒体、Telegram、
  Payment、游戏、UK/EU/US 区域组等）退化为「归属复核 + 连通性 + `surge-cli http probe`
  回读的物理节点 + Cloudflare colo 代码」，不会报错。
- **L4 的结果会随时间漂。** 节点被手动切过、CDN 出口 IP 变化、站点挡爬虫，都会让两次跑的
  结果不同。硬失败只有三类：出站模式/接管状态不对、代理组出口等于本机真实出口、
  WebRTC srflx 等于本机真实出口。其余一律是提示或仅报告。
