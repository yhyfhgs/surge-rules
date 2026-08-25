# Surge 分流测试套件

给这套规则体系做「仿真实网络环境」的回归测试：改完规则先跑一遍，别等到用着不对劲了才发现。

四个入口，从纯离线到真实网络，逐层加码：

| 层  | 入口             | 要不要联网 | 回答的问题                                            | 单次耗时 |
| --- | ---------------- | ---------- | ----------------------------------------------------- | -------- |
| L0  | `engine.py`      | 否         | 这个域名会命中哪条规则、走哪个组、从哪个出口出去？    | < 1 秒   |
| L1  | `audit.py`       | 否         | 规则表本身有没有毛病（DNS 泄漏面、重复、遮蔽、失联）？| ~5 秒    |
| L2  | `runsuite.py`    | 否         | 90 个真实使用场景的 500 条请求，分流结果符合预期吗？  | ~10 秒   |
| L3  | `live_check.py`  | **是**     | 真实网络里实际发生的，跟离线推演的一样吗？出口 IP 对吗？| 1–5 分钟 |

全部 python3 标准库实现，无第三方依赖，macOS 自带的 python3 直接能跑。

---

## 30 秒上手

```bash
cd "/Users/<你>/Library/Application Support/Surge/Profiles/rules/tests"

python3 engine.py match chatgpt.com      # 查单个域名怎么走
python3 audit.py                         # 体检规则表
python3 runsuite.py                      # 跑全部场景断言
```

这三条不碰网络、不改任何文件，随便跑。第四个入口 `live_check.py` 需要先开一次
Surge HTTP API，见下方[开启 Surge HTTP API](#开启-surge-http-api)。

---

## 目录结构

```
rules/tests/
├── engine.py            L0 规则语义引擎（解析 conf + 31 个 list，离线模拟匹配）
├── audit.py             L1 静态审计器（A1–A6 六项检查）
├── runsuite.py          L2 场景断言运行器
├── live_check.py        L3 在线实测（Surge HTTP API + 真实请求）
├── allowlist.json       审计豁免表（把「刻意设计」标出来，免得每次都报）
├── scenarios/           场景数据集，九个 .json，共 90 场景 / 500 请求
│   ├── ai_overseas.json      海外独立 AI（OpenAI / Anthropic / Perplexity …）
│   ├── ai_ecosystem.json     大厂 AI 生态一致性（Gemini / Copilot / Grok …）
│   ├── ai_domestic.json      国内 AI 直连（DeepSeek / Kimi / 通义 …）
│   ├── cn_intl.json          国内厂商国际站（Coze / Trae / TikTok …）
│   ├── cn_ecosystem.json     国内大厂全家桶（微信 / 淘宝 / B站 …）
│   ├── intl_services.json    国际非 AI（GitHub / Netflix / Steam …）
│   ├── cdn_pairing.json      主站与 CDN 配对一致性
│   ├── edge_cases.json       边界（OCSP / NTP / captive / 纯 IP / 遥测域）
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
```

---

## L0 `engine.py` —— 规则语义引擎

离线复刻 Surge 的匹配语义：读 `Surge.conf` 的 `[Rule]`，把每条 `RULE-SET` 的远程 URL
按文件名映射回本地 `rules/*.list` 内联展开，然后按顺序做首次命中匹配。

```bash
python3 engine.py match chatgpt.com                  # 人读输出
python3 engine.py match chatgpt.com --json           # 机器可读
python3 engine.py match claude.ai --process Claude   # 带进程名
python3 engine.py match 1.1.1.1                      # 纯 IP 查询
python3 engine.py dump-index                         # 导出展开后的全规则表
python3 engine.py --selftest                         # 内置自检（≥20 条手工断言）
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
`EU` / `DIRECT` / `REJECT`。

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
python3 audit.py --selftest                       # 用植入已知缺陷的合成配置自检
```

六项检查：

| 编号 | 查什么                                   | 为什么重要                                       |
| ---- | ---------------------------------------- | ------------------------------------------------ |
| A1   | IP 类规则缺 `no-resolve`                 | 直接对应 DNS 泄漏，本体系的头号红线              |
| A2   | 跨 list 精确重复                         | 后出现的那条是死条目                             |
| A3   | 同 list 内部覆盖                         | `DOMAIN` 被同表 `SUFFIX` 吃掉之类                |
| A4   | 跨 list 遮蔽                             | 尤其「直连区条目被代理区抢跑」= P0               |
| A5   | conf 引用完整性                          | 引用了不存在的 list，或有 list 没人引用          |
| A6   | `DOMAIN-KEYWORD` 清单                    | 只列出来给人复核，不判对错                       |

严重度：P0 功能损坏或明确错误分流 / P1 IP 一致性与 DNS 泄漏风险 / P2 冗余遮蔽但无直接伤害 /
P3 风格建议。

### `allowlist.json`

把「明知故犯」的设计登记在案，审计就不会反复报它。按 `(check, file, rule)` 三元组匹配，
每条**必须**写 `reason`：

```json
{
  "version": 1,
  "exemptions": [
    {
      "check": ["A2", "A3", "A4"],
      "file": "*",
      "rule": "PROCESS-NAME,*",
      "preventive": true,
      "reason": "PROCESS-NAME 大小写变体是跨平台覆盖，禁止去重"
    }
  ]
}
```

- `check` 可以是字符串或数组，省略表示所有检查项。
- `file` / `rule` 支持 `*` `?` 通配；还可以用 `by` / `by_file` 指定「遮蔽方」来缩小豁免面。
- `preventive: true` 表示这是防回归条目 —— 当前配置本来就不该命中它，没命中不会被算成
  「无用豁免」。

当前表里 14 条，覆盖：PROCESS-NAME 大小写变体、`amazonaws.com` 的兜底与分层、
`Reject.list` 未被引用（文件保留但 conf 里注释停用）、以及 00-context 那张上游合并排除表。
基线是 2026-08-25 的一次全量审计（A1=0、A4=0，所以本表以防回归为主）。

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

首次全量运行的结论（供参考）：90 场景 / 500 请求 / 933 断言，失败 0，已知待修 78 条；
351 条 DNS 泄漏断言全通过，说明「零本地 DNS 解析」这条约束目前是成立的。

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

64500 =ISP-A，64501 =ISP-B，64502 =DC-X。

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
`/v1/requests/recent` 里的 `policyName` 通常是链路末端的物理节点（如 `🇺🇸REDACTED-ISP-A-ISP-A-DC-X-LAX`），
不是 `AI`。程序会从 notes 里还原完整链路，还原不出来时退一步比 `exit_class`。
表里写成 `AI→🇺🇸REDACTED-ISP-A-ISP-A-DC-X-LAX` 就是还原成功了。

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
这时候看**网段名**：`ATT-NET-REDACTED` 一样能确认是 ISP-A。空 ASN 不代表异常。

**7. 「实测≠推导」**
两种可能：链路降级了（家宽那一跳没走通，退回落地机房出口），或者中转商改写了出口。
值得人工看一眼，但不是程序的问题。另外 CDN 出口 IP 本身会随时间漂，两次跑结果不同很正常。

**8. `known_broken` 的场景「失败」了**
那是待修清单，不是测试失败。`runsuite.py --list-known-broken` 能单独列出来。
反过来，如果一个 `known_broken` 场景突然通过了，说明问题已经修好，把标记删掉。

**9. 主站与静态资源分属不同组**
`DownloadCDN.list` 的分层设计会让一部分场景出现「主站走 Final、静态资源走下载组」。
这是既有架构取舍。如果确认要保留，把对应场景的期望改成 `same_policy: false` 并在
`allowlist.json` 里登记，别让它一直占着待修清单。

**10. 这些是刻意设计，审计和场景都别报**

- YouTube 全量归流媒体组、且排在 Google 之前 —— 与 Google 组分离是刻意的。
- 大厂自有 AI 归各自生态：Gemini → Google.list，Grok/x.ai → Twitter.list，
  Meta AI → Meta.list。conf 里 Google/Twitter/Meta 都排在 AI.list 之前。
- `PROCESS-NAME` 的大小写变体（`Claude` / `claude` / `Claude.exe`）是跨平台覆盖，禁止去重。
- `DOMAIN-SUFFIX,amazonaws.com` 在 ProxyGFW 是 AWS 兜底，具体 CDN 子域在 DownloadCDN
  分层处理，这是刻意分层。
- `Reject.list` 在 conf 里注释停用但文件保留。

**11. `AI.list` 那行带 `extended-matching`**
意味着它对 SNI 和 HTTP Host 都会匹配，比其它 RULE-SET 更「贪」一点。看到 AI 组抓到了
预期之外的域名时，先想想是不是这个原因。

**12. audit 报的 P2 大多不用急**
A2/A3 那些 P2 条目大部分是分层设计的自然产物（同一厂商在细分表和长尾兜底表里都出现）。
先处理 P0/P1，P2 攒着一起清。

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
```

**推送之前**（联网确认一次）：

```bash
python3 live_check.py --full --report ~/Desktop/surge-audit/live_report.md
```

**挂进 `update.sh` 当前置钩子**（可选）：

```bash
python3 "$(dirname "$0")/tests/audit.py" --fail-on P1 || {
    echo "审计未通过，先修 P0/P1 再推送"; exit 1;
}
python3 "$(dirname "$0")/tests/runsuite.py" || exit 1
```

---

## 退出码约定

`0` 通过、`1` 有失败项，这两条四个入口都一样；`2` 以上各家含义略有差别：

| 入口            | 0        | 1                             | 2                          | 3                        |
| --------------- | -------- | ----------------------------- | -------------------------- | ------------------------ |
| `engine.py`     | 正常     | `--selftest` 有断言失败       | —                          | —                        |
| `audit.py`      | 无发现   | 命中 `--fail-on` 级别（默认 P1）| —                        | —                        |
| `runsuite.py`   | 断言全过 | 有断言失败                    | 场景目录或引擎不可用       | —                        |
| `live_check.py` | 通过     | 有失败项 / DNS 泄漏 / 无可判定结果 | Surge HTTP API 不可用 | 用法错误或被 Ctrl-C 打断 |

`known_broken` 和「仅报告不断言」的项目一律不计为失败。所有入口都支持 `--json`，
配合退出码方便接 CI。

---

## 已知限制

- **离线层的 IP 判定是近似的。** `GEOIP,CN` 用 `ChinaIP.list` 近似，`IP-ASN` 用内置小表，
  `URL-REGEX` 因为离线没有 URL 上下文而恒不匹配。纯 IP 和 URL 相关的结论以在线为准。
- **`RULE-SET,SYSTEM` 和 `RULE-SET,LAN` 是近似实现**（系统域集合 / RFC1918 段），
  Surge 内置表的确切内容不公开。
- **离线层按策略组首项推演**，跟你手选的节点可能不一致，先跑 `--policies` 确认。
- **在线层依赖 recent requests 匹配**，连接复用或请求合并时会拿不到记录（`NOT_FOUND`）。
- **exit-map 的探针域名会失效**（站点换 CDN、关掉 trace 端点）。失效时该组退化为
  「配置推导 + 归属验证」，不会报错。换端点只需改 `live_check.py` 顶部的 `EXIT_PROBES` 表，
  选取标准就一条：**这个域名本身必须命中目标组的规则**。
- **场景数据集是手工维护的。** 厂商换域名、加 CDN，场景就会过时；请求失败先怀疑域名过期，
  再怀疑规则。
