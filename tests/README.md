# Surge 分流测试套件

五个入口，从纯离线到真实客户端逐层加码。全部 python3 标准库实现，无第三方依赖；L4 另用系统
自带的 `curl / dig / netstat / scutil / ifconfig / lsof` 与 Surge 自带的 `surge-cli`。

| 层 | 入口 | 联网 | 回答的问题 | 耗时 |
| --- | --- | --- | --- | --- |
| L0 | `engine.py` | 否 | 这个域名命中哪条规则、走哪个组、从哪个出口出去 | < 1 秒 |
| L1 | `audit.py` | 否 | 规则表本身有没有毛病（泄漏面 / 重复 / 遮蔽 / 失联） | ~5 秒 |
| L2 | `runsuite.py` | 否 | 场景断言全过吗 | ~10 秒 |
| L3 | `live_check.py` | **是** | 真实网络里发生的与离线推演一致吗、出口 IP 对吗 | 1–5 分钟 |
| L4 | `realworld.py` | 部分 | 真实客户端发出去会怎样、DNS/WebRTC/TUN/UA 真的生效吗 | 3–5 分钟 |

L3 读「Surge 认为发生了什么」（需手工开一次 `http-api`），L4 用真实客户端 + 系统命令 +
`surge-cli` 看「机器上实际发生了什么」（不改配置）—— 两个观测面，不是替代关系。**判定原则：
在线为准。发布闸门只有 `audit.py` 与 `runsuite.py`**（纯离线、可复现）；L3/L4 随节点与站点可达
性波动，刻意不挂闸门，是推送前手工跑一遍的确认步骤。

数据面：`realworld_targets.json`（L4 代表域 / 画像 / STUN / UA 用例）、`allowlist.json`（豁免表
+ forbidden 禁令段）、`scenarios/`（场景数据集）、`data/`（入库判据快照 PSL / IANA，说明见
`data/SNAPSHOTS.json`）、`live_check_local.json`（私有出口映射覆盖档，gitignore）；另有
`analyze_rules_selftest.py`（`tools/analyze_rules.py` 的自检）。报告不要写进 `rules/`（会被
jsDelivr 分发），用 `--out` 指到别处。

**私有节点信息一律外置。** `tests/` 随公开仓库分发，真实策略组名、节点名、出口 IP、线路商与
机房标识、自家 ASN 都不许进入任何入库文件；代码里只留中性占位默认值（`美国家宽A` /
`US-HOME-A` / `ISP-A` / `DC-X` / 私有段 ASN `64500`…），报告要外发再加 `--redact`。覆盖档
`engine.py` 与 `live_check.py` 共用，取**第一个存在的文件**（不叠加）：① 环境变量
`LIVE_CHECK_LOCAL`；② `<repo>/../rules-local/live_check_local.json`（推荐，整个目录在仓库外）；
③ `<repo>/tests/live_check_local.json`（旧路径，靠 `.gitignore` 兜底）。缺失不报错，全走中性默
认值：`engine.py` 自检的出口画像断言 R03–R05 标 skipped，`live_check.py` 归类退化到国旗兜底。

```json
{"exit_class_exact":    {"<策略组或叶子出口组名>": "<exit_class>"},
 "exit_class_keywords": [["<物理节点名关键字>", "<exit_class>"]],
 "asn_map":             {"<ASN>": "<注释>"},
 "residential_hints":   ["<RDAP 机构/网段名关键字>"],
 "datacenter_hints":    ["<RDAP 机构/网段名关键字>"]}
```

## L0 `engine.py`

离线复刻 Surge 匹配语义：读 `Surge.conf` 的 `[Rule]`，把每条 `RULE-SET` 的远程 URL 按文件名
映射回本地 `lists/*.list` 内联展开，再按顺序首次命中匹配。

```bash
python3 engine.py match chatgpt.com [--json] [--process X] [--ip 1.2.3.4] [--ua UA]
python3 engine.py match 1.1.1.1                          # 纯 IP 查询
python3 engine.py dump-index                             # 导出展开后的全规则表
python3 engine.py --selftest                             # 内置自检
python3 engine.py match X --conf <conf> --rules <dir>    # 指定候选 conf / 规则目录
```

输出字段：`matched_rule`（命中原文）、`rule_index`（展开后位次，越小越优先）、`source`（来自
哪张表）、`policy`、`physical_exit`（递归解析组首项后的物理节点）、`exit_class`（出口归类，
判断两个请求是否同一出口，取值集合是共享契约：`US-HOME-A` / `US-HOME-B` / `US-DC` /
`JP-HOME` / `JP-DC` / `EU` / `DIRECT` / `REJECT`，映射由私有覆盖档提供）、`dns_leak` /
`dns_leak_at`（命中前是否途经不带 `no-resolve` 的 IP 类规则）。

两个前提：① 策略组一律按**成员首项**推演，手动切过节点则离线结论不适用；② `IP-ASN` /
`GEOIP` 是离线近似（`GEOIP,CN` 用 `ChinaIP.list`，ASN 用内置小表），纯 IP 结论以在线为准。

## L1 `audit.py`

```bash
python3 audit.py [--out DIR] [--check A1,A4] [--fail-on P0] [--selftest]
python3 audit.py --conf <conf> --rules lists --check all --fail-on P1   # 闸门用法
```

| 编号 | 查什么 |
| --- | --- |
| A1 | IP 类规则缺 `no-resolve` —— 直接对应 DNS 泄漏，头号红线 |
| A2 | 跨 list 精确重复 —— 后出现的那条是死条目 |
| A3 | 同 list 内部覆盖 —— `DOMAIN` 被同表 `SUFFIX` 吃掉之类 |
| A4 | 跨 list 遮蔽 —— 直连区条目被代理区抢跑 = P0 |
| A5 | conf 引用完整性 —— 引用了不存在的表，或有表没人引用 |
| A6 | `DOMAIN-KEYWORD` 清单 —— 只列出来给人复核，不判对错 |
| A7 | 规则行格式 lint —— 无类型前缀的裸行会被静默忽略 = 死规则，P1 |
| A8 | 禁止回流 —— `forbidden` 段登记的模式一出现即 P0，**不可豁免** |
| A9 | IP 跨表包含 / 遮蔽 —— 按 conf 真实序判「后位 CIDR 被前位覆盖」；同策略 P3，跨策略 P1 |
| A10 | 单标签后缀与 PSL 注册边界 —— 用入库 PSL + IANA 快照判，离线不联网 |

严重度：P0 功能损坏或明确错误分流 / P1 IP 一致性与 DNS 泄漏风险 / P2 冗余遮蔽但无直接伤害 /
P3 风格建议。

`allowlist.json` 两段：`exemptions` 登记「允许存在的刻意设计」，按 `(check, file, rule)` 匹配；
`forbidden` 登记「必须持续不存在的规则模式」，由 A8 扫源文件强制。每条都**必须**写 `reason`。

```json
{"version": 1,
 "exemptions": [{"check": ["A2","A3","A4"], "file": "Google.list",
                 "by_file": "YouTube.list", "preventive": true,
                 "reason": "YouTube 专属资产由前位 YouTube.list 认领"}],
 "forbidden":  [{"pattern": "USER-AGENT,*", "reason": "D7 裁决：全库零 USER-AGENT"}]}
```

`check` 省略 = 所有检查项；`file` / `rule` 支持 `*` `?` 通配；`by` / `by_file` 指定遮蔽方以缩
小豁免面；`preventive: true` = 防回归条目，没命中不算「无用豁免」。`forbidden` 不吃豁免、命中即
P0，签名必须锚定注册域（S3 族写 `s3.*.amazonaws.com` 而非 `s3*`，否则误伤第一方 `s3.<brand>`
host）。两段条数刻意不写进本文档 —— 每轮都会增长，真值以 `tests/allowlist.json` 为准。

## L2 `runsuite.py`

场景 = 一次自然用户行为触发的整组域名（主站 + API + CDN + 登录风控 + 遥测）。判的不是「单个
域名走哪」，而是「这一整套操作会不会被拆到不同出口上」。

```bash
python3 runsuite.py [--filter openai] [--json] [--list-known-broken]
python3 runsuite.py --conf <conf> --rules lists     # 闸门用法
```

```json
{"name": "openai_chatgpt_web", "desc": "网页版 ChatGPT 登录并对话+上传图片",
 "requests": [{"host": "chatgpt.com"}, {"host": "auth.openai.com"},
              {"host": "cdn.oaistatic.com"}],
 "assert": {"same_policy": true, "policy": "AI", "no_dns_leak": true}}
```

断言字段：`same_policy`（会话内所有请求落同一组）、`policy`（期望组名）、`policy_in`（允许其
一）、`per_request`（给个别请求单独定期望）、`no_dns_leak`（匹配路径上不得触发本地解析）。
请求项也可写 `{"ip": "8.8.8.8"}`，`per_request` 里同样可用 `ip` 作键。`"known_broken": true`
的场景是当前确实过不了、但已知原因的，单独统计成待修清单而不算失败，修好就删标记。当轮基线
（场景 / 请求 / 断言 / DNS 泄漏断言数）见 `CHANGELOG.md`，真值以本命令输出为准。

## L3 `live_check.py`

```bash
export SURGE_API_KEY=surgetest
python3 live_check.py --check-api    # API 通不通；其它子命令都会先做这一步
python3 live_check.py --policies     # 各组当前选中项 vs 引擎假设（成员首项）
python3 live_check.py --scenario all # 场景实测（真发请求），也可 --hosts a.com,b.com
python3 live_check.py --exit-map     # 出口画像：组 → 出口 IP → ASN → 住宅/机房
python3 live_check.py --dns-leak     # flush 后访问代理域，读 /v1/dns 找实锤
python3 live_check.py --full         # 2→5 全跑并生成 live_report.md
```

`--policies` 区分两种不一致：`select` 组不一致 = 你手动切过节点（★ 告警），`smart` /
`url-test` / `fallback` 不一致 = 动态择优、非问题。`--scenario` 结果状态 `PASS` / `FAIL` /
`KNOWN_BROKEN` / `UNREACHABLE`（网络层没打通，不算断言失败）/ `NOT_FOUND`（发出去了但 recent
里没找到）/ `SKIPPED`；一次跑下来一条都没判定成会直接退出 1。`--exit-map` 每组用一个**本身就
命中该组规则**的探针域（否则量的不是这个组），并从配置推导一遍出口 IP（本配置是 snell 级联，
面向互联网的那跳是家宽节点自己的 server 地址），实测与推导并排就能看出链路有没有降级；建
`expected_asn.json` 才做 ASN 断言（真实 ASN 能反查线路商，建议一并 gitignore）。

参数：`--key` / `SURGE_API_KEY`、`--api`（默认 `http://127.0.0.1:6171`）、`--proxy-port`、
`--scenarios-dir`、`--timeout`（8 秒）、`--rate`（3 req/s）、`--report`、`--json`、
`--dump-raw DIR`、`--no-flush`。

**开启 HTTP API（只有 L3 需要，程序不会替你改配置）**：在 `Surge.conf` 的 `[General]` 段手工加
`http-api = surgetest@127.0.0.1:6171`（格式 `<Key>@<地址>:<端口>`），重载配置，再
`export SURGE_API_KEY=surgetest`。监听地址务必写 `127.0.0.1` —— 写 `0.0.0.0` 等于把 Surge 控制
权交给整个局域网。排查：连接被拒 = 配置没生效（`lsof -nP -iTCP:6171 -sTCP:LISTEN`）；401/403 =
Key 对不上（区分大小写）；端口占用就换一个并配 `--api`；出站模式不是 rule 时先切回规则模式。

## L4 `realworld.py`

不需要 `http-api`；`surge-cli` 走本机控制通道。

```bash
python3 realworld.py --tun        # 接管状态：utun / 默认路由 / 系统 DNS / hijack
python3 realworld.py --dns        # hijack 生效性 / fake-IP / canary / SVCB / DoH / 泄漏抽样
python3 realworld.py --webrtc     # 最小 STUN 客户端取 srflx 公网 IP 比对
python3 realworld.py --clients    # 真实客户端画像 × 各组代表域
python3 realworld.py --crosscheck # surge-cli 实测语义 vs engine.py 离线推演，逐条对账
python3 realworld.py --ua-routing # UA 分流生效性（四格通道矩阵）
python3 realworld.py --offline    # 只跑 --tun --crosscheck --ua-routing
python3 realworld.py --list-targets   # 只打印数据配置并复核归属，零外部请求
```

- `--tun` 硬断言三条：出站模式必须是 `rule`、IPv4 默认路由必须指向 utun、系统 DNS 必须指向
  Surge 的响应器（macOS 是 `198.18.0.2`）。有一条不成立后面所有结论都不作数，所以第一个跑。
- `--dns` 四件事：hijack 生效性（`dig @8.8.8.8` 等的应答必须落 fake-IP 池 `198.18.0.0/15`）、
  响应器行为（canary `use-application-dns.net` 须 `NXDOMAIN`，`allow-dns-svcb` 关时 TYPE65 须
  `NOTIMP`）、DoH 可用性（RFC 8484 GET + 查 Surge 实际上游有无回落明文 53）、本地泄漏 live 抽样
  （`dump dns` 前后快照**只看新增**，零写操作）。
- `--webrtc` 判定基准不写死任何 IP：`baseline: true` 的 STUN 必须落 DIRECT，其余各组的 srflx 与
  它比，srflx == 本机真实出口而该域命中代理组 = 硬失败；
  `udp-policy-not-supported-behaviour = REJECT` 时**超时无应答 = 零泄漏，不算失败**。
- `--crosscheck` 抓离线引擎与真实 Surge 的语义差异：域名类不一致 = 硬失败，纯 IP 不一致默认只
  提示（`GEOIP` 非 CN / `IP-ASN` 是显式声明的近似）、`--strict` 升为硬失败；顺带对 DNS 缓存取
  前后快照 —— 规则评估本身不应触发任何本地解析。
- `--ua-routing` 四格矩阵：`proxy_https`（UA 在 `CONNECT` 头里）/ `proxy_http` / `tun_http` 三格
  Surge 都读得到 UA，`tun_https` 只有 SNI 需 MITM（未启用自动 SKIP）；每条跑规则层
  （`rule explain`，随时可跑）与线路层（真发两次比出口 IP，只有两个落点物理出口本来就不同时才
  做 IP 断言）。

改测什么全在 `realworld_targets.json`：`clients`（画像 UA / HTTP 版本 / headers）、`groups`（每
组 2–3 个代表域 + 用哪些画像）、`stun`、`dns`、`ua_routing`。`groups[].hosts` 的选取标准只有一
条：**该域名本身必须命中该组的规则**；程序每轮用 `surge-cli` 复核归属，换了组直接报失败 ——
这张表是自校验的。

参数：`--via auto|proxy|tun`、`--redact`、`--strict`、`--filter`、`--limit`、`--targets`、
`--surge-cli`、`--timeout`（10 秒）、`--rate`（3 req/s）、`--report`、`--json`。

**L3 / L4 共同的安全边界**：不切策略、不改配置、不重载 profile、不修改 `Surge.conf` 或 `rules/`
下任何文件；从不读取或打印 psk / ca-p12；对外只发普通 HTTPS GET/HEAD，只访问场景与
`realworld_targets.json` 登记的端点，默认限速 3 req/s。L3 唯一的写操作是
`POST /v1/dns/flush`（`--no-flush` 可关），L4 全程零写（`surge-cli` 只用 `status` /
`rule explain` / `http probe` / `dump dns` / `dns lookup`）。

## 退出码

`0` 通过、`1` 有失败项，五个入口一致。`2`：`runsuite.py` = 场景目录或引擎不可用，
`live_check.py` = Surge HTTP API 不可用，`realworld.py` = Surge 未运行 / surge-cli 缺失 / 出站
模式不是 rule。`3` = 用法错误或被 Ctrl-C 打断（仅 L3/L4）。`known_broken`、`WARN` 提示项、
「仅报告不断言」的项目一律不计失败。所有入口都支持 `--json`。

## 已知观察项与限制 —— 这些不是 bug

- **组选中项与假设不一致** = 你切过节点（离线三层永远按成员首项推演）；**在线策略显示节点名而
  非组名**（`policyName` 是链路末端物理节点，还原不出链路时退一步比 `exit_class`）；
  **`UNREACHABLE`**（TCP/TLS 没打通）/ **`NOT_FOUND`**（连接复用或请求合并）不算分流错，但大面
  积出现时程序会警告覆盖率不够。
- **DNS 泄漏要 flush 之后立刻看**：本地缓存全机共享，浏览器 DoH 旁路会往里写；flush 之前就存在
  的记录单列「无法判定」，直连域没出现在本地 DNS 也不是错误。**ASN 列为空**不代表异常（ARIN 的
  RDAP 对家宽客户网段常不返回 ASN，看网段名同样能确认归属）；**「实测≠推导」**是链路降级或中转
  商改写出口。
- **刻意设计，审计和场景都别报**：YouTube 全量归流媒体组且排在 Google 之前；大厂自有 AI 归各自
  生态（Gemini → Google.list、Grok/x.ai → Twitter.list、Meta AI → Meta.list，conf 里这三张都排
  在 AI.list 之前）；全库零 `USER-AGENT` / `PROCESS-NAME` / `URL-REGEX`（D7 裁决，A8 把守）；
  `ProxyGFW` 只收无专属 owner 且已验证需代理的精确域名；`Reject.list` 在 conf 最前的拦截层；
  `AI.list` 带 `extended-matching`，对 SNI 和 HTTP Host 都匹配。audit 的 P2 大多是分层设计的自
  然产物，先处理 P0/P1。
- **离线层的 IP 判定是近似的**：`GEOIP,CN` 用 `ChinaIP.list`、`IP-ASN` 用内置小表、`URL-REGEX`
  离线恒不匹配；`RULE-SET,SYSTEM` / `LAN` 同样是近似（Surge 内置表不公开，`--crosscheck` 发现
  漏项按在线为准补进 `BUILTIN_SYSTEM_DOMAINS`）。`--crosscheck` 已量化：全部差异集中在纯 IP 的
  `GEOIP` 非 CN —— 区域表里的 `GEOIP,XX` 离线判不匹配落 Final，真实 Surge 会收进对应区域组。
  补齐需要 MaxMind 库（与「标准库 only」冲突）**刻意不补**，要 MMDB 展开就用
  `tools/analyze_rules.py --country-db/--asn-db`。`USER-AGENT` 的生效面取决于通道而非 MITM 开关。
- **会随时间漂的三处**：exit-map 探针域会失效（站点换 CDN 或关掉 trace 端点，该组退化为「配置
  推导 + 归属验证」，不报错）；场景数据集手工维护，厂商换域名就过时，请求失败先怀疑域名过期；
  L4 出口 IP 只在有回显端点的组量得到，其余退化为归属复核 + 连通性 + `http probe` 回读。L4 的
  硬失败只有三类：接管状态不对、代理组出口等于本机真实出口、WebRTC srflx 等于本机真实出口。
