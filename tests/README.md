# Surge 分流测试套件

五个入口，从纯离线到真实客户端逐层加码。全部 python3 标准库实现；L4 另用系统自带的
`curl / dig / netstat / scutil / ifconfig / lsof` 与 Surge 自带的 `surge-cli`。

| 层 | 入口 | 联网 | 回答的问题 | 耗时 |
| --- | --- | --- | --- | --- |
| L0 | `engine.py` | 否 | 这个域名命中哪条规则、走哪个组、从哪个出口出去 | < 1 秒 |
| L1 | `audit.py` | 否 | 规则表本身有没有毛病（泄漏面 / 重复 / 遮蔽 / 失联） | ~5 秒 |
| L2 | `runsuite.py` | 否 | 场景断言全过吗 | ~10 秒 |
| L3 | `live_check.py` | **是** | 真实网络里发生的与离线推演一致吗、出口 IP 对吗 | 1–5 分钟 |
| L4 | `realworld.py` | 部分 | 真实客户端发出去会怎样、DNS/WebRTC/TUN 真的生效吗 | 3–5 分钟 |

**判定原则：在线为准。发布闸门只有 `audit.py` 与 `runsuite.py`**（纯离线、可复现）；
L3/L4 随节点与站点可达性波动，刻意不挂闸门，是推送前手工跑一遍的确认步骤。
报告不要写进 `rules/`（会被 jsDelivr 分发），用 `--out` / `--report` 指到别处。

**私有节点信息一律外置。** `tests/` 随公开仓库分发：真实策略组名、节点名、出口 IP、
线路商与机房标识、自家 ASN 都不许进入任何入库文件，代码里只留中性占位默认值
（`US-HOME-A` / `ISP-A` / ASN `64500`…），报告要外发再加 `--redact`。覆盖档由
`engine.py` 与 `live_check.py` 共用，取第一个存在的文件：① 环境变量
`LIVE_CHECK_LOCAL`；② `tests/live_check_local.json`（已 gitignore）。缺失不报错，
全走中性默认值，出口画像断言自动跳过 / 退化到国旗兜底。schema：

```json
{"exit_class_exact":    {"<策略组或叶子出口组名>": "<exit_class>"},
 "exit_class_keywords": [["<物理节点名关键字>", "<exit_class>"]],
 "asn_map":             {"<ASN>": "<注释>"},
 "residential_hints":   ["<RDAP 机构/网段名关键字>"],
 "datacenter_hints":    ["<RDAP 机构/网段名关键字>"]}
```

数据面：`scenarios/`（场景数据集，9 个主题文件）、`allowlist.json`（豁免表 +
forbidden 禁令段）、`realworld_targets.json`（L4 代表域 / 画像 / STUN / DNS 用例）、
`data/`（A10 判据快照 PSL / IANA，说明见 `data/SNAPSHOTS.json`）、
`analyze_rules_selftest.py`（分析器自检）。

## L0 `engine.py`

离线复刻 Surge 匹配语义：读 `Surge.conf` 的 `[Rule]`，把每条 `RULE-SET` 按文件名
映射回本地 `lists/*.list` 内联展开，再按顺序首次命中匹配。只支持本仓库允许的规则面
（8 种类型 + RULE-SET/FINAL + 内置 SYSTEM/LAN 近似），其余类型告警并跳过。

```bash
python3 engine.py match chatgpt.com [--json] [--ip 1.2.3.4]
python3 engine.py match 1.1.1.1                          # 纯 IP 查询
python3 engine.py dump-index [--file NAME]               # 导出展开后的全规则表
python3 engine.py --selftest
python3 engine.py match X --conf <conf> --rules <dir>    # 指定候选 conf / 规则目录
```

输出字段：`matched_rule` / `rule_index`（展开后位次，越小越优先）/ `source` /
`policy` / `physical_exit`（递归解析组首项）/ `exit_class`（出口归类，映射由私有
覆盖档提供）/ `dns_leak` / `dns_leak_at`（命中前是否途经缺 `no-resolve` 的 IP 规则）。

两个前提：① 策略组一律按**成员首项**推演，手动切过节点则离线结论不适用；
② `IP-ASN` / `GEOIP` 是离线近似（`GEOIP,CN` 用 `ChinaIP.list`，ASN 用内置小表），
纯 IP 结论以在线为准。

## L1 `audit.py`

```bash
python3 audit.py [--check A1,A4] [--fail-on P0] [--out DIR] [--selftest]
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
| A9 | IP 跨表包含 —— 按 conf 真实序只报「后位 CIDR 被前位吞掉」；同策略 P3，跨策略 P1 |
| A10 | 单标签后缀与 PSL 注册边界 —— 用入库 PSL + IANA 快照判，离线不联网 |

严重度：P0 功能损坏或明确错误分流 / P1 IP 一致性与 DNS 泄漏风险 / P2 冗余遮蔽但
无直接伤害 / P3 风格建议。`--out` 写 findings.jsonl。

`allowlist.json` 两段：`exemptions` 登记「允许存在的刻意设计」，按 `(check, file,
rule)` 匹配，可选 `by` / `by_file` / `kind` 收窄豁免面，`preventive: true` 为防回归
条目（未命中不算无用豁免）；`forbidden` 登记「必须持续不存在的规则模式」，由 A8
强制，命中即 P0 不吃豁免，可带 `file`（只在该表内禁）或 `not_file`（该表之外禁）。
每条都**必须**写 `reason`。签名要锚定注册域（写 `s3.*.amazonaws.com` 而非 `s3*`）。

```json
{"version": 1,
 "exemptions": [{"check": ["A2","A3","A4"], "file": "Google.list",
                 "by_file": "YouTube.list", "preventive": true,
                 "reason": "YouTube 专属资产由前位 YouTube.list 认领"}],
 "forbidden":  [{"pattern": "USER-AGENT,*", "reason": "裁决：全库零 USER-AGENT"}]}
```

## L2 `runsuite.py`

场景 = 一次自然用户行为触发的整组域名（主站 + API + CDN + 登录风控）。判的不是
「单个域名走哪」，而是「这一整套操作会不会被拆到不同出口上」。

```bash
python3 runsuite.py [--filter openai] [--json]
python3 runsuite.py --conf <conf> --rules lists     # 闸门用法
```

```json
{"name": "openai_chatgpt_web", "desc": "网页版 ChatGPT 登录并对话",
 "requests": [{"host": "chatgpt.com"}, {"host": "auth.openai.com"}],
 "assert": {"same_policy": true, "policy": "AI", "no_dns_leak": true}}
```

断言字段：`same_policy`（会话内所有请求同组）、`policy` / `policy_in`（互斥）、
`per_request`（给个别请求单独定期望，按 `(host, ip)` 精确对上）、`no_dns_leak`。
请求项也可写 `{"ip": "8.8.8.8"}`。schema 在加载期严格校验（未知键、空场景、假绿的
`same_policy` 都拒载）。当轮基线数字见 `CHANGELOG.md`，真值以本命令输出为准。

## L3 `live_check.py`

```bash
export SURGE_API_KEY=surgetest
python3 live_check.py --check-api    # API 通不通；其它子命令都会先做这一步
python3 live_check.py --policies     # 各组当前选中项 vs 引擎假设（成员首项）
python3 live_check.py --scenario all # 场景实测（真发请求），也可 --hosts a.com,b.com
python3 live_check.py --exit-map     # 出口画像：组 → 出口 IP → ASN → 住宅/机房
python3 live_check.py --dns-leak     # flush 后访问代理域，读 /v1/dns 找实锤
python3 live_check.py --full         # 全跑并生成 live_report.md
```

`--policies` 区分：`select` 组不一致 = 你手动切过节点（★ 告警），`smart` /
`url-test` 不一致 = 动态择优、非问题。`--scenario` 状态 `PASS` / `FAIL` /
`UNREACHABLE`（网络层没打通，不算断言失败）/ `NOT_FOUND`（连接复用）/ `SKIPPED`；
一条都没判定成会直接退出 1。`--exit-map` 每组用一个本身就命中该组规则的探针域，
并从配置推导一遍出口 IP，实测与推导并排能看出链路有没有降级；建
`expected_asn.json`（建议 gitignore）才做 ASN 断言。

**开启 HTTP API（只有 L3 需要，程序不会替你改配置）**：在 `Surge.conf` 的
`[General]` 手工加 `http-api = surgetest@127.0.0.1:6171`，重载配置，再
`export SURGE_API_KEY=surgetest`。监听地址务必写 `127.0.0.1`。

## L4 `realworld.py`

不需要 `http-api`；`surge-cli` 走本机控制通道。

```bash
python3 realworld.py --tun        # 接管状态：utun / 默认路由 / 系统 DNS / hijack
python3 realworld.py --dns        # hijack / fake-IP / canary / SVCB / DoH / 泄漏抽样
python3 realworld.py --webrtc     # 最小 STUN 客户端取 srflx 公网 IP 比对
python3 realworld.py --clients    # 真实客户端画像 × 各组代表域
python3 realworld.py --crosscheck # surge-cli 实测语义 vs engine.py 离线推演，逐条对账
python3 realworld.py --ua-routing # MITM/auto-quic-block 红线 + 零 UA 规则负向验证
python3 realworld.py --offline    # 只跑 --tun --crosscheck --ua-routing
python3 realworld.py --list-targets   # 只打印数据配置并复核归属，零外部请求
```

- `--tun` 硬断言三条：出站模式 `rule`、IPv4 默认路由指向 utun、系统 DNS 指向 Surge
  响应器（macOS 是 `198.18.0.2`）。有一条不成立后面所有结论都不作数。
- `--dns`：hijack 生效性（应答须落 fake-IP 池 `198.18.0.0/15`）、canary/SVCB 响应器
  行为、DoH 可用性、本地泄漏 live 抽样（`dump dns` 前后快照只看新增，零写操作）。
- `--webrtc` 不写死任何 IP：`baseline: true` 的 STUN 须落 DIRECT，其余组的 srflx
  与它比；`udp-policy-not-supported-behaviour = REJECT` 时超时无应答 = 零泄漏。
- `--crosscheck` 抓离线引擎与真实 Surge 的语义差异：域名类不一致 = 硬失败，纯 IP
  不一致默认只提示（GEOIP 非 CN / IP-ASN 是显式声明的近似）、`--strict` 升为硬失败。
- `--ua-routing` 断言两件事：`[MITM] hostname` 非空时 `auto-quic-block = true`
  （profile 红线）；每个用例带 UA 与不带 UA 落点必须相同（全库已零 UA 规则，落点
  变化 = 规则回流）。

改测什么全在 `realworld_targets.json`；`groups[].hosts` 的选取标准只有一条：该域名
本身必须命中该组的规则，程序每轮用 `surge-cli` 复核归属——这张表是自校验的。

**L3 / L4 共同的安全边界**：不切策略、不改配置、不重载 profile；从不读取或打印
psk / ca-p12；对外只发普通 HTTPS GET/HEAD，只访问场景与 targets 登记的端点，默认
限速 3 req/s。L3 唯一的写操作是 `POST /v1/dns/flush`（`--no-flush` 可关），L4 全程
零写（`surge-cli` 只用 `status` / `rule explain` / `http probe` / `dump dns` /
`dns lookup`）。

## 退出码与已知观察项

退出码：`0` 通过、`1` 有失败项；`2` = 环境不可用（L2 场景/引擎、L3 HTTP API、
L4 Surge/surge-cli/出站模式）；`3` = 用法错误或 Ctrl-C（仅 L3/L4）。所有入口都支持
`--json`。

这些不是 bug：组选中项与假设不一致 = 你切过节点（离线层永远按成员首项推演）；
在线策略显示节点名而非组名（还原不出链路时退一步比 `exit_class`）；`UNREACHABLE` /
`NOT_FOUND` 不算分流错，但大面积出现时程序会警告覆盖率不够；DNS 泄漏要 flush 之后
立刻看（本地缓存全机共享）；ASN 列为空不代表异常（ARIN 对家宽网段常不返回 ASN）。
刻意设计（审计和场景都别报）：YouTube 全量归流媒体组且排在 Google 之前；大厂自有
AI 归各自生态（Gemini → Google、Grok → Twitter、Meta AI → Meta）；全库零
`USER-AGENT` / `PROCESS-NAME` / `URL-REGEX`（A8 把守）；`AI.list` 带
`extended-matching`。离线层的 IP 判定是近似的：`GEOIP,CN` 用 `ChinaIP.list`、
`IP-ASN` 用内置小表、`RULE-SET,SYSTEM`/`LAN` 用内置近似（`--crosscheck` 发现漏项
按在线为准补进 `BUILTIN_SYSTEM_DOMAINS`）；要 MMDB 展开用
`tools/analyze_rules.py --country-db/--asn-db`。
