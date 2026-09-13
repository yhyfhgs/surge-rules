# Surge 分流测试

以下命令均在仓库根目录执行。完整分流验证与发布流程见
[维护手册](../docs/MAINTENANCE.md#validate-a-change)；这里说明各测试的用途和边界。

| 层 | 入口 | 网络要求 | 用途 |
|---|---|---|---|
| L0 | `engine.py` | 离线 | 首次命中、策略、出口推演与 DNS 泄漏路径 |
| L1 | `audit.py` | 离线 | A1–A10 静态审计 |
| L2 | `runsuite.py` | 离线 | 整组会话请求的分流断言 |
| L3 | `live_check.py` | 运行中的 Surge HTTP API + 联网 | 实测策略、出口和 DNS 缓存 |
| L4 | `realworld.py` | 运行中的 Surge / surge-cli，部分联网 | TUN、DNS、STUN、客户端画像及原生匹配 |

域名检查与基础探针使用标准库；IP 匹配、MMDB 分析及配置生成需要安装
`requirements-analysis.txt`（maxminddb、PyYAML）。发布脚本还运行分析器、配置和派生层检查，并非只有 L1/L2。
L3/L4 受网络与节点状态影响，按相关任务范围运行，不作离线发布闸门。

## 配置、数据与隐私

支持 `--conf` 的入口可指定候选配置。默认依次使用有效的 `SURGE_CONF` 和仓库
相邻的 `../Surge.conf`；可用 `--rules` 或 `SURGE_RULES_DIR` 明确指定规则目录。

真实节点名、出口 IP/ASN/ISP 映射和凭据不得入库。`engine.py` 与
`live_check.py` 优先读取 `LIVE_CHECK_LOCAL` 指定的私有 JSON，否则读取
`tests/live_check_local.json`。缺失时使用中性占位值，出口画像断言跳过或退化。
可用字段：

```json
{"exit_class_exact": {"<策略组>": "<exit_class>"},
 "exit_class_keywords": [["<节点关键字>", "<exit_class>"]],
 "asn_map": {"<ASN>": "<说明>"},
 "residential_hints": ["<机构关键字>"],
 "datacenter_hints": ["<机构关键字>"]}
```

提交前用 `git check-ignore tests/live_check_local.json` 确认隔离。报告通过
`--out` / `--report` 写到仓库外，对外分享前使用支持的 `--redact`。

| 数据 | 用途 |
|---|---|
| `scenarios/*.json` | 会话场景与正负例；数量以运行输出为准 |
| `allowlist.json` | 审计豁免与 forbidden 防回流规则 |
| `realworld_targets.json` | L4 代表域、客户端画像、STUN 和 DNS 用例 |
| `data/SNAPSHOTS.json` | PSL / IANA 快照哈希及刷新步骤 |

## L0–L2：离线匹配、审计和场景

```bash
python3 tests/engine.py match example.com --conf /tmp/Surge.candidate.conf --json
python3 tests/engine.py match 1.1.1.1
python3 tests/engine.py dump-index --file Google.list
python3 tests/audit.py --conf /tmp/Surge.candidate.conf --rules lists --check all --fail-on P1
python3 tests/runsuite.py --conf /tmp/Surge.candidate.conf --rules lists
python3 tests/runsuite.py --filter openai --json
```

引擎按 `[Rule]` 顺序展开本地 RULE-SET，仅支持仓库允许的规则类型，其余告警
并跳过。结果包括 `matched_rule`、`rule_index`、`source`、`policy`、
`physical_exit`、`exit_class`、`dns_leak` 与 `dns_leak_at`。
策略组按成员首项推演；GEOIP/ASN 使用真实 MMDB，SYSTEM/LAN 仍为声明过的
近似。没有 DNS 观测时 `routing_complete=false`，不会伪造最终策略。
`stage=domain` / CLI `--stage domain` 只验域名边界，阶段 Final 不代表连接最终
落点。`dns_status=resolved/success/failed`、`resolved_ips`、`sni`、`http_host`
可提供完整测试观测；IP 结果仍须与原生客户端验证。

| 检查 | 内容 |
|---|---|
| A1 | 域名先于主动 IP 解析；加密 DNS 与证书检查 |
| A2 / A3 / A4 | 跨表重复 / 同表覆盖 / 跨表遮蔽 |
| A5 / A6 / A7 | 配置引用完整性 / 关键词清单 / 规则格式 |
| A8 | forbidden 与 IP 隔离清单防回流，命中即 P0 |
| A9 | 按实际列表顺序检查 IP 跨表包含 |
| A10 | 单标签后缀与 PSL 注册边界 |

P0 表示功能或分流错误，P1 表示 IP/DNS 风险，P2 表示冗余遮蔽，P3 为信息建议。
豁免按 `(check, file, rule)` 匹配，可用 `by` / `by_file` / `kind` 收窄；
`preventive: true` 表示防回归条目。forbidden 可用 `file` / `not_file` 限定范围。
两类条目都必须有 `reason`，模式应锚定注册域。

```json
{"name": "openai_chatgpt_web", "desc": "ChatGPT 登录并对话",
 "requests": [{"host": "chatgpt.com"}, {"host": "auth.openai.com"}],
 "assert": {"same_policy": true, "policy": "AI", "no_dns_leak": true}}
```

场景支持 `same_policy`、互斥的 `policy` / `policy_in`、按 `(host, ip)` 匹配的
`per_request`、`no_dns_leak`、`routing_complete`、`dns_resolution_count`；
请求也可只写 `ip`。`no_dns_leak` 检查未经允许的明文查询，不再把任何本地
加密解析都称为泄漏。相同 host/ip 的不同观测应拆成独立场景。未知键、空场景及只剩一个
未覆盖请求的 `same_policy` 会拒载，不能以空测试得到通过。

## 工具自检与 Clash 合同

```bash
python3 tests/engine.py --selftest
python3 tests/audit.py --selftest
python3 tests/analyze_rules_selftest.py
python3 tests/routing_v2_test.py
python3 tests/expiry_safety_test.py
python3 tests/realworld.py --selftest
python3 tools/sort_lists.py --selftest
python3 tools/probe_dead_domains.py --selftest
python3 tests/adversarial_harness.py --conf /tmp/Surge.candidate.conf --rules lists
python3 tests/adversarial_analyze_rules_test.py
python3 tests/adversarial_probe_dead_domains_test.py
python3 tests/clash_contract.py --conf /tmp/Surge.candidate.conf
```

按改动范围运行已有自检。压力测试覆盖域名/IP 边界、会话一致性、DNS 泄漏、
QUIC 模糊输入和 STUN 报文。Clash 合同逐条比较源规则与 payload、manifest
顺序、IP 减法/匹配参数、DNS 路径及归属正负例。
`tests/mihomo_dns_failure_test.py` 使用隔离 DNS 实例验证不可用代理返回 SERVFAIL；
不启用 TUN、不改系统代理或用户配置。原生加载与系统 DNS 接管的验证边界见
[Clash 部署说明](../docs/CLASH.md)，语法通过不等于 provider 已加载。

## L3/L4：实测

L3 使用仅监听 `127.0.0.1` 的已配置 HTTP API，密钥由 `SURGE_API_KEY` 提供；
程序不代改配置。L4 使用本机 surge-cli，无需 HTTP API。

```bash
python3 tests/live_check.py --check-api
python3 tests/live_check.py --policies
python3 tests/live_check.py --scenario all
python3 tests/live_check.py --exit-map
python3 tests/live_check.py --dns-leak
python3 tests/realworld.py --tun
python3 tests/realworld.py --dns
python3 tests/realworld.py --webrtc
python3 tests/realworld.py --clients
python3 tests/realworld.py --quic
python3 tests/realworld.py --crosscheck
python3 tests/realworld.py --ua-routing
```

L3 `--policies` 区分 select 手动选择与 smart/url-test 动态择优；`--exit-map`
仅在提供私有 `expected_asn.json` 时断言 ASN。`UNREACHABLE` / `NOT_FOUND`
不等于分流错误，但覆盖不足不能报全面成功，一条都未判定会失败。

L4 `--tun` 检查规则模式、默认路由和 Surge DNS；`--dns` 检查 fake-IP、
canary/SVCB/DoH 与缓存增量；`--webrtc` 比较 DIRECT 基线和代理 STUN 出口。
`--crosscheck` 的域名差异硬失败，IP 近似差异默认提示，`--strict` 升为失败。
`--ua-routing` 检查 MITM hostname 与 auto-quic-block 配对及零 UA 规则。
`--offline` 仍依赖运行中的 Surge；真正无运行时依赖的是 `--selftest`。

实测不切策略、不改配置、不重载 profile、不打印密钥或证书。L3 DNS flush 可用
`--no-flush` 关闭；L4 只读本地控制接口，网络探针按 targets 定义限速运行。
正常退出为 0，失败为 1；L2–L4 环境不可用为 2，L3/L4 用法错误或中断为 3。


## 过期候选的证据边界

`probe_dead_domains.py` 使用 curl 给 DoH 的 DNS/TLS/读取总时间设限，
并将排队与网络超时分开；`--dns-only` 可不读取网站内容。只有至少两个干净
解析器的 NXDOMAIN 共识和权威确认才能进入未注册候选；超时、NODATA、
无 NS 回应和停放页线索均不能直接触发删除。死亡计数每隔至少24小时才递增。
当前网络受代理/TUN影响时，CN DNS异常标签仅供调查，不能单独用于新增代理规则。
